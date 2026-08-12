// vibecheck — monitors CRUD + due-queue selection + cron fan-out
//
// Split deliberately into two halves per the ADR/task brief:
//   - Pure decision logic (isMonitorDue, selectDueMonitors, buildCheckInsert,
//     applyCheckResultToMonitor) — plain functions over plain data, testable
//     without a D1 binding.
//   - Thin D1 I/O wrappers (fetchDueMonitors, insertMonitor, recordCheck,
//     openAlertExists, insertAlert) — one prepared statement each, no
//     branching logic of their own, so a bug can only live in the pure half.
//
// See docs/cto/vibecheck-monitoring-tier-adr.md §2 and §6 for the design.

import type { AlertRow, AlertType, CheckRow, MonitorRow } from './types';
import type { ProbeResult } from './probe';

// ── Pure: due-queue selection (mirrors the ADR §2 SQL) ──────────────────────
//
//   SELECT * FROM monitors
//   WHERE next_check_at <= ? AND paused = 0 AND subscription_active = 1
//   ORDER BY next_check_at ASC
//   LIMIT 500
//
// `subscription_active` isn't a monitors column (ADR §6 step 5: it's derived
// by joining users.subscription_status = 'active'); callers pre-filter to
// only monitors whose owning user is active before calling this, or pass an
// `isSubscriptionActive` lookup. Kept here as an explicit parameter rather
// than baked into the row shape, so this function stays a pure filter over
// `monitors` exactly as named in the ADR.

export const DUE_QUEUE_LIMIT = 500;

export interface DueQueueOptions {
  limit?: number;
  // Given a monitor, is its owning user's subscription currently active?
  // Defaults to "always true" so callers that already pre-filtered (e.g. a
  // SQL join) don't need to pass anything.
  isSubscriptionActive?: (monitor: MonitorRow) => boolean;
}

export function isMonitorDue(monitor: MonitorRow, nowIso: string): boolean {
  return monitor.paused === 0 && monitor.next_check_at <= nowIso;
}

export function selectDueMonitors(
  monitors: MonitorRow[],
  nowIso: string,
  options: DueQueueOptions = {}
): MonitorRow[] {
  const limit = options.limit ?? DUE_QUEUE_LIMIT;
  const isActive = options.isSubscriptionActive ?? (() => true);

  return monitors
    .filter(m => isMonitorDue(m, nowIso) && isActive(m))
    .sort((a, b) => (a.next_check_at < b.next_check_at ? -1 : a.next_check_at > b.next_check_at ? 1 : 0))
    .slice(0, limit);
}

// ── Pure: turning a probe result into the next monitor/check state ─────────

export interface CheckInsert {
  monitor_id: number;
  checked_at: string;
  status_code: number | null;
  latency_ms: number | null;
  ok: 0 | 1;
  error: string | null;
}

export function buildCheckInsert(monitorId: number, probe: ProbeResult, nowIso: string): CheckInsert {
  return {
    monitor_id: monitorId,
    checked_at: nowIso,
    status_code: probe.status,
    latency_ms: probe.latencyMs,
    ok: probe.ok && probe.status !== null && probe.status < 500 ? 1 : 0,
    error: probe.error,
  };
}

export interface MonitorUpdate {
  next_check_at: string;
  last_check_at: string;
  last_status: number | null;
  consecutive_failures: number;
}

// Computes the next monitor row fields after a check — next_check_at bumped
// by interval_seconds, consecutive_failures incremented on failure / reset to
// 0 on success (ADR §6 step 5).
export function applyCheckResultToMonitor(monitor: MonitorRow, check: CheckInsert, nowIso: string): MonitorUpdate {
  const succeeded = check.ok === 1;
  return {
    next_check_at: new Date(Date.parse(nowIso) + monitor.interval_seconds * 1000).toISOString(),
    last_check_at: nowIso,
    last_status: check.status_code,
    consecutive_failures: succeeded ? 0 : monitor.consecutive_failures + 1,
  };
}

// ── D1 I/O wrappers ──────────────────────────────────────────────────────────
// Each function is one prepared statement, no decision logic of its own —
// the branching already happened in the pure functions above.

export async function fetchDueMonitors(db: D1Database, nowIso: string, limit = DUE_QUEUE_LIMIT): Promise<MonitorRow[]> {
  // Joins users to gate on an active-or-grace subscription, per ADR §6 step 5
  // ("a canceled subscription's monitors stop consuming probe budget") *and*
  // critic-munger's pre-mortem finding #2 (docs/critic/vibecheck-monitoring-tier-premortem.md):
  // Stripe fires `invoice.payment_failed` -> our `past_due` status on the
  // *first* declined card, weeks before the subscription is actually
  // canceled. Gating strictly on 'active' would silently stop monitoring on
  // a routine expired card, with no in-product notice, right when the user
  // is least likely to notice. Keep probing through 'past_due'; only stop on
  // 'canceled'/'unpaid' (narrowSubscriptionStatus in stripe.ts maps both of
  // those, plus any other terminal Stripe status, to 'canceled').
  const { results } = await db
    .prepare(
      `SELECT monitors.* FROM monitors
       JOIN users ON users.id = monitors.user_id
       WHERE monitors.next_check_at <= ?1
         AND monitors.paused = 0
         AND users.subscription_status IN ('active', 'past_due')
       ORDER BY monitors.next_check_at ASC
       LIMIT ?2`
    )
    .bind(nowIso, limit)
    .all<MonitorRow>();
  return results ?? [];
}

export interface CreateMonitorParams {
  userId: number;
  url: string;
  intervalSeconds?: number;
}

export async function insertMonitor(db: D1Database, params: CreateMonitorParams): Promise<MonitorRow> {
  const nowIso = new Date().toISOString();
  const intervalSeconds = params.intervalSeconds ?? 300;
  const row = await db
    .prepare(
      `INSERT INTO monitors (user_id, url, interval_seconds, next_check_at, created_at)
       VALUES (?1, ?2, ?3, ?4, ?4)
       RETURNING *`
    )
    .bind(params.userId, params.url, intervalSeconds, nowIso)
    .first<MonitorRow>();
  if (!row) throw new Error('Failed to insert monitor');
  return row;
}

export async function listMonitorsForUser(db: D1Database, userId: number): Promise<MonitorRow[]> {
  const { results } = await db
    .prepare('SELECT * FROM monitors WHERE user_id = ?1 ORDER BY created_at DESC')
    .bind(userId)
    .all<MonitorRow>();
  return results ?? [];
}

export async function recordCheck(db: D1Database, check: CheckInsert): Promise<CheckRow> {
  const row = await db
    .prepare(
      `INSERT INTO checks (monitor_id, checked_at, status_code, latency_ms, ok, error)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)
       RETURNING *`
    )
    .bind(check.monitor_id, check.checked_at, check.status_code, check.latency_ms, check.ok, check.error)
    .first<CheckRow>();
  if (!row) throw new Error('Failed to insert check');
  return row;
}

export async function updateMonitorAfterCheck(db: D1Database, monitorId: number, update: MonitorUpdate): Promise<void> {
  await db
    .prepare(
      `UPDATE monitors
       SET next_check_at = ?1, last_check_at = ?2, last_status = ?3, consecutive_failures = ?4
       WHERE id = ?5`
    )
    .bind(update.next_check_at, update.last_check_at, update.last_status, update.consecutive_failures, monitorId)
    .run();
}

// Fetches the trailing check history used as the anomaly baseline (§4/spec
// §1.2) — most recent `limit` checks for a monitor, oldest first so callers
// can feed it straight into detectTrafficAnomaly's `trailingValues`.
export async function fetchTrailingChecks(db: D1Database, monitorId: number, limit: number): Promise<CheckRow[]> {
  const { results } = await db
    .prepare('SELECT * FROM checks WHERE monitor_id = ?1 ORDER BY checked_at DESC LIMIT ?2')
    .bind(monitorId, limit)
    .all<CheckRow>();
  return (results ?? []).reverse();
}

export async function hasOpenDownAlert(db: D1Database, monitorId: number): Promise<boolean> {
  const row = await db
    .prepare(`SELECT id FROM alerts WHERE monitor_id = ?1 AND type = 'down' AND resolved_at IS NULL LIMIT 1`)
    .bind(monitorId)
    .first<{ id: number }>();
  return row !== null;
}

export async function insertAlert(
  db: D1Database,
  monitorId: number,
  type: AlertType,
  details: string | null,
  nowIso: string
): Promise<AlertRow> {
  const row = await db
    .prepare(
      `INSERT INTO alerts (monitor_id, type, fired_at, details)
       VALUES (?1, ?2, ?3, ?4)
       RETURNING *`
    )
    .bind(monitorId, type, nowIso, details)
    .first<AlertRow>();
  if (!row) throw new Error('Failed to insert alert');
  return row;
}

export async function resolveOpenDownAlert(db: D1Database, monitorId: number, nowIso: string): Promise<void> {
  await db
    .prepare(`UPDATE alerts SET resolved_at = ?1 WHERE monitor_id = ?2 AND type = 'down' AND resolved_at IS NULL`)
    .bind(nowIso, monitorId)
    .run();
}

// ── Bounded-parallel fan-out (mirrors github.ts's fetchFiles shape) ─────────
// Kept generic over the per-monitor unit of work so the scheduled handler in
// index.ts supplies the actual probe + write logic; this file only owns the
// concurrency shape.

const DEFAULT_FAN_OUT_CONCURRENCY = 20;

export async function runBoundedFanOut<T, R>(
  items: T[],
  worker: (item: T) => Promise<R>,
  concurrency = DEFAULT_FAN_OUT_CONCURRENCY
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array(items.length);
  let cursor = 0;

  async function runNext(): Promise<void> {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      try {
        const value = await worker(items[index]);
        results[index] = { status: 'fulfilled', value };
      } catch (reason) {
        results[index] = { status: 'rejected', reason };
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => runNext());
  await Promise.all(workers);
  return results;
}
