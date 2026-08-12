// vibecheck — paid-tier dashboard: pure derivation logic + D1 I/O
//
// Split the same way as monitors.ts/auth.ts (see monitors.ts's module
// header for the pattern this repo follows): pure functions over plain data
// (deriveCostRiskState, diffSecurityFindings, isMonitorOwnedByUser,
// computeMutedUntil, isMuted) live here untested-by-D1, next to the thin D1
// wrappers (fetchAlertsForMonitor, fetchMostRecentAlertOfType) that have no
// branching logic of their own. See docs/product/vibecheck-monitoring-tier-spec.md
// §5 for the five dashboard elements this file supports (all but element 1's
// sparkline, which reuses monitors.ts's existing fetchTrailingChecks).

import type { AlertRow, AlertType, Finding, MonitorRow } from './types';
import { COLD_START_MIN_SAMPLES } from './anomaly';

// ── Element 2: cost-risk three-state label ──────────────────────────────────
//
// Spec §5.2: "Normal / Learning / Elevated", derived at read time, no new
// persisted column.
//
// Rule (documented here since the spec explicitly leaves it to us to pick a
// concrete one):
//   - "Learning" — fewer than COLD_START_MIN_SAMPLES (7) trailing checks
//     exist yet. Mirrors anomaly.ts's own cold-start gate exactly, so the
//     dashboard's notion of "not enough data" never disagrees with the
//     detector actually making the call.
//   - "Elevated" — a 'latency_anomaly' alert fired within the last 24h.
//     Alert rows of this type never get resolved_at set (only 'down' alerts
//     do, via resolveOpenDownAlert in monitors.ts/index.ts's cron) — so
//     "unresolved" isn't a usable signal here, recency is the only thing
//     left to key off. 24h is chosen to match the mute toggle's own "pause
//     alerts for 24h" window elsewhere on this same page, so the whole
//     dashboard shares one consistent notion of "still relevant right now"
//     rather than two different tunable windows a reader has to reconcile.
//   - "Normal" — otherwise.
export type CostRiskState = 'Normal' | 'Learning' | 'Elevated';

export const COST_RISK_ELEVATED_WINDOW_MS = 24 * 60 * 60 * 1000;

export function deriveCostRiskState(
  trailingCheckCount: number,
  mostRecentLatencyAnomalyFiredAt: string | null,
  nowIso: string = new Date().toISOString(),
  options: { minSamplesForBaseline?: number; windowMs?: number } = {}
): CostRiskState {
  const minSamplesForBaseline = options.minSamplesForBaseline ?? COLD_START_MIN_SAMPLES;
  const windowMs = options.windowMs ?? COST_RISK_ELEVATED_WINDOW_MS;

  if (trailingCheckCount < minSamplesForBaseline) return 'Learning';

  if (mostRecentLatencyAnomalyFiredAt) {
    const ageMs = Date.parse(nowIso) - Date.parse(mostRecentLatencyAnomalyFiredAt);
    if (ageMs >= 0 && ageMs <= windowMs) return 'Elevated';
  }

  return 'Normal';
}

// ── Element 3: security drift ───────────────────────────────────────────────
//
// Spec §5.3: diff the signup-time baseline against a fresh live-probe call.
// Diffed on `title`, not `id` — liveChecks.ts's nextLiveId() counter resets
// on every buildLiveFindings() call (liveFindingCounter = 0 at the top), so
// ids are per-call, not stable identity across the baseline capture and a
// later dashboard-load call. Finding.title is stable across calls for the
// same underlying condition (e.g. "Permissive CORS policy on live
// deployment (wildcard origin)"), so it's the only usable diff key here.
export interface SecurityDriftDiff {
  newFindings: Finding[];
}

export function diffSecurityFindings(baseline: Finding[], live: Finding[]): SecurityDriftDiff {
  const baselineTitles = new Set(baseline.map(f => f.title));
  return { newFindings: live.filter(f => !baselineTitles.has(f.title)) };
}

// ── Element 5: mute toggle ("pause alerts for 24h") ─────────────────────────

export const MUTE_DURATION_MS = 24 * 60 * 60 * 1000;

// Turning the toggle on sets muted_until 24h out; turning it off clears it
// (explicit un-mute) rather than only ever expiring on its own — the spec's
// "pause alerts for 24h" phrasing implies a way to end early if the user
// changes their mind, and without it the mute state would never visibly
// clear in the UI short of a 24h wait + page reload.
export function computeMutedUntil(mute: boolean, nowIso: string = new Date().toISOString()): string | null {
  if (!mute) return null;
  return new Date(Date.parse(nowIso) + MUTE_DURATION_MS).toISOString();
}

export function isMuted(mutedUntil: string | null, nowIso: string = new Date().toISOString()): boolean {
  return mutedUntil !== null && mutedUntil > nowIso;
}

// First ownership-checked mutation endpoint in this codebase (POST
// /api/monitors/:id/mute) — every prior write either scoped itself via the
// authenticated user's own id (POST /api/monitors' insertMonitor) or wasn't
// a per-row mutation at all. Kept as a standalone pure predicate (not
// inlined in index.ts) specifically so this check has its own unit test
// rather than only being exercised indirectly through an HTTP round-trip.
export function isMonitorOwnedByUser(monitor: Pick<MonitorRow, 'user_id'>, userId: number): boolean {
  return monitor.user_id === userId;
}

// ── D1 I/O ───────────────────────────────────────────────────────────────────

// Element 4: last 10 alerts, newest first.
export async function fetchAlertsForMonitor(db: D1Database, monitorId: number, limit = 10): Promise<AlertRow[]> {
  const { results } = await db
    .prepare('SELECT * FROM alerts WHERE monitor_id = ?1 ORDER BY fired_at DESC LIMIT ?2')
    .bind(monitorId, limit)
    .all<AlertRow>();
  return results ?? [];
}

// Feeds deriveCostRiskState's recency check — the last 10 alerts (any type)
// might not include the most recent latency_anomaly if other alert types
// fired more recently, so this is a dedicated, type-filtered query rather
// than reusing fetchAlertsForMonitor's result.
export async function fetchMostRecentAlertOfType(
  db: D1Database,
  monitorId: number,
  type: AlertType
): Promise<AlertRow | null> {
  const row = await db
    .prepare('SELECT * FROM alerts WHERE monitor_id = ?1 AND type = ?2 ORDER BY fired_at DESC LIMIT 1')
    .bind(monitorId, type)
    .first<AlertRow>();
  return row ?? null;
}
