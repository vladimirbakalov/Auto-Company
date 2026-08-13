// vibecheck — lightweight self-hosted analytics (Cycle #126)
//
// The company had zero visibility into top-of-funnel activity for this
// product: no count of landing page views, scans submitted, or
// signups/checkouts started vs completed. This module is the entire
// "analytics platform": one D1 table (migrations/0003_events.sql), a
// fire-and-forget write, and a few COUNT(*) aggregates for GET /admin/stats
// (src/index.ts). Not a queue, not a rollup job, not per-user tracking — a
// counter, on purpose (see the task brief this shipped from,
// docs/fullstack/vibecheck-analytics-cycle126.md).
//
// Split the same way as monitors.ts/auth.ts: this file owns the D1 I/O and
// the pure aggregation shape; index.ts owns wiring each event to a
// fire-and-forget call at the right route (recordEventInBackground there
// handles the ExecutionContext.waitUntil plumbing, since that's Hono/Workers
// request-lifecycle concern, not an events-domain one).

export type EventType = 'landing_pageview' | 'scan_submitted' | 'checkout_started' | 'checkout_completed';

// Inserts one event row. Never throws — analytics must never break or slow
// down the real user-facing response it's attached to (every call site in
// index.ts fires this in the background via recordEventInBackground, never
// awaited inline in the request's critical path). A missing DB binding is a
// silent no-op, not a log line: every other `if (!c.env.DB)` branch in
// index.ts already logs the missing-binding TODO loudly once per request
// that needed it; logging it again here per-event would just be duplicate
// noise for the same underlying gap.
export async function recordEvent(db: D1Database | undefined, eventType: EventType, path: string | null = null): Promise<void> {
  if (!db) return;
  try {
    await db.prepare('INSERT INTO events (event_type, path) VALUES (?1, ?2)').bind(eventType, path).run();
  } catch (err) {
    console.error('Failed to record analytics event', eventType, err);
  }
}

// Window cutoff is computed by SQLite itself (`datetime('now', modifier)`),
// NOT by formatting a JS Date to an ISO string and comparing it against
// `occurred_at` as text. Those two formats disagree: `occurred_at` is
// stored via the column's `DEFAULT (datetime('now'))`
// (migrations/0003_events.sql), which SQLite renders as
// "YYYY-MM-DD HH:MM:SS" (space separator, no fractional seconds, no "Z").
// `Date#toISOString()` renders "YYYY-MM-DDTHH:MM:SS.sssZ". A plain text
// `>=` comparison between the two breaks exactly when the two timestamps
// fall on the *same calendar date*: SQLite compares byte-for-byte, and the
// 11th character diverges first ("T" 0x54 vs the space 0x20), so an event
// timestamped *later* in the day than the cutoff still sorts as "less than"
// the cutoff purely because of the format mismatch — silently dropping real
// events from the count. (This is the same failure mode flagged in
// snapog's pre-existing dashboard query; verified against real D1/workerd
// in test/index.workers.test.ts before landing this fix.) Doing the
// arithmetic inside SQLite sidesteps the format mismatch entirely, since
// both sides of the comparison are then in SQLite's own format.
export async function countEventsInWindow(db: D1Database, eventType: EventType, modifier: string): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) as count FROM events WHERE event_type = ?1 AND occurred_at >= datetime('now', ?2)`)
    .bind(eventType, modifier)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

// Cheap to pull alongside the event counts for GET /admin/stats — not from
// the `events` table at all, just a live COUNT(*) over monitors.paused = 0,
// the same "is monitoring actually running for anyone" signal
// fetchDueMonitors' WHERE clause (monitors.ts) already relies on.
export async function countActiveMonitors(db: D1Database): Promise<number> {
  const row = await db.prepare('SELECT COUNT(*) as count FROM monitors WHERE paused = 0').first<{ count: number }>();
  return row?.count ?? 0;
}

export interface EventCounts {
  last24h: number;
  last7d: number;
  last30d: number;
}

export interface AdminStats {
  landingPageviews: EventCounts;
  scansSubmitted: EventCounts;
  checkoutStarted: EventCounts;
  checkoutCompleted: EventCounts;
  activeMonitors: number;
  generatedAt: string;
}

// SQLite `datetime()` modifiers (see countEventsInWindow above) — mirrors
// snapog's src/admin/routes.ts WINDOWS constant for the same reason.
const STATS_WINDOWS: ReadonlyArray<{ key: keyof EventCounts; modifier: string }> = [
  { key: 'last24h', modifier: '-1 day' },
  { key: 'last7d', modifier: '-7 day' },
  { key: 'last30d', modifier: '-30 day' },
];

async function countAllWindows(db: D1Database, eventType: EventType): Promise<EventCounts> {
  const entries = await Promise.all(
    STATS_WINDOWS.map(async ({ key, modifier }) => [key, await countEventsInWindow(db, eventType, modifier)] as const)
  );
  return Object.fromEntries(entries) as unknown as EventCounts;
}

// One D1 round-trip per (eventType x window) — 12 queries total plus the
// active-monitors count. Fine for GET /admin/stats' traffic (a human
// checking a dashboard, not a hot path): correctness and readability over
// collapsing this into one clever aggregate SQL query, per this codebase's
// "clear over clever" bias (see CLAUDE.md).
//
// `nowMs` only feeds `generatedAt` in the response body now — the window
// cutoffs themselves are computed by SQLite's own `datetime('now', ...)`
// (see countEventsInWindow), not from this value, so results are always
// consistent with what's actually in the `occurred_at` column regardless
// of what `nowMs` is passed as.
export async function buildAdminStats(db: D1Database, nowMs: number = Date.now()): Promise<AdminStats> {
  const [landingPageviews, scansSubmitted, checkoutStarted, checkoutCompleted, activeMonitors] = await Promise.all([
    countAllWindows(db, 'landing_pageview'),
    countAllWindows(db, 'scan_submitted'),
    countAllWindows(db, 'checkout_started'),
    countAllWindows(db, 'checkout_completed'),
    countActiveMonitors(db),
  ]);
  return {
    landingPageviews,
    scansSubmitted,
    checkoutStarted,
    checkoutCompleted,
    activeMonitors,
    generatedAt: new Date(nowMs).toISOString(),
  };
}
