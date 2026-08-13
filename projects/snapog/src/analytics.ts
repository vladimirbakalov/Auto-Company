// SnapOG — top-of-funnel analytics (see migrations/0003_analytics.sql)
//
// Deliberately separate from usage_events (migrations/0001_init.sql), which
// already covers OG generation itself once a visitor has an API key. This
// module is everything upstream of that: did anyone see the landing page,
// did they get to /register, did they actually complete signup. A counter,
// not a full analytics platform — no user/session/IP tracking, just an
// event log queried by GET /admin/stats (src/admin/routes.ts).

export type EventType = 'landing_pageview' | 'register_pageview' | 'signup';

export async function recordEvent(
  db: D1Database,
  eventType: EventType,
  path: string | null = null
): Promise<void> {
  await db
    .prepare('INSERT INTO events (id, event_type, path) VALUES (?, ?, ?)')
    .bind(crypto.randomUUID(), eventType, path)
    .run();
}
