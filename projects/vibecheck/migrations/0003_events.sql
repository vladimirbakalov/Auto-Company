-- vibecheck D1 schema
-- Migration 0003: lightweight analytics `events` table — top-of-funnel
-- visibility (Cycle #126 mandate: "no count of landing page views, no count
-- of scans submitted, no count of signups/checkouts started vs completed").
--
-- Deliberately minimal — a counter table, not an analytics platform. No
-- session/user tracking, no PII, no IP addresses: just what happened, an
-- optional path, and when. GET /admin/stats (src/index.ts, src/events.ts)
-- aggregates this with COUNT(*) on demand rather than pre-aggregating —
-- cheap enough at this traffic volume that a rollup job would be premature.
--
-- event_type values in use (see src/events.ts's EventType union — keep both
-- in sync, there's no CHECK constraint enforcing this at the DB level,
-- matching how alerts.type / users.subscription_status are documented
-- in-comment rather than constrained in migrations/0001_init.sql):
--   'landing_pageview'   — GET /
--   'scan_submitted'     — POST /api/scan was attempted (not gated on the
--                          scan's own result — a failed/erroring scan still
--                          counts as "someone submitted one")
--   'checkout_started'   — POST /api/checkout successfully created a Stripe
--                          Checkout Session (the user is being sent to pay)
--   'checkout_completed' — POST /api/stripe/webhook's checkout.session.completed
--                          handler successfully upserted the D1 user row
--                          (the actual "did someone convert" signal)

CREATE TABLE IF NOT EXISTS events (
  id           INTEGER PRIMARY KEY,
  event_type   TEXT NOT NULL,
  path         TEXT,
  occurred_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, occurred_at);
