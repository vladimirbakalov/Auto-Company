-- SnapOG D1 Schema
-- Migration 0003: top-of-funnel analytics
--
-- usage_events (0001) already tracks OG generation itself. This table
-- covers everything upstream of that: landing pageviews, register
-- pageviews, and completed signups. Deliberately minimal — a counter for
-- "is outreach/marketing doing anything", not a full analytics platform.
-- No IP/UA/referrer columns on purpose: nothing here is PII, so there's
-- nothing to retention-policy or redact later.

CREATE TABLE IF NOT EXISTS events (
  id           TEXT PRIMARY KEY,
  event_type   TEXT NOT NULL,          -- landing_pageview | register_pageview | signup
  path         TEXT,                   -- request path, nullable (not every event maps to one)
  occurred_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Serves "count by type in the last N days" (GET /admin/stats): type is the
-- equality filter, occurred_at the range scan, so put type first.
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, occurred_at);
