-- vibecheck D1 schema
-- Migration 0001: monitoring-tier tables (users, magic_links, monitors,
-- checks, alerts) — see docs/cto/vibecheck-monitoring-tier-adr.md §6 for the
-- design rationale. The free-tier scanner remains fully stateless; none of
-- these tables are read/written by the existing /api/scan path.
--
-- Convention follows projects/snapog/migrations/0001_init.sql (sibling
-- project, same D1-on-Workers setup): apply with
--   wrangler d1 migrations apply vibecheck-db --local
--   wrangler d1 migrations apply vibecheck-db
-- (see package.json db:local / db:remote scripts).

CREATE TABLE IF NOT EXISTS users (
  id                      INTEGER PRIMARY KEY,
  email                   TEXT UNIQUE NOT NULL,
  stripe_customer_id      TEXT UNIQUE,
  stripe_subscription_id  TEXT,
  subscription_status     TEXT NOT NULL DEFAULT 'inactive', -- active | past_due | canceled | inactive
  api_key_hash            TEXT,          -- nullable until user generates one
  created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS magic_links (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id),
  expires_at  TEXT NOT NULL,
  used_at     TEXT
);

CREATE TABLE IF NOT EXISTS monitors (
  id                    INTEGER PRIMARY KEY,
  user_id               INTEGER NOT NULL REFERENCES users(id),
  url                   TEXT NOT NULL,
  interval_seconds      INTEGER NOT NULL DEFAULT 300, -- 5 min default, 5-15 min range per CEO brief
  next_check_at         TEXT NOT NULL,
  last_check_at         TEXT,
  last_status           INTEGER,
  consecutive_failures  INTEGER NOT NULL DEFAULT 0,
  paused                INTEGER NOT NULL DEFAULT 0,
  created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_monitors_due ON monitors(next_check_at) WHERE paused = 0;

CREATE TABLE IF NOT EXISTS checks (
  id           INTEGER PRIMARY KEY,
  monitor_id   INTEGER NOT NULL REFERENCES monitors(id),
  checked_at   TEXT NOT NULL,
  status_code  INTEGER,
  latency_ms   INTEGER,
  ok           INTEGER NOT NULL,
  error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_monitor_time ON checks(monitor_id, checked_at);
-- Retention: prune checks older than 30-60 days via a second cron tick, or
-- this table grows unbounded at (86400/interval * monitors) rows/day. Not
-- built in this migration/change — flagged in the ADR as a day-one-bounded
-- concern, tracked as follow-up work, not a schema blocker.

CREATE TABLE IF NOT EXISTS alerts (
  id           INTEGER PRIMARY KEY,
  monitor_id   INTEGER NOT NULL REFERENCES monitors(id),
  type         TEXT NOT NULL, -- 'down' | 'recovered' | 'latency_anomaly'
  fired_at     TEXT NOT NULL,
  resolved_at  TEXT,
  notified_at  TEXT,
  details      TEXT
);
