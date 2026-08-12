-- vibecheck D1 schema
-- Migration 0002: dashboard support columns on `monitors` — see
-- docs/product/vibecheck-monitoring-tier-spec.md §5 (dashboard elements 3
-- and 5) and docs/fullstack/vibecheck-dashboard-implementation.md for the
-- design rationale.
--
-- Both columns are nullable with no backfill needed: existing monitor rows
-- simply get NULL, which is already the correct "no baseline captured yet" /
-- "not muted" state for those two columns respectively — no migration-time
-- computation required.

ALTER TABLE monitors ADD COLUMN baseline_findings_json TEXT;
ALTER TABLE monitors ADD COLUMN muted_until TEXT;
