// vibecheck — shared types

export interface Env {
  ENVIRONMENT: string;
  // Optional: raises the GitHub API rate limit from 60 req/hr (unauthenticated)
  // to 5,000 req/hr. Not required for the MVP. Set with:
  //   wrangler secret put GITHUB_TOKEN
  GITHUB_TOKEN?: string;
  // Waitlist store for the "cost + uptime monitoring, coming soon" signup
  // (see docs/ceo/vibecheck-godecision-cycle4.md). Declared in wrangler.toml
  // with a placeholder id — must be created via `wrangler kv:namespace create
  // WAITLIST` and the id filled in before first deploy. Until then this binding
  // is undefined at runtime; the /api/waitlist handler checks for that and
  // no-ops with a logged TODO instead of throwing, so local dev / dry-run
  // never breaks on a missing namespace.
  WAITLIST?: KVNamespace;

  // Coarse per-IP rate-limit counters for the unauthenticated URL-probing/
  // scanning endpoints (POST /api/scan, POST /api/probe-check, POST
  // /api/monitors — see src/rateLimit.ts for the fixed-window design and
  // src/index.ts's QA-cycle-#1146 comment for the gap this closes). Declared
  // in wrangler.toml with a placeholder id — same graceful-degradation
  // convention as WAITLIST above: created via `wrangler kv:namespace create
  // RATE_LIMIT` before first deploy. Until then this binding is undefined at
  // runtime; checkRateLimit() treats a missing binding as "always allow"
  // rather than throwing, so local dev / dry-run never breaks on a missing
  // namespace. A dedicated namespace rather than reusing WAITLIST because the
  // two are semantically unrelated (a mailing list vs. abuse counters) and
  // have very different write patterns (rare/durable vs. frequent/throwaway).
  RATE_LIMIT?: KVNamespace;

  // Monitoring-tier D1 database: users, magic_links, monitors, checks, alerts
  // (docs/cto/vibecheck-monitoring-tier-adr.md §1/§6). Declared in
  // wrangler.toml with a placeholder id — same graceful-degradation
  // convention as WAITLIST above: created via `wrangler d1 create
  // vibecheck-db`, migrations applied via `wrangler d1 migrations apply`, and
  // every handler that touches it checks `if (!c.env.DB)` first so local dev
  // without a provisioned database degrades instead of 500ing.
  DB?: D1Database;

  // Stripe secret key for creating Checkout Sessions / Billing Portal
  // sessions server-side (ADR §5). Set with `wrangler secret put
  // STRIPE_SECRET_KEY`. Optional at the type level so typecheck/tests don't
  // require it; POST /api/checkout no-ops gracefully if it's missing.
  STRIPE_SECRET_KEY?: string;
  // Signing secret for verifying `Stripe-Signature` webhook headers
  // (`wrangler secret put STRIPE_WEBHOOK_SECRET`). Required to trust any
  // webhook payload — the handler rejects events if this is missing rather
  // than trusting an unverified body.
  STRIPE_WEBHOOK_SECRET?: string;
  // Stripe Price object id for the $20/mo monitoring subscription
  // (`wrangler secret put STRIPE_PRICE_ID`, or a plain [vars] entry — not
  // secret-shaped data, but kept alongside the other Stripe config here).
  STRIPE_PRICE_ID?: string;

  // Signing key (HMAC) for the session cookie set after a magic-link click
  // (ADR §5 step 3). Set with `wrangler secret put SESSION_SECRET`.
  SESSION_SECRET?: string;

  // Transactional email provider API key (Resend or Postmark — ADR §5 names
  // either as acceptable, "not a consequential choice"). Set with
  // `wrangler secret put RESEND_API_KEY`. Optional: email-sending call sites
  // no-op with a logged TODO when absent, same style as WAITLIST/GITHUB_TOKEN.
  RESEND_API_KEY?: string;
}

export interface WaitlistEntry {
  repoUrl: string;
  scannedAt: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  explanation: string;
  file?: string;
  line?: number;
}

export interface RepoRef {
  owner: string;
  repo: string;
}

export interface RepoFile {
  path: string;
  content: string;
}

export interface ScanResult {
  owner: string;
  repo: string;
  defaultBranch: string;
  score: number;
  grade: string;
  findings: Finding[];
  filesScanned: number;
  filesInTree: number;
  scannedAt: string;
  notes: string[];
}

export class ScanError extends Error {
  constructor(
    message: string,
    public status: number
  ) {
    super(message);
    this.name = 'ScanError';
  }
}

// ── Monitoring tier: D1 row shapes ──────────────────────────────────────────
// Mirrors migrations/0001_init.sql exactly. Kept as plain row shapes (D1's
// snake_case column names, not camelCased) so the mapping from a D1 query
// result to a typed object is a no-op cast, not a translation layer to keep
// in sync — see docs/cto/vibecheck-monitoring-tier-adr.md §6.

export type SubscriptionStatus = 'active' | 'past_due' | 'canceled' | 'inactive';

export interface UserRow {
  id: number;
  email: string;
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  subscription_status: SubscriptionStatus;
  api_key_hash: string | null;
  created_at: string;
}

export interface MagicLinkRow {
  token_hash: string;
  user_id: number;
  expires_at: string;
  used_at: string | null;
}

export interface MonitorRow {
  id: number;
  user_id: number;
  url: string;
  interval_seconds: number;
  next_check_at: string;
  last_check_at: string | null;
  last_status: number | null;
  consecutive_failures: number;
  paused: 0 | 1;
  created_at: string;
  // Added by migrations/0002_dashboard.sql — dashboard element 3 (security
  // drift) and element 5 (mute toggle). Both nullable, no backfill: NULL is
  // already the correct "no baseline yet" / "not muted" state for existing
  // rows (see that migration's header comment).
  baseline_findings_json: string | null;
  muted_until: string | null;
}

export interface CheckRow {
  id: number;
  monitor_id: number;
  checked_at: string;
  status_code: number | null;
  latency_ms: number | null;
  ok: 0 | 1;
  error: string | null;
}

export type AlertType = 'down' | 'recovered' | 'latency_anomaly';

export interface AlertRow {
  id: number;
  monitor_id: number;
  type: AlertType;
  fired_at: string;
  resolved_at: string | null;
  notified_at: string | null;
  details: string | null;
}
