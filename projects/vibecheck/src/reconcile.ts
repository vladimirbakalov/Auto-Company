// vibecheck — Stripe/D1 reconciliation safety net
//
// Backstop for critic-munger's pre-mortem finding (docs/critic/
// vibecheck-monitoring-tier-premortem.md: "reconciliation-cron webhook
// safety net"): POST /api/stripe/webhook (src/index.ts) is the only thing
// that ever creates a D1 `users` row from a Stripe payment. Stripe retries a
// failing webhook, but not forever, and a Worker bug/outage could still drop
// one — a customer who paid Stripe would then have no dashboard access
// despite being charged, and nothing in this codebase would ever notice.
//
// This job re-derives "Stripe thinks this customer has an active
// subscription" (stripe.ts's fetchActiveStripeCustomerIds) and diffs it
// against D1's view of the world (fetchKnownStripeCustomerIds below), same
// split as monitors.ts/auth.ts: pure gap-detection logic, testable without
// any network or D1, vs. a thin D1-touching wrapper around it.

// ── Pure: gap detection ──────────────────────────────────────────────────────

// Given the Stripe customer ids Stripe currently considers
// active-or-trialing, and the set of customer ids D1 already knows about,
// returns the ids present in Stripe but missing from D1 — the exact bug
// signature a dropped/failed webhook would produce. Order of the input list
// is preserved (minus duplicates, which fetchActiveStripeCustomerIds already
// dedupes); this function does no further sorting or grouping, v1 only
// needs the raw list to log.
export function findReconciliationGap(stripeActiveCustomerIds: string[], knownCustomerIds: Set<string>): string[] {
  return stripeActiveCustomerIds.filter(id => !knownCustomerIds.has(id));
}

// ── D1 wrapper ────────────────────────────────────────────────────────────────

// All non-null stripe_customer_id values currently in `users` — the D1 side
// of the diff. Follows the same raw prepare/bind/all query style as
// monitors.ts/auth.ts, no ORM.
export async function fetchKnownStripeCustomerIds(db: D1Database): Promise<Set<string>> {
  const { results } = await db
    .prepare('SELECT stripe_customer_id FROM users WHERE stripe_customer_id IS NOT NULL')
    .all<{ stripe_customer_id: string }>();
  return new Set((results ?? []).map(row => row.stripe_customer_id));
}
