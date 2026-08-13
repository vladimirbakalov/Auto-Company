// vibecheck — Stripe Checkout + webhook handling (ADR §5)
//
// Implementation note / deliberate deviation from the ADR's literal
// suggestion: the ADR recommends stripe-node v14+ with
// Stripe.createFetchHttpClient() and Stripe.createSubtleCryptoProvider() to
// avoid the SDK defaulting to Node's `http`/`crypto` modules (which don't
// exist the same way in the Workers runtime) — and flags that mismatch as a
// "fails silently in prod, passes in whatever local harness doesn't catch
// it" trap.
//
// Rather than pull in the ~1MB stripe-node dependency and its two
// Workers-specific initializers, this file hand-rolls the two things
// actually needed against Stripe's plain HTTP API:
//   1. Creating a Checkout Session is one POST to api.stripe.com with
//      form-encoded params and a Bearer token — plain `fetch`, no SDK.
//   2. Webhook signature verification is documented, stable HMAC-SHA256 over
//      `${timestamp}.${payload}` — done here with `crypto.subtle` directly,
//      which *is* the Workers/browser-native primitive, not a Node shim of
//      one. This sidesteps the exact Node-API mismatch the ADR warns about,
//      rather than working around it via the SDK's alternate initializers.
// One dependency fewer, same verification guarantee, and the whole thing is
// ~100 lines even including the DI interface below. If a future need for
// broader Stripe API surface (Billing Portal sessions, subscription reads,
// etc.) makes a hand-rolled client unwieldy, revisit stripe-node then — this
// is not a principled rejection of the SDK, just right-sized for what v1
// checkout + one webhook actually need.
//
// Both pieces are behind the StripeGateway interface so callers (and tests)
// can inject a fake implementation — no real Stripe credentials are needed
// to test the routing/upsert logic in this codebase.

export interface CreateCheckoutSessionParams {
  priceId: string;
  customerEmail?: string;
  successUrl: string;
  cancelUrl: string;
  // Round-tripped through Stripe (Checkout Session -> webhook's
  // checkout.session.completed) so the funnel gap flagged in
  // docs/product/vibecheck-monitoring-tier-spec.md §3.4 can be closed: the
  // "instant live-ping demo" step verifies a URL is live *before* checkout,
  // but without carrying that URL through Checkout itself, nothing ever
  // creates the monitor the user just paid for. Stripe's metadata map is
  // plain string->string, form-encoded as metadata[key]=value below.
  metadata?: Record<string, string> | null;
}

export interface CheckoutSession {
  id: string;
  url: string | null;
}

export interface StripeGateway {
  createCheckoutSession(params: CreateCheckoutSessionParams): Promise<CheckoutSession>;
  verifyWebhookSignature(payload: string, signatureHeader: string, nowMs?: number): Promise<boolean>;
}

const STRIPE_API = 'https://api.stripe.com/v1';
// Stripe's own default replay-protection tolerance.
const SIGNATURE_TOLERANCE_SECONDS = 300;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Constant-time hex-string compare. The two hex digests here are equal-length
// HMAC-SHA256 outputs (64 hex chars) by construction, so this never leaks
// length; a plain `===` short-circuits on the first mismatched byte, which
// hands a network-observable timing oracle to whoever is calling this
// webhook endpoint — exactly the class of bug the ADR's crypto section warns
// about getting right, even though this repo isn't otherwise exposed to
// that many bytes.
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// Pure, exported standalone so it's testable without constructing a full
// gateway or touching the network — this is the function the ADR's warning
// is actually about getting right.
export async function verifyStripeSignature(
  payload: string,
  signatureHeader: string,
  webhookSecret: string,
  nowMs: number = Date.now(),
  toleranceSeconds = SIGNATURE_TOLERANCE_SECONDS
): Promise<boolean> {
  const parts = Object.fromEntries(
    signatureHeader.split(',').map(kv => {
      const [k, v] = kv.split('=');
      return [k, v];
    })
  );
  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) return false;

  const timestampMs = Number(timestamp) * 1000;
  if (!Number.isFinite(timestampMs)) return false;
  if (Math.abs(nowMs - timestampMs) > toleranceSeconds * 1000) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(webhookSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const expected = toHex(new Uint8Array(sigBytes));
  return timingSafeEqualHex(expected, v1);
}

// `secretKey` authenticates API calls (creating Checkout Sessions);
// `webhookSecret` verifies inbound webhook signatures — two different
// Stripe-issued secrets, both required, kept as two params rather than one
// config object so a caller can't accidentally transpose them.
export function createStripeGateway(secretKey: string, webhookSecret: string): StripeGateway {
  return {
    async createCheckoutSession(params: CreateCheckoutSessionParams): Promise<CheckoutSession> {
      const body = new URLSearchParams({
        mode: 'subscription',
        'line_items[0][price]': params.priceId,
        'line_items[0][quantity]': '1',
        success_url: params.successUrl,
        cancel_url: params.cancelUrl,
      });
      if (params.customerEmail) body.set('customer_email', params.customerEmail);
      if (params.metadata) {
        for (const [key, value] of Object.entries(params.metadata)) {
          body.set(`metadata[${key}]`, value);
        }
      }

      const res = await fetch(`${STRIPE_API}/checkout/sessions`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${secretKey}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`Stripe checkout session creation failed (${res.status}): ${text}`);
      }
      const data = (await res.json()) as { id: string; url: string | null };
      return { id: data.id, url: data.url };
    },

    verifyWebhookSignature(payload: string, signatureHeader: string, nowMs?: number): Promise<boolean> {
      return verifyStripeSignature(payload, signatureHeader, webhookSecret, nowMs);
    },
  };
}

// ── Reconciliation: listing Stripe's own view of active subscriptions ──────
// Backstop for critic-munger's pre-mortem finding (docs/critic/
// vibecheck-monitoring-tier-premortem.md: "reconciliation-cron webhook
// safety net") — POST /api/stripe/webhook above is the only thing that ever
// creates a D1 `users` row from a Stripe payment. Stripe retries a failing
// webhook, but not forever, and a Worker bug/outage could still drop one:
// a customer who paid Stripe would then have no dashboard access despite
// being charged, with nothing in this codebase ever noticing. This function
// re-derives "Stripe thinks this customer should have access" so
// src/reconcile.ts can diff it against D1's view (see that file for the
// pure gap-detection logic; this file only owns the Stripe HTTP call).

interface StripeSubscriptionListItem {
  id: string;
  customer: string;
}

interface StripeSubscriptionListResponse {
  data: StripeSubscriptionListItem[];
  has_more: boolean;
}

// Deliberately NOT filtered by `created` — that's the subscription object's
// creation timestamp, not "when it last changed status." A subscription
// created days ago that only just transitioned into active/trialing (a
// delayed trial start, a 3DS payment confirmation completing hours later, a
// past_due→active recovery, a reactivation) would have an old `created` and
// silently fall outside any creation-time window forever, defeating the
// point of a safety net. Instead this walks Stripe's full current
// active/trialing list via cursor pagination (`starting_after`) every tick
// — correct over cheap, since this is the thing whose entire job is to
// catch what the primary path missed.
async function fetchStripeSubscriptionCustomerIds(secretKey: string, status: 'active' | 'trialing'): Promise<string[]> {
  const customerIds: string[] = [];
  let startingAfter: string | undefined;

  for (;;) {
    const params = new URLSearchParams({ status, limit: '100' });
    if (startingAfter) params.set('starting_after', startingAfter);

    const res = await fetch(`${STRIPE_API}/subscriptions?${params.toString()}`, {
      headers: { Authorization: `Bearer ${secretKey}` },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Stripe subscription list (status=${status}) failed (${res.status}): ${text}`);
    }
    const data = (await res.json()) as StripeSubscriptionListResponse;
    for (const sub of data.data) customerIds.push(sub.customer);

    if (!data.has_more || data.data.length === 0) break;
    startingAfter = data.data[data.data.length - 1].id;
  }

  return customerIds;
}

// Lists distinct Stripe customer ids that Stripe currently considers
// active-or-trialing, across all pages.
//
// Design choice: Stripe's `status=active` filter does NOT include
// `trialing` — they're distinct statuses in Stripe's vocabulary. Rather than
// fetch `status=all` and filter client-side over every possible Stripe
// status (past_due, canceled, incomplete, unpaid, ...), this makes two
// narrow calls — one per status this codebase actually expects to have a D1
// user row (see `narrowSubscriptionStatus` above: 'active' and 'trialing'
// both narrow to our 'active' subscription_status). Two small, explicit
// calls are easier to reason about than one broad call plus a status
// allowlist that has to be kept in sync with narrowSubscriptionStatus by
// hand.
export async function fetchActiveStripeCustomerIds(secretKey: string): Promise<string[]> {
  const [active, trialing] = await Promise.all([
    fetchStripeSubscriptionCustomerIds(secretKey, 'active'),
    fetchStripeSubscriptionCustomerIds(secretKey, 'trialing'),
  ]);
  return Array.from(new Set([...active, ...trialing]));
}

// ── Pure: webhook event routing ──────────────────────────────────────────────
// Minimal shape of the Stripe events this endpoint cares about — not the
// full Stripe.Event type (that's the SDK's job if/when we add it), just what
// routeStripeEvent needs to read. Matches Stripe's documented payload shape
// for these event types.

export interface StripeCheckoutSessionCompletedEvent {
  type: 'checkout.session.completed';
  data: {
    object: {
      customer: string | null;
      customer_email: string | null;
      customer_details?: { email: string | null } | null;
      subscription: string | null;
      // Round-tripped from CreateCheckoutSessionParams.metadata above.
      // Optional so older/hand-constructed payloads (and every existing test
      // fixture predating this field) still type-check and route correctly —
      // routeStripeEvent below must treat a missing/absent metadata map the
      // same as one with no deployed_url key.
      metadata?: Record<string, string> | null;
    };
  };
}

export interface StripeSubscriptionUpdatedEvent {
  type: 'customer.subscription.updated' | 'customer.subscription.deleted';
  data: {
    object: {
      customer: string;
      status: string; // Stripe's subscription status vocabulary
    };
  };
}

export interface StripeInvoicePaymentFailedEvent {
  type: 'invoice.payment_failed';
  data: {
    object: {
      customer: string;
    };
  };
}

export type StripeWebhookEvent =
  | StripeCheckoutSessionCompletedEvent
  | StripeSubscriptionUpdatedEvent
  | StripeInvoicePaymentFailedEvent
  | { type: string; data: { object: Record<string, unknown> } };

export type RoutedStripeAction =
  | {
      kind: 'upsert_user_from_checkout';
      email: string;
      stripeCustomerId: string;
      stripeSubscriptionId: string | null;
      // The URL verified live in the pre-checkout probe demo (spec §3.4),
      // carried through Stripe as Checkout Session metadata. null when
      // absent — either an older payload shape or a checkout started
      // without the probe step (e.g. a direct Stripe link).
      deployedUrl: string | null;
    }
  | { kind: 'update_subscription_status'; stripeCustomerId: string; status: 'active' | 'past_due' | 'canceled' }
  | { kind: 'ignored'; eventType: string };

// Stripe's own subscription-status vocabulary is wider than our three-state
// `subscription_status` column; this is the (documented, deliberate)
// narrowing per ADR §6 step 8.
function narrowSubscriptionStatus(stripeStatus: string): 'active' | 'past_due' | 'canceled' | null {
  if (stripeStatus === 'active' || stripeStatus === 'trialing') return 'active';
  if (stripeStatus === 'past_due' || stripeStatus === 'unpaid') return 'past_due';
  if (stripeStatus === 'canceled' || stripeStatus === 'incomplete_expired') return 'canceled';
  return null;
}

export function routeStripeEvent(event: StripeWebhookEvent): RoutedStripeAction {
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = (event as StripeCheckoutSessionCompletedEvent).data.object;
      const email = session.customer_email ?? session.customer_details?.email ?? null;
      if (!email || !session.customer) {
        return { kind: 'ignored', eventType: event.type };
      }
      return {
        kind: 'upsert_user_from_checkout',
        email,
        stripeCustomerId: session.customer,
        stripeSubscriptionId: session.subscription,
        deployedUrl: session.metadata?.deployed_url ?? null,
      };
    }
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const sub = (event as StripeSubscriptionUpdatedEvent).data.object;
      const status = narrowSubscriptionStatus(sub.status);
      if (!status) return { kind: 'ignored', eventType: event.type };
      return { kind: 'update_subscription_status', stripeCustomerId: sub.customer, status };
    }
    case 'invoice.payment_failed': {
      const invoice = (event as StripeInvoicePaymentFailedEvent).data.object;
      return { kind: 'update_subscription_status', stripeCustomerId: invoice.customer, status: 'past_due' };
    }
    default:
      return { kind: 'ignored', eventType: event.type };
  }
}
