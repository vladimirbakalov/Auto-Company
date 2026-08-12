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
  return expected === v1;
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
  | { kind: 'upsert_user_from_checkout'; email: string; stripeCustomerId: string; stripeSubscriptionId: string | null }
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
