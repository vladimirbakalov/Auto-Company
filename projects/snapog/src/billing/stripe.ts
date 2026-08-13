// SnapOG — Stripe client + tier/price mapping helpers
//
// Runs on Cloudflare Workers, so this deliberately avoids the Stripe SDK's
// default (Node-targeted) transport: `Stripe.createFetchHttpClient()` is
// the fetch()-based HTTP client that actually works in the Workers runtime.
// Webhook signature verification uses the SubtleCrypto-based async path
// (`constructEventAsync` + `Stripe.createSubtleCryptoProvider()`) since
// Workers has no `node:crypto` module for the SDK's default sync verifier
// to fall back on. Both are made explicit here rather than relying on the
// SDK's platform auto-detection, so this also behaves correctly under
// plain (non-workerd) vitest, which the SDK would otherwise treat as Node.

import Stripe from 'stripe';
import type { Env, Tier } from '../types';

export type PaidTier = Exclude<Tier, 'free'>;

export function isPaidTier(value: string): value is PaidTier {
  return value === 'pro' || value === 'business';
}

// Lazily constructs a Stripe client, or null if STRIPE_SECRET_KEY isn't
// configured yet (e.g. a --temporary deploy before a human has set the
// secret, or this repo before a Stripe account exists at all). Callers
// must treat null as "billing not configured" and respond with a 503 —
// never throw.
export function getStripe(env: Env): Stripe | null {
  if (!env.STRIPE_SECRET_KEY) return null;
  return new Stripe(env.STRIPE_SECRET_KEY, {
    httpClient: Stripe.createFetchHttpClient(),
  });
}

// Maps a configured Stripe Price ID (as seen on a Checkout Session or
// Subscription line item) back to the SnapOG tier it represents. Returns
// null for an unrecognized price (e.g. price env vars not yet set, or a
// price from an unrelated product).
export function tierForPriceId(env: Env, priceId: string | null | undefined): PaidTier | null {
  if (!priceId) return null;
  if (env.STRIPE_PRICE_ID_PRO && priceId === env.STRIPE_PRICE_ID_PRO) return 'pro';
  if (env.STRIPE_PRICE_ID_BUSINESS && priceId === env.STRIPE_PRICE_ID_BUSINESS) return 'business';
  return null;
}

export function priceIdForTier(env: Env, tier: PaidTier): string | null {
  return (tier === 'pro' ? env.STRIPE_PRICE_ID_PRO : env.STRIPE_PRICE_ID_BUSINESS) ?? null;
}

// Verifies a raw webhook body against the configured signing secret. Must
// be the async variant — see the module comment above.
export async function verifyWebhook(
  stripe: Stripe,
  body: string,
  signature: string,
  secret: string
): Promise<Stripe.Event> {
  return stripe.webhooks.constructEventAsync(
    body,
    signature,
    secret,
    undefined,
    Stripe.createSubtleCryptoProvider()
  );
}
