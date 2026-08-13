// SnapOG — Billing routes: Stripe Checkout, webhook, customer portal.
//
// This file is the ONLY code path allowed to write a `tier`/`monthly_limit`
// above 'free' to the database. POST /register (see ../index.ts) only ever
// creates free-tier keys now — a client can no longer self-grant a paid
// tier by POSTing `tier=pro` to a form field. Every upgrade here traces
// back to a Stripe webhook event whose signature was verified against
// STRIPE_WEBHOOK_SECRET.

import { Hono } from 'hono';
import type Stripe from 'stripe';
import type { ApiKey, Env } from '../types';
import { TIER_LIMITS } from '../types';
import { getStripe, isPaidTier, priceIdForTier, tierForPriceId, verifyWebhook } from './stripe';

export const billingRoutes = new Hono<{ Bindings: Env }>();

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

interface ApiKeyWithUser extends ApiKey {
  user_email: string;
  stripe_customer_id: string | null;
}

async function resolveApiKeyWithUser(db: D1Database, rawKey: string): Promise<ApiKeyWithUser | null> {
  const hash = await sha256(rawKey);
  const row = await db
    .prepare(
      `SELECT api_keys.*, users.email AS user_email, users.stripe_customer_id AS stripe_customer_id
         FROM api_keys
         JOIN users ON users.id = api_keys.user_id
        WHERE api_keys.key_hash = ?`
    )
    .bind(hash)
    .first<ApiKeyWithUser>();
  return row ?? null;
}

// Subscription events carry the api_key_id in their own metadata (set at
// checkout time via subscription_data.metadata below), which survives
// Stripe-side plan switches. Falls back to matching on the
// stripe_subscription_id we stored during checkout.session.completed, in
// case an event for this subscription is ever processed before that one.
async function resolveApiKeyIdForSubscription(
  db: D1Database,
  subscription: Stripe.Subscription
): Promise<string | null> {
  const metaId = subscription.metadata?.api_key_id;
  if (metaId) return metaId;

  const row = await db
    .prepare('SELECT id FROM api_keys WHERE stripe_subscription_id = ?')
    .bind(subscription.id)
    .first<{ id: string }>();
  return row?.id ?? null;
}

// ── POST /billing/checkout ──────────────────────────────────────────────
// Body: key=<raw API key>, tier=pro|business
// Creates a Stripe Checkout Session (subscription mode, test-mode keys
// until a human sets real ones) and redirects the browser to Stripe's
// hosted checkout page. Nothing is written to `tier` here — only the
// webhook below does that, once Stripe confirms the subscription.
billingRoutes.post('/checkout', async c => {
  const stripe = getStripe(c.env);
  if (!stripe) {
    return c.json({ error: 'Billing is not configured yet. Try again soon.' }, 503);
  }

  let rawKey: string;
  let tier: string;
  try {
    const form = await c.req.formData();
    rawKey = ((form.get('key') as string) ?? '').trim();
    tier = ((form.get('tier') as string) ?? '').trim();
  } catch {
    return c.json({ error: 'Invalid form data' }, 400);
  }

  if (!rawKey) return c.json({ error: 'key is required' }, 400);
  if (!isPaidTier(tier)) return c.json({ error: 'tier must be "pro" or "business"' }, 400);

  const priceId = priceIdForTier(c.env, tier);
  if (!priceId) {
    return c.json({ error: `Billing is not configured for the ${tier} tier yet` }, 503);
  }

  const apiKey = await resolveApiKeyWithUser(c.env.DB, rawKey);
  if (!apiKey) return c.json({ error: 'Invalid API key' }, 401);

  const origin = new URL(c.req.url).origin;

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price: priceId, quantity: 1 }],
    ...(apiKey.stripe_customer_id
      ? { customer: apiKey.stripe_customer_id }
      : { customer_email: apiKey.user_email }),
    success_url: `${origin}/dashboard?key=${encodeURIComponent(rawKey)}&checkout=success`,
    cancel_url: `${origin}/dashboard?key=${encodeURIComponent(rawKey)}&checkout=cancelled`,
    // Both session and subscription metadata carry api_key_id/tier: the
    // session's copy is read by checkout.session.completed, the
    // subscription's copy is read by later subscription.* events (see
    // resolveApiKeyIdForSubscription above).
    metadata: { api_key_id: apiKey.id, tier },
    subscription_data: { metadata: { api_key_id: apiKey.id, tier } },
  });

  if (!session.url) {
    return c.json({ error: 'Could not create checkout session' }, 502);
  }

  return c.redirect(session.url, 303);
});

// ── GET /billing/portal ─────────────────────────────────────────────────
// ?key=<raw API key> — redirects to Stripe's self-serve customer portal
// (plan changes, cancellation, invoices/receipts).
billingRoutes.get('/portal', async c => {
  const stripe = getStripe(c.env);
  if (!stripe) {
    return c.json({ error: 'Billing is not configured yet.' }, 503);
  }

  const rawKey = c.req.query('key');
  if (!rawKey) return c.json({ error: 'key is required' }, 400);

  const apiKey = await resolveApiKeyWithUser(c.env.DB, rawKey);
  if (!apiKey) return c.json({ error: 'Invalid API key' }, 401);
  if (!apiKey.stripe_customer_id) {
    return c.json({ error: 'No billing account on file yet — subscribe to Pro or Business first' }, 404);
  }

  const origin = new URL(c.req.url).origin;
  const portalSession = await stripe.billingPortal.sessions.create({
    customer: apiKey.stripe_customer_id,
    return_url: `${origin}/dashboard?key=${encodeURIComponent(rawKey)}`,
  });

  return c.redirect(portalSession.url, 303);
});

// ── POST /billing/webhook ───────────────────────────────────────────────
// The single source of truth for tier upgrades/downgrades. Verifies the
// Stripe-Signature header before touching the database at all.
billingRoutes.post('/webhook', async c => {
  const stripe = getStripe(c.env);
  const webhookSecret = c.env.STRIPE_WEBHOOK_SECRET;
  if (!stripe || !webhookSecret) {
    return c.json({ error: 'Billing is not configured yet.' }, 503);
  }

  const signature = c.req.header('stripe-signature');
  const body = await c.req.text();
  if (!signature) return c.json({ error: 'Missing stripe-signature header' }, 400);

  let event: Stripe.Event;
  try {
    event = await verifyWebhook(stripe, body, signature, webhookSecret);
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err);
    return c.json({ error: 'Invalid signature' }, 400);
  }

  const db = c.env.DB;

  switch (event.type) {
    // Fired once the customer completes Stripe Checkout. This is the only
    // place a key's tier ever moves above 'free'.
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      const apiKeyId = session.metadata?.api_key_id;
      const tier = session.metadata?.tier;
      if (!apiKeyId || !tier || !isPaidTier(tier)) break;

      const customerId = typeof session.customer === 'string' ? session.customer : session.customer?.id;
      const subscriptionId =
        typeof session.subscription === 'string' ? session.subscription : session.subscription?.id;

      const key = await db
        .prepare('SELECT user_id FROM api_keys WHERE id = ?')
        .bind(apiKeyId)
        .first<{ user_id: string }>();
      if (!key) break; // key was deleted between checkout start and completion — nothing to upgrade

      if (customerId) {
        await db
          .prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?')
          .bind(customerId, key.user_id)
          .run();
      }

      await db
        .prepare(
          `UPDATE api_keys
              SET tier = ?, monthly_limit = ?, stripe_subscription_id = ?, stripe_subscription_status = 'active'
            WHERE id = ?`
        )
        .bind(tier, TIER_LIMITS[tier], subscriptionId ?? null, apiKeyId)
        .run();
      break;
    }

    // Fired on plan changes (upgrade/downgrade between Pro/Business) and
    // status transitions (e.g. into 'past_due' during dunning). Only
    // 'active'/'trialing' move the tier — a lapsed-payment key keeps its
    // current tier (with its status recorded) rather than being silently
    // downgraded mid-grace-period; true cancellation is handled by
    // customer.subscription.deleted below.
    case 'customer.subscription.updated': {
      const subscription = event.data.object as Stripe.Subscription;
      const apiKeyId = await resolveApiKeyIdForSubscription(db, subscription);
      if (!apiKeyId) break;

      const priceId = subscription.items.data[0]?.price?.id;
      const tier = tierForPriceId(c.env, priceId);
      const status = subscription.status;

      if (tier && (status === 'active' || status === 'trialing')) {
        await db
          .prepare(
            `UPDATE api_keys
                SET tier = ?, monthly_limit = ?, stripe_subscription_status = ?
              WHERE id = ?`
          )
          .bind(tier, TIER_LIMITS[tier], status, apiKeyId)
          .run();
      } else {
        await db
          .prepare('UPDATE api_keys SET stripe_subscription_status = ? WHERE id = ?')
          .bind(status, apiKeyId)
          .run();
      }
      break;
    }

    // Subscription fully ended (cancellation took effect, or payment
    // retries exhausted) — downgrade back to free.
    case 'customer.subscription.deleted': {
      const subscription = event.data.object as Stripe.Subscription;
      const apiKeyId = await resolveApiKeyIdForSubscription(db, subscription);
      if (!apiKeyId) break;

      await db
        .prepare(
          `UPDATE api_keys
              SET tier = 'free', monthly_limit = ?, stripe_subscription_status = 'canceled'
            WHERE id = ?`
        )
        .bind(TIER_LIMITS.free, apiKeyId)
        .run();
      break;
    }

    default:
      break; // event type we don't act on — acknowledge and move on
  }

  return c.json({ received: true });
});
