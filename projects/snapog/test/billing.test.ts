// Route-level tests for the Stripe billing wiring, mirroring the FakeD1
// pattern in test/index.test.ts (prepare(sql) branches on SQL text against
// a small in-memory stand-in, no real D1). No network calls are made —
// webhook payloads are hand-crafted JSON, signed locally via Stripe's own
// `generateTestHeaderStringAsync` helper against the same webhook secret
// the route verifies against, so signature verification is exercised for
// real without ever hitting Stripe's API.

import { describe, it, expect, beforeEach } from 'vitest';
import Stripe from 'stripe';
import type { Env, Tier } from '../src/types';
import { TIER_LIMITS } from '../src/types';
import app from '../src/index';

const WEBHOOK_SECRET = 'whsec_test_secret';

interface ApiKeyRow {
  id: string;
  user_id: string;
  tier: Tier;
  monthly_limit: number;
  stripe_subscription_id: string | null;
  stripe_subscription_status: string | null;
  key_hash?: string;
}

interface UserRow {
  id: string;
  email: string;
  stripe_customer_id: string | null;
}

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Minimal, stateful in-memory D1 stand-in covering only the SQL the billing
// webhook handler (src/billing/routes.ts) actually issues.
class FakeD1 {
  apiKeys = new Map<string, ApiKeyRow>();
  users = new Map<string, UserRow>();

  prepare(sql: string) {
    const self = this;
    return {
      bind(...args: unknown[]) {
        return {
          async first<T>(): Promise<T | null> {
            if (sql.includes('SELECT user_id FROM api_keys WHERE id')) {
              const [id] = args as [string];
              const row = self.apiKeys.get(id);
              return (row ? { user_id: row.user_id } : null) as unknown as T;
            }
            if (sql.includes('SELECT id FROM api_keys WHERE stripe_subscription_id')) {
              const [subId] = args as [string];
              const row = [...self.apiKeys.values()].find(k => k.stripe_subscription_id === subId);
              return (row ? { id: row.id } : null) as unknown as T;
            }
            // resolveApiKeyWithUser's JOIN, used by both POST /billing/checkout
            // and GET /billing/portal to resolve+authenticate the raw key.
            if (sql.includes('api_keys.key_hash = ?')) {
              const [hash] = args as [string];
              const row = [...self.apiKeys.values()].find(k => k.key_hash === hash);
              if (!row) return null;
              const user = self.users.get(row.user_id);
              return {
                ...row,
                user_email: user?.email ?? '',
                stripe_customer_id: user?.stripe_customer_id ?? null,
              } as unknown as T;
            }
            return null;
          },
          async run() {
            if (sql.includes('UPDATE users SET stripe_customer_id')) {
              const [customerId, userId] = args as [string, string];
              const u = self.users.get(userId);
              if (u) u.stripe_customer_id = customerId;
            } else if (
              sql.includes('UPDATE api_keys') &&
              sql.includes('stripe_subscription_id = ?') &&
              sql.includes("stripe_subscription_status = 'active'")
            ) {
              // checkout.session.completed upgrade path
              const [tier, monthlyLimit, subscriptionId, id] = args as [Tier, number, string | null, string];
              const k = self.apiKeys.get(id);
              if (k) {
                k.tier = tier;
                k.monthly_limit = monthlyLimit;
                k.stripe_subscription_id = subscriptionId;
                k.stripe_subscription_status = 'active';
              }
            } else if (sql.includes("SET tier = 'free'")) {
              // customer.subscription.deleted downgrade path
              const [monthlyLimit, id] = args as [number, string];
              const k = self.apiKeys.get(id);
              if (k) {
                k.tier = 'free';
                k.monthly_limit = monthlyLimit;
                k.stripe_subscription_status = 'canceled';
              }
            } else if (
              sql.includes('UPDATE api_keys') &&
              sql.includes('SET tier = ?, monthly_limit = ?, stripe_subscription_status = ?')
            ) {
              // customer.subscription.updated tier-changing path
              const [tier, monthlyLimit, status, id] = args as [Tier, number, string, string];
              const k = self.apiKeys.get(id);
              if (k) {
                k.tier = tier;
                k.monthly_limit = monthlyLimit;
                k.stripe_subscription_status = status;
              }
            } else if (sql.includes('UPDATE api_keys SET stripe_subscription_status = ? WHERE id')) {
              // customer.subscription.updated status-only path (e.g. past_due)
              const [status, id] = args as [string, string];
              const k = self.apiKeys.get(id);
              if (k) k.stripe_subscription_status = status;
            }
            return { success: true };
          },
        };
      },
    };
  }
}

function baseEnv(db: FakeD1): Env {
  return {
    DB: db as unknown as Env['DB'],
    ENVIRONMENT: 'test',
    STRIPE_SECRET_KEY: 'sk_test_fake',
    STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET,
    STRIPE_PRICE_ID_PRO: 'price_pro_test',
    STRIPE_PRICE_ID_BUSINESS: 'price_business_test',
  } as Env;
}

// Used purely to sign test payloads locally — never makes a network call.
const signingStripe = new Stripe('sk_test_fake', { httpClient: Stripe.createFetchHttpClient() });

async function signedWebhookRequest(payload: string, secret = WEBHOOK_SECRET) {
  const signature = await signingStripe.webhooks.generateTestHeaderStringAsync({ payload, secret });
  return { signature, payload };
}

describe('POST /billing/webhook', () => {
  let db: FakeD1;
  let env: Env;

  beforeEach(() => {
    db = new FakeD1();
    env = baseEnv(db);
  });

  it('rejects a webhook whose signature does not match the configured secret', async () => {
    const payload = JSON.stringify({
      id: 'evt_bad_sig',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_x', metadata: {} } },
    });
    // Signed with a different secret than the one env.STRIPE_WEBHOOK_SECRET
    // holds — this is what an attacker (or a misconfigured client) posting
    // an unsigned/mis-signed payload looks like.
    const { signature } = await signedWebhookRequest(payload, 'whsec_wrong_secret');

    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
      env
    );
    expect(res.status).toBe(400);
  });

  it('rejects a webhook with a missing stripe-signature header', async () => {
    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', body: JSON.stringify({ type: 'checkout.session.completed' }) },
      env
    );
    expect(res.status).toBe(400);
  });

  it('returns 503 instead of crashing when Stripe secrets are not configured', async () => {
    const unconfiguredEnv = { DB: db as unknown as Env['DB'], ENVIRONMENT: 'test' } as Env;
    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': 'irrelevant' }, body: '{}' },
      unconfiguredEnv
    );
    expect(res.status).toBe(503);
  });

  it('upgrades a key to "pro" and records the subscription on checkout.session.completed', async () => {
    db.users.set('user_1', { id: 'user_1', email: 'dev@example.com', stripe_customer_id: null });
    db.apiKeys.set('key_1', {
      id: 'key_1',
      user_id: 'user_1',
      tier: 'free',
      monthly_limit: TIER_LIMITS.free,
      stripe_subscription_id: null,
      stripe_subscription_status: null,
    });

    const payload = JSON.stringify({
      id: 'evt_checkout_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_1',
          object: 'checkout.session',
          customer: 'cus_test_1',
          subscription: 'sub_test_1',
          metadata: { api_key_id: 'key_1', tier: 'pro' },
        },
      },
    });
    const { signature } = await signedWebhookRequest(payload);

    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
      env
    );

    expect(res.status).toBe(200);
    const key = db.apiKeys.get('key_1')!;
    expect(key.tier).toBe('pro');
    expect(key.monthly_limit).toBe(TIER_LIMITS.pro);
    expect(key.stripe_subscription_id).toBe('sub_test_1');
    expect(key.stripe_subscription_status).toBe('active');
    expect(db.users.get('user_1')!.stripe_customer_id).toBe('cus_test_1');
  });

  it('tolerates a duplicate (replayed) checkout.session.completed for the same session without double-provisioning or erroring', async () => {
    // Stripe retries webhook deliveries (e.g. if our endpoint is briefly
    // unreachable or answers slowly) and explicitly documents that
    // handlers must be idempotent. This locks in that the handler's writes
    // are plain SETs keyed by api_key_id/tier — never increments — so
    // replaying the exact same event twice converges to the same state
    // instead of erroring or drifting (e.g. double-billing side effects,
    // clobbering a later legitimate upgrade).
    db.users.set('user_1', { id: 'user_1', email: 'dev@example.com', stripe_customer_id: null });
    db.apiKeys.set('key_1', {
      id: 'key_1',
      user_id: 'user_1',
      tier: 'free',
      monthly_limit: TIER_LIMITS.free,
      stripe_subscription_id: null,
      stripe_subscription_status: null,
    });

    const payload = JSON.stringify({
      id: 'evt_checkout_replay',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_replay',
          object: 'checkout.session',
          customer: 'cus_test_replay',
          subscription: 'sub_test_replay',
          metadata: { api_key_id: 'key_1', tier: 'pro' },
        },
      },
    });
    const { signature } = await signedWebhookRequest(payload);

    for (let i = 0; i < 2; i++) {
      const res = await app.request(
        '/billing/webhook',
        { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
        env
      );
      expect(res.status).toBe(200);
    }

    const key = db.apiKeys.get('key_1')!;
    expect(key.tier).toBe('pro');
    expect(key.monthly_limit).toBe(TIER_LIMITS.pro);
    expect(key.stripe_subscription_id).toBe('sub_test_replay');
    expect(key.stripe_subscription_status).toBe('active');
  });

  it('ignores a checkout.session.completed event with no recognized tier in metadata', async () => {
    db.apiKeys.set('key_2', {
      id: 'key_2',
      user_id: 'user_1',
      tier: 'free',
      monthly_limit: TIER_LIMITS.free,
      stripe_subscription_id: null,
      stripe_subscription_status: null,
    });
    const payload = JSON.stringify({
      id: 'evt_checkout_bad',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_x', metadata: { api_key_id: 'key_2', tier: 'enterprise' } } },
    });
    const { signature } = await signedWebhookRequest(payload);

    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
      env
    );
    expect(res.status).toBe(200);
    expect(db.apiKeys.get('key_2')!.tier).toBe('free'); // untouched
  });

  it('downgrades a canceled subscription back to free on customer.subscription.deleted', async () => {
    db.apiKeys.set('key_3', {
      id: 'key_3',
      user_id: 'user_1',
      tier: 'business',
      monthly_limit: TIER_LIMITS.business,
      stripe_subscription_id: 'sub_test_3',
      stripe_subscription_status: 'active',
    });

    const payload = JSON.stringify({
      id: 'evt_deleted_1',
      type: 'customer.subscription.deleted',
      data: {
        object: {
          id: 'sub_test_3',
          object: 'subscription',
          status: 'canceled',
          metadata: {},
          items: { data: [] },
        },
      },
    });
    const { signature } = await signedWebhookRequest(payload);

    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
      env
    );

    expect(res.status).toBe(200);
    const key = db.apiKeys.get('key_3')!;
    expect(key.tier).toBe('free');
    expect(key.monthly_limit).toBe(TIER_LIMITS.free);
    expect(key.stripe_subscription_status).toBe('canceled');
  });

  it('moves the tier on customer.subscription.updated when the plan changed (e.g. Pro -> Business)', async () => {
    db.apiKeys.set('key_4', {
      id: 'key_4',
      user_id: 'user_1',
      tier: 'pro',
      monthly_limit: TIER_LIMITS.pro,
      stripe_subscription_id: 'sub_test_4',
      stripe_subscription_status: 'active',
    });

    const payload = JSON.stringify({
      id: 'evt_updated_upgrade',
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_test_4',
          object: 'subscription',
          status: 'active',
          metadata: { api_key_id: 'key_4' },
          items: { data: [{ price: { id: 'price_business_test' } }] },
        },
      },
    });
    const { signature } = await signedWebhookRequest(payload);

    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
      env
    );

    expect(res.status).toBe(200);
    const key = db.apiKeys.get('key_4')!;
    expect(key.tier).toBe('business');
    expect(key.monthly_limit).toBe(TIER_LIMITS.business);
    expect(key.stripe_subscription_status).toBe('active');
  });

  it('records a past_due status without touching the tier on customer.subscription.updated', async () => {
    // Dunning: a failed payment retry moves the subscription into 'past_due'
    // without Stripe reporting a price change. The key must keep its current
    // tier through the grace period — only customer.subscription.deleted
    // (tested above) downgrades to free.
    db.apiKeys.set('key_5', {
      id: 'key_5',
      user_id: 'user_1',
      tier: 'business',
      monthly_limit: TIER_LIMITS.business,
      stripe_subscription_id: 'sub_test_5',
      stripe_subscription_status: 'active',
    });

    const payload = JSON.stringify({
      id: 'evt_updated_past_due',
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_test_5',
          object: 'subscription',
          status: 'past_due',
          metadata: { api_key_id: 'key_5' },
          items: { data: [{ price: { id: 'price_business_test' } }] },
        },
      },
    });
    const { signature } = await signedWebhookRequest(payload);

    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
      env
    );

    expect(res.status).toBe(200);
    const key = db.apiKeys.get('key_5')!;
    expect(key.tier).toBe('business'); // untouched through the grace period
    expect(key.monthly_limit).toBe(TIER_LIMITS.business); // untouched
    expect(key.stripe_subscription_status).toBe('past_due');
  });

  it('resolves the api_key_id via stripe_subscription_id when subscription metadata is absent', async () => {
    // Fallback path in resolveApiKeyIdForSubscription: an event for this
    // subscription can in principle be processed before
    // checkout.session.completed ever wrote metadata onto it.
    db.apiKeys.set('key_6', {
      id: 'key_6',
      user_id: 'user_1',
      tier: 'pro',
      monthly_limit: TIER_LIMITS.pro,
      stripe_subscription_id: 'sub_test_6',
      stripe_subscription_status: 'active',
    });

    const payload = JSON.stringify({
      id: 'evt_updated_no_metadata',
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_test_6',
          object: 'subscription',
          status: 'active',
          metadata: {},
          items: { data: [{ price: { id: 'price_business_test' } }] },
        },
      },
    });
    const { signature } = await signedWebhookRequest(payload);

    const res = await app.request(
      '/billing/webhook',
      { method: 'POST', headers: { 'stripe-signature': signature }, body: payload },
      env
    );

    expect(res.status).toBe(200);
    expect(db.apiKeys.get('key_6')!.tier).toBe('business');
  });
});

describe('POST /billing/checkout', () => {
  it('returns 503 instead of throwing when STRIPE_SECRET_KEY is not set', async () => {
    const db = new FakeD1();
    const unconfiguredEnv = { DB: db as unknown as Env['DB'], ENVIRONMENT: 'test' } as Env;

    const res = await app.request(
      '/billing/checkout',
      { method: 'POST', body: new URLSearchParams({ key: 'sk_whatever', tier: 'pro' }) },
      unconfiguredEnv
    );
    expect(res.status).toBe(503);
  });

  it('rejects a tier that is not "pro" or "business"', async () => {
    const db = new FakeD1();
    const env = baseEnv(db);
    const res = await app.request(
      '/billing/checkout',
      { method: 'POST', body: new URLSearchParams({ key: 'sk_whatever', tier: 'free' }) },
      env
    );
    expect(res.status).toBe(400);
  });
});

describe('GET /billing/portal', () => {
  it('returns 503 instead of throwing when STRIPE_SECRET_KEY is not set', async () => {
    const db = new FakeD1();
    const unconfiguredEnv = { DB: db as unknown as Env['DB'], ENVIRONMENT: 'test' } as Env;
    const res = await app.request('/billing/portal?key=sk_whatever', {}, unconfiguredEnv);
    expect(res.status).toBe(503);
  });

  it('rejects a request with no key at all', async () => {
    const db = new FakeD1();
    const env = baseEnv(db);
    const res = await app.request('/billing/portal', {}, env);
    expect(res.status).toBe(400);
  });

  it('rejects an API key that does not resolve to any user', async () => {
    const db = new FakeD1();
    const env = baseEnv(db);
    const res = await app.request('/billing/portal?key=sk_does_not_exist', {}, env);
    expect(res.status).toBe(401);
  });

  it('returns 404 when the key resolves but has no Stripe customer on file yet (never subscribed)', async () => {
    const db = new FakeD1();
    const env = baseEnv(db);
    const rawKey = 'sk_live_key_no_billing';
    const hash = await sha256(rawKey);
    db.users.set('user_1', { id: 'user_1', email: 'dev@example.com', stripe_customer_id: null });
    db.apiKeys.set('key_7', {
      id: 'key_7',
      user_id: 'user_1',
      tier: 'free',
      monthly_limit: TIER_LIMITS.free,
      stripe_subscription_id: null,
      stripe_subscription_status: null,
      key_hash: hash,
    });

    const res = await app.request(`/billing/portal?key=${rawKey}`, {}, env);
    expect(res.status).toBe(404);
  });
});
