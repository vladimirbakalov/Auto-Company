// Same route/helper-level coverage the mock-based suites already have (see
// test/auth.test.ts, test/monitors.test.ts, test/index.test.ts), but running
// inside real workerd (via @cloudflare/vitest-pool-workers) against a real
// local D1 instance with the actual migrations/0001_init.sql +
// 0002_dashboard.sql applied, and a real KV binding — not hand-rolled mocks.
//
// This exists specifically to close the gap src/auth.ts flags at its own
// top: upsertUserFromCheckout and generateAndStoreApiKey are marked STUB
// there because they were "not integration-tested against live D1 ... no
// miniflare/D1 simulation wired into vitest" at the time they were written.
// That harness now exists (see vitest.workers.config.mts, copied from the
// proven pattern in projects/snapog). Run via `npm run test:workers`; kept
// separate from the default `npm test` suite so day-to-day runs stay
// workerd-free and fast.
import { env, exports } from 'cloudflare:workers';
import { describe, it, expect } from 'vitest';
import {
  upsertUserFromCheckout,
  generateAndStoreApiKey,
  findUserByApiKey,
  createMagicLink,
  validateAndConsumeMagicLink,
  signSession,
} from '../src/auth';
import { insertMonitor } from '../src/monitors';
import type { UserRow } from '../src/types';

const SELF = exports.default;

describe('vibecheck auth helpers (real D1 via workerd)', () => {
  it('upsertUserFromCheckout: real UNIQUE(email) constraint drives insert-then-update, not a duplicate row', async () => {
    const email = `dup-${crypto.randomUUID()}@example.com`;

    const first = await upsertUserFromCheckout(env.DB!, {
      email,
      stripeCustomerId: 'cus_first',
      stripeSubscriptionId: 'sub_first',
    });
    expect(first.subscription_status).toBe('active');

    // Second checkout for the same email (e.g. resubscribe with a new Stripe
    // customer) must hit ON CONFLICT(email) DO UPDATE, not violate the real
    // UNIQUE constraint or insert a second row.
    const second = await upsertUserFromCheckout(env.DB!, {
      email,
      stripeCustomerId: 'cus_second',
      stripeSubscriptionId: 'sub_second',
    });
    expect(second.id).toBe(first.id);
    expect(second.stripe_customer_id).toBe('cus_second');

    const { results } = await env.DB!.prepare('SELECT id FROM users WHERE email = ?1').bind(email).all();
    expect(results.length).toBe(1); // real UNIQUE constraint held, upsert not duplicate-insert
  });

  it('generateAndStoreApiKey + findUserByApiKey round-trip through real hashed lookup, replacing any previous key', async () => {
    const user = await upsertUserFromCheckout(env.DB!, {
      email: `key-${crypto.randomUUID()}@example.com`,
      stripeCustomerId: 'cus_key',
      stripeSubscriptionId: null,
    });

    const firstKey = await generateAndStoreApiKey(env.DB!, user.id);
    const foundFirst = await findUserByApiKey(env.DB!, firstKey);
    expect(foundFirst?.id).toBe(user.id);

    // Regenerating replaces the stored hash (single key per user, per ADR §5)
    // — the old raw key must no longer resolve against real D1.
    const secondKey = await generateAndStoreApiKey(env.DB!, user.id);
    expect(secondKey).not.toBe(firstKey);
    expect(await findUserByApiKey(env.DB!, firstKey)).toBeNull();
    expect((await findUserByApiKey(env.DB!, secondKey))?.id).toBe(user.id);
  });

  it('createMagicLink + validateAndConsumeMagicLink: real FK to users, single-use enforced by D1 state', async () => {
    const user = await upsertUserFromCheckout(env.DB!, {
      email: `magic-${crypto.randomUUID()}@example.com`,
      stripeCustomerId: 'cus_magic',
      stripeSubscriptionId: null,
    });

    const { token } = await createMagicLink(env.DB!, user.id);

    const consumedUserId = await validateAndConsumeMagicLink(env.DB!, token);
    expect(consumedUserId).toBe(user.id);

    // Second consumption of the same token must fail — real used_at column
    // state, not a mock's in-memory assumption about single-use.
    const reconsumed = await validateAndConsumeMagicLink(env.DB!, token);
    expect(reconsumed).toBeNull();
  });
});

describe('vibecheck routes (real D1 + KV via workerd)', () => {
  it('GET /health returns ok', async () => {
    const res = await SELF.fetch('https://vibecheck.test/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true });
  });

  it('round-trips a waitlist signup through the real WAITLIST KV binding', async () => {
    const email = `wait-${crypto.randomUUID()}@example.com`;
    const res = await SELF.fetch('https://vibecheck.test/api/waitlist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, repoUrl: 'https://github.com/example/repo' }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, stored: true });

    const stored = await env.WAITLIST!.get(`waitlist:${email}`);
    expect(stored).not.toBeNull();
    expect(JSON.parse(stored!).repoUrl).toBe('https://github.com/example/repo');
  });

  it('POST /api/monitors creates a real D1 row (session-cookie auth) honoring the FK to users and default interval', async () => {
    const user = await upsertUserFromCheckout(env.DB!, {
      email: `monitor-${crypto.randomUUID()}@example.com`,
      stripeCustomerId: 'cus_monitor',
      stripeSubscriptionId: null,
    });
    const sessionValue = await signSession({ userId: user.id, expiresAtMs: Date.now() + 60_000 }, 'test-session-secret');

    const res = await SELF.fetch('https://vibecheck.test/api/monitors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `vc_session=${sessionValue}` },
      body: JSON.stringify({ url: 'https://example.com' }),
    });
    expect(res.status).toBe(201);
    const { monitor } = await res.json<{ monitor: { user_id: number; interval_seconds: number } }>();
    expect(monitor.user_id).toBe(user.id);
    expect(monitor.interval_seconds).toBe(300); // real column DEFAULT, not a mock's assumption

    const { results } = await env.DB!.prepare('SELECT * FROM monitors WHERE user_id = ?1').bind(user.id).all();
    expect(results.length).toBe(1);
  });

  it('insertMonitor rejects a user_id with no matching row — real FK reference, not a mock that would silently accept it', async () => {
    await expect(insertMonitor(env.DB!, { userId: 999_999_999, url: 'https://example.com' })).rejects.toThrow();
  });
});
