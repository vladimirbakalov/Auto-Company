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

// Cycle #126 analytics: closes the same "does the real migration/schema
// actually work, not just the hand-rolled mocks" gap the rest of this file
// closes for auth/monitors — migrations/0003_events.sql's `events` table,
// GET / writing to it, and GET /admin/stats reading real COUNT(*)
// aggregates back out.
describe('vibecheck analytics (Cycle #126, real D1 via workerd)', () => {
  it('GET / writes a real landing_pageview row to the events table', async () => {
    const res = await SELF.fetch('https://vibecheck.test/');
    expect(res.status).toBe(200);

    const { results } = await env
      .DB!.prepare("SELECT event_type, path FROM events WHERE event_type = 'landing_pageview'")
      .all<{ event_type: string; path: string | null }>();
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0]).toEqual({ event_type: 'landing_pageview', path: '/' });
  });

  it('GET /admin/stats: wrong key -> 401, correct key -> 200 with real events-table counts', async () => {
    // ADMIN_STATS_KEY IS bound in this test env (vitest.workers.config.mts) —
    // the "not configured -> 503" state is covered against a mocked env in
    // test/index.test.ts, since this suite's env always has it bound.
    const wrongKey = await SELF.fetch('https://vibecheck.test/admin/stats', {
      headers: { Authorization: 'Bearer not-the-real-key' },
    });
    expect(wrongKey.status).toBe(401);

    // Seed a couple of real rows directly, same shape recordEvent() would insert.
    await env.DB!.prepare("INSERT INTO events (event_type, path) VALUES ('scan_submitted', '/api/scan')").run();
    await env.DB!.prepare("INSERT INTO events (event_type, path) VALUES ('scan_submitted', '/api/scan')").run();

    const res = await SELF.fetch('https://vibecheck.test/admin/stats', {
      headers: { Authorization: 'Bearer test-admin-stats-key' },
    });
    expect(res.status).toBe(200);
    const stats = await res.json<{ scansSubmitted: { last24h: number } }>();
    expect(stats.scansSubmitted.last24h).toBeGreaterThanOrEqual(2);
  });

  // Regression test for a real bug caught in QA review (Cycle #126): an
  // earlier version of countEventsInWindow (src/events.ts) computed each
  // window's cutoff in JS (`new Date(nowMs - ms).toISOString()`) and bound
  // it directly for a text `occurred_at >= ?` comparison. SQLite's own
  // `datetime('now')` — what the `occurred_at` column's DEFAULT actually
  // writes — renders "YYYY-MM-DD HH:MM:SS" (space separator), while
  // `toISOString()` renders "YYYY-MM-DDTHH:MM:SS.sssZ" ("T"/"Z", millis).
  // Comparing those two formats as plain text silently drops any event that
  // shares a calendar date with the cutoff but occurred later in that day,
  // because "T" (0x54) sorts after the space (0x20) — a same-day event with
  // a *later* clock time still compares as "less than" the cutoff. This
  // wasn't a rare edge case: it hits every single day, for however much of
  // that day falls on the 24h/7d/30d cutoff's calendar date. Fixed by
  // pushing the cutoff arithmetic into SQLite itself
  // (`datetime('now', ?)`), so both sides of the comparison are always in
  // the same format. This test seeds a row landing exactly in the failure
  // window — same calendar date as the 24h cutoff, 30 minutes after it — to
  // make sure it stays fixed.
  it('counts an event 30 minutes inside the 24h window even when it shares a calendar date with the cutoff', async () => {
    const cutoffMs = Date.now() - 24 * 60 * 60 * 1000;
    const eventTime = new Date(cutoffMs + 30 * 60 * 1000);
    const sqliteFormatted = eventTime.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');

    await env.DB!.prepare(
      "INSERT INTO events (event_type, path, occurred_at) VALUES ('checkout_started', '/api/checkout', ?1)"
    )
      .bind(sqliteFormatted)
      .run();

    const res = await SELF.fetch('https://vibecheck.test/admin/stats', {
      headers: { Authorization: 'Bearer test-admin-stats-key' },
    });
    expect(res.status).toBe(200);
    const stats = await res.json<{ checkoutStarted: { last24h: number } }>();
    expect(stats.checkoutStarted.last24h).toBeGreaterThanOrEqual(1);
  });
});
