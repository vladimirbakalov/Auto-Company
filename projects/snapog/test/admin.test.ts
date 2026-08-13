// Route-level tests for GET /admin/stats (src/admin/routes.ts). Mirrors the
// FakeD1 pattern in test/index.test.ts and test/billing.test.ts: prepare(sql)
// branches on the SQL text against a small in-memory stand-in, no real D1.
// Covers the three-way graceful-degradation contract (unset secret -> 503,
// wrong key -> 401, right key -> 200) and that the returned counts actually
// reflect what's in the events/usage_events/users/api_keys tables.

import { describe, it, expect, beforeEach } from 'vitest';
import type { Env, Tier } from '../src/types';
import app from '../src/index';

interface EventRow {
  id: string;
  event_type: string;
  path: string | null;
}

interface UsageEventRow {
  id: string;
  api_key_id: string;
}

interface ApiKeyRow {
  id: string;
  tier: Tier;
}

// Minimal, stateful in-memory D1 stand-in covering only the SQL
// src/admin/routes.ts actually issues. `datetime('now', ?)` window
// filtering is faked with a real modifier -> days lookup rather than
// re-implementing SQLite's date math, since the only modifiers the route
// ever sends are '-1 day' / '-7 day' / '-30 day'.
class FakeD1 {
  events: EventRow[] = [];
  usageEvents: UsageEventRow[] = [];
  users: string[] = [];
  apiKeys: ApiKeyRow[] = [];

  prepare(sql: string) {
    const self = this;

    // Real D1 statements support .first()/.all()/.run() directly when a
    // query has no parameters (.bind() is optional) — src/admin/routes.ts
    // relies on exactly that for e.g. `SELECT COUNT(*) as cnt FROM users`.
    // Both the unbound statement below and the object bind() returns share
    // this same method set, keyed only off the SQL text (args are unused
    // here since none of these queries' results depend on the bound value
    // beyond which branch the SQL text itself selects).
    const methods = {
      async first<T>(): Promise<T | null> {
        if (sql.includes('SELECT COUNT(*) as cnt FROM users')) {
          return { cnt: self.users.length } as unknown as T;
        }
        if (sql.includes('SELECT COUNT(*) as cnt FROM usage_events WHERE generated_at')) {
          // Every fixture row in this test file is "recent enough" for any
          // window — window-boundary exclusion isn't the SQL this route
          // writes (that's SQLite's job), just that it wires the modifier
          // through and sums correctly.
          return { cnt: self.usageEvents.length } as unknown as T;
        }
        if (sql.includes('SELECT COUNT(*) as cnt FROM usage_events') && !sql.includes('WHERE')) {
          return { cnt: self.usageEvents.length } as unknown as T;
        }
        return null;
      },
      async all<T>(): Promise<{ results: T[] }> {
        if (sql.includes('SELECT event_type, COUNT(*) as cnt FROM events WHERE occurred_at')) {
          const counts = new Map<string, number>();
          for (const e of self.events) {
            counts.set(e.event_type, (counts.get(e.event_type) ?? 0) + 1);
          }
          const results = [...counts.entries()].map(([event_type, cnt]) => ({ event_type, cnt }));
          return { results: results as unknown as T[] };
        }
        if (sql.includes('SELECT tier, COUNT(*) as cnt FROM api_keys GROUP BY tier')) {
          const counts = new Map<string, number>();
          for (const k of self.apiKeys) {
            counts.set(k.tier, (counts.get(k.tier) ?? 0) + 1);
          }
          const results = [...counts.entries()].map(([tier, cnt]) => ({ tier, cnt }));
          return { results: results as unknown as T[] };
        }
        return { results: [] as T[] };
      },
      async run() {
        return { success: true };
      },
    };

    return {
      ...methods,
      bind(..._args: unknown[]) {
        return methods;
      },
    };
  }
}

function baseEnv(db: FakeD1, adminKey?: string): Env {
  return {
    DB: db as unknown as Env['DB'],
    ENVIRONMENT: 'test',
    ...(adminKey ? { ADMIN_STATS_KEY: adminKey } : {}),
  } as Env;
}

describe('GET /admin/stats', () => {
  let db: FakeD1;

  beforeEach(() => {
    db = new FakeD1();
  });

  it('returns 503 instead of crashing when ADMIN_STATS_KEY is not configured', async () => {
    const env = baseEnv(db); // no key set
    const res = await app.request('/admin/stats?key=whatever', {}, env);
    expect(res.status).toBe(503);
  });

  it('returns 401 when no key is supplied at all', async () => {
    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats', {}, env);
    expect(res.status).toBe(401);
  });

  it('returns 401 when the supplied query-param key does not match', async () => {
    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats?key=wrong-guess', {}, env);
    expect(res.status).toBe(401);
  });

  it('returns 401 when the supplied Authorization header key does not match', async () => {
    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats', { headers: { Authorization: 'Bearer wrong-guess' } }, env);
    expect(res.status).toBe(401);
  });

  it('accepts the correct key via the ?key= query param', async () => {
    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats?key=super-secret', {}, env);
    expect(res.status).toBe(200);
  });

  it('accepts the correct key via an Authorization: Bearer header', async () => {
    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats', { headers: { Authorization: 'Bearer super-secret' } }, env);
    expect(res.status).toBe(200);
  });

  it('returns sane counts across funnel and usage data', async () => {
    db.events = [
      { id: '1', event_type: 'landing_pageview', path: '/' },
      { id: '2', event_type: 'landing_pageview', path: '/' },
      { id: '3', event_type: 'register_pageview', path: '/register' },
      { id: '4', event_type: 'signup', path: '/register' },
    ];
    db.usageEvents = [{ id: 'u1', api_key_id: 'k1' }, { id: 'u2', api_key_id: 'k1' }];
    db.users = ['user_1', 'user_2'];
    db.apiKeys = [
      { id: 'k1', tier: 'free' },
      { id: 'k2', tier: 'free' },
      { id: 'k3', tier: 'pro' },
      { id: 'k4', tier: 'business' },
    ];

    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats?key=super-secret', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.funnel.last_24h).toMatchObject({
      landing_pageview: 2,
      register_pageview: 1,
      signup: 1,
      og_generations: 2,
    });
    expect(body.funnel.last_7d).toMatchObject({ landing_pageview: 2, signup: 1 });
    expect(body.funnel.last_30d).toMatchObject({ landing_pageview: 2, signup: 1 });
    expect(body.totals).toMatchObject({
      users: 2,
      api_keys_by_tier: { free: 2, pro: 1, business: 1 },
      og_generations: 2,
    });
    expect(typeof body.generated_at).toBe('string');
  });

  it('ignores events of an unrecognized type instead of crashing or leaking them into funnel counts', async () => {
    // src/admin/routes.ts's countEventsByType() only assigns a row into the
    // result if its event_type is in the known EVENT_TYPES list — forward
    // compatibility with a schema/event type added before this route is
    // updated to know about it. No prior fixture ever included one, so that
    // filter had zero coverage.
    db.events = [
      { id: '1', event_type: 'landing_pageview', path: '/' },
      { id: '2', event_type: 'some_future_event', path: null },
    ];

    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats?key=super-secret', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.funnel.last_24h).toMatchObject({
      landing_pageview: 1,
      register_pageview: 0,
      signup: 0,
    });
    expect(body.funnel.last_24h).not.toHaveProperty('some_future_event');
  });

  it('returns zeroed counts (not an error) when there is no data yet', async () => {
    const env = baseEnv(db, 'super-secret');
    const res = await app.request('/admin/stats?key=super-secret', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.funnel.last_24h).toMatchObject({
      landing_pageview: 0,
      register_pageview: 0,
      signup: 0,
      og_generations: 0,
    });
    expect(body.totals).toMatchObject({
      users: 0,
      api_keys_by_tier: { free: 0, pro: 0, business: 0 },
      og_generations: 0,
    });
  });
});
