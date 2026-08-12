// Exercises POST /api/scan end-to-end (Hono's app.request() needs no server)
// with global.fetch mocked for both the GitHub calls (github.ts) and the
// live-URL probe calls (probe.ts) — this is the "live-finding-merge logic"
// test called for in the build brief: it confirms live findings from an
// optional deployedUrl actually land in ScanResult.findings (and affect
// score/grade) via the real route, not just via the pure liveChecks.ts
// helpers (covered separately in test/liveChecks.test.ts).

import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  app,
  scheduled,
  RECONCILIATION_CRON,
  SCAN_RATE_LIMIT,
  PROBE_CHECK_RATE_LIMIT,
  MONITORS_RATE_LIMIT,
} from '../src/index';
import type { Env, ScanResult, UserRow, MonitorRow } from '../src/types';

function fakeScheduledEvent(cron: string): ScheduledEvent {
  return { cron, scheduledTime: Date.now(), type: 'scheduled', noRetry: () => {} } as unknown as ScheduledEvent;
}

function fakeExecutionContext(): ExecutionContext {
  return { waitUntil: () => {}, passThroughOnException: () => {}, props: {} } as unknown as ExecutionContext;
}

const TEST_ENV = {} as Env;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function streamedResponse(body: string, init: { status?: number; headers?: Headers } = {}): Response {
  const bytes = new TextEncoder().encode(body);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  return new Response(stream, { status: init.status ?? 200, headers: init.headers });
}

// Minimal in-memory stand-in for the one KV surface checkRateLimit
// (src/rateLimit.ts) actually uses (get/put) — same "fake the binding, not
// the whole SDK" approach as the D1/Stripe mocks below.
function createFakeKV(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: async (key: string) => store.get(key) ?? null,
    put: async (key: string, value: string) => {
      store.set(key, value);
    },
  } as unknown as KVNamespace;
}

// A minimal, clean (no-findings) repo: one source file with no secrets, no
// permissive CORS, no .env, no Supabase usage. Isolates the assertions to
// "did the live check contribute findings", not "did the static scan".
function mockGithubAndProbe(opts: {
  deployedHost?: string;
  deployedBehavior?: (url: string) => Response | Promise<Response>;
}) {
  return vi.fn(async (input: RequestInit | string | URL) => {
    const url = String(input);

    if (url === 'https://api.github.com/repos/acme/widgets') {
      return jsonResponse({ default_branch: 'main', private: false });
    }
    if (url.startsWith('https://api.github.com/repos/acme/widgets/git/trees/main')) {
      return jsonResponse({ tree: [{ path: 'index.js', type: 'blob' }], truncated: false });
    }
    if (url.startsWith('https://raw.githubusercontent.com/acme/widgets/main/index.js')) {
      return streamedResponse("console.log('hello world');", { status: 200 });
    }

    if (opts.deployedHost && url.startsWith(opts.deployedHost) && opts.deployedBehavior) {
      return opts.deployedBehavior(url);
    }

    return streamedResponse('not found', { status: 404 });
  }) as unknown as typeof fetch;
}

describe('POST /api/scan — live-finding merge (ADR §3 caller #1)', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  it('returns only static findings when no deployedUrl is supplied', async () => {
    global.fetch = mockGithubAndProbe({});

    const res = await app.request(
      '/api/scan',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: 'acme/widgets' }),
      },
      TEST_ENV
    );

    expect(res.status).toBe(200);
    const result = (await res.json()) as ScanResult;
    expect(result.grade).toBe('A');
    expect(result.findings).toEqual([]);
  });

  it('merges live findings (wildcard CORS + missing headers) into ScanResult.findings and drops the grade', async () => {
    global.fetch = mockGithubAndProbe({
      deployedHost: 'https://deployed.example.com',
      deployedBehavior: url => {
        if (url === 'https://deployed.example.com/') {
          // No hardening headers set at all -> also trips the
          // missing-security-headers check, so this exercises both live
          // finding builders merging into the same ScanResult in one pass.
          return streamedResponse('<html></html>', {
            status: 200,
            headers: new Headers({ 'access-control-allow-origin': '*' }),
          });
        }
        return streamedResponse('not found', { status: 404 });
      },
    });

    const res = await app.request(
      '/api/scan',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: 'acme/widgets', deployedUrl: 'https://deployed.example.com' }),
      },
      TEST_ENV
    );

    expect(res.status).toBe(200);
    const result = (await res.json()) as ScanResult;
    expect(result.findings).toHaveLength(2);
    const titles = result.findings.map(f => f.title);
    expect(titles.some(t => t.includes('Permissive CORS'))).toBe(true);
    expect(titles.some(t => t.includes('Missing common security headers'))).toBe(true);
    expect(result.findings.every(f => f.file === '(live: https://deployed.example.com/)')).toBe(true);
    // Live findings contribute to scoring exactly like static ones.
    expect(result.grade).not.toBe('A');
  });

  it('skips live findings and adds a note, without failing the scan, for a private/loopback deployedUrl', async () => {
    const fetchMock = mockGithubAndProbe({});
    global.fetch = fetchMock;

    const res = await app.request(
      '/api/scan',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: 'acme/widgets', deployedUrl: 'http://127.0.0.1:8080' }),
      },
      TEST_ENV
    );

    expect(res.status).toBe(200);
    const result = (await res.json()) as ScanResult;
    expect(result.findings).toEqual([]);
    expect(result.notes.some(n => n.includes('Skipped live URL check'))).toBe(true);
    // The blocked host must never have been fetched at all.
    const fetchedUrls = fetchMock.mock.calls.map(c => String(c[0]));
    expect(fetchedUrls.some(u => u.includes('127.0.0.1'))).toBe(false);
  });

  it('skips live findings and adds a note, without failing the scan, when the deployedUrl is unreachable', async () => {
    global.fetch = mockGithubAndProbe({
      deployedHost: 'https://unreachable.example.com',
      deployedBehavior: () => {
        throw new TypeError('fetch failed');
      },
    });

    const res = await app.request(
      '/api/scan',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: 'acme/widgets', deployedUrl: 'https://unreachable.example.com' }),
      },
      TEST_ENV
    );

    expect(res.status).toBe(200);
    const result = (await res.json()) as ScanResult;
    expect(result.findings).toEqual([]);
    expect(result.notes.some(n => n.includes('Skipped live URL check') && n.includes('could not reach'))).toBe(
      true
    );
  });
});

describe('POST /api/probe-check', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  it('rejects a private/loopback URL before attempting any fetch', async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;

    const res = await app.request(
      '/api/probe-check',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'http://169.254.169.254/' }),
      },
      TEST_ENV
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as { reachable: boolean };
    expect(body.reachable).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('reports reachable:true with latency for a live target', async () => {
    global.fetch = vi.fn(async () => streamedResponse('ok', { status: 200 })) as unknown as typeof fetch;

    const res = await app.request(
      '/api/probe-check',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://myapp.example.com' }),
      },
      TEST_ENV
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { reachable: boolean; latencyMs: number };
    expect(body.reachable).toBe(true);
    expect(typeof body.latencyMs).toBe('number');
  });

  it('reports reachable:false when the target cannot be reached', async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;

    const res = await app.request(
      '/api/probe-check',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://down.example.com' }),
      },
      TEST_ENV
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { reachable: boolean };
    expect(body.reachable).toBe(false);
  });
});

// Coarse per-IP rate limiting (src/rateLimit.ts) — closes the KNOWN GAP
// flagged above POST /api/probe-check in src/index.ts (QA cycle #1146).
// Covers the three cases the task calls for: under-limit allows through,
// over-limit returns 429, and a missing RATE_LIMIT binding gracefully
// no-ops (the endpoint still works normally) — same graceful-degradation
// contract as every other optional binding in this codebase.
describe('POST /api/scan — rate limiting', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  it('allows requests under the limit', async () => {
    global.fetch = mockGithubAndProbe({});
    const env = { RATE_LIMIT: createFakeKV() } as Env;

    for (let i = 0; i < SCAN_RATE_LIMIT; i++) {
      const res = await app.request(
        '/api/scan',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '1.1.1.1' },
          body: JSON.stringify({ repoUrl: 'acme/widgets' }),
        },
        env
      );
      expect(res.status).toBe(200);
    }
  });

  it('returns 429 once a single IP exceeds the limit within the window', async () => {
    global.fetch = mockGithubAndProbe({});
    const env = { RATE_LIMIT: createFakeKV() } as Env;
    const request = () =>
      app.request(
        '/api/scan',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '2.2.2.2' },
          body: JSON.stringify({ repoUrl: 'acme/widgets' }),
        },
        env
      );

    for (let i = 0; i < SCAN_RATE_LIMIT; i++) {
      expect((await request()).status).toBe(200);
    }
    const res = await request();
    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain('Too many requests');
  });

  it('does not throttle two different IPs against the same budget', async () => {
    global.fetch = mockGithubAndProbe({});
    const env = { RATE_LIMIT: createFakeKV() } as Env;
    const requestFrom = (ip: string) =>
      app.request(
        '/api/scan',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
          body: JSON.stringify({ repoUrl: 'acme/widgets' }),
        },
        env
      );

    for (let i = 0; i < SCAN_RATE_LIMIT; i++) {
      expect((await requestFrom('3.3.3.3')).status).toBe(200);
    }
    expect((await requestFrom('3.3.3.3')).status).toBe(429);
    // A different IP has its own untouched budget.
    expect((await requestFrom('4.4.4.4')).status).toBe(200);
  });

  it('still works normally (no throttling) when the RATE_LIMIT binding is missing', async () => {
    global.fetch = mockGithubAndProbe({});
    for (let i = 0; i < SCAN_RATE_LIMIT + 5; i++) {
      const res = await app.request(
        '/api/scan',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '5.5.5.5' },
          body: JSON.stringify({ repoUrl: 'acme/widgets' }),
        },
        TEST_ENV
      );
      expect(res.status).toBe(200);
    }
  });
});

describe('POST /api/probe-check — rate limiting', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  const probeRequest = (env: Env, ip: string) =>
    app.request(
      '/api/probe-check',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
        body: JSON.stringify({ url: 'https://myapp.example.com' }),
      },
      env
    );

  it('allows requests under the limit', async () => {
    global.fetch = vi.fn(async () => streamedResponse('ok', { status: 200 })) as unknown as typeof fetch;
    const env = { RATE_LIMIT: createFakeKV() } as Env;

    for (let i = 0; i < PROBE_CHECK_RATE_LIMIT; i++) {
      expect((await probeRequest(env, '6.6.6.6')).status).toBe(200);
    }
  });

  it('returns 429 once the limit is exceeded', async () => {
    global.fetch = vi.fn(async () => streamedResponse('ok', { status: 200 })) as unknown as typeof fetch;
    const env = { RATE_LIMIT: createFakeKV() } as Env;

    for (let i = 0; i < PROBE_CHECK_RATE_LIMIT; i++) {
      expect((await probeRequest(env, '7.7.7.7')).status).toBe(200);
    }
    const res = await probeRequest(env, '7.7.7.7');
    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain('Too many requests');
  });

  it('still works normally when the RATE_LIMIT binding is missing', async () => {
    global.fetch = vi.fn(async () => streamedResponse('ok', { status: 200 })) as unknown as typeof fetch;
    for (let i = 0; i < PROBE_CHECK_RATE_LIMIT + 5; i++) {
      expect((await probeRequest(TEST_ENV, '8.8.8.8')).status).toBe(200);
    }
  });
});

describe('POST /api/monitors — rate limiting', () => {
  // Fake D1 that answers both requireAuth's user lookup and insertMonitor's
  // INSERT ... RETURNING * without caring about bound params — same
  // "branch on the SQL text, not real query semantics" shortcut as other
  // hand-rolled D1 fakes in this suite; the rate-limit tests only need a
  // deterministic 201-vs-429, not real persistence.
  function fakeMonitorsDb(user: UserRow, monitorRow: MonitorRow): D1Database {
    return {
      prepare: (sql: string) => ({
        bind: () => ({
          first: async <T>() => {
            if (sql.includes('FROM users')) return user as unknown as T;
            if (sql.includes('INSERT INTO monitors')) return monitorRow as unknown as T;
            return null as unknown as T;
          },
        }),
      }),
    } as unknown as D1Database;
  }

  const testUser: UserRow = {
    id: 1,
    email: 'user@example.com',
    stripe_customer_id: null,
    stripe_subscription_id: null,
    subscription_status: 'active',
    api_key_hash: 'irrelevant-fake-does-not-check-hash',
    created_at: '2026-08-01T00:00:00.000Z',
  };

  const testMonitor: MonitorRow = {
    id: 1,
    user_id: 1,
    url: 'https://myapp.example.com',
    interval_seconds: 300,
    next_check_at: '2026-08-12T00:05:00.000Z',
    last_check_at: null,
    last_status: null,
    consecutive_failures: 0,
    paused: 0,
    created_at: '2026-08-12T00:00:00.000Z',
  };

  const monitorsRequest = (env: Env, ip: string) =>
    app.request(
      '/api/monitors',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CF-Connecting-IP': ip,
          Authorization: 'Bearer fake-api-key',
        },
        body: JSON.stringify({ url: 'https://myapp.example.com' }),
      },
      env
    );

  it('allows requests under the limit', async () => {
    const env = { DB: fakeMonitorsDb(testUser, testMonitor), RATE_LIMIT: createFakeKV() } as Env;
    for (let i = 0; i < MONITORS_RATE_LIMIT; i++) {
      expect((await monitorsRequest(env, '9.9.9.9')).status).toBe(201);
    }
  });

  it('returns 429 once the limit is exceeded, before ever touching auth/DB', async () => {
    const db = fakeMonitorsDb(testUser, testMonitor);
    const prepareSpy = vi.spyOn(db, 'prepare');
    const env = { DB: db, RATE_LIMIT: createFakeKV() } as Env;

    for (let i = 0; i < MONITORS_RATE_LIMIT; i++) {
      expect((await monitorsRequest(env, '10.10.10.10')).status).toBe(201);
    }
    prepareSpy.mockClear();

    const res = await monitorsRequest(env, '10.10.10.10');
    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain('Too many requests');
    // Rejected before requireAuth/insertMonitor ever ran a query.
    expect(prepareSpy).not.toHaveBeenCalled();
  });

  it('still works normally when the RATE_LIMIT binding is missing', async () => {
    const env = { DB: fakeMonitorsDb(testUser, testMonitor) } as Env;
    for (let i = 0; i < MONITORS_RATE_LIMIT + 5; i++) {
      expect((await monitorsRequest(env, '11.11.11.11')).status).toBe(201);
    }
  });
});

// Mirrors the existing graceful-degradation coverage style for other
// bindings in this file (POST /api/monitors, POST /api/stripe/webhook,
// etc.): the reconciliation-cron tick must never throw just because a
// binding/secret hasn't been provisioned yet — it's a Cron Trigger with no
// caller to hand an error to.
describe('scheduled — reconciliation cron (RECONCILIATION_CRON) graceful degradation', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  it('no-ops without touching Stripe when STRIPE_SECRET_KEY is missing', async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    const env = { DB: {} as unknown as D1Database } as Env;
    await expect(
      scheduled(fakeScheduledEvent(RECONCILIATION_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('STRIPE_SECRET_KEY missing'));
  });

  it('no-ops without touching Stripe when DB is missing', async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    const env = { STRIPE_SECRET_KEY: 'sk_test_fake' } as Env;
    await expect(
      scheduled(fakeScheduledEvent(RECONCILIATION_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('DB binding missing'));
  });

  it('no-ops when both STRIPE_SECRET_KEY and DB are missing', async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    vi.spyOn(console, 'log').mockImplementation(() => {});

    const env = {} as Env;
    await expect(
      scheduled(fakeScheduledEvent(RECONCILIATION_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('logs and returns without throwing when D1 fails after a successful Stripe fetch', async () => {
    global.fetch = vi.fn(async () =>
      jsonResponse({ data: [{ id: 'sub_1', customer: 'cus_A' }], has_more: false })
    ) as unknown as typeof fetch;
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const failingDb = {
      prepare: () => ({
        all: () => Promise.reject(new Error('D1 unavailable')),
      }),
    } as unknown as D1Database;
    const env = { STRIPE_SECRET_KEY: 'sk_test_fake', DB: failingDb } as Env;

    await expect(
      scheduled(fakeScheduledEvent(RECONCILIATION_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('failed to read known Stripe customer ids from D1'),
      expect.any(Error)
    );
  });
});
