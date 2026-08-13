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
  MONITOR_CHECK_CRON,
  SCAN_RATE_LIMIT,
  PROBE_CHECK_RATE_LIMIT,
  MONITORS_RATE_LIMIT,
} from '../src/index';
import type { Env, ScanResult, UserRow, MonitorRow, AlertRow, CheckRow } from '../src/types';

function fakeScheduledEvent(cron: string): ScheduledEvent {
  return { cron, scheduledTime: Date.now(), type: 'scheduled', noRetry: () => {} } as unknown as ScheduledEvent;
}

function fakeExecutionContext(): ExecutionContext {
  return { waitUntil: () => {}, passThroughOnException: () => {}, props: {} } as unknown as ExecutionContext;
}

// Cycle #126 analytics tests below need to actually observe the
// ExecutionContext.waitUntil()-scheduled background event write (unlike
// fakeExecutionContext() above, which just drops it) — this variant
// captures every promise handed to waitUntil() so a test can await it before
// asserting, mirroring how the real Workers runtime keeps the isolate alive
// until waitUntil()'d work finishes, just synchronously and on-demand for
// test determinism instead of via the runtime's own scheduling.
function fakeCapturingExecutionContext(): { ctx: ExecutionContext; settle: () => Promise<void> } {
  const promises: Promise<unknown>[] = [];
  const ctx = {
    waitUntil: (p: Promise<unknown>) => {
      promises.push(p);
    },
    passThroughOnException: () => {},
    props: {},
  } as unknown as ExecutionContext;
  return {
    ctx,
    settle: async () => {
      await Promise.allSettled(promises);
    },
  };
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
    baseline_findings_json: null,
    muted_until: null,
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

// ── Next Action #2: Resend email wiring ──────────────────────────────────
// The four previously-stubbed "email transport" points (src/email.ts) now
// actually call sendEmail. These tests exercise each call site through the
// real route/cron entry point (not just email.ts in isolation, covered in
// test/email.test.ts) to confirm the right recipient/content is resolved
// from whatever data that call site actually has (Stripe webhook payload,
// or a MonitorRow's user_id), and that a missing key / lookup gap degrades
// gracefully — same graceful-degradation contract as every other optional
// binding in this file.
describe('POST /api/stripe/webhook — email wiring', () => {
  const originalFetch = global.fetch;
  const webhookSecret = 'whsec_test_secret';

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  // Same signing helper as test/stripe.test.ts's verifyStripeSignature
  // coverage — duplicated locally rather than imported/exported since
  // it's ~15 lines and test-only (rule of three: not worth a shared module
  // for two test files).
  async function signPayload(payload: string, secret: string, timestamp: number): Promise<string> {
    const signedPayload = `${timestamp}.${payload}`;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
    const hex = Array.from(new Uint8Array(sigBytes))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return `t=${timestamp},v1=${hex}`;
  }

  async function postWebhook(env: Env, payload: object): Promise<Response> {
    const body = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await signPayload(body, webhookSecret, timestamp);
    return app.request(
      '/api/stripe/webhook',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Stripe-Signature': signature },
        body,
      },
      env
    );
  }

  const testUser: UserRow = {
    id: 42,
    email: 'founder@example.com',
    stripe_customer_id: 'cus_ABC123',
    stripe_subscription_id: 'sub_XYZ789',
    subscription_status: 'active',
    api_key_hash: null,
    created_at: '2026-08-01T00:00:00.000Z',
  };

  // Fake D1: branches on the SQL text, same shortcut as fakeMonitorsDb above
  // — these tests only need deterministic email-wiring behavior, not real
  // persistence semantics.
  function fakeWebhookDb(
    user: UserRow | null,
    opts: { existingMonitors?: MonitorRow[]; onInsertMonitor?: () => void; onUpdateBaseline?: () => void } = {}
  ): D1Database {
    const existingMonitors = opts.existingMonitors ?? [];
    return {
      prepare: (sql: string) => ({
        bind: () => ({
          first: async <T>() => {
            if (sql.includes('INSERT INTO users')) return user as unknown as T;
            if (sql.includes('SELECT * FROM users WHERE stripe_customer_id')) return user as unknown as T;
            if (sql.includes('INSERT INTO monitors')) {
              opts.onInsertMonitor?.();
              return {
                id: 501,
                user_id: user?.id ?? 0,
                url: 'https://deployed.example.com',
                interval_seconds: 300,
                last_status: null,
                last_checked_at: null,
                consecutive_failures: 0,
                paused: 0,
                created_at: '2026-08-12T00:00:00.000Z',
                baseline_findings_json: null,
                muted_until: null,
              } as unknown as T;
            }
            return null as unknown as T;
          },
          run: async () => {
            if (sql.includes('UPDATE monitors SET baseline_findings_json')) opts.onUpdateBaseline?.();
            return { success: true } as unknown as D1Result;
          },
          all: async <T>() => {
            if (sql.includes('SELECT * FROM monitors WHERE user_id')) {
              return { results: existingMonitors as unknown as T[] } as unknown as D1Result<T>;
            }
            return { results: [] } as unknown as D1Result<T>;
          },
        }),
      }),
    } as unknown as D1Database;
  }

  const checkoutCompletedEvent = {
    type: 'checkout.session.completed',
    data: {
      object: {
        customer: 'cus_ABC123',
        customer_email: 'founder@example.com',
        customer_details: { email: 'founder@example.com' },
        subscription: 'sub_XYZ789',
      },
    },
  };

  it('emails a magic link pointing at GET /api/auth/verify when RESEND_API_KEY is configured', async () => {
    const resendMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://api.resend.com/emails');
      const body = JSON.parse(String(init?.body));
      expect(body.to).toBe('founder@example.com');
      expect(body.html).toContain('/api/auth/verify?token=');
      return new Response(JSON.stringify({ id: 'email_1' }), { status: 200 });
    });
    global.fetch = resendMock as unknown as typeof fetch;

    const env = {
      STRIPE_SECRET_KEY: 'sk_test_fake',
      STRIPE_WEBHOOK_SECRET: webhookSecret,
      DB: fakeWebhookDb(testUser),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    const res = await postWebhook(env, checkoutCompletedEvent);
    expect(res.status).toBe(200);
    expect(resendMock).toHaveBeenCalledTimes(1);
  });

  it('no-ops the magic-link email (logged TODO, no fetch) when RESEND_API_KEY is missing, and still applies the webhook', async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    const env = {
      STRIPE_SECRET_KEY: 'sk_test_fake',
      STRIPE_WEBHOOK_SECRET: webhookSecret,
      DB: fakeWebhookDb(testUser),
    } as Env;

    const res = await postWebhook(env, checkoutCompletedEvent);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; applied: boolean };
    expect(body).toEqual({ ok: true, applied: true });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('RESEND_API_KEY not configured'),
      'founder@example.com',
      'subject:',
      expect.any(String)
    );
  });

  const pastDueEvent = {
    type: 'invoice.payment_failed',
    data: { object: { customer: 'cus_ABC123' } },
  };

  it('emails a payment-failed notice to the user resolved from stripe_customer_id on past_due', async () => {
    const resendMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://api.resend.com/emails');
      const body = JSON.parse(String(init?.body));
      expect(body.to).toBe('founder@example.com');
      expect(body.html).toContain('grace period');
      return new Response(JSON.stringify({ id: 'email_2' }), { status: 200 });
    });
    global.fetch = resendMock as unknown as typeof fetch;

    const env = {
      STRIPE_SECRET_KEY: 'sk_test_fake',
      STRIPE_WEBHOOK_SECRET: webhookSecret,
      DB: fakeWebhookDb(testUser),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    const res = await postWebhook(env, pastDueEvent);
    expect(res.status).toBe(200);
    expect(resendMock).toHaveBeenCalledTimes(1);
  });

  it('logs the gap (no email sent) when no D1 user row matches the Stripe customer id', async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const env = {
      STRIPE_SECRET_KEY: 'sk_test_fake',
      STRIPE_WEBHOOK_SECRET: webhookSecret,
      DB: fakeWebhookDb(null),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    const res = await postWebhook(env, pastDueEvent);
    expect(res.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalledWith(
      'Payment-failed notice: no D1 user row for Stripe customer',
      'cus_ABC123',
      expect.stringContaining('cannot resolve an email')
    );
  });

  it('a Resend failure does not fail the webhook response', async () => {
    global.fetch = vi.fn(async () => new Response('server error', { status: 500 })) as unknown as typeof fetch;
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const env = {
      STRIPE_SECRET_KEY: 'sk_test_fake',
      STRIPE_WEBHOOK_SECRET: webhookSecret,
      DB: fakeWebhookDb(testUser),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    const res = await postWebhook(env, checkoutCompletedEvent);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  // Funnel-gap fix coverage (spec §3.4) — this branch had zero HTTP-level
  // tests before (qa-bach review, cycle 11): only routeStripeEvent's pure
  // metadata-parsing was covered, not the handler that actually calls
  // insertMonitor/buildLiveFindings.
  describe('checkout monitor creation (funnel-gap fix, spec §3.4)', () => {
    const checkoutCompletedEventWithUrl = {
      ...checkoutCompletedEvent,
      data: {
        object: { ...checkoutCompletedEvent.data.object, metadata: { deployed_url: 'https://deployed.example.com' } },
      },
    };

    function mockResendAndProbe(): typeof fetch {
      return vi.fn(async (input: RequestInit | string | URL) => {
        const url = String(input);
        if (url === 'https://api.resend.com/emails') {
          return new Response(JSON.stringify({ id: 'email_x' }), { status: 200 });
        }
        if (url === 'https://deployed.example.com/') {
          return streamedResponse('<html></html>', {
            status: 200,
            headers: new Headers({
              'strict-transport-security': 'max-age=1',
              'x-frame-options': 'DENY',
              'x-content-type-options': 'nosniff',
            }),
          });
        }
        return streamedResponse('not found', { status: 404 });
      }) as unknown as typeof fetch;
    }

    it('creates a monitor and captures a security-drift baseline when the user has no existing monitor', async () => {
      const onInsertMonitor = vi.fn();
      const onUpdateBaseline = vi.fn();
      global.fetch = mockResendAndProbe();

      const env = {
        STRIPE_SECRET_KEY: 'sk_test_fake',
        STRIPE_WEBHOOK_SECRET: webhookSecret,
        DB: fakeWebhookDb(testUser, { existingMonitors: [], onInsertMonitor, onUpdateBaseline }),
        RESEND_API_KEY: 're_test_fake',
      } as Env;

      const res = await postWebhook(env, checkoutCompletedEventWithUrl);
      expect(res.status).toBe(200);
      expect(onInsertMonitor).toHaveBeenCalledTimes(1);
      expect(onUpdateBaseline).toHaveBeenCalledTimes(1);
    });

    // The bug this guards against: Stripe redeliveries (at-least-once) hitting
    // this same webhook again — without this check, insertMonitor would run
    // a second time with no unique constraint, leaving an un-mutable ghost
    // monitor the dashboard never shows (monitors[0], newest-first) but that
    // keeps polling and alerting forever.
    it('skips monitor creation when the user already has a monitor (idempotent under Stripe webhook retries)', async () => {
      const onInsertMonitor = vi.fn();
      global.fetch = mockResendAndProbe();
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      const existingMonitor: MonitorRow = {
        id: 500,
        user_id: testUser.id,
        url: 'https://deployed.example.com',
        interval_seconds: 300,
        last_status: 200,
        last_checked_at: '2026-08-12T00:00:00.000Z',
        consecutive_failures: 0,
        paused: 0,
        created_at: '2026-08-01T00:00:00.000Z',
        baseline_findings_json: '[]',
        muted_until: null,
      };

      const env = {
        STRIPE_SECRET_KEY: 'sk_test_fake',
        STRIPE_WEBHOOK_SECRET: webhookSecret,
        DB: fakeWebhookDb(testUser, { existingMonitors: [existingMonitor], onInsertMonitor }),
        RESEND_API_KEY: 're_test_fake',
      } as Env;

      const res = await postWebhook(env, checkoutCompletedEventWithUrl);
      expect(res.status).toBe(200);
      expect(onInsertMonitor).not.toHaveBeenCalled();
      expect(logSpy).toHaveBeenCalledWith(
        'Checkout monitor creation skipped: user id',
        testUser.id,
        'already has a monitor (likely a Stripe webhook retry).'
      );
    });
  });
});

describe('scheduled — monitor cron (MONITOR_CHECK_CRON) down/recovered alert emails', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  const baseMonitor: MonitorRow = {
    id: 7,
    user_id: 99,
    url: 'https://myapp.example.com',
    interval_seconds: 300,
    next_check_at: '2026-08-12T00:00:00.000Z',
    last_check_at: null,
    last_status: 200,
    consecutive_failures: 1,
    paused: 0,
    created_at: '2026-08-01T00:00:00.000Z',
    baseline_findings_json: null,
    muted_until: null,
  };

  // Fake D1 covering every query the fan-out worker touches for one due
  // monitor: fetchDueMonitors, recordCheck, updateMonitorAfterCheck,
  // hasOpenDownAlert, insertAlert, resolveOpenDownAlert, fetchTrailingChecks,
  // and (new) findUserEmailById — branches on SQL text, same shortcut as
  // fakeMonitorsDb/fakeWebhookDb above.
  function fakeCronDb(opts: { monitor: MonitorRow; hasOpenDownAlert: boolean; userEmail: string | null }): D1Database {
    return {
      prepare: (sql: string) => ({
        bind: () => ({
          all: async <T>() => {
            if (sql.includes('FROM monitors') && sql.includes('JOIN users')) {
              return { results: [opts.monitor] } as unknown as { results: T[] };
            }
            return { results: [] } as unknown as { results: T[] };
          },
          first: async <T>() => {
            if (sql.includes('INSERT INTO checks')) return { id: 1 } as unknown as T;
            if (sql.startsWith('SELECT id FROM alerts')) {
              return opts.hasOpenDownAlert ? ({ id: 1 } as unknown as T) : (null as unknown as T);
            }
            if (sql.includes('INSERT INTO alerts')) return { id: 1 } as unknown as T;
            if (sql.includes('SELECT email FROM users')) {
              return opts.userEmail ? ({ email: opts.userEmail } as unknown as T) : (null as unknown as T);
            }
            return null as unknown as T;
          },
          run: async () => ({ success: true }) as unknown as D1Result,
        }),
      }),
    } as unknown as D1Database;
  }

  it('emails the monitor owner a down alert on the fire_down transition', async () => {
    const fetchMock = vi.fn(async (input: RequestInit | string | URL) => {
      const url = String(input);
      if (url === 'https://api.resend.com/emails') {
        return new Response(JSON.stringify({ id: 'email_3' }), { status: 200 });
      }
      // The monitored URL itself: simulate it being down.
      throw new TypeError('fetch failed');
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    const env = {
      DB: fakeCronDb({ monitor: baseMonitor, hasOpenDownAlert: false, userEmail: 'owner@example.com' }),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    await expect(
      scheduled(fakeScheduledEvent(MONITOR_CHECK_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();

    const resendCalls = fetchMock.mock.calls.filter(c => String(c[0]) === 'https://api.resend.com/emails');
    expect(resendCalls).toHaveLength(1);
    const resendBody = JSON.parse(String((resendCalls[0][1] as RequestInit).body));
    expect(resendBody.to).toBe('owner@example.com');
    expect(resendBody.subject).toContain('is down');
  });

  it('emails the monitor owner a recovered alert on the fire_recovered transition', async () => {
    const fetchMock = vi.fn(async (input: RequestInit | string | URL) => {
      const url = String(input);
      if (url === 'https://api.resend.com/emails') {
        return new Response(JSON.stringify({ id: 'email_4' }), { status: 200 });
      }
      // The monitored URL itself: simulate it being back up.
      return new Response('ok', { status: 200 });
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    const recoveredMonitor: MonitorRow = { ...baseMonitor, consecutive_failures: 3 };
    const env = {
      DB: fakeCronDb({ monitor: recoveredMonitor, hasOpenDownAlert: true, userEmail: 'owner@example.com' }),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    await expect(
      scheduled(fakeScheduledEvent(MONITOR_CHECK_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();

    const resendCalls = fetchMock.mock.calls.filter(c => String(c[0]) === 'https://api.resend.com/emails');
    expect(resendCalls).toHaveLength(1);
    const resendBody = JSON.parse(String((resendCalls[0][1] as RequestInit).body));
    expect(resendBody.to).toBe('owner@example.com');
    expect(resendBody.subject).toContain('back up');
  });

  it('does not throw the cron tick when no user email is found for the monitor (fire_down)', async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const env = {
      DB: fakeCronDb({ monitor: baseMonitor, hasOpenDownAlert: false, userEmail: null }),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    await expect(
      scheduled(fakeScheduledEvent(MONITOR_CHECK_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();

    expect(errorSpy).toHaveBeenCalledWith(
      'Down alert: no user email found for monitor id',
      baseMonitor.id,
      'user_id',
      baseMonitor.user_id
    );
  });

  it('a Resend failure during the cron tick does not throw / abort the fan-out', async () => {
    global.fetch = vi.fn(async (input: RequestInit | string | URL) => {
      const url = String(input);
      if (url === 'https://api.resend.com/emails') {
        return new Response('server error', { status: 500 });
      }
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const env = {
      DB: fakeCronDb({ monitor: baseMonitor, hasOpenDownAlert: false, userEmail: 'owner@example.com' }),
      RESEND_API_KEY: 're_test_fake',
    } as Env;

    await expect(
      scheduled(fakeScheduledEvent(MONITOR_CHECK_CRON), env, fakeExecutionContext())
    ).resolves.toBeUndefined();
  });
});

// GET /dashboard + POST /api/monitors/:id/mute (spec §5). Fake D1 branches on
// SQL text, same shortcut used by fakeMonitorsDb/fakeWebhookDb/fakeCronDb
// above — these are route-wiring tests, not a real-persistence integration
// suite. Auth goes through requireAuth's Authorization: Bearer path (not the
// signed session cookie) purely for test simplicity — both paths funnel into
// the exact same requireAuth() call in index.ts, so this exercises the same
// downstream route logic either way; session-cookie-specific behavior is
// already covered by test/auth.test.ts.
describe('GET /dashboard', () => {
  const dashboardUser: UserRow = {
    id: 1,
    email: 'owner@example.com',
    stripe_customer_id: 'cus_1',
    stripe_subscription_id: 'sub_1',
    subscription_status: 'active',
    api_key_hash: 'irrelevant-fake-does-not-check-hash',
    created_at: '2026-08-01T00:00:00.000Z',
  };

  const dashboardMonitor: MonitorRow = {
    id: 5,
    user_id: 1,
    url: 'https://myapp.example.com',
    interval_seconds: 300,
    next_check_at: '2026-08-12T00:10:00.000Z',
    last_check_at: '2026-08-12T00:05:00.000Z',
    last_status: 200,
    consecutive_failures: 0,
    paused: 0,
    created_at: '2026-08-01T00:00:00.000Z',
    // null baseline deliberately: exercises the "no baseline yet" branch
    // without needing to also mock the live-probe fetch call for this
    // route-wiring test (that diff logic has its own coverage in
    // test/dashboard.test.ts).
    baseline_findings_json: null,
    muted_until: null,
  };

  function fakeDashboardDb(opts: { user: UserRow; monitor: MonitorRow | null; alerts: AlertRow[] }): D1Database {
    return {
      prepare: (sql: string) => ({
        bind: () => ({
          first: async <T>() => {
            if (sql.includes('FROM users WHERE api_key_hash')) return opts.user as unknown as T;
            return null as unknown as T;
          },
          all: async <T>() => {
            if (sql.startsWith('SELECT * FROM monitors WHERE user_id')) {
              return { results: opts.monitor ? [opts.monitor] : [] } as unknown as { results: T[] };
            }
            if (sql.startsWith('SELECT * FROM checks')) {
              return { results: [] as CheckRow[] } as unknown as { results: T[] };
            }
            if (sql.startsWith('SELECT * FROM alerts')) {
              return { results: opts.alerts } as unknown as { results: T[] };
            }
            return { results: [] } as unknown as { results: T[] };
          },
        }),
      }),
    } as unknown as D1Database;
  }

  it('renders the dashboard for an authenticated user with a monitor', async () => {
    const env = {
      DB: fakeDashboardDb({ user: dashboardUser, monitor: dashboardMonitor, alerts: [] }),
    } as Env;

    const res = await app.request(
      '/dashboard',
      { headers: { Authorization: 'Bearer fake-api-key' } },
      env
    );

    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain('https://myapp.example.com');
    expect(html).toContain('owner@example.com');
    // Fewer than COLD_START_MIN_SAMPLES trailing checks (zero here) -> Learning.
    expect(html).toContain('Learning');
    expect(html).toContain('No baseline captured yet');
    expect(html).toContain("No alerts yet");
    expect(html).toContain('Pause alerts for 24h');

    // CSP is nonce-based (script-src has no 'unsafe-inline') since the page
    // ships its interactivity as an inline <script>: the header's nonce must
    // match the one on the tag, or the mute/resume button silently breaks.
    const csp = res.headers.get('Content-Security-Policy');
    expect(csp).toContain("script-src 'self' 'nonce-");
    const nonce = csp?.match(/'nonce-([^']+)'/)?.[1];
    expect(nonce).toBeTruthy();
    expect(html).toContain(`<script nonce="${nonce}">`);
  });

  it('renders the sign-in state when unauthenticated', async () => {
    const env = {
      DB: fakeDashboardDb({ user: dashboardUser, monitor: dashboardMonitor, alerts: [] }),
    } as Env;

    const res = await app.request('/dashboard', {}, env);

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("This link isn't valid");
  });

  it('renders an empty state for an authenticated user with no monitor yet', async () => {
    const env = {
      DB: fakeDashboardDb({ user: dashboardUser, monitor: null, alerts: [] }),
    } as Env;

    const res = await app.request(
      '/dashboard',
      { headers: { Authorization: 'Bearer fake-api-key' } },
      env
    );

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('No monitor yet');
  });

  // renderAlerts/alertResolutionText (pages.ts) were only ever exercised
  // with alerts: [] by the tests above, so the "has alerts" branch — type
  // label lookup, and the Ongoing/Resolved/no-resolution-text distinction
  // per alert type — had no coverage at all.
  it('renders alert rows with type labels and resolution state', async () => {
    const alerts: AlertRow[] = [
      { id: 1, monitor_id: 5, type: 'down', fired_at: '2026-08-12T00:00:00.000Z', resolved_at: null, notified_at: null, details: null },
      { id: 2, monitor_id: 5, type: 'down', fired_at: '2026-08-11T00:00:00.000Z', resolved_at: '2026-08-11T01:00:00.000Z', notified_at: null, details: null },
      { id: 3, monitor_id: 5, type: 'recovered', fired_at: '2026-08-11T01:00:00.000Z', resolved_at: null, notified_at: null, details: null },
    ];
    const env = {
      DB: fakeDashboardDb({ user: dashboardUser, monitor: dashboardMonitor, alerts }),
    } as Env;

    const res = await app.request(
      '/dashboard',
      { headers: { Authorization: 'Bearer fake-api-key' } },
      env
    );

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Went down');
    expect(html).toContain('Ongoing');
    expect(html).toContain('Resolved');
    expect(html).toContain('Back up');
  });

  // Route-level coverage for the security-drift live-probe branch (qa-bach
  // review, cycle 11: this branch was previously only exercised indirectly
  // through diffSecurityFindings's own unit tests in dashboard.test.ts, never
  // through the actual GET /dashboard handler's try/catch around
  // buildLiveFindings).
  describe('security drift — live-probe branch (non-null baseline)', () => {
    const monitorWithBaseline: MonitorRow = {
      ...dashboardMonitor,
      baseline_findings_json: JSON.stringify([
        { id: 'live-cors-1', title: 'Permissive CORS policy on live deployment (wildcard origin)', severity: 'medium', confidence: 'high', explanation: 'x' },
      ]),
    };

    const originalFetch = global.fetch;
    afterEach(() => {
      vi.restoreAllMocks();
      global.fetch = originalFetch;
    });

    it('degrades gracefully (200, "check failed" message) when the live probe throws', async () => {
      global.fetch = vi.fn(async () => {
        throw new Error('network unreachable');
      }) as unknown as typeof fetch;

      const env = {
        DB: fakeDashboardDb({ user: dashboardUser, monitor: monitorWithBaseline, alerts: [] }),
      } as Env;

      const res = await app.request('/dashboard', { headers: { Authorization: 'Bearer fake-api-key' } }, env);

      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain("Can't check security drift right now");
    });

    it('reports no new findings when the live probe matches the stored baseline', async () => {
      global.fetch = vi.fn(async (input: RequestInit | string | URL) => {
        const url = String(input);
        if (url === 'https://myapp.example.com/') {
          // Include the hardening headers so only the CORS-wildcard finding
          // fires — matching monitorWithBaseline's single stored finding
          // exactly, otherwise checkLiveMissingSecurityHeaders would also
          // fire and this "no changes" test would see a spurious new finding.
          return streamedResponse('<html></html>', {
            status: 200,
            headers: new Headers({
              'access-control-allow-origin': '*',
              'strict-transport-security': 'max-age=1',
              'x-frame-options': 'DENY',
              'x-content-type-options': 'nosniff',
            }),
          });
        }
        return streamedResponse('not found', { status: 404 });
      }) as unknown as typeof fetch;

      const env = {
        DB: fakeDashboardDb({ user: dashboardUser, monitor: monitorWithBaseline, alerts: [] }),
      } as Env;

      const res = await app.request('/dashboard', { headers: { Authorization: 'Bearer fake-api-key' } }, env);

      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('No changes since your last scan');
    });

    // The fourth SecurityDriftSummary state ('new_findings' — renderSecurityDrift
    // in pages.ts) had no coverage: only no_baseline/check_failed/no_changes were
    // exercised above. Omit all hardening headers so the live probe reports
    // findings beyond monitorWithBaseline's single stored CORS finding.
    it('lists new findings when the live probe diverges from the stored baseline', async () => {
      global.fetch = vi.fn(async (input: RequestInit | string | URL) => {
        const url = String(input);
        if (url === 'https://myapp.example.com/') {
          return streamedResponse('<html></html>', {
            status: 200,
            headers: new Headers({ 'access-control-allow-origin': '*' }),
          });
        }
        return streamedResponse('not found', { status: 404 });
      }) as unknown as typeof fetch;

      const env = {
        DB: fakeDashboardDb({ user: dashboardUser, monitor: monitorWithBaseline, alerts: [] }),
      } as Env;

      const res = await app.request('/dashboard', { headers: { Authorization: 'Bearer fake-api-key' } }, env);

      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('new finding');
      expect(html).toContain('since monitoring started');
    });
  });
});

describe('POST /api/monitors/:id/mute', () => {
  const owner: UserRow = {
    id: 1,
    email: 'owner@example.com',
    stripe_customer_id: null,
    stripe_subscription_id: null,
    subscription_status: 'active',
    api_key_hash: 'irrelevant',
    created_at: '2026-08-01T00:00:00.000Z',
  };

  const otherUser: UserRow = {
    id: 2,
    email: 'other@example.com',
    stripe_customer_id: null,
    stripe_subscription_id: null,
    subscription_status: 'active',
    api_key_hash: 'irrelevant',
    created_at: '2026-08-01T00:00:00.000Z',
  };

  const ownedMonitor: MonitorRow = {
    id: 9,
    user_id: 1, // belongs to `owner`, not `otherUser`
    url: 'https://myapp.example.com',
    interval_seconds: 300,
    next_check_at: '2026-08-12T00:10:00.000Z',
    last_check_at: null,
    last_status: null,
    consecutive_failures: 0,
    paused: 0,
    created_at: '2026-08-01T00:00:00.000Z',
    baseline_findings_json: null,
    muted_until: null,
  };

  // `authedAs` is whoever requireAuth's fake api-key lookup resolves to for
  // this request — independent of which monitor row getMonitorById returns —
  // so ownership-mismatch scenarios (a different user's credential hitting
  // someone else's monitor id) are just a matter of passing a different user.
  function fakeMuteDb(opts: { authedAs: UserRow; monitor: MonitorRow | null }): D1Database {
    return {
      prepare: (sql: string) => ({
        bind: () => ({
          first: async <T>() => {
            if (sql.includes('FROM users WHERE api_key_hash')) return opts.authedAs as unknown as T;
            if (sql.startsWith('SELECT * FROM monitors WHERE id')) return opts.monitor as unknown as T;
            return null as unknown as T;
          },
          run: async () => ({ success: true }) as unknown as D1Result,
        }),
      }),
    } as unknown as D1Database;
  }

  const muteRequest = (env: Env, monitorId: number, mute: boolean) =>
    app.request(
      `/api/monitors/${monitorId}/mute`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fake-api-key' },
        body: JSON.stringify({ mute }),
      },
      env
    );

  it('mutes the caller\'s own monitor and returns the new state', async () => {
    const env = { DB: fakeMuteDb({ authedAs: owner, monitor: ownedMonitor }) } as Env;

    const res = await muteRequest(env, 9, true);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { muted: boolean; mutedUntil: string | null };
    expect(body.muted).toBe(true);
    expect(body.mutedUntil).not.toBeNull();
  });

  it('un-mutes when mute:false is sent', async () => {
    const env = { DB: fakeMuteDb({ authedAs: owner, monitor: { ...ownedMonitor, muted_until: '2026-08-13T00:00:00.000Z' } }) } as Env;

    const res = await muteRequest(env, 9, false);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { muted: boolean; mutedUntil: string | null };
    expect(body.muted).toBe(false);
    expect(body.mutedUntil).toBeNull();
  });

  it('returns 404 (not the monitor state) when a different user tries to mute someone else\'s monitor', async () => {
    const env = { DB: fakeMuteDb({ authedAs: otherUser, monitor: ownedMonitor }) } as Env;

    const res = await muteRequest(env, 9, true);

    expect(res.status).toBe(404);
  });

  it('returns 404 when the monitor id does not exist', async () => {
    const env = { DB: fakeMuteDb({ authedAs: owner, monitor: null }) } as Env;

    const res = await muteRequest(env, 999, true);

    expect(res.status).toBe(404);
  });

  it('returns 401 when unauthenticated', async () => {
    const env = { DB: fakeMuteDb({ authedAs: owner, monitor: ownedMonitor }) } as Env;

    const res = await app.request(
      '/api/monitors/9/mute',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mute: true }),
      },
      env
    );

    expect(res.status).toBe(401);
  });
});

// ── Cycle #126: analytics event instrumentation ─────────────────────────────
// Covers: events fire at the right trigger points (and NOT at points that
// don't represent a real funnel step, e.g. a rate-limited or malformed scan
// request), GET /admin/stats' three-state auth contract, and — the
// non-negotiable one — an event-recording failure never breaks the real
// user-facing response it's attached to.
describe('Analytics — event instrumentation (Cycle #126)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Minimal fake D1 for these tests: records every `events` INSERT it sees
  // (event_type + path) and, for the admin-stats tests, answers COUNT(*)
  // queries from a fixed lookup table. Same "branch on the SQL text, not
  // real query semantics" shortcut as every other hand-rolled D1 fake in
  // this file (see fakeMonitorsDb/fakeWebhookDb above).
  function fakeEventsDb(
    opts: { countsByType?: Record<string, number>; activeMonitors?: number; failInsert?: boolean } = {}
  ): { db: D1Database; inserted: Array<{ eventType: string; path: string | null }> } {
    const inserted: Array<{ eventType: string; path: string | null }> = [];
    const db = {
      prepare: (sql: string) => ({
        bind: (...params: unknown[]) => ({
          run: async () => {
            if (sql.includes('INSERT INTO events')) {
              if (opts.failInsert) throw new Error('D1 unavailable');
              inserted.push({ eventType: params[0] as string, path: (params[1] as string | null) ?? null });
            }
            return { success: true } as unknown as D1Result;
          },
          first: async <T>() => {
            if (sql.includes('FROM events')) {
              const eventType = params[0] as string;
              return { count: opts.countsByType?.[eventType] ?? 0 } as unknown as T;
            }
            return null as unknown as T;
          },
        }),
        // countActiveMonitors (src/events.ts) has no bound params, so it
        // calls `.first()` directly on the prepare() result — same
        // zero-param convention as reconcile.ts's fetchKnownStripeCustomerIds.
        first: async <T>() => {
          if (sql.includes('FROM monitors')) {
            return { count: opts.activeMonitors ?? 0 } as unknown as T;
          }
          return null as unknown as T;
        },
      }),
    } as unknown as D1Database;
    return { db, inserted };
  }

  describe('GET / — landing_pageview', () => {
    it('records a landing_pageview event for the real request', async () => {
      const { db, inserted } = fakeEventsDb();
      const { ctx, settle } = fakeCapturingExecutionContext();

      const res = await app.request('/', {}, { DB: db } as Env, ctx);
      expect(res.status).toBe(200);
      await settle();

      expect(inserted).toEqual([{ eventType: 'landing_pageview', path: '/' }]);
    });

    it('still serves the page normally when DB is missing — no crash, no event', async () => {
      const { ctx, settle } = fakeCapturingExecutionContext();

      const res = await app.request('/', {}, {} as Env, ctx);
      expect(res.status).toBe(200);
      expect(await res.text()).toContain('<html');
      await settle();
    });

    it('a failing event write never breaks the real response (and never surfaces as an unhandled rejection)', async () => {
      const { db } = fakeEventsDb({ failInsert: true });
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const { ctx, settle } = fakeCapturingExecutionContext();

      const res = await app.request('/', {}, { DB: db } as Env, ctx);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('<html');

      // The background write rejects internally inside recordEvent()'s own
      // try/catch, which logs and resolves — not something `settle()`
      // (Promise.allSettled) needs to special-case, and specifically NOT a
      // rejection that could have propagated anywhere the response depends
      // on.
      await settle();
      expect(errorSpy).toHaveBeenCalledWith('Failed to record analytics event', 'landing_pageview', expect.any(Error));
    });
  });

  describe('POST /api/scan — scan_submitted', () => {
    it('records scan_submitted once the request clears rate-limiting/parsing, even when the scan itself then fails', async () => {
      const { db, inserted } = fakeEventsDb();
      const { ctx, settle } = fakeCapturingExecutionContext();

      const res = await app.request(
        '/api/scan',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repoUrl: 'not a valid github repo url' }),
        },
        { DB: db } as Env,
        ctx
      );
      expect(res.status).toBe(400); // parseRepoUrl rejects this — the scan attempt itself fails
      await settle();

      expect(inserted).toEqual([{ eventType: 'scan_submitted', path: '/api/scan' }]);
    });

    it('does NOT record scan_submitted when the request is rate-limited', async () => {
      const { db, inserted } = fakeEventsDb();
      const { ctx, settle } = fakeCapturingExecutionContext();
      const env = { DB: db, RATE_LIMIT: createFakeKV() } as Env;
      const ip = 'CF-Connecting-IP-events-1';
      const scanRequest = () =>
        app.request(
          '/api/scan',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
            body: JSON.stringify({ repoUrl: 'acme/widgets' }),
          },
          env,
          ctx
        );

      for (let i = 0; i < SCAN_RATE_LIMIT; i++) await scanRequest();
      inserted.length = 0; // discard the SCAN_RATE_LIMIT allowed attempts' own events

      const res = await scanRequest();
      expect(res.status).toBe(429);
      await settle();

      expect(inserted).toEqual([]);
    });

    it('does NOT record scan_submitted on malformed JSON', async () => {
      const { db, inserted } = fakeEventsDb();
      const { ctx, settle } = fakeCapturingExecutionContext();

      const res = await app.request(
        '/api/scan',
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: 'not json' },
        { DB: db } as Env,
        ctx
      );
      expect(res.status).toBe(400);
      await settle();

      expect(inserted).toEqual([]);
    });
  });

  describe('POST /api/checkout — checkout_started', () => {
    it('records checkout_started once Stripe actually issues a session', async () => {
      global.fetch = vi.fn(async () =>
        jsonResponse({ id: 'cs_test_events', url: 'https://checkout.stripe.com/pay/cs_test_events' })
      ) as unknown as typeof fetch;
      const { db, inserted } = fakeEventsDb();
      const { ctx, settle } = fakeCapturingExecutionContext();
      const env = {
        DB: db,
        STRIPE_SECRET_KEY: 'sk_test_fake',
        STRIPE_WEBHOOK_SECRET: 'whsec_fake',
        STRIPE_PRICE_ID: 'price_123',
      } as Env;

      const res = await app.request(
        '/api/checkout',
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'a@b.com' }) },
        env,
        ctx
      );
      expect(res.status).toBe(200);
      await settle();

      expect(inserted).toEqual([{ eventType: 'checkout_started', path: '/api/checkout' }]);
    });

    it('does NOT record checkout_started when Stripe secrets are missing (503)', async () => {
      const { db, inserted } = fakeEventsDb();
      const { ctx, settle } = fakeCapturingExecutionContext();

      const res = await app.request(
        '/api/checkout',
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
        { DB: db } as Env,
        ctx
      );
      expect(res.status).toBe(503);
      await settle();

      expect(inserted).toEqual([]);
    });

    it('does NOT record checkout_started when Stripe session creation fails (502)', async () => {
      global.fetch = vi.fn(async () => new Response('bad request', { status: 400 })) as unknown as typeof fetch;
      const { db, inserted } = fakeEventsDb();
      const { ctx, settle } = fakeCapturingExecutionContext();
      const env = {
        DB: db,
        STRIPE_SECRET_KEY: 'sk_test_fake',
        STRIPE_WEBHOOK_SECRET: 'whsec_fake',
        STRIPE_PRICE_ID: 'price_123',
      } as Env;

      const res = await app.request(
        '/api/checkout',
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
        env,
        ctx
      );
      expect(res.status).toBe(502);
      await settle();

      expect(inserted).toEqual([]);
    });
  });

  describe('POST /api/stripe/webhook — checkout_completed', () => {
    const webhookSecret = 'whsec_test_events_secret';

    // Duplicated locally rather than imported/exported — same call as the
    // existing 'POST /api/stripe/webhook — email wiring' describe block
    // above (~15 lines, test-only, not worth a shared module for two test
    // files/blocks).
    async function signPayload(payload: string, secret: string, timestamp: number): Promise<string> {
      const signedPayload = `${timestamp}.${payload}`;
      const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
      const hex = Array.from(new Uint8Array(sigBytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      return `t=${timestamp},v1=${hex}`;
    }

    async function postWebhook(env: Env, payload: object, ctx: ExecutionContext): Promise<Response> {
      const body = JSON.stringify(payload);
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = await signPayload(body, webhookSecret, timestamp);
      return app.request(
        '/api/stripe/webhook',
        { method: 'POST', headers: { 'Content-Type': 'application/json', 'Stripe-Signature': signature }, body },
        env,
        ctx
      );
    }

    const checkoutCompletedEvent = {
      type: 'checkout.session.completed',
      data: {
        object: {
          customer: 'cus_EVT1',
          customer_email: 'evt@example.com',
          customer_details: { email: 'evt@example.com' },
          subscription: 'sub_EVT1',
        },
      },
    };

    // Answers upsertUserFromCheckout's INSERT ... RETURNING *, plus whatever
    // else the handler touches on the way (createMagicLink's INSERT,
    // listMonitorsForUser's existence check) with harmless no-op-shaped
    // responses — this describe block only cares about the `events` INSERT,
    // not the rest of the webhook's side effects (covered by the existing
    // 'POST /api/stripe/webhook' describe blocks elsewhere in this file).
    function fakeDb(): { db: D1Database; inserted: Array<{ eventType: string; path: string | null }> } {
      const inserted: Array<{ eventType: string; path: string | null }> = [];
      const db = {
        prepare: (sql: string) => ({
          bind: (...params: unknown[]) => ({
            first: async <T>() => {
              if (sql.includes('INSERT INTO users')) {
                return {
                  id: 77,
                  email: 'evt@example.com',
                  stripe_customer_id: 'cus_EVT1',
                  stripe_subscription_id: 'sub_EVT1',
                  subscription_status: 'active',
                  api_key_hash: null,
                  created_at: '2026-08-13T00:00:00.000Z',
                } as unknown as T;
              }
              return null as unknown as T;
            },
            run: async () => {
              if (sql.includes('INSERT INTO events')) {
                inserted.push({ eventType: params[0] as string, path: (params[1] as string | null) ?? null });
              }
              return { success: true } as unknown as D1Result;
            },
            all: async <T>() => ({ results: [] as unknown as T[] }) as unknown as D1Result<T>,
          }),
        }),
      } as unknown as D1Database;
      return { db, inserted };
    }

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('records checkout_completed once the D1 upsert succeeds', async () => {
      vi.spyOn(console, 'log').mockImplementation(() => {}); // silence the "RESEND_API_KEY missing" TODO log
      const { db, inserted } = fakeDb();
      const { ctx, settle } = fakeCapturingExecutionContext();
      const env = { DB: db, STRIPE_SECRET_KEY: 'sk_test_fake', STRIPE_WEBHOOK_SECRET: webhookSecret } as Env;

      const res = await postWebhook(env, checkoutCompletedEvent, ctx);
      expect(res.status).toBe(200);
      await settle();

      expect(inserted).toEqual([{ eventType: 'checkout_completed', path: '/api/stripe/webhook' }]);
    });

    it('does NOT record checkout_completed when the webhook signature is invalid', async () => {
      const { db, inserted } = fakeDb();
      const { ctx, settle } = fakeCapturingExecutionContext();
      const env = { DB: db, STRIPE_SECRET_KEY: 'sk_test_fake', STRIPE_WEBHOOK_SECRET: webhookSecret } as Env;

      const res = await app.request(
        '/api/stripe/webhook',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Stripe-Signature': 't=1,v1=deadbeef' },
          body: JSON.stringify(checkoutCompletedEvent),
        },
        env,
        ctx
      );
      expect(res.status).toBe(400);
      await settle();

      expect(inserted).toEqual([]);
    });

    it('does NOT record checkout_completed for an unrelated event type', async () => {
      vi.spyOn(console, 'log').mockImplementation(() => {});
      const { db, inserted } = fakeDb();
      const { ctx, settle } = fakeCapturingExecutionContext();
      const env = { DB: db, STRIPE_SECRET_KEY: 'sk_test_fake', STRIPE_WEBHOOK_SECRET: webhookSecret } as Env;

      const res = await postWebhook(env, { type: 'invoice.payment_failed', data: { object: { customer: 'cus_EVT1' } } }, ctx);
      expect(res.status).toBe(200);
      await settle();

      expect(inserted).toEqual([]);
    });
  });

  describe('GET /admin/stats', () => {
    it('returns 503 when ADMIN_STATS_KEY is not configured', async () => {
      const { db } = fakeEventsDb();
      const res = await app.request('/admin/stats', { headers: { Authorization: 'Bearer whatever' } }, { DB: db } as Env);
      expect(res.status).toBe(503);
    });

    it('returns 503 when DB is not configured (even with a key set)', async () => {
      const res = await app.request(
        '/admin/stats',
        { headers: { Authorization: 'Bearer secret-key' } },
        { ADMIN_STATS_KEY: 'secret-key' } as Env
      );
      expect(res.status).toBe(503);
    });

    it('returns 401 when no Authorization header is sent', async () => {
      const { db } = fakeEventsDb();
      const res = await app.request('/admin/stats', {}, { DB: db, ADMIN_STATS_KEY: 'secret-key' } as Env);
      expect(res.status).toBe(401);
    });

    it('returns 401 when the wrong key is sent', async () => {
      const { db } = fakeEventsDb();
      const res = await app.request(
        '/admin/stats',
        { headers: { Authorization: 'Bearer totally-wrong-key' } },
        { DB: db, ADMIN_STATS_KEY: 'secret-key' } as Env
      );
      expect(res.status).toBe(401);
    });

    it('returns 200 with counts when the correct key is sent', async () => {
      const { db } = fakeEventsDb({
        countsByType: { landing_pageview: 10, scan_submitted: 4, checkout_started: 2, checkout_completed: 1 },
        activeMonitors: 3,
      });
      const res = await app.request(
        '/admin/stats',
        { headers: { Authorization: 'Bearer secret-key' } },
        { DB: db, ADMIN_STATS_KEY: 'secret-key' } as Env
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        landingPageviews: { last24h: number; last7d: number; last30d: number };
        scansSubmitted: { last24h: number; last7d: number; last30d: number };
        checkoutStarted: { last24h: number; last7d: number; last30d: number };
        checkoutCompleted: { last24h: number; last7d: number; last30d: number };
        activeMonitors: number;
        generatedAt: string;
      };
      expect(body.landingPageviews).toEqual({ last24h: 10, last7d: 10, last30d: 10 });
      expect(body.scansSubmitted).toEqual({ last24h: 4, last7d: 4, last30d: 4 });
      expect(body.checkoutStarted).toEqual({ last24h: 2, last7d: 2, last30d: 2 });
      expect(body.checkoutCompleted).toEqual({ last24h: 1, last7d: 1, last30d: 1 });
      expect(body.activeMonitors).toBe(3);
      expect(typeof body.generatedAt).toBe('string');
    });
  });
});
