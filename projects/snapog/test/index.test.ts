// Route-level tests via Hono's app.request() (no server needed). Mirrors
// vibecheck's test/index.test.ts pattern: prepare(sql) branches on the SQL
// text against a small in-memory D1/R2 stand-in rather than mocking the
// Cloudflare SDK. generateOGImage is mocked out (workers-og needs the
// Workers/WASM runtime, which plain vitest doesn't provide) — buildCacheKey
// and buildElement, the two pure pieces it depends on, are covered directly
// in render.test.ts / templates.test.ts.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Env, ApiKey, Tier } from '../src/types';

// vi.mock's factory is hoisted above all imports/const declarations, so the
// mock fn itself must be created via vi.hoisted() to be visible inside it.
const { generateOGImageMock } = vi.hoisted(() => ({
  generateOGImageMock: vi.fn(async (_params: unknown, _watermark: boolean) => {
    return new Response(new Uint8Array([1, 2, 3]).buffer);
  }),
}));

vi.mock('../src/og/render', async importOriginal => {
  const actual = await importOriginal<typeof import('../src/og/render')>();
  return { ...actual, generateOGImage: generateOGImageMock };
});

// Static import after vi.mock — Vitest hoists vi.mock calls above imports,
// so `app` below already resolves against the mocked render module.
import app from '../src/index';

function fakeExecutionContext(): ExecutionContext {
  return { waitUntil: () => {}, passThroughOnException: () => {}, props: {} } as unknown as ExecutionContext;
}

interface ApiKeyRow extends ApiKey {}

// Minimal, stateful in-memory stand-in for the D1 surface src/index.ts
// actually uses — real upsert/increment semantics, not canned responses,
// since usage-limit and month-rollover behavior depends on state mutating
// across calls within a single test.
class FakeD1 {
  usersByEmail = new Map<string, { id: string; email: string }>();
  apiKeys = new Map<string, ApiKeyRow>();
  usageEvents: Array<{ id: string; api_key_id: string; template: string; cache_hit: number; generated_at: string }> = [];
  events: Array<{ id: string; event_type: string; path: string | null }> = [];
  // Test-only escape hatch for the "broken INSERT must not break the page
  // response" case below — real D1 doesn't have a flag like this, a real
  // failure would be e.g. a transient network error or schema drift.
  failEventsInsert = false;

  prepare(sql: string) {
    const self = this;
    return {
      bind(...args: unknown[]) {
        return {
          async first<T>(): Promise<T | null> {
            if (sql.includes('SELECT * FROM api_keys WHERE key_hash')) {
              const hash = args[0] as string;
              const row = [...self.apiKeys.values()].find(k => k.key_hash === hash);
              return (row ?? null) as unknown as T;
            }
            if (sql.includes('SELECT id FROM users WHERE email')) {
              const email = args[0] as string;
              const u = self.usersByEmail.get(email);
              return (u ? { id: u.id } : null) as unknown as T;
            }
            if (sql.includes('SELECT COUNT(*) as cnt FROM usage_events')) {
              const [apiKeyId, since] = args as [string, string];
              const cnt = self.usageEvents.filter(
                e => e.api_key_id === apiKeyId && e.generated_at > since
              ).length;
              return { cnt } as unknown as T;
            }
            return null;
          },
          async run() {
            if (sql.includes('INSERT INTO users')) {
              const [id, email] = args as [string, string];
              if (!self.usersByEmail.has(email)) self.usersByEmail.set(email, { id, email });
            } else if (sql.includes('INSERT INTO api_keys')) {
              const [id, user_id, name, key_prefix, key_hash, tier, monthly_limit, usage_reset_at] =
                args as [string, string, string, string, string, Tier, number, string];
              self.apiKeys.set(id, {
                id,
                user_id,
                name,
                key_prefix,
                key_hash,
                tier,
                monthly_limit,
                usage_count: 0,
                usage_reset_at,
                created_at: new Date().toISOString(),
              });
            } else if (sql.includes('UPDATE api_keys SET usage_count = 0')) {
              const [newResetAt, id] = args as [string, string];
              const k = self.apiKeys.get(id);
              if (k) {
                k.usage_count = 0;
                k.usage_reset_at = newResetAt;
              }
            } else if (sql.includes('UPDATE api_keys SET usage_count = usage_count + 1')) {
              // Mirrors the real conditional UPDATE in src/index.ts
              // (`... WHERE id = ? AND usage_count < monthly_limit`) and its
              // meta.changes contract: only increments — and only reports a
              // change — when the key is still under quota. tryConsumeUsage
              // relies on meta.changes to detect "quota exhausted".
              const [id] = args as [string];
              const k = self.apiKeys.get(id);
              let changes = 0;
              if (k && k.usage_count < k.monthly_limit) {
                k.usage_count += 1;
                changes = 1;
              }
              return { success: true, meta: { changes } };
            } else if (sql.includes('INSERT INTO usage_events')) {
              const [id, api_key_id, template, cache_hit] = args as [string, string, string, number];
              self.usageEvents.push({
                id,
                api_key_id,
                template,
                cache_hit,
                generated_at: new Date().toISOString(),
              });
            } else if (sql.includes('INSERT INTO events')) {
              if (self.failEventsInsert) {
                throw new Error('simulated D1 failure recording analytics event');
              }
              const [id, event_type, path] = args as [string, string, string | null];
              self.events.push({ id, event_type, path });
            }
            return { success: true };
          },
        };
      },
    };
  }

  async batch(statements: Array<{ run: () => Promise<unknown> }>) {
    const results = [];
    for (const stmt of statements) results.push(await stmt.run());
    return results;
  }
}

function fakeR2(): R2Bucket {
  const store = new Map<string, ArrayBuffer>();
  return {
    get: async (key: string) => {
      const data = store.get(key);
      if (!data) return null;
      return { arrayBuffer: async () => data } as unknown as R2ObjectBody;
    },
    put: async (key: string, value: ArrayBuffer) => {
      store.set(key, value);
    },
  } as unknown as R2Bucket;
}

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

describe('snapog routes', () => {
  let db: FakeD1;
  let env: Env;

  beforeEach(() => {
    db = new FakeD1();
    env = { DB: db as unknown as Env['DB'], ENVIRONMENT: 'test' } as Env;
    generateOGImageMock.mockClear();
  });

  async function registerKey(tier: Tier = 'free'): Promise<string> {
    const res = await app.request(
      '/register',
      {
        method: 'POST',
        body: new URLSearchParams({ email: 'dev@example.com', keyname: 'ci', tier }),
      },
      env
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    const match = html.match(/sk_[0-9a-f]{64}/);
    if (!match) throw new Error('no API key found in register response HTML');
    return match[0];
  }

  it('GET /health returns ok', async () => {
    const res = await app.request('/health', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ ok: true });
  });

  it('GET / returns the landing page', async () => {
    const res = await app.request('/', {}, env);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
  });

  it('GET / sets a nonce-based CSP header matching the inline script tag', async () => {
    // CSP is nonce-based (script-src has no 'unsafe-inline') since the page
    // ships its interactivity as an inline <script>: the header's nonce must
    // match the one on the tag, or the copy-to-clipboard button silently
    // breaks. Also guards against a future regression back to no CSP at all
    // (finding #5 of docs/qa/snapog-security-audit-cycle121.md).
    const res = await app.request('/', {}, env);
    const csp = res.headers.get('Content-Security-Policy');
    expect(csp).toContain("script-src 'self' 'nonce-");
    expect(csp).toContain("default-src 'self'");
    const nonce = csp?.match(/'nonce-([^']+)'/)?.[1];
    expect(nonce).toBeTruthy();
    const html = await res.text();
    expect(html).toContain(`<script nonce="${nonce}">`);
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
  });

  it('unknown route returns 404', async () => {
    const res = await app.request('/does-not-exist', {}, env);
    expect(res.status).toBe(404);
  });

  describe('top-of-funnel analytics (migrations/0003_analytics.sql)', () => {
    it('GET / records a landing_pageview event', async () => {
      const res = await app.request('/', {}, env);
      expect(res.status).toBe(200);
      expect(db.events).toHaveLength(1);
      expect(db.events[0]).toMatchObject({ event_type: 'landing_pageview', path: '/' });
    });

    it('GET /register records a register_pageview event', async () => {
      const res = await app.request('/register', {}, env);
      expect(res.status).toBe(200);
      expect(db.events).toHaveLength(1);
      expect(db.events[0]).toMatchObject({ event_type: 'register_pageview', path: '/register' });
    });

    it('POST /register records a signup event only after a key is actually created, not on a 400', async () => {
      const badRes = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'not-an-email' }) },
        env
      );
      expect(badRes.status).toBe(400);
      expect(db.events).toHaveLength(0); // no signup logged for the rejected submission

      const okRes = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'funnel@example.com', keyname: 'ci' }) },
        env
      );
      expect(okRes.status).toBe(200);
      expect(db.events).toHaveLength(1);
      expect(db.events[0]).toMatchObject({ event_type: 'signup', path: '/register' });
    });

    it('does not record a duplicate signup event per hit — one per successful POST /register only', async () => {
      await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'a@example.com', keyname: 'one' }) },
        env
      );
      await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'b@example.com', keyname: 'two' }) },
        env
      );
      const signups = db.events.filter(e => e.event_type === 'signup');
      expect(signups).toHaveLength(2);
    });

    it('a failed analytics INSERT never turns into a 500 on the landing page (fire-and-forget resilience)', async () => {
      db.failEventsInsert = true;
      const res = await app.request('/', {}, env);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/html');
      // The write was attempted and rejected — just never surfaced to the response.
      expect(db.events).toHaveLength(0);
    });

    it('a failed analytics INSERT never turns into a 500 on POST /register either', async () => {
      db.failEventsInsert = true;
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'resilient@example.com', keyname: 'ci' }) },
        env
      );
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toMatch(/sk_[0-9a-f]{64}/); // key was still created despite the analytics failure
    });
  });

  describe('POST /register', () => {
    it('rejects an invalid email', async () => {
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'not-an-email' }) },
        env
      );
      expect(res.status).toBe(400);
    });

    // registerPage()'s `error ?` branch (dashboard/pages.ts) was only ever
    // exercised for its status code above, never for the actual alert-error
    // markup/message it's supposed to render.
    it('renders the validation error message in the alert-error div', async () => {
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'not-an-email' }) },
        env
      );
      const html = await res.text();
      expect(html).toContain('alert alert-error');
      expect(html).toContain('Please enter a valid email address');
    });

    it('creates a user + API key on valid submission', async () => {
      const rawKey = await registerKey('free');
      expect(rawKey).toMatch(/^sk_[0-9a-f]{64}$/);
      const hash = await sha256(rawKey);
      const stored = [...db.apiKeys.values()].find(k => k.key_hash === hash);
      expect(stored?.tier).toBe('free');
      expect(stored?.monthly_limit).toBe(100);
    });

    it('the key-created page also carries a nonce-based CSP matching its inline script', async () => {
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'dev@example.com', keyname: 'ci', tier: 'free' }) },
        env
      );
      expect(res.status).toBe(200);
      const csp = res.headers.get('Content-Security-Policy');
      const nonce = csp?.match(/'nonce-([^']+)'/)?.[1];
      expect(nonce).toBeTruthy();
      const html = await res.text();
      expect(html).toContain(`<script nonce="${nonce}">`);
    });

    it('falls back to the free tier for an invalid tier value', async () => {
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'x@example.com', tier: 'enterprise' }) },
        env
      );
      expect(res.status).toBe(200);
      const [key] = [...db.apiKeys.values()];
      expect(key.tier).toBe('free');
    });

    it('always creates a free-tier key, ignoring a client-submitted "pro"/"business" tier field', async () => {
      // Regression test for the exact gap this cycle closes: POST /register
      // used to trust `tier` straight from the form body, so anyone could
      // POST tier=business and get a paid tier for free. Now the only path
      // that may write a tier above 'free' is the Stripe webhook
      // (src/billing/routes.ts), after a real subscription is confirmed.
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'payer@example.com', tier: 'business' }) },
        env
      );
      expect(res.status).toBe(200);
      const [key] = [...db.apiKeys.values()];
      expect(key.tier).toBe('free');
      expect(key.monthly_limit).toBe(100);
    });

    // keyCreatedPage()'s upsell block (dashboard/pages.ts) never appeared in
    // any prior assertion — only its absence was implied by other tests
    // never checking for it. `tier=pro`/`tier=business` on the register form
    // is display-only (the created key is always free), but should still
    // surface a "continue to checkout" upsell naming the requested tier.
    it('shows a Pro-specific upsell block when the register form requested tier=pro', async () => {
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'upsell-pro@example.com', tier: 'pro' }) },
        env
      );
      const html = await res.text();
      expect(html).toContain('Continue to PRO');
      expect(html).toContain('10,000 images/month');
      expect(html).toContain('Subscribe to Pro');
    });

    it('shows a Business-specific upsell block when the register form requested tier=business', async () => {
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'upsell-biz@example.com', tier: 'business' }) },
        env
      );
      const html = await res.text();
      expect(html).toContain('Continue to BUSINESS');
      expect(html).toContain('100,000 images/month');
      expect(html).toContain('Subscribe to Business');
    });

    it('shows no upsell block when the register form did not request a paid tier', async () => {
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'no-upsell@example.com' }) },
        env
      );
      const html = await res.text();
      expect(html).not.toContain('Continue to');
      expect(html).not.toContain('Subscribe to');
    });

    it('reuses the existing user on a duplicate email (upsert, not duplicate insert)', async () => {
      await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'dup@example.com', keyname: 'one' }) },
        env
      );
      await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: 'dup@example.com', keyname: 'two' }) },
        env
      );
      expect(db.usersByEmail.size).toBe(1);
      expect(db.apiKeys.size).toBe(2); // two keys, same user
    });

    it('rejects an email whose local part carries HTML metacharacters', async () => {
      // Belt-and-suspenders alongside the escapeHtml() fix below: the email
      // regex itself should reject this, not just rely on render-time escaping.
      const res = await app.request(
        '/register',
        { method: 'POST', body: new URLSearchParams({ email: '<script>alert(1)</script>@evil.com' }) },
        env
      );
      expect(res.status).toBe(400);
    });

    it('keyCreatedPage() escapes the email before echoing it back', async () => {
      // Regression test for the render-time defense-in-depth layer,
      // independent of the route-level regex tightened above: even if a
      // malicious-looking-but-technically-valid email ever slipped past
      // validation (or the regex regresses in a future change), the render
      // function itself must not emit it unescaped. Calls keyCreatedPage()
      // directly so this doesn't depend on the /register regex's current
      // strictness.
      const { keyCreatedPage } = await import('../src/dashboard/pages');
      const html = keyCreatedPage('sk_deadbeef', '"><img src=x onerror=alert(1)>@evil.com', 'free', 'test-nonce');
      expect(html).not.toContain('<img src=x onerror=alert(1)>');
      expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    });
  });

  describe('GET /register', () => {
    it('escapes a malicious tier query param instead of reflecting it raw', async () => {
      // Regression test: GET /register?tier=... used to interpolate `tier`
      // straight into a `value="..."` HTML attribute unescaped, so a value
      // like `"><script>...` broke out of the attribute and injected a
      // script tag — a plain, unauthenticated reflected-XSS link, no form
      // submission needed. Assert the raw payload never appears in the
      // response and the escaped form does.
      const payload = '"><script>alert(document.cookie)</script>';
      const res = await app.request(`/register?tier=${encodeURIComponent(payload)}`, {}, env);
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).not.toContain('<script>alert(document.cookie)</script>');
      expect(body).toContain('&lt;script&gt;');
    });
  });

  describe('GET /og', () => {
    it('requires a title', async () => {
      const res = await app.request('/og?key=sk_x', {}, env, fakeExecutionContext());
      expect(res.status).toBe(400);
    });

    it('requires a key', async () => {
      const res = await app.request('/og?title=Hello', {}, env, fakeExecutionContext());
      expect(res.status).toBe(401);
    });

    it('rejects an invalid key', async () => {
      const res = await app.request('/og?title=Hello&key=sk_invalid', {}, env, fakeExecutionContext());
      expect(res.status).toBe(401);
    });

    it('generates and caches an image on a cold cache (MISS)', async () => {
      const rawKey = await registerKey('free');
      env.OG_CACHE = fakeR2();

      const res = await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());

      expect(res.status).toBe(200);
      expect(res.headers.get('X-Cache')).toBe('MISS');
      expect(res.headers.get('Content-Type')).toBe('image/png');
      expect(generateOGImageMock).toHaveBeenCalledTimes(1);
      // free tier -> watermark=true
      expect(generateOGImageMock.mock.calls[0][1]).toBe(true);
    });

    it('serves from R2 on a warm cache (HIT) without regenerating', async () => {
      const rawKey = await registerKey('free');
      env.OG_CACHE = fakeR2();

      await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());
      generateOGImageMock.mockClear();
      const res = await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());

      expect(res.status).toBe(200);
      expect(res.headers.get('X-Cache')).toBe('HIT');
      expect(generateOGImageMock).not.toHaveBeenCalled();
    });

    it('degrades to always-MISS when OG_CACHE is unbound (e.g. --temporary deploy)', async () => {
      const rawKey = await registerKey('free');
      // env.OG_CACHE intentionally left undefined

      const first = await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());
      const second = await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());

      expect(first.headers.get('X-Cache')).toBe('MISS');
      expect(second.headers.get('X-Cache')).toBe('MISS');
      expect(generateOGImageMock).toHaveBeenCalledTimes(2);
    });

    it('omits the watermark for a paid tier', async () => {
      // Paid tiers can no longer be granted via the /register form (see the
      // "always creates a free-tier key" test below) — simulate the state a
      // real Stripe webhook-driven upgrade would leave behind by mutating
      // the stored row directly, same pattern as the 429/reset tests below.
      const rawKey = await registerKey('free');
      const hash = await sha256(rawKey);
      const key = [...db.apiKeys.values()].find(k => k.key_hash === hash)!;
      key.tier = 'pro';

      await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());
      expect(generateOGImageMock.mock.calls[0][1]).toBe(false);
    });

    it('returns 429 once the monthly limit is reached', async () => {
      const rawKey = await registerKey('free');
      const hash = await sha256(rawKey);
      const key = [...db.apiKeys.values()].find(k => k.key_hash === hash)!;
      key.usage_count = key.monthly_limit; // simulate limit already hit

      const res = await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());
      expect(res.status).toBe(429);
      const body = await res.json();
      expect(body).toMatchObject({ tier: 'free', limit: 100 });
    });

    it('resets usage when the billing month has rolled over', async () => {
      const rawKey = await registerKey('free');
      const hash = await sha256(rawKey);
      const key = [...db.apiKeys.values()].find(k => k.key_hash === hash)!;
      key.usage_count = key.monthly_limit;
      key.usage_reset_at = '2020-01-01T00:00:00.000Z'; // long-past month

      const res = await app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext());
      expect(res.status).toBe(200); // limit no longer exceeded post-reset
    });

    it('truncates an overlong title to 120 chars', async () => {
      const rawKey = await registerKey('free');
      const longTitle = 'x'.repeat(200);
      await app.request(`/og?title=${longTitle}&key=${rawKey}`, {}, env, fakeExecutionContext());
      const paramsArg = generateOGImageMock.mock.calls[0][0] as { title: string };
      expect(paramsArg.title.length).toBe(120);
    });

    it('does not let concurrent requests race past the monthly limit', async () => {
      // Regression test for the TOCTOU quota bug: the old code read
      // usage_count once at the top of the handler and only incremented it
      // later (after image generation, via a fire-and-forget waitUntil), so
      // N concurrent requests could all observe the same under-limit
      // usage_count and all be allowed through — a single key could
      // generate unbounded images by firing requests concurrently instead
      // of sequentially. tryConsumeUsage() now does an atomic conditional
      // UPDATE up front, so exactly one slot's worth of requests should
      // succeed no matter how many arrive at once.
      const rawKey = await registerKey('free');
      const hash = await sha256(rawKey);
      const key = [...db.apiKeys.values()].find(k => k.key_hash === hash)!;
      key.usage_count = key.monthly_limit - 1; // exactly one slot left

      const results = await Promise.all(
        Array.from({ length: 5 }, () =>
          app.request(`/og?title=Hello&key=${rawKey}`, {}, env, fakeExecutionContext())
        )
      );

      const succeeded = results.filter(r => r.status === 200);
      const limited = results.filter(r => r.status === 429);
      expect(succeeded.length).toBe(1);
      expect(limited.length).toBe(4);
      expect(key.usage_count).toBe(key.monthly_limit); // never exceeded, never under-counted
    });
  });

  describe('GET /dashboard', () => {
    it('requires a key', async () => {
      const res = await app.request('/dashboard', {}, env);
      expect(res.status).toBe(400);
    });

    it('404s on an unknown key', async () => {
      const res = await app.request('/dashboard?key=sk_nope', {}, env);
      expect(res.status).toBe(404);
    });

    it('renders for a valid key', async () => {
      const rawKey = await registerKey('free');
      const res = await app.request(`/dashboard?key=${rawKey}`, {}, env);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/html');
    });

    it('shows the upgrade CTA but no billing-portal link for a free-tier key', async () => {
      const rawKey = await registerKey('free');
      const res = await app.request(`/dashboard?key=${rawKey}`, {}, env);
      const html = await res.text();
      expect(html).toContain('Upgrade to Pro');
      expect(html).not.toContain('/billing/portal');
    });

    it('shows the billing-portal link but no upgrade CTA for a paid-tier key', async () => {
      // Paid tiers only ever come from a Stripe webhook (see the "always
      // creates a free-tier key" test above) — simulate that state by
      // mutating the stored row directly, same pattern used for the
      // watermark/quota tests above.
      const rawKey = await registerKey('free');
      const hash = await sha256(rawKey);
      const key = [...db.apiKeys.values()].find(k => k.key_hash === hash)!;
      key.tier = 'pro';

      const res = await app.request(`/dashboard?key=${rawKey}`, {}, env);
      const html = await res.text();
      expect(html).toContain('Manage billing');
      expect(html).toContain('/billing/portal?key=');
      expect(html).not.toContain('Upgrade to Pro');
    });

    it('flags the usage bar as "full" once the monthly limit is reached', async () => {
      const rawKey = await registerKey('free');
      const hash = await sha256(rawKey);
      const key = [...db.apiKeys.values()].find(k => k.key_hash === hash)!;
      key.usage_count = key.monthly_limit;

      const res = await app.request(`/dashboard?key=${rawKey}`, {}, env);
      const html = await res.text();
      expect(html).toContain('usage-bar full');
      expect(html).toContain('100% used');
    });

    it('flags the usage bar as "warn" past 80% but not yet full', async () => {
      const rawKey = await registerKey('free');
      const hash = await sha256(rawKey);
      const key = [...db.apiKeys.values()].find(k => k.key_hash === hash)!;
      key.usage_count = Math.round(key.monthly_limit * 0.85);

      const res = await app.request(`/dashboard?key=${rawKey}`, {}, env);
      const html = await res.text();
      expect(html).toContain('usage-bar warn');
      expect(html).not.toContain('usage-bar full');
    });
  });
});
