// SnapOG — Main Cloudflare Worker
// Routes: GET /og (image gen), GET / (landing), GET/POST /register, GET /dashboard

import { Hono } from 'hono';
import type { Context } from 'hono';
import { generateOGImage, buildCacheKey } from './og/render';
import { billingRoutes } from './billing/routes';
import { adminRoutes } from './admin/routes';
import { recordEvent } from './analytics';
import type { EventType } from './analytics';
import {
  landingPage,
  registerPage,
  keyCreatedPage,
  dashboardPage,
  errorPage,
} from './dashboard/pages';
import type { ApiKey, Env, OGParams, Tier } from './types';
import { TIER_LIMITS } from './types';

const app = new Hono<{ Bindings: Env }>();

app.route('/billing', billingRoutes);
app.route('/admin', adminRoutes);

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateRawKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return 'sk_' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// CSP is nonce-based rather than 'unsafe-inline' on script-src: every page
// here ships its JS as an inline <script> block (no framework, no bundler),
// so a blanket 'unsafe-inline' would allow any injected <script> too and
// defeat the point. A fresh nonce per response lets the legitimate inline
// block run while blocking anything an attacker manages to inject. Pages
// with no inline script just ignore the nonce their builder receives.
function htmlResponseWithNonce(build: (nonce: string) => string, status = 200): Response {
  const nonce = crypto.randomUUID();
  return new Response(build(nonce), {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'`,
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

// Validate an API key from request and return the DB row, or null
async function resolveApiKey(
  db: D1Database,
  rawKey: string | null
): Promise<ApiKey | null> {
  if (!rawKey) return null;
  const hash = await sha256(rawKey);
  const row = await db
    .prepare('SELECT * FROM api_keys WHERE key_hash = ?')
    .bind(hash)
    .first<ApiKey>();
  return row ?? null;
}

// Reset monthly usage if billing month rolled over
async function maybeResetUsage(db: D1Database, key: ApiKey): Promise<ApiKey> {
  const resetAt = new Date(key.usage_reset_at);
  const now = new Date();
  const thisMonth = new Date(now.getFullYear(), now.getMonth(), 1);

  if (resetAt < thisMonth) {
    const newResetAt = thisMonth.toISOString();
    await db
      .prepare(
        'UPDATE api_keys SET usage_count = 0, usage_reset_at = ? WHERE id = ?'
      )
      .bind(newResetAt, key.id)
      .run();
    return { ...key, usage_count: 0, usage_reset_at: newResetAt };
  }
  return key;
}

// Atomically attempt to consume one unit of the key's monthly quota via a
// conditional UPDATE, rather than a separate "read usage_count, compare,
// then increment later" sequence. D1/SQLite serializes writes per database,
// so this compare-and-increment is race-free even when many /og requests
// for the same key arrive concurrently — no window where two overlapping
// requests both observe a stale usage_count and both pass the limit check.
// Returns false (no row matched, no increment happened) once the key is
// already at/over its monthly_limit; callers must treat that as "quota
// exhausted" and do no further (expensive) work.
async function tryConsumeUsage(db: D1Database, key: ApiKey): Promise<boolean> {
  const result = await db
    .prepare(
      'UPDATE api_keys SET usage_count = usage_count + 1 WHERE id = ? AND usage_count < monthly_limit'
    )
    .bind(key.id)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

// Record a usage event for analytics/dashboard display only. Quota
// consumption already happened atomically in tryConsumeUsage before this is
// called, so a slow/failed analytics insert can never let a request bypass
// the monthly limit.
async function recordUsageEvent(
  db: D1Database,
  apiKeyId: string,
  template: string,
  cacheHit: boolean
): Promise<void> {
  const eventId = crypto.randomUUID();
  await db
    .prepare(
      'INSERT INTO usage_events (id, api_key_id, template, cache_hit) VALUES (?, ?, ?, ?)'
    )
    .bind(eventId, apiKeyId, template, cacheHit ? 1 : 0)
    .run();
}

// Fire-and-forget top-of-funnel analytics write (see ./analytics.ts and
// migrations/0003_analytics.sql). This must never slow down or fail the
// actual page response it's attached to, so it guards two separate ways
// that could otherwise happen: a failed INSERT (caught via .catch on the
// write itself) and a missing ExecutionContext, e.g. some test harnesses
// call app.request() without one, and c.executionCtx throws just on
// *access* in that case, before waitUntil is even reached (caught via the
// try/catch below).
function trackEvent(c: Context<{ Bindings: Env }>, eventType: EventType, path: string | null = null): void {
  const write = recordEvent(c.env.DB, eventType, path).catch(err => {
    console.error(`Failed to record ${eventType} analytics event:`, err);
  });
  try {
    c.executionCtx.waitUntil(write);
  } catch {
    // No ExecutionContext on this request — the write's own .catch above
    // already means nothing here can throw back into the caller.
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Landing page
app.get('/', c => {
  trackEvent(c, 'landing_pageview', '/');
  const host = new URL(c.req.url).host;
  return htmlResponseWithNonce(nonce => landingPage(host, nonce));
});

// ── OG image generation ────────────────────────────────────────────────────────
app.get('/og', async c => {
  const q = c.req.query();
  const rawKey = q['key'] ?? null;

  // Validate required param
  const title = (q['title'] ?? '').trim().slice(0, 120);
  if (!title) {
    return c.json({ error: 'title parameter is required' }, 400);
  }

  // Resolve API key (required)
  if (!rawKey) {
    return c.json({ error: 'key parameter is required. Get a free key at /register' }, 401);
  }
  let apiKey = await resolveApiKey(c.env.DB, rawKey);
  if (!apiKey) {
    return c.json({ error: 'Invalid API key' }, 401);
  }

  // Reset usage if month rolled
  apiKey = await maybeResetUsage(c.env.DB, apiKey);

  // Atomically claim one unit of quota *before* doing any cache lookup or
  // (expensive) image generation. This must happen up front, not after the
  // response is built — see tryConsumeUsage for why a later/fire-and-forget
  // increment lets concurrent requests race past the monthly limit.
  const withinQuota = await tryConsumeUsage(c.env.DB, apiKey);
  if (!withinQuota) {
    return c.json(
      {
        error: 'Monthly image limit reached',
        tier: apiKey.tier,
        limit: apiKey.monthly_limit,
        upgrade_url: '/register?tier=pro',
      },
      429
    );
  }

  const params: OGParams = {
    title,
    description: (q['description'] ?? '').trim().slice(0, 200) || undefined,
    domain: (q['domain'] ?? '').trim().slice(0, 100) || undefined,
    author: (q['author'] ?? '').trim().slice(0, 80) || undefined,
    tag: (q['tag'] ?? '').trim().slice(0, 40) || undefined,
    theme: (q['theme'] === 'light' ? 'light' : 'dark') as 'dark' | 'light',
    template: (['blog', 'article'].includes(q['template'] ?? '')
      ? q['template']
      : 'default') as OGParams['template'],
  };

  const watermark = apiKey.tier === 'free';
  const cacheKey = await buildCacheKey(params, watermark);
  const r2Key = `og/${cacheKey}.png`;

  // ── R2 cache lookup (skipped entirely if OG_CACHE isn't bound — see Env) ──
  const cached = c.env.OG_CACHE ? await c.env.OG_CACHE.get(r2Key) : null;
  if (cached) {
    // Cache hit — return stored PNG. Quota was already consumed above;
    // this just logs the event for the dashboard's "recent generations".
    await recordUsageEvent(c.env.DB, apiKey.id, params.template ?? 'default', true);
    const imageData = await cached.arrayBuffer();
    return new Response(imageData, {
      headers: {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=86400, s-maxage=604800',
        'X-Cache': 'HIT',
        'X-SnapOG-Tier': apiKey.tier,
      },
    });
  }

  // ── Generate image ──
  const imageResponse = await generateOGImage(params, watermark);
  const imageBuffer = await imageResponse.arrayBuffer();

  // Store in R2 (fire-and-forget, don't block response). No-op if OG_CACHE
  // isn't bound (e.g. a --temporary deploy) — every request is a MISS.
  if (c.env.OG_CACHE) {
    c.executionCtx.waitUntil(
      c.env.OG_CACHE.put(r2Key, imageBuffer.slice(0), {
        httpMetadata: { contentType: 'image/png' },
        customMetadata: { tier: apiKey.tier, template: params.template ?? 'default' },
      })
    );
  }

  // Log the analytics event (fire-and-forget). Quota was already consumed
  // above, before generation started.
  c.executionCtx.waitUntil(
    recordUsageEvent(c.env.DB, apiKey.id, params.template ?? 'default', false)
  );

  return new Response(imageBuffer, {
    headers: {
      'Content-Type': 'image/png',
      'Cache-Control': 'public, max-age=86400, s-maxage=604800',
      'X-Cache': 'MISS',
      'X-SnapOG-Tier': apiKey.tier,
    },
  });
});

// ── Registration ──────────────────────────────────────────────────────────────
app.get('/register', c => {
  trackEvent(c, 'register_pageview', '/register');
  const tier = c.req.query('tier');
  return htmlResponseWithNonce(() => registerPage(undefined, tier));
});

app.post('/register', async c => {
  let email: string, keyname: string, requestedTier: string;
  try {
    const form = await c.req.formData();
    email = (form.get('email') as string ?? '').trim().toLowerCase();
    keyname = (form.get('keyname') as string ?? '').trim() || 'default';
    // `tier` here is NEVER trusted to set the actual tier — see safeTier
    // below. It's only used to decide which upsell CTA to show on the
    // key-created page (e.g. someone who clicked "Start Pro" still sees a
    // "continue to checkout" button after their free key is created).
    requestedTier = (form.get('tier') as string ?? 'free').trim();
  } catch {
    return htmlResponseWithNonce(() => registerPage('Invalid form data'), 400);
  }

  // Excludes HTML metacharacters in addition to whitespace/@ — defense in
  // depth alongside escapeHtml() at every render site (keyCreatedPage),
  // since the original pattern happily accepted a local-part like
  // `<script>alert(1)</script>` as a "valid" email.
  if (!email || !/^[^\s@<>"'&]+@[^\s@<>"'&]+\.[^\s@<>"'&]+$/.test(email)) {
    return htmlResponseWithNonce(() => registerPage('Please enter a valid email address', requestedTier), 400);
  }

  // Every key created here is 'free', full stop. Paid tiers are only ever
  // granted by the Stripe webhook (src/billing/routes.ts) after a real
  // subscription is confirmed — this used to trust a client-submitted
  // `tier` form field directly, which meant anyone could POST `tier=business`
  // and get a paid tier for free. `requestedTier` above is display-only.
  const safeTier: Tier = 'free';
  const upsellTier: Tier | undefined =
    requestedTier === 'pro' || requestedTier === 'business' ? requestedTier : undefined;

  // Upsert user
  const userId = crypto.randomUUID();
  await c.env.DB
    .prepare(
      'INSERT INTO users (id, email) VALUES (?, ?) ON CONFLICT(email) DO NOTHING'
    )
    .bind(userId, email)
    .run();

  const user = await c.env.DB
    .prepare('SELECT id FROM users WHERE email = ?')
    .bind(email)
    .first<{ id: string }>();
  if (!user) {
    return htmlResponseWithNonce(() => registerPage('Database error — please try again'), 500);
  }

  // Generate API key
  const rawKey = generateRawKey();
  const keyHash = await sha256(rawKey);
  const keyPrefix = rawKey.slice(0, 12);
  const keyId = crypto.randomUUID();
  const resetAt = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();
  const monthlyLimit = TIER_LIMITS[safeTier];

  await c.env.DB
    .prepare(
      `INSERT INTO api_keys
         (id, user_id, name, key_prefix, key_hash, tier, monthly_limit, usage_reset_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(keyId, user.id, keyname, keyPrefix, keyHash, safeTier, monthlyLimit, resetAt)
    .run();

  // Fires only once a new API key has actually been created — not on every
  // hit to this handler, and not on the earlier 400/500 returns above.
  trackEvent(c, 'signup', '/register');

  return htmlResponseWithNonce(nonce => keyCreatedPage(rawKey, email, safeTier, nonce, upsellTier));
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/dashboard', async c => {
  const rawKey = c.req.query('key');
  if (!rawKey) {
    return htmlResponseWithNonce(() => registerPage('Enter your API key or create a new one below'), 400);
  }

  const apiKey = await resolveApiKey(c.env.DB, rawKey);
  if (!apiKey) {
    return htmlResponseWithNonce(() => errorPage(404, 'API key not found'), 404);
  }

  const refreshed = await maybeResetUsage(c.env.DB, apiKey);

  // Count recent events (last 24h)
  const yesterday = new Date(Date.now() - 86_400_000).toISOString();
  const recent = await c.env.DB
    .prepare(
      'SELECT COUNT(*) as cnt FROM usage_events WHERE api_key_id = ? AND generated_at > ?'
    )
    .bind(refreshed.id, yesterday)
    .first<{ cnt: number }>();

  return htmlResponseWithNonce(() => dashboardPage(refreshed, recent?.cnt ?? 0, rawKey));
});

// ── Health / ops ──────────────────────────────────────────────────────────────
app.get('/health', c => c.json({ ok: true, ts: new Date().toISOString() }));

// 404 fallback
app.notFound(_c => htmlResponseWithNonce(() => errorPage(404, 'Page not found'), 404));
app.onError((err, _c) => {
  console.error('Unhandled error:', err);
  return htmlResponseWithNonce(() => errorPage(500, 'Internal server error'), 500);
});

export default app;
