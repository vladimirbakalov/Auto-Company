// Same route-level coverage as test/index.test.ts, but running inside real
// workerd (via @cloudflare/vitest-pool-workers) against a real local D1
// instance with the actual migrations/0001_init.sql applied, and a real
// R2 binding — not the hand-rolled FakeD1/fakeR2 stand-ins. This exists to
// catch drift between the mocks' assumed SQL semantics (UNIQUE/FK
// constraints, ON CONFLICT, column defaults) and what real D1/SQLite
// actually enforces. Run via `npm run test:workers`; kept separate from
// the default `npm test` suite so day-to-day runs stay workerd-free and
// fast. generateOGImage is still mocked — workers-og's WASM rendering
// path is covered separately (see the comment in test/index.test.ts) and
// isn't the concern this file is validating.
import { env, exports } from 'cloudflare:workers';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const SELF = exports.default;

const { generateOGImageMock } = vi.hoisted(() => ({
  generateOGImageMock: vi.fn(async (_params: unknown, _watermark: boolean) => {
    return new Response(new Uint8Array([1, 2, 3]).buffer);
  }),
}));

vi.mock('../src/og/render', async importOriginal => {
  const actual = await importOriginal<typeof import('../src/og/render')>();
  return { ...actual, generateOGImage: generateOGImageMock };
});

function extractKey(html: string): string {
  const match = html.match(/sk_[0-9a-f]{64}/);
  if (!match) throw new Error('no API key found in register response HTML');
  return match[0];
}

async function registerKey(tier = 'free'): Promise<string> {
  const res = await SELF.fetch('https://snapog.test/register', {
    method: 'POST',
    body: new URLSearchParams({ email: `dev-${crypto.randomUUID()}@example.com`, keyname: 'ci', tier }),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  expect(res.status).toBe(200);
  return extractKey(await res.text());
}

describe('snapog routes (real D1 + R2 via workerd)', () => {
  beforeEach(() => {
    generateOGImageMock.mockClear();
  });

  it('GET /health returns ok', async () => {
    const res = await SELF.fetch('https://snapog.test/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true });
  });

  it('creates a user + API key against real D1, honoring column defaults', async () => {
    const rawKey = await registerKey('free');
    expect(rawKey).toMatch(/^sk_[0-9a-f]{64}$/);

    const hash = Array.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawKey)))
    )
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const row = await env.DB.prepare('SELECT * FROM api_keys WHERE key_hash = ?').bind(hash).first<{
      tier: string;
      monthly_limit: number;
      usage_count: number;
    }>();
    expect(row?.tier).toBe('free');
    expect(row?.monthly_limit).toBe(100);
    expect(row?.usage_count).toBe(0); // real column DEFAULT 0, not a mock's assumption
  });

  it('enforces the real UNIQUE(email) constraint via ON CONFLICT DO NOTHING (upsert, not duplicate insert)', async () => {
    const email = `dup-${crypto.randomUUID()}@example.com`;
    for (const keyname of ['one', 'two']) {
      const res = await SELF.fetch('https://snapog.test/register', {
        method: 'POST',
        body: new URLSearchParams({ email, keyname }),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      expect(res.status).toBe(200);
    }
    const { results } = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).all();
    expect(results.length).toBe(1); // real UNIQUE constraint held, no duplicate row
  });

  it('round-trips an OG image through the real R2 binding (MISS then HIT)', async () => {
    const rawKey = await registerKey('free');

    const first = await SELF.fetch(`https://snapog.test/og?title=Hello&key=${rawKey}`);
    expect(first.status).toBe(200);
    expect(first.headers.get('X-Cache')).toBe('MISS');

    // give the fire-and-forget R2 put (via waitUntil) a tick to land
    await env.DB.prepare('SELECT 1').first();

    const second = await SELF.fetch(`https://snapog.test/og?title=Hello&key=${rawKey}`);
    expect(second.status).toBe(200);
    expect(second.headers.get('X-Cache')).toBe('HIT'); // served from real R2, not regenerated
  });

  it('returns 429 once the real usage_count column reaches monthly_limit', async () => {
    const rawKey = await registerKey('free');
    const hash = Array.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawKey)))
    )
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    await env.DB.prepare('UPDATE api_keys SET usage_count = monthly_limit WHERE key_hash = ?').bind(hash).run();

    const res = await SELF.fetch(`https://snapog.test/og?title=Hello&key=${rawKey}`);
    expect(res.status).toBe(429);
  });
});
