import { describe, it, expect, vi, afterEach } from 'vitest';
import { checkRateLimit, rateLimitKey } from '../src/rateLimit';

// Minimal in-memory stand-in for the one KV surface checkRateLimit actually
// uses (get/put) — same "fake the binding, not the whole SDK" approach as
// the D1/Stripe mocks elsewhere in this test suite.
function createFakeKV(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
    }),
  } as unknown as KVNamespace;
}

describe('checkRateLimit', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows requests under the limit', async () => {
    const kv = createFakeKV();
    for (let i = 0; i < 5; i++) {
      const result = await checkRateLimit(kv, 'ip1:scan', 5, 60);
      expect(result.allowed).toBe(true);
    }
  });

  it('blocks requests once the limit is reached within the same window', async () => {
    const kv = createFakeKV();
    for (let i = 0; i < 3; i++) {
      expect((await checkRateLimit(kv, 'ip1:scan', 3, 60)).allowed).toBe(true);
    }
    // 4th call in the same window exceeds the limit of 3.
    expect((await checkRateLimit(kv, 'ip1:scan', 3, 60)).allowed).toBe(false);
    // Still blocked — a rejected call doesn't reset anything.
    expect((await checkRateLimit(kv, 'ip1:scan', 3, 60)).allowed).toBe(false);
  });

  it('tracks separate keys independently', async () => {
    const kv = createFakeKV();
    for (let i = 0; i < 2; i++) {
      expect((await checkRateLimit(kv, 'ip1:scan', 2, 60)).allowed).toBe(true);
    }
    expect((await checkRateLimit(kv, 'ip1:scan', 2, 60)).allowed).toBe(false);
    // A different key (different IP or route) has its own untouched budget.
    expect((await checkRateLimit(kv, 'ip2:scan', 2, 60)).allowed).toBe(true);
    expect((await checkRateLimit(kv, 'ip1:probe-check', 2, 60)).allowed).toBe(true);
  });

  it('resets once the fixed window rolls over', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-12T00:00:00.000Z'));

    const kv = createFakeKV();
    expect((await checkRateLimit(kv, 'ip1:scan', 1, 60)).allowed).toBe(true);
    expect((await checkRateLimit(kv, 'ip1:scan', 1, 60)).allowed).toBe(false);

    // Jump forward into the next 60s window.
    vi.setSystemTime(new Date('2026-08-12T00:01:05.000Z'));
    expect((await checkRateLimit(kv, 'ip1:scan', 1, 60)).allowed).toBe(true);
  });

  it('always allows through when the KV binding is missing (graceful no-op)', async () => {
    const result = await checkRateLimit(undefined, 'ip1:scan', 0, 60);
    expect(result.allowed).toBe(true);
  });

  it('sets an expirationTtl with headroom past the window', async () => {
    const kv = createFakeKV();
    await checkRateLimit(kv, 'ip1:scan', 5, 60);
    expect(kv.put).toHaveBeenCalledWith(expect.stringContaining('ip1:scan'), '1', { expirationTtl: 70 });
  });
});

describe('rateLimitKey', () => {
  it('combines ip and route', () => {
    expect(rateLimitKey('1.2.3.4', 'scan')).toBe('1.2.3.4:scan');
  });

  it('falls back to a shared unknown-ip bucket when the IP is absent', () => {
    expect(rateLimitKey(undefined, 'scan')).toBe('unknown-ip:scan');
    expect(rateLimitKey(null, 'scan')).toBe('unknown-ip:scan');
    expect(rateLimitKey('', 'scan')).toBe('unknown-ip:scan');
  });

  it('keeps different routes distinct for the same ip', () => {
    expect(rateLimitKey('1.2.3.4', 'scan')).not.toBe(rateLimitKey('1.2.3.4', 'probe-check'));
  });
});
