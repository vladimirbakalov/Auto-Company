import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { probeUrl, probeSensitivePaths, SENSITIVE_PATHS } from '../src/probe';
import { SECRET_PATTERNS } from '../src/checks';

function jsonHeaders(extra: Record<string, string> = {}): Headers {
  return new Headers({ 'content-type': 'application/json', ...extra });
}

// Builds a Response with a real ReadableStream body so readTextBounded's
// streaming byte-cap logic is exercised, not bypassed via res.text().
function streamedResponse(body: string, init: { status?: number; headers?: Headers; url?: string } = {}): Response {
  const bytes = new TextEncoder().encode(body);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  const res = new Response(stream, { status: init.status ?? 200, headers: init.headers });
  if (init.url) {
    Object.defineProperty(res, 'url', { value: init.url });
  }
  return res;
}

describe('probeUrl', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = originalFetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  it('returns ok:true with status/latency/headers/body on a successful probe', async () => {
    global.fetch = vi.fn(async () =>
      streamedResponse('{"hello":"world"}', {
        status: 200,
        headers: jsonHeaders({ 'access-control-allow-origin': '*' }),
        url: 'https://example.com/',
      })
    ) as unknown as typeof fetch;

    const result = await probeUrl('https://example.com');

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.error).toBeNull();
    expect(result.headers['access-control-allow-origin']).toBe('*');
    expect(result.bodySnippet).toBe('{"hello":"world"}');
    expect(result.finalUrl).toBe('https://example.com/');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('reports a timeout as ok:false with a null status', async () => {
    global.fetch = vi.fn((_url: string, init?: RequestInit) => {
      return new Promise((_resolve, reject) => {
        const signal = init?.signal;
        signal?.addEventListener('abort', () => {
          const err = new Error('The operation was aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    }) as unknown as typeof fetch;

    const result = await probeUrl('https://slow.example.com', { timeoutMs: 5 });

    expect(result.ok).toBe(false);
    expect(result.status).toBeNull();
    expect(result.error).toBe('Request timed out');
  });

  it('treats a non-200 status as a reachable ("ok") probe, not a failure', async () => {
    global.fetch = vi.fn(async () =>
      streamedResponse('Internal Server Error', { status: 500, headers: jsonHeaders() })
    ) as unknown as typeof fetch;

    const result = await probeUrl('https://example.com', { path: '/broken' });

    expect(result.ok).toBe(true);
    expect(result.status).toBe(500);
    expect(result.error).toBeNull();
  });

  it('surfaces secret-shaped content in a sensitive-path response body', async () => {
    // Stripe live secret key shape — matches an existing SECRET_PATTERNS entry.
    const leaked = 'STRIPE_KEY=sk_' + 'live_abcdefghijklmnopqrstuvwx';
    global.fetch = vi.fn(async (input: RequestInit | string | URL) => {
      const url = String(input);
      if (url.endsWith('/.env')) {
        return streamedResponse(leaked, { status: 200, headers: jsonHeaders() });
      }
      return streamedResponse('', { status: 404, headers: jsonHeaders() });
    }) as unknown as typeof fetch;

    const results = await probeSensitivePaths('https://example.com');

    expect(Object.keys(results)).toEqual(SENSITIVE_PATHS);
    const envResult = results['/.env'];
    expect(envResult.ok).toBe(true);
    expect(envResult.status).toBe(200);
    expect(envResult.bodySnippet).toBe(leaked);

    // probe.ts deliberately does not run detection itself (ADR §3) — confirm
    // the bodySnippet it captured is exactly what checks.ts's existing
    // SECRET_PATTERNS would flag, so a downstream caller can reuse them as-is.
    const matched = SECRET_PATTERNS.some(p => p.regex.test(envResult.bodySnippet ?? ''));
    expect(matched).toBe(true);
  });

  it('drops an oversized body instead of returning a truncated/misleading snippet', async () => {
    const bigBody = 'x'.repeat(1000);
    global.fetch = vi.fn(async () =>
      streamedResponse(bigBody, { status: 200, headers: jsonHeaders() })
    ) as unknown as typeof fetch;

    const result = await probeUrl('https://example.com', { maxBodyBytes: 100 });

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.bodySnippet).toBeNull();
  });

  it('returns ok:false with an error for a generic network failure', async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;

    const result = await probeUrl('https://unreachable.example.com');

    expect(result.ok).toBe(false);
    expect(result.status).toBeNull();
    expect(result.error).toBe('fetch failed');
  });
});

describe('probeSensitivePaths', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('probes every entry in SENSITIVE_PATHS and returns a result keyed by path', async () => {
    global.fetch = vi.fn(async () =>
      streamedResponse('not found', { status: 404, headers: jsonHeaders() })
    ) as unknown as typeof fetch;

    const results = await probeSensitivePaths('https://example.com');

    expect(Object.keys(results).sort()).toEqual([...SENSITIVE_PATHS].sort());
    for (const path of SENSITIVE_PATHS) {
      expect(results[path].status).toBe(404);
    }
  });
});
