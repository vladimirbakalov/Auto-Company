import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { probeUrl, probeSensitivePaths, SENSITIVE_PATHS, validateProbeTarget } from '../src/probe';
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

describe('validateProbeTarget', () => {
  it('accepts a well-formed https URL', () => {
    const result = validateProbeTarget('https://myapp.vercel.app');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.url).toBe('https://myapp.vercel.app/');
    }
  });

  it('accepts a well-formed http URL', () => {
    const result = validateProbeTarget('http://example.com/some/path');
    expect(result.ok).toBe(true);
  });

  it('rejects an empty/whitespace-only input', () => {
    const result = validateProbeTarget('   ');
    expect(result.ok).toBe(false);
  });

  it('rejects an unparseable URL', () => {
    const result = validateProbeTarget('not a url');
    expect(result.ok).toBe(false);
  });

  it('rejects non-http(s) schemes', () => {
    for (const scheme of ['ftp://example.com', 'file:///etc/passwd', 'gopher://example.com']) {
      const result = validateProbeTarget(scheme);
      expect(result.ok).toBe(false);
    }
  });

  it('rejects the "localhost" hostname literal', () => {
    const result = validateProbeTarget('http://localhost:3000');
    expect(result.ok).toBe(false);
  });

  it('rejects 0.0.0.0', () => {
    expect(validateProbeTarget('http://0.0.0.0').ok).toBe(false);
  });

  it('rejects IPv4 loopback (127.0.0.0/8)', () => {
    expect(validateProbeTarget('http://127.0.0.1').ok).toBe(false);
    expect(validateProbeTarget('http://127.1.2.3').ok).toBe(false);
  });

  it('rejects IPv4 private ranges (10/8, 172.16/12, 192.168/16)', () => {
    expect(validateProbeTarget('http://10.0.0.5').ok).toBe(false);
    expect(validateProbeTarget('http://172.16.0.1').ok).toBe(false);
    expect(validateProbeTarget('http://172.31.255.255').ok).toBe(false);
    expect(validateProbeTarget('http://192.168.1.1').ok).toBe(false);
  });

  it('does not treat 172.15.x.x or 172.32.x.x as private (boundary check)', () => {
    expect(validateProbeTarget('http://172.15.0.1').ok).toBe(true);
    expect(validateProbeTarget('http://172.32.0.1').ok).toBe(true);
  });

  it('rejects IPv4 link-local (169.254.0.0/16)', () => {
    expect(validateProbeTarget('http://169.254.169.254').ok).toBe(false);
  });

  it('rejects IPv6 loopback and unspecified addresses', () => {
    expect(validateProbeTarget('http://[::1]').ok).toBe(false);
    expect(validateProbeTarget('http://[::]').ok).toBe(false);
  });

  it('rejects IPv6 unique-local (fc00::/7) and link-local (fe80::/10)', () => {
    expect(validateProbeTarget('http://[fc00::1]').ok).toBe(false);
    expect(validateProbeTarget('http://[fd12:3456::1]').ok).toBe(false);
    expect(validateProbeTarget('http://[fe80::1]').ok).toBe(false);
  });

  it('rejects IPv4-mapped IPv6 literals encoding private/loopback/link-local addresses', () => {
    // Regression for a bypass found in QA: WHATWG URL normalizes these to
    // hex-group form (e.g. "[::ffff:169.254.169.254]" -> hostname
    // "[::ffff:a9fe:a9fe]"), which the plain dotted-quad IPv4 check and the
    // old IPv6 check (::1/::/fc00::/fe80::) both missed entirely — including
    // the cloud-metadata address 169.254.169.254.
    expect(validateProbeTarget('http://[::ffff:169.254.169.254]').ok).toBe(false);
    expect(validateProbeTarget('http://[::ffff:127.0.0.1]').ok).toBe(false);
    expect(validateProbeTarget('http://[::ffff:10.0.0.1]').ok).toBe(false);
    expect(validateProbeTarget('http://[::ffff:192.168.1.1]').ok).toBe(false);
    expect(validateProbeTarget('http://[::ffff:172.16.0.1]').ok).toBe(false);
  });

  it('accepts an IPv4-mapped IPv6 literal encoding a public address', () => {
    expect(validateProbeTarget('http://[::ffff:93.184.216.34]').ok).toBe(true);
  });

  it('accepts a public IPv4 literal', () => {
    expect(validateProbeTarget('http://93.184.216.34').ok).toBe(true);
  });

  it('rejects a bare "127" or malformed IPv4-looking hostname only via strict 4-octet match (no false negative on partial forms)', () => {
    // Sanity: something that merely contains "127" but isn't a loopback IP
    // should NOT be blocked — the check is exact-hostname, not substring.
    expect(validateProbeTarget('http://127example.com').ok).toBe(true);
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
