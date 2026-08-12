import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  checkLivePermissiveCors,
  checkLiveMissingSecurityHeaders,
  checkLiveSensitivePaths,
  buildLiveFindings,
} from '../src/liveChecks';
import type { ProbeResult } from '../src/probe';

function probeResult(overrides: Partial<ProbeResult> = {}): ProbeResult {
  return {
    ok: true,
    status: 200,
    latencyMs: 42,
    headers: {},
    bodySnippet: null,
    error: null,
    finalUrl: 'https://example.com/',
    ...overrides,
  };
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

describe('checkLivePermissiveCors', () => {
  it('flags a wildcard Access-Control-Allow-Origin header', () => {
    const findings = checkLivePermissiveCors(
      'https://example.com',
      probeResult({ headers: { 'access-control-allow-origin': '*' } })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].file).toBe('(live: https://example.com)');
  });

  it('does not flag a scoped (non-wildcard) origin', () => {
    const findings = checkLivePermissiveCors(
      'https://example.com',
      probeResult({ headers: { 'access-control-allow-origin': 'https://trusted.example.com' } })
    );
    expect(findings).toEqual([]);
  });

  it('does not flag when the header is absent', () => {
    const findings = checkLivePermissiveCors('https://example.com', probeResult({ headers: {} }));
    expect(findings).toEqual([]);
  });
});

describe('checkLiveMissingSecurityHeaders', () => {
  it('flags when all core headers are missing', () => {
    const findings = checkLiveMissingSecurityHeaders('https://example.com', probeResult({ headers: {} }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].explanation).toContain('Strict-Transport-Security');
    expect(findings[0].explanation).toContain('X-Frame-Options');
    expect(findings[0].explanation).toContain('X-Content-Type-Options');
  });

  it('does not flag when all core headers are present', () => {
    const findings = checkLiveMissingSecurityHeaders(
      'https://example.com',
      probeResult({
        headers: {
          'strict-transport-security': 'max-age=63072000',
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
        },
      })
    );
    expect(findings).toEqual([]);
  });

  it('lists only the specific headers that are missing', () => {
    const findings = checkLiveMissingSecurityHeaders(
      'https://example.com',
      probeResult({ headers: { 'x-frame-options': 'DENY' } })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].explanation).toContain('Strict-Transport-Security');
    expect(findings[0].explanation).toContain('X-Content-Type-Options');
    expect(findings[0].explanation).not.toContain('X-Frame-Options');
  });
});

describe('checkLiveSensitivePaths', () => {
  it('flags secret-shaped content on a 200 response, reusing checks.ts SECRET_PATTERNS', () => {
    const findings = checkLiveSensitivePaths('https://example.com', {
      '/.env': probeResult({ status: 200, bodySnippet: 'STRIPE_KEY=sk_' + 'live_abcdefghijklmnopqrstuvwx' }),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].file).toBe('(live: https://example.com/.env)');
  });

  it('does not flag a 404 even if the body coincidentally matches a pattern', () => {
    const findings = checkLiveSensitivePaths('https://example.com', {
      '/.env': probeResult({ ok: true, status: 404, bodySnippet: 'sk_' + 'live_abcdefghijklmnopqrstuvwx' }),
    });
    expect(findings).toEqual([]);
  });

  it('does not flag an unreachable path', () => {
    const findings = checkLiveSensitivePaths('https://example.com', {
      '/.env': probeResult({ ok: false, status: null, bodySnippet: null, error: 'Request timed out' }),
    });
    expect(findings).toEqual([]);
  });

  it('does not flag clean content', () => {
    const findings = checkLiveSensitivePaths('https://example.com', {
      '/config.json': probeResult({ status: 200, bodySnippet: '{"public": true}' }),
    });
    expect(findings).toEqual([]);
  });
});

describe('buildLiveFindings', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  it('throws when the root URL is unreachable, so callers can degrade gracefully', async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;

    await expect(buildLiveFindings('https://unreachable.example.com')).rejects.toThrow();
  });

  it('merges CORS, missing-header, and sensitive-path findings from a reachable target', async () => {
    global.fetch = vi.fn(async (input: RequestInit | string | URL) => {
      const url = String(input);
      if (url === 'https://example.com/') {
        return streamedResponse('<html></html>', {
          status: 200,
          headers: new Headers({ 'access-control-allow-origin': '*' }),
        });
      }
      if (url.endsWith('/.env')) {
        return streamedResponse('AKIA1234567890ABCD12', { status: 200 });
      }
      return streamedResponse('not found', { status: 404 });
    }) as unknown as typeof fetch;

    const findings = await buildLiveFindings('https://example.com');

    const titles = findings.map(f => f.title);
    expect(titles.some(t => t.includes('Permissive CORS'))).toBe(true);
    expect(titles.some(t => t.includes('Missing common security headers'))).toBe(true);
    expect(titles.some(t => t.includes('AWS Access Key ID'))).toBe(true);
    // Every finding is in the exact same shape the static scanner emits.
    for (const f of findings) {
      expect(f.id).toBeTruthy();
      expect(f.title).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(['high', 'medium', 'low']).toContain(f.confidence);
      expect(f.file).toMatch(/^\(live: /);
    }
  });
});
