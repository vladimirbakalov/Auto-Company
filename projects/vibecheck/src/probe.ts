// vibecheck — shared live-URL probing infra
//
// Structurally a sibling to github.ts, reusing its proven fetch discipline
// (now factored into http.ts): AbortController-based deadlines and
// byte-capped streaming reads. Two callers share this one module, per the
// CEO ruling's explicit "don't build two probers" instruction:
//   1. The free-tier live security check (CORS/security-header inspection +
//      probeSensitivePaths for exposed .env/.git/config-style leaks) — NOT
//      wired up in this change; see docs/cto/vibecheck-monitoring-tier-adr.md
//      §3 caller #1. That's a scan-flow/UI change (src/pages.ts, src/index.ts
//      POST /api/scan) explicitly out of scope for this backend-infra pass.
//   2. The paid-tier uptime/cost-risk check, driven by the Cron Trigger in
//      index.ts's `scheduled` handler (this change).
//
// See docs/cto/vibecheck-monitoring-tier-adr.md §3 for the full design.

import { fetchWithTimeout, readTextBounded, DEFAULT_FETCH_TIMEOUT_MS, DEFAULT_MAX_BODY_BYTES } from './http';

export interface ProbeResult {
  ok: boolean; // true if we got any HTTP response (even 4xx/5xx — "ok" means "reachable")
  status: number | null; // null if the request failed before getting a response (timeout, DNS, TLS)
  latencyMs: number;
  headers: Record<string, string>; // bounded allowlist, see HEADER_ALLOWLIST below
  bodySnippet: string | null; // byte-capped, same pattern as readTextBounded
  error: string | null; // populated on failure (timeout, network, abort)
  finalUrl: string; // after redirects, for open-redirect / unexpected-host awareness
}

export interface ProbeOptions {
  method?: 'GET' | 'HEAD';
  path?: string; // e.g. '/', '/.env', '/config.json' — for security-check probes
  timeoutMs?: number; // default FETCH_TIMEOUT_MS = 10_000, same constant github.ts uses
  maxBodyBytes?: number; // default matches github.ts's MAX_FILE_BYTES = 300_000
}

// Bounded allowlist of response headers we ever capture — deliberately not
// "all headers", so we never accidentally carry an origin's cookies/auth
// echoes into our own storage. Covers what the security-posture diff (spec
// §2.2) and CORS check (ADR §3 caller #1) actually need.
const HEADER_ALLOWLIST = [
  'content-type',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'x-frame-options',
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'server',
  'x-powered-by',
];

// Fixed list of security-sensitive paths probed for the free-tier live check
// (ADR §3 caller #1). Kept short and fixed deliberately — this is not a
// crawler or a fuzzer, just a well-known "did you accidentally expose this"
// checklist.
export const SENSITIVE_PATHS = ['/.env', '/.git/config', '/config.json', '/.aws/credentials'];

function resolveUrl(baseUrl: string, path: string): string | null {
  try {
    return new URL(path, baseUrl).toString();
  } catch {
    return null;
  }
}

export async function probeUrl(baseUrl: string, opts: ProbeOptions = {}): Promise<ProbeResult> {
  const method = opts.method ?? 'GET';
  const path = opts.path ?? '';
  const timeoutMs = opts.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  const url = resolveUrl(baseUrl, path);
  if (!url) {
    return {
      ok: false,
      status: null,
      latencyMs: 0,
      headers: {},
      bodySnippet: null,
      error: 'Invalid URL',
      finalUrl: baseUrl,
    };
  }

  const start = Date.now();
  let res: Response;
  try {
    res = await fetchWithTimeout(url, { method, redirect: 'follow' }, timeoutMs);
  } catch (err) {
    const latencyMs = Date.now() - start;
    const isAbort = err instanceof Error && err.name === 'AbortError';
    return {
      ok: false,
      status: null,
      latencyMs,
      headers: {},
      bodySnippet: null,
      error: isAbort ? 'Request timed out' : err instanceof Error ? err.message : 'Network error',
      finalUrl: url,
    };
  }
  const latencyMs = Date.now() - start;

  const headers: Record<string, string> = {};
  for (const name of HEADER_ALLOWLIST) {
    const value = res.headers.get(name);
    if (value !== null) headers[name] = value;
  }

  // HEAD requests have no body to read; readTextBounded on a HEAD response
  // is harmless (empty body) but skip the work anyway.
  const bodySnippet = method === 'HEAD' ? null : await readTextBounded(res, maxBodyBytes);

  return {
    ok: true,
    status: res.status,
    latencyMs,
    headers,
    bodySnippet,
    error: null,
    finalUrl: res.url || url,
  };
}

// Runs probeUrl against SENSITIVE_PATHS in parallel (bounded by the fixed,
// short list itself — same Promise.all-with-cap shape as github.ts's
// fetchFiles, just with a cap that's structurally small rather than sliced).
export async function probeSensitivePaths(baseUrl: string): Promise<Record<string, ProbeResult>> {
  const entries = await Promise.all(
    SENSITIVE_PATHS.map(async path => [path, await probeUrl(baseUrl, { path })] as const)
  );
  const results: Record<string, ProbeResult> = {};
  for (const [path, result] of entries) {
    results[path] = result;
  }
  return results;
}
