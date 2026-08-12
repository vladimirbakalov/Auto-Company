// vibecheck — shared live-URL probing infra
//
// Structurally a sibling to github.ts, reusing its proven fetch discipline
// (now factored into http.ts): AbortController-based deadlines and
// byte-capped streaming reads. Two callers share this one module, per the
// CEO ruling's explicit "don't build two probers" instruction:
//   1. The free-tier live security check (CORS/security-header inspection +
//      probeSensitivePaths for exposed .env/.git/config-style leaks) — wired
//      up in src/liveChecks.ts, called from POST /api/scan in src/index.ts.
//      See docs/cto/vibecheck-monitoring-tier-adr.md §3 caller #1.
//   2. The paid-tier uptime/cost-risk check, driven by the Cron Trigger in
//      index.ts's `scheduled` handler.
//
// See docs/cto/vibecheck-monitoring-tier-adr.md §3 for the full design.
//
// SSRF note: this module fetches whatever URL a caller hands it. Both
// callers above are reachable from unauthenticated requests (POST /api/scan
// is public; POST /api/monitors requires auth but not payment-verified
// trust), so this is a public server-side-fetch surface. validateProbeTarget
// below is the literal-hostname guard both callers must run before calling
// probeUrl/probeSensitivePaths — it is NOT a full SSRF hardening pass (no DNS
// rebinding protection, no redirect-chain re-validation after the initial
// fetch follows redirects). That's explicitly out of scope for this change;
// tracked as a follow-up, not silently skipped.

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

export type ProbeTargetValidation = { ok: true; url: string } | { ok: false; reason: string };

const BLOCKED_HOSTNAME_LITERALS = new Set(['localhost', '0.0.0.0']);

// Literal-hostname check only — does not resolve DNS, so a hostname that
// *resolves* to a private/loopback address (DNS rebinding, or just a domain
// someone points at 127.0.0.1) is NOT caught here. That's a deeper problem
// explicitly deferred (see module header). This blocks the obvious cases: an
// attacker (or curious user) typing "localhost", "127.0.0.1", "10.x.x.x",
// etc. directly into the URL field.
function isPrivateOrLoopbackIPv4(hostname: string): boolean {
  const m = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  if (octets.some(o => o < 0 || o > 255)) return false;
  const [a, b] = octets;
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  return false;
}

// IPv4-mapped IPv6 literals (::ffff:a.b.c.d, or its hex-group form
// ::ffff:AABB:CCDD) let a private/loopback/link-local IPv4 address — including
// 169.254.169.254, the cloud-metadata SSRF target — smuggle past the plain
// IPv4 dotted-quad check via bracket syntax (e.g. "http://[::ffff:169.254.169.254]/").
// WHATWG URL's hostname getter normalizes this to "[::ffff:a9fe:a9fe]" rather
// than keeping the dotted-quad form, so it must be decoded back to IPv4 and
// re-checked, not just pattern-matched as opaque IPv6.
function extractIPv4MappedAddress(h: string): string | null {
  const dotted = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) return dotted[1];

  const hexGroups = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexGroups) {
    const hi = parseInt(hexGroups[1], 16);
    const lo = parseInt(hexGroups[2], 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) return null;
    return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff].join('.');
  }

  return null;
}

function isPrivateOrLoopbackIPv6(hostname: string): boolean {
  // new URL().hostname keeps the brackets for IPv6 literals (e.g. "[::1]").
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === '::1') return true; // loopback
  if (h === '::') return true; // unspecified address
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return true; // fc00::/7 unique local
  if (/^fe[89ab][0-9a-f]:/.test(h)) return true; // fe80::/10 link-local

  const mapped = extractIPv4MappedAddress(h);
  if (mapped && isPrivateOrLoopbackIPv4(mapped)) return true;

  return false;
}

// Reusable guard for any caller about to hand a user-supplied URL to
// probeUrl/probeSensitivePaths against a target we don't control: rejects
// non-http(s) schemes and obvious loopback/private/link-local hostname
// literals. Both current callers (POST /api/scan's optional deployedUrl, and
// POST /api/monitors' url) must run this before probing — see module header.
export function validateProbeTarget(input: string): ProbeTargetValidation {
  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, reason: 'A URL is required.' };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, reason: 'That does not look like a valid, absolute URL (e.g. https://myapp.vercel.app).' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'Only http:// and https:// URLs can be checked.' };
  }

  const hostname = url.hostname.toLowerCase();
  if (
    BLOCKED_HOSTNAME_LITERALS.has(hostname) ||
    isPrivateOrLoopbackIPv4(hostname) ||
    isPrivateOrLoopbackIPv6(hostname)
  ) {
    return { ok: false, reason: 'That host cannot be checked (local/private network addresses are not supported).' };
  }

  return { ok: true, url: url.toString() };
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
