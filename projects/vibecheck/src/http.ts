// vibecheck — shared HTTP fetch primitives
//
// Extracted from github.ts so every outbound fetch in this codebase (GitHub
// raw/API calls, and now live-URL probing in probe.ts) gets the exact same
// timeout + byte-cap discipline instead of two slightly-different copies to
// keep in sync. See docs/cto/vibecheck-monitoring-tier-adr.md §3 — the ADR
// explicitly asks probe.ts to reuse these patterns "verbatim in spirit"; this
// file is what makes that literal instead of a second implementation.

// Default hard deadline for any outbound fetch, so a slow/hanging upstream
// can't tie up a Worker invocation indefinitely. Individual callers may
// override (e.g. a shorter timeout for uptime probes).
export const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

// Default hard byte cap enforced while *streaming* a response body,
// independent of Content-Length (which a malicious/misconfigured origin
// could omit or lie about).
export const DEFAULT_MAX_BODY_BYTES = 300_000;

export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number = DEFAULT_FETCH_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// Reads a response body up to `maxBytes`, decoding as UTF-8. Returns null if
// the body exceeds the cap (rather than truncating silently and risking a
// truncated payload producing misleading — or missed — findings).
export async function readTextBounded(
  res: Response,
  maxBytes: number = DEFAULT_MAX_BODY_BYTES
): Promise<string | null> {
  if (!res.body) {
    return await res.text();
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          return null;
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock?.();
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8').decode(combined);
}
