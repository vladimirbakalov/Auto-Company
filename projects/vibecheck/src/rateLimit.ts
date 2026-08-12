// vibecheck — coarse per-IP rate limiting for unauthenticated URL-probing/
// scanning endpoints
//
// Closes the KNOWN GAP flagged in index.ts above POST /api/probe-check (QA
// cycle #1146, deferred 2+ cycles): POST /api/scan, POST /api/probe-check,
// and POST /api/monitors all let a caller trigger a server-side fetch of an
// arbitrary (SSRF-guarded, see probe.ts) URL, and none of them were
// throttled — a single IP could fire unlimited requests. This module is the
// "coarse per-IP throttle (e.g. KV-backed sliding window, same binding style
// as WAITLIST)" that comment called for.
//
// Deliberately NOT a precise sliding-window or token-bucket algorithm: KV is
// eventually consistent (a read can lag a write across colos) and enforces a
// 60s minimum TTL, so any exactness this code pretended to have would be
// fake precision. What's implemented is a fixed-window counter — bucket the
// current time into windowSeconds-sized slices, count requests per
// (key, bucket), reject once the count is at/over the limit. That is "good
// enough to blunt abuse" (the original TODO's own framing), not a
// general-purpose rate-limiting framework.
//
// Bucketed per (ip, route) rather than one shared bucket across all three
// endpoints: /api/scan does substantially more work per call (GitHub tree +
// file fetches, plus an optional live probe) than /api/probe-check (a single
// ping) or /api/monitors (one INSERT), so each route gets its own limit
// tuned to its own cost, and a caller hammering one endpoint doesn't burn a
// shared budget that then blocks a legitimate call to a different one.

export interface RateLimitResult {
  allowed: boolean;
}

// KV's put() enforces a 60s minimum TTL. Give every bucket a little headroom
// past its own window so a write landing right at the window boundary still
// expires cleanly instead of a stale, already-rolled-over bucket key lingering.
const TTL_HEADROOM_SECONDS = 10;

// Checks and increments a fixed-window counter for `key`, allowing up to
// `limit` requests per `windowSeconds`. A call that finds the window already
// at/over the limit returns { allowed: false } and does NOT increment the
// counter further (a rejected request isn't a consumed one). No-ops to
// "always allowed" when `kv` is undefined — missing binding, e.g. local dev
// before `wrangler kv:namespace create RATE_LIMIT` has been run, same
// graceful-degradation convention as every other optional binding in this
// codebase (see the `if (!c.env.WAITLIST)` pattern in index.ts) — so a
// not-yet-provisioned namespace can never turn into a 500 or an unexpected
// availability regression. Unlike the availability guarantee, this no-op
// path DOES log — a missing rate-limit store is a silently reopened abuse
// gap, not a cosmetic feature gap like a missing waitlist signup, so it gets
// the same one-time-per-request visibility WAITLIST's missing-binding path
// has, to make a forgotten `wrangler kv:namespace create RATE_LIMIT` before
// deploy loud rather than invisible.
//
// Note this get-then-put is not atomic — KV has no compare-and-swap — so a
// burst of concurrent requests for the same key can all read the same
// pre-write count and all pass, overshooting `limit` by more than the
// window-boundary case above already allows for. This is a second, distinct
// source of imprecision from KV's cross-colo eventual consistency; both are
// accepted under the "coarse, blunt-abuse-deterrent" framing this module
// documents above, not a precise enforcement guarantee.
export async function checkRateLimit(
  kv: KVNamespace | undefined,
  key: string,
  limit: number,
  windowSeconds: number
): Promise<RateLimitResult> {
  if (!kv) {
    console.log('RATE_LIMIT KV binding missing — skipping rate limit check for:', key);
    return { allowed: true };
  }

  const bucket = Math.floor(Date.now() / 1000 / windowSeconds);
  const bucketKey = `ratelimit:${key}:${bucket}`;

  const current = await kv.get(bucketKey);
  const count = current ? parseInt(current, 10) || 0 : 0;

  if (count >= limit) {
    return { allowed: false };
  }

  await kv.put(bucketKey, String(count + 1), {
    expirationTtl: windowSeconds + TTL_HEADROOM_SECONDS,
  });
  return { allowed: true };
}

// Builds the per-(ip, route) key checkRateLimit expects. Falls back to a
// single shared "unknown-ip" bucket per route when CF-Connecting-IP is
// absent (local dev, tests, or anything not fronted by Cloudflare) rather
// than throwing or skipping the check entirely — every un-attributed caller
// then shares one coarse budget for that route, which is at least
// directionally the same "blunt abuse" behavior real, IP-attributed traffic
// gets.
export function rateLimitKey(ip: string | undefined | null, route: string): string {
  return `${ip || 'unknown-ip'}:${route}`;
}
