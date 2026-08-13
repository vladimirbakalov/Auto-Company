// SnapOG — Admin routes: internal "how's snapog doing" dashboard.
//
// Single endpoint (GET /admin/stats) answering that question across both
// funnel data (src/analytics.ts's `events` table — landing/register
// pageviews, signups) and usage data (usage_events, written by the /og
// handler in ../index.ts). Gated by ADMIN_STATS_KEY, the same
// optional-secret graceful-degradation pattern billing uses (see
// ../billing/routes.ts): unset -> 503, wrong key -> 401, right key -> 200.
// Set via `wrangler secret put ADMIN_STATS_KEY` — there is no separate
// login here, this key IS the auth. Pass it as either `?key=...` or an
// `Authorization: Bearer ...` header.

import { Hono } from 'hono';
import type { Env, Tier } from '../types';

export const adminRoutes = new Hono<{ Bindings: Env }>();

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Constant-time secret comparison over an HTTP boundary. A plain `===`
// short-circuits on the first differing character, which leaks timing
// information proportional to how many leading characters an attacker
// guessed correctly — over enough requests that's a practical oracle for
// brute-forcing ADMIN_STATS_KEY one byte at a time. Hashing both sides to a
// fixed-length SHA-256 digest first (so string length itself leaks
// nothing) and then comparing every byte unconditionally (no early return)
// closes both leaks without needing node:crypto's timingSafeEqual, which
// additionally requires equal-length buffers up front.
async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const [digestA, digestB] = await Promise.all([sha256(a), sha256(b)]);
  let diff = 0;
  for (let i = 0; i < digestA.length; i++) {
    diff |= digestA.charCodeAt(i) ^ digestB.charCodeAt(i);
  }
  return diff === 0;
}

function extractCallerKey(authHeader: string | undefined, queryKey: string | undefined): string | null {
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length).trim();
    return token || null;
  }
  return queryKey ?? null;
}

// SQLite `datetime('now', <modifier>)` computes the window cutoff inside
// the database itself, in the exact same `datetime('now')` format used by
// every DEFAULT in migrations/0001-0003 — deliberately *not*
// `new Date(...).toISOString()` from JS, whose 'T'/'Z'-bearing output does
// not sort consistently against SQLite's space-separated format in a plain
// string comparison.
const WINDOWS = {
  last_24h: '-1 day',
  last_7d: '-7 day',
  last_30d: '-30 day',
} as const;

const EVENT_TYPES = ['landing_pageview', 'register_pageview', 'signup'] as const;
type FunnelEventType = (typeof EVENT_TYPES)[number];

async function countEventsByType(db: D1Database, modifier: string): Promise<Record<FunnelEventType, number>> {
  const { results } = await db
    .prepare(
      `SELECT event_type, COUNT(*) as cnt FROM events WHERE occurred_at > datetime('now', ?) GROUP BY event_type`
    )
    .bind(modifier)
    .all<{ event_type: string; cnt: number }>();

  const counts: Record<FunnelEventType, number> = {
    landing_pageview: 0,
    register_pageview: 0,
    signup: 0,
  };
  for (const row of results ?? []) {
    if ((EVENT_TYPES as readonly string[]).includes(row.event_type)) {
      counts[row.event_type as FunnelEventType] = row.cnt;
    }
  }
  return counts;
}

async function countUsageEvents(db: D1Database, modifier: string): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) as cnt FROM usage_events WHERE generated_at > datetime('now', ?)`)
    .bind(modifier)
    .first<{ cnt: number }>();
  return row?.cnt ?? 0;
}

adminRoutes.get('/stats', async c => {
  const adminKey = c.env.ADMIN_STATS_KEY;
  if (!adminKey) {
    return c.json({ error: 'Admin stats are not configured yet.' }, 503);
  }

  const callerKey = extractCallerKey(c.req.header('Authorization'), c.req.query('key'));
  if (!callerKey || !(await constantTimeEqual(callerKey, adminKey))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const db = c.env.DB;

  const [funnel24h, funnel7d, funnel30d, og24h, og7d, og30d, usersRow, tierRows, ogTotalRow] = await Promise.all([
    countEventsByType(db, WINDOWS.last_24h),
    countEventsByType(db, WINDOWS.last_7d),
    countEventsByType(db, WINDOWS.last_30d),
    countUsageEvents(db, WINDOWS.last_24h),
    countUsageEvents(db, WINDOWS.last_7d),
    countUsageEvents(db, WINDOWS.last_30d),
    db.prepare('SELECT COUNT(*) as cnt FROM users').first<{ cnt: number }>(),
    db.prepare('SELECT tier, COUNT(*) as cnt FROM api_keys GROUP BY tier').all<{ tier: Tier; cnt: number }>(),
    db.prepare('SELECT COUNT(*) as cnt FROM usage_events').first<{ cnt: number }>(),
  ]);

  const apiKeysByTier: Record<string, number> = { free: 0, pro: 0, business: 0 };
  for (const row of tierRows.results ?? []) {
    apiKeysByTier[row.tier] = row.cnt;
  }

  return c.json({
    generated_at: new Date().toISOString(),
    funnel: {
      last_24h: { ...funnel24h, og_generations: og24h },
      last_7d: { ...funnel7d, og_generations: og7d },
      last_30d: { ...funnel30d, og_generations: og30d },
    },
    totals: {
      users: usersRow?.cnt ?? 0,
      api_keys_by_tier: apiKeysByTier,
      og_generations: ogTotalRow?.cnt ?? 0,
    },
  });
});
