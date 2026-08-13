// Pure/D1-mocked unit coverage for src/events.ts, mirroring the split this
// codebase already uses for monitors.ts/auth.ts: hand-rolled D1 fakes here
// (no route wiring — that's test/index.test.ts's "Analytics — event
// instrumentation (Cycle #126)" describe block instead).

import { describe, it, expect, vi } from 'vitest';
import { recordEvent, countEventsInWindow, countActiveMonitors, buildAdminStats } from '../src/events';

describe('recordEvent', () => {
  it('no-ops without touching D1 when db is undefined', async () => {
    await expect(recordEvent(undefined, 'landing_pageview')).resolves.toBeUndefined();
  });

  it('inserts a row with the given event_type and path', async () => {
    const calls: unknown[][] = [];
    const db = {
      prepare: (sql: string) => ({
        bind: (...params: unknown[]) => {
          calls.push([sql, ...params]);
          return { run: async () => ({ success: true }) as unknown as D1Result };
        },
      }),
    } as unknown as D1Database;

    await recordEvent(db, 'scan_submitted', '/api/scan');

    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toContain('INSERT INTO events');
    expect(calls[0].slice(1)).toEqual(['scan_submitted', '/api/scan']);
  });

  it('defaults path to null when not provided', async () => {
    let boundParams: unknown[] = [];
    const db = {
      prepare: () => ({
        bind: (...params: unknown[]) => {
          boundParams = params;
          return { run: async () => ({ success: true }) as unknown as D1Result };
        },
      }),
    } as unknown as D1Database;

    await recordEvent(db, 'landing_pageview');

    expect(boundParams).toEqual(['landing_pageview', null]);
  });

  it('never throws when the D1 write fails — logs instead', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const db = {
      prepare: () => ({
        bind: () => ({
          run: async () => {
            throw new Error('D1 unavailable');
          },
        }),
      }),
    } as unknown as D1Database;

    await expect(recordEvent(db, 'checkout_started')).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalledWith('Failed to record analytics event', 'checkout_started', expect.any(Error));
    errorSpy.mockRestore();
  });
});

describe('countEventsInWindow', () => {
  // Cutoff is computed by SQLite's own `datetime('now', ?2)` rather than a
  // JS-formatted ISO string bound in directly — see the comment on
  // countEventsInWindow in src/events.ts for why: a text `>=` comparison
  // between `occurred_at` (SQLite's "YYYY-MM-DD HH:MM:SS" format) and a JS
  // `Date#toISOString()` value ("YYYY-MM-DDTHH:MM:SS.sssZ") silently drops
  // real events whenever the two timestamps share a calendar date, because
  // "T" sorts after the space. Binding a bare modifier like '-1 day' and
  // letting SQLite do the date arithmetic avoids the format mismatch
  // entirely (real-D1 regression coverage: test/index.workers.test.ts).
  it('queries by event_type and occurred_at >= datetime(\'now\', modifier), returning the D1 count', async () => {
    const db = {
      prepare: (sql: string) => ({
        bind: (...params: unknown[]) => ({
          first: async () => {
            expect(sql).toContain('FROM events');
            expect(sql).toContain('event_type = ?1');
            expect(sql).toContain("occurred_at >= datetime('now', ?2)");
            expect(params).toEqual(['scan_submitted', '-1 day']);
            return { count: 42 };
          },
        }),
      }),
    } as unknown as D1Database;

    expect(await countEventsInWindow(db, 'scan_submitted', '-1 day')).toBe(42);
  });

  it('returns 0 when D1 returns no row', async () => {
    const db = {
      prepare: () => ({ bind: () => ({ first: async () => null }) }),
    } as unknown as D1Database;

    expect(await countEventsInWindow(db, 'landing_pageview', '-1 day')).toBe(0);
  });
});

describe('countActiveMonitors', () => {
  // No bound params for this query (see reconcile.ts's
  // fetchKnownStripeCustomerIds for the same zero-param prepare().all()/
  // .first() convention elsewhere in this codebase) — the fake's `first`
  // sits directly on the prepare() result, no `.bind()` call needed or
  // expected.
  it('counts monitors where paused = 0', async () => {
    const db = {
      prepare: (sql: string) => ({
        first: async () => {
          expect(sql).toContain('FROM monitors');
          expect(sql).toContain('paused = 0');
          return { count: 5 };
        },
      }),
    } as unknown as D1Database;

    expect(await countActiveMonitors(db)).toBe(5);
  });

  it('returns 0 when D1 returns no row', async () => {
    const db = { prepare: () => ({ first: async () => null }) } as unknown as D1Database;
    expect(await countActiveMonitors(db)).toBe(0);
  });
});

describe('buildAdminStats', () => {
  // countEventsInWindow always binds (event_type, modifier), but
  // countActiveMonitors calls `.first()` directly with no `.bind()` (no
  // params to bind) — the fake supports both chains on the same prepare()
  // result.
  function fakeStatsDb(countsByType: Record<string, number>, activeMonitors: number): D1Database {
    return {
      prepare: (sql: string) => ({
        bind: (...params: unknown[]) => ({
          first: async () => {
            const eventType = params[0] as string;
            return { count: countsByType[eventType] ?? 0 };
          },
        }),
        first: async () => {
          if (sql.includes('FROM monitors')) return { count: activeMonitors };
          return null;
        },
      }),
    } as unknown as D1Database;
  }

  it('aggregates each event type across all three windows plus active monitors', async () => {
    const db = fakeStatsDb(
      { landing_pageview: 30, scan_submitted: 12, checkout_started: 3, checkout_completed: 1 },
      7
    );
    const nowMs = Date.parse('2026-08-13T00:00:00.000Z');

    const stats = await buildAdminStats(db, nowMs);

    expect(stats).toEqual({
      landingPageviews: { last24h: 30, last7d: 30, last30d: 30 },
      scansSubmitted: { last24h: 12, last7d: 12, last30d: 12 },
      checkoutStarted: { last24h: 3, last7d: 3, last30d: 3 },
      checkoutCompleted: { last24h: 1, last7d: 1, last30d: 1 },
      activeMonitors: 7,
      generatedAt: '2026-08-13T00:00:00.000Z',
    });
  });

  it('sends the right SQLite datetime() modifier for each window — not JS-computed cutoffs', async () => {
    // The actual date arithmetic (does "3 days ago" fall inside the 24h
    // window or not) is SQLite's job now, exercised against real D1 in
    // test/index.workers.test.ts. This unit test only proves buildAdminStats
    // wires each window to the right modifier string — '-1 day' / '-7 day' /
    // '-30 day' — same convention as snapog's src/admin/routes.ts WINDOWS.
    const modifiersSeen: string[] = [];
    const db = {
      prepare: (sql: string) => ({
        bind: (...params: unknown[]) => ({
          first: async () => {
            if (sql.includes('FROM events') && params[0] === 'landing_pageview') {
              modifiersSeen.push(params[1] as string);
            }
            return { count: 0 };
          },
        }),
        first: async () => ({ count: 0 }), // countActiveMonitors — irrelevant to this test
      }),
    } as unknown as D1Database;

    await buildAdminStats(db);

    expect(modifiersSeen.sort()).toEqual(['-1 day', '-30 day', '-7 day']);
  });

  it('defaults nowMs to Date.now() when not provided', async () => {
    const db = fakeStatsDb({}, 0);
    const before = Date.now();
    const stats = await buildAdminStats(db);
    const after = Date.now();

    const generatedAtMs = Date.parse(stats.generatedAt);
    expect(generatedAtMs).toBeGreaterThanOrEqual(before);
    expect(generatedAtMs).toBeLessThanOrEqual(after);
  });
});
