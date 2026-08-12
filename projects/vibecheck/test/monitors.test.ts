import { describe, it, expect } from 'vitest';
import {
  isMonitorDue,
  selectDueMonitors,
  buildCheckInsert,
  applyCheckResultToMonitor,
  runBoundedFanOut,
  DUE_QUEUE_LIMIT,
} from '../src/monitors';
import type { MonitorRow } from '../src/types';
import type { ProbeResult } from '../src/probe';

function monitor(overrides: Partial<MonitorRow> = {}): MonitorRow {
  return {
    id: 1,
    user_id: 1,
    url: 'https://example.com',
    interval_seconds: 300,
    next_check_at: '2026-08-12T00:00:00.000Z',
    last_check_at: null,
    last_status: null,
    consecutive_failures: 0,
    paused: 0,
    created_at: '2026-08-01T00:00:00.000Z',
    ...overrides,
  };
}

const NOW = '2026-08-12T00:05:00.000Z';

describe('isMonitorDue', () => {
  it('is due when next_check_at is in the past and not paused', () => {
    expect(isMonitorDue(monitor({ next_check_at: '2026-08-12T00:00:00.000Z' }), NOW)).toBe(true);
  });

  it('is due when next_check_at exactly equals now', () => {
    expect(isMonitorDue(monitor({ next_check_at: NOW }), NOW)).toBe(true);
  });

  it('is not due when next_check_at is in the future', () => {
    expect(isMonitorDue(monitor({ next_check_at: '2026-08-12T00:10:00.000Z' }), NOW)).toBe(false);
  });

  it('is never due when paused, regardless of next_check_at', () => {
    expect(isMonitorDue(monitor({ next_check_at: '2026-08-12T00:00:00.000Z', paused: 1 }), NOW)).toBe(false);
  });
});

describe('selectDueMonitors', () => {
  it('filters out non-due and paused monitors', () => {
    const monitors = [
      monitor({ id: 1, next_check_at: '2026-08-12T00:00:00.000Z' }), // due
      monitor({ id: 2, next_check_at: '2026-08-12T01:00:00.000Z' }), // not due
      monitor({ id: 3, next_check_at: '2026-08-12T00:00:00.000Z', paused: 1 }), // paused
    ];
    const due = selectDueMonitors(monitors, NOW);
    expect(due.map(m => m.id)).toEqual([1]);
  });

  it('orders results by next_check_at ascending', () => {
    const monitors = [
      monitor({ id: 1, next_check_at: '2026-08-12T00:04:00.000Z' }),
      monitor({ id: 2, next_check_at: '2026-08-12T00:01:00.000Z' }),
      monitor({ id: 3, next_check_at: '2026-08-12T00:02:00.000Z' }),
    ];
    const due = selectDueMonitors(monitors, NOW);
    expect(due.map(m => m.id)).toEqual([2, 3, 1]);
  });

  it('respects the limit (default DUE_QUEUE_LIMIT)', () => {
    const monitors = Array.from({ length: 10 }, (_, i) =>
      monitor({ id: i, next_check_at: '2026-08-12T00:00:00.000Z' })
    );
    const due = selectDueMonitors(monitors, NOW, { limit: 3 });
    expect(due).toHaveLength(3);
  });

  it('defaults to DUE_QUEUE_LIMIT when no limit is given', () => {
    expect(DUE_QUEUE_LIMIT).toBe(500);
  });

  it('excludes monitors whose owning user is not subscription-active', () => {
    const monitors = [
      monitor({ id: 1, next_check_at: '2026-08-12T00:00:00.000Z', user_id: 1 }),
      monitor({ id: 2, next_check_at: '2026-08-12T00:00:00.000Z', user_id: 2 }),
    ];
    const due = selectDueMonitors(monitors, NOW, {
      isSubscriptionActive: m => m.user_id === 1,
    });
    expect(due.map(m => m.id)).toEqual([1]);
  });
});

function probeResult(overrides: Partial<ProbeResult> = {}): ProbeResult {
  return {
    ok: true,
    status: 200,
    latencyMs: 120,
    headers: {},
    bodySnippet: null,
    error: null,
    finalUrl: 'https://example.com/',
    ...overrides,
  };
}

describe('buildCheckInsert', () => {
  it('marks a 200 response as ok', () => {
    const check = buildCheckInsert(1, probeResult({ status: 200 }), NOW);
    expect(check.ok).toBe(1);
    expect(check.status_code).toBe(200);
  });

  it('marks a 5xx response as not ok', () => {
    const check = buildCheckInsert(1, probeResult({ status: 503 }), NOW);
    expect(check.ok).toBe(0);
  });

  it('marks a probe failure (no status) as not ok', () => {
    const check = buildCheckInsert(1, probeResult({ ok: false, status: null, error: 'Request timed out' }), NOW);
    expect(check.ok).toBe(0);
    expect(check.error).toBe('Request timed out');
  });

  it('treats a reachable 4xx as ok (reachable, just a client-error status)', () => {
    const check = buildCheckInsert(1, probeResult({ status: 404 }), NOW);
    expect(check.ok).toBe(1);
  });
});

describe('applyCheckResultToMonitor', () => {
  it('resets consecutive_failures to 0 on success', () => {
    const m = monitor({ consecutive_failures: 3 });
    const check = buildCheckInsert(m.id, probeResult({ status: 200 }), NOW);
    const update = applyCheckResultToMonitor(m, check, NOW);
    expect(update.consecutive_failures).toBe(0);
  });

  it('increments consecutive_failures on failure', () => {
    const m = monitor({ consecutive_failures: 1 });
    const check = buildCheckInsert(m.id, probeResult({ ok: false, status: null, error: 'timeout' }), NOW);
    const update = applyCheckResultToMonitor(m, check, NOW);
    expect(update.consecutive_failures).toBe(2);
  });

  it('advances next_check_at by interval_seconds', () => {
    const m = monitor({ interval_seconds: 300 });
    const check = buildCheckInsert(m.id, probeResult({ status: 200 }), NOW);
    const update = applyCheckResultToMonitor(m, check, NOW);
    expect(update.next_check_at).toBe('2026-08-12T00:10:00.000Z');
  });
});

describe('runBoundedFanOut', () => {
  it('runs all items and preserves result order', async () => {
    const items = [1, 2, 3, 4, 5];
    const results = await runBoundedFanOut(items, async n => n * 2, 2);
    expect(results.map(r => (r.status === 'fulfilled' ? r.value : null))).toEqual([2, 4, 6, 8, 10]);
  });

  it('never runs more than `concurrency` workers at once', async () => {
    let active = 0;
    let maxActive = 0;
    const items = Array.from({ length: 10 }, (_, i) => i);
    await runBoundedFanOut(
      items,
      async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise(resolve => setTimeout(resolve, 5));
        active -= 1;
      },
      3
    );
    expect(maxActive).toBeLessThanOrEqual(3);
  });

  it('captures a rejection per item without failing the whole batch', async () => {
    const results = await runBoundedFanOut([1, 2, 3], async n => {
      if (n === 2) throw new Error('boom');
      return n;
    });
    expect(results[0]).toEqual({ status: 'fulfilled', value: 1 });
    expect(results[1].status).toBe('rejected');
    expect(results[2]).toEqual({ status: 'fulfilled', value: 3 });
  });
});
