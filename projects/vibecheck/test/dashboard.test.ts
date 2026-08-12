import { describe, it, expect } from 'vitest';
import {
  deriveCostRiskState,
  diffSecurityFindings,
  computeMutedUntil,
  isMuted,
  isMonitorOwnedByUser,
  COST_RISK_ELEVATED_WINDOW_MS,
  MUTE_DURATION_MS,
} from '../src/dashboard';
import { COLD_START_MIN_SAMPLES } from '../src/anomaly';
import type { Finding, MonitorRow } from '../src/types';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'live-cors-1',
    title: 'Permissive CORS policy on live deployment (wildcard origin)',
    severity: 'medium',
    confidence: 'high',
    explanation: 'explanation',
    ...overrides,
  };
}

describe('deriveCostRiskState', () => {
  const NOW = '2026-08-12T12:00:00.000Z';

  it('is "Learning" when trailing check count is below the cold-start floor', () => {
    expect(deriveCostRiskState(COLD_START_MIN_SAMPLES - 1, null, NOW)).toBe('Learning');
  });

  it('is not "Learning" once trailing check count reaches the cold-start floor exactly', () => {
    expect(deriveCostRiskState(COLD_START_MIN_SAMPLES, null, NOW)).toBe('Normal');
  });

  it('is "Normal" with enough samples and no recent latency_anomaly alert', () => {
    expect(deriveCostRiskState(50, null, NOW)).toBe('Normal');
  });

  it('is "Elevated" when a latency_anomaly fired just now', () => {
    expect(deriveCostRiskState(50, NOW, NOW)).toBe('Elevated');
  });

  it('is "Elevated" when a latency_anomaly fired exactly at the edge of the 24h window', () => {
    const firedAt = new Date(Date.parse(NOW) - COST_RISK_ELEVATED_WINDOW_MS).toISOString();
    expect(deriveCostRiskState(50, firedAt, NOW)).toBe('Elevated');
  });

  it('is "Normal" once the latency_anomaly is just outside the 24h window', () => {
    const firedAt = new Date(Date.parse(NOW) - COST_RISK_ELEVATED_WINDOW_MS - 1).toISOString();
    expect(deriveCostRiskState(50, firedAt, NOW)).toBe('Normal');
  });

  it('is "Normal" (not "Elevated") if the alert timestamp is somehow in the future', () => {
    const firedAt = new Date(Date.parse(NOW) + 60_000).toISOString();
    expect(deriveCostRiskState(50, firedAt, NOW)).toBe('Normal');
  });

  it('"Learning" takes priority over a recent latency_anomaly during cold-start', () => {
    expect(deriveCostRiskState(COLD_START_MIN_SAMPLES - 1, NOW, NOW)).toBe('Learning');
  });

  it('honors overridden minSamplesForBaseline/windowMs options', () => {
    expect(deriveCostRiskState(3, null, NOW, { minSamplesForBaseline: 3 })).toBe('Normal');
    const firedAt = new Date(Date.parse(NOW) - 60_000).toISOString();
    expect(deriveCostRiskState(50, firedAt, NOW, { windowMs: 30_000 })).toBe('Normal');
  });
});

describe('diffSecurityFindings', () => {
  it('returns no new findings when live matches baseline exactly', () => {
    const baseline = [finding({ title: 'A' }), finding({ title: 'B' })];
    const live = [finding({ title: 'A' }), finding({ title: 'B' })];
    expect(diffSecurityFindings(baseline, live)).toEqual({ newFindings: [] });
  });

  it('flags a finding present live but not in the baseline', () => {
    const baseline = [finding({ title: 'A' })];
    const newFinding = finding({ title: 'B' });
    const live = [finding({ title: 'A' }), newFinding];
    expect(diffSecurityFindings(baseline, live)).toEqual({ newFindings: [newFinding] });
  });

  it('does not flag a finding that disappeared since baseline (drift is additive-only)', () => {
    const baseline = [finding({ title: 'A' }), finding({ title: 'B' })];
    const live = [finding({ title: 'A' })];
    expect(diffSecurityFindings(baseline, live)).toEqual({ newFindings: [] });
  });

  it('diffs on title, not id, since live-probe ids are per-call and not stable', () => {
    const baseline = [finding({ id: 'live-cors-1', title: 'Permissive CORS' })];
    const live = [finding({ id: 'live-cors-7', title: 'Permissive CORS' })];
    expect(diffSecurityFindings(baseline, live)).toEqual({ newFindings: [] });
  });

  it('handles an empty baseline (everything live is "new")', () => {
    const live = [finding({ title: 'A' }), finding({ title: 'B' })];
    expect(diffSecurityFindings([], live)).toEqual({ newFindings: live });
  });
});

describe('computeMutedUntil / isMuted', () => {
  const NOW = '2026-08-12T12:00:00.000Z';

  it('computeMutedUntil(false) clears the mute (returns null)', () => {
    expect(computeMutedUntil(false, NOW)).toBeNull();
  });

  it('computeMutedUntil(true) sets muted_until MUTE_DURATION_MS out from now', () => {
    const result = computeMutedUntil(true, NOW);
    expect(result).toBe(new Date(Date.parse(NOW) + MUTE_DURATION_MS).toISOString());
  });

  it('isMuted is true when muted_until is in the future', () => {
    const mutedUntil = new Date(Date.parse(NOW) + 1000).toISOString();
    expect(isMuted(mutedUntil, NOW)).toBe(true);
  });

  it('isMuted is false when muted_until is in the past', () => {
    const mutedUntil = new Date(Date.parse(NOW) - 1000).toISOString();
    expect(isMuted(mutedUntil, NOW)).toBe(false);
  });

  it('isMuted is false when muted_until is exactly now (mute has just expired)', () => {
    expect(isMuted(NOW, NOW)).toBe(false);
  });

  it('isMuted is false when muted_until is null', () => {
    expect(isMuted(null, NOW)).toBe(false);
  });
});

describe('isMonitorOwnedByUser', () => {
  function monitor(userId: number): Pick<MonitorRow, 'user_id'> {
    return { user_id: userId };
  }

  it('is true when the monitor belongs to the given user', () => {
    expect(isMonitorOwnedByUser(monitor(1), 1)).toBe(true);
  });

  it('is false when the monitor belongs to a different user', () => {
    expect(isMonitorOwnedByUser(monitor(2), 1)).toBe(false);
  });
});
