import { describe, it, expect } from 'vitest';
import {
  median,
  detectTrafficAnomaly,
  evaluateUptimeTransition,
  COLD_START_THRESHOLD,
  COLD_START_MIN_SAMPLES,
  CONSECUTIVE_FAILURE_THRESHOLD,
} from '../src/anomaly';

describe('median', () => {
  it('returns 0 for an empty array', () => {
    expect(median([])).toBe(0);
  });

  it('returns the middle value for an odd-length array', () => {
    expect(median([3, 1, 2])).toBe(2);
  });

  it('averages the two middle values for an even-length array', () => {
    expect(median([1, 2, 3, 4])).toBe(2.5);
  });

  it('does not mutate the input array', () => {
    const input = [5, 3, 1];
    median(input);
    expect(input).toEqual([5, 3, 1]);
  });
});

describe('detectTrafficAnomaly', () => {
  it('uses the fixed cold-start threshold when fewer than 7 trailing samples exist', () => {
    const verdict = detectTrafficAnomaly({ currentValue: 600, trailingValues: [10, 20, 30] });
    expect(verdict.coldStart).toBe(true);
    expect(verdict.reason).toBe('cold_start_threshold');
    expect(verdict.isAnomaly).toBe(true);
    expect(verdict.baselineMedian).toBeNull();
  });

  it('does not flag cold-start traffic below the fixed threshold', () => {
    const verdict = detectTrafficAnomaly({ currentValue: 100, trailingValues: [] });
    expect(verdict.isAnomaly).toBe(false);
    expect(verdict.reason).toBe('cold_start_threshold');
  });

  it('exactly at COLD_START_MIN_SAMPLES trailing values, uses the median baseline (not cold-start)', () => {
    const trailing = Array(COLD_START_MIN_SAMPLES).fill(50); // median = 50
    const verdict = detectTrafficAnomaly({ currentValue: 600, trailingValues: trailing });
    expect(verdict.coldStart).toBe(false);
    expect(verdict.reason).toBe('median_multiplier');
    expect(verdict.isAnomaly).toBe(true); // 600 > 50 * 10
  });

  it('flags a value more than 10x the trailing median once a baseline exists', () => {
    const trailing = [40, 50, 60, 45, 55, 48, 52]; // median 50
    const verdict = detectTrafficAnomaly({ currentValue: 501, trailingValues: trailing });
    expect(verdict.isAnomaly).toBe(true);
    expect(verdict.baselineMedian).toBe(50);
  });

  it('does not flag a value at or below 10x the trailing median', () => {
    const trailing = [40, 50, 60, 45, 55, 48, 52]; // median 50
    const verdict = detectTrafficAnomaly({ currentValue: 500, trailingValues: trailing });
    expect(verdict.isAnomaly).toBe(false);
  });

  it('falls back to the fixed threshold when the trailing baseline median is zero', () => {
    const trailing = [0, 0, 0, 0, 0, 0, 0];
    const belowThreshold = detectTrafficAnomaly({ currentValue: 5, trailingValues: trailing });
    expect(belowThreshold.reason).toBe('zero_baseline');
    expect(belowThreshold.isAnomaly).toBe(false);

    const aboveThreshold = detectTrafficAnomaly({
      currentValue: COLD_START_THRESHOLD + 1,
      trailingValues: trailing,
    });
    expect(aboveThreshold.isAnomaly).toBe(true);
  });

  it('respects custom threshold/multiplier overrides', () => {
    const verdict = detectTrafficAnomaly({
      currentValue: 30,
      trailingValues: [10, 10, 10, 10, 10, 10, 10],
      spikeMultiplier: 2,
    });
    expect(verdict.isAnomaly).toBe(true); // 30 > 10 * 2
  });
});

describe('evaluateUptimeTransition', () => {
  it('does nothing on the first failure (below the consecutive-failure threshold)', () => {
    const result = evaluateUptimeTransition({
      ok: false,
      consecutiveFailures: 1,
      hasOpenDownAlert: false,
    });
    expect(result).toBe('none');
  });

  it('fires a down alert once consecutive failures reach the threshold', () => {
    const result = evaluateUptimeTransition({
      ok: false,
      consecutiveFailures: CONSECUTIVE_FAILURE_THRESHOLD,
      hasOpenDownAlert: false,
    });
    expect(result).toBe('fire_down');
  });

  it('does not re-fire down while already in a down state', () => {
    const result = evaluateUptimeTransition({
      ok: false,
      consecutiveFailures: 5,
      hasOpenDownAlert: true,
    });
    expect(result).toBe('none');
  });

  it('fires a recovered alert on the first success after an open down alert', () => {
    const result = evaluateUptimeTransition({
      ok: true,
      consecutiveFailures: 0,
      hasOpenDownAlert: true,
    });
    expect(result).toBe('fire_recovered');
  });

  it('does nothing on a normal success with no open alert', () => {
    const result = evaluateUptimeTransition({
      ok: true,
      consecutiveFailures: 0,
      hasOpenDownAlert: false,
    });
    expect(result).toBe('none');
  });
});
