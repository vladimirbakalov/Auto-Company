// vibecheck — anomaly detection math (pure functions, no D1/HTTP I/O)
//
// Deliberately arithmetic, not infrastructure (ADR §4): everything here is a
// pure function over plain numbers/booleans so it can be unit tested without
// a live D1 binding, and so the `scheduled` handler in index.ts stays a thin
// orchestrator that reads check history, calls these, and writes the verdict.
//
// Two things are implemented, matching the two ADR §6 alert triggers:
//   1. detectTrafficAnomaly — product spec §1.2's cost-spike proxy: a 10x
//      trailing-median trigger, with a fixed absolute threshold during
//      cold-start (< 7 days of baseline). NOTE on the metric it's fed: the
//      D1 checks schema (migrations/0001_init.sql) records latency/status
//      per check, not a raw request-volume count — vibecheck's uptime probe
//      doesn't have visibility into the monitored app's real traffic. Per
//      ADR §4, the honest v1 proxy signal is response-time/error-rate drift,
//      so `currentValue`/`trailingValues` here are meant to be fed
//      latency-ms (or, once a real volume signal exists — e.g. from the
//      security-scan's flagged-endpoint list — request counts) rather than
//      invented traffic numbers. The math is identical either way; this
//      function does not care what the unit is, only that "10x trailing
//      median" is the decidable rule spec §1.2 asked for.
//   2. evaluateUptimeTransition — ADR §6 steps 5-7: 2 consecutive failures
//      fires a 'down' alert (one blip shouldn't page anyone), and the next
//      success after a 'down' state fires a 'recovered' alert.

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

// Minimum trailing observations required before we trust a computed median
// baseline over the fixed cold-start threshold. Spec §1.2 frames this as
// "< 7 days of baseline data" — expressed here as a sample-count floor
// (the caller decides what one "sample" represents, e.g. one per day).
export const COLD_START_MIN_SAMPLES = 7;

// Fixed absolute threshold used during cold-start, per spec §1.2 example
// ("e.g., >500 requests/hour to a single endpoint"). Kept as a named export
// so it's a single, greppable knob to tune, not a magic number.
export const COLD_START_THRESHOLD = 500;

// Multiplier that defines a "spike" once a real baseline exists.
export const SPIKE_MULTIPLIER = 10;

export type AnomalyReason = 'cold_start_threshold' | 'median_multiplier' | 'zero_baseline';

export interface AnomalyVerdict {
  isAnomaly: boolean;
  reason: AnomalyReason;
  baselineMedian: number | null; // null during cold-start (no trustworthy baseline yet)
  coldStart: boolean;
}

export interface AnomalyInput {
  currentValue: number;
  // Trailing baseline samples (most recent check excluded), e.g. one value
  // per day over the trailing 7 days per spec §1.2.
  trailingValues: number[];
  coldStartThreshold?: number;
  spikeMultiplier?: number;
  minSamplesForBaseline?: number;
}

export function detectTrafficAnomaly(input: AnomalyInput): AnomalyVerdict {
  const {
    currentValue,
    trailingValues,
    coldStartThreshold = COLD_START_THRESHOLD,
    spikeMultiplier = SPIKE_MULTIPLIER,
    minSamplesForBaseline = COLD_START_MIN_SAMPLES,
  } = input;

  const coldStart = trailingValues.length < minSamplesForBaseline;
  if (coldStart) {
    return {
      isAnomaly: currentValue > coldStartThreshold,
      reason: 'cold_start_threshold',
      baselineMedian: null,
      coldStart: true,
    };
  }

  const baseline = median(trailingValues);
  if (baseline === 0) {
    // 10x of zero is zero — every positive value would "spike" a genuinely
    // idle baseline. Fall back to the fixed threshold rather than firing on
    // noise (spec §1.2: "deliberately conservative on false positives").
    return {
      isAnomaly: currentValue > coldStartThreshold,
      reason: 'zero_baseline',
      baselineMedian: 0,
      coldStart: false,
    };
  }

  return {
    isAnomaly: currentValue > baseline * spikeMultiplier,
    reason: 'median_multiplier',
    baselineMedian: baseline,
    coldStart: false,
  };
}

// ── Uptime state transitions (ADR §6 steps 5-7) ─────────────────────────────

// One blip shouldn't page anyone — require 2 consecutive failures before
// firing a 'down' alert.
export const CONSECUTIVE_FAILURE_THRESHOLD = 2;

export type UptimeTransition = 'fire_down' | 'fire_recovered' | 'none';

export interface UptimeTransitionInput {
  ok: boolean; // this check's result
  consecutiveFailures: number; // count *after* this check (0 if ok)
  hasOpenDownAlert: boolean; // whether an unresolved 'down' alert exists for this monitor
  failureThreshold?: number;
}

// Decides whether this check result should fire a new 'down' alert, resolve
// an existing one with a 'recovered' alert, or do nothing (still-failing
// below threshold, or still-healthy with no open alert — no state change).
export function evaluateUptimeTransition(input: UptimeTransitionInput): UptimeTransition {
  const { ok, consecutiveFailures, hasOpenDownAlert, failureThreshold = CONSECUTIVE_FAILURE_THRESHOLD } = input;

  if (!ok) {
    if (!hasOpenDownAlert && consecutiveFailures >= failureThreshold) {
      return 'fire_down';
    }
    return 'none';
  }

  // ok === true
  if (hasOpenDownAlert) {
    return 'fire_recovered';
  }
  return 'none';
}
