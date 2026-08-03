// vibecheck — turns a list of findings into a 0-100 score and A-F grade.

import type { Finding } from './types';

const SEVERITY_WEIGHT: Record<Finding['severity'], number> = {
  critical: 30,
  high: 18,
  medium: 10,
  low: 4,
};

// Low-confidence findings are real signal but shouldn't tank the score as hard
// as a high-confidence hit of the same severity — the missing-auth heuristic
// in particular is noisy by design (see checks.ts).
const CONFIDENCE_MULTIPLIER: Record<Finding['confidence'], number> = {
  high: 1,
  medium: 0.7,
  low: 0.4,
};

export function computeScore(findings: Finding[]): number {
  const penalty = findings.reduce(
    (sum, f) => sum + SEVERITY_WEIGHT[f.severity] * CONFIDENCE_MULTIPLIER[f.confidence],
    0
  );
  return Math.max(0, Math.round(100 - penalty));
}

export function scoreToGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
