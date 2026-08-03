import { describe, it, expect } from 'vitest';
import { computeScore, scoreToGrade } from '../src/scoring';
import type { Finding } from '../src/types';

function finding(severity: Finding['severity'], confidence: Finding['confidence']): Finding {
  return {
    id: 'x',
    title: 't',
    severity,
    confidence,
    explanation: 'e',
  };
}

describe('computeScore', () => {
  it('returns 100 for no findings', () => {
    expect(computeScore([])).toBe(100);
  });

  it('applies severity weight at full confidence', () => {
    // critical/high confidence: 30 * 1 = 30 penalty
    expect(computeScore([finding('critical', 'high')])).toBe(70);
  });

  it('applies the confidence multiplier to reduce penalty', () => {
    // high severity, low confidence: 18 * 0.4 = 7.2 -> rounds to 7
    expect(computeScore([finding('high', 'low')])).toBe(93);
  });

  it('rounds fractional penalties from the confidence multiplier', () => {
    // low severity, medium confidence: 4 * 0.7 = 2.8 -> 100 - 2.8 = 97.2 -> rounds to 97
    expect(computeScore([finding('low', 'medium')])).toBe(97);
  });

  it('sums penalties across multiple findings', () => {
    // critical/high (30) + medium/medium (10*0.7=7) = 37 penalty
    expect(computeScore([finding('critical', 'high'), finding('medium', 'medium')])).toBe(63);
  });

  it('clamps the score at 0 rather than going negative', () => {
    const findings = Array.from({ length: 10 }, () => finding('critical', 'high'));
    expect(computeScore(findings)).toBe(0);
  });
});

describe('scoreToGrade', () => {
  it('grades boundary values correctly', () => {
    expect(scoreToGrade(100)).toBe('A');
    expect(scoreToGrade(90)).toBe('A');
    expect(scoreToGrade(89)).toBe('B');
    expect(scoreToGrade(75)).toBe('B');
    expect(scoreToGrade(74)).toBe('C');
    expect(scoreToGrade(60)).toBe('C');
    expect(scoreToGrade(59)).toBe('D');
    expect(scoreToGrade(40)).toBe('D');
    expect(scoreToGrade(39)).toBe('F');
    expect(scoreToGrade(0)).toBe('F');
  });
});
