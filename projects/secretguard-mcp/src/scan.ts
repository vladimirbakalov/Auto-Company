import type { AddedLine } from "./input.js";
import {
  PATTERN_RULES,
  buildGenericAssignmentRegex,
  isPlaceholderOrReference,
  shannonEntropy,
  ENTROPY_THRESHOLD,
  MIN_GENERIC_SECRET_LENGTH,
  type Confidence,
} from "./rules.js";

export interface Finding {
  filename: string;
  line: number;
  ruleId: string;
  description: string;
  confidence: Confidence;
  /** The raw matched secret substring. Kept in-memory only — every output path (tool result, logs) must redact this before it leaves the process. */
  secret: string;
  /** The full added-line content (raw, unredacted secret still inside — same rule applies). */
  contextLine: string;
}

function runPatternRules(al: AddedLine): Finding[] {
  const findings: Finding[] = [];

  for (const rule of PATTERN_RULES) {
    const regex = rule.build();
    let match: RegExpExecArray | null;
    while ((match = regex.exec(al.content))) {
      const secret = match[1] ?? match[0];
      findings.push({
        filename: al.filename,
        line: al.line,
        ruleId: rule.id,
        description: rule.description,
        confidence: rule.confidence ?? "high",
        secret,
        contextLine: al.content,
      });
      if (match[0].length === 0) regex.lastIndex++; // guard against zero-length-match infinite loops
    }
  }

  return findings;
}

function runGenericEntropyRule(al: AddedLine, exclude: Finding[]): Finding[] {
  const findings: Finding[] = [];
  const regex = buildGenericAssignmentRegex();
  let match: RegExpExecArray | null;

  while ((match = regex.exec(al.content))) {
    const [, varName, value] = match;
    if (value.length < MIN_GENERIC_SECRET_LENGTH) continue;
    if (isPlaceholderOrReference(value, al.content)) continue;
    if (shannonEntropy(value) < ENTROPY_THRESHOLD) continue;

    // Don't double-report a secret a pattern rule on this line already caught
    // (e.g. an AWS secret key assigned to a var literally named "aws_secret_access_key"
    // matches both the AWS pattern rule and this generic one).
    const alreadyCaught = exclude.some(
      (f) => f.secret === value || f.secret.includes(value) || value.includes(f.secret),
    );
    if (alreadyCaught) continue;

    findings.push({
      filename: al.filename,
      line: al.line,
      ruleId: "generic-high-entropy-secret",
      description: `High-entropy value assigned to "${varName.trim()}"`,
      confidence: "generic",
      secret: value,
      contextLine: al.content,
    });
  }

  return findings;
}

export function scanLine(al: AddedLine): Finding[] {
  const patternFindings = runPatternRules(al);
  const genericFindings = runGenericEntropyRule(al, patternFindings);
  return [...patternFindings, ...genericFindings];
}

export function scan(lines: AddedLine[]): Finding[] {
  return lines.flatMap(scanLine);
}
