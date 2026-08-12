/**
 * The pure logic behind the `scan_for_secrets` MCP tool, kept separate from
 * the MCP server wiring in index.ts so it can be unit tested without a
 * transport.
 *
 * Same rule as the rest of this codebase: a raw secret value never leaves
 * this function. Every finding's `redactedLine` goes through `redactLine`
 * before it's returned — the caller (an AI agent, over stdio) only ever
 * sees the masked version.
 */
import { linesFromCode } from "./input.js";
import { scan } from "./scan.js";
import { redactLine } from "./redact.js";
import type { Confidence } from "./rules.js";

export interface ScanFinding {
  filename: string;
  line: number;
  ruleId: string;
  description: string;
  confidence: Confidence;
  /** The finding's line, with the secret value masked via redactLine — never the raw value. */
  redactedLine: string;
}

export interface ScanResult {
  findings: ScanFinding[];
  summary: string;
}

export function scanForSecrets(code: string, filename?: string): ScanResult {
  const lines = linesFromCode(code, filename);
  const rawFindings = scan(lines);

  const findings: ScanFinding[] = rawFindings.map((f) => ({
    filename: f.filename,
    line: f.line,
    ruleId: f.ruleId,
    description: f.description,
    confidence: f.confidence,
    redactedLine: redactLine(f.contextLine, f.secret),
  }));

  return { findings, summary: buildSummary(findings) };
}

function buildSummary(findings: ScanFinding[]): string {
  if (findings.length === 0) {
    return "No secrets detected.";
  }

  const highCount = findings.filter((f) => f.confidence === "high").length;
  const genericCount = findings.length - highCount;

  const header = `Found ${findings.length} potential secret${findings.length === 1 ? "" : "s"} (${highCount} high-confidence, ${genericCount} needs-review).`;

  const rows = findings.map(
    (f) => `- [${f.confidence}] ${f.filename}:${f.line} — ${f.description} (${f.ruleId})\n  ${f.redactedLine}`,
  );

  return [header, "", ...rows].join("\n");
}
