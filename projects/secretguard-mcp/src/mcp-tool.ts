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

/**
 * Upper bound on how much of the `code` input is actually scanned.
 *
 * `code` comes straight from an MCP tool call — any client on the other end
 * of the stdio transport can send an arbitrarily large string. The rule
 * engine runs ~90 regexes per line with no cap of its own (unlike
 * secret-scan-action, where GitHub's PR-diff API already bounds patch size
 * per file before this code ever sees it), so an unbounded input is a real
 * CPU/memory exhaustion vector for the local server process. 5MB comfortably
 * covers any real single-file/snippet scan an agent would plausibly submit.
 */
const MAX_CODE_LENGTH = 5_000_000;

export function scanForSecrets(code: string, filename?: string): ScanResult {
  const truncated = code.length > MAX_CODE_LENGTH;
  const bounded = truncated ? code.slice(0, MAX_CODE_LENGTH) : code;

  const lines = linesFromCode(bounded, filename);
  const rawFindings = scan(lines);

  const findings: ScanFinding[] = rawFindings.map((f) => ({
    filename: f.filename,
    line: f.line,
    ruleId: f.ruleId,
    description: f.description,
    confidence: f.confidence,
    redactedLine: redactLine(f.contextLine, f.secret),
  }));

  return { findings, summary: buildSummary(findings, truncated) };
}

/**
 * Shape returned by the `scan_for_secrets` MCP tool handler, per the MCP tool-result
 * contract. `structuredContent` is intersected with `Record<string, unknown>` — not
 * because callers should index into it dynamically, but because the MCP SDK's
 * `CallToolResult` type requires a string index signature on `structuredContent`,
 * which the plain `ScanResult` interface doesn't declare.
 */
export interface ScanToolResponse extends Record<string, unknown> {
  content: [{ type: "text"; text: string }];
  structuredContent: ScanResult & Record<string, unknown>;
}

/**
 * Maps a {@link ScanResult} to the MCP tool-result envelope. Kept separate from
 * index.ts's server wiring, same reason as `scanForSecrets` itself, so the exact
 * response shape a client receives — including that `summary` appears both in
 * `content` (for a text-only client) and `structuredContent` (for a typed one) —
 * is unit tested without standing up a transport.
 */
export function toToolResponse(result: ScanResult): ScanToolResponse {
  return {
    content: [{ type: "text", text: result.summary }],
    structuredContent: { ...result },
  };
}

function buildSummary(findings: ScanFinding[], truncated: boolean): string {
  const truncationNote = truncated
    ? `\n\n(Input exceeded ${MAX_CODE_LENGTH.toLocaleString()} characters — only the first ${MAX_CODE_LENGTH.toLocaleString()} were scanned. Consider scanning smaller chunks.)`
    : "";

  if (findings.length === 0) {
    return `No secrets detected.${truncationNote}`;
  }

  const highCount = findings.filter((f) => f.confidence === "high").length;
  const genericCount = findings.length - highCount;

  const header = `Found ${findings.length} potential secret${findings.length === 1 ? "" : "s"} (${highCount} high-confidence, ${genericCount} needs-review).`;

  const rows = findings.map(
    (f) => `- [${f.confidence}] ${f.filename}:${f.line} — ${f.description} (${f.ruleId})\n  ${f.redactedLine}`,
  );

  return [header, "", ...rows].join("\n") + truncationNote;
}
