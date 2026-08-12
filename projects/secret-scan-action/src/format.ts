import { redactLine } from "./redact";
import type { Finding } from "./scan";

const SIGNATURE = "— flagged by secret-scan-action";

export interface FormatOptions {
  /** Whether the optional Claude triage step ran and already filtered the generic-tier findings. */
  triageApplied: boolean;
}

export function formatComment(findings: Finding[], options: FormatOptions): string {
  if (findings.length === 0) {
    return ["## 🔒 Secret Scan", "", "No secrets detected in this PR's changed lines. ✅", "", SIGNATURE].join("\n");
  }

  const high = findings.filter((f) => f.confidence === "high");
  const generic = findings.filter((f) => f.confidence === "generic");

  const lines: string[] = ["## 🔒 Secret Scan", ""];
  lines.push(
    `Found **${findings.length}** potential secret${findings.length === 1 ? "" : "s"} in this PR's changed lines.`,
  );
  lines.push("");

  if (high.length > 0) {
    lines.push(`### 🚫 High confidence — blocks this check (${high.length})`);
    lines.push("");
    lines.push(...renderTable(high));
    lines.push("");
  }

  if (generic.length > 0) {
    lines.push(`### ⚠️ Needs review — generic high-entropy match (${generic.length})`);
    lines.push("");
    if (options.triageApplied) {
      lines.push("_Already reviewed by Claude to cut obvious false positives — still worth a human look._");
      lines.push("");
    }
    lines.push(...renderTable(generic));
    lines.push("");
  }

  lines.push(
    "False positive? Add a pattern to `.secretscanignore` (or the `allowlist` input) matching the value, the line, or the file path.",
  );
  lines.push("");
  lines.push(SIGNATURE);

  return lines.join("\n");
}

function renderTable(findings: Finding[]): string[] {
  return [
    "| File | Line | Rule | Snippet |",
    "|---|---|---|---|",
    ...findings.map((f) => {
      const redacted = redactLine(f.contextLine, f.secret);
      const snippet = truncate(sanitizeForTable(redacted));
      return `| \`${sanitizeForTable(f.filename)}\` | ${f.line} | ${sanitizeForTable(f.description)} | \`${snippet}\` |`;
    }),
  ];
}

function sanitizeForTable(value: string): string {
  // Swap markdown-table-breaking characters for lookalikes rather than
  // backslash-escaping them — an escaped "\|" still contains a literal "|"
  // that a naive downstream split/parse of the table could trip on.
  return value
    .replace(/`/g, "'")
    .replace(/\|/g, "｜") // fullwidth vertical bar
    .replace(/\r?\n/g, " ")
    .trim();
}

function truncate(value: string, max = 160): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}
