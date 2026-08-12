/**
 * Lets a repo suppress known false positives without disabling the rule
 * that keeps tripping on them. Sources: the `allowlist` action input
 * (inline, newline-separated) and an optional `.secretscanignore` file in
 * the repo, merged together.
 *
 * Each non-empty, non-comment line is a regex (case-insensitive) tested
 * against the finding's raw secret value, its full changed-line content, and
 * its file path. Any match suppresses the finding. Invalid regex lines are
 * skipped rather than crashing the run — a typo in an ignore file shouldn't
 * take down the whole check.
 */

import type { Finding } from "./scan";

export interface AllowlistEntry {
  source: string;
  regex: RegExp;
}

export function parseAllowlistSource(raw: string): AllowlistEntry[] {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((pattern) => {
      try {
        return { source: pattern, regex: new RegExp(pattern, "i") };
      } catch {
        return undefined;
      }
    })
    .filter((entry): entry is AllowlistEntry => entry !== undefined);
}

export function buildAllowlist(inlineInput: string, fileContent?: string): AllowlistEntry[] {
  const entries = parseAllowlistSource(inlineInput);
  if (fileContent) entries.push(...parseAllowlistSource(fileContent));
  return entries;
}

export function isAllowlisted(finding: Pick<Finding, "filename" | "secret" | "contextLine">, entries: AllowlistEntry[]): boolean {
  return entries.some(
    (entry) =>
      entry.regex.test(finding.secret) || entry.regex.test(finding.contextLine) || entry.regex.test(finding.filename),
  );
}
