/**
 * Turns the unified-diff `patch` text GitHub returns per file into a flat
 * list of *added* lines, each tagged with its line number in the new file.
 *
 * This is deliberately narrow: we only ever want to scan lines a PR is
 * introducing. Context lines (unchanged, prefixed with a space) and removed
 * lines (prefixed with `-`) are walked only to keep the new-file line
 * counter correct — their content is never scanned, so a secret that was
 * already sitting in the repo before this PR (and merely shown as context,
 * or even deleted) is never flagged. That's the whole point: this action
 * reviews what a PR is adding, not the state of the repo.
 */

export interface PullRequestFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  patch?: string;
}

export interface AddedLine {
  filename: string;
  line: number;
  content: string;
}

const HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

export function extractAddedLines(files: PullRequestFile[]): AddedLine[] {
  const result: AddedLine[] = [];

  for (const file of files) {
    if (!file.patch) continue; // binary file, or diff too large for the API to return — nothing to scan
    if (file.status === "removed") continue; // deleted file: it has no new lines

    let newLineNum = 0;

    for (const rawLine of file.patch.split("\n")) {
      const hunkMatch = rawLine.match(HUNK_HEADER);
      if (hunkMatch) {
        newLineNum = parseInt(hunkMatch[1], 10);
        continue;
      }

      if (rawLine.startsWith("\\")) continue; // "\ No newline at end of file" — not a content line

      if (rawLine.startsWith("+")) {
        result.push({ filename: file.filename, line: newLineNum, content: rawLine.slice(1) });
        newLineNum++;
      } else if (rawLine.startsWith("-")) {
        // Removed line: existed only in the old file, doesn't advance the new-file counter.
      } else {
        // Context line (unchanged, present in both old and new file).
        newLineNum++;
      }
    }
  }

  return result;
}
