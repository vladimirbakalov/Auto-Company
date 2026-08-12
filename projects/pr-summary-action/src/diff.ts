/**
 * Turns the list of changed files from the GitHub API into a bounded chunk
 * of text we can safely hand to the model.
 *
 * Strategy, cheapest-first:
 *   1. Always include a full file list (path, status, +/-) — this is small
 *      and gives the model the full shape of the change even if patches
 *      get cut.
 *   2. Fill the remaining budget with patches, smallest files first. Small
 *      diffs are usually the most information-dense per character (a
 *      one-line config change matters more than 4,000 lines of a
 *      generated lockfile), so they get shown in full while any leftover
 *      budget is spent on the big ones.
 *   3. Whatever doesn't fit gets a "(diff omitted — budget exceeded)" or
 *      "(diff truncated — showing first N of M characters)" note instead
 *      of being silently dropped or blowing the character budget.
 */

export interface PullRequestFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  patch?: string;
}

export interface DiffPayload {
  /** The bounded text to send to the model. */
  text: string;
  /** Whether anything was cut (missing patch, per-file truncation, or omitted files). */
  truncated: boolean;
}

const MIN_CHARS_PER_FILE = 200;

export function buildDiffText(files: PullRequestFile[], maxChars: number): DiffPayload {
  const budget = Math.max(maxChars, 50); // absolute floor so slicing math below stays sane
  let truncated = false;

  const fileListLines = files.map((f) => `- ${f.status}: ${f.filename} (+${f.additions}/-${f.deletions})`);
  const fileListSection = `Changed files (${files.length}):\n${fileListLines.join("\n")}`;

  let remaining = budget - fileListSection.length - 200; // headroom for headers/joins
  if (remaining <= 0) {
    // The file list alone blew the budget (an enormous PR). Truncate the
    // list itself rather than emit nothing.
    return {
      text: fileListSection.slice(0, budget),
      truncated: true,
    };
  }

  // Smallest patches first so they're least likely to get cut.
  const order = [...files]
    .map((f, index) => ({ file: f, index }))
    .sort((a, b) => (a.file.patch?.length ?? 0) - (b.file.patch?.length ?? 0));

  const sections = new Map<number, string>();

  for (let i = 0; i < order.length; i++) {
    const { file, index } = order[i];
    const header = `\n\n=== ${file.filename} (${file.status}, +${file.additions}/-${file.deletions}) ===\n`;

    if (!file.patch) {
      const note = file.status === "renamed" && file.changes === 0
        ? "(renamed, no content change)"
        : "(no textual diff available — binary file or diff too large for the GitHub API to return)";
      const entry = header + note;
      // These notes are cheap individually, but a PR touching thousands of
      // binary/oversized files (nothing rare for a vendored dependency
      // bump) would otherwise add them unconditionally with no budget
      // check at all — the one part of this function that wasn't actually
      // bounded. Charge them against `remaining` like everything else, and
      // drop the note (the file is still named in the file list above)
      // once the budget is gone.
      if (entry.length > remaining) {
        truncated = true;
        continue;
      }
      sections.set(index, entry);
      remaining -= entry.length;
      truncated = truncated || file.status !== "renamed";
      continue;
    }

    const filesLeft = order.length - i;
    // Give later (larger) files a fair share of what's left, but never so
    // much that one huge file eats everything.
    const perFileCap = Math.max(MIN_CHARS_PER_FILE, Math.floor(remaining / filesLeft));
    const cap = Math.min(perFileCap, remaining);

    if (cap < MIN_CHARS_PER_FILE) {
      sections.set(index, header + "(diff omitted — character budget exceeded)");
      truncated = true;
      continue;
    }

    if (file.patch.length <= cap) {
      sections.set(index, header + file.patch);
      remaining -= header.length + file.patch.length;
    } else {
      const shown = file.patch.slice(0, cap);
      sections.set(
        index,
        `${header}${shown}\n… (truncated — showing first ${cap} of ${file.patch.length} characters)`,
      );
      remaining -= header.length + cap;
      truncated = true;
    }
  }

  const orderedSections = files.map((_, index) => sections.get(index) ?? "").join("");
  return {
    text: `${fileListSection}${orderedSections}`,
    truncated,
  };
}
