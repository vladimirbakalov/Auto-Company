/**
 * Turns an arbitrary code string into the same `AddedLine[]` shape the
 * original secret-scan-action builds from a PR diff, so `scanLine`/`scan`
 * can run unchanged against it.
 *
 * There's no diff here — an AI agent calling this tool is handing over code
 * it's about to write or commit, not a PR. Every line in the input is
 * scanned (there's no "unchanged context" to skip), tagged with its 1-based
 * line number and the given (or default) filename.
 */

export interface AddedLine {
  filename: string;
  line: number;
  content: string;
}

export const DEFAULT_FILENAME = "input";

export function linesFromCode(code: string, filename: string = DEFAULT_FILENAME): AddedLine[] {
  return code.split("\n").map((content, index) => ({
    filename,
    line: index + 1,
    content,
  }));
}
