import { describe, expect, it } from "vitest";
import { extractAddedLines, type PullRequestFile } from "./diff";

function file(overrides: Partial<PullRequestFile> = {}): PullRequestFile {
  return {
    filename: "src/foo.ts",
    status: "modified",
    additions: 1,
    deletions: 1,
    changes: 2,
    ...overrides,
  };
}

describe("extractAddedLines", () => {
  it("extracts only added lines, with correct new-file line numbers", () => {
    const patch = ["@@ -1,3 +1,4 @@", " context line", "-removed line", "+added line one", "+added line two", " trailing context"].join(
      "\n",
    );
    const lines = extractAddedLines([file({ patch })]);

    expect(lines).toEqual([
      { filename: "src/foo.ts", line: 2, content: "added line one" },
      { filename: "src/foo.ts", line: 3, content: "added line two" },
    ]);
  });

  it("does not flag pre-existing secrets shown only as unchanged context", () => {
    const patch = [
      "@@ -1,3 +1,3 @@",
      " const OLD_KEY = 'AKIAABCDEFGHIJKLMNOP';",
      "-const unrelated = 1;",
      "+const unrelated = 2;",
    ].join("\n");
    const lines = extractAddedLines([file({ patch })]);

    expect(lines).toHaveLength(1);
    expect(lines[0].content).toBe("const unrelated = 2;");
    expect(lines.some((l) => l.content.includes("AKIA"))).toBe(false);
  });

  it("does not flag a secret that only appears on a removed line", () => {
    const patch = ["@@ -1,2 +1,1 @@", "-const KEY = 'AKIAABCDEFGHIJKLMNOP';", " const stays = true;"].join("\n");
    const lines = extractAddedLines([file({ patch })]);

    expect(lines.some((l) => l.content.includes("AKIA"))).toBe(false);
  });

  it("handles multiple hunks in one file, resetting the line counter per hunk header", () => {
    const patch = [
      "@@ -1,2 +1,2 @@",
      " a",
      "+b",
      "@@ -10,2 +11,2 @@",
      " c",
      "+d",
    ].join("\n");
    const lines = extractAddedLines([file({ patch })]);

    expect(lines).toEqual([
      { filename: "src/foo.ts", line: 2, content: "b" },
      { filename: "src/foo.ts", line: 12, content: "d" },
    ]);
  });

  it("skips files with no patch (binary or too large for the API)", () => {
    const lines = extractAddedLines([file({ patch: undefined, filename: "image.png" })]);
    expect(lines).toEqual([]);
  });

  it("skips removed files entirely", () => {
    const patch = ["@@ -1,2 +0,0 @@", "-const KEY = 'AKIAABCDEFGHIJKLMNOP';"].join("\n");
    const lines = extractAddedLines([file({ patch, status: "removed" })]);
    expect(lines).toEqual([]);
  });

  it("ignores the 'no newline at end of file' marker without shifting line numbers", () => {
    const patch = ["@@ -1,1 +1,2 @@", "+first", "+second", "\\ No newline at end of file"].join("\n");
    const lines = extractAddedLines([file({ patch })]);

    expect(lines).toEqual([
      { filename: "src/foo.ts", line: 1, content: "first" },
      { filename: "src/foo.ts", line: 2, content: "second" },
    ]);
  });

  it("handles a newly added file (all lines added)", () => {
    const patch = ["@@ -0,0 +1,2 @@", "+line one", "+line two"].join("\n");
    const lines = extractAddedLines([file({ patch, status: "added" })]);

    expect(lines).toEqual([
      { filename: "src/foo.ts", line: 1, content: "line one" },
      { filename: "src/foo.ts", line: 2, content: "line two" },
    ]);
  });

  it("processes multiple files independently", () => {
    const files = [
      file({ filename: "a.ts", patch: "@@ -1,1 +1,1 @@\n+from a" }),
      file({ filename: "b.ts", patch: "@@ -1,1 +1,1 @@\n+from b" }),
    ];
    const lines = extractAddedLines(files);

    expect(lines.map((l) => l.filename)).toEqual(["a.ts", "b.ts"]);
  });
});
