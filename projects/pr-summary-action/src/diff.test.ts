import { describe, expect, it } from "vitest";
import { buildDiffText, type PullRequestFile } from "./diff";

function file(overrides: Partial<PullRequestFile> = {}): PullRequestFile {
  return {
    filename: "src/foo.ts",
    status: "modified",
    additions: 1,
    deletions: 1,
    changes: 2,
    patch: "@@ -1,1 +1,1 @@\n-old\n+new",
    ...overrides,
  };
}

describe("buildDiffText", () => {
  it("includes the full patch when everything fits comfortably under the budget", () => {
    const files = [file({ filename: "a.ts" }), file({ filename: "b.ts" })];
    const { text, truncated } = buildDiffText(files, 60000);

    expect(truncated).toBe(false);
    expect(text).toContain("a.ts");
    expect(text).toContain("b.ts");
    expect(text).toContain("-old");
    expect(text).toContain("+new");
  });

  it("always includes the full file list even when patches must be cut", () => {
    const bigPatch = "+".repeat(50000);
    const files = [
      file({ filename: "small.ts", patch: "tiny diff" }),
      file({ filename: "huge-generated.lock", patch: bigPatch }),
    ];
    const { text, truncated } = buildDiffText(files, 2000);

    expect(truncated).toBe(true);
    expect(text).toContain("Changed files (2)");
    expect(text).toContain("small.ts");
    expect(text).toContain("huge-generated.lock");
  });

  it("never emits text longer than a small multiple of the requested budget", () => {
    const bigPatch = "x".repeat(200000);
    const files = Array.from({ length: 20 }, (_, i) => file({ filename: `file-${i}.ts`, patch: bigPatch }));
    const { text } = buildDiffText(files, 5000);

    // We don't promise an exact byte cap (headers/notes add a little overhead),
    // but a 20x overrun would mean the truncation logic isn't doing its job.
    expect(text.length).toBeLessThan(5000 * 5);
  });

  it("prioritizes small diffs, showing them in full before spending budget on large ones", () => {
    const smallPatch = "small change here";
    const bigPatch = "y".repeat(100000);
    const files = [
      file({ filename: "big.ts", patch: bigPatch }),
      file({ filename: "small.ts", patch: smallPatch }),
    ];
    const { text } = buildDiffText(files, 3000);

    expect(text).toContain(smallPatch);
  });

  it("marks files with no patch (binary or too large for the API) instead of crashing", () => {
    const files = [file({ filename: "image.png", patch: undefined, status: "modified" })];
    const { text, truncated } = buildDiffText(files, 60000);

    expect(text).toContain("image.png");
    expect(text).toContain("no textual diff available");
    expect(truncated).toBe(true);
  });

  it("does not flag a content-free rename as truncated", () => {
    const files = [file({ filename: "new-name.ts", patch: undefined, status: "renamed", changes: 0 })];
    const { truncated } = buildDiffText(files, 60000);

    expect(truncated).toBe(false);
  });

  it("preserves original file order in the output regardless of internal size-sorting", () => {
    const files = [
      file({ filename: "z-first.ts", patch: "z content" }),
      file({ filename: "a-second.ts", patch: "a content" }),
    ];
    const { text } = buildDiffText(files, 60000);

    expect(text.indexOf("z-first.ts")).toBeLessThan(text.indexOf("a-second.ts"));
  });

  it("handles an empty file list without throwing", () => {
    const { text, truncated } = buildDiffText([], 60000);
    expect(text).toContain("Changed files (0)");
    expect(truncated).toBe(false);
  });

  it("bounds output even when many files have no patch (binary/oversized diffs)", () => {
    // Regression test: the "no textual diff available" note used to be
    // appended for every patch-less file with zero budget accounting, so a
    // PR touching thousands of binary/oversized files (plausible for a
    // vendored dependency bump) could blow the character budget wide open
    // even though every other code path in this function was bounded.
    const files = Array.from({ length: 100 }, (_, i) =>
      file({ filename: `asset-${i}.png`, patch: undefined, status: "modified", changes: 1 }),
    );
    const { text, truncated } = buildDiffText(files, 5000);

    expect(truncated).toBe(true);
    expect(text.length).toBeLessThan(5000 * 2);
  });

  it("truncates the file list itself for absurdly small budgets", () => {
    const files = Array.from({ length: 500 }, (_, i) => file({ filename: `file-${i}.ts` }));
    const { text, truncated } = buildDiffText(files, 100);

    expect(text.length).toBeLessThanOrEqual(100);
    expect(truncated).toBe(true);
  });
});
