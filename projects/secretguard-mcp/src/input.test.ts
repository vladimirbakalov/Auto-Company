import { describe, expect, it } from "vitest";
import { linesFromCode, DEFAULT_FILENAME } from "./input.js";

describe("linesFromCode", () => {
  it("splits a multi-line code string into one AddedLine per line, 1-indexed", () => {
    const lines = linesFromCode('const a = 1;\nconst b = 2;\nconst c = 3;');
    expect(lines).toEqual([
      { filename: DEFAULT_FILENAME, line: 1, content: "const a = 1;" },
      { filename: DEFAULT_FILENAME, line: 2, content: "const b = 2;" },
      { filename: DEFAULT_FILENAME, line: 3, content: "const c = 3;" },
    ]);
  });

  it("uses the given filename instead of the default", () => {
    const lines = linesFromCode('const a = 1;', "src/config.ts");
    expect(lines).toEqual([{ filename: "src/config.ts", line: 1, content: "const a = 1;" }]);
  });

  it("handles a single-line input with no trailing newline", () => {
    const lines = linesFromCode("const a = 1;");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toEqual({ filename: DEFAULT_FILENAME, line: 1, content: "const a = 1;" });
  });

  it("handles an empty string as a single empty line", () => {
    const lines = linesFromCode("");
    expect(lines).toEqual([{ filename: DEFAULT_FILENAME, line: 1, content: "" }]);
  });

  it("preserves a trailing blank line as its own entry", () => {
    const lines = linesFromCode("const a = 1;\n");
    expect(lines).toEqual([
      { filename: DEFAULT_FILENAME, line: 1, content: "const a = 1;" },
      { filename: DEFAULT_FILENAME, line: 2, content: "" },
    ]);
  });
});
