import { describe, expect, it } from "vitest";
import { parseAllowlistSource, buildAllowlist, isAllowlisted } from "./allowlist";
import type { Finding } from "./scan";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    filename: "src/config.ts",
    line: 10,
    ruleId: "aws-access-key-id",
    description: "AWS Access Key ID",
    confidence: "high",
    secret: "AKIAIOSFODNN7EXAMPLE",
    contextLine: `const key = "AKIAIOSFODNN7EXAMPLE";`,
    ...overrides,
  };
}

describe("parseAllowlistSource", () => {
  it("parses non-empty, non-comment lines as case-insensitive regexes", () => {
    const entries = parseAllowlistSource("AKIAIOSFODNN7EXAMPLE\n# a comment\n\nfixtures/.*\n");
    expect(entries).toHaveLength(2);
    expect(entries[0].source).toBe("AKIAIOSFODNN7EXAMPLE");
    expect(entries[1].source).toBe("fixtures/.*");
  });

  it("skips invalid regex patterns instead of throwing", () => {
    const entries = parseAllowlistSource("(unclosed\nvalid-pattern");
    expect(entries.map((e) => e.source)).toEqual(["valid-pattern"]);
  });

  it("returns an empty array for empty input", () => {
    expect(parseAllowlistSource("")).toEqual([]);
  });
});

describe("buildAllowlist", () => {
  it("merges inline patterns with file-sourced patterns", () => {
    const entries = buildAllowlist("inline-pattern", "file-pattern-one\nfile-pattern-two");
    expect(entries.map((e) => e.source)).toEqual(["inline-pattern", "file-pattern-one", "file-pattern-two"]);
  });

  it("works with no file content", () => {
    const entries = buildAllowlist("inline-pattern", undefined);
    expect(entries.map((e) => e.source)).toEqual(["inline-pattern"]);
  });
});

describe("isAllowlisted", () => {
  it("suppresses a finding whose secret value matches an allowlist pattern", () => {
    const entries = parseAllowlistSource("AKIAIOSFODNN7EXAMPLE");
    expect(isAllowlisted(finding(), entries)).toBe(true);
  });

  it("suppresses a finding whose file path matches an allowlist pattern", () => {
    const entries = parseAllowlistSource("^src/fixtures/");
    expect(isAllowlisted(finding({ filename: "src/fixtures/example.ts" }), entries)).toBe(true);
  });

  it("suppresses a finding whose context line matches an allowlist pattern", () => {
    const entries = parseAllowlistSource("test-fixture-only");
    expect(isAllowlisted(finding({ contextLine: "const key = 'test-fixture-only-value';" }), entries)).toBe(true);
  });

  it("does not suppress a finding that matches nothing in the allowlist", () => {
    const entries = parseAllowlistSource("some-unrelated-pattern");
    expect(isAllowlisted(finding(), entries)).toBe(false);
  });

  it("returns false when the allowlist is empty", () => {
    expect(isAllowlisted(finding(), [])).toBe(false);
  });
});
