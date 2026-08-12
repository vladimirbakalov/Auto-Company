import { describe, expect, it } from "vitest";
import { formatComment } from "./format";
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

describe("formatComment", () => {
  it("reports a clean scan without alarming language, but still signs the comment", () => {
    const body = formatComment([], { triageApplied: false });
    expect(body).toContain("No secrets detected");
    expect(body).toContain("— flagged by [secret-scan-action](https://github.com/vladimirbakalov/secret-scan-action)");
  });

  it("never includes the raw secret value in the output", () => {
    const body = formatComment([finding()], { triageApplied: false });
    expect(body).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("includes the redacted snippet, file, line, and rule description", () => {
    const body = formatComment([finding()], { triageApplied: false });
    expect(body).toContain("src/config.ts");
    expect(body).toContain("10");
    expect(body).toContain("AWS Access Key ID");
  });

  it("separates high-confidence and generic findings into distinct sections", () => {
    const findings = [
      finding({ confidence: "high" }),
      finding({
        confidence: "generic",
        ruleId: "generic-high-entropy-secret",
        description: 'High-entropy value assigned to "apiToken"',
        secret: "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY",
        contextLine: `const apiToken = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";`,
      }),
    ];
    const body = formatComment(findings, { triageApplied: false });

    expect(body).toContain("High confidence");
    expect(body).toContain("Needs review");
  });

  it("notes when Claude triage already reviewed the generic-tier findings", () => {
    const findings = [finding({ confidence: "generic", ruleId: "generic-high-entropy-secret" })];
    const body = formatComment(findings, { triageApplied: true });
    expect(body).toMatch(/claude/i);
  });

  it("always includes the attribution signature, even with findings", () => {
    const body = formatComment([finding()], { triageApplied: false });
    expect(body.trim().endsWith("— flagged by [secret-scan-action](https://github.com/vladimirbakalov/secret-scan-action)")).toBe(
      true,
    );
  });

  it("escapes markdown table-breaking characters in the snippet", () => {
    const f = finding({ contextLine: "const x = `raw` | weird" });
    const body = formatComment([f], { triageApplied: false });
    // The table row must still be well-formed: no stray unescaped pipe from the content.
    const row = body.split("\n").find((l) => l.includes("src/config.ts") && l.startsWith("|"));
    expect(row).toBeDefined();
    expect(row?.split("|").length).toBe(6); // leading, File, Line, Rule, Snippet, trailing
  });

  it("mentions how to suppress a false positive via the allowlist", () => {
    const body = formatComment([finding()], { triageApplied: false });
    expect(body).toContain(".secretscanignore");
    expect(body).toContain("allowlist");
  });
});
