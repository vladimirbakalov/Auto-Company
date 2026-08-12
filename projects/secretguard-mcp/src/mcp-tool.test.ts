import { describe, expect, it } from "vitest";
import { scanForSecrets } from "./mcp-tool.js";

describe("scanForSecrets", () => {
  it("returns an empty findings list and a clear summary for clean code", () => {
    const result = scanForSecrets(`const greeting = "hello world";\nexport function add(a, b) { return a + b; }`);
    expect(result.findings).toEqual([]);
    expect(result.summary).toBe("No secrets detected.");
  });

  it("flags a high-confidence pattern match with a redacted line, never the raw secret", () => {
    const result = scanForSecrets(`const key = "AKIAIOSFODNN7EXAMPLE";`, "src/config.ts");

    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding).toMatchObject({
      filename: "src/config.ts",
      line: 1,
      ruleId: "aws-access-key-id",
      confidence: "high",
    });
    expect(finding.redactedLine).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(finding.redactedLine).toContain("const key =");
    expect(result.summary).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(result.summary).toContain("1 potential secret");
    expect(result.summary).toContain("1 high-confidence");
  });

  it("defaults the filename when none is given", () => {
    const result = scanForSecrets(`const key = "AKIAIOSFODNN7EXAMPLE";`);
    expect(result.findings[0].filename).toBe("input");
  });

  it("flags multiple findings across multiple lines with correct line numbers", () => {
    const code = [
      `const greeting = "hello";`,
      `const key = "AKIAIOSFODNN7EXAMPLE";`,
      `const apiToken = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";`,
    ].join("\n");

    const result = scanForSecrets(code, "app.ts");

    expect(result.findings).toHaveLength(2);
    expect(result.findings[0]).toMatchObject({ line: 2, ruleId: "aws-access-key-id", confidence: "high" });
    expect(result.findings[1]).toMatchObject({
      line: 3,
      ruleId: "generic-high-entropy-secret",
      confidence: "generic",
    });
    expect(result.summary).toContain("2 potential secrets");
    expect(result.summary).toContain("1 needs-review");
  });

  it("never leaks a raw secret value into the summary text for any finding", () => {
    // Built by concatenation, not a literal — a contiguous "sk_live_..."
    // string here would trip GitHub's own push-protection secret scanner,
    // even though it's a synthetic test value and not a real key.
    const secret = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc";
    const result = scanForSecrets(`const stripeKey = "${secret}";`);
    expect(result.summary).not.toContain(secret);
    for (const finding of result.findings) {
      expect(finding.redactedLine).not.toContain(secret);
    }
  });
});
