import { describe, expect, it } from "vitest";
import { redactSecret, redactLine } from "./redact";

describe("redactSecret", () => {
  it("masks the middle of a long secret, keeping a few chars on each end", () => {
    const redacted = redactSecret("AKIAIOSFODNN7EXAMPLE");
    expect(redacted.startsWith("AKIA")).toBe(true);
    expect(redacted.endsWith("MPLE")).toBe(true);
    expect(redacted).not.toContain("IOSFODNN7EXA");
  });

  it("fully masks very short secrets rather than revealing most of them", () => {
    const redacted = redactSecret("abcdef");
    expect(redacted).not.toContain("abcdef");
    expect(/^\*+$/.test(redacted)).toBe(true);
  });

  it("never contains the original secret as a substring", () => {
    const secrets = ["AKIAIOSFODNN7EXAMPLE", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", "short1"];
    for (const s of secrets) {
      expect(redactSecret(s)).not.toContain(s);
    }
  });

  it("does not let the visible head/tail windows overlap and expose most of a short secret", () => {
    // Regression: a fixed "show 4 chars each end" scheme reveals 8 of 9-16
    // characters once the windows overlap — the generic-entropy rule's
    // 12-char floor (MIN_GENERIC_SECRET_LENGTH) sits squarely in that range.
    for (let len = 9; len <= 16; len++) {
      const secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".slice(0, len);
      const redacted = redactSecret(secret);
      const revealedChars = redacted.replace(/\*/g, "").length;
      expect(revealedChars).toBeLessThanOrEqual(Math.ceil(len * 0.4));
      expect(redacted).not.toContain(secret);
    }
  });

  it("still shows up to 4 chars on each end once the secret is long enough that doing so is safe", () => {
    const redacted = redactSecret("AKIAIOSFODNN7EXAMPLE"); // 20 chars
    expect(redacted).toBe("AKIA************MPLE");
  });
});

describe("redactLine", () => {
  it("replaces the secret occurrence in the line with its redacted form", () => {
    const line = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const redacted = redactLine(line, "AKIAIOSFODNN7EXAMPLE");

    expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(redacted).toContain("const key =");
  });

  it("replaces every occurrence if the secret appears more than once", () => {
    const line = "AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE";
    const redacted = redactLine(line, "AKIAIOSFODNN7EXAMPLE");
    expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("returns the line unchanged if the secret is empty", () => {
    expect(redactLine("hello world", "")).toBe("hello world");
  });
});
