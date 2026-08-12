import { describe, expect, it } from "vitest";
import { scan, scanLine } from "./scan";
import type { AddedLine } from "./diff";

function line(content: string, overrides: Partial<AddedLine> = {}): AddedLine {
  return { filename: "src/config.ts", line: 1, content, ...overrides };
}

describe("scanLine — true positives (known-leaked-secret patterns)", () => {
  it("flags an AWS access key ID", () => {
    const findings = scanLine(line(`const key = "AKIAIOSFODNN7EXAMPLE";`));
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("aws-access-key-id");
    expect(findings[0].confidence).toBe("high");
    expect(findings[0].secret).toBe("AKIAIOSFODNN7EXAMPLE");
  });

  it("flags a contextual AWS secret access key", () => {
    const findings = scanLine(line(`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"`));
    const aws = findings.find((f) => f.ruleId === "aws-secret-access-key");
    expect(aws).toBeDefined();
    expect(aws?.confidence).toBe("high");
  });

  it("flags a Stripe live secret key", () => {
    const findings = scanLine(line(`const stripeKey = "sk_live_${"4eC39HqLyjWDarjtT1zdp7dc"}";`));
    expect(findings.some((f) => f.ruleId === "stripe-live-secret-key" && f.confidence === "high")).toBe(true);
  });

  it("flags a Stripe live restricted key", () => {
    const findings = scanLine(line(`const stripeKey = "rk_live_${"51H8anLkjasdkjKJHKJHkjhKJHkjh12"}";`));
    expect(findings.some((f) => f.ruleId === "stripe-live-restricted-key")).toBe(true);
  });

  it("flags a GitHub personal access token", () => {
    const findings = scanLine(line(`GITHUB_TOKEN=ghp_${"A".repeat(36)}`));
    expect(findings.some((f) => f.ruleId === "github-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a GitHub fine-grained PAT", () => {
    const findings = scanLine(line(`token = "github_pat_11ABCDEFG0123456789012${"x".repeat(20)}"`));
    expect(findings.some((f) => f.ruleId === "github-fine-grained-pat")).toBe(true);
  });

  it("flags a Google API key", () => {
    const findings = scanLine(line(`const GOOGLE_API_KEY = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBcx";`));
    expect(findings.some((f) => f.ruleId === "google-api-key")).toBe(true);
  });

  it("flags a Slack bot token", () => {
    const findings = scanLine(line(`SLACK_TOKEN=xoxb-${"1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"}`));
    expect(findings.some((f) => f.ruleId === "slack-token")).toBe(true);
  });

  it("flags a private key block", () => {
    const findings = scanLine(line(`-----BEGIN RSA PRIVATE KEY-----`));
    expect(findings.some((f) => f.ruleId === "private-key-block" && f.confidence === "high")).toBe(true);
  });

  it("flags a JWT", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const findings = scanLine(line(`const authHeader = "Bearer ${jwt}";`));
    expect(findings.some((f) => f.ruleId === "jwt" && f.confidence === "high")).toBe(true);
  });

  it("flags a legacy OpenAI API key", () => {
    const findings = scanLine(line(`const OPENAI_API_KEY = "sk-${"A".repeat(48)}";`));
    expect(findings.some((f) => f.ruleId === "openai-api-key" && f.confidence === "high")).toBe(true);
    expect(findings.some((f) => f.ruleId === "openai-project-api-key")).toBe(false);
  });

  it("flags an OpenAI project API key without also matching the legacy rule", () => {
    const findings = scanLine(line(`const OPENAI_API_KEY = "sk-proj-${"aB3_-".repeat(10)}";`));
    expect(findings.some((f) => f.ruleId === "openai-project-api-key" && f.confidence === "high")).toBe(true);
    expect(findings.some((f) => f.ruleId === "openai-api-key")).toBe(false);
  });

  it("flags an OpenAI service-account API key", () => {
    const findings = scanLine(line(`const key = "sk-svcacct-${"aB3_-".repeat(10)}";`));
    expect(findings.some((f) => f.ruleId === "openai-project-api-key")).toBe(true);
  });

  it("flags an Anthropic API key without also matching the legacy OpenAI rule", () => {
    const findings = scanLine(line(`const ANTHROPIC_API_KEY = "sk-ant-api03-${"aB3_-".repeat(10)}";`));
    expect(findings.some((f) => f.ruleId === "anthropic-api-key" && f.confidence === "high")).toBe(true);
    expect(findings.some((f) => f.ruleId === "openai-api-key")).toBe(false);
  });

  it("flags an npm access token", () => {
    const findings = scanLine(line(`//registry.npmjs.org/:_authToken=npm_${"A".repeat(36)}`));
    expect(findings.some((f) => f.ruleId === "npm-access-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a generic high-entropy value assigned to a secret-like variable name", () => {
    const findings = scanLine(line(`const apiToken = "zT9pQ2xR7mK4vL8nW1sD6fH3jC0bA5eY";`));
    expect(findings.some((f) => f.ruleId === "generic-high-entropy-secret" && f.confidence === "generic")).toBe(
      true,
    );
  });

  it("does not double-report the same value under both a pattern rule and the generic rule", () => {
    const findings = scanLine(line(`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"`));
    const generic = findings.filter((f) => f.confidence === "generic");
    expect(generic).toHaveLength(0);
  });
});

describe("scanLine — no false positives on clean code", () => {
  const cleanLines = [
    `const greeting = "hello world";`,
    `export function add(a: number, b: number) { return a + b; }`,
    `import { useState } from "react";`,
    `const id = "550e8400-e29b-41d4-a716-446655440000"; // a UUID, not a secret`,
    `const apiKey = process.env.API_KEY;`,
    `const token = "\${API_TOKEN}";`,
    `apiKey: "changeme"`,
    `password = "xxxxxxxxxxxx"`,
    `const password = "hunter2";`, // short, low entropy — not flagged
    `// TODO: add auth token support`,
    `const description = "this line is just prose about a token and a password, nothing assigned";`,
    `const count = 42;`,
    `const shortId = "AKIA123";`, // too short to be a real AWS key ID
  ];

  it.each(cleanLines)("flags nothing for: %s", (content) => {
    const findings = scanLine(line(content));
    expect(findings).toEqual([]);
  });
});

describe("scan", () => {
  it("scans across multiple added lines and preserves file/line attribution", () => {
    const lines: AddedLine[] = [
      { filename: "a.ts", line: 5, content: `const key = "AKIAIOSFODNN7EXAMPLE";` },
      { filename: "b.ts", line: 9, content: `const clean = true;` },
    ];
    const findings = scan(lines);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ filename: "a.ts", line: 5, ruleId: "aws-access-key-id" });
  });

  it("returns no findings for an empty input", () => {
    expect(scan([])).toEqual([]);
  });
});
