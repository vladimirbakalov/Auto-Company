import { describe, expect, it } from "vitest";
import { scan, scanLine } from "./scan.js";
import type { AddedLine } from "./input.js";

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

  it("flags a GCP OAuth client secret", () => {
    const findings = scanLine(line(`const clientSecret = "GOCSPX-${"aB3_-cD4e".repeat(3)}";`));
    expect(findings.some((f) => f.ruleId === "gcp-oauth-client-secret" && f.confidence === "high")).toBe(true);
  });

  it("flags a SendGrid API key", () => {
    const key = `SG.${"a".repeat(22)}.${"b".repeat(43)}`;
    const findings = scanLine(line(`const SENDGRID_API_KEY = "${key}";`));
    expect(findings.some((f) => f.ruleId === "sendgrid-api-key" && f.confidence === "high")).toBe(true);
  });

  it("flags a Twilio API key", () => {
    const findings = scanLine(line(`const twilioKey = "SK${"a1b2c3d4".repeat(4)}";`));
    expect(findings.some((f) => f.ruleId === "twilio-api-key" && f.confidence === "high")).toBe(true);
  });

  it("flags an Azure Storage account key without also matching the generic rule", () => {
    const key = `${"aB3+/9dE".repeat(10)}zzXXaB==`;
    const findings = scanLine(line(`const connStr = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${key};EndpointSuffix=core.windows.net";`));
    expect(findings.some((f) => f.ruleId === "azure-storage-account-key" && f.confidence === "high")).toBe(true);
    const generic = findings.filter((f) => f.confidence === "generic");
    expect(generic).toHaveLength(0);
  });

  it("flags a database connection string with a plausible embedded password, as generic confidence", () => {
    const findings = scanLine(line(`const DATABASE_URL = "postgres://admin:Tr0ub4dor&3xK9z@db.example.com:5432/prod";`));
    const match = findings.find((f) => f.ruleId === "database-connection-string-password");
    expect(match).toBeDefined();
    expect(match?.confidence).toBe("generic");
  });

  it("flags a MongoDB connection string with a plausible embedded password", () => {
    const findings = scanLine(line(`uri: "mongodb+srv://svc:kP3mZ9vLwQ7nR2sD@cluster0.example.mongodb.net/app"`));
    expect(
      findings.some((f) => f.ruleId === "database-connection-string-password" && f.confidence === "generic"),
    ).toBe(true);
  });

  it("flags a Slack incoming webhook URL", () => {
    const url = `https://hooks.slack.com/services/T${"A".repeat(9)}/B${"B".repeat(9)}/${"c".repeat(24)}`;
    const findings = scanLine(line(`const SLACK_WEBHOOK = "${url}";`));
    expect(findings.some((f) => f.ruleId === "slack-webhook-url" && f.confidence === "high")).toBe(true);
  });

  it("flags a Shopify admin API access token", () => {
    const token = `shpat_${"a1b2c3d4".repeat(4)}`;
    const findings = scanLine(line(`const SHOPIFY_ACCESS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "shopify-access-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Shopify custom app access token", () => {
    const token = `shpca_${"f0e1d2c3".repeat(4)}`;
    const findings = scanLine(line(`headers["X-Shopify-Access-Token"] = "${token}"`));
    expect(findings.some((f) => f.ruleId === "shopify-access-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Telegram bot API token", () => {
    const token = "110201543:AodJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTS";
    const findings = scanLine(line(`const TELEGRAM_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "telegram-bot-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a DigitalOcean personal access token", () => {
    const token = `dop_v1_${"a1b2c3d4e5f6a7b8".repeat(4)}`;
    const findings = scanLine(line(`const DIGITALOCEAN_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "digitalocean-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a DigitalOcean OAuth access token and refresh token", () => {
    const accessToken = `doo_v1_${"0123456789abcdef".repeat(4)}`;
    const refreshToken = `dor_v1_${"fedcba9876543210".repeat(4)}`;
    const findings = scanLine(line(`accessToken="${accessToken}"; refreshToken="${refreshToken}";`));
    expect(findings.some((f) => f.ruleId === "digitalocean-token" && f.secret === accessToken)).toBe(true);
    expect(findings.some((f) => f.ruleId === "digitalocean-token" && f.secret === refreshToken)).toBe(true);
  });

  it("flags a Hugging Face access token", () => {
    const token = `hf_${"aBcDeFgHiJ".repeat(3)}wXyZ`; // 34 letters
    const findings = scanLine(line(`const HF_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "huggingface-access-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Hugging Face organization API token", () => {
    const token = `api_org_${"aBcDeFgHiJ".repeat(3)}wXyZ`; // 34 letters
    const findings = scanLine(line(`const HF_ORG_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "huggingface-organization-api-token" && f.confidence === "high")).toBe(
      true,
    );
  });

  it("flags a Notion API token", () => {
    const token = `ntn_${"1".repeat(11)}${"a1B2c3D4e5".repeat(3)}fGhIj`; // 11 digits + 35 alnum
    const findings = scanLine(line(`const NOTION_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "notion-api-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Mailchimp API key when the variable name is mailchimp-prefixed", () => {
    const key = `${"a1b2c3d4".repeat(4)}-us21`; // 32 hex + datacenter suffix
    const findings = scanLine(line(`const MAILCHIMP_API_KEY = "${key}";`));
    expect(findings.some((f) => f.ruleId === "mailchimp-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a mailchimp-shaped value with no mailchimp keyword nearby", () => {
    const key = `${"a1b2c3d4".repeat(4)}-us21`; // same shape, no "mailchimp" prefix
    const findings = scanLine(line(`const API_KEY = "${key}";`));
    expect(findings.some((f) => f.ruleId === "mailchimp-api-key")).toBe(false);
  });

  it("flags a Postman API token", () => {
    const token = `PMAK-${"a1b2c3".repeat(4)}-${"a1b2c3d4e5".repeat(3)}f6a1`; // 24 hex + "-" + 34 hex
    const findings = scanLine(line(`const POSTMAN_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "postman-api-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Linear API key", () => {
    const token = `lin_api_${"a1B2c3D4e5".repeat(4)}`; // 40 alphanumeric
    const findings = scanLine(line(`const LINEAR_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "linear-api-key" && f.confidence === "high")).toBe(true);
  });

  it("flags a Readme API key", () => {
    const token = `rdme_${"a1b2c3d4e5".repeat(7)}`; // 70 lowercase alphanumeric
    const findings = scanLine(line(`const README_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "readme-api-key" && f.confidence === "high")).toBe(true);
  });

  it("flags a Clojars API token", () => {
    const token = `CLOJARS_${"a1b2c3d4e5".repeat(6)}`; // 60 alphanumeric
    const findings = scanLine(line(`const CLOJARS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "clojars-api-token" && f.confidence === "high")).toBe(true);
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
    `const url = "postgres://user:password@localhost:5432/mydb";`, // placeholder password, not flagged
    `const url = "mysql://root:changeit@127.0.0.1:3306/app";`, // placeholder password, not flagged
    `const url = "postgres://user:\${DB_PASSWORD}@localhost:5432/mydb";`, // env-var reference, not a literal value
    `const aspectRatio = "16:9";`, // digit:digit, far too short for the Telegram token shape
    `const port = "localhost:8080";`, // digit:alnum but not 35 chars and doesn't start with 'A'
    `const timestamp = "1699999999:BPtYgjmUhBel31iEl2hpChYgCfrL1spNxny";`, // right shape and length but secret doesn't start with 'A'
    `const schemaRef = "12345:AgencyIdentificationCodeContentTypeExtended";`, // digit:CamelCase identifier longer than the token shape — word boundary rules it out
    `const buildTag = "dop_v1_${"a".repeat(63)}"`, // one hex char short of a real DigitalOcean token
    `const modelId = "hf_${"a".repeat(33)}"`, // one letter short of a real Hugging Face token
    `const dbId = "ntn_${"1".repeat(11)}${"a".repeat(34)}"`, // one alnum char short of a real Notion token
    `const workspaceKey = "PMAK-${"a".repeat(23)}-${"b".repeat(34)}"`, // one hex char short of a real Postman token
    `const teamKey = "lin_api_${"a".repeat(39)}"`, // one alnum char short of a real Linear API key
    `const docsKey = "rdme_${"a".repeat(69)}"`, // one alnum char short of a real Readme API key
    `const releaseToken = "CLOJARS_${"a".repeat(59)}"`, // one alnum char short of a real Clojars API token
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
