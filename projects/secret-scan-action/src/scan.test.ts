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

  it("does not flag a Clojars-shaped token whose body is one character short", () => {
    const token = `CLOJARS_${"a1b2c3d4e5".repeat(6).slice(0, -1)}`; // 59 alphanumeric
    const findings = scanLine(line(`const CLOJARS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "clojars-api-token")).toBe(false);
  });

  it("flags a Pulumi API token", () => {
    const token = `pul-${"a1b2c3d4e5".repeat(4)}`; // 40 hex chars
    const findings = scanLine(line(`const PULUMI_ACCESS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "pulumi-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Pulumi-shaped token whose body is one character short", () => {
    const token = `pul-${"a1b2c3d4e5".repeat(4).slice(0, -1)}`; // 39 hex chars
    const findings = scanLine(line(`const PULUMI_ACCESS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "pulumi-api-token")).toBe(false);
  });

  it("flags a RubyGems API token", () => {
    const token = `rubygems_${"a1b2c3d4e5".repeat(5).slice(0, 48)}`; // 48 hex chars
    const findings = scanLine(line(`const RUBYGEMS_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "rubygems-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a RubyGems-shaped token whose body is one character short", () => {
    const token = `rubygems_${"a1b2c3d4e5".repeat(5).slice(0, 47)}`; // 47 hex chars
    const findings = scanLine(line(`const RUBYGEMS_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "rubygems-api-token")).toBe(false);
  });

  it("flags a Doppler API token", () => {
    const token = `dp.pt.${"a1B2c3D4e5".repeat(5).slice(0, 43)}`; // 43 alphanumeric chars
    const findings = scanLine(line(`const DOPPLER_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "doppler-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Doppler-shaped token whose body is one character short", () => {
    const token = `dp.pt.${"a1B2c3D4e5".repeat(5).slice(0, 42)}`; // 42 alphanumeric chars
    const findings = scanLine(line(`const DOPPLER_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "doppler-api-token")).toBe(false);
  });

  it("flags a PlanetScale API token at the minimum body length", () => {
    const token = `pscale_tkn_${"a1B2c3D4e5".repeat(4).slice(0, 32)}`; // 32 chars
    const findings = scanLine(line(`const PLANETSCALE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "planetscale-api-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a PlanetScale API token at the maximum body length", () => {
    const token = `pscale_tkn_${"a1B2c3D4e5".repeat(7).slice(0, 64)}`; // 64 chars
    const findings = scanLine(line(`const PLANETSCALE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "planetscale-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a PlanetScale-shaped token whose body is one character short of the minimum", () => {
    const token = `pscale_tkn_${"a1B2c3D4e5".repeat(4).slice(0, 31)}`; // 31 chars
    const findings = scanLine(line(`const PLANETSCALE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "planetscale-api-token")).toBe(false);
  });

  it("flags a Databricks API token", () => {
    const token = `dapi${"a1b2c3d4e5".repeat(4).slice(0, 32)}`; // 32 hex chars
    const findings = scanLine(line(`const DATABRICKS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "databricks-api-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Databricks API token with the optional numeric suffix", () => {
    const token = `dapi${"a1b2c3d4e5".repeat(4).slice(0, 32)}-2`;
    const findings = scanLine(line(`const DATABRICKS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "databricks-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Databricks-shaped token whose body is one character short", () => {
    const token = `dapi${"a1b2c3d4e5".repeat(4).slice(0, 31)}`; // 31 hex chars
    const findings = scanLine(line(`const DATABRICKS_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "databricks-api-token")).toBe(false);
  });

  it("flags a Frame.io API token", () => {
    const token = `fio-u-${"aB1-_=cD2".repeat(8).slice(0, 64)}`; // 64 chars
    const findings = scanLine(line(`const FRAMEIO_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "frameio-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Frame.io-shaped token whose body is one character short", () => {
    const token = `fio-u-${"aB1-_=cD2".repeat(8).slice(0, 63)}`; // 63 chars
    const findings = scanLine(line(`const FRAMEIO_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "frameio-api-token")).toBe(false);
  });

  it("flags a Duffel API token", () => {
    const token = `duffel_test_${"aB1-_9cD2".repeat(5).slice(0, 43)}`; // 43 chars
    const findings = scanLine(line(`const DUFFEL_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "duffel-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Duffel-shaped token whose body is one character short", () => {
    const token = `duffel_live_${"aB1-_9cD2".repeat(5).slice(0, 42)}`; // 42 chars
    const findings = scanLine(line(`const DUFFEL_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "duffel-api-token")).toBe(false);
  });

  it("flags an Atlassian API token (ATATT3 format)", () => {
    const token = `ATATT3${"aB1cD2eF3gH4".repeat(16).slice(0, 186)}`; // 186 chars
    const findings = scanLine(line(`const ATLASSIAN_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "atlassian-api-token-atatt3" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an ATATT3-shaped token whose body is one character short", () => {
    const token = `ATATT3${"aB1cD2eF3gH4".repeat(16).slice(0, 185)}`; // 185 chars
    const findings = scanLine(line(`const ATLASSIAN_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "atlassian-api-token-atatt3")).toBe(false);
  });

  it("flags a Sourcegraph access token (sgp_<16-hex>_<40-hex> form)", () => {
    const token = `sgp_${"a1b2c3d4e5f6a7b8"}_${"c".repeat(40)}`;
    const findings = scanLine(line(`const SRC_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "sourcegraph-access-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Sourcegraph access token (sgp_local_<40-hex> form)", () => {
    const token = `sgp_local_${"d".repeat(40)}`;
    const findings = scanLine(line(`const SRC_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "sourcegraph-access-token" && f.confidence === "high")).toBe(true);
  });

  it("flags a Sourcegraph access token (bare sgp_<40-hex> form)", () => {
    const token = `sgp_${"e".repeat(40)}`;
    const findings = scanLine(line(`const SRC_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "sourcegraph-access-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Sourcegraph-shaped token whose body is one character short", () => {
    const token = `sgp_${"e".repeat(39)}`;
    const findings = scanLine(line(`const SRC_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "sourcegraph-access-token")).toBe(false);
  });

  it("does not flag a bare 40-char hex string with no sgp_ prefix, even near the word 'sourcegraph'", () => {
    const findings = scanLine(line(`// sourcegraph commit: ${"f".repeat(40)}`));
    expect(findings.some((f) => f.ruleId === "sourcegraph-access-token")).toBe(false);
  });

  it("flags an EasyPost API token", () => {
    const token = `EZAK${"aB1cD2eF3".repeat(6)}`; // 54 chars
    const findings = scanLine(line(`const EASYPOST_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "easypost-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an EasyPost-shaped token whose body is one character short", () => {
    const token = `EZAK${"aB1cD2eF3".repeat(6).slice(0, 53)}`; // 53 chars
    const findings = scanLine(line(`const EASYPOST_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "easypost-api-token")).toBe(false);
  });

  it("flags an EasyPost test API token", () => {
    const token = `EZTK${"aB1cD2eF3".repeat(6)}`; // 54 chars
    const findings = scanLine(line(`const EASYPOST_TEST_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "easypost-test-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an EasyPost-test-shaped token whose body is one character short", () => {
    const token = `EZTK${"aB1cD2eF3".repeat(6).slice(0, 53)}`; // 53 chars
    const findings = scanLine(line(`const EASYPOST_TEST_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "easypost-test-api-token")).toBe(false);
  });

  it("flags a Dynatrace API token", () => {
    const token = `dt0c01.${"aB1cD2eF3".repeat(3).slice(0, 24)}.${"aB1cD2eF3".repeat(8).slice(0, 64)}`;
    const findings = scanLine(line(`const DYNATRACE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "dynatrace-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Dynatrace-shaped token whose second segment is one character short", () => {
    const token = `dt0c01.${"aB1cD2eF3".repeat(3).slice(0, 24)}.${"aB1cD2eF3".repeat(8).slice(0, 63)}`;
    const findings = scanLine(line(`const DYNATRACE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "dynatrace-api-token")).toBe(false);
  });

  it("flags an Infracost API token", () => {
    const token = `ico-${"aB1cD2eF3".repeat(4).slice(0, 32)}`;
    const findings = scanLine(line(`const INFRACOST_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "infracost-api-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an Infracost-shaped token that is one character short", () => {
    const token = `ico-${"aB1cD2eF3".repeat(4).slice(0, 31)}`;
    const findings = scanLine(line(`const INFRACOST_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "infracost-api-token")).toBe(false);
  });

  it("flags a GitLab Personal Access Token", () => {
    const token = `glpat-${"aB1cD2eF3".repeat(3).slice(0, 20)}`;
    const findings = scanLine(line(`const GITLAB_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "gitlab-pat" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a GitLab-PAT-shaped token that is one character short", () => {
    const token = `glpat-${"aB1cD2eF3".repeat(3).slice(0, 19)}`;
    const findings = scanLine(line(`const GITLAB_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "gitlab-pat")).toBe(false);
  });

  it("flags a Square Access Token", () => {
    const token = `sq0atp-${"aB1cD2eF3".repeat(3).slice(0, 22)}`;
    const findings = scanLine(line(`const SQUARE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "square-access-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Square-Access-Token-shaped token that is one character short", () => {
    const token = `sq0atp-${"aB1cD2eF3".repeat(3).slice(0, 21)}`;
    const findings = scanLine(line(`const SQUARE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "square-access-token")).toBe(false);
  });

  it("flags an age encryption secret key", () => {
    const body = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".repeat(2).slice(0, 58);
    const findings = scanLine(line(`const AGE_KEY = "AGE-SECRET-KEY-1${body}";`));
    expect(findings.some((f) => f.ruleId === "age-secret-key" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an age-secret-key-shaped token that is one character short", () => {
    const body = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".repeat(2).slice(0, 57);
    const findings = scanLine(line(`const AGE_KEY = "AGE-SECRET-KEY-1${body}";`));
    expect(findings.some((f) => f.ruleId === "age-secret-key")).toBe(false);
  });

  it("flags a 1Password service account token", () => {
    const body = "aB1cD2eF3".repeat(28).slice(0, 250);
    const findings = scanLine(line(`const OP_TOKEN = "ops_eyJ${body}";`));
    expect(
      findings.some((f) => f.ruleId === "1password-service-account-token" && f.confidence === "high"),
    ).toBe(true);
  });

  it("does not flag a 1Password-service-account-token-shaped token whose body is one character short", () => {
    const body = "aB1cD2eF3".repeat(28).slice(0, 249);
    const findings = scanLine(line(`const OP_TOKEN = "ops_eyJ${body}";`));
    expect(findings.some((f) => f.ruleId === "1password-service-account-token")).toBe(false);
  });

  it("flags an Alibaba Cloud AccessKey ID", () => {
    const token = `LTAI${"aB1cD2eF3".repeat(3).slice(0, 20)}`;
    const findings = scanLine(line(`const ALIBABA_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "alibaba-access-key-id" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an Alibaba-AccessKey-ID-shaped token that is one character short", () => {
    const token = `LTAI${"aB1cD2eF3".repeat(3).slice(0, 19)}`;
    const findings = scanLine(line(`const ALIBABA_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "alibaba-access-key-id")).toBe(false);
  });

  it("flags an Artifactory API key", () => {
    const token = `AKCp${"aB1cD2eF3".repeat(8).slice(0, 69)}`;
    const findings = scanLine(line(`const ARTIFACTORY_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "artifactory-api-key" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an Artifactory-API-key-shaped token that is one character short", () => {
    const token = `AKCp${"aB1cD2eF3".repeat(8).slice(0, 68)}`;
    const findings = scanLine(line(`const ARTIFACTORY_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "artifactory-api-key")).toBe(false);
  });

  it("flags an Artifactory reference token", () => {
    const token = `cmVmd${"aB1cD2eF3".repeat(8).slice(0, 59)}`;
    const findings = scanLine(line(`const ARTIFACTORY_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "artifactory-reference-token" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an Artifactory-reference-token-shaped token that is one character short", () => {
    const token = `cmVmd${"aB1cD2eF3".repeat(8).slice(0, 58)}`;
    const findings = scanLine(line(`const ARTIFACTORY_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "artifactory-reference-token")).toBe(false);
  });

  it("flags a Cloudflare Origin CA Key", () => {
    const frag = "ab12cd34ef56";
    const token = `v1.0-${frag.repeat(3).slice(0, 24)}-${frag.repeat(13).slice(0, 146)}`;
    const findings = scanLine(line(`const CF_ORIGIN_CA_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-origin-ca-key" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a Cloudflare-Origin-CA-Key-shaped token that is one character short", () => {
    const frag = "ab12cd34ef56";
    const token = `v1.0-${frag.repeat(3).slice(0, 24)}-${frag.repeat(13).slice(0, 145)}`;
    const findings = scanLine(line(`const CF_ORIGIN_CA_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-origin-ca-key")).toBe(false);
  });

  it("flags an Amazon Bedrock long-lived API key", () => {
    const frag = "aB1cD2eF3gH4";
    const token = `ABSK${frag.repeat(10).slice(0, 109)}`;
    const findings = scanLine(line(`const BEDROCK_API_KEY = "${token}";`));
    expect(
      findings.some((f) => f.ruleId === "aws-amazon-bedrock-api-key-long-lived" && f.confidence === "high"),
    ).toBe(true);
  });

  it("does not flag an Amazon-Bedrock-API-key-shaped token that is one character short", () => {
    const frag = "aB1cD2eF3gH4";
    const token = `ABSK${frag.repeat(10).slice(0, 108)}`;
    const findings = scanLine(line(`const BEDROCK_API_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "aws-amazon-bedrock-api-key-long-lived")).toBe(false);
  });

  it("flags an Adobe Client Secret", () => {
    const frag = "aB1cD2eF3gH4";
    const token = `p8e-${frag.repeat(3).slice(0, 32)}`;
    const findings = scanLine(line(`const ADOBE_CLIENT_SECRET = "${token}";`));
    expect(findings.some((f) => f.ruleId === "adobe-client-secret" && f.confidence === "high")).toBe(true);
  });

  it("does not flag an Adobe-Client-Secret-shaped token that is one character short", () => {
    const frag = "aB1cD2eF3gH4";
    const token = `p8e-${frag.repeat(3).slice(0, 31)}`;
    const findings = scanLine(line(`const ADOBE_CLIENT_SECRET = "${token}";`));
    expect(findings.some((f) => f.ruleId === "adobe-client-secret")).toBe(false);
  });

  it("flags a 1Password Secret Key", () => {
    const frag = "AB12CD34EF56";
    const token = `A3-${frag.slice(0, 6)}-${frag.repeat(2).slice(0, 11)}-${frag.slice(0, 5)}-${frag.slice(0, 5)}-${frag.slice(0, 5)}`;
    const findings = scanLine(line(`const OP_SECRET_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "1password-secret-key" && f.confidence === "high")).toBe(true);
  });

  it("does not flag a 1Password-Secret-Key-shaped token that is one character short", () => {
    const frag = "AB12CD34EF56";
    const token = `A3-${frag.slice(0, 6)}-${frag.repeat(2).slice(0, 11)}-${frag.slice(0, 5)}-${frag.slice(0, 5)}-${frag.slice(0, 4)}`;
    const findings = scanLine(line(`const OP_SECRET_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "1password-secret-key")).toBe(false);
  });

  it("flags an Airtable Personal Access Token", () => {
    const alnum14 = "aB3fD1".repeat(3).slice(0, 14);
    const hex64 = "a1b2c3d4e5".repeat(7).slice(0, 64);
    const token = `pat${alnum14}.${hex64}`;
    const findings = scanLine(line(`const AIRTABLE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "airtable-personnal-access-token" && f.confidence === "high")).toBe(
      true,
    );
  });

  it("does not flag an Airtable-Personal-Access-Token-shaped value that is one character short", () => {
    const alnum14 = "aB3fD1".repeat(3).slice(0, 14);
    const hex64 = "a1b2c3d4e5".repeat(7).slice(0, 63);
    const token = `pat${alnum14}.${hex64}`;
    const findings = scanLine(line(`const AIRTABLE_TOKEN = "${token}";`));
    expect(findings.some((f) => f.ruleId === "airtable-personnal-access-token")).toBe(false);
  });

  it("flags an Authress Service Client Access Key", () => {
    const seg1 = "aB3fD1x9Qz".repeat(3).slice(0, 20);
    const seg2 = "aB3f".repeat(2).slice(0, 5);
    const seg3 = "aB3fD1x9Qz-".repeat(3).slice(0, 20);
    const seg4 = "aB3fD1x9Qz".repeat(4).slice(0, 30);
    const token = `authress_${seg1}.${seg2}.acc_${seg3}.${seg4}`;
    const findings = scanLine(line(`const AUTHRESS_KEY = "${token}";`));
    expect(
      findings.some((f) => f.ruleId === "authress-service-client-access-key" && f.confidence === "high"),
    ).toBe(true);
  });

  it("does not flag an Authress-Service-Client-Access-Key-shaped value that is one character short", () => {
    const seg1 = "aB3fD1x9Qz".repeat(3).slice(0, 20);
    const seg2 = "aB3f".repeat(2).slice(0, 5);
    const seg3 = "aB3fD1x9Qz-".repeat(3).slice(0, 20);
    const seg4 = "aB3fD1x9Qz".repeat(4).slice(0, 29);
    const token = `authress_${seg1}.${seg2}.acc_${seg3}.${seg4}`;
    const findings = scanLine(line(`const AUTHRESS_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "authress-service-client-access-key")).toBe(false);
  });

  it("flags a ClickHouse Cloud API secret key", () => {
    const suffix = "aB3fD1x9Qz".repeat(4).slice(0, 38);
    const token = `4b1d${suffix}`;
    const findings = scanLine(line(`const CLICKHOUSE_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "clickhouse-cloud-api-secret-key" && f.confidence === "generic")).toBe(
      true,
    );
  });

  it("does not flag a ClickHouse-Cloud-API-secret-key-shaped value that is one character short", () => {
    const suffix = "aB3fD1x9Qz".repeat(4).slice(0, 37);
    const token = `4b1d${suffix}`;
    const findings = scanLine(line(`const CLICKHOUSE_KEY = "${token}";`));
    expect(findings.some((f) => f.ruleId === "clickhouse-cloud-api-secret-key")).toBe(false);
  });

  it("flags an Adafruit-shaped value when the keyword 'adafruit' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const adafruit_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "adafruit-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like an Adafruit key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "adafruit-api-key")).toBe(false);
  });

  it("does not flag an Adafruit-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const adafruit_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "adafruit-api-key")).toBe(false);
  });

  it("flags an Airtable-shaped value when the keyword 'airtable' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 17).toLowerCase();
    const findings = scanLine(line(`const airtable_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "airtable-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 17-char value shaped like an Airtable key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 17).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "airtable-api-key")).toBe(false);
  });

  it("does not flag an Airtable-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 16).toLowerCase();
    const findings = scanLine(line(`const airtable_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "airtable-api-key")).toBe(false);
  });

  it("flags a Discord-token-shaped value when the keyword 'discord' is nearby", () => {
    const value = "a".repeat(64);
    const findings = scanLine(line(`const discord_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 64-char hex value shaped like a Discord token without the keyword nearby", () => {
    const value = "a".repeat(64);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-api-token")).toBe(false);
  });

  it("does not flag a Discord-token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "a".repeat(63);
    const findings = scanLine(line(`const discord_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-api-token")).toBe(false);
  });

  it("flags an Adobe-client-ID-shaped value when the keyword 'adobe' is nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const adobe_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "adobe-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char hex value shaped like an Adobe client ID without the keyword nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "adobe-client-id")).toBe(false);
  });

  it("does not flag an Adobe-client-ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "b".repeat(31);
    const findings = scanLine(line(`const adobe_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "adobe-client-id")).toBe(false);
  });

  it("flags an Algolia-shaped value when the keyword 'algolia' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const algolia_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "algolia-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like an Algolia key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "algolia-api-key")).toBe(false);
  });

  it("does not flag an Algolia-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const algolia_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "algolia-api-key")).toBe(false);
  });

  it("flags a Codecov-shaped value when the keyword 'codecov' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const codecov_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "codecov-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Codecov token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "codecov-access-token")).toBe(false);
  });

  it("does not flag a Codecov-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const codecov_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "codecov-access-token")).toBe(false);
  });

  it("flags a Datadog-shaped value when the keyword 'datadog' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const datadog_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "datadog-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 40-char value shaped like a Datadog token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "datadog-access-token")).toBe(false);
  });

  it("does not flag a Datadog-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 39).toLowerCase();
    const findings = scanLine(line(`const datadog_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "datadog-access-token")).toBe(false);
  });

  it("flags a Cloudflare-API-key-shaped value when the keyword 'cloudflare' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const cloudflare_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 40-char value shaped like a Cloudflare API key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-api-key")).toBe(false);
  });

  it("does not flag a Cloudflare-API-key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 39).toLowerCase();
    const findings = scanLine(line(`const cloudflare_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-api-key")).toBe(false);
  });

  it("flags a Cloudflare-Global-API-key-shaped value when the keyword 'cloudflare' is nearby", () => {
    const value = "b".repeat(37);
    const findings = scanLine(line(`const cloudflare_global_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-global-api-key" && f.confidence === "generic")).toBe(
      true,
    );
  });

  it("does not flag a 37-char hex value shaped like a Cloudflare Global API key without the keyword nearby", () => {
    const value = "b".repeat(37);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-global-api-key")).toBe(false);
  });

  it("does not flag a Cloudflare-Global-API-key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "b".repeat(36);
    const findings = scanLine(line(`const cloudflare_global_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cloudflare-global-api-key")).toBe(false);
  });

  it("flags a Coinbase-shaped value when the keyword 'coinbase' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const coinbase_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "coinbase-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 64-char value shaped like a Coinbase token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "coinbase-access-token")).toBe(false);
  });

  it("does not flag a Coinbase-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 63).toLowerCase();
    const findings = scanLine(line(`const coinbase_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "coinbase-access-token")).toBe(false);
  });

  it("flags a Contentful-shaped value when the keyword 'contentful' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(5).slice(0, 43).toLowerCase();
    const findings = scanLine(line(`const contentful_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "contentful-delivery-api-token" && f.confidence === "generic")).toBe(
      true,
    );
  });

  it("does not flag a 43-char value shaped like a Contentful token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(5).slice(0, 43).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "contentful-delivery-api-token")).toBe(false);
  });

  it("does not flag a Contentful-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(5).slice(0, 42).toLowerCase();
    const findings = scanLine(line(`const contentful_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "contentful-delivery-api-token")).toBe(false);
  });

  it("flags an Intercom-shaped value when the keyword 'intercom' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(6).slice(0, 60).toLowerCase();
    const findings = scanLine(line(`const intercom_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "intercom-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 60-char value shaped like an Intercom token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(6).slice(0, 60).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "intercom-api-key")).toBe(false);
  });

  it("does not flag an Intercom-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(6).slice(0, 59).toLowerCase();
    const findings = scanLine(line(`const intercom_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "intercom-api-key")).toBe(false);
  });

  it("flags a HubSpot-shaped value when the keyword 'hubspot' is nearby", () => {
    const value = "12345678-9abc-def0-1234-56789abcdef0";
    const findings = scanLine(line(`const hubspot_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "hubspot-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a UUID-shaped value without the 'hubspot' keyword nearby", () => {
    const value = "12345678-9abc-def0-1234-56789abcdef0";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "hubspot-api-key")).toBe(false);
  });

  it("does not flag a HubSpot-shaped value that is malformed even with the keyword nearby", () => {
    const value = "12345678-9abc-def0-1234-56789abcdef";
    const findings = scanLine(line(`const hubspot_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "hubspot-api-key")).toBe(false);
  });

  it("flags a Heroku-shaped value when the keyword 'heroku' is nearby", () => {
    const value = "12345678-9abc-def0-1234-56789abcdef0";
    const findings = scanLine(line(`const heroku_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "heroku-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a UUID-shaped value without the 'heroku' keyword nearby", () => {
    const value = "12345678-9abc-def0-1234-56789abcdef0";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "heroku-api-key")).toBe(false);
  });

  it("does not flag a Heroku-shaped value that is malformed even with the keyword nearby", () => {
    const value = "12345678-9abc-def0-1234-56789abcdef";
    const findings = scanLine(line(`const heroku_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "heroku-api-key")).toBe(false);
  });

  it("flags a Sentry-shaped value when the keyword 'sentry' is nearby", () => {
    const value = "a1b2c3d4e5".repeat(7).slice(0, 64);
    const findings = scanLine(line(`const sentry_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sentry-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 64-char hex value shaped like a Sentry token without the keyword nearby", () => {
    const value = "a1b2c3d4e5".repeat(7).slice(0, 64);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sentry-access-token")).toBe(false);
  });

  it("does not flag a Sentry-shaped value that is one character short even with the keyword nearby", () => {
    const value = "a1b2c3d4e5".repeat(7).slice(0, 63);
    const findings = scanLine(line(`const sentry_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sentry-access-token")).toBe(false);
  });

  it("flags a Zendesk-shaped value when the keyword 'zendesk' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const zendesk_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "zendesk-secret-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 40-char value shaped like a Zendesk key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "zendesk-secret-key")).toBe(false);
  });

  it("does not flag a Zendesk-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 39).toLowerCase();
    const findings = scanLine(line(`const zendesk_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "zendesk-secret-key")).toBe(false);
  });

  it("flags a Discord client ID-shaped value when the keyword 'discord' is nearby", () => {
    const value = "123456789".repeat(2);
    const findings = scanLine(line(`const discord_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag an 18-digit value shaped like a Discord client ID without the keyword nearby", () => {
    const value = "123456789".repeat(2);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-client-id")).toBe(false);
  });

  it("does not flag a Discord client ID-shaped value that is one digit short even with the keyword nearby", () => {
    const value = "123456789".repeat(2).slice(0, 17);
    const findings = scanLine(line(`const discord_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-client-id")).toBe(false);
  });

  it("flags a Discord client secret-shaped value when the keyword 'discord' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const discord_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-client-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Discord client secret without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-client-secret")).toBe(false);
  });

  it("does not flag a Discord client secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const discord_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "discord-client-secret")).toBe(false);
  });

  it("flags a Dropbox-shaped value when the keyword 'dropbox' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 15).toLowerCase();
    const findings = scanLine(line(`const dropbox_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 15-char value shaped like a Dropbox token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 15).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-api-token")).toBe(false);
  });

  it("does not flag a Dropbox-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 14).toLowerCase();
    const findings = scanLine(line(`const dropbox_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-api-token")).toBe(false);
  });

  it("flags a Bitbucket Client ID-shaped value when the keyword 'bitbucket' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const bitbucket_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bitbucket-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Bitbucket Client ID without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bitbucket-client-id")).toBe(false);
  });

  it("does not flag a Bitbucket Client ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const bitbucket_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bitbucket-client-id")).toBe(false);
  });

  it("flags a Twitch API token-shaped value when the keyword 'twitch' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 30).toLowerCase();
    const findings = scanLine(line(`const twitch_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitch-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 30-char value shaped like a Twitch API token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 30).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitch-api-token")).toBe(false);
  });

  it("does not flag a Twitch API token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 29).toLowerCase();
    const findings = scanLine(line(`const twitch_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitch-api-token")).toBe(false);
  });

  it("flags an Asana Client ID-shaped value when the keyword 'asana' is nearby", () => {
    const value = "123456789".repeat(2).slice(0, 16);
    const findings = scanLine(line(`const asana_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "asana-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 16-digit value shaped like an Asana Client ID without the keyword nearby", () => {
    const value = "123456789".repeat(2).slice(0, 16);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "asana-client-id")).toBe(false);
  });

  it("does not flag an Asana Client ID-shaped value that is one digit short even with the keyword nearby", () => {
    const value = "123456789".repeat(2).slice(0, 15);
    const findings = scanLine(line(`const asana_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "asana-client-id")).toBe(false);
  });

  it("flags an Asana Client Secret-shaped value when the keyword 'asana' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const asana_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "asana-client-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like an Asana Client Secret without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "asana-client-secret")).toBe(false);
  });

  it("does not flag an Asana Client Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const asana_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "asana-client-secret")).toBe(false);
  });

  it("flags a Bitbucket Client Secret-shaped value when the keyword 'bitbucket' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const bitbucket_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bitbucket-client-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 64-char value shaped like a Bitbucket Client Secret without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bitbucket-client-secret")).toBe(false);
  });

  it("does not flag a Bitbucket Client Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 63).toLowerCase();
    const findings = scanLine(line(`const bitbucket_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bitbucket-client-secret")).toBe(false);
  });

  it("flags a Droneci Access Token-shaped value when the keyword 'droneci' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const droneci_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "droneci-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Droneci Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "droneci-access-token")).toBe(false);
  });

  it("does not flag a Droneci Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const droneci_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "droneci-access-token")).toBe(false);
  });

  it("flags a Beamer API Token-shaped value when the keyword 'beamer' is nearby", () => {
    const value = "b_" + "aB3fD1x9Qz".repeat(5).slice(0, 44).toLowerCase();
    const findings = scanLine(line(`const beamer_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "beamer-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a b_-prefixed value shaped like a Beamer API Token without the keyword nearby", () => {
    const value = "b_" + "aB3fD1x9Qz".repeat(5).slice(0, 44).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "beamer-api-token")).toBe(false);
  });

  it("does not flag a Beamer API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "b_" + "aB3fD1x9Qz".repeat(5).slice(0, 43).toLowerCase();
    const findings = scanLine(line(`const beamer_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "beamer-api-token")).toBe(false);
  });

  it("flags a Bittrex Access Key-shaped value when the keyword 'bittrex' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const bittrex_access_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bittrex-access-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Bittrex Access Key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bittrex-access-key")).toBe(false);
  });

  it("does not flag a Bittrex Access Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const bittrex_access_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bittrex-access-key")).toBe(false);
  });

  it("flags a Bittrex Secret Key-shaped value when the keyword 'bittrex' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const bittrex_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bittrex-secret-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Bittrex Secret Key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bittrex-secret-key")).toBe(false);
  });

  it("does not flag a Bittrex Secret Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const bittrex_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "bittrex-secret-key")).toBe(false);
  });

  it("flags a Confluent Access Token-shaped value when the keyword 'confluent' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 16).toLowerCase();
    const findings = scanLine(line(`const confluent_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "confluent-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 16-char value shaped like a Confluent Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 16).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "confluent-access-token")).toBe(false);
  });

  it("does not flag a Confluent Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 15).toLowerCase();
    const findings = scanLine(line(`const confluent_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "confluent-access-token")).toBe(false);
  });

  it("flags a Confluent Secret Key-shaped value when the keyword 'confluent' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const confluent_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "confluent-secret-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 64-char value shaped like a Confluent Secret Key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "confluent-secret-key")).toBe(false);
  });

  it("does not flag a Confluent Secret Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 63).toLowerCase();
    const findings = scanLine(line(`const confluent_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "confluent-secret-key")).toBe(false);
  });

  it("flags a Fastly API Token-shaped value when the keyword 'fastly' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const fastly_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "fastly-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Fastly API Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "fastly-api-token")).toBe(false);
  });

  it("does not flag a Fastly API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const fastly_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "fastly-api-token")).toBe(false);
  });

  it("flags a Finicity API Token-shaped value when the keyword 'finicity' is nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const finicity_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finicity-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char hex value shaped like a Finicity API Token without the keyword nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finicity-api-token")).toBe(false);
  });

  it("does not flag a Finicity API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "b".repeat(31);
    const findings = scanLine(line(`const finicity_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finicity-api-token")).toBe(false);
  });

  it("flags a Finicity Client Secret-shaped value when the keyword 'finicity' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 20).toLowerCase();
    const findings = scanLine(line(`const finicity_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finicity-client-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 20-char value shaped like a Finicity Client Secret without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 20).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finicity-client-secret")).toBe(false);
  });

  it("does not flag a Finicity Client Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 19).toLowerCase();
    const findings = scanLine(line(`const finicity_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finicity-client-secret")).toBe(false);
  });

  it("flags a Finnhub Access Token-shaped value when the keyword 'finnhub' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 20).toLowerCase();
    const findings = scanLine(line(`const finnhub_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finnhub-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 20-char value shaped like a Finnhub Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 20).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finnhub-access-token")).toBe(false);
  });

  it("does not flag a Finnhub Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 19).toLowerCase();
    const findings = scanLine(line(`const finnhub_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "finnhub-access-token")).toBe(false);
  });

  it("flags a Flickr Access Token-shaped value when the keyword 'flickr' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const flickr_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "flickr-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char value shaped like a Flickr Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 32).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "flickr-access-token")).toBe(false);
  });

  it("does not flag a Flickr Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 31).toLowerCase();
    const findings = scanLine(line(`const flickr_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "flickr-access-token")).toBe(false);
  });

  it("flags a Freshbooks Access Token-shaped value when the keyword 'freshbooks' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const freshbooks_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "freshbooks-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 64-char value shaped like a Freshbooks Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "freshbooks-access-token")).toBe(false);
  });

  it("does not flag a Freshbooks Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 63).toLowerCase();
    const findings = scanLine(line(`const freshbooks_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "freshbooks-access-token")).toBe(false);
  });

  it("flags an Alibaba Cloud Secret Key-shaped value when the keyword 'alibaba' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 30).toLowerCase();
    const findings = scanLine(line(`const alibaba_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "alibaba-secret-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 30-char value shaped like an Alibaba Cloud Secret Key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 30).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "alibaba-secret-key")).toBe(false);
  });

  it("does not flag an Alibaba Cloud Secret Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 29).toLowerCase();
    const findings = scanLine(line(`const alibaba_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "alibaba-secret-key")).toBe(false);
  });

  it("flags a Facebook App Secret-shaped value when the keyword 'facebook' is nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const facebook_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "facebook-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a 32-char hex value shaped like a Facebook App Secret without the keyword nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "facebook-secret")).toBe(false);
  });

  it("does not flag a Facebook App Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "b".repeat(31);
    const findings = scanLine(line(`const facebook_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "facebook-secret")).toBe(false);
  });

  it("flags a Gitter Access Token-shaped value when the keyword 'gitter' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const gitter_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "gitter-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Gitter Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "gitter-access-token")).toBe(false);
  });

  it("does not flag a Gitter Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 39).toLowerCase();
    const findings = scanLine(line(`const gitter_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "gitter-access-token")).toBe(false);
  });

  it("flags a GoCardless API Token-shaped value when the keyword 'gocardless' is nearby", () => {
    const value = "live_" + "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const gocardless_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "gocardless-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a GoCardless API Token without the keyword nearby", () => {
    const value = "live_" + "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "gocardless-api-token")).toBe(false);
  });

  it("does not flag a GoCardless API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "live_" + "aB3fD1x9Qz".repeat(4).slice(0, 39).toLowerCase();
    const findings = scanLine(line(`const gocardless_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "gocardless-api-token")).toBe(false);
  });

  it("flags a JFrog API Key-shaped value when the keyword 'jfrog' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(8).slice(0, 73).toLowerCase();
    const findings = scanLine(line(`const jfrog_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "jfrog-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a JFrog API Key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(8).slice(0, 73).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "jfrog-api-key")).toBe(false);
  });

  it("does not flag a JFrog API Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(8).slice(0, 72).toLowerCase();
    const findings = scanLine(line(`const jfrog_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "jfrog-api-key")).toBe(false);
  });

  it("flags a JFrog Identity Token-shaped value when the keyword 'jfrog' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const jfrog_identity_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "jfrog-identity-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a JFrog Identity Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "jfrog-identity-token")).toBe(false);
  });

  it("does not flag a JFrog Identity Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 63).toLowerCase();
    const findings = scanLine(line(`const jfrog_identity_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "jfrog-identity-token")).toBe(false);
  });

  it("flags a Kraken Access Token-shaped value when the keyword 'kraken' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(9).slice(0, 85).toLowerCase();
    const findings = scanLine(line(`const kraken_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kraken-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Kraken Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(9).slice(0, 85).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kraken-access-token")).toBe(false);
  });

  it("does not flag a Kraken Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(8).slice(0, 79).toLowerCase();
    const findings = scanLine(line(`const kraken_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kraken-access-token")).toBe(false);
  });

  it("flags a Kucoin Access Token-shaped value when the keyword 'kucoin' is nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 24);
    const findings = scanLine(line(`const kucoin_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kucoin-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Kucoin Access Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 24);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kucoin-access-token")).toBe(false);
  });

  it("does not flag a Kucoin Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 23);
    const findings = scanLine(line(`const kucoin_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kucoin-access-token")).toBe(false);
  });

  it("flags a Kucoin Secret Key-shaped value when the keyword 'kucoin' is nearby", () => {
    const value = "ab3fd1a9-1234-5678-9abc-def012345678";
    const findings = scanLine(line(`const kucoin_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kucoin-secret-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Kucoin Secret Key without the keyword nearby", () => {
    const value = "ab3fd1a9-1234-5678-9abc-def012345678";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kucoin-secret-key")).toBe(false);
  });

  it("does not flag a Kucoin Secret Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1a9-1234-5678-9abc-def01234567";
    const findings = scanLine(line(`const kucoin_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "kucoin-secret-key")).toBe(false);
  });

  it("flags a LaunchDarkly Access Token-shaped value when the keyword 'launchdarkly' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const launchdarkly_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "launchdarkly-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a LaunchDarkly Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "launchdarkly-access-token")).toBe(false);
  });

  it("does not flag a LaunchDarkly Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 39).toLowerCase();
    const findings = scanLine(line(`const launchdarkly_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "launchdarkly-access-token")).toBe(false);
  });

  it("flags a Linear Client Secret-shaped value when the keyword 'linear' is nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const linear_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linear-client-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Linear Client Secret without the keyword nearby", () => {
    const value = "b".repeat(32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linear-client-secret")).toBe(false);
  });

  it("does not flag a Linear Client Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "b".repeat(31);
    const findings = scanLine(line(`const linear_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linear-client-secret")).toBe(false);
  });

  it("flags a LinkedIn Client ID-shaped value when the keyword 'linkedin' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 14).toLowerCase();
    const findings = scanLine(line(`const linkedin_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linkedin-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a LinkedIn Client ID without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 14).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linkedin-client-id")).toBe(false);
  });

  it("does not flag a LinkedIn Client ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 13).toLowerCase();
    const findings = scanLine(line(`const linkedin_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linkedin-client-id")).toBe(false);
  });

  it("flags a LinkedIn Client Secret-shaped value when the keyword 'linkedin' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 16).toLowerCase();
    const findings = scanLine(line(`const linkedin_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linkedin-client-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a LinkedIn Client Secret without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 16).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linkedin-client-secret")).toBe(false);
  });

  it("does not flag a LinkedIn Client Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 15).toLowerCase();
    const findings = scanLine(line(`const linkedin_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "linkedin-client-secret")).toBe(false);
  });

  it("flags a Mattermost Access Token-shaped value when the keyword 'mattermost' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 26).toLowerCase();
    const findings = scanLine(line(`const mattermost_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mattermost-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Mattermost Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 26).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mattermost-access-token")).toBe(false);
  });

  it("does not flag a Mattermost Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 25).toLowerCase();
    const findings = scanLine(line(`const mattermost_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mattermost-access-token")).toBe(false);
  });

  it("flags a Dropbox Long-Lived API Token-shaped value when the keyword 'dropbox' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 11).toLowerCase() + "AAAAAAAAAA" + "aB3fD1x9Qz".repeat(5).slice(0, 43).toLowerCase();
    const findings = scanLine(line(`const dropbox_long_lived_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-long-lived-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Dropbox Long-Lived API Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 11).toLowerCase() + "AAAAAAAAAA" + "aB3fD1x9Qz".repeat(5).slice(0, 43).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-long-lived-api-token")).toBe(false);
  });

  it("does not flag a Dropbox Long-Lived API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 11).toLowerCase() + "AAAAAAAAAA" + "aB3fD1x9Qz".repeat(5).slice(0, 42).toLowerCase();
    const findings = scanLine(line(`const dropbox_long_lived_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-long-lived-api-token")).toBe(false);
  });

  it("flags a Dropbox Short-Lived API Token-shaped value when the keyword 'dropbox' is nearby", () => {
    const value = "sl." + "aB3fD1x9Qz".repeat(14).slice(0, 135).toLowerCase();
    const findings = scanLine(line(`const dropbox_short_lived_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-short-lived-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Dropbox Short-Lived API Token without the keyword nearby", () => {
    const value = "sl." + "aB3fD1x9Qz".repeat(14).slice(0, 135).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-short-lived-api-token")).toBe(false);
  });

  it("does not flag a Dropbox Short-Lived API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "sl." + "aB3fD1x9Qz".repeat(14).slice(0, 134).toLowerCase();
    const findings = scanLine(line(`const dropbox_short_lived_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "dropbox-short-lived-api-token")).toBe(false);
  });

  it("flags a Defined Networking API Token-shaped value when the keyword 'dnkey' is nearby", () => {
    const value = "dnkey-" + "aB3fD1x9Qz".repeat(3).slice(0, 26).toLowerCase() + "-" + "aB3fD1x9Qz".repeat(6).slice(0, 52).toLowerCase();
    const findings = scanLine(line(`const dnkey_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "defined-networking-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Defined Networking API Token without the keyword nearby", () => {
    const value = "dnkey-" + "aB3fD1x9Qz".repeat(3).slice(0, 26).toLowerCase() + "-" + "aB3fD1x9Qz".repeat(6).slice(0, 52).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "defined-networking-api-token")).toBe(false);
  });

  it("does not flag a Defined Networking API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "dnkey-" + "aB3fD1x9Qz".repeat(3).slice(0, 25).toLowerCase() + "-" + "aB3fD1x9Qz".repeat(6).slice(0, 52).toLowerCase();
    const findings = scanLine(line(`const dnkey_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "defined-networking-api-token")).toBe(false);
  });

  it("flags a Lob API Key-shaped value when the keyword 'lob' is nearby", () => {
    const value = "live_" + "ab3fd1".repeat(6).slice(0, 35);
    const findings = scanLine(line(`const lob_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "lob-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Lob API Key without the keyword nearby", () => {
    const value = "live_" + "ab3fd1".repeat(6).slice(0, 35);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "lob-api-key")).toBe(false);
  });

  it("does not flag a Lob API Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "live_" + "ab3fd1".repeat(6).slice(0, 34);
    const findings = scanLine(line(`const lob_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "lob-api-key")).toBe(false);
  });

  it("flags a Lob Publishable API Key-shaped value when the keyword 'lob' is nearby", () => {
    const value = "test_pub_" + "ab3fd1".repeat(6).slice(0, 31);
    const findings = scanLine(line(`const lob_pub_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "lob-pub-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Lob Publishable API Key without the keyword nearby", () => {
    const value = "test_pub_" + "ab3fd1".repeat(6).slice(0, 31);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "lob-pub-api-key")).toBe(false);
  });

  it("does not flag a Lob Publishable API Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "test_pub_" + "ab3fd1".repeat(6).slice(0, 30);
    const findings = scanLine(line(`const lob_pub_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "lob-pub-api-key")).toBe(false);
  });

  it("flags a Looker Client ID-shaped value when the keyword 'looker' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 20).toLowerCase();
    const findings = scanLine(line(`const looker_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "looker-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Looker Client ID without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 20).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "looker-client-id")).toBe(false);
  });

  it("does not flag a Looker Client ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(2).slice(0, 19).toLowerCase();
    const findings = scanLine(line(`const looker_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "looker-client-id")).toBe(false);
  });

  it("flags a Looker Client Secret-shaped value when the keyword 'looker' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 24).toLowerCase();
    const findings = scanLine(line(`const looker_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "looker-client-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Looker Client Secret without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 24).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "looker-client-secret")).toBe(false);
  });

  it("does not flag a Looker Client Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 23).toLowerCase();
    const findings = scanLine(line(`const looker_client_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "looker-client-secret")).toBe(false);
  });

  it("flags a Mailgun Private API Token-shaped value when the keyword 'mailgun' is nearby", () => {
    const value = "key-" + "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const mailgun_private_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-private-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Mailgun Private API Token without the keyword nearby", () => {
    const value = "key-" + "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-private-api-token")).toBe(false);
  });

  it("does not flag a Mailgun Private API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "key-" + "ab3fd1".repeat(6).slice(0, 31);
    const findings = scanLine(line(`const mailgun_private_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-private-api-token")).toBe(false);
  });

  it("flags a Mailgun Public Validation Key-shaped value when the keyword 'mailgun' is nearby", () => {
    const value = "pubkey-" + "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const mailgun_pub_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-pub-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Mailgun Public Validation Key without the keyword nearby", () => {
    const value = "pubkey-" + "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-pub-key")).toBe(false);
  });

  it("does not flag a Mailgun Public Validation Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "pubkey-" + "ab3fd1".repeat(6).slice(0, 31);
    const findings = scanLine(line(`const mailgun_pub_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-pub-key")).toBe(false);
  });

  it("flags a Mailgun Webhook Signing Key-shaped value when the keyword 'mailgun' is nearby", () => {
    const value = "ab3fd1".repeat(6).slice(0, 32) + "-" + "ab3fd1".repeat(2).slice(0, 8) + "-" + "ab3fd1".repeat(2).slice(0, 8);
    const findings = scanLine(line(`const mailgun_signing_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-signing-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Mailgun Webhook Signing Key without the keyword nearby", () => {
    const value = "ab3fd1".repeat(6).slice(0, 32) + "-" + "ab3fd1".repeat(2).slice(0, 8) + "-" + "ab3fd1".repeat(2).slice(0, 8);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-signing-key")).toBe(false);
  });

  it("does not flag a Mailgun Webhook Signing Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(6).slice(0, 32) + "-" + "ab3fd1".repeat(2).slice(0, 8) + "-" + "ab3fd1".repeat(2).slice(0, 7);
    const findings = scanLine(line(`const mailgun_signing_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mailgun-signing-key")).toBe(false);
  });

  it("flags a MapBox API Token-shaped value when the keyword 'mapbox' is nearby", () => {
    const value = "pk." + "aB3fD1x9Qz".repeat(6).slice(0, 60).toLowerCase() + "." + "aB3fD1x9Qz".repeat(3).slice(0, 22).toLowerCase();
    const findings = scanLine(line(`const mapbox_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mapbox-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a MapBox API Token without the keyword nearby", () => {
    const value = "pk." + "aB3fD1x9Qz".repeat(6).slice(0, 60).toLowerCase() + "." + "aB3fD1x9Qz".repeat(3).slice(0, 22).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mapbox-api-token")).toBe(false);
  });

  it("does not flag a MapBox API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "pk." + "aB3fD1x9Qz".repeat(6).slice(0, 60).toLowerCase() + "." + "aB3fD1x9Qz".repeat(3).slice(0, 21).toLowerCase();
    const findings = scanLine(line(`const mapbox_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "mapbox-api-token")).toBe(false);
  });

  it("flags a MessageBird API Token-shaped value when the keyword 'messagebird' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 25).toLowerCase();
    const findings = scanLine(line(`const messagebird_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "messagebird-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a MessageBird API Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 25).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "messagebird-api-token")).toBe(false);
  });

  it("does not flag a MessageBird API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 24).toLowerCase();
    const findings = scanLine(line(`const messagebird_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "messagebird-api-token")).toBe(false);
  });

  it("flags a MessageBird Client ID-shaped value when the keyword 'messagebird' is nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const messagebird_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "messagebird-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a MessageBird Client ID without the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "messagebird-client-id")).toBe(false);
  });

  it("does not flag a MessageBird Client ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d";
    const findings = scanLine(line(`const messagebird_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "messagebird-client-id")).toBe(false);
  });

  it("flags a Netlify Access Token-shaped value when the keyword 'netlify' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const netlify_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "netlify-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Netlify Access Token without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 40).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "netlify-access-token")).toBe(false);
  });

  it("does not flag a Netlify Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(4).slice(0, 39).toLowerCase();
    const findings = scanLine(line(`const netlify_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "netlify-access-token")).toBe(false);
  });

  it("flags a New Relic Browser API Token-shaped value when the keyword 'new-relic' is nearby", () => {
    const value = "NRJS-" + "ab3fd1".repeat(4).slice(0, 19);
    const findings = scanLine(line(`const new_relic_browser_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-browser-api-token" && f.confidence === "generic")).toBe(
      true,
    );
  });

  it("does not flag a value shaped like a New Relic Browser API Token without the keyword nearby", () => {
    const value = "NRJS-" + "ab3fd1".repeat(4).slice(0, 19);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-browser-api-token")).toBe(false);
  });

  it("does not flag a New Relic Browser API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "NRJS-" + "ab3fd1".repeat(4).slice(0, 18);
    const findings = scanLine(line(`const new_relic_browser_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-browser-api-token")).toBe(false);
  });

  it("flags a New Relic Insert Key-shaped value when the keyword 'new-relic' is nearby", () => {
    const value = "NRII-" + "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const new_relic_insert_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-insert-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a New Relic Insert Key without the keyword nearby", () => {
    const value = "NRII-" + "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-insert-key")).toBe(false);
  });

  it("does not flag a New Relic Insert Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "NRII-" + "ab3fd1".repeat(6).slice(0, 31);
    const findings = scanLine(line(`const new_relic_insert_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-insert-key")).toBe(false);
  });

  it("flags a New Relic User API ID-shaped value when the keyword 'new-relic' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const new_relic_user_api_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-user-api-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a New Relic User API ID without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 64).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-user-api-id")).toBe(false);
  });

  it("does not flag a New Relic User API ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(7).slice(0, 63).toLowerCase();
    const findings = scanLine(line(`const new_relic_user_api_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-user-api-id")).toBe(false);
  });

  it("flags a New Relic User API Key-shaped value when the keyword 'new-relic' is nearby", () => {
    const value = "NRAK-" + "aB3fD1x9Qz".repeat(3).slice(0, 27).toLowerCase();
    const findings = scanLine(line(`const new_relic_user_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-user-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a New Relic User API Key without the keyword nearby", () => {
    const value = "NRAK-" + "aB3fD1x9Qz".repeat(3).slice(0, 27).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-user-api-key")).toBe(false);
  });

  it("does not flag a New Relic User API Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "NRAK-" + "aB3fD1x9Qz".repeat(3).slice(0, 26).toLowerCase();
    const findings = scanLine(line(`const new_relic_user_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "new-relic-user-api-key")).toBe(false);
  });

  it("flags a Plaid API Token-shaped value when the keyword 'plaid' is nearby", () => {
    const value = "access-sandbox-12345678-1234-1234-1234-123456789012";
    const findings = scanLine(line(`const plaid_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Plaid API Token without the keyword nearby", () => {
    const value = "access-sandbox-12345678-1234-1234-1234-123456789012";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-api-token")).toBe(false);
  });

  it("does not flag a Plaid API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "access-sandbox-12345678-1234-1234-1234-12345678901";
    const findings = scanLine(line(`const plaid_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-api-token")).toBe(false);
  });

  it("flags a Plaid Client ID-shaped value when the keyword 'plaid' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 24).toLowerCase();
    const findings = scanLine(line(`const plaid_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-client-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Plaid Client ID without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 24).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-client-id")).toBe(false);
  });

  it("does not flag a Plaid Client ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 23).toLowerCase();
    const findings = scanLine(line(`const plaid_client_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-client-id")).toBe(false);
  });

  it("flags a Plaid Secret Key-shaped value when the keyword 'plaid' is nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 30).toLowerCase();
    const findings = scanLine(line(`const plaid_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-secret-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Plaid Secret Key without the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 30).toLowerCase();
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-secret-key")).toBe(false);
  });

  it("does not flag a Plaid Secret Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "aB3fD1x9Qz".repeat(3).slice(0, 29).toLowerCase();
    const findings = scanLine(line(`const plaid_secret_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "plaid-secret-key")).toBe(false);
  });

  it("flags a Sendbird Access ID-shaped value when the keyword 'sendbird' is nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const sendbird_access_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sendbird-access-id" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Sendbird Access ID without the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sendbird-access-id")).toBe(false);
  });

  it("does not flag a Sendbird Access ID-shaped value that is one character short even with the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d";
    const findings = scanLine(line(`const sendbird_access_id = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sendbird-access-id")).toBe(false);
  });

  it("flags a Sendbird Access Token-shaped value when the keyword 'sendbird' is nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const sendbird_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sendbird-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Sendbird Access Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sendbird-access-token")).toBe(false);
  });

  it("does not flag a Sendbird Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 39);
    const findings = scanLine(line(`const sendbird_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sendbird-access-token")).toBe(false);
  });

  it("flags a Sidekiq Secret-shaped value when the keyword 'BUNDLE_ENTERPRISE__CONTRIBSYS__COM' is nearby", () => {
    const value = "12345678:87654321";
    const findings = scanLine(line(`BUNDLE_ENTERPRISE__CONTRIBSYS__COM: "${value}"`));
    expect(findings.some((f) => f.ruleId === "sidekiq-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Sidekiq Secret without the keyword nearby", () => {
    const value = "12345678:87654321";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sidekiq-secret")).toBe(false);
  });

  it("does not flag a Sidekiq Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "1234567:87654321";
    const findings = scanLine(line(`BUNDLE_ENTERPRISE__CONTRIBSYS__COM: "${value}"`));
    expect(findings.some((f) => f.ruleId === "sidekiq-secret")).toBe(false);
  });

  it("flags a New York Times Access Token-shaped value when the keyword 'nytimes' is nearby", () => {
    const value = "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const nytimes_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "nytimes-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a New York Times Access Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(6).slice(0, 32);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "nytimes-access-token")).toBe(false);
  });

  it("does not flag a New York Times Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(6).slice(0, 31);
    const findings = scanLine(line(`const nytimes_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "nytimes-access-token")).toBe(false);
  });

  it("flags a RapidAPI Access Token-shaped value when the keyword 'rapidapi' is nearby", () => {
    const value = "ab3fd1".repeat(9).slice(0, 50);
    const findings = scanLine(line(`const rapidapi_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "rapidapi-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a RapidAPI Access Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(9).slice(0, 50);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "rapidapi-access-token")).toBe(false);
  });

  it("does not flag a RapidAPI Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(9).slice(0, 49);
    const findings = scanLine(line(`const rapidapi_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "rapidapi-access-token")).toBe(false);
  });

  it("flags a Squarespace Access Token-shaped value when the keyword 'squarespace' is nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const squarespace_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "squarespace-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Squarespace Access Token without the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "squarespace-access-token")).toBe(false);
  });

  it("does not flag a Squarespace Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d";
    const findings = scanLine(line(`const squarespace_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "squarespace-access-token")).toBe(false);
  });

  it("flags a Travis CI Access Token-shaped value when the keyword 'travis' is nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 22);
    const findings = scanLine(line(`const travis_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "travisci-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Travis CI Access Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 22);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "travisci-access-token")).toBe(false);
  });

  it("does not flag a Travis CI Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 21);
    const findings = scanLine(line(`const travis_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "travisci-access-token")).toBe(false);
  });

  it("flags a Typeform API Token-shaped value when the keyword 'typeform' is nearby", () => {
    const value = "tfp_" + "ab3fd1".repeat(10).slice(0, 59);
    const findings = scanLine(line(`const typeform_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "typeform-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Typeform API Token without the keyword nearby", () => {
    const value = "tfp_" + "ab3fd1".repeat(10).slice(0, 59);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "typeform-api-token")).toBe(false);
  });

  it("does not flag a Typeform API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "tfp_" + "ab3fd1".repeat(10).slice(0, 58);
    const findings = scanLine(line(`const typeform_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "typeform-api-token")).toBe(false);
  });

  it("flags a Twitter Access Secret-shaped value when the keyword 'twitter' is nearby", () => {
    const value = "ab3fd1".repeat(8).slice(0, 45);
    const findings = scanLine(line(`const twitter_access_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-access-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Twitter Access Secret without the keyword nearby", () => {
    const value = "ab3fd1".repeat(8).slice(0, 45);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-access-secret")).toBe(false);
  });

  it("does not flag a Twitter Access Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(8).slice(0, 44);
    const findings = scanLine(line(`const twitter_access_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-access-secret")).toBe(false);
  });

  it("flags a Twitter Access Token-shaped value when the keyword 'twitter' is nearby", () => {
    const value = "1".repeat(18) + "-" + "ab3fd1".repeat(5).slice(0, 30);
    const findings = scanLine(line(`const twitter_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Twitter Access Token without the keyword nearby", () => {
    const value = "1".repeat(18) + "-" + "ab3fd1".repeat(5).slice(0, 30);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-access-token")).toBe(false);
  });

  it("does not flag a Twitter Access Token-shaped value that is malformed even with the keyword nearby", () => {
    const value = "1".repeat(10) + "-" + "ab3fd1".repeat(5).slice(0, 30);
    const findings = scanLine(line(`const twitter_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-access-token")).toBe(false);
  });

  it("flags a Twitter API Key-shaped value when the keyword 'twitter' is nearby", () => {
    const value = "ab3fd1".repeat(5).slice(0, 25);
    const findings = scanLine(line(`const twitter_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Twitter API Key without the keyword nearby", () => {
    const value = "ab3fd1".repeat(5).slice(0, 25);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-api-key")).toBe(false);
  });

  it("does not flag a Twitter API Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(5).slice(0, 24);
    const findings = scanLine(line(`const twitter_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-api-key")).toBe(false);
  });

  it("flags a Twitter API Secret-shaped value when the keyword 'twitter' is nearby", () => {
    const value = "ab3fd1".repeat(9).slice(0, 50);
    const findings = scanLine(line(`const twitter_api_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-api-secret" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Twitter API Secret without the keyword nearby", () => {
    const value = "ab3fd1".repeat(9).slice(0, 50);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-api-secret")).toBe(false);
  });

  it("does not flag a Twitter API Secret-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(9).slice(0, 49);
    const findings = scanLine(line(`const twitter_api_secret = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-api-secret")).toBe(false);
  });

  it("flags a Twitter Bearer Token-shaped value when the keyword 'twitter' is nearby", () => {
    const value = "A".repeat(22) + "ab3fd1".repeat(15).slice(0, 90);
    const findings = scanLine(line(`const twitter_bearer_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-bearer-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Twitter Bearer Token without the keyword nearby", () => {
    const value = "A".repeat(22) + "ab3fd1".repeat(15).slice(0, 90);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-bearer-token")).toBe(false);
  });

  it("does not flag a Twitter Bearer Token-shaped value that is too short even with the keyword nearby", () => {
    const value = "A".repeat(22) + "ab3fd1".repeat(14).slice(0, 79);
    const findings = scanLine(line(`const twitter_bearer_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "twitter-bearer-token")).toBe(false);
  });

  it("flags a Yandex Access Token-shaped value when the keyword 'yandex' is nearby", () => {
    const value = "t1." + "ab3fD1".repeat(4).slice(0, 20) + "." + "ab3fD1".repeat(15).slice(0, 86);
    const findings = scanLine(line(`const yandex_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Yandex Access Token without the keyword nearby", () => {
    const value = "t1." + "ab3fD1".repeat(4).slice(0, 20) + "." + "ab3fD1".repeat(15).slice(0, 86);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-access-token")).toBe(false);
  });

  it("does not flag a Yandex Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "t1." + "ab3fD1".repeat(4).slice(0, 20) + "." + "ab3fD1".repeat(15).slice(0, 85);
    const findings = scanLine(line(`const yandex_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-access-token")).toBe(false);
  });

  it("flags a Yandex API Key-shaped value when the keyword 'yandex' is nearby", () => {
    const value = "AQVN" + "ab3fd1".repeat(7).slice(0, 38);
    const findings = scanLine(line(`const yandex_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Yandex API Key without the keyword nearby", () => {
    const value = "AQVN" + "ab3fd1".repeat(7).slice(0, 38);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-api-key")).toBe(false);
  });

  it("does not flag a Yandex API Key-shaped value that is too short even with the keyword nearby", () => {
    const value = "AQVN" + "ab3fd1".repeat(6).slice(0, 34);
    const findings = scanLine(line(`const yandex_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-api-key")).toBe(false);
  });

  it("flags a Yandex Cloud AWS-compatible Access Token-shaped value when the keyword 'yandex' is nearby", () => {
    const value = "YC" + "ab3fd1".repeat(7).slice(0, 38);
    const findings = scanLine(line(`const yandex_aws_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-aws-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Yandex Cloud AWS-compatible Access Token without the keyword nearby", () => {
    const value = "YC" + "ab3fd1".repeat(7).slice(0, 38);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-aws-access-token")).toBe(false);
  });

  it("does not flag a Yandex Cloud AWS-compatible Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "YC" + "ab3fd1".repeat(7).slice(0, 37);
    const findings = scanLine(line(`const yandex_aws_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "yandex-aws-access-token")).toBe(false);
  });

  it("flags a Cohere Token-shaped value when the keyword 'cohere' is nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const cohere_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cohere-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Cohere Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cohere-api-token")).toBe(false);
  });

  it("does not flag a Cohere Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 39);
    const findings = scanLine(line(`const cohere_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cohere-api-token")).toBe(false);
  });

  it("flags a Snyk API Token-shaped value when a compound snyk keyword is nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const snyk_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "snyk-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Snyk API Token without the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "snyk-api-token")).toBe(false);
  });

  it("does not flag a malformed Snyk API Token-shaped value even with the keyword nearby", () => {
    const value = "a1b2c3d4-e5f6-a1b-c3d4-e5f6a1b2c3d4";
    const findings = scanLine(line(`const snyk_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "snyk-api-token")).toBe(false);
  });

  it("flags a Sonar API Token-shaped value when the keyword 'sonar_token' is nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const sonar_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sonar-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Sonar API Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sonar-api-token")).toBe(false);
  });

  it("does not flag a Sonar API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 39);
    const findings = scanLine(line(`const sonar_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sonar-api-token")).toBe(false);
  });

  it("flags an Okta Access Token-shaped value when the keyword 'okta' is nearby", () => {
    const value = "00" + "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const okta_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "okta-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like an Okta Access Token without the keyword nearby", () => {
    const value = "00" + "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "okta-access-token")).toBe(false);
  });

  it("does not flag an Okta Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "00" + "ab3fd1".repeat(7).slice(0, 39);
    const findings = scanLine(line(`const okta_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "okta-access-token")).toBe(false);
  });

  it("flags an Etsy Access Token-shaped value when the keyword 'etsy' is nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 24);
    const findings = scanLine(line(`const etsy_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "etsy-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like an Etsy Access Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 24);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "etsy-access-token")).toBe(false);
  });

  it("does not flag an Etsy Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 23);
    const findings = scanLine(line(`const etsy_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "etsy-access-token")).toBe(false);
  });

  it("flags a Cisco Meraki API Key-shaped value when the keyword 'meraki' is nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const meraki_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cisco-meraki-api-key" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a Cisco Meraki API Key without the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 40);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cisco-meraki-api-key")).toBe(false);
  });

  it("does not flag a Cisco Meraki API Key-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(7).slice(0, 39);
    const findings = scanLine(line(`const meraki_api_key = "${value}";`));
    expect(findings.some((f) => f.ruleId === "cisco-meraki-api-key")).toBe(false);
  });

  it("flags a SumoLogic Access Token-shaped value when the keyword 'sumo' is nearby", () => {
    const value = "ab3fd1".repeat(11).slice(0, 64);
    const findings = scanLine(line(`const sumo_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sumologic-access-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like a SumoLogic Access Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(11).slice(0, 64);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sumologic-access-token")).toBe(false);
  });

  it("does not flag a SumoLogic Access Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(11).slice(0, 63);
    const findings = scanLine(line(`const sumo_access_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "sumologic-access-token")).toBe(false);
  });

  it("flags an Atlassian API Token-shaped value when the keyword 'jira' is nearby", () => {
    const value = "ab3fd1".repeat(4);
    const findings = scanLine(line(`const jira_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "atlassian-api-token" && f.confidence === "generic")).toBe(true);
  });

  it("does not flag a value shaped like an Atlassian API Token without the keyword nearby", () => {
    const value = "ab3fd1".repeat(4);
    const findings = scanLine(line(`const unrelated_var = "${value}";`));
    expect(findings.some((f) => f.ruleId === "atlassian-api-token")).toBe(false);
  });

  it("does not flag an Atlassian API Token-shaped value that is one character short even with the keyword nearby", () => {
    const value = "ab3fd1".repeat(4).slice(0, 23);
    const findings = scanLine(line(`const jira_api_token = "${value}";`));
    expect(findings.some((f) => f.ruleId === "atlassian-api-token")).toBe(false);
  });

  it("flags a HashiCorp Terraform password field in a .tf file", () => {
    const findings = scanLine(line(`password = "abc123456789"`, { filename: "main.tf" }));
    expect(findings.some((f) => f.ruleId === "hashicorp-tf-password" && f.confidence === "generic")).toBe(true);
  });

  it("flags a HashiCorp Terraform password field in a .hcl file", () => {
    const findings = scanLine(line(`administrator_login_password = "abc123456789"`, { filename: "config.hcl" }));
    expect(findings.some((f) => f.ruleId === "hashicorp-tf-password")).toBe(true);
  });

  it("does not flag a HashiCorp Terraform password field in a non-.tf/.hcl file", () => {
    const findings = scanLine(line(`password = "abc123456789"`, { filename: "src/config.ts" }));
    expect(findings.some((f) => f.ruleId === "hashicorp-tf-password")).toBe(false);
  });

  it("does not flag a .tf file line shaped like a password field but one character short", () => {
    const findings = scanLine(line(`password = "abc1234"`, { filename: "main.tf" }));
    expect(findings.some((f) => f.ruleId === "hashicorp-tf-password")).toBe(false);
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
