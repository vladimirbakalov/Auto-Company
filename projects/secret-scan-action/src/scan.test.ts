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
