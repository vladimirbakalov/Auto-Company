/**
 * The ruleset applied to each added line.
 *
 * Two tiers:
 *  - Pattern rules: distinctive, provider-specific formats (AKIA..., sk_live_...,
 *    ghp_..., etc). A match is a near-certain secret, so these are "high"
 *    confidence and never need AI triage.
 *  - The generic entropy rule: a value assigned to a suspiciously-named
 *    variable (secret/key/token/password/credential/...) that also looks
 *    random. This catches secrets with no distinctive prefix, at the cost of
 *    being genuinely ambiguous — config placeholders, hashes, and UUIDs can
 *    all trip it. That ambiguity is exactly what the optional Claude triage
 *    step (src/triage.ts) exists to reduce.
 */

export type Confidence = "high" | "generic";

export interface PatternRule {
  id: string;
  description: string;
  /** Must NOT have the "g" flag pre-set here — callers create a fresh RegExp per scan to avoid shared lastIndex state. */
  build(): RegExp;
  /**
   * Confidence tier for this rule's findings. Defaults to "high" (near-certain
   * match, never triaged) when omitted — that default covers every
   * fixed-format provider token rule above, where a match IS the secret.
   * Set to "generic" for a rule whose captured value, even after excluding
   * known placeholders in the pattern itself, can still plausibly be a
   * non-secret (e.g. a tutorial's example DB password) rather than a
   * mis-shaped provider key. "generic" findings get the same optional Claude
   * triage and non-blocking-by-default treatment as the entropy rule.
   */
  confidence?: Confidence;
}

export const PATTERN_RULES: PatternRule[] = [
  {
    id: "aws-access-key-id",
    description: "AWS Access Key ID",
    build: () => /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    id: "aws-secret-access-key",
    description: "AWS Secret Access Key (contextual)",
    build: () => /\baws[a-z_-]{0,20}(?:secret|access)[a-z_-]{0,20}\s*[:=]\s*["'`]?([A-Za-z0-9/+=]{40})["'`]?/gi,
  },
  {
    id: "stripe-live-secret-key",
    description: "Stripe live secret key",
    build: () => /\bsk_live_[0-9a-zA-Z]{16,}\b/g,
  },
  {
    id: "stripe-live-restricted-key",
    description: "Stripe live restricted key",
    build: () => /\brk_live_[0-9a-zA-Z]{16,}\b/g,
  },
  {
    id: "github-token",
    description: "GitHub token",
    build: () => /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  },
  {
    id: "github-fine-grained-pat",
    description: "GitHub fine-grained personal access token",
    build: () => /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  {
    id: "google-api-key",
    description: "Google API key",
    build: () => /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    id: "slack-token",
    description: "Slack token",
    build: () => /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g,
  },
  {
    id: "private-key-block",
    description: "Private key block",
    build: () => /-----BEGIN\s?(?:RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----/g,
  },
  {
    id: "jwt",
    description: "JSON Web Token",
    build: () => /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    id: "openai-api-key",
    description: "OpenAI API key (legacy)",
    // No hyphens/underscores allowed in the body, which is what keeps this from also
    // matching sk-proj-/sk-svcacct- keys (openai-project-api-key) or sk-ant- keys
    // (anthropic-api-key): those all hit a "-" within the first few chars and stop short
    // of the 20-char floor here.
    build: () => /\bsk-[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: "openai-project-api-key",
    description: "OpenAI project/service-account API key",
    build: () => /\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "anthropic-api-key",
    description: "Anthropic API key",
    build: () => /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "npm-access-token",
    description: "npm access token",
    build: () => /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "gcp-oauth-client-secret",
    description: "Google Cloud OAuth client secret",
    build: () => /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "sendgrid-api-key",
    description: "SendGrid API key",
    build: () => /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  },
  {
    id: "twilio-api-key",
    description: "Twilio API key",
    build: () => /\bSK[0-9a-fA-F]{32}\b/g,
  },
  {
    id: "azure-storage-account-key",
    description: "Azure Storage account key (contextual)",
    build: () => /\bAccountKey=([A-Za-z0-9+/]{86}==)/g,
  },
  {
    id: "database-connection-string-password",
    description: "Database connection string with embedded password (contextual)",
    // Excludes a fixed list of common non-secret placeholder passwords via a
    // negative lookahead (e.g. postgres://user:password@host is not flagged),
    // and excludes ${...}/<...>/%{...} template-reference syntax by leaving
    // those characters out of the capture class entirely — a var reference
    // like postgres://user:${DB_PASSWORD}@host isn't a literal value to flag.
    // Even after that filtering the surviving matches are still genuinely
    // ambiguous (a real prod credential vs. a low-stakes tutorial example),
    // which is why this is "generic" tier, not "high" — see the isPlaceholder
    // note on Confidence above.
    build: () =>
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[A-Za-z0-9_.-]+:(?!(?:user|username|admin|root|guest|public|postgres|mysql|mariadb|pass|password|dbpassword|mypassword|yourpassword|changeit|changeme|test|example|placeholder|dummy|fake|sample|123456|12345678|letmein)@)([^@/\s'"{}$<>]{3,})@/gi,
    confidence: "generic",
  },
  {
    id: "slack-webhook-url",
    description: "Slack incoming webhook URL",
    // The URL itself is the full bearer credential — anyone with it can post
    // messages to the channel it's bound to, no other secret required. Fixed
    // hooks.slack.com/services/T.../B.../... shape has no legitimate
    // non-secret use, so this is "high" confidence like the other
    // fixed-format provider rules above.
    build: () => /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]{8,}\/B[A-Za-z0-9]{8,}\/[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: "shopify-access-token",
    description: "Shopify access token",
    // shpat_ (public app), shpca_ (custom app), shpss_ (legacy private app
    // shared secret), shppa_ (private app), shpua_ (undecided-listing app) —
    // all fixed prefixes followed by a hex body. The body was originally 32
    // hex chars; Shopify's own changelog documents it growing over time, so
    // this matches {32,} rather than an exact count.
    build: () => /\bshp(?:at|ca|ss|pa|ua)_[a-fA-F0-9]{32,}\b/g,
  },
  {
    id: "telegram-bot-token",
    description: "Telegram bot API token",
    // <bot_id>:<35-char secret>, secret always starts with 'A' (base64url
    // encoding of Telegram's internal token-type byte prefix). An earlier,
    // looser version of this pattern (bare digits + 35 arbitrary base64url
    // chars, no leading-'A' constraint) is exactly what gitleaks' own
    // telegram-bot-token rule used to ship, and it produced false positives
    // on unrelated digit:alnum35 pairs (e.g. XML schema identifiers) — see
    // gitleaks PR #1404. Requiring the leading 'A' plus a word boundary
    // narrows the match back down to the real token shape.
    build: () => /\b[0-9]{5,16}:A[A-Za-z0-9_-]{34}\b/g,
  },
  {
    id: "digitalocean-token",
    description: "DigitalOcean personal access / OAuth / refresh token",
    // dop_v1_ (personal access token), doo_v1_ (OAuth access token), dor_v1_
    // (OAuth refresh token) — fixed prefix + 64-char lowercase-hex body, no
    // legitimate non-secret use of this exact shape.
    build: () => /\bdo[opr]_v1_[a-f0-9]{64}\b/g,
  },
  {
    id: "huggingface-access-token",
    description: "Hugging Face access token",
    // hf_ + 34 letters, fixed prefix and exact length, no legitimate
    // non-secret use of this shape.
    build: () => /\bhf_[A-Za-z]{34}\b/g,
  },
  {
    id: "huggingface-organization-api-token",
    description: "Hugging Face organization API token",
    build: () => /\bapi_org_[A-Za-z]{34}\b/g,
  },
  {
    id: "notion-api-token",
    description: "Notion API token",
    // ntn_ + 11 digits + 35 alphanumeric, fixed prefix and exact length.
    build: () => /\bntn_[0-9]{11}[A-Za-z0-9]{35}\b/g,
  },
  {
    id: "mailchimp-api-key",
    description: "Mailchimp API key (contextual)",
    // A bare 32-hex-char + "-usNN" datacenter suffix is too generic a shape to
    // trust on its own (gitleaks' own rule gates it the same way), so this
    // requires a "mailchimp"-prefixed variable/key name immediately before the
    // assignment, mirroring the azure-storage-account-key /
    // database-connection-string-password contextual style already in this
    // file. Even with that gate the datacenter suffix alone doesn't rule out
    // an unrelated hex value that happens to end in "-usNN", so this stays
    // "generic" tier rather than "high".
    build: () => /\bmailchimp[a-z0-9_.-]{0,20}\s*[:=]\s*["'`]?([a-f0-9]{32}-us\d{1,2})\b["'`]?/gi,
    confidence: "generic",
  },
  {
    id: "postman-api-token",
    description: "Postman API token",
    // PMAK- + 24 hex + "-" + 34 hex, fixed prefix and exact length, no
    // legitimate non-secret use of this shape.
    build: () => /\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}\b/g,
  },
  {
    id: "linear-api-key",
    description: "Linear API key",
    // lin_api_ + 40 alphanumeric chars, fixed prefix and exact length, no
    // legitimate non-secret use of this shape.
    build: () => /\blin_api_[A-Za-z0-9]{40}\b/g,
  },
  {
    id: "readme-api-key",
    description: "Readme API key",
    // rdme_ + 70 lowercase alphanumeric chars, fixed prefix and exact
    // length, no legitimate non-secret use of this shape.
    build: () => /\brdme_[a-z0-9]{70}\b/g,
  },
  {
    id: "clojars-api-token",
    description: "Clojars API token",
    // CLOJARS_ (case-insensitive) + 60 alphanumeric chars, fixed prefix and
    // exact length, no legitimate non-secret use of this shape.
    build: () => /\bCLOJARS_[a-z0-9]{60}\b/gi,
  },
  {
    id: "pulumi-api-token",
    description: "Pulumi API token",
    // pul- + 40 lowercase-hex chars, fixed prefix and exact length, no
    // legitimate non-secret use of this shape.
    build: () => /\bpul-[a-f0-9]{40}\b/g,
  },
  {
    id: "rubygems-api-token",
    description: "RubyGems API token",
    // rubygems_ + 48 lowercase-hex chars, fixed prefix and exact length, no
    // legitimate non-secret use of this shape.
    build: () => /\brubygems_[a-f0-9]{48}\b/g,
  },
  {
    id: "doppler-api-token",
    description: "Doppler API token",
    // dp.pt. + 43 case-insensitive alphanumeric chars, fixed prefix and
    // exact length, no legitimate non-secret use of this shape.
    build: () => /\bdp\.pt\.[a-zA-Z0-9]{43}\b/g,
  },
  {
    id: "planetscale-api-token",
    description: "PlanetScale API token",
    // pscale_tkn_ + 32-64 word/dot/equals/hyphen chars. Body length is
    // variable (mirrors gitleaks' own {32,64} bound) rather than fixed, but
    // the 11-char prefix is unusual and distinctive enough on its own that
    // this stays high confidence, same as every other fixed-prefix rule
    // above.
    build: () => /\bpscale_tkn_[\w.=-]{32,64}\b/g,
  },
  {
    id: "databricks-api-token",
    description: "Databricks API token",
    // dapi + 32 lowercase-hex chars, with an optional -N numeric suffix
    // some Databricks tokens carry. Fixed prefix and body shape, no
    // legitimate non-secret use.
    build: () => /\bdapi[a-f0-9]{32}(?:-\d)?\b/g,
  },
  {
    id: "frameio-api-token",
    description: "Frame.io API token",
    // fio-u- + 64 alphanumeric/-/_/= chars, exact length. Fixed prefix
    // and body shape, no legitimate non-secret use.
    build: () => /\bfio-u-[A-Za-z0-9\-_=]{64}\b/g,
  },
  {
    id: "duffel-api-token",
    description: "Duffel API token",
    // duffel_test_ or duffel_live_ + 43 case-insensitive word/hyphen/equals
    // chars, exact length. Fixed prefix and body shape, no legitimate
    // non-secret use.
    build: () => /\bduffel_(?:test|live)_[A-Za-z0-9_\-=]{43}\b/g,
  },
  {
    id: "easypost-api-token",
    description: "EasyPost API token",
    // EZAK + 54 case-insensitive alphanumeric chars, exact length. Fixed
    // prefix and body shape, no legitimate non-secret use.
    build: () => /\bEZAK[A-Za-z0-9]{54}\b/g,
  },
  {
    id: "easypost-test-api-token",
    description: "EasyPost test API token",
    // EZTK + 54 case-insensitive alphanumeric chars, exact length. Fixed
    // prefix and body shape, no legitimate non-secret use.
    build: () => /\bEZTK[A-Za-z0-9]{54}\b/g,
  },
  {
    id: "dynatrace-api-token",
    description: "Dynatrace API token",
    // dt0c01. + 24 case-insensitive alphanumeric chars + . + 64
    // case-insensitive alphanumeric chars, exact lengths. Fixed prefix
    // and body shape, no legitimate non-secret use.
    build: () => /\bdt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}\b/g,
  },
  {
    id: "infracost-api-token",
    description: "Infracost API token",
    // ico- + 32 case-insensitive alphanumeric chars, exact length. Fixed
    // prefix and body shape, no legitimate non-secret use.
    build: () => /\bico-[A-Za-z0-9]{32}\b/g,
  },
  {
    id: "gitlab-pat",
    description: "GitLab Personal Access Token",
    // glpat- + 20 word/hyphen chars, exact length. Fixed prefix and body
    // shape, no legitimate non-secret use.
    build: () => /\bglpat-[\w-]{20}\b/g,
  },
  {
    id: "square-access-token",
    description: "Square Access Token",
    // sq0atp- + 22-60 word/hyphen chars (mirrors gitleaks' own {22,60}
    // bound). Upstream also alternates on a bare "EAAA" prefix, which is
    // too short/common to ship as a distinct high-confidence pattern on
    // its own, so only the distinctive sq0atp- prefix is included here.
    build: () => /\bsq0atp-[\w-]{22,60}\b/g,
  },
];

/**
 * Variable-name fragment that makes a high-entropy value worth flagging.
 *
 * The `*key` compounds are deliberately an explicit allowlist of prefixes
 * commonly used for actual secret material (api/access/private/signing/
 * encryption/session/master/client/jwt/hmac/cipher/oauth/refresh/cookie/
 * csrf/webhook/license), not a bare `key`. A bare `key` would also catch
 * extremely common non-secret identifiers — partitionKey, sortKey, cacheKey,
 * queryKey, primaryKey/foreignKey, translationKey, localeKey — and turn
 * every DB/cache/i18n/React-Query-shaped codebase into wall-to-wall noise.
 * QA review (adversarial pattern testing, see rules.test.ts) validated this
 * split against both categories before landing it.
 */
export const SECRET_VAR_NAME_FRAGMENT =
  "(?:secret|(?:api|access|private|signing|encryption|session|master|client|jwt|hmac|cipher|oauth|refresh|cookie|csrf|webhook|license)[_-]?key|token|password|passwd|pwd|credential|auth)";

export function buildGenericAssignmentRegex(): RegExp {
  // name = "value" | name: "value" | name := value | NAME=value (.env style)
  return new RegExp(
    `([A-Za-z0-9_.-]*${SECRET_VAR_NAME_FRAGMENT}[A-Za-z0-9_.-]*)\\s*[:=]{1,2}\\s*["'\`]?([A-Za-z0-9_\\-+/=]{12,})["'\`]?`,
    "gi",
  );
}

const PLACEHOLDER_VALUE = /^(x+|\*+|0+|1+|change-?me|your[-_]?api[-_]?key|example|placeholder|dummy|fake|redacted|test|sample)$/i;
const REFERENCE_LINE = /process\.env|os\.environ|System\.getenv|ENV\[|getenv\(|\$\{|<%=|%\{/;

export function isPlaceholderOrReference(value: string, fullLine: string): boolean {
  if (PLACEHOLDER_VALUE.test(value)) return true;
  if (/^<[^>]+>$/.test(value)) return true; // <your-key-here>
  if (REFERENCE_LINE.test(fullLine)) return true; // an env-var reference, not a literal value
  return false;
}

export const ENTROPY_THRESHOLD = 3.5;
export const MIN_GENERIC_SECRET_LENGTH = 12;

/** Shannon entropy in bits/character. Higher = more random-looking. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
