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
  {
    id: "age-secret-key",
    description: "age encryption secret key",
    build: () => /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/g,
  },
  {
    id: "1password-service-account-token",
    description: "1Password service account token",
    // ops_eyJ + 250+ base64 chars + up to 3 trailing '=' padding chars. No
    // upper bound on body length upstream; the fixed prefix plus very long
    // minimum length makes this distinctive enough to stay high confidence.
    build: () => /\bops_eyJ[a-zA-Z0-9+/]{250,}={0,3}\b/g,
  },
  {
    id: "alibaba-access-key-id",
    description: "Alibaba Cloud AccessKey ID",
    // LTAI (case-sensitive) + 20 case-insensitive alphanumeric chars,
    // exact length. Fixed prefix and body shape, no legitimate non-secret
    // use.
    build: () => /\bLTAI[a-zA-Z0-9]{20}\b/g,
  },
  {
    id: "artifactory-api-key",
    description: "Artifactory API key",
    // AKCp + 69 alphanumeric chars, exact length. Fixed prefix and body
    // shape, no legitimate non-secret use.
    build: () => /\bAKCp[A-Za-z0-9]{69}\b/g,
  },
  {
    id: "artifactory-reference-token",
    description: "Artifactory reference token",
    // cmVmd + 59 alphanumeric chars, exact length. Fixed prefix and body
    // shape, no legitimate non-secret use.
    build: () => /\bcmVmd[A-Za-z0-9]{59}\b/g,
  },
  {
    id: "cloudflare-origin-ca-key",
    description: "Cloudflare Origin CA Key",
    // v1.0- + 24 hex chars + - + 146 hex chars, exact lengths. The
    // combined shape (fixed prefix, two hex segments of exact length) is
    // distinctive even though "v1.0-" alone isn't.
    build: () => /\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b/g,
  },
  {
    id: "aws-amazon-bedrock-api-key-long-lived",
    description: "AWS Amazon Bedrock long-lived API key",
    // ABSK + 109-269 base64ish chars + up to 2 trailing '=' padding chars
    // (mirrors gitleaks' own {109,269} bound). Fixed prefix and very long
    // minimum body length make this distinctive enough to stay high
    // confidence despite the variable-length range.
    build: () => /\bABSK[A-Za-z0-9+/]{109,269}={0,2}\b/g,
  },
  {
    id: "adobe-client-secret",
    description: "Adobe Client Secret",
    // p8e- (case-sensitive) + 32 alnum chars (both cases). Upstream gitleaks
    // scopes its (?i) flag to the body only, not the prefix, so the prefix
    // stays case-sensitive here too.
    build: () => /\bp8e-[A-Za-z0-9]{32}\b/g,
  },
  {
    id: "1password-secret-key",
    description: "1Password Secret Key",
    // A3- + 6 uppercase-alnum + - + (11 uppercase-alnum, or 6+5 split by a
    // dash) + - + three more 5-char uppercase-alnum groups. The short A3-
    // prefix alone would be too generic, but the full 5/6-segment dashed
    // structure is distinctive enough to stay high confidence.
    build: () =>
      /\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b/g,
  },
  {
    id: "airtable-personnal-access-token",
    description: "Airtable Personal Access Token",
    // pat + 14 alnum + . + 64 hex chars. The bare "pat" prefix alone is a
    // common short variable-name fragment, but the fixed-length dot-joined
    // 64-hex suffix is distinctive enough to keep this high confidence.
    build: () => /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g,
  },
  {
    id: "authress-service-client-access-key",
    description: "Authress Service Client Access Key",
    // One of four branded prefixes (sc_/ext_/scauth_/authress_) + a dotted
    // 4-segment body: two alnum segments, a literal "acc" (case-sensitive,
    // even though the rest of the body is case-insensitive upstream)
    // followed by a separator and alnum-dash chars, then a long base64ish
    // segment. The branded prefixes plus the fixed "acc" marker make this
    // distinctive despite the variable-length segments.
    build: () =>
      /\b(?:sc|ext|scauth|authress)_[A-Za-z0-9]{5,30}\.[A-Za-z0-9]{4,6}\.acc[_-][A-Za-z0-9-]{10,32}\.[A-Za-z0-9+/_=-]{30,120}\b/g,
  },
  {
    id: "clickhouse-cloud-api-secret-key",
    description: "ClickHouse Cloud API secret key",
    // Fixed 4-char literal prefix "4b1d" + exactly 38 alnum chars. Unlike the
    // branded prefixes above (hf_, ntn_, PMAK-, ...), "4b1d" isn't a
    // human-recognizable brand marker — it's four hex-range characters that
    // could plausibly turn up as a substring inside an unrelated random
    // hex/hash blob of the same rough length. That's real ambiguity even
    // after the fixed-length shape match, so this stays "generic" tier
    // (optional AI triage) rather than "high", unlike the other fixed-prefix
    // rules in this file.
    build: () => /\b4b1d[A-Za-z0-9]{38}\b/g,
    confidence: "generic",
  },
  {
    id: "adafruit-api-key",
    description: "Adafruit API Key (contextual)",
    // First rule of a genuinely different shape than everything above: no
    // fixed prefix on the secret itself. Adafruit keys are bare 32-char
    // lowercase-alnum/underscore/hyphen strings, indistinguishable from
    // countless other 32-char tokens on their own — the only signal is the
    // word "adafruit" appearing within ~70 chars before an assignment
    // operator. Ported from upstream gitleaks' keyword-proximity shape
    // (`[\w.-]{0,50}?(?:keyword)[\w.\s-]{0,20}[assignment-op][quote/space]{0,5}(value)`),
    // which several dozen other upstream rules also use (airtable-api-key,
    // discord-api-token, etc. — see Cycle #58/#71 notes) and none of which
    // had been ported before this one. "generic" tier, not "high": even
    // with the keyword gate, a 32-char value near the word "adafruit" could
    // be a config key name, a hash, or another non-secret token.
    build: () =>
      /[\w.-]{0,50}?adafruit(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9_-]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "airtable-api-key",
    description: "Airtable API Key (contextual)",
    // Same keyword-proximity shape as adafruit-api-key above, second of the
    // three follow-on candidates identified in Cycle #71 as sharing the
    // exact same upstream regex skeleton. Value is a bare 17-char
    // lowercase-alnum string, gated on "airtable" appearing before the
    // assignment. "generic" tier for the same reason as adafruit: the
    // 17-char value alone is not distinctive.
    build: () =>
      /[\w.-]{0,50}?airtable(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{17})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "discord-api-token",
    description: "Discord API Token (contextual)",
    // Same keyword-proximity shape, third follow-on candidate from Cycle
    // #71. Value is a bare 64-char hex string, gated on "discord" appearing
    // before the assignment. "generic" tier: a 64-char hex string near the
    // word "discord" could still be a hash or unrelated token.
    build: () =>
      /[\w.-]{0,50}?discord(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "adobe-client-id",
    description: "Adobe OAuth Web Client ID (contextual)",
    // Same keyword-proximity shape, fourth follow-on candidate from Cycle
    // #71. Value is a bare 32-char hex string, gated on "adobe" appearing
    // before the assignment. "generic" tier: a 32-char hex string near the
    // word "adobe" could still be a config ID, hash, or unrelated token.
    build: () =>
      /[\w.-]{0,50}?adobe(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "algolia-api-key",
    description: "Algolia API Key (contextual)",
    // Same keyword-proximity shape as adafruit-api-key/airtable-api-key/
    // discord-api-token/adobe-client-id, sourced from the same cached
    // upstream regex skeleton. Value is a bare 32-char lowercase-alnum
    // string, gated on "algolia" appearing before the assignment.
    // "generic" tier: a 32-char value near the word "algolia" could still
    // be a config ID, hash, or unrelated token.
    build: () =>
      /[\w.-]{0,50}?algolia(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "codecov-access-token",
    description: "Codecov Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char lowercase-alnum
    // string, gated on "codecov" appearing before the assignment.
    // "generic" tier for the same reason as the other rules in this class.
    build: () =>
      /[\w.-]{0,50}?codecov(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "datadog-access-token",
    description: "Datadog Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 40-char lowercase-alnum
    // string, gated on "datadog" appearing before the assignment.
    // "generic" tier for the same reason as the other rules in this class.
    build: () =>
      /[\w.-]{0,50}?datadog(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "cloudflare-api-key",
    description: "Cloudflare API Key (contextual)",
    // Same keyword-proximity shape as the rest of this class. Value is a
    // bare 40-char lowercase-alnum-with-dashes/underscores string, gated on
    // "cloudflare" appearing before the assignment. "generic" tier: a
    // 40-char value near the word "cloudflare" could still be a config ID,
    // hash, or unrelated token.
    build: () =>
      /[\w.-]{0,50}?cloudflare(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9_-]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "cloudflare-global-api-key",
    description: "Cloudflare Global API Key (contextual)",
    // Same keyword-proximity shape and same "cloudflare" keyword gate as
    // cloudflare-api-key above, but a distinct value shape (37-char hex)
    // matching the Global API Key format upstream distinguishes as its own
    // rule. "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?cloudflare(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{37})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "coinbase-access-token",
    description: "Coinbase Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 64-char
    // lowercase-alnum-with-dashes/underscores string, gated on "coinbase"
    // appearing before the assignment. "generic" tier for the same reason
    // as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?coinbase(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9_-]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
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
