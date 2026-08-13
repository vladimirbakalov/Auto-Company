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
  /**
   * Restricts this rule to files whose path matches, tested against the
   * finding's filename before the value regex runs at all. Omit for rules
   * that apply regardless of file type (the overwhelming majority). Exists
   * for upstream rules gated on file extension (e.g. Terraform's
   * `.tf`/`.hcl` password fields) where the keyword+value shape alone is
   * too broad to ship confidently everywhere.
   */
  pathFilter?: RegExp;
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
    id: "atlassian-api-token-atatt3",
    description: "Atlassian API token (ATATT3 format)",
    // Split out of upstream gitleaks' atlassian-api-token rule, which is
    // actually two unrelated forms OR'd into one regex: a keyword-proximity
    // form (kept separately below, in the generic keyword-proximity class)
    // and this fixed "ATATT3" prefix + 186-char body form. The ATATT3 form
    // needs no nearby keyword to be identified with confidence, so it
    // belongs in the high-confidence tier with the rest of this file's
    // fixed-prefix rules rather than alongside the keyword-gated form it
    // shipped under upstream.
    build: () => /\bATATT3[A-Za-z0-9_\-=]{186}\b/g,
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
  {
    id: "contentful-delivery-api-token",
    description: "Contentful Delivery API Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 43-char
    // alnum-with-`=`/`_`/`-` string, gated on "contentful" appearing before
    // the assignment. "generic" tier for the same reason as the rest of
    // this class.
    build: () =>
      /[\w.-]{0,50}?contentful(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_-]{43})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "intercom-api-key",
    description: "Intercom API Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 60-char
    // alnum-with-`=`/`_`/`-` string, gated on "intercom" appearing before
    // the assignment. "generic" tier for the same reason as the rest of
    // this class.
    build: () =>
      /[\w.-]{0,50}?intercom(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_-]{60})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "hubspot-api-key",
    description: "HubSpot API Key (contextual)",
    // Same keyword-proximity shape, but a UUID-shaped value (HubSpot's own
    // format) rather than a bare alnum run. Gated on "hubspot" appearing
    // before the assignment. "generic" tier for the same reason as the
    // rest of this class.
    build: () =>
      /[\w.-]{0,50}?hubspot(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "heroku-api-key",
    description: "Heroku API Key (contextual)",
    // Same keyword-proximity shape as hubspot-api-key, another UUID-shaped
    // value. Gated on "heroku" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?heroku(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "sentry-access-token",
    description: "Sentry.io Access Token (contextual)",
    // Same keyword-proximity shape as coinbase-access-token, a bare 64-char
    // hex value. Gated on "sentry" appearing before the assignment.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?sentry(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "zendesk-secret-key",
    description: "Zendesk Secret Key (contextual)",
    // Same keyword-proximity shape. Value is a bare 40-char lowercase-alnum
    // string, gated on "zendesk" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?zendesk(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "discord-client-id",
    description: "Discord Client ID (contextual)",
    // Same keyword-proximity shape as the rest of this class. Value is a
    // bare 18-digit numeric string, gated on "discord" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?discord(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9]{18})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "discord-client-secret",
    description: "Discord Client Secret (contextual)",
    // Same keyword-proximity shape, a bare 32-char alnum/=/_/- value, gated
    // on "discord" appearing before the assignment. "generic" tier for the
    // same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?discord(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_-]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "dropbox-api-token",
    description: "Dropbox API Token (contextual)",
    // Same keyword-proximity shape, a bare 15-char lowercase-alnum value,
    // gated on "dropbox" appearing before the assignment. "generic" tier
    // for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?dropbox(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{15})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "bitbucket-client-id",
    description: "Bitbucket Client ID (contextual)",
    // Same keyword-proximity shape as the rest of this class. Value is a
    // bare 32-char lowercase-alnum value, gated on "bitbucket" appearing
    // before the assignment. "generic" tier for the same reason as the
    // rest of this class.
    build: () =>
      /[\w.-]{0,50}?bitbucket(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "twitch-api-token",
    description: "Twitch API Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 30-char lowercase-alnum
    // value, gated on "twitch" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?twitch(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{30})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "asana-client-id",
    description: "Asana Client ID (contextual)",
    // Same keyword-proximity shape. Value is a bare 16-digit numeric value,
    // gated on "asana" appearing before the assignment. "generic" tier for
    // the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?asana(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9]{16})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "asana-client-secret",
    description: "Asana Client Secret (contextual)",
    // Same keyword-proximity shape and "asana" keyword gate as
    // asana-client-id above, but a distinct value shape (32-char
    // lowercase-alnum) distinguishes it as its own rule — same
    // two-rules-one-keyword pattern used for discord-client-id/-secret.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?asana(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "bitbucket-client-secret",
    description: "Bitbucket Client Secret (contextual)",
    // Same keyword-proximity shape and "bitbucket" keyword gate as
    // bitbucket-client-id above, but a distinct value shape (64-char
    // alnum/=/_/- value) distinguishes it as its own rule — same
    // two-rules-one-keyword pattern used for discord and asana above.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?bitbucket(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_-]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "droneci-access-token",
    description: "Droneci Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char lowercase-alnum
    // value, gated on "droneci" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?droneci(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "beamer-api-token",
    description: "Beamer API Token (contextual)",
    // Same keyword-proximity shape, gated on "beamer" appearing before the
    // assignment. Value has a fixed "b_" literal prefix plus a 44-char
    // alnum/=/_/- body, captured together as one group. "generic" tier for
    // the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?beamer(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(b_[a-z0-9=_-]{44})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "bittrex-access-key",
    description: "Bittrex Access Key (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char lowercase-alnum
    // value, gated on "bittrex" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?bittrex(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "bittrex-secret-key",
    description: "Bittrex Secret Key (contextual)",
    // Same keyword-proximity shape and "bittrex" keyword gate as
    // bittrex-access-key above; same value shape (32-char lowercase-alnum)
    // but a distinct id, mirroring how gitleaks splits access/secret pairs
    // under one keyword. "generic" tier for the same reason as the rest of
    // this class.
    build: () =>
      /[\w.-]{0,50}?bittrex(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "confluent-access-token",
    description: "Confluent Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 16-char lowercase-alnum
    // value, gated on "confluent" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?confluent(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{16})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "confluent-secret-key",
    description: "Confluent Secret Key (contextual)",
    // Same keyword-proximity shape and "confluent" keyword gate as
    // confluent-access-token above, but a distinct value shape (64-char
    // lowercase-alnum) distinguishes it as its own rule — same
    // two-rules-one-keyword pattern used for bittrex above.
    build: () =>
      /[\w.-]{0,50}?confluent(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "fastly-api-token",
    description: "Fastly API Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char alnum/=/_/- value,
    // gated on "fastly" appearing before the assignment. "generic" tier for
    // the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?fastly(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_-]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "finicity-api-token",
    description: "Finicity API Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char hex value, gated
    // on "finicity" appearing before the assignment. "generic" tier for the
    // same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?finicity(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "finicity-client-secret",
    description: "Finicity Client Secret (contextual)",
    // Same keyword-proximity shape and "finicity" keyword gate as
    // finicity-api-token above, but a distinct value shape (20-char
    // lowercase-alnum, not hex) distinguishes it as its own rule — same
    // two-rules-one-keyword pattern used for bittrex and confluent above.
    build: () =>
      /[\w.-]{0,50}?finicity(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{20})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "finnhub-access-token",
    description: "Finnhub Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 20-char lowercase-alnum
    // value, gated on "finnhub" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?finnhub(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{20})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "flickr-access-token",
    description: "Flickr Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char lowercase-alnum
    // value, gated on "flickr" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?flickr(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "freshbooks-access-token",
    description: "Freshbooks Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 64-char lowercase-alnum
    // value, gated on "freshbooks" appearing before the assignment.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?freshbooks(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "alibaba-secret-key",
    description: "Alibaba Cloud Secret Key (contextual)",
    // Same keyword-proximity shape. Value is a bare 30-char lowercase-alnum
    // value, gated on "alibaba" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?alibaba(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{30})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "facebook-secret",
    description: "Facebook App Secret (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char hex value, gated
    // on "facebook" appearing before the assignment. "generic" tier for the
    // same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?facebook(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "gitter-access-token",
    description: "Gitter Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 40-char lowercase-alnum
    // (plus "_"/"-") value, gated on "gitter" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?gitter(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9_-]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "gocardless-api-token",
    description: "GoCardless API Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "live_" prefix plus a
    // 40-char alnum/"="/"_"/"-" body, gated on "gocardless" appearing before
    // the assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?gocardless(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(live_[a-z0-9\-_=]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "jfrog-api-key",
    description: "JFrog API Key (contextual)",
    // Same keyword-proximity shape. Value is a bare 73-char lowercase-alnum
    // value, gated on any of "jfrog"/"artifactory"/"bintray"/"xray"
    // appearing before the assignment (a flat keyword alternation, still a
    // simple single-capture-group shape). "generic" tier for the same
    // reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{73})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "jfrog-identity-token",
    description: "JFrog Identity Token (contextual)",
    // Same keyword-proximity shape and keyword gate as jfrog-api-key. Value
    // is a bare 64-char lowercase-alnum value (shorter than the API key
    // shape, distinguishing the two rules). "generic" tier for the same
    // reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "kraken-access-token",
    description: "Kraken Access Token (contextual)",
    // Same keyword-proximity shape. Value is an 80-90-char
    // alnum/"/"/"="/"_"/"+"/"-" value, gated on "kraken" appearing before
    // the assignment. "generic" tier for the same reason as the rest of
    // this class.
    build: () =>
      /[\w.-]{0,50}?kraken(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9\/=_+-]{80,90})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "kucoin-access-token",
    description: "Kucoin Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 24-char hex value,
    // gated on "kucoin" appearing before the assignment. "generic" tier for
    // the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?kucoin(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{24})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "kucoin-secret-key",
    description: "Kucoin Secret Key (contextual)",
    // Same keyword-proximity shape and keyword gate as kucoin-access-token.
    // Value is UUID-shaped (hyphens preserved in the capture group, same
    // convention as this codebase's other UUID-shaped rules). "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?kucoin(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "launchdarkly-access-token",
    description: "LaunchDarkly Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 40-char
    // alnum/"="/"_"/"-" value, gated on "launchdarkly" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?launchdarkly(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_-]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "linear-client-secret",
    description: "Linear Client Secret (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char hex value,
    // gated on "linear" appearing before the assignment. Distinct from the
    // existing "linear-api-key" rule (different id, different shape).
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?linear(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "linkedin-client-id",
    description: "LinkedIn Client ID (contextual)",
    // Same keyword-proximity shape. Value is a bare 14-char lowercase-alnum
    // value, gated on "linkedin"/"linked_in"/"linked-in" (optional
    // separator, still a flat pattern) appearing before the assignment.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?linked[_-]?in(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{14})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "linkedin-client-secret",
    description: "LinkedIn Client Secret (contextual)",
    // Same keyword-proximity shape and keyword gate as linkedin-client-id.
    // Value is a bare 16-char lowercase-alnum value (longer than the client
    // ID shape, distinguishing the two rules). "generic" tier for the same
    // reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?linked[_-]?in(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{16})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "mattermost-access-token",
    description: "Mattermost Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 26-char lowercase-alnum
    // value, gated on "mattermost" appearing before the assignment.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?mattermost(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{26})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "dropbox-long-lived-api-token",
    description: "Dropbox Long-Lived API Token (contextual)",
    // Same keyword-proximity shape. Value is an 11-char lowercase-alnum
    // segment, a fixed "AAAAAAAAAA" middle segment, then a 43-char
    // alnum/"-"/"_"/"=" tail, all inside one capture group, gated on
    // "dropbox" appearing before the assignment. Distinct from the existing
    // "dropbox-api-token" rule (different id, different shape). "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?dropbox(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{11}(?:AAAAAAAAAA)[a-z0-9\-_=]{43})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "dropbox-short-lived-api-token",
    description: "Dropbox Short-Lived API Token (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // dropbox-long-lived-api-token. Value has a fixed "sl." prefix plus a
    // 135-char alnum/"-"/"="/"_" body. "generic" tier for the same reason
    // as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?dropbox(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(sl\.[a-z0-9\-=_]{135})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "defined-networking-api-token",
    description: "Defined Networking API Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "dnkey-" prefix, then
    // two hyphen-separated segments (26-char then 52-char, alnum/"="/"_"/
    // "-") kept inside one capture group, gated on "dnkey" appearing before
    // the assignment. "generic" tier for the same reason as the rest of
    // this class.
    build: () =>
      /[\w.-]{0,50}?dnkey(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(dnkey-[a-z0-9=_-]{26}-[a-z0-9=_-]{52})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "lob-api-key",
    description: "Lob API Key (contextual)",
    // Same keyword-proximity shape. Value has a fixed "live_"/"test_"
    // prefix (non-capturing alternation) plus a 35-char hex body, gated on
    // "lob" appearing before the assignment. "generic" tier for the same
    // reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?lob(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}((?:live|test)_[a-f0-9]{35})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "lob-pub-api-key",
    description: "Lob Publishable API Key (contextual)",
    // Same keyword-proximity shape and keyword gate as lob-api-key. Value
    // has a fixed "test_pub_"/"live_pub_" prefix (non-capturing
    // alternation) plus a 31-char hex body. "generic" tier for the same
    // reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?lob(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}((?:test|live)_pub_[a-f0-9]{31})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "looker-client-id",
    description: "Looker Client ID (contextual)",
    // Same keyword-proximity shape. Value is a bare 20-char lowercase-alnum
    // value, gated on "looker" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?looker(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{20})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "looker-client-secret",
    description: "Looker Client Secret (contextual)",
    // Same keyword-proximity shape and keyword gate as looker-client-id.
    // Value is a bare 24-char lowercase-alnum value (longer than the
    // client ID shape, distinguishing the two rules). "generic" tier for
    // the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?looker(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{24})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "mailgun-private-api-token",
    description: "Mailgun Private API Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "key-" prefix plus a
    // 32-char hex body, gated on "mailgun" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?mailgun(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(key-[a-f0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "mailgun-pub-key",
    description: "Mailgun Public Validation Key (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // mailgun-private-api-token. Value has a fixed "pubkey-" prefix plus a
    // 32-char hex body. "generic" tier for the same reason as the rest of
    // this class.
    build: () =>
      /[\w.-]{0,50}?mailgun(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "mailgun-signing-key",
    description: "Mailgun Webhook Signing Key (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // mailgun-private-api-token. Value is a 32-hex segment, an 8-hex
    // segment, and another 8-hex segment, hyphen-separated and kept
    // inside one capture group. "generic" tier for the same reason as the
    // rest of this class.
    build: () =>
      /[\w.-]{0,50}?mailgun(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "mapbox-api-token",
    description: "MapBox API Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "pk." prefix, a
    // 60-char alnum segment, a ".", and a 22-char alnum segment, all
    // inside one capture group, gated on "mapbox" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?mapbox(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "messagebird-api-token",
    description: "MessageBird API Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 25-char lowercase-alnum
    // value, gated on "messagebird"/"message_bird"/"message-bird"
    // (optional separator, still a flat pattern) appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?message[_-]?bird(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{25})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "messagebird-client-id",
    description: "MessageBird Client ID (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // messagebird-api-token. Value is UUID-shaped (hyphens preserved in
    // the capture group, same convention as this codebase's other
    // UUID-shaped rules). "generic" tier for the same reason as the rest
    // of this class.
    build: () =>
      /[\w.-]{0,50}?message[_-]?bird(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "netlify-access-token",
    description: "Netlify Access Token (contextual)",
    // Same keyword-proximity shape. Value is a 40-46-char range
    // alnum/"="/"_"/"-" value, gated on "netlify" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?netlify(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_-]{40,46})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "new-relic-browser-api-token",
    description: "New Relic Browser API Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "NRJS-" prefix plus a
    // 19-char hex body, gated on "new-relic"/"newrelic"/"new_relic" (flat
    // alternation) appearing before the assignment. "generic" tier for the
    // same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "new-relic-insert-key",
    description: "New Relic Insert Key (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // new-relic-browser-api-token. Value has a fixed "NRII-" prefix plus a
    // 32-char alnum/"-" body. "generic" tier for the same reason as the
    // rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "new-relic-user-api-id",
    description: "New Relic User API ID (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // new-relic-browser-api-token. Value is a bare 64-char lowercase-alnum
    // value. "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{64})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "new-relic-user-api-key",
    description: "New Relic User API Key (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // new-relic-browser-api-token. Value has a fixed "NRAK-" prefix plus a
    // 27-char lowercase-alnum body. "generic" tier for the same reason as
    // the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "plaid-api-token",
    description: "Plaid API Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "access-" prefix, a
    // non-capturing "sandbox"/"development"/"production" segment, and a
    // UUID shape, all inside one capture group, gated on "plaid" appearing
    // before the assignment. "generic" tier for the same reason as the
    // rest of this class.
    build: () =>
      /[\w.-]{0,50}?plaid(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "plaid-client-id",
    description: "Plaid Client ID (contextual)",
    // Same keyword-proximity shape and keyword gate as plaid-api-token.
    // Value is a bare 24-char lowercase-alnum value. "generic" tier for the
    // same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?plaid(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{24})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "plaid-secret-key",
    description: "Plaid Secret Key (contextual)",
    // Same keyword-proximity shape and keyword gate as plaid-api-token.
    // Value is a bare 30-char lowercase-alnum value (longer than the client
    // ID shape, distinguishing the two rules). "generic" tier for the same
    // reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?plaid(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{30})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "sendbird-access-id",
    description: "Sendbird Access ID (contextual)",
    // Same keyword-proximity shape. Value is UUID-shaped (hyphens
    // preserved in the capture group, same convention as this codebase's
    // other UUID-shaped rules), gated on "sendbird" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?sendbird(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "sendbird-access-token",
    description: "Sendbird Access Token (contextual)",
    // Same keyword-proximity shape and keyword gate as sendbird-access-id.
    // Value is a bare 40-char hex value. "generic" tier for the same
    // reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?sendbird(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "sidekiq-secret",
    description: "Sidekiq Secret (contextual)",
    // Same keyword-proximity shape, but the keyword gate is two fixed
    // Bundler env-var-name strings (flat alternation) instead of a service
    // name, since Sidekiq Pro/Enterprise credentials are conventionally
    // supplied via BUNDLE_GEMS__CONTRIBSYS__COM /
    // BUNDLE_ENTERPRISE__CONTRIBSYS__COM. Value is two 8-char hex segments
    // separated by a colon, kept inside one capture group. "generic" tier
    // for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "nytimes-access-token",
    description: "New York Times Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 32-char alnum/"=_-"
    // body, gated on "nytimes"/"new-york-times,"/"newyorktimes" appearing
    // before the assignment. The trailing comma in the middle alternative
    // is a faithful port of an upstream typo, not a mistake introduced
    // here. "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "rapidapi-access-token",
    description: "RapidAPI Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 50-char alnum/"_-"
    // body, gated on "rapidapi" appearing before the assignment.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?rapidapi(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9_-]{50})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "squarespace-access-token",
    description: "Squarespace Access Token (contextual)",
    // Same keyword-proximity shape. Value is UUID-shaped, gated on
    // "squarespace" appearing before the assignment. "generic" tier for
    // the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?squarespace(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "travisci-access-token",
    description: "Travis CI Access Token (contextual)",
    // Same keyword-proximity shape. Value is a bare 22-char lowercase-alnum
    // body, gated on "travis" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?travis(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{22})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "typeform-api-token",
    description: "Typeform API Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "tfp_" prefix plus a
    // 59-char alnum/"-_.=" body, gated on "typeform" appearing before the
    // assignment. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?typeform(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(tfp_[a-z0-9\-_.=]{59})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "twitter-access-secret",
    description: "Twitter Access Secret (contextual)",
    // Same keyword-proximity shape. Value is a bare 45-char lowercase-alnum
    // body, gated on "twitter" appearing before the assignment. "generic"
    // tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?twitter(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{45})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "twitter-access-token",
    description: "Twitter Access Token (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // twitter-access-secret. Value is 15-25 digits, a hyphen, then
    // 20-40 mixed-case alnum chars, all inside one capture group.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?twitter(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "twitter-api-key",
    description: "Twitter API Key (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // twitter-access-secret. Value is a bare 25-char lowercase-alnum
    // body. "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?twitter(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{25})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "twitter-api-secret",
    description: "Twitter API Secret (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // twitter-access-secret. Value is a bare 50-char lowercase-alnum
    // body. "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?twitter(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-z0-9]{50})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "twitter-bearer-token",
    description: "Twitter Bearer Token (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // twitter-access-secret. Value is a fixed run of 22 uppercase "A"
    // chars (case-insensitively matched, same as the rest of this class)
    // plus 80-100 mixed alnum/"%" chars, all inside one capture group.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?twitter(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "yandex-access-token",
    description: "Yandex Access Token (contextual)",
    // Same keyword-proximity shape. Value has a fixed "t1." prefix, a
    // variable-length segment, a ".", then an 86-char segment with
    // optional trailing "=" padding, all inside one capture group, gated
    // on "yandex" appearing before the assignment. "generic" tier for the
    // same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?yandex(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "yandex-api-key",
    description: "Yandex API Key (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // yandex-access-token. Value has a fixed "AQVN" prefix plus a
    // 35-38-char alnum/"_-" body. "generic" tier for the same reason as
    // the rest of this class.
    build: () =>
      /[\w.-]{0,50}?yandex(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(AQVN[A-Za-z0-9_-]{35,38})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "yandex-aws-access-token",
    description: "Yandex Cloud AWS-compatible Access Token (contextual)",
    // Same keyword-proximity shape and keyword gate as
    // yandex-access-token. Value has a fixed "YC" prefix plus a 38-char
    // alnum/"_-" body. "generic" tier for the same reason as the rest of
    // this class.
    build: () =>
      /[\w.-]{0,50}?yandex(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(YC[a-zA-Z0-9_-]{38})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "cohere-api-token",
    description: "Cohere Token (contextual)",
    // Same keyword-proximity shape. Keyword gate is a flat alternation of
    // "cohere" or "CO_API_KEY" (both matched case-insensitively, same as
    // the rest of this class). Value is a bare 40-char alnum body.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-zA-Z0-9]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "snyk-api-token",
    description: "Snyk API Token (contextual)",
    // Same keyword-proximity shape, but the keyword gate is a compound
    // fragment ("snyk" plus optional "api"/"oauth" plus "key"/"token",
    // e.g. "snyk_api_token", "SNYK_TOKEN", "snyk_oauth_key") instead of a
    // single flat name, matched case-insensitively like the rest of this
    // class. Value is UUID-shaped. "generic" tier for the same reason as
    // the rest of this class.
    build: () =>
      /[\w.-]{0,50}?snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "sonar-api-token",
    description: "Sonar API Token (contextual)",
    // Same keyword-proximity shape, keyword gate is "sonar" plus "login"
    // or "token" (e.g. "sonar_token", "sonar.login"), matched
    // case-insensitively like the rest of this class. Value is a bare
    // 40-char alnum/"=_-" body with an optional "squ_"/"sqp_"/"sqa_"
    // prefix, all inside one capture group — upstream captures this value
    // via a second, non-value capture group around the "login|token"
    // keyword alternative (its `secretGroup = 2`); that inner group is
    // flattened to non-capturing here so the value stays in capture group
    // 1, matching this codebase's single-capture-group convention.
    // "generic" tier for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?sonar[_.-]?(?:login|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_-]{40})(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
  },
  {
    id: "okta-access-token",
    description: "Okta Access Token (contextual)",
    // Same keyword-proximity shape, but upstream restricts the keyword to
    // exactly three case spellings ("okta", "Okta", "OKTA" — not arbitrary
    // mixed case) via an inline case-sensitive sub-pattern that has no
    // direct ECMAScript equivalent, so this rule is built without the "i"
    // flag and spells out that exact alternation instead of a single
    // case-insensitive literal. The value pattern (a fixed "00" prefix
    // plus a 40-char "\w"/"="/"-" body) is already case-complete via "\w",
    // so it needs no further change from the case-insensitive-flag
    // version. "generic" tier for the same reason as the rest of this
    // class.
    build: () =>
      /[\w.-]{0,50}?(?:okta|Okta|OKTA)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}(00[\w=\-]{40})(?:[`'"\s;]|\\[nr]|$)/g,
    confidence: "generic",
  },
  {
    id: "etsy-access-token",
    description: "Etsy Access Token (contextual)",
    // Same keyword-proximity shape and same "exactly three case spellings"
    // constraint as okta-access-token (keyword must be "etsy", "Etsy", or
    // "ETSY"), so this rule is likewise built without the "i" flag. Unlike
    // okta-access-token, the value pattern (a bare 24-char alnum body) was
    // case-insensitive under upstream's outer flag, so it is widened from
    // upstream's literal "[a-z0-9]{24}" to "[a-zA-Z0-9]{24}" here to
    // preserve that behavior without a global "i" flag. "generic" tier for
    // the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:ETSY|Etsy|etsy)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-zA-Z0-9]{24})(?:[`'"\s;]|\\[nr]|$)/g,
    confidence: "generic",
  },
  {
    id: "cisco-meraki-api-key",
    description: "Cisco Meraki API Key (contextual)",
    // Same keyword-proximity shape and same "exactly three case spellings"
    // constraint as okta-access-token (keyword must be "meraki", "Meraki",
    // or "MERAKI"), so this rule is likewise built without the "i" flag,
    // with the value pattern (a bare 40-char hex body) widened from
    // upstream's case-insensitive-under-flag "[0-9a-f]{40}" to
    // "[0-9a-fA-F]{40}" to preserve that behavior directly. "generic" tier
    // for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:meraki|Meraki|MERAKI)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([0-9a-fA-F]{40})(?:[`'"\s;]|\\[nr]|$)/g,
    confidence: "generic",
  },
  {
    id: "sumologic-access-token",
    description: "SumoLogic Access Token (contextual)",
    // Same keyword-proximity shape and same "exactly three case spellings"
    // constraint as okta-access-token (keyword must be "sumo", "Sumo", or
    // "SUMO"), so this rule is likewise built without the "i" flag, with
    // the value pattern (a bare 64-char alnum body) widened from
    // upstream's case-insensitive-under-flag "[a-z0-9]{64}" to
    // "[a-zA-Z0-9]{64}" to preserve that behavior directly. "generic" tier
    // for the same reason as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:sumo|Sumo|SUMO)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-zA-Z0-9]{64})(?:[`'"\s;]|\\[nr]|$)/g,
    confidence: "generic",
  },
  {
    id: "atlassian-api-token",
    description: "Atlassian API Token (contextual)",
    // Keyword-proximity half of upstream gitleaks' atlassian-api-token
    // rule; the fixed-prefix "ATATT3..." half is shipped separately as
    // atlassian-api-token-atatt3 in the high-confidence tier above (see
    // that rule's comment for why). Upstream restricts each of its three
    // keywords ("atlassian", "confluence", "jira") to exactly three case
    // spellings via an inline case-sensitive sub-pattern, so this rule is
    // built without the "i" flag and spells out all nine explicit
    // spellings, the same technique as okta-access-token etc. above. The
    // value pattern (a 20-char alnum body + 4-char hex suffix) was
    // case-insensitive under upstream's outer flag, so it is widened from
    // "[a-z0-9]{20}[a-f0-9]{4}" to "[a-zA-Z0-9]{20}[a-fA-F0-9]{4}" here to
    // preserve that behavior directly. "generic" tier for the same reason
    // as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:ATLASSIAN|Atlassian|atlassian|CONFLUENCE|Confluence|confluence|JIRA|Jira|jira)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}([a-zA-Z0-9]{20}[a-fA-F0-9]{4})(?:[`'"\s;]|\\[nr]|$)/g,
    confidence: "generic",
  },
  {
    id: "hashicorp-tf-password",
    description: "HashiCorp Terraform password field (contextual)",
    // Same keyword-proximity shape as the rest of this class, but upstream
    // additionally gates this rule on the file path ending in .tf or .hcl
    // (`path = '''(?i)\.(?:tf|hcl)$'''`), since "password = ..." alone is
    // far too broad a keyword to ship file-type-agnostically. AddedLine
    // already carries a filename per line (see scan.ts), so this is
    // expressed via the pathFilter field rather than being permanently
    // out of scope. The captured value keeps its literal surrounding
    // double quotes (upstream's own capture group is `("[a-z0-9=_\-]{8,20}")`,
    // not just the inner chars) — Terraform string literals are always
    // double-quoted, so this rule deliberately only matches that exact
    // quoting style, unlike most other rules in this class which accept
    // backtick/single/double quotes interchangeably. Value charset widened
    // from upstream's case-insensitive-under-flag "[a-z0-9=_-]" to
    // "[a-zA-Z0-9=_-]" since this rule has no keyword-case restriction and
    // so keeps the standard "gi" flag. "generic" tier for the same reason
    // as the rest of this class.
    build: () =>
      /[\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}("[a-zA-Z0-9=_\-]{8,20}")(?:[`'"\s;]|\\[nr]|$)/gi,
    confidence: "generic",
    pathFilter: /\.(?:tf|hcl)$/i,
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
