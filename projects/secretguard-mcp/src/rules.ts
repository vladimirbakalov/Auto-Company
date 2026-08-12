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
