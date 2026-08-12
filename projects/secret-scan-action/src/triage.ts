import Anthropic from "@anthropic-ai/sdk";
import { redactSecret, redactLine } from "./redact";
import { shannonEntropy } from "./rules";
import type { Finding } from "./scan";

/**
 * Optional BYOK triage for "generic" confidence findings only — the
 * ambiguous high-entropy-variable hits that are cheap to false-positive on
 * (hashes, UUIDs, test fixtures, encoded-but-non-secret data). Confirmed
 * pattern matches (AWS/Stripe/GitHub/... keys) are never sent here; they
 * don't need a second opinion.
 *
 * Only a masked form of each value is sent (see `redactSecret`) — the model
 * gets enough shape (length, entropy, variable name, masked context line) to
 * judge plausibility without the actual secret ever leaving the runner. This
 * mirrors the "never send the raw key/secret anywhere but api.anthropic.com"
 * guarantee the sibling pr-summary-action makes, extended to the values this
 * action discovers, not just the caller's own API key.
 */

const MAX_TRIAGE_CANDIDATES = 30;

export interface TriageCandidate {
  id: number;
  finding: Finding;
}

const SYSTEM_PROMPT = `You are a security engineer triaging possible secret leaks found by a generic \
high-entropy heuristic scanning a pull request's added lines. Each candidate is a value assigned \
to a variable whose name suggests a secret (token/key/password/credential/...), and whose value \
looks random enough to be one. The actual value is masked — you're given its length, its Shannon \
entropy, the variable name, and the surrounding line with the value masked.

Decide whether each candidate is LIKELY a real secret/credential that should block the PR, or a \
FALSE POSITIVE — e.g. a git commit SHA, a UUID, a hashed password (bcrypt/sha256 output), a test \
fixture or mock value, a non-secret encoded identifier, or an obvious placeholder.

Respond with ONLY a JSON array (no markdown fence, no prose), one object per candidate, in the form:
[{"id": <number>, "isLikelySecret": <boolean>}]

Include every candidate id exactly once. If you are unsure, prefer isLikelySecret: true — a missed \
real secret is worse than a flagged false positive.`;

export function buildTriagePayload(candidates: TriageCandidate[]) {
  return candidates.map(({ id, finding }) => ({
    id,
    filename: finding.filename,
    ruleDescription: finding.description,
    valueLength: finding.secret.length,
    entropyBitsPerChar: Number(shannonEntropy(finding.secret).toFixed(2)),
    maskedValue: redactSecret(finding.secret),
    maskedContextLine: redactLine(finding.contextLine, finding.secret),
  }));
}

/**
 * Calls the Anthropic API to triage ambiguous findings. Returns a map of
 * candidate id -> keep (true = treat as a real secret, false = drop as a
 * false positive). Fails safe: any id the model doesn't clearly address, or
 * any error parsing/calling the API, resolves to `true` (kept flagged)
 * rather than silently dropped.
 */
export async function triageCandidates(params: {
  apiKey: string;
  model: string;
  candidates: TriageCandidate[];
}): Promise<Map<number, boolean>> {
  const { apiKey, model } = params;
  const candidates = params.candidates.slice(0, MAX_TRIAGE_CANDIDATES);
  const overflow = params.candidates.slice(MAX_TRIAGE_CANDIDATES);

  const result = new Map<number, boolean>();
  for (const c of overflow) result.set(c.id, true); // fail safe: never sent, stay flagged

  if (candidates.length === 0) return result;

  // baseURL pinned explicitly — see summarize.ts in pr-summary-action for why:
  // the SDK falls back to process.env.ANTHROPIC_BASE_URL when unset, which
  // would let a prior workflow step silently redirect the key and masked
  // finding data to a non-Anthropic endpoint.
  const client = new Anthropic({ apiKey, baseURL: "https://api.anthropic.com" });

  let response: Anthropic.Message;
  try {
    response = await client.messages.create({
      model,
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: JSON.stringify(buildTriagePayload(candidates), null, 2) }],
    });
  } catch (err) {
    throw toSafeTriageError(err);
  }

  const textBlock = response.content.find((b): b is Anthropic.TextBlock => b.type === "text");
  const parsed = textBlock ? parseTriageResponse(textBlock.text) : new Map<number, boolean>();

  for (const c of candidates) {
    result.set(c.id, parsed.get(c.id) ?? true); // fail safe: unaddressed id stays flagged
  }

  return result;
}

export function parseTriageResponse(text: string): Map<number, boolean> {
  const result = new Map<number, boolean>();
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start === -1 || end === -1 || end < start) return result;

  try {
    const parsed = JSON.parse(text.slice(start, end + 1)) as Array<{ id: unknown; isLikelySecret: unknown }>;
    for (const item of parsed) {
      if (typeof item.id === "number" && typeof item.isLikelySecret === "boolean") {
        result.set(item.id, item.isLikelySecret);
      }
    }
  } catch {
    // Malformed JSON — return whatever (nothing) we have; caller fails safe per-id.
  }

  return result;
}

/**
 * Converts an Anthropic SDK error into a generic, secret-free message.
 * Deliberately does NOT forward `err.message` verbatim (see summarize.ts).
 */
export function toSafeTriageError(err: unknown): Error {
  if (err instanceof Anthropic.AuthenticationError) {
    return new Error(
      "Anthropic API authentication failed (401) during secret triage. Check that the `anthropic-api-key` input is valid.",
    );
  }
  if (err instanceof Anthropic.PermissionDeniedError) {
    return new Error("Anthropic API permission denied (403) during secret triage.");
  }
  if (err instanceof Anthropic.NotFoundError) {
    return new Error("Anthropic API returned 404 during secret triage. Check the `model` input.");
  }
  if (err instanceof Anthropic.RateLimitError) {
    return new Error("Anthropic API rate limit exceeded (429) during secret triage.");
  }
  if (err instanceof Anthropic.APIConnectionError) {
    return new Error("Could not connect to the Anthropic API during secret triage (transient network issue).");
  }
  if (err instanceof Anthropic.APIError) {
    const status = typeof err.status === "number" ? err.status : "unknown status";
    return new Error(`Anthropic API error (${status}) during secret triage.`);
  }
  return new Error("Unexpected error while triaging ambiguous secret findings.");
}
