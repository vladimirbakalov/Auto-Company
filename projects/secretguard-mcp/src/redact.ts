/**
 * Redaction helpers. Every place a finding's raw secret value could reach a
 * PR comment, a log line, or an AI triage request goes through these first.
 */

/**
 * Masks a secret value, keeping a few chars on each end for identification.
 *
 * The visible window is capped at 4 chars per side AND at 20% of the total
 * length per side (whichever is smaller). The 20% cap matters most for
 * short values: the generic-entropy rule's floor is 12 chars
 * (MIN_GENERIC_SECRET_LENGTH in rules.ts), and a naive fixed "4 visible each
 * end" scheme reveals the majority of a 9-16 char secret once the two
 * visible windows start to overlap (e.g. a 10-char secret would show 8 of
 * its 10 characters — barely redacted at all). Scaling the visible window
 * down for short secrets keeps the leading/trailing hint useful for a human
 * skimming the PR comment without defeating the point of redaction.
 */
export function redactSecret(secret: string): string {
  const len = secret.length;
  if (len <= 8) return "*".repeat(Math.max(len, 4));

  const visible = Math.min(4, Math.floor(len * 0.2));
  if (visible <= 0) return "*".repeat(len);

  const maskedLength = len - visible * 2;
  return `${secret.slice(0, visible)}${"*".repeat(maskedLength)}${secret.slice(-visible)}`;
}

/** Replaces every occurrence of `secret` inside `content` with its redacted form. */
export function redactLine(content: string, secret: string): string {
  if (!secret) return content;
  return content.split(secret).join(redactSecret(secret));
}
