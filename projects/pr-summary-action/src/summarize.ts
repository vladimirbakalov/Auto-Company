import Anthropic from "@anthropic-ai/sdk";

export interface SummarizeParams {
  apiKey: string;
  model: string;
  prTitle: string;
  prBody: string;
  diffText: string;
  diffTruncated: boolean;
}

const SYSTEM_PROMPT = `You are a senior engineer writing a concise pull request summary for reviewers.

Given a PR title, description, and diff, write a short summary in GitHub-flavored markdown with three sections:

## What changed
2-5 bullet points of the concrete changes.

## Why
1-2 sentences on the apparent intent, inferred from the diff and description.

## Risk areas
Bullet points calling out anything a reviewer should look closely at (e.g. error handling, security-sensitive code, migrations, breaking changes, missing tests). If nothing stands out, say so briefly — do not invent risk.

Be specific and reference file names where useful. Do not restate the entire diff. Do not include a preamble or sign-off — start directly with "## What changed".`;

/**
 * Calls the Anthropic API to generate a PR summary. Throws a sanitized
 * Error on failure — never the raw SDK error, so a misbehaving SDK/proxy
 * that happens to echo request details back can't leak the caller's API
 * key into Action logs.
 */
export async function summarizePr(params: SummarizeParams): Promise<string> {
  const client = new Anthropic({ apiKey: params.apiKey });

  let response: Anthropic.Message;
  try {
    response = await client.messages.create({
      model: params.model,
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: buildUserMessage(params) }],
    });
  } catch (err) {
    throw toSafeSummarizeError(err);
  }

  const textBlock = response.content.find(
    (block): block is Anthropic.TextBlock => block.type === "text",
  );

  if (!textBlock || !textBlock.text.trim()) {
    throw new Error("Anthropic API returned an empty response.");
  }

  return textBlock.text.trim();
}

function buildUserMessage(params: SummarizeParams): string {
  const truncationNote = params.diffTruncated
    ? "\n\n(Note: this diff was too large to include in full — it has been truncated. Base the summary on what's shown and mention that some changes were omitted if relevant.)"
    : "";

  return [
    `PR title: ${params.prTitle || "(no title)"}`,
    `PR description: ${params.prBody || "(no description)"}`,
    `Diff:\n${params.diffText}`,
    truncationNote,
  ]
    .filter(Boolean)
    .join("\n\n");
}

/**
 * Converts an Anthropic SDK error into a generic, secret-free message.
 * Deliberately does NOT forward `err.message` verbatim — it's built fresh
 * per error class so nothing from the underlying request/response (which
 * could in principle echo back parts of the request) ever reaches the
 * caller or the Action's logs.
 */
export function toSafeSummarizeError(err: unknown): Error {
  if (err instanceof Anthropic.AuthenticationError) {
    return new Error(
      "Anthropic API authentication failed (401). Check that the `anthropic-api-key` input is set to a valid, active Anthropic API key.",
    );
  }
  if (err instanceof Anthropic.PermissionDeniedError) {
    return new Error(
      "Anthropic API permission denied (403). The API key may lack access to the requested model.",
    );
  }
  if (err instanceof Anthropic.NotFoundError) {
    return new Error(
      "Anthropic API returned 404. Check that the `model` input is a valid, current model ID.",
    );
  }
  if (err instanceof Anthropic.RateLimitError) {
    return new Error("Anthropic API rate limit exceeded (429). Try again later.");
  }
  if (err instanceof Anthropic.APIConnectionError) {
    return new Error("Could not connect to the Anthropic API. This is likely a transient network issue.");
  }
  if (err instanceof Anthropic.APIError) {
    const status = typeof err.status === "number" ? err.status : "unknown status";
    return new Error(`Anthropic API error (${status}). See https://status.anthropic.com for service status.`);
  }
  return new Error("Unexpected error while generating the PR summary.");
}
