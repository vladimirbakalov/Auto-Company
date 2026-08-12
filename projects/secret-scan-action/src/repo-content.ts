/**
 * Reads a single text file out of the repo via the GitHub Contents API. This
 * is how `.secretscanignore` gets read without requiring an
 * `actions/checkout` step — same "GitHub-native only, no extra setup"
 * constraint the rest of this action follows.
 *
 * Callers must pass the PR's BASE commit as `ref`, not its head — see the
 * comment in run.ts for why (a head-pinned read would let a PR suppress its
 * own newly-introduced secret via an allowlist entry added in that same PR).
 */

export interface RepoContentClient {
  getContent(params: { owner: string; repo: string; path: string; ref: string }): Promise<{ data: unknown }>;
}

/** Returns the file's decoded text content, or undefined if it doesn't exist / isn't a regular file. */
export async function fetchTextFile(
  client: RepoContentClient,
  params: { owner: string; repo: string; path: string; ref: string },
): Promise<string | undefined> {
  let data: unknown;
  try {
    const response = await client.getContent(params);
    data = response.data;
  } catch (err) {
    const status = (err as { status?: unknown }).status;
    if (status === 404) return undefined; // no such file — perfectly normal, not an error
    throw err;
  }

  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    !("content" in data) ||
    typeof (data as { content?: unknown }).content !== "string"
  ) {
    return undefined; // directory listing, submodule, symlink, etc. — nothing usable
  }

  return Buffer.from((data as { content: string }).content, "base64").toString("utf8");
}
