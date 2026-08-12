/**
 * Finds and updates this action's own PR comment across runs, instead of
 * spamming a new comment on every push. We identify "our" comment with a
 * hidden HTML marker rather than by author — the marker survives even if
 * the action is ever run under a different token/bot identity.
 */

export const MARKER = "<!-- secret-scan-action:comment -->";

// Minimal surface of @octokit/rest's issues client this module needs.
// Kept narrow and structural so tests can pass a plain fake object instead
// of standing up a real Octokit instance.
export interface CommentsClient {
  listComments(params: {
    owner: string;
    repo: string;
    issue_number: number;
    per_page?: number;
  }): Promise<{ data: Array<{ id: number; body?: string | null }> }>;
  updateComment(params: { owner: string; repo: string; comment_id: number; body: string }): Promise<unknown>;
  createComment(params: { owner: string; repo: string; issue_number: number; body: string }): Promise<{
    data: { id: number };
  }>;
}

export interface UpsertCommentParams {
  owner: string;
  repo: string;
  issueNumber: number;
  body: string;
}

/**
 * Creates the marked comment if none exists yet, otherwise updates the
 * existing one in place. Returns the comment ID either way.
 */
export async function upsertComment(client: CommentsClient, params: UpsertCommentParams): Promise<number> {
  const { owner, repo, issueNumber, body } = params;
  const markedBody = body.includes(MARKER) ? body : `${MARKER}\n${body}`;

  const existing = await findExistingComment(client, owner, repo, issueNumber);

  if (existing) {
    await client.updateComment({ owner, repo, comment_id: existing.id, body: markedBody });
    return existing.id;
  }

  const created = await client.createComment({ owner, repo, issue_number: issueNumber, body: markedBody });
  return created.data.id;
}

export async function findExistingComment(
  client: CommentsClient,
  owner: string,
  repo: string,
  issueNumber: number,
): Promise<{ id: number } | undefined> {
  const { data } = await client.listComments({ owner, repo, issue_number: issueNumber, per_page: 100 });
  return data.find((comment) => (comment.body ?? "").includes(MARKER));
}
