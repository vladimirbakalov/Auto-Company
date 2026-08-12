import * as core from "@actions/core";
import * as github from "@actions/github";
import { buildDiffText, type PullRequestFile } from "./diff";
import { summarizePr } from "./summarize";
import { upsertComment, type CommentsClient } from "./comment";

const DEFAULT_MODEL = "claude-opus-4-8";
const DEFAULT_MAX_DIFF_CHARS = 60000;

const MISSING_KEY_COMMENT = [
  "### 🔑 PR summary skipped — no Anthropic API key configured",
  "",
  "This repo has the **BYOK AI PR Summary** action installed, but the `anthropic-api-key` " +
    "input isn't set (or resolved to an empty string).",
  "",
  "To enable it: add your own Anthropic API key as a repo secret (e.g. `ANTHROPIC_API_KEY`) " +
    "and pass it to the action's `anthropic-api-key` input. See the action's README for the " +
    "full workflow snippet.",
  "",
  "Nothing was sent anywhere — this action never runs without your key.",
].join("\n");

export async function run(): Promise<void> {
  try {
    const context = github.context;

    if (context.eventName !== "pull_request" && context.eventName !== "pull_request_target") {
      core.info(`Event "${context.eventName}" is not a pull_request event — nothing to do.`);
      return;
    }

    const pr = context.payload.pull_request;
    if (!pr) {
      core.info("No pull_request payload on this event — nothing to do.");
      return;
    }

    const apiKey = core.getInput("anthropic-api-key");
    const token = core.getInput("github-token", { required: true });
    const model = core.getInput("model") || DEFAULT_MODEL;
    const maxDiffCharsInput = core.getInput("max-diff-chars");
    const maxDiffChars = maxDiffCharsInput ? parseInt(maxDiffCharsInput, 10) : DEFAULT_MAX_DIFF_CHARS;

    const octokit = github.getOctokit(token);
    const owner = context.repo.owner;
    const repo = context.repo.repo;
    const issueNumber = pr.number as number;

    const commentsClient: CommentsClient = {
      listComments: async (params) => {
        const data = await octokit.paginate(octokit.rest.issues.listComments, params);
        return { data };
      },
      updateComment: (params) => octokit.rest.issues.updateComment(params),
      createComment: (params) => octokit.rest.issues.createComment(params),
    };

    if (!apiKey || apiKey.trim() === "") {
      core.warning(
        "ANTHROPIC_API_KEY / `anthropic-api-key` input is not set — skipping PR summary generation.",
      );
      try {
        await upsertComment(commentsClient, { owner, repo, issueNumber, body: MISSING_KEY_COMMENT });
      } catch (commentErr) {
        // Missing key is not a hard failure; a failed courtesy comment shouldn't be either.
        core.info(`Could not post the "missing API key" comment: ${(commentErr as Error).message}`);
      }
      return;
    }

    const files = (await octokit.paginate(octokit.rest.pulls.listFiles, {
      owner,
      repo,
      pull_number: issueNumber,
      per_page: 100,
    })) as PullRequestFile[];

    if (files.length === 0) {
      core.info("PR has no changed files — nothing to summarize.");
      return;
    }

    const { text: diffText, truncated } = buildDiffText(files, maxDiffChars);

    let summary: string;
    try {
      summary = await summarizePr({
        apiKey,
        model,
        prTitle: pr.title ?? "",
        prBody: pr.body ?? "",
        diffText,
        diffTruncated: truncated,
      });
    } catch (err) {
      core.setFailed((err as Error).message);
      return;
    }

    const commentId = await upsertComment(commentsClient, {
      owner,
      repo,
      issueNumber,
      body: summary,
    });

    core.setOutput("summary", summary);
    core.setOutput("comment-id", String(commentId));
  } catch (err) {
    core.setFailed(err instanceof Error ? err.message : "Unexpected error running pr-summary-action.");
  }
}
