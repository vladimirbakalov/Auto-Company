import * as core from "@actions/core";
import * as github from "@actions/github";
import { extractAddedLines, type PullRequestFile } from "./diff";
import { scan, type Finding } from "./scan";
import { buildAllowlist, isAllowlisted } from "./allowlist";
import { triageCandidates, type TriageCandidate } from "./triage";
import { formatComment } from "./format";
import { upsertComment, type CommentsClient } from "./comment";
import { fetchTextFile, type RepoContentClient } from "./repo-content";

const DEFAULT_MODEL = "claude-opus-4-8";
const DEFAULT_ALLOWLIST_PATH = ".secretscanignore";
const DEFAULT_FAIL_ON = "high";

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

    const token = core.getInput("github-token", { required: true });
    const apiKey = core.getInput("anthropic-api-key");
    const model = core.getInput("model") || DEFAULT_MODEL;
    const allowlistInput = core.getInput("allowlist");
    const allowlistPath = core.getInput("allowlist-path") || DEFAULT_ALLOWLIST_PATH;
    const failOnInput = core.getInput("fail-on") || DEFAULT_FAIL_ON;
    const failOn = failOnInput === "any" ? "any" : "high";

    const octokit = github.getOctokit(token);
    const owner = context.repo.owner;
    const repo = context.repo.repo;
    const issueNumber = pr.number as number;
    // The allowlist file is read from the PR's BASE ref, not its head. If it
    // were read from the head, a PR could introduce a real secret and an
    // `.secretscanignore` entry that matches it in the same commit,
    // self-suppressing detection of its own leak before a human ever reviews
    // the diff. Reading from base means an allowlist entry only takes effect
    // once it's already merged.
    const baseSha = (pr.base as { sha?: string } | undefined)?.sha;

    const commentsClient: CommentsClient = {
      listComments: async (params) => {
        const data = await octokit.paginate(octokit.rest.issues.listComments, params);
        return { data };
      },
      updateComment: (params) => octokit.rest.issues.updateComment(params),
      createComment: (params) => octokit.rest.issues.createComment(params),
    };

    const contentClient: RepoContentClient = {
      getContent: (params) => octokit.rest.repos.getContent(params) as unknown as Promise<{ data: unknown }>,
    };

    const files = (await octokit.paginate(octokit.rest.pulls.listFiles, {
      owner,
      repo,
      pull_number: issueNumber,
      per_page: 100,
    })) as PullRequestFile[];

    if (files.length === 0) {
      core.info("PR has no changed files — nothing to scan.");
      return;
    }

    const addedLines = extractAddedLines(files);
    const allFindings = scan(addedLines);

    let allowlistFileContent: string | undefined;
    if (!baseSha) {
      core.warning(
        `Could not determine the PR's base commit — skipping "${allowlistPath}" (refusing to fall back to the PR head, which the PR author controls).`,
      );
    } else {
      try {
        allowlistFileContent = await fetchTextFile(contentClient, {
          owner,
          repo,
          path: allowlistPath,
          ref: baseSha,
        });
      } catch (err) {
        core.warning(
          `Could not read allowlist file "${allowlistPath}" — proceeding without it: ${(err as Error).message}`,
        );
      }
    }

    const allowlistEntries = buildAllowlist(allowlistInput, allowlistFileContent);
    const activeFindings = allFindings.filter((f) => !isAllowlisted(f, allowlistEntries));

    const high = activeFindings.filter((f) => f.confidence === "high");
    let generic = activeFindings.filter((f) => f.confidence === "generic");

    let triageApplied = false;
    if (apiKey && apiKey.trim() !== "" && generic.length > 0) {
      const candidates: TriageCandidate[] = generic.map((finding, id) => ({ id, finding }));
      try {
        const verdicts = await triageCandidates({ apiKey, model, candidates });
        generic = generic.filter((_, id) => verdicts.get(id) ?? true);
        triageApplied = true;
      } catch (err) {
        // Triage is a noise-reduction enhancement, not a requirement — a
        // failure here must not silently drop findings nor fail the whole
        // check. Log it and fall back to reporting every generic candidate.
        core.warning(`Ambiguous-match AI triage failed, reporting all generic matches unfiltered: ${(err as Error).message}`);
      }
    }

    const finalFindings: Finding[] = [...high, ...generic];

    const body = formatComment(finalFindings, { triageApplied });
    const commentId = await upsertComment(commentsClient, { owner, repo, issueNumber, body });

    core.setOutput("findings-count", String(finalFindings.length));
    core.setOutput("high-confidence-count", String(high.length));
    core.setOutput("comment-id", String(commentId));

    const shouldFail = failOn === "any" ? finalFindings.length > 0 : high.length > 0;
    if (shouldFail) {
      core.setFailed(
        `secret-scan-action found ${high.length} high-confidence secret(s)` +
          (failOn === "any" ? ` and ${generic.length} unresolved generic match(es)` : "") +
          " in this PR's changed lines — see the PR comment for details.",
      );
    }
  } catch (err) {
    core.setFailed(err instanceof Error ? err.message : "Unexpected error running secret-scan-action.");
  }
}
