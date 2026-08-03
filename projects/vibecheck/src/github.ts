// vibecheck — GitHub fetch layer
//
// IMPORTANT rate-limit note (read before touching this file):
// The GitHub REST API allows 60 requests/hour per source IP for *unauthenticated*
// requests (https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).
// Since Cloudflare Workers share egress IPs across a datacenter/region, this limit
// can be hit faster than a single client would expect — it's shared across all
// vibecheck traffic routed through the same PoP, not just one user's requests.
// This is an accepted MVP limitation (see docs/research + CEO mandate: ship first,
// validate demand, harden later). Mitigations already applied:
//   1. Only 2 api.github.com calls per scan (repo meta + recursive tree) — the
//      expensive part (fetching individual file contents) uses raw.githubusercontent.com,
//      which is served off GitHub's CDN and is NOT subject to the same 60/hr API quota.
//   2. File content fetches are capped (MAX_FILES_TO_FETCH) to bound total request volume.
// If GITHUB_TOKEN is set (wrangler secret), we send it as a Bearer token, which raises
// the api.github.com quota to 5,000 req/hr — recommended before any real launch traffic.

import type { Env, RepoFile, RepoRef } from './types';
import { ScanError } from './types';

const GITHUB_API = 'https://api.github.com';
const RAW_HOST = 'https://raw.githubusercontent.com';

// Hard cap on how many file contents we fetch per scan, to stay well inside
// rate limits and keep scan latency reasonable for a synchronous request.
export const MAX_FILES_TO_FETCH = 40;

// Cap on tree size we'll even attempt to reason about (very large monorepos
// are out of scope for the MVP — see README "Out of scope").
const MAX_TREE_ENTRIES = 5000;

function userAgent(): string {
  return 'vibecheck-scanner (+https://github.com/vladimirbakalov/Auto-Company)';
}

function githubHeaders(env: Env, accept: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: accept,
    'User-Agent': userAgent(),
  };
  if (env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  }
  return headers;
}

// Accepts a full GitHub URL (https://github.com/owner/repo, with or without
// .git suffix, trailing slash, or /tree/branch path) or a bare "owner/repo".
export function parseRepoUrl(input: string): RepoRef {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new ScanError('Repo URL is required', 400);
  }

  let candidate = trimmed;
  // Strip protocol/host if a full URL was pasted.
  const urlMatch = candidate.match(
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+)\/([^/\s#?]+)/i
  );
  if (urlMatch) {
    candidate = `${urlMatch[1]}/${urlMatch[2]}`;
  }

  candidate = candidate.replace(/\.git$/i, '').replace(/\/+$/, '');
  const parts = candidate.split('/').filter(Boolean);
  if (parts.length !== 2) {
    throw new ScanError(
      'Could not parse a GitHub owner/repo from that input. Paste a URL like https://github.com/owner/repo',
      400
    );
  }
  const [owner, repo] = parts;
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) {
    throw new ScanError('Owner or repo name contains invalid characters', 400);
  }
  return { owner, repo };
}

async function githubFetch(url: string, env: Env, accept: string): Promise<Response> {
  const res = await fetch(url, { headers: githubHeaders(env, accept) });

  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get('x-ratelimit-remaining');
    if (remaining === '0') {
      throw new ScanError(
        'GitHub API rate limit reached for this deployment (60 requests/hour, unauthenticated, shared across all vibecheck traffic on this IP). Please try again in a few minutes.',
        429
      );
    }
    throw new ScanError('GitHub API request was rejected (403). The repo may be private or GitHub is throttling.', 403);
  }
  return res;
}

export async function fetchDefaultBranch(ref: RepoRef, env: Env): Promise<string> {
  const res = await githubFetch(
    `${GITHUB_API}/repos/${ref.owner}/${ref.repo}`,
    env,
    'application/vnd.github+json'
  );
  if (res.status === 404) {
    throw new ScanError(
      `Repo ${ref.owner}/${ref.repo} not found. It must be public and the URL must be correct.`,
      404
    );
  }
  if (!res.ok) {
    throw new ScanError(`GitHub API error fetching repo metadata (${res.status})`, 502);
  }
  const data = (await res.json()) as { default_branch?: string; private?: boolean };
  if (data.private) {
    throw new ScanError('vibecheck only scans public repos in this MVP.', 400);
  }
  return data.default_branch ?? 'main';
}

// Returns the full recursive file-path list for the default branch.
export async function fetchTree(ref: RepoRef, branch: string, env: Env): Promise<string[]> {
  const res = await githubFetch(
    `${GITHUB_API}/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    env,
    'application/vnd.github+json'
  );
  if (!res.ok) {
    throw new ScanError(`GitHub API error fetching file tree (${res.status})`, 502);
  }
  const data = (await res.json()) as {
    tree?: { path: string; type: string }[];
    truncated?: boolean;
  };
  const paths = (data.tree ?? [])
    .filter(entry => entry.type === 'blob')
    .map(entry => entry.path)
    .slice(0, MAX_TREE_ENTRIES);
  return paths;
}

// Fetches raw file content via raw.githubusercontent.com (not subject to the
// api.github.com rate limit — see file header comment). Returns null on any
// failure (missing file, binary, too large) rather than throwing, since a
// single missing file shouldn't fail the whole scan.
export async function fetchFileContent(
  ref: RepoRef,
  branch: string,
  path: string
): Promise<string | null> {
  try {
    const url = `${RAW_HOST}/${ref.owner}/${ref.repo}/${encodeURIComponent(branch).replace(/%2F/g, '/')}/${path
      .split('/')
      .map(encodeURIComponent)
      .join('/')}`;
    const res = await fetch(url, { headers: { 'User-Agent': userAgent() } });
    if (!res.ok) return null;
    const contentLength = res.headers.get('content-length');
    if (contentLength && Number(contentLength) > 300_000) return null; // skip huge files
    return await res.text();
  } catch {
    return null;
  }
}

// Fetches content for a bounded list of candidate paths, in parallel batches.
export async function fetchFiles(
  ref: RepoRef,
  branch: string,
  paths: string[]
): Promise<RepoFile[]> {
  const bounded = paths.slice(0, MAX_FILES_TO_FETCH);
  const results = await Promise.all(
    bounded.map(async path => {
      const content = await fetchFileContent(ref, branch, path);
      return content !== null ? { path, content } : null;
    })
  );
  return results.filter((f): f is RepoFile => f !== null);
}
