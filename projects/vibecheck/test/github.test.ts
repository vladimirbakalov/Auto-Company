import { describe, it, expect, vi, afterEach } from 'vitest';
import { parseRepoUrl, fetchDefaultBranch, fetchTree, fetchFileContent, fetchFiles } from '../src/github';
import { ScanError } from '../src/types';
import type { Env, RepoRef } from '../src/types';

describe('parseRepoUrl', () => {
  it('parses a full https URL', () => {
    expect(parseRepoUrl('https://github.com/vercel/next.js')).toEqual({
      owner: 'vercel',
      repo: 'next.js',
    });
  });

  it('parses a bare owner/repo string with no host', () => {
    expect(parseRepoUrl('vercel/next.js')).toEqual({ owner: 'vercel', repo: 'next.js' });
  });

  it('strips a trailing .git suffix', () => {
    expect(parseRepoUrl('https://github.com/facebook/react.git')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('strips trailing slashes', () => {
    expect(parseRepoUrl('https://github.com/facebook/react///')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('accepts a www. prefix and http scheme', () => {
    expect(parseRepoUrl('http://www.github.com/facebook/react')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('ignores a trailing /tree/<branch> path segment', () => {
    expect(parseRepoUrl('https://github.com/facebook/react/tree/main')).toEqual({
      owner: 'facebook',
      repo: 'react',
    });
  });

  it('allows dots, dashes, and underscores in owner/repo names', () => {
    expect(parseRepoUrl('my-org_1/my.repo_name')).toEqual({
      owner: 'my-org_1',
      repo: 'my.repo_name',
    });
  });

  it('throws on empty input', () => {
    expect(() => parseRepoUrl('')).toThrow(ScanError);
    expect(() => parseRepoUrl('   ')).toThrow('Repo URL is required');
  });

  it('throws when only an owner is given as a github.com URL (no repo segment)', () => {
    expect(() => parseRepoUrl('https://github.com/justowner')).toThrow(ScanError);
  });

  it('throws on input with too many path segments and no github.com host', () => {
    expect(() => parseRepoUrl('owner/repo/extra')).toThrow(
      'Could not parse a GitHub owner/repo from that input'
    );
  });

  it('throws on invalid characters in owner or repo', () => {
    expect(() => parseRepoUrl('owner name/repo!')).toThrow(
      'Owner or repo name contains invalid characters'
    );
  });

  it('throws on a single-segment bare string', () => {
    expect(() => parseRepoUrl('justarepo')).toThrow(ScanError);
  });
});

// fetchDefaultBranch/fetchTree/fetchFileContent/fetchFiles all funnel through
// githubFetch (not exported), whose error-branch handling — timeout, generic
// network failure, 403/429 rate-limit detection, and the public callers'
// own 404/private/truncation logic — had no direct test coverage: index.test.ts
// only ever exercises the happy path via its mockGithubAndProbe helper.
const env: Env = { ENVIRONMENT: 'test' };
const ref: RepoRef = { owner: 'acme', repo: 'widgets' };

function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'content-type': 'application/json', ...init.headers },
  });
}

describe('fetchDefaultBranch', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns the repo default_branch on success', async () => {
    global.fetch = vi.fn(async () => jsonResponse({ default_branch: 'develop', private: false })) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).resolves.toBe('develop');
  });

  it('falls back to "main" when default_branch is missing from the response', async () => {
    global.fetch = vi.fn(async () => jsonResponse({ private: false })) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).resolves.toBe('main');
  });

  it('throws a 404 ScanError when the repo does not exist', async () => {
    global.fetch = vi.fn(async () => jsonResponse({}, { status: 404 })) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({
      status: 404,
      message: expect.stringContaining('not found'),
    });
  });

  it('throws a 400 ScanError when the repo is private', async () => {
    global.fetch = vi.fn(async () => jsonResponse({ default_branch: 'main', private: true })) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({
      status: 400,
      message: expect.stringContaining('public repos'),
    });
  });

  it('throws a 502 ScanError on an unexpected non-ok status', async () => {
    global.fetch = vi.fn(async () => jsonResponse({}, { status: 500 })) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({ status: 502 });
  });

  it('maps a fetch AbortError to a 502 "timed out" ScanError', async () => {
    global.fetch = vi.fn(async () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      throw err;
    }) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({
      status: 502,
      message: expect.stringContaining('timed out'),
    });
  });

  it('maps a generic network failure to a 502 "could not reach" ScanError', async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({
      status: 502,
      message: expect.stringContaining('Could not reach GitHub API'),
    });
  });

  it('maps a 403 with x-ratelimit-remaining: 0 to a 429 rate-limit ScanError', async () => {
    global.fetch = vi.fn(async () =>
      jsonResponse({}, { status: 403, headers: { 'x-ratelimit-remaining': '0' } })
    ) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({
      status: 429,
      message: expect.stringContaining('rate limit reached'),
    });
  });

  it('maps a plain 403 (not a rate-limit) to a 403 "rejected" ScanError', async () => {
    global.fetch = vi.fn(async () => jsonResponse({}, { status: 403 })) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({
      status: 403,
      message: expect.stringContaining('rejected'),
    });
  });

  it('maps a 429 status the same way as a rate-limited 403', async () => {
    global.fetch = vi.fn(async () =>
      jsonResponse({}, { status: 429, headers: { 'x-ratelimit-remaining': '0' } })
    ) as unknown as typeof fetch;
    await expect(fetchDefaultBranch(ref, env)).rejects.toMatchObject({ status: 429 });
  });
});

describe('fetchTree', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns only blob paths, filtering out tree (directory) entries', async () => {
    global.fetch = vi.fn(async () =>
      jsonResponse({
        tree: [
          { path: 'src', type: 'tree' },
          { path: 'src/index.ts', type: 'blob' },
          { path: 'README.md', type: 'blob' },
        ],
        truncated: false,
      })
    ) as unknown as typeof fetch;
    await expect(fetchTree(ref, 'main', env)).resolves.toEqual(['src/index.ts', 'README.md']);
  });

  it('caps the number of paths returned at MAX_TREE_ENTRIES (5000)', async () => {
    const entries = Array.from({ length: 5010 }, (_, i) => ({ path: `file${i}.ts`, type: 'blob' }));
    global.fetch = vi.fn(async () => jsonResponse({ tree: entries, truncated: true })) as unknown as typeof fetch;
    const paths = await fetchTree(ref, 'main', env);
    expect(paths).toHaveLength(5000);
  });

  it('throws a 502 ScanError on a non-ok status', async () => {
    global.fetch = vi.fn(async () => jsonResponse({}, { status: 500 })) as unknown as typeof fetch;
    await expect(fetchTree(ref, 'main', env)).rejects.toMatchObject({ status: 502 });
  });
});

describe('fetchFileContent', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns the raw file content on success', async () => {
    global.fetch = vi.fn(async () => new Response('export const x = 1;', { status: 200 })) as unknown as typeof fetch;
    await expect(fetchFileContent(ref, 'main', 'src/index.ts')).resolves.toBe('export const x = 1;');
  });

  it('returns null (not a throw) when the file does not exist', async () => {
    global.fetch = vi.fn(async () => new Response('Not Found', { status: 404 })) as unknown as typeof fetch;
    await expect(fetchFileContent(ref, 'main', 'missing.ts')).resolves.toBeNull();
  });

  it('skips (returns null) files whose Content-Length exceeds the byte cap, without reading the body', async () => {
    const bodyReader = vi.fn();
    global.fetch = vi.fn(async () => {
      const res = new Response('x'.repeat(10), {
        status: 200,
        headers: { 'content-length': String(400_000) },
      });
      // Sanity: fetchFileContent must short-circuit on the header check
      // rather than ever touching the body.
      Object.defineProperty(res, 'body', { get: bodyReader });
      return res;
    }) as unknown as typeof fetch;
    await expect(fetchFileContent(ref, 'main', 'huge.bin')).resolves.toBeNull();
    expect(bodyReader).not.toHaveBeenCalled();
  });

  it('returns null (not a throw) on a network failure', async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    await expect(fetchFileContent(ref, 'main', 'src/index.ts')).resolves.toBeNull();
  });
});

describe('fetchFiles', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('bounds the fetch to MAX_FILES_TO_FETCH (40) paths, ignoring the rest', async () => {
    const fetchMock = vi.fn(async () => new Response('content', { status: 200 }));
    global.fetch = fetchMock as unknown as typeof fetch;
    const paths = Array.from({ length: 50 }, (_, i) => `file${i}.ts`);
    const files = await fetchFiles(ref, 'main', paths);
    expect(files).toHaveLength(40);
    expect(fetchMock).toHaveBeenCalledTimes(40);
  });

  it('filters out paths whose content fetch failed (404/network error)', async () => {
    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('missing.ts')) return new Response('Not Found', { status: 404 });
      return new Response('ok', { status: 200 });
    }) as unknown as typeof fetch;
    const files = await fetchFiles(ref, 'main', ['present.ts', 'missing.ts']);
    expect(files).toEqual([{ path: 'present.ts', content: 'ok' }]);
  });
});
