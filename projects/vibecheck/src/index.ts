// vibecheck — Main Cloudflare Worker
// Routes: GET / (landing page + scan UI), POST /api/scan (scan a public GitHub repo), GET /health
//
// Stateless MVP: no D1/R2, no auth, no persistence. Every request re-fetches from
// GitHub. See github.ts for the unauthenticated rate-limit caveat (60 req/hr,
// shared per-IP) — this is a known, accepted limitation for this validation-stage
// build, not an oversight.

import { Hono } from 'hono';
import { fetchDefaultBranch, fetchFiles, fetchTree, parseRepoUrl } from './github';
import { runAllChecks, selectCandidateFiles } from './checks';
import { computeScore, scoreToGrade } from './scoring';
import { landingPage } from './pages';
import type { Env, ScanResult } from './types';
import { ScanError } from './types';

const app = new Hono<{ Bindings: Env }>();

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// ── Landing page + scan UI ──────────────────────────────────────────────────
app.get('/', () => htmlResponse(landingPage()));

// ── Scan API ─────────────────────────────────────────────────────────────────
app.post('/api/scan', async c => {
  let body: { repoUrl?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Expected JSON body with a repoUrl field' }, 400);
  }

  try {
    const ref = parseRepoUrl(body.repoUrl ?? '');
    const defaultBranch = await fetchDefaultBranch(ref, c.env);
    const tree = await fetchTree(ref, defaultBranch, c.env);

    const candidates = selectCandidateFiles(tree);
    const files = await fetchFiles(ref, defaultBranch, candidates);

    const findings = runAllChecks(tree, files);
    const score = computeScore(findings);
    const grade = scoreToGrade(score);

    const notes: string[] = [
      'GitHub public API is rate-limited to 60 requests/hour per IP when unauthenticated; scans may occasionally fail during high traffic — retry after a minute.',
    ];
    if (tree.length > files.length + candidates.length) {
      notes.push('Repo tree was larger than this scan\'s sampling budget; only a subset of files were checked.');
    }

    const result: ScanResult = {
      owner: ref.owner,
      repo: ref.repo,
      defaultBranch,
      score,
      grade,
      findings,
      filesScanned: files.length,
      filesInTree: tree.length,
      scannedAt: new Date().toISOString(),
      notes,
    };

    return c.json(result);
  } catch (err) {
    if (err instanceof ScanError) {
      return c.json({ error: err.message }, err.status as 400 | 404 | 429 | 502);
    }
    console.error('Unhandled scan error:', err);
    return c.json({ error: 'Unexpected error while scanning. Please try again.' }, 500);
  }
});

// ── Health / ops ──────────────────────────────────────────────────────────────
app.get('/health', c => c.json({ ok: true, ts: new Date().toISOString() }));

// 404 fallback
app.notFound(c => c.json({ error: 'Not found' }, 404));
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({ error: 'Internal server error' }, 500);
});

export default app;
