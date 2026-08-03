# vibecheck

Free security-risk scanner for vibe-coded apps (Lovable / Bolt / Replit / Cursor / v0). Paste a public GitHub repo URL, get a 0-100 score and a list of findings. Hosted on Cloudflare Workers. No signup, no database, stateless.

Built as the MVP artifact for the "Vibe-Coded App Health Check" direction — see `docs/research/next-vertical-search-cycle4.md` (§2, §5) for the product rationale.

## Quick start

```bash
npm install
npm run dev        # wrangler dev, http://localhost:8787
npm run typecheck  # tsc --noEmit
npm run deploy     # wrangler deploy (requires Cloudflare auth — not configured in this environment yet)
```

## API

```
POST /api/scan
Content-Type: application/json

{ "repoUrl": "https://github.com/owner/repo" }
```

Returns:

```json
{
  "owner": "owner",
  "repo": "repo",
  "defaultBranch": "main",
  "score": 82,
  "grade": "B",
  "findings": [
    {
      "id": "secret-1",
      "title": "Possible hardcoded Stripe live secret key",
      "severity": "critical",
      "confidence": "medium",
      "explanation": "...",
      "file": "src/config.ts",
      "line": 12
    }
  ],
  "filesScanned": 40,
  "filesInTree": 482,
  "scannedAt": "2026-08-03T01:11:56.250Z",
  "notes": ["..."]
}
```

`GET /` serves the scan UI (plain HTML/CSS/JS, no framework). `GET /health` is a liveness check.

## What it checks (all heuristic — see `src/checks.ts`)

1. Hardcoded secrets/API keys (AWS keys, Stripe live/test keys, Supabase `service_role` JWTs, generic `apiKey`/`secret`/`token`-named variables assigned literal strings).
2. `.env` committed to the repo and not excluded by `.gitignore`.
3. Supabase `createClient` usage with no visible migration/RLS evidence in the sampled files — explicitly labeled low confidence; this is a heuristic, not proof RLS is missing (it may be configured in the Supabase dashboard, outside the repo).
4. Permissive CORS (`Access-Control-Allow-Origin: *` or equivalent).
5. Route handlers with no nearby auth/session keyword — the weakest signal in the tool, labeled low confidence in both the API response and the UI.

Every finding carries `severity` (critical/high/medium/low) and `confidence` (high/medium/low). The score in `src/scoring.ts` weights both — a low-confidence finding costs less than a high-confidence one of the same severity.

## Known limitations (by design, for this MVP)

- **GitHub API rate limit**: unauthenticated requests to `api.github.com` are capped at 60/hour per source IP, and Cloudflare Workers share egress IPs across a datacenter — so this limit is shared across all vibecheck traffic routed through the same PoP, not just one user. Mitigated by using `raw.githubusercontent.com` (not subject to the same quota) for file content, and capping `api.github.com` calls to 2 per scan (repo metadata + one recursive tree call). Set `GITHUB_TOKEN` via `wrangler secret put GITHUB_TOKEN` before real launch traffic to raise the api.github.com quota to 5,000/hr.
- **Sampled, not exhaustive**: only up to `MAX_FILES_TO_FETCH` (40) files are fetched and scanned per repo, prioritized by filename/path relevance (`src/checks.ts: selectCandidateFiles`). Large monorepos will only get partial coverage.
- **Static heuristics only**: regex/pattern matching over file text, no AST parsing, no data-flow analysis, no live-app testing. Expect false positives and false negatives — that's what the `confidence` field communicates to the user.
- **Public repos only**: no OAuth, no private repo access, by design — keeps the cold start honest and avoids needing to build a trust/auth flow before validating demand.

## Explicitly out of scope for this MVP

- Cost-risk scanning (API/cloud bill spike detection) and uptime monitoring — part of the longer-term "bundle" positioning per the research doc, not built yet.
- Live app URL scanning (only GitHub repo URLs are accepted).
- Any persistence (scan history, accounts, saved reports) — no D1/R2 bindings, unlike `snapog`.
- MCP server integration for in-editor use (Cursor/Claude/Windsurf) — mentioned as a distribution channel in the research doc, not part of this build.
- Paid tier / billing.

## Deploy status

Code is deploy-ready (`npx tsc --noEmit` passes, `wrangler deploy --dry-run` succeeds) but **not deployed** — no Cloudflare credentials are configured in this environment. See `docs/devops/snapog-deploy-runbook.md` for the pending human unblock that applies here too.
