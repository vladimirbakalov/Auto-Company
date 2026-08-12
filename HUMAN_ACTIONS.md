# Human Actions Needed

Consolidated from 19+ autonomous cycles (2026-07-28 → 2026-08-12) of scattered
notes in `memories/consensus.md`. Every item below is a real blocker the
company cannot clear itself — no credentials, no browser, no way to accept a
ToS/agreement autonomously. Ordered by leverage-per-minute, not by discovery
order. Once you do one, delete its section (or just tell the agent — it'll
notice and update `memories/consensus.md`).

## Do these first — near-zero effort, unlocks real users

### 1. Post the two outreach drafts (zero technical steps)
Drafts are written, reviewed, and verified accurate against the live repos:
`docs/marketing/pr-summary-action-outreach-cycle16.md`. Just copy-paste into
Show HN and Show IH. This is the single fastest path to a first real,
non-company user.

### 2. Publish `secretguard-mcp` to the official MCP Registry
```bash
mcp-publisher login github   # one-time device-flow browser click
# then, from projects/secretguard-mcp/:
mcp-publisher publish
```
`server.json` is already prepared and points at the correct `.mcpb` release
asset. `mcp-publisher` is now installed (`brew install mcp-publisher`, done
Cycle #26) — `login` is the only step left, browser click only.

### 3. List `pr-summary-action` and `secret-scan-action` on GitHub Marketplace
No API for this — has to be the web UI, per repo:
1. Go to the repo's `v1` release page.
2. Edit the release → check **"Publish this Action to the GitHub
   Marketplace"**.
3. Accept the Marketplace Developer Agreement (one-time, covers all your
   Actions after the first).

Repos: `github.com/vladimirbakalov/pr-summary-action`,
`github.com/vladimirbakalov/secret-scan-action`.

## Small effort, real unlock

### 4. Grant the `workflow` OAuth scope
```bash
gh auth refresh -h github.com -s workflow
```
Browser approval, ~30 seconds. Unblocks CI (`.github/workflows/*`) for the
monorepo and all three standalone repos — currently the agent can't commit or
push workflow files at all without this.

## Bigger unlock — the actual revenue blocker

### 5. Cloudflare deploy (vibecheck + snapog)
Both products are scope-complete, tested, and deploy-ready. This has been the
top blocker for 19+ cycles. Full steps:
`docs/devops/snapog-deploy-runbook.md` (vibecheck's runbook is equivalent —
same account, separate D1/R2 resources).

```bash
wrangler login   # wrangler is now installed (npm install -g wrangler, done
                 # Cycle #26) — login is the only step left, browser click only
```

### 6. Resend (for vibecheck/snapog transactional email)
Sign up at resend.com, verify a sending domain, then:
```bash
wrangler secret put RESEND_API_KEY
```
Depends on #5 being done first (need `wrangler` + a deployed Worker to attach
the secret to).

## Optional, low priority

### 7. `npm adduser` / `npm login`
Would let the agent `npm publish secretguard-mcp` directly instead of relying
on `npx github:...`. Not required — the GitHub-based install already works
end-to-end (verified Cycle #24 with a real `npx -y github:...` handshake).

---
**Not on this list on purpose**: automated/unsolicited outreach PRs to
third-party repos (e.g. submitting to `awesome-*` list repos). That growth
tactic stays out of bounds without your explicit sign-off — see
`memories/consensus.md` open questions.
