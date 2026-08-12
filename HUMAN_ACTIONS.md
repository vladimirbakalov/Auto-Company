# Human Actions Needed

Consolidated from 19+ autonomous cycles (2026-07-28 → 2026-08-12) of scattered
notes in `memories/consensus.md`. Every item below is a real blocker the
company cannot clear itself — no credentials, no browser, no way to accept a
ToS/agreement autonomously. Ordered by leverage-per-minute, not by discovery
order. Once you do one, delete its section (or just tell the agent — it'll
notice and update `memories/consensus.md`).

## Do these first — near-zero effort, unlocks real users

### 1. Post the outreach drafts (zero technical steps)
Drafts are written, reviewed, and verified accurate against the live repos —
one pair of Show HN / Show IH drafts per live product, all pointing at
the correct standalone repos (`pr-summary-action`'s draft had a stale
monorepo link, fixed Cycle #27), plus Reddit-specific drafts (Cycle #28,
distinct copy per-subreddit, not a reuse of the HN text — Reddit's
anti-spam/self-promo norms are stricter and different from HN/IH):
- `docs/marketing/pr-summary-action-outreach-cycle16.md`
- `docs/marketing/secret-scan-action-outreach-cycle27.md`
- `docs/marketing/secretguard-mcp-outreach-cycle27.md`
- `docs/marketing/reddit-outreach-cycle28.md` (6 subreddit-specific drafts
  across all 3 products, with per-subreddit fit/risk notes and posting
  hygiene guidance — read the top-of-file notes before posting, especially
  "don't crosspost the same title/body same-day")
- `docs/marketing/devto-secret-detection-cycle29.md` (technical deep-dive
  covering secret-scan-action + secretguard-mcp together — different from
  the forum posts above: evergreen/SEO content, not a one-shot pitch. Has
  its own front-matter + posting-hygiene notes at the top of the file.)
- `docs/marketing/devto-pr-summary-cycle30.md` (technical deep-dive
  covering pr-summary-action's diff-budgeting algorithm, baseURL-hijack
  prevention, error sanitization, and idempotent-comment pattern — same
  evergreen/SEO dev.to format as the Cycle 29 piece, for the third live
  product. Has its own front-matter + posting-hygiene notes, including a
  tag choice and posting-day spacing so it doesn't compete with the Cycle
  29 piece.)

Just copy-paste into Show HN, Show IH, and/or the relevant subreddits (one
post per product/channel, or pick the one you think is most interesting to
lead with). This is the single fastest path to a first real, non-company
user.

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
4. Fill in category + tagline/description — copy-paste text for both repos
   is pre-written in `docs/marketing/marketplace-listing-cycle31.md`
   (categories, tagline, longer description, pricing plan = Free). Both
   repos' `LICENSE` and `action.yml` branding are already in place, so
   that's the only free-text step left.

Repos: `github.com/vladimirbakalov/pr-summary-action`,
`github.com/vladimirbakalov/secret-scan-action`.

## Small effort, real unlock

### 4. Grant the `workflow` OAuth scope
```bash
gh auth refresh -h github.com -s workflow
```
Browser approval, ~30 seconds. Unblocks CI (`.github/workflows/*`) for the
monorepo and all three standalone repos — currently the agent can't commit or
push workflow files at all without this. The CI workflow itself is already
written and verified against both repos' live `package.json` — see
`docs/devops/action-repos-ci-workflow-cycle32.md` for the ready-to-paste
`.github/workflows/ci.yml` content (typecheck + test + build + dist-drift
check) for `pr-summary-action` and `secret-scan-action`. Once this scope is
granted, dropping that file in and pushing is the only remaining step —
no design work left to do.

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
