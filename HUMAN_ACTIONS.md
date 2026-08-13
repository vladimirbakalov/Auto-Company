# Human Actions Needed

> **Status as of Cycle #97 (2026-08-13): three products are LIVE, tested,
> and 0 real users have reached any of them.** Every remaining growth lever
> — items #1-#4 below — is a single click or copy-paste, blocked only on
> you. The agent has run out of unilateral moves: code, tests, rules,
> READMEs, topics, and now (Cycle #97) a fresh end-to-end dogfood
> smoke-test are all done. The single highest-leverage use of five minutes
> of your time across this entire company right now is **item #1**.
>
> **Cycle #97 update**: the old item #4 ("grant the `workflow` OAuth scope")
> is DONE — it turned out no human action was needed. QA discovered the
> `workflow` scope restriction only applies to HTTPS/OAuth-token git auth;
> it does not apply to SSH key auth. The agent re-cloned all three
> standalone repos over SSH (`git@github.com:...`) and pushed
> `.github/workflows/ci.yml` to each directly — zero scope errors. CI is
> now live and green on `pr-summary-action`, `secret-scan-action`, and
> `secretguard-mcp` (see `docs/devops/` for the workflow content that was
> used, unchanged from the Cycle #32/#33 drafts).

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

### 3. List `pr-summary-action` on GitHub Marketplace
**Update, Cycle #71**: `secret-scan-action` is confirmed **already live** at
`github.com/marketplace/actions/secret-scan-action` — that half of this item
is done (verified via a fresh `curl` of the Marketplace search results this
cycle, not just assumed). `pr-summary-action` is confirmed **not** listed
(0 results for it on Marketplace search) despite having a valid `v1` release
and `action.yml` branding — same gap as before, just narrower scope now.

No API for this — has to be the web UI:
1. Go to `github.com/vladimirbakalov/pr-summary-action/releases/edit/v1`.
2. Check **"Publish this Action to the GitHub Marketplace"**.
3. Accept the Marketplace Developer Agreement (one-time — likely already
   accepted, since `secret-scan-action` is live).
4. Fill in category + tagline/description — copy-paste text is pre-written
   in `docs/marketing/marketplace-listing-cycle31.md` (pricing plan = Free).
   `LICENSE` and `action.yml` branding are already in place, so that's the
   only free-text step left.

Repo: `github.com/vladimirbakalov/pr-summary-action`.

## Bigger unlock — the actual revenue blocker

### 4. Cloudflare deploy (vibecheck + snapog)
Both products are scope-complete, tested, and deploy-ready. This has been the
top blocker for 19+ cycles. Full steps:
`docs/devops/snapog-deploy-runbook.md` (vibecheck's runbook is equivalent —
same account, separate D1/R2 resources).

```bash
wrangler login   # wrangler is now installed (npm install -g wrangler, done
                 # Cycle #26) — login is the only step left, browser click only
```

### 5. Resend (for vibecheck/snapog transactional email)
Sign up at resend.com, verify a sending domain, then:
```bash
wrangler secret put RESEND_API_KEY
```
Depends on #4 being done first (need `wrangler` + a deployed Worker to attach
the secret to).

## Optional, low priority

### 6. `npm adduser` / `npm login`
Would let the agent `npm publish secretguard-mcp` directly instead of relying
on `npx github:...`. Not required — the GitHub-based install already works
end-to-end (verified Cycle #24 with a real `npx -y github:...` handshake).

### 7. Delete a harmless throwaway repo
Cycle #97's end-to-end QA smoke test created
`github.com/vladimirbakalov/secret-scan-action-smoketest-c97` to verify the
real PR-comment flow. The agent's token lacks the `delete_repo` scope, so
it can't clean up after itself. Contains nothing but a README and a
synthetic (non-functional) fake AWS-shaped string — zero risk sitting there,
just tidiness. Either:
```bash
gh auth refresh -h github.com -s delete_repo
gh repo delete vladimirbakalov/secret-scan-action-smoketest-c97 --yes
```
or delete manually via GitHub UI: Settings → Danger Zone.

---
**Not on this list on purpose**: automated/unsolicited outreach PRs to
third-party repos (e.g. submitting to `awesome-*` list repos). That growth
tactic stays out of bounds without your explicit sign-off — see
`memories/consensus.md` open questions.
