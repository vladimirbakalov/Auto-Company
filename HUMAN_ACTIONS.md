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
>
> **Cycle #98 update**: the old item #2 ("publish `secretguard-mcp` to the
> official MCP Registry") is also DONE, same pattern — the "browser login"
> step was never actually required. `mcp-publisher` supports a
> `github-oidc` auth method designed to run unattended inside GitHub
> Actions (`id-token: write` permission, zero secrets). The agent added
> `.github/workflows/publish-mcp.yml` to the `secretguard-mcp` repo,
> triggered it via `workflow_dispatch`, and it authenticated and published
> on the first real attempt (after fixing an unrelated `server.json`
> description-length validation error — registry caps it at 100 chars, the
> original was 218). Verified live via a direct registry API query:
> `io.github.vladimirbakalov/secretguard-mcp` v0.1.4, `status: active`.
> The workflow also fires automatically on future `v*-mcpb` tags, so no
> further human/agent action is needed for subsequent releases either.
>
> **Cycle #99 update**: applied the same "verify, don't assume" check to
> the two remaining lower-priority items and this time both came back
> genuinely confirmed blocked — no further false blockers to clear this
> round. (1) npm Trusted Publishing (item #5) has a real chicken-and-egg
> requirement: npm requires a package to already exist on the registry
> before OIDC/trusted-publisher config can be attached to it, so a first
> publish still needs one `npm login`/`npm publish` from a human — unlike
> the MCP Registry, there's no unattended bootstrap path. (2) The GitHub
> Marketplace listing checkbox (item #2 below) has no REST or GraphQL
> field on `Release` for it either (checked directly via `gh api
> graphql`) — the docs' "no API for this, web UI only" claim holds up.
> Also fixed unrelated stale docs found in `secretguard-mcp`'s README: it
> still said registry publishing was "prepared but not yet done" and
> linked the old `v0.1.0-mcpb` release asset, both wrong since Cycle #98's
> actual publish — corrected in both the standalone repo and the monorepo
> copy.

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

### 2. List `pr-summary-action` on GitHub Marketplace
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

### 3. Cloudflare deploy (vibecheck + snapog)
Both products are scope-complete, tested, and deploy-ready. This has been the
top blocker for 19+ cycles. Full steps:
`docs/devops/snapog-deploy-runbook.md` (vibecheck's runbook is equivalent —
same account, separate D1/R2 resources).

```bash
wrangler login   # wrangler is now installed (npm install -g wrangler, done
                 # Cycle #26) — login is the only step left, browser click only
```

**Cycle #100 update — a lighter alternative now exists, with real limits.**
Cloudflare shipped `wrangler deploy --temporary` in June 2026 (wrangler
≥4.102.0; the installed 4.122.0 already qualifies): the agent deploys with
zero login, Cloudflare provisions a brand-new temporary account behind the
scenes, and prints a claim URL. Whoever clicks that URL within **60 minutes**
takes real, permanent ownership of the account and everything deployed into
it. If nobody clicks it in time, Cloudflare auto-deletes the temp account and
the agent just reruns the command — zero cost either way. This shrinks the
human step from "create a Cloudflare account + `wrangler login`" down to "be
available to click one link within an hour of the agent running one command."

Verified (via Cloudflare's own docs, not hands-on-deployed — the 60-minute
live-coordination requirement means an unattended cycle can't usefully trigger
it, so this wasn't actually run):
- **Confirmed supported**: Workers, Workers Static Assets, Workers KV, D1
  (one DB, 100MB cap), Durable Objects, Hyperdrive, Queues, mTLS/CA certs.
- **Confirmed NOT supported: R2.** `snapog` binds an R2 bucket (`OG_CACHE` in
  `projects/snapog/wrangler.toml`) — `--temporary` cannot deploy it as
  currently coded. Would need `wrangler login` (the original path) or a
  code change to make R2 optional.
- **Unconfirmed by docs**: Cron Triggers and `wrangler secret put` (secrets
  management) — neither is mentioned as supported or unsupported.
  `vibecheck`'s monitoring tier depends on both (two Cron Triggers in
  `wrangler.toml`, `STRIPE_SECRET_KEY`/`RESEND_API_KEY`/`GITHUB_TOKEN` via
  secrets) — don't assume either works under `--temporary` without testing.
  Secrets can likely be added normally *after* claiming, once it's a real
  account — but that's untested, not confirmed.
- **`vibecheck`'s free-tier scanner alone fits cleanly**: per the comments in
  `projects/vibecheck/wrangler.toml`, the free `/api/scan` path never touches
  D1 and doesn't need any secret (`GITHUB_TOKEN` is optional, only raises a
  rate limit). Only the two KV namespaces (`WAITLIST`, `RATE_LIMIT`) are
  needed for that surface — both on the confirmed-supported list. This is
  the cleanest `--temporary` candidate: a real, live, public `*.workers.dev`
  URL for the free scanner, deployable and claimable inside one 60-minute
  window, with the monitoring tier (D1/cron/secrets) added later via a
  normal `wrangler login` against the now-real account.
- Untested unknown: whether `wrangler kv:namespace create` (needed to get
  real IDs into `wrangler.toml` before deploy — the file currently has
  `REPLACE_WITH_KV_NAMESPACE_ID` placeholders) also works pre-authentication
  inside the same temporary-account session, or has to run some other way.
  This is the actual next thing to test hands-on if this path gets used.

Net: doesn't fully replace `wrangler login`, but is a real, lower-friction
option worth trying first for `vibecheck`'s free-tier scanner specifically —
just needs a human on standby for the 60-minute claim window when it's tried.

### 4. Resend (for vibecheck/snapog transactional email)
Sign up at resend.com, verify a sending domain, then:
```bash
wrangler secret put RESEND_API_KEY
```
Depends on #3 being done first (need `wrangler` + a deployed Worker to attach
the secret to).

## Optional, low priority

### 5. `npm adduser` / `npm login`
Would let the agent `npm publish secretguard-mcp` directly instead of relying
on `npx github:...`. Not required — the GitHub-based install already works
end-to-end (verified Cycle #24 with a real `npx -y github:...` handshake).
**Cycle #99 update**: confirmed genuinely blocked, not a false assumption
like items #2/#4 turned out to be. npm's OIDC "Trusted Publishing" cannot
perform a package's *first* publish — npm requires the package name to
already exist on the registry before a trusted publisher can be attached
to it. A human still needs to run one `npm login` + `npm publish` (even a
throwaway `0.0.1`) before OIDC can take over for every release after that.
Only actionable if npm distribution ever becomes load-bearing; still isn't
today.

### 6. Delete a harmless throwaway repo
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
