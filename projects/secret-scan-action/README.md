# Secret Scan Action

A free GitHub Action that scans a pull request's **changed lines only** for
leaked secrets — AWS keys, Stripe keys, GitHub tokens, Google API keys and
OAuth client secrets, Slack tokens and incoming webhook URLs, Shopify access
tokens, Telegram bot tokens, DigitalOcean tokens, Hugging Face tokens,
Notion API tokens, Mailchimp API keys, Postman API tokens, Linear API keys,
Readme API keys, Clojars API tokens, Pulumi API tokens, OpenAI keys, Anthropic keys, npm access tokens, SendGrid keys, Twilio API keys, Azure
Storage account keys, database connection strings with embedded passwords,
private key blocks, JWTs, and generic high-entropy credentials — and fails
the check when it finds a
confirmed one. It works out of the box with zero configuration and no API
key. Optionally, bring your own Anthropic API key to have Claude triage the
small set of ambiguous matches and cut noise.

## Why "changed lines only"

This action reads the PR's diff, not the repo's current state. Only lines a
PR is *adding* are scanned — pre-existing secrets sitting in unchanged
context lines, or ones being *removed*, are never flagged. That keeps this
useful on day one in an existing repo: it won't dredge up every secret
already committed to history, it just stops new ones from landing.

## What it does

On every `pull_request` event:

1. Fetches the PR's changed files and parses each unified diff, extracting
   only added lines with their line numbers in the new file.
2. Runs a curated ruleset against those lines:
   - **Pattern rules (high confidence)** — distinctive formats that are
     near-certain secrets when matched: AWS access key IDs (`AKIA...`) and
     contextual secret keys, Stripe live keys (`sk_live_`, `rk_live_`),
     GitHub tokens (`ghp_`, `gho_`, `github_pat_`, ...), Google API keys
     (`AIza...`), Google OAuth client secrets (`GOCSPX-...`), Slack tokens
     (`xox[baprs]-...`), Slack incoming webhook URLs
     (`hooks.slack.com/services/...`), Shopify access tokens (`shpat_...`,
     `shpca_...`, `shpss_...`, `shppa_...`, `shpua_...`), Telegram bot tokens
     (`<bot_id>:A...`, 35-char secret), DigitalOcean tokens (`dop_v1_...`,
     `doo_v1_...`, `dor_v1_...`, 64-char hex), Hugging Face tokens (`hf_...`,
     `api_org_...`, 34-char alpha), Notion API tokens (`ntn_...`, 11 digits +
     35 alphanumeric), OpenAI keys (`sk-...`, `sk-proj-...`,
     `sk-svcacct-...`), Anthropic keys (`sk-ant-...`), npm access tokens
     (`npm_...`), SendGrid keys (`SG....`), Twilio API keys (`SK...`), Azure
     Storage account keys (contextual `AccountKey=...`), private key blocks
     (`-----BEGIN ... PRIVATE KEY-----`), and JWTs. One pattern rule —
     database connection strings with an embedded password
     (`postgres://`, `mysql://`, `mongodb(+srv)://`, `redis(s)://`,
     `amqp(s)://`) — is deliberately *not* near-certain even after excluding
     known placeholder passwords (`user`, `password`, `changeit`, ...) and
     `${...}`-style env-var references, since a real value there could still
     be a low-stakes tutorial example rather than a live credential; it's
     reported at generic confidence, same as the entropy rule below. Another
     pattern rule — Mailchimp API keys (a 32-char hex value followed by a
     `-usNN` datacenter suffix) — is also generic confidence: it only fires
     when a `mailchimp`-prefixed variable/key name immediately precedes the
     value, but that keyword gate still doesn't rule out an unrelated hex
     value that happens to end in the same suffix shape. Postman API tokens
     (`PMAK-...`, 24-char hex + `-` + 34-char hex), Linear API keys
     (`lin_api_...`, 40-char alphanumeric), Readme API keys
     (`rdme_...`, 70-char lowercase alphanumeric), Clojars API tokens
     (`CLOJARS_...`, case-insensitive, 60-char alphanumeric), and Pulumi API
     tokens (`pul-...`, 40-char lowercase hex) are high confidence — a fixed
     prefix and exact length, same as the other provider-token rules.
   - **Generic entropy rule** — a value assigned to a variable named like
     `secret`, `token`, `password`/`credential`, or a `*key` compound
     commonly used for real secret material (`apiKey`, `sessionKey`,
     `signingKey`, `encryptionKey`, `clientKey`, `jwtKey`, `webhookKey`, ...)
     whose value also has high Shannon entropy (looks random, not like a
     placeholder or an env-var reference). Deliberately does *not* match a
     bare `*Key` — that would also catch `partitionKey`, `cacheKey`,
     `queryKey`, and similar non-secret identifiers that are common in
     ordinary code. This tier (plus the DB connection-string rule above) is
     where ambiguity lives — even with the name gate, hashes, UUIDs, and
     test fixtures can trip the entropy rule.
3. **Optional BYOK triage**: if you set `anthropic-api-key`, every generic-tier
   finding (the entropy rule's hits, plus the DB connection-string rule's —
   near-certain pattern matches don't need a second opinion) is sent to
   Claude, masked, for a real/false-positive judgment. Only the value's
   length, entropy, variable name, and a masked context line are sent — never
   the raw secret. If the call fails for any reason, every generic match is
   reported unfiltered rather than silently dropped (fail-safe, not
   fail-open).
4. Posts (or updates) a single PR comment listing every finding — file, line,
   rule, and a redacted snippet — signed with a one-line attribution at the
   bottom.
5. **Fails the check** if any high-confidence (pattern-matched) finding
   exists. Generic-tier matches are shown but don't fail the check by
   default — set `fail-on: any` if you want them to.

## Example output

This is the comment the action posts when it finds something (built directly
from the same template the code renders, so it's exact — not a mockup):

> ## 🔒 Secret Scan
>
> Found **2** potential secrets in this PR's changed lines.
>
> ### 🚫 High confidence — blocks this check (1)
>
> | File | Line | Rule | Snippet |
> |---|---|---|---|
> | `src/config/aws.ts` | 14 | AWS Access Key ID | `const AWS_ACCESS_KEY_ID = 'AKIA************MPLE';` |
>
> ### ⚠️ Needs review — generic high-entropy match (1)
>
> _Already reviewed by Claude to cut obvious false positives — still worth a human look._
>
> | File | Line | Rule | Snippet |
> |---|---|---|---|
> | `src/lib/webhook-notify.ts` | 42 | High-entropy value assigned to "webhookKey" | `const webhookKey = 'wk9f****************6bA3';` |
>
> False positive? Add a pattern to `.secretscanignore` (or the `allowlist` input) matching the value, the line, or the file path.
>
> — flagged by secret-scan-action

Every secret value shown is redacted (see [Security notes](#security-notes))
— the raw AWS key above is AWS's own public documentation placeholder, not a
live credential. When a PR is clean, the comment is a single line: "No
secrets detected in this PR's changed lines. ✅"

## Setup

Add the workflow — no repo secret required for the basic scan:

```yaml
name: Secret Scan

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  pull-requests: write # needed to post/update the findings comment
  contents: read        # needed to read the diff and (optionally) .secretscanignore

concurrency:
  group: secret-scan-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: vladimirbakalov/secret-scan-action@v1
        with:
          # anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}  # optional — enables AI triage of ambiguous matches
          # fail-on: "high"        # optional, this is the default ("any" also blocks on generic matches)
          # allowlist-path: ".secretscanignore"  # optional, this is the default
```

That's it. Open (or push to) a pull request and the action comments within a
minute or two — no Anthropic key, no other account, no signup.

> `@v1` tracks the latest `v1.x` release. Pin to a full commit SHA instead
> if you want builds immune to any future tag update.

The `concurrency` block prevents duplicate comments when you push multiple
commits to a PR in quick succession.

### Suppressing false positives

Add a `.secretscanignore` file to the repo root (or point `allowlist-path` at
a different file), one regex pattern per line, `#` for comments:

```
# ignore this specific test fixture value
AKIAIOSFODNN7EXAMPLE

# ignore anything under the fixtures directory
^test/fixtures/
```

A finding is suppressed if any pattern matches the secret value, the full
changed line, or the file path. You can also pass patterns inline via the
`allowlist` input (newline-separated) without committing a file.

Keep patterns as narrow as you can — a broad path prefix (e.g. `^test/`)
suppresses *every* finding under that path, including a real secret an
attacker deliberately drops there later. Prefer exact values or tightly
scoped filenames over broad prefixes where possible.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `github-token` | no | `${{ github.token }}` | Token used to read the diff, optionally read `.secretscanignore`, and post the comment. |
| `anthropic-api-key` | no | *(none)* | Your own Anthropic API key. Enables Claude triage of ambiguous generic-entropy matches. Scanning works fully without it. |
| `model` | no | `claude-opus-4-8` | Anthropic model ID used for optional triage. |
| `allowlist` | no | *(none)* | Newline-separated regex patterns to suppress known false positives. |
| `allowlist-path` | no | `.secretscanignore` | Path to a repo file of allowlist patterns, read via the GitHub Contents API at the PR's **base** commit (no checkout needed). |
| `fail-on` | no | `high` | `high` fails only on confirmed-pattern matches; `any` also fails on unresolved generic-entropy matches. |

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Total findings posted to the comment, after allowlist filtering. |
| `high-confidence-count` | Number of high-confidence (confirmed-pattern) findings. |
| `comment-id` | The ID of the PR comment that was created or updated. |

## Security notes

- The optional Anthropic API key is never logged, never echoed into the PR
  comment, and the SDK's `baseURL` is pinned explicitly to
  `https://api.anthropic.com` so a compromised or misconfigured prior
  workflow step can't redirect it via `ANTHROPIC_BASE_URL`.
- Only masked/redacted values ever leave the runner for AI triage — never
  the raw secret.
- The PR comment itself never contains an unredacted secret value, even for
  findings it lists.
- `.secretscanignore` is read from the PR's **base** commit, not its head. A
  PR can't suppress a secret it just introduced by adding a matching
  allowlist entry in that same PR — the entry only takes effect once merged.

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest run — all network calls are mocked
npm run build       # bundles src/ into dist/index.js via @vercel/ncc
```

`dist/index.js` is committed to this repo (standard practice for JavaScript
GitHub Actions) — run `npm run build` and commit the result after any change
to `src/`.

## Scope (v1)

This is a stateless Action that runs inside your own CI job. No dashboard,
no persistent secret-history database, no webhook server, no npm publish, no
new cloud account. It reads the PR diff and (optionally) one allowlist file,
and writes one PR comment. That's it.

## Distribution

Lives in its own dedicated repo (`vladimirbakalov/secret-scan-action`), so the
`uses:` line above works for anyone today. It is **not yet listed on the
GitHub Marketplace** — that requires an interactive "Publish this release to
the Marketplace" step in GitHub's web UI (there's no API/CLI equivalent).
Completing that publish step is a follow-up, not a blocker to using the
action today.

## License

MIT.
