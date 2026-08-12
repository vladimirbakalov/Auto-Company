# secretguard-mcp

An MCP (Model Context Protocol) server that scans a code string for
hardcoded secrets — AWS keys, Stripe keys, GitHub tokens, Google API keys and
OAuth client secrets, Slack tokens, OpenAI keys, Anthropic keys, npm access
tokens, SendGrid keys, Twilio API keys, Azure Storage account keys, private
key blocks, JWTs, and generic high-entropy credentials — so an AI coding agent (Claude Code, Cursor, Windsurf, ...) can catch a
secret *before* it writes the file or makes the commit, instead of finding
out at CI/PR-review time. It exposes exactly one tool, `scan_for_secrets`,
runs entirely locally over stdio, needs no API key, and never returns a raw
secret value — every finding comes back redacted.

## Why this exists

[`secret-scan-action`](https://github.com/vladimirbakalov/secret-scan-action)
already catches these secrets in CI, on every PR. That's necessary but late
— by the time it runs, the secret has already been written, committed, and
pushed. This project reuses that same detection engine (same rules, same
entropy check, same redaction) but puts it in front of the agent as a tool
call, so the check can happen at generation time, before the secret ever
touches disk or history.

## What it does

On a `scan_for_secrets` call:

1. Splits the input `code` string into lines.
2. Runs the same two-tier ruleset `secret-scan-action` uses:
   - **Pattern rules (high confidence)** — distinctive formats that are
     near-certain secrets when matched: AWS access key IDs (`AKIA...`) and
     contextual secret keys, Stripe live keys (`sk_live_`, `rk_live_`),
     GitHub tokens (`ghp_`, `gho_`, `github_pat_`, ...), Google API keys
     (`AIza...`), Google OAuth client secrets (`GOCSPX-...`), Slack tokens
     (`xox[baprs]-...`), OpenAI keys (`sk-...`, `sk-proj-...`,
     `sk-svcacct-...`), Anthropic keys (`sk-ant-...`), npm access tokens
     (`npm_...`), SendGrid keys (`SG....`), Twilio API keys (`SK...`), Azure
     Storage account keys (contextual `AccountKey=...`), private key blocks
     (`-----BEGIN ... PRIVATE KEY-----`), and JWTs.
   - **Generic entropy rule** — a value assigned to a variable named like
     `secret`, `token`, `password`/`credential`, or a `*key` compound
     commonly used for real secret material (`apiKey`, `sessionKey`,
     `signingKey`, `clientKey`, `webhookKey`, ...) whose value also has high
     Shannon entropy (looks random, not like a placeholder or an env-var
     reference). Deliberately does *not* match a bare `*Key` — that would
     also catch `partitionKey`, `cacheKey`, `queryKey`, and similar
     non-secret identifiers common in ordinary code.
3. Returns every finding's `filename`, `line`, `ruleId`, `description`,
   `confidence` (`"high"` | `"generic"`), and a **redacted** line — the raw
   secret value never leaves the process. If nothing is found, it returns a
   plain "No secrets detected." result.

## Example output

Calling `scan_for_secrets` with:

```json
{
  "code": "const key = \"AKIAIOSFODNN7EXAMPLE\";\nconst greeting = \"hello\";",
  "filename": "src/config.ts"
}
```

returns:

```json
{
  "findings": [
    {
      "filename": "src/config.ts",
      "line": 1,
      "ruleId": "aws-access-key-id",
      "description": "AWS Access Key ID",
      "confidence": "high",
      "redactedLine": "const key = \"AKIA************MPLE\";"
    }
  ],
  "summary": "Found 1 potential secret (1 high-confidence, 0 needs-review).\n\n- [high] src/config.ts:1 — AWS Access Key ID (aws-access-key-id)\n  const key = \"AKIA************MPLE\";"
}
```

(The AWS key above is AWS's own public documentation placeholder, not a live
credential.) A clean scan — e.g. `{ "code": "const greeting = \"hello
world\";" }` — returns `{ "findings": [], "summary": "No secrets
detected." }`.

## Setup

Not yet published to the npm registry — install directly from GitHub via
`npx`. `npm install` from a git source runs this package's `prepare` script
automatically, which builds `dist/` on the fly, so no separate build step is
needed.

### Claude Code

Add to your project's `.mcp.json` (or run `claude mcp add`):

```json
{
  "mcpServers": {
    "secretguard": {
      "command": "npx",
      "args": ["-y", "github:vladimirbakalov/secretguard-mcp"]
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secretguard": {
      "command": "npx",
      "args": ["-y", "github:vladimirbakalov/secretguard-mcp"]
    }
  }
}
```

No API key, no account, no config options — restart Claude Code / Claude
Desktop and `scan_for_secrets` is available. The tool description tells the
agent to call it before writing code that could contain a credential, and
again before a commit or PR — most of the time you won't need to ask for it
explicitly.

### Cursor / Windsurf

Both read the same `command`/`args` shape from their own MCP settings UI or
config file — point them at `npx -y github:vladimirbakalov/secretguard-mcp`
the same way.

Once this package is published to npm, the `args` above can drop to
`["-y", "secretguard-mcp"]` instead — that's a follow-up, not a blocker.

### One-click install (.mcpb)

A prebuilt [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) is
attached to the
[`v0.1.0-mcpb` release](https://github.com/vladimirbakalov/secretguard-mcp/releases/tag/v0.1.0-mcpb) —
download `secretguard-mcp-0.1.0.mcpb` and open it in Claude Desktop (or any
other MCPB-compatible client) for a one-click local install, no `npx`/Node
setup required on the client side. Rebuild it yourself with
`npm run package:mcpb` (see `scripts/build-mcpb.sh`).

This same `.mcpb` release asset is what `server.json` at the repo root points
at for the [official MCP Registry](https://registry.modelcontextprotocol.io/)
— publishing there is prepared but not yet done, since it requires a one-time
interactive `mcp-publisher login github` device-flow authorization.

## Security notes

- The raw secret value matched by a rule is held in memory only for the
  duration of a single `scan_for_secrets` call and is redacted
  (`redactLine`/`redactSecret`) before the tool result is built — it never
  appears in the returned `content`, `structuredContent`, or any log line.
- The server does no network calls of any kind. It reads stdin, writes
  stdout (MCP stdio transport), and does nothing else.
- Generic-tier findings are ambiguous by nature (config placeholders,
  hashes, and UUIDs can trip the entropy check) — that's expected. Treat
  `confidence: "generic"` as "worth a second look," not "confirmed."

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run build       # tsc -p tsconfig.build.json -> dist/
```

`dist/` is not committed — it's built from `src/` via the `prepare` script,
which runs both on a git-based `npx`/`npm install` and before any future
`npm publish`.

## Scope (v1)

One tool, one job: scan a code string, return redacted findings. No
allowlist file, no AI triage step, no config options, no persistent state.
If this needs any of that later, it'll get added once real usage shows it's
needed — not before.

## Relationship to secret-scan-action

`secretguard-mcp` and
[`secret-scan-action`](https://github.com/vladimirbakalov/secret-scan-action)
share the same detection engine (`rules.ts`, `redact.ts`, and the core of
`scan.ts`) but are independent, separately distributed packages: one is a
GitHub Action that scans PR diffs in CI, the other is an MCP server that
scans arbitrary code strings locally, before a commit exists. Fixing a
false positive/negative in the ruleset means updating both.

## License

MIT.
