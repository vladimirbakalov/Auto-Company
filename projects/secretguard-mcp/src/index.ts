#!/usr/bin/env node
/**
 * secretguard-mcp — a single-tool MCP server that scans a code string for
 * hardcoded secrets before it's written to a file or committed.
 *
 * Wraps the same detection engine (rules.ts / scan.ts / redact.ts) that
 * powers secret-scan-action's GitHub Action, minus the diff/GitHub plumbing
 * — here the input is just a code string, not a PR.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanForSecrets, toToolResponse } from "./mcp-tool.js";

const server = new McpServer({
  name: "secretguard-mcp",
  version: "0.1.0",
});

server.registerTool(
  "scan_for_secrets",
  {
    title: "Scan for secrets",
    description:
      "Scans a code string for hardcoded secrets (AWS keys, Stripe keys, GitHub tokens, Google API keys, " +
      "Slack tokens, private key blocks, JWTs, and generic high-entropy credentials assigned to " +
      "secret/token/password/key-like variable names) BEFORE that code is written to a file or committed. " +
      "Call this proactively whenever you are about to write, edit, or commit code that could plausibly " +
      "contain a credential — config files, env handling, API client setup, tests with fixture values, " +
      "or any snippet you're not 100% sure is clean — and again right before creating a commit or PR. " +
      "Every reported line is redacted; the raw secret value is never returned.",
    inputSchema: {
      code: z.string().describe("The code to scan, as plain text (one file's contents, or any snippet)."),
      filename: z
        .string()
        .optional()
        .describe("Optional filename to attribute findings to (for display only). Defaults to \"input\"."),
    },
    outputSchema: {
      findings: z.array(
        z.object({
          filename: z.string(),
          line: z.number(),
          ruleId: z.string(),
          description: z.string(),
          confidence: z.enum(["high", "generic"]),
          redactedLine: z.string().describe("The finding's line with the secret value masked."),
        }),
      ),
      summary: z.string(),
    },
    annotations: {
      readOnlyHint: true,
      openWorldHint: false,
    },
  },
  async ({ code, filename }) => toToolResponse(scanForSecrets(code, filename)),
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("secretguard-mcp failed to start:", error);
  process.exit(1);
});
