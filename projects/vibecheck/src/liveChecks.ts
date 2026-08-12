// vibecheck — live-URL security checks (ADR §3 caller #1, spec §2.2)
//
// Runs the same "produce a Finding[]" shape as checks.ts's static repo scan,
// but against a live HTTP response instead of source files. Deliberately a
// separate module from probe.ts: probe.ts does network I/O only and does not
// run detection itself (see its module header + test/probe.test.ts), so this
// file is the live-URL counterpart to checks.ts — reusing checks.ts's
// SECRET_PATTERNS for the secret-shaped-content check rather than inventing
// a second set of patterns, per the ADR's "one code path to fix" mandate.

import type { Finding } from './types';
import type { ProbeResult } from './probe';
import { probeUrl, probeSensitivePaths } from './probe';
import { SECRET_PATTERNS } from './checks';

let liveFindingCounter = 0;
function nextLiveId(prefix: string): string {
  liveFindingCounter += 1;
  return `live-${prefix}-${liveFindingCounter}`;
}

// Core headers we check for on the live root response. Kept short and
// well-known (not an exhaustive hardening checklist) — one combined finding
// rather than one-per-header, so a site missing all three doesn't spam the
// findings list for what is, in most vibe-coded apps, a single root cause
// (platform defaults, not per-header oversights).
const CORE_SECURITY_HEADERS: { header: string; label: string }[] = [
  { header: 'strict-transport-security', label: 'Strict-Transport-Security' },
  { header: 'x-frame-options', label: 'X-Frame-Options' },
  { header: 'x-content-type-options', label: 'X-Content-Type-Options' },
];

export function checkLivePermissiveCors(deployedUrl: string, rootProbe: ProbeResult): Finding[] {
  if (rootProbe.headers['access-control-allow-origin'] !== '*') return [];
  return [
    {
      id: nextLiveId('cors'),
      title: 'Permissive CORS policy on live deployment (wildcard origin)',
      severity: 'medium',
      confidence: 'high',
      explanation:
        'The live deployment responds with Access-Control-Allow-Origin: *, which lets any website make requests to this app from a browser. Fine for a truly public read-only API; risky if any endpoint here handles auth or user data.',
      file: `(live: ${deployedUrl})`,
    },
  ];
}

export function checkLiveMissingSecurityHeaders(deployedUrl: string, rootProbe: ProbeResult): Finding[] {
  const missing = CORE_SECURITY_HEADERS.filter(h => !rootProbe.headers[h.header]);
  if (missing.length === 0) return [];
  return [
    {
      id: nextLiveId('headers'),
      title: 'Missing common security headers on live response',
      severity: 'low',
      confidence: 'low',
      explanation: `The live deployment's response is missing: ${missing.map(m => m.label).join(', ')}. These headers harden against clickjacking, MIME-sniffing, and protocol-downgrade attacks. Missing them is common on default platform configs and isn't necessarily a vulnerability by itself, but is worth reviewing.`,
      file: `(live: ${deployedUrl})`,
    },
  ];
}

// Reuses checks.ts's SECRET_PATTERNS verbatim against live response bodies —
// exact same regexes the static scanner already runs against repo files, per
// ADR §3's "one code path to fix" instruction.
export function checkLiveSensitivePaths(
  deployedUrl: string,
  sensitiveResults: Record<string, ProbeResult>
): Finding[] {
  const findings: Finding[] = [];
  for (const path of Object.keys(sensitiveResults)) {
    const result = sensitiveResults[path];
    if (!result.ok || result.status !== 200 || !result.bodySnippet) continue;

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(result.bodySnippet)) {
        findings.push({
          id: nextLiveId('secret'),
          title: `Possible exposed ${pattern.name} at live path ${path}`,
          severity: pattern.severity,
          confidence: 'medium',
          explanation: `The live deployment responded 200 OK to ${path} with content matching the pattern for a ${pattern.name}. This path is a common accidental-exposure target. Verify this isn't a real, live credential reachable on your deployed app.`,
          file: `(live: ${deployedUrl}${path})`,
        });
      }
    }
  }
  return findings;
}

// Entry point for POST /api/scan's optional deployedUrl. Throws if the
// deployed URL isn't reachable at all (root probe fails) — callers should
// catch this and degrade gracefully (skip live findings, add a ScanResult
// note) rather than fail the whole scan, per the product brief. Individual
// sensitive-path probes that fail to reach are simply excluded from
// consideration (probeSensitivePaths already returns ok:false per-path
// rather than throwing).
//
// Callers MUST validate `deployedUrl` with validateProbeTarget (probe.ts)
// before calling this — this function does not re-validate, to keep the
// validate-then-fetch sequence explicit at the call site.
export async function buildLiveFindings(deployedUrl: string): Promise<Finding[]> {
  liveFindingCounter = 0;

  const rootProbe = await probeUrl(deployedUrl, { path: '/' });
  if (!rootProbe.ok) {
    throw new Error(rootProbe.error ?? 'Could not reach the deployed URL');
  }

  const findings: Finding[] = [
    ...checkLivePermissiveCors(deployedUrl, rootProbe),
    ...checkLiveMissingSecurityHeaders(deployedUrl, rootProbe),
  ];

  const sensitiveResults = await probeSensitivePaths(deployedUrl);
  findings.push(...checkLiveSensitivePaths(deployedUrl, sensitiveResults));

  return findings;
}
