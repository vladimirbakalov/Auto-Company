// vibecheck — heuristic security checks
//
// These are static, regex/pattern-based heuristics run over a bounded sample of
// a repo's files (see github.ts MAX_FILES_TO_FETCH). They are NOT a substitute
// for a real security audit: no AST parsing, no data-flow analysis, no dynamic
// testing against a live app. False positives and false negatives are expected.
// Every finding carries a `confidence` field for exactly this reason — surface
// it in the UI, don't hide it.

import type { Finding, RepoFile } from './types';

// ─── File selection ─────────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = [
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.java', '.php',
];

const PRIORITY_HINTS = [
  'route', 'api', 'auth', 'supabase', 'config', 'server',
  'middleware', 'handler', 'client', '.env',
];

const ALWAYS_INCLUDE_BASENAMES = new Set([
  '.env', '.env.local', '.env.production', '.gitignore', 'package.json',
]);

// Cloud credential JSON files (GCP/Firebase service accounts, OAuth client
// secrets) are a common real-world leak in vibe-coded repos, but generic
// .json isn't in SOURCE_EXTENSIONS (that would pull in package-lock.json,
// tsconfig.json, etc.) so these were structurally invisible to the scanner.
const CREDENTIAL_JSON_HINT = /(service[-_]?account|firebase-adminsdk|gcp[-_]?key|client_secret|credentials?)[^/]*\.json$/i;

function isSourceFile(path: string): boolean {
  return SOURCE_EXTENSIONS.some(ext => path.endsWith(ext));
}

function isMigrationOrSql(path: string): boolean {
  return (
    /\.sql$/i.test(path) ||
    /migrations?\//i.test(path) ||
    /supabase\/migrations/i.test(path)
  );
}

// Picks which file paths to actually fetch content for, given the full tree
// and a budget (github.ts enforces the hard cap; this just prioritizes).
export function selectCandidateFiles(tree: string[]): string[] {
  const basename = (p: string) => p.split('/').pop() ?? p;

  const always = tree.filter(
    p => ALWAYS_INCLUDE_BASENAMES.has(basename(p)) || CREDENTIAL_JSON_HINT.test(p)
  );
  const migrations = tree.filter(isMigrationOrSql).slice(0, 8);
  const sourceFiles = tree.filter(isSourceFile);

  const scored = sourceFiles
    .map(p => ({
      path: p,
      score: PRIORITY_HINTS.reduce((s, hint) => (p.toLowerCase().includes(hint) ? s + 1 : s), 0),
    }))
    .sort((a, b) => b.score - a.score)
    .map(x => x.path);

  const combined = [...always, ...migrations, ...scored];
  return Array.from(new Set(combined));
}

// ─── Finding builders ────────────────────────────────────────────────────────

let findingCounter = 0;
function nextId(prefix: string): string {
  findingCounter += 1;
  return `${prefix}-${findingCounter}`;
}

// 1. Exposed .env committed to the repo
export function checkExposedEnv(tree: string[], files: RepoFile[]): Finding[] {
  const envInTree = tree.some(p => /(^|\/)\.env$/.test(p));
  if (!envInTree) return [];

  const gitignore = files.find(f => f.path.split('/').pop() === '.gitignore');
  const ignoresEnv = gitignore
    ? /(^|\n)\s*(\*\*\/)?\.env(\.\*|\*)?\s*($|\n)/.test(gitignore.content)
    : false;

  if (ignoresEnv) {
    return [
      {
        id: nextId('env'),
        title: '.env file present in repo history (but .gitignore now excludes it)',
        severity: 'medium',
        confidence: 'medium',
        explanation:
          'A .env file exists in the tree. .gitignore currently excludes .env going forward, but if it was ever committed, its contents (including any old secrets) remain in git history and should be treated as leaked.',
      },
    ];
  }

  return [
    {
      id: nextId('env'),
      title: '.env file is committed and not gitignored',
      severity: 'critical',
      confidence: 'high',
      explanation:
        '.env files typically hold API keys, database URLs, and secrets. It is present in the repo tree and not excluded by .gitignore, meaning secrets are likely exposed to anyone who can view this public repo.',
      file: '.env',
    },
  ];
}

// 2. Hardcoded secrets / API keys in source files
//
// Exported so probe.ts's live-URL security check (ADR §3, caller #1) can run
// the exact same detection regexes against live HTTP response bodies instead
// of inventing a second set of patterns — "one code path to fix" per the ADR.
export const SECRET_PATTERNS: { name: string; regex: RegExp; severity: Finding['severity'] }[] = [
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
  { name: 'Stripe live secret key', regex: /\bsk_live_[0-9a-zA-Z]{16,}\b/, severity: 'critical' },
  { name: 'Stripe live restricted key', regex: /\brk_live_[0-9a-zA-Z]{16,}\b/, severity: 'critical' },
  { name: 'Stripe test key (lower risk, still shouldn\'t be hardcoded)', regex: /\bsk_test_[0-9a-zA-Z]{16,}\b/, severity: 'low' },
  {
    name: 'Supabase service_role key (bypasses RLS — treat as full DB admin credential)',
    regex: /service_role["'\s:=]+["']?eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    severity: 'critical',
  },
  {
    name: 'PEM private key (e.g. GCP/Firebase service account credential)',
    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
  },
];

// Unambiguous placeholder prefixes only. "test" is deliberately excluded here — it's a
// common prefix for real (if lower-stakes) live keys, so it's handled separately below
// with a tighter match that requires the value to *be* a placeholder, not merely start
// with one, avoiding a false negative on real secrets like "testapikeyvalue1234".
const PLACEHOLDER_VALUES = /^(your[-_]?|xxx+|changeme|example|placeholder|<.*>|\.{3,}|dummy)/i;
const TEST_PLACEHOLDER_VALUE = /^test[-_]?(key|token|secret|value|placeholder)?$/i;

function checkGenericAssignedSecret(line: string): { value: string } | null {
  const m = line.match(
    /(api[_-]?key|secret[_-]?key|secret|access[_-]?token|token|password)\s*[:=]\s*([`'"])([^`'"]{16,})\2/i
  );
  if (!m) return null;
  const value = m[3];
  if (PLACEHOLDER_VALUES.test(value)) return null;
  if (TEST_PLACEHOLDER_VALUE.test(value)) return null;
  if (/^(process\.env|import\.meta\.env|Deno\.env)/.test(value)) return null;
  // Skip if the value itself looks like a reference/interpolation rather than a literal.
  if (/[${}]/.test(value)) return null;
  return { value };
}

export function checkHardcodedSecrets(files: RepoFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    // Skip files that are clearly not shipped source (lockfiles, non-credential json)
    // but keep scanning credential-shaped json (service accounts, client secrets).
    if (/\.lock$/.test(file.path)) continue;
    if (
      /\.json$/.test(file.path) &&
      !/package\.json$/.test(file.path) &&
      !CREDENTIAL_JSON_HINT.test(file.path)
    ) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(file.content)) {
        findings.push({
          id: nextId('secret'),
          title: `Possible hardcoded ${pattern.name}`,
          severity: pattern.severity,
          confidence: 'medium',
          explanation: `A string matching the pattern for a ${pattern.name} was found in this file. Verify it isn't a real, live credential committed to source.`,
          file: file.path,
        });
      }
    }

    const lines = file.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const hit = checkGenericAssignedSecret(lines[i]);
      if (hit) {
        findings.push({
          id: nextId('secret-generic'),
          title: 'Variable named like a secret assigned a hardcoded literal',
          severity: 'high',
          confidence: 'low',
          explanation:
            'A variable named like an API key, token, secret, or password is assigned a quoted literal string rather than an environment variable reference. Could be a real leaked credential, or a harmless test fixture — worth a manual look.',
          file: file.path,
          line: i + 1,
        });
        // Cap generic findings per file to avoid spam on one messy file.
        break;
      }
    }
  }

  return findings;
}

// 3. Permissive CORS
export function checkPermissiveCors(files: RepoFile[]): Finding[] {
  const findings: Finding[] = [];
  const patterns = [
    /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/i,
    /origin\s*:\s*['"]\*['"]/i,
    /cors\(\s*\{\s*origin\s*:\s*true/i,
  ];

  for (const file of files) {
    if (patterns.some(re => re.test(file.content))) {
      findings.push({
        id: nextId('cors'),
        title: 'Permissive CORS policy (wildcard origin)',
        severity: 'medium',
        confidence: 'medium',
        explanation:
          'This file sets Access-Control-Allow-Origin to "*" (or an equivalent wildcard/allow-all origin config), which lets any website make authenticated-looking requests to this API from a browser. Fine for a truly public read-only API; risky if any endpoint here handles auth or user data.',
        file: file.path,
      });
    }
  }
  return findings;
}

// 4. Supabase createClient without visible RLS/migration evidence (heuristic)
export function checkSupabaseRLS(tree: string[], files: RepoFile[]): Finding[] {
  const usesSupabaseClient = files.some(
    f => /createClient\s*\(/.test(f.content) && /supabase/i.test(f.content)
  );
  if (!usesSupabaseClient) return [];

  const hasMigrationEvidence = tree.some(isMigrationOrSql);
  const hasPolicyMention = files.some(f =>
    /\brow[- ]level security\b|\bcreate\s+policy\b|\brls\b/i.test(f.content)
  );

  if (hasMigrationEvidence || hasPolicyMention) return [];

  return [
    {
      id: nextId('rls'),
      title: 'Supabase client detected, no migration/RLS evidence found in scanned files',
      severity: 'high',
      confidence: 'low',
      explanation:
        'This repo uses the Supabase client, but no SQL migration files or Row Level Security (RLS) policy references were found among the files this scan sampled. This is a heuristic, not a certainty — RLS may be configured directly in the Supabase dashboard rather than in the repo. Manually verify RLS is enabled on every table with an anon/public key in use: this exact gap caused a real 2026 breach (1.5M leaked API keys) in a vibe-coded app.',
    },
  ];
}

// 5. Missing auth checks near route handlers — weakest heuristic, label clearly.
const ROUTE_HANDLER_PATTERNS = [
  /\bapp\.(get|post|put|delete|patch)\s*\(/,
  /\brouter\.(get|post|put|delete|patch)\s*\(/,
  /export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(/,
  /export\s+default\s+(async\s+)?function\s+handler\s*\(/,
];
const AUTH_HINT_PATTERN = /auth|session|getUser|requireAuth|middleware|verifyToken|jwt|bearer|isAuthenticated|currentUser/i;

const MAX_MISSING_AUTH_FINDINGS = 5;

export function checkMissingAuthHeuristic(files: RepoFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (findings.length >= MAX_MISSING_AUTH_FINDINGS) break;
    const looksLikeRouteFile = ROUTE_HANDLER_PATTERNS.some(re => re.test(file.content));
    if (!looksLikeRouteFile) continue;

    const hasAuthHint = AUTH_HINT_PATTERN.test(file.content);
    if (!hasAuthHint) {
      findings.push({
        id: nextId('auth'),
        title: 'Route handler with no nearby auth/session reference',
        severity: 'low',
        confidence: 'low',
        explanation:
          'LOW CONFIDENCE: this file defines what looks like an API route handler, and no auth/session/middleware-related keyword was found anywhere else in the file. This is a weak signal — the route may be intentionally public, or auth may be enforced elsewhere (e.g. a shared middleware file this scan did not sample). Treat as "worth a manual look," not a confirmed vulnerability.',
        file: file.path,
      });
    }
  }

  return findings;
}

// Each check runs in isolation: if one throws (e.g. an unexpected file shape
// a future change didn't defensively handle), the scan still returns the
// other checks' findings instead of failing the whole request with zero
// results. `failedChecks` lets the caller surface which heuristic(s), if
// any, couldn't complete — same graceful-degradation pattern index.ts
// already uses for the optional live-URL probe.
export function runAllChecks(
  tree: string[],
  files: RepoFile[]
): { findings: Finding[]; failedChecks: string[] } {
  findingCounter = 0; // reset per scan for stable, readable ids

  const checks: { name: string; run: () => Finding[] }[] = [
    { name: 'exposed .env', run: () => checkExposedEnv(tree, files) },
    { name: 'hardcoded secrets', run: () => checkHardcodedSecrets(files) },
    { name: 'permissive CORS', run: () => checkPermissiveCors(files) },
    { name: 'Supabase RLS', run: () => checkSupabaseRLS(tree, files) },
    { name: 'missing auth heuristic', run: () => checkMissingAuthHeuristic(files) },
  ];

  const findings: Finding[] = [];
  const failedChecks: string[] = [];
  for (const check of checks) {
    try {
      findings.push(...check.run());
    } catch (err) {
      console.error(`vibecheck: "${check.name}" check failed, skipping:`, err);
      failedChecks.push(check.name);
    }
  }

  return { findings, failedChecks };
}
