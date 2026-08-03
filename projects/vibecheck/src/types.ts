// vibecheck — shared types

export interface Env {
  ENVIRONMENT: string;
  // Optional: raises the GitHub API rate limit from 60 req/hr (unauthenticated)
  // to 5,000 req/hr. Not required for the MVP. Set with:
  //   wrangler secret put GITHUB_TOKEN
  GITHUB_TOKEN?: string;
  // Waitlist store for the "cost + uptime monitoring, coming soon" signup
  // (see docs/ceo/vibecheck-godecision-cycle4.md). Declared in wrangler.toml
  // with a placeholder id — must be created via `wrangler kv:namespace create
  // WAITLIST` and the id filled in before first deploy. Until then this binding
  // is undefined at runtime; the /api/waitlist handler checks for that and
  // no-ops with a logged TODO instead of throwing, so local dev / dry-run
  // never breaks on a missing namespace.
  WAITLIST?: KVNamespace;
}

export interface WaitlistEntry {
  repoUrl: string;
  scannedAt: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  explanation: string;
  file?: string;
  line?: number;
}

export interface RepoRef {
  owner: string;
  repo: string;
}

export interface RepoFile {
  path: string;
  content: string;
}

export interface ScanResult {
  owner: string;
  repo: string;
  defaultBranch: string;
  score: number;
  grade: string;
  findings: Finding[];
  filesScanned: number;
  filesInTree: number;
  scannedAt: string;
  notes: string[];
}

export class ScanError extends Error {
  constructor(
    message: string,
    public status: number
  ) {
    super(message);
    this.name = 'ScanError';
  }
}
