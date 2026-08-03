// vibecheck — shared types

export interface Env {
  ENVIRONMENT: string;
  // Optional: raises the GitHub API rate limit from 60 req/hr (unauthenticated)
  // to 5,000 req/hr. Not required for the MVP. Set with:
  //   wrangler secret put GITHUB_TOKEN
  GITHUB_TOKEN?: string;
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
