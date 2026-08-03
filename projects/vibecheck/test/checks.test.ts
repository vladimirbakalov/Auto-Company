import { describe, it, expect } from 'vitest';
import {
  selectCandidateFiles,
  checkExposedEnv,
  checkHardcodedSecrets,
  checkPermissiveCors,
  checkSupabaseRLS,
  checkMissingAuthHeuristic,
  runAllChecks,
} from '../src/checks';
import type { RepoFile } from '../src/types';

function file(path: string, content: string): RepoFile {
  return { path, content };
}

describe('selectCandidateFiles', () => {
  it('always includes .env/.gitignore/package.json regardless of extension', () => {
    const tree = ['README.md', '.env', '.gitignore', 'package.json', 'src/index.ts'];
    const result = selectCandidateFiles(tree);
    expect(result).toContain('.env');
    expect(result).toContain('.gitignore');
    expect(result).toContain('package.json');
    // README.md is neither an always-include basename nor a source extension.
    expect(result).not.toContain('README.md');
  });

  it('caps migration/sql files at 8', () => {
    const migrations = Array.from({ length: 12 }, (_, i) => `migrations/${i}.sql`);
    const result = selectCandidateFiles(migrations);
    const migrationHits = result.filter(p => p.startsWith('migrations/'));
    expect(migrationHits).toHaveLength(8);
  });

  it('prioritizes source files whose path matches more priority hints', () => {
    const tree = ['src/utils.ts', 'src/routes/auth.ts'];
    const result = selectCandidateFiles(tree);
    // auth.ts matches both "route" and "auth" hints, utils.ts matches none.
    expect(result.indexOf('src/routes/auth.ts')).toBeLessThan(result.indexOf('src/utils.ts'));
  });

  it('deduplicates paths that would otherwise appear twice', () => {
    const tree = ['.env', '.env'];
    const result = selectCandidateFiles(tree);
    expect(result.filter(p => p === '.env')).toHaveLength(1);
  });

  it('excludes non-source, non-always-include files entirely', () => {
    const tree = ['image.png', 'notes.txt'];
    expect(selectCandidateFiles(tree)).toEqual([]);
  });

  it('includes credential-shaped JSON files (service accounts, client secrets)', () => {
    const tree = [
      'config/my-app-firebase-adminsdk-x1y2z.json',
      'secrets/service-account.json',
      'client_secret_123.json',
      'package-lock.json',
      'tsconfig.json',
    ];
    const result = selectCandidateFiles(tree);
    expect(result).toContain('config/my-app-firebase-adminsdk-x1y2z.json');
    expect(result).toContain('secrets/service-account.json');
    expect(result).toContain('client_secret_123.json');
    expect(result).not.toContain('package-lock.json');
    expect(result).not.toContain('tsconfig.json');
  });
});

describe('checkExposedEnv', () => {
  it('returns no findings when .env is not in the tree', () => {
    expect(checkExposedEnv(['src/index.ts'], [])).toEqual([]);
  });

  it('flags .env as critical when no .gitignore is present', () => {
    const findings = checkExposedEnv(['.env'], []);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].confidence).toBe('high');
  });

  it('flags .env as critical when .gitignore exists but does not exclude it', () => {
    const gitignore = file('.gitignore', 'node_modules\n.env.local\ndist\n');
    const findings = checkExposedEnv(['.env'], [gitignore]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('downgrades to medium when .gitignore explicitly excludes .env', () => {
    const gitignore = file('.gitignore', 'node_modules\n.env\ndist\n');
    const findings = checkExposedEnv(['.env'], [gitignore]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].confidence).toBe('medium');
  });

  it('does not treat .env.example as the exposed .env file', () => {
    expect(checkExposedEnv(['.env.example'], [])).toEqual([]);
  });

  it('detects a nested .env path (server/.env)', () => {
    const findings = checkExposedEnv(['server/.env'], []);
    expect(findings).toHaveLength(1);
  });

  it('downgrades to medium when .gitignore excludes .env via a .env* wildcard', () => {
    const gitignore = file('.gitignore', 'node_modules\n.env*\ndist\n');
    const findings = checkExposedEnv(['.env'], [gitignore]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('medium');
  });
});

describe('checkHardcodedSecrets', () => {
  it('flags an AWS access key ID', () => {
    const findings = checkHardcodedSecrets([file('src/a.ts', 'const key = "AKIAABCDEFGHIJKLMNOP";')]);
    expect(findings.some(f => f.title.includes('AWS Access Key ID'))).toBe(true);
  });

  it('flags a Stripe live secret key as critical but a test key as low severity', () => {
    const live = checkHardcodedSecrets([file('a.ts', 'sk_' + 'live_abcdefghijklmnopqrstuvwx')]);
    const test = checkHardcodedSecrets([file('b.ts', 'sk_' + 'test_abcdefghijklmnopqrstuvwx')]);
    expect(live.find(f => f.title.includes('Stripe live secret key'))?.severity).toBe('critical');
    expect(test.find(f => f.title.includes('Stripe test key'))?.severity).toBe('low');
  });

  it('flags a Supabase service_role key', () => {
    const content = `service_role: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0"`;
    const findings = checkHardcodedSecrets([file('config.ts', content)]);
    expect(findings.some(f => f.title.includes('service_role'))).toBe(true);
  });

  it('flags a generic hardcoded secret-like variable assignment', () => {
    const findings = checkHardcodedSecrets([
      file('src/client.ts', 'const apiKey = "abcdefghij1234567890";'),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].confidence).toBe('low');
    expect(findings[0].line).toBe(1);
  });

  it('does not flag placeholder values like "your_api_key_here"', () => {
    const findings = checkHardcodedSecrets([
      file('src/client.ts', 'const apiKey = "your_api_key_here";'),
    ]);
    expect(findings).toEqual([]);
  });

  it('does not flag values that start with the word "test" even outside sk_test_', () => {
    const findings = checkHardcodedSecrets([
      file('src/client.ts', 'const token = "testapikeyvalue1234";'),
    ]);
    expect(findings).toEqual([]);
  });

  it('does not flag values that are environment variable references', () => {
    const findings = checkHardcodedSecrets([
      file('src/client.ts', 'const secretKey = "process.env.SECRET_KEY_LOOKS_LONG";'),
    ]);
    expect(findings).toEqual([]);
  });

  it('does not flag interpolated template values', () => {
    const findings = checkHardcodedSecrets([
      file('src/client.ts', 'const token = "${SOME_TOKEN_VALUE_HERE}";'),
    ]);
    expect(findings).toEqual([]);
  });

  it('caps generic secret findings at one per file even with multiple hits', () => {
    const content = [
      'const apiKey = "abcdefghij1234567890";',
      'const secret = "zzzzzzzzzzzzzzzzzzzz";',
    ].join('\n');
    const findings = checkHardcodedSecrets([file('src/client.ts', content)]);
    expect(findings.filter(f => f.title.includes('Variable named like a secret'))).toHaveLength(1);
  });

  it('does not cap distinct SECRET_PATTERNS hits in the same file', () => {
    const content = 'AKIAABCDEFGHIJKLMNOP and sk_' + 'live_abcdefghijklmnopqrstuvwx';
    const findings = checkHardcodedSecrets([file('src/multi.ts', content)]);
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it('skips lockfiles and non-package.json JSON files', () => {
    const findings = checkHardcodedSecrets([
      file('package-lock.json', 'AKIAABCDEFGHIJKLMNOP'),
      file('config.json', 'AKIAABCDEFGHIJKLMNOP'),
      file('yarn.lock', 'AKIAABCDEFGHIJKLMNOP'),
    ]);
    expect(findings).toEqual([]);
  });

  it('still scans package.json itself', () => {
    const findings = checkHardcodedSecrets([file('package.json', 'AKIAABCDEFGHIJKLMNOP')]);
    expect(findings).toHaveLength(1);
  });

  it('scans credential-shaped JSON files (GCP/Firebase service accounts)', () => {
    const findings = checkHardcodedSecrets([
      file(
        'config/my-app-firebase-adminsdk-x1y2z.json',
        '{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBg==\\n-----END PRIVATE KEY-----\\n"}'
      ),
    ]);
    expect(findings.some(f => f.title.includes('PEM private key'))).toBe(true);
  });

  it('flags a PEM private key in any source file, not just credential JSON', () => {
    const findings = checkHardcodedSecrets([
      file('scripts/deploy.ts', 'const key = `-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END RSA PRIVATE KEY-----`;'),
    ]);
    expect(findings.some(f => f.title.includes('PEM private key'))).toBe(true);
  });
});

describe('checkPermissiveCors', () => {
  it('flags Access-Control-Allow-Origin: *', () => {
    const findings = checkPermissiveCors([
      file('src/mw.ts', 'res.headers.set("Access-Control-Allow-Origin", "*");'),
    ]);
    expect(findings).toHaveLength(1);
  });

  it('flags origin: "*" style cors config', () => {
    const findings = checkPermissiveCors([file('src/mw.ts', "app.use(cors({ origin: '*' }));")]);
    expect(findings).toHaveLength(1);
  });

  it('flags cors({ origin: true ... })', () => {
    const findings = checkPermissiveCors([file('src/mw.ts', 'app.use(cors({ origin: true }));')]);
    expect(findings).toHaveLength(1);
  });

  it('does not flag a specific allowed origin', () => {
    const findings = checkPermissiveCors([
      file('src/mw.ts', "app.use(cors({ origin: 'https://example.com' }));"),
    ]);
    expect(findings).toEqual([]);
  });

  it('flags a lowercase access-control-allow-origin header name', () => {
    const findings = checkPermissiveCors([
      file('src/mw.ts', 'res.headers.set("access-control-allow-origin", "*");'),
    ]);
    expect(findings).toHaveLength(1);
  });
});

describe('checkSupabaseRLS', () => {
  it('returns no findings when supabase client is not used', () => {
    expect(checkSupabaseRLS([], [file('src/a.ts', 'createClient(url, key);')])).toEqual([]);
  });

  it('requires createClient and "supabase" mention in the SAME file', () => {
    const files = [
      file('src/db.ts', 'createClient(url, key);'), // no mention of supabase here
      file('src/notes.ts', 'we use supabase for auth'), // mentions supabase, no createClient
    ];
    expect(checkSupabaseRLS([], files)).toEqual([]);
  });

  it('flags supabase client usage with no migration or RLS evidence', () => {
    const files = [file('src/db.ts', "import { createClient } from '@supabase/supabase-js';\ncreateClient(url, key);")];
    const findings = checkSupabaseRLS(['src/db.ts'], files);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].confidence).toBe('low');
  });

  it('does not flag when a migration file is present in the tree', () => {
    const files = [file('src/db.ts', "createClient(url, key); // supabase")];
    const tree = ['src/db.ts', 'supabase/migrations/001_init.sql'];
    expect(checkSupabaseRLS(tree, files)).toEqual([]);
  });

  it('does not flag when a policy/RLS mention exists in scanned files', () => {
    const files = [
      file('src/db.ts', 'createClient(url, key); // supabase'),
      file('docs/notes.md', 'We enabled row level security on all tables.'),
    ];
    expect(checkSupabaseRLS(['src/db.ts'], files)).toEqual([]);
  });

  it('still flags when the only "policy" mention is unrelated (cookie policy)', () => {
    const files = [
      file('src/db.ts', 'createClient(url, key); // supabase'),
      file('docs/notes.md', 'See our cookie policy and retry policy for details.'),
    ];
    expect(checkSupabaseRLS(['src/db.ts'], files)).toHaveLength(1);
  });

  it('does not flag when a CREATE POLICY statement is present', () => {
    const files = [
      file('src/db.ts', 'createClient(url, key); // supabase'),
      file('scripts/setup.sql', 'create policy "allow read" on public.items for select using (true);'),
    ];
    expect(checkSupabaseRLS(['src/db.ts'], files)).toEqual([]);
  });
});

describe('checkMissingAuthHeuristic', () => {
  it('flags a route handler with no auth hint', () => {
    const findings = checkMissingAuthHeuristic([
      file('src/routes/data.ts', "app.get('/data', (req, res) => { res.send(items); });"),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].confidence).toBe('low');
  });

  it('does not flag a route handler that references auth', () => {
    const findings = checkMissingAuthHeuristic([
      file('src/routes/data.ts', "app.get('/data', requireAuth, (req, res) => { res.send(items); });"),
    ]);
    expect(findings).toEqual([]);
  });

  it('does not flag files with no route handler pattern', () => {
    const findings = checkMissingAuthHeuristic([file('src/utils.ts', 'export const add = (a, b) => a + b;')]);
    expect(findings).toEqual([]);
  });

  it('caps findings at 5 even with more qualifying files', () => {
    const files = Array.from({ length: 8 }, (_, i) =>
      file(`src/routes/r${i}.ts`, `app.get('/r${i}', (req, res) => res.send('ok'));`)
    );
    expect(checkMissingAuthHeuristic(files)).toHaveLength(5);
  });
});

describe('runAllChecks', () => {
  it('combines findings from every check', () => {
    const tree = ['.env'];
    const files = [file('.gitignore', 'node_modules\n')];
    const findings = runAllChecks(tree, files);
    expect(findings.some(f => f.title.includes('.env'))).toBe(true);
  });

  it('resets finding ids to start fresh on each call', () => {
    const first = runAllChecks(['.env'], []);
    const second = runAllChecks(['.env'], []);
    expect(first[0].id).toBe(second[0].id);
  });
});
