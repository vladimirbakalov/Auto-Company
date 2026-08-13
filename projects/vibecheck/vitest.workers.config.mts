// Separate config for tests that run inside real workerd via Miniflare,
// exercising the actual D1/KV bindings instead of the hand-rolled mocks the
// default `vitest run` suite uses. Same pattern as projects/snapog (see that
// project's vitest.workers.config.mts for the reference version this was
// copied from — proven working there first). Run with `npm run test:workers`.
// Kept isolated from the default config/suite so the fast plain-vitest suite
// (test/*.test.ts) is untouched and still runs with zero workerd startup cost.
import path from 'node:path';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const migrationsPath = path.join(import.meta.dirname, 'migrations');

export default defineConfig(async () => {
  const migrations = await readD1Migrations(migrationsPath);
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          // Test-only bindings: TEST_MIGRATIONS applied in workers-setup.ts,
          // SESSION_SECRET because it's a `wrangler secret` in real
          // deployments (not in wrangler.toml [vars]) and the session-cookie
          // auth path under test needs a real value to sign/verify against.
          // ADMIN_STATS_KEY (Cycle #126 analytics, `wrangler secret put
          // ADMIN_STATS_KEY` in real deployments) is here for the same
          // reason — GET /admin/stats' auth path under test needs a real
          // value to compare against.
          bindings: { TEST_MIGRATIONS: migrations, SESSION_SECRET: 'test-session-secret', ADMIN_STATS_KEY: 'test-admin-stats-key' },
        },
      }),
    ],
    test: {
      include: ['test/**/*.workers.test.ts'],
      setupFiles: ['./test/workers-setup.ts'],
    },
  };
});
