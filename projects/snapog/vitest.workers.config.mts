// Separate config for tests that run inside real workerd via Miniflare,
// exercising the actual D1/R2 bindings instead of the hand-rolled
// in-memory stand-ins used by the default `vitest run` suite (see the
// comment at the top of test/index.test.ts). Run with `npm run test:workers`.
// Kept isolated from the default config/suite so the fast plain-vitest
// suite (test/*.test.ts) is untouched and still runs with zero workerd
// startup cost.
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
          // Test-only binding for migrations, applied in test/workers-setup.ts
          bindings: { TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      include: ['test/**/*.workers.test.ts'],
      setupFiles: ['./test/workers-setup.ts'],
    },
  };
});
