import { defaultExclude, defineConfig } from 'vitest/config';

// Plain-vitest suite (fast, no workerd). The real-D1/KV suite
// (test/*.workers.test.ts) requires the @cloudflare/vitest-pool-workers
// plugin/pool and has its own config — see vitest.workers.config.mts and
// `npm run test:workers`.
export default defineConfig({
  test: {
    exclude: [...defaultExclude, 'test/**/*.workers.test.ts'],
  },
});
