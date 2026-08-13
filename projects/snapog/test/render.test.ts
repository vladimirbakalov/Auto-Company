// buildCacheKey — deterministic hashing used for R2 cache keys (src/index.ts
// builds `og/${cacheKey}.png` from this). Correctness here matters because a
// non-deterministic or colliding key would silently serve the wrong cached
// image for a different title/theme/tier combination.

import { describe, it, expect } from 'vitest';
import { buildCacheKey } from '../src/og/render';
import type { OGParams } from '../src/types';

const BASE: OGParams = { title: 'Hello world' };

describe('buildCacheKey', () => {
  it('is deterministic for identical params', async () => {
    const a = await buildCacheKey(BASE, false);
    const b = await buildCacheKey(BASE, false);
    expect(a).toBe(b);
  });

  it('is stable regardless of key insertion order', async () => {
    const p1: OGParams = { title: 'Hello world', theme: 'dark', tag: 'news' };
    const p2: OGParams = { tag: 'news', theme: 'dark', title: 'Hello world' };
    expect(await buildCacheKey(p1, false)).toBe(await buildCacheKey(p2, false));
  });

  it('differs when the watermark flag differs', async () => {
    const withWatermark = await buildCacheKey(BASE, true);
    const withoutWatermark = await buildCacheKey(BASE, false);
    expect(withWatermark).not.toBe(withoutWatermark);
  });

  it('differs when any param field differs', async () => {
    const base = await buildCacheKey(BASE, false);
    const differentTitle = await buildCacheKey({ ...BASE, title: 'Goodbye world' }, false);
    const differentTheme = await buildCacheKey({ ...BASE, theme: 'light' }, false);
    const differentTemplate = await buildCacheKey({ ...BASE, template: 'blog' }, false);
    expect(differentTitle).not.toBe(base);
    expect(differentTheme).not.toBe(base);
    expect(differentTemplate).not.toBe(base);
  });

  it('produces a 64-char lowercase hex SHA-256 digest', async () => {
    const key = await buildCacheKey(BASE, false);
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });
});
