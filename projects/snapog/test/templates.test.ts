// buildElement — template selection + content wiring for OG image VNodes.
// These are pure object-tree builders (no rendering/WASM involved), so they
// can be asserted on directly without needing the Workers runtime.

import { describe, it, expect } from 'vitest';
import { buildElement } from '../src/og/templates';
import type { OGParams } from '../src/types';

// Depth-first search for a child whose `children` is the given string.
function findText(node: unknown, text: string): boolean {
  if (node == null) return false;
  if (typeof node === 'string') return node === text;
  if (Array.isArray(node)) return node.some(n => findText(n, text));
  if (typeof node === 'object' && 'props' in (node as Record<string, unknown>)) {
    const props = (node as { props?: { children?: unknown } }).props;
    return findText(props?.children, text);
  }
  return false;
}

describe('buildElement', () => {
  const base: OGParams = { title: 'Ship it' };

  it('defaults to the default template when template is unset', () => {
    const el = buildElement(base, false);
    expect(findText(el, 'Ship it')).toBe(true);
  });

  it('selects the blog template', () => {
    const el = buildElement({ ...base, template: 'blog' }, false);
    expect(findText(el, 'Ship it')).toBe(true);
  });

  it('selects the article template', () => {
    const el = buildElement({ ...base, template: 'article' }, false);
    expect(findText(el, 'Ship it')).toBe(true);
  });

  it('includes the description when provided', () => {
    const el = buildElement({ ...base, description: 'A great release' }, false);
    expect(findText(el, 'A great release')).toBe(true);
  });

  it('omits the watermark for paid tiers (watermark=false)', () => {
    const el = buildElement(base, false);
    expect(findText(el, 'snapog.dev')).toBe(false);
  });

  it('shows the watermark for the free tier (watermark=true)', () => {
    const el = buildElement(base, true);
    expect(findText(el, 'snapog.dev')).toBe(true);
  });

  it('prefixes author with an em dash when provided', () => {
    const el = buildElement({ ...base, author: 'Ada Lovelace' }, false);
    expect(findText(el, '— Ada Lovelace')).toBe(true);
  });

  it('does not throw for every template x watermark combination', () => {
    const templates: Array<OGParams['template']> = [undefined, 'default', 'blog', 'article'];
    for (const template of templates) {
      for (const watermark of [true, false]) {
        expect(() => buildElement({ ...base, template }, watermark)).not.toThrow();
      }
    }
  });
});
