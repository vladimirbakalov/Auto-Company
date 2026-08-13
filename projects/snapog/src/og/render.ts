// SnapOG — OG image renderer
// Uses workers-og (Satori + resvg-wasm, CF Workers compatible)

import { buildElement } from './templates';
import type { OGParams } from '../types';

const OG_WIDTH = 1200;
const OG_HEIGHT = 630;

export async function generateOGImage(
  params: OGParams,
  watermark: boolean
): Promise<Response> {
  const element = buildElement(params, watermark);

  // Lazy-imported: workers-og pulls in a WASM binary that only resolves
  // under the Workers runtime (or a bundler that inlines it), not plain
  // Node — keeping it out of this module's top-level import lets
  // buildCacheKey below be imported/tested in isolation (e.g. plain
  // vitest) without dragging the renderer's WASM dependency along.
  const { ImageResponse } = await import('workers-og');
  const response = new ImageResponse(element, {
    width: OG_WIDTH,
    height: OG_HEIGHT,
  });

  return response;
}

// Build a deterministic cache key from OG params
export async function buildCacheKey(params: OGParams, watermark: boolean): Promise<string> {
  const sorted = JSON.stringify(
    Object.fromEntries(
      Object.entries({ ...params, watermark }).sort(([a], [b]) => a.localeCompare(b))
    )
  );
  const encoder = new TextEncoder();
  const data = encoder.encode(sorted);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
