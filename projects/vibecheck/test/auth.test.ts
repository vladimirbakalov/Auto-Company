import { describe, it, expect } from 'vitest';
import {
  generateToken,
  hashToken,
  magicLinkExpiry,
  isExpired,
  isMagicLinkValid,
  signSession,
  verifySession,
  MAGIC_LINK_TTL_MS,
} from '../src/auth';

describe('generateToken', () => {
  it('generates a hex string of the expected length (2 hex chars per byte)', () => {
    const token = generateToken(16);
    expect(token).toMatch(/^[0-9a-f]{32}$/);
  });

  it('generates different tokens on each call', () => {
    const a = generateToken();
    const b = generateToken();
    expect(a).not.toBe(b);
  });
});

describe('hashToken', () => {
  it('produces a deterministic SHA-256 hex digest', async () => {
    const hash1 = await hashToken('same-input');
    const hash2 = await hashToken('same-input');
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces different hashes for different inputs', async () => {
    const hash1 = await hashToken('input-a');
    const hash2 = await hashToken('input-b');
    expect(hash1).not.toBe(hash2);
  });

  it('never returns the raw input', async () => {
    const raw = 'super-secret-token';
    const hash = await hashToken(raw);
    expect(hash).not.toBe(raw);
    expect(hash).not.toContain(raw);
  });
});

describe('magicLinkExpiry / isExpired', () => {
  it('sets expiry MAGIC_LINK_TTL_MS (15 min) in the future', () => {
    const now = Date.parse('2026-08-12T00:00:00.000Z');
    const expiry = magicLinkExpiry(now);
    expect(Date.parse(expiry) - now).toBe(MAGIC_LINK_TTL_MS);
  });

  it('treats a past timestamp as expired', () => {
    expect(isExpired('2026-08-12T00:00:00.000Z', '2026-08-12T00:15:01.000Z')).toBe(true);
  });

  it('treats a future timestamp as not expired', () => {
    expect(isExpired('2026-08-12T00:15:00.000Z', '2026-08-12T00:00:00.000Z')).toBe(false);
  });

  it('treats an exactly-equal timestamp as expired (inclusive boundary)', () => {
    expect(isExpired('2026-08-12T00:15:00.000Z', '2026-08-12T00:15:00.000Z')).toBe(true);
  });
});

describe('isMagicLinkValid', () => {
  const now = '2026-08-12T00:05:00.000Z';

  it('is valid when unused and unexpired', () => {
    const link = { expires_at: '2026-08-12T00:15:00.000Z', used_at: null };
    expect(isMagicLinkValid(link, now)).toBe(true);
  });

  it('is invalid when already used', () => {
    const link = { expires_at: '2026-08-12T00:15:00.000Z', used_at: '2026-08-12T00:01:00.000Z' };
    expect(isMagicLinkValid(link, now)).toBe(false);
  });

  it('is invalid when expired', () => {
    const link = { expires_at: '2026-08-12T00:00:00.000Z', used_at: null };
    expect(isMagicLinkValid(link, now)).toBe(false);
  });
});

describe('signSession / verifySession', () => {
  const secret = 'test-session-secret';

  it('round-trips a signed session payload', async () => {
    const nowMs = Date.parse('2026-08-12T00:00:00.000Z');
    const payload = { userId: 42, expiresAtMs: nowMs + 60_000 };
    const value = await signSession(payload, secret);
    const verified = await verifySession(value, secret, nowMs);
    expect(verified).toEqual(payload);
  });

  it('rejects a tampered payload (userId changed after signing)', async () => {
    const nowMs = Date.parse('2026-08-12T00:00:00.000Z');
    const value = await signSession({ userId: 42, expiresAtMs: nowMs + 60_000 }, secret);
    const [, expiresAtMsStr, sig] = value.split('.');
    const tampered = `999.${expiresAtMsStr}.${sig}`;
    expect(await verifySession(tampered, secret, nowMs)).toBeNull();
  });

  it('rejects a value signed with a different secret', async () => {
    const nowMs = Date.parse('2026-08-12T00:00:00.000Z');
    const value = await signSession({ userId: 42, expiresAtMs: nowMs + 60_000 }, secret);
    expect(await verifySession(value, 'wrong-secret', nowMs)).toBeNull();
  });

  it('rejects an expired session', async () => {
    const nowMs = Date.parse('2026-08-12T00:00:00.000Z');
    const value = await signSession({ userId: 42, expiresAtMs: nowMs - 1 }, secret);
    expect(await verifySession(value, secret, nowMs)).toBeNull();
  });

  it('rejects a malformed value', async () => {
    expect(await verifySession('not-a-valid-session-value', secret)).toBeNull();
  });
});
