// vibecheck — minimal auth: magic links + API keys + signed session cookie
//
// Per ADR §5: no password auth. Identity is anchored to email + Stripe
// customer; a magic-link email grants a signed session cookie, and an
// optional API key covers programmatic access. Nothing here is a general
// identity system — it's the smallest thing that supports "pay → get a
// dashboard → manage monitors."
//
// Split the same way as monitors.ts: pure token/hash/expiry/signing
// functions (testable without D1) vs. thin D1-touching wrappers. The D1
// wrappers are real implementations, not stubs, EXCEPT where explicitly
// marked STUB below — those need a live D1 binding to actually exercise and
// are out of this change's test surface (no miniflare/D1 simulation wired
// into vitest here), so they're flagged rather than silently assumed-correct.

import type { UserRow } from './types';

// ── Pure: token generation, hashing, expiry ─────────────────────────────────

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Cryptographically random, URL-safe-ish hex token. Used both for magic-link
// tokens and raw API keys — same shape, different table/prefix at the call
// site.
export function generateToken(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return toHex(arr);
}

// SHA-256 hex digest — we store only the hash of a magic-link/API-key token,
// never the raw value, so a D1 read (or backup leak) doesn't hand out live
// credentials. Web Crypto (`crypto.subtle`) is available in both the Workers
// runtime and modern Node, so this needs no polyfill for tests.
export async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return toHex(new Uint8Array(digest));
}

export const MAGIC_LINK_TTL_MS = 15 * 60 * 1000; // 15 minutes, per ADR §5

export function magicLinkExpiry(nowMs: number = Date.now()): string {
  return new Date(nowMs + MAGIC_LINK_TTL_MS).toISOString();
}

export function isExpired(expiresAtIso: string, nowIso: string = new Date().toISOString()): boolean {
  return expiresAtIso <= nowIso;
}

// A magic link is usable iff unexpired and not yet used.
export function isMagicLinkValid(link: { expires_at: string; used_at: string | null }, nowIso: string = new Date().toISOString()): boolean {
  return link.used_at === null && !isExpired(link.expires_at, nowIso);
}

// ── Pure: signed session cookie value ───────────────────────────────────────
// A small HMAC-signed "userId.expiresAtMs.signature" value — no external JWT
// library needed, Web Crypto's HMAC covers this in one primitive.

export interface SessionPayload {
  userId: number;
  expiresAtMs: number;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

export async function signSession(payload: SessionPayload, secret: string): Promise<string> {
  const body = `${payload.userId}.${payload.expiresAtMs}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  return `${body}.${toHex(new Uint8Array(sig))}`;
}

// Returns the payload if the signature verifies and it isn't expired, else null.
export async function verifySession(value: string, secret: string, nowMs: number = Date.now()): Promise<SessionPayload | null> {
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  const [userIdStr, expiresAtMsStr, sigHex] = parts;
  const body = `${userIdStr}.${expiresAtMsStr}`;
  const key = await hmacKey(secret);
  const expectedSig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const expectedHex = toHex(new Uint8Array(expectedSig));
  if (expectedHex !== sigHex) return null;

  const userId = Number(userIdStr);
  const expiresAtMs = Number(expiresAtMsStr);
  if (!Number.isFinite(userId) || !Number.isFinite(expiresAtMs)) return null;
  if (expiresAtMs <= nowMs) return null;
  return { userId, expiresAtMs };
}

export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// ── D1-touching wrappers ─────────────────────────────────────────────────────

// STUB: real implementation is a straightforward upsert-by-email, but it's
// untested against a live D1 in this change (no miniflare/D1 pool wired into
// vitest yet — see note at top of file). Wire up + integration-test once a
// local D1 test harness exists; the SQL shape below is what ADR §5/§6 step 2
// specifies (upsert on `checkout.session.completed`).
export async function upsertUserFromCheckout(
  db: D1Database,
  params: { email: string; stripeCustomerId: string; stripeSubscriptionId: string | null }
): Promise<UserRow> {
  const nowIso = new Date().toISOString();
  const row = await db
    .prepare(
      `INSERT INTO users (email, stripe_customer_id, stripe_subscription_id, subscription_status, created_at)
       VALUES (?1, ?2, ?3, 'active', ?4)
       ON CONFLICT(email) DO UPDATE SET
         stripe_customer_id = excluded.stripe_customer_id,
         stripe_subscription_id = excluded.stripe_subscription_id,
         subscription_status = 'active'
       RETURNING *`
    )
    .bind(params.email, params.stripeCustomerId, params.stripeSubscriptionId, nowIso)
    .first<UserRow>();
  if (!row) throw new Error('Failed to upsert user');
  return row;
}

export async function updateSubscriptionStatus(
  db: D1Database,
  stripeCustomerId: string,
  status: UserRow['subscription_status']
): Promise<void> {
  await db
    .prepare('UPDATE users SET subscription_status = ?1 WHERE stripe_customer_id = ?2')
    .bind(status, stripeCustomerId)
    .run();
}

export async function createMagicLink(db: D1Database, userId: number): Promise<{ token: string; expiresAt: string }> {
  const token = generateToken();
  const tokenHash = await hashToken(token);
  const expiresAt = magicLinkExpiry();
  await db
    .prepare('INSERT INTO magic_links (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)')
    .bind(tokenHash, userId, expiresAt)
    .run();
  return { token, expiresAt };
}

// Validates a raw magic-link token against D1: looks up by hash, checks
// validity (pure isMagicLinkValid), and marks it used. Returns the user id on
// success, null on any failure (not found, expired, already used).
export async function validateAndConsumeMagicLink(db: D1Database, token: string): Promise<number | null> {
  const tokenHash = await hashToken(token);
  const link = await db
    .prepare('SELECT * FROM magic_links WHERE token_hash = ?1')
    .bind(tokenHash)
    .first<{ token_hash: string; user_id: number; expires_at: string; used_at: string | null }>();
  if (!link) return null;

  const nowIso = new Date().toISOString();
  if (!isMagicLinkValid(link, nowIso)) return null;

  await db.prepare('UPDATE magic_links SET used_at = ?1 WHERE token_hash = ?2').bind(nowIso, tokenHash).run();
  return link.user_id;
}

// STUB: generates + stores a new API key, replacing any previous one (single
// key per user, per ADR §5 — "generate on first dashboard visit, shown once,
// stored hashed"). Not integration-tested against live D1 in this change;
// the hashing/generation halves it calls (generateToken/hashToken) are.
export async function generateAndStoreApiKey(db: D1Database, userId: number): Promise<string> {
  const key = generateToken(24);
  const hash = await hashToken(key);
  await db.prepare('UPDATE users SET api_key_hash = ?1 WHERE id = ?2').bind(hash, userId).run();
  return key;
}

export async function findUserByApiKey(db: D1Database, apiKey: string): Promise<UserRow | null> {
  const hash = await hashToken(apiKey);
  const user = await db.prepare('SELECT * FROM users WHERE api_key_hash = ?1').bind(hash).first<UserRow>();
  return user ?? null;
}

// Resolves a Stripe customer id to a user row — used by the webhook's
// `past_due` handler (index.ts) to find an email address to notify, since
// the `invoice.payment_failed`/`customer.subscription.updated` events only
// carry `customer`, not an email.
export async function findUserByStripeCustomerId(db: D1Database, stripeCustomerId: string): Promise<UserRow | null> {
  const user = await db
    .prepare('SELECT * FROM users WHERE stripe_customer_id = ?1')
    .bind(stripeCustomerId)
    .first<UserRow>();
  return user ?? null;
}

// Resolves a user id to just their email — used by the scheduled monitor
// fan-out (index.ts) to notify a monitor's owner on down/recovered
// transitions. Monitors already carry `user_id` (migrations/0001_init.sql
// FK), so this is a single-row lookup by primary key, not a join.
export async function findUserEmailById(db: D1Database, userId: number): Promise<string | null> {
  const user = await db.prepare('SELECT email FROM users WHERE id = ?1').bind(userId).first<{ email: string }>();
  return user?.email ?? null;
}
