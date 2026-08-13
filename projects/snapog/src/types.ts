// SnapOG — shared types

export type Tier = 'free' | 'pro' | 'business';

export const TIER_LIMITS: Record<Tier, number> = {
  free: 100,
  pro: 10_000,
  business: 100_000,
};

export interface ApiKey {
  id: string;
  user_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  tier: Tier;
  monthly_limit: number;
  usage_count: number;
  usage_reset_at: string;
  created_at: string;
  // Added in migrations/0002_billing.sql — null until a checkout completes.
  stripe_subscription_id?: string | null;
  stripe_subscription_status?: string | null;
}

export interface OGParams {
  title: string;
  description?: string;
  theme?: 'dark' | 'light';
  template?: 'default' | 'blog' | 'article';
  author?: string;
  domain?: string;
  tag?: string;
}

export interface Env {
  DB: D1Database;
  // Optional: `wrangler deploy --temporary` (used for zero-login live demos)
  // doesn't support R2, so caching degrades gracefully to a MISS-only /og
  // path rather than failing the deploy or crashing at request time.
  OG_CACHE?: R2Bucket;
  ENVIRONMENT: string;
  AUTH_SECRET?: string;
  // Stripe billing (all optional, same graceful-degrade pattern as
  // OG_CACHE): a deploy without these set must not crash — see
  // src/billing/stripe.ts's getStripe() and the 503 responses in
  // src/billing/routes.ts. Set via `wrangler secret put` once a real
  // Stripe account exists (see docs/fullstack/snapog-billing-cycle125.md).
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRICE_ID_PRO?: string;
  STRIPE_PRICE_ID_BUSINESS?: string;
}
