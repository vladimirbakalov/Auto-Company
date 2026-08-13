-- SnapOG D1 Schema
-- Migration 0002: Stripe billing linkage
--
-- Minimal columns needed to reconcile Stripe webhook events back to the
-- right user/api_key row — not a generic billing system. Tier is still
-- tracked on api_keys (unchanged from 0001); these columns just let the
-- webhook handler (src/billing/routes.ts) find the right row and record
-- enough Stripe state to react to plan changes and cancellations.

-- One Stripe Customer per SnapOG user (created lazily on first checkout).
ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;

-- Subscription linkage lives on the api_key row (not users) because tier/
-- monthly_limit already live there per-key, not per-user.
ALTER TABLE api_keys ADD COLUMN stripe_subscription_id TEXT;
-- Mirrors Stripe's subscription.status (active | past_due | canceled | ...).
-- Kept even when it doesn't (yet) change the tier, so a human can see why a
-- key is stuck at its current tier (e.g. 'past_due' during dunning).
ALTER TABLE api_keys ADD COLUMN stripe_subscription_status TEXT;

CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_stripe_subscription ON api_keys(stripe_subscription_id);
