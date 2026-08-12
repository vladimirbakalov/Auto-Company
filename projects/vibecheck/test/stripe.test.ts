import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  verifyStripeSignature,
  createStripeGateway,
  routeStripeEvent,
  type StripeWebhookEvent,
} from '../src/stripe';

async function signPayload(payload: string, secret: string, timestamp: number): Promise<string> {
  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const hex = Array.from(new Uint8Array(sigBytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `t=${timestamp},v1=${hex}`;
}

describe('verifyStripeSignature', () => {
  const secret = 'whsec_test_secret';
  const payload = JSON.stringify({ id: 'evt_123', type: 'checkout.session.completed' });

  it('accepts a correctly signed payload within the tolerance window', async () => {
    const nowMs = Date.parse('2026-08-12T00:00:00.000Z');
    const header = await signPayload(payload, secret, Math.floor(nowMs / 1000));
    const valid = await verifyStripeSignature(payload, header, secret, nowMs);
    expect(valid).toBe(true);
  });

  it('rejects a payload signed with the wrong secret', async () => {
    const nowMs = Date.parse('2026-08-12T00:00:00.000Z');
    const header = await signPayload(payload, 'wrong_secret', Math.floor(nowMs / 1000));
    const valid = await verifyStripeSignature(payload, header, secret, nowMs);
    expect(valid).toBe(false);
  });

  it('rejects a tampered payload (signature no longer matches body)', async () => {
    const nowMs = Date.parse('2026-08-12T00:00:00.000Z');
    const header = await signPayload(payload, secret, Math.floor(nowMs / 1000));
    const tamperedPayload = JSON.stringify({ id: 'evt_999', type: 'checkout.session.completed' });
    const valid = await verifyStripeSignature(tamperedPayload, header, secret, nowMs);
    expect(valid).toBe(false);
  });

  it('rejects a signature outside the replay-protection tolerance window', async () => {
    const signedAtMs = Date.parse('2026-08-12T00:00:00.000Z');
    const header = await signPayload(payload, secret, Math.floor(signedAtMs / 1000));
    const farFutureMs = signedAtMs + 10 * 60 * 1000; // 10 minutes later, default tolerance is 5 min
    const valid = await verifyStripeSignature(payload, header, secret, farFutureMs);
    expect(valid).toBe(false);
  });

  it('rejects a malformed signature header', async () => {
    const valid = await verifyStripeSignature(payload, 'not-a-valid-header', secret);
    expect(valid).toBe(false);
  });
});

describe('createStripeGateway.createCheckoutSession', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs to the Stripe checkout sessions endpoint and returns id/url', async () => {
    global.fetch = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://api.stripe.com/v1/checkout/sessions');
      expect(init?.headers).toMatchObject({ Authorization: 'Bearer sk_test_fake' });
      expect(String(init?.body)).toContain('mode=subscription');
      return new Response(JSON.stringify({ id: 'cs_test_123', url: 'https://checkout.stripe.com/pay/cs_test_123' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const gateway = createStripeGateway('sk_test_fake', 'whsec_fake');
    const session = await gateway.createCheckoutSession({
      priceId: 'price_123',
      successUrl: 'https://vibecheck.dev/success',
      cancelUrl: 'https://vibecheck.dev/cancel',
    });

    expect(session).toEqual({ id: 'cs_test_123', url: 'https://checkout.stripe.com/pay/cs_test_123' });
  });

  it('throws with a readable message on a non-2xx Stripe response', async () => {
    global.fetch = vi.fn(async () => new Response('bad request', { status: 400 })) as unknown as typeof fetch;
    const gateway = createStripeGateway('sk_test_fake', 'whsec_fake');
    await expect(
      gateway.createCheckoutSession({
        priceId: 'price_123',
        successUrl: 'https://vibecheck.dev/success',
        cancelUrl: 'https://vibecheck.dev/cancel',
      })
    ).rejects.toThrow(/Stripe checkout session creation failed \(400\)/);
  });
});

describe('routeStripeEvent', () => {
  // Hand-constructed payload matching Stripe's documented
  // checkout.session.completed shape
  // (https://stripe.com/docs/api/checkout/sessions/object,
  // https://stripe.com/docs/webhooks#example-payloads) — trimmed to the
  // fields this router actually reads.
  it('routes checkout.session.completed to a user upsert', () => {
    const event: StripeWebhookEvent = {
      id: 'evt_1NcJ2f2eZvKYlo2CxYzABC1',
      type: 'checkout.session.completed',
      api_version: '2024-06-20',
      created: 1692000000,
      data: {
        object: {
          id: 'cs_test_a1b2c3',
          object: 'checkout.session',
          customer: 'cus_ABC123',
          customer_email: 'founder@example.com',
          customer_details: { email: 'founder@example.com' },
          mode: 'subscription',
          payment_status: 'paid',
          subscription: 'sub_XYZ789',
        },
      },
    } as unknown as StripeWebhookEvent;

    const action = routeStripeEvent(event);
    expect(action).toEqual({
      kind: 'upsert_user_from_checkout',
      email: 'founder@example.com',
      stripeCustomerId: 'cus_ABC123',
      stripeSubscriptionId: 'sub_XYZ789',
    });
  });

  it('falls back to customer_details.email when customer_email is null', () => {
    const event: StripeWebhookEvent = {
      type: 'checkout.session.completed',
      data: {
        object: {
          customer: 'cus_ABC123',
          customer_email: null,
          customer_details: { email: 'fallback@example.com' },
          subscription: 'sub_XYZ789',
        },
      },
    } as unknown as StripeWebhookEvent;

    const action = routeStripeEvent(event);
    expect(action).toMatchObject({ kind: 'upsert_user_from_checkout', email: 'fallback@example.com' });
  });

  it('ignores checkout.session.completed with no resolvable email', () => {
    const event: StripeWebhookEvent = {
      type: 'checkout.session.completed',
      data: { object: { customer: 'cus_ABC123', customer_email: null, subscription: null } },
    } as unknown as StripeWebhookEvent;

    expect(routeStripeEvent(event)).toEqual({ kind: 'ignored', eventType: 'checkout.session.completed' });
  });

  it('routes customer.subscription.updated (active) to a status update', () => {
    const event: StripeWebhookEvent = {
      type: 'customer.subscription.updated',
      data: { object: { customer: 'cus_ABC123', status: 'active' } },
    } as unknown as StripeWebhookEvent;

    expect(routeStripeEvent(event)).toEqual({
      kind: 'update_subscription_status',
      stripeCustomerId: 'cus_ABC123',
      status: 'active',
    });
  });

  it('routes customer.subscription.deleted (canceled) to a status update', () => {
    const event: StripeWebhookEvent = {
      type: 'customer.subscription.deleted',
      data: { object: { customer: 'cus_ABC123', status: 'canceled' } },
    } as unknown as StripeWebhookEvent;

    expect(routeStripeEvent(event)).toEqual({
      kind: 'update_subscription_status',
      stripeCustomerId: 'cus_ABC123',
      status: 'canceled',
    });
  });

  it('routes invoice.payment_failed to a past_due status update', () => {
    const event: StripeWebhookEvent = {
      type: 'invoice.payment_failed',
      data: { object: { customer: 'cus_ABC123' } },
    } as unknown as StripeWebhookEvent;

    expect(routeStripeEvent(event)).toEqual({
      kind: 'update_subscription_status',
      stripeCustomerId: 'cus_ABC123',
      status: 'past_due',
    });
  });

  it('ignores unrecognized event types rather than throwing', () => {
    const event: StripeWebhookEvent = {
      type: 'charge.refunded',
      data: { object: {} },
    } as unknown as StripeWebhookEvent;

    expect(routeStripeEvent(event)).toEqual({ kind: 'ignored', eventType: 'charge.refunded' });
  });
});
