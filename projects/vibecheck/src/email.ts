// vibecheck — transactional email transport (Resend)
//
// One function, one HTTP call: POST https://api.resend.com/emails with a
// Bearer token and a JSON {from, to, subject, html} body — that's the whole
// Resend API surface this product needs (no templates, no batch sends, no
// attachments), so a raw fetch is the boring-technology choice over pulling
// in the `resend` npm package — same reasoning as stripe.ts/github.ts
// calling their respective APIs directly instead of an SDK.
//
// Same graceful-degradation contract as every other optional binding/secret
// in this codebase (WAITLIST, GITHUB_TOKEN, STRIPE_SECRET_KEY, DB): no
// RESEND_API_KEY -> log a TODO and no-op, never throw. A Resend outage or a
// non-2xx response is caught and logged too — an email provider being down
// must never fail the caller (a Stripe webhook's 200, or a cron tick).

const RESEND_API = 'https://api.resend.com/emails';

// Placeholder sender until a real domain is verified with Resend (Resend
// requires the `from` domain to be verified via DNS before it will send —
// a human/deploy-time step, tracked alongside RESEND_API_KEY provisioning,
// not something this change can do). vibecheck.dev is the product's
// intended domain; swap this constant once a real domain is verified.
export const EMAIL_FROM = 'vibecheck <alerts@vibecheck.dev>';

export interface SendEmailParams {
  to: string;
  subject: string;
  html: string;
}

export async function sendEmail(apiKey: string | undefined, params: SendEmailParams): Promise<{ sent: boolean }> {
  if (!apiKey) {
    console.log(
      'TODO: RESEND_API_KEY not configured — would have emailed',
      params.to,
      'subject:',
      params.subject
    );
    return { sent: false };
  }

  try {
    const res = await fetch(RESEND_API, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: params.to,
        subject: params.subject,
        html: params.html,
      }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.error('Resend send failed:', res.status, 'to:', params.to, text);
      return { sent: false };
    }
    return { sent: true };
  } catch (err) {
    // Network error, DNS failure, Resend outage, etc. — never let an
    // unavailable email provider throw into the caller (matches the
    // house style for GITHUB_TOKEN/WAITLIST/DB elsewhere in this codebase).
    console.error('Resend send threw:', err, 'to:', params.to);
    return { sent: false };
  }
}

// ── Templates ────────────────────────────────────────────────────────────
// Plain, minimal HTML — this is a utility SaaS product, not a design
// showcase. Kept as small pure functions so they're testable without
// touching fetch, and so index.ts's call sites stay one-liners.

export interface EmailContent {
  subject: string;
  html: string;
}

// ADR §5 step 3: emailed after Stripe checkout, consumed by GET
// /api/auth/verify?token=... (see index.ts).
export function magicLinkEmail(verifyUrl: string): EmailContent {
  return {
    subject: 'Your vibecheck sign-in link',
    html: `<p>Click below to sign in to vibecheck:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>This link expires in 15 minutes and can only be used once. If you didn't request this, you can ignore this email.</p>`,
  };
}

// Pre-mortem finding #2 (docs/critic/vibecheck-monitoring-tier-premortem.md):
// Stripe's own dunning email talks about the card, not about "your
// monitoring is still on for now" — this fills that gap.
export function paymentFailedEmail(): EmailContent {
  return {
    subject: 'vibecheck: your last payment failed',
    html: `<p>We couldn't charge your card for your vibecheck monitoring subscription.</p><p>Your monitors are still running during this grace period — please update your payment method to avoid an interruption.</p>`,
  };
}

// Spec §4.1.
export function downAlertEmail(url: string): EmailContent {
  return {
    subject: `vibecheck alert: ${url} is down`,
    html: `<p><strong>${url}</strong> is not responding to vibecheck's health checks.</p><p>We'll email you again once it recovers.</p>`,
  };
}

// Spec §4.2.
export function recoveredAlertEmail(url: string): EmailContent {
  return {
    subject: `vibecheck: ${url} is back up`,
    html: `<p><strong>${url}</strong> is responding normally again.</p>`,
  };
}
