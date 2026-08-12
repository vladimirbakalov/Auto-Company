// Exercises src/email.ts's sendEmail transport + template builders in
// isolation, with global.fetch mocked — same "mock global.fetch, don't hit
// the network" approach as test/stripe.test.ts and test/github.test.ts.

import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  sendEmail,
  magicLinkEmail,
  paymentFailedEmail,
  downAlertEmail,
  recoveredAlertEmail,
  EMAIL_FROM,
} from '../src/email';

describe('sendEmail', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
  });

  it('no-ops and logs a TODO when apiKey is undefined, never touching fetch', async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    const result = await sendEmail(undefined, {
      to: 'user@example.com',
      subject: 'Hello',
      html: '<p>Hi</p>',
    });

    expect(result).toEqual({ sent: false });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('RESEND_API_KEY not configured'),
      'user@example.com',
      'subject:',
      'Hello'
    );
  });

  it('POSTs to the Resend API with the expected shape when a key is configured', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://api.resend.com/emails');
      expect(init?.method).toBe('POST');
      expect(init?.headers).toMatchObject({
        Authorization: 'Bearer re_test_fake',
        'Content-Type': 'application/json',
      });
      const body = JSON.parse(String(init?.body));
      expect(body).toEqual({
        from: EMAIL_FROM,
        to: 'user@example.com',
        subject: 'Hello',
        html: '<p>Hi</p>',
      });
      return new Response(JSON.stringify({ id: 'email_123' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    const result = await sendEmail('re_test_fake', {
      to: 'user@example.com',
      subject: 'Hello',
      html: '<p>Hi</p>',
    });

    expect(result).toEqual({ sent: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns sent:false and logs without throwing on a non-2xx Resend response', async () => {
    global.fetch = vi.fn(async () => new Response('bad request', { status: 400 })) as unknown as typeof fetch;
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const result = await sendEmail('re_test_fake', {
      to: 'user@example.com',
      subject: 'Hello',
      html: '<p>Hi</p>',
    });

    expect(result).toEqual({ sent: false });
    expect(errorSpy).toHaveBeenCalledWith(
      'Resend send failed:',
      400,
      'to:',
      'user@example.com',
      'bad request'
    );
  });

  it('returns sent:false and logs without throwing when fetch itself rejects (Resend outage/network error)', async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const result = await sendEmail('re_test_fake', {
      to: 'user@example.com',
      subject: 'Hello',
      html: '<p>Hi</p>',
    });

    expect(result).toEqual({ sent: false });
    expect(errorSpy).toHaveBeenCalledWith(
      'Resend send threw:',
      expect.any(TypeError),
      'to:',
      'user@example.com'
    );
  });
});

describe('email templates', () => {
  it('magicLinkEmail embeds the verify URL and mentions expiry', () => {
    const { subject, html } = magicLinkEmail('https://vibecheck.dev/api/auth/verify?token=abc123');
    expect(subject).toContain('sign-in link');
    expect(html).toContain('https://vibecheck.dev/api/auth/verify?token=abc123');
    expect(html).toContain('15 minutes');
  });

  it('paymentFailedEmail mentions the grace period, not just the failure', () => {
    const { subject, html } = paymentFailedEmail();
    expect(subject).toContain('payment failed');
    expect(html).toContain('grace period');
  });

  it('downAlertEmail embeds the monitored URL', () => {
    const { subject, html } = downAlertEmail('https://myapp.example.com');
    expect(subject).toContain('https://myapp.example.com');
    expect(subject).toContain('down');
    expect(html).toContain('https://myapp.example.com');
  });

  it('recoveredAlertEmail embeds the monitored URL', () => {
    const { subject, html } = recoveredAlertEmail('https://myapp.example.com');
    expect(subject).toContain('https://myapp.example.com');
    expect(subject).toContain('back up');
    expect(html).toContain('https://myapp.example.com');
  });
});
