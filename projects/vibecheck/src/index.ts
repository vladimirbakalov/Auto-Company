// vibecheck — Main Cloudflare Worker
// Routes: GET / (landing page + scan UI), POST /api/scan (scan a public GitHub repo), GET /health
// Monitoring tier (docs/cto/vibecheck-monitoring-tier-adr.md): POST /api/monitors,
// POST /api/checkout, POST /api/stripe/webhook, GET /api/auth/verify, and the
// `scheduled` export (Cron Trigger, see wrangler.toml [triggers]).
//
// The free scan path is unchanged: stateless, no D1, re-fetches from GitHub
// every request. See github.ts for the unauthenticated rate-limit caveat
// (60 req/hr, shared per-IP) — a known, accepted limitation, not an oversight.
//
// The monitoring-tier routes below all check their D1/Stripe/session bindings
// before using them and degrade gracefully (matching the existing
// `if (!c.env.WAITLIST)` pattern) rather than 500ing when a binding hasn't
// been provisioned yet — vibecheck currently cannot deploy to Cloudflare
// (credentials blocked, a human/deploy-time concern), so this code is
// verified via `npm run typecheck` + `npm test`, not a live deploy.

import { Hono, type Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { fetchDefaultBranch, fetchFiles, fetchTree, parseRepoUrl } from './github';
import { runAllChecks, selectCandidateFiles } from './checks';
import { computeScore, scoreToGrade } from './scoring';
import {
  landingPage,
  dashboardPage,
  dashboardSignInPage,
  dashboardEmptyStatePage,
  type DashboardData,
  type SecurityDriftSummary,
} from './pages';
import type { Env, Finding, ScanResult, UserRow, WaitlistEntry } from './types';
import { ScanError } from './types';
import { probeUrl, validateProbeTarget } from './probe';
import { checkRateLimit, rateLimitKey } from './rateLimit';
// Every rateLimitKey(...) call below reads only the `CF-Connecting-IP`
// header, never `X-Forwarded-For` or any other client-settable header:
// Cloudflare's edge strips/overwrites any client-supplied CF-Connecting-IP
// before a proxied request reaches this Worker, so it isn't spoofable from
// outside — X-Forwarded-For has no such guarantee and must not be added as
// a fallback here, or the rate limiter becomes trivially bypassable.
import { buildLiveFindings } from './liveChecks';
import { CONSECUTIVE_FAILURE_THRESHOLD, detectTrafficAnomaly, evaluateUptimeTransition } from './anomaly';
import {
  applyCheckResultToMonitor,
  buildCheckInsert,
  fetchDueMonitors,
  fetchTrailingChecks,
  getMonitorById,
  hasOpenDownAlert,
  insertAlert,
  insertMonitor,
  listMonitorsForUser,
  recordCheck,
  resolveOpenDownAlert,
  runBoundedFanOut,
  setMonitorMutedUntil,
  updateMonitorAfterCheck,
  updateMonitorBaseline,
  DUE_QUEUE_LIMIT,
} from './monitors';
import {
  computeMutedUntil,
  deriveCostRiskState,
  diffSecurityFindings,
  fetchAlertsForMonitor,
  fetchMostRecentAlertOfType,
  isMonitorOwnedByUser,
  isMuted,
} from './dashboard';
import {
  findUserByApiKey,
  findUserByStripeCustomerId,
  findUserEmailById,
  updateSubscriptionStatus,
  upsertUserFromCheckout,
  validateAndConsumeMagicLink,
  verifySession,
  signSession,
  createMagicLink,
  SESSION_TTL_MS,
} from './auth';
import { createStripeGateway, fetchActiveStripeCustomerIds, routeStripeEvent, type StripeWebhookEvent } from './stripe';
import { fetchKnownStripeCustomerIds, findReconciliationGap } from './reconcile';
import { sendEmail, magicLinkEmail, paymentFailedEmail, downAlertEmail, recoveredAlertEmail } from './email';

const SESSION_COOKIE = 'vc_session';

// Deliberately simple RFC-5322-ish check — good enough to reject typos and
// junk, not trying to be a full email grammar validator for a pre-launch
// waitlist. See CEO mandate: docs/ceo/vibecheck-godecision-cycle4.md.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Coarse per-IP rate limits (src/rateLimit.ts) for the three unauthenticated
// URL-probing/scanning endpoints — see the QA-cycle-#1146 comment above
// POST /api/probe-check for the gap this closes. All three share one
// 60-second window; the request budget itself is tuned per route below
// (fixed-window counter, so "per minute" here is approximate, not exact —
// see rateLimit.ts for why). 10/min comfortably covers a real user
// iterating on a scan/probe/monitor while still bounding the server-side
// fetches a single IP can trigger.
// Exported (not just `const`) so tests can assert against the real numbers
// instead of duplicating magic literals — same reasoning as
// MONITOR_CHECK_CRON/RECONCILIATION_CRON below.
export const RATE_LIMIT_WINDOW_SECONDS = 60;
export const SCAN_RATE_LIMIT = 10;
export const PROBE_CHECK_RATE_LIMIT = 10;
export const MONITORS_RATE_LIMIT = 10;

const RATE_LIMIT_ERROR = { error: 'Too many requests. Please wait a minute and try again.' } as const;

const app = new Hono<{ Bindings: Env }>();

// CSP is nonce-based rather than 'unsafe-inline' on script-src: every page
// here ships its JS as an inline <script> block (no framework, no bundler),
// so a blanket 'unsafe-inline' would allow any injected <script> too and
// defeat the point. A fresh nonce per response lets the legitimate inline
// block run while blocking anything an attacker manages to inject.
function htmlResponseWithNonce(build: (nonce: string) => string, status = 200): Response {
  const nonce = crypto.randomUUID();
  return new Response(build(nonce), {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'`,
    },
  });
}

// ── Landing page + scan UI ──────────────────────────────────────────────────
app.get('/', () => htmlResponseWithNonce(nonce => landingPage(nonce)));

// ── Scan API ─────────────────────────────────────────────────────────────────
app.post('/api/scan', async c => {
  const { allowed } = await checkRateLimit(
    c.env.RATE_LIMIT,
    rateLimitKey(c.req.header('CF-Connecting-IP'), 'scan'),
    SCAN_RATE_LIMIT,
    RATE_LIMIT_WINDOW_SECONDS
  );
  if (!allowed) {
    return c.json(RATE_LIMIT_ERROR, 429);
  }

  let body: { repoUrl?: string; deployedUrl?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Expected JSON body with a repoUrl field' }, 400);
  }

  try {
    const ref = parseRepoUrl(body.repoUrl ?? '');
    const defaultBranch = await fetchDefaultBranch(ref, c.env);
    const tree = await fetchTree(ref, defaultBranch, c.env);

    const candidates = selectCandidateFiles(tree);
    const files = await fetchFiles(ref, defaultBranch, candidates);

    const { findings, failedChecks } = runAllChecks(tree, files);

    const notes: string[] = [
      'GitHub public API is rate-limited to 60 requests/hour per IP when unauthenticated; scans may occasionally fail during high traffic — retry after a minute.',
    ];
    if (tree.length > files.length + candidates.length) {
      notes.push('Repo tree was larger than this scan\'s sampling budget; only a subset of files were checked.');
    }
    for (const name of failedChecks) {
      notes.push(`The "${name}" check could not complete for this repo and was skipped; other checks still ran normally.`);
    }

    // Optional live-URL security check (ADR §3 caller #1, spec §2.2). This is
    // an *unauthenticated* server-side fetch of a user-supplied URL, so it
    // must go through validateProbeTarget first (see probe.ts) — same
    // graceful-degradation style as the WAITLIST/DB binding checks elsewhere
    // in this file: a bad/unreachable URL never fails the whole scan, it
    // just skips live findings and says why.
    const deployedUrlInput = (body.deployedUrl ?? '').trim();
    if (deployedUrlInput) {
      const validated = validateProbeTarget(deployedUrlInput);
      if (!validated.ok) {
        notes.push(`Skipped live URL check: ${validated.reason}`);
      } else {
        try {
          const liveFindings = await buildLiveFindings(validated.url);
          findings.push(...liveFindings);
        } catch (err) {
          console.error('Live URL probe failed:', err);
          notes.push(
            'Skipped live URL check: could not reach the deployed URL. This did not affect the repo scan above.'
          );
        }
      }
    }

    const score = computeScore(findings);
    const grade = scoreToGrade(score);

    const result: ScanResult = {
      owner: ref.owner,
      repo: ref.repo,
      defaultBranch,
      score,
      grade,
      findings,
      filesScanned: files.length,
      filesInTree: tree.length,
      scannedAt: new Date().toISOString(),
      notes,
    };

    return c.json(result);
  } catch (err) {
    if (err instanceof ScanError) {
      return c.json({ error: err.message }, err.status as 400 | 404 | 429 | 502);
    }
    console.error('Unhandled scan error:', err);
    return c.json({ error: 'Unexpected error while scanning. Please try again.' }, 500);
  }
});

// ── Live-ping demo (spec §3.4) ───────────────────────────────────────────────
// Lightweight reachability + latency check used by the "Start monitoring"
// inline flow on the scan-results page: proves the product works, before any
// payment is discussed, and doubles as the tourist filter CFO asked for
// (someone with no real deployment simply cannot pass this check). Reuses
// the exact same validateProbeTarget guard as POST /api/scan's deployedUrl
// and POST /api/monitors' url — one probe validation path, not a third one.
// Deliberately just a reachability ping (probeUrl on '/'), not the fuller
// buildLiveFindings security check — that already ran as part of the scan
// if the user supplied a deployedUrl there; this endpoint's only job is the
// green/red "we can see it's live" moment from spec §3.4 step 2.
//
// FORMERLY A KNOWN GAP (QA cycle #1146, deferred 2+ cycles, closed this
// cycle): this endpoint is unauthenticated, so without a throttle it was a
// free reachability/latency oracle for any target that clears
// validateProbeTarget. Same was true of POST /api/scan's deployedUrl and
// POST /api/monitors' url. All three now go through checkRateLimit
// (src/rateLimit.ts) first — a coarse, KV-backed fixed-window counter per
// (IP, route), same graceful-degradation binding style as WAITLIST. See
// rateLimit.ts's module doc for the exact design and why "coarse" is
// intentional, not a shortcut.
app.post('/api/probe-check', async c => {
  const { allowed } = await checkRateLimit(
    c.env.RATE_LIMIT,
    rateLimitKey(c.req.header('CF-Connecting-IP'), 'probe-check'),
    PROBE_CHECK_RATE_LIMIT,
    RATE_LIMIT_WINDOW_SECONDS
  );
  if (!allowed) {
    return c.json(RATE_LIMIT_ERROR, 429);
  }

  let body: { url?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Expected JSON body with a url field' }, 400);
  }

  const validated = validateProbeTarget((body.url ?? '').trim());
  if (!validated.ok) {
    return c.json({ reachable: false, error: validated.reason }, 400);
  }

  try {
    const probe = await probeUrl(validated.url, { path: '/' });
    if (!probe.ok) {
      return c.json({ reachable: false, error: probe.error ?? 'Could not reach that URL.' });
    }
    return c.json({ reachable: true, latencyMs: probe.latencyMs, status: probe.status });
  } catch (err) {
    // probeUrl's own try/catch only covers the initial fetchWithTimeout call;
    // a mid-body stream error (origin resets the connection after headers,
    // TLS failure during body read) rejects instead. This endpoint's contract
    // is to always return a reachable:true/false JSON body, never fall
    // through to the generic 500 handler, same graceful-degradation style as
    // POST /api/scan's live-probe path.
    console.error('probe-check failed:', err);
    return c.json({ reachable: false, error: 'Could not reach that URL.' });
  }
});

// ── Waitlist capture ─────────────────────────────────────────────────────────
// "Cost + uptime monitoring, coming soon" signup shown after a scan completes.
// This is a pre-paid-tier proxy signal (CEO mandate), not a production email
// system — no double opt-in, no unsubscribe flow, just a KV write.
app.post('/api/waitlist', async c => {
  let body: { email?: string; repoUrl?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Expected JSON body with an email field' }, 400);
  }

  const email = (body.email ?? '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) {
    return c.json({ error: 'Please enter a valid email address.' }, 400);
  }

  const entry: WaitlistEntry = {
    repoUrl: (body.repoUrl ?? '').trim(),
    scannedAt: new Date().toISOString(),
  };

  if (!c.env.WAITLIST) {
    // No KV namespace bound yet (see wrangler.toml TODO) — most likely local
    // dev before `wrangler kv:namespace create WAITLIST` has been run, or a
    // pre-deploy dry run. No-op gracefully rather than 500ing on the user.
    console.log('TODO: WAITLIST KV binding missing — would have stored:', email, entry);
    return c.json({ ok: true, stored: false });
  }

  try {
    await c.env.WAITLIST.put(`waitlist:${email}`, JSON.stringify(entry));
    return c.json({ ok: true, stored: true });
  } catch (err) {
    console.error('Waitlist KV write failed:', err);
    return c.json({ error: 'Could not save your email right now. Please try again.' }, 500);
  }
});

// ── Monitoring-tier auth ─────────────────────────────────────────────────────
// Two accepted credentials, per ADR §5: an `Authorization: Bearer <apiKey>`
// header, or the signed session cookie set by GET /api/auth/verify. Returns
// null (not a thrown error) on any auth failure so callers decide the HTTP
// status — this is a lookup, not a guard clause.
async function requireAuth(c: Context<{ Bindings: Env }>): Promise<UserRow | null> {
  if (!c.env.DB) return null;

  const authHeader = c.req.header('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const apiKey = authHeader.slice('Bearer '.length).trim();
    if (apiKey) {
      const user = await findUserByApiKey(c.env.DB, apiKey);
      if (user) return user;
    }
  }

  const sessionValue = getCookie(c, SESSION_COOKIE);
  if (sessionValue && c.env.SESSION_SECRET) {
    const payload = await verifySession(sessionValue, c.env.SESSION_SECRET);
    if (payload) {
      const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?1').bind(payload.userId).first<UserRow>();
      if (user) return user;
    }
  }

  return null;
}

// Consumes a magic-link token (emailed after Stripe checkout, ADR §5 step 3),
// marks it used, and issues a signed httpOnly session cookie, then redirects
// to GET /dashboard — now that that page exists, there's somewhere real to
// send the user instead of a bare JSON acknowledgement. Failure paths stay
// JSON (this is a link a user clicks from email, but a non-2xx JSON body is
// still the simplest honest response for a browser hitting a dead link).
app.get('/api/auth/verify', async c => {
  if (!c.env.DB) {
    console.log('TODO: DB binding missing — magic-link verification not available yet');
    return c.json({ error: 'Not available yet.' }, 503);
  }

  const token = c.req.query('token');
  if (!token) {
    return c.json({ error: 'Missing token query parameter' }, 400);
  }

  const userId = await validateAndConsumeMagicLink(c.env.DB, token);
  if (!userId) {
    return c.json({ error: 'This link is invalid, expired, or already used.' }, 400);
  }

  if (!c.env.SESSION_SECRET) {
    console.log('TODO: SESSION_SECRET missing — cannot issue a session cookie for user', userId);
    // Still redirect: the magic link itself was valid. GET /dashboard's own
    // requireAuth will find no session cookie and fall back to
    // dashboardSignInPage(), which surfaces the gap instead of hiding it
    // behind a JSON body nobody but a developer would ever see.
    return c.redirect('/dashboard', 302);
  }

  const expiresAtMs = Date.now() + SESSION_TTL_MS;
  const sessionValue = await signSession({ userId, expiresAtMs }, c.env.SESSION_SECRET);
  setCookie(c, SESSION_COOKIE, sessionValue, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
  });
  return c.redirect('/dashboard', 302);
});

// ── Monitors CRUD ─────────────────────────────────────────────────────────────
app.post('/api/monitors', async c => {
  if (!c.env.DB) {
    console.log('TODO: DB binding missing — monitoring not available yet');
    return c.json({ error: 'Monitoring is not available yet.' }, 503);
  }

  // Rate-limited by IP ahead of auth (not just ahead of the DB write): this
  // endpoint is auth-gated but not payment-verified (see the SSRF-guard
  // comment below), so an unthrottled attacker could also use it to hammer
  // requireAuth's API-key lookup. Checking here means a blocked caller never
  // reaches that DB query either. Trade-off: the key is IP+route only, with
  // no awareness of API key/auth state, so an unauthenticated attacker
  // sharing an IP with a legitimate authenticated user (same NAT/corporate
  // egress/CGNAT block) could burn that IP's budget with junk requests and
  // lock the legitimate user out for the window. Requires the attacker to
  // already share an IP with the target, so accepted as low-severity for a
  // coarse, blunt-abuse throttle.
  const { allowed } = await checkRateLimit(
    c.env.RATE_LIMIT,
    rateLimitKey(c.req.header('CF-Connecting-IP'), 'monitors'),
    MONITORS_RATE_LIMIT,
    RATE_LIMIT_WINDOW_SECONDS
  );
  if (!allowed) {
    return c.json(RATE_LIMIT_ERROR, 429);
  }

  const user = await requireAuth(c);
  if (!user) {
    return c.json({ error: 'Authentication required. Use a valid session cookie or API key.' }, 401);
  }

  let body: { url?: string; intervalSeconds?: number };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Expected JSON body with a url field' }, 400);
  }

  // Same literal-hostname SSRF guard as POST /api/scan's optional
  // deployedUrl (probe.ts's validateProbeTarget) — this endpoint is
  // auth-gated but not payment-verified, and every monitor here feeds
  // straight into the Cron Trigger's probeUrl fan-out, so it gets the same
  // guard rather than a narrower one.
  const validated = validateProbeTarget((body.url ?? '').trim());
  if (!validated.ok) {
    return c.json({ error: validated.reason }, 400);
  }

  // 5-15 min range per CEO brief (ADR §2 "Interval enforcement").
  const intervalSeconds = body.intervalSeconds ?? 300;
  if (intervalSeconds < 300 || intervalSeconds > 900) {
    return c.json({ error: 'intervalSeconds must be between 300 (5 min) and 900 (15 min).' }, 400);
  }

  try {
    const monitor = await insertMonitor(c.env.DB, { userId: user.id, url: validated.url, intervalSeconds });
    return c.json({ monitor }, 201);
  } catch (err) {
    console.error('Failed to create monitor:', err);
    return c.json({ error: 'Could not create monitor right now. Please try again.' }, 500);
  }
});

// ── Paid-tier dashboard (spec §5) ────────────────────────────────────────────
// Feeds both the sparkline (element 1) and the cost-risk sample count
// (element 2, deriveCostRiskState's cold-start gate) from one D1 call, per
// dashboard.ts's design note. 50 is comfortably above COLD_START_MIN_SAMPLES
// (7) so "Learning" vs "Normal"/"Elevated" is decided correctly, and small
// enough to keep this a cheap read on every dashboard load. There's no
// day-bucketed check history yet (checks land every 5-15 min per monitor,
// not once/day) — so "7-day sparkline" is honestly "most recent checks"
// until a real bucketing scheme exists, which spec §5.1 explicitly allows
// ("empty/placeholder state acceptable on day one, not blank").
const DASHBOARD_TRAILING_CHECKS_LIMIT = 50;

app.get('/dashboard', async c => {
  if (!c.env.DB) {
    return htmlResponseWithNonce(() => dashboardSignInPage());
  }

  const user = await requireAuth(c);
  if (!user) {
    return htmlResponseWithNonce(() => dashboardSignInPage());
  }

  // v1 is one builder, one app (spec §5) — take the first (also most
  // recently created, per listMonitorsForUser's ORDER BY) monitor rather
  // than building any multi-project selection UI.
  const monitors = await listMonitorsForUser(c.env.DB, user.id);
  const monitor = monitors[0];
  if (!monitor) {
    return htmlResponseWithNonce(() => dashboardEmptyStatePage());
  }

  const trailing = await fetchTrailingChecks(c.env.DB, monitor.id, DASHBOARD_TRAILING_CHECKS_LIMIT);
  const mostRecentLatencyAlert = await fetchMostRecentAlertOfType(c.env.DB, monitor.id, 'latency_anomaly');
  const costRiskState = deriveCostRiskState(trailing.length, mostRecentLatencyAlert?.fired_at ?? null);

  // Element 3: a null baseline means the checkout-time capture (this file's
  // Stripe webhook handler) never ran or failed — an honest "no baseline
  // yet" state, not the same as "diffed clean" — so this short-circuits
  // before ever probing the live URL.
  let securityDrift: SecurityDriftSummary;
  if (monitor.baseline_findings_json === null) {
    securityDrift = { state: 'no_baseline' };
  } else {
    try {
      const live = await buildLiveFindings(monitor.url);
      const baseline = JSON.parse(monitor.baseline_findings_json) as Finding[];
      const diff = diffSecurityFindings(baseline, live);
      securityDrift =
        diff.newFindings.length === 0 ? { state: 'no_changes' } : { state: 'new_findings', findings: diff.newFindings };
    } catch (err) {
      console.error('Dashboard security-drift check failed for monitor id', monitor.id, err);
      securityDrift = { state: 'check_failed' };
    }
  }

  const alerts = await fetchAlertsForMonitor(c.env.DB, monitor.id);

  // Mirrors evaluateUptimeTransition's own "2 consecutive failures" bar
  // (anomaly.ts) rather than a raw last_status check, so the dashboard never
  // shows "Down" for a single blip that wouldn't have fired a 'down' alert
  // either — one definition of "down" across the whole product.
  const status: DashboardData['status'] =
    monitor.last_check_at === null
      ? 'unknown'
      : monitor.consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD
        ? 'down'
        : 'up';

  const data: DashboardData = {
    monitorId: monitor.id,
    monitorUrl: monitor.url,
    status,
    lastCheckAt: monitor.last_check_at,
    lastStatus: monitor.last_status,
    sparkline: trailing.map(check => ({ checkedAt: check.checked_at, latencyMs: check.latency_ms })),
    costRiskState,
    securityDrift,
    alerts,
    alertEmail: user.email,
    muted: isMuted(monitor.muted_until),
    mutedUntil: monitor.muted_until,
  };

  return htmlResponseWithNonce(nonce => dashboardPage(data, nonce));
});

// First ownership-checked mutation endpoint in this codebase (see
// isMonitorOwnedByUser's doc comment, dashboard.ts). 404s — not 403 — on
// both "monitor doesn't exist" and "exists but belongs to someone else" so a
// caller can't use the response to enumerate other users' monitor ids.
app.post('/api/monitors/:id/mute', async c => {
  if (!c.env.DB) {
    return c.json({ error: 'Monitoring is not available yet.' }, 503);
  }

  const user = await requireAuth(c);
  if (!user) {
    return c.json({ error: 'Authentication required. Use a valid session cookie or API key.' }, 401);
  }

  const monitorId = Number(c.req.param('id'));
  if (!Number.isInteger(monitorId)) {
    return c.json({ error: 'Not found' }, 404);
  }

  const monitor = await getMonitorById(c.env.DB, monitorId);
  if (!monitor || !isMonitorOwnedByUser(monitor, user.id)) {
    return c.json({ error: 'Not found' }, 404);
  }

  let body: { mute?: boolean };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Expected JSON body with a mute boolean field' }, 400);
  }

  const mutedUntil = computeMutedUntil(Boolean(body.mute));
  await setMonitorMutedUntil(c.env.DB, monitorId, mutedUntil);
  return c.json({ muted: isMuted(mutedUntil), mutedUntil });
});

// ── Billing: Stripe Checkout + webhook (ADR §5) ──────────────────────────────
app.post('/api/checkout', async c => {
  if (!c.env.STRIPE_SECRET_KEY || !c.env.STRIPE_WEBHOOK_SECRET || !c.env.STRIPE_PRICE_ID) {
    console.log('TODO: Stripe secrets missing — checkout not available yet');
    return c.json({ error: 'Checkout is not available yet.' }, 503);
  }

  let body: { email?: string; url?: string; successUrl?: string; cancelUrl?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Expected JSON body' }, 400);
  }

  const successUrl = body.successUrl ?? new URL('/checkout/success', c.req.url).toString();
  const cancelUrl = body.cancelUrl ?? new URL('/', c.req.url).toString();

  // Funnel-gap fix (docs/product/vibecheck-monitoring-tier-spec.md §3.4):
  // carry the URL the user just proved live in the inline probe demo
  // through Checkout as metadata, so the webhook (below) has something to
  // create a monitor from. Deliberately NOT re-validated with
  // validateProbeTarget here — this is just an opaque string handed to
  // Stripe as metadata, never fetched by this endpoint; the untrusted-input
  // boundary that matters is on the other side of the round-trip, where the
  // webhook handler treats it as untrusted and re-validates before ever
  // probing it.
  const deployedUrl = (body.url ?? '').trim();

  const gateway = createStripeGateway(c.env.STRIPE_SECRET_KEY, c.env.STRIPE_WEBHOOK_SECRET);
  try {
    const session = await gateway.createCheckoutSession({
      priceId: c.env.STRIPE_PRICE_ID,
      customerEmail: body.email,
      successUrl,
      cancelUrl,
      metadata: deployedUrl ? { deployed_url: deployedUrl } : undefined,
    });
    return c.json({ id: session.id, url: session.url });
  } catch (err) {
    console.error('Stripe checkout session creation failed:', err);
    return c.json({ error: 'Could not start checkout right now. Please try again.' }, 502);
  }
});

app.post('/api/stripe/webhook', async c => {
  if (!c.env.STRIPE_SECRET_KEY || !c.env.STRIPE_WEBHOOK_SECRET) {
    console.log('TODO: Stripe secrets missing — webhook not available yet');
    return c.json({ error: 'Webhook not configured' }, 503);
  }

  const signature = c.req.header('Stripe-Signature');
  if (!signature) {
    return c.json({ error: 'Missing Stripe-Signature header' }, 400);
  }

  const rawBody = await c.req.text();
  const gateway = createStripeGateway(c.env.STRIPE_SECRET_KEY, c.env.STRIPE_WEBHOOK_SECRET);
  const validSignature = await gateway.verifyWebhookSignature(rawBody, signature);
  if (!validSignature) {
    return c.json({ error: 'Invalid signature' }, 400);
  }

  let event: StripeWebhookEvent;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return c.json({ error: 'Invalid JSON payload' }, 400);
  }

  const action = routeStripeEvent(event);

  if (!c.env.DB) {
    console.log('TODO: DB binding missing — would have applied Stripe webhook action:', action);
    return c.json({ ok: true, applied: false });
  }

  try {
    switch (action.kind) {
      case 'upsert_user_from_checkout': {
        const user = await upsertUserFromCheckout(c.env.DB, {
          email: action.email,
          stripeCustomerId: action.stripeCustomerId,
          stripeSubscriptionId: action.stripeSubscriptionId,
        });
        const { token } = await createMagicLink(c.env.DB, user.id);
        // The verify link's origin is derived from this very request's URL
        // (same pattern as POST /api/checkout's successUrl/cancelUrl above)
        // rather than a hardcoded per-environment hostname: Stripe posts
        // this webhook straight at the deployed Worker, so c.req.url is
        // already the correct public origin for whichever environment
        // (dev/staging/production, per wrangler.toml) is handling it — one
        // fewer piece of environment-specific config to keep in sync.
        const verifyUrl = new URL('/api/auth/verify', c.req.url);
        verifyUrl.searchParams.set('token', token);
        const { subject, html } = magicLinkEmail(verifyUrl.toString());
        const { sent } = await sendEmail(c.env.RESEND_API_KEY, { to: user.email, subject, html });
        if (!sent) {
          // sendEmail already logged why (missing key vs. provider error);
          // this line adds the correlation id an ops triage actually needs.
          console.error('Magic-link email not delivered for user id', user.id);
        }

        // Funnel-gap fix (spec §3.4): this is the ONLY place in the codebase
        // that ever creates a monitor from a real paying user — without it,
        // a subscriber pays $20/mo and the dashboard stays empty forever
        // (see this change's task brief for how that gap was found). The
        // URL round-tripped through Stripe as metadata, so it's untrusted
        // input exactly like POST /api/monitors' body.url and gets the same
        // validateProbeTarget SSRF guard, not a shortcut past it.
        //
        // Stripe delivers webhooks at-least-once and this branch's own probe
        // calls can legitimately take long enough to trigger a Stripe-side
        // retry (qa-bach review, cycle 11) — without this existence check, a
        // retry would insertMonitor a second time with no unique constraint
        // to stop it, leaving an un-mutable ghost monitor polling forever
        // that the dashboard (monitors[0], newest-first) never shows again.
        // v1 is one user/one app (spec §5), so "does this user have any
        // monitor yet" is the right idempotency key, not one keyed on the URL.
        const existingMonitors = await listMonitorsForUser(c.env.DB, user.id);
        if (existingMonitors.length > 0) {
          console.log(
            'Checkout monitor creation skipped: user id',
            user.id,
            'already has a monitor (likely a Stripe webhook retry).'
          );
        } else if (action.deployedUrl) {
          const validated = validateProbeTarget(action.deployedUrl);
          if (!validated.ok) {
            console.error(
              'Checkout monitor creation skipped: deployedUrl failed validation for user id',
              user.id,
              validated.reason
            );
          } else {
            try {
              const monitor = await insertMonitor(c.env.DB, { userId: user.id, url: validated.url });

              // Security-drift baseline (dashboard element 3, spec §5.3):
              // captured once here so the dashboard has something to diff
              // against later. buildLiveFindings throws if the root probe
              // fails — a real possibility seconds after checkout if the
              // deployment changed — so this is wrapped and left null on
              // failure rather than failing the whole webhook. A null
              // baseline is the dashboard's honest "no baseline yet" state,
              // not an error.
              try {
                const baselineFindings: Finding[] = await buildLiveFindings(validated.url);
                await updateMonitorBaseline(c.env.DB, monitor.id, JSON.stringify(baselineFindings));
              } catch (err) {
                console.error(
                  'Security-drift baseline capture failed for monitor id',
                  monitor.id,
                  '— leaving baseline_findings_json null (dashboard will show "no baseline yet"):',
                  err
                );
              }
            } catch (err) {
              console.error('Failed to create monitor from checkout for user id', user.id, err);
            }
          }
        } else {
          console.log('Checkout completed with no deployedUrl in metadata for user id', user.id, '— no monitor created.');
        }
        break;
      }
      case 'update_subscription_status':
        await updateSubscriptionStatus(c.env.DB, action.stripeCustomerId, action.status);
        // Pre-mortem finding #2 (docs/critic/vibecheck-monitoring-tier-premortem.md):
        // monitoring now keeps running through 'past_due' (see fetchDueMonitors
        // in monitors.ts), but the user still needs their own heads-up — Stripe's
        // dunning email talks about the card, not about "your monitoring is still
        // on for now."
        if (action.status === 'past_due') {
          // Fires on every 'past_due' webhook delivery with no dedup against
          // the user's previously-stored status — Stripe's at-least-once
          // delivery (retries) or a flapping subscription (past_due -> active
          // -> past_due) can send more than one of these for what a human
          // would call "the same failure." Accepted for now: a redundant
          // dunning reminder is a much smaller cost than a missed one, and
          // dedup would need its own persisted "last notified" state. Revisit
          // if this turns out to be noisy in practice.
          //
          // The webhook event only carries a Stripe customer id, not an
          // email — look the user up in D1 rather than inventing one.
          const user = await findUserByStripeCustomerId(c.env.DB, action.stripeCustomerId);
          if (user) {
            const { subject, html } = paymentFailedEmail();
            const { sent } = await sendEmail(c.env.RESEND_API_KEY, { to: user.email, subject, html });
            if (!sent) {
              console.error('Payment-failed email not delivered for user id', user.id);
            }
          } else {
            console.error(
              'Payment-failed notice: no D1 user row for Stripe customer',
              action.stripeCustomerId,
              '— cannot resolve an email to notify (reconciliation-cron should also flag this gap).'
            );
          }
        }
        break;
      case 'ignored':
        break;
    }
    return c.json({ ok: true, applied: action.kind !== 'ignored' });
  } catch (err) {
    console.error('Failed to apply Stripe webhook action:', err);
    return c.json({ error: 'Failed to process webhook' }, 500);
  }
});

// ── Health / ops ──────────────────────────────────────────────────────────────
app.get('/health', c => c.json({ ok: true, ts: new Date().toISOString() }));

// 404 fallback
app.notFound(c => c.json({ error: 'Not found' }, 404));
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({ error: 'Internal server error' }, 500);
});

// Cron schedule strings (wrangler.toml [triggers].crons) — kept as named
// constants rather than inline literals so `scheduled` below and its tests
// can't drift out of sync with wrangler.toml by a typo'd cron string.
export const MONITOR_CHECK_CRON = '* * * * *';
export const RECONCILIATION_CRON = '0 * * * *';

// ── Cron Trigger: Stripe/D1 reconciliation safety net ───────────────────────
// Fires hourly (RECONCILIATION_CRON, wrangler.toml [triggers]). Backstop for
// critic-munger's pre-mortem finding (docs/critic/
// vibecheck-monitoring-tier-premortem.md: "reconciliation-cron webhook
// safety net") — POST /api/stripe/webhook above is the only thing that ever
// creates a D1 `users` row from a Stripe payment, and a dropped/failed
// webhook would otherwise leave a paying customer with no dashboard access
// and nobody the wiser. Lists Stripe's own current view of active-or-trialing
// subscriptions (stripe.ts, no creation-time filter — see that file for why)
// and diffs it against D1's known customer ids (reconcile.ts) — any gap is
// logged loudly. No-ops gracefully if STRIPE_SECRET_KEY or DB isn't bound,
// same style as every other binding check in this file.
async function runReconciliationCheck(env: Env): Promise<void> {
  if (!env.STRIPE_SECRET_KEY) {
    console.log('TODO: STRIPE_SECRET_KEY missing — reconciliation check skipped this tick');
    return;
  }
  if (!env.DB) {
    console.log('TODO: DB binding missing — reconciliation check skipped this tick');
    return;
  }

  let stripeActiveCustomerIds: string[];
  try {
    stripeActiveCustomerIds = await fetchActiveStripeCustomerIds(env.STRIPE_SECRET_KEY);
  } catch (err) {
    console.error('Reconciliation check: failed to list active Stripe subscriptions', err);
    return;
  }
  if (stripeActiveCustomerIds.length === 0) return;

  let knownCustomerIds: Set<string>;
  try {
    knownCustomerIds = await fetchKnownStripeCustomerIds(env.DB);
  } catch (err) {
    console.error('Reconciliation check: failed to read known Stripe customer ids from D1', err);
    return;
  }
  const gap = findReconciliationGap(stripeActiveCustomerIds, knownCustomerIds);

  for (const stripeCustomerId of gap) {
    // STUB: no alert channel is wired up yet (email/Slack — same
    // not-yet-configured state as RESEND_API_KEY elsewhere in this file, see
    // types.ts). This structured, greppable log line is the entire v1 alert
    // until a real channel exists.
    console.error('RECONCILIATION GAP: Stripe customer has active subscription but no D1 user row', {
      stripeCustomerId,
    });
  }
}

// ── Cron Trigger: monitor due-queue polling + bounded fan-out (ADR §2) ──────
// Fires every 1 minute (MONITOR_CHECK_CRON, wrangler.toml [triggers]). Polls
// D1 for monitors due for a check, probes each (bounded concurrency),
// records the check, updates the monitor's next_check_at/
// consecutive_failures, and inserts alerts on uptime state transitions (ADR
// §6 steps 5-7) and traffic anomalies (spec §1.2). No-ops gracefully if DB
// isn't bound, same style as every other binding check in this file.
//
// Cloudflare Workers feeds every cron in wrangler.toml's [triggers].crons
// into this same `scheduled` export, distinguished by `event.cron` — branch
// on it up front rather than splitting into two Worker exports.
async function scheduled(event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
  if (event.cron === RECONCILIATION_CRON) {
    await runReconciliationCheck(env);
    return;
  }

  const db = env.DB;
  if (!db) {
    console.log('TODO: DB binding missing — scheduled monitor checks skipped this tick');
    return;
  }

  const nowIso = new Date().toISOString();
  const due = await fetchDueMonitors(db, nowIso, DUE_QUEUE_LIMIT);
  if (due.length === 0) return;

  await runBoundedFanOut(
    due,
    async monitor => {
      const probe = await probeUrl(monitor.url);
      const check = buildCheckInsert(monitor.id, probe, nowIso);
      await recordCheck(db, check);

      const update = applyCheckResultToMonitor(monitor, check, nowIso);
      await updateMonitorAfterCheck(db, monitor.id, update);

      const openDown = await hasOpenDownAlert(db, monitor.id);
      const transition = evaluateUptimeTransition({
        ok: check.ok === 1,
        consecutiveFailures: update.consecutive_failures,
        hasOpenDownAlert: openDown,
      });
      if (transition === 'fire_down') {
        await insertAlert(
          db,
          monitor.id,
          'down',
          JSON.stringify({ status: check.status_code, error: check.error }),
          nowIso
        );
        // Spec §4.1: notify the monitor's owner. `monitor.user_id` is
        // already on the row (migrations/0001_init.sql FK) — one lookup for
        // the email, no join needed.
        const downEmail = await findUserEmailById(db, monitor.user_id);
        if (downEmail) {
          const { subject, html } = downAlertEmail(monitor.url);
          const { sent } = await sendEmail(env.RESEND_API_KEY, { to: downEmail, subject, html });
          if (!sent) {
            console.error('Down alert email not delivered for monitor id', monitor.id);
          }
        } else {
          console.error('Down alert: no user email found for monitor id', monitor.id, 'user_id', monitor.user_id);
        }
      } else if (transition === 'fire_recovered') {
        await resolveOpenDownAlert(db, monitor.id, nowIso);
        await insertAlert(db, monitor.id, 'recovered', null, nowIso);
        // Spec §4.2.
        const recoveredEmail = await findUserEmailById(db, monitor.user_id);
        if (recoveredEmail) {
          const { subject, html } = recoveredAlertEmail(monitor.url);
          const { sent } = await sendEmail(env.RESEND_API_KEY, { to: recoveredEmail, subject, html });
          if (!sent) {
            console.error('Recovered alert email not delivered for monitor id', monitor.id);
          }
        } else {
          console.error(
            'Recovered alert: no user email found for monitor id',
            monitor.id,
            'user_id',
            monitor.user_id
          );
        }
      }

      // Traffic-anomaly proxy (product spec §1.2). KNOWN SIMPLIFICATION: v1's
      // `checks` table (migrations/0001_init.sql) records latency/status per
      // probe, not real per-endpoint request-volume — vibecheck's uptime
      // probe has no visibility into the monitored app's actual traffic (see
      // anomaly.ts's module doc and ADR §4). Trailing latency samples are
      // used here as the "10x median" input to keep the alerting loop
      // exercised end-to-end with the honest signal v1 actually has; a real
      // volume signal (e.g. from the ADR §4-flagged future webhook-ingestion
      // endpoint) can be swapped in later without touching the detection math.
      const trailing = await fetchTrailingChecks(db, monitor.id, 7);
      const verdict = detectTrafficAnomaly({
        currentValue: check.latency_ms ?? 0,
        trailingValues: trailing.map(c => c.latency_ms ?? 0),
      });
      if (verdict.isAnomaly) {
        await insertAlert(db, monitor.id, 'latency_anomaly', JSON.stringify(verdict), nowIso);
      }
    },
    20
  );
}

// Exported for tests (Hono apps support `.request()` directly, no server
// needed — see test/index.test.ts) — the default export below is what
// wrangler actually loads. `scheduled` is exported too so tests can invoke
// the cron handler directly with a fake ScheduledEvent (see
// test/index.test.ts's reconciliation-cron coverage).
export { app, scheduled };

export default {
  fetch: app.fetch,
  scheduled,
};
