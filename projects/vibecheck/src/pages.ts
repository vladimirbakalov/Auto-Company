// vibecheck — single-page frontend (plain HTML/CSS/JS, no framework).
// Served directly from the Worker. Calls POST /api/scan and renders the result.

import type { AlertRow, AlertType, Finding } from './types';
import type { CostRiskState } from './dashboard';

export function landingPage(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>vibecheck — free security check for AI-generated apps</title>
<meta name="description" content="Paste a public GitHub repo URL and get a free first-pass security check for common vibe-coding mistakes: hardcoded secrets, exposed .env files, permissive CORS, unguarded routes — plus a few platform-config flags. Not a replacement for your platform's own security tools." />
<style>
  :root {
    --bg: #0b0d12;
    --panel: #12151c;
    --panel-border: #232734;
    --text: #e7e9ee;
    --muted: #8a91a3;
    --accent: #6ee7b7;
    --accent-dim: #34d399;
    --critical: #f87171;
    --high: #fb923c;
    --medium: #fbbf24;
    --low: #93c5fd;
    --radius: 10px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  .wrap { max-width: 760px; margin: 0 auto; padding: 48px 20px 80px; }
  header.hero { text-align: center; margin-bottom: 40px; }
  .brand { display: inline-flex; align-items: center; gap: 8px; font-weight: 700; font-size: 15px; color: var(--muted); letter-spacing: 0.04em; text-transform: uppercase; }
  .brand-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 8px var(--accent); }
  h1 { font-size: 32px; margin: 16px 0 8px; letter-spacing: -0.01em; }
  .sub { color: var(--muted); font-size: 16px; max-width: 520px; margin: 0 auto; }

  .card {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: var(--radius);
    padding: 24px;
  }

  form { display: flex; gap: 10px; }
  #scan-form { flex-direction: column; }
  .form-row { display: flex; gap: 10px; }
  .form-row-optional { display: flex; flex-direction: column; gap: 6px; }
  .optional-tag { color: var(--muted); font-size: 12px; }
  input[type="text"] {
    flex: 1;
    background: #0e1117;
    border: 1px solid var(--panel-border);
    color: var(--text);
    border-radius: 8px;
    padding: 13px 14px;
    font-size: 15px;
    outline: none;
  }
  input[type="text"]:focus { border-color: var(--accent-dim); }
  button {
    background: var(--accent);
    color: #06281c;
    border: none;
    border-radius: 8px;
    padding: 13px 22px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  button:hover { background: var(--accent-dim); }
  button:disabled { opacity: 0.6; cursor: default; }

  .note { color: var(--muted); font-size: 13px; margin-top: 12px; }

  #result { margin-top: 28px; display: none; }
  #error { margin-top: 20px; display: none; color: var(--critical); font-size: 14px; }

  .score-row { display: flex; align-items: center; gap: 20px; margin-bottom: 20px; }
  .grade-badge {
    width: 76px; height: 76px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 32px; font-weight: 800;
    border: 3px solid var(--panel-border);
    flex-shrink: 0;
  }
  .grade-A, .grade-B { color: var(--accent); border-color: var(--accent); }
  .grade-C, .grade-D { color: var(--medium); border-color: var(--medium); }
  .grade-F { color: var(--critical); border-color: var(--critical); }
  .score-meta .score-num { font-size: 22px; font-weight: 700; }
  .score-meta .score-label { color: var(--muted); font-size: 13px; }

  .finding {
    border-top: 1px solid var(--panel-border);
    padding: 14px 0;
  }
  .finding:first-child { border-top: none; }
  .finding-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .sev {
    font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;
    padding: 2px 8px; border-radius: 999px;
  }
  .sev-critical { background: rgba(248,113,113,0.15); color: var(--critical); }
  .sev-high { background: rgba(251,146,60,0.15); color: var(--high); }
  .sev-medium { background: rgba(251,191,36,0.15); color: var(--medium); }
  .sev-low { background: rgba(147,197,253,0.15); color: var(--low); }
  .conf { font-size: 11px; color: var(--muted); }
  .finding-title { font-weight: 600; margin: 6px 0 4px; }
  .finding-explain { color: var(--muted); font-size: 14px; }
  .finding-file { color: var(--muted); font-size: 12px; font-family: ui-monospace, monospace; margin-top: 4px; }
  .finding-monitor-link { display: block; margin-top: 6px; font-size: 13px; color: var(--accent-dim); text-decoration: none; }
  .finding-monitor-link:hover { color: var(--accent); text-decoration: underline; }

  .clean { color: var(--accent); text-align: center; padding: 12px 0; }

  .meta-line { color: var(--muted); font-size: 13px; margin-top: 18px; border-top: 1px solid var(--panel-border); padding-top: 14px; }

  .waitlist { margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--panel-border); }
  .waitlist p { color: var(--muted); font-size: 14px; margin: 0 0 12px; }
  .waitlist form { display: flex; gap: 8px; }
  .waitlist input[type="email"] {
    flex: 1;
    background: #0e1117;
    border: 1px solid var(--panel-border);
    color: var(--text);
    border-radius: 8px;
    padding: 11px 14px;
    font-size: 14px;
    outline: none;
  }
  .waitlist input[type="email"]:focus { border-color: var(--accent-dim); }
  .waitlist button {
    background: var(--accent);
    color: #06281c;
    border: none;
    border-radius: 8px;
    padding: 11px 18px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  .waitlist button:hover { background: var(--accent-dim); }
  .waitlist button:disabled { opacity: 0.6; cursor: default; }
  .waitlist-msg { font-size: 13px; margin-top: 10px; }
  .waitlist-msg.ok { color: var(--accent); }
  .waitlist-msg.err { color: var(--critical); }

  #start-monitoring-btn { margin-top: 2px; }
  .monitor-step { margin-top: 16px; }
  .checkout-step { margin-top: 14px; }
  .probe-result { font-size: 13px; margin-top: 10px; }
  .probe-result.ok { color: var(--accent); }
  .probe-result.err { color: var(--critical); }
  .waitlist-fallback { margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--panel-border); }

  footer { text-align: center; color: var(--muted); font-size: 13px; margin-top: 48px; }
  footer a { color: var(--muted); }

  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(6,40,28,0.4); border-top-color: #06281c; border-radius: 50%; animation: spin 0.7s linear infinite; margin-right: 8px; vertical-align: -2px; }
  .spinner-light { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(231,233,238,0.25); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.7s linear infinite; margin-right: 8px; vertical-align: -2px; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <div class="brand"><span class="brand-dot"></span> vibecheck</div>
      <h1>Is your AI-generated app safe to ship?</h1>
      <p class="sub">Paste a public GitHub repo URL for a fast first-pass check &mdash; the code-level mistakes that most often leak data from Lovable / Bolt / Replit / Cursor / v0 apps &mdash; free, no signup. Not a certified audit, and not a substitute for your platform's own security tools (e.g. Supabase's built-in Security Advisor).</p>
    </header>

    <div class="card">
      <form id="scan-form">
        <div class="form-row">
          <input type="text" id="repo-input" placeholder="https://github.com/owner/repo" autocomplete="off" spellcheck="false" required />
          <button type="submit" id="scan-btn">Scan</button>
        </div>
        <div class="form-row-optional">
          <input type="text" id="deployed-input" placeholder="https://myapp.vercel.app" autocomplete="off" spellcheck="false" />
          <span class="optional-tag">Optional &mdash; add your live deployed URL to also check response headers, CORS, and exposed paths on the running app.</span>
        </div>
      </form>
      <p class="note">Public repos only. Runs against GitHub's public API, so occasionally rate-limited &mdash; if a scan fails, wait a minute and retry. Static heuristics, not a full audit &mdash; see confidence label on each finding.</p>

      <div id="error"></div>

      <div id="result"></div>
    </div>

    <footer>
      Heuristic scan, not a certified audit. Built to catch code-level mistakes your AI builder won't warn you about &mdash; hardcoded secrets, exposed .env files, permissive CORS, unguarded routes. Also flags a possible missing-RLS signal as a heuristic hint, but always check your platform's own security dashboard (e.g. Supabase Security Advisor) for the authoritative answer on that one.
    </footer>
  </div>

<script nonce="${nonce}">
(function () {
  const form = document.getElementById('scan-form');
  const input = document.getElementById('repo-input');
  const deployedInput = document.getElementById('deployed-input');
  const btn = document.getElementById('scan-btn');
  const resultEl = document.getElementById('result');
  const errorEl = document.getElementById('error');

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // Touchpoint 2 (spec §3.3): findings that are literally the cost/uptime
  // risk vectors §1 describes — missing auth, permissive CORS, exposed
  // .env/secrets — get an inline link into the monitoring flow. IDs come
  // from nextId()/nextLiveId() in checks.ts/liveChecks.ts: static findings
  // are '<prefix>-N' (e.g. 'auth-3', 'secret-generic-1'), live-probe
  // findings are 'live-<prefix>-N' (e.g. 'live-cors-2'), so strip an
  // optional 'live-' prefix before matching.
  const MONITORABLE_FINDING_PREFIXES = ['auth', 'cors', 'env', 'secret'];
  function isMonitorableFinding(f) {
    if (!f || !f.id) return false;
    const id = String(f.id);
    const bare = id.indexOf('live-') === 0 ? id.slice(5) : id;
    return MONITORABLE_FINDING_PREFIXES.some(function (p) { return bare.indexOf(p) === 0; });
  }

  function renderResult(data) {
    const grade = data.grade;
    let html = '';
    html += '<div class="score-row">';
    html += '<div class="grade-badge grade-' + grade + '">' + grade + '</div>';
    html += '<div class="score-meta"><div class="score-num">' + data.score + ' / 100</div>';
    html += '<div class="score-label">' + escapeHtml(data.owner) + '/' + escapeHtml(data.repo) + '</div></div>';
    html += '</div>';

    if (data.findings.length === 0) {
      html += '<div class="clean">No issues found by these heuristic checks. That does not mean the app is fully secure &mdash; only that this scan did not catch anything.</div>';
    } else {
      for (const f of data.findings) {
        html += '<div class="finding">';
        html += '<div class="finding-head">';
        html += '<span class="sev sev-' + f.severity + '">' + f.severity + '</span>';
        html += '<span class="conf">confidence: ' + f.confidence + '</span>';
        html += '</div>';
        html += '<div class="finding-title">' + escapeHtml(f.title) + '</div>';
        html += '<div class="finding-explain">' + escapeHtml(f.explanation) + '</div>';
        if (isMonitorableFinding(f)) {
          html += '<a href="#" class="finding-monitor-link" data-finding-id="' + escapeHtml(f.id) + '">This is exactly the kind of issue that leads to a surprise bill if left unfixed. <strong>Monitor this endpoint &rarr;</strong></a>';
        }
        if (f.file) {
          html += '<div class="finding-file">' + escapeHtml(f.file) + (f.line ? ':' + f.line : '') + '</div>';
        }
        html += '</div>';
      }
    }

    html += '<div class="meta-line">Scanned ' + data.filesScanned + ' of ' + data.filesInTree + ' files in the repo (sampled, not exhaustive &mdash; see note below). ' + escapeHtml(data.notes.join(' ')) + '</div>';

    // Outcome-aware upgrade CTA (spec §3.2) — the offer is framed as a direct
    // consequence of what the user just saw, not a generic upsell.
    const isClean = grade === 'A';
    const ctaCopy = isClean
      ? 'Clean scan. Want to know the moment that changes &mdash; or if your traffic starts looking expensive?'
      : 'You just fixed real issues &mdash; or you&rsquo;re about to. Want to know if this app slips back into a bad state, or if its traffic starts looking like it&rsquo;s about to cost you money?';

    html += '<div class="waitlist">';
    html += '<p id="upgrade-copy">' + ctaCopy + '</p>';
    html += '<button type="button" id="start-monitoring-btn">Start monitoring &mdash; $20/mo</button>';

    // Touchpoint 3 (spec §3.4): clicking "Start monitoring" reveals an inline
    // live-ping demo in the same card, no navigation — a real, visible proof
    // the product already works before any payment is discussed.
    html += '<div id="monitor-url-step" class="monitor-step" style="display:none;">';
    html += '<p class="note">What&rsquo;s your live URL?</p>';
    html += '<form id="probe-form">';
    html += '<input type="text" id="probe-url-input" placeholder="https://myapp.vercel.app" autocomplete="off" spellcheck="false" required />';
    html += '<button type="submit" id="probe-btn">Check</button>';
    html += '</form>';
    html += '<div id="probe-result" class="probe-result" style="display:none;"></div>';
    html += '<div id="checkout-step" class="checkout-step" style="display:none;">';
    html += '<form id="checkout-form">';
    html += '<input type="email" id="checkout-email" placeholder="you@example.com" autocomplete="email" required />';
    html += '<button type="submit" id="checkout-btn">Continue to checkout</button>';
    html += '</form>';
    html += '<div id="checkout-msg" class="waitlist-msg" style="display:none;"></div>';
    html += '</div>'; // #checkout-step
    html += '</div>'; // #monitor-url-step

    // Touchpoint 4 (spec §3.5): waitlist stays as the pre-launch fallback
    // path for anyone who doesn't want to click through the full flow now.
    html += '<div class="waitlist-fallback">';
    html += '<p>Not ready yet? Join the waitlist and we&rsquo;ll email you the moment monitoring launches.</p>';
    html += '<form id="waitlist-form">';
    html += '<input type="email" id="waitlist-email" placeholder="you@example.com" autocomplete="email" required />';
    html += '<button type="submit" id="waitlist-btn">Join waitlist</button>';
    html += '</form>';
    html += '<div id="waitlist-msg" class="waitlist-msg" style="display:none;"></div>';
    html += '</div>'; // .waitlist-fallback

    html += '</div>'; // .waitlist

    resultEl.innerHTML = html;
    resultEl.style.display = 'block';

    wireWaitlistForm(data.owner + '/' + data.repo);
    wireUpgradeFlow();
  }

  function wireWaitlistForm(repoUrl) {
    const wlForm = document.getElementById('waitlist-form');
    const wlEmail = document.getElementById('waitlist-email');
    const wlBtn = document.getElementById('waitlist-btn');
    const wlMsg = document.getElementById('waitlist-msg');
    if (!wlForm) return;

    wlForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      wlMsg.style.display = 'none';
      wlBtn.disabled = true;
      wlBtn.textContent = 'Joining…';

      try {
        const res = await fetch('/api/waitlist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: wlEmail.value, repoUrl: repoUrl }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Could not join the waitlist. Please try again.');
        }
        wlMsg.className = 'waitlist-msg ok';
        wlMsg.textContent = "You're on the list — we'll email you when cost + uptime monitoring launches.";
        wlMsg.style.display = 'block';
        wlForm.style.display = 'none';
      } catch (err) {
        wlMsg.className = 'waitlist-msg err';
        wlMsg.textContent = err.message || 'Something went wrong. Please try again.';
        wlMsg.style.display = 'block';
        wlBtn.disabled = false;
        wlBtn.textContent = 'Join waitlist';
      }
    });
  }

  // Touchpoint 3 (spec §3.4): "Start monitoring" -> inline live-ping demo ->
  // checkout. Uses POST /api/probe-check (reachability + latency only, same
  // validateProbeTarget guard as POST /api/scan's deployedUrl) so the "we can
  // see it's live" moment doesn't require re-running the full security scan.
  function wireUpgradeFlow() {
    const startBtn = document.getElementById('start-monitoring-btn');
    const step = document.getElementById('monitor-url-step');
    const probeForm = document.getElementById('probe-form');
    const probeInput = document.getElementById('probe-url-input');
    const probeBtn = document.getElementById('probe-btn');
    const probeResult = document.getElementById('probe-result');
    const checkoutStep = document.getElementById('checkout-step');
    const checkoutForm = document.getElementById('checkout-form');
    const checkoutEmail = document.getElementById('checkout-email');
    const checkoutBtn = document.getElementById('checkout-btn');
    const checkoutMsg = document.getElementById('checkout-msg');

    // Shared by "Start monitoring" (touchpoint 1) and the inline per-finding
    // "Monitor this endpoint" links (touchpoint 2, spec §3.3) — one DOM flow,
    // multiple entry points into it, per the spec's explicit instruction not
    // to build a second parallel monitoring flow for the inline links.
    function revealMonitorStep() {
      if (!step) return;
      step.style.display = 'block';
      if (startBtn) startBtn.style.display = 'none';
      // Reuse whatever the user already typed in the optional deployed-URL
      // field on the scan form, if anything, so they don't retype it.
      if (deployedInput && deployedInput.value.trim() && probeInput) {
        probeInput.value = deployedInput.value.trim();
      }
      step.scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (probeInput) probeInput.focus();
    }

    // Wired independently of startBtn's existence check below so the inline
    // finding links (which can render even if, for some reason, the bottom
    // CTA markup didn't) never silently no-op.
    const monitorLinks = document.querySelectorAll('.finding-monitor-link');
    monitorLinks.forEach(function (link) {
      link.addEventListener('click', function (e) {
        e.preventDefault();
        revealMonitorStep();
      });
    });

    if (!startBtn) return;

    startBtn.addEventListener('click', function () {
      revealMonitorStep();
    });

    probeForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      checkoutStep.style.display = 'none';
      probeResult.className = 'probe-result';
      probeResult.innerHTML = '<span class="spinner-light"></span>Checking&hellip;';
      probeResult.style.display = 'block';
      probeBtn.disabled = true;

      try {
        const res = await fetch('/api/probe-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: probeInput.value }),
        });
        const data = await res.json();
        if (res.ok && data.reachable) {
          probeResult.className = 'probe-result ok';
          probeResult.textContent = '✓ We can see it’s live. Response time: ' + data.latencyMs + 'ms.';
          checkoutStep.style.display = 'block';
        } else {
          probeResult.className = 'probe-result err';
          probeResult.textContent = "We couldn't reach that URL. Monitoring needs a live, publicly reachable deployment — that's what makes uptime and cost alerts possible in the first place. Not deployed yet? Bookmark this scan and come back once it's live — your free scan results stay saved.";
        }
      } catch (err) {
        probeResult.className = 'probe-result err';
        probeResult.textContent = 'Something went wrong checking that URL. Please try again.';
      } finally {
        probeBtn.disabled = false;
      }
    });

    checkoutForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      checkoutMsg.style.display = 'none';
      checkoutBtn.disabled = true;
      checkoutBtn.innerHTML = '<span class="spinner"></span>Redirecting&hellip;';

      try {
        const res = await fetch('/api/checkout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: checkoutEmail.value }),
        });
        const data = await res.json();
        if (!res.ok || !data.url) {
          throw new Error(data.error || 'Checkout is not available yet. Please join the waitlist below instead.');
        }
        window.location.href = data.url;
      } catch (err) {
        checkoutMsg.className = 'waitlist-msg err';
        checkoutMsg.textContent = err.message || 'Something went wrong. Please try again.';
        checkoutMsg.style.display = 'block';
        checkoutBtn.disabled = false;
        checkoutBtn.textContent = 'Continue to checkout';
      }
    });
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    errorEl.style.display = 'none';
    resultEl.style.display = 'none';
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Scanning&hellip;';

    try {
      const payload = { repoUrl: input.value };
      const deployedUrlValue = deployedInput.value.trim();
      if (deployedUrlValue) payload.deployedUrl = deployedUrlValue;
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Scan failed');
      }
      renderResult(data);
    } catch (err) {
      errorEl.textContent = err.message || 'Something went wrong. Please try again.';
      errorEl.style.display = 'block';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Scan';
    }
  });
})();
</script>
</body>
</html>`;
}

// ── Paid-tier dashboard (spec §5) ────────────────────────────────────────────
// GET /dashboard (index.ts). Deliberately a second, separate <html> document
// rather than a client-side route bolted onto landingPage() — the two pages
// have almost no shared interactivity (this one is server-rendered per
// request from D1 state, not a static shell that fetches JSON), so sharing
// one <script> block would mean more branching for no real reuse. What *is*
// shared, on purpose (product continuity, per this change's brief): the
// :root CSS variable palette below is copied verbatim from landingPage(),
// and the finding-list classes (.finding/.sev-*/etc.) are reused as-is for
// element 3's "new findings" list so a finding looks identical whether it's
// shown on the free scan or here.

function escapeHtml(s: unknown): string {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleString('en-US', { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short' }) + ' UTC';
}

// Shared <head>/<style>/wrapper for all three dashboard-family pages
// (sign-in, empty-state, real dashboard) so the CSS variable block and page
// chrome live in exactly one place.
function dashboardShell(title: string, bodyHtml: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)} — vibecheck</title>
<style>
  :root {
    --bg: #0b0d12;
    --panel: #12151c;
    --panel-border: #232734;
    --text: #e7e9ee;
    --muted: #8a91a3;
    --accent: #6ee7b7;
    --accent-dim: #34d399;
    --critical: #f87171;
    --high: #fb923c;
    --medium: #fbbf24;
    --low: #93c5fd;
    --radius: 10px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); line-height: 1.5; }
  .wrap { max-width: 640px; margin: 0 auto; padding: 48px 20px 80px; }
  .brand { display: inline-flex; align-items: center; gap: 8px; font-weight: 700; font-size: 15px; color: var(--muted); letter-spacing: 0.04em; text-transform: uppercase; }
  .brand-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 8px var(--accent); }
  .brand-dot.status-down { background: var(--critical); box-shadow: 0 0 8px var(--critical); }
  .brand-dot.status-unknown { background: var(--muted); box-shadow: none; }
  h1 { font-size: 26px; margin: 16px 0 8px; letter-spacing: -0.01em; }
  h2 { font-size: 16px; margin: 0 0 12px; }
  .sub { color: var(--muted); font-size: 15px; margin: 0 0 32px; word-break: break-all; }

  .card {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: var(--radius);
    padding: 22px;
    margin-bottom: 16px;
  }
  .muted-text { color: var(--muted); font-size: 13px; }

  .status-pill { display: inline-block; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; padding: 3px 10px; border-radius: 999px; margin-right: 10px; }
  .status-pill.status-up { background: rgba(110,231,183,0.15); color: var(--accent); }
  .status-pill.status-down { background: rgba(248,113,113,0.15); color: var(--critical); }
  .status-pill.status-unknown { background: rgba(138,145,163,0.15); color: var(--muted); }
  .health-row { display: flex; align-items: center; margin-bottom: 14px; }
  .sparkline { display: block; margin-top: 4px; }

  .risk-badge { display: inline-block; font-size: 13px; font-weight: 700; padding: 4px 12px; border-radius: 999px; margin-bottom: 10px; }
  .risk-badge.risk-normal { background: rgba(110,231,183,0.15); color: var(--accent); }
  .risk-badge.risk-learning { background: rgba(138,145,163,0.15); color: var(--muted); }
  .risk-badge.risk-elevated { background: rgba(251,146,60,0.15); color: var(--high); }

  .finding { border-top: 1px solid var(--panel-border); padding: 12px 0; }
  .finding:first-child { border-top: none; padding-top: 0; }
  .finding-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .sev { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; padding: 2px 8px; border-radius: 999px; }
  .sev-critical { background: rgba(248,113,113,0.15); color: var(--critical); }
  .sev-high { background: rgba(251,146,60,0.15); color: var(--high); }
  .sev-medium { background: rgba(251,191,36,0.15); color: var(--medium); }
  .sev-low { background: rgba(147,197,253,0.15); color: var(--low); }
  .finding-title { font-weight: 600; margin: 6px 0 2px; font-size: 14px; }

  .alert-row { border-top: 1px solid var(--panel-border); padding: 10px 0; display: flex; justify-content: space-between; gap: 12px; font-size: 14px; }
  .alert-row:first-child { border-top: none; padding-top: 0; }
  .alert-type { font-weight: 600; }
  .alert-meta { color: var(--muted); font-size: 12px; text-align: right; }

  button { background: var(--accent); color: #06281c; border: none; border-radius: 8px; padding: 11px 18px; font-size: 14px; font-weight: 600; cursor: pointer; }
  button:hover { background: var(--accent-dim); }
  button:disabled { opacity: 0.6; cursor: default; }

  a { color: var(--accent-dim); }
</style>
</head>
<body>
  <div class="wrap">
${bodyHtml}
  </div>
</body>
</html>`;
}

// Shown by GET /dashboard when requireAuth finds no valid session/API key.
// Spec §5 explicitly rules out multi-project/team flows for v1, and building
// a new "resend my magic link" form is its own scoped feature this change
// doesn't own — so this is deliberately just an explanation, not a recovery
// flow.
export function dashboardSignInPage(): string {
  return dashboardShell(
    'Sign in',
    `    <div class="brand"><span class="brand-dot status-unknown"></span> vibecheck</div>
    <h1>This link isn't valid</h1>
    <div class="card">
      <p style="margin:0;">This link isn't valid or has expired — check your email for the link we sent after checkout.</p>
    </div>`
  );
}

// Shown when an authenticated user has no monitor yet (e.g. checkout
// succeeded but the funnel-gap monitor creation — see index.ts's Stripe
// webhook handler — didn't have a deployedUrl to work with). Kept to one
// line rather than a second onboarding flow: v1 is one builder, one app,
// created at checkout time, not from the dashboard itself.
export function dashboardEmptyStatePage(): string {
  return dashboardShell(
    'Dashboard',
    `    <div class="brand"><span class="brand-dot status-unknown"></span> vibecheck</div>
    <h1>No monitor yet</h1>
    <div class="card">
      <p style="margin:0 0 12px;">We don't have a live URL on file for your account yet, so there's nothing to monitor.</p>
      <p style="margin:0;"><a href="/">Run a free scan →</a> and use "Start monitoring" once you've verified your live URL.</p>
    </div>`
  );
}

export interface DashboardSparklinePoint {
  checkedAt: string;
  latencyMs: number | null;
}

// Discriminated on `state` rather than a boolean + nullable fields — the
// three "nothing to diff" reasons (no baseline captured, live probe failed
// right now, diffed clean) are meaningfully different messages to a user,
// not the same empty state with different footnotes.
export type SecurityDriftSummary =
  | { state: 'no_baseline' }
  | { state: 'check_failed' }
  | { state: 'no_changes' }
  | { state: 'new_findings'; findings: Finding[] };

export interface DashboardData {
  monitorId: number;
  monitorUrl: string;
  // 'unknown' covers "never checked yet" (last_check_at is null) as its own
  // state rather than defaulting to 'up' or 'down' — neither is true yet.
  status: 'up' | 'down' | 'unknown';
  lastCheckAt: string | null;
  lastStatus: number | null;
  sparkline: DashboardSparklinePoint[];
  costRiskState: CostRiskState;
  securityDrift: SecurityDriftSummary;
  alerts: AlertRow[];
  alertEmail: string;
  muted: boolean;
  mutedUntil: string | null;
}

const ALERT_TYPE_LABELS: Record<AlertType, string> = {
  down: 'Went down',
  recovered: 'Back up',
  latency_anomaly: 'Unusual traffic',
};

// Only 'down' alerts ever get resolved_at set (dashboard.ts's module header
// explains why — 'recovered'/'latency_anomaly' rows are themselves the
// resolution event for a prior 'down' row, not something that resolves on
// its own), so this is the only alert type with a meaningful ongoing/
// resolved distinction to show.
function alertResolutionText(alert: AlertRow): string {
  if (alert.type !== 'down') return '';
  return alert.resolved_at ? `Resolved ${formatTimestamp(alert.resolved_at)}` : 'Ongoing';
}

const COST_RISK_COPY: Record<CostRiskState, string> = {
  Normal: 'Nothing unusual right now.',
  Learning: "Still learning your app's normal traffic — alerts may be more sensitive for the first week.",
  Elevated:
    'Traffic on your app looks unusual in the last 24 hours. This is a pattern, not a bill reading — worth a quick check of your usage dashboard.',
};

// Empty/placeholder state is acceptable on day one (spec §5.1) but must not
// be blank — fewer than 2 points can't draw a line, so show why instead of
// an empty box.
function renderSparkline(points: DashboardSparklinePoint[]): string {
  const values = points.map(p => p.latencyMs).filter((v): v is number => v !== null);
  if (values.length < 2) {
    return `<p class="muted-text">Still gathering response-time data — check back soon.</p>`;
  }
  const width = 280;
  const height = 40;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const range = max - min || 1;
  const step = width / (values.length - 1);
  const coords = values.map((v, i) => `${(i * step).toFixed(1)},${(height - ((v - min) / range) * height).toFixed(1)}`);
  return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" width="100%" height="${height}" preserveAspectRatio="none"><polyline points="${coords.join(' ')}" fill="none" stroke="var(--accent-dim)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" /></svg>`;
}

function renderSecurityDrift(drift: SecurityDriftSummary): string {
  switch (drift.state) {
    case 'no_baseline':
      return `<p class="muted-text" style="margin:0;">No baseline captured yet — we'll compare against your next check.</p>`;
    case 'check_failed':
      return `<p class="muted-text" style="margin:0;">Can't check security drift right now — we'll try again on the next check.</p>`;
    case 'no_changes':
      return `<p style="margin:0;">No changes since your last scan.</p>`;
    case 'new_findings': {
      const count = drift.findings.length;
      const rows = drift.findings
        .map(
          f => `      <div class="finding">
        <div class="finding-head"><span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span></div>
        <div class="finding-title">${escapeHtml(f.title)}</div>
      </div>`
        )
        .join('\n');
      return `<p style="margin:0 0 8px;">${count} new finding${count === 1 ? '' : 's'} since monitoring started:</p>\n${rows}`;
    }
  }
}

function renderAlerts(alerts: AlertRow[]): string {
  if (alerts.length === 0) {
    return `<p class="muted-text" style="margin:0;">No alerts yet — that's good news.</p>`;
  }
  return alerts
    .map(
      a => `    <div class="alert-row">
      <span class="alert-type">${escapeHtml(ALERT_TYPE_LABELS[a.type])}</span>
      <span class="alert-meta">${formatTimestamp(a.fired_at)}${alertResolutionText(a) ? ' · ' + alertResolutionText(a) : ''}</span>
    </div>`
    )
    .join('\n');
}

export function dashboardPage(data: DashboardData, nonce: string): string {
  const lastCheckedText = data.lastCheckAt ? formatTimestamp(data.lastCheckAt) : 'Not checked yet';
  const statusLabel = data.status === 'up' ? 'Up' : data.status === 'down' ? 'Down' : 'Unknown';

  const body = `    <div class="brand"><span class="brand-dot status-${data.status}"></span> vibecheck</div>
    <h1>Dashboard</h1>
    <p class="sub">${escapeHtml(data.monitorUrl)}</p>

    <div class="card">
      <h2>Live Site Health</h2>
      <div class="health-row">
        <span class="status-pill status-${data.status}">${statusLabel}</span>
        <span class="muted-text">Last checked ${lastCheckedText}${data.lastStatus !== null ? ` &middot; HTTP ${data.lastStatus}` : ''}</span>
      </div>
      ${renderSparkline(data.sparkline)}
    </div>

    <div class="card">
      <h2>Cost Risk</h2>
      <span class="risk-badge risk-${data.costRiskState.toLowerCase()}">${data.costRiskState}</span>
      <p class="muted-text" style="margin:0;">${COST_RISK_COPY[data.costRiskState]}</p>
    </div>

    <div class="card">
      <h2>Security Drift</h2>
      ${renderSecurityDrift(data.securityDrift)}
    </div>

    <div class="card">
      <h2>Alerts</h2>
${renderAlerts(data.alerts)}
    </div>

    <div class="card">
      <h2>Settings</h2>
      <p style="margin:0 0 14px;">Alerts go to <strong>${escapeHtml(data.alertEmail)}</strong></p>
      <button id="mute-toggle" data-monitor-id="${data.monitorId}" data-muted="${data.muted}">${data.muted ? 'Resume alerts' : 'Pause alerts for 24h'}</button>
      <p id="mute-status" class="muted-text" style="margin:10px 0 0;">${data.muted && data.mutedUntil ? `Alerts paused until ${formatTimestamp(data.mutedUntil)}` : 'Alerts are active.'}</p>
    </div>

<script nonce="${nonce}">
(function () {
  var btn = document.getElementById('mute-toggle');
  if (!btn) return;
  var statusEl = document.getElementById('mute-status');

  btn.addEventListener('click', async function () {
    var monitorId = btn.getAttribute('data-monitor-id');
    var currentlyMuted = btn.getAttribute('data-muted') === 'true';
    btn.disabled = true;

    try {
      var res = await fetch('/api/monitors/' + monitorId + '/mute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mute: !currentlyMuted }),
      });
      var data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Could not update mute setting.');
      btn.setAttribute('data-muted', String(data.muted));
      btn.textContent = data.muted ? 'Resume alerts' : 'Pause alerts for 24h';
      statusEl.textContent = data.muted ? 'Alerts paused until ' + data.mutedUntil : 'Alerts are active.';
    } catch (err) {
      statusEl.textContent = err.message || 'Something went wrong. Please try again.';
    } finally {
      btn.disabled = false;
    }
  });
})();
</script>`;

  return dashboardShell('Dashboard', body);
}
