// vibecheck — single-page frontend (plain HTML/CSS/JS, no framework).
// Served directly from the Worker. Calls POST /api/scan and renders the result.

export function landingPage(): string {
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

<script>
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
    if (!startBtn) return;

    startBtn.addEventListener('click', function () {
      step.style.display = 'block';
      startBtn.style.display = 'none';
      // Reuse whatever the user already typed in the optional deployed-URL
      // field on the scan form, if anything, so they don't retype it.
      if (deployedInput && deployedInput.value.trim()) {
        probeInput.value = deployedInput.value.trim();
      }
      probeInput.focus();
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
