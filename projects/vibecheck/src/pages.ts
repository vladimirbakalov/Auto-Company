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

  footer { text-align: center; color: var(--muted); font-size: 13px; margin-top: 48px; }
  footer a { color: var(--muted); }

  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(6,40,28,0.4); border-top-color: #06281c; border-radius: 50%; animation: spin 0.7s linear infinite; margin-right: 8px; vertical-align: -2px; }
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
        <input type="text" id="repo-input" placeholder="https://github.com/owner/repo" autocomplete="off" spellcheck="false" required />
        <button type="submit" id="scan-btn">Scan</button>
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

    resultEl.innerHTML = html;
    resultEl.style.display = 'block';
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    errorEl.style.display = 'none';
    resultEl.style.display = 'none';
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Scanning&hellip;';

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: input.value }),
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
