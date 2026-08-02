"""The analyst console: the one surface where a person changes a state.

The self-contained report (:mod:`engagement.report`) is deliberately read-only,
and stays that way. This is its counterpart — the page that *can* write, and
therefore the page that has to know who is using it. The two are not
alternatives: the report is an artifact you attach to a ticket and open with no
server, and this is an application you sign in to.

## The authentication model, and why this one

**OIDC authorization code with PKCE, token held in memory, sent as a bearer.**
No cookie, no server-side session, no refresh token on disk.

The control plane was already bearer-only, and that is worth preserving rather
than working around. A cookie would be sent by the browser automatically on
every request to this origin, which is precisely what makes CSRF possible; a
bearer token that only exists in a JavaScript variable is attached deliberately
or not at all, so a form on another site can no more write here than a stranger
can. The cost is that a page refresh signs you out again, and that is an
acceptable price for a console an analyst opens to adjudicate a queue.

PKCE rather than an implicit flow because the page is a public client and
cannot hold a secret: the code verifier never leaves the tab, and an
intercepted authorization code is useless without it.

## What the page is not allowed to decide

Every rule about *who may do what* is answered by the server and rendered here,
never re-implemented. ``/api/whoami`` returns the exact set of states this
principal may set, computed by the same function that enforces it, and the
console renders that list. An analyst is therefore never offered a control the
server will refuse — and, more importantly, the page hiding a control is a
courtesy rather than a protection: the server refuses regardless.

## Treating the queue as hostile

Every value rendered here comes from a repository under review. Titles, paths
and evidence are attacker-influenced text by construction, so nothing is ever
written into the document as markup — the page builds nodes and assigns
``textContent``. A finding titled ``<img onerror=…>`` renders as those
characters, which is the only thing it should ever be.
"""

from __future__ import annotations

_STYLE = """
:root { color-scheme: light dark; --bg:#fff; --fg:#1a1a1a; --muted:#5a5a5a;
  --line:#e2e2e2; --card:#f7f7f8; --ok:#1e7f4a; --warn:#8a6100; --bad:#a11;
  --accent:#2b5fa8; }
@media (prefers-color-scheme: dark) { :root { --bg:#111214; --fg:#e8e8ea;
  --muted:#9a9aa2; --line:#2a2b30; --card:#1a1b1f; --ok:#4ad990; --warn:#d9b44a;
  --bad:#e06a6a; --accent:#7fb0ff; } }
* { box-sizing: border-box; }
body { margin:0; padding:1.5rem 1.25rem 4rem; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
main { max-width: 82rem; margin: 0 auto; }
h1 { font-size:1.35rem; margin:0 0 .2rem; }
.sub { color:var(--muted); margin:0 0 1.25rem; font-size:.9rem; }
header.bar { display:flex; flex-wrap:wrap; gap:1rem; align-items:center;
  justify-content:space-between; border:1px solid var(--line); background:var(--card);
  border-radius:6px; padding:.75rem 1rem; margin-bottom:1.25rem; }
.who { font-size:.88rem; color:var(--muted); }
.who b { color:var(--fg); }
button { font:inherit; padding:.4rem .8rem; border-radius:5px; cursor:pointer;
  border:1px solid var(--line); background:var(--card); color:var(--fg); }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
button:disabled { opacity:.45; cursor:not-allowed; }
select, input, textarea { font:inherit; padding:.35rem .5rem; border-radius:5px;
  border:1px solid var(--line); background:var(--bg); color:var(--fg); max-width:100%; }
.scroll { overflow-x:auto; border:1px solid var(--line); border-radius:6px; }
table { border-collapse:collapse; width:100%; font-size:.88rem; }
th,td { text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line);
  vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.75rem; text-transform:uppercase;
  letter-spacing:.04em; position:sticky; top:0; background:var(--bg); }
tr:last-child td { border-bottom:none; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.86em; }
.tag { display:inline-block; padding:.05rem .4rem; border-radius:4px; font-size:.75rem;
  border:1px solid var(--line); white-space:nowrap; }
.tag.critical, .tag.high { color:var(--bad); border-color:var(--bad); }
.tag.medium { color:var(--warn); border-color:var(--warn); }
.bad { color:var(--bad); } .warn { color:var(--warn); } .ok { color:var(--ok); }
.muted { color:var(--muted); }
.empty { color:var(--muted); font-style:italic; padding:1.5rem; text-align:center; }
.row-actions { display:flex; gap:.4rem; align-items:center; flex-wrap:wrap; }
.note { min-width:11rem; }
#flash { position:sticky; top:0; z-index:5; }
.msg { border:1px solid var(--line); border-left-width:4px; border-radius:6px;
  padding:.6rem .9rem; margin-bottom:.75rem; font-size:.88rem; background:var(--card); }
.msg.err { border-left-color:var(--bad); }
.msg.ok { border-left-color:var(--ok); }
.msg.warn { border-left-color:var(--warn); }
.filters { display:flex; gap:.6rem; flex-wrap:wrap; align-items:center;
  margin-bottom:.75rem; font-size:.88rem; }
footer { margin-top:2rem; padding-top:1rem; border-top:1px solid var(--line);
  color:var(--muted); font-size:.82rem; }
tr.selected td { background:color-mix(in srgb, var(--accent) 12%, transparent); }
tr.clickable { cursor:pointer; }
dialog { border:1px solid var(--line); border-radius:8px; background:var(--bg);
  color:var(--fg); max-width:52rem; width:92vw; padding:0; }
dialog::backdrop { background:rgba(0,0,0,.45); }
.panel { padding:1.25rem 1.5rem 1.5rem; }
.panel h2 { margin:.25rem 0 .1rem; font-size:1.1rem; }
.panel h3 { margin:1.25rem 0 .4rem; font-size:.82rem; text-transform:uppercase;
  letter-spacing:.05em; color:var(--muted); }
.panel pre { background:var(--card); border:1px solid var(--line); border-radius:6px;
  padding:.6rem .75rem; overflow-x:auto; font-size:.82rem; white-space:pre-wrap;
  word-break:break-word; }
.panel ol, .panel ul { margin:.3rem 0; padding-left:1.2rem; }
.panel li { margin:.15rem 0; }
.close { position:sticky; top:0; float:right; }
.bar-actions { display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; }
.selection { border:1px solid var(--line); background:var(--card); border-radius:6px;
  padding:.6rem .9rem; margin-bottom:.75rem; display:flex; gap:.6rem;
  align-items:center; flex-wrap:wrap; font-size:.88rem; }
.breakdown { display:flex; flex-wrap:wrap; gap:1rem; margin:.4rem 0; }
.breakdown div { min-width:6rem; }
.breakdown span { display:block; color:var(--muted); font-size:.72rem;
  text-transform:uppercase; letter-spacing:.04em; }
.breakdown b { font-size:1.05rem; }
.hist { font-size:.84rem; }
.hist li { margin:.25rem 0; }
"""

# The whole application. Written as one script with no build step and no
# external origin, so the CSP in `api.SECURITY_HEADERS` can forbid everything
# except this document.
_SCRIPT = r"""
'use strict';

// The access token lives here and nowhere else. Not localStorage, not a
// cookie: a value the page must attach deliberately cannot be replayed by a
// cross-site request, and a refresh signing the analyst out is the price.
let TOKEN = null;
let REFRESH = null;          // also memory-only; a reload still signs you out
let REFRESH_TIMER = null;
let CONFIG = {};
let ME = null;
let FINDINGS = [];
let RUNS = [];
let CURRENT_RUN = null;
let SELECTED = new Set();

const $ = (id) => document.getElementById(id);

function flash(text, kind) {
  const box = $('flash');
  const el = document.createElement('div');
  el.className = 'msg ' + (kind || 'warn');
  el.textContent = text;           // never as markup: this can quote a finding
  box.replaceChildren(el);
  if (kind === 'ok') setTimeout(() => { if (box.firstChild === el) box.replaceChildren(); }, 4000);
}

// -- PKCE -------------------------------------------------------------------

function random(bytes) {
  const raw = new Uint8Array(bytes);
  crypto.getRandomValues(raw);
  return b64url(raw);
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function challenge(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

async function signIn() {
  // Development only, and only when the server said so. The server refuses to
  // enable this off loopback, so a page that offers it is a page nobody else
  // can reach.
  if (CONFIG.allow_token_entry) {
    const token = window.prompt('Development token for this local console:');
    if (!token) return;
    TOKEN = token.trim();
    await load();
    return;
  }
  if (!CONFIG.authorize_url || !CONFIG.client_id) {
    flash('This deployment has no identity provider configured, so there is '
      + 'nothing to sign in to.', 'err');
    return;
  }
  const verifier = random(48);
  const state = random(16);
  // sessionStorage, not localStorage: scoped to this tab and cleared with it.
  // The verifier is useless to anyone who cannot also receive the redirect.
  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('pkce_state', state);
  const url = new URL(CONFIG.authorize_url);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CONFIG.client_id);
  url.searchParams.set('redirect_uri', window.location.origin + '/');
  url.searchParams.set('scope', CONFIG.audience
    ? CONFIG.audience + '/.default openid profile'
    : 'openid profile');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', await challenge(verifier));
  url.searchParams.set('code_challenge_method', 'S256');
  window.location.assign(url.toString());
}

async function completeSignIn() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  if (!code) return false;
  const expected = sessionStorage.getItem('pkce_state');
  // A redirect whose state does not match the one this tab generated is not
  // this tab's redirect. Refusing it is what stops an injected code.
  if (!expected || params.get('state') !== expected) {
    flash('The sign-in response did not match this tab. Nothing was accepted; '
      + 'start again.', 'err');
    history.replaceState({}, '', '/');
    return false;
  }
  const verifier = sessionStorage.getItem('pkce_verifier');
  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('pkce_state');
  history.replaceState({}, '', '/');   // keep the code out of history and the title bar
  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CONFIG.client_id,
      code: code,
      redirect_uri: window.location.origin + '/',
      code_verifier: verifier || '',
    });
    const tokenUrl = CONFIG.token_url;
    if (!tokenUrl) throw new Error('no token endpoint configured');
    const res = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body,
    });
    if (!res.ok) throw new Error('token exchange failed');
    const data = await res.json();
    acceptTokens(data);
    return true;
  } catch (err) {
    flash('Sign-in did not complete. The identity provider rejected the exchange.', 'err');
    return false;
  }
}

function acceptTokens(data) {
  TOKEN = data.access_token;
  // The refresh token is held in memory alongside the access token, never in
  // storage. It keeps a working session alive across an access token's
  // lifetime; it does not survive a reload, which is the same trade the access
  // token makes and for the same reason.
  if (data.refresh_token) REFRESH = data.refresh_token;
  scheduleRefresh(Number(data.expires_in) || 0);
}

function scheduleRefresh(expiresIn) {
  if (REFRESH_TIMER) clearTimeout(REFRESH_TIMER);
  if (!REFRESH || !expiresIn) return;
  // Early, deliberately: refreshing at the moment of expiry races every
  // in-flight request against the clock, and a minute of margin costs nothing.
  const delay = Math.max(30, expiresIn - 60) * 1000;
  REFRESH_TIMER = setTimeout(refreshToken, delay);
}

async function refreshToken() {
  if (!REFRESH || !CONFIG.token_url) return false;
  try {
    const res = await fetch(CONFIG.token_url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CONFIG.client_id,
        refresh_token: REFRESH,
      }),
    });
    if (!res.ok) throw new Error('refresh rejected');
    acceptTokens(await res.json());
    return true;
  } catch (err) {
    // Signed out rather than silently broken: an expired session that keeps
    // showing a stale queue is worse than one that says so.
    TOKEN = null;
    REFRESH = null;
    ME = null;
    renderWho();
    flash('Your session expired. Sign in again to continue.', 'warn');
    return false;
  }
}

// -- API --------------------------------------------------------------------

async function api(path, options, retried) {
  const opts = Object.assign({ headers: {} }, options || {});
  opts.headers = Object.assign({}, opts.headers);
  if (TOKEN) opts.headers['authorization'] = 'Bearer ' + TOKEN;
  const res = await fetch(path, opts);
  let payload = null;
  try { payload = await res.json(); } catch (err) { payload = null; }
  if (!res.ok) {
    // One silent retry after a refresh: an access token that expired between
    // rendering a page and clicking a button should not surface as an error
    // the analyst has to understand.
    if (res.status === 401 && !retried && REFRESH && await refreshToken()) {
      return api(path, options, true);
    }
    // The server says 401 and 403 without saying which check failed. The page
    // does not invent a reason it was not told.
    const message = res.status === 401
      ? 'Not signed in, or the session has expired.'
      : res.status === 403
      ? 'Your account is not permitted to do that.'
      : res.status === 429
      ? 'Too many requests — the server is rate limiting this account. Wait a moment.'
      : res.status === 409
      ? 'A run against that target is already in progress.'
      : (payload && payload.error) || ('Request failed (' + res.status + ')');
    const error = new Error(message);
    error.status = res.status;
    throw error;
  }
  return payload;
}

// -- rendering --------------------------------------------------------------

function cell(row, text, className) {
  const td = document.createElement('td');
  td.textContent = text === null || text === undefined || text === '' ? '—' : String(text);
  if (className) td.className = className;
  row.appendChild(td);
  return td;
}

function severityTag(value) {
  const span = document.createElement('span');
  span.className = 'tag ' + String(value || '').toLowerCase();
  span.textContent = value || 'unknown';
  return span;
}

function stateLabel(decision) {
  if (!decision) return 'not reviewed';
  return decision.state + (decision.machine ? ' (proposed)' : '');
}

function renderWho() {
  const who = $('who');
  if (!ME) {
    who.textContent = 'Not signed in';
    $('signin').hidden = false;
    return;
  }
  who.replaceChildren();
  const name = document.createElement('b');
  name.textContent = ME.display || ME.subject;
  who.appendChild(name);
  const roles = document.createElement('span');
  roles.textContent = ' — ' + (ME.roles.length ? ME.roles.join(', ') : 'no roles');
  who.appendChild(roles);
  $('signin').hidden = true;
}

function matchesFilter(item) {
  const term = $('search').value.trim().toLowerCase();
  if ($('only-open').checked && item.decision && !item.decision.machine) return false;
  if (!term) return true;
  return [item.id, item.title, item.repo, item.path, item.component]
    .filter(Boolean).some((v) => String(v).toLowerCase().includes(term));
}

function renderRuns() {
  const picker = $('run');
  picker.replaceChildren();
  RUNS.forEach((run) => {
    const option = document.createElement('option');
    option.value = run.id;
    option.textContent = run.id + ' — ' + run.findings + ' finding(s)';
    if (run.id === CURRENT_RUN) option.selected = true;
    picker.appendChild(option);
  });
  picker.hidden = RUNS.length < 2;
  const current = RUNS.find((r) => r.id === CURRENT_RUN);
  const link = $('threat-link');
  link.hidden = !(current && current.has_threat_model);
}

function renderSelection() {
  const bar = $('selection');
  bar.hidden = SELECTED.size === 0;
  if (!SELECTED.size) return;
  $('selected-count').textContent = SELECTED.size + ' selected';
}

function renderQueue() {
  const body = $('rows');
  body.replaceChildren();
  const shown = FINDINGS.filter(matchesFilter);
  $('count').textContent = shown.length + ' of ' + FINDINGS.length + ' finding(s)';
  renderSelection();
  if (!shown.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 10;
    td.className = 'empty';
    td.textContent = FINDINGS.length
      ? 'Nothing matches this filter.'
      : 'This run produced no findings, which is not the same as none existing.';
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  shown.forEach((item) => body.appendChild(renderRow(item)));
}

function renderRow(item) {
  const tr = document.createElement('tr');
  if (SELECTED.has(item.id)) tr.className = 'selected';

  const pick = document.createElement('td');
  const box = document.createElement('input');
  box.type = 'checkbox';
  box.checked = SELECTED.has(item.id);
  box.setAttribute('aria-label', 'select ' + item.id);
  box.addEventListener('change', () => {
    if (box.checked) SELECTED.add(item.id); else SELECTED.delete(item.id);
    tr.className = box.checked ? 'selected' : '';
    renderSelection();
  });
  pick.appendChild(box);
  tr.appendChild(pick);

  const idCell = cell(tr, item.id);
  idCell.className = 'muted clickable';
  idCell.addEventListener('click', () => openDetail(item.id));
  const titleCell = cell(tr, item.title);
  titleCell.className = 'clickable';
  titleCell.addEventListener('click', () => openDetail(item.id));

  const sev = document.createElement('td');
  sev.appendChild(severityTag(item.severity));
  tr.appendChild(sev);

  cell(tr, typeof item.risk_score === 'number' ? item.risk_score.toFixed(1) : item.risk_score);
  cell(tr, item.kev ? 'KEV' : '', item.kev ? 'bad' : 'muted');
  cell(tr, item.path || item.component);
  cell(tr, item.severity_delta);
  cell(tr, stateLabel(item.decision), item.decision ? '' : 'muted');

  const actions = document.createElement('td');
  const wrap = document.createElement('div');
  wrap.className = 'row-actions';

  const select = document.createElement('select');
  const blank = document.createElement('option');
  blank.value = '';
  blank.textContent = 'set state…';
  select.appendChild(blank);
  (ME ? ME.may_set : []).forEach((state) => {
    const option = document.createElement('option');
    option.value = state;
    option.textContent = state;
    select.appendChild(option);
  });
  select.disabled = !ME || !ME.may_set.length;
  wrap.appendChild(select);

  const note = document.createElement('input');
  note.className = 'note';
  note.placeholder = 'why (recorded)';
  wrap.appendChild(note);

  const apply = document.createElement('button');
  apply.textContent = 'Apply';
  apply.disabled = select.disabled;
  apply.addEventListener('click', () => setState(item, select.value, note.value, apply));
  wrap.appendChild(apply);

  if (ME && ME.may_draft && CONFIG.drafting) {
    const poc = document.createElement('button');
    poc.textContent = 'Draft PoC';
    poc.title = 'Ask for a proof of concept. Runs automatically only for criticals.';
    poc.addEventListener('click', () => draftPoc(item, poc));
    wrap.appendChild(poc);
  }

  actions.appendChild(wrap);
  tr.appendChild(actions);
  return tr;
}

// -- detail -----------------------------------------------------------------

function section(parent, heading) {
  const h = document.createElement('h3');
  h.textContent = heading;
  parent.appendChild(h);
  return parent;
}

function para(parent, text, className) {
  const p = document.createElement('p');
  p.textContent = text;
  if (className) p.className = className;
  parent.appendChild(p);
  return p;
}

function pre(parent, text) {
  const el = document.createElement('pre');
  el.textContent = text;        // evidence is repository source; never markup
  parent.appendChild(el);
}

function scoreBreakdown(parent, f) {
  section(parent, 'Why it scores what it does');
  const grid = document.createElement('div');
  grid.className = 'breakdown';
  const parts = [
    ['final', f.risk_score.toFixed(1)],
    ['before adjustments', (f.base_score ?? f.risk_score).toFixed(1)],
    ['lifecycle', plus(f.lifecycle_adjust)],
    ['exposure', plus(f.exposure_adjust)],
    ['chaining', plus(f.chaining_adjust)],
    ['epss', f.epss === null || f.epss === undefined ? '—' : f.epss.toFixed(3)],
  ];
  parts.forEach(([label, value]) => {
    const cellEl = document.createElement('div');
    const s = document.createElement('span');
    s.textContent = label;
    const b = document.createElement('b');
    b.textContent = value;
    cellEl.append(s, b);
    grid.appendChild(cellEl);
  });
  parent.appendChild(grid);
  // Every adjustment this package applies is recorded beside the score rather
  // than folded into it, so the backbone's own number is always recoverable.
  // Saying so is the difference between an explanation and an assertion.
  para(parent, f.kev
    ? 'Listed in CISA KEV, so it cannot rank below the exploited floor whatever the blend says.'
    : 'Adjustments are recorded separately, so the score before them is '
      + 'recoverable by subtraction.',
    'muted');
}

function plus(value) {
  const n = Number(value || 0);
  return n ? (n > 0 ? '+' : '') + n.toFixed(1) : '—';
}

async function openDetail(fingerprint) {
  const dialog = $('detail');
  const panel = $('detail-body');
  panel.replaceChildren();
  para(panel, 'Loading…', 'muted');
  dialog.showModal();
  let data;
  try {
    const query = CURRENT_RUN ? '?run=' + encodeURIComponent(CURRENT_RUN) : '';
    data = await api('/api/findings/' + encodeURIComponent(fingerprint) + query);
  } catch (err) {
    panel.replaceChildren();
    para(panel, err.message, 'bad');
    return;
  }
  panel.replaceChildren();
  const f = data.finding;

  const title = document.createElement('h2');
  title.textContent = f.title || f.id;
  panel.appendChild(title);
  para(panel, [f.severity, f.repo, f.path || f.component].filter(Boolean).join(' · '), 'muted');

  scoreBreakdown(panel, f);

  if (f.evidence) {
    section(panel, 'Evidence');
    pre(panel, f.evidence);
  }

  section(panel, 'Reachability');
  para(panel, f.exposure_boundary
    ? 'Recon found a ' + f.exposure_boundary + ' boundary in this file, so it '
      + 'is reachable from outside.'
    : 'No request boundary was found in this file. That is weaker evidence '
      + 'than "unreachable" — recon only sees boundaries it recognises.');

  section(panel, 'Combinations');
  if (!data.chains_ran) {
    para(panel, 'Chain discovery did not run for this run, so nothing is known '
      + 'about how this finding combines.', 'muted');
  } else if (!data.chains.length) {
    para(panel, 'No chain references this finding.', 'muted');
  } else {
    const list = document.createElement('ul');
    data.chains.forEach((chain) => {
      const li = document.createElement('li');
      li.textContent = chain.title + ' — score ' + Number(chain.score).toFixed(1)
        + ', likelihood ' + Number(chain.likelihood).toFixed(2);
      list.appendChild(li);
    });
    panel.appendChild(list);
  }

  section(panel, 'Proof of concept');
  if (data.poc && data.poc.available) {
    if (data.poc.summary) para(panel, data.poc.summary);
    if (data.poc.preconditions && data.poc.preconditions.length) {
      para(panel, 'Preconditions — these decide whether the path is really '
        + 'open:', 'muted');
      const ul = document.createElement('ul');
      data.poc.preconditions.forEach((line) => {
        const li = document.createElement('li');
        li.textContent = line;
        ul.appendChild(li);
      });
      panel.appendChild(ul);
    }
    if (data.poc.steps && data.poc.steps.length) {
      const ol = document.createElement('ol');
      data.poc.steps.forEach((step) => {
        const li = document.createElement('li');
        li.textContent = step;
        ol.appendChild(li);
      });
      panel.appendChild(ol);
    }
    para(panel, 'A draft, not an exploit. Nothing here has been executed.', 'muted');
  } else if (!data.pocs_ran) {
    para(panel, 'No drafts were produced for this run.', 'muted');
  } else {
    para(panel, 'No draft for this finding. Drafting is automatic only for '
      + 'findings that come out critical — a bound on the appendix, not a '
      + 'judgement that no proof of concept exists.', 'muted');
  }

  section(panel, 'Decision history');
  if (!data.history.length) {
    para(panel, 'Nobody has recorded a decision about this finding.', 'muted');
  } else {
    const list = document.createElement('ul');
    list.className = 'hist';
    data.history.forEach((entry) => {
      const li = document.createElement('li');
      li.textContent = entry.state + ' — ' + (entry.actor_display || entry.actor)
        + (entry.machine ? ' (machine proposal)' : '')
        + ' at ' + entry.timestamp
        + (entry.note ? ' — ' + entry.note : '');
      list.appendChild(li);
    });
    panel.appendChild(list);
  }
}

// -- actions ----------------------------------------------------------------

async function setState(item, state, note, button) {
  if (!state) { flash('Choose a state first.', 'warn'); return; }
  button.disabled = true;
  try {
    const result = await api('/api/findings/' + encodeURIComponent(item.id) + '/state', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ state: state, note: note || null }),
    });
    item.decision = result.decision;
    // `applied` can be false even on a 200: a machine proposal loses to a
    // human decision, and the server reports what survived rather than what
    // was sent. Saying "saved" here would be a lie the page tells itself.
    if (result.applied) {
      flash('Recorded ' + result.decision.state + ' for ' + item.id + '.', 'ok');
    } else {
      flash('Not applied — an existing decision took precedence. Showing what is stored.', 'warn');
    }
    renderQueue();
  } catch (err) {
    flash(err.message, 'err');
  } finally {
    button.disabled = false;
  }
}

async function draftPoc(item, button) {
  button.disabled = true;
  const original = button.textContent;
  button.textContent = 'Drafting…';
  try {
    const path = '/api/findings/' + encodeURIComponent(item.id) + '/poc';
    const result = await api(path, { method: 'POST' });
    flash(result && result.drafted
      ? 'Draft written for ' + item.id + '.'
      : 'Nothing was drafted for ' + item.id + ' — that is not a judgement '
        + 'that no proof of concept exists.', result && result.drafted ? 'ok' : 'warn');
  } catch (err) {
    flash(err.message, 'err');
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function applyBulk() {
  const state = $('bulk-state').value;
  if (!state) { flash('Choose a state to apply.', 'warn'); return; }
  const note = $('bulk-note').value;
  const button = $('bulk-apply');
  button.disabled = true;
  try {
    const result = await api('/api/findings/state', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        state: state,
        note: note || null,
        fingerprints: [...SELECTED],
      }),
    });
    const byId = new Map(result.results.map((row) => [row.fingerprint, row]));
    FINDINGS.forEach((item) => {
      const row = byId.get(item.id);
      if (row) item.decision = row.decision;
    });
    SELECTED.clear();
    renderQueue();
    // Reports what survived, per finding. A count alone would hide that a
    // machine proposal lost to a human decision on some of them.
    flash(result.applied === result.total
      ? 'Recorded ' + state + ' on ' + result.total + ' finding(s).'
      : result.applied + ' of ' + result.total + ' applied; the rest already had a '
        + 'decision that took precedence.',
      result.applied === result.total ? 'ok' : 'warn');
  } catch (err) {
    flash(err.message, 'err');
  } finally {
    button.disabled = false;
  }
}

async function startRun() {
  const target = $('scan-target').value.trim();
  if (!target) { flash('Name a target to scan.', 'warn'); return; }
  const button = $('scan-start');
  button.disabled = true;
  try {
    const record = await api('/api/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: target, repo: $('scan-repo').value.trim() }),
    });
    flash('Started ' + record.target + '/' + record.run_id + '. This spends from '
      + 'the ceiling this deployment sets, not one you choose.', 'ok');
    $('scan').close();
    pollScan(record.id);
  } catch (err) {
    flash(err.message, 'err');
  } finally {
    button.disabled = false;
  }
}

async function pollScan(id) {
  let record;
  try {
    record = await api('/api/scans/' + encodeURIComponent(id));
  } catch (err) {
    return;
  }
  if (record.status === 'running') {
    setTimeout(() => pollScan(id), 5000);
    return;
  }
  // Exit 3 is "finished, but left work parked or unfunded". Showing that as a
  // failure teaches an analyst to ignore the status; showing it as success
  // hides that the run did not finish its backlog.
  const kind = record.status === 'complete' ? 'ok'
    : record.status === 'incomplete' ? 'warn' : 'err';
  flash(record.status === 'complete'
    ? record.target + '/' + record.run_id + ' finished.'
    : record.status === 'incomplete'
    ? record.target + '/' + record.run_id + ' finished but left work unreviewed.'
    : record.target + '/' + record.run_id + ' failed. ' + (record.tail.slice(-1)[0] || ''),
    kind);
  await loadRuns();
}

async function loadRuns() {
  try {
    const data = await api('/api/runs');
    RUNS = data.runs || [];
    if (!CURRENT_RUN || !RUNS.some((r) => r.id === CURRENT_RUN)) {
      // The run this console was started against, not merely the newest: an
      // operator who pointed at one run should be shown it.
      const chosen = RUNS.find((r) => r.selected) || RUNS[0];
      CURRENT_RUN = chosen ? chosen.id : null;
    }
    renderRuns();
  } catch (err) {
    RUNS = [];
    renderRuns();
  }
}

async function load() {
  try {
    ME = await api('/api/whoami');
    renderWho();
  } catch (err) {
    ME = null;
    renderWho();
    if (err.status !== 401) flash(err.message, 'err');
    return;
  }
  populateBulkStates();
  $('scan-open').hidden = !(CONFIG.runs_enabled && ME.roles.includes('scanner'));
  await loadRuns();
  try {
    const query = CURRENT_RUN ? '?run=' + encodeURIComponent(CURRENT_RUN) : '';
    const data = await api('/api/findings' + query);
    FINDINGS = data.findings || [];
    SELECTED.clear();
    renderQueue();
  } catch (err) {
    FINDINGS = [];
    renderQueue();
    flash(err.status === 503
      ? 'No queue is configured on this deployment, so there is nothing to review here yet.'
      : err.message, err.status === 503 ? 'warn' : 'err');
  }
}

function populateBulkStates() {
  const select = $('bulk-state');
  select.replaceChildren();
  const blank = document.createElement('option');
  blank.value = '';
  blank.textContent = 'set selected to…';
  select.appendChild(blank);
  (ME ? ME.may_set : []).forEach((state) => {
    const option = document.createElement('option');
    option.value = state;
    option.textContent = state;
    select.appendChild(option);
  });
}

async function start() {
  try {
    CONFIG = await api('/api/config');
  } catch (err) {
    flash('Could not read this deployment’s configuration.', 'err');
    return;
  }
  if (CONFIG.environment) {
    $('env').textContent = CONFIG.environment;
    $('env').hidden = false;
  }
  await completeSignIn();
  $('signin').addEventListener('click', signIn);
  $('refresh').addEventListener('click', load);
  $('search').addEventListener('input', renderQueue);
  $('only-open').addEventListener('change', renderQueue);
  $('run').addEventListener('change', (event) => {
    CURRENT_RUN = event.target.value;
    load();
  });
  $('select-all').addEventListener('change', (event) => {
    FINDINGS.filter(matchesFilter).forEach((item) => {
      if (event.target.checked) SELECTED.add(item.id); else SELECTED.delete(item.id);
    });
    renderQueue();
  });
  $('bulk-apply').addEventListener('click', applyBulk);
  $('bulk-clear').addEventListener('click', () => { SELECTED.clear(); renderQueue(); });
  $('detail-close').addEventListener('click', () => $('detail').close());
  $('scan-open').addEventListener('click', () => $('scan').showModal());
  $('scan-cancel').addEventListener('click', () => $('scan').close());
  $('scan-start').addEventListener('click', startRun);
  $('threat-link').addEventListener('click', () => {
    flash('threat-model.md is written beside the run’s other outputs; open '
      + 'it from the run directory.', 'warn');
  });
  await load();
}

start();
"""

_BODY = """
<main>
  <header class="bar">
    <div>
      <h1>Engagement queue <span id="env" class="tag" hidden></span></h1>
      <p class="sub" id="count">loading…</p>
    </div>
    <div class="bar-actions">
      <select id="run" aria-label="run" hidden></select>
      <button id="threat-link" hidden title="This run wrote a threat model">Threat model</button>
      <span class="who" id="who">Not signed in</span>
      <button id="scan-open" hidden>Start a scan</button>
      <button id="signin" class="primary" hidden>Sign in</button>
      <button id="refresh">Refresh</button>
    </div>
  </header>

  <div id="flash"></div>

  <div class="filters">
    <input id="search" type="search" placeholder="filter by id, title, repo or path">
    <label><input id="only-open" type="checkbox"> hide findings a person already decided</label>
  </div>

  <div class="selection" id="selection" hidden>
    <b id="selected-count">0 selected</b>
    <select id="bulk-state" aria-label="state for selected findings"></select>
    <input id="bulk-note" class="note" placeholder="why (recorded on each)">
    <button id="bulk-apply" class="primary">Apply to selected</button>
    <button id="bulk-clear">Clear</button>
  </div>

  <div class="scroll">
    <table>
      <thead>
        <tr>
          <th><input id="select-all" type="checkbox" aria-label="select all shown"></th>
          <th>Id</th><th>Finding</th><th>Severity</th><th>Score</th><th>KEV</th>
          <th>Where</th><th>Moved</th><th>State</th><th>Decide</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>

  <footer>
    Every state change is recorded against your verified identity and is
    auditable. A machine proposal never overwrites a decision a person made,
    and closing a finding needs the approver role — if a change does not apply,
    this page shows you what is stored rather than what you sent.
  </footer>
</main>

<dialog id="detail">
  <div class="panel">
    <button id="detail-close" class="close">Close</button>
    <div id="detail-body"></div>
  </div>
</dialog>

<dialog id="scan">
  <div class="panel">
    <h2>Start a scan</h2>
    <p class="sub">
      This reads a repository and spends model budget. The ceiling and the model
      are set by this deployment, not here — a caller-supplied ceiling is not a
      ceiling. One run per target at a time.
    </p>
    <p><input id="scan-target" size="40"
       placeholder="target (the workspace's name for it)"></p>
    <p><input id="scan-repo" size="40"
       placeholder="repository name recorded on findings (optional)"></p>
    <div class="row-actions">
      <button id="scan-start" class="primary">Start</button>
      <button id="scan-cancel">Cancel</button>
    </div>
  </div>
</dialog>
"""


def render() -> str:
    """The console as one self-contained document.

    No external asset of any kind, for the same reason the report has none: the
    page must work behind a private endpoint with no route to a CDN, and a
    console that silently degrades when a font server is unreachable is a
    console nobody trusts. It also lets the CSP forbid every origin but this
    document.
    """
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Engagement queue</title>"
        f"<style>{_STYLE}</style></head><body>"
        f"{_BODY}"
        f"<script>{_SCRIPT}</script>"
        "</body></html>"
    )
