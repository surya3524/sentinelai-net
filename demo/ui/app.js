// SentinelAI demo UI, shared by the server demo and the in-browser (WebAssembly) demo.
// The page defines window.sentinelTransport before loading this file:
//   cases() -> JSON text, run(body), approve(id, verdict), state() -> object,
//   reset(), policy() -> text, subscribe(onEvent, onStatus)
// plus label, optional homeUrl, and pollCases (re-read case files while presenting).
(() => {
const T = window.sentinelTransport;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

$('#app').innerHTML = `
<header>
  <div class="brand"><i>◈</i>SentinelAI <em>${esc(T.label)}</em></div>
  <div class="toggle">Sentinel <span id="pl" class="state-on">ON</span>
    <button class="switch" id="prot" role="switch" aria-checked="true" aria-label="Sentinel protection"></button></div>
  <span class="stat">Stopped<b id="sStop">0</b></span>
  <span class="stat">Damage<b id="sDmg">0</b></span>
  <span class="sp"></span>
  ${T.note ? `<span class="wasm-note">${esc(T.note)}</span>` : ''}
  <button class="hbtn" id="policyBtn">Policy</button>
  <button class="hbtn" id="resetBtn">Reset</button>
  ${T.homeUrl ? `<a class="hbtn" href="${esc(T.homeUrl)}">Site ↗</a>` : ''}
</header>
<main>
  <section>
    <div class="sh">Scenarios <span id="count"></span></div>
    <div class="scroll" id="cases"><div class="empty">Loading…</div></div>
  </section>
  <section>
    <div class="sh">Support agent · signed in as alice (C-1001)</div>
    <div class="scroll" id="chatWrap"><div id="chat"><div class="intro" id="intro"><h2>Run a scenario, then <em>flip the switch.</em></h2><p>Each one runs through input scanning, retrieval, the model, the tool firewall and output scanning. Turn Sentinel off to see the same agent unguarded.</p></div></div></div>
    <form id="f"><input id="msg" placeholder="Or type to the agent… e.g. Where is my order O-5001?" autocomplete="off" aria-label="Message"><button>Send</button></form>
  </section>
  <section class="tl">
    <div class="sh">Security timeline <span id="live">○ starting</span></div>
    <div class="scroll" id="timeline"></div>
    <div class="stateb"><div class="sh">System state</div><div class="scroll" id="state"></div></div>
  </section>
</main>
<dialog id="dlg"><div class="dh">sentinel.yaml <button class="hbtn" id="dlgClose">Close</button></div><pre id="pol"></pre></dialog>`;

let protection = true, stopped = 0;
const groups = {control:'Controls (should pass)',tool:'Tool firewall',output:'Output scanning',direct:'Direct injection',indirect:'Indirect / RAG injection',multi_turn:'Multi-turn',other:'Other'};

const sw = $('#prot');
sw.onclick = () => {
  protection = !protection;
  sw.setAttribute('aria-checked', protection);
  const l = $('#pl'); l.textContent = protection ? 'ON' : 'OFF'; l.className = protection ? 'state-on' : 'state-off';
};

// scenarios
let lastCases = '';
async function loadCases() {
  const raw = await T.cases();
  if (raw === lastCases) return;
  lastCases = raw;
  const cases = JSON.parse(raw);
  const box = $('#cases'); box.innerHTML = ''; $('#count').textContent = cases.length;
  const by = {};
  cases.forEach(c => (by[groups[c.category] ? c.category : 'other'] ??= []).push(c));
  for (const k of Object.keys(groups)) {
    if (!by[k]) continue;
    const g = document.createElement('div'); g.className = 'group'; g.innerHTML = `<h4>${groups[k]}</h4>`;
    by[k].forEach(c => {
      const b = document.createElement('button'); b.className = 'case';
      b.innerHTML = `<div class="t">${esc(c.title)}</div><div class="m"><span class="chip ${c.kind === 'attack' ? 'attack' : 'benign'}">${esc(c.kind)}</span>${c.technique ? `<span class="chip">${esc(c.technique)}</span>` : ''}${c.expected ? `<span class="chip">expect ${esc(c.expected)}</span>` : ''}</div>`;
      b.title = [c.reference, c.notes].filter(Boolean).join(' · ');
      b.onclick = () => run({caseId: c.id});
      g.append(b);
    });
    box.append(g);
  }
  if (!by.direct && !by.indirect && !by.multi_turn) {
    const e = document.createElement('div'); e.className = 'empty';
    e.innerHTML = 'No prompt-injection cases loaded yet. Add a JSON file of cases from a published benchmark or your red-team tool to <code>demo/Demo.Agent/cases/</code>.';
    box.append(e);
  }
}

async function run(body) {
  try { await T.run({...body, protection, pace: true}); }
  catch (e) { alert(e.message || e); }
}
$('#f').onsubmit = e => { e.preventDefault(); const m = $('#msg').value.trim(); if (!m) return; $('#msg').value = ''; run({message: m}); };

// chat
const chat = $('#chat'), wrap = $('#chatWrap');
function add(el) { $('#intro')?.remove(); chat.append(el); wrap.scrollTop = wrap.scrollHeight; }
function bubble(cls, html) { const d = document.createElement('div'); d.className = 'msg ' + cls; d.innerHTML = html; add(d); return d; }
function renderReply(text) {
  let h = esc(text).replace(/\[REDACTED:([A-Z_]+)\]/g, '<span class="red">REDACTED · $1</span>');
  // Never render images from model output: show what a browser would have fetched instead.
  h = h.replace(/!\[[^\]]*\]\(([^)\s]+)[^)]*\)/g, (m, u) => `<span class="leak">⚠ auto-loading image → ${u}</span>`);
  return h;
}

// timeline
const tl = $('#timeline');
function stepEl(s) {
  const d = document.createElement('div'); d.className = 'step';
  const f = (s.findings || []).filter(x => x.rule !== 'combined-score').slice(0, 5);
  d.innerHTML = `<div class="r"><span class="stage">${esc(s.stage)}</span><span class="badge b-${esc(s.action.split(' ')[0])}">${esc(s.action.replace('_', ' '))}</span></div>
   <div class="ttl">${esc(s.title)}</div><div class="d">${esc(s.detail)}</div>
   ${f.length ? `<ul>${f.map(x => `<li>${esc(x.scanner)}/${esc(x.rule)} ${(+x.confidence).toFixed(2)}${x.detail ? ' — ' + esc(x.detail) : ''}</li>`).join('')}</ul>` : ''}`;
  tl.append(d); tl.parentElement.scrollTop = tl.parentElement.scrollHeight;
}

// state
function renderState(s) {
  const dmg = s.effects.filter(e => e.severity === 'damage').length;
  const sd = $('#sDmg'); sd.textContent = dmg; sd.className = dmg ? 'bad' : '';
  $('#state').innerHTML = `<h6>Accounts</h6>${s.customers.map(c => `<div class="acct"><span>${esc(c.id)} · ${esc(c.name)}</span><span class="${c.status === 'closed' ? 'closed' : ''}">${esc(c.status)}</span></div>`).join('')}
   <h6>What actually happened</h6>${s.effects.length ? s.effects.slice().reverse().map(e => `<div class="eff ${e.severity}">${e.severity === 'damage' ? '✗ ' : '✓ '}${esc(e.text)}</div>`).join('') : '<div class="acct">Nothing yet.</div>'}`;
}

// live events
const handlers = {
  run(r) {
    const h = document.createElement('div'); h.className = 'runh' + (r.protection ? '' : ' off');
    h.textContent = `${r.title} · Sentinel ${r.protection ? 'on' : 'off'}`; add(h);
    r.turns.forEach(t => bubble('user', esc(t)));
    const th = document.createElement('div'); th.className = 'trun';
    th.innerHTML = `<span>${esc(r.title)}</span><span>${r.protection ? 'protected' : 'unprotected'}</span>`; tl.append(th);
  },
  step(s) {
    stepEl(s);
    if (/^(block|quarantine)/.test(s.action)) { stopped++; $('#sStop').textContent = stopped; }
  },
  done(d) { bubble('bot' + (d.outcome === 'block' ? ' blocked' : ''), renderReply(d.reply)); },
  approval(a) {
    const c = document.createElement('div'); c.className = 'approval'; c.id = 'ap-' + a.id;
    c.innerHTML = `<h5>Approval required · ${esc(a.tool)}</h5><code>${esc(a.call)}</code><p>${esc(a.reason)}</p><div class="act"><button class="ok">Approve</button><button>Reject</button></div>`;
    const [ok, no] = c.querySelectorAll('button');
    ok.onclick = () => T.approve(a.id, 'approve');
    no.onclick = () => T.approve(a.id, 'reject');
    add(c);
  },
  approval_resolved(r) {
    const c = document.getElementById('ap-' + r.id);
    if (c) c.querySelector('.act').outerHTML = `<div class="res">${r.approve ? '✓ Approved' : '✗ Rejected'} — ${esc(r.result)}</div>`;
  },
  state: renderState,
};

function status(ok) {
  const l = $('#live');
  l.textContent = ok ? '● live' : '○ reconnecting';
  l.style.color = ok ? 'var(--lime)' : '#ff8a85';
}

$('#policyBtn').onclick = async () => { $('#pol').textContent = await T.policy(); $('#dlg').showModal(); };
$('#dlgClose').onclick = () => $('#dlg').close();
$('#resetBtn').onclick = async () => { await T.reset(); chat.innerHTML = ''; tl.innerHTML = ''; stopped = 0; $('#sStop').textContent = 0; };

T.subscribe((type, data) => handlers[type]?.(data), status);
loadCases();
T.state().then(renderState);
if (T.pollCases) setInterval(loadCases, 5000);
})();
