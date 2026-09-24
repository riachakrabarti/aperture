'use strict';
const $ = id => document.getElementById(id);
let token = '', state = null, tab = 'runtime', profile = 'commercial';

const sampleArgs = tool => ({
  'external.send': {destination: profile === 'federal' ? 'partner.example' : 'outside.example'},
  'access.grant': {subject: 'employee-demo', role: 'reader'},
  'spend.commit': {amount_cents: 6000},
  'shell.execute': {cmd: 'synthetic'},
}[tool] || {});

function notice(text) { $('notice').textContent = text; $('notice').hidden = false; setTimeout(() => $('notice').hidden = true, 6000); }

async function api(path, body, credential = token) {
  const r = await fetch(path, {method: body === undefined ? 'GET' : 'POST',
    headers: {'Authorization': 'Bearer ' + credential, 'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await r.json();
  if (!r.ok) throw Error(data.error || r.statusText);
  return data;
}

function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }

function selectTab(name) {
  tab = name;
  for (const n of ['runtime', 'assurance', 'evidence']) $(n).hidden = n !== name;
  document.querySelectorAll('.nav').forEach(n => n.classList.toggle('active', n.dataset.tab === name));
  const headings = {
    runtime: ['Every action has a decision.', 'Exercise real policy enforcement against synthetic business tools.'],
    assurance: ['Prove the controls hold.', 'Run adversarial scenarios and inspect the resulting business state.'],
    evidence: ['Evidence you can verify.', 'Export signed decisions and reproduce policy evaluation independently.'],
  };
  $('pageTitle').textContent = headings[name][0];
  $('pageSubtitle').textContent = headings[name][1];
}

const P = () => state?.profiles?.[profile];

function setProfile(next, fromWorkflow = false) {
  profile = next;
  document.body.classList.toggle('federal', next === 'federal');
  document.querySelectorAll('.prof').forEach(b => { const on = b.dataset.profile === next; b.classList.toggle('active', on); b.setAttribute('aria-pressed', String(on)); });
  if (!fromWorkflow) {
    const match = state?.workflows.find(w => w.profile === next);
    $('workflow').value = match ? match.id : '';
    $('approvalId').value = '';
  }
  $('arguments').value = JSON.stringify(sampleArgs($('tool').value), null, 2);
  renderProfile(); renderWorkflow();
}

function renderProfile() {
  const p = P(); if (!p) return;
  $('createProfile').textContent = p.label;
  $('boundaryTitle').textContent = p.label + ' profile';
  $('profileSummary').textContent = p.summary;
  $('packLabel').textContent = p.label;
  const allow = p.egress_allowlist ? `Egress allowlist: ${p.egress_allowlist.join(', ')}.` : 'No egress allowlist.';
  $('packIntro').textContent = `${allow} Approvals last at most ${p.max_approval_ttl_seconds / 60} minutes. Rules below are policy data evaluated by OPA over the workflow's recorded history.`;
  $('rules').replaceChildren();
  for (const r of p.sequence_rules) {
    const li = el('li'); const head = el('div');
    head.append(el('code', r.pattern.join('  →  ')), el('span', r.overridable ? '  approvable' : '  hard block', r.overridable ? 'soft' : 'hard'));
    li.append(head, el('p', r.description)); $('rules').append(li);
  }
  $('tags').replaceChildren();
  for (const [name, t] of Object.entries(state.tools)) {
    const tr = el('tr'), cell = el('td');
    for (const tag of t.tags) cell.append(el('span', tag, 'tagchip'));
    for (const tag of (state.policy.data.aperture_config.profiles[profile].extra_tags[name] || [])) cell.append(el('span', tag + ' (profile)', 'tagchip added'));
    tr.append(el('td', name), cell); $('tags').append(tr);
  }
  const cov = state.control_coverage[profile];
  $('controlsTitle').textContent = profile === 'federal' ? 'Control evidence (draft 800-53 mapping)' : 'SIEM triage categories';
  $('controlsFramework').textContent = p.evidence.framework;
  $('controlsNote').textContent = cov ? `${cov.decisions} signed decisions in ${p.label} workflows. A row means the decision is offered as evidence toward that item, not that the control is satisfied.` : `No decisions in ${p.label} workflows yet.`;
  $('controls').replaceChildren();
  for (const [c, v] of Object.entries(cov?.controls || {}).sort((a, b) => a[0].localeCompare(b[0], undefined, {numeric: true}))) {
    const tr = el('tr'); tr.append(el('td', c), el('td', String(v.decisions)), el('td', String(v.denials))); $('controls').append(tr);
  }
  $('deployNotes').replaceChildren(...p.deployment_notes.map(n => el('li', n)));
}

function renderWorkflow() {
  const w = state?.workflows.find(w => w.id === $('workflow').value);
  if (!w) { $('workflowState').textContent = `No ${P()?.label || ''} workflow selected`; return; }
  const s = w.summary;
  const tags = s ? (s.tags_seen.filter(t => t.startsWith('source:')).join(', ') || 'none') : 'unavailable';
  const spent = s ? s.spent_cents : '?';
  $('workflowState').textContent = `${state.profiles[w.profile].label} · Sources touched: ${tags} · Spent: ${spent}/${w.budget} cents · ${w.state.unresolved ? 'QUARANTINED: unknown outcome' : 'Ready'}`;
}

async function refresh() {
  state = await api('/api/state');
  const ds = state.events.map(e => e.body).filter(e => e.kind === 'decision');
  $('decisions').textContent = ds.length;
  $('blocked').textContent = ds.filter(e => !e.decision.allow).length;
  $('coverage').textContent = state.coverage.percent === null ? '—' : state.coverage.percent + '%';
  $('coverageNote').textContent = `${state.coverage.matched_actions}/${state.coverage.observed_actions} observed synthetic actions`;
  if (!$('tool').options.length) {
    for (const name of [...Object.keys(state.tools), 'shell.execute']) $('tool').append(el('option', name));
    $('arguments').value = JSON.stringify(sampleArgs($('tool').value), null, 2);
  }
  const selected = $('workflow').value;
  $('workflow').replaceChildren();
  for (const w of state.workflows) {
    const src = w.summary?.tags_seen.some(t => t.startsWith('source:')) ? 'sources touched' : 'clear';
    const o = el('option', `${state.profiles[w.profile].label} · ${w.id.slice(0, 8)} · ${src} · ${w.summary?.spent_cents ?? '?'} cents`); o.value = w.id;
    $('workflow').append(o);
  }
  const none = el('option', 'Create a workflow to begin'); none.value = ''; $('workflow').prepend(none);
  $('workflow').value = state.workflows.some(w => w.id === selected) ? selected : '';
  renderWorkflow();
  $('timeline').replaceChildren();
  for (const e of ds.slice(-30).reverse()) {
    const tr = el('tr');
    tr.append(el('td', new Date(e.timestamp_ns / 1e6).toLocaleTimeString()));
    const who = el('td', e.agent); who.append(el('small', `${e.workflow.slice(0, 8)} · ${state.profiles[e.profile]?.label || e.profile}`));
    tr.append(who, el('td', e.tool));
    const badge = el('td'); badge.append(el('span', e.decision.allow ? 'ALLOW' : 'DENY', 'badge' + (e.decision.allow ? '' : ' deny')));
    const over = (e.decision.overridden || []).length ? ` (approved: ${e.decision.overridden.join(', ')})` : '';
    tr.append(badge, el('td', (e.decision.reasons.join(', ') || 'Policy satisfied') + over));
    tr.append(el('td', (e.decision.evidence?.controls || []).join(', ') || '—', 'ev'));
    $('timeline').append(tr);
  }
  if (!ds.length) { const tr = el('tr'), td = el('td', 'No decisions yet. Create a workflow and propose an action.'); td.colSpan = 6; tr.append(td); $('timeline').append(tr); }
  $('publicKey').textContent = state.public_key;
  $('policyHash').textContent = state.policy.hash.slice(0, 16);
  $('policySource').textContent = state.policy.source;
  $('policyData').textContent = JSON.stringify(state.policy.data, null, 2);
  renderProfile();
  renderTests(await api('/api/assurance'));
}

function renderTests(report) {
  if (report.status !== 'completed') return;
  $('testCount').textContent = `${report.passed}/${report.total}`;
  $('assuranceStatus').textContent = `${report.passed} of ${report.total} checks passed. ${report.scope}`;
  $('tests').replaceChildren();
  for (const t of report.tests) {
    const card = el('article', undefined, 'test'), flag = el('div');
    flag.append(el('span', t.passed ? 'PASS' : 'FAIL', 'badge' + (t.passed ? '' : ' deny')));
    const body = el('div');
    body.append(el('h3', t.name), el('p', t.evidence), el('small', `${t.control} · ${state?.profiles?.[t.profile]?.label || t.profile} profile · ${t.duration_ms} ms`));
    card.append(flag, body); $('tests').append(card);
  }
}

function action() {
  if (!$('workflow').value) throw Error('Create or select a workflow first.');
  return {workflow: $('workflow').value, agent: $('agent').value, tool: $('tool').value,
          arguments: JSON.parse($('arguments').value), approval_id: $('approvalId').value || null};
}

async function download(path, name) {
  const r = await fetch(path, {headers: {Authorization: 'Bearer ' + token}});
  if (!r.ok) throw Error('Export failed');
  const url = URL.createObjectURL(await r.blob()); const a = el('a'); a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function bind(id, fn) { $(id).addEventListener('click', async () => { const b = $(id); b.disabled = true; try { await fn(); } catch (e) { notice(e.message); } finally { b.disabled = false; } }); }

bind('connect', async () => { token = $('operatorToken').value.trim(); await refresh(); setProfile(profile); $('operatorToken').value = ''; $('login').hidden = true; $('workspace').hidden = false; });
bind('disconnect', async () => { token = ''; $('reviewerToken').value = ''; $('workspace').hidden = true; $('login').hidden = false; state = null; });
bind('refresh', refresh);
bind('newWorkflow', async () => {
  const w = await api('/api/workflows', {budget_cents: Number($('budget').value), profile});
  await refresh(); $('workflow').value = w.id; $('approvalId').value = ''; renderWorkflow();
  notice(`${P().label} workflow created. Its action history is held by the server.`);
});
bind('execute', async () => { const result = await api('/api/demo/call', action()); $('actionResult').textContent = JSON.stringify(result, null, 2); await refresh(); });
bind('approve', async () => {
  const reviewer = $('reviewerToken').value.trim();
  if (!reviewer) throw Error('Enter the separate reviewer token.');
  const result = await api('/api/approvals', {...action(), ttl: 300}, reviewer);
  $('approvalId').value = result.approval_id;
  notice('Exact-action approval created. Execute the unchanged action within five minutes.');
  await refresh();
});
bind('runTests', async () => { $('assuranceStatus').textContent = 'Running isolated runtime, outcome, profile and evidence checks. This takes about 20 seconds.'; const r = await api('/api/assurance/run', {}); renderTests(r); notice(`${r.passed}/${r.total} assurance checks passed.`); });
bind('verify', async () => { $('verifyResult').textContent = JSON.stringify(await api('/api/verify', {}), null, 2); });
bind('download', () => download('/api/evidence', 'aperture-evidence.zip'));
bind('siem', () => download('/api/siem', 'aperture-siem.ndjson'));
$('tool').addEventListener('change', () => { $('arguments').value = JSON.stringify(sampleArgs($('tool').value), null, 2); $('approvalId').value = ''; });
$('workflow').addEventListener('change', () => { const w = state?.workflows.find(w => w.id === $('workflow').value); if (w && w.profile !== profile) setProfile(w.profile, true); renderWorkflow(); $('approvalId').value = ''; });
document.querySelectorAll('.prof').forEach(b => b.addEventListener('click', () => { if (state) setProfile(b.dataset.profile); }));
document.querySelectorAll('.nav').forEach(b => b.addEventListener('click', () => selectTab(b.dataset.tab)));
