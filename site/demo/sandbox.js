// Browser sandbox for the Aperture dashboard. Mirrors aperture.py's Runtime, Ledger and
// evidence export in memory, evaluates the unmodified Rego policy compiled to WebAssembly,
// and serves the dashboard's /api/* calls by patching fetch. Nothing leaves this tab.
import opa from './vendor/opa-wasm-browser.esm.js';
const { loadPolicy } = opa;
import * as ed from './vendor/noble-ed25519.js';

const TOKENS = { 'demo-operator': 'operator', 'demo-reviewer': 'reviewer' };
const enc = new TextEncoder();

class Fault extends Error { constructor(status, message) { super(message); this.status = status; } }

// Same bytes as Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
function canonical(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw Error('nonfinite'); return JSON.stringify(v); }
  if (typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => Uint8Array.from(h.match(/../g), x => parseInt(x, 16));
const b64 = b => btoa(String.fromCharCode(...b));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const sha256 = async bytes => hex(await crypto.subtle.digest('SHA-256', bytes));
const digest = v => sha256(enc.encode(canonical(v)));
const uid = () => crypto.randomUUID();
const nowNs = () => Math.round((performance.timeOrigin + performance.now()) * 1e6);
const round = (x, n) => Math.round(x * 10 ** n) / 10 ** n;

let POLICY, POLICY_HASH, REGO, DATA_TEXT, CONFIG;

async function query(rule, input) {
  const r = POLICY.evaluate(input, 'aperture/' + rule);
  if (!r?.length || !('result' in r[0])) throw Error('OPA returned no result for ' + rule);
  return r[0].result;
}

function validateArgs(tool, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Fault(400, 'arguments must be an object');
  const schema = CONFIG.tools[tool]?.inputSchema;
  if (!schema) return; // OPA handles unknown tools with a signed deny decision.
  const keys = Object.keys(args), props = Object.keys(schema.properties);
  if (!(schema.required || []).every(k => keys.includes(k)) || !keys.every(k => props.includes(k)))
    throw new Fault(400, 'arguments do not match the registered tool schema');
  for (const [k, v] of Object.entries(args)) {
    const spec = schema.properties[k];
    if (spec.type === 'integer') {
      const lo = spec.minimum ?? 1, hi = spec.maximum ?? 1000000;
      if (!Number.isInteger(v) || v < lo || v > hi) throw new Fault(400, `${k} must be an integer from ${lo} to ${hi}`);
    } else if (typeof v !== 'string' || v.length < 1 || v.length > 256) throw new Fault(400, 'text arguments must contain 1 to 256 characters');
  }
}

function fallbackEvidence(profile, reason) {
  const p = CONFIG.profiles[profile]?.evidence || {};
  return { profile, framework: p.framework || 'none', controls: [...new Set([...(p.baseline || []), ...((p.by_reason || {})[reason] || [])])].sort(), engine: 'fallback' };
}

class Runtime {
  static async create() {
    const r = new Runtime();
    r.secret = ed.utils.randomSecretKey();
    r.public = b64(await ed.getPublicKeyAsync(r.secret));
    return r;
  }
  constructor() {
    this.events = []; this.workflows = new Map(); this.histories = new Map(); this.approvals = new Map();
    this.requests = new Map(); this.actions = []; this.policyUp = true; this.downstreamFailNext = false;
  }

  async append(body) {
    const prev = this.events.at(-1);
    body = { ...body, seq: prev ? prev.body.seq + 1 : 1, previous_hash: prev ? prev.hash : '0'.repeat(64), timestamp_ns: nowNs() };
    const hash = await digest(body);
    const signature = b64(await ed.signAsync(unhex(hash), this.secret));
    const e = { body, hash, signature };
    this.events.push(e);
    return e;
  }

  async checkpoint() {
    const body = { count: this.events.length, head: this.events.at(-1)?.hash || '0'.repeat(64), public_key: this.public };
    return { body, signature: b64(await ed.signAsync(enc.encode(canonical(body)), this.secret)) };
  }

  async createWorkflow(owner = 'operator', agents = null, budget = 10000, profile = 'commercial') {
    if (!Number.isInteger(budget) || budget < 1 || budget > 1000000) throw new Fault(400, 'invalid budget');
    if (!CONFIG.profiles[profile]) throw new Fault(400, 'unknown profile; expected one of ' + Object.keys(CONFIG.profiles).join(', '));
    agents = agents || ['agent-a', 'agent-b'];
    const id = uid();
    this.workflows.set(id, { id, owner, agents, state: { unresolved: false }, budget, profile });
    this.histories.set(id, []);
    await this.append({ kind: 'workflow_created', workflow: id, owner, agents, budget_cents: budget, profile, policy_hash: POLICY_HASH });
    return { id, owner, agents, budget_cents: budget, profile };
  }

  workflow(w) {
    const row = this.workflows.get(w);
    if (!row) throw new Fault(404, 'unknown workflow; agents cannot create or reset workflows');
    return row;
  }

  policyInput(row, tool, args, approvalValid) {
    return { profile: row.profile, tool, arguments: args, history: this.histories.get(row.id).map(h => ({ ...h })),
             state: { unresolved: !!row.state.unresolved }, budget_cents: row.budget, approval_valid: approvalValid };
  }

  async approve(w, actor, tool, args, ttl = 300) {
    validateArgs(tool, args);
    const row = this.workflow(w);
    if (actor === row.owner || row.agents.includes(actor)) throw new Fault(403, 'self approval forbidden');
    let terms;
    try { if (!this.policyUp) throw Error('down'); terms = await query('approval_terms', this.policyInput(row, tool, args, false)); }
    catch { throw new Fault(503, 'policy engine unavailable; approvals are not issued'); }
    if (!terms.approvable) throw new Fault(400, 'policy does not allow an approval to override this action');
    const limit = terms.max_ttl_seconds ?? 900;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > limit) throw new Fault(400, `approval expiry must be 1..${limit} seconds for this profile`);
    const id = uid(), fingerprint = await digest({ tool, arguments: args }), expires = Date.now() / 1000 + ttl;
    this.approvals.set(id, { id, workflow: w, fingerprint, approver: actor, expires, used: false });
    await this.append({ kind: 'approval', workflow: w, profile: row.profile, approval_id: id, approver: actor, action_hash: fingerprint, expires });
    return { approval_id: id, expires };
  }

  async call(w, agent, tool, args, requestId, approvalId = null, transportSession = null) {
    validateArgs(tool, args);
    if (typeof requestId !== 'string' || requestId.length < 1 || requestId.length > 128) throw new Fault(400, 'request_id required (1..128 characters)');
    const start = performance.now();
    const row = this.workflow(w);
    if (!row.agents.includes(agent)) throw new Fault(403, 'agent is not assigned to this workflow');
    const actionHash = await digest({ tool, arguments: args });
    const fp = await digest({ agent, action_hash: actionHash, approval_id: approvalId });
    const key = w + '\n' + requestId, previous = this.requests.get(key);
    if (previous) {
      if (previous.fingerprint !== fp) throw new Fault(409, 'request_id cannot be reused for a different action');
      return { ...previous.result, idempotent_replay: true };
    }
    const approval = approvalId ? this.approvals.get(approvalId) : null;
    const valid = !!(approval && approval.workflow === w && !approval.used && approval.expires > Date.now() / 1000 && approval.fingerprint === actionHash);
    const value = this.policyInput(row, tool, args, valid);
    const policyStart = performance.now();
    let decision, engineError = null;
    try {
      if (!this.policyUp) throw Error('down');
      decision = this.brokenPolicy ? { allow: true, reasons: [], overridden: [], evidence: { profile: row.profile, framework: 'none', controls: [] } }
        : await query('decision', value);
      if (typeof decision?.allow !== 'boolean' || !Array.isArray(decision.reasons)) throw Error('invalid decision');
    } catch {
      decision = { allow: false, reasons: ['policy_unavailable'], overridden: [], evidence: fallbackEvidence(row.profile, 'policy_unavailable') };
      engineError = 'OPA unavailable or invalid response; fail closed';
    }
    const policyMs = round(performance.now() - policyStart, 3);
    const d = uid();
    await this.append({ kind: 'decision', decision_id: d, workflow: w, profile: row.profile, agent, initiating_human: row.owner,
      transport_session: transportSession, request_id: requestId, tool, arguments_hash: await digest(args),
      policy_hash: POLICY_HASH, policy_input: value, decision, approval_id: approvalId,
      approver: valid ? approval.approver : null, policy_ms: policyMs, engine_error: engineError });
    const result = { decision_id: d, allow: decision.allow, reasons: decision.reasons, overridden: decision.overridden || [],
      controls: decision.evidence?.controls || [], profile: row.profile, status: 'blocked', policy_ms: policyMs };
    if (decision.allow) {
      // Reserve before dispatch, as in aperture.py: the action joins policy-visible history now.
      row.state.unresolved = true;
      this.histories.get(w).push({ tool, arguments: args });
      if (valid) approval.used = true;
      result.status = 'unresolved';
    }
    this.requests.set(key, { fingerprint: fp, result });
    if (decision.allow) {
      try {
        const outcome = this.dispatch(w, d, tool, args);
        Object.assign(result, { status: 'completed', outcome });
        row.state.unresolved = false;
      } catch {
        Object.assign(result, { status: 'unresolved', error: 'Downstream result unknown; workflow quarantined; no automatic retry' });
      }
      await this.append({ kind: 'outcome', workflow: w, decision_id: d, status: result.status, outcome: result.outcome ?? null });
    }
    result.elapsed_ms = round(performance.now() - start, 3);
    return result;
  }

  // Synthetic downstream tool service with its own ledger, deduplicated by decision ID.
  dispatch(w, d, tool, args) {
    if (this.downstreamFailNext) { this.downstreamFailNext = false; throw Error('503'); }
    const existing = this.actions.find(a => a.id === d);
    if (existing) return JSON.parse(existing.result);
    const payload = { execution_id: d, tool, status: 'completed', synthetic: true };
    if (tool === 'crm.read') payload.records = [{ id: 'demo-customer', classification: 'restricted' }];
    if (tool === 'access.grant') payload.membership = args;
    if (tool === 'spend.commit') payload.committed_cents = args.amount_cents;
    this.actions.push({ id: d, workflow: w, decision_id: d, tool, args: canonical(args), result: canonical(payload) });
    return payload;
  }

  async snapshot() {
    const decisions = this.events.map(e => e.body).filter(b => b.kind === 'decision');
    const matched = await matchedActions(decisions, this.actions);
    const workflows = [];
    for (const r of [...this.workflows.values()].reverse()) {
      let summary = null;
      try { summary = await query('summary', { profile: r.profile, history: this.histories.get(r.id) }); } catch {}
      workflows.push({ ...r, agents: [...r.agents], state: { ...r.state }, summary });
    }
    const n = this.actions.length;
    const pick = (o, ks) => Object.fromEntries(ks.map(k => [k, o[k]]));
    return {
      workflows, events: this.events, public_key: this.public, checkpoint: await this.checkpoint(),
      coverage: { observed_actions: n, matched_actions: matched, unmatched_actions: n - matched, percent: n ? round(100 * matched / n, 1) : null,
                  scope: 'Synthetic downstream service only; no account-wide visibility', unknown: 'All other execution paths' },
      policy: { hash: POLICY_HASH, source: REGO, data: JSON.parse(DATA_TEXT) },
      profiles: Object.fromEntries(Object.entries(CONFIG.profiles).map(([k, v]) => [k, pick(v, ['label', 'summary', 'egress_allowlist', 'max_approval_ttl_seconds', 'sequence_rules', 'evidence', 'deployment_notes'])])),
      tools: Object.fromEntries(Object.entries(CONFIG.tools).map(([k, v]) => [k, { tags: v.tags }])),
      control_coverage: controlCoverage(decisions), synthetic: true,
    };
  }

  siem() {
    return this.events.map(e => JSON.stringify({ time: e.body.timestamp_ns / 1e9, sourcetype: 'aperture:decision', event: e })).join('\n');
  }

  // Same member set and signed manifest as Runtime.bundle(), so verify_bundle.py accepts it.
  async bundle() {
    const s = await this.snapshot();
    const files = [
      ['events.json', JSON.stringify(s.events, null, 2)],
      ['checkpoint.json', JSON.stringify(s.checkpoint, null, 2)],
      ['public_key.txt', s.public_key],
      ['policy.rego', REGO],
      ['policy_data.json', DATA_TEXT],
      ['controls.json', JSON.stringify(s.control_coverage, null, 2)],
      ['control-evidence.csv', controlCsv(s.events)],
      ['downstream.json', JSON.stringify(this.actions, null, 2)],
      ['coverage.json', JSON.stringify(s.coverage, null, 2)],
      ['siem.ndjson', this.siem()],
      ['README.txt', 'Synthetic pilot evidence from the Aperture browser sandbox. The signing key was generated in the browser for this session only. Structured decision inputs are retained. No raw model prompts. Verify with verify_bundle.py. Retain the key and checkpoint separately. Policy replay is not agent replay. No certification or complete-coverage claim.\n'
        + 'controls.json and control-evidence.csv map decisions to the framework named in each profile. The federal-adjacent mapping to NIST SP 800-53 is a DRAFT that has not been reviewed by an assessor; it indicates where evidence would be offered, not that a control is satisfied.\n'],
    ].map(([name, text]) => [name, enc.encode(text)]);
    const hashes = {};
    for (const [name, bytes] of files) hashes[name] = await sha256(bytes);
    const body = { format: 'aperture-bundle-v1', files: hashes };
    const manifest = { body, signature: b64(await ed.signAsync(enc.encode(canonical(body)), this.secret)) };
    files.push(['manifest.json', enc.encode(canonical(manifest))]);
    return zip(files);
  }
}

async function matchedActions(decisions, actions) {
  const allowed = new Map(decisions.filter(d => d.decision.allow).map(d => [d.decision_id, d]));
  const seen = new Set(); let count = 0;
  for (const a of actions) {
    const d = allowed.get(a.decision_id);
    let ok = false;
    try {
      ok = !!d && a.id === d.decision_id && !seen.has(a.id) && a.workflow === d.workflow && a.tool === d.tool
        && await digest(JSON.parse(a.args)) === d.arguments_hash && JSON.parse(a.result).execution_id === d.decision_id;
    } catch { ok = false; }
    if (ok) { seen.add(a.id); count++; }
  }
  return count;
}

function controlCoverage(decisions) {
  const out = {};
  for (const d of decisions) {
    const ev = d.decision.evidence || {};
    const prof = out[d.profile || 'unknown'] ??= { framework: ev.framework || 'none', decisions: 0, controls: {} };
    prof.decisions++;
    for (const c of ev.controls || []) {
      const item = prof.controls[c] ??= { decisions: 0, denials: 0 };
      item.decisions++; item.denials += d.decision.allow ? 0 : 1;
    }
  }
  return out;
}

function controlCsv(events) {
  const rows = ['control,profile,framework,seq,decision_id,workflow,agent,tool,allow,reasons'];
  for (const e of events) {
    const b = e.body;
    if (b.kind !== 'decision') continue;
    const ev = b.decision.evidence || {};
    for (const c of ev.controls || []) {
      const cells = [c, b.profile ?? '', ev.framework ?? '', String(b.seq), b.decision_id, b.workflow, b.agent, b.tool, String(b.decision.allow), b.decision.reasons.join(' ')];
      rows.push(cells.map(x => '"' + x.replaceAll('"', '""') + '"').join(','));
    }
  }
  return rows.join('\n') + '\n';
}

async function verify(events, checkpoint, trustedKey) {
  const pub = unb64(trustedKey);
  if (!await ed.verifyAsync(unb64(checkpoint.signature), enc.encode(canonical(checkpoint.body)), pub)) throw Error('checkpoint signature invalid');
  if (checkpoint.body.public_key !== trustedKey) throw Error('untrusted checkpoint key');
  let previous = '0'.repeat(64), i = 0;
  for (const e of events) {
    i++;
    const b = e.body;
    if (b.seq !== i || b.previous_hash !== previous || await digest(b) !== e.hash) throw Error('event chain mismatch');
    if (!await ed.verifyAsync(unb64(e.signature), unhex(e.hash), pub)) throw Error('event signature invalid');
    previous = e.hash;
  }
  if (checkpoint.body.count !== events.length || checkpoint.body.head !== previous) throw Error('checkpoint mismatch (missing or extra events)');
  return { valid: true, events: events.length, head: previous };
}

// Minimal ZIP writer (stored entries) for the evidence bundle.
function zip(files) {
  const table = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc32 = b => { let c = 0xffffffff; for (const x of b) c = table[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const parts = [], central = []; let offset = 0;
  const header = (size, fill) => { const h = new DataView(new ArrayBuffer(size)); fill(h); return new Uint8Array(h.buffer); };
  for (const [name, data] of files) {
    const n = enc.encode(name), crc = crc32(data);
    const local = header(30, h => { h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(8, 0, true); h.setUint32(14, crc, true);
      h.setUint32(18, data.length, true); h.setUint32(22, data.length, true); h.setUint16(26, n.length, true); });
    central.push(header(46, h => { h.setUint32(0, 0x02014b50, true); h.setUint16(4, 20, true); h.setUint16(6, 20, true); h.setUint32(16, crc, true);
      h.setUint32(20, data.length, true); h.setUint32(24, data.length, true); h.setUint16(28, n.length, true); h.setUint32(42, offset, true); }), n);
    parts.push(local, n, data); offset += 30 + n.length + data.length;
  }
  const size = central.reduce((s, p) => s + p.length, 0);
  const end = header(22, h => { h.setUint32(0, 0x06054b50, true); h.setUint16(8, files.length, true); h.setUint16(10, files.length, true);
    h.setUint32(12, size, true); h.setUint32(16, offset, true); });
  return new Blob([...parts, ...central, end], { type: 'application/zip' });
}

// ---- Assurance: isolated runtimes exercising the same WASM policy, checking downstream effects.

async function runSuite() {
  const rows = [];
  const check = (ok, msg) => { if (!ok) throw Error(msg); };
  async function kase(name, control, fn, profile = 'commercial') {
    const started = performance.now();
    const r = await Runtime.create();
    const w = (await r.createWorkflow('operator', null, 10000, profile)).id;
    const call = (tool, args = {}, agent = 'agent-a', approval = null, req = uid()) => r.call(w, agent, tool, args, req, approval);
    try {
      rows.push({ name, control, profile, passed: true, evidence: await fn(r, w, call), duration_ms: round(performance.now() - started, 2) });
    } catch (e) {
      rows.push({ name, control, profile, passed: false, evidence: e.message, duration_ms: round(performance.now() - started, 2) });
    }
  }
  const sent = r => r.actions.some(a => a.tool === 'external.send');

  await kase('Collect → archive → send blocked', 'trajectory', async (r, w, call) => {
    await call('crm.read'); await call('archive.create');
    const a = await call('external.send', { destination: 'outside.example' });
    check(!a.allow && !sent(r), 'sequence was allowed');
    return 'Read and archive executed; external send absent from the synthetic tool ledger.';
  });
  await kase('Agent handoff preserves restriction', 'trajectory', async (r, w, call) => {
    await call('crm.read');
    const a = await call('external.send', { destination: 'outside.example' }, 'agent-b');
    check(!a.allow && !sent(r), 'handoff bypassed the restriction');
    return 'agent-b inherited agent-a’s restricted read through the shared workflow history.';
  });
  await kase('Legitimate unrestricted send succeeds', 'trajectory', async (r, w, call) => {
    const a = await call('external.send', { destination: 'outside.example' });
    check(a.allow && sent(r), 'clean send was blocked');
    return 'No restricted source in history; send allowed and observed downstream.';
  });
  await kase('Approval controls actual access grant', 'approval', async (r, w, call) => {
    const args = { subject: 'employee-demo', role: 'reader' };
    const a = await call('access.grant', args);
    check(!a.allow && !r.actions.length, 'unapproved grant executed');
    const ap = await r.approve(w, 'reviewer', 'access.grant', args);
    const b = await call('access.grant', args, 'agent-a', ap.approval_id);
    check(b.allow && r.actions.length === 1, 'approved grant did not execute');
    return 'Denied without approval; executed once with an exact-action approval.';
  });
  await kase('Parameter substitution rejected', 'approval', async (r, w, call) => {
    const ap = await r.approve(w, 'reviewer', 'access.grant', { subject: 'employee-demo', role: 'reader' });
    const a = await call('access.grant', { subject: 'employee-demo', role: 'admin' }, 'agent-a', ap.approval_id);
    check(!a.allow && !r.actions.length, 'substituted arguments executed');
    return 'Approval for role=reader did not authorize role=admin.';
  });
  await kase('Approval replay rejected', 'approval', async (r, w, call) => {
    const args = { subject: 'employee-demo', role: 'reader' };
    const ap = await r.approve(w, 'reviewer', 'access.grant', args);
    await call('access.grant', args, 'agent-a', ap.approval_id);
    const b = await call('access.grant', args, 'agent-a', ap.approval_id);
    check(!b.allow && r.actions.length === 1, 'approval reused');
    return 'Second use of a consumed approval denied; one downstream grant.';
  });
  await kase('Expired approval rejected', 'approval', async (r, w, call) => {
    const args = { subject: 'employee-demo', role: 'reader' };
    const ap = await r.approve(w, 'reviewer', 'access.grant', args);
    r.approvals.get(ap.approval_id).expires = Date.now() / 1000 - 1;
    const a = await call('access.grant', args, 'agent-a', ap.approval_id);
    check(!a.allow && !r.actions.length, 'expired approval accepted');
    return 'Approval past its expiry did not authorize the action.';
  });
  await kase('Separation of duties enforced', 'approval', async (r, w) => {
    for (const actor of ['operator', 'agent-a']) {
      try { await r.approve(w, actor, 'access.grant', { subject: 'employee-demo', role: 'reader' }); throw Error(actor + ' self-approved'); }
      catch (e) { check(e.status === 403, e.message); }
    }
    return 'Workflow owner and member agent cannot approve their own workflow.';
  });
  await kase('Cumulative spend cannot exceed cap', 'budget', async (r, w, call) => {
    await call('spend.commit', { amount_cents: 6000 });
    const b = await call('spend.commit', { amount_cents: 6000 });
    check(!b.allow && r.actions.length === 1, 'budget exceeded');
    return '6,000 + 6,000 cents against a 10,000-cent cap: second commit denied.';
  });
  await kase('Idempotent retries and conflicts', 'integrity', async (r, w, call) => {
    await call('spend.commit', { amount_cents: 100 }, 'agent-a', null, 'retry-1');
    const again = await call('spend.commit', { amount_cents: 100 }, 'agent-a', null, 'retry-1');
    check(again.idempotent_replay && r.actions.length === 1, 'retry executed twice');
    try { await call('spend.commit', { amount_cents: 200 }, 'agent-a', null, 'retry-1'); throw Error('conflicting reuse accepted'); }
    catch (e) { check(e.status === 409, e.message); }
    return 'Same request ID returned the cached result; a different action under it was refused.';
  });
  await kase('Unknown tools fail closed', 'boundary', async (r, w, call) => {
    const a = await call('shell.execute', { cmd: 'synthetic' });
    check(!a.allow && a.reasons.includes('unknown_tool') && !r.actions.length, 'unknown tool allowed');
    return 'Unregistered tool denied with a signed decision.';
  });
  await kase('Policy outage fails closed', 'availability', async (r, w, call) => {
    r.policyUp = false;
    const a = await call('crm.read');
    check(!a.allow && a.reasons.includes('policy_unavailable') && !r.actions.length, 'executed without policy');
    return 'With the engine unavailable, the call was denied and nothing executed.';
  });
  await kase('Unknown outcome quarantines workflow', 'integrity', async (r, w, call) => {
    r.downstreamFailNext = true;
    const a = await call('crm.read');
    const b = await call('archive.create');
    check(a.status === 'unresolved' && !b.allow && b.reasons.includes('workflow_unresolved'), 'workflow not quarantined');
    return 'Ambiguous downstream result quarantined the workflow; further actions denied.';
  });
  await kase('Negative control exposes broken enforcement', 'assurance', async (r, w, call) => {
    r.brokenPolicy = true; // Deliberately permissive stand-in for the policy.
    await call('crm.read'); await call('archive.create');
    await call('external.send', { destination: 'outside.example' });
    check(sent(r), 'broken policy went unnoticed');
    return 'With an allow-everything policy, the send reached the tool ledger, so the trajectory check above would fail as it should.';
  });
  await kase('Signed chain and checkpoint verification', 'evidence', async (r, w, call) => {
    await call('crm.read'); await call('external.send', { destination: 'outside.example' });
    const cp = await r.checkpoint();
    await verify(r.events, cp, r.public);
    const tampered = structuredClone(r.events); tampered[1].body.tool = 'archive.create';
    let caught = false; try { await verify(tampered, cp, r.public); } catch { caught = true; }
    check(caught, 'tampering not detected');
    let truncated = false; try { await verify(r.events.slice(0, -1), cp, r.public); } catch { truncated = true; }
    check(truncated, 'truncation not detected');
    return `Chain of ${r.events.length} events verified; edited and truncated copies rejected.`;
  });
  await kase('Commercial: approval overrides restricted send', 'profile', async (r, w, call) => {
    await call('crm.read');
    const args = { destination: 'outside.example' };
    const ap = await r.approve(w, 'reviewer', 'external.send', args);
    const a = await call('external.send', args, 'agent-b', ap.approval_id);
    check(a.allow && a.overridden.includes('restricted_data_external_send') && sent(r), 'approved send blocked');
    return 'Reviewer approval lifted the approvable restricted-send rule.';
  });
  await kase('Federal: egress allowlist is not approvable', 'profile', async (r, w, call) => {
    const a = await call('external.send', { destination: 'outside.example' });
    check(!a.allow && a.reasons.includes('egress_destination_not_allowlisted') && !sent(r), 'non-allowlisted egress allowed');
    return 'Send to a non-allowlisted destination denied.';
  }, 'federal');
  await kase('Federal: staged exfiltration cannot be approved', 'profile', async (r, w, call) => {
    await call('crm.read'); await call('archive.create');
    const args = { destination: 'partner.example' };
    const ap = await r.approve(w, 'reviewer', 'external.send', args);
    const a = await call('external.send', args, 'agent-b', ap.approval_id);
    check(!a.allow && a.reasons.includes('staged_exfiltration') && !sent(r), 'hard block overridden');
    return 'Read → stage → send stayed blocked despite an exact approval.';
  }, 'federal');
  await kase('Federal: approval lifetime capped by profile', 'profile', async (r, w) => {
    try { await r.approve(w, 'reviewer', 'access.grant', { subject: 'employee-demo', role: 'reader' }, 900); throw Error('15-minute approval issued'); }
    catch (e) { check(e.status === 400, e.message); }
    return 'Federal profile refused a 15-minute approval (limit 5 minutes).';
  }, 'federal');

  const passed = rows.filter(t => t.passed).length;
  return { status: 'completed', passed, total: rows.length, tests: rows, policy_hash: POLICY_HASH, finished_at: new Date().toISOString(),
    scope: `Browser sandbox: ${rows.length} checks against isolated in-memory runtimes and the same WebAssembly policy. The full 41-check Python suite (crash recovery, MCP transport, bundle tampering) runs locally with python assurance.py.` };
}

// ---- Serve the dashboard's API from the in-memory runtime.

const ready = (async () => {
  const [wasm, rego, data] = await Promise.all([
    fetch('/demo/policy/policy.wasm').then(r => r.arrayBuffer()),
    fetch('/demo/policy/controls.rego').then(r => r.text()),
    fetch('/demo/policy/aperture_data.json').then(r => r.text()),
  ]);
  REGO = rego; DATA_TEXT = data; CONFIG = JSON.parse(data).aperture_config;
  POLICY = await loadPolicy(wasm);
  POLICY.setData(JSON.parse(data));
  POLICY_HASH = await digest({ rego, data: JSON.parse(data) });
  return Runtime.create();
})();

let report = { status: 'not_run', tests: [] }, running = false;
const realFetch = window.fetch.bind(window);
const json = (status, value) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });

async function handle(path, method, headers, body) {
  const rt = await ready;
  const role = TOKENS[(headers.get('Authorization') || '').replace(/^Bearer /, '')];
  if (!role) throw new Fault(401, 'valid bearer credential required (use the prefilled demo tokens)');
  const need = roles => { if (!roles.includes(role)) throw new Fault(403, 'role not permitted'); };
  if (method === 'GET') {
    need(['operator', 'reviewer']);
    if (path === '/api/state') return json(200, await rt.snapshot());
    if (path === '/api/assurance') return json(200, report);
    if (path === '/api/evidence') return new Response(await rt.bundle(), { status: 200, headers: { 'Content-Type': 'application/zip' } });
    if (path === '/api/siem') return new Response(rt.siem(), { status: 200, headers: { 'Content-Type': 'application/x-ndjson' } });
    throw new Fault(404, 'not found');
  }
  const p = JSON.parse(body || '{}');
  if (path === '/api/approvals') { need(['reviewer']); return json(200, await rt.approve(p.workflow, role, p.tool, p.arguments || {}, p.ttl ?? 300)); }
  need(['operator']);
  if (path === '/api/workflows') return json(201, await rt.createWorkflow(role, p.agents, p.budget_cents ?? 10000, p.profile || 'commercial'));
  if (path === '/api/demo/call') return json(200, await rt.call(p.workflow, p.agent || 'agent-a', p.tool, p.arguments || {}, p.request_id || uid(), p.approval_id || null));
  if (path === '/api/verify') { const s = await rt.snapshot(); return json(200, await verify(s.events, s.checkpoint, s.public_key)); }
  if (path === '/api/assurance/run') {
    if (running) throw new Fault(409, 'assurance already running');
    running = true;
    try { report = await runSuite(); return json(200, report); } finally { running = false; }
  }
  throw new Fault(404, 'not found');
}

window.fetch = async (input, init = {}) => {
  const url = new URL(typeof input === 'string' ? input : input.url, location.href);
  if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) return realFetch(input, init);
  try { return await handle(url.pathname, (init.method || 'GET').toUpperCase(), new Headers(init.headers), init.body); }
  catch (e) {
    if (e instanceof Fault) return json(e.status, { error: e.message });
    if (e instanceof SyntaxError || e instanceof TypeError) return json(400, { error: 'invalid request' });
    console.error(e);
    return json(500, { error: 'sandbox failure: ' + e.message });
  }
};

// Prefill the demo credentials and open the workspace once the policy has loaded.
function start() {
  const op = document.getElementById('operatorToken'), rv = document.getElementById('reviewerToken');
  op.value = 'demo-operator'; rv.value = 'demo-reviewer';
  document.getElementById('disconnect').addEventListener('click', () => setTimeout(() => {
    op.value = 'demo-operator'; rv.value = 'demo-reviewer';
  }));
  ready.then(() => document.getElementById('connect').click(), e => {
    const n = document.getElementById('notice'); n.textContent = 'The sandbox could not load the policy engine: ' + e.message; n.hidden = false;
  });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
