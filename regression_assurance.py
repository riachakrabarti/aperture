"""v0.3 release regressions: configuration, export integrity, policy pins and crashes."""
import base64
import copy
from contextlib import contextmanager
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import zipfile
from aperture import (ROOT, POLICY_DATA, Policy, Runtime, Downstream, Fault, canonical, digest,
                      matched_actions, uid, start_opa)
from policy_validation import parse_config
from verify_bundle import verify_bundle


@contextmanager
def fixture(policy, profile='commercial'):
    with tempfile.TemporaryDirectory() as folder:
        d = Downstream(folder); r = Runtime(folder, policy, d)
        try:
            yield r, d, r.create(profile=profile)['id']
        finally:
            r.ledger.db.close(); d.close()


def check(value, message):
    if not value:
        raise AssertionError(message)


def run_regressions(policy):
    rows = []
    def case(name, fn, profile='both'):
        start = time.perf_counter()
        try:
            evidence = fn(); passed = True
        except Exception as e:
            evidence = type(e).__name__ + ': ' + str(e); passed = False
        rows.append({'name': name, 'control': 'v0.3-regression', 'profile': profile, 'passed': passed,
                     'evidence': evidence, 'duration_ms': round((time.perf_counter()-start)*1000, 2)})

    def configuration():
        original = json.loads(POLICY_DATA.read_text())
        mutations = [
            lambda c: c['profiles']['federal']['sequence_rules'][1].pop('overridable'),
            lambda c: c['profiles']['commercial'].pop('sequence_rules'),
            lambda c: c['profiles']['commercial']['sequence_rules'][0].update(overridable='false'),
            lambda c: c['profiles']['federal']['sequence_rules'][1].update(pattern=['source:cui', 'misspelled']),
            lambda c: c['profiles']['federal']['sequence_rules'][1].update(pattern=['source:cui']*4),
            lambda c: c['profiles']['federal']['sequence_rules'][1].pop('pattern'),
            lambda c: c['tools']['spend.commit'].pop('spend_argument'),
            lambda c: c['tools']['spend.commit'].update(spend_argument='missing'),
            lambda c: c['tools']['external.send'].pop('destination_argument'),
            lambda c: c.update(max_history=True),
            lambda c: c.update(max_history=0),
            lambda c: c['profiles']['federal'].update(max_approval_ttl_seconds='300'),
            lambda c: c['profiles']['federal'].update(egress_allowlist='partner.example'),
            lambda c: c['profiles']['federal']['extra_tags'].update(unknown=['source:cui']),
            lambda c: c['tools']['spend.commit']['inputSchema']['properties']['amount_cents'].update(minimum=-1),
        ]
        for mutate in mutations:
            bad = copy.deepcopy(original); mutate(bad['aperture_config'])
            try: Policy(policy.url, data_text=json.dumps(bad))
            except ValueError: pass
            else: raise AssertionError('Malformed policy accepted')
        try: parse_config('{"aperture_config":{},"aperture_config":{}}')
        except ValueError: pass
        else: raise AssertionError('Duplicate key accepted')
        # Same regression through the real activation path. Binary cannot execute.
        bad = copy.deepcopy(original); mutations[0](bad['aperture_config'])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'bad.json'; path.write_text(json.dumps(bad))
            try: start_opa('/binary-must-not-execute', 0, path)
            except ValueError: pass
            else: raise AssertionError('Invalid policy reached activation')
        return '16 malformed/duplicate configurations rejected; startup rejects missing hard-deny field before executing OPA.'
    case('Malformed configuration cannot activate', configuration)

    def pinning():
        for profile in ('commercial', 'federal'):
            with fixture(policy, profile) as (r, d, w):
                r.call(w, 'agent-a', 'crm.read', {}, uid())
                original_count = len(r.ledger.events())
                data = json.loads(policy.data_text)
                data['aperture_config']['profiles']['commercial']['max_approval_ttl_seconds'] = 600
                changed = Policy(policy.url, data_text=json.dumps(data))
                # Legacy v0.2 ledgers have no meta pin; signed history must still protect them.
                for legacy in (False, True):
                    if legacy:
                        r.ledger.db.execute("DELETE FROM meta WHERE key='policy_hash'"); r.ledger.db.commit()
                    try: Runtime(r.ledger.folder, changed, d)
                    except ValueError: pass
                    else: raise AssertionError('Mixed policy ledger accepted')
                    check(len(r.ledger.events()) == original_count, 'Rejected startup altered events')
                reopened = Runtime(r.ledger.folder, policy, d)
                reopened.ledger.db.close()
        return 'Both profiles reject changed policy in pinned and legacy ledgers; unchanged policy reopens.'
    case('Policy changes refuse existing ledgers', pinning)

    def evidence():
        count = 0
        for profile in ('commercial', 'federal'):
            with fixture(policy, profile) as (r, d, w):
                r.call(w, 'agent-a', 'crm.read', {}, uid())
                bundle = r.bundle(); key = r.ledger.public; checkpoint = r.ledger.checkpoint()
                verify_bundle(io.BytesIO(bundle), key, checkpoint, ROOT/'bin/opa')
                with zipfile.ZipFile(io.BytesIO(bundle)) as z:
                    files = {n: z.read(n) for n in z.namelist()}
                def zipped(mapping):
                    b = io.BytesIO()
                    with zipfile.ZipFile(b, 'w') as z:
                        for n, data in mapping.items(): z.writestr(n, data)
                    b.seek(0); return b
                for name in files:
                    altered = dict(files); altered[name] = files[name] + b' '
                    # A whitespace-only manifest alteration is equivalent JSON; change its signature instead.
                    if name == 'manifest.json':
                        m = json.loads(files[name]); m['signature'] = base64.b64encode(b'0'*64).decode()
                        altered[name] = canonical(m)
                    try: verify_bundle(zipped(altered), key, checkpoint)
                    except Exception: count += 1
                    else: raise AssertionError('Tampered member accepted: ' + name)
                for mode in ('missing', 'extra', 'unsigned'):
                    altered = dict(files)
                    if mode == 'missing': altered.pop('controls.json')
                    elif mode == 'unsigned': altered.pop('manifest.json')
                    else: altered['extra.txt'] = b'new'
                    try: verify_bundle(zipped(altered), key, checkpoint)
                    except Exception: count += 1
                    else: raise AssertionError('Invalid file set accepted: ' + mode)
                # Even a correctly signed manifest must not bless an inconsistent derived report.
                for name in ('controls.json', 'coverage.json', 'control-evidence.csv', 'siem.ndjson'):
                    altered = dict(files); altered[name] = b'{}' if name.endswith('.json') else b''
                    m = json.loads(files['manifest.json'])
                    import hashlib
                    m['body']['files'][name] = hashlib.sha256(altered[name]).hexdigest()
                    m['signature'] = base64.b64encode(r.ledger.key.sign(canonical(m['body']))).decode()
                    altered['manifest.json'] = canonical(m)
                    try: verify_bundle(zipped(altered), key, checkpoint)
                    except Exception: count += 1
                    else: raise AssertionError('Inconsistent derived export accepted: ' + name)
        return f'Both original bundles verified/replayed; {count} altered bundle variants rejected, including re-signed inconsistent reports.'
    case('Every evidence export is authenticated and checked', evidence)

    def correlation():
        with fixture(policy) as (r, d, w):
            r.call(w, 'agent-a', 'crm.read', {}, uid())
            decisions = [e['body'] for e in r.ledger.events() if e['body']['kind'] == 'decision']
            actions = d.actions()
            check(matched_actions(decisions, actions) == 1, 'Valid observation not matched')
            for key, bad in [('tool', 'external.send'), ('workflow', 'other'), ('args', '{"changed":true}'), ('id', 'other'), ('result', '{"execution_id":"other"}')]:
                altered = copy.deepcopy(actions); altered[0][key] = bad
                check(matched_actions(decisions, altered) == 0, 'Mismatched observation counted: ' + key)
            check(matched_actions(decisions, actions*2) == 1, 'Duplicate observation counted twice')
        return 'Wrong tool, workflow, arguments, execution ID and duplicate observations do not inflate coverage.'
    case('Coverage binds complete action identity', correlation)

    for profile in ('commercial', 'federal'):
        def core(profile=profile):
            import concurrent.futures
            with fixture(policy, profile) as (r, d, w):
                def spend(_): return r.call(w, 'agent-a', 'spend.commit', {'amount_cents': 6000}, uid())
                with concurrent.futures.ThreadPoolExecutor(2) as pool: results = list(pool.map(spend, range(2)))
                check(sum(x['allow'] for x in results) == 1 and len(d.actions()) == 1, 'Budget race')
                args = {'subject': 'test', 'role': 'reader'}
                a = r.approve(w, 'reviewer', 'access.grant', args)['approval_id']
                r.ledger.db.execute('UPDATE approvals SET expires=0 WHERE id=?', (a,)); r.ledger.db.commit()
                check(not r.call(w, 'agent-a', 'access.grant', args, uid(), a)['allow'], 'Expired approval accepted')
                r.call(w, 'agent-a', 'crm.read', {}, uid())
                reopened = Runtime(r.ledger.folder, policy, d)
                try:
                    result = reopened.call(w, 'agent-b', 'external.send', {'destination': 'partner.example'}, uid())
                    check(not result['allow'], 'Restart/handoff lost history')
                    reopened.policy = Policy('http://127.0.0.1:1')
                    result = reopened.call(w, 'agent-a', 'archive.create', {}, uid())
                    check(not result['allow'] and result['reasons'] == ['policy_unavailable'], 'Outage failed open')
                finally: reopened.ledger.db.close()
            return 'Concurrent budget, expired approval, restart with agent handoff and policy outage enforced.'
        case('Shared resilience checks: ' + profile, core, profile)

        for point in ('before_intent', 'before_dispatch', 'after_dispatch'):
            def crash(profile=profile, point=point):
                with tempfile.TemporaryDirectory() as folder:
                    cmd = [sys.executable, str(Path(__file__).resolve()), '--crash-worker', folder, policy.url, profile, point]
                    result = subprocess.run(cmd, capture_output=True, timeout=15)
                    check(result.returncode == 77, 'Crash worker did not terminate at failpoint: ' + result.stderr.decode())
                    d = Downstream(folder); r = Runtime(folder, policy, d)
                    try:
                        w = r.ledger.db.execute('SELECT id FROM workflows').fetchone()['id']
                        before = len(d.actions())
                        check(before == (1 if point == 'after_dispatch' else 0), 'Unexpected durable effects')
                        retry = r.call(w, 'agent-a', 'spend.commit', {'amount_cents': 100}, 'crash-action')
                        if point == 'before_intent':
                            check(retry['status'] == 'completed' and len(d.actions()) == 1, 'Pre-intent recovery failed')
                        else:
                            check(retry['status'] == 'unresolved' and len(d.actions()) == before, 'Ambiguous action was retried')
                            denied = r.call(w, 'agent-a', 'spend.commit', {'amount_cents': 100}, uid())
                            check(not denied['allow'] and len(d.actions()) == before, 'Quarantine failed')
                            check(len(r.history(w)) == 1, 'Reservation lost')
                    finally: r.ledger.db.close(); d.close()
                return 'Abrupt process exit tested; durable intent, quarantine and retry behavior checked against persisted tool ledger.'
            case('Process termination ' + point + ': ' + profile, crash, profile)
    for profile in ('commercial', 'federal'):
        def transport(profile=profile):
            import threading
            from aperture import make_server, load_credentials, http_json
            with fixture(policy, profile) as (r, d, w):
                credentials = load_credentials(r.ledger.folder)
                server = make_server(r, credentials, 0)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                url = f'http://127.0.0.1:{server.server_port}/mcp'
                def req(agent, method, sid=None, rpc_id=1, key=None):
                    import urllib.request
                    headers = {'Authorization': 'Bearer '+credentials[agent]['token'], 'X-Aperture-Workflow': w,
                               'Content-Type': 'application/json', 'MCP-Protocol-Version': '2025-11-25'}
                    if sid: headers['Mcp-Session-Id'] = sid
                    params = {'name': 'spend.commit', 'arguments': {'amount_cents': 100}}
                    if key is not None: params['_meta'] = {'aperture/idempotency_key': key}
                    body = {'jsonrpc': '2.0', 'id': rpc_id, 'method': method, 'params': params if method == 'tools/call' else {}}
                    with urllib.request.urlopen(urllib.request.Request(url, data=canonical(body), headers=headers)) as resp:
                        return json.loads(resp.read()), resp.headers.get('Mcp-Session-Id')
                try:
                    _, a = req('agent-a', 'initialize'); _, b = req('agent-b', 'initialize')
                    req('agent-a', 'tools/call', a); req('agent-b', 'tools/call', b)
                    check(len(d.actions()) == 2, 'Independent sessions collided on JSON-RPC id')
                    req('agent-a', 'tools/call', a)
                    check(len(d.actions()) == 2, 'Same-session retry executed twice')
                    req('agent-a', 'tools/call', a, rpc_id='1')
                    check(len(d.actions()) == 3, 'String and integer request IDs collided')
                    req('agent-a', 'tools/call', a, rpc_id=2, key='durable-action')
                    _, reconnect = req('agent-a', 'initialize')
                    replay, _ = req('agent-a', 'tools/call', reconnect, rpc_id=100, key='durable-action')
                    check(len(d.actions()) == 4 and replay['result']['structuredContent']['idempotent_replay'], 'Explicit retry key lost across reconnect')
                finally: server.shutdown(); server.server_close()
            return 'HTTP tests: session-local IDs, typed IDs, same-session retry and explicit cross-session retry key.'
        case('MCP request IDs and durable retries: ' + profile, transport, profile)
    return rows


def crash_worker(folder, url, profile, point):
    import os
    d = Downstream(folder); p = Policy(url); r = Runtime(folder, p, d)
    w = r.create(profile=profile)['id']
    if point == 'before_intent':
        p.evaluate = lambda value: os._exit(77)
    else:
        original = r._rpc
        def dispatch(method, params):
            if point == 'before_dispatch': os._exit(77)
            original(method, params)
            os._exit(77)
        r._rpc = dispatch
    r.call(w, 'agent-a', 'spend.commit', {'amount_cents': 100}, 'crash-action')
    raise RuntimeError('Failpoint not reached')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--crash-worker':
        crash_worker(*sys.argv[2:])
    else:
        raise SystemExit('Run python assurance.py to include these release gates.')
