"""Verify signed bundle bytes, event history, derived exports and optional policy replay."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from aperture import canonical, policy_hash, verify, control_coverage, control_csv, matched_actions
from policy_validation import parse_config

REQUIRED = {'events.json', 'checkpoint.json', 'public_key.txt', 'policy.rego', 'policy_data.json',
            'controls.json', 'control-evidence.csv', 'downstream.json', 'coverage.json', 'siem.ndjson', 'README.txt'}


def verify_bundle(bundle, trusted_key, checkpoint=None, opa=None):
    with zipfile.ZipFile(bundle) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or set(names) != REQUIRED | {'manifest.json'}:
            raise ValueError('Missing, duplicate or unexpected bundle members')
        if sum(i.file_size for i in z.infolist()) > 128 * 1024 * 1024:
            raise ValueError('Bundle exceeds bounded verifier size limit (128 MiB)')
        manifest = json.loads(z.read('manifest.json'))
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_key))
        pub.verify(base64.b64decode(manifest['signature']), canonical(manifest['body']))
        body = manifest['body']
        if body.get('format') != 'aperture-bundle-v1' or set(body['files']) != REQUIRED:
            raise ValueError('Invalid signed manifest file set')
        files = {name: z.read(name) for name in REQUIRED}
        for name, content in files.items():
            if hashlib.sha256(content).hexdigest() != body['files'][name]:
                raise ValueError('Bundle member hash mismatch: ' + name)
    if files['public_key.txt'].decode().strip() != trusted_key:
        raise ValueError('Bundle public key differs from trusted key')
    events = json.loads(files['events.json'])
    embedded = json.loads(files['checkpoint.json'])
    chain = verify(events, embedded, trusted_key)
    if checkpoint is not None:
        verify(events, checkpoint, trusted_key)
    policy = files['policy.rego'].decode(); policy_data = files['policy_data.json'].decode()
    parse_config(policy_data)
    expected = policy_hash(policy, policy_data)
    for e in events:
        if 'policy_hash' in e['body'] and e['body']['policy_hash'] != expected:
            raise ValueError('Policy hash mismatch at sequence ' + str(e['body']['seq']))
    decisions = [e['body'] for e in events if e['body']['kind'] == 'decision']
    if json.loads(files['controls.json']) != control_coverage(decisions):
        raise ValueError('Derived control report mismatch')
    if files['control-evidence.csv'].decode() != control_csv(events):
        raise ValueError('Derived control CSV mismatch')
    siem = [json.loads(line) for line in files['siem.ndjson'].decode().splitlines()]
    expected_siem = [{'time': e['body']['timestamp_ns']/1e9, 'sourcetype': 'aperture:decision', 'event': e} for e in events]
    if siem != expected_siem:
        raise ValueError('Derived SIEM export mismatch')
    actions = json.loads(files['downstream.json']); coverage = json.loads(files['coverage.json'])
    matched = matched_actions(decisions, actions)
    expected_counts = {'observed_actions': len(actions), 'matched_actions': matched,
                       'unmatched_actions': len(actions)-matched,
                       'percent': round(100*matched/len(actions), 1) if actions else None}
    if any(coverage.get(k) != v for k, v in expected_counts.items()):
        raise ValueError('Derived coverage report mismatch')
    replayed = 0; excluded = 0
    if opa:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'policy.rego'; path.write_text(policy)
            data = Path(folder)/'policy_data.json'; data.write_text(policy_data)
            for d in decisions:
                if d.get('engine_error'):
                    excluded += 1; continue
                result = subprocess.run([str(opa), 'eval', '--format=json', '--data', str(path), '--data', str(data),
                                         '--stdin-input', 'data.aperture.decision'], input=canonical(d['policy_input']),
                                        capture_output=True, check=True, timeout=10)
                actual = json.loads(result.stdout)['result'][0]['expressions'][0]['value']
                if actual != d['decision']:
                    raise ValueError('Policy replay mismatch at sequence ' + str(d['seq']))
                replayed += 1
    return {'bundle_integrity': 'verified', 'event_chain': chain,
            'derived_exports': 'consistent', 'external_checkpoint': 'verified' if checkpoint else 'not_supplied',
            'policy_replay': 'verified' if opa else 'not_run', 'replayed_decisions': replayed,
            'nonreplayable_engine_failures': excluded, 'tools_executed': 0,
            'observation_scope': 'Signed synthetic observations only; external completeness and independent source authenticity are not established'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('bundle'); p.add_argument('--trusted-key', required=True)
    p.add_argument('--checkpoint'); p.add_argument('--opa')
    args = p.parse_args()
    report = verify_bundle(args.bundle, Path(args.trusted_key).read_text().strip(),
                           json.loads(Path(args.checkpoint).read_text()) if args.checkpoint else None, args.opa)
    print(json.dumps(report, indent=2))
    if not args.checkpoint:
        print('NOTICE: no external checkpoint; freshness is not established.')


if __name__ == '__main__':
    main()
