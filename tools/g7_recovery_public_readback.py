"""Compare authenticated public UVM retained readbacks with source sentinels."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--phase', choices=('pre-migration', 'post-migration', 'rollback', 'released'), required=True)
    args = parser.parse_args()
    root = args.evidence
    ids = json.loads((root / 'retained-fixture-ids.json').read_text())
    storage = json.loads((root / 'recovery-auth-state.json').read_text())
    cookies = [c['value'] for c in storage['cookies'] if c['name'] == 'uvm_session' and c['domain'] == '127.0.0.1']
    if len(cookies) != 1:
        raise ValueError('exact retained session cookie is unavailable')
    receipts = {}
    for name, path in (
            ('group', '/api/v1/assessment/groups/' + ids['group']),
            ('audit', '/api/v1/assessment/audit?group_id=' + ids['group'])):
        request = urllib.request.Request('http://127.0.0.1:8000' + path,
            headers={'Cookie': 'uvm_session=' + cookies[0], 'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                if response.status != 200: raise ValueError('public readback failed')
                value = json.load(response)
        except urllib.error.HTTPError as error:
            diagnostic = {'phase': args.phase, 'endpoint': path, 'status': error.code,
                'body': error.read().decode('utf-8', errors='replace')[:4096]}
            (root / (args.phase + '-uvm-readback-http-error.json')).write_text(
                json.dumps(diagnostic, sort_keys=True, separators=(',', ':')) + '\n')
            raise RuntimeError('public readback HTTP failure; see phase-bound diagnostic') from error
        expected = json.loads((root / ('source-uvm-retained-' + name + '.json')).read_text())
        observed_path = root / (args.phase + '-uvm-' + name + '-observed.json')
        expected_path = root / (args.phase + '-uvm-' + name + '-expected.json')
        observed_path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
        expected_path.write_text(json.dumps(expected, sort_keys=True, separators=(',', ':')))
        observed_path.chmod(0o600); expected_path.chmod(0o600)
        comparison_expected = expected
        additive_authority_revision = False
        if (name == 'group' and args.phase == 'post-migration'
                and 'authority_revision' not in expected.get('assessment', {})):
            authority_revision = value.get('assessment', {}).get('authority_revision')
            if type(authority_revision) is not int or authority_revision < 0:
                raise ValueError('post-migration group read has invalid additive authority revision')
            comparison_expected = json.loads(json.dumps(expected))
            comparison_expected['assessment']['authority_revision'] = authority_revision
            additive_authority_revision = True
        if value != comparison_expected:
            actual_digest = hashlib.sha256(json.dumps(value, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            expected_digest = hashlib.sha256(json.dumps(comparison_expected, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            raise ValueError('retained public UVM ' + name +
                f' differs after replacement (observed={actual_digest}, expected={expected_digest}); '
                'see phase-bound observed/expected JSON evidence')
        (root / (args.phase + '-uvm-' + name + '.json')).write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
        receipts[name] = {'digest': 'sha256:' + hashlib.sha256(json.dumps(value,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'additive_authority_revision': additive_authority_revision}
    if not receipts: raise ValueError('no retained public assertions were exercised')
    print(json.dumps({'phase': args.phase, 'passed': True, 'readback_digests': receipts}, sort_keys=True))


if __name__ == '__main__':
    main()
