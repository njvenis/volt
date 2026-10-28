"""Compare authenticated public UVM retained readbacks with source sentinels."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--phase', choices=('pre-migration', 'post-migration', 'released'), required=True)
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
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200: raise ValueError('public readback failed')
            value = json.load(response)
        expected = json.loads((root / ('source-uvm-retained-' + name + '.json')).read_text())
        if value != expected:
            raise ValueError('retained public UVM ' + name + ' differs after replacement')
        (root / (args.phase + '-uvm-' + name + '.json')).write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
        receipts[name] = 'sha256:' + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if not receipts: raise ValueError('no retained public assertions were exercised')
    print(json.dumps({'phase': args.phase, 'passed': True, 'readback_digests': receipts}, sort_keys=True))


if __name__ == '__main__':
    main()
