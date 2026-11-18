"""Admission of the actual local API container's image and narrow mount set."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys


def validate(root: Path, host_root: Path, info: dict, container: dict) -> None:
    if container.get('Image') != info['image_admission']['id']:
        raise ValueError('actual image differs from admitted image')
    labels = container.get('Config', {}).get('Labels', {})
    if labels.get('volt.compose.owner-token') != info['owner_token']:
        raise ValueError('actual container owner differs')
    expected = {
        '/var/lib/postgresql/data': ('volume', f"{info['project']}_postgres", True),
        '/app/media': ('volume', f"{info['project']}_media", True),
        '/opt/uvm/state': ('volume', f"{info['project']}_state", True),
        '/etc/volt/oidc.json': ('bind', 'oidc.json', False),
        '/run/volt-bootstrap': ('bind', 'secrets/bootstrap-delivery', True),
        '/run/volt-restore-fence': ('bind', 'secrets/local-restore-fence', False),
        '/run/secrets/local-auth.json': ('bind', 'local-auth.json', False),
        '/run/secrets/local-auth-key': ('bind', 'secrets/local-auth-key', False),
        '/run/secrets/local-recovery.json': ('bind', 'local-recovery.json', False),
    }
    for name in ('uvm_db_password', 'ce_db_password', 'ce_admin_password', 'ce_secret_key',
                 'ce_credential_key', 'uvm_cursor_secret', 'oidc_client_secret', 'oidc_sync_secret',
                 'oidc_operator_secret', 'recovery-server.crt', 'recovery-server.key', 'recovery-ca.crt'):
        expected['/run/secrets/' + name] = ('bind', 'secrets/' + name, False)
    for name in ('issuer.key', 'issuer.pub', 'operator.pub', 'material.key'):
        expected['/run/secrets/local-recovery-' + name] = ('bind', 'secrets/local-recovery-runtime/' + name, False)
    mounts = container.get('Mounts', [])
    if len(mounts) != len(expected) or {m.get('Destination') for m in mounts} != set(expected):
        raise ValueError('actual mount inventory differs')
    protected = [(root / 'secrets/local-recovery-authority' / name).resolve(strict=True)
                 for name in ('operator.key', 'host.json')]
    for mount in mounts:
        kind, source, writable = expected[mount['Destination']]
        if mount.get('Type') != kind or mount.get('RW') is not writable:
            raise ValueError('actual mount access differs')
        if kind == 'volume':
            if mount.get('Name') != source or mount.get('Driver') != 'local':
                raise ValueError('actual volume differs')
            continue
        if mount.get('Source') != str(host_root / source):
            raise ValueError('actual bind source differs')
        local_source = root / source
        resolved = local_source.resolve(strict=True)
        if resolved != local_source or any(resolved == secret or resolved in secret.parents for secret in protected):
            raise ValueError('actual bind aliases or contains operator-private custody')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--instance-root', required=True, type=Path)
    parser.add_argument('--host-root', required=True, type=Path)
    args = parser.parse_args()
    info = json.loads((args.instance_root / 'instance.json').read_text())
    containers = json.load(sys.stdin)
    if not isinstance(containers, list) or len(containers) != 1:
        raise ValueError('one actual API container required')
    validate(args.instance_root, args.host_root, info, containers[0])
    print('actual_mounts=admitted')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('actual API container custody admission failed', file=sys.stderr)
        raise SystemExit(1) from None
