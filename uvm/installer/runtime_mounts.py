"""Admission of the actual local API container's image and narrow mount set."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys


def validate(root: Path, host_root: Path, info: dict, container: dict, volumes: list[dict]) -> None:
    if info.get('installer_contract_version') == 2:
        from uvm.installer.installed_artifacts import cache_name, reject_mount_overlap, validate_pin
        validate_pin(info.get('installer_admission'))
        reject_mount_overlap(str(host_root.parent / cache_name(str(host_root))),
            {'containers': [container], 'volumes': volumes})
    if container.get('Image') != info['image_admission']['id']:
        witness = container.get('ImageManifestDescriptor') or {}
        expected = info['image_admission'].get('selected_descriptor') or {}
        if (info['image_admission'].get('id_kind') != 'selected_manifest'
                or container.get('Image') != info['image_admission'].get('engine_image_id')
                or witness.get('digest') != info['image_admission']['id']
                or any(witness.get(key) != expected.get(key) for key in ('digest', 'mediaType', 'size'))
                or f"{witness.get('platform', {}).get('os')}/{witness.get('platform', {}).get('architecture')}" != info['platform']):
            raise ValueError('actual image lacks the admitted selected-child witness')
    labels = container.get('Config', {}).get('Labels', {})
    if labels.get('volt.compose.owner-token') != info['owner_token']:
        raise ValueError('actual container owner differs')
    network_name = info['project'] + '_network'
    attachments = container.get('NetworkSettings', {}).get('Networks')
    if (not isinstance(attachments, dict) or set(attachments) != {network_name}
            or container.get('HostConfig', {}).get('NetworkMode') != network_name
            or not isinstance(attachments[network_name], dict)
            or attachments[network_name].get('DriverOpts') not in (None, {})):
        raise ValueError('actual network attachment inventory differs')
    expected = {
        '/var/lib/postgresql/data': ('volume', f"{info['project']}_postgres", True),
        '/app/media': ('volume', f"{info['project']}_media", True),
        '/opt/uvm/state': ('volume', f"{info['project']}_state", True),
        '/etc/volt/oidc.json': ('bind', 'oidc.json', False),
        '/run/volt-bootstrap': ('bind', 'secrets/bootstrap-delivery', True),
        '/run/volt-start-admission': ('bind', 'secrets/local-start-admission', False),
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
    volume_records = {volume.get('Name'): volume for volume in volumes}
    if (len(volumes) != 3 or set(volume_records) != {f"{info['project']}_{store}" for store in ('postgres', 'media', 'state')}):
        raise ValueError('actual named volume inventory differs')
    for volume in volumes:
        if (volume.get('Driver') != 'local' or volume.get('Options') not in (None, {})
                or (volume.get('Labels') or {}).get('volt.compose.owner-token') != info['owner_token']):
            raise ValueError('actual named volume driver/custody differs')
    protected = [(root / 'secrets/local-recovery-authority' / name).resolve(strict=True)
                 for name in ('operator.key', 'host.json')]
    for mount in mounts:
        kind, source, writable = expected[mount['Destination']]
        if mount.get('Type') != kind or mount.get('RW') is not writable:
            raise ValueError('actual mount access differs')
        if kind == 'volume':
            if (mount.get('Name') != source or mount.get('Driver') != 'local'
                    or mount.get('Source') != volume_records[source].get('Mountpoint')):
                raise ValueError('actual volume differs')
            continue
        if mount.get('Source') != str(host_root / source):
            raise ValueError('actual bind source differs')
        local_source = root / source
        resolved = local_source.resolve(strict=True)
        if resolved != local_source or any(resolved == secret or resolved in secret.parents for secret in protected):
            raise ValueError('actual bind aliases or contains operator-private custody')


def validate_start_context(info: dict, container: dict) -> None:
    """Compare actual Config.Env to validated metadata, never self-witness it."""
    raw = container.get('Config', {}).get('Env')
    if (not isinstance(raw,list) or any(type(item) is not str or '=' not in item for item in raw)):
        raise ValueError('actual start environment is missing or malformed')
    rows = [item.split('=',1) for item in raw]
    if len({key for key,_ in rows}) != len(rows):
        raise ValueError('actual start environment has duplicate names')
    values = dict(rows)
    expected = {'UVM_LOCAL_START_IMAGE_ID':info['image_admission']['id'],
        'UVM_LOCAL_START_RESOURCES_SHA256':(info.get('local_start_admission') or {}).get('resources_sha256','')}
    if any(key not in values or values[key] != value for key,value in expected.items()):
        raise ValueError('actual start environment differs from validated expected metadata')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--instance-root', required=True, type=Path)
    parser.add_argument('--host-root', required=True, type=Path)
    args = parser.parse_args()
    info = json.loads((args.instance_root / 'instance.json').read_text())
    document = json.load(sys.stdin)
    if not isinstance(document, dict) or set(document) != {'containers', 'volumes'}:
        raise ValueError('closed actual-container and volume inventory required')
    containers = document['containers']
    if not isinstance(containers, list) or len(containers) != 1:
        raise ValueError('one actual API container required')
    validate(args.instance_root, args.host_root, info, containers[0], document["volumes"])
    validate_start_context(info, containers[0])
    print('actual_mounts=admitted')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('actual API container custody admission failed', file=sys.stderr)
        raise SystemExit(1) from None
