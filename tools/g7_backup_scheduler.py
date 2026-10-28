#!/usr/bin/env python3
"""Independent host schedule consumer; requests never grant UVM host authority."""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.g7_backup_controller import atomic_json, load_config
from uvm.operations.backup_host import digest
from uvm.operations.observer_settings import validate_backup_values


def consume(config, now=None):
    now = now or datetime.now(timezone.utc)
    readback_path = Path(config['scheduler_readback_file'])
    try:
        prior = json.loads(readback_path.read_text())
    except FileNotFoundError:
        prior = None
    rejected, accepted = None, True
    try:
        candidate = json.loads(Path(config['active_settings_file']).read_text())
        rejected = candidate
        values = validate_backup_values(candidate['values'], config['host_policy'])
        if (candidate['deployment_id'] != config['deployment_id'] or
                candidate['digest'] != 'sha256:' + digest(values) or
                type(candidate['revision']) is not int or candidate['revision'] < 1 or
                (prior and (candidate['revision'] < prior['revision'] or
                    (candidate['revision'] == prior['revision'] and
                        (candidate['digest'] != prior['digest'] or candidate['intent_id'] != prior['intent_id']))))):
            raise ValueError('candidate settings identity regressed or changed')
    except (OSError, ValueError, KeyError):
        accepted = False
        if prior is None:
            raise
        candidate = prior
        values = validate_backup_values(prior['values'], config['host_policy'])
    failure_path = readback_path.with_suffix('.failure.json')
    if not accepted and isinstance(rejected, dict):
        atomic_json(failure_path, {'revision': rejected.get('revision'), 'digest': rejected.get('digest'),
            'intent_id': rejected.get('intent_id'), 'failure_code': 'consumer_rejected',
            'observed_at': now.isoformat().replace('+00:00', 'Z')})
    elif accepted:
        failure_path.unlink(missing_ok=True)
    same = prior and prior['revision'] == candidate['revision']
    due = prior['next_capture_at'] if same else now.timestamp()
    # These are host-owned work requests. The capture driver independently
    # fences/drains/stops the deployment before reading the named volumes.
    if now.timestamp() >= due:
        atomic_json(Path(config['capture_request_file']), {
            'schema_version': 1, 'deployment_id': config['deployment_id'],
            'revision': candidate['revision'], 'digest': candidate['digest'],
            'intent_id': candidate['intent_id'], 'values': values,
            'requested_at': now.isoformat().replace('+00:00', 'Z'),
            'capture_timeout_seconds': values['timeout_seconds'],
            'verification_timeout_seconds': values['restore_verification_timeout_seconds'],
            'archive_target_ref': values['archive_target_ref'],
            'recovery_profile_ref': values['recovery_profile_ref']})
        due = int(now.timestamp()) + values['interval_seconds']
    result = {'schema_version': 1, 'deployment_id': config['deployment_id'],
        'revision': candidate['revision'], 'digest': candidate['digest'],
        'intent_id': candidate['intent_id'], 'values': values,
        'observed_at': now.isoformat().replace('+00:00', 'Z'),
        'next_capture_at': due}
    atomic_json(readback_path, result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    config = load_config(args.config)
    while True:
        try:
            config = load_config(args.config)
            consume(config)
        except (OSError, ValueError, KeyError):
            try:
                rejected = json.loads(Path(config['active_settings_file']).read_text())
                atomic_json(Path(config['scheduler_readback_file']).with_suffix('.failure.json'), {
                    'revision': rejected['revision'], 'digest': rejected['digest'], 'intent_id': rejected['intent_id'],
                    'failure_code': 'consumer_rejected',
                    'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')})
            except (OSError, ValueError, KeyError):
                pass
            # Leave the last verified schedule/readback intact. A failed new
            # candidate cannot overwrite the consumer's last-good state.
            if args.once: raise
        if args.once: return
        time.sleep(0.2)


if __name__ == '__main__':
    main()
