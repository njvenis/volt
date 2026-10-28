"""Prove a real released CE worker and advancing beat, beyond wrapper startup."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--container', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence
    release = json.loads((root/'host-fence-release-journal.json').read_text())
    released_at = datetime.fromisoformat(release['observed_at'])
    config = json.loads((root/'backup-capture-request.json').read_text())
    from tools.g7_backup_deadline import remaining
    deadline = time.monotonic() + remaining(root/'verification-deadline.json')
    container_id = subprocess.check_output(['docker', 'inspect', args.container, '--format', '{{.Id}}'], text=True).strip()
    expected_worker = 'celery@' + container_id[:12]
    first_progress = None
    attempts = []
    def execute(argv, timeout=20):
        return subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    while time.monotonic() < deadline:
        phase = execute(['docker','exec',args.container,'cat','/run/uvm-g7/runtime-mode'])
        ready = execute(['docker','exec',args.container,'test','-f','/run/uvm-g7/ready'])
        if phase.returncode or phase.stdout.strip() != 'runtime' or ready.returncode:
            time.sleep(1); continue
        ping = execute(['docker','exec',args.container,'celery','-A','dojo','inspect','ping','--timeout=5'])
        attempts.append({'exit': ping.returncode, 'stdout': ping.stdout, 'stderr': ping.stderr})
        (root/'released-worker-ping-attempts.json').write_text(json.dumps(attempts,sort_keys=True))
        workers = re.findall(r'(?m)^->\s+([^:\s]+):\s+OK\s*$',ping.stdout)
        if ping.returncode or workers != [expected_worker] or not re.search(r'(?m)^\s+pong\s*$',ping.stdout):
            time.sleep(1); continue
        progress = execute(['docker','exec',args.container,'cat','/run/uvm-g7-scheduler/progress.json'])
        if progress.returncode:
            time.sleep(1); continue
        try:
            value = json.loads(progress.stdout)
            observed = datetime.fromisoformat(value['completed_at'])
            if observed < released_at or observed > datetime.now(timezone.utc):
                time.sleep(1); continue
            if first_progress is None:
                first_progress = value
            elif value['loop_sequence'] > first_progress['loop_sequence']:
                result = {'worker_ping_passed': True, 'expected_worker': expected_worker,
                    'runtime_ready': True, 'scheduler_first': first_progress, 'scheduler_second': value}
                (root/'released-runtime-proof.json').write_text(json.dumps(result,sort_keys=True))
                release.update(workers_release_requested=True, runtime_verified_at=datetime.now(timezone.utc).isoformat(),
                    worker_ping_passed=True, scheduler_progress_passed=True)
                from tools.g7_backup_controller import atomic_json
                atomic_json(root/'host-fence-release-journal.json', release)
                print(json.dumps({'runtime_ready': True,'worker_ping_passed':True,'scheduler_progress_passed':True},sort_keys=True))
                return
        except (ValueError, KeyError):
            pass
        time.sleep(1)
    raise RuntimeError('released runtime did not prove worker ping and advancing scheduler within the consumed verification deadline')


if __name__ == '__main__':
    main()
