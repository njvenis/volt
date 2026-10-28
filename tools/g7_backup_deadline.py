"""Host-owned wall-clock operation budget, retained across interruptions."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def remaining(path):
    value = json.loads(Path(path).read_text())
    deadline = datetime.fromisoformat(value['deadline_at'])
    return (deadline - datetime.now(timezone.utc)).total_seconds()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--journal', required=True, type=Path)
    parser.add_argument('--request', type=Path)
    parser.add_argument('--kind', choices=['capture', 'verification'])
    parser.add_argument('--parent-pid', type=int)
    parser.add_argument('--complete', action='store_true')
    parser.add_argument('--run', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.run:
        budget = remaining(args.journal)
        if budget <= 0: raise SystemExit(124)
        child = subprocess.Popen(args.run, start_new_session=True)
        try:
            raise SystemExit(child.wait(timeout=budget))
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); child.wait()
            value = json.loads(args.journal.read_text())
            value.update(outcome='timed_out', failed_at=datetime.now(timezone.utc).isoformat())
            atomic(args.journal,value)
            raise SystemExit(124)
    if args.complete:
        value = json.loads(args.journal.read_text())
        if remaining(args.journal) <= 0: raise SystemExit(124)
        value.update(outcome='complete', completed_at=datetime.now(timezone.utc).isoformat())
        atomic(args.journal, value)
        return
    if not args.journal.exists():
        request = json.loads(args.request.read_text())
        seconds = request['capture_timeout_seconds' if args.kind == 'capture' else 'verification_timeout_seconds']
        if type(seconds) is not int or seconds < 1: raise ValueError('invalid consumed operation timeout')
        now = datetime.now(timezone.utc)
        atomic(args.journal, {'kind': args.kind, 'revision': request['revision'], 'digest': request['digest'],
            'started_at': now.isoformat(), 'deadline_at': (now + timedelta(seconds=seconds)).isoformat(),
            'timeout_seconds': seconds, 'outcome': 'running'})
    while remaining(args.journal) > 0:
        time.sleep(max(0.001, min(0.2, remaining(args.journal))))
    value = json.loads(args.journal.read_text())
    if value['outcome'] != 'complete':
        value.update(outcome='timed_out', failed_at=datetime.now(timezone.utc).isoformat())
        atomic(args.journal, value)
        os.kill(args.parent_pid, signal.SIGTERM)


if __name__ == '__main__': main()
