"""Real POSIX tracked jobs; Docker/custody stubbed, not native authority proof."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ParallelInventoryTests(unittest.TestCase):
    def run_case(self, phase='observed', mode='ok', preparation=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / 'work'; work.mkdir(mode=0o700)
            observation = root / 'observation'; observation.mkdir(mode=0o700)
            binary = root / 'docker'
            binary.write_text('''#!/bin/sh
set -eu
if [ "$1:$2" = volume:inspect ]; then
 store=${3##*_}
 if [ "$MODE:$store" = slow:postgres ]; then sleep 1.4; fi
 if [ "$MODE:$store" = preparation-slow:postgres ]; then sleep 14; fi
 if [ "$MODE:$store" = foreign:media ]; then printf 'foreign|local|null\\n'; exit 0; fi
 printf 'unit|local|null\\n'; exit 0
fi
[ "$1" = run ] || exit 90
printf '%s\\n' "$*" >"$WORK/run-$$"
sleep 1
if [ "$MODE" = nonzero ] && [ "${*#*unit_media}" != "$*" ]; then exit 17; fi
printf '{"entries":1,"sha256":"fixed"}'
''')
            binary.chmod(0o700)
            script = '''set -eu
. "$DRIVER"
fail() { printf '%s\\n' "$1" >&2; exit 7; }
ensure_lock_owner() { return 0; }
PROJECT=unit;OWNER_TOKEN=unit;PLATFORM=linux/amd64;IMAGE_REF=unit-image;STATE="$WORK/state"
ACTION=backup-record
trap 'printf "%s\\n" "${RETAIN_STOP_EVIDENCE:-0}" >"$WORK/retained"' 0
offline_stop_clock
budget=500
[ "$MODE" != slow ] || budget=40
OFFLINE_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS+budget))
printf '%s\\n' "$OFFLINE_STOP_DEADLINE_CS" >"$WORK/original-deadline"
if [ "$PREPARATION" = 1 ]; then
 OFFLINE_STOP_DEADLINE_CS=''
 OFFLINE_ORDINARY_STOP_DEADLINE_CS=''
 if [ "$MODE" = ordinary ]; then OFFLINE_ORDINARY_STOP_DEADLINE_CS=999999999; fi
 if [ "$MODE" = existing ]; then OFFLINE_STOP_DEADLINE_CS=999999999; fi
 offline_prepare_backup_inventory "$PHASE" || exit 7
 [ -z "$OFFLINE_STOP_DEADLINE_CS" ] || exit 91
 printf 'snapshot permitted after preparation only\\n' >"$WORK/snapshot-reached"
 # Fresh snapshot budget is measured separately, not authority or a clock reset.
 offline_stop_clock
 OFFLINE_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS+1300))
else
 offline_inventory_parallel "$PHASE"
fi
printf '%s\\n' "$OFFLINE_STOP_DEADLINE_CS" >"$WORK/final-deadline"
'''
            start = time.monotonic()
            # Wait for the actual original parent, not communicate() EOF from
            # intentionally retained RO descendants inheriting a capture pipe.
            with (root/'parent.stdout').open('w') as stdout, (root/'parent.stderr').open('w') as stderr:
                child = subprocess.Popen(['sh', '-c', script], stdout=stdout, stderr=stderr,
                    env=os.environ | {'DRIVER':str(ROOT/'deploy/compose/offline-host.sh'),
                    'WORK':str(work),'OFFLINE_OBSERVATION':str(observation),'MODE':mode,'PHASE':phase,
                    'PREPARATION':str(int(preparation)),
                    'PATH':str(root)+os.pathsep+os.environ['PATH']})
                code = child.wait(timeout=17)
            elapsed = time.monotonic()-start
            result = subprocess.CompletedProcess(child.args,code,
                (root/'parent.stdout').read_bytes(),(root/'parent.stderr').read_bytes())
            # Finite stubs end naturally, including a retained slow RO client.
            if mode in ('slow','preparation-slow'): time.sleep(1.5)
            files={str(p.relative_to(root)):p.read_text() for p in root.rglob('*') if p.is_file() and p != binary}
            return result, elapsed, files

    def test_three_or_four_single_mounts_overlap_and_every_original_wait_succeeds(self):
        for phase, stores in [('observed',['postgres','media','state']),
                              ('captured',['postgres','media','state','instance'])]:
            with self.subTest(phase=phase):
                result, elapsed, files = self.run_case(phase)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertLess(elapsed,2.5) # Serial fixed 1s helpers require >=3/4s.
                self.assertEqual(list(json.loads(files['observation/inventories.json'])),stores)
                commands=[v for k,v in files.items() if k.startswith('work/run-')]
                self.assertEqual(len(commands),len(stores))
                for command in commands:
                    self.assertEqual(command.count('--mount '),1)
                    self.assertIn('dst=/restore,readonly',command)
                    for flag in ('--pull=never','--network none','--read-only','--cap-drop=ALL','--cap-add=DAC_OVERRIDE','--user 0:0'):
                        self.assertIn(flag,command)
                for suffix in ('child-wait','guard-wait','result'):
                    values=[v.strip() for k,v in files.items() if k.endswith('/'+suffix)]
                    self.assertEqual(values,['0']*len(stores))
                releases=[int(v) for k,v in files.items() if k.endswith('/released-centiseconds')]
                finishes=[int(v) for k,v in files.items() if k.endswith('/finished-centiseconds')]
                self.assertLess(max(releases),min(finishes))
                self.assertEqual(files['work/original-deadline'],files['work/final-deadline'])

    def test_foreign_owner_or_helper_failure_cannot_assemble_inventory(self):
        for mode in ('foreign','nonzero'):
            with self.subTest(mode=mode):
                result, _, files = self.run_case(mode=mode)
                self.assertEqual(result.returncode,7,result.stderr)
                self.assertNotIn('observation/inventories.json',files)
                self.assertEqual(files['work/retained'].strip(),'1')
                if mode=='foreign':
                    self.assertFalse(any('unit_media' in v for k,v in files.items() if k.startswith('work/run-')))
                else:
                    self.assertIn('17',[v.strip() for k,v in files.items() if k.endswith('/child-wait')])

    def test_blocked_precheck_returns_bounded_retains_and_cannot_launch_after_cutoff(self):
        result, elapsed, files = self.run_case(mode='slow')
        self.assertEqual(result.returncode,7,result.stderr)
        self.assertLess(elapsed,1.1)
        self.assertEqual(files['work/retained'].strip(),'1')
        self.assertNotIn('observation/inventories.json',files)
        self.assertFalse(any('unit_postgres' in v for k,v in files.items() if k.startswith('work/run-')))
        self.assertTrue(any(v.strip()=='deadline' for k,v in files.items() if k.endswith('/reason')))

    def test_restore_or_unknown_phase_cannot_start_parallel_helpers(self):
        result, _, files = self.run_case(phase='provisioned')
        self.assertEqual(result.returncode,7,result.stderr)
        self.assertFalse(any(k.startswith('work/run-') for k in files))

    def test_separate_preparation_completes_before_fresh_snapshot_clock(self):
        result, elapsed, files = self.run_case(preparation=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertLess(elapsed,2.5)
        self.assertIn('work/snapshot-reached',files)
        self.assertEqual(len(json.loads(files['observation/inventories.json'])),3)
        self.assertTrue(all(v.strip()=='0' for k,v in files.items() if k.endswith('/result')))

    def test_preparation_timeout_prevents_snapshot_and_retains_original_jobs(self):
        result, elapsed, files = self.run_case(mode='preparation-slow',preparation=True)
        self.assertEqual(result.returncode,7,result.stderr)
        self.assertGreater(elapsed,12)
        self.assertLess(elapsed,14)
        self.assertNotIn('work/snapshot-reached',files)
        self.assertNotIn('observation/inventories.json',files)
        self.assertEqual(files['work/retained'].strip(),'1')
        self.assertFalse(any('unit_postgres' in v for k,v in files.items() if k.startswith('work/run-')))

    def test_preparation_cannot_clear_existing_acquisition_or_ordinary_stop_deadline(self):
        for mode in ('existing','ordinary'):
            with self.subTest(mode=mode):
                result, _, files = self.run_case(mode=mode,preparation=True)
                self.assertEqual(result.returncode,7,result.stderr)
                self.assertIn(b'cannot reset',result.stderr)
                self.assertNotIn('work/snapshot-reached',files)
                self.assertFalse(any(k.startswith('work/run-') for k in files))
