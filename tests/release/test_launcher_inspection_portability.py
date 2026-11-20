"""Real POSIX reached command shapes; Docker/API and clock are substituted."""
from pathlib import Path
import json,os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class LauncherInspectionTests(unittest.TestCase):
    def run_case(self,client='1.48',server='1.48',advertised=False,failure=False,requested='linux/arm64'):
        text=(ROOT/'deploy/compose/launcher.sh').read_text();functions=text[text.index('select_inspect_capability() {'):text.index('cleanup() {')]
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);log=root/'calls';docker=root/'docker';docker.write_text('''#!/bin/sh
case "$1:$2" in
 version:--format) printf '%s|%s\\n' "$CLIENT_API" "$SERVER_API" ;;
 image:inspect)
  if [ "$3" = --help ]; then [ "$ADVERTISED" = 1 ] && printf '      --platform string\\n' || printf '      --format string\\n'; exit 0; fi
  printf '%s\\n' "$*" >>"$CALL_LOG"
  [ "$INSPECT_FAIL" = 0 ] || exit 125
  printf '[{"Id":"sha256:opaque","Os":"linux","Architecture":"arm64"}]\\n'
 ;;
 *) exit 99 ;;
esac
''');docker.chmod(0o700)
            script='set -eu\nfail() { printf "%s\\n" "$1" >&2; exit 1; }\n'+functions+'''\nENGINE_PLATFORM=linux/arm64
select_inspect_capability
inspect_runtime_image "$REQUESTED" 'fixed@sha256:reference'
inspect_runtime_image "$REQUESTED" --format '{{.Id}}|{{.Os}}/{{.Architecture}}' 'fixed@sha256:reference'
inspect_runtime_image "$REQUESTED" 'fixed@sha256:reference'
'''
            r=subprocess.run(['sh','-c',script],env=os.environ|{'PATH':str(root)+':'+os.environ['PATH'],'CLIENT_API':client,'SERVER_API':server,'ADVERTISED':str(int(advertised)),'INSPECT_FAIL':str(int(failure)),'CALL_LOG':str(log),'REQUESTED':requested},capture_output=True,text=True)
            return r,log.read_text().splitlines()if log.exists()else[]
    def test_28_initial_formatted_and_offline_refresh_have_no_unsupported_flag(self):
        r,calls=self.run_case();self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(len(calls),3)
        self.assertTrue(all('--platform'not in c for c in calls));self.assertIn('--format {{.Id}}|{{.Os}}/{{.Architecture}}',calls[1])
    def test_new_help_alone_cannot_override_old_server_api(self):
        r,calls=self.run_case('1.55','1.48',True);self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(all('--platform'not in c for c in calls))
    def test_new_capability_has_one_exact_platform_and_failure_never_retries(self):
        r,calls=self.run_case('1.55','1.55',True);self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(all(c.count('--platform linux/arm64')==1 for c in calls))
        r,calls=self.run_case('1.55','1.55',True,True);self.assertEqual(r.returncode,125);self.assertEqual(len(calls),1)
    def test_unknown_api_and_foreign_platform_deny_before_inspect(self):
        for client,requested in (('bad','linux/arm64'),('1.48','linux/amd64')):
            r,calls=self.run_case(client=client,requested=requested);self.assertNotEqual(r.returncode,0);self.assertEqual(calls,[])
    def test_every_reached_product_site_uses_fixed_internal_helper(self):
        text=(ROOT/'deploy/compose/launcher.sh').read_text()
        self.assertEqual(text.count('docker image inspect --platform'),1)
        self.assertIn('inspect_runtime_image "$ENGINE_PLATFORM" --format',text)
        self.assertIn('inspect_runtime_image "$PLATFORM" "$IMAGE_REF"',text)
if __name__=='__main__':unittest.main()
