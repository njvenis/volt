"""Real POSIX rename/package binding; verifier/FD responses are component stubs.

Cryptography is not substituted with authority: this test credits only package
path/byte binding and ordering, never a signed installation or cache admission.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class InitialPublicationPackageTests(unittest.TestCase):
    def run_publication(self, root, *, offline=True, stale=False, substitute=False):
        launcher=Path(os.environ.get('PUBLICATION_LAUNCHER',str(ROOT/'deploy/compose/launcher.sh'))).read_text()
        start=launcher.index('publish_installer_cache() {')
        function=launcher[start:launcher.index('\n}\n',start)+3]
        anchor=root/'anchor';stage=anchor/'.originals.partial.A1b2C3d4';package=stage/'package';package.mkdir(parents=True)
        for name,data in [('installer.bundle.tar.gz',b'original signed bundle'),('installer.bundle.sigstore.json',b'original signature')]:
            (package/name).write_bytes(data);(root/name).write_bytes(data)
        original=package
        if not offline:
            original=root/'external-package';original.mkdir()
            for path in package.iterdir():(original/path.name).write_bytes(path.read_bytes())
        if stale:original=root/'stale-package'
        work=root/'work';work.mkdir()
        assignments={'CACHE_PARENT':str(anchor),'CACHE_DIRECTORY':str(stage),'SELF_DIR':str(original),'CACHE_STAGE':stage.name,'CACHE_STATE':str(root/'instance'),'WORK':str(work),'VERIFIER_IMAGE':'fixed-admitted-verifier','OFFLINE_MODE':str(int(offline)),'EXPECTED':str(root),'SUBSTITUTE':str(int(substitute))}
        script='set -eu\numask 077\n'+''.join(k+'='+shlex.quote(v)+'\n'for k,v in assignments.items())
        script+='''BUNDLE="$SELF_DIR/installer.bundle.tar.gz"
BUNDLE_SIG="$SELF_DIR/installer.bundle.sigstore.json"
fail() { printf '%s\\n' "$*" >&2; exit 1; }
ensure_lock_owner() { printf '%s\\n' lock-checked >>"$WORK/order"; }
collect_cache_mounts() { :; }
graph_verifier() {
 [ "$1" = publish ] || exit 92
 [ ! -e "$CACHE_PARENT/originals" ] || exit 93
 mv "$CACHE_DIRECTORY" "$CACHE_PARENT/originals"
 if [ "$SUBSTITUTE" -eq 1 ]; then printf '%s' substituted >"$CACHE_PARENT/originals/package/installer.bundle.tar.gz"; fi
 printf '%s\\n' '{}'
}
refresh_installer_admission() {
 printf '%s\\n' refresh >>"$WORK/order"
 [ "$BUNDLE" = "$SELF_DIR/installer.bundle.tar.gz" ] && [ "$BUNDLE_SIG" = "$SELF_DIR/installer.bundle.sigstore.json" ] || fail derived-reference-mismatch
 cmp -s "$BUNDLE" "$EXPECTED/installer.bundle.tar.gz" || fail exact-package-bytes-differ
 cmp -s "$BUNDLE_SIG" "$EXPECTED/installer.bundle.sigstore.json" || fail exact-signature-bytes-differ
 cmp -s "$BUNDLE" "$CACHE_DIRECTORY/package/installer.bundle.tar.gz" || fail committed-destination-differs
}
'''+function+'''
publish_installer_cache
printf '%s\\n' "$SELF_DIR" "$BUNDLE" "$BUNDLE_SIG"
'''
        result=subprocess.run(['sh','-c',script],capture_output=True,text=True)
        return result,anchor,original,work

    def test_actual_offline_rename_keeps_all_later_package_inputs_on_exact_originals(self):
        with tempfile.TemporaryDirectory()as temporary:
            result,anchor,original,work=self.run_publication(Path(temporary))
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(original.exists())
            expected=anchor/'originals/package'
            self.assertEqual(result.stdout.splitlines(),[str(expected),str(expected/'installer.bundle.tar.gz'),str(expected/'installer.bundle.sigstore.json')])
            self.assertEqual((work/'order').read_text().splitlines(),['lock-checked','refresh','lock-checked'])

    def test_online_external_signed_package_path_is_preserved_and_rechecked(self):
        with tempfile.TemporaryDirectory()as temporary:
            result,anchor,original,work=self.run_publication(Path(temporary),offline=False)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.splitlines()[0],str(original))
            self.assertEqual((work/'order').read_text().splitlines(),['lock-checked','refresh','lock-checked'])

    def test_stale_source_denies_before_rename_and_substituted_destination_before_return(self):
        for stale,substitute,message in [(True,False,'offline package source differs'),(False,True,'exact-package-bytes-differ')]:
            with self.subTest(stale=stale,substitute=substitute),tempfile.TemporaryDirectory()as temporary:
                result,anchor,original,work=self.run_publication(Path(temporary),stale=stale,substitute=substitute)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(message,result.stderr)
                self.assertEqual(result.stdout,'')
                if stale:self.assertFalse((anchor/'originals').exists())
                else:self.assertEqual((work/'order').read_text().splitlines(),['lock-checked','refresh'])
