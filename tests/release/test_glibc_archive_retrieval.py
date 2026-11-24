"""Exact Debian glibc archive dispatch; no package install or network in tests."""
import hashlib,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class GlibcArchiveRetrievalTests(unittest.TestCase):
    def test_only_two_pinned_glibc_packages_share_original_all_architecture_bytes(self):
        lock=dict(line.split('=',1)for line in (ROOT/'docker/g7/versions.lock').read_text().splitlines()if line and not line.startswith('#')and '='in line)
        selected={k:v for k,v in lock.items()if k.startswith('os_')and v.startswith('2.41-12+deb13u4|')}
        self.assertEqual(selected,{
            'os_delta_package_libc-l10n':'2.41-12+deb13u4|dbaa885f5504c67fe43c079f76e2b2b39fcf647ae39880aab3dd66e48f5e772d',
            'os_delta_package_locales':'2.41-12+deb13u4|ffc5578d5c2c30ca70d46113908f200a09ab6e5e9eda199463af3285dbbaae8c'})
    def branch(self):
        return (ROOT/'Dockerfile.g7').read_text().split('        libc-l10n|locales) \\\n',1)[1].split('        *) apt-get download',1)[0].replace('\\\n','').rsplit(';;',1)[0]
    def test_actual_shell_dispatch_version_architecture_and_filename_guards(self):
        for package,version,arch,allowed in [('libc-l10n','2.41-12+deb13u4','',True),('locales','2.41-12+deb13u4','',True),('locales','2.41-12+deb13u5','',False),('locales','2.41-12+deb13u4','arm64',False)]:
            with self.subTest(package=package,version=version,arch=arch),tempfile.TemporaryDirectory()as d:
                root=Path(d);stub=root/'python3';stub.write_text('#!/bin/sh\nprintf "%s\\n" "$3" > "$RECORD"\n');stub.chmod(0o700)
                record=root/'record';result=subprocess.run(['bash','-c','set -eu; '+self.branch()],cwd=root,env=os.environ|{'PATH':str(root)+':'+os.environ['PATH'],'RECORD':str(record),'package':package,'version':version,'arch':arch},capture_output=True)
                self.assertEqual(result.returncode==0,allowed)
                if allowed:self.assertEqual(record.read_text().strip(),package+'_'+version+'_all.deb')
                else:self.assertFalse(record.exists())
    def test_retrieval_is_fixed_official_snapshot_with_original_validation_afterwards(self):
        body=self.branch();self.assertIn('https://snapshot.debian.org/archive/debian/20260711T202405Z/pool/main/g/glibc/',body)
        self.assertIn('timeout=60',body);self.assertIn('response.read(67108865)',body);self.assertIn('len(data)<=67108864',body)
        docker=(ROOT/'Dockerfile.g7').read_text();start=docker.index('        libc-l10n|locales)')
        self.assertLess(start,docker.index('"$digest" "$deb" | sha256sum -c -'))
        self.assertIn('apt-get install -yqq --no-install-recommends "${verified_debs[@]}"',docker)
        self.assertIn('diff -u /tmp/g7-packages-expected /tmp/g7-packages-added-or-upgraded',docker)
        self.assertIn('test ! -s /tmp/g7-packages-removed',docker)
if __name__=='__main__':unittest.main()
