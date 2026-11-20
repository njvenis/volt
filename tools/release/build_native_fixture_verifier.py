"""Build-only native fixture Q from independently provided PUBLIC policy.

No key generation, signing, transparency bypass, upload or production target
change. Hosted CI must receive this context and expected hash independently.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.release.native_runtime_probe import native_context, frozen_git_source, verify_source_context
NAMES={'fixture-trust.json','fixture.pub','trusted-root.json'}
URL='http://127.0.0.1:47280'


def unique_pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('duplicate public policy field')
        result[key]=value
    return result


def read_public_policy(directory: Path, expected: str) -> tuple[dict,dict]:
    if not re.fullmatch('sha256:[0-9a-f]{64}',expected):raise ValueError('independent policy hash required')
    directory=directory.absolute()
    if directory.resolve(strict=True)!=directory:raise ValueError('canonical unlinked private context required')
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    def same(a,b):return all(getattr(a,k)==getattr(b,k)for k in fields)
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
    files={}
    try:
        directory_before=os.fstat(dfd)
        if (directory_before.st_uid!=os.getuid() or stat.S_IMODE(directory_before.st_mode)!=0o700
                or not same(directory_before,directory.lstat())):
            raise ValueError('stable owned private context required')
        if set(os.listdir(dfd))!=NAMES:raise ValueError('exact three public files required')
        for name in sorted(NAMES):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dfd)
            with os.fdopen(fd,'rb')as f:
                before=os.fstat(f.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid()
                        or before.st_size>65536 or stat.S_IMODE(before.st_mode)&0o022
                        or not same(before,os.stat(name,dir_fd=dfd,follow_symlinks=False))):
                    raise ValueError('public material custody/size differs')
                raw=f.read(65537);after=os.fstat(f.fileno())
                if (len(raw)!=before.st_size or not same(before,after)
                        or not same(after,os.stat(name,dir_fd=dfd,follow_symlinks=False))):
                    raise ValueError('public material name/bytes changed')
            if b'PRIVATE' in raw.upper():raise ValueError('private material forbidden')
            files[name]=raw
        if set(os.listdir(dfd))!=NAMES or not same(directory_before,os.fstat(dfd)) or not same(directory_before,directory.lstat()):
            raise ValueError('public context changed while reading')
    finally:os.close(dfd)
    inventory={name:hashlib.sha256(raw).hexdigest()for name,raw in files.items()}
    actual='sha256:'+hashlib.sha256(json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if actual!=expected:raise ValueError('independently expected public policy differs')
    policy=json.loads(files['fixture-trust.json'],object_pairs_hook=unique_pairs);root=json.loads(files['trusted-root.json'],object_pairs_hook=unique_pairs)
    if policy!={'rekor_base_url':URL}:raise ValueError('fixed fixture log endpoint required')
    pem=files['fixture.pub'].decode('ascii').strip().splitlines()
    if len(pem)<3 or pem[0]!='-----BEGIN PUBLIC KEY-----'or pem[-1]!='-----END PUBLIC KEY-----':raise ValueError('SPKI public key required')
    base64.b64decode(''.join(pem[1:-1]),validate=True)
    if set(root)!={'mediaType','tlogs'}or root['mediaType']!='application/vnd.dev.sigstore.trustedroot+json;version=0.1'or type(root['tlogs'])is not list or len(root['tlogs'])!=1:
        raise ValueError('closed public fixture trusted root required')
    log=root['tlogs'][0]
    if (set(log)!={'baseUrl','hashAlgorithm','logId','publicKey'}or log['baseUrl']!=URL
            or log['hashAlgorithm']!='SHA2_256'or set(log['logId'])!={'keyId'}
            or set(log['publicKey'])!={'keyDetails','rawBytes','validFor'}
            or log['publicKey']['keyDetails']!='PKIX_ECDSA_P256_SHA_256'
            or set(log['publicKey']['validFor'])!={'start'}
            or type(log['publicKey']['validFor']['start'])is not str):
        raise ValueError('public fixture log key schema differs')
    key=base64.b64decode(log['publicKey']['rawBytes'],validate=True)
    if base64.b64decode(log['logId']['keyId'],validate=True)!=hashlib.sha256(key).digest():raise ValueError('log public key ID differs')
    return {'sha256':actual,'files_sha256':inventory},files


def public_policy(directory: Path, expected: str) -> dict:
    return read_public_policy(directory,expected)[0]


def stage_public_policy(out: Path, files: dict, expected: str) -> tuple[Path,dict]:
    if (out.resolve(strict=True)!=out.absolute() or out.lstat().st_uid!=os.getuid()
            or stat.S_IMODE(out.lstat().st_mode)!=0o700):raise ValueError('private stable staging parent required')
    destination=out/'public-policy';destination.mkdir(mode=0o700)
    dfd=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        for name in sorted(NAMES):
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=dfd)
            with os.fdopen(fd,'wb')as stream:stream.write(files[name]);stream.flush();os.fsync(stream.fileno())
        os.fsync(dfd)
    finally:os.close(dfd)
    return destination,public_policy(destination,expected)


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform',choices=('linux/amd64','linux/arm64'),required=True)
    p.add_argument('--source-commit',required=True);p.add_argument('--source-snapshot',required=True)
    p.add_argument('--public-policy',type=Path,required=True);p.add_argument('--expected-policy-sha256',required=True)
    p.add_argument('--evidence',type=Path,required=True);a=p.parse_args();os.umask(0o077)
    if not re.fullmatch('[0-9a-f]{40}',a.source_commit)or not re.fullmatch('sha256:[0-9a-f]{64}',a.source_snapshot):raise ValueError('exact source hashes required')
    policy=a.public_policy.absolute();proof,public_bytes=read_public_policy(policy,a.expected_policy_sha256)
    if ROOT==policy or ROOT in policy.parents:raise ValueError('policy must be independently supplied outside source context')
    daemon=subprocess.check_output(['docker','version','--format','{{.Server.Os}}/{{.Server.Arch}}'],text=True).strip();native_context(a.platform,platform.machine(),daemon)
    out=a.evidence.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    source,binding=frozen_git_source(out,a.source_commit,a.source_snapshot)
    staged,staged_proof=stage_public_policy(out,public_bytes,a.expected_policy_sha256)
    if staged_proof!=proof:raise ValueError('private re-staging differs')
    tag='volt-native-fixture-q:'+a.platform.split('/')[1]
    argv=['docker','build','--pull=false','--network=none','--platform',a.platform,'--target','verifier-fixture',
        '--build-context','fixture-policy='+str(staged),'--file',str(source/'tools/release/verifier.Dockerfile'),
        '--label','org.opencontainers.image.revision='+a.source_commit,
        '--label','org.volt.compose.source-snapshot='+a.source_snapshot,'--tag',tag,str(source)]
    (out/'build.invocation.json').write_text(json.dumps({'argv':argv,'cwd':str(ROOT),'public_policy':proof,
        'source_revision':a.source_commit,'source_snapshot':a.source_snapshot,'source_binding':binding,'scope':'native fixture verifier build only; no signing/admission/runtime qualification'},indent=2)+'\n')
    verify_source_context(source,binding['files'])
    if public_policy(staged,a.expected_policy_sha256)!=proof:raise ValueError('staged policy changed before build')
    with(out/'build.stdout').open('x')as stdout,(out/'build.stderr').open('x')as stderr:r=subprocess.run(argv,cwd=ROOT,stdout=stdout,stderr=stderr)
    (out/'build.exit').write_text(str(r.returncode)+'\n')
    if r.returncode:return r.returncode
    verify_source_context(source,binding['files'])
    if public_policy(staged,a.expected_policy_sha256)!=proof:raise ValueError('private staged policy changed across build')
    row=json.loads(subprocess.check_output(['docker','image','inspect','--platform',a.platform,tag]))[0]
    if row['Os']+'/'+row['Architecture']!=a.platform or row['Config']['Labels'].get('org.opencontainers.image.revision')!=a.source_commit or row['Config']['Labels'].get('org.volt.compose.source-snapshot')!=a.source_snapshot:raise ValueError('fixture verifier image binding differs')
    (out/'image.json').write_text(json.dumps(row,indent=2)+'\n')
    subprocess.run(['docker','image','save','--output',str(out/'fixture-verifier.tar'),tag],check=True)
    (out/'fixture-verifier.tar.sha256').write_text(hashlib.sha256((out/'fixture-verifier.tar').read_bytes()).hexdigest()+'  fixture-verifier.tar\n')
    return 0


if __name__=='__main__':raise SystemExit(main())
