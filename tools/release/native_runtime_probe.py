"""Native build-only protected COPY/FD component; never signed LOCAL qualification."""
from __future__ import annotations
import argparse
import hashlib
import json
import io
import stat
import tarfile
import os
from pathlib import Path
import platform
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
MACHINES = {'linux/amd64': 'x86_64', 'linux/arm64': 'aarch64'}
TMPFS = {'/tmp': 'rw,noexec,nosuid,size=16m',
    '/app/media': 'rw,noexec,nosuid,nodev,size=1m',
    '/opt/uvm/state': 'rw,noexec,nosuid,nodev,size=1m',
    '/var/lib/postgresql/data': 'rw,noexec,nosuid,nodev,size=1m'}
DRIVER = '''import hashlib,json,os,runpy,signal,subprocess,sys
from pathlib import Path
assert os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site
component=runpy.run_path('/run/component/protected_launch_component.py',run_name='_native_fd_import_only')
assert not any(k=='uvm' or k.startswith('uvm.') or k=='sqlalchemy' for k in sys.modules)
audit=subprocess.run(['/usr/local/bin/python3.14','-I','-S','/usr/local/libexec/volt-check-protected-python.py'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},capture_output=True,timeout=10)
assert audit.returncode==0
fd=os.pidfd_open(os.getpid(),0)
try:signal.pidfd_send_signal(fd,0,None,0)
finally:os.close(fd)
api=component['fd_diagnostic']()
p=Path('/usr/local/lib/volt-private/volt_route_check_records.py');s=p.stat()
print(json.dumps({'scope':'native build component only; supplementary fixed FD diagnostic, no broker launch/readiness/DB/LOCAL admission/signature/backup claim','machine':os.uname().machine,'root_isolated_no_site':True,'root_no_API_imports':True,'protected_audit_exit':0,'kernel_pidfd':True,'root_records_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'API_UID1800_FD_venv_and_same_physical_copy':api},sort_keys=True))
'''



def regular_bytes(path: Path, limit: int) -> bytes:
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>limit:raise ValueError('bounded regular input required')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
        if len(raw)!=before.st_size or any(getattr(before,k)!=getattr(after,k)for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
            raise ValueError('input changed while reading')
    return raw


def verify_source_context(context: Path, inventory: dict) -> None:
    context=context.absolute()
    if context.resolve(strict=True)!=context or not context.is_dir():raise ValueError('unlinked source context required')
    if any(p.is_symlink()or not(p.is_file()or p.is_dir())for p in context.rglob('*')):raise ValueError('source links/special files forbidden')
    observed={str(p.relative_to(context))for p in context.rglob('*')if p.is_file()}
    if observed!=set(inventory):raise ValueError('source file inventory differs')
    for name,checksum in inventory.items():
        if hashlib.sha256(regular_bytes(context/name,64*1024*1024)).hexdigest()!=checksum:
            raise ValueError('source bytes differ from Git archive')


def frozen_git_source(out: Path, revision: str, snapshot: str, *, archive: Path|None=None) -> tuple[Path,dict]:
    # All executed host probe/build code and Docker context bytes must match the
    # same immutable Git archive before candidate execution. No checkout COPY.
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()!=revision:
        raise ValueError('selected source differs')
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True):
        raise ValueError('clean selected source required')
    raw=(regular_bytes(archive,64*1024*1024)if archive is not None else
         subprocess.check_output(['git','archive','--format=tar',revision],cwd=ROOT))
    if 'sha256:'+hashlib.sha256(raw).hexdigest()!=snapshot:raise ValueError('Git archive digest differs')
    if (out.resolve(strict=True)!=out.absolute() or out.lstat().st_uid!=os.getuid()
            or stat.S_IMODE(out.lstat().st_mode)!=0o700):raise ValueError('private source staging parent required')
    saved=out/'source.tar';saved.write_bytes(raw);saved.chmod(0o600);source=out/'source';source.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(raw))as tar:
        for member in tar.getmembers():
            parts=Path(member.name).parts
            if member.name.startswith('/')or '..'in parts or not(member.isfile()or member.isdir()):raise ValueError('source archive shape differs')
        tar.extractall(source,filter='data')
    inventory={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()for p in source.rglob('*')if p.is_file()}
    # Check actual executed checkout scripts AND all tracked build inputs.
    for name,checksum in inventory.items():
        if hashlib.sha256(regular_bytes(ROOT/name,64*1024*1024)).hexdigest()!=checksum:raise ValueError('actual source differs from clean Git archive')
    verify_source_context(source,inventory)
    record={'revision':revision,'source_snapshot':snapshot,'archive':str(saved),'source':str(source),'files':inventory}
    (out/'source-binding.json').write_text(json.dumps(record,indent=2)+'\n')
    return source,record


def valid_witness(value: dict|None, requested: str) -> bool:
    return (type(value)is dict and type(value.get('digest'))is str
        and re.fullmatch('sha256:[0-9a-f]{64}',value['digest'])is not None
        and type(value.get('mediaType'))is str
        and value['mediaType']in ('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json')
        and type(value.get('size'))is int and value['size']>0
        and type(value.get('platform'))is dict
        and value['platform']=={'os':'linux','architecture':requested.split('/')[1]})


def native_context(requested: str, machine: str, daemon: str) -> None:
    if requested not in MACHINES or machine != MACHINES[requested] or daemon != requested:
        raise ValueError('native host and Docker platform must both match; no emulation')



def option_advertised(help_text: str, option: str) -> bool:
    return any(re.match(r'^\s+(?:-[A-Za-z],\s+)?'+re.escape(option)+r'(?:[ =]|$)',line)
        for line in help_text.splitlines())


def audit_docker_cli(run, *, fixture_build: bool=False) -> dict:
    version=json.loads(run('docker-client-server-version',['docker','version','--format','{{json .}}']).stdout)
    apis=[]
    for key in ('Client','Server'):
        value=version.get(key)
        if type(value)is not dict or type(value.get('ApiVersion'))is not str or re.fullmatch(r'[0-9]+\.[0-9]+',value['ApiVersion'])is None:
            raise ValueError('exact Docker client/server API versions required')
        apis.append(tuple(int(p)for p in value['ApiVersion'].split('.')))
    inspect_help=run('image-inspect-help',['docker','image','inspect','--help']).stdout
    commands=[('create',['docker','create','--help'],('--platform','--pull','--name','--restart','--network','--read-only','--user','--security-opt','--label','--tmpfs','--mount','--entrypoint')),
        ('container-inspect',['docker','inspect','--help'],()),
        ('start',['docker','start','--help'],('--attach',)),
        ('remove',['docker','rm','--help'],('--force',))]
    if fixture_build:
        commands += [('build',['docker','build','--help'],('--platform','--pull','--network','--target','--build-context','--file','--label','--tag')),
            ('image-save',['docker','image','save','--help'],('--output',))]
    for name,argv,options in commands:
        help_text=run(name+'-help',argv).stdout
        if any(not option_advertised(help_text,o)for o in options):raise ValueError('fixed Docker CLI recipe unavailable: '+name)
    if min(apis)<(1,32):raise ValueError('explicit native create platform unavailable')
    return {'version':version,'inspect_platform':option_advertised(inspect_help,'--platform')and min(apis)>=(1,49)}


def inspected_native_image(run, tag: str, requested: str, revision: str, snapshot: str,
                           capabilities: dict, *, kind: str='runtime') -> tuple[dict,dict]:
    # Capability selection happens BEFORE inspection, never after an error. Old
    # clients use the single native build tag/ID, not a default multi-index child.
    if kind not in ('runtime','verifier'):raise ValueError('fixed image kind required')
    argv=['docker','image','inspect']
    if capabilities['inspect_platform']:argv += ['--platform',requested]
    rows=json.loads(run('selected-image',argv+[tag]).stdout)
    if type(rows)is not list or len(rows)!=1 or type(rows[0])is not dict:raise ValueError('one native image required')
    selected=rows[0]
    config=selected.get('Config');labels=config.get('Labels')if type(config)is dict else None
    if (type(selected.get('Id'))is not str or re.fullmatch('sha256:[0-9a-f]{64}',selected['Id'])is None
            or type(selected.get('Os'))is not str or type(selected.get('Architecture'))is not str
            or selected['Os']+'/'+selected['Architecture']!=requested
            or type(labels)is not dict or labels.get('org.opencontainers.image.revision')!=revision
            or labels.get('org.volt.compose.source-snapshot')!=snapshot
            or kind=='runtime'and labels.get('org.opencontainers.image.version')!='0.1.0-rc.4'):
        raise ValueError('native built image source/platform differs')
    if not capabilities['inspect_platform'] and selected.get('Descriptor')is not None and not valid_witness(selected['Descriptor'],requested):
        raise ValueError('ordinary inspection is not an unambiguous native image')
    engines=json.loads(run('engine-image',['docker','image','inspect',tag]).stdout)
    if type(engines)is not list or len(engines)!=1 or type(engines[0])is not dict:raise ValueError('one current engine image required')
    engine=engines[0]
    if type(engine.get('Id'))is not str or re.fullmatch('sha256:[0-9a-f]{64}',engine['Id'])is None:raise ValueError('engine image ID differs')
    if not capabilities['inspect_platform'] and engine!=selected:raise ValueError('single native build tag changed during inspection')
    return selected,engine


def create_command(image: str, requested: str, name: str, token: str,
                   component: Path, driver: Path) -> list[str]:
    command = ['docker','create','--platform',requested,'--pull=never','--name',name,
        '--restart=no','--network','none','--read-only','--user','0:0',
        '--security-opt=no-new-privileges','--label','volt.native-probe.owner='+token]
    for destination, options in TMPFS.items():command += ['--tmpfs',destination+':'+options]
    for source, destination in ((component,'/run/component/protected_launch_component.py'),
                                (driver,'/run/component/driver.py')):
        command += ['--mount',f'type=bind,src={source},dst={destination},readonly']
    return command + ['--entrypoint','/usr/bin/env',image,'-i','PATH=/usr/bin:/bin','LC_ALL=C',
        '/usr/local/bin/python3.14','-I','-S','/run/component/driver.py']


def checked_identity(row: dict, *, cid: str, name: str, token: str, selected: dict,
                     engine: dict, command: list[str], component: Path, driver: Path, requested: str) -> None:
    cfg=row['Config'];host=row['HostConfig'];descriptor=selected.get('Descriptor')
    if (row['Id']!=cid or row['Name']!='/'+name or cfg['Labels'].get('volt.native-probe.owner')!=token
            or cfg['Image']!=selected['Id'] or cfg['Entrypoint']!=['/usr/bin/env']
            or cfg['Cmd']!=command[command.index('--entrypoint')+3:] or cfg['User']!='0:0'
            or host['NetworkMode']!='none' or host['ReadonlyRootfs'] is not True
            or host['Privileged']is not False or host['CapAdd'] not in (None,[])
            or host['CapDrop'] not in (None,[]) or host['PortBindings']not in (None,{})
            or host['Tmpfs']!=TMPFS or host['SecurityOpt']!=['no-new-privileges']
            or host['RestartPolicy']!={'Name':'no','MaximumRetryCount':0}):
        raise ValueError('registered native probe identity/recipe differs')
    if row['Image']!=selected['Id']:
        witness=row.get('ImageManifestDescriptor')
        if (row['Image']!=engine['Id'] or not valid_witness(descriptor,requested) or not valid_witness(witness,requested)
                or any(witness.get(k)!=descriptor.get(k) for k in ('digest','mediaType','size','platform'))):
            raise ValueError('selected native image witness differs')
    expected={str(component):'/run/component/protected_launch_component.py',str(driver):'/run/component/driver.py'}
    mounts=row['Mounts']
    if (len(mounts)!=2 or {m['Source']:m['Destination']for m in mounts}!=expected
            or any(m['Type']!='bind' or m['RW']is not False for m in mounts)):
        raise ValueError('native probe mount inventory differs')


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=tuple(MACHINES),required=True)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--source-snapshot',required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--prepare-build',action='store_true')
    parser.add_argument('--source-archive',type=Path)
    parser.add_argument('--build-context',type=Path)
    args=parser.parse_args();os.umask(0o077)
    if not re.fullmatch('[0-9a-f]{40}',args.source_commit) or not re.fullmatch('sha256:[0-9a-f]{64}',args.source_snapshot):
        raise ValueError('exact source hashes required')
    out=args.evidence.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    def run(label,argv,check=True):
        (out/(label+'.argv.json')).write_text(json.dumps(argv)+'\n')
        r=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True,timeout=60)
        for suffix,value in (('stdout',r.stdout),('stderr',r.stderr),('exit',str(r.returncode))):
            (out/(label+'.'+suffix)).write_text(value)
        if check and r.returncode:raise RuntimeError('native probe producer failed: '+label)
        return r
    if args.prepare_build and (args.source_archive is not None or args.build_context is not None):raise ValueError('fresh preparation only')
    frozen,binding=frozen_git_source(out,args.source_commit,args.source_snapshot,archive=args.source_archive)
    if args.build_context is not None:verify_source_context(args.build_context,binding['files'])
    if args.prepare_build:return 0
    daemon=run('daemon-platform',['docker','version','--format','{{.Server.Os}}/{{.Server.Arch}}']).stdout.strip()
    native_context(args.platform,platform.machine(),daemon)
    tag='volt-easy-rc4:'+args.platform.split('/')[1]
    capabilities=audit_docker_cli(run)
    (out/'docker-cli-capabilities.json').write_text(json.dumps(capabilities,indent=2)+'\n')
    selected,engine=inspected_native_image(run,tag,args.platform,args.source_commit,args.source_snapshot,capabilities)
    component=frozen/'tools/release/protected_launch_component.py';driver=out/'driver.py';driver.write_text(DRIVER)
    component_hash=hashlib.sha256(regular_bytes(component,1048576)).hexdigest();driver_hash=hashlib.sha256(regular_bytes(driver,1048576)).hexdigest()
    token=uuid.uuid4().hex;name='volt-native-protected-'+token
    (out/'input-binding.json').write_text(json.dumps({'source_revision':args.source_commit,
        'source_snapshot':args.source_snapshot,'source_binding':binding,
        'actual_host_probe_sha256':hashlib.sha256(regular_bytes(Path(__file__),1048576)).hexdigest(),
        'component_sha256':component_hash,'driver_sha256':driver_hash,
        'build_context_verified':str(args.build_context)if args.build_context else None,
        'recorded_before_container_creation':True},indent=2)+'\n')
    command=create_command(selected['Id'],args.platform,name,token,component,driver)
    cid=run('create',command).stdout.strip()
    if not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('full registered CID required')
    def inspect(label):
        row=json.loads(run(label,['docker','inspect',cid]).stdout)[0]
        checked_identity(row,cid=cid,name=name,token=token,selected=selected,engine=engine,
            command=command,component=component,driver=driver,requested=args.platform)
        return row
    try:
        verify_source_context(frozen,binding['files'])
        if hashlib.sha256(regular_bytes(driver,1048576)).hexdigest()!=driver_hash:raise ValueError('driver changed')
        inspect('before-start')
        run('start-attach',['docker','start','--attach',cid])
        after=inspect('after-exit')
        if after['State']['Running']is not False or type(after['State']['ExitCode'])is not int or after['State']['ExitCode']!=0:
            raise ValueError('native probe container did not exit zero')
        verify_source_context(frozen,binding['files'])
        if hashlib.sha256(regular_bytes(driver,1048576)).hexdigest()!=driver_hash:raise ValueError('driver changed')
        result=json.loads((out/'start-attach.stdout').read_text())
        if result['machine']!=MACHINES[args.platform] or result['kernel_pidfd']is not True:
            raise ValueError('actual kernel/architecture result differs')
        (out/'outcome.json').write_text(json.dumps({'status':'passed_native_protected_FD_import_component',
            'platform':args.platform,'source_revision':args.source_commit,'source_snapshot':args.source_snapshot,
            'actual_image':selected['Id'],'component_sha256':component_hash,
            'source_binding':binding,'build_context_verified':str(args.build_context)if args.build_context else None,
            'driver_sha256':driver_hash,'proof':result,
            'signed_LOCAL_qualification':False,'default_capability_recipe_no_additions':True},indent=2)+'\n')
    finally:
        inspect('cleanup-guard')
        run('registered-cleanup',['docker','rm','-f',cid])
    return 0


if __name__=='__main__':raise SystemExit(main())
