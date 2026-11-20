"""Job-local real Sigstore ceremony for the ordinary hosted ARM LOCAL journey.

No production keys/endpoints, emulation, public signing or generic command API.
Private workspace MUST NOT be uploaded. Only a closed public summary is exported.
"""
from __future__ import annotations
import argparse,base64,datetime,hashlib,io,json,os,re,secrets,shutil,stat,subprocess,sys,tarfile,time,urllib.request,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.release import hosted_arm_essential as essential
from tools.release import build_native_fixture_verifier as q_builder
from tools.release import native_runtime_probe as native
from tools.release.easy_bootstrap import COSIGN_IMAGE
from uvm.installer.admission import platform_children

REGISTRY='registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
URL='http://127.0.0.1:47280'
LABEL='volt.hosted-arm.owner'
ROLE='volt.hosted-arm.role'
MEDIA={'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}
INDEX_MEDIA={'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'}

def sha(path):
    with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def digest(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def write(path,value):
    with path.open('xb')as f:f.write(value);f.flush();os.fsync(f.fileno())
def json_write(path,value):write(path,canonical(value))

def strict_descriptor(row,arch='arm64'):
    return (type(row)is dict and type(row.get('digest'))is str and essential.DIGEST.fullmatch(row['digest'])is not None
      and row.get('mediaType')in MEDIA and type(row.get('size'))is int and row['size']>0
      and type(row.get('platform'))is dict and row['platform'].get('os')=='linux'and row['platform'].get('architecture')==arch
      and set(row['platform'])<={'os','architecture','variant'}and row['platform'].get('variant')in (None,'v8'))

def artifact_config(directory,arch,revision,snapshot,event_sha):
    """Validate entire same-run Docker archive before any docker load."""
    if directory.resolve(strict=True)!=directory.absolute():raise ValueError('artifact path alias')
    def text(name,limit=16384):return native.regular_bytes(directory/name,limit).decode().strip()
    if text('source-revision.txt')!=revision or text('source-snapshot.txt')!=snapshot or text('source-event-revision.txt')!=event_sha:raise ValueError('same-run artifact source differs')
    selection=json.loads(text('source-selection.json'),object_pairs_hook=essential.pairs)
    if (selection.get('event_sha')!=event_sha or selection.get('selected_source_sha')!=revision
            or selection.get('checked_out_sha')!=revision or selection.get('source_snapshot')!=snapshot):raise ValueError('selected/checked out source differs')
    expected=text('runtime.tar.sha256').split()
    if len(expected)!=2 or not re.fullmatch('[0-9a-f]{64}',expected[0])or expected[1]!='runtime.tar':raise ValueError('closed archive checksum required')
    archive=directory/'runtime.tar';before=archive.lstat()
    if (not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or before.st_nlink!=1
            or sha(archive)!=expected[0]):raise ValueError('native archive custody/hash differs')
    small={};seen=set()
    with tarfile.open(archive,'r:')as tar:
        for member in tar:
            parts=Path(member.name).parts
            if member.name in seen or member.name.startswith('/')or '..'in parts or not(member.isdir()or member.isfile()):raise ValueError('native Docker archive path/type differs')
            seen.add(member.name)
            if member.isfile()and member.size<=2*1024*1024 and (member.name.endswith('.json')or member.name.startswith('blobs/sha256/')):
                raw=tar.extractfile(member).read(member.size+1)
                try:json.loads(raw,object_pairs_hook=essential.pairs)
                except (ValueError,UnicodeDecodeError):continue
                small[member.name]=raw
    manifest=json.loads(small['manifest.json'],object_pairs_hook=essential.pairs)
    if (type(manifest)is not list or len(manifest)!=1 or manifest[0].get('RepoTags')!=['volt-easy-rc4:'+arch]
            or type(manifest[0].get('Layers'))is not list or not manifest[0]['Layers']
            or any(type(name)is not str or name not in seen for name in manifest[0]['Layers'])):raise ValueError('one exact native build tag required')
    raw=small[manifest[0]['Config']];config=json.loads(raw,object_pairs_hook=essential.pairs);labels=config.get('config',{}).get('Labels',{})
    if (config.get('os')!='linux'or config.get('architecture')!=arch
            or labels.get('org.opencontainers.image.revision')!=revision or labels.get('org.volt.compose.source-snapshot')!=snapshot
            or labels.get('org.opencontainers.image.version')!='0.1.0-rc.4' or labels.get('org.volt.compose-install.contract')!='1'
            or 'local'not in labels.get('org.volt.oidc-deployment-modes','').split(',')):raise ValueError('actual config/source/platform differs')
    fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    identity=[getattr(before,k)for k in fields]
    if identity!=[getattr(archive.lstat(),k)for k in fields]:raise ValueError('native archive changed during validation')
    return {'archive':str(archive),'archive_identity':identity,'tar_sha256':expected[0],'config_id':digest(raw),'tag':'volt-easy-rc4:'+arch,'platform':'linux/'+arch}

def trust_documents(rekor_pem,signer_pem,start):
    # Real public key from the registered, live job-local Rekor. Never a fake
    # entry or synthesized signature/proof. Cosign creates/verifies inclusion.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    log=serialization.load_pem_public_key(rekor_pem)
    if not isinstance(log,ec.EllipticCurvePublicKey)or not isinstance(log.curve,ec.SECP256R1):raise ValueError('Rekor P256 public key required')
    serialization.load_pem_public_key(signer_pem)
    der=log.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    root={'mediaType':'application/vnd.dev.sigstore.trustedroot+json;version=0.1','tlogs':[{'baseUrl':URL,'hashAlgorithm':'SHA2_256',
        'logId':{'keyId':base64.b64encode(hashlib.sha256(der).digest()).decode()},'publicKey':{'keyDetails':'PKIX_ECDSA_P256_SHA_256','rawBytes':base64.b64encode(der).decode(),'validFor':{'start':start}}}]}
    policy={'fixture-trust.json':canonical({'rekor_base_url':URL}),'fixture.pub':signer_pem,'trusted-root.json':canonical(root)}
    config={'mediaType':'application/vnd.dev.sigstore.signingconfig.v0.2+json','rekorTlogConfig':{'selector':'ANY'},
        'rekorTlogUrls':[{'majorApiVersion':1,'operator':'volt-hosted-arm-ephemeral','url':URL,'validFor':{'start':start}}],'tsaConfig':{}}
    return policy,canonical(config)

def stable_recipe(row):
    return {k:row.get(k)for k in ('Id','Created','Image','Name','Config','HostConfig')}

class Ceremony:
    def __init__(self,work,revision,snapshot):
        self.work=work;self.revision=revision;self.snapshot=snapshot;self.owner=uuid.uuid4().hex
        self.prefix='volt-arm-'+self.owner[:12];self.counter=0;self.containers=[];self.network=None;self.public={};self.dependencies={}
        self.raw=work/'raw';self.raw.mkdir(mode=0o700);self.started=datetime.datetime.now(datetime.timezone.utc)
        self.lock=json.loads((ROOT/'tools/release/hosted-arm-fixture-components.json').read_text())
        self.capabilities=None;self.last_producer=None;self.uncertain=[]
    def run(self,label,argv,*,check=True,input_bytes=None,stdin=None):
        self.last_producer=label
        self.counter+=1;base=self.raw/(str(self.counter).zfill(4)+'-'+label)
        json_write(base.with_suffix('.argv.json'),{'argv':argv,'cwd':str(ROOT),'before_execution':True})
        r=subprocess.run(argv,cwd=ROOT,input=input_bytes,stdin=stdin,capture_output=True)
        for suffix,raw in (('.stdout',r.stdout),('.stderr',r.stderr),('.exit',str(r.returncode).encode())):write(base.with_suffix(suffix),raw)
        if check and r.returncode:raise RuntimeError('private ceremony producer failed: '+label)
        return r
    def document(self,label,argv):return json.loads(self.run(label,argv).stdout,object_pairs_hook=essential.pairs)
    def inspection(self,cid):
        rows=self.document('registered-inspect',['docker','inspect',cid])
        if type(rows)is not list or len(rows)!=1 or rows[0]['Id']!=cid:raise ValueError('registered full CID differs')
        return rows[0]
    def dependency(self,label,reference,*,native_platform='linux/arm64'):
        raw=self.run(label+'-index',['docker','buildx','imagetools','inspect','--raw',reference]).stdout
        if digest(raw)!=reference.rsplit('@',1)[1]:raise ValueError('pinned dependency index differs')
        index=json.loads(raw,object_pairs_hook=essential.pairs)
        if index.get('mediaType')in INDEX_MEDIA:
            rows=[r for r in index['manifests']if r.get('platform',{}).get('os')=='linux'and r['platform'].get('architecture')=='arm64']
            if len(rows)!=1 or not strict_descriptor(rows[0]):raise ValueError('one typed native ARM dependency child required')
            child=rows[0];child_ref=reference.split('@')[0]+'@'+child['digest']
            childraw=self.run(label+'-child',['docker','buildx','imagetools','inspect','--raw',child_ref]).stdout
            if digest(childraw)!=child['digest']or len(childraw)!=child['size']:raise ValueError('dependency child bytes differ')
            manifest=json.loads(childraw,object_pairs_hook=essential.pairs)
        else:raise ValueError('pinned official dependency must expose native index')
        if manifest.get('schemaVersion')!=2 or manifest.get('mediaType')not in MEDIA:raise ValueError('executable native dependency manifest required')
        config=manifest.get('config',{})
        if (type(config.get('size'))is not int or config['size']<=0 or config.get('mediaType')not in ('application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json')):raise ValueError('typed dependency config descriptor required')
        if type(config.get('digest'))is not str or not essential.DIGEST.fullmatch(config['digest']):raise ValueError('dependency config digest required')
        self.run(label+'-pull',['docker','pull','--platform',native_platform,reference])
        row=self.document(label+'-image',['docker','image','inspect',reference])[0]
        if row.get('Os')+'/'+row.get('Architecture')!=native_platform:raise ValueError('actual dependency is not native ARM')
        if row['Id']not in (config['digest'],child['digest'],reference.split('@')[1]):raise ValueError('unknown engine dependency identity')
        dep={'reference':reference,'engine_id':row['Id'],'child':child,'config_id':config['digest'],'image':row}
        self.dependencies[label]=dep;return dep
    def create(self,role,dep,cmd,*,aliases=(),env=(),tmpfs=None,ports=(),binds=(),user=None,entrypoint=None,cap_drop=True):
        name=self.prefix+'-'+role;tmpfs=tmpfs or {'/tmp':'rw,noexec,nosuid,size=16m'}
        cmd=cmd or dep['image']['Config'].get('Cmd')or[]
        self.network_check()
        argv=['docker','create','--platform','linux/arm64','--pull=never','--restart=no','--name',name,
            '--network',self.network['Name'],'--read-only','--security-opt=no-new-privileges','--label',LABEL+'='+self.owner,'--label',ROLE+'='+role]
        if cap_drop:argv+=['--cap-drop=ALL']
        for alias in aliases:argv+=['--network-alias',alias]
        for value in env:argv+=['--env',value]
        for path,options in tmpfs.items():argv+=['--tmpfs',path+':'+options]
        for value in ports:argv+=['--publish',value]
        for value in binds:argv+=['--mount',value]
        if user is not None:argv+=['--user',user]
        if entrypoint is not None:argv+=['--entrypoint',entrypoint]
        argv += [dep['engine_id'],*cmd]
        cid=self.run(role+'-create',argv).stdout.decode().strip()
        if not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('full new CID required')
        self.uncertain.append('unvalidated-container-'+cid)
        row=self.inspection(cid);cfg=row['Config'];host=row['HostConfig'];witness=row.get('ImageManifestDescriptor')
        if (row['Name']!='/'+name or cfg.get('Labels',{}).get(LABEL)!=self.owner or cfg['Labels'].get(ROLE)!=role
                or cfg.get('Image')!=dep['engine_id']or cfg.get('Cmd')!=cmd or host.get('NetworkMode')!=self.network['Name']
                or host.get('ReadonlyRootfs')is not True or host.get('Privileged')is not False
                or (host.get('Tmpfs')or{})!=tmpfs or row['Image']not in (dep['engine_id'],dep['config_id'])):raise ValueError('created infrastructure recipe differs')
        expected_user=user if user is not None else dep['image']['Config'].get('User','')
        expected_entry=[entrypoint]if entrypoint else dep['image']['Config'].get('Entrypoint')
        expected_ports={}
        for mapping in ports:
            ip,port,target=mapping.split(':');expected_ports[target+'/tcp']=[{'HostIp':ip,'HostPort':port}]
        if (cfg.get('User','')!=expected_user or cfg.get('Entrypoint')!=expected_entry
                or (host.get('PortBindings')or{})!=expected_ports or host.get('PublishAllPorts')is not False
                or host.get('RestartPolicy',{}).get('Name')!='no'or host.get('CapAdd')
                or set(host.get('CapDrop')or[])!=({'ALL'}if cap_drop else set())
                or set(host.get('SecurityOpt')or[])!={'no-new-privileges'}
                or host.get('Devices')or host.get('VolumesFrom')or host.get('ExtraHosts')):raise ValueError('closed infrastructure role recipe differs')
        self.validate_mounts(row,tmpfs,binds)
        if row['Image']!=dep['config_id']and witness!=dep['child']:raise ValueError('non-config engine identity requires exact actual child witness')
        record={'cid':cid,'recipe':stable_recipe(row),'started_at':row['State']['StartedAt'],'role':role,'tmpfs':tmpfs,'binds':list(binds)}
        self.containers.append(record);self.uncertain.remove('unvalidated-container-'+cid);json_write(self.work/('container-'+role+'.json'),record)
        self.run(role+'-start',['docker','start',cid]);row=self.inspection(cid)
        if stable_recipe(row)!=record['recipe']or row['State'].get('Running')is not True:raise ValueError('registered infrastructure did not start unchanged')
        self.validate_mounts(row,tmpfs,binds)
        networks=row.get('NetworkSettings',{}).get('Networks',{})
        if set(networks)!={self.network['Name']}or networks[self.network['Name']].get('NetworkID')!=self.network['Id']:raise ValueError('actual infrastructure network differs')
        record['started_at']=row['State']['StartedAt'];return record
    def network_check(self):
        row=self.document('network-current',['docker','network','inspect',self.network['Id']])[0]
        if {k:row.get(k)for k in self.network}!=self.network:raise ValueError('original infrastructure network differs')
    @staticmethod
    def validate_mounts(row,tmpfs,binds):
        expected={}
        for value in binds:
            fields=dict(item.split('=',1)for item in value.split(','))
            if fields.get('type')!='bind'or set(fields)!={'type','src','dst'}:raise ValueError('fixed bind recipe required')
            expected[fields['dst']]=fields['src']
        found={};destinations=set()
        for mount in row.get('Mounts',[]):
            destination=mount.get('Destination')
            if type(destination)is not str or destination in destinations:raise ValueError('duplicate or invalid infrastructure mount')
            destinations.add(destination)
            if mount.get('Type')=='tmpfs'and destination in tmpfs and mount.get('RW')is True:continue
            if (mount.get('Type')!='bind'or destination not in expected or destination in found
                    or mount.get('Source')!=expected[destination]or mount.get('RW')is not True):raise ValueError('unexpected inherited or changed infrastructure mount')
            found[destination]=mount['Source']
        if found!=expected:raise ValueError('infrastructure bind missing')
    def check(self,record):
        row=self.inspection(record['cid'])
        if (stable_recipe(row)!=record['recipe']or row['State']['StartedAt']!=record['started_at']
                or row['State'].get('Running')is not True or row['State'].get('Paused')is not False
                or row['State'].get('Restarting')is not False):raise ValueError('original infrastructure identity changed')
        self.validate_mounts(row,record['tmpfs'],record['binds']);return row
    def http(self,url,limit=65536):
        if url not in ('http://127.0.0.1:46150/v2/',URL+'/ping',URL+'/api/v1/log/publicKey',URL+'/api/v1/log'):raise ValueError('fixed loopback query required')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        with opener.open(url,timeout=3)as response:
            raw=response.read(limit+1)
            if response.status!=200 or len(raw)>limit:raise ValueError('bounded loopback response required')
            return raw
    def service_health(self,record):
        import ipaddress
        row=self.check(record)
        if record['role']not in ('trillian-server','trillian-signer'):raise ValueError('fixed health role required')
        networks=row.get('NetworkSettings',{}).get('Networks',{})
        if set(networks)!={self.network['Name']}:raise ValueError('private health network differs')
        network=networks[self.network['Name']]
        if network.get('NetworkID')!=self.network['Id']:raise ValueError('private health attachment differs')
        address=ipaddress.ip_address(network['IPAddress'])
        subnets=[ipaddress.ip_network(r['Subnet'])for r in self.network['IPAM']['Config']if 'Subnet'in r]
        if not any(address in subnet for subnet in subnets):raise ValueError('private health address outside owned subnet')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        with opener.open('http://'+str(address)+':8091/healthz',timeout=3)as response:
            raw=response.read(65537)
            return response.status==200 and len(raw)<=65536
    def wait(self,label,predicate,seconds=180):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            try:
                if predicate():return
            except (OSError,ValueError):pass
            time.sleep(2)
        raise RuntimeError('private fixture readiness failed: '+label)
    def bootstrap(self):
        def text_run(label,argv):
            r=self.run('capability-'+label,argv)
            return subprocess.CompletedProcess(argv,r.returncode,r.stdout.decode(),r.stderr.decode())
        self.capabilities=native.audit_docker_cli(text_run,fixture_build=True)
        for port in (46150,47280,46180,46181):
            import socket
            with socket.socket()as sock:sock.bind(('127.0.0.1',port))
        # Build only canonical schema/config on the same exact pinned MySQL base.
        source=self.work/'upstream-db';source.mkdir(mode=0o700)
        for name,expected in essential.DB_FILES.items():
            url='https://raw.githubusercontent.com/google/trillian/'+essential.DB_COMMIT+'/'+name
            with urllib.request.urlopen(url,timeout=30)as response:raw=response.read(1024*1024+1)
            if len(raw)>1024*1024 or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('pinned upstream source differs')
            path=source/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);write(path,raw)
        context=self.work/'db-context';essential.prepare_db_context(source,context)
        mysql=self.dependency('mysql-base',self.lock['db']['base_index_reference'])
        self.run('db-native-build',['docker','build','--platform','linux/arm64','--pull=false','--network=none','--file',str(context/'examples/deployment/docker/db_server/Dockerfile'),'--tag',self.prefix+'-db',str(context)])
        row=self.document('db-native-image',['docker','image','inspect',self.prefix+'-db'])[0]
        if row.get('Os')!='linux'or row.get('Architecture')!='arm64':raise ValueError('native canonical DB image required')
        # Conservative store boundary: require a config ID for this newly built
        # single-platform DB. Never guess a child from an ambiguous local index.
        saved=self.work/'db-image.tar';self.run('db-image-save',['docker','image','save','--output',str(saved),row['Id']])
        with tarfile.open(saved,'r:')as tar:
            manifest=json.load(tar.extractfile('manifest.json'),object_pairs_hook=essential.pairs)
            if len(manifest)!=1:raise ValueError('one canonical DB image required')
            cfg=tar.extractfile(manifest[0]['Config']).read(2*1024*1024+1)
        if len(cfg)>2*1024*1024 or row['Id']!=digest(cfg):raise ValueError('canonical DB engine must expose the exact config identity')
        db={'reference':self.prefix+'-db','engine_id':row['Id'],'config_id':digest(cfg),'child':None,'image':row}
        for label,entry in self.lock['component_indices'].items():self.dependency(label,entry['parent_reference'])
        self.dependency('registry',REGISTRY);self.dependency('cosign',COSIGN_IMAGE)
        network_id=self.run('network-create',['docker','network','create','--driver','bridge','--internal','--label',LABEL+'='+self.owner,self.prefix+'-network']).stdout.decode().strip()
        self.uncertain.append('unvalidated-network-'+network_id)
        row=self.document('network-initial',['docker','network','inspect',network_id])[0]
        if row['Id']!=network_id or row['Name']!=self.prefix+'-network'or row.get('Labels',{}).get(LABEL)!=self.owner or row.get('Containers')or row.get('Internal')is not True:raise ValueError('new isolated infrastructure network required')
        self.network={k:row[k]for k in ('Id','Name','Driver','Internal','Labels','IPAM')}
        self.uncertain.remove('unvalidated-network-'+network_id)
        password=secrets.token_hex(24);dsn='test:'+password+'@tcp(mysql:3306)/test?parseTime=true&interpolateParams=true'
        dbrecord=self.create('db',db,[],aliases=('mysql',),env=('MYSQL_ROOT_PASSWORD='+password,'MYSQL_DATABASE=test','MYSQL_USER=test','MYSQL_PASSWORD='+password),tmpfs={'/tmp':'rw,nosuid,size=16m','/var/run/mysqld':'rw,nosuid,size=16m','/var/lib/mysql':'rw,nosuid,size=768m'},cap_drop=False)
        def mysql_ready():
            self.check(dbrecord)
            return self.run('mysql-readiness',['docker','exec',dbrecord['cid'],'mysql','--protocol=TCP','--host=127.0.0.1','--user=test','--password='+password,'--database=test','--batch','--skip-column-names','--execute','SELECT COUNT(*) FROM Trees'],check=False).returncode==0
        self.wait('canonical-mysql',mysql_ready)
        common=['--quota_system=noop','--storage_system=mysql','--mysql_uri='+dsn,'--rpc_endpoint=0.0.0.0:8090','--http_endpoint=0.0.0.0:8091','--alsologtostderr']
        server=self.create('trillian-server',self.dependencies['trillian-server'],common,aliases=('trillian-log-server',))
        self.wait('trillian-server',lambda:self.service_health(server))
        signer=self.create('trillian-signer',self.dependencies['trillian-signer'],[*common,'--force_master'])
        self.wait('trillian-signer',lambda:self.service_health(signer))
        rekor_cmd=['serve','--trillian_log_server.address=trillian-log-server','--trillian_log_server.port=8090',
            '--rekor_server.address=0.0.0.0','--rekor_server.signer=memory','--enable_attestation_storage',
            '--attestation_storage_bucket=file:///var/run/attestations','--search_index.storage_provider=mysql','--search_index.mysql.dsn='+dsn]
        self.rekor=self.create('rekor',self.dependencies['rekor'],rekor_cmd,ports=('127.0.0.1:47280:3000',),tmpfs={'/tmp':'rw,noexec,nosuid,size=16m','/var/run/attestations':'rw,noexec,nosuid,size=64m,mode=1777'})
        self.wait('genuine-rekor',lambda:bool(self.http(URL+'/ping')))
        data=self.work/'registry-data';data.mkdir(mode=0o700)
        self.registry=self.create('registry',self.dependencies['registry'],[],ports=('127.0.0.1:46150:5000',),binds=('type=bind,src='+str(data)+',dst=/var/lib/registry',),user=str(os.getuid())+':'+str(os.getgid()))
        self.wait('owned-registry',lambda:bool(self.http('http://127.0.0.1:46150/v2/')))
    def cosign(self,label,args,*,sign=False):
        signer=self.work/'signer';out=self.work/'graph';dep=self.dependencies['cosign']
        argv=['docker','run','--rm','--platform','linux/arm64','--pull=never','--network','host'if sign else'none',
          '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
          '--env','HOME=/tmp','--env','COSIGN_PASSWORD=','--user',str(os.getuid())+':'+str(os.getgid()),
          '--mount','type=bind,src='+str(signer)+',dst=/keys'+(''if args[0]=='generate-key-pair'else',readonly'),
          '--mount','type=bind,src='+str(out)+',dst=/out',dep['engine_id'],*args]
        return self.run(label,argv)
    def prepare_trust(self):
        signer=self.work/'signer';graph=self.work/'graph';policy=self.work/'public-policy'
        for path in (signer,graph,policy):path.mkdir(mode=0o700)
        self.cosign('new-ephemeral-signer',['generate-key-pair','--output-key-prefix','/keys/cosign'])
        key=signer/'cosign.key';info=key.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=os.getuid()or info.st_nlink!=1:raise ValueError('new private signer custody differs')
        key.chmod(0o600)
        self.check(self.rekor);pem=self.http(URL+'/api/v1/log/publicKey')
        if pem.startswith(b'"'):pem=json.loads(pem).encode()
        start=(self.started-datetime.timedelta(minutes=5)).isoformat().replace('+00:00','Z')
        files,config=trust_documents(pem,native.regular_bytes(signer/'cosign.pub',65536),start)
        for name,raw in files.items():write(policy/name,raw)
        write(signer/'trusted-root.json',files['trusted-root.json']);write(signer/'signing-config.json',config)
        proof='sha256:'+hashlib.sha256(json.dumps({n:hashlib.sha256(r).hexdigest()for n,r in files.items()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        q_builder.public_policy(policy,proof);self.policy=policy;self.policy_hash=proof;self.rekor_public=pem
    def load_graph(self,artifacts,event_sha):
        records={arch:artifact_config(artifacts/('volt-easy-rc4-runtime-'+arch),arch,self.revision,self.snapshot,event_sha)for arch in ('amd64','arm64')}
        refs=[]
        for arch,row in records.items():
            fd=os.open(row['archive'],os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb')as original:
                fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                if [getattr(os.fstat(original.fileno()),k)for k in fields]!=row['archive_identity']:raise ValueError('original artifact identity changed before load')
                if hashlib.file_digest(original,'sha256').hexdigest()!=row['tar_sha256']:raise ValueError('original artifact bytes changed before load')
                original.seek(0);self.run('native-load-'+arch,['docker','load'],stdin=original)
                if [getattr(os.fstat(original.fileno()),k)for k in fields]!=row['archive_identity']:raise ValueError('original artifact changed during load')
            image=self.document('loaded-'+arch,['docker','image','inspect',row['tag']])[0]
            if image.get('Architecture')!=arch or image.get('Os')!='linux'or image['Id']!=row['config_id']:raise ValueError('loaded archive is not original native child')
            ref='127.0.0.1:46150/volt:'+self.owner+'-'+arch
            self.run('runtime-tag-'+arch,['docker','tag',image['Id'],ref]);self.run('runtime-push-'+arch,['docker','push',ref]);refs.append(ref)
        tag='127.0.0.1:46150/volt:'+self.owner+'-index'
        self.run('runtime-index-create',['docker','buildx','imagetools','create','--tag',tag,*refs])
        raw=self.run('runtime-index-inspect',['docker','buildx','imagetools','inspect','--raw',tag]).stdout
        self.runtime='127.0.0.1:46150/volt@'+digest(raw);children=platform_children(raw,self.runtime)
        self.children=children;self.public['runtime_reference']=self.runtime
        # Native ARM child must be the exact original CI config after push/index.
        manifest=self.run('runtime-arm-manifest',['docker','buildx','imagetools','inspect','--raw','127.0.0.1:46150/volt@'+children['linux/arm64']]).stdout
        if json.loads(manifest,object_pairs_hook=essential.pairs)['config']['digest']!=records['arm64']['config_id']:raise ValueError('assembled ARM child config differs from original native artifact')
        for arch in ('amd64','arm64'):
            rawchild=self.run('runtime-'+arch+'-manifest',['docker','buildx','imagetools','inspect','--raw','127.0.0.1:46150/volt@'+children['linux/'+arch]]).stdout
            if json.loads(rawchild,object_pairs_hook=essential.pairs)['config']['digest']!=records[arch]['config_id']:raise ValueError('assembled child differs from original native artifact')
        qout=self.work/'native-q'
        self.run('native-q-build',[sys.executable,str(ROOT/'tools/release/build_native_fixture_verifier.py'),'--platform','linux/arm64','--source-commit',self.revision,'--source-snapshot',self.snapshot,'--public-policy',str(self.policy),'--expected-policy-sha256',self.policy_hash,'--evidence',str(qout)])
        qrow=json.loads((qout/'image.json').read_text());qtag='127.0.0.1:46150/volt-installer-verifier:'+self.owner
        self.run('q-tag',['docker','tag',qrow['Id'],qtag]);self.run('q-push',['docker','push',qtag])
        qraw=self.run('q-manifest',['docker','buildx','imagetools','inspect','--raw',qtag]).stdout
        self.verifier='127.0.0.1:46150/volt-installer-verifier@'+digest(qraw)
        graph=self.work/'graph';fixture=graph/'admission-fixture';fixture.mkdir(mode=0o700)
        from tools.build_compose_bundle import build,verify
        bundle=graph/'installer.bundle.tar.gz';build(bundle,self.runtime,ROOT,local_admission_fixture=True,verifier_reference=self.verifier)
        verify(bundle,ROOT,local_admission_fixture=True,verifier_reference=self.verifier)
        with tarfile.open(bundle,'r:gz')as tar:write(graph/'launcher.sh',tar.extractfile('volt-compose-0.1.0-rc.4/launcher.sh').read())
        predicate={'schema_version':1,'release_version':'0.1.0-rc.4','source_repository':'https://github.com/njvenis/volt','source_revision':self.revision,'source_snapshot':self.snapshot,'image_index_digest':self.runtime.split('@')[1],'platform_children':children,'installer_bundle_sha256':sha(bundle)}
        json_write(graph/'runtime-predicate.json',predicate)
        qbuild=json.loads((qout/'build.invocation.json').read_text())
        qpredicate={'buildDefinition':{'buildType':'https://volt.dev/build/independent-local-verifier-fixture/v1','externalParameters':{'source_revision':self.revision,'source_snapshot':self.snapshot},'internalParameters':{'target':'verifier-fixture','platform':'linux/arm64'},'resolvedDependencies':[{'uri':'git+https://github.com/njvenis/volt@'+self.revision,'digest':{'sha256':self.snapshot[7:]}}]+[{'uri':'independently-provisioned-public-fixture/'+name,'digest':{'sha256':checksum}}for name,checksum in qbuild['public_policy']['files_sha256'].items()]},'runDetails':{'builder':{'id':'volt-hosted-arm-ephemeral-fixture'},'metadata':{}}}
        json_write(graph/'verifier-predicate.json',qpredicate)
        for name in ('fixture.pub','trusted-root.json'):shutil.copyfile(self.policy/name,fixture/name)
        write(fixture/'verifier.ref',(self.verifier+'\n').encode())
        return graph,fixture,bundle
    def sign_graph(self):
        self.check(self.rekor);self.check(self.registry)
        flags=['--yes','--key','/keys/cosign.key','--signing-config','/keys/signing-config.json','--trusted-root','/keys/trusted-root.json']
        self.cosign('q-sign',['sign',*flags,self.verifier],sign=True)
        self.cosign('q-slsa',['attest',*flags,'--predicate','/out/verifier-predicate.json','--type','https://slsa.dev/provenance/v1',self.verifier],sign=True)
        self.cosign('runtime-index-sign',['sign',*flags,self.runtime],sign=True)
        for arch,child in self.children.items():self.cosign('runtime-child-'+arch.split('/')[1],['sign',*flags,'127.0.0.1:46150/volt@'+child],sign=True)
        self.cosign('runtime-provenance',['attest',*flags,'--predicate','/out/runtime-predicate.json','--type','https://volt.dev/attestation/easy-install/v1',self.runtime],sign=True)
        for label,file in (('installer.bundle','installer.bundle.tar.gz'),('launcher','launcher.sh')):
            self.cosign(label+'-sign',['sign-blob',*flags,'--bundle','/out/admission-fixture/'+label+'.sigstore.json','/out/'+file],sign=True)
        # Original local log/key and container identities must remain unchanged.
        self.check(self.rekor)
        pem=self.http(URL+'/api/v1/log/publicKey')
        if pem.startswith(b'"'):pem=json.loads(pem).encode()
        if pem!=self.rekor_public:raise ValueError('original ephemeral log identity changed')
    def export_original_proofs(self,destination):
        """Export ONLY authenticated, closed public cache + public trust bytes.

        Never copy the instance, signer, raw logs or an arbitrary directory tree.
        This retains original transparency bundles/sidecars, not a cached pass.
        """
        from tools import compose_release_qualification as q
        from uvm.installer.offline_artifacts import Closure,_read,MAX_MEMBER
        private=self.work/'journey-private';evidence=self.work/'journey-evidence'
        retained=json.loads((evidence/'retained-fixture.json').read_text())
        env=q.trusted_launcher_environment(private/'proof-minimal-host-path',retained['admission'])
        q.run('hosted-final-original-crypto',['sh',str(private/'trusted-offline-entry.sh'),'verify-cache','--directory',str(private/'instance')],evidence,env=env)
        cache=private/'instance.installer-artifacts'/'originals'
        closure=Closure(fixture=None,custody_root=cache)
        expected={'runtime_reference':self.runtime,'verifier_reference':self.verifier,'source_revision':self.revision,'source_snapshot':self.snapshot,
            'bundle_sha256':'sha256:'+sha(self.work/'graph'/'installer.bundle.tar.gz'),'launcher_sha256':'sha256:'+sha(self.work/'graph'/'launcher.sh')}
        if any(closure.release.get(k)!=v for k,v in expected.items()):raise ValueError('original proof graph differs from independently selected ceremony')
        files=dict(closure.files);files['closure.json']=_read(cache,'closure.json',MAX_MEMBER)[0]
        for name in ('fixture.pub','trusted-root.json','fixture-trust.json'):files['public-trust/'+name]=native.regular_bytes(self.policy/name,65536)
        # No private PEM or instance authority may cross this explicit boundary.
        if any(re.search(br'-----BEGIN [A-Z ]*PRIVATE KEY-----',raw)for raw in files.values()):raise ValueError('private material cannot be exported')
        closure.assert_unchanged()
        if destination.exists()or destination.resolve(strict=False)!=destination.absolute():raise ValueError('fresh proof-only destination required')
        destination.mkdir(mode=0o700)
        for name,raw in files.items():
            target=destination/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);write(target,raw)
        json_write(destination/'export-inventory.json',{'schema_version':1,'profile':'hosted_arm_public_original_proofs_v1','source_revision':self.revision,'source_snapshot':self.snapshot,
            'files':{name:{'bytes':len(raw),'sha256':digest(raw)}for name,raw in files.items()},'scope':'original authenticated PUBLIC metadata/signature/inclusion closure plus independently provisioned public fixture root, no instance or signer private data'})
        return len(files)

    def cleanup_infra(self):
        failures=list(self.uncertain)
        for record in reversed(self.containers):
            try:
                row=self.inspection(record['cid'])
                if stable_recipe(row)!=record['recipe']or row['State']['StartedAt']!=record['started_at']or row['State'].get('Paused')is not False or row['State'].get('Restarting')is not False:raise ValueError('ownership/recipe drift; retain')
                self.validate_mounts(row,record['tmpfs'],record['binds'])
                self.run('cleanup-'+record['role'],['docker','rm','--force',record['cid']])
            except Exception:failures.append(record['role'])
        if self.network:
            try:
                row=self.document('network-final',['docker','network','inspect',self.network['Id']])[0]
                if {k:row.get(k)for k in self.network}!=self.network or row.get('Containers'):raise ValueError('network identity or aliases differ; retain')
                self.run('network-cleanup',['docker','network','rm',self.network['Id']])
            except Exception:failures.append('network')
        json_write(self.work/'cleanup.json',{'registered_resources_removed':not failures,'retained_uncertain_roles':failures})
        return not failures


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-commit',required=True);p.add_argument('--source-snapshot',required=True)
    p.add_argument('--artifacts',type=Path,required=True);p.add_argument('--event-sha',required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--public-result',type=Path,required=True);p.add_argument('--public-proofs',type=Path,required=True)
    a=p.parse_args();os.umask(0o077);c=None;outcome=1;clean=False;failed_producer=None;proof_files=0
    try:
        essential.require_native()
        essential.source_binding({'source_checkout':str(ROOT),'source_revision':a.source_commit,'source_snapshot':a.source_snapshot})
        if a.work.exists()or a.work.resolve(strict=False)!=a.work.absolute()or ROOT in a.work.parents:raise ValueError('new private job workspace required')
        if a.public_result.exists()or a.public_result.parent.resolve(strict=True)!=a.public_result.parent.absolute():raise ValueError('fresh independent public result required')
        if a.public_proofs.exists()or a.public_proofs.parent.resolve(strict=True)!=a.public_proofs.parent.absolute()or a.work in a.public_proofs.parents or ROOT in a.public_proofs.parents:raise ValueError('separate new public-proof output required')
        a.work.mkdir(mode=0o700);c=Ceremony(a.work,a.source_commit,a.source_snapshot)
        for arch in ('amd64','arm64'):artifact_config(a.artifacts/('volt-easy-rc4-runtime-'+arch),arch,a.source_commit,a.source_snapshot,a.event_sha)
        c.bootstrap();c.prepare_trust();graph,fixture,bundle=c.load_graph(a.artifacts,a.event_sha);c.sign_graph()
        c.run('selected-runtime-pull',['docker','pull','--platform','linux/arm64',c.runtime])
        from tools.compose_release_qualification import fixture_inspect_argv
        inspect=c.document('selected-runtime',fixture_inspect_argv(c.runtime,'linux/arm64',inspect_platform=c.capabilities['inspect_platform']))[0]
        value={'schema_version':1,'profile':essential.PROFILE,'source_revision':a.source_commit,'source_snapshot':a.source_snapshot,'source_checkout':str(ROOT),'evidence':str(a.work/'journey-evidence'),'bundle':str(bundle),'fixture':str(fixture),'image_id':inspect['Id'],'private':str(a.work/'journey-private')}
        c.last_producer='maintained-signed-LOCAL-journey'
        essential.essential(value,ROOT)
        c.last_producer='final-original-public-proof-export'
        proof_files=c.export_original_proofs(a.public_proofs);outcome=0
    except Exception:
        failed_producer=c.last_producer if c else 'preflight'
        print('hosted ARM private ceremony failed; no qualification credit; private evidence retained',file=sys.stderr)
    finally:
        if c:
            # Supported authenticated cleanup only; never manually repair or
            # delete uncertain instance resources. Infra objects have exact IDs.
            try:
                evidence=a.work/'journey-evidence';retained=evidence/'retained-fixture.json'
                if retained.exists():
                    from tools import compose_release_qualification as q
                    record=json.loads(retained.read_text());private=a.work/'journey-private'
                    env=q.trusted_launcher_environment(private/'cleanup-minimal-host-path',record['admission'])
                    q.run('hosted-supported-destroy',['sh',str(private/'trusted-offline-entry.sh'),'destroy','--directory',str(private/'instance'),'--confirm-project',record['project'],'--remove-state'],evidence,env=env)
                elif (a.work/'journey-private').exists():raise ValueError('unreconciled initial fixture; retain')
                clean=c.cleanup_infra()
            except Exception:clean=False
            if not clean:
                outcome=1;failed_producer=failed_producer or 'guarded-cleanup'
            try:essential.source_binding({'source_checkout':str(ROOT),'source_revision':a.source_commit,'source_snapshot':a.source_snapshot})
            except Exception:outcome=1;failed_producer='source-recheck'
            # Closed summary only, never raw recursive/private upload.
            json_write(a.public_result,{'schema_version':1,'status':'passed'if outcome==0 else'failed','platform':'linux/arm64',
                'source_revision':a.source_commit,'source_snapshot':a.source_snapshot,'registered_cleanup_passed':clean,'failed_producer':failed_producer,'original_public_proof_files':proof_files,
                'signed_install_stop_backup_restore_health_final_stop':outcome==0,'scope':'native ephemeral fixture-signed LOCAL development qualification; not production/Qualys/emulation',
                'runtime_reference':getattr(c,'runtime',None),'verifier_reference':getattr(c,'verifier',None)})
    return outcome
if __name__=='__main__':raise SystemExit(main())
