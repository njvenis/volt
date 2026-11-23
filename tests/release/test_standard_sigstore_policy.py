"""Fixed policy/transport controls. Crypto positives are separately recorded real Cosign components."""
import json,unittest,subprocess
from unittest.mock import patch
from types import SimpleNamespace
from urllib.error import HTTPError
from uvm.installer import sigstore_policy as p,offline_export as e,offline_artifacts as a
class StandardPolicyTests(unittest.TestCase):
 def test_exact_identity_before_any_root_or_crypto_access(self):
  for signer,issuer in [('foreign',p.ISSUER),(p.SIGNER,'foreign'),(p.SIGNER+'x',p.ISSUER)]:
   with patch.object(p.Path,'lstat',side_effect=AssertionError('must not read roots')):
    with self.assertRaisesRegex(ValueError,'exact RC4'):p.keyless_arguments(signer,issuer)
 def test_fixed_root_custody_and_no_key_skip_or_clock(self):
  import stat
  ok=SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_nlink=1,st_size=6787)
  with patch.object(p.Path,'lstat',return_value=ok):
   args=p.keyless_arguments(p.SIGNER,p.ISSUER);self.assertEqual(args,['--certificate-identity',p.SIGNER,'--certificate-oidc-issuer',p.ISSUER,'--trusted-root',str(p.TRUSTED_ROOT)])
  for key,value in [('st_mode',stat.S_IFREG|0o666),('st_mode',stat.S_IFLNK|0o444),('st_uid',65532),('st_nlink',2),('st_size',65537)]:
   bad=SimpleNamespace(**(vars(ok)|{key:value}))
   with patch.object(p.Path,'lstat',return_value=bad),self.assertRaises(ValueError):p.keyless_arguments(p.SIGNER,p.ISSUER)
 def test_public_registry_closed_roles_before_request(self):
  for ref in ['http://ghcr.io/njvenis/volt@sha256:'+'a'*64,'ghcr.io/foreign/volt@sha256:'+'a'*64,'ghcr.io/njvenis/volt:latest','127.0.0.1:46150/volt@sha256:'+'a'*64]:
   with self.assertRaises(ValueError):e.ProductionRegistry(ref)
  registry=e.ProductionRegistry('ghcr.io/njvenis/volt@sha256:'+'a'*64)
  for kind,value in [('blobs','../token'),('token','sha256:'+'a'*64)]:
   with self.assertRaises(ValueError):registry.read(kind,value)
 def test_GHCR_authentication_uses_fixed_scope_not_challenge_and_bounded_bytes(self):
  class Response:
   def __init__(self,raw):self.raw=raw
   def read(self,n):return self.raw[:n]
   def __enter__(self):return self
   def __exit__(self,*x):pass
  requests=[]
  def open(req,**kw):
   requests.append(req)
   if len(requests)==1:raise HTTPError(req.full_url,401,'denied',{'WWW-Authenticate':'Bearer realm="https://foreign.invalid"'},None)
   if len(requests)==2:return Response(b'{"token":"public.token"}')
   return Response(b'original')
  registry=e.ProductionRegistry('ghcr.io/njvenis/volt@sha256:'+'a'*64)
  with patch.object(registry.opener,'open',side_effect=open):self.assertEqual(registry.read('blobs','sha256:'+'b'*64),b'original')
  self.assertEqual(requests[1].full_url,'https://ghcr.io/token?scope=repository%3Anjvenis%2Fvolt%3Apull');self.assertNotIn('Authorization',requests[1].headers);self.assertEqual(requests[2].get_header('Authorization'),'Bearer public.token')
  with patch.object(registry.opener,'open',return_value=Response(b'x'*(a.MAX_MEMBER+1))),self.assertRaises(ValueError):registry.read('blobs','sha256:'+'b'*64)
 def test_production_offline_calls_real_closed_keyless_command_shape(self):
  import base64
  from pathlib import Path
  closure=a.Closure.__new__(a.Closure);closure.fixture=False;closure.root=Path('/run/volt-offline-artifacts');closure.release={'signer':p.SIGNER,'issuer':p.ISSUER};ref='ghcr.io/njvenis/volt@sha256:'+'a'*64;closure.references={ref:'runtime-index'};closure.assert_unchanged=lambda:None
  statement={'predicateType':a.RUNTIME_TYPE,'subject':[{'digest':{'sha256':'a'*64}}]};envelope=json.dumps({'payload':base64.b64encode(json.dumps(statement).encode()).decode()});calls=[]
  def run(argv,**kw):calls.append(argv);return subprocess.CompletedProcess(argv,0,envelope,'')
  with patch.object(p,'keyless_arguments',return_value=['--certificate-identity',p.SIGNER,'--certificate-oidc-issuer',p.ISSUER,'--trusted-root',str(p.TRUSTED_ROOT)]),patch.object(a.subprocess,'run',side_effect=run):
   closure.verify_blob('launcher.sh',signer=p.SIGNER,issuer=p.ISSUER);closure.verify_envelope(ref,a.RUNTIME_TYPE,signer=p.SIGNER,issuer=p.ISSUER)
  for argv in calls:self.assertNotIn('--key',argv);self.assertNotIn('--insecure-ignore-tlog',argv);self.assertIn(p.SIGNER,argv)
  self.assertIn('--local-image',calls[1]);self.assertIn(a.RUNTIME_TYPE,calls[1])
if __name__=='__main__':unittest.main()
