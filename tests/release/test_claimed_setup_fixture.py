"""The narrow package proof uses a genuine capability once and keeps secrets private."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import compose_release_qualification as q

class PublicClaimTests(unittest.TestCase):
    def test_genuine_capability_and_private_credentials_without_cookie_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'instance';(state/'secrets').mkdir(parents=True)
            cap=state/'secrets/bootstrap-capability-output';cap.write_text('issued.private-capability\n');cap.chmod(0o600)
            private=root/'private';private.mkdir(mode=0o700);evidence=root/'evidence';evidence.mkdir()
            class Response:
                status=201
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def read(self,limit):return json.dumps({'principal_id':'00000000-0000-4000-8000-000000000001','receipt_id':'00000000-0000-4000-8000-000000000002','authenticated':True,'credential_mode':'local_session','csrf_token':'PRIVATE_RESPONSE_SECRET'}).encode()
            class Opener:
                def open(self,request,timeout):
                    self.request=request
                    assert request.full_url=='http://127.0.0.1:46180/api/v1/auth/setup/claim'
                    assert json.loads(request.data)['capability']=='issued.private-capability'
                    assert request.get_header('Cookie') is None
                    return Response()
            opener=Opener()
            with patch('urllib.request.build_opener',return_value=opener):
                q.claim_first_admin_for_maintenance(state=state,private=private,evidence=evidence)
            self.assertEqual((private/'setup-credentials.json').stat().st_mode&0o777,0o600)
            report=(evidence/'focused-public-first-admin-claim.json').read_text()
            self.assertNotIn('issued.private-capability',report);self.assertNotIn('PRIVATE_RESPONSE_SECRET',report)
            self.assertEqual(set(p.name for p in private.iterdir()),{'setup-credentials.json'})

    def test_symlink_capability_denies_before_credentials_or_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();secret=root/'secret';secret.write_text('private');secret.chmod(0o600)
            (root/'secrets/bootstrap-capability-output').symlink_to(secret)
            private=root/'private';private.mkdir()
            with patch('urllib.request.build_opener') as opener:
                with self.assertRaises(OSError):q.claim_first_admin_for_maintenance(state=root,private=private,evidence=root)
                opener.assert_not_called()
            self.assertEqual(list(private.iterdir()),[])

    def test_failed_public_claim_cannot_expose_private_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();cap=root/'secrets/bootstrap-capability-output';cap.write_text('issued');cap.chmod(0o600)
            private=root/'private';private.mkdir()
            with patch('urllib.request.build_opener') as builder:
                builder.return_value.open.side_effect=RuntimeError('PRIVATE_HTTP_ERROR')
                with self.assertRaisesRegex(RuntimeError,'private response suppressed') as failure:
                    q.claim_first_admin_for_maintenance(state=root,private=private,evidence=root)
            self.assertNotIn('PRIVATE_HTTP_ERROR',str(failure.exception))
            self.assertFalse((root/'focused-public-first-admin-claim.json').exists())
