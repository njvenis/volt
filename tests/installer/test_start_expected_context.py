"""Pure actual-Config.Env comparison; no Docker/FD/mount authority claim."""
import unittest
from uvm.installer.runtime_mounts import validate_start_context

class ExpectedStartContextTests(unittest.TestCase):
    def test_metadata_is_required_and_actual_env_cannot_choose_its_own_context(self):
        info={'image_admission':{'id':'sha256:'+'a'*64},'local_start_admission':{'resources_sha256':'b'*64}}
        raw=['UVM_LOCAL_START_IMAGE_ID='+info['image_admission']['id'],
            'UVM_LOCAL_START_RESOURCES_SHA256='+'b'*64,'OTHER=private=value']
        validate_start_context(info,{'Config':{'Env':raw}})
        for changed in ([],raw[:1],raw+raw[:1],[raw[0],raw[1].replace('b','c')],
                [raw[0].replace('a','c'),raw[1]],None):
            with self.subTest(changed=changed is None),self.assertRaises(ValueError):
                validate_start_context(info,{'Config':{'Env':changed}})
        self.assertEqual(info['local_start_admission']['resources_sha256'],'b'*64)
        # Legitimate pre-prepare composition has exactly its existing empty
        # resource context; it cannot manufacture an issued hash from Env.
        initial={'image_admission':info['image_admission']}
        validate_start_context(initial,{'Config':{'Env':[raw[0],'UVM_LOCAL_START_RESOURCES_SHA256=']}})
        with self.assertRaises(ValueError):validate_start_context(initial,{'Config':{'Env':raw}})
