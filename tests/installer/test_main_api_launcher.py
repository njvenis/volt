"""Protected broker input/error-channel boundaries, no production path fallback."""
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest

SPEC=importlib.util.spec_from_file_location('broker_source_fixture',Path(__file__).resolve().parents[2]/'docker/g7/main_api_launcher.py')
broker=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(broker)


def request():
    env={key:''for key in broker.API_KEYS};env.update(broker.FIXED_ENV)
    env.update(UVM_API_HOST='0.0.0.0',UVM_API_PORT='8000',UVM_DB_URL='component-only',
        UVM_API_CURSOR_SECRET='component-only',UVM_AUTH_MODE='bearer',
        UVM_OIDC_DEPLOYMENT_MODE='external',UVM_UI_ROOT='/opt/uvm/ui')
    return {'schema_version':1,'profile':broker.PROFILE,'main_bind':'0.0.0.0','main_port':8000,'api_environment':env}


class LaunchInputTests(unittest.TestCase):
    def test_exact_existing_recipe_whitelist_no_loader_environment(self):
        value=request();self.assertEqual(broker.validate_request(value),value)
        value['api_environment']['LD_PRELOAD']='private-sentinel'
        with self.assertRaises(broker.LaunchError)as error:broker.validate_request(value)
        self.assertEqual(str(error.exception),'api_launch_failed:invalid_input')
    def test_byte_bounds_missing_context_and_fixed_constants(self):
        for change in ('multibyte','aggregate','missing','path','nul','identity'):
            value=request();env=value['api_environment']
            if change=='multibyte':env['UVM_API_PRINCIPALS']='é'*2049
            elif change=='aggregate':
                for key in env:
                    if key not in broker.FIXED_ENV:env[key]='x'*1000
            elif change=='missing':env.pop('UVM_DB_URL')
            elif change=='path':env['PATH']='/private/sentinel'
            elif change=='nul':env['UVM_DB_URL']='bad\0value'
            else:value['main_port']=True
            with self.subTest(change=change),self.assertRaises(broker.LaunchError):broker.validate_request(value)
    def test_duplicate_trailing_truncated_and_encoded_overflow(self):
        for raw in (b'{"schema_version":1,"schema_version":1}',b'{}{}',b'{',b' '*(524288+1)):
            with tempfile.TemporaryFile()as stream:
                stream.write(raw);stream.seek(0)
                with self.assertRaises(broker.LaunchError)as error:broker.read_request(stream)
                self.assertNotIn('private-sentinel',str(error.exception))
    def test_valid_encoded_input_stays_private(self):
        value=request()
        with tempfile.TemporaryFile()as stream:
            stream.write(json.dumps(value).encode());stream.seek(0)
            self.assertEqual(broker.read_request(stream),value)
    def test_open_pipe_without_eof_has_actual_five_second_deadline(self):
        read,write=os.pipe();start=time.monotonic()
        try:
            with os.fdopen(read,'rb')as stream,self.assertRaises(broker.LaunchError):broker.read_request(stream)
        finally:os.close(write)
        elapsed=time.monotonic()-start
        self.assertGreaterEqual(elapsed,4.8);self.assertLess(elapsed,10)
    def test_fixed_error_frame_never_accepts_success_or_partial_message(self):
        for raw in (b'',b'VAPIERR1',b'VAPIERR1'+struct.pack('!II',4,1)+b'x',
                b'VAPIERR1'+struct.pack('!II',0,1),b'VAPIERR1'+struct.pack('!II',4,0)):
            with self.subTest(length=len(raw)),self.assertRaises(broker.LaunchError)as error:broker._error_frame(raw)
            self.assertEqual(error.exception.code,'exec_failed')
        with self.assertRaises(broker.LaunchError)as error:broker._error_frame(b'VAPIERR1'+struct.pack('!II',4,38))
        self.assertEqual(error.exception.code,'unsupported_kernel')
