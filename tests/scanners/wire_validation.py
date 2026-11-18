"""Independent Draft2020-12 validation of serialized OpenAPI examples.

The auxiliary interpreter needs jsonschema; it imports no product/runtime code.
UVM_SCHEMA_TEST_PYTHON selects a test tool only, never installation behavior.
"""
import json
import os
import subprocess

_VALIDATOR = '''import json,sys
from jsonschema import Draft202012Validator, FormatChecker
value=json.load(sys.stdin)
Draft202012Validator.check_schema(value['schema'])
errors=list(Draft202012Validator(value['schema'],format_checker=FormatChecker()).iter_errors(value['value']))
print(json.dumps([{'path':list(e.absolute_path),'validator':e.validator} for e in errors]))
sys.exit(bool(errors))
'''


def schema_accepts(schema, value):
    result = subprocess.run([os.environ.get('UVM_SCHEMA_TEST_PYTHON', '/usr/bin/python3'),
        '-c', _VALIDATOR], input=json.dumps({'schema': schema, 'value': value}),
        text=True, capture_output=True, timeout=10)
    if result.returncode not in (0, 1) or result.stderr:
        raise AssertionError('JSON schema validation tool failed: ' + result.stderr)
    return result.returncode == 0


def assert_response(test, app, path, response, method='post'):
    schema = app.openapi()['paths'][path][method]['responses'][str(response.status_code)][
        'content']['application/json']['schema']
    test.assertTrue(schema_accepts(schema, response.json()),
        'serialized response does not match concrete OpenAPI schema')
