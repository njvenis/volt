from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RecoveryTLSCompatibilityTests(unittest.TestCase):
    def test_generated_server_and_client_verify_under_strict_x509_policy(self):
        spec = importlib.util.spec_from_file_location('compose_setup_tls', ROOT / 'deploy/compose/setup.py')
        setup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(setup)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            # Keep OpenSSL progress out of test output without changing the
            # actual certificate generation or strict verification commands.
            original = setup.command
            setup.command = lambda *args: original(*args, capture=True)
            setup.make_tls(directory)
            for purpose, leaf, extra in (
                ('sslserver', 'recovery-server.crt', ['-verify_hostname', 'localhost']),
                ('sslclient', 'recovery-client.crt', []),
            ):
                with self.subTest(purpose=purpose):
                    result = subprocess.run(['openssl', 'verify', '-x509_strict', '-purpose', purpose,
                        *extra, '-CAfile', str(directory / 'recovery-ca.crt'), str(directory / leaf)],
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((directory / 'recovery-ca.key').exists())


if __name__ == '__main__':
    unittest.main()
