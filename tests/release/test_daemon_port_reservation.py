"""Strict daemon-reservation classifier and embedded observer syntax checks."""
import ast
from pathlib import Path
import subprocess
import unittest
from tools.compose_release_qualification import exact_daemon_reservation_error


class DaemonReservationTests(unittest.TestCase):
    def test_generic_ports_unavailable_500_never_becomes_reservation_cause(self):
        for text in ('Error response from daemon: Bind for 127.0.0.1:46180 failed: port is already allocated',
                'listen tcp 127.0.0.1:46180: bind: address already in use'):
            self.assertTrue(exact_daemon_reservation_error(text))
        for text in ('Error response from daemon: ports are not available: exposing port TCP 127.0.0.1:46180 -> 127.0.0.1:0: /forwards/expose returned unexpected status: 500',
                'port is already allocated\n127.0.0.1:46180','127.0.0.1:46181 address already in use','timeout'):
            self.assertFalse(exact_daemon_reservation_error(text))

    def test_exact_embedded_compose_observer_is_valid_POSIX_shell(self):
        source=Path(__file__).resolve().parents[2]/'tools/compose_release_qualification.py'
        function=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='qualify_daemon_reserved_port')
        bodies=[n.value for n in ast.walk(function)if isinstance(n,ast.Constant)and isinstance(n.value,str)and 'producer.argv-lines'in n.value]
        self.assertEqual(len(bodies),1)
        result=subprocess.run(['sh','-n'],input=bodies[0],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
