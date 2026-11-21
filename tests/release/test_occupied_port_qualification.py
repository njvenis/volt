"""Closed actual daemon-error classifier and fixed binder program syntax only."""
import unittest
from tools.compose_release_qualification import occupied_port_binder_program, occupied_port_daemon_error


class OccupiedPortQualificationTests(unittest.TestCase):
    def test_fixed_registered_binder_program_compiles_without_dynamic_indentation(self):
        compile(occupied_port_binder_program(),'<fixed-owned-binder>','exec')

    def test_only_exact_endpoint_and_daemon_bind_semantics_are_credited(self):
        for text in ('Error response from daemon: driver failed programming external connectivity: Bind for 127.0.0.1:46180 failed: port is already allocated',
                'Ports are not available: exposing TCP 127.0.0.1:46180: listen tcp 127.0.0.1:46180: bind: address already in use',
                'failed to bind host port for 127.0.0.1:46180: address already in use'):
            with self.subTest(text=text):self.assertTrue(occupied_port_daemon_error(text))
        for text in ('daemon failed','timeout at 127.0.0.1:46180','synthetic user diagnostic 127.0.0.1:46180 address already in use',
                'Ports are not available: 127.0.0.1:46181','Bind for 0.0.0.0:46180 failed: port is already allocated',
                'port is already allocated\n127.0.0.1:46180'):
            with self.subTest(text=text):self.assertFalse(occupied_port_daemon_error(text))
