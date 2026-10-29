import subprocess
import unittest
from unittest.mock import patch

from tools.g7_listener_probe import classify_listener_result, probe_listener


class ListenerProbeTests(unittest.TestCase):
    def test_only_exact_closed_and_open_results_are_admitted(self):
        self.assertEqual(classify_listener_result(0,
            '{"listener":"closed","connect_errno":111}'),
            {"listener": "closed", "connect_errno": 111})
        self.assertEqual(classify_listener_result(0,
            '{"listener":"open","connect_errno":0}'),
            {"listener": "open", "connect_errno": 0})

    def test_process_and_socket_errors_fail_closed_through_probe_path(self):
        for code in (125, 137, 3):
            with self.subTest(code=code), patch("tools.g7_listener_probe.subprocess.run",
                    return_value=subprocess.CompletedProcess([], code, "", "probe error")):
                with self.assertRaisesRegex(RuntimeError, "process failed"):
                    probe_listener("container", 8000)
        with patch("tools.g7_listener_probe.subprocess.run", side_effect=FileNotFoundError("docker")):
            with self.assertRaisesRegex(RuntimeError, "could not execute"):
                probe_listener("container", 8000)
        for stdout in ("", '{"listener":"closed","connect_errno":113}',
                       '{"listener":"closed","connect_errno":111,"extra":true}',
                       '{"listener":"open","connect_errno":111}'):
            with self.subTest(stdout=stdout), patch("tools.g7_listener_probe.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, stdout, "")):
                with self.assertRaises(RuntimeError):
                    probe_listener("container", 8000)


if __name__ == "__main__":
    unittest.main()
