"""Pure byte readers; crypto, original waits and current context are NOT proven."""
import io
import os
import time
import unittest
from unittest.mock import patch

from uvm.auth import route_check_records as shared
from uvm.installer import route_check, stopped_capture as capture


class Measured(io.BytesIO):
    def read(self, size=-1):
        if not 0 < size <= 65536:
            raise AssertionError('unbounded private stream read')
        return super().read(size)


class ShortReads(Measured):
    def read(self, size=-1):
        if not 0 < size <= 65536:
            raise AssertionError('unbounded private stream read')
        return super().read(min(size, 1))


class StoppedCaptureTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch.object(route_check, '_shared', return_value=shared)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.record = {'schema_version': 1, 'profile': shared.COMPLETION_PROFILE,
            'entrypoint': {'pid': 1, 'proc_start_ticks': 10},
            'supervisor': {'pid': 2, 'proc_start_ticks': 20},
            'api': {'pid': 3, 'proc_start_ticks': 30}, 'operation_id': 'a' * 64,
            'launch_sha256': 'b' * 64, 'status_sha256': 'c' * 64,
            'broker_wait_exit_code': 0}
        self.raw = shared.canonical(self.record)
        shared.validate_record('completion', self.raw)

    def test_exact_wait_requires_both_bytes_and_eof(self):
        self.assertEqual(capture.docker_wait_output(ShortReads(b'0\n')), b'0\n')
        for raw in (b'', b'0', b'0\n\n', b'0\nsecret', b'1\n', b'00\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                capture.docker_wait_output(Measured(raw))

    def test_bounded_unrelated_history_and_split_marker_keep_only_exact_candidate(self):
        history = ((b'x' * 2048 + b'\n') * 511)
        self.assertEqual(capture.completion_line(Measured(history + self.raw + b'\n')), self.raw)
        with self.assertRaises(ValueError):
            capture.completion_line(Measured(b'x' * (capture.MAX_LOG_BYTES + 1)))
        self.assertEqual(capture.completion_line(ShortReads(self.raw + b'\n')), self.raw)

    def test_marker_substring_noncanonical_duplicate_and_truncated_do_not_pass(self):
        noncanonical = shared.canonical(self.record).replace(b'":', b'": ', 1)
        duplicate_key = self.raw[:-1] + b',"schema_version":1}'
        for name, raw in (
                ('prefix', b'prefix' + self.raw + b'\n'), ('suffix', self.raw + b' suffix\n'),
                ('noncanonical', noncanonical + b'\n'), ('duplicate-key', duplicate_key + b'\n'),
                ('duplicate-line', self.raw + b'\n' + self.raw + b'\n'), ('truncated', self.raw),
                ('valid-then-unmarked-tail', self.raw + b'\nunterminated'),
                ('pre-marker-truncated-tail', b'{\"profi'),
                ('valid-then-premarker-tail', self.raw + b'\n{\"profi'),
                ('oversized', b'x' * 4096 + self.raw + b'\n'),
                ('marked-tail', b'x' * 65530 + self.raw + b'\n')):
            with self.subTest(name=name), self.assertRaises(ValueError):
                capture.completion_line(Measured(raw))

    def test_escaped_profile_and_duplicate_escaped_record_are_not_ignored(self):
        escaped = self.raw.replace(b'volt_main_api_completion_v1', b'\\u0076olt_main_api_completion_v1')
        escaped_key = self.raw.replace(b'"profile"', b'"pro\\u0066ile"')
        duplicate_profile = self.raw[:-1] + b',"pro\\u0066ile":"other"}'
        for name, raw in (('escaped-value', escaped), ('escaped-key', escaped_key),
                ('escaped-second', self.raw + b'\n' + escaped),
                ('escaped-key-second', self.raw + b'\n' + escaped_key),
                ('duplicate-profile', duplicate_profile)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                capture.completion_line(Measured(raw + b'\n'))

    def test_real_pipe_without_eof_times_out_and_preserves_descriptor_flags(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, self.raw + b'\n')
            before = os.get_blocking(reader)
            # Actual select/pipe EOF wait; accelerated test deadline only.
            with os.fdopen(os.dup(reader), 'rb', buffering=0) as stream:
                start = time.monotonic()
                with patch.object(capture, 'MAX_LOG_SECONDS', 0.05), self.assertRaises(TimeoutError):
                    capture.completion_line(stream)
                self.assertLess(time.monotonic() - start, 0.5)
            self.assertEqual(os.get_blocking(reader), before)
        finally:
            os.close(reader); os.close(writer)
        self.assertEqual(capture.MAX_LOG_BYTES, 1024 * 1024)
        self.assertEqual(capture.MAX_LOG_SECONDS, 10)

    def test_bom_unsupported_encoding_and_escaped_second_record_deny_before_classification(self):
        escaped = self.raw.replace(b'volt_main_api_completion_v1', b'\\u0076olt_main_api_completion_v1')
        for name, raw in (
                ('bom-first', b'\xef\xbb\xbf' + self.raw + b'\n'),
                ('bom-escaped-second', self.raw + b'\n\xef\xbb\xbf' + escaped + b'\n'),
                ('bom-escaped-key-second', self.raw + b'\n\xef\xbb\xbf' + self.raw.replace(b'"profile"', b'"pro\\u0066ile"') + b'\n'),
                ('utf16-second', self.raw + b'\n' + (escaped.decode() + '\n').encode('utf-16')),
                ('nul-second', self.raw + b'\n' + escaped.replace(b'{', b'{\x00', 1) + b'\n'),
                ('invalid-utf8', self.raw + b'\n\xff\n'),
                ('prefixed-escaped-second', self.raw + b'\nprefix' + escaped + b'\n')):
            with self.subTest(name=name), self.assertRaises(ValueError):
                capture.completion_line(Measured(raw))

    def test_real_pipe_eof_requires_complete_lines_even_after_valid_candidate(self):
        for tail in (b'', b'unterminated', b'{"profi'):
            with self.subTest(tail=tail):
                reader, writer = os.pipe()
                try:
                    os.write(writer, self.raw + b'\n' + tail); os.close(writer); writer = None
                    with os.fdopen(reader, 'rb', buffering=0) as stream:
                        reader = None
                        if tail:
                            with self.assertRaises(ValueError):capture.completion_line(stream)
                        else:self.assertEqual(capture.completion_line(stream), self.raw)
                finally:
                    if reader is not None:os.close(reader)
                    if writer is not None:os.close(writer)

    def test_missing_unknown_and_line_overflow_deny(self):
        for raw in (b'', b'old marker only\n', b'x\n' * 1024 + self.raw + b'\n'):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                capture.completion_line(Measured(raw))

    def test_valid_candidate_cannot_mask_producer_or_reader_failure_before_eof(self):
        class Failed(Measured):
            def read(self, size=-1):
                value = super().read(size)
                if not value:
                    raise OSError('synthetic producer transport failure')
                return value
        with self.assertRaises(OSError):
            capture.completion_line(Failed(self.raw + b'\n'))

    def test_tar_limit_and_original_byte_delegation(self):
        with patch.object(route_check, 'stopped_tar_records', return_value={}) as parser:
            raw = b'a' * capture.MAX_TAR
            self.assertEqual(capture.routing_tar(Measured(raw)), raw)
            parser.assert_called_once_with(raw)
            with self.assertRaises(ValueError):
                capture.routing_tar(Measured(raw + b'x'))
            self.assertEqual(parser.call_count, 1)
        with self.assertRaises(ValueError):
            capture.routing_tar(Measured(b'not a tar'))
