"""An explicitly configured disposable clock must never silently use wall time."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sqlalchemy as sa
from uvm.api.app import create_app


class DisposableClockTest(unittest.TestCase):
    def test_exact_trusted_instant_and_malformed_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            clock=Path(root)/'clock'
            engine=sa.create_engine('sqlite://')
            with patch.dict('os.environ',{'UVM_AUTH_MODE':'bearer',
                    'UVM_G7_DISPOSABLE_MODE':'1','UVM_G7_TEST_CLOCK_FILE':str(clock)}):
                app=create_app(engine,principals={},cursor_secret='synthetic-clock-test-secret')
                clock.write_text('2026-10-30T12:00:01Z\n')
                self.assertEqual(app.state.utc_now(),datetime(2026,10,30,12,0,1,tzinfo=timezone.utc))
                for bad in ('2026-10-30T12:00:01Z\\n','garbage','2026-10-30T12:00:01','2026-10-30T13:00:01+01:00'):
                    clock.write_text(bad)
                    with self.subTest(clock=bad),self.assertRaises(RuntimeError):app.state.utc_now()
                clock.unlink()
                with self.assertRaises(RuntimeError):app.state.utc_now()
            engine.dispose()
