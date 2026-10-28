"""Celery beat scheduler that publishes progress only after a completed tick."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time

from celery.beat import PersistentScheduler


class G7ProgressScheduler(PersistentScheduler):
    """Persistent CE scheduler with a monotonic, loop-completion heartbeat."""

    # A bounded scheduler nap makes the observer deadline meaningful even when
    # the CE schedule has no task due for its upstream five-minute default.
    max_interval = 5

    def tick(self, *args, **kwargs):
        delay = super().tick(*args, **kwargs)
        stall_path = os.environ.get("UVM_G7_SCHEDULER_STALL_FILE")
        if os.environ.get("UVM_G7_DISPOSABLE_MODE") == "1" and stall_path:
            marker = Path(stall_path)
            while marker.exists():
                # Deliberately model a live scheduler loop stuck after work but
                # before its completion heartbeat. CPU activity is not progress.
                pass
        self._write_progress()
        return delay

    @staticmethod
    def _write_progress() -> None:
        target = Path(os.environ.get("UVM_G7_SCHEDULER_PROGRESS_FILE",
                                    "/run/uvm-g7/scheduler/progress.json"))
        record = {
            "schema_version": 1,
            "loop_sequence": int(time.monotonic_ns()),
            "monotonic_ns": time.monotonic_ns(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        fd, temporary = tempfile.mkstemp(prefix=".progress-", dir=target.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(record, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
            directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            if os.environ.get("UVM_G7_DISPOSABLE_MODE") == "1":
                # The observer's separate host process reads only this
                # non-secret completion sequence and timestamps.
                os.chmod(target, 0o644)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
