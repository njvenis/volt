"""Hold one lifecycle lock without granting the runtime a Docker socket."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import sys
import time


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    path = Path(sys.argv[1])
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.fchmod(fd, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("lock-held", flush=True)
        return 75
    print("locked=1", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main())
