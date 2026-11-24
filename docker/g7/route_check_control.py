#!/usr/local/bin/python3.14
"""Fixed protected control entry; no API-owned Python import or fallback."""
import os
from pathlib import Path
import stat
import sys

try:
    for target in (Path('/usr/local/lib/volt-private'), Path('/usr/local/lib/volt-private/volt_route_check_control.py')):
        for path in (target, *target.parents):
            value=path.lstat()
            if value.st_uid!=0 or value.st_mode&0o022 or path.is_symlink():raise RuntimeError
    if not(sys.flags.isolated and sys.flags.no_site)or os.geteuid()!=0:raise RuntimeError
    sys.path.insert(0,'/usr/local/lib/volt-private')
    from volt_route_check_control import _run
    raise SystemExit(_run())
except Exception:
    # Pre-import custody/bootstrap failures have no trusted semantic code.
    print('route_check_failed:cleanup_failed',file=sys.stderr)
    raise SystemExit(1)from None
