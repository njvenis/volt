#!/bin/bash
set -Eeuo pipefail
# Runs under tini before any database, listener or writer on every restart.
/opt/uvm/venv/bin/python /tmp/g7_runtime_egress_fence.py >/run/g7-runtime-egress-fence.json
cat /run/g7-runtime-egress-fence.json
exec /usr/bin/tini -- /usr/local/bin/uvm-g7-entrypoint
