#!/bin/sh
set -eu
test -f /run/uvm-g7/ready
test ! -e /run/uvm-g7/critical-failed
if [ "${UVM_G7_RECOVERY_STAGE:-}" = control-only ]; then
  kill -0 "$(cat /run/uvm-g7/pid-recovery-control)"
  pg_isready -q -h 127.0.0.1 -p 5432 -U postgres
  valkey-cli -h 127.0.0.1 -p 6379 ping | grep -qx PONG
  RECOVERY_CONTROL_PORT=${UVM_G7_RECOVERY_CONTROL_PORT:-8002} /opt/uvm/venv/bin/python -c \
    'import os,socket; s=socket.create_connection(("127.0.0.1",int(os.environ["RECOVERY_CONTROL_PORT"])),timeout=1); s.close()'
  exit 0
fi
kill -0 "$(cat /run/uvm-g7/pid-api)"
kill -0 "$(cat /run/uvm-g7/pid-ce-web)"
if [ "${UVM_G7_VERIFICATION_ONLY:-0}" != 1 ]; then
  kill -0 "$(cat /run/uvm-g7/pid-ce-worker)"
  kill -0 "$(cat /run/uvm-g7/pid-ce-beat)"
fi
if [ "${UVM_EXCEPTION_WARNING_WORKER:-0}" = 1 ]; then
  kill -0 "$(cat /run/uvm-g7/pid-exception-warning-worker)"
  cd /opt/uvm/app
  PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.assessment.exception_warning_healthcheck
fi
pg_isready -q -h 127.0.0.1 -p 5432 -U postgres
valkey-cli -h 127.0.0.1 -p 6379 ping | grep -qx PONG
curl --fail --silent --show-error http://127.0.0.1:8000/openapi.json >/dev/null
if [ "${UVM_AUTH_MODE:-bearer}" = oidc ]; then
  curl --fail --silent --show-error "http://127.0.0.1:${UVM_OIDC_PROVIDER_PORT:-9000}/healthz" >/dev/null
fi
if [ "${UVM_G7_VERIFICATION_ONLY:-0}" = 1 ]; then
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8081/api/v2/findings/)
  case "$status" in 200|301|302|401|403) ;; *) exit 1 ;; esac
else
  curl --fail --silent --show-error http://127.0.0.1:8081/login >/dev/null
fi
