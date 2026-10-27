#!/bin/sh
set -eu
test -f /run/uvm-g7/ready
test ! -e /run/uvm-g7/critical-failed
kill -0 "$(cat /run/uvm-g7/pid-api)"
kill -0 "$(cat /run/uvm-g7/pid-ce-web)"
kill -0 "$(cat /run/uvm-g7/pid-ce-worker)"
kill -0 "$(cat /run/uvm-g7/pid-ce-beat)"
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
curl --fail --silent --show-error http://127.0.0.1:8081/login >/dev/null
