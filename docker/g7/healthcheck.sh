#!/bin/bash
set -eu
# A fixed diagnostic only: preserve the original status and never print inputs.
health_phase=identity-runtime
health_exit() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then printf 'VOLT_HEALTH_CHECK_V1 %s\n' "$health_phase" >&2 || :; fi
  exit "$status"
}
trap health_exit EXIT
health_phase=identity-runtime
source /usr/local/bin/uvm-g7-identity-runtime
health_phase=ready-marker
test -f /run/uvm-g7/ready
health_phase=critical-marker
test ! -e /run/uvm-g7/critical-failed
health_phase=quiesce-marker
test ! -e /run/uvm-g7/quiesce-failed
health_phase=runtime-mode
mode=$(cat /run/uvm-g7/runtime-mode)
case "$mode" in control|verification|runtime) ;; *) exit 1 ;; esac
if [ "$mode" = control ]; then
  health_phase=recovery-process
  kill -0 "$(cat /run/uvm-g7/pid-recovery-control)"
  health_phase=postgres
  pg_isready -q -h 127.0.0.1 -p 5432 -U postgres
  health_phase=valkey
  valkey-cli -h 127.0.0.1 -p 6379 ping | grep -qx PONG
  health_phase=recovery-port
  RECOVERY_CONTROL_PORT=${UVM_G7_RECOVERY_CONTROL_PORT:-8002} /opt/uvm/venv/bin/python -c \
    'import os,socket; s=socket.create_connection(("127.0.0.1",int(os.environ["RECOVERY_CONTROL_PORT"])),timeout=1); s.close()'
  exit 0
fi
if [ "$mode" = verification ]; then
  action=health-verification
else
  action=health-normal
fi
# Persisted canonical profile decides the purpose; no ambient boot exemption.
health_phase=broker-readiness
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/local/bin/python3.14 -I -S \
  /usr/local/libexec/volt-route-check-control.py "$action"
health_phase=api-process
kill -0 "$(cat /run/uvm-g7/pid-api)"
health_phase=web-process
kill -0 "$(cat /run/uvm-g7/pid-ce-web)"
if [ "$mode" = runtime ]; then
  health_phase=worker-process
  kill -0 "$(cat /run/uvm-g7/pid-ce-worker)"
  health_phase=beat-process
  kill -0 "$(cat /run/uvm-g7/pid-ce-beat)"
fi
if [ "$mode" = runtime ] && [ "${UVM_EXCEPTION_WARNING_WORKER:-0}" = 1 ]; then
  health_phase=warning-process
  kill -0 "$(cat /run/uvm-g7/pid-exception-warning-worker)"
  health_phase=warning-health
  cd /opt/uvm/app
  PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.assessment.exception_warning_healthcheck
fi
health_phase=postgres
pg_isready -q -h 127.0.0.1 -p 5432 -U postgres
health_phase=valkey
valkey-cli -h 127.0.0.1 -p 6379 ping | grep -qx PONG
health_phase=api-http
curl --fail --silent --show-error http://127.0.0.1:8000/openapi.json >/dev/null
if [ "$mode" = runtime ] && [ "${UVM_AUTH_MODE:-bearer}" = oidc ]; then
  if [ "${UVM_OIDC_DEPLOYMENT_MODE:-demo}" = demo ]; then
    health_phase=oidc-provider
    curl --fail --silent --show-error "http://127.0.0.1:${UVM_OIDC_PROVIDER_PORT:-9000}/healthz" >/dev/null
  fi
  health_phase=oidc-proxy
  curl --fail --silent --show-error http://127.0.0.1:8001/healthz >/dev/null
fi
if [ "$mode" = runtime ] && [ "${UVM_AUTH_MODE:-bearer}" = oidc ] &&
   [ "${UVM_OIDC_DEPLOYMENT_MODE:-demo}" = external ]; then
  health_phase=oidc-publisher
  uvm_g7_okta_publisher_healthy /run/uvm-g7-secrets/okta-publisher.json \
    /run/uvm-g7/pid-okta-identity-publisher /opt/uvm/venv/bin/python || exit 1
fi
if [ "$mode" = verification ]; then
  health_phase=verification-web
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8081/api/v2/findings/)
  case "$status" in 200|301|302|401|403) ;; *) exit 1 ;; esac
else
  health_phase=web-http
  curl --fail --silent --show-error http://127.0.0.1:8081/login >/dev/null
fi
