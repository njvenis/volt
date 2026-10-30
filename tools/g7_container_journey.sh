#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

MODE=${1-}
if [[ ( $MODE != --observer-settings-only && $MODE != --backup-recovery-only && $MODE != --upgrade-rollback-only && $MODE != --data-preservation-audit-only && $MODE != --exception-warning-only && $MODE != --exception-sla-only && $MODE != --identity-access-ownership-only ) || $# != 1 ]]; then
  echo 'usage: G7_EVIDENCE_DIR=/absolute/path bash tools/g7_container_journey.sh (--observer-settings-only|--backup-recovery-only|--upgrade-rollback-only|--data-preservation-audit-only|--exception-warning-only|--exception-sla-only|--identity-access-ownership-only)' >&2
  exit 64
fi
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

export UV_CACHE_DIR=${UV_CACHE_DIR:-/tmp/volt-g7-uv-cache}
mkdir -p "$UV_CACHE_DIR"
EVIDENCE=${G7_EVIDENCE_DIR:?G7_EVIDENCE_DIR must name an evidence directory}
[[ $EVIDENCE == /* && $EVIDENCE != "$ROOT"/* ]] || { echo 'evidence must be outside the source tree' >&2; exit 64; }
mkdir -p "$EVIDENCE"
chmod 700 "$EVIDENCE"
RUN_STARTED_AT=$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')
RUN_STARTED_MONOTONIC_NS=$(python3 -c 'import time;print(time.monotonic_ns())')
python3 - "$EVIDENCE/journey-timing.json" "$RUN_STARTED_AT" "$RUN_STARTED_MONOTONIC_NS" <<'JSTART'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({'started_at_utc':sys.argv[2],
 'started_monotonic_ns':int(sys.argv[3])},sort_keys=True,separators=(',',':'))+'\n')
JSTART
RUN_ROOT=$(mktemp -d /tmp/volt-g7-observer-run.XXXXXX)
RUN_ID=${RUN_ROOT##*.}
DATA_PRESERVATION_MODE=0
if [[ $MODE == --data-preservation-audit-only ]]; then DATA_PRESERVATION_MODE=1; fi
UPGRADE_ROLLBACK_MODE=0
EXCEPTION_WARNING_MODE=0
if [[ $MODE == --exception-warning-only ]]; then EXCEPTION_WARNING_MODE=1; fi
EXCEPTION_SLA_MODE=0
if [[ $MODE == --exception-sla-only ]]; then EXCEPTION_SLA_MODE=1; fi
IDENTITY_MODE=0
if [[ $MODE == --identity-access-ownership-only ]]; then IDENTITY_MODE=1; fi
if [[ $MODE == --upgrade-rollback-only ]]; then
  UPGRADE_ROLLBACK_MODE=1
  IMAGE="volt-g7-upgrade-a-dev:$RUN_ID"
  CANDIDATE_IMAGE="volt-g7-upgrade-b-dev:$RUN_ID"
  RESTORE_IMAGE=$CANDIDATE_IMAGE
elif [[ $MODE == --backup-recovery-only ]]; then
  CONTAINER=volt-g7-observer-journey
  ANCHOR_CONTAINER=volt-g7-observer-anchor
  IMAGE="volt-g7-backup-recovery-dev:$(git -C "$ROOT" rev-parse --short HEAD)"
  CANDIDATE_IMAGE=$IMAGE
  RESTORE_IMAGE=$IMAGE
elif (( IDENTITY_MODE )); then
  CONTAINER="volt-g7-identity-app-$RUN_ID"
  ANCHOR_CONTAINER="volt-g7-identity-anchor-$RUN_ID"
  IMAGE="volt-g7-identity-dev:$RUN_ID"
  CANDIDATE_IMAGE=$IMAGE
  RESTORE_IMAGE=$IMAGE
elif (( DATA_PRESERVATION_MODE )); then
  CONTAINER="volt-g7-preservation-app-$RUN_ID"
  ANCHOR_CONTAINER="volt-g7-preservation-anchor-$RUN_ID"
  IMAGE="volt-g7-preservation-dev:$RUN_ID"
  CANDIDATE_IMAGE=$IMAGE
  RESTORE_IMAGE=$IMAGE
else
  if (( EXCEPTION_WARNING_MODE || EXCEPTION_SLA_MODE )); then
    CONTAINER="volt-g7-exception-app-$RUN_ID"
    ANCHOR_CONTAINER="volt-g7-exception-anchor-$RUN_ID"
    IMAGE="volt-g7-exception-dev:$RUN_ID"
  else
    CONTAINER=volt-g7-observer-journey
    ANCHOR_CONTAINER=volt-g7-observer-anchor
    IMAGE="volt-g7-observer-dev:$(git -C "$ROOT" rev-parse --short HEAD)"
  fi
  CANDIDATE_IMAGE=$IMAGE
  RESTORE_IMAGE=$IMAGE
fi
IS_BACKUP_MODE=0
if [[ $MODE == --backup-recovery-only || $MODE == --upgrade-rollback-only ]]; then IS_BACKUP_MODE=1; fi
SCHEMA_MODE_ARGS=()
if (( UPGRADE_ROLLBACK_MODE )); then SCHEMA_MODE_ARGS=(--env UVM_G7_SCHEMA_MODE=upgrade-verification); fi
if (( ! DATA_PRESERVATION_MODE && ! EXCEPTION_WARNING_MODE && ! EXCEPTION_SLA_MODE && ! IDENTITY_MODE )); then
  CONTAINER=volt-g7-observer-journey
  ANCHOR_CONTAINER=volt-g7-observer-anchor
fi
OIDC_HOST=127.0.0.1
ANCHOR_PORT=$(python3 - <<'PYPORT'
import socket
for port in (15433, 25433, 35433, 45433, 55433, 65433):
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
        print(port)
        sock.close()
        break
    except OSError:
        sock.close()
else:
    raise SystemExit("no preapproved anchor port available")
PYPORT
)
OIDC_PORT=$(python3 - <<'PYOIDCPORT'
import socket
for port in (18000,19000,29000,39000,49000,59000):
    sock=socket.socket()
    try:
        sock.bind(('127.0.0.1',port)); print(port); sock.close(); break
    except OSError: sock.close()
else: raise SystemExit('no preapproved OIDC loopback port available')
PYOIDCPORT
)
API_PORT=8000
RECOVERY_PORT=8002
OIDC_PROXY_PORT=$(python3 - <<'PYOIDCPROXYPORT'
import socket
for port in (9000,19090,29090,39090,49090,59090):
    sock=socket.socket()
    try: sock.bind(('127.0.0.1',port)); print(port); sock.close(); break
    except OSError: sock.close()
else: raise SystemExit('no preapproved OIDC proxy loopback port available')
PYOIDCPROXYPORT
)
if (( DATA_PRESERVATION_MODE )); then
  choose_port() {
    python3 - "$@" <<'PICKPORT'
import socket,sys
for port in map(int,sys.argv[1:]):
    sock=socket.socket()
    try: sock.bind(('127.0.0.1',port)); print(port); sock.close(); break
    except OSError: sock.close()
else: raise SystemExit('no unique disposable journey port available')
PICKPORT
  }
  API_PORT=$(choose_port 18080 28080 38080 48080 58080)
  RECOVERY_PORT=$(choose_port 18082 28082 38082 48082 58082)
  OIDC_PROXY_PORT=$(choose_port 29090 39090 49090 59090)
elif (( EXCEPTION_WARNING_MODE || EXCEPTION_SLA_MODE )); then
  choose_port() {
    python3 - "$@" <<'PICKPORT'
import socket,sys
for port in map(int,sys.argv[1:]):
    sock=socket.socket()
    try: sock.bind(('127.0.0.1',port)); print(port); sock.close(); break
    except OSError: sock.close()
else: raise SystemExit('no unique disposable journey port available')
PICKPORT
  }
  OIDC_PROXY_PORT=$(choose_port 19090 29090 39090 49090 59090)
fi
STARTED_CONTAINER=0
STARTED_ANCHOR=0
CREATED_IMAGE=0
CREATED_CANDIDATE_IMAGE=0
EXIT_STATUS=0
DEADLINE_PID=''
ACTIVE_DEADLINE=''
trap 'exit 124' TERM
CONTAINER_ID=''
ANCHOR_ID=''
RESTORE_CONTAINER=volt-g7-backup-restored
RESTORE_CONTAINER_ID=''
RESTORE_STARTED=0
RECOVERY_NETWORK=''
FAULT_PROXY_PID=''
RESTORE_IP=''
RESTORE_VOLUMES_JSON=''
UPGRADE_VOLUMES_JSON=''
PRESERVE_UPGRADE_VOLUMES=0
RESTORE_IMAGE_DIGEST=''
SOURCE_PACKAGE_DIGEST=''
CANDIDATE_PACKAGE_DIGEST=''
PRESERVE_UPGRADE_VOLUMES=$UPGRADE_ROLLBACK_MODE
PRESERVATION_VOLUME_NAMES=()
PRESERVATION_MOUNTS=()
PRESERVATION_STORAGE_GENERATION=''
PRESERVATION_VOLUME_SET_DIGEST=''

# Each blocking host command gets only the operation's remaining durable
# budget. The watchdog also interrupts loops; cleanup runs outside the budget.
budget_command() {
  if [[ -n ${ACTIVE_DEADLINE:-} ]]; then
    python3 "$ROOT/tools/g7_backup_deadline.py" --journal "$ACTIVE_DEADLINE" --run "$@"
  else
    command "$@"
  fi
}
docker() { budget_command docker "$@"; }
uv() { budget_command uv "$@"; }
curl() { budget_command curl "$@"; }
node() { budget_command node "$@"; }
phase_mark() {
  python3 - "$EVIDENCE/phase-timestamps.json" "$1" <<'PHTS'
import json,sys,time
from datetime import datetime,timezone
from pathlib import Path
p=Path(sys.argv[1]); x=json.loads(p.read_text()) if p.exists() else {}
x[sys.argv[2]]={"utc":datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),"monotonic_ns":time.monotonic_ns()}
p.write_text(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n')
PHTS
}
start_operation_deadline() {
  local kind=$1
  python3 "$ROOT/tools/g7_backup_deadline.py" --request "$RUN_ROOT/host/state/backup/capture-request.json" \
    --kind "$kind" --journal "$EVIDENCE/$kind-deadline.json" --parent-pid "$$" &
  DEADLINE_PID=$!
  for _ in $(seq 1 100); do
    [[ -s "$EVIDENCE/$kind-deadline.json" ]] && { ACTIVE_DEADLINE="$EVIDENCE/$kind-deadline.json"; return 0; }
    kill -0 "$DEADLINE_PID" || return 1
    sleep 0.05
  done
  return 1
}
finish_operation_deadline() {
  python3 "$ROOT/tools/g7_backup_deadline.py" --journal "$EVIDENCE/$1-deadline.json" --complete
  kill "$DEADLINE_PID" 2>/dev/null || true
  wait "$DEADLINE_PID" 2>/dev/null || true
  DEADLINE_PID=''
  ACTIVE_DEADLINE=''
}
restart_recovery_checkpoint() {
  local phase=$1 admitted=0
  docker restart "$RESTORE_CONTAINER" >"$EVIDENCE/$phase-restart.stdout"
  for _ in $(seq 1 90); do
    if docker exec "$RESTORE_CONTAINER" test -f /run/uvm-g7/ready 2>/dev/null \
        && [[ $(docker exec "$RESTORE_CONTAINER" cat /run/uvm-g7/runtime-mode) == verification ]] \
        && curl --fail --silent --max-time 2 http://127.0.0.1:8000/openapi.json >/dev/null; then admitted=1; break; fi
    sleep 1
  done
  (( admitted )) || { echo "recovery restart did not resume $phase" >&2; return 2; }
  docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-worker
  docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-beat
  [[ $(docker exec "$RESTORE_CONTAINER" cat /run/uvm-g7/runtime-mode) == verification ]]
  printf 'verification_listener_resumed=1\nruntime_workers_absent=1\n' >"$EVIDENCE/$phase-restart-proof.txt"
}
cleanup() {
  local rc=$?
  ACTIVE_DEADLINE=''
  if [[ -n $DEADLINE_PID ]]; then kill "$DEADLINE_PID" 2>/dev/null || true; wait "$DEADLINE_PID" 2>/dev/null || true; fi
  local cleanup_rc=0 container_removed=0 anchor_removed=0 container_rm_exit=not_started anchor_rm_exit=not_started
  trap - EXIT
  set +e
  if [[ -n $FAULT_PROXY_PID ]]; then
    kill "$FAULT_PROXY_PID" 2>/dev/null
    wait "$FAULT_PROXY_PID" 2>/dev/null
    printf 'pid=%s\nprocess_removed=%s\n' "$FAULT_PROXY_PID" "$(( $? == 0 ))" \
      >"$EVIDENCE/evidence-fault-proxy-cleanup.txt"
    chmod 0600 "$EVIDENCE/evidence-fault-proxy-cleanup.txt"
  fi
  remove_owned_volume() {
    local volume=$1 tag=$2 rm_rc inspect_rc absent=0
    docker volume rm "$volume" >"$EVIDENCE/owned-volume-$tag-rm.stdout" 2>"$EVIDENCE/owned-volume-$tag-rm.stderr"
    rm_rc=$?
    docker volume inspect "$volume" >"$EVIDENCE/owned-volume-$tag-inspect.json" 2>"$EVIDENCE/owned-volume-$tag-inspect.stderr"
    inspect_rc=$?
    (( inspect_rc != 0 )) && absent=1
    python3 - "$EVIDENCE/owned-volume-$tag-cleanup.json" "$volume" "$rm_rc" "$inspect_rc" "$absent" <<'PVCLEAN'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({'volume_id':sys.argv[2],'rm_exit':int(sys.argv[3]),'post_rm_inspect_exit':int(sys.argv[4]),'absence_verified':sys.argv[5]=='1'},sort_keys=True,separators=(',',':'))+'\n')
PVCLEAN
    (( absent == 1 ))
  }
  for process_file in "$RUN_ROOT"/host/*.pid; do
    [[ -f $process_file ]] || continue
    host_pid=$(cat "$process_file")
    [[ $host_pid =~ ^[1-9][0-9]*$ ]] || continue
    kill "$host_pid" >/dev/null 2>&1 || true
  done
  for log_name in observer supervisor controller; do
    [[ -f "$RUN_ROOT/host/$log_name.log" ]] || continue
    sed -E 's/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\1[redacted]/Ig' \
      "$RUN_ROOT/host/$log_name.log" >"$EVIDENCE/host-$log_name-redacted.log"
  done
  if [[ -f "$RUN_ROOT/host/oidc-proxy.log" ]]; then
    cp "$RUN_ROOT/host/oidc-proxy.log" "$EVIDENCE/oidc-proxy.log" || cleanup_rc=1
    chmod 600 "$EVIDENCE/oidc-proxy.log" || cleanup_rc=1
  fi
  if (( STARTED_ANCHOR )); then
    docker inspect "$ANCHOR_CONTAINER" >"$EVIDENCE/anchor-container-inspect.json" 2>/dev/null || true
    docker logs "$ANCHOR_CONTAINER" 2>&1 | sed -E \
      "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
      >"$EVIDENCE/anchor-container-redacted.log" || true
  fi
  if (( STARTED_CONTAINER )); then
    docker inspect "$CONTAINER" >"$EVIDENCE/app-container-inspect.json" 2>/dev/null || true
    docker logs "$CONTAINER" 2>&1 | sed -E \
      "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
      >"$EVIDENCE/app-container-redacted.log" || true
    if docker cp "$CONTAINER:/run/uvm-g7/api.log" "$RUN_ROOT/api.log" >/dev/null 2>&1; then
      sed -E "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
        "$RUN_ROOT/api.log" >"$EVIDENCE/api-service-redacted.log"
    fi
  fi
  if (( STARTED_CONTAINER )) && [[ -n $CONTAINER_ID ]]; then
    docker exec -u 0 "$CONTAINER_ID" chmod -R a+rwX /run/uvm-g7-scheduler >/dev/null 2>&1 || true
    docker rm -fv "$CONTAINER_ID" >/dev/null 2>&1
    container_rm_exit=$?
    if (( container_rm_exit == 0 )); then
      container_removed=1
    elif docker inspect "$CONTAINER_ID" >/dev/null 2>&1; then
      container_removed=0
      cleanup_rc=1
    elif docker info >/dev/null 2>&1; then
      container_removed=1
    else
      container_removed=0
      cleanup_rc=1
    fi
  elif (( STARTED_CONTAINER )); then
    container_rm_exit=missing_owned_id
    cleanup_rc=1
  fi
  restore_container_removed=not_started restore_container_rm_exit=not_started
  if (( RESTORE_STARTED )) && [[ -n $RESTORE_CONTAINER_ID ]]; then
    docker inspect "$RESTORE_CONTAINER_ID" >"$EVIDENCE/restore-container-inspect.json" 2>/dev/null || true
    docker logs "$RESTORE_CONTAINER_ID" 2>&1 | sed -E \
      "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
      >"$EVIDENCE/restore-container-redacted.log" || true
    docker exec -u 0 "$RESTORE_CONTAINER_ID" chmod -R a+rwX /run/uvm-g7-scheduler >/dev/null 2>&1 || true
    docker rm -fv "$RESTORE_CONTAINER_ID" >/dev/null 2>&1
    restore_container_rm_exit=$?
    if (( restore_container_rm_exit == 0 )); then restore_container_removed=1
    elif docker inspect "$RESTORE_CONTAINER_ID" >/dev/null 2>&1; then restore_container_removed=0; cleanup_rc=1
    elif docker info >/dev/null 2>&1; then restore_container_removed=1
    else restore_container_removed=0; cleanup_rc=1; fi
  elif (( RESTORE_STARTED )); then
    restore_container_rm_exit=missing_owned_id; cleanup_rc=1
  fi
  restore_volumes_removed=not_created
  if [[ $PRESERVE_UPGRADE_VOLUMES == 0 && -n $UPGRADE_VOLUMES_JSON && -f $UPGRADE_VOLUMES_JSON ]]; then
    volume_index=0
    while IFS= read -r volume; do
      [[ -n $volume ]] || continue
      volume_index=$((volume_index+1)); remove_owned_volume "$volume" "forward-$volume_index" || cleanup_rc=1
    done < <(python3 - "$UPGRADE_VOLUMES_JSON" <<'PYUPGRADEVOLS'
import json,sys
print("\n".join(json.load(open(sys.argv[1],encoding="utf-8")).values()))
PYUPGRADEVOLS
)
  fi
  keep_restore_volumes=0
  if [[ $PRESERVE_UPGRADE_VOLUMES == 1 && -n $RESTORE_VOLUMES_JSON && -f $RESTORE_VOLUMES_JSON &&
      -n $UPGRADE_VOLUMES_JSON && -f $UPGRADE_VOLUMES_JSON ]]; then
    if python3 - "$RESTORE_VOLUMES_JSON" "$UPGRADE_VOLUMES_JSON" <<'PRESERVEIDS'
import json,sys
left=json.load(open(sys.argv[1],encoding='utf-8')); right=json.load(open(sys.argv[2],encoding='utf-8'))
raise SystemExit(0 if set(left.values()) == set(right.values()) else 1)
PRESERVEIDS
    then keep_restore_volumes=1; fi
  fi
  if [[ -n $RESTORE_VOLUMES_JSON && -f $RESTORE_VOLUMES_JSON && $keep_restore_volumes == 0 ]]; then
    restore_volumes_removed=1
    volume_index=0
    while IFS= read -r volume; do
      [[ -n $volume ]] || continue
      volume_index=$((volume_index+1)); remove_owned_volume "$volume" "restore-$volume_index" || restore_volumes_removed=0
    done < <(python3 - "$RESTORE_VOLUMES_JSON" <<'PYVOLS'
import json,sys
print("\n".join(json.load(open(sys.argv[1],encoding="utf-8")).values()))
PYVOLS
)
    (( restore_volumes_removed == 1 )) || cleanup_rc=1
  elif [[ $keep_restore_volumes == 1 || ( -n $UPGRADE_VOLUMES_JSON && -f $UPGRADE_VOLUMES_JSON && $PRESERVE_UPGRADE_VOLUMES == 1 ) ]]; then
    restore_volumes_removed=preserved_for_reconciliation
  fi
  if (( DATA_PRESERVATION_MODE )); then
    volume_index=0
    preservation_volumes_removed=1
    for volume in "${PRESERVATION_VOLUME_NAMES[@]}"; do
      [[ -n $volume ]] || continue
      volume_index=$((volume_index+1))
      remove_owned_volume "$volume" "preservation-$volume_index" || preservation_volumes_removed=0
    done
    (( preservation_volumes_removed == 1 )) || cleanup_rc=1
  else
    preservation_volumes_removed=not_created
  fi
  if [[ -n $RECOVERY_NETWORK ]]; then docker network rm "$RECOVERY_NETWORK" >/dev/null 2>&1 || true; fi
  if (( STARTED_ANCHOR )) && [[ -n $ANCHOR_ID ]]; then
    docker rm -fv "$ANCHOR_ID" >/dev/null 2>&1
    anchor_rm_exit=$?
    if (( anchor_rm_exit == 0 )); then
      anchor_removed=1
    elif docker inspect "$ANCHOR_ID" >/dev/null 2>&1; then
      anchor_removed=0
      cleanup_rc=1
    elif docker info >/dev/null 2>&1; then
      anchor_removed=1
    else
      anchor_removed=0
      cleanup_rc=1
    fi
  elif (( STARTED_ANCHOR )); then
    anchor_rm_exit=missing_owned_id
    cleanup_rc=1
  fi
  if [[ -f "$RUN_ROOT/host/state/backup/controller-journal.json" ]]; then
    cp "$RUN_ROOT/host/state/backup/controller-journal.json" "$EVIDENCE/controller-journal.json" || cleanup_rc=1
    cp "$RUN_ROOT/secrets/host-pub.pem" "$EVIDENCE/host-public-key.pem" || cleanup_rc=1
    cp "$RUN_ROOT/host/backup-policy.json" "$EVIDENCE/host-backup-policy.json" || cleanup_rc=1
  fi
  if [[ -s "$EVIDENCE/recovery-auth-state.json" ]]; then
    python3 - "$EVIDENCE/recovery-auth-state.json" "$EVIDENCE/recovery-auth-redactions.json" <<'PHSCRUB'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]); data=json.loads(p.read_text()); rows=[]
for cookie in data.get('cookies',[]):
 if cookie.get('name')=='uvm_session':
  raw=cookie.get('value','').encode(); rows.append({'name':cookie['name'],'sha256':'sha256:'+hashlib.sha256(raw).hexdigest()}); cookie['value']='[redacted]'
p.write_text(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n')
Path(sys.argv[2]).write_text(json.dumps({'redacted_cookies':rows},sort_keys=True,separators=(',',':'))+'\n')
PHSCRUB
    chmod 600 "$EVIDENCE/recovery-auth-state.json" "$EVIDENCE/recovery-auth-redactions.json"
  fi
  # A stopped replacement may have left a root-owned scheduler directory on
  # this run's sole writable bind. Repair only that known disposable mount.
  if [[ -d "$RUN_ROOT/scheduler" ]] && ! rm -rf "$RUN_ROOT/scheduler" 2>/dev/null; then
    docker run --rm --network none --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/owned-scheduler" \
      --entrypoint /bin/chmod "$IMAGE" -R a+rwX /owned-scheduler >/dev/null 2>&1 || cleanup_rc=1
  fi
  if (( DATA_PRESERVATION_MODE )) && [[ -d "$RUN_ROOT/copied-preservation" ]]; then
    docker run --rm --network none --label "uvm.g7.run-id=$RUN_ID" \
      --tmpfs /var/lib/postgresql/data --tmpfs /app/media --tmpfs /opt/uvm/state \
      --mount "type=bind,src=$RUN_ROOT/copied-preservation,dst=/owned" --entrypoint /bin/sh "$IMAGE" \
      -c "chown -R $(id -u):$(id -g) /owned && chmod -R u+rwX /owned" >/dev/null 2>&1 || cleanup_rc=1
  fi
  if (( DATA_PRESERVATION_MODE )); then
    cp "$RUN_ROOT/secrets/host-pub.pem" "$EVIDENCE/preservation-verifier-public-key.pem" || cleanup_rc=1
    cp -a "$RUN_ROOT/host/preservation-trust" "$EVIDENCE/preservation-trust" || cleanup_rc=1
  fi
  python3 "$ROOT/tools/g7_redact_retained_inspects.py" "$EVIDENCE" >"$EVIDENCE/credential-redaction.stdout" || cleanup_rc=1
  chmod -R u+rwX "$RUN_ROOT" 2>/dev/null || true
  rm -rf "$RUN_ROOT" || cleanup_rc=1
  [[ ! -e "$RUN_ROOT" ]] || cleanup_rc=1
  if (( CREATED_IMAGE )); then docker image rm "$IMAGE" >/dev/null 2>&1; fi
  if (( CREATED_CANDIDATE_IMAGE )); then docker image rm "$CANDIDATE_IMAGE" >/dev/null 2>&1; fi
  printf 'container_id=%s\ncontainer_remove_exit=%s\ncontainer_absence_verified=%s\nrestore_container_id=%s\nrestore_container_remove_exit=%s\nrestore_container_absence_verified=%s\nrestore_volumes_absence_verified=%s\npreservation_volumes_absence_verified=%s\nanchor_id=%s\nanchor_remove_exit=%s\nanchor_absence_verified=%s\nrunner_exit=%s\ncleanup_exit=%s\n' \
    "${CONTAINER_ID:-unknown}" "$container_rm_exit" "$container_removed" \
    "${RESTORE_CONTAINER_ID:-not_started}" "$restore_container_rm_exit" "$restore_container_removed" "$restore_volumes_removed" "$preservation_volumes_removed" \
    "${ANCHOR_ID:-unknown}" "$anchor_rm_exit" "$anchor_removed" "$rc" "$cleanup_rc" \
    >"$EVIDENCE/owned-resource-cleanup.txt"
  python3 - "$EVIDENCE/journey-timing.json" "$RUN_STARTED_AT" "$RUN_STARTED_MONOTONIC_NS" <<'JEND'
import json,sys,time
from datetime import datetime,timezone
from pathlib import Path
p=Path(sys.argv[1]); data=json.loads(p.read_text())
end_ns=time.monotonic_ns()
data.update({'ended_at_utc':datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),
 'ended_monotonic_ns':end_ns,'duration_monotonic_ns':end_ns-int(sys.argv[3])})
p.write_text(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n')
JEND
  if (( cleanup_rc != 0 && rc == 0 )); then rc=70; fi
  exit "$rc"
}
trap cleanup EXIT

printf 'G7_EVIDENCE_DIR=%s bash tools/g7_container_journey.sh %s\n' "$EVIDENCE" "$MODE" \
  >"$EVIDENCE/journey-command.txt"
git -C "$ROOT" rev-parse HEAD >"$EVIDENCE/source-revision.txt"
git -C "$ROOT" status --porcelain=v1 >"$EVIDENCE/source-status.txt"
tar -C "$ROOT" --exclude=.git --exclude=node_modules --exclude=.venv \
  --exclude=dist --exclude=build --exclude=.pytest_cache -czf "$EVIDENCE/source-snapshot.tar.gz" .
sha256sum "$EVIDENCE/source-snapshot.tar.gz" >"$EVIDENCE/source-snapshot.sha256"

command -v docker >/dev/null || { echo 'Docker CLI unavailable' >&2; exit 69; }
command -v curl >/dev/null || { echo 'curl unavailable' >&2; exit 69; }
command -v nsenter >/dev/null || { echo 'nsenter is required for the host controller to reach the isolated recovery namespace' >&2; exit 69; }
[[ -x /home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome ]] || {
  echo 'Playwright Chromium 1234 executable unavailable' >&2; exit 69;
}
PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright node -e \
  "process.stdout.write(require('./ui/node_modules/playwright/package.json').version+'\\n')" \
  >"$EVIDENCE/playwright-version.txt"
df -Pk /tmp >"$EVIDENCE/tmp-space-preflight.txt"
for port in "$API_PORT" "$RECOVERY_PORT" "$OIDC_PROXY_PORT" "$OIDC_PORT" "$ANCHOR_PORT"; do
  if (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1; then
    echo "required local port $port is occupied" >&2; exit 69
  fi
done
printf 'api_loopback_port=%s\nrecovery_loopback_port=%s\nanchor_loopback_port=%s\noidc_proxy_host=%s\noidc_proxy_port=%s\noidc_backend_loopback_port=%s\n' \
  "$API_PORT" "$RECOVERY_PORT" "$ANCHOR_PORT" "$OIDC_HOST" "$OIDC_PROXY_PORT" "$OIDC_PORT" >"$EVIDENCE/runtime-ports.txt"
docker version --format 'engine={{.Server.Version}}' >"$EVIDENCE/docker-version.txt"
DOCKER_BRIDGE_SUBNET=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Subnet}}')
python3 - "$DOCKER_BRIDGE_SUBNET" <<'CHECKBRIDGE'
import ipaddress,sys
network=ipaddress.ip_network(sys.argv[1], strict=True)
if network.version != 4 or not network.is_private:
    raise SystemExit('default Docker bridge must be a private IPv4 subnet')
CHECKBRIDGE
printf 'docker_bridge_subnet=%s\n' "$DOCKER_BRIDGE_SUBNET" >>"$EVIDENCE/runtime-ports.txt"
for name in "$CONTAINER" "$ANCHOR_CONTAINER"; do
  if docker inspect "$name" >/dev/null 2>&1; then
    echo "owned journey container name already exists: $name" >&2; exit 69
  fi
done
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then CREATED_IMAGE=1; fi
if [[ $CANDIDATE_IMAGE != "$IMAGE" ]] && ! docker image inspect "$CANDIDATE_IMAGE" >/dev/null 2>&1; then
  CREATED_CANDIDATE_IMAGE=1
fi

FIXTURE_OIDC_INTERNAL_ARGS=()
HOST_OIDC_INTERNAL_ARGS=()
if (( ! DATA_PRESERVATION_MODE )) && [[ $OIDC_PROXY_PORT != 9000 ]]; then
  FIXTURE_OIDC_INTERNAL_ARGS=(--oidc-internal)
  HOST_OIDC_INTERNAL_ARGS=(--oidc-internal)
fi
FIXTURE_OIDC_ARGS=(--oidc-port "$OIDC_PROXY_PORT" "${FIXTURE_OIDC_INTERNAL_ARGS[@]}")
if (( EXCEPTION_WARNING_MODE || EXCEPTION_SLA_MODE )); then FIXTURE_OIDC_ARGS+=(--oidc-host "$OIDC_HOST"); fi
if (( DATA_PRESERVATION_MODE )); then FIXTURE_OIDC_ARGS=(--oidc-port "$OIDC_PORT" --oidc-internal); fi
if (( EXCEPTION_WARNING_MODE )); then FIXTURE_OIDC_ARGS+=(--exception-warning); fi
if (( EXCEPTION_SLA_MODE )); then FIXTURE_OIDC_ARGS+=(--exception-sla); fi
if (( IDENTITY_MODE )); then FIXTURE_OIDC_ARGS+=(--identity-access-ownership); fi
if (( UPGRADE_ROLLBACK_MODE )); then FIXTURE_OIDC_ARGS+=(--heartbeat-max-age-seconds 900); fi
uv run python "$ROOT/tools/g7_observer_fixture.py" create --root "$RUN_ROOT" --image "$IMAGE" \
  "${FIXTURE_OIDC_ARGS[@]}" --api-port "$API_PORT" --recovery-port "$RECOVERY_PORT"
if (( EXCEPTION_WARNING_MODE || EXCEPTION_SLA_MODE )); then
  WARNING_NOW=$(date -u +'%Y-%m-%dT%H:%M:%S+00:00')
  printf '%s\n' "$WARNING_NOW" >"$RUN_ROOT/scheduler/warning-clock.txt"
  chmod 0666 "$RUN_ROOT/scheduler/warning-clock.txt"
  if (( EXCEPTION_WARNING_MODE )); then
  mkdir -p "$RUN_ROOT/warning"
  chmod 0777 "$RUN_ROOT/warning"
  printf '%s\n' 'g7-warning-fixture-token' >"$RUN_ROOT/secrets/slack-warning-token"
  chmod 0600 "$RUN_ROOT/secrets/slack-warning-token"
  printf '%s\n' 'fixture-secret' >"$RUN_ROOT/secrets/smtp-warning-token"
  chmod 0600 "$RUN_ROOT/secrets/smtp-warning-token"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=g7-warning-smtp-fixture' \
    -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
    -keyout "$RUN_ROOT/warning/smtp-key.pem" -out "$RUN_ROOT/warning/smtp-cert.pem" \
    >"$EVIDENCE/smtp-certificate.stdout" 2>"$EVIDENCE/smtp-certificate.stderr"
  chmod 0644 "$RUN_ROOT/warning/smtp-key.pem" "$RUN_ROOT/warning/smtp-cert.pem"
  cp "$RUN_ROOT/warning/smtp-cert.pem" "$EVIDENCE/smtp-fixture-certificate.pem"
  cat >"$EVIDENCE/warning-fixture-config.json" <<'WARNINGCONFIG'
{"clock_file":"/run/uvm-g7-scheduler/warning-clock.txt","slack":{"host":"127.0.0.1","port":18181,"channels":["C_FIXTURE_SUCCESS","C_FIXTURE_FAILED","C_FIXTURE_UNCERTAIN"],"secret_ref":"secret:slack-warning-token"},"smtp":{"host":"127.0.0.1","port":18465,"tls":"implicit","recipients":{"fixture-smtp-accepted":"accepted@fixture.invalid","fixture-smtp-retry":"retry@fixture.invalid","fixture-smtp-uncertain":"uncertain@fixture.invalid","fixture-smtp-predatadisconnect":"predatadisconnect@fixture.invalid"},"secret_ref":"secret:smtp-warning-token"},"retry":{"smtp_base_seconds":1,"smtp_max_attempts":3,"slack_fixture_retry_not_advanced":true}}
WARNINGCONFIG
  chmod 0600 "$EVIDENCE/warning-fixture-config.json"
  sha256sum "$EVIDENCE/warning-fixture-config.json" "$RUN_ROOT/warning/smtp-cert.pem" \
    >"$EVIDENCE/warning-fixture-config.sha256"
  cat >>"$RUN_ROOT/container.env" <<WARNINGENV
UVM_G7_TEST_CLOCK_FILE=/run/uvm-g7-scheduler/warning-clock.txt
UVM_EXCEPTION_WARNING_WORKER=1
UVM_EXCEPTION_WARNING_POLL_SECONDS=1
UVM_EXCEPTION_WARNING_INSTALLATION_ID=fixture-installation
UVM_EXCEPTION_WARNING_APP_ID=fixture-app
UVM_EXCEPTION_WARNING_SIGNING_SECRET_FILE=/run/uvm-g7-secrets/exception-warning/slack-signing-secret
SSL_CERT_FILE=/run/uvm-g7-warning-fixture/smtp-cert.pem
UVM_EXCEPTION_WARNING_USE_LOOPBACK_HTTP=1
UVM_EXCEPTION_WARNING_DESTINATIONS={"fixture-destination":{"channel":"slack","secret_ref":"secret:slack-warning-token","endpoint":"http://127.0.0.1:18181/api/chat.postMessage","installation_id":"fixture-installation","workspace_id":"T_FIXTURE","channel_id":"C_FIXTURE_SUCCESS"},"fixture-failed-destination":{"channel":"slack","secret_ref":"secret:slack-warning-token","endpoint":"http://127.0.0.1:18181/api/chat.postMessage","installation_id":"fixture-installation","workspace_id":"T_FIXTURE","channel_id":"C_FIXTURE_FAILED"},"fixture-uncertain-destination":{"channel":"slack","secret_ref":"secret:slack-warning-token","endpoint":"http://127.0.0.1:18181/api/chat.postMessage","installation_id":"fixture-installation","workspace_id":"T_FIXTURE","channel_id":"C_FIXTURE_UNCERTAIN"},"fixture-signing-reference":{"channel":"slack","secret_ref":"secret:slack-signing-secret","endpoint":"http://127.0.0.1:18181/api/chat.postMessage","installation_id":"fixture-installation","workspace_id":"T_FIXTURE","channel_id":"C_FIXTURE_SUCCESS"},"fixture-smtp-accepted":{"channel":"email","secret_ref":"secret:smtp-warning-token","smtp_host":"127.0.0.1","smtp_port":18465,"smtp_user":"g7-fixture","sender":"uvm@fixture.invalid","recipient":"accepted@fixture.invalid","smtp_tls":"implicit"},"fixture-smtp-retry":{"channel":"email","secret_ref":"secret:smtp-warning-token","smtp_host":"127.0.0.1","smtp_port":18465,"smtp_user":"g7-fixture","sender":"uvm@fixture.invalid","recipient":"retry@fixture.invalid","smtp_tls":"implicit"},"fixture-smtp-uncertain":{"channel":"email","secret_ref":"secret:smtp-warning-token","smtp_host":"127.0.0.1","smtp_port":18465,"smtp_user":"g7-fixture","sender":"uvm@fixture.invalid","recipient":"uncertain@fixture.invalid","smtp_tls":"implicit"},"fixture-smtp-predatadisconnect":{"channel":"email","secret_ref":"secret:smtp-warning-token","smtp_host":"127.0.0.1","smtp_port":18465,"smtp_user":"g7-fixture","sender":"uvm@fixture.invalid","recipient":"predatadisconnect@fixture.invalid","smtp_tls":"implicit"}}
WARNINGENV
  printf '%s\n' 'g7-warning-fixture-signing-secret' >"$RUN_ROOT/secrets/slack-signing-secret"
  chmod 0600 "$RUN_ROOT/secrets/slack-signing-secret"
  else
    cat >>"$RUN_ROOT/container.env" <<SLAENV
UVM_G7_TEST_CLOCK_FILE=/run/uvm-g7-scheduler/warning-clock.txt
SLAENV
  fi
fi
if (( DATA_PRESERVATION_MODE )); then
  PRESERVATION_VOLUME_NAMES=("volt-g7-preservation-$RUN_ID-postgres" "volt-g7-preservation-$RUN_ID-media" "volt-g7-preservation-$RUN_ID-state")
  for volume in "${PRESERVATION_VOLUME_NAMES[@]}"; do
    docker volume create --label uvm.g7.data-preservation-check=true --label "uvm.g7.run-id=$RUN_ID" "$volume" \
      >>"$EVIDENCE/preservation-volumes.stdout"
  done
  PRESERVATION_STORAGE_GENERATION=$(python3 -c 'import uuid;print(uuid.uuid4())')
  PRESERVATION_VOLUME_SET_DIGEST=$(python3 - "${PRESERVATION_VOLUME_NAMES[@]}" <<'PRESVOL'
import hashlib,json,subprocess,sys
rows=[]
for kind,name in zip(('postgres_cluster','ce_media','uvm_state'),sys.argv[1:]):
    value=json.loads(subprocess.check_output(['docker','volume','inspect',name],text=True))[0]
    rows.append({'kind':kind,'name':value['Name'],'driver':value['Driver'],'labels':value.get('Labels') or {}})
print(hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest())
PRESVOL
)
  printf '%s\n' "${PRESERVATION_VOLUME_NAMES[@]}" >"$EVIDENCE/preservation-volume-names.txt"
  mkdir -p "$RUN_ROOT/host/preservation-trust"
  chmod 755 "$RUN_ROOT/host/preservation-trust"
  PRESERVATION_SCHEMA_HEAD_DIGEST=$(python3 - "$ROOT/docker/g7/schema-head" <<'SCHEMAHASH'
import hashlib,json,sys
from pathlib import Path
print(hashlib.sha256(json.dumps([Path(sys.argv[1]).read_text().strip()],separators=(',',':')).encode()).hexdigest())
SCHEMAHASH
)
  PRESERVATION_KEY_VALID_FROM=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
  PRESERVATION_KEY_VALID_UNTIL=$(date -u -d '1 day' +%Y-%m-%dT%H:%M:%SZ)
  mkdir -p "$RUN_ROOT/host/preservation-reports"
  chmod 755 "$RUN_ROOT/host/preservation-reports"
  cat >>"$RUN_ROOT/container.env" <<PRESENV
UVM_G7_DEPLOYMENT_ID=g7-local
UVM_G7_RECOVERY_EPOCH=1
UVM_G7_STORAGE_GENERATION=$PRESERVATION_STORAGE_GENERATION
UVM_G7_VOLUME_SET_DIGEST=$PRESERVATION_VOLUME_SET_DIGEST
UVM_G7_PRESERVATION_PUBLIC_KEY_FILE=/run/uvm-g7-host-pub.pem
UVM_G7_PRESERVATION_KEY_ID=g7-preservation-fixture
UVM_G7_PRESERVATION_TRUST_DIR=/run/uvm-g7-preservation-trust
UVM_G7_PRESERVATION_ENVIRONMENT=local
UVM_G7_PRESERVATION_REPORT_DIR=/run/uvm-g7-preservation-reports
UVM_G7_PRESERVATION_MAX_FUTURE_SKEW_SECONDS=30
PRESENV
  PRESERVATION_MOUNTS=(
    --mount "type=volume,src=${PRESERVATION_VOLUME_NAMES[0]},dst=/var/lib/postgresql/data"
    --mount "type=volume,src=${PRESERVATION_VOLUME_NAMES[1]},dst=/app/media"
    --mount "type=volume,src=${PRESERVATION_VOLUME_NAMES[2]},dst=/opt/uvm/state"
    --mount "type=bind,src=$RUN_ROOT/host/preservation-trust,dst=/run/uvm-g7-preservation-trust,readonly"
    --mount "type=bind,src=$RUN_ROOT/host/preservation-reports,dst=/run/uvm-g7-preservation-reports,readonly"
  )
fi
if [[ $MODE == --backup-recovery-only || $MODE == --upgrade-rollback-only ]]; then
  printf '\nUVM_G7_QUIESCE_NO_KILL=1\nUVM_G7_QUIESCE_TIMEOUT_SECONDS=300\n' >>"$RUN_ROOT/container.env"
fi
if (( UPGRADE_ROLLBACK_MODE )); then
  printf 'true\n' >"$EVIDENCE/upgrade-rollback-mode.txt"
  A_FIXTURE="$RUN_ROOT/image-a"
  python3 "$ROOT/tools/g7_upgrade_fixture.py" --source 983ce03455de33fa48f34d6a656d700873b37319 \
    --destination "$A_FIXTURE" >"$EVIDENCE/image-a-fixture.stdout"
  cp "$A_FIXTURE/source-A.tar" "$EVIDENCE/image-a-source.tar"
  cp "$A_FIXTURE/overlay.patch" "$EVIDENCE/image-a-overlay.patch"
  cp "$A_FIXTURE/schema-compatibility.py" "$EVIDENCE/image-a-schema-compatibility.py"
  cp "$A_FIXTURE/schema-head" "$EVIDENCE/image-a-schema-head"
  cp "$A_FIXTURE/fixture-manifest.json" "$EVIDENCE/image-a-fixture-manifest.json"
  A_SOURCE_EPOCH=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source_epoch"])' "$EVIDENCE/image-a-fixture-manifest.json")
  A_CONTEXT_DIGEST=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["context_archive_sha256"])' "$EVIDENCE/image-a-fixture-manifest.json")
  python3 "$ROOT/tools/g7_upgrade_fixture.py" --source 983ce03455de33fa48f34d6a656d700873b37319 \
    --destination "$EVIDENCE/image-a-gitless-reconstruction" --source-export "$EVIDENCE/image-a-source.tar" \
    --compatibility-export "$EVIDENCE/image-a-schema-compatibility.py" --schema-head-export "$EVIDENCE/image-a-schema-head" \
    --source-epoch "$A_SOURCE_EPOCH" --expected-context-sha256 "$A_CONTEXT_DIGEST" \
    >"$EVIDENCE/image-a-gitless-reconstruction.stdout"
  docker build -f "$A_FIXTURE/context/Dockerfile.g7" -t "$IMAGE" "$A_FIXTURE/context" \
    >"$EVIDENCE/image-a-build.stdout" 2>"$EVIDENCE/image-a-build.stderr"
  docker image inspect "$IMAGE" --format '{{.Id}} {{json .RepoDigests}}' \
    >"$EVIDENCE/image-a-pinned.txt"
  docker build -f "$ROOT/Dockerfile.g7" -t "$CANDIDATE_IMAGE" "$ROOT" \
    >"$EVIDENCE/image-b-build.stdout" 2>"$EVIDENCE/image-b-build.stderr"
  docker image inspect "$CANDIDATE_IMAGE" --format '{{.Id}} {{json .RepoDigests}}' \
    >"$EVIDENCE/image-b-pinned.txt"
  docker image inspect "$CANDIDATE_IMAGE" --format '{{.Id}}' >"$EVIDENCE/image-b-id.txt"
  RESTORE_IMAGE_DIGEST=$(cat "$EVIDENCE/image-b-id.txt")
  CANDIDATE_PACKAGE_DIGEST=$(python3 - "$ROOT" <<'PYPACKAGE'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1]); digest=hashlib.sha256()
for name in ('pyproject.toml','uv.lock'): digest.update(name.encode()+b'\0'+(root/name).read_bytes()+b'\0')
print('sha256:'+digest.hexdigest())
PYPACKAGE
)
  SOURCE_PACKAGE_DIGEST=$(python3 - "$A_FIXTURE/context" <<'PYPACKAGE'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1]); digest=hashlib.sha256()
for name in ('pyproject.toml','uv.lock'): digest.update(name.encode()+b'\0'+(root/name).read_bytes()+b'\0')
print('sha256:'+digest.hexdigest())
PYPACKAGE
)
  [[ $SOURCE_PACKAGE_DIGEST == "$CANDIDATE_PACKAGE_DIGEST" ]] || {
    echo 'A/B package manifest digests differ outside the declared schema transition' >&2; exit 2;
  }
  printf 'image_a=%s\nimage_b=%s\nsource_package_manifest_digest=%s\ntarget_package_manifest_digest=%s\n' \
    "$IMAGE" "$CANDIDATE_IMAGE" "$SOURCE_PACKAGE_DIGEST" "$CANDIDATE_PACKAGE_DIGEST" >"$EVIDENCE/image-bindings.txt"
  UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/volt-uv-cache}" uv run python "$ROOT/tools/g7_schema_migration_probe.py" \
    --image "$RESTORE_IMAGE_DIGEST" --run-id "$RUN_ID" \
    --source-head 0061 --target-head 0062 \
    --evidence "$EVIDENCE/migration-fault-probe" \
    >"$EVIDENCE/migration-fault-probe.stdout" \
    2>"$EVIDENCE/migration-fault-probe.stderr"
else
  docker build -f "$ROOT/Dockerfile.g7" -t "$IMAGE" "$ROOT" \
    >"$EVIDENCE/docker-build.stdout" 2>"$EVIDENCE/docker-build.stderr"
  docker image inspect "$IMAGE" --format '{{.Id}} {{json .RepoDigests}}' \
    >"$EVIDENCE/pinned-image.txt"
fi

STARTED_ANCHOR=1
docker run -d --name "$ANCHOR_CONTAINER" --label uvm.g7.observer-journey=true --label "uvm.g7.run-id=$RUN_ID" \
  -p "127.0.0.1:$ANCHOR_PORT:5432" \
  --tmpfs /var/lib/postgresql/data:rw,uid=101,gid=103,mode=0700 \
  --mount "type=bind,src=$RUN_ROOT/anchor-password,dst=/run/secrets/anchor-password,readonly" \
  --env "G7_DOCKER_BRIDGE_SUBNET=$DOCKER_BRIDGE_SUBNET" \
  --user postgres --entrypoint /bin/bash "$IMAGE" -lc \
  'if [[ ! -s /var/lib/postgresql/data/PG_VERSION ]]; then /usr/lib/postgresql/18/bin/initdb -D /var/lib/postgresql/data --auth-local=trust --auth-host=scram-sha-256 --pwfile=/run/secrets/anchor-password >/dev/null; fi; printf "host all all %s scram-sha-256\\n" "$G7_DOCKER_BRIDGE_SUBNET" >>/var/lib/postgresql/data/pg_hba.conf; exec /usr/lib/postgresql/18/bin/postgres -D /var/lib/postgresql/data -h 0.0.0.0 -p 5432' \
  >"$EVIDENCE/anchor-container-id.txt"
ANCHOR_ID=$(cat "$EVIDENCE/anchor-container-id.txt")
for _ in $(seq 1 60); do
  [[ $(docker inspect "$ANCHOR_CONTAINER" --format '{{.State.Status}}' 2>/dev/null) == running ]] && break
  sleep 1
done
if [[ $(docker inspect "$ANCHOR_CONTAINER" --format '{{.State.Status}}' 2>/dev/null) != running ]]; then
  echo 'independent audit anchor exited during startup; see retained container evidence' >&2
  exit 70
fi
anchor_ready=0
for _ in $(seq 1 60); do
  if docker exec "$ANCHOR_CONTAINER" /usr/lib/postgresql/18/bin/pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
    anchor_ready=1; break
  fi
  [[ $(docker inspect "$ANCHOR_CONTAINER" --format '{{.State.Status}}' 2>/dev/null) == running ]] || break
  sleep 1
done
if (( ! anchor_ready )); then
  echo 'independent audit anchor did not accept connections; see retained container evidence' >&2
  exit 70
fi
uv run python "$ROOT/tools/g7_observer_fixture.py" anchor-init --root "$RUN_ROOT" --container "$ANCHOR_CONTAINER" \
  >"$EVIDENCE/anchor-fixture.stdout" 2>"$EVIDENCE/anchor-fixture.stderr"
preservation_role_denial() {
  local label=$1 role=$2 database=$3 statement=$4
  if docker exec "$ANCHOR_CONTAINER" psql -X -U postgres -d "$database" -v ON_ERROR_STOP=1 \
      -c "SET ROLE $role; $statement" \
      >"$EVIDENCE/role-$label.stdout" 2>"$EVIDENCE/role-$label.stderr"; then
    echo "least-privilege role unexpectedly changed protected history: $label" >&2
    return 1
  fi
  if ! grep -qi 'permission denied' "$EVIDENCE/role-$label.stderr"; then
    echo "role fence failed for an unexpected reason: $label" >&2
    return 1
  fi
  printf 'role=%s\ndatabase=%s\nprotected_write=denied\n' "$role" "$database" \
    >"$EVIDENCE/role-$label-result.txt"
  chmod 0600 "$EVIDENCE/role-$label.stdout" "$EVIDENCE/role-$label.stderr" \
    "$EVIDENCE/role-$label-result.txt"
}
preservation_role_denial siem-update siem_exporter audit_sink \
  'UPDATE uvm_audit_export.events SET committed_at=committed_at WHERE false'
preservation_role_denial siem-delete siem_exporter audit_sink \
  'DELETE FROM uvm_audit_export.events WHERE false'
preservation_role_denial anchor-update anchor_signer audit_anchor \
  'UPDATE uvm_audit_anchor.inventory SET sink_receipt=sink_receipt WHERE false'
preservation_role_denial anchor-delete anchor_signer audit_anchor \
  'DELETE FROM uvm_audit_anchor.inventory WHERE false'
preservation_role_denial exporter-insert exporter_ro audit_anchor \
  'INSERT INTO uvm_audit_anchor.inventory SELECT * FROM uvm_audit_anchor.inventory LIMIT 0'
preservation_role_denial host-update host_ro audit_anchor \
  'UPDATE uvm_audit_anchor.incidents SET state=state WHERE false'

STARTED_CONTAINER=1
APP_EXTRA_MOUNTS=()
APP_EXTRA_PORTS=()
if (( EXCEPTION_WARNING_MODE )); then
  APP_EXTRA_MOUNTS+=(--mount "type=bind,src=$RUN_ROOT/warning,dst=/run/uvm-g7-warning-fixture")
fi
if (( EXCEPTION_WARNING_MODE || EXCEPTION_SLA_MODE )); then
  APP_EXTRA_PORTS+=( -p "127.0.0.1:$OIDC_PROXY_PORT:$OIDC_PROXY_PORT" )
fi
docker run -d --name "$CONTAINER" --label uvm.g7.observer-journey=true --label "uvm.g7.run-id=$RUN_ID" \
  -p "127.0.0.1:$API_PORT:8000" -p "127.0.0.1:$RECOVERY_PORT:8002" -p "127.0.0.1:$OIDC_PORT:9000" \
  "${APP_EXTRA_PORTS[@]}" \
  "${PRESERVATION_MOUNTS[@]}" \
  --mount "type=bind,src=$RUN_ROOT/secrets,dst=/run/secrets,readonly" \
  --mount "type=bind,src=$RUN_ROOT/secrets/registry.json,dst=/run/uvm-g7-registry.json,readonly" \
  --mount "type=bind,src=$RUN_ROOT/secrets/host-pub.pem,dst=/run/uvm-g7-host-pub.pem,readonly" \
  --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/run/uvm-g7-scheduler" "${APP_EXTRA_MOUNTS[@]}" \
  --env-file "$RUN_ROOT/container.env" "$IMAGE" >"$EVIDENCE/app-container-id.txt"
CONTAINER_ID=$(cat "$EVIDENCE/app-container-id.txt")

ready=0
for _ in $(seq 1 300); do
  if docker inspect "$CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null | grep -qx healthy; then ready=1; break; fi
  if [[ $(docker inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null) != running ]]; then break; fi
  sleep 2
done
if (( ! ready )); then
  docker inspect "$CONTAINER" --format '{{.State.Status}} {{.State.ExitCode}} {{.State.Health.Status}}' \
    >"$EVIDENCE/app-container-state.txt" || true
  docker logs "$CONTAINER" 2>&1 | sed -E \
    "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
    >"$EVIDENCE/app-startup-redacted.log" || true
  echo 'disposable application did not become healthy; see retained redacted startup evidence' >&2
  exit 70
fi
if (( ! DATA_PRESERVATION_MODE && ! EXCEPTION_WARNING_MODE && ! EXCEPTION_SLA_MODE )) && [[ $OIDC_PROXY_PORT != 9000 ]]; then
  cat >"$RUN_ROOT/host/oidc-container-loopback-proxy.py" <<'PYCONTAINERPROXY'
import select,socket,socketserver,sys
port=int(sys.argv[1])
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  try:
   with socket.create_connection(('127.0.0.1',9000),timeout=5) as upstream:
    client=self.request; client.setblocking(False); upstream.setblocking(False)
    while True:
     readable,_,_=select.select((client,upstream),(),(),30)
     if not readable: return
     for source in readable:
      data=source.recv(65536)
      if not data: return
      (upstream if source is client else client).sendall(data)
  except OSError:
   return
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
Server(('127.0.0.1',port),Handler).serve_forever()
PYCONTAINERPROXY
  chmod 0644 "$RUN_ROOT/host/oidc-container-loopback-proxy.py"
  cp "$RUN_ROOT/host/oidc-container-loopback-proxy.py" \
    "$EVIDENCE/oidc-container-loopback-proxy.py"
  docker cp "$RUN_ROOT/host/oidc-container-loopback-proxy.py" \
    "$CONTAINER:/tmp/oidc-container-loopback-proxy.py" >/dev/null
  docker exec -u uvm -d "$CONTAINER" /opt/uvm/venv/bin/python \
    /tmp/oidc-container-loopback-proxy.py "$OIDC_PROXY_PORT"
  oidc_container_proxy_ready=0
  for _ in $(seq 1 30); do
    if docker exec -u uvm "$CONTAINER" /opt/uvm/venv/bin/python -c \
        'import socket,sys; socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=1).close()' \
        "$OIDC_PROXY_PORT" >"$EVIDENCE/oidc-container-loopback-proxy-ready.stdout" \
        2>"$EVIDENCE/oidc-container-loopback-proxy-ready.stderr"; then
      oidc_container_proxy_ready=1; break
    fi
    sleep 1
  done
  (( oidc_container_proxy_ready )) || {
    echo 'historical A loopback OIDC endpoint did not become ready' >&2
    exit 70
  }
fi
curl --fail --silent --show-error "http://127.0.0.1:$API_PORT/openapi.json" >/dev/null
if (( EXCEPTION_WARNING_MODE )); then
  docker exec -d "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_exception_warning_provider.py \
    --host 127.0.0.1 --port 18181 --output /run/uvm-g7-warning-fixture/provider-captures.json \
    --token g7-warning-fixture-token
  docker exec -d "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_exception_warning_smtp.py \
    --host 127.0.0.1 --port 18465 \
    --cert /run/uvm-g7-warning-fixture/smtp-cert.pem \
    --key /run/uvm-g7-warning-fixture/smtp-key.pem \
    --output /run/uvm-g7-warning-fixture/smtp-captures.json
  for _ in $(seq 1 30); do
    if docker exec "$CONTAINER" curl --fail --silent http://127.0.0.1:18181/healthz >/dev/null \
        && docker exec "$CONTAINER" /opt/uvm/venv/bin/python -c 'import socket; socket.create_connection(("127.0.0.1",18465),timeout=1).close()' 2>/dev/null; then break; fi
    sleep 1
  done
  docker exec "$CONTAINER" curl --fail --silent http://127.0.0.1:18181/healthz >/dev/null
  docker exec "$CONTAINER" /opt/uvm/venv/bin/python -c \
    'import os,ssl,smtplib; path=os.environ.get("SSL_CERT_FILE"); print("trust_file="+str(path)+" exists="+str(bool(path and os.path.isfile(path)))); print("trust_store="+str(ssl.create_default_context().cert_store_stats())); client=smtplib.SMTP_SSL("127.0.0.1",18465,timeout=5,context=ssl.create_default_context()); print("tls_cipher="+str(client.sock.cipher()[0])); client.quit()' \
    >"$EVIDENCE/smtp-tls-probe.stdout" 2>"$EVIDENCE/smtp-tls-probe.stderr" || {
      echo 'disposable SMTP TLS trust/hostname probe failed; see retained probe output' >&2; exit 70;
    }
fi
if (( EXCEPTION_WARNING_MODE || EXCEPTION_SLA_MODE )); then
  docker exec -d "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_exception_warning_oidc_proxy.py \
    --host 0.0.0.0 --port "$OIDC_PROXY_PORT" --upstream-port 9000
  for _ in $(seq 1 30); do
    if docker exec "$CONTAINER" curl --fail --silent --max-time 2 \
        "http://127.0.0.1:$OIDC_PROXY_PORT/healthz" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  docker exec "$CONTAINER" curl --fail --silent --show-error --max-time 2 \
    "http://127.0.0.1:$OIDC_PROXY_PORT/healthz" >"$EVIDENCE/oidc-proxy-health.txt"
  curl --fail --silent --show-error --max-time 2 \
    "http://127.0.0.1:$OIDC_PROXY_PORT/healthz" >/dev/null
elif (( ! DATA_PRESERVATION_MODE )); then
cat >"$RUN_ROOT/host/oidc-loopback-proxy.mjs" <<'NODEPROXY'
import net from 'node:net';
const upstreamPort=Number(process.env.OIDC_UPSTREAM_PORT);
const server=net.createServer(client=>{
 const upstream=net.connect({host:'127.0.0.1',port:upstreamPort});
 client.pipe(upstream); upstream.pipe(client);
 client.on('error',()=>upstream.destroy()); upstream.on('error',()=>client.destroy());
});
server.listen(Number(process.env.OIDC_PROXY_PORT),process.env.OIDC_PROXY_HOST);
NODEPROXY
OIDC_UPSTREAM_PORT=$OIDC_PORT OIDC_PROXY_PORT=$OIDC_PROXY_PORT OIDC_PROXY_HOST=$OIDC_HOST node "$RUN_ROOT/host/oidc-loopback-proxy.mjs" \
  >"$RUN_ROOT/host/oidc-proxy.log" 2>&1 &
OIDC_PROXY_PID=$!
printf '%s\n' "$OIDC_PROXY_PID" >"$RUN_ROOT/host/oidc-proxy.pid"
for _ in $(seq 1 30); do
  if curl --fail --silent --max-time 2 "http://$OIDC_HOST:$OIDC_PROXY_PORT/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$OIDC_PROXY_PID" 2>/dev/null; then
    cp "$RUN_ROOT/host/oidc-proxy.log" "$EVIDENCE/oidc-proxy-startup.log" 2>/dev/null || true
    echo 'G7 local OIDC forwarding proxy exited during startup' >&2
    exit 70
  fi
  sleep 1
done
if ! curl --fail --silent --show-error --max-time 2 "http://$OIDC_HOST:$OIDC_PROXY_PORT/healthz" >/dev/null; then
  cp "$RUN_ROOT/host/oidc-proxy.log" "$EVIDENCE/oidc-proxy-startup.log" 2>/dev/null || true
  echo 'G7 local OIDC forwarding proxy health request failed' >&2
  exit 70
fi
fi

if (( DATA_PRESERVATION_MODE )); then
  uv run python "$ROOT/tools/g7_observer_fixture.py" link-actor --root "$RUN_ROOT" \
    --container "$CONTAINER" >"$EVIDENCE/preservation-oidc-link.stdout" \
    2>"$EVIDENCE/preservation-oidc-link.stderr"
  PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
    node "$ROOT/tools/g7_preservation_authority_browser.mjs" \
      --origin "http://127.0.0.1:$API_PORT" \
      --storage-state "$RUN_ROOT/host/preservation-session.json" \
      >"$EVIDENCE/preservation-authority.stdout" 2>"$EVIDENCE/preservation-authority.stderr"
  docker cp "$ROOT/tools/g7_preservation_seed_source.py" \
    "$CONTAINER:/tmp/g7_preservation_seed_source.py" >/dev/null
  docker exec -u uvm "$CONTAINER" /opt/uvm/venv/bin/python \
    /tmp/g7_preservation_seed_source.py >"$EVIDENCE/preservation-source-seed.stdout" \
    2>"$EVIDENCE/preservation-source-seed.stderr"
  ANCHOR_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ANCHOR_CONTAINER")
  [[ $ANCHOR_IP =~ ^[0-9.]+$ ]] || { echo 'independent audit sidecar address is unavailable' >&2; exit 70; }
  SIEM_PASSWORD=$(cat "$RUN_ROOT/host/siem-exporter-password")
  EXPORTER_ANCHOR_PASSWORD=$(cat "$RUN_ROOT/host/exporter-ro-password")
  SIGNER_ANCHOR_PASSWORD=$(cat "$RUN_ROOT/host/anchor-signer-password")
  DEPLOYMENT_AUDIT_TOKEN=$(cat "$RUN_ROOT/secrets/g7_preservation_source_token")
  docker exec \
    --env G7_DEPLOYMENT_AUDIT_TOKEN="$DEPLOYMENT_AUDIT_TOKEN" \
    --env G7_AUDIT_SOURCE_FAMILY=local --env G7_AUDIT_SOURCE_ACCOUNT=g7-local \
    --env G7_AUDIT_SCOPE_KEY=all --env G7_AUDIT_AUTH_ORIGIN=http://127.0.0.1:8000 \
    --env G7_AUDIT_DEPLOYMENT_ID=g7-local \
    --env "G7_SIEM_DSN=postgresql://siem_exporter:$SIEM_PASSWORD@$ANCHOR_IP:5432/audit_sink" \
    --env "G7_AUDIT_ANCHOR_DSN=postgresql://exporter_ro:$EXPORTER_ANCHOR_PASSWORD@$ANCHOR_IP:5432/audit_anchor" \
    --env "G7_AUDIT_ANCHOR_SIGNER_DSN=postgresql://anchor_signer:$SIGNER_ANCHOR_PASSWORD@$ANCHOR_IP:5432/audit_anchor" \
    "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_container_audit_export.py \
    siem-export --limit 5000 --sink-id g7-siem >"$EVIDENCE/preservation-audit-export.stdout" \
    2>"$EVIDENCE/preservation-audit-export.stderr"
  docker exec \
    --env G7_DEPLOYMENT_AUDIT_TOKEN="$DEPLOYMENT_AUDIT_TOKEN" \
    --env G7_AUDIT_SOURCE_FAMILY=local --env G7_AUDIT_SOURCE_ACCOUNT=g7-local \
    --env G7_AUDIT_SCOPE_KEY=all --env G7_AUDIT_AUTH_ORIGIN=http://127.0.0.1:8000 \
    --env G7_AUDIT_DEPLOYMENT_ID=g7-local \
    --env "G7_SIEM_DSN=postgresql://siem_exporter:$SIEM_PASSWORD@$ANCHOR_IP:5432/audit_sink" \
    --env "G7_AUDIT_ANCHOR_SIGNER_DSN=postgresql://anchor_signer:$SIGNER_ANCHOR_PASSWORD@$ANCHOR_IP:5432/audit_anchor" \
    "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_container_audit_export.py \
    anchor-history --limit 5000 --sink-id g7-siem >"$EVIDENCE/preservation-audit-anchor.stdout" \
    2>"$EVIDENCE/preservation-audit-anchor.stderr"
  docker exec \
    --env G7_DEPLOYMENT_AUDIT_TOKEN="$DEPLOYMENT_AUDIT_TOKEN" \
    --env G7_AUDIT_SOURCE_FAMILY=local --env G7_AUDIT_SOURCE_ACCOUNT=g7-local \
    --env G7_AUDIT_SCOPE_KEY=all --env G7_AUDIT_AUTH_ORIGIN=http://127.0.0.1:8000 \
    --env G7_AUDIT_DEPLOYMENT_ID=g7-local \
    --env "G7_SIEM_DSN=postgresql://siem_exporter:$SIEM_PASSWORD@$ANCHOR_IP:5432/audit_sink" \
    --env "G7_AUDIT_ANCHOR_SIGNER_DSN=postgresql://anchor_signer:$SIGNER_ANCHOR_PASSWORD@$ANCHOR_IP:5432/audit_anchor" \
    "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_container_audit_export.py \
    audit-state --limit 5000 --sink-id g7-siem >"$EVIDENCE/preservation-audit-state.json" \
    2>"$EVIDENCE/preservation-audit-state.stderr"
  chmod 600 "$EVIDENCE/preservation-audit-state.json" "$EVIDENCE/preservation-audit-state.stderr"
  unset SIEM_PASSWORD EXPORTER_ANCHOR_PASSWORD SIGNER_ANCHOR_PASSWORD DEPLOYMENT_AUDIT_TOKEN
  uv run python "$ROOT/tools/g7_preservation_inventory.py" \
    --origin "http://127.0.0.1:$API_PORT" \
    --token-file "$RUN_ROOT/secrets/g7_preservation_source_token" \
    --signing-key-file "$RUN_ROOT/host/ed25519.pem" \
    --trust-dir "$RUN_ROOT/host/preservation-trust" \
    --freshness-seconds 900 --volume-set-digest "$PRESERVATION_VOLUME_SET_DIGEST" --schema-head-digest "$PRESERVATION_SCHEMA_HEAD_DIGEST" \
    --key-valid-from "$PRESERVATION_KEY_VALID_FROM" --key-valid-until "$PRESERVATION_KEY_VALID_UNTIL" \
    --admit-new-members --provision-controller \
    --report-dir "$RUN_ROOT/host/preservation-reports" \
    --key-id g7-preservation-fixture --deployment-id g7-local --recovery-epoch 1 \
    --storage-generation "$PRESERVATION_STORAGE_GENERATION" --environment local \
    --source-family local --source-account-id g7-local --scope-key all \
    --audit-state-file "$EVIDENCE/preservation-audit-state.json" \
    --metadata-output "$EVIDENCE/preservation-source-metadata.json" \
    >"$EVIDENCE/preservation-signed-inventory.stdout" \
    2>"$EVIDENCE/preservation-signed-inventory.stderr"
  report_source=$(find "$RUN_ROOT/host/preservation-reports" -maxdepth 1 -type f -name '*.json' -print -quit)
  if [[ -z $report_source || ! -f $report_source ]]; then
    echo 'signed preservation report missing after producer success' >&2
    exit 70
  fi
  install -m 0600 "$report_source" "$EVIDENCE/preservation-signed-report.json"
  PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
  node "$ROOT/tools/g7_preservation_live_readback.mjs" \
      --origin "http://127.0.0.1:$API_PORT" \
      --storage-state "$RUN_ROOT/host/preservation-session.json" \
      --output "$EVIDENCE/preservation-public-readback.json" \
      >"$EVIDENCE/preservation-public-readback.stdout" \
      2>"$EVIDENCE/preservation-public-readback.stderr"
  mkdir -m 0700 "$EVIDENCE/preservation-negative"
  phase_mark copied_store_negatives_start
  uv run python "$ROOT/tools/g7_preservation_copied_stores.py" \
    --run-root "$RUN_ROOT" --source-container "$CONTAINER" --anchor-container "$ANCHOR_CONTAINER" \
    --image "$IMAGE" --report-path "$report_source" --evidence-dir "$EVIDENCE/copied-stores" \
    --key-valid-from "$PRESERVATION_KEY_VALID_FROM" --key-valid-until "$PRESERVATION_KEY_VALID_UNTIL" \
    --schema-head-digest "$PRESERVATION_SCHEMA_HEAD_DIGEST" \
    >"$EVIDENCE/copied-store-negatives.stdout" 2>"$EVIDENCE/copied-store-negatives.stderr"
  phase_mark copied_store_negatives_end
  cp -a "$RUN_ROOT/host/preservation-trust" "$RUN_ROOT/host/preservation-trust-sink-unavailable"
  mkdir -m 0755 "$RUN_ROOT/host/preservation-reports-sink-unavailable"
  ANCHOR_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ANCHOR_CONTAINER")
  SIGNER_ANCHOR_PASSWORD=$(cat "$RUN_ROOT/host/anchor-signer-password")
  DEPLOYMENT_AUDIT_TOKEN=$(cat "$RUN_ROOT/secrets/g7_preservation_source_token")
  if docker exec \
      --env G7_DEPLOYMENT_AUDIT_TOKEN="$DEPLOYMENT_AUDIT_TOKEN" \
      --env G7_AUDIT_SOURCE_FAMILY=local --env G7_AUDIT_SOURCE_ACCOUNT=g7-local \
      --env G7_AUDIT_SCOPE_KEY=all --env G7_AUDIT_AUTH_ORIGIN=http://127.0.0.1:8000 \
      --env G7_AUDIT_DEPLOYMENT_ID=g7-local \
      --env G7_SIEM_DSN=postgresql://unavailable:unavailable@127.0.0.1:1/audit_sink \
      --env "G7_AUDIT_ANCHOR_SIGNER_DSN=postgresql://anchor_signer:$SIGNER_ANCHOR_PASSWORD@$ANCHOR_IP:5432/audit_anchor" \
      "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_container_audit_export.py \
      audit-state --limit 5000 --sink-id g7-siem \
      >"$EVIDENCE/preservation-sink-unavailable.stdout" \
      2>"$EVIDENCE/preservation-sink-unavailable.stderr"; then
    echo 'audit-state unexpectedly succeeded with an unavailable sink' >&2; exit 70
  fi
  [[ ! -s "$EVIDENCE/preservation-sink-unavailable.stdout" ]] || {
    echo 'audit-state emitted partial state after sink failure' >&2; exit 70;
  }
  chmod 0600 "$EVIDENCE/preservation-sink-unavailable.stdout" \
    "$EVIDENCE/preservation-sink-unavailable.stderr"
  unset SIGNER_ANCHOR_PASSWORD DEPLOYMENT_AUDIT_TOKEN
  uv run python "$ROOT/tools/g7_preservation_inventory.py" \
    --origin "http://127.0.0.1:$API_PORT" \
    --token-file "$RUN_ROOT/secrets/g7_preservation_source_token" \
    --signing-key-file "$RUN_ROOT/host/ed25519.pem" \
    --trust-dir "$RUN_ROOT/host/preservation-trust-sink-unavailable" \
    --freshness-seconds 900 --volume-set-digest "$PRESERVATION_VOLUME_SET_DIGEST" --schema-head-digest "$PRESERVATION_SCHEMA_HEAD_DIGEST" \
    --key-valid-from "$PRESERVATION_KEY_VALID_FROM" --key-valid-until "$PRESERVATION_KEY_VALID_UNTIL" \
    --report-dir "$RUN_ROOT/host/preservation-reports-sink-unavailable" \
    --key-id g7-preservation-fixture --deployment-id g7-local --recovery-epoch 1 \
    --storage-generation "$PRESERVATION_STORAGE_GENERATION" --environment local \
    --audit-state-failure-reason sink_unavailable \
    --source-family local --source-account-id g7-local --scope-key all \
    --metadata-output "$EVIDENCE/preservation-sink-unavailable-source-metadata.json" \
    >"$EVIDENCE/preservation-sink-unavailable-inventory.stdout" \
    2>"$EVIDENCE/preservation-sink-unavailable-inventory.stderr"
  chmod 0600 "$EVIDENCE/preservation-sink-unavailable-inventory.stdout" \
    "$EVIDENCE/preservation-sink-unavailable-inventory.stderr" \
    "$EVIDENCE/preservation-sink-unavailable-source-metadata.json"
  cp -a "$RUN_ROOT/host/preservation-trust" "$RUN_ROOT/host/preservation-trust-evidence-unavailable"
  mkdir -m 0755 "$RUN_ROOT/host/preservation-reports-evidence-unavailable"
  EVIDENCE_PROXY_PORT=$(choose_port 19091 29091 39091 49091 59091)
  command node "$ROOT/tools/g7_preservation_evidence_fault_proxy.mjs" \
    --listen "$EVIDENCE_PROXY_PORT" --upstream "$API_PORT" \
    >"$EVIDENCE/evidence-fault-proxy.stdout" 2>"$EVIDENCE/evidence-fault-proxy.stderr" &
  FAULT_PROXY_PID=$!
  printf '%s\n' "$FAULT_PROXY_PID" >"$EVIDENCE/evidence-fault-proxy-pid.txt"
  proxy_ready=0
  for _ in $(seq 1 30); do
    if curl --fail --silent --max-time 2 "http://127.0.0.1:$EVIDENCE_PROXY_PORT/healthz" >/dev/null 2>&1; then
      proxy_ready=1; break
    fi
    sleep 1
  done
  (( proxy_ready )) || { echo 'evidence fault proxy did not become ready' >&2; exit 70; }
  uv run python "$ROOT/tools/g7_preservation_inventory.py" \
    --origin "http://127.0.0.1:$EVIDENCE_PROXY_PORT" \
    --token-file "$RUN_ROOT/secrets/g7_preservation_source_token" \
    --signing-key-file "$RUN_ROOT/host/ed25519.pem" \
    --trust-dir "$RUN_ROOT/host/preservation-trust-evidence-unavailable" \
    --freshness-seconds 900 --volume-set-digest "$PRESERVATION_VOLUME_SET_DIGEST" --schema-head-digest "$PRESERVATION_SCHEMA_HEAD_DIGEST" \
    --key-valid-from "$PRESERVATION_KEY_VALID_FROM" --key-valid-until "$PRESERVATION_KEY_VALID_UNTIL" \
    --report-dir "$RUN_ROOT/host/preservation-reports-evidence-unavailable" \
    --key-id g7-preservation-fixture --deployment-id g7-local --recovery-epoch 1 \
    --storage-generation "$PRESERVATION_STORAGE_GENERATION" --environment local \
    --audit-state-file "$EVIDENCE/preservation-audit-state.json" \
    --source-family local --source-account-id g7-local --scope-key all \
    --metadata-output "$EVIDENCE/preservation-evidence-unavailable-source-metadata.json" \
    >"$EVIDENCE/preservation-evidence-unavailable-inventory.stdout" \
    2>"$EVIDENCE/preservation-evidence-unavailable-inventory.stderr"
  curl --fail --silent --show-error "http://127.0.0.1:$EVIDENCE_PROXY_PORT/__g7_fault_status" \
    >"$EVIDENCE/evidence-fault-proxy-status.json"
  UV_CACHE_DIR="$UV_CACHE_DIR" uv run --frozen python - "$EVIDENCE/evidence-fault-proxy-status.json" \
      "$EVIDENCE/preservation-evidence-unavailable-inventory.stdout" <<'EVIDENCEFAULTASSERT'
import json,sys
status=json.load(open(sys.argv[1])); report=json.load(open(sys.argv[2]))
assert status['snapshot_requests']==1 and status['evidence_requests']>0
assert report['class_states']=={'operational.scanner_collection':'failed',
 'product.audit_history':'verified','product.source_evidence':'failed'}
assert report['class_members']['product.source_evidence'] is None
assert report['class_members']['operational.scanner_collection'] is None
print(json.dumps({'source_snapshot_requests':status['snapshot_requests'],
 'evidence_downloads_denied':status['evidence_requests'],
 'failed_classes':['product.source_evidence','operational.scanner_collection']},sort_keys=True))
EVIDENCEFAULTASSERT
  chmod 0600 "$EVIDENCE/evidence-fault-proxy.stdout" "$EVIDENCE/evidence-fault-proxy.stderr" \
    "$EVIDENCE/evidence-fault-proxy-pid.txt" "$EVIDENCE/evidence-fault-proxy-status.json" \
    "$EVIDENCE/preservation-evidence-unavailable-inventory.stdout" \
    "$EVIDENCE/preservation-evidence-unavailable-inventory.stderr" \
    "$EVIDENCE/preservation-evidence-unavailable-source-metadata.json"
  uv run python "$ROOT/tools/g7_preservation_report_failure_matrix.py" \
    --report "$report_source" --key "$RUN_ROOT/host/ed25519.pem" \
    --origin "http://127.0.0.1:$API_PORT" \
    --storage-state "$RUN_ROOT/host/preservation-session.json" \
    --evidence "$EVIDENCE/preservation-negative" \
    --sink-unavailable-report "$RUN_ROOT/host/preservation-reports-sink-unavailable/$(basename "$report_source")" \
    --evidence-unavailable-report "$RUN_ROOT/host/preservation-reports-evidence-unavailable/$(basename "$report_source")" \
    >"$EVIDENCE/preservation-negative-matrix.stdout" \
    2>"$EVIDENCE/preservation-negative-matrix.stderr"
  chmod 0600 "$EVIDENCE/preservation-negative-matrix.stdout" \
    "$EVIDENCE/preservation-negative-matrix.stderr"
  docker stop --time 30 "$CONTAINER" >"$EVIDENCE/preservation-source-outage-stop.stdout"
  if uv run python "$ROOT/tools/g7_preservation_inventory.py" \
      --origin "http://127.0.0.1:$API_PORT" \
      --token-file "$RUN_ROOT/secrets/g7_preservation_source_token" \
      --signing-key-file "$RUN_ROOT/host/ed25519.pem" \
    --trust-dir "$RUN_ROOT/host/preservation-trust" \
    --freshness-seconds 900 --volume-set-digest "$PRESERVATION_VOLUME_SET_DIGEST" --schema-head-digest "$PRESERVATION_SCHEMA_HEAD_DIGEST" \
    --key-valid-from "$PRESERVATION_KEY_VALID_FROM" --key-valid-until "$PRESERVATION_KEY_VALID_UNTIL" \
      --report-dir "$RUN_ROOT/host/preservation-reports-source-unavailable" \
      --key-id g7-preservation-fixture --deployment-id g7-local --recovery-epoch 1 \
      --storage-generation "$PRESERVATION_STORAGE_GENERATION" --environment local \
      --source-family local --source-account-id g7-local --scope-key all \
      >"$EVIDENCE/preservation-source-unavailable.stdout" \
      2>"$EVIDENCE/preservation-source-unavailable.stderr"; then
    docker start "$CONTAINER" >"$EVIDENCE/preservation-source-outage-restart.stdout"
    echo 'source inventory unexpectedly succeeded while the app service was stopped' >&2; exit 70
  fi
  [[ ! -e "$RUN_ROOT/host/preservation-reports-source-unavailable/$(basename "$report_source")" ]] || {
    docker start "$CONTAINER" >"$EVIDENCE/preservation-source-outage-restart.stdout"
    echo 'source outage published a report' >&2; exit 70;
  }
  docker start "$CONTAINER" >"$EVIDENCE/preservation-source-outage-restart.stdout"
  source_restored=0
  for _ in $(seq 1 300); do
    if [[ $(docker inspect "$CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == healthy ]]; then
      source_restored=1; break
    fi
    sleep 2
  done
  (( source_restored )) || { echo 'source app did not recover after outage probe' >&2; exit 70; }
  chmod 0600 "$EVIDENCE/preservation-source-outage-stop.stdout" \
    "$EVIDENCE/preservation-source-outage-restart.stdout" \
    "$EVIDENCE/preservation-source-unavailable.stdout" \
    "$EVIDENCE/preservation-source-unavailable.stderr"
  printf '%s\n' "$CONTAINER_ID" >"$EVIDENCE/pre-replacement-container-id.txt"
  PRESERVATION_STORAGE_GENERATION=$(python3 -c 'import uuid;print(uuid.uuid4())')
  REPLACEMENT_REPORT_DIR="$RUN_ROOT/host/preservation-reports-replacement"
  mkdir -m 0755 "$REPLACEMENT_REPORT_DIR"
  cp -a "$RUN_ROOT/host/preservation-reports/snapshots" "$REPLACEMENT_REPORT_DIR/snapshots"
  # Advance the independently signed generation before replacement starts
  # and before any source/export/readback operation uses that generation.
  uv run python "$ROOT/tools/g7_preservation_inventory.py" \
    --origin "http://127.0.0.1:$API_PORT" \
    --token-file "$RUN_ROOT/secrets/g7_preservation_source_token" \
    --signing-key-file "$RUN_ROOT/host/ed25519.pem" \
    --trust-dir "$RUN_ROOT/host/preservation-trust" \
    --report-dir "$REPLACEMENT_REPORT_DIR" \
    --freshness-seconds 900 --volume-set-digest "$PRESERVATION_VOLUME_SET_DIGEST" --schema-head-digest "$PRESERVATION_SCHEMA_HEAD_DIGEST" \
    --key-valid-from "$PRESERVATION_KEY_VALID_FROM" --key-valid-until "$PRESERVATION_KEY_VALID_UNTIL" \
    --provision-controller --provision-controller-only \
    --key-id g7-preservation-fixture --deployment-id g7-local --recovery-epoch 1 \
    --storage-generation "$PRESERVATION_STORAGE_GENERATION" --environment local \
    --source-family local --source-account-id g7-local --scope-key all \
    >"$EVIDENCE/replacement-controller-provision.stdout" 2>"$EVIDENCE/replacement-controller-provision.stderr"
  python3 - "$RUN_ROOT/container.env" "$PRESERVATION_STORAGE_GENERATION" \
      "$REPLACEMENT_REPORT_DIR" <<'PRESENVUPDATE'
import sys
from pathlib import Path
path=Path(sys.argv[1]); text=path.read_text()
for key,value in (("UVM_G7_STORAGE_GENERATION",sys.argv[2]),
                  ("UVM_G7_PRESERVATION_REPORT_DIR","/run/uvm-g7-preservation-reports-replacement")):
    prefix=key+"="; matches=[line for line in text.splitlines() if line.startswith(prefix)]
    if len(matches)!=1: raise SystemExit("replacement environment binding is ambiguous")
    text=text.replace(matches[0],prefix+value,1)
path.write_text(text)
PRESENVUPDATE
  PRESERVATION_MOUNTS=(
    --mount "type=volume,src=${PRESERVATION_VOLUME_NAMES[0]},dst=/var/lib/postgresql/data"
    --mount "type=volume,src=${PRESERVATION_VOLUME_NAMES[1]},dst=/app/media"
    --mount "type=volume,src=${PRESERVATION_VOLUME_NAMES[2]},dst=/opt/uvm/state"
    --mount "type=bind,src=$RUN_ROOT/host/preservation-trust,dst=/run/uvm-g7-preservation-trust,readonly"
    --mount "type=bind,src=$REPLACEMENT_REPORT_DIR,dst=/run/uvm-g7-preservation-reports-replacement,readonly"
  )
  docker stop --time 30 "$CONTAINER" >"$EVIDENCE/pre-replacement-stop.txt"
  docker rm "$CONTAINER" >"$EVIDENCE/pre-replacement-remove.txt"
  docker run -d --name "$CONTAINER" --label uvm.g7.observer-journey=true \
    --label "uvm.g7.run-id=$RUN_ID" \
    -p "127.0.0.1:$API_PORT:8000" -p "127.0.0.1:$RECOVERY_PORT:8002" \
    -p "127.0.0.1:$OIDC_PORT:9000" \
    "${PRESERVATION_MOUNTS[@]}" \
    --mount "type=bind,src=$RUN_ROOT/secrets,dst=/run/secrets,readonly" \
    --mount "type=bind,src=$RUN_ROOT/secrets/registry.json,dst=/run/uvm-g7-registry.json,readonly" \
    --mount "type=bind,src=$RUN_ROOT/secrets/host-pub.pem,dst=/run/uvm-g7-host-pub.pem,readonly" \
    --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/run/uvm-g7-scheduler" \
    --env-file "$RUN_ROOT/container.env" "$IMAGE" >"$EVIDENCE/replacement-container-id.txt"
  CONTAINER_ID=$(cat "$EVIDENCE/replacement-container-id.txt")
  docker inspect "$CONTAINER" --format '{{.Id}} {{.Image}} {{.State.Status}}' \
    >"$EVIDENCE/replacement-container-inspect.txt"
  ready=0
  for _ in $(seq 1 300); do
    if [[ $(docker inspect "$CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == healthy ]]; then
      ready=1; break
    fi
    if [[ $(docker inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null) != running ]]; then break; fi
    sleep 2
  done
  if (( ! ready )); then
    docker inspect "$CONTAINER" --format '{{.State.Status}} {{.State.ExitCode}} {{.State.Health.Status}}' \
      >"$EVIDENCE/replacement-container-state.txt" || true
    docker logs "$CONTAINER" 2>&1 | sed -E \
      "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
      >"$EVIDENCE/replacement-startup-redacted.log" || true
    echo 'replacement application did not become healthy; see redacted startup evidence' >&2
    exit 70
  fi
  [[ $(cat "$EVIDENCE/pre-replacement-container-id.txt") != "$CONTAINER_ID" ]] || {
    echo 'replacement reused the original container identity' >&2; exit 70;
  }
  printf 'replacement_storage_generation=%s\n' "$PRESERVATION_STORAGE_GENERATION" \
    >"$EVIDENCE/replacement-generation.txt"
  ANCHOR_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ANCHOR_CONTAINER")
  SIEM_PASSWORD=$(cat "$RUN_ROOT/host/siem-exporter-password")
  EXPORTER_ANCHOR_PASSWORD=$(cat "$RUN_ROOT/host/exporter-ro-password")
  SIGNER_ANCHOR_PASSWORD=$(cat "$RUN_ROOT/host/anchor-signer-password")
  DEPLOYMENT_AUDIT_TOKEN=$(cat "$RUN_ROOT/secrets/g7_preservation_source_token")
  docker exec \
    --env G7_DEPLOYMENT_AUDIT_TOKEN="$DEPLOYMENT_AUDIT_TOKEN" \
    --env G7_AUDIT_SOURCE_FAMILY=local --env G7_AUDIT_SOURCE_ACCOUNT=g7-local \
    --env G7_AUDIT_SCOPE_KEY=all --env G7_AUDIT_AUTH_ORIGIN=http://127.0.0.1:8000 \
    --env G7_AUDIT_DEPLOYMENT_ID=g7-local \
    --env "G7_SIEM_DSN=postgresql://siem_exporter:$SIEM_PASSWORD@$ANCHOR_IP:5432/audit_sink" \
    --env "G7_AUDIT_ANCHOR_DSN=postgresql://exporter_ro:$EXPORTER_ANCHOR_PASSWORD@$ANCHOR_IP:5432/audit_anchor" \
    --env "G7_AUDIT_ANCHOR_SIGNER_DSN=postgresql://anchor_signer:$SIGNER_ANCHOR_PASSWORD@$ANCHOR_IP:5432/audit_anchor" \
    "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_container_audit_export.py \
    audit-state --limit 5000 --sink-id g7-siem >"$EVIDENCE/replacement-audit-state.json" \
    2>"$EVIDENCE/replacement-audit-state.stderr"
  chmod 600 "$EVIDENCE/replacement-audit-state.json" "$EVIDENCE/replacement-audit-state.stderr"
  unset SIEM_PASSWORD EXPORTER_ANCHOR_PASSWORD SIGNER_ANCHOR_PASSWORD DEPLOYMENT_AUDIT_TOKEN
  uv run python "$ROOT/tools/g7_preservation_inventory.py" \
    --origin "http://127.0.0.1:$API_PORT" \
    --token-file "$RUN_ROOT/secrets/g7_preservation_source_token" \
    --signing-key-file "$RUN_ROOT/host/ed25519.pem" \
    --trust-dir "$RUN_ROOT/host/preservation-trust" \
    --freshness-seconds 900 --volume-set-digest "$PRESERVATION_VOLUME_SET_DIGEST" --schema-head-digest "$PRESERVATION_SCHEMA_HEAD_DIGEST" \
    --key-valid-from "$PRESERVATION_KEY_VALID_FROM" --key-valid-until "$PRESERVATION_KEY_VALID_UNTIL" \
    --provision-controller \
    --previous-report "$EVIDENCE/preservation-signed-report.json" \
    --report-dir "$REPLACEMENT_REPORT_DIR" \
    --key-id g7-preservation-fixture --deployment-id g7-local --recovery-epoch 1 \
    --storage-generation "$PRESERVATION_STORAGE_GENERATION" --environment local \
    --source-family local --source-account-id g7-local --scope-key all \
    --audit-state-file "$EVIDENCE/replacement-audit-state.json" \
    --metadata-output "$EVIDENCE/preservation-replacement-source-metadata.json" \
    >"$EVIDENCE/preservation-replacement-signed-inventory.stdout" \
    2>"$EVIDENCE/preservation-replacement-signed-inventory.stderr"
  report_source=$(find "$REPLACEMENT_REPORT_DIR" -maxdepth 1 -type f -name '*.json' -print -quit)
  [[ -n $report_source && -f $report_source ]] || {
    echo 'replacement signed report missing after continuity-checked publication' >&2; exit 70;
  }
  install -m 0600 "$report_source" "$EVIDENCE/preservation-replacement-signed-report.json"
  python3 - "$EVIDENCE/preservation-signed-report.json" \
      "$EVIDENCE/preservation-replacement-signed-report.json" \
      "$EVIDENCE/preservation-inventory-continuity.json" <<'PRESERVATIONCONTINUITY'
import hashlib,json,sys
old,new=(json.load(open(path,encoding='utf-8'))['payload'] for path in sys.argv[1:3])
def identities(payload):
    result={}
    for entry in payload['classes']:
        rows=[]
        for member in entry['members']:
            timestamp=member.get('retained_at')
            if timestamp and timestamp.endswith('+00:00'): timestamp=timestamp[:-6]+'Z'
            fields=[member['record_kind'],member['record_key'],member.get('expected_sha256'),
                timestamp,member.get('byte_bearing'),member.get('evidence_id')]
            if entry['class_id']=='product.audit_history':
                fields.extend([member.get('state'),member.get('reasons'),member.get('legacy_payload_sha256'),
                    member.get('canonicalization_version'),member.get('representation_metadata')])
            else:
                fields.append(member['record_sha256'])
            rows.append(fields)
        result[entry['class_id']]=hashlib.sha256(json.dumps(rows,sort_keys=True,
            separators=(',',':')).encode()).hexdigest()
    return result
a,b=identities(old),identities(new)
if (old['snapshot_id']==new['snapshot_id'] or old['storage_generation']==new['storage_generation']
        or old['scope']!=new['scope'] or a!=b):
    raise SystemExit('replacement_inventory_continuity_assertion_failed')
json.dump({'schema_version':1,'old_snapshot_id':old['snapshot_id'],
 'replacement_snapshot_id':new['snapshot_id'],'old_storage_generation':old['storage_generation'],
 'replacement_storage_generation':new['storage_generation'],'member_identity_digests':b,
 'preserved':True},open(sys.argv[3],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PRESERVATIONCONTINUITY
  PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
    node "$ROOT/tools/g7_preservation_live_readback.mjs" \
      --origin "http://127.0.0.1:$API_PORT" \
      --storage-state "$RUN_ROOT/host/preservation-session.json" \
      --previous-readback "$EVIDENCE/preservation-public-readback.json" \
      --output "$EVIDENCE/preservation-replacement-public-readback.json" \
      >"$EVIDENCE/preservation-replacement-public-readback.stdout" \
      2>"$EVIDENCE/preservation-replacement-public-readback.stderr"
  python3 - "$EVIDENCE/preservation-public-readback.json" \
      "$EVIDENCE/preservation-replacement-public-readback.json" \
      "$EVIDENCE/preservation-replacement-comparison.json" \
      <<'PRESERVATIONREPLACEMENT'
import json,sys
before,after=(json.load(open(path,encoding='utf-8')) for path in sys.argv[1:3])
fields=('scope','class_states','class_counts','audit_copy','record_pages','evidence','denied_scope_status','write_methods_observed')
if any(before.get(key)!=after.get(key) for key in fields):
    raise SystemExit('replacement_public_readback_changed')
if before.get('snapshot_id')==after.get('snapshot_id'):
    raise SystemExit('replacement_report_snapshot_not_advanced')
if after.get('write_methods_observed') is not False:
    raise SystemExit('replacement_readback_observed_write')
json.dump({'schema_version':1,'same_snapshot':False,'same_class_states':True,
 'same_audit_union':True,'same_evidence_digest_and_size':True,
 'denied_scope_status':after['denied_scope_status'],'write_methods_observed':False},
 open(sys.argv[3],'w',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PRESERVATIONREPLACEMENT
  CHROMIUM_EXECUTABLE_PATH=/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome \
    node "$ROOT/tools/g7_preservation_browser_handoff.mjs" \
      --origin "http://127.0.0.1:$API_PORT" \
      --storage-state "$RUN_ROOT/host/preservation-session.json" \
      --signed-report "$EVIDENCE/preservation-replacement-signed-report.json" \
      --source-metadata "$EVIDENCE/preservation-replacement-source-metadata.json" \
      --evidence "$EVIDENCE/browser" \
      >"$EVIDENCE/preservation-browser-handoff.stdout" \
      2>"$EVIDENCE/preservation-browser-handoff.stderr"
  echo 'PASS: signed source evidence, deployment audit union and scanner history remained readable after application container replacement' \
    | tee "$EVIDENCE/result.txt"
  exit 0
fi

if (( IS_BACKUP_MODE )); then
  CE_ADMIN_PASSWORD=$(cat "$RUN_ROOT/secrets/ce_admin_password")
  docker exec "$CONTAINER" /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_recovery_retained_fixture.py \
    >"$EVIDENCE/retained-fixture-ids.json"
  python3 - "$RUN_ROOT/g7-ce-recovery-sentinel.json" <<'PYSENTINEL'
import json,sys
json.dump({'name':'G7 Backup Recovery Sentinel','type':'G7 Backup Recovery Fixture',
 'findings':[{'title':'G7 retained CE recovery sentinel','severity':'Low',
  'description':'Synthetic finding imported through DefectDojo public API to prove cold backup and restore retention.',
  'date':__import__('datetime').date.today().isoformat(),'active':True,'verified':False,
  'unique_id_from_tool':'g7-backup-recovery-sentinel-v1'}]},
 open(sys.argv[1],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYSENTINEL
  docker cp "$RUN_ROOT/g7-ce-recovery-sentinel.json" \
    "$CONTAINER:/tmp/g7-ce-recovery-sentinel.json" >/dev/null
  docker exec "$CONTAINER" curl --fail --silent --show-error --max-time 30 -u "admin:$CE_ADMIN_PASSWORD" \
    -F 'scan_type=Generic Findings Import' \
    -F 'product_name=G7 Backup Recovery Evidence' \
    -F 'product_type_name=Research and Development' \
    -F 'engagement_name=G7 Backup Recovery Retention' \
    -F 'auto_create_context=true' -F 'verified=true' -F 'minimum_severity=Info' \
    -F 'close_old_findings=false' -F 'skip_duplicates=true' \
    -F 'file=@/tmp/g7-ce-recovery-sentinel.json;type=application/json' \
    'http://127.0.0.1:8081/api/v2/import-scan/' \
    >"$EVIDENCE/source-ce-import-response.json"
  docker exec "$CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
    'http://127.0.0.1:8081/api/v2/findings/?limit=100' \
    >"$EVIDENCE/source-ce-findings.json"

  FINDING_ID=$(python3 -c 'import json,sys;print(next(f["id"] for f in json.load(open(sys.argv[1]))["results"] if f.get("unique_id_from_tool")=="g7-backup-recovery-sentinel-v1"))' "$EVIDENCE/source-ce-findings.json")
  printf 'Synthetic retained CE media sentinel v1\n' >"$RUN_ROOT/recovery-media.txt"
  docker cp "$RUN_ROOT/recovery-media.txt" "$CONTAINER:/tmp/recovery-media.txt"
  docker exec "$CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
    -F title=g7-recovery-media -F 'file=@/tmp/recovery-media.txt;type=text/plain' \
    "http://127.0.0.1:8081/api/v2/findings/$FINDING_ID/files/" >"$EVIDENCE/source-ce-media-descriptor.json"
  MEDIA_ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$EVIDENCE/source-ce-media-descriptor.json")
  docker exec "$CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
    "http://127.0.0.1:8081/api/v2/findings/$FINDING_ID/files/download/$MEDIA_ID/" >"$EVIDENCE/source-ce-media.txt"
  cmp "$RUN_ROOT/recovery-media.txt" "$EVIDENCE/source-ce-media.txt"
  docker exec "$CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
    'http://127.0.0.1:8081/api/v2/findings/?limit=100' >"$EVIDENCE/source-ce-findings.json"
  python3 - "$EVIDENCE/source-ce-findings.json" "$EVIDENCE/source-ce-public-sentinel.json" <<'PYSOURCECE'
import hashlib,json,sys
document=json.load(open(sys.argv[1],encoding='utf-8'))
results=document.get('results') if isinstance(document,dict) else None
if not isinstance(results,list): raise SystemExit('CE public findings endpoint did not return a results array')
retained=[f for f in results if f.get('unique_id_from_tool')=='g7-backup-recovery-sentinel-v1']
if len(retained)!=1: raise SystemExit('source CE public API did not return exactly one recovery sentinel finding')
encoded=json.dumps(retained,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
json.dump({'count':len(retained),'results_sha256':'sha256:'+hashlib.sha256(encoded).hexdigest()},
 open(sys.argv[2],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYSOURCECE
  ENGAGEMENT_ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["engagement_id"])' "$EVIDENCE/source-ce-import-response.json")
  docker exec "$CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
    "http://127.0.0.1:8081/api/v2/engagements/$ENGAGEMENT_ID/" >"$EVIDENCE/source-ce-engagement.json"
  chmod 600 "$RUN_ROOT/g7-ce-recovery-sentinel.json" "$EVIDENCE/source-ce-import-response.json" \
    "$EVIDENCE/source-ce-findings.json" "$EVIDENCE/source-ce-public-sentinel.json"
fi

if (( EXCEPTION_WARNING_MODE || EXCEPTION_SLA_MODE )); then
  if (( EXCEPTION_WARNING_MODE )); then
  docker exec -e UVM_G7_WARNING_FIXTURE=1 "$CONTAINER" \
    /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_recovery_retained_fixture.py \
    >"$EVIDENCE/warning-fixture-ids.json"
    chmod 0600 "$EVIDENCE/warning-fixture-ids.json"
  else
    docker exec -e UVM_G7_SLA_STAGE=prepolicy "$CONTAINER" \
      /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_recovery_retained_fixture.py \
      >"$EVIDENCE/sla-preactivation-ids.json"
    chmod 0600 "$EVIDENCE/sla-preactivation-ids.json"
    docker exec -e UVM_G7_SLA_STAGE=pre_g7_target "$CONTAINER" \
      /opt/uvm/venv/bin/python /opt/uvm/app/tools/g7_recovery_retained_fixture.py \
      >"$EVIDENCE/sla-g7-target-preactivation-ids.json"
    chmod 0600 "$EVIDENCE/sla-g7-target-preactivation-ids.json"
  fi
fi
uv run python "$ROOT/tools/g7_observer_fixture.py" link-actor --root "$RUN_ROOT" \
  --container "$CONTAINER" \
  >"$EVIDENCE/oidc-link.stdout" 2>"$EVIDENCE/oidc-link.stderr"
if (( EXCEPTION_SLA_MODE )); then
  uv run python "$ROOT/tools/g7_observer_fixture.py" link-exception-approver --root "$RUN_ROOT" \
    --container "$CONTAINER" >"$EVIDENCE/oidc-exception-approver-link.stdout" \
    2>"$EVIDENCE/oidc-exception-approver-link.stderr"
fi
uv run python "$ROOT/tools/g7_observer_fixture.py" host-config --root "$RUN_ROOT" --image "$IMAGE" \
  --anchor-port "$ANCHOR_PORT" --api-port "$API_PORT" --recovery-port "$RECOVERY_PORT" \
  --oidc-port "$OIDC_PROXY_PORT" \
  "${HOST_OIDC_INTERNAL_ARGS[@]}" \
  >"$EVIDENCE/host-config.stdout" 2>"$EVIDENCE/host-config.stderr"
if (( IDENTITY_MODE )); then
  uv run python "$ROOT/tools/g7_observer_fixture.py" link-identity-user --root "$RUN_ROOT" \
    --container "$CONTAINER" >"$EVIDENCE/identity-user-link.stdout" \
    2>"$EVIDENCE/identity-user-link.stderr"
  uv run python "$ROOT/tools/g7_observer_fixture.py" link-identity-deny-user --root "$RUN_ROOT" \
    --container "$CONTAINER" >"$EVIDENCE/identity-deny-user-link.stdout" \
    2>"$EVIDENCE/identity-deny-user-link.stderr"
  docker exec --env UVM_G7_DISPOSABLE_MODE=1 --env UVM_G7_IDENTITY_FIXTURE=1 -i "$CONTAINER" /opt/uvm/venv/bin/python - \
    <"$ROOT/tools/g7_recovery_retained_fixture.py" \
    >"$EVIDENCE/identity-owner-finding-fixture.stdout" \
    2>"$EVIDENCE/identity-owner-finding-fixture.stderr"
  PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
    node "$ROOT/tools/g7_identity_access_ownership_browser.mjs" \
      --origin "http://127.0.0.1:$API_PORT" --evidence "$EVIDENCE" \
      --fixture-root "$RUN_ROOT" --oidc-proxy-port "$OIDC_PROXY_PORT" --app-container "$CONTAINER" \
      >"$EVIDENCE/identity-browser.stdout" 2>"$EVIDENCE/identity-browser.stderr"
  echo 'G7 local identity/access/ownership public lifecycle journey completed' | tee "$EVIDENCE/result.txt"
  exit 0
fi
PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
  node "$ROOT/tools/g7_observer_journey_browser.mjs" \
  --origin "http://127.0.0.1:$API_PORT" --evidence "$EVIDENCE" --fixture-root "$RUN_ROOT" \
  --app-container "$CONTAINER" \
  $([[ $IS_BACKUP_MODE == 1 ]] && printf '%s' '--backup-seed-only') \
  $([[ $EXCEPTION_WARNING_MODE == 1 ]] && printf '%s %s' '--oidc-proxy-port' "$OIDC_PROXY_PORT") \
  $([[ $EXCEPTION_WARNING_MODE == 1 ]] && printf '%s' '--exception-warning-only') \
  $([[ $EXCEPTION_SLA_MODE == 1 ]] && printf '%s %s' '--oidc-proxy-port' "$OIDC_PROXY_PORT") \
  $([[ $EXCEPTION_SLA_MODE == 1 ]] && printf '%s' '--exception-sla-only') \
  >"$EVIDENCE/browser-journey.stdout" 2>"$EVIDENCE/browser-journey.stderr"

# Retain backup settings only in backup recovery modes. Observer and warning
# journeys deliberately revoke or never establish this backup session.
if (( IS_BACKUP_MODE )); then
python3 - "$EVIDENCE/recovery-auth-state.json" "$API_PORT" \
    "$EVIDENCE/source-backup-settings-readback.json" <<'PYSOURCEBACKUPSETTINGS'
import json,sys,urllib.request
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
cookie=next(c['value'] for c in state['cookies'] if c['name']=='uvm_session' and c['domain']=='127.0.0.1')
request=urllib.request.Request(f'http://127.0.0.1:{int(sys.argv[2])}/api/v1/operations/backup-settings/g7-local',
    headers={'Cookie':'uvm_session='+cookie})
with urllib.request.urlopen(request,timeout=15) as response:
    value=json.load(response)
if not isinstance(value.get('desired'),dict) or not isinstance(value.get('status'),dict):
    raise SystemExit('source backup-settings readback is incomplete')
Path(sys.argv[3]).write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PYSOURCEBACKUPSETTINGS
fi

if (( EXCEPTION_WARNING_MODE )); then
  for _ in $(seq 1 45); do
    if [[ -s "$RUN_ROOT/warning/provider-captures.json" ]] && python3 - "$RUN_ROOT/warning/provider-captures.json" <<'WARMCAPTUREREADY'
import json,sys
rows=json.load(open(sys.argv[1],encoding='utf-8'))
raise SystemExit(0 if {row.get('payload',{}).get('channel') for row in rows} >=
    {'C_FIXTURE_SUCCESS','C_FIXTURE_FAILED','C_FIXTURE_UNCERTAIN'} else 1)
WARMCAPTUREREADY
    then break; fi
    sleep 1
  done
  [[ -s "$RUN_ROOT/warning/provider-captures.json" ]] || {
    echo 'warning worker produced no loopback Slack provider request' >&2; exit 70;
  }
  python3 - "$RUN_ROOT/warning/provider-captures.json" "$EVIDENCE/provider-captures.json" \
      "$EVIDENCE/provider-capture-redaction.json" <<'REDACTPROVIDER'
import copy,hashlib,json,sys
source=json.load(open(sys.argv[1],encoding='utf-8'))
rows=copy.deepcopy(source)
proof=[]
for row in rows:
    payload=row.get('payload',{})
    blocks=payload.get('blocks',[])
    if len(blocks)<2 or not blocks[1].get('elements'):
        continue
    action=blocks[1]['elements'][0]
    token=action.get('value')
    if not isinstance(token,str) or not token:
        raise SystemExit('captured Slack acknowledgement action lacks its opaque value')
    digest=hashlib.sha256(token.encode()).hexdigest()
    action['value']='sha256:'+digest
    row['action_value_redacted']=True
    proof.append({'channel':payload.get('channel'),'action_value_sha256':digest})
if not proof:
    raise SystemExit('no Slack acknowledgement actions were available for safe evidence')
json.dump(rows,open(sys.argv[2],'w',encoding='utf-8'),sort_keys=True,separators=(',',':'))
json.dump({'redacted_action_values':len(proof),'proof':proof},
    open(sys.argv[3],'w',encoding='utf-8'),sort_keys=True,separators=(',',':'))
for path in sys.argv[2:]:
    import os
    os.chmod(path,0o600)
REDACTPROVIDER
  [[ -s "$RUN_ROOT/warning/smtp-captures.json" ]] || {
    echo 'warning worker produced no loopback SMTP fixture exchange' >&2; exit 70;
  }
  cp "$RUN_ROOT/warning/smtp-captures.json" "$EVIDENCE/smtp-captures.json"
  python3 - "$EVIDENCE/smtp-captures.json" <<'SMTPCAPTURE'
import json,sys
rows=json.load(open(sys.argv[1],encoding='utf-8'))
by_recipient={}
for row in rows: by_recipient.setdefault(row.get('recipient'),[]).append(row)
if len(by_recipient.get('accepted@fixture.invalid',[]))!=1 or \
        by_recipient['accepted@fixture.invalid'][0].get('result')!='accepted':
    raise SystemExit('SMTP fixture did not capture one accepted submission')
retry=by_recipient.get('retry@fixture.invalid',[])
if len(retry)!=2 or [row.get('result') for row in retry] != [
        'temporary_rcpt_rejection','accepted']:
    raise SystemExit('SMTP fixture did not capture exactly one confirmed rejection and one accepted retry')
uncertain=by_recipient.get('uncertain@fixture.invalid',[])
if len(uncertain)!=1 or uncertain[0].get('result')!='connection_lost_after_data':
    raise SystemExit('SMTP fixture did not capture exactly one post-DATA ambiguous exchange')
predata=by_recipient.get('predatadisconnect@fixture.invalid',[])
if len(predata)!=2 or [row.get('result') for row in predata] != [
        'connection_lost_before_data','accepted']:
    raise SystemExit('SMTP fixture did not capture a safe pre-DATA disconnect and same-destination retry')
if any(row.get('authenticated') is not True for row in rows):
    raise SystemExit('SMTP fixture received a submission without the synthetic credential')
if retry[0].get('sender') != 'from:<uvm@fixture.invalid>' or \
        retry[1].get('sender') != retry[0].get('sender'):
    raise SystemExit('SMTP retry changed the approved sender identity')
if retry[1].get('message_id') is None or retry[1].get('byte_count',0) <= 0:
    raise SystemExit('SMTP accepted retry lacks message identity or message bytes')
SMTPCAPTURE
  python3 - "$EVIDENCE/warning-smtp-retry-proof.json" <<'SMTPIDENTITY'
import json,sys
proof=json.load(open(sys.argv[1],encoding='utf-8'))
retry=proof['retry_exchange']
if retry[1]['message_id'] != proof['retried_intent']['attempts'][1]['receipt'].split('|',2)[2]:
    raise SystemExit('durable SMTP acceptance receipt does not match captured Message-ID')
if proof['retried_intent']['retry']['attempts'] != 2:
    raise SystemExit('public warning readback does not show exactly two attempts for the retained intent')
SMTPIDENTITY
  python3 - "$EVIDENCE/warning-smtp-retry-proof.json" <<'PREDATAIDENTITY'
import json,sys
proof=json.load(open(sys.argv[1],encoding='utf-8'))
rows=proof['pre_data_exchange']; intent=proof['pre_data_retried_intent']
if rows[1]['message_id'] != intent['attempts'][1]['receipt'].split('|',2)[2]:
    raise SystemExit('pre-DATA retry receipt does not match captured SMTP Message-ID')
if [item['outcome'] for item in intent['attempts']] != ['failed','sent'] or \
        [item['attempt_number'] for item in intent['attempts']] != [1,2]:
    raise SystemExit('pre-DATA retry did not preserve the failed attempt and bounded second attempt')
PREDATAIDENTITY
  python3 - "$RUN_ROOT/warning/provider-captures.json" <<'WARNACCEPT'
import json,sys
rows=json.load(open(sys.argv[1],encoding='utf-8'))
channels={row.get('payload',{}).get('channel') for row in rows}
if channels!={'C_FIXTURE_SUCCESS','C_FIXTURE_FAILED','C_FIXTURE_UNCERTAIN'}:
    raise SystemExit(f'provider requests did not cover all synthetic outcomes: {channels}')
if any(row.get('authorization_verified') is not True for row in rows):
    raise SystemExit('provider fixture received a request with an invalid synthetic credential')
payload=next(row['payload'] for row in rows if row['payload']['channel']=='C_FIXTURE_SUCCESS')
if not payload.get('blocks'):
    raise SystemExit('captured provider payload does not include the approved acknowledgement action')
action=payload['blocks'][1]['elements'][0]
if action.get('action_id')!='uvm_warning_ack' or not action.get('value'):
    raise SystemExit('captured Slack acknowledgement action is incomplete')
WARNACCEPT
  echo 'G7 exception warning public worker reached Slack provider acceptance and SMTP submission, rejection, retry and held-uncertain outcomes' | tee "$EVIDENCE/result.txt"
  exit 0
fi


if (( IS_BACKUP_MODE )); then
  for role in observer supervisor controller; do
    uv run python "$ROOT/tools/g7_observer_fixture.py" host-control --root "$RUN_ROOT" \
      --role "$role" --action terminate >"$EVIDENCE/host-$role-fence-stop.stdout" 2>"$EVIDENCE/host-$role-fence-stop.stderr"
  done


  NETWORKS_JSON=$(docker inspect "$CONTAINER" --format '{{json .NetworkSettings.Networks}}')
  mapfile -t ATTACHED_NETWORKS < <(NETWORKS_JSON="$NETWORKS_JSON" python3 -c 'import json,os; print("\n".join(json.loads(os.environ["NETWORKS_JSON"])))')
  [[ ${#ATTACHED_NETWORKS[@]} == 1 && -n ${ATTACHED_NETWORKS[0]} ]] || {
    echo 'recovery fence requires exactly one removable container network endpoint' >&2; exit 2;
  }
  FENCE_NETWORK=${ATTACHED_NETWORKS[0]}
  FENCE_NETWORK_ID=$(docker network inspect "$FENCE_NETWORK" --format '{{.Id}}')
  docker network disconnect "$FENCE_NETWORK" "$CONTAINER" >"$EVIDENCE/network-disconnect.stdout" 2>"$EVIDENCE/network-disconnect.stderr"
  if (( UPGRADE_ROLLBACK_MODE )); then phase_mark outage_start; fi
  NETWORKS_JSON=$(docker inspect "$CONTAINER" --format '{{json .NetworkSettings.Networks}}')
  [[ $(NETWORKS_JSON="$NETWORKS_JSON" python3 -c 'import json,os; print(len(json.loads(os.environ["NETWORKS_JSON"])))') == 0 ]] || {
    echo 'host network endpoint removal was not confirmed' >&2; exit 2;
  }
  for port in 8000 8002 9000 "$OIDC_PORT"; do
    if curl --connect-timeout 2 --max-time 3 --silent --show-error "http://127.0.0.1:$port/" >/dev/null 2>&1; then
      echo "host ingress fence failed for loopback port $port" >&2; exit 2
    fi
  done
  SOCKET_FENCE=$(docker exec "$CONTAINER" /opt/uvm/venv/bin/python -c 'import json; out={"established_external_tcp":0,"established_external_udp":0,"socket_files":[]}; loop={"0100007F","00000000000000000000000001000000"};
for p,kind in (("/proc/net/tcp","tcp"),("/proc/net/tcp6","tcp"),("/proc/net/udp","udp"),("/proc/net/udp6","udp")):
 try:
  rows=open(p).read().splitlines()[1:]; out["socket_files"].append(p)
  for row in rows:
   cols=row.split()
   if len(cols)>3 and cols[3]=="01" and cols[2].split(":")[0].upper() not in loop: out["established_external_"+kind]+=1
 except OSError: pass
print(json.dumps(out,sort_keys=True))')
  printf '%s\n' "$SOCKET_FENCE" >"$EVIDENCE/existing-connection-fence.json"
  [[ $(python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print(int(r["established_external_tcp"])+int(r["established_external_udp"]))' "$SOCKET_FENCE") == 0 ]] || {
    echo 'existing non-loopback TCP/UDP connections remain after network endpoint removal' >&2; exit 2;
  }
  FENCE_CONTAINER_ID=$(docker inspect "$CONTAINER" --format '{{.Id}}')
  FENCE_IMAGE_ID=$(docker inspect "$CONTAINER" --format '{{.Image}}')
  FENCE_NETWORK_NAME=$FENCE_NETWORK FENCE_NETWORK_ID=$FENCE_NETWORK_ID \
    FENCE_CONTAINER_ID=$FENCE_CONTAINER_ID FENCE_IMAGE_ID=$FENCE_IMAGE_ID OIDC_PORT=$OIDC_PORT \
    python3 - "$EVIDENCE/ingress-egress-fence.json" <<'PYFENCE'
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path
record={"schema_version":1,"network_name":os.environ["FENCE_NETWORK_NAME"],
"network_id":os.environ["FENCE_NETWORK_ID"],"container_id":os.environ["FENCE_CONTAINER_ID"],
"image_id":os.environ["FENCE_IMAGE_ID"],"endpoint_removed":True,
"loopback_listener_probes_blocked":[8000,8002,9000],"alternate_oidc_backend_port":int(os.environ['OIDC_PORT']),
"alternate_oidc_backend_probe_blocked":True,"existing_external_tcp_count":0,
"existing_external_udp_count":0,
"fenced_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
Path(sys.argv[1]).write_text(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
PYFENCE
  start_operation_deadline capture
  ENTRYPOINT_PID=$(docker exec "$CONTAINER" cat /run/uvm-g7/entrypoint-pid)
  docker exec "$CONTAINER" kill -USR1 "$ENTRYPOINT_PID"
  writers_stopped=0
  for _ in $(seq 1 300); do
    if docker exec "$CONTAINER" test -e /run/uvm-g7/quiesce-writers-stopped >/dev/null 2>&1; then writers_stopped=1; break; fi
    if [[ $(docker inspect "$CONTAINER" --format '{{.State.Running}}') != true ]]; then break; fi
    sleep 1
  done
  (( writers_stopped )) || { echo 'supervisor did not acknowledge staged writer stop' >&2; exit 2; }
  if (( UPGRADE_ROLLBACK_MODE )); then
    docker cp "$ROOT/tools/g7_product_inventory.py" "$CONTAINER:/tmp/g7_product_inventory.py"
    docker exec "$CONTAINER" /opt/uvm/venv/bin/python /tmp/g7_product_inventory.py --output /tmp/source-product-inventory.json
    docker cp "$CONTAINER:/tmp/source-product-inventory.json" "$EVIDENCE/source-product-inventory.json"
    chmod 600 "$EVIDENCE/source-product-inventory.json"
  fi
  uv run python "$ROOT/tools/g7_backup_recovery.py" observe-queue \
    --container "$CONTAINER" --output "$EVIDENCE/queue-observation.json" \
    --network-fenced --writers-stopped \
    >"$EVIDENCE/queue-observation.stdout" 2>"$EVIDENCE/queue-observation.stderr"
  cp "$EVIDENCE/queue-observation.json" "$EVIDENCE/pre-stop-queue-inventory.json"
  if [[ $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["unresolved"]))' "$EVIDENCE/queue-observation.json") != 0 ]]; then
    echo 'G7 recovery-only source seed completed; staged fence is active but queue/effect inventory is unresolved' | tee "$EVIDENCE/result.txt"
    exit 2
  fi
  docker exec "$CONTAINER" touch /run/uvm-g7/quiesce-drain-complete
  services_stopped=0
  for _ in $(seq 1 300); do
    if docker exec "$CONTAINER" test -e /run/uvm-g7/quiesce-services-stopped >/dev/null 2>&1; then services_stopped=1; break; fi
    if [[ $(docker inspect "$CONTAINER" --format '{{.State.Running}}') != true ]]; then break; fi
    sleep 1
  done
  (( services_stopped )) || { echo 'supervisor did not acknowledge clean worker/database stop' >&2; exit 2; }
  docker logs "$CONTAINER" 2>&1 | sed -E \
    "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
    >"$EVIDENCE/quiesce-supervisor-redacted.log"
  docker exec -u 0 "$CONTAINER" chmod -R a+rwX /run/uvm-g7-scheduler
  docker exec "$CONTAINER" touch /run/uvm-g7/quiesce-capture-release
  exited=0
  for _ in $(seq 1 30); do
    if [[ $(docker inspect "$CONTAINER" --format '{{.State.Running}}' 2>/dev/null) != true ]]; then exited=1; break; fi
    sleep 1
  done
  (( exited )) || { echo 'source container did not complete the staged shutdown' >&2; exit 2; }
  docker logs "$CONTAINER" 2>&1 | sed -E \
    "s/(Webhook Secret:[[:space:]]*)[[:alnum:]-]+/\\1[redacted]/Ig; s/(PASSWORD[[:space:]]+')([^']+)(')/\\1[redacted]\\3/Ig; s/([[:alnum:]_-]*(PASSWORD|SECRET|TOKEN|KEY)[[:alnum:]_-]*[:=][[:space:]]*)[^[:space:]]+/\\1[redacted]/Ig" \
    >"$EVIDENCE/quiesce-supervisor-redacted.log"
  uv run python "$ROOT/tools/g7_backup_recovery.py" sign-drain-proof \
    --container "$CONTAINER" --deployment-id g7-local --key-id g7-host-controller-key \
    --signing-key "$RUN_ROOT/host/ed25519.pem" \
    --queue-inventory "$EVIDENCE/queue-observation.json" \
    --network-fence "$EVIDENCE/ingress-egress-fence.json" \
    --supervisor-log "$EVIDENCE/quiesce-supervisor-redacted.log" \
    --output "$EVIDENCE/signed-drain-proof.json" \
    >"$EVIDENCE/drain-proof.stdout" 2>"$EVIDENCE/drain-proof.stderr"
  IMAGE_DIGEST=$(docker inspect "$CONTAINER" --format '{{.Image}}')
  if (( UPGRADE_ROLLBACK_MODE )); then printf '%s\n' "$IMAGE_DIGEST" >"$EVIDENCE/image-a-id.txt"; fi
  PACKAGE_DIGEST=$(python3 - <<'PYPKG'
import hashlib
from pathlib import Path
h=hashlib.sha256()
for name in ('pyproject.toml','uv.lock'):
 p=Path(name); h.update(name.encode()+b'\0'+p.read_bytes()+b'\0')
print('sha256:'+h.hexdigest())
PYPKG
)
  if (( ! UPGRADE_ROLLBACK_MODE )); then RESTORE_IMAGE_DIGEST=$IMAGE_DIGEST; fi
  SETTINGS_DIGEST=$(python3 - "$EVIDENCE/backup-seed-readback.json" <<'PYSET'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['effective_digest'])
PYSET
)
  POLICY_DIGEST=$(python3 - "$RUN_ROOT/host/backup-policy.json" <<'PYPOL'
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8'))['digest'])
PYPOL
)
  ARCHIVE_DIR="$RUN_ROOT/host/backup/archive"
  python3 - "$RUN_ROOT" "$ARCHIVE_DIR" <<'PYARCHIVE'
from pathlib import Path
import sys
run_root = Path(sys.argv[1]).resolve(strict=True)
archive_dir = Path(sys.argv[2]).resolve(strict=False)
try:
    archive_dir.relative_to(run_root)
except ValueError:
    raise SystemExit("archive directory escapes the run-owned temporary root")
if archive_dir == run_root:
    raise SystemExit("archive directory must be below the run-owned temporary root")
PYARCHIVE
  [[ ! -e $ARCHIVE_DIR && ! -L $ARCHIVE_DIR ]] || {
    echo 'archive destination already exists inside the run-owned path' >&2; exit 2;
  }
  mkdir -p -m 700 "$(dirname "$ARCHIVE_DIR")"
  uv run python "$ROOT/tools/g7_backup_recovery.py" capture \
    --container "$CONTAINER" --deployment-id g7-local \
    --archive-dir "$ARCHIVE_DIR" \
    --drain-proof "$EVIDENCE/signed-drain-proof.json" \
    --public-key "$RUN_ROOT/secrets/host-pub.pem" \
    --signing-key "$RUN_ROOT/host/ed25519.pem" \
    --key-id g7-host-controller-key --generation 1 --recovery-epoch 0 \
    --settings-revision "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["effective_revision"])' "$EVIDENCE/backup-seed-readback.json")" --settings-digest "$SETTINGS_DIGEST" \
    --host-policy-revision 1 --host-policy-digest "$POLICY_DIGEST" \
    --controller-instance-id 00000000-0000-4000-8000-000000000017 \
    --controller-sequence "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["last_sequence"])' "$RUN_ROOT/host/state/backup/controller-journal.json")" --package-manifest-digest "$PACKAGE_DIGEST" \
    --deadline-file "$ACTIVE_DEADLINE" \
    --stop-timeout "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["capture_timeout_seconds"])' "$RUN_ROOT/host/state/backup/capture-request.json")" \
    --consumer-state "$RUN_ROOT/host/state/backup/capture-request.json" \
    --helper-image "$IMAGE" >"$EVIDENCE/capture.stdout" 2>"$EVIDENCE/capture.stderr"
  finish_operation_deadline capture
  cp "$RUN_ROOT/host/state/backup/scheduler-readback.json" "$EVIDENCE/backup-scheduler-readback.json"
  cp "$RUN_ROOT/host/state/backup/capture-request.json" "$EVIDENCE/backup-capture-request.json"
  cp -a "$ARCHIVE_DIR" "$EVIDENCE/archive"
  uv run python "$ROOT/tools/g7_backup_recovery.py" verify \
    --archive-dir "$EVIDENCE/archive" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
    --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
    --package-manifest-digest "$PACKAGE_DIGEST" --expected-key-id g7-host-controller-key \
    >"$EVIDENCE/archive-verify.stdout" 2>"$EVIDENCE/archive-verify.stderr"
  for NEGATIVE_CASE in missing-member corrupt-member; do
    NEGATIVE_ARCHIVE="$EVIDENCE/archive-negative-$NEGATIVE_CASE"
    cp -a "$EVIDENCE/archive" "$NEGATIVE_ARCHIVE"
    if [[ $NEGATIVE_CASE == missing-member ]]; then
      rm -- "$NEGATIVE_ARCHIVE/ce_media.tar.gz"
    else
      python3 - "$NEGATIVE_ARCHIVE/ce_media.tar.gz" <<'PYTAMPER'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = path.read_bytes()
if not data:
    raise SystemExit("cannot corrupt an empty archive member")
path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
PYTAMPER
    fi
    phase_mark upgrade_start
    set +e
    uv run python "$ROOT/tools/g7_backup_recovery.py" verify \
      --archive-dir "$NEGATIVE_ARCHIVE" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
      --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
      --package-manifest-digest "$PACKAGE_DIGEST" --expected-key-id g7-host-controller-key \
      >"$EVIDENCE/archive-$NEGATIVE_CASE.stdout" 2>"$EVIDENCE/archive-$NEGATIVE_CASE.stderr"
    NEGATIVE_EXIT=$?
    set -e
    printf '%s\n' "$NEGATIVE_EXIT" >"$EVIDENCE/archive-$NEGATIVE_CASE.exit"
    if (( NEGATIVE_EXIT == 0 )); then
      echo "archive verifier accepted $NEGATIVE_CASE" >&2
      exit 1
    fi
  done
  start_operation_deadline verification
  RESTORE_VOLUMES_RAW="$EVIDENCE/replacement-volumes.stdout.json"
  RECOVERY_EPOCH=1
  CONNECTOR_RECOVERY_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
  uv run python "$ROOT/tools/g7_backup_recovery.py" restore \
    --archive-dir "$EVIDENCE/archive" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
    --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
    --package-manifest-digest "$PACKAGE_DIGEST" --expected-key-id g7-host-controller-key \
    --helper-image "$IMAGE" --name-prefix "volt-g7-r26" \
    --host-journal "$RUN_ROOT/host/state/backup/controller-journal.json" \
    --recovery-epoch "$RECOVERY_EPOCH" >"$RESTORE_VOLUMES_RAW" 2>"$EVIDENCE/restore-volumes.stderr"
  python3 - "$RESTORE_VOLUMES_RAW" "$EVIDENCE/replacement-volume-ids.json" <<'PYVOLUMES'
import json,sys
source=json.load(open(sys.argv[1],encoding='utf-8'))
volumes=source.get('replacement_volumes')
if not isinstance(volumes,dict) or set(volumes)!={'postgres_cluster','ce_media','uvm_state'}:
 raise SystemExit('restore helper did not return the exact replacement volume set')
json.dump(volumes,open(sys.argv[2],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYVOLUMES
  RESTORE_VOLUMES_JSON="$EVIDENCE/replacement-volume-ids.json"
  if (( UPGRADE_ROLLBACK_MODE )); then UPGRADE_VOLUMES_JSON="$RESTORE_VOLUMES_JSON"; fi
  ARCHIVE_DIGEST=$(sha256sum "$EVIDENCE/archive/manifest.json" | awk '{print "sha256:"$1}')
  if (( UPGRADE_ROLLBACK_MODE )); then
    python3 - "$RESTORE_VOLUMES_JSON" "$EVIDENCE/schema-compatibility-admission-input.json" \
      "$IMAGE_DIGEST" "$SOURCE_PACKAGE_DIGEST" "$RESTORE_IMAGE_DIGEST" "$CANDIDATE_PACKAGE_DIGEST" \
      "$ARCHIVE_DIGEST" "$RECOVERY_EPOCH" <<'PYADMISSION'
import json,sys,uuid
volumes=json.load(open(sys.argv[1],encoding='utf-8'))
admission={'admission_id':str(uuid.uuid4()),'recovery_epoch':int(sys.argv[8]),
 'source_image_digest':sys.argv[3],'source_package_manifest_digest':sys.argv[4],
 'target_image_digest':sys.argv[5],'target_package_manifest_digest':sys.argv[6],
 'archive_digest':sys.argv[7],'from_schema':'0058','to_schema':'0062','volume_ids':volumes}
json.dump(admission,open(sys.argv[2],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYADMISSION
    uv run python "$ROOT/tools/g7_backup_controller.py" --config "$RUN_ROOT/host/backup-controller.json" \
      --schema-compatibility-admission-json "$EVIDENCE/schema-compatibility-admission-input.json" \
      >"$EVIDENCE/schema-compatibility-admission.json"
    python3 - "$EVIDENCE/schema-compatibility-admission-input.json" "$EVIDENCE/schema-compatibility-admission.json" <<'PYADMISSIONACK'
import json,sys
if json.load(open(sys.argv[1],encoding='utf-8')) != json.load(open(sys.argv[2],encoding='utf-8')):
 raise SystemExit('host journal changed the exact compatibility admission record')
PYADMISSIONACK
    COMPATIBILITY_ADMISSION_ARGS=(--compatibility-admission-json "$EVIDENCE/schema-compatibility-admission.json")
  else
    COMPATIBILITY_ADMISSION_ARGS=()
  fi
  uv run python "$ROOT/tools/g7_backup_recovery.py" startup-token \
    --deployment-id g7-local --image-digest "$RESTORE_IMAGE_DIGEST" \
    --volume-ids-json "$RESTORE_VOLUMES_JSON" --archive-digest "$ARCHIVE_DIGEST" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
    "${COMPATIBILITY_ADMISSION_ARGS[@]}" \
    --key-id g7-host-controller-key --signing-key "$RUN_ROOT/host/ed25519.pem" \
    --output "$RUN_ROOT/secrets/startup-fence.json" >"$EVIDENCE/startup-token.stdout" \
    2>"$EVIDENCE/startup-token.stderr"
  RECOVERY_NETWORK="volt-g7-recovery-$RANDOM"
  docker network create --label uvm.g7.backup-recovery=true "$RECOVERY_NETWORK" \
    >"$EVIDENCE/recovery-network-id.txt"
  RECOVERY_NETWORK_ID=$(cat "$EVIDENCE/recovery-network-id.txt")
  NETWORK_INSPECT=$(docker network inspect "$RECOVERY_NETWORK")
  RESTORE_IP=$(NETWORK_INSPECT="$NETWORK_INSPECT" python3 - <<'PYIP'
import ipaddress,json,os
network=json.loads(os.environ['NETWORK_INSPECT'])[0]
config=network['IPAM']['Config']
if len(config)!=1: raise SystemExit('recovery network must have exactly one IPv4 subnet')
subnet=ipaddress.ip_network(config[0]['Subnet'])
gateway=ipaddress.ip_address(config[0]['Gateway'])
if subnet.version!=4 or gateway not in subnet: raise SystemExit('recovery bridge IPv4 subnet is invalid')
candidate=gateway+1
if candidate not in subnet: raise SystemExit('recovery bridge has no deterministic replacement address')
print(candidate)
PYIP
)
  RESTORE_STARTED=1
  docker run -d --name "$RESTORE_CONTAINER" --label uvm.g7.backup-recovery=true \
    --network "$RECOVERY_NETWORK" --ip "$RESTORE_IP" --cap-add NET_ADMIN \
    --mount "type=bind,src=$ROOT/tools/g7_runtime_egress_fence.py,dst=/tmp/g7_runtime_egress_fence.py,readonly" \
    --mount "type=bind,src=$ROOT/tools/g7_fenced_entrypoint.sh,dst=/tmp/g7_fenced_entrypoint.sh,readonly" \
    --entrypoint /bin/bash \
    -p 127.0.0.1:8000:8000 -p 127.0.0.1:8002:8002 -p "127.0.0.1:$OIDC_PORT:9000" \
    --mount "type=bind,src=$RUN_ROOT/secrets,dst=/run/secrets,readonly" \
    --mount "type=bind,src=$RUN_ROOT/secrets/registry.json,dst=/run/uvm-g7-registry.json,readonly" \
    --mount "type=bind,src=$RUN_ROOT/secrets/host-pub.pem,dst=/run/uvm-g7-host-pub.pem,readonly" \
    --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/run/uvm-g7-scheduler" \
    --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["postgres_cluster"])' "$RESTORE_VOLUMES_JSON"),dst=/var/lib/postgresql/data" \
    --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ce_media"])' "$RESTORE_VOLUMES_JSON"),dst=/app/media" \
    --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["uvm_state"])' "$RESTORE_VOLUMES_JSON"),dst=/opt/uvm/state" \
    --env-file "$RUN_ROOT/container.env" \
    --env UVM_G7_VERIFICATION_ONLY=1 --env UVM_G7_RECOVERY_STAGE=control-only \
    --env UVM_AUTH_MODE=oidc \
    --env UVM_G7_STARTUP_FENCE_TOKEN=/run/secrets/startup-fence.json \
    --env UVM_G7_HOST_PUBLIC_KEY_FILE=/run/secrets/host-pub.pem \
    --env UVM_G7_DEPLOYMENT_ID=g7-local --env UVM_G7_TARGET_IMAGE_DIGEST="$RESTORE_IMAGE_DIGEST" \
    --env UVM_G7_RECOVERY_VOLUME_IDS="$(cat "$RESTORE_VOLUMES_JSON")" \
    --env UVM_G7_ARCHIVE_DIGEST="$ARCHIVE_DIGEST" --env UVM_G7_RECOVERY_EPOCH="$RECOVERY_EPOCH" \
    --env UVM_G7_CONNECTOR_RECOVERY_ID="$CONNECTOR_RECOVERY_ID" \
    "${SCHEMA_MODE_ARGS[@]}" \
    "$RESTORE_IMAGE" /tmp/g7_fenced_entrypoint.sh \
    >"$EVIDENCE/restore-container-id.txt"
  RESTORE_CONTAINER_ID=$(cat "$EVIDENCE/restore-container-id.txt")
  restore_control_ready=0
  for _ in $(seq 1 300); do
    if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == healthy ]]; then
      restore_control_ready=1; break
    fi
    if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Status}}' 2>/dev/null) != running ]]; then break; fi
    sleep 2
  done
  (( restore_control_ready )) || { echo 'replacement did not become healthy in control-only recovery mode' >&2; exit 2; }
  docker exec "$RESTORE_CONTAINER" cat /run/g7-runtime-egress-fence.json >"$EVIDENCE/b-startup-egress-fence.json"
  docker exec "$RESTORE_CONTAINER" /opt/uvm/venv/bin/python /tmp/g7_runtime_egress_fence.py --verify >"$EVIDENCE/b-before-admission-egress-fence.json"
  uv run python "$ROOT/tools/g7_backup_recovery.py" admit-restore \
    --config "$RUN_ROOT/host/backup-controller.json" \
    --manifest "$EVIDENCE/archive/manifest.json" --volume-ids "$RESTORE_VOLUMES_JSON" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
    --drain-proof "$EVIDENCE/signed-drain-proof.json" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
    --target-image-digest "$RESTORE_IMAGE_DIGEST" \
    >"$EVIDENCE/restore-event-acks.json" 2>"$EVIDENCE/restore-event-acks.stderr"
  cp "$RUN_ROOT/host/state/backup/controller-journal.json" "$EVIDENCE/before-replay-controller-journal.json"
  uv run python "$ROOT/tools/g7_backup_recovery.py" admit-restore \
    --config "$RUN_ROOT/host/backup-controller.json" \
    --manifest "$EVIDENCE/archive/manifest.json" --volume-ids "$RESTORE_VOLUMES_JSON" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
    --drain-proof "$EVIDENCE/signed-drain-proof.json" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
    --target-image-digest "$RESTORE_IMAGE_DIGEST" \
    >"$EVIDENCE/restore-event-replay-acks.json" 2>"$EVIDENCE/restore-event-replay-acks.stderr"
  python3 - "$EVIDENCE" "$RUN_ROOT/host/state/backup/controller-journal.json" <<'PYEXACTREPLAY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1]); original=json.loads((root/'restore-event-acks.json').read_text())
replay=json.loads((root/'restore-event-replay-acks.json').read_text())
assert original == replay, 'restore replay changed a retained stage acknowledgement'
assert [event['current_state'] for event in replay['events']] == ['started','restored']
assert replay['events'][0]['event_id'] != replay['events'][1]['event_id']
assert (root/'before-replay-controller-journal.json').read_bytes() == Path(sys.argv[2]).read_bytes()
(root/'exact-stage-replay-proof.json').write_text(json.dumps({'passed':True,'stage_ack_ids':[v['event_id'] for v in replay['events']],'journal_unchanged':True},sort_keys=True))
PYEXACTREPLAY
  if (( UPGRADE_ROLLBACK_MODE )); then
    # Refresh the short-lived signed startup context after host restore work,
    # then advance its authenticated resync before checking the restored gate.
    rm "$RUN_ROOT/secrets/startup-fence.json"
    uv run python "$ROOT/tools/g7_backup_recovery.py" startup-token \
      --deployment-id g7-local --image-digest "$RESTORE_IMAGE_DIGEST" \
      --volume-ids-json "$RESTORE_VOLUMES_JSON" --archive-digest "$ARCHIVE_DIGEST" \
      --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
      "${COMPATIBILITY_ADMISSION_ARGS[@]}" \
      --key-id g7-host-controller-key --signing-key "$RUN_ROOT/host/ed25519.pem" \
      --output "$RUN_ROOT/secrets/startup-fence.json" >"$EVIDENCE/pre-migration-startup-token.stdout"
    # Controller resync timestamps are second precision; leave one full second
    # so its authenticated checkpoint is never older than this token's
    # microsecond-precision issued_at value.
    sleep 1
    CURRENT_SEQUENCE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["last_sequence"])' "$RUN_ROOT/host/state/backup/controller-journal.json")
    uv run python "$ROOT/tools/g7_backup_controller.py" --config "$RUN_ROOT/host/backup-controller.json" \
      --resync-database-epoch "$RECOVERY_EPOCH" --resync-database-sequence "$CURRENT_SEQUENCE" \
      --resync-checkpoint-epoch "$RECOVERY_EPOCH" --force-resync \
      >"$EVIDENCE/pre-migration-resync.json"
    docker restart "$RESTORE_CONTAINER" >"$EVIDENCE/pre-migration-restart.stdout"
    pre_migration_control_ready=0
    for _ in $(seq 1 90); do
      if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == healthy ]]; then
        pre_migration_control_ready=1; break
      fi
      if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Running}}' 2>/dev/null) != true ]]; then break; fi
      sleep 1
    done
    (( pre_migration_control_ready )) || { echo 'refreshed current-image control-only restore did not become healthy' >&2; exit 2; }
  fi
  if (( UPGRADE_ROLLBACK_MODE )); then
  docker exec "$RESTORE_CONTAINER" bash -lc 'test "$(cat /run/uvm-g7/runtime-mode)" = control'
  docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-api
  docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-web
  docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-worker
  docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-beat
  docker exec "$RESTORE_CONTAINER" cat /run/uvm-g7/schema-migration-gate-query.stderr \
    >"$EVIDENCE/pre-migration-reader-gate.stderr" 2>/dev/null || :
  docker exec "$RESTORE_CONTAINER" bash -lc \
    'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; exec /opt/uvm/venv/bin/python -m uvm.operations.startup_fence --check-admission' \
    >"$EVIDENCE/pre-migration-restored-context.json"
  for probe in uvm_api:8000 ce_api:8081; do
    probe_name=${probe%%:*}; probe_port=${probe##*:}
    set +e
    uv run python -m tools.g7_listener_probe "$RESTORE_CONTAINER" "$probe_port" \
      >"$EVIDENCE/pre-migration-listener-$probe_name.stdout" \
      2>"$EVIDENCE/pre-migration-listener-$probe_name.stderr"
    probe_exit=$?
    set -e
    printf '%s\n' "$probe_exit" >"$EVIDENCE/pre-migration-listener-$probe_name.exit"
    (( probe_exit == 0 )) || { echo "listener probe failed for $probe_name" >&2; exit 2; }
  done
  python3 - "$RESTORE_CONTAINER" "$EVIDENCE" <<'PYCONTROLONLY'
import json,sys
from pathlib import Path
container,root=sys.argv[1:]; root=Path(root); ports={}
for name in ('uvm_api','ce_api'):
 value=json.loads((root/f'pre-migration-listener-{name}.stdout').read_text())
 ports[name]={'listener_open':value['listener']=='open','probe_exit':int((root/f'pre-migration-listener-{name}.exit').read_text())}
if any(v['listener_open'] for v in ports.values()): raise SystemExit('product listener opened before admitted migration')
json.dump({'passed':True,'runtime_mode':'control','product_listeners':ports,
 'product_api_pid_absent':True,'ce_web_pid_absent':True,'workers_absent':True,
 'restored_context_verified':True},open(root/'pre-migration-control-only.json','x'),sort_keys=True,separators=(',',':'))
PYCONTROLONLY
  fi
  if (( UPGRADE_ROLLBACK_MODE )); then
    docker exec "$RESTORE_CONTAINER" bash -lc \
      'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; cd /opt/uvm/app; exec /opt/uvm/venv/bin/python -m alembic -c alembic.ini current' \
      >"$EVIDENCE/pre-migration-schema-current.stdout" 2>"$EVIDENCE/pre-migration-schema-current.stderr"
    rg -q '^0058([[:space:]]|$)' "$EVIDENCE/pre-migration-schema-current.stdout" || {
      echo 'archive restore did not establish exactly schema 0058 before upgrade' >&2; exit 2;
    }
    set +e
    docker exec "$RESTORE_CONTAINER" bash -lc \
      'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; cd /opt/uvm/app; exec /opt/uvm/venv/bin/python -m alembic -c alembic.ini upgrade 0062' \
      >"$EVIDENCE/explicit-migration.stdout" 2>"$EVIDENCE/explicit-migration.stderr"
    MIGRATION_EXIT=$?
    set -e
  else
    set +e
    docker exec "$RESTORE_CONTAINER" bash -lc \
      'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; cd /opt/uvm/app; exec /opt/uvm/venv/bin/python -m alembic -c alembic.ini upgrade head' \
      >"$EVIDENCE/explicit-migration.stdout" 2>"$EVIDENCE/explicit-migration.stderr"
    MIGRATION_EXIT=$?
    set -e
  fi
    printf '%s\n' "$MIGRATION_EXIT" >"$EVIDENCE/explicit-migration.exit"
    phase_mark upgrade_end
  (( MIGRATION_EXIT == 0 )) || exit "$MIGRATION_EXIT"
  if (( UPGRADE_ROLLBACK_MODE )); then
    docker exec "$RESTORE_CONTAINER" bash -lc \
      'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; cd /opt/uvm/app; exec /opt/uvm/venv/bin/python -m alembic -c alembic.ini current' \
      >"$EVIDENCE/post-migration-schema-current.stdout" 2>"$EVIDENCE/post-migration-schema-current.stderr"
    rg -q '^0062([[:space:]]|$)' "$EVIDENCE/post-migration-schema-current.stdout" || {
      echo 'explicit migration did not establish exactly schema 0062' >&2; exit 2;
    }
  fi
  # Renew the startup context, restart verification processes after the explicit
  # migration, and obtain a fresh authenticated checkpoint before readers return.
  rm "$RUN_ROOT/secrets/startup-fence.json"
  uv run python "$ROOT/tools/g7_backup_recovery.py" startup-token \
    --deployment-id g7-local --image-digest "$RESTORE_IMAGE_DIGEST" \
    --volume-ids-json "$RESTORE_VOLUMES_JSON" --archive-digest "$ARCHIVE_DIGEST" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
    "${COMPATIBILITY_ADMISSION_ARGS[@]}" \
    --key-id g7-host-controller-key --signing-key "$RUN_ROOT/host/ed25519.pem" \
    --output "$RUN_ROOT/secrets/startup-fence.json" >"$EVIDENCE/post-migration-startup-token.stdout"
  docker restart "$RESTORE_CONTAINER" >"$EVIDENCE/post-migration-restart.stdout"
  for _ in $(seq 1 90); do
    if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == healthy ]]; then break; fi
    sleep 1
  done
  CURRENT_SEQUENCE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["last_sequence"])' "$RUN_ROOT/host/state/backup/controller-journal.json")
  uv run python "$ROOT/tools/g7_backup_controller.py" --config "$RUN_ROOT/host/backup-controller.json" \
    --resync-database-epoch "$RECOVERY_EPOCH" --resync-database-sequence "$CURRENT_SEQUENCE" \
    --resync-checkpoint-epoch "$RECOVERY_EPOCH" --force-resync >"$EVIDENCE/post-migration-resync.json"
  post_migration_ready=0
  for _ in $(seq 1 90); do
    if curl --fail --silent --max-time 2 http://127.0.0.1:8000/openapi.json >/dev/null; then post_migration_ready=1; break; fi
    sleep 1
  done
  (( post_migration_ready )) || { echo 'post-migration verification listener unavailable' >&2; exit 2; }
  uv run python "$ROOT/tools/g7_recovery_public_readback.py" --evidence "$EVIDENCE" --phase post-migration \
    >"$EVIDENCE/post-migration-public-readback.json"
  restore_ce_ready=0
    for _ in $(seq 1 90); do
      if docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 5 \
          -u "admin:$CE_ADMIN_PASSWORD" 'http://127.0.0.1:8081/api/v2/findings/?limit=1' \
          >"$EVIDENCE/restore-ce-readiness.json" 2>"$EVIDENCE/restore-ce-readiness.stderr"; then
        restore_ce_ready=1; break
      fi
      sleep 1
    done
  (( restore_ce_ready )) || { echo 'CE public reader did not start after restored-context admission' >&2; exit 2; }
    docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 \
      -u "admin:$CE_ADMIN_PASSWORD" 'http://127.0.0.1:8081/api/v2/findings/?limit=100' \
      >"$EVIDENCE/restore-ce-findings.json"
    python3 - "$EVIDENCE/source-ce-public-sentinel.json" "$EVIDENCE/restore-ce-findings.json" \
        "$EVIDENCE/restore-ce-public-sentinel.json" <<'PYRESTORECE'
import hashlib,json,sys
source=json.load(open(sys.argv[1],encoding='utf-8'))
document=json.load(open(sys.argv[2],encoding='utf-8'))
results=document.get('results') if isinstance(document,dict) else None
if not isinstance(results,list): raise SystemExit('restored CE public findings endpoint did not return a results array')
retained=[f for f in results if f.get('unique_id_from_tool')=='g7-backup-recovery-sentinel-v1']
if len(retained)!=1: raise SystemExit('restored CE public API did not return exactly one recovery sentinel finding')
encoded=json.dumps(retained,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
restored={'count':len(retained),'results_sha256':'sha256:'+hashlib.sha256(encoded).hexdigest()}
json.dump(restored,open(sys.argv[3],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
if restored != source: raise SystemExit('restored CE public findings differ from source public readback')
PYRESTORECE
    docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
      "http://127.0.0.1:8081/api/v2/findings/$FINDING_ID/files/download/$MEDIA_ID/" >"$EVIDENCE/restore-ce-media.txt"
    cmp "$EVIDENCE/source-ce-media.txt" "$EVIDENCE/restore-ce-media.txt"
    docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
      "http://127.0.0.1:8081/api/v2/engagements/$ENGAGEMENT_ID/" >"$EVIDENCE/restore-ce-engagement.json"
    cmp "$EVIDENCE/source-ce-engagement.json" "$EVIDENCE/restore-ce-engagement.json"
  chmod 600 "$EVIDENCE/restore-ce-findings.json" "$EVIDENCE/restore-ce-public-sentinel.json"
  if (( UPGRADE_ROLLBACK_MODE )); then
    docker cp "$ROOT/tools/g7_product_inventory.py" "$RESTORE_CONTAINER:/tmp/g7_product_inventory.py"
    docker exec "$RESTORE_CONTAINER" /opt/uvm/venv/bin/python /tmp/g7_product_inventory.py --output /tmp/forward-product-inventory.json
    docker cp "$RESTORE_CONTAINER:/tmp/forward-product-inventory.json" "$EVIDENCE/forward-product-inventory.json"
    chmod 600 "$EVIDENCE/forward-product-inventory.json"
    cp "$RUN_ROOT/host/state/backup/controller-journal.json" "$EVIDENCE/inventory-controller-journal.json"
    PYTHONPATH="$ROOT" uv run python "$ROOT/tools/g7_product_inventory.py" --output "$EVIDENCE/product-inventory-attestation.json" \
      --journal "$EVIDENCE/inventory-controller-journal.json" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
      --expected-output "$EVIDENCE/expected-product-inventory.json" \
      --compare "$EVIDENCE/source-product-inventory.json" "$EVIDENCE/forward-product-inventory.json"
    # Preserve B's migrated volumes while proving that its complete retained
    # readbacks and effect inventory still match the captured source.
    cp "$RESTORE_VOLUMES_JSON" "$EVIDENCE/upgrade-forward-volume-ids.json"
    RESTORE_VOLUMES_JSON="$EVIDENCE/upgrade-forward-volume-ids.json"
    PRESERVE_UPGRADE_VOLUMES=1
    uv run python "$ROOT/tools/g7_backup_recovery.py" observe-queue \
      --container "$RESTORE_CONTAINER" --output "$EVIDENCE/post-migration-queue-inventory.json" \
      --network-fenced --writers-stopped >"$EVIDENCE/post-migration-queue.stdout" \
      2>"$EVIDENCE/post-migration-queue.stderr"
    cp "$EVIDENCE/post-migration-queue-inventory.json" "$EVIDENCE/post-migration-queue-observation-raw.json"
    docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-worker
    docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-beat
    docker exec "$RESTORE_CONTAINER" /opt/uvm/venv/bin/python -c 'import json,pathlib; hits=[]
for p in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
 try:
  args=p.read_bytes().split(b"\0")
  if any(a in (b"worker",b"beat") for a in args) and any(b"celery" in a for a in args): hits.append(p.parent.name)
 except (OSError,ProcessLookupError): pass
files=[str(p) for p in pathlib.Path("/run/uvm-g7").glob("pid-ce-*") if p.name in ("pid-ce-worker","pid-ce-beat")]
print(json.dumps({"passed":not hits and not files,"process_scan_exit":0,"worker_processes":hits,"pid_files":files}))' >"$EVIDENCE/verification-worker-absence.json"
    python3 - "$EVIDENCE/post-migration-queue-inventory.json" "$EVIDENCE/verification-worker-absence.json" <<'PYCLASSIFYQUEUE'
import json,sys
from pathlib import Path
from tools.g7_upgrade_assertions import classify_verification_queue
p=Path(sys.argv[1]); x=json.loads(p.read_text())
x=classify_verification_queue(x,json.loads(Path(sys.argv[2]).read_text()))
p.write_text(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n')
PYCLASSIFYQUEUE
    python3 - "$EVIDENCE/pre-stop-queue-inventory.json" "$EVIDENCE/post-migration-queue-inventory.json" \
      "$EVIDENCE/post-migration-effect-inventory-proof.json" <<'PYQUEUE'
import json,sys
from pathlib import Path
from tools.g7_upgrade_assertions import validate_verification_queue
before=json.load(open(sys.argv[1],encoding='utf-8')); after=json.load(open(sys.argv[2],encoding='utf-8'))
proof=validate_verification_queue(before,after)
proof.update(source_queue_drained=True,post_migration_workers_disabled=True,effect_intent_inventory_unchanged=True)
Path(sys.argv[3]).write_text(json.dumps(proof,sort_keys=True,separators=(',',':'))+'\n')
PYQUEUE
    docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-worker
    docker exec "$RESTORE_CONTAINER" test ! -f /run/uvm-g7/pid-ce-beat
    python3 - "$EVIDENCE" "$RUN_ROOT/host/backup-controller.json" <<'PYROLLBACKREQUEST'
import hashlib,json,sys,uuid
from datetime import datetime,timezone
from pathlib import Path
from tools.g7_backup_controller import Controller,load_config
root=Path(sys.argv[1]); controller=Controller(load_config(Path(sys.argv[2])))
manifest=json.loads((root/'archive/manifest.json').read_text())
volumes=json.loads((root/'upgrade-forward-volume-ids.json').read_text())
inventory=json.loads((root/'product-inventory-attestation.json').read_text())
if inventory.get('passed') is not True: raise ValueError('complete product mutation inventory failed')
queue=json.loads((root/'post-migration-effect-inventory-proof.json').read_text())
unresolved=queue.get('unresolved_external_effect_count')
if type(unresolved) is not int: raise ValueError('external effect inventory did not provide a measured unresolved count')
bindings=dict(line.rstrip().split('=',1) for line in (root/'image-bindings.txt').read_text().splitlines())
archive_digest='sha256:'+hashlib.sha256((root/'archive/manifest.json').read_bytes()).hexdigest()
attestation={'attestation_id':str(uuid.uuid4()),'recovery_epoch':1,'forward_volume_ids':volumes,
 'source_digest':inventory['source_digest'],'candidate_digest':inventory['candidate_digest'],
 'delta_digest':inventory['delta_digest'],'archive_digest':archive_digest,
 'source_image_digest':manifest['image_digest'],'source_package_manifest_digest':manifest['package_manifest_digest'],
 'upgraded_image_digest':(root/'image-b-id.txt').read_text().strip(),
 'target_package_manifest_digest':bindings['target_package_manifest_digest'],
 'product_mutation_count':inventory['product_mutation_count'],'control_mutation_count':inventory['control_mutation_count'],
 'unexpected_inventory_change_count':inventory['unexpected_inventory_change_count'],
 'unresolved_external_effect_count':unresolved,
 'controller_journal_pre_digest':'sha256:'+hashlib.sha256(controller.journal.read_bytes()).hexdigest()}
attestation_digest='sha256:'+hashlib.sha256(json.dumps(attestation,sort_keys=True,separators=(',',':')).encode()).hexdigest()
controller.state["inventory_delta_evidence"]={"submissions":controller.state["submission_receipts"],"expectation_digest":inventory["expectation_digest"],"allowed_deltas":inventory["allowed_deltas"]}
controller.journal_product_inventory_attestation(attestation)
request={'request_id':str(uuid.uuid4()),'state':'development_rollback_requested',
 'recovery_epoch':1,'archive_id':manifest['archive_id'],
 'archive_digest':archive_digest,
 'source_image_digest':manifest['image_digest'],
 'source_package_manifest_digest':manifest['package_manifest_digest'],
 'upgraded_image_digest':(root/'image-b-id.txt').read_text().strip(),
 'target_package_manifest_digest':None,
 'forward_volume_ids':volumes,'schema_head':'0062','inventory_attestation_id':attestation['attestation_id'],
 'inventory_attestation_digest':attestation_digest,'product_write_count':attestation['product_mutation_count'],
 'control_mutation_count':attestation['control_mutation_count'],
 'unexpected_inventory_change_count':attestation['unexpected_inventory_change_count'],'unresolved_external_effect_count':attestation['unresolved_external_effect_count'],
 'ingress_fenced':True,'egress_fenced':True,'public_readback_match':True,
 'requested_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
request['target_package_manifest_digest']=bindings['target_package_manifest_digest']
path=root/'development-rollback-request.json'; path.write_text(json.dumps(request,sort_keys=True,separators=(',',':')))
PYROLLBACKREQUEST
    uv run python "$ROOT/tools/g7_backup_controller.py" --config "$RUN_ROOT/host/backup-controller.json" \
      --development-rollback-request-json "$EVIDENCE/development-rollback-request.json" \
      >"$EVIDENCE/development-rollback-request-ack.json"
    # Stop B while preserving its volumes, then prove prior image A fails closed on 0062.
    docker inspect "$RESTORE_CONTAINER" >"$EVIDENCE/upgraded-b-container-inspect.json"
    docker logs "$RESTORE_CONTAINER" >"$EVIDENCE/upgraded-b-container.log" 2>&1
    phase_mark rollback_start
    docker rm -f "$RESTORE_CONTAINER" >"$EVIDENCE/upgraded-b-container-remove.stdout"
    RESTORE_STARTED=0
    RESTORE_CONTAINER_ID=''
    UPGRADE_CONNECTOR_RECOVERY_ID=$CONNECTOR_RECOVERY_ID
    CONNECTOR_RECOVERY_ID=$(python3 -c 'import uuid;print(uuid.uuid4())')
    rm -f "$RUN_ROOT/secrets/startup-fence.json"
    uv run python "$ROOT/tools/g7_backup_recovery.py" startup-token \
      --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
      --volume-ids-json "$RESTORE_VOLUMES_JSON" --archive-digest "$ARCHIVE_DIGEST" \
      --recovery-epoch 1 --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
      --key-id g7-host-controller-key --signing-key "$RUN_ROOT/host/ed25519.pem" \
      --output "$RUN_ROOT/secrets/startup-fence.json" >"$EVIDENCE/a-reject-0062-token.stdout"
    set +e
    docker run --name "${RESTORE_CONTAINER}-reject-0062" --rm --network none \
      --mount "type=bind,src=$RUN_ROOT/secrets,dst=/run/secrets,readonly" \
      --mount "type=bind,src=$RUN_ROOT/secrets/registry.json,dst=/run/uvm-g7-registry.json,readonly" \
      --mount "type=bind,src=$RUN_ROOT/secrets/host-pub.pem,dst=/run/uvm-g7-host-pub.pem,readonly" \
      --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["postgres_cluster"])' "$RESTORE_VOLUMES_JSON"),dst=/var/lib/postgresql/data" \
      --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ce_media"])' "$RESTORE_VOLUMES_JSON"),dst=/app/media" \
      --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["uvm_state"])' "$RESTORE_VOLUMES_JSON"),dst=/opt/uvm/state" \
      --env-file "$RUN_ROOT/container.env" --env UVM_G7_VERIFICATION_ONLY=1 \
      --env UVM_G7_RECOVERY_STAGE=control-only --env UVM_AUTH_MODE=oidc \
      --env UVM_G7_STARTUP_FENCE_TOKEN=/run/secrets/startup-fence.json \
      --env UVM_G7_HOST_PUBLIC_KEY_FILE=/run/uvm-g7-host-pub.pem \
      --env UVM_G7_DEPLOYMENT_ID=g7-local --env UVM_G7_TARGET_IMAGE_DIGEST="$IMAGE_DIGEST" \
      --env UVM_G7_RECOVERY_VOLUME_IDS="$(cat "$RESTORE_VOLUMES_JSON")" \
      --env UVM_G7_ARCHIVE_DIGEST="$ARCHIVE_DIGEST" --env UVM_G7_RECOVERY_EPOCH=1 \
      --env UVM_G7_CONNECTOR_RECOVERY_ID="$CONNECTOR_RECOVERY_ID" "$IMAGE" \
      >"$EVIDENCE/a-reject-0062.stdout" 2>"$EVIDENCE/a-reject-0062.stderr"
    A_REJECT_EXIT=$?
    set -e
    printf '%s\n' "$A_REJECT_EXIT" >"$EVIDENCE/a-reject-0062.exit"
    (( A_REJECT_EXIT != 0 )) || { echo 'A unexpectedly accepted 0062 schema' >&2; exit 2; }
    rg -q 'G7_SCHEMA_COMPATIBILITY_REJECTED' "$EVIDENCE/a-reject-0062.stderr" || {
      echo 'A rejection did not come from the image schema guard' >&2; exit 2;
    }
    # Restore the same signed archive with A into distinct volumes at epoch 2.
    RECOVERY_EPOCH=2
    CONNECTOR_RECOVERY_ID=$(python3 -c 'import uuid;print(uuid.uuid4())')
    uv run python "$ROOT/tools/g7_backup_recovery.py" restore \
      --archive-dir "$EVIDENCE/archive" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
      --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
      --package-manifest-digest "$PACKAGE_DIGEST" --expected-key-id g7-host-controller-key \
      --helper-image "$IMAGE" --name-prefix volt-g7-rollback \
      --host-journal "$RUN_ROOT/host/state/backup/controller-journal.json" \
      --recovery-epoch "$RECOVERY_EPOCH" >"$EVIDENCE/rollback-volumes.stdout.json" \
      2>"$EVIDENCE/rollback-volumes.stderr"
    python3 - "$EVIDENCE/rollback-volumes.stdout.json" "$EVIDENCE/rollback-volume-ids.json" \
      "$EVIDENCE/upgrade-forward-volume-ids.json" <<'PYROLLBACKVOLS'
import json,sys
value=json.load(open(sys.argv[1],encoding='utf-8'))['replacement_volumes']
if set(value)!={'postgres_cluster','ce_media','uvm_state'}: raise SystemExit('rollback restore volume set is invalid')
if set(value.values()) & set(json.load(open(sys.argv[3],encoding='utf-8')).values()): raise SystemExit('rollback reused upgraded volume')
json.dump(value,open(sys.argv[2],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYROLLBACKVOLS
    RESTORE_VOLUMES_JSON="$EVIDENCE/rollback-volume-ids.json"
    python3 - "$RUN_ROOT/secrets/startup-fence.json" "$EVIDENCE/a-reject-0062-token-binding.json" <<'PYTOKENBINDING'
import json,sys
from pathlib import Path
x=json.loads(Path(sys.argv[1]).read_text()); x.pop('signature',None)
Path(sys.argv[2]).write_text(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n')
PYTOKENBINDING
    rm -f "$RUN_ROOT/secrets/startup-fence.json"
    uv run python "$ROOT/tools/g7_backup_recovery.py" startup-token \
      --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
      --volume-ids-json "$RESTORE_VOLUMES_JSON" --archive-digest "$ARCHIVE_DIGEST" \
      --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
      --key-id g7-host-controller-key --signing-key "$RUN_ROOT/host/ed25519.pem" \
      --output "$RUN_ROOT/secrets/startup-fence.json" >"$EVIDENCE/rollback-startup-token.stdout"
    COMPATIBILITY_ADMISSION_ARGS=(); SCHEMA_MODE_ARGS=(); RESTORE_IMAGE_DIGEST="$IMAGE_DIGEST"
    RESTORE_STARTED=1
    docker run -d --name "$RESTORE_CONTAINER" --label uvm.g7.backup-recovery=true \
      --network "$RECOVERY_NETWORK" --ip "$RESTORE_IP" --cap-add NET_ADMIN \
      --mount "type=bind,src=$ROOT/tools/g7_fenced_entrypoint.sh,dst=/tmp/g7_fenced_entrypoint.sh,readonly" \
      --entrypoint /bin/bash \
      -p 127.0.0.1:8000:8000 -p 127.0.0.1:8002:8002 -p "127.0.0.1:$OIDC_PORT:9000" \
      --mount "type=bind,src=$RUN_ROOT/secrets,dst=/run/secrets,readonly" \
      --mount "type=bind,src=$RUN_ROOT/secrets/registry.json,dst=/run/uvm-g7-registry.json,readonly" \
      --mount "type=bind,src=$RUN_ROOT/secrets/host-pub.pem,dst=/run/uvm-g7-host-pub.pem,readonly" \
      --mount "type=bind,src=$ROOT/tools/g7_runtime_egress_fence.py,dst=/tmp/g7_runtime_egress_fence.py,readonly" \
      --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/run/uvm-g7-scheduler" \
      --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["postgres_cluster"])' "$RESTORE_VOLUMES_JSON"),dst=/var/lib/postgresql/data" \
      --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["ce_media"])' "$RESTORE_VOLUMES_JSON"),dst=/app/media" \
      --mount "type=volume,src=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["uvm_state"])' "$RESTORE_VOLUMES_JSON"),dst=/opt/uvm/state" \
      --env-file "$RUN_ROOT/container.env" --env UVM_G7_VERIFICATION_ONLY=1 \
      --env UVM_G7_RECOVERY_STAGE=control-only --env UVM_AUTH_MODE=oidc \
      --env UVM_G7_STARTUP_FENCE_TOKEN=/run/secrets/startup-fence.json \
      --env UVM_G7_HOST_PUBLIC_KEY_FILE=/run/uvm-g7-host-pub.pem \
      --env UVM_G7_DEPLOYMENT_ID=g7-local --env UVM_G7_TARGET_IMAGE_DIGEST="$RESTORE_IMAGE_DIGEST" \
      --env UVM_G7_RECOVERY_VOLUME_IDS="$(cat "$RESTORE_VOLUMES_JSON")" \
      --env UVM_G7_ARCHIVE_DIGEST="$ARCHIVE_DIGEST" --env UVM_G7_RECOVERY_EPOCH="$RECOVERY_EPOCH" \
      --env UVM_G7_CONNECTOR_RECOVERY_ID="$CONNECTOR_RECOVERY_ID" "$IMAGE" /tmp/g7_fenced_entrypoint.sh \
      >"$EVIDENCE/rollback-container-id.txt"
    RESTORE_CONTAINER_ID=$(cat "$EVIDENCE/rollback-container-id.txt")
    rollback_ready=0
    for _ in $(seq 1 300); do
      if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == healthy ]]; then rollback_ready=1; break; fi
      if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Status}}' 2>/dev/null) != running ]]; then break; fi
      sleep 2
    done
    (( rollback_ready )) || { echo 'A archive rollback did not become healthy' >&2; exit 2; }
    docker exec "$RESTORE_CONTAINER" cat /run/g7-runtime-egress-fence.json >"$EVIDENCE/a-startup-egress-fence.json"
    docker exec "$RESTORE_CONTAINER" /opt/uvm/venv/bin/python /tmp/g7_runtime_egress_fence.py --verify >"$EVIDENCE/a-before-admission-egress-fence.json"
    uv run python "$ROOT/tools/g7_backup_recovery.py" admit-restore \
      --config "$RUN_ROOT/host/backup-controller.json" --manifest "$EVIDENCE/archive/manifest.json" \
      --volume-ids "$RESTORE_VOLUMES_JSON" --recovery-epoch "$RECOVERY_EPOCH" \
      --connector-recovery-id "$CONNECTOR_RECOVERY_ID" --drain-proof "$EVIDENCE/signed-drain-proof.json" \
      --public-key "$RUN_ROOT/secrets/host-pub.pem" --target-image-digest "$IMAGE_DIGEST" \
      >"$EVIDENCE/rollback-restore-event-acks.json" 2>"$EVIDENCE/rollback-restore-event-acks.stderr"
    uv run python "$ROOT/tools/g7_backup_recovery.py" admit-restore \
      --config "$RUN_ROOT/host/backup-controller.json" --manifest "$EVIDENCE/archive/manifest.json" \
      --volume-ids "$RESTORE_VOLUMES_JSON" --recovery-epoch "$RECOVERY_EPOCH" \
      --connector-recovery-id "$CONNECTOR_RECOVERY_ID" --drain-proof "$EVIDENCE/signed-drain-proof.json" \
      --public-key "$RUN_ROOT/secrets/host-pub.pem" --target-image-digest "$IMAGE_DIGEST" \
      >"$EVIDENCE/rollback-restore-event-replay-acks.json" 2>"$EVIDENCE/rollback-restore-event-replay-acks.stderr"
    python3 - "$EVIDENCE/rollback-restore-event-acks.json" "$EVIDENCE/rollback-restore-event-replay-acks.json" <<'PYROLLBACKREPLAY'
import json,sys
if json.load(open(sys.argv[1])) != json.load(open(sys.argv[2])): raise SystemExit('epoch-2 restore replay changed its acknowledgement')
PYROLLBACKREPLAY
    set +e
    uv run python "$ROOT/tools/g7_backup_recovery.py" admit-restore \
      --config "$RUN_ROOT/host/backup-controller.json" --manifest "$EVIDENCE/archive/manifest.json" \
      --volume-ids "$EVIDENCE/upgrade-forward-volume-ids.json" --recovery-epoch 1 \
      --connector-recovery-id "$UPGRADE_CONNECTOR_RECOVERY_ID" --drain-proof "$EVIDENCE/signed-drain-proof.json" \
      --public-key "$RUN_ROOT/secrets/host-pub.pem" --target-image-digest "$(cat "$EVIDENCE/image-b-id.txt")" \
      >"$EVIDENCE/stale-epoch-restore.stdout" 2>"$EVIDENCE/stale-epoch-restore.stderr"
    STALE_EPOCH_EXIT=$?
    set -e
    printf '%s\n' "$STALE_EPOCH_EXIT" >"$EVIDENCE/stale-epoch-restore.exit"
    (( STALE_EPOCH_EXIT != 0 )) || { echo 'stale epoch-1 restore replay was accepted after epoch 2' >&2; exit 2; }
    rg -q 'backup recovery failed closed: RecoveryError' "$EVIDENCE/stale-epoch-restore.stderr" || {
      echo 'stale epoch rejection did not fail through the recovery controller' >&2; exit 2;
    }
    rollback_api_ready=0
    for _ in $(seq 1 300); do
      if curl --fail --silent --max-time 2 http://127.0.0.1:8000/openapi.json >/dev/null; then
        rollback_api_ready=1; break
      fi
      if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Running}}' 2>/dev/null) != true ]]; then break; fi
      sleep 1
    done
    (( rollback_api_ready )) || { echo 'epoch-2 A restore did not release its public verification listener' >&2; exit 2; }
    uv run python "$ROOT/tools/g7_recovery_public_readback.py" --evidence "$EVIDENCE" --phase rollback \
      >"$EVIDENCE/rollback-public-readback.json"
    phase_mark rollback_end
    rollback_ce_ready=0
    for _ in $(seq 1 120); do
      if docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 5 \
          -u "admin:$CE_ADMIN_PASSWORD" 'http://127.0.0.1:8081/api/v2/findings/?limit=1' \
          >"$EVIDENCE/rollback-ce-readiness.json" 2>"$EVIDENCE/rollback-ce-readiness.stderr"; then
        rollback_ce_ready=1; break
      fi
      sleep 1
    done
    if (( ! rollback_ce_ready )); then
      docker exec "$RESTORE_CONTAINER" ps -eo pid,ppid,uid,stat,args >"$EVIDENCE/rollback-processes.txt" 2>&1 || true
      docker exec "$RESTORE_CONTAINER" cat /run/uvm-g7/ce-web.log >"$EVIDENCE/rollback-ce-startup.log" 2>&1 || true
      echo 'epoch-2 A restore CE public API did not become reachable' >&2
      exit 2
    fi
    docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 \
      -u "admin:$CE_ADMIN_PASSWORD" 'http://127.0.0.1:8081/api/v2/findings/?limit=100' \
      >"$EVIDENCE/rollback-ce-findings.json"
    python3 - "$EVIDENCE/source-ce-findings.json" "$EVIDENCE/rollback-ce-findings.json" <<'PYCE'
import json,sys
def sentinels(path):
 value=json.load(open(path,encoding='utf-8'))['results']
 return sorted((x for x in value if x.get('unique_id_from_tool')=='g7-backup-recovery-sentinel-v1'),key=lambda x:x['id'])
if sentinels(sys.argv[1]) != sentinels(sys.argv[2]): raise SystemExit('rollback CE finding differs from captured API readback')
PYCE
    docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 \
      -u "admin:$CE_ADMIN_PASSWORD" \
      "http://127.0.0.1:8081/api/v2/findings/$FINDING_ID/files/download/$MEDIA_ID/" \
      >"$EVIDENCE/restore-ce-media.txt"
    cmp "$EVIDENCE/source-ce-media.txt" "$EVIDENCE/restore-ce-media.txt"
    docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 \
      -u "admin:$CE_ADMIN_PASSWORD" "http://127.0.0.1:8081/api/v2/engagements/$ENGAGEMENT_ID/" \
      >"$EVIDENCE/restore-ce-engagement.json"
    cmp "$EVIDENCE/source-ce-engagement.json" "$EVIDENCE/restore-ce-engagement.json"
    cp "$EVIDENCE/rollback-ce-findings.json" "$EVIDENCE/restore-ce-findings.json"
    cp "$EVIDENCE/rollback-public-readback.json" "$EVIDENCE/epoch-2-rollback-readback.json"
  fi
  uv run python - "$RUN_ROOT/host/backup-controller.json" "$EVIDENCE" <<'PYFINISH'
from datetime import datetime,timedelta,timezone
import hashlib,json,sys,urllib.request,uuid
from pathlib import Path
from tools.g7_backup_controller import Controller,load_config,atomic_json
from tools.g7_upgrade_assertions import validate_epoch_two_readbacks
from uvm.operations.backup_host import digest
config=load_config(Path(sys.argv[1])); controller=Controller(config); root=Path(sys.argv[2])
if (root/'explicit-migration.exit').read_text().strip()!='0': raise ValueError('explicit migration failed')
upgrade=(root/'upgrade-rollback-mode.txt').exists()
if upgrade and json.loads((root/'pre-migration-control-only.json').read_text()).get('passed') is not True: raise ValueError('pre-migration reader fence was not proved')
if json.loads((root/'post-migration-public-readback.json').read_text()).get('passed') is not True: raise ValueError('post-migration public retained assertions missing')
for name in ('media.txt','engagement.json'):
 if (root/('source-ce-'+name)).read_bytes() != (root/('restore-ce-'+name)).read_bytes(): raise ValueError('CE retained sentinel differs')
files=['post-migration-public-readback.json','source-ce-public-sentinel.json','restore-ce-public-sentinel.json','source-ce-media.txt','restore-ce-media.txt','source-ce-engagement.json','restore-ce-engagement.json','source-backup-settings-readback.json','explicit-migration.exit','signed-drain-proof.json']
if upgrade: files.append('pre-migration-control-only.json')
if (root/'upgrade-rollback-mode.txt').exists():
 required=['rollback-public-readback.json','rollback-uvm-group.json','rollback-uvm-audit.json','rollback-ce-findings.json','rollback-volume-ids.json','restore-ce-media.txt','restore-ce-engagement.json']
 for name in required:
  path=root/name
  if not path.is_file() or not path.stat().st_size: raise ValueError('epoch-2 rollback verification result is missing: '+name)
 if json.loads((root/'rollback-public-readback.json').read_text()).get('passed') is not True: raise ValueError('epoch-2 A public readback did not pass')
 context=controller.state['last_recovery_event']['event']; volumes=json.loads((root/'rollback-volume-ids.json').read_text())
 if context.get('recovery_epoch')!=2 or context.get('new_volume_ids')!=volumes or context.get('target_image_digest')!=(root/'image-a-id.txt').read_text().strip(): raise ValueError('epoch-2 verification context mismatches A image or volumes')
 archive=json.loads((root/'archive/manifest.json').read_text()); bindings=dict(line.rstrip().split('=',1) for line in (root/'image-bindings.txt').read_text().splitlines())
 if archive.get('image_digest')!=context.get('target_image_digest') or archive.get('package_manifest_digest')!=bindings['source_package_manifest_digest'] or context.get('manifest_digest')!='sha256:'+hashlib.sha256((root/'archive/manifest.json').read_bytes()).hexdigest(): raise ValueError('epoch-2 archive/image/package context mismatch')
if (root/'upgrade-rollback-mode.txt').exists():
 files += ['rollback-public-readback.json','rollback-uvm-group.json','rollback-uvm-audit.json','rollback-ce-findings.json','rollback-volume-ids.json','epoch-2-rollback-readback.json']
readbacks={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}
readback_digest='sha256:'+digest(readbacks)
atomic_json(root/'verification-readback-manifest.json',readbacks)
last=controller.state['last_recovery_event']['event']
unsigned={k:v for k,v in last.items() if k not in {'signature','sequence','controller_instance_id'}}
verification={k:'passed' for k in ('uvm_public_api','ce_public_api','media_readback','queue_reconciliation','migration')}
verification['details_digest']=readback_digest
dto=json.loads((root/'source-backup-settings-readback.json').read_text())
if not isinstance(dto.get('desired'),dict) or not isinstance(dto.get('status'),dict):
 raise ValueError('source backup-settings readback is incomplete')
if (root/'upgrade-rollback-mode.txt').exists():
 archive=json.loads((root/'archive/manifest.json').read_text()); bindings=dict(line.rstrip().split('=',1) for line in (root/'image-bindings.txt').read_text().splitlines())
 context_binding={**{k:last.get(k) for k in ('recovery_epoch','target_image_digest','new_volume_ids','connector_recovery_id','archive_id','manifest_digest','source_image_digest')},'package_manifest_digest':archive['package_manifest_digest'],'archive_digest':'sha256:'+hashlib.sha256((root/'archive/manifest.json').read_bytes()).hexdigest(),'expected_source_package_digest':bindings['source_package_manifest_digest']}
 atomic_json(root/'rollback-context-binding.json',context_binding)
 readbacks['rollback-context-binding.json']=hashlib.sha256((root/'rollback-context-binding.json').read_bytes()).hexdigest()
 atomic_json(root/'verification-readback-manifest.json',readbacks)
 verification['details_digest']=validate_epoch_two_readbacks(root,readbacks,context_binding)
unsigned.update(event_id=str(uuid.uuid4()),previous_epoch=last['recovery_epoch'],event_type='verification_passed',verification=verification,public_readback_digest=readback_digest,observed_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
verified=controller.submit_recovery_event(unsigned)
manifest=json.loads((root/'archive/manifest.json').read_text())
now=datetime.now(timezone.utc);completed=datetime.fromisoformat(manifest['completed_at'].replace('Z','+00:00'))
maximum=dto['desired']['values']['maximum_backup_age_seconds'];age=int((now-completed).total_seconds())
status={'schema_version':1,'deployment_id':controller.deployment,'report_id':str(uuid.uuid4()),'report_kind':'status','host_policy':config['host_policy'],
 'desired':{k:dto['desired'][k] for k in ('revision','digest')},'settings_application':dto['status']['settings_application'],
 'completed_archive':{'archive_id':manifest['archive_id'],'completed_at':manifest['completed_at'],'manifest_digest':'sha256:'+hashlib.sha256((root/'archive/manifest.json').read_bytes()).hexdigest(),'outcome':'complete'},
 'freshness':{'state':'fresh' if age<=maximum else 'stale','evaluated_at':now.isoformat().replace('+00:00','Z'),'age_seconds':age,'basis_completed_at':manifest['completed_at'],'maximum_backup_age_seconds':maximum},
 'restore_verification':{'state':'verified','archive_id':last['archive_id'],'recovery_epoch':last['recovery_epoch'],'verified_at':last['observed_at'],'failure_code':None},'recovery_epoch':last['recovery_epoch'],
 'observed_at':now.isoformat().replace('+00:00','Z'),'fresh_until':(now+timedelta(seconds=config['host_policy']['maximum_report_age_seconds'])).isoformat().replace('+00:00','Z')}
status_ack=controller.submit_status(status)
unsigned.update(event_id=str(uuid.uuid4()),event_type='fence_released',observed_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
atomic_json(root/'pending-release-event.json',unsigned)
atomic_json(root/'signed-verification-release-acks.json',{'verification':verified,'status':status_ack})
PYFINISH
  restart_recovery_checkpoint verified
  uv run python "$ROOT/tools/g7_backup_controller.py" --config "$RUN_ROOT/host/backup-controller.json" \
    --recovery-event-json "$EVIDENCE/pending-release-event.json" >"$EVIDENCE/signed-release-ack.json"
  restart_recovery_checkpoint released
  python3 - "$EVIDENCE" <<'PYRELEASEACK'
import json,sys
from pathlib import Path
root=Path(sys.argv[1]); path=root/'signed-verification-release-acks.json'
value=json.loads(path.read_text()); value['release']=json.loads((root/'signed-release-ack.json').read_text())
path.write_text(json.dumps(value,sort_keys=True))
PYRELEASEACK
  python3 - "$EVIDENCE/host-fence-release-journal.json" <<'PYRELEASE'
from datetime import datetime,timezone
import json,os,sys
from pathlib import Path
path=Path(sys.argv[1]); value={'signed_public_acknowledgement_retained':True,'ingress':'loopback-only-disposable','external_egress':'namespace-fence-installed-before-entrypoint','workers_release_requested':True,'observed_at':datetime.now(timezone.utc).isoformat()}
with path.open('x') as stream:
 json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
PYRELEASE
  docker exec "$RESTORE_CONTAINER" /opt/uvm/venv/bin/python /tmp/g7_runtime_egress_fence.py --verify >"$EVIDENCE/before-runtime-release-egress-fence.json"
  docker exec "$RESTORE_CONTAINER" bash -lc \
    'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; cd /opt/uvm/app; exec /opt/uvm/venv/bin/python -m uvm.operations.startup_fence --authorize-host-release' \
    >"$EVIDENCE/host-release-authorized.stdout" 2>"$EVIDENCE/host-release-authorized.stderr"
  released_runtime_ready=0
  for _ in $(seq 1 180); do
    if docker exec "$RESTORE_CONTAINER" test -f /run/uvm-g7/pid-ce-worker \
        && curl --fail --silent --max-time 2 http://127.0.0.1:8000/openapi.json >/dev/null; then released_runtime_ready=1; break; fi
    if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Running}}') != true ]]; then break; fi
    sleep 1
  done
  (( released_runtime_ready )) || { echo 'signed recovery did not release runtime workers' >&2; exit 2; }
  if (( UPGRADE_ROLLBACK_MODE )); then phase_mark outage_end; fi
  docker exec "$RESTORE_CONTAINER" cat /run/g7-runtime-egress-fence.json \
    >"$EVIDENCE/runtime-egress-fence.json" 2>"$EVIDENCE/runtime-egress-fence.stderr"
  docker exec "$RESTORE_CONTAINER" /opt/uvm/venv/bin/python -c 'import socket; s=socket.socket(); s.settimeout(2); r=s.connect_ex(("203.0.113.1",443)); print(r); raise SystemExit(0 if r else 1)' \
    >"$EVIDENCE/fenced-egress-probe.stdout" 2>"$EVIDENCE/fenced-egress-probe.stderr"
  grep -qx '101' "$EVIDENCE/fenced-egress-probe.stdout" || { echo 'runtime external egress probe was not denied by the admitted container route fence' >&2; exit 2; }
  curl --fail --silent --max-time 5 http://127.0.0.1:8000/openapi.json >"$EVIDENCE/runtime-local-control-readback.json"
  PYTHONPATH="$ROOT" uv run python "$ROOT/tools/g7_recovery_runtime_probe.py" \
    --container "$RESTORE_CONTAINER" --evidence "$EVIDENCE" >"$EVIDENCE/released-runtime-proof.stdout" \
    2>"$EVIDENCE/released-runtime-proof.stderr"
  docker exec "$RESTORE_CONTAINER" /opt/uvm/venv/bin/python /tmp/g7_runtime_egress_fence.py --verify >"$EVIDENCE/after-runtime-progress-egress-fence.json"
  uv run python "$ROOT/tools/g7_recovery_public_readback.py" --evidence "$EVIDENCE" --phase released \
    >"$EVIDENCE/released-public-readback.json"
  docker exec "$RESTORE_CONTAINER" ps -eo pid,comm,args >"$EVIDENCE/released-processes.txt"
  python3 - "$EVIDENCE/restore-browser-expectations.json" <<'PYEXPECT'
import json,sys
json.dump({'schema_version':1,'id':'restored-readback','deployment_id':'g7-local','action':'read',
 'timeout_ms':60000,'expect':{'desired_revision':4,'effective_revision':4,'application':'applied',
 'archive':'complete','freshness':'fresh','restore':'verified'}},
 open(sys.argv[1],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYEXPECT
  node "$ROOT/tools/g7_recovery_ui_probe.mjs" --origin http://127.0.0.1:8000 \
    --storage-state "$EVIDENCE/recovery-auth-state.json" \
    --evidence "$EVIDENCE/restore-public-browser-probe" \
    >"$EVIDENCE/restore-public-browser-probe.stdout" \
    2>"$EVIDENCE/restore-public-browser-probe.stderr"
  PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
    node "$ROOT/ui/tests/backup-recovery-browser.mjs" --origin http://127.0.0.1:8000 \
    --storage-state "$EVIDENCE/recovery-auth-state.json" \
    --expectations "$EVIDENCE/restore-browser-expectations.json" \
    --evidence "$EVIDENCE/restore-public-browser" \
    >"$EVIDENCE/restore-public-browser.stdout" 2>"$EVIDENCE/restore-public-browser.stderr"
  if (( UPGRADE_ROLLBACK_MODE )); then
    python3 - "$EVIDENCE/phase-timestamps.json" "$EVIDENCE/phase-durations.json" <<'PHDUR'
import json,sys
from pathlib import Path
x=json.loads(Path(sys.argv[1]).read_text()); pairs={'upgrade_seconds':('upgrade_start','upgrade_end'),'rollback_seconds':('rollback_start','rollback_end'),'outage_seconds':('outage_start','outage_end')}
out={k:(x[b]['monotonic_ns']-x[a]['monotonic_ns'])/1e9 for k,(a,b) in pairs.items()}
if any(v<0 for v in out.values()): raise SystemExit('phase monotonic clock regressed')
Path(sys.argv[2]).write_text(json.dumps({'schema_version':1,'clock':'host monotonic_ns','durations':out,'timestamp_file':'phase-timestamps.json'},sort_keys=True,separators=(',',':'))+'\n')
PHDUR
    PRESERVE_UPGRADE_VOLUMES=0
  fi
  finish_operation_deadline verification
  if (( UPGRADE_ROLLBACK_MODE )); then
    echo 'G7 current-image 0058-to-0062 verification upgrade rolled back from the signed archive with A at epoch 2; UVM UI and CE public retained-state readback passed' | tee "$EVIDENCE/result.txt"
  else
    echo 'G7 recovery-only signed archive restored into new volumes; UVM UI and CE public retained-state readback passed' | tee "$EVIDENCE/result.txt"
  fi
  exit 0
fi
if (( EXCEPTION_SLA_MODE )); then
  echo 'G7 authoritative ingestion and exception SLA pause/resume public journey completed' | tee "$EVIDENCE/result.txt"
elif (( EXCEPTION_WARNING_MODE )); then
  echo 'G7 exception warning public lifecycle journey completed' | tee "$EVIDENCE/result.txt"
else
  echo 'G7 observer-settings-only journey completed' | tee "$EVIDENCE/result.txt"
fi
