#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

MODE=${1-}
if [[ ( $MODE != --observer-settings-only && $MODE != --backup-recovery-only ) || $# != 1 ]]; then
  echo 'usage: G7_EVIDENCE_DIR=/absolute/path bash tools/g7_container_journey.sh (--observer-settings-only|--backup-recovery-only)' >&2
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
RUN_ROOT=$(mktemp -d /tmp/volt-g7-observer-run.XXXXXX)
if [[ $MODE == --backup-recovery-only ]]; then
  CONTAINER=volt-g7-observer-journey
  ANCHOR_CONTAINER=volt-g7-observer-anchor
  IMAGE="volt-g7-backup-recovery-dev:$(git -C "$ROOT" rev-parse --short HEAD)"
else
  CONTAINER=volt-g7-observer-journey
  ANCHOR_CONTAINER=volt-g7-observer-anchor
  IMAGE="volt-g7-observer-dev:$(git -C "$ROOT" rev-parse --short HEAD)"
fi
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
STARTED_CONTAINER=0
STARTED_ANCHOR=0
CREATED_IMAGE=0
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
RESTORE_IP=''
RESTORE_FIREWALL_TABLE=''
RESTORE_VOLUMES_JSON=''

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
  restore_firewall_remove_exit=not_installed
  if [[ -n $RESTORE_FIREWALL_TABLE ]]; then
    sudo -n nft delete table inet "$RESTORE_FIREWALL_TABLE" \
      >"$EVIDENCE/restore-egress-firewall-cleanup.stdout" \
      2>"$EVIDENCE/restore-egress-firewall-cleanup.stderr"
    restore_firewall_remove_exit=$?
    (( restore_firewall_remove_exit == 0 )) || cleanup_rc=1
  fi
  restore_volumes_removed=not_created
  if [[ -n $RESTORE_VOLUMES_JSON && -f $RESTORE_VOLUMES_JSON ]]; then
    restore_volumes_removed=1
    while IFS= read -r volume; do
      [[ -n $volume ]] || continue
      docker volume rm "$volume" >/dev/null 2>&1 || {
        docker volume inspect "$volume" >/dev/null 2>&1 && restore_volumes_removed=0
      }
    done < <(python3 - "$RESTORE_VOLUMES_JSON" <<'PYVOLS'
import json,sys
print("\n".join(json.load(open(sys.argv[1],encoding="utf-8")).values()))
PYVOLS
)
    (( restore_volumes_removed == 1 )) || cleanup_rc=1
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
  # A stopped replacement may have left a root-owned scheduler directory on
  # this run's sole writable bind. Repair only that known disposable mount.
  if [[ -d "$RUN_ROOT/scheduler" ]] && ! rm -rf "$RUN_ROOT/scheduler" 2>/dev/null; then
    docker run --rm --network none --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/owned-scheduler" \
      --entrypoint /bin/chmod "$IMAGE" -R a+rwX /owned-scheduler >/dev/null 2>&1 || cleanup_rc=1
  fi
  chmod -R u+rwX "$RUN_ROOT" 2>/dev/null || true
  rm -rf "$RUN_ROOT" || cleanup_rc=1
  [[ ! -e "$RUN_ROOT" ]] || cleanup_rc=1
  if (( CREATED_IMAGE )); then docker image rm "$IMAGE" >/dev/null 2>&1; fi
  printf 'container_id=%s\ncontainer_remove_exit=%s\ncontainer_absence_verified=%s\nrestore_container_id=%s\nrestore_container_remove_exit=%s\nrestore_container_absence_verified=%s\nrestore_volumes_absence_verified=%s\nanchor_id=%s\nanchor_remove_exit=%s\nanchor_absence_verified=%s\nrunner_exit=%s\ncleanup_exit=%s\n' \
    "${CONTAINER_ID:-unknown}" "$container_rm_exit" "$container_removed" \
    "${RESTORE_CONTAINER_ID:-not_started}" "$restore_container_rm_exit" "$restore_container_removed" "$restore_volumes_removed" \
    "${ANCHOR_ID:-unknown}" "$anchor_rm_exit" "$anchor_removed" "$rc" "$cleanup_rc" \
    >"$EVIDENCE/owned-resource-cleanup.txt"
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
for port in 8000 8002 9000 "$ANCHOR_PORT"; do
  if (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1; then
    echo "required local port $port is occupied" >&2; exit 69
  fi
done
printf 'anchor_loopback_port=%s\n' "$ANCHOR_PORT" >"$EVIDENCE/runtime-ports.txt"
docker version --format 'engine={{.Server.Version}}' >"$EVIDENCE/docker-version.txt"
for name in "$CONTAINER" "$ANCHOR_CONTAINER"; do
  if docker inspect "$name" >/dev/null 2>&1; then
    echo "owned journey container name already exists: $name" >&2; exit 69
  fi
done
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then CREATED_IMAGE=1; fi

uv run python "$ROOT/tools/g7_observer_fixture.py" create --root "$RUN_ROOT" --image "$IMAGE"
if [[ $MODE == --backup-recovery-only ]]; then
  printf '\nUVM_G7_QUIESCE_NO_KILL=1\nUVM_G7_QUIESCE_TIMEOUT_SECONDS=300\n' >>"$RUN_ROOT/container.env"
fi
docker build -f "$ROOT/Dockerfile.g7" -t "$IMAGE" "$ROOT" \
  >"$EVIDENCE/docker-build.stdout" 2>"$EVIDENCE/docker-build.stderr"
docker image inspect "$IMAGE" --format '{{.Id}} {{json .RepoDigests}}' \
  >"$EVIDENCE/pinned-image.txt"

STARTED_ANCHOR=1
docker run -d --name "$ANCHOR_CONTAINER" --label uvm.g7.observer-journey=true \
  -p "127.0.0.1:$ANCHOR_PORT:5432" \
  --tmpfs /var/lib/postgresql/data:rw,uid=101,gid=103,mode=0700 \
  --mount "type=bind,src=$RUN_ROOT/anchor-password,dst=/run/secrets/anchor-password,readonly" \
  --user postgres --entrypoint /bin/bash "$IMAGE" -lc \
  'if [[ ! -s /var/lib/postgresql/data/PG_VERSION ]]; then /usr/lib/postgresql/18/bin/initdb -D /var/lib/postgresql/data --auth-local=trust --auth-host=scram-sha-256 --pwfile=/run/secrets/anchor-password >/dev/null; fi; exec /usr/lib/postgresql/18/bin/postgres -D /var/lib/postgresql/data -h 0.0.0.0 -p 5432' \
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
uv run python "$ROOT/tools/g7_observer_fixture.py" anchor-init --root "$RUN_ROOT" \
  >"$EVIDENCE/anchor-fixture.stdout" 2>"$EVIDENCE/anchor-fixture.stderr"

STARTED_CONTAINER=1
docker run -d --name "$CONTAINER" --label uvm.g7.observer-journey=true \
  -p 127.0.0.1:8000:8000 -p 127.0.0.1:8002:8002 -p 127.0.0.1:9000:9000 \
  --mount "type=bind,src=$RUN_ROOT/secrets,dst=/run/secrets,readonly" \
  --mount "type=bind,src=$RUN_ROOT/secrets/registry.json,dst=/run/uvm-g7-registry.json,readonly" \
  --mount "type=bind,src=$RUN_ROOT/secrets/host-pub.pem,dst=/run/uvm-g7-host-pub.pem,readonly" \
  --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/run/uvm-g7-scheduler" \
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
curl --fail --silent --show-error http://127.0.0.1:8000/openapi.json >/dev/null
curl --fail --silent --show-error http://127.0.0.1:9000/healthz >/dev/null

if [[ $MODE == --backup-recovery-only ]]; then
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

uv run python "$ROOT/tools/g7_observer_fixture.py" link-actor --root "$RUN_ROOT" \
  >"$EVIDENCE/oidc-link.stdout" 2>"$EVIDENCE/oidc-link.stderr"
uv run python "$ROOT/tools/g7_observer_fixture.py" host-config --root "$RUN_ROOT" --image "$IMAGE" --anchor-port "$ANCHOR_PORT" \
  >"$EVIDENCE/host-config.stdout" 2>"$EVIDENCE/host-config.stderr"
PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
  node "$ROOT/tools/g7_observer_journey_browser.mjs" \
  --origin http://127.0.0.1:8000 --evidence "$EVIDENCE" --fixture-root "$RUN_ROOT" \
  $([[ $MODE == --backup-recovery-only ]] && printf '%s' '--backup-seed-only') \
  >"$EVIDENCE/browser-journey.stdout" 2>"$EVIDENCE/browser-journey.stderr"

if [[ $MODE == --backup-recovery-only ]]; then
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
  NETWORKS_JSON=$(docker inspect "$CONTAINER" --format '{{json .NetworkSettings.Networks}}')
  [[ $(NETWORKS_JSON="$NETWORKS_JSON" python3 -c 'import json,os; print(len(json.loads(os.environ["NETWORKS_JSON"])))') == 0 ]] || {
    echo 'host network endpoint removal was not confirmed' >&2; exit 2;
  }
  for port in 8000 8002 9000; do
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
    FENCE_CONTAINER_ID=$FENCE_CONTAINER_ID FENCE_IMAGE_ID=$FENCE_IMAGE_ID \
    python3 - "$EVIDENCE/ingress-egress-fence.json" <<'PYFENCE'
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path
record={"schema_version":1,"network_name":os.environ["FENCE_NETWORK_NAME"],
"network_id":os.environ["FENCE_NETWORK_ID"],"container_id":os.environ["FENCE_CONTAINER_ID"],
"image_id":os.environ["FENCE_IMAGE_ID"],"endpoint_removed":True,
"loopback_listener_probes_blocked":[8000,8002,9000],"existing_external_tcp_count":0,
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
  PACKAGE_DIGEST=$(python3 - <<'PYPKG'
import hashlib
from pathlib import Path
h=hashlib.sha256()
for name in ('pyproject.toml','uv.lock'):
 p=Path(name); h.update(name.encode()+b'\0'+p.read_bytes()+b'\0')
print('sha256:'+h.hexdigest())
PYPKG
)
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
  ARCHIVE_DIGEST=$(sha256sum "$EVIDENCE/archive/manifest.json" | awk '{print "sha256:"$1}')
  uv run python "$ROOT/tools/g7_backup_recovery.py" startup-token \
    --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
    --volume-ids-json "$RESTORE_VOLUMES_JSON" --archive-digest "$ARCHIVE_DIGEST" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
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
  RESTORE_FIREWALL_TABLE="g7br$(printf '%08x' "$RANDOM")"
  sudo -n nft add table inet "$RESTORE_FIREWALL_TABLE" \
    >"$EVIDENCE/restore-egress-firewall-install.stdout" \
    2>"$EVIDENCE/restore-egress-firewall-install.stderr"
  sudo -n nft "add chain inet $RESTORE_FIREWALL_TABLE forward { type filter hook forward priority -1; policy accept; }" \
    >>"$EVIDENCE/restore-egress-firewall-install.stdout" \
    2>>"$EVIDENCE/restore-egress-firewall-install.stderr"
  sudo -n nft add rule inet "$RESTORE_FIREWALL_TABLE" forward ip saddr "$RESTORE_IP" ct state established,related accept \
    >>"$EVIDENCE/restore-egress-firewall-install.stdout" \
    2>>"$EVIDENCE/restore-egress-firewall-install.stderr"
  sudo -n nft add rule inet "$RESTORE_FIREWALL_TABLE" forward ip saddr "$RESTORE_IP" drop \
    >>"$EVIDENCE/restore-egress-firewall-install.stdout" \
    2>>"$EVIDENCE/restore-egress-firewall-install.stderr"
  sudo -n nft list table inet "$RESTORE_FIREWALL_TABLE" \
    >"$EVIDENCE/restore-egress-firewall-active.txt"
  python3 - "$EVIDENCE/restore-egress-firewall.json" "$RESTORE_IP" "$RESTORE_FIREWALL_TABLE" "$RECOVERY_NETWORK_ID" <<'PYFW'
import json,sys
from datetime import datetime,timezone
json.dump({'schema_version':1,'table':sys.argv[3],'network_id':sys.argv[4],
 'replacement_ipv4':sys.argv[2],'established_replies':'accept','new_forwarded_egress':'drop',
 'installed_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')},
 open(sys.argv[1],'x',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYFW
  RESTORE_STARTED=1
  docker run -d --name "$RESTORE_CONTAINER" --label uvm.g7.backup-recovery=true \
    --network "$RECOVERY_NETWORK" --ip "$RESTORE_IP" \
    -p 127.0.0.1:8000:8000 -p 127.0.0.1:8002:8002 \
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
    --env UVM_G7_DEPLOYMENT_ID=g7-local --env UVM_G7_TARGET_IMAGE_DIGEST="$IMAGE_DIGEST" \
    --env UVM_G7_RECOVERY_VOLUME_IDS="$(cat "$RESTORE_VOLUMES_JSON")" \
    --env UVM_G7_ARCHIVE_DIGEST="$ARCHIVE_DIGEST" --env UVM_G7_RECOVERY_EPOCH="$RECOVERY_EPOCH" \
    --env UVM_G7_CONNECTOR_RECOVERY_ID="$CONNECTOR_RECOVERY_ID" "$IMAGE" \
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
  uv run python "$ROOT/tools/g7_backup_recovery.py" admit-restore \
    --config "$RUN_ROOT/host/backup-controller.json" \
    --manifest "$EVIDENCE/archive/manifest.json" --volume-ids "$RESTORE_VOLUMES_JSON" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
    --drain-proof "$EVIDENCE/signed-drain-proof.json" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
    >"$EVIDENCE/restore-event-acks.json" 2>"$EVIDENCE/restore-event-acks.stderr"
  cp "$RUN_ROOT/host/state/backup/controller-journal.json" "$EVIDENCE/before-replay-controller-journal.json"
  uv run python "$ROOT/tools/g7_backup_recovery.py" admit-restore \
    --config "$RUN_ROOT/host/backup-controller.json" \
    --manifest "$EVIDENCE/archive/manifest.json" --volume-ids "$RESTORE_VOLUMES_JSON" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
    --drain-proof "$EVIDENCE/signed-drain-proof.json" --public-key "$RUN_ROOT/secrets/host-pub.pem" \
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
  product_readers_ready=0
  for _ in $(seq 1 180); do
    if docker exec "$RESTORE_CONTAINER" test -f /run/uvm-g7/pid-api \
        && docker exec "$RESTORE_CONTAINER" test -f /run/uvm-g7/pid-ce-web; then product_readers_ready=1; break; fi
    if [[ $(docker inspect "$RESTORE_CONTAINER" --format '{{.State.Running}}') != true ]]; then break; fi
    sleep 1
  done
  (( product_readers_ready )) || { echo 'replacement did not start both verification-only product listeners after volumes_restored' >&2; exit 2; }
  product_api_ready=0
  for _ in $(seq 1 60); do
    if curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/openapi.json \
        >"$EVIDENCE/restore-uvm-openapi.json" 2>"$EVIDENCE/restore-uvm-openapi.stderr"; then
      product_api_ready=1; break
    fi
    sleep 1
  done
  if (( ! product_api_ready )); then
    docker exec "$RESTORE_CONTAINER" ps -eo pid,ppid,uid,stat,args \
      >"$EVIDENCE/restore-processes.txt" 2>&1 || true
    docker exec "$RESTORE_CONTAINER" cat /run/uvm-g7/api.log \
      >"$EVIDENCE/restore-api-startup.log" 2>&1 || true
    docker exec "$RESTORE_CONTAINER" cat /run/uvm-g7/ce-web.log \
      >"$EVIDENCE/restore-ce-startup.log" 2>&1 || true
    echo 'replacement UVM public API did not become reachable on its loopback listener' >&2
    exit 2
  fi
  restore_ce_ready=0
  for _ in $(seq 1 90); do
    if docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 5 \
        -u "admin:$CE_ADMIN_PASSWORD" 'http://127.0.0.1:8081/api/v2/findings/?limit=1' \
        >"$EVIDENCE/restore-ce-readiness.json" 2>"$EVIDENCE/restore-ce-readiness.stderr"; then
      restore_ce_ready=1; break
    fi
    sleep 1
  done
  if (( ! restore_ce_ready )); then
    docker exec "$RESTORE_CONTAINER" ps -eo pid,ppid,uid,stat,args \
      >"$EVIDENCE/restore-processes.txt" 2>&1 || true
    docker exec "$RESTORE_CONTAINER" cat /run/uvm-g7/ce-web.log \
      >"$EVIDENCE/restore-ce-startup.log" 2>&1 || true
    echo 'replacement CE public API did not become reachable on its loopback listener' >&2
    exit 2
  fi
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
if restored['count'] < 1: raise SystemExit('CE public readback has no retained sentinel finding')
PYRESTORECE
  docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
    "http://127.0.0.1:8081/api/v2/findings/$FINDING_ID/files/download/$MEDIA_ID/" >"$EVIDENCE/restore-ce-media.txt"
  cmp "$EVIDENCE/source-ce-media.txt" "$EVIDENCE/restore-ce-media.txt"
  docker exec "$RESTORE_CONTAINER" curl --fail --silent --show-error --max-time 15 -u "admin:$CE_ADMIN_PASSWORD" \
    "http://127.0.0.1:8081/api/v2/engagements/$ENGAGEMENT_ID/" >"$EVIDENCE/restore-ce-engagement.json"
  cmp "$EVIDENCE/source-ce-engagement.json" "$EVIDENCE/restore-ce-engagement.json"
  chmod 600 "$EVIDENCE/restore-ce-findings.json" "$EVIDENCE/restore-ce-public-sentinel.json"
  python3 - "$EVIDENCE/recovery-auth-state.json" "$EVIDENCE" <<'PYPUBLICPROBE'
import http.client,json,sys,urllib.error,urllib.request
from pathlib import Path
state=json.load(open(sys.argv[1],encoding='utf-8'))
cookies=[c for c in state.get('cookies',[]) if c.get('name')=='uvm_session' and c.get('domain')=='127.0.0.1']
if len(cookies)!=1: raise SystemExit('recovery browser state must contain exactly one UVM session cookie')
cookie=cookies[0]['value']
root=Path(sys.argv[2])
for name,path in [('recovery-session','/api/v1/auth/session'),
                  ('recovery-backup-discovery','/api/v1/operations/backup-settings'),
                  ('recovery-backup-readback','/api/v1/operations/backup-settings/g7-local')]:
 request=urllib.request.Request('http://127.0.0.1:8000'+path,headers={'Cookie':'uvm_session='+cookie,'Accept':'application/json'})
 try:
  with urllib.request.urlopen(request,timeout=15) as response:
   status=response.status; body=response.read()
 except urllib.error.HTTPError as error:
  status=error.code; body=error.read()
 except Exception as error:
  json.dump({'status':None,'transport_error':type(error).__name__},open(root/(name+'.json'),'w',encoding='utf-8'),sort_keys=True)
  continue
 try:
  value=json.loads(body)
  if name=='recovery-session' and isinstance(value,dict): value.pop('csrf_token',None)
 except Exception:
  value={'body_bytes':len(body)}
 json.dump({'status':status,'response':value},open(root/(name+'.json'),'w',encoding='utf-8'),sort_keys=True,separators=(',',':'))
PYPUBLICPROBE
  uv run python "$ROOT/tools/g7_recovery_public_readback.py" --evidence "$EVIDENCE" --phase pre-migration \
    >"$EVIDENCE/pre-migration-public-readback.json"
  set +e
  docker exec "$RESTORE_CONTAINER" bash -lc \
    'export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; cd /opt/uvm/app; exec /opt/uvm/venv/bin/python -m alembic -c alembic.ini upgrade head' \
    >"$EVIDENCE/explicit-migration.stdout" 2>"$EVIDENCE/explicit-migration.stderr"
  MIGRATION_EXIT=$?
  set -e
  printf '%s\n' "$MIGRATION_EXIT" >"$EVIDENCE/explicit-migration.exit"
  (( MIGRATION_EXIT == 0 )) || exit "$MIGRATION_EXIT"
  # Renew the startup context, restart verification processes after the explicit
  # migration, and obtain a fresh authenticated checkpoint before readers return.
  rm "$RUN_ROOT/secrets/startup-fence.json"
  uv run python "$ROOT/tools/g7_backup_recovery.py" startup-token \
    --deployment-id g7-local --image-digest "$IMAGE_DIGEST" \
    --volume-ids-json "$RESTORE_VOLUMES_JSON" --archive-digest "$ARCHIVE_DIGEST" \
    --recovery-epoch "$RECOVERY_EPOCH" --connector-recovery-id "$CONNECTOR_RECOVERY_ID" \
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
  uv run python - "$RUN_ROOT/host/backup-controller.json" "$EVIDENCE" <<'PYFINISH'
from datetime import datetime,timedelta,timezone
import hashlib,json,sys,urllib.request,uuid
from pathlib import Path
from tools.g7_backup_controller import Controller,load_config,atomic_json
from uvm.operations.backup_host import digest
config=load_config(Path(sys.argv[1])); controller=Controller(config); root=Path(sys.argv[2])
if (root/'explicit-migration.exit').read_text().strip()!='0': raise ValueError('explicit migration failed')
for phase in ('pre-migration','post-migration'):
 if json.loads((root/(phase+'-public-readback.json')).read_text()).get('passed') is not True: raise ValueError('public retained assertions missing')
for name in ('media.txt','engagement.json'):
 if (root/('source-ce-'+name)).read_bytes() != (root/('restore-ce-'+name)).read_bytes(): raise ValueError('CE retained sentinel differs')
files=['pre-migration-public-readback.json','post-migration-public-readback.json','source-ce-public-sentinel.json','restore-ce-public-sentinel.json','source-ce-media.txt','restore-ce-media.txt','source-ce-engagement.json','restore-ce-engagement.json','explicit-migration.exit','signed-drain-proof.json']
readbacks={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}
readback_digest='sha256:'+digest(readbacks)
atomic_json(root/'verification-readback-manifest.json',readbacks)
last=controller.state['last_recovery_event']['event']
unsigned={k:v for k,v in last.items() if k not in {'signature','sequence','controller_instance_id'}}
verification={k:'passed' for k in ('uvm_public_api','ce_public_api','media_readback','queue_reconciliation','migration')}
verification['details_digest']=readback_digest
unsigned.update(event_id=str(uuid.uuid4()),previous_epoch=last['recovery_epoch'],event_type='verification_passed',verification=verification,public_readback_digest=readback_digest,observed_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
verified=controller.submit_recovery_event(unsigned)
storage=json.loads((root/'recovery-auth-state.json').read_text())
cookie=next(c['value'] for c in storage['cookies'] if c['name']=='uvm_session' and c['domain']=='127.0.0.1')
request=urllib.request.Request('http://127.0.0.1:8000/api/v1/operations/backup-settings/g7-local',headers={'Cookie':'uvm_session='+cookie})
with urllib.request.urlopen(request,timeout=15) as response: dto=json.load(response)
manifest=json.loads((root/'archive/manifest.json').read_text())
now=datetime.now(timezone.utc);completed=datetime.fromisoformat(manifest['completed_at'].replace('Z','+00:00'))
maximum=dto['desired']['values']['maximum_backup_age_seconds'];age=int((now-completed).total_seconds())
status={'schema_version':1,'deployment_id':controller.deployment,'report_id':str(uuid.uuid4()),'report_kind':'status','host_policy':config['host_policy'],
 'desired':{k:dto['desired'][k] for k in ('revision','digest')},'settings_application':dto['status']['settings_application'],
 'completed_archive':{'archive_id':manifest['archive_id'],'completed_at':manifest['completed_at'],'manifest_digest':'sha256:'+hashlib.sha256((root/'archive/manifest.json').read_bytes()).hexdigest(),'outcome':'complete'},
 'freshness':{'state':'fresh' if age<=maximum else 'stale','evaluated_at':now.isoformat().replace('+00:00','Z'),'age_seconds':age,'basis_completed_at':manifest['completed_at'],'maximum_backup_age_seconds':maximum},
 'restore_verification':dto['status']['restore_verification'],'recovery_epoch':last['recovery_epoch'],
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
  sudo -n nft delete table inet "$RESTORE_FIREWALL_TABLE" >"$EVIDENCE/host-egress-release.stdout" 2>"$EVIDENCE/host-egress-release.stderr"
  RESTORE_FIREWALL_TABLE=''
  python3 - "$EVIDENCE/host-fence-release-journal.json" <<'PYRELEASE'
from datetime import datetime,timezone
import json,os,sys
from pathlib import Path
path=Path(sys.argv[1]); value={'signed_public_acknowledgement_retained':True,'ingress':'loopback-only-disposable','egress_rule_removed':True,'workers_release_requested':False,'observed_at':datetime.now(timezone.utc).isoformat()}
with path.open('x') as stream:
 json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
PYRELEASE
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
  PYTHONPATH="$ROOT" uv run python "$ROOT/tools/g7_recovery_runtime_probe.py" \
    --container "$RESTORE_CONTAINER" --evidence "$EVIDENCE" >"$EVIDENCE/released-runtime-proof.stdout" \
    2>"$EVIDENCE/released-runtime-proof.stderr"
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
  finish_operation_deadline verification
  echo 'G7 recovery-only signed archive restored into new volumes; UVM UI and CE public retained-state readback passed' | tee "$EVIDENCE/result.txt"
  exit 0
fi
echo 'G7 observer-settings-only journey completed' | tee "$EVIDENCE/result.txt"
