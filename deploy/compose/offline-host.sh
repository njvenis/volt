#!/bin/sh
# Authenticated package functions; sourced only after caller admission.
# No standalone action, verifier selection or authority flag exists here.

_offline_data_exec() {
  stdin_flag=''; case "$1" in filter-stop-*) stdin_flag=-i ;; esac
  case "$1" in
    queried-stopped-identity)
      [ "$#" -eq 1 ] || return 1
      # One fixed typed projection of the SAME saved inspection, not a fresh
      # context selector. No code, module or path comes from an argument.
      set -- -c 'import json,re
from uvm.installer import offline_lifecycle as data
raw=data._bounded_file(data.OBSERVATION/"docker.json",data.MAX_INPUT,private=True)
observed=json.loads(raw,object_pairs_hook=data.pairs)
if (type(observed) is not dict or set(observed)!={"image","containers","volumes","networks"}
    or any(type(observed[key]) is not list for key in observed)
    or any(type(row) is not dict for rows in observed.values() for row in rows)
    or len(observed["image"])!=1 or type(observed["image"][0]) is not dict
    or len(observed["containers"])!=1
    or type(observed["containers"][0].get("State")) is not dict):
    raise ValueError("one saved current Docker inspection required")
item=data.project_observation(observed)["containers"][0]
cid=item["Id"]
if type(cid) is not str or re.fullmatch("[0-9a-f]{64}",cid) is None:
    raise ValueError("full canonical saved container ID required")
started=data._started_at(item["State"]["StartedAt"])
print(cid+"|"+started)'
      ;;
    emit-stopped-observation|emit-observation)
      # Assemble only existing closed data/phase frames, using the SAME codec.
      # This removes encode -> host file -> second Docker startup. It never
      # validates/seals an outcome; the independent final validator remains.
      set -- -c 'import json,sys
from uvm.installer import offline_lifecycle as data, stopped_transport as wire
arguments=sys.argv[1:]
if arguments==["emit-stopped-observation"]:
    phase=None
elif (len(arguments)==3 and arguments[:2]==["emit-observation","--phase"]
      and arguments[2] in ("observed","captured","provisioned")):
    phase=arguments[2]
else:
    raise ValueError("fixed observation assembly arguments required")
def read(name,limit):
    return data._bounded_file(data.OBSERVATION/name,limit,private=True)
def document(name,limit):
    return json.loads(read(name,limit),object_pairs_hook=data.pairs)
data._directory(data.OBSERVATION)
projected=data.project_observation(document("docker.json",data.MAX_INPUT))
if phase is None and len(projected["containers"])!=1:
    raise ValueError("one current stopped container required")
if projected["containers"]:
    item=projected["containers"][0]
    logs=wire.encode(item,read("stop-wait.stdout",2),read("stop-routing.tar",131072),
        read("stop-envelope.json",2048),document("stop-post-container.json",65536),
        document("stop-producer-statuses.json",4096))
    proof,_tar,_envelope=wire.decode(logs)
    since=data._started_at(proof["queried_started_at"])
else:
    logs,since="",None
projected.update(logs=logs,logs_since=since,inventories=document("inventories.json",65536),
    independent_admission=document("independent-admission.json",1048576))
if phase is None:
    value=projected
else:
    previous,raw=data._response({"observed":"plan","captured":"capture","provisioned":"provision"}[phase])
    value={**previous,"phase":phase,"predecessor_sha256":data.digest(raw),"data":projected}
encoded=data.canonical(value)
if len(encoded)>data.MAX_INPUT:
    raise ValueError("closed observation exceeds bound")
sys.stdout.buffer.write(encoded)' "$@"
      ;;
    *) set -- -m uvm.installer.offline_lifecycle "$@" ;;
  esac
  exec docker run --platform "$PLATFORM" --pull=never --rm $stdin_flag --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$OFFLINE_OUTPUT,dst=/run/volt-offline-output,readonly" \
    --mount "type=bind,src=$OFFLINE_OBSERVATION,dst=/run/volt-offline-observation,readonly" \
    --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly" \
    --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" "$@"
}

offline_data() {
  if [ -n "${OFFLINE_STOP_DEADLINE_CS:-}" ]; then offline_host_data "$@"
  else ( _offline_data_exec "$@" ); fi
}

# Host clock only; no assumption that Desktop/daemon BOOTTIME equals this host.
OFFLINE_STOP_DEADLINE_CS=''
OFFLINE_ORDINARY_STOP_DEADLINE_CS=''
offline_stop_clock() {
  IFS=' ' read -r stop_uptime stop_unused </proc/uptime || return 1
  stop_seconds=${stop_uptime%.*}; stop_fraction=${stop_uptime#*.}
  case "$stop_seconds:$stop_fraction" in *[!0-9:]*|:*) return 1 ;; esac
  [ "${#stop_fraction}" -eq 2 ] || return 1
  OFFLINE_NOW_CS=$((stop_seconds * 100 + 1$stop_fraction - 100))
}

offline_stop_before() {
  offline_stop_clock || return 1
  [ "$OFFLINE_NOW_CS" -lt "$OFFLINE_STOP_DEADLINE_CS" ]
}

# The producer is an original Bash/POSIX child; ticks are comparison data only.
# No process search, replacement/adoption, or numeric-PID kill after uncertainty.
offline_producer_ticks() {
  IFS= read -r stop_proc_line <"/proc/$1/stat" || return 1
  stop_proc_tail=${stop_proc_line##*) }
  [ "$stop_proc_tail" != "$stop_proc_line" ] || return 1
  set -- $stop_proc_tail
  [ "$#" -ge 20 ] || return 1
  shift 19
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s' "$1"
}

# Temporary gates and negative timeout files are host mechanics only. They are
# never terminal proof, Store authority, or input to the nested wire.
OFFLINE_JOB_SEQUENCE=0
offline_host_start() {
  RETAIN_STOP_EVIDENCE=1
  stop_job_kind=$1; stop_job_input=$2; stop_job_output=$3; stop_job_deadline=$4; shift 4
  case "$stop_job_kind" in
    snapshot|report) [ "$#" -eq 0 ] || return 1 ;;
    data) case "${1:-}" in queried-*|filter-stop-*|encode-stopped-transport|emit-stopped-observation|emit-observation|plan-lines) ;; *) return 1 ;; esac ;;
    docker) case "${1:-}:${2:-}" in wait:*|cp:*|logs:*|inspect:*|image:inspect|container:inspect|volume:inspect|network:inspect|info:--format|context:inspect|context:show) ;; *) return 1 ;; esac ;;
    setup) [ "$#" -eq 0 ] || return 1 ;;
    *) return 1 ;;
  esac
  offline_stop_clock || return 1
  [ "$OFFLINE_NOW_CS" -lt "$stop_job_deadline" ] || return 1
  IFS=' ' read -r stop_parent stop_parent_rest </proc/self/stat || return 1
  stop_parent_ticks=$(offline_producer_ticks "$stop_parent") || return 1
  OFFLINE_JOB_SEQUENCE=$((OFFLINE_JOB_SEQUENCE + 1))
  OFFLINE_JOB="$WORK/stop-job-$stop_parent-$OFFLINE_JOB_SEQUENCE"
  mkdir -m 700 "$OFFLINE_JOB" || return 1
  stop_job=$OFFLINE_JOB
  (
    while [ ! -f "$stop_job/gate" ]; do
      offline_stop_clock && [ "$OFFLINE_NOW_CS" -lt "$stop_job_deadline" ] || exit 124
      sleep .01 || exit 124
    done
    [ ! -L "$stop_job/gate" ] || exit 124
    IFS= read -r stop_gate <"$stop_job/gate" && [ "$stop_gate" = G ] || exit 124
    ulimit -f 16384 || exit 125
    if [ -n "$stop_job_input" ]; then exec 0<"$stop_job_input"; fi
    if [ -n "$stop_job_output" ]; then exec 1>"$stop_job_output"; fi
    offline_stop_clock && [ "$OFFLINE_NOW_CS" -lt "$stop_job_deadline" ] || exit 124
    case "$stop_job_kind" in
      snapshot) offline_snapshot_body >"$stop_job/stdout" 2>"$stop_job/stderr" ;;
      report) exec cat "$stop_job_input" 2>"$stop_job/stderr" ;;
      data) _offline_data_exec "$@" >"$stop_job/stdout" 2>"$stop_job/stderr" ;;
      docker)
        if [ -n "$stop_job_output" ]; then exec docker "$@" 2>&1
        else exec docker "$@" >"$stop_job/stdout" 2>"$stop_job/stderr"; fi ;;
      setup) HELPER_EXEC_ONLY=1 _helper_command "$STATE" host-stop-validate /state >"$stop_job/stdout" 2>"$stop_job/stderr" ;;
    esac
  ) &
  stop_child=$!
  stop_child_ticks=$(offline_producer_ticks "$stop_child") || return 1
  (
    exec </dev/null >/dev/null 2>&1
    while :; do
      [ ! -f "$stop_job/cancel" ] || exit 0
      stop_current=$(offline_producer_ticks "$stop_child" 2>/dev/null) || stop_current=''
      [ "$stop_current" = "$stop_child_ticks" ] || exit 0
      if ! offline_stop_clock || [ "$OFFLINE_NOW_CS" -ge "$stop_job_deadline" ]; then
        printf 'timeout\n' >"$stop_job/timeout" || :
        # Shell cannot atomically signal a PID/proc-ticks tuple. Timeout is
        # negative-only: retain exact RO client records, never signal by PID.
        exit 124
      fi
      sleep .01 || exit 124
    done
  ) &
  stop_guard=$!
  stop_guard_ticks=$(offline_producer_ticks "$stop_guard") || return 1
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$stop_child" "$stop_child_ticks" "$stop_guard" "$stop_guard_ticks" \
    "$stop_parent" "$stop_parent_ticks" "$stop_job_deadline" >"$stop_job/registered"
  offline_stop_clock && [ "$OFFLINE_NOW_CS" -lt "$stop_job_deadline" ] || return 124
  # Private monotonic measurement only; never part of completion authority.
  printf '%s\n' "$stop_job_kind" >"$stop_job/kind" || return 1
  printf '%s\n' "$OFFLINE_NOW_CS" >"$stop_job/released-centiseconds" || return 1
  printf 'G\n' >"$stop_job/gate"
}

offline_host_dead() {
  # Absence or an actual zombie is death; SIGSTOP/permission uncertainty is NOT.
  if [ ! -e "/proc/$1/stat" ]; then return 0; fi
  IFS= read -r stop_dead_stat <"/proc/$1/stat" || return 1
  stop_dead_tail=${stop_dead_stat##*) }
  case "$stop_dead_tail" in 'Z '*|'X '*) return 0 ;; *) return 1 ;; esac
}

offline_host_finish() {
  RETAIN_STOP_EVIDENCE=1
  stop_finish_job=$1
  case "$stop_finish_job" in "$WORK"/stop-job-*) ;; *) return 1 ;; esac
  [ -f "$stop_finish_job/registered" ] && [ ! -L "$stop_finish_job/registered" ] || return 1
  IFS='|' read -r stop_child stop_child_ticks stop_guard stop_guard_ticks stop_parent stop_parent_ticks stop_job_deadline <"$stop_finish_job/registered"
  case "$stop_child:$stop_child_ticks:$stop_guard:$stop_guard_ticks:$stop_parent:$stop_parent_ticks:$stop_job_deadline" in *[!0-9:]*|'') return 1 ;; esac
  IFS=' ' read -r stop_actual_parent stop_rest </proc/self/stat || return 1
  [ "$stop_actual_parent" = "$stop_parent" ] && [ "$(offline_producer_ticks "$stop_parent")" = "$stop_parent_ticks" ] || return 1
  stop_result=0; stop_reason=completed
  while ! offline_host_dead "$stop_child"; do
    stop_current=$(offline_producer_ticks "$stop_child" 2>/dev/null) || stop_current=''
    if [ -z "$stop_current" ]; then
      stop_result=255; stop_reason=tick_read_unavailable; break
    fi
    [ "$stop_current" = "$stop_child_ticks" ] || { stop_result=255; stop_reason=identity_mismatch; break; }
    if ! offline_stop_clock || [ "$OFFLINE_NOW_CS" -ge "$stop_job_deadline" ]; then
      stop_result=124; stop_reason=deadline
      break
    fi
    sleep .01 || { stop_result=255; stop_reason=poll_interrupted; break; }
  done
  if offline_host_dead "$stop_child"; then
    stop_wait=0; wait "$stop_child" || stop_wait=$?
    printf '%s\n' "$stop_wait" >"$stop_finish_job/child-wait" || { stop_result=255; stop_reason=record_io_failed; }
    # A child can disappear after the live check and before its ticks read.
    # Resolve ONLY that missing-read case using proved death and this parent's
    # exact original-child wait. A different identity is never resolved here.
    if [ "$stop_result" -eq 0 ] || [ "$stop_reason" = tick_read_unavailable ]; then
      stop_result=$stop_wait
      if [ "$stop_wait" -eq 127 ]; then stop_reason=wait_status_127
      elif [ "$stop_wait" -ne 0 ]; then stop_reason=child_nonzero
      elif [ "$stop_reason" = tick_read_unavailable ]; then stop_reason=completed_after_tick_read
      fi
    fi
  elif [ "$stop_result" -ne 124 ]; then
    stop_result=255
    [ "$stop_reason" = identity_mismatch ] || stop_reason=child_live_uncertain
  fi
  printf 'cancel\n' >"$stop_finish_job/cancel" || { stop_result=255; stop_reason=record_io_failed; }
  # Finish polling is itself finite; no wait on a live/STOPPED guard.
  if ! offline_stop_clock; then
    printf 'clock_unavailable\n' >"$stop_finish_job/reason" || :
    printf '124\n' >"$stop_finish_job/result" || :
    return 124
  fi
  stop_guard_deadline=$((OFFLINE_NOW_CS + 20))
  [ "$stop_guard_deadline" -le "$stop_job_deadline" ] || stop_guard_deadline=$stop_job_deadline
  while ! offline_host_dead "$stop_guard"; do
    if ! offline_stop_clock || [ "$OFFLINE_NOW_CS" -ge "$stop_guard_deadline" ]; then
      stop_result=124; stop_reason=deadline
      break
    fi
    sleep .01 || { stop_result=255; stop_reason=poll_interrupted; break; }
  done
  if offline_host_dead "$stop_guard"; then
    stop_guard_wait=0; wait "$stop_guard" || stop_guard_wait=$?
    printf '%s\n' "$stop_guard_wait" >"$stop_finish_job/guard-wait" || { stop_result=255; stop_reason=record_io_failed; }
    [ "$stop_guard_wait" -eq 0 ] || { stop_result=124; stop_reason=guard_nonzero; }
  elif [ "$stop_result" -ne 124 ]; then stop_result=255; stop_reason=guard_live_uncertain; fi
  [ ! -f "$stop_finish_job/timeout" ] || { stop_result=124; stop_reason=deadline; }
  if ! offline_stop_clock; then stop_result=124; stop_reason=clock_unavailable
  elif [ "$OFFLINE_NOW_CS" -ge "$stop_job_deadline" ]; then stop_result=124; stop_reason=deadline; fi
  printf '%s\n' "$OFFLINE_NOW_CS" >"$stop_finish_job/finished-centiseconds" || { stop_result=255; stop_reason=record_io_failed; }
  printf '%s\n' "$stop_reason" >"$stop_finish_job/reason" || stop_result=255
  printf '%s\n' "$stop_result" >"$stop_finish_job/result" || stop_result=255
  if [ "$stop_result" -ne 0 ]; then
    RETAIN_STOP_EVIDENCE=1
    printf '%s\n' 'readonly client completion uncertain; private original job records retained' >&2
  fi
  return "$stop_result"
}

offline_host_data() {
  offline_host_start data '' '' "$OFFLINE_STOP_DEADLINE_CS" "$@" || return 1
  stop_data_job=$OFFLINE_JOB
  offline_host_finish "$stop_data_job" || return $?
  offline_host_start report "$stop_data_job/stdout" '' "$OFFLINE_STOP_DEADLINE_CS" || return 1
  stop_data_report=$OFFLINE_JOB
  offline_host_finish "$stop_data_report"
}

offline_capture_stream() {
  STOP_PRODUCER_STATUS=255; STOP_FILTER_STATUS=255
  stop_kind=$1; stop_budget=$2; stop_output=$3; shift 3
  case "$stop_kind:$stop_budget" in wait:50|tar:100|logs:1000|post:50) ;; *) return 1 ;; esac
  [ "$1" = docker ] || return 1; shift
  offline_stop_before || return 1
  # Parser limits begin inside the fixed filter after Docker startup. Host
  # startup/tracking shares the ORIGINAL aggregate deadline, without reset.
  stop_phase_deadline=$OFFLINE_STOP_DEADLINE_CS
  stop_fifo="$WORK/stopped-$stop_kind-stream"
  mkfifo "$stop_fifo" || return 1
  offline_host_start docker '' "$stop_fifo" "$stop_phase_deadline" "$@" || return 1
  stop_producer_job=$OFFLINE_JOB
  offline_host_start data "$stop_fifo" '' "$stop_phase_deadline" "filter-stop-$stop_kind" \
    >"$OFFLINE_OBSERVATION/$stop_output" 2>/dev/null || return 1
  stop_reader_job=$OFFLINE_JOB
  STOP_FILTER_STATUS=0; offline_host_finish "$stop_reader_job" || STOP_FILTER_STATUS=$?
  if [ "$STOP_FILTER_STATUS" -eq 0 ]; then cp "$stop_reader_job/stdout" "$OFFLINE_OBSERVATION/$stop_output" || STOP_FILTER_STATUS=1; fi
  STOP_PRODUCER_STATUS=0; offline_host_finish "$stop_producer_job" || STOP_PRODUCER_STATUS=$?
  rm "$stop_fifo" || STOP_FILTER_STATUS=1
  chmod 600 "$OFFLINE_OBSERVATION/$stop_output" || STOP_FILTER_STATUS=1
  [ "$STOP_PRODUCER_STATUS" -eq 0 ] && [ "$STOP_FILTER_STATUS" -eq 0 ]
}

offline_capture_shutdown() {
  RETAIN_STOP_EVIDENCE=1
  offline_stop_clock || fail 'host stopped-acquisition clock is unavailable'
  if [ -z "$OFFLINE_STOP_DEADLINE_CS" ]; then OFFLINE_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS + 1300)); fi
  if [ -n "$OFFLINE_ORDINARY_STOP_DEADLINE_CS" ] && [ "$OFFLINE_ORDINARY_STOP_DEADLINE_CS" -lt "$OFFLINE_STOP_DEADLINE_CS" ]; then
    OFFLINE_STOP_DEADLINE_CS=$OFFLINE_ORDINARY_STOP_DEADLINE_CS
  fi
  stopped_identity=$(offline_data queried-stopped-identity) || fail 'actual current identity could not be decoded from saved inspection'
  stopped_cid=${stopped_identity%%|*}; started=${stopped_identity#*|}
  case "$stopped_cid" in ''|*[!0-9a-f]*) fail 'saved current container ID is malformed' ;; esac
  [ "${#stopped_cid}" -eq 64 ] || fail 'saved current container ID is incomplete'
  case "$started" in ''|*[!0-9TZ.:-]*) fail 'saved current StartedAt is malformed' ;; esac
  [ "${#started}" -le 40 ] || fail 'saved current StartedAt exceeds bound'
  offline_stop_before || fail 'current stopped-acquisition deadline expired'
  stop_statuses="$OFFLINE_OBSERVATION/stop-producer-statuses.json"
  printf '{' >"$stop_statuses"
  for stop_part in wait tar logs post; do
    case "$stop_part" in
      wait) set -- wait 50 stop-wait.stdout docker wait "$stopped_cid"; stop_keys=docker_wait ;;
      tar) set -- tar 100 stop-routing.tar docker cp "$stopped_cid:/run/uvm-route-check/." -; stop_keys=routing_tar ;;
      logs) set -- logs 1000 stop-envelope.json docker logs --tail 256 --since "$started" "$stopped_cid"; stop_keys=docker_logs ;;
      post) set -- post 50 stop-post-container.json docker inspect "$stopped_cid"; stop_keys=post_inspect ;;
    esac
    stop_capture_status=0
    offline_capture_stream "$@" || stop_capture_status=1
    [ "$stop_part" = wait ] || printf ',' >>"$stop_statuses"
    printf '"%s_producer_exit":%s,"%s_filter_exit":%s' "$stop_keys" "${STOP_PRODUCER_STATUS:-255}" "$stop_keys" "${STOP_FILTER_STATUS:-255}" >>"$stop_statuses"
    if [ "$stop_capture_status" -ne 0 ]; then
      printf '}' >>"$stop_statuses"; chmod 600 "$stop_statuses"
      fail 'private current stopped acquisition failed; independent producer/reader outcomes retained'
    fi
    ensure_lock_owner
  done
  printf '}' >>"$stop_statuses"; chmod 600 "$stop_statuses"
  offline_stop_before || fail 'current stopped-acquisition deadline expired'
  # The fixed observation emitter encodes these exact raw inputs in-process;
  # stop and backup share it, with no additional startup or cached-proof path.
}

offline_wait() {
  phase=$1; attempts=0
  while [ "$attempts" -lt 900 ]; do
    ensure_lock_owner
    running=$(docker inspect "$LOCK_NAME" --format '{{.State.Running}}') || fail 'offline lock owner disappeared; no completion may be inferred'
    if [ "$running" != true ]; then
      docker logs "$LOCK_NAME" >&2 || :
      fail 'offline owner stopped; publication may already have committed; use exact read-only backup-status, never overwrite or promote a partial'
    fi
    if [ -f "$OFFLINE_OUTPUT/$phase.json" ] && [ ! -L "$OFFLINE_OUTPUT/$phase.json" ]; then return; fi
    attempts=$((attempts + 1)); sleep 1
  done
  fail 'offline operation timed out waiting for its actual FD owner'
}

offline_plan() {
  phase=$1
  offline_wait "$phase"
  lines=$(offline_data plan-lines --phase "$phase") || fail 'offline owner returned an invalid closed plan'
  PARTIAL_NAME=''
  while IFS='=' read -r key value; do
    case "$key" in
      project) [ "$value" = "$PROJECT" ] || fail 'offline plan project changed' ;;
      owner_token) [ "$value" = "$OWNER_TOKEN" ] || fail 'offline plan ownership changed' ;;
      image) [ "$value" = "$IMAGE_REF" ] || fail 'offline plan image changed' ;;
      platform) [ "$value" = "$PLATFORM" ] || fail 'offline plan platform changed' ;;
      subnet) OFFLINE_SUBNET=$value ;;
      gateway) OFFLINE_GATEWAY=$value ;;
      network_internal) [ "$value" = 0 ] || fail 'ordinary offline network policy changed' ;;
      network) [ "$value" = "${PROJECT}_network" ] || fail 'offline network escaped selected project' ;;
      container) [ "$value" = "${PROJECT}-volt-1" ] || fail 'offline container escaped selected project' ;;
      volume_postgres) [ "$value" = "${PROJECT}_postgres" ] || fail 'offline PostgreSQL volume changed' ;;
      volume_media) [ "$value" = "${PROJECT}_media" ] || fail 'offline media volume changed' ;;
      volume_state) [ "$value" = "${PROJECT}_state" ] || fail 'offline state volume changed' ;;
      partial_name) PARTIAL_NAME=$value ;;
      operation_id)
        [ -z "${OFFLINE_OPERATION_ID:-}" ] || [ "$value" = "$OFFLINE_OPERATION_ID" ] || fail 'offline operation UUID changed'
        OFFLINE_OPERATION_ID=$value ;;
      identity_sha256)
        if [ -n "${OFFLINE_IDENTITY_SHA256:-}" ] && [ "$ACTION:$phase" != restore-provision:provision ]; then
          [ "$value" = "$OFFLINE_IDENTITY_SHA256" ] || fail 'offline identity changed outside the durable restore transition'
        fi
        OFFLINE_IDENTITY_SHA256=$value ;;
      phase) : ;;
      *) fail 'unknown closed offline plan field' ;;
    esac
  done <<EOF_OFFLINE_PLAN
$lines
EOF_OFFLINE_PLAN
  if [ "$phase" = plan ]; then
    printf 'offline_operation_id=%s\noffline_identity_sha256=%s\n' "$OFFLINE_OPERATION_ID" "$OFFLINE_IDENTITY_SHA256"
  fi
}

run_backup_status() {
  [ -n "$BACKUP_DIRECTORY" ] && [ -n "$BACKUP_OPERATION_ID" ] && [ -n "$BACKUP_IDENTITY_SHA256" ] \
    || fail 'backup-status requires exact backup directory, original operation ID and identity SHA256'
  [ -d "$BACKUP_DIRECTORY" ] && [ ! -L "$BACKUP_DIRECTORY" ] || fail 'published backup directory is missing or linked'
  parent=$(cd -P -- "$(dirname -- "$BACKUP_DIRECTORY")" && pwd -P) || fail 'published backup parent is inaccessible'
  backup_name=${BACKUP_DIRECTORY##*/}
  case "$backup_name" in ''|.*|*[!A-Za-z0-9._-]*) fail 'backup-status cannot promote or acknowledge a private partial name' ;; esac
  backup_directory="$parent/$backup_name"
  case "$backup_directory" in *,*|*:*) fail 'published backup path cannot contain bind separators' ;; esac
  docker run --platform "$PLATFORM" --pull=never --rm --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$STATE,dst=/state,readonly" --mount "type=bind,src=$backup_directory,dst=/backup,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.offline_lifecycle backup-status \
    --backup-name "$backup_name" --operation-id "$BACKUP_OPERATION_ID" --identity-sha256 "$BACKUP_IDENTITY_SHA256"
}

offline_inspect_object() {
  kind=$1; name=$2
  if docker "$kind" inspect "$name" --format '{{json .}}' 2>"$WORK/offline-inspect-error"; then return 0; fi
  case "$kind" in
    volume) pattern='no such volume' ;;
    network) pattern='not found' ;;
    container) pattern='No such' ;;
    *) return 1 ;;
  esac
  if grep -F -i "$pattern" "$WORK/offline-inspect-error" >/dev/null; then return 3; fi
  return 1
}

offline_inventory() {
  store=$1
  if [ "$store" = instance ]; then
    source_mount="type=bind,src=$STATE,dst=/restore,readonly"
  else
    actual=$(docker volume inspect "${PROJECT}_$store" --format '{{index .Labels "volt.compose.owner-token"}}|{{.Driver}}|{{json .Options}}') \
      || fail 'offline inventory resource is missing'
    case "$actual" in "$OWNER_TOKEN|local|null"|"$OWNER_TOKEN|local|{}") ;; *) fail 'offline inventory refuses foreign or bind-backed store' ;; esac
    source_mount="type=volume,src=${PROJECT}_$store,dst=/restore,readonly"
  fi
  docker run --platform "$PLATFORM" --pull=never --rm --network none --read-only --cap-drop=ALL \
    --cap-add=DAC_OVERRIDE --security-opt=no-new-privileges --user 0:0 \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --mount "$source_mount" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.offline_backup inventory
}

offline_snapshot_body() {
  ensure_lock_owner
  refresh_installer_admission
  ensure_lock_owner
  cp "$WORK/graph-admission.json" "$OFFLINE_OBSERVATION/independent-admission.json"
  chmod 600 "$OFFLINE_OBSERVATION/independent-admission.json"
  {
    printf '{"image":'
    if docker image inspect --help | grep -q -- --platform; then
      docker image inspect --platform "$PLATFORM" "$IMAGE_REF" || fail 'cached native image inspection failed'
    else
      docker image inspect "$IMAGE_REF" || fail 'cached native image inspection failed'
    fi
    for kind in container volume network; do
      case "$kind" in
        container) key=containers; names="${PROJECT}-volt-1" ;;
        volume) key=volumes; names="${PROJECT}_postgres ${PROJECT}_media ${PROJECT}_state" ;;
        network) key=networks; names="${PROJECT}_network" ;;
      esac
      printf ',"%s":[' "$key"; separator=''
      for name in $names; do
        if object=$(offline_inspect_object "$kind" "$name"); then
          printf '%s%s' "$separator" "$object"; separator=,
        else
          result=$?; [ "$result" -eq 3 ] || fail 'offline Docker inspection is unavailable; absence cannot be inferred'
        fi
      done
      printf ']'
    done
    printf '}\n'
  } >"$OFFLINE_OBSERVATION/docker.json"
  chmod 600 "$OFFLINE_OBSERVATION/docker.json"
}

offline_snapshot() {
  RETAIN_STOP_EVIDENCE=1
  offline_stop_clock || return 1
  if [ -z "$OFFLINE_STOP_DEADLINE_CS" ]; then OFFLINE_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS + 1300)); fi
  if [ -n "$OFFLINE_ORDINARY_STOP_DEADLINE_CS" ] && [ "$OFFLINE_ORDINARY_STOP_DEADLINE_CS" -lt "$OFFLINE_STOP_DEADLINE_CS" ]; then
    OFFLINE_STOP_DEADLINE_CS=$OFFLINE_ORDINARY_STOP_DEADLINE_CS
  fi
  offline_host_start snapshot '' '' "$OFFLINE_STOP_DEADLINE_CS" || fail 'readonly snapshot could not be registered'
  stop_snapshot_job=$OFFLINE_JOB
  offline_host_finish "$stop_snapshot_job" || fail 'readonly snapshot incomplete; private workspace retained'
}

offline_observe() {
  phase=$1
  offline_snapshot
  {
    printf '{'; separator=''
    if [ "$ACTION" != restore-provision ]; then
      stores='postgres media state'
      [ "$phase" != captured ] || stores="$stores instance"
      for store in $stores; do
        value=$(offline_inventory "$store") || fail 'fixed read-only offline inventory failed'
        printf '%s"%s":%s' "$separator" "$store" "$value"; separator=,
      done
    fi
    printf '}\n'
  } >"$OFFLINE_OBSERVATION/inventories.json"
  chmod 600 "$OFFLINE_OBSERVATION/inventories.json"
  if [ "$ACTION" = backup-record ]; then offline_capture_shutdown; fi
  offline_data emit-observation --phase "$phase" >"$OFFLINE_INPUT/.next-phase" || fail 'closed offline observation emission failed'
  chmod 600 "$OFFLINE_INPUT/.next-phase"
  mv "$OFFLINE_INPUT/.next-phase" "$OFFLINE_INPUT/$phase.json"
  OFFLINE_STOP_DEADLINE_CS=''
}

# Read-only validation under the existing original host lifecycle holder. This
# adds no writer/issuer/mount: the same eight-key observation crosses stdin.
run_public_local_stop() {
  offline_stop_clock || fail 'host ordinary-stop clock is unavailable'
  OFFLINE_ORDINARY_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS + 60000))
  verify_actual_mounts
  locked_compose stop --timeout 600
  offline_stop_clock || fail 'host ordinary-stop clock is unavailable'
  [ "$OFFLINE_NOW_CS" -lt "$OFFLINE_ORDINARY_STOP_DEADLINE_CS" ] || fail 'ordinary stop deadline expired'
  RETAIN_STOP_EVIDENCE=1
  OFFLINE_OUTPUT="$WORK/stop-output"; OFFLINE_OBSERVATION="$WORK/stop-observation"
  mkdir -m 700 "$OFFLINE_OUTPUT" "$OFFLINE_OBSERVATION"
  offline_snapshot
  offline_capture_shutdown
  printf '{}' >"$OFFLINE_OBSERVATION/inventories.json"
  chmod 600 "$OFFLINE_OBSERVATION/inventories.json"
  offline_data emit-stopped-observation >"$WORK/stop-proof.json" \
    || fail 'current stopped observation is unavailable'
  chmod 600 "$WORK/stop-proof.json"
  ensure_lock_owner
  offline_host_start setup "$WORK/stop-proof.json" '' "$OFFLINE_STOP_DEADLINE_CS" || fail 'stopped helper could not be registered'
  stop_validation_job=$OFFLINE_JOB
  offline_host_finish "$stop_validation_job" \
    || fail 'current stopped completion validation failed'
  ensure_lock_owner
  offline_stop_clock || fail 'host ordinary-stop clock is unavailable'
  [ "$OFFLINE_NOW_CS" -lt "$OFFLINE_ORDINARY_STOP_DEADLINE_CS" ] || fail 'ordinary stop deadline expired'
  RETAIN_STOP_EVIDENCE=0
}

offline_final_report() {
  offline_stop_clock || fail 'completion report clock is unavailable'
  OFFLINE_STOP_DEADLINE_CS=$((OFFLINE_NOW_CS + 1000))
  offline_host_start docker '' '' "$OFFLINE_STOP_DEADLINE_CS" logs "$LOCK_ID" || fail 'completion report could not be registered'
  stop_report_job=$OFFLINE_JOB
  offline_host_finish "$stop_report_job" || fail 'offline owner completion evidence is unavailable'
  offline_host_start report "$stop_report_job/stdout" '' "$OFFLINE_STOP_DEADLINE_CS" || fail 'completion output could not be registered'
  stop_report_output=$OFFLINE_JOB
  offline_host_finish "$stop_report_output" || fail 'offline owner completion output failed'
  ensure_lock_owner
  printf 'offline_operation=%s\nstatus=complete\n' "$ACTION"
  RETAIN_STOP_EVIDENCE=0
}

run_offline_action() {
  OFFLINE_OPERATION_ID=''; OFFLINE_IDENTITY_SHA256=''
  OFFLINE_INPUT="$WORK/offline-input"; OFFLINE_OUTPUT="$WORK/offline-output"; OFFLINE_OBSERVATION="$WORK/offline-observation"
  mkdir -m 700 "$OFFLINE_INPUT" "$OFFLINE_OUTPUT" "$OFFLINE_OBSERVATION"
  set --
  if [ "$ACTION" = backup-record ]; then
    [ -n "$BACKUP_DIRECTORY" ] || fail 'backup-record requires --backup-directory with a new destination'
    case "$BACKUP_DIRECTORY" in /*) ;; *) BACKUP_DIRECTORY="$PWD/$BACKUP_DIRECTORY" ;; esac
    BACKUP_NAME=${BACKUP_DIRECTORY##*/}
    BACKUP_PARENT=$(cd -P -- "$(dirname -- "$BACKUP_DIRECTORY")" && pwd -P) || fail 'backup parent must be an existing private directory'
    case "$BACKUP_PARENT/" in "$STATE/"|"$STATE/"*) fail 'backup destination cannot be inside the instance' ;; esac
    case "$STATE/" in "$BACKUP_PARENT/"*) fail 'backup parent cannot contain the instance or its operator authority' ;; esac
    case "$BACKUP_PARENT" in *,*|*:*) fail 'backup parent cannot contain bind separators' ;; esac
    set -- --backup-name "$BACKUP_NAME"
  else
    [ -z "$BACKUP_DIRECTORY" ] || fail 'restore lifecycle cannot select a capture destination'
  fi
  offline_data emit-request "$@" >"$OFFLINE_INPUT/request.json" || fail 'fixed data-only offline request emission failed'
  chmod 600 "$OFFLINE_INPUT/request.json"
  LOCK_NAME="volt-offline-${PROJECT}-$$"
  set -- docker run --platform "$PLATFORM" --pull=never -d --name "$LOCK_NAME" --restart=no --network none --read-only \
    --label "volt.compose.owner-token=$OWNER_TOKEN" --label "volt.compose.project=$PROJECT" \
    --label org.volt.compose-install.role=host-lifecycle-lock \
    --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --tmpfs /app/media:rw,noexec,nosuid,nodev,size=1m \
    --tmpfs /opt/uvm/state:rw,noexec,nosuid,nodev,size=1m \
    --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m \
    --mount "type=bind,src=$STATE,dst=/state" --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$OFFLINE_INPUT,dst=/run/volt-offline-input,readonly" \
    --mount "type=bind,src=$OFFLINE_OUTPUT,dst=/run/volt-offline-output" \
    --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly" \
    --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly"
  if [ "$ACTION" = restore-provision ]; then
    set -- "$@" --user 0:0 --cap-add=CHOWN --cap-add=SETUID --cap-add=DAC_OVERRIDE
  else
    set -- "$@" --user "$(id -u):$(id -g)"
  fi
  [ "$ACTION" != backup-record ] || set -- "$@" --mount "type=bind,src=$BACKUP_PARENT,dst=/run/volt-backup-publication"
  LOCK_ID=$("$@" --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.lock /state/.install.lock "--offline-$ACTION") \
    || fail 'offline fixed owner could not start'
  case "$LOCK_ID" in *[!0-9a-f]*|'') fail 'actual offline owner ID is malformed' ;; esac
  [ "${#LOCK_ID}" -eq 64 ] || fail 'actual offline owner ID is malformed'
  LOCK_CREATED=1
  pin_lock_owner
  offline_plan plan
  offline_observe observed
  if [ "$ACTION" = backup-record ]; then
    offline_plan capture
    [ -n "$PARTIAL_NAME" ] || fail 'offline private capture plan is missing'
    for store in postgres media state instance; do
      if [ "$store" = instance ]; then mount_source="type=bind,src=$STATE,dst=/restore,readonly";
      else mount_source="type=volume,src=${PROJECT}_$store,dst=/restore,readonly"; fi
      docker run --platform "$PLATFORM" --pull=never --rm --network none --read-only --cap-drop=ALL \
        --cap-add=DAC_OVERRIDE --cap-add=CHOWN --security-opt=no-new-privileges --user 0:0 \
        --tmpfs /tmp:rw,noexec,nosuid,size=16m --mount "$mount_source" \
        --mount "type=bind,src=$BACKUP_PARENT/$PARTIAL_NAME,dst=/backup" \
        --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.offline_backup capture --store "$store" \
        || fail 'fixed numeric-owner offline archive capture failed; private partial retained'
    done
    offline_observe captured
  elif [ "$ACTION" = restore-provision ]; then
    offline_plan provision
    for store in postgres media state; do
      docker volume create --label "volt.compose.owner-token=$OWNER_TOKEN" \
        --label "com.docker.compose.project=$PROJECT" --label "com.docker.compose.volume=$store" \
        "${PROJECT}_$store" >/dev/null || fail 'pending offline store provisioning failed'
    done
    if ! docker network inspect "${PROJECT}_network" >/dev/null 2>&1; then
      docker network create --driver bridge --label "volt.compose.owner-token=$OWNER_TOKEN" \
        --label "com.docker.compose.project=$PROJECT" --label com.docker.compose.network=application \
        --subnet "$OFFLINE_SUBNET" --gateway "$OFFLINE_GATEWAY" "${PROJECT}_network" >/dev/null \
        || fail 'pending offline network provisioning failed'
    fi
    offline_observe provisioned
  fi
  offline_plan complete
  offline_final_report

}


# Fixed read-only diagnostic data operations inside the admitted runtime.
diagnostic_data() {
  diagnostic_stdin=''
  case "$1" in emit-request) ;; filter-logs) diagnostic_stdin=-i ;; *) fail 'unsupported fixed diagnostic data operation' ;; esac
  docker run --platform "$PLATFORM" --pull=never --rm $diagnostic_stdin --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    --tmpfs /app/media:rw,noexec,nosuid,nodev,size=1m \
    --tmpfs /opt/uvm/state:rw,noexec,nosuid,nodev,size=1m \
    --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.diagnostics "$@"
}

diagnostic_api() {
  if docker container inspect "${PROJECT}-volt-1" --format '[{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"ImageManifestDescriptor":{{json (index . "ImageManifestDescriptor")}},"Config":{"Labels":{{json .Config.Labels}}},"HostConfig":{"NetworkMode":{{json .HostConfig.NetworkMode}}},"NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}}},"Mounts":[{{ $sep := "" }}{{range .Mounts}}{{$sep}}{"Type":{{json .Type}},"Name":{{json (index . "Name")}},"Source":{{json .Source}},"Destination":{{json .Destination}},"Driver":{{json (index . "Driver")}},"RW":{{json .RW}}}{{$sep = ","}}{{end}}],"State":{"Running":{{json .State.Running}},"Status":{{json .State.Status}},"Health":{{with index .State "Health"}}{{json (index . "Status")}}{{else}}null{{end}},"StartedAt":{{json .State.StartedAt}},"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}}}}]' >"$WORK/diagnostic-api.json" 2>"$WORK/diagnostic-docker-error"; then
    cat "$WORK/diagnostic-api.json"
  elif grep -F -i 'No such' "$WORK/diagnostic-docker-error" >/dev/null; then
    printf '[]\n'
  else
    fail 'diagnostic API inspection failed; absence cannot be inferred'
  fi
}

diagnostic_observe() {
  ensure_lock_owner
  {
    printf '{"schema_version":1,"profile":"volt_diagnostic_observation_v1","operation_id":"%s","request_sha256":"%s","phase":"%s","data":{"containers":' "$DIAG_OPERATION_ID" "$DIAG_REQUEST_SHA256" "$1"; diagnostic_api
    printf ',"volumes":['; separator=''
    for store in postgres media state; do
      printf '%s' "$separator"
      docker volume inspect "${PROJECT}_$store" --format '{"Name":{{json .Name}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},"Mountpoint":{{json .Mountpoint}},"Options":{{json .Options}},"Labels":{{json .Labels}}}' \
        2>"$WORK/diagnostic-docker-error" || fail 'diagnostic owned store inspection failed'
      separator=,
    done
    printf '],"networks":['
    docker network inspect "${PROJECT}_network" --format '{"Name":{{json .Name}},"Id":{{json .Id}},"Driver":{{json .Driver}},"Internal":{{json .Internal}},"Labels":{{json .Labels}},"IPAM":{"Config":{{json .IPAM.Config}}},"Containers":{{json .Containers}}}' \
      2>"$WORK/diagnostic-docker-error" || fail 'diagnostic owned network inspection failed'
    printf '],"holder":'
    docker inspect "$LOCK_ID" --format '{"Id":{{json .Id}},"Image":{{json .Image}},"ImageManifestDescriptor":{{json (index . "ImageManifestDescriptor")}},"Config":{"Image":{{json .Config.Image}},"Labels":{{json .Config.Labels}}},"State":{"Running":{{json .State.Running}},"StartedAt":{{json .State.StartedAt}}}}' \
      2>"$WORK/diagnostic-docker-error" || fail 'diagnostic actual FD owner inspection failed'
    printf '}}\n'
  } >"$DIAG_INPUT/.observation"
  chmod 600 "$DIAG_INPUT/.observation"
  mv "$DIAG_INPUT/.observation" "$DIAG_INPUT/$1.json"
}

diagnostic_identity() {
  docker inspect "$LOCK_ID" --format '{{.Id}}|{{.Image}}|{{.Config.Image}}|{{.State.StartedAt}}|{{.State.Running}}|{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "volt.compose.project"}}' \
    2>"$WORK/diagnostic-docker-error" || fail 'diagnostic actual FD owner identity failed'
  if docker inspect "${PROJECT}-volt-1" --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "com.docker.compose.project"}}' \
      2>"$WORK/diagnostic-docker-error"; then :
  elif grep -F -i 'No such' "$WORK/diagnostic-docker-error" >/dev/null; then printf 'absent\n'
  else fail 'diagnostic API identity failed'; fi
}

run_diagnostics() {
  [ -n "${DIAG_INPUT:-}" ] && [ -n "${DIAG_OUTPUT:-}" ] || fail 'diagnostics require the actual fixed FD owner'
  ensure_lock_owner
  diagnostic_original_identity=$(diagnostic_identity) || fail 'initial diagnostic identity is unavailable'
  cp "$WORK/graph-admission.json" "$DIAG_INPUT/.receipt"
  chmod 600 "$DIAG_INPUT/.receipt"; mv "$DIAG_INPUT/.receipt" "$DIAG_INPUT/receipt.json"
  diagnostic_observe before
  if [ "$ACTION" = logs ]; then
    diagnostic_capture_logs
  fi
  diagnostic_observe after
  attempts=0
  while [ "$attempts" -lt 150 ]; do
    ensure_lock_owner
    if [ -f "$DIAG_OUTPUT/result-exit" ] && [ ! -L "$DIAG_OUTPUT/result-exit" ]; then break; fi
    attempts=$((attempts + 1)); sleep 1
  done
  [ "$attempts" -lt 150 ] || fail 'actual FD diagnostic validation timed out'
  diagnostic_status=$(cat "$DIAG_OUTPUT/result-exit")
  case "$diagnostic_status" in 0|1) ;; *) fail 'diagnostic completion status differs' ;; esac
  ensure_lock_owner
  diagnostic_current_identity=$(diagnostic_identity) || fail 'final diagnostic identity is unavailable'
  diagnostic_validated_identity=$(cat "$DIAG_OUTPUT/identity-lines") || fail 'diagnostic validated identity is unavailable'
  [ "$diagnostic_original_identity" = "$diagnostic_current_identity" ] && [ "$diagnostic_validated_identity" = "$diagnostic_current_identity" ] \
    || fail 'diagnostic identity changed or stale projection arrived before output'
  [ -f "$DIAG_OUTPUT/result.json" ] && [ ! -L "$DIAG_OUTPUT/result.json" ] || fail 'actual FD diagnostic result is missing'
  cat "$DIAG_OUTPUT/result.json"
  return "$diagnostic_status"
}


diagnostic_capture_logs() {
    diagnostic_query=$(docker inspect "${PROJECT}-volt-1" --format '{{.Id}}|{{.State.StartedAt}}' 2>"$WORK/diagnostic-docker-error") \
      || fail 'current-run log container is unavailable'
    IFS='|' read -r diagnostic_api_id started <<EOF_DIAGNOSTIC_QUERY
$diagnostic_query
EOF_DIAGNOSTIC_QUERY
    case "$diagnostic_api_id" in ''|*[!0-9a-f]*) fail 'current log container ID is malformed' ;; esac
    [ "${#diagnostic_api_id}" -eq 64 ] || fail 'current log container ID is incomplete'
    case "$started" in 0001-*) fail 'current-run logs require a previously started container' ;; esac
    case "$started" in ''|*[!0-9TZ.:-]*) fail 'current-run log StartedAt is malformed' ;; esac
    [ "${#started}" -le 40 ] || fail 'current-run log StartedAt exceeds bound'
    fifo="$WORK/diagnostic-log-stream"; mkfifo "$fifo" || fail 'private diagnostic stream unavailable'
    docker logs --timestamps --since "$started" --tail 1024 "$diagnostic_api_id" >"$fifo" 2>&1 &
    diagnostic_producer=$!
    diagnostic_data filter-logs --started-at "$started" <"$fifo" >"$DIAG_INPUT/.logs" 2>"$WORK/diagnostic-reader-error" &
    diagnostic_reader=$!
    ( sleep 15
      printf '%s\n' timeout >"$WORK/diagnostic-wall-timeout"
      kill -KILL "$diagnostic_producer" "$diagnostic_reader" 2>/dev/null || :
    ) </dev/null >/dev/null 2>&1 &
    diagnostic_watchdog=$!
    if wait "$diagnostic_reader"; then diagnostic_reader_status=0
    else
      diagnostic_reader_status=$?
      kill "$diagnostic_producer" 2>/dev/null || :
    fi
    if wait "$diagnostic_producer"; then diagnostic_producer_status=0; else diagnostic_producer_status=$?; fi
    kill "$diagnostic_watchdog" 2>/dev/null || :
    wait "$diagnostic_watchdog" 2>/dev/null || :
    if [ -f "$WORK/diagnostic-wall-timeout" ] || [ "$diagnostic_reader_status" -ge 125 ]; then
      # The Docker client/filter transport did not return a complete response.
      # Preserve its original partial inode privately; late bytes cannot alter
      # the NEW fixed failure record delivered to the actual FD owner.
      mv "$DIAG_INPUT/.logs" "$WORK/diagnostic-reader-partial"
      diagnostic_transport_outcome=filter_unavailable
      [ ! -f "$WORK/diagnostic-wall-timeout" ] || diagnostic_transport_outcome=timeout
      printf '{"schema_version":1,"profile":"volt_filtered_markers_v1","started_at":"%s","markers":[],"omitted_lines":0,"truncated":true,"reader_outcome":"%s"}\n' \
        "$started" "$diagnostic_transport_outcome" >"$DIAG_INPUT/.logs"
    fi
    rm "$fifo"
    chmod 600 "$DIAG_INPUT/.logs"; mv "$DIAG_INPUT/.logs" "$DIAG_INPUT/logs.json"
    printf '{"producer_exit":%s,"reader_exit":%s}\n' "$diagnostic_producer_status" "$diagnostic_reader_status" >"$DIAG_INPUT/.statuses"
    chmod 600 "$DIAG_INPUT/.statuses"; mv "$DIAG_INPUT/.statuses" "$DIAG_INPUT/statuses.json"
}
