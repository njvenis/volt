#!/bin/bash
set -Eeuo pipefail
umask 077
source /usr/local/bin/uvm-g7-identity-runtime

STATE=/run/uvm-g7
# CE uses its pinned vendor interpreter/dependencies; UVM has a separate venv.
CE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CHILD_PIDS=()
CHILD_NAMES=()
declare -A REAPED_CHILDREN=()
declare -A CHILD_EXIT_STATUS=()
declare -A UNRESOLVED_CHILDREN=()
SERVICE_PIDS=()
shutdown_requested=0
quiesce_requested=0
quiesce_failed_latched=0
shutdown_status=0
services_started=0
cleanup_running=0
recovery_control_gate_passed=0
mkdir -p "$STATE" /run/secrets
install -d -o 1001 -g 1337 -m 0750 /run/uvm-g7-scheduler
if [[ ${UVM_G7_DISPOSABLE_MODE:-0} == 1 ]]; then
  # The scheduler signal is bounded process health metadata, not host policy
  # or secret material. A separately launched local observer must be able to
  # read it from the dedicated bind mount.
  chmod 0755 /run/uvm-g7-scheduler
fi
rm -f "$STATE/ready" "$STATE/critical-failed" "$STATE/quiesce-failed" "$STATE"/pid-*

# FD9 is reserved ONLY for the anonymous terminal writer in original Bash.
# It is NOT claimed CLOEXEC: every external/background/subshell boundary below
# closes it explicitly. Broker receives read-only FD3; sole adapter gets FD4.
api_terminal_active=0
api_stop_started=0
api_protocol_uncertain=0
api_cleanup_poisoned=0
api_terminal_sent=0

api_report() {
  if ! printf '%s\n' "$1"; then api_cleanup_poisoned=1; return 1; fi
}

api_remove_ready() {
  if ! rm -f "$STATE/ready"; then api_cleanup_poisoned=1; return 1; fi
}

api_phase_marker() {
  # Fixed private lifecycle markers only, no arbitrary path or repair selector.
  case "$1" in quiesce-writers-stopped|quiesce-services-stopped|quiesce-failed|critical-failed|ready) ;;
    *) api_cleanup_poisoned=1; return 1 ;; esac
  if ! touch "$STATE/$1"; then api_cleanup_poisoned=1; return 1; fi
}

# Fixed external-command boundaries also cover startup/error paths and the
# pipeline components used by quiesce, stop and bounded private diagnostics.
sleep() { command sleep "$@" 9>&-; }
seq() { command seq "$@" 9>&-; }
rm() { command rm "$@" 9>&-; }
touch() { command touch "$@" 9>&-; }
chmod() { command chmod "$@" 9>&-; }
dirname() { command dirname "$@" 9>&-; }
tail() { command tail "$@" 9>&-; }
sed() { command sed "$@" 9>&-; }
ps() { command ps "$@" 9>&-; }
awk() { command awk "$@" 9>&-; }
setpriv() { command setpriv "$@" 9>&-; }
valkey-cli() { command valkey-cli "$@" 9>&-; }

api_before() {
  local cutoff=$1 uptime unused
  IFS=' ' read -r uptime unused </proc/uptime || return 1
  uptime=${uptime%%.*}
  [[ $uptime =~ ^[0-9]+$ && ${api_stop_t0:-} =~ ^[0-9]+$ ]] || return 1
  (( uptime < api_stop_t0 + cutoff ))
}

api_private_payload() {
  local action=$1 reader writer encoder status value
  api_private_result=''
  coproc API_ENCODING {
    exec 9>&-
    IFS= read -r -t 2 gate && [[ $gate == G ]] || exit 70
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/local/bin/python3.14 -I -S \
      /usr/local/libexec/volt-route-check-control.py "entrypoint-$action" 9>&- 2>/dev/null
  }
  encoder=$API_ENCODING_PID
  exec {reader}<&"${API_ENCODING[0]}"
  exec {writer}>&"${API_ENCODING[1]}"
  exec {API_ENCODING[0]}<&-
  exec {API_ENCODING[1]}>&-
  printf 'G\n' >&"$writer" || { api_protocol_uncertain=1; return 1; }
  if [[ $action != stop-operation ]]; then
    [[ ${api_stop_operation:-} =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s' "$api_stop_operation" >&"$writer" || { api_protocol_uncertain=1; return 1; }
  fi
  exec {writer}>&-
  # The fixed encoder emits at most2048 canonical bytes and EOF. NUL, timeout,
  # missing output or producer failure cannot become a terminal decision.
  if IFS= read -r -d '' -t 5 value <&"$reader"; then status=0; else status=$?; fi
  exec {reader}<&-
  if (( status != 1 )); then api_protocol_uncertain=1; return 1; fi
  if wait "$encoder"; then status=0; else status=$?; fi
  (( status == 0 )) && [[ -n $value && ${#value} -le 2048 ]] || return 1
  api_private_result=$value
}

begin_api_stop() {
  (( ${api_terminal_active:-0} )) || return 0
  (( ! api_stop_started )) || return 0
  # Once set, neither entropy failure nor a lost encoder result may retry.
  api_stop_started=1
  local uptime unused
  record_api_stop_receipt
  [[ ${api_stop_t0:-} =~ ^[0-9]+$ ]] || { api_cleanup_poisoned=1; return 1; }
  IFS=' ' read -r uptime unused </proc/uptime || { api_cleanup_poisoned=1; return 1; }
  api_stop_remaining=$(( api_stop_t0 + 587 - ${uptime%%.*} ))
  (( api_stop_remaining > 0 )) || { api_cleanup_poisoned=1; return 1; }
  api_stop_deadline_expired=0
  trap 'api_stop_deadline_expired=1; api_protocol_uncertain=1; exit 70' ALRM
  coproc API_STOP_TIMER {
    exec 9>&-
    if IFS= read -r -t "$api_stop_remaining" cancel && [[ $cancel == C ]]; then exit 0; fi
    kill -ALRM "$$"
    exit 70
  }
  api_stop_timer=$API_STOP_TIMER_PID
  exec {api_stop_timer_write}>&"${API_STOP_TIMER[1]}"
  exec {API_STOP_TIMER[0]}<&-
  exec {API_STOP_TIMER[1]}>&-
  if ! api_private_payload stop-operation; then api_cleanup_poisoned=1; return 1; fi
  api_stop_operation=$api_private_result
  [[ $api_stop_operation =~ ^[0-9a-f]{64}$ ]] || { api_cleanup_poisoned=1; return 1; }
}

api_stop_progress() {
  local kind=$1 attempt uptime unused progress_t0
  IFS=' ' read -r uptime unused </proc/uptime || return 1
  progress_t0=${uptime%%.*}
  if [[ $kind == quiesce ]]; then
    api_broker_control signal-quiesce || { api_cleanup_poisoned=1; return 1; }
  elif ! api_broker_control signal-stop; then
    api_cleanup_poisoned=1
    # Exact original orphan termination+disarm is cleanup progress ONLY.
    api_broker_control orphan-terminated
    return $?
  fi
  for ((attempt=0;attempt<350;attempt++)); do
    IFS=' ' read -r uptime unused </proc/uptime || return 1
    uptime=${uptime%%.*}
    (( uptime < progress_t0 + 33 )) || break
    if [[ $kind != quiesce ]] && ! api_before 33; then break; fi
    if api_broker_control api-stop-progress >/dev/null 2>&1; then return 0; fi
    if [[ $kind != quiesce ]] && ! api_before 35; then break; fi
    if [[ $kind == quiesce ]] && (( shutdown_requested )); then return 1; fi
    sleep .1
  done
  if [[ $kind == quiesce ]] && api_broker_control quiesce-timeout; then return 75; fi
  api_cleanup_poisoned=1
  return 1
}

begin_api_phase_guard() {
  coproc API_PHASE_TIMER {
    exec 9>&-
    if IFS= read -r -t 2 cancel && [[ $cancel == C ]]; then exit 0; fi
    kill -ALRM "$$"
    exit 70
  }
  api_phase_timer=$API_PHASE_TIMER_PID
  exec {api_phase_timer_write}>&"${API_PHASE_TIMER[1]}"
  exec {API_PHASE_TIMER[0]}<&-
  exec {API_PHASE_TIMER[1]}>&-
}

finish_api_phase_guard() {
  printf 'C\n' >&"$api_phase_timer_write" || return 1
  exec {api_phase_timer_write}>&-
  wait "$api_phase_timer"
}

finish_api_terminal() {
  (( ${api_terminal_active:-0} )) || return 0
  local status=0 action=terminal-success adapter producer result reader writer
  (( ! api_terminal_sent )) || return 1
  api_terminal_sent=1
  api_before 565 || api_cleanup_poisoned=1
  if (( api_cleanup_poisoned || shutdown_status )); then action=terminal-failure; fi
  if ! api_private_payload "$action"; then api_protocol_uncertain=1; return 1; fi
  api_before 565 || return 1
  begin_api_phase_guard
  # The empty Linux stdin pipe and single bounded <=2048byte feed are private.
  # Adapter validates PIPE type/parent/closed canonical input and owns2s TOTAL.
  coproc API_TERMINAL_INPUT { exec 9>&-; IFS= read -r -t 2 value && printf '%s' "$value"; }
  local feed=$API_TERMINAL_INPUT_PID
  exec {reader}<&"${API_TERMINAL_INPUT[0]}"
  exec {writer}>&"${API_TERMINAL_INPUT[1]}"
  exec {API_TERMINAL_INPUT[0]}<&-
  exec {API_TERMINAL_INPUT[1]}>&-
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/local/bin/python3.14 -I -S \
    /usr/local/libexec/volt-terminal-write.py <&"$reader" 4>&9 9>&- >/dev/null 2>&1 &
  adapter=$!
  exec 9>&-
  exec {reader}<&-
  printf '%s\n' "$api_private_result" >&"$writer" || status=1
  exec {writer}>&-
  if wait "$feed"; then :; else status=1; fi
  if wait "$adapter"; then result=0; else result=$?; fi
  finish_api_phase_guard || status=1
  (( result == 0 && status == 0 )) && api_before 567 || { api_protocol_uncertain=1; return 1; }
  # Poll the original child without consuming another job's status. An exact
  # read-only candidate is not enough: only this Bash job's actual wait0 counts.
  while kill -0 "$api_broker_pid" 2>/dev/null; do
    api_before 577 || { api_protocol_uncertain=1; return 1; }
    sleep .05
  done
  if wait "$api_broker_pid"; then result=0; else result=$?; fi
  if (( result == 127 )); then api_cleanup_poisoned=1; api_protocol_uncertain=1; return 1; fi
  CHILD_EXIT_STATUS[$api_broker_pid]=$result
  REAPED_CHILDREN[$api_broker_pid]=1
  (( result == 0 && ! api_cleanup_poisoned && ! shutdown_status )) || return 1
  api_private_payload completion-request || return 1
  api_before 585 || return 1
  begin_api_phase_guard
  coproc API_COMPLETION_INPUT { IFS= read -r -t 2 value && printf '%s' "$value"; }
  feed=$API_COMPLETION_INPUT_PID
  exec {reader}<&"${API_COMPLETION_INPUT[0]}"
  exec {writer}>&"${API_COMPLETION_INPUT[1]}"
  exec {API_COMPLETION_INPUT[0]}<&-
  exec {API_COMPLETION_INPUT[1]}>&-
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/local/bin/python3.14 -I -S \
    /usr/local/libexec/volt-main-api-completion.py <&"$reader" 2>/dev/null &
  producer=$!
  exec {reader}<&-
  printf '%s\n' "$api_private_result" >&"$writer" || status=1
  exec {writer}>&-
  if wait "$feed"; then :; else status=1; fi
  if wait "$producer"; then result=0; else result=$?; fi
  finish_api_phase_guard || status=1
  (( result == 0 && status == 0 )) && api_before 587 || return 1
  printf 'C\n' >&"$api_stop_timer_write" || return 1
  exec {api_stop_timer_write}>&-
  if wait "$api_stop_timer"; then :; else return 1; fi
  trap - ALRM
  api_terminal_active=0
}

close_api_input() {
  # Close ONLY already registered anonymous endpoints. An interrupted wait is
  # not a reap: retain registration until a subsequent actual wait result.
  if [[ ${api_input_read:-} ]]; then exec {api_input_read}<&-; unset api_input_read; fi
  if [[ ${api_input_gate_fd:-} ]]; then exec {api_input_gate_fd}>&-; unset api_input_gate_fd; fi
  if [[ ${api_input_original_read:-} ]]; then exec {api_input_original_read}<&-; unset api_input_original_read; fi
  local producer_status=0 before_epoch result
  if [[ ${api_input_producer:-} ]]; then
    while :; do
      if (( ${api_input_deadline_expired:-0} )); then
        api_input_uncertain=1
        return 70
      fi
      before_epoch=${api_input_wait_epoch:-0}
      if wait "$api_input_producer"; then result=0; else result=$?; fi
      if (( before_epoch != ${api_input_wait_epoch:-0} )); then continue; fi
      if (( result == 127 )); then api_input_uncertain=1; return 70; fi
      producer_status=$result
      unset api_input_producer
      api_input_pending=0
      break
    done
  fi
  if [[ ${api_input_deadline_pid:-} ]]; then
    while :; do
      before_epoch=${api_input_wait_epoch:-0}
      if wait "$api_input_deadline_pid"; then result=0; else result=$?; fi
      if (( before_epoch != ${api_input_wait_epoch:-0} )); then continue; fi
      if (( result == 127 )); then api_input_uncertain=1; return 70; fi
      unset api_input_deadline_pid
      (( result == 0 )) || { api_input_uncertain=1; return 70; }
      break
    done
  fi
  return "$producer_status"
}

handle_api_input_deadline() {
  api_input_wait_epoch=$(( ${api_input_wait_epoch:-0} + 1 ))
  if (( ${api_input_pending:-0} )); then api_input_deadline_expired=1; fi
  return 0
}

begin_api_input_deadline() {
  api_input_pending=1
  api_input_deadline_expired=0
  api_input_uncertain=0
  trap handle_api_input_deadline ALRM
  # A fixed bounded child signals only its ORIGINAL PID1 parent. In the
  # supported container PID1 cannot be reused while its children survive.
  # No API/producer PID is signalled or adopted; uncertainty terminates PID1
  # nonzero with registration retained, and the kernel terminates the container.
  ( sleep 5; kill -ALRM "$$" ) &
  api_input_deadline_pid=$!
}


record_api_stop_receipt() {
  [[ ! ${api_stop_receipt_set:-} ]] || return 0
  api_stop_receipt_set=1
  local uptime unused
  if IFS=' ' read -r uptime unused </proc/uptime; then
    api_stop_t0=${uptime%%.*}
    [[ $api_stop_t0 =~ ^[0-9]+$ ]] && return 0
  fi
  api_cleanup_poisoned=1
  return 1
}

handle_shutdown() { record_api_stop_receipt || :; shutdown_requested=1; api_input_wait_epoch=$(( ${api_input_wait_epoch:-0} + 1 )); }
handle_quiesce() { api_input_wait_epoch=$(( ${api_input_wait_epoch:-0} + 1 )); if (( ! quiesce_failed_latched )); then quiesce_requested=1; fi; return 0; }
cleanup_on_exit() {
  local original_status=$? cleanup_status=0
  trap - EXIT TERM INT
  # Unknown producer completion must not enter another unbounded wait or emit
  # controlled-clean markers. PID1 exit is the bounded whole-container failure.
  if (( ${api_protocol_uncertain:-0} || ${api_input_uncertain:-0} )); then
    api_report 'G7_API_LAUNCH=private-input-completion-uncertain' >&2
    exit 70
  fi
  close_api_input || cleanup_status=1
  if (( ${api_protocol_uncertain:-0} || ${api_input_uncertain:-0} )); then
    api_report 'G7_API_LAUNCH=private-input-completion-uncertain' >&2
    exit 70
  fi
  if (( services_started && ! cleanup_running )); then
    cleanup_running=1
    if (( original_status != 0 )); then api_cleanup_poisoned=1; fi
    stop_all || cleanup_status=$?
    if (( cleanup_status )); then api_cleanup_poisoned=1; fi
    finish_api_terminal || cleanup_status=1
    api_report "G7_STARTUP_CLEANUP=complete original_status=$original_status cleanup_status=$cleanup_status" >&2 || cleanup_status=1
    if (( original_status == 0 && cleanup_status != 0 )); then original_status=71; fi
  fi
  exit "$original_status"
}
trap cleanup_on_exit EXIT
trap handle_shutdown TERM INT
trap handle_quiesce USR1
printf '%s\n' "$$" >"$STATE/entrypoint-pid" || { api_cleanup_poisoned=1; exit 70; }

abort_if_shutdown() {
  if (( shutdown_requested )); then
    api_report 'G7_STARTUP_INTERRUPTED phase=service-startup' >&2
    return 143
  fi
}

stop_phase() {
  local phase=$1 pid name status=0 i attempt rc stopped timed_out limit group_processes broker_requested=0
  shift
  local -a selected=() selected_names=()
  declare -p CHILD_EXIT_STATUS >/dev/null 2>&1 || declare -gA CHILD_EXIT_STATUS=()
  declare -p UNRESOLVED_CHILDREN >/dev/null 2>&1 || declare -gA UNRESOLVED_CHILDREN=()
  for name in "$@"; do
    if [[ $name == api-broker && ${api_terminal_active:-0} == 1 ]]; then broker_requested=1; continue; fi
    for i in "${!CHILD_NAMES[@]}"; do
      pid=${CHILD_PIDS[$i]}
      [[ ${CHILD_NAMES[$i]} == "$name" ]] || continue
      if [[ ${UNRESOLVED_CHILDREN[$pid]+present} ]]; then
        api_cleanup_poisoned=1; status=1
      elif [[ ${REAPED_CHILDREN[$pid]+present} ]]; then
        if [[ ! ${CHILD_EXIT_STATUS[$pid]+present} ]] ||
            (( CHILD_EXIT_STATUS[$pid] != 0 && CHILD_EXIT_STATUS[$pid] != 143 )); then
          api_cleanup_poisoned=1; status=1
        fi
      else
        selected+=("$pid"); selected_names+=("$name")
      fi
    done
  done
  if (( broker_requested )); then
    local api_result=0
    if [[ ${UVM_G7_QUIESCE_NO_KILL:-0} == 1 ]]; then
      api_stop_progress quiesce || api_result=$?
    else
      api_stop_progress stop || api_result=$?
    fi
    if (( api_result == 75 )); then status=75
    elif (( api_result != 0 )); then status=1; api_cleanup_poisoned=1
    fi
  fi
  for i in "${!selected[@]}"; do
    pid=${selected[$i]}; name=${selected_names[$i]}
    if [[ $name == api-broker ]]; then
      if [[ ${UVM_G7_QUIESCE_NO_KILL:-0} == 1 ]]; then
        api_broker_control signal-quiesce || status=1
      else
        api_broker_control signal-stop || status=1
      fi
    elif kill -0 "$pid" 2>/dev/null; then
      if [[ $name == ce-web && -p /run/uwsgi/uvm-g7.fifo ]]; then
        printf q >/run/uwsgi/uvm-g7.fifo || { api_cleanup_poisoned=1; api_report "G7_STOP_ERROR phase=$phase action=uwsgi-fifo name=ce-web" >&2; status=1; }
      else
        kill -TERM "$pid" || { api_cleanup_poisoned=1; api_report "G7_STOP_ERROR phase=$phase action=term name=$name" >&2; status=1; }
      fi
    fi
  done
  for i in "${!selected[@]}"; do
    pid=${selected[$i]}; name=${selected_names[$i]}; stopped=0; timed_out=0; limit=300
    [[ $name != api-broker ]] || limit=350
    for ((attempt=0; attempt<limit; attempt++)); do
      if ! kill -0 "$pid" 2>/dev/null; then stopped=1; break; fi
      if (( ${api_stop_started:-0} )) && ! api_before 395; then break; fi
      sleep 0.1
    done
    if (( ! stopped )); then
      api_cleanup_poisoned=1
      api_report "G7_STOP_ERROR phase=$phase action=timeout name=$name" >&2
      if [[ ${UVM_G7_QUIESCE_NO_KILL:-0} == 1 ]]; then
        timed_out=1
      elif [[ $name == api-broker ]]; then
        api_broker_control signal-kill || status=1
      else
        kill -KILL -- "-$pid" 2>/dev/null || :
      fi
      status=1
    fi
    if (( timed_out )); then continue; fi
    # A failed exact broker signal is uncertainty, never an unbounded wait.
    if [[ $name == api-broker ]] && kill -0 "$pid" 2>/dev/null; then
      for ((attempt=0; attempt<20; attempt++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then status=1; api_cleanup_poisoned=1; continue; fi
    fi
    if wait "$pid"; then rc=0; else rc=$?; fi
    if (( rc == 127 )); then
      # No wait result is not a successful reap. Keep unresolved registration,
      # never signal a possibly reused PID or fabricate CHILD_STOPPED later.
      UNRESOLVED_CHILDREN[$pid]=1
      api_cleanup_poisoned=1; status=1
      api_report "G7_STOP_ERROR phase=$phase action=wait-unavailable name=$name" >&2 || :
      continue
    fi
    CHILD_EXIT_STATUS[$pid]=$rc
    REAPED_CHILDREN[$pid]=1
    if (( rc != 143 && rc != 0 )); then
      api_cleanup_poisoned=1
      api_report "G7_STOP_ERROR phase=$phase action=wait name=$name status=$rc" >&2
      status=1
    fi
    if [[ $name == api-broker ]]; then
      # API has a separate session. Only its original full root launch record
      # plus pidfd may authorize orphan cleanup; no process-group fallback.
      api_broker_control orphan-cleanup || status=1
    elif [[ ${UVM_G7_QUIESCE_NO_KILL:-0} == 1 ]]; then
      group_processes=$(exec 9>&-; ps -eo pgid= | awk -v pgid="$pid" '$1 == pgid { count++ } END { print count+0 }')
      if [[ $group_processes != 0 ]]; then
        api_cleanup_poisoned=1
        api_report "G7_STOP_ERROR phase=$phase action=process-group-remains name=$name" >&2; status=1
      fi
    fi
    api_report "G7_STOP_CHILD_STOPPED phase=$phase name=$name"
  done
  api_report "G7_STOP_PHASE=$phase status=$status"
  return "$status"
}
reconcile_registered_broker() {
  local name i pid
  # Reaped bookkeeping suppresses repeat waits, NEVER original-API cleanup.
  # This runs on ordinary TERM, EXIT cleanup and quiesce before databases or
  # success markers, including simultaneous TERM and broker death.
  for name in "${CHILD_NAMES[@]}"; do
    if [[ $name == api-broker ]]; then
      if (( ${api_terminal_active:-0} )); then
        for i in "${!CHILD_NAMES[@]}"; do
          [[ ${CHILD_NAMES[$i]} == api-broker ]] || continue
          pid=${CHILD_PIDS[$i]}
          if [[ ! ${REAPED_CHILDREN[$pid]+present} ]] && kill -0 "$pid" 2>/dev/null; then
            api_broker_control api-stop-progress >/dev/null
            return $?
          fi
        done
      fi
      api_cleanup_poisoned=1
      api_broker_control orphan-terminated
      return $?
    fi
  done
  return 0
}

stop_all() {
  # Every ordinary/EXIT cleanup forwards TERM even when its caller inherited
  # the no-kill quiesce policy. Only staged_quiesce may request USR1.
  local UVM_G7_QUIESCE_NO_KILL=0
  local status=0
  begin_api_stop || { status=1; api_cleanup_poisoned=1; }
  api_remove_ready || status=1
  stop_phase writers okta-identity-publisher oidc-sync-api recovery-control api-broker oidc-provider ce-web || status=1
  if ! reconcile_registered_broker; then
    api_cleanup_poisoned=1
    api_report 'G7_STOP_ERROR action=api-progress-unproven' >&2
    return 1  # Keep database teardown behind actual checked API termination.
  fi
  stop_phase workers exception-warning-worker ce-beat ce-worker || status=1
  if [[ -s /run/valkey/valkey.pid ]]; then
    valkey-cli -h 127.0.0.1 shutdown nosave >/dev/null 2>&1 || { api_cleanup_poisoned=1; api_report 'G7_STOP_ERROR service=valkey' >&2; status=1; }
  fi
  local pg_status=0 pg_timeout=60 uptime unused
  setpriv --reuid=postgres --regid=postgres --init-groups \
    /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" status >/dev/null 2>&1 || pg_status=$?
  if (( pg_status == 0 )); then
    if (( ${api_stop_started:-0} )); then
      IFS=' ' read -r uptime unused </proc/uptime || return 1
      pg_timeout=$(( api_stop_t0 + 395 - ${uptime%%.*} ))
      (( pg_timeout > 0 )) || { api_cleanup_poisoned=1; return 1; }
    fi
    if setpriv --reuid=postgres --regid=postgres --init-groups \
        /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" -m fast -t "$pg_timeout" -w stop >/dev/null 2>&1; then
      api_report 'G7_STOP_DATABASE_STOPPED service=postgresql'
    else
      api_cleanup_poisoned=1; status=1
      api_report 'G7_STOP_ERROR service=postgresql' >&2
    fi
  elif (( pg_status != 3 )); then
    api_cleanup_poisoned=1; status=1
    api_report 'G7_STOP_ERROR service=postgresql-status' >&2
  fi
  if [[ ${UVM_G7_TEST_FAULT:-} == cleanup-fail-after-broker ]]; then
    api_cleanup_poisoned=1
    api_report 'G7_STOP_ERROR injected=cleanup-fail-after-broker' >&2
    status=1
  fi
  if (( ${api_terminal_active:-0} )); then
    api_before 395 || status=1
    if (( status )); then api_cleanup_poisoned=1; fi
  fi
  api_report "G7_STOP_PHASE=databases status=$status"
  if (( ${api_cleanup_poisoned:-0} )); then status=1; fi
  return "$status"
}

staged_quiesce() {
  local status=0 acknowledged=0 phase_result=0
  quiesce_recoverable=0
  api_remove_ready || status=1
  stop_phase quiesce-producers okta-identity-publisher oidc-sync-api ce-beat || status=1
  stop_phase quiesce-admission recovery-control api-broker oidc-provider ce-web || phase_result=$?
  if (( phase_result == 75 && status == 0 && ! api_cleanup_poisoned )); then
    quiesce_recoverable=1
    return 75
  fi
  if (( status || phase_result || api_cleanup_poisoned )); then api_cleanup_poisoned=1; return 1; fi
  if ! reconcile_registered_broker; then api_cleanup_poisoned=1; return 1; fi
  stop_phase quiesce-effects exception-warning-worker || { api_cleanup_poisoned=1; return 1; }
  (( ! api_cleanup_poisoned )) || return 1
  api_phase_marker quiesce-writers-stopped || return 1
  api_report 'G7_QUIESCE=writers-stopped'
  for attempt in $(exec 9>&-; seq 1 "${UVM_G7_QUIESCE_TIMEOUT_SECONDS:-300}"); do
    if [[ -e "$STATE/quiesce-drain-complete" ]]; then acknowledged=1; break; fi
    if (( shutdown_requested )); then return 143; fi
    sleep 1
  done
  if (( ! acknowledged )); then
    # This is this fixed Bash wait's observed no-kill deadline, not a service
    # command's arbitrary exit75 or an unacknowledged publication failure.
    (( api_cleanup_poisoned )) || quiesce_recoverable=1
    api_report 'G7_QUIESCE_ERROR=drain-not-acknowledged' >&2
    return 1
  fi
  stop_phase quiesce-consumers ce-worker || { api_cleanup_poisoned=1; return 1; }
  if [[ -s /run/valkey/valkey.pid ]]; then
    valkey-cli -h 127.0.0.1 shutdown nosave >/dev/null 2>&1 || { api_cleanup_poisoned=1; status=1; }
    api_report 'G7_STOP_DATABASE_STOPPED service=valkey'
  fi
  local pg_status=0
  setpriv --reuid=postgres --regid=postgres --init-groups \
    /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" status >/dev/null 2>&1 || pg_status=$?
  if (( pg_status == 0 )); then
    if setpriv --reuid=postgres --regid=postgres --init-groups \
        /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" -m fast -t 60 -w stop >/dev/null 2>&1; then
      api_report 'G7_STOP_DATABASE_STOPPED service=postgresql'
    else api_cleanup_poisoned=1; status=1
    fi
  elif (( pg_status != 3 )); then api_cleanup_poisoned=1; status=1
  fi
  (( status == 0 )) || return 1
  api_phase_marker quiesce-services-stopped || return 1
  api_report 'G7_QUIESCE=services-stopped'
  for attempt in $(exec 9>&-; seq 1 "${UVM_G7_QUIESCE_TIMEOUT_SECONDS:-300}"); do
    [[ -e "$STATE/quiesce-capture-release" ]] && return 0
    (( ! shutdown_requested )) || return 143
    sleep 1
  done
  (( api_cleanup_poisoned )) || quiesce_recoverable=1
  api_report 'G7_QUIESCE_ERROR=capture-release-not-received' >&2
  return 1
}

secret() {
  local name=$1 path="/run/secrets/$1"
  [[ -s "$path" ]] || { api_report "required secret file is absent: $path" >&2; exit 70; }
  cat "$path"
}
if [[ -n ${UVM_GITHUB_TOKEN_FILE:-} ]]; then
  [[ -f "$UVM_GITHUB_TOKEN_FILE" ]] || { api_report 'configured GitHub token file is absent' >&2; exit 70; }
  install -d -o uvm -g uvm -m 0700 /run/uvm-github
  install -o uvm -g uvm -m 0600 "$UVM_GITHUB_TOKEN_FILE" /run/uvm-github/token
  UVM_GITHUB_TOKEN_FILE=/run/uvm-github/token
  export UVM_GITHUB_TOKEN_FILE
fi
if [[ -n ${UVM_CONNECTOR_LOCAL_KEY_FILE:-} ]]; then
  [[ -f "$UVM_CONNECTOR_LOCAL_KEY_FILE" && ! -L "$UVM_CONNECTOR_LOCAL_KEY_FILE" ]] || { api_report 'configured connector local key file is absent or unsafe' >&2; exit 70; }
  if [[ ${UVM_AUTH_MODE:-} == local && $(exec 9>&-; wc -c <"$UVM_CONNECTOR_LOCAL_KEY_FILE") -ne 32 ]]; then
    api_report 'G7_LOCAL_AUTH=key-length-invalid' >&2; exit 70
  fi
  install -d -o uvm -g uvm -m 0700 /run/uvm-connector
  install -o uvm -g uvm -m 0600 "$UVM_CONNECTOR_LOCAL_KEY_FILE" /run/uvm-connector/local-key
  UVM_CONNECTOR_LOCAL_KEY_FILE=/run/uvm-connector/local-key
  export UVM_CONNECTOR_LOCAL_KEY_FILE
fi
urlpart() { python -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().rstrip("\n"), safe=""))'; }
UVM_PASSWORD=$(exec 9>&-; secret uvm_db_password)
CE_PASSWORD=$(exec 9>&-; secret ce_db_password)
DD_ADMIN_PASSWORD=$(exec 9>&-; secret ce_admin_password)
DD_SECRET_KEY=$(exec 9>&-; secret ce_secret_key)
DD_CREDENTIAL_AES_256_KEY=$(exec 9>&-; secret ce_credential_key)
UVM_API_CURSOR_SECRET=$(exec 9>&-; secret uvm_cursor_secret)
export DD_ADMIN_PASSWORD DD_SECRET_KEY DD_CREDENTIAL_AES_256_KEY UVM_API_CURSOR_SECRET
if [[ -s /run/secrets/github_preview_secret ]]; then
  UVM_GITHUB_PREVIEW_SECRET=$(exec 9>&-; secret github_preview_secret)
  export UVM_GITHUB_PREVIEW_SECRET
fi

oidc_config_value() {
  local field=$1
  UVM_OIDC_CONFIG="$UVM_OIDC_CONFIG" python -c 'import json,os,sys; print(json.loads(os.environ["UVM_OIDC_CONFIG"])[sys.argv[1]])' "$field"
}
UVM_OIDC_DEPLOYMENT_MODE=${UVM_OIDC_DEPLOYMENT_MODE:-demo}
case "$UVM_OIDC_DEPLOYMENT_MODE" in
  demo|external|local) ;;
  *) api_report 'G7_OIDC_DEPLOYMENT_MODE=invalid' >&2; exit 70 ;;
esac
if [[ $UVM_OIDC_DEPLOYMENT_MODE == external && ${UVM_AUTH_MODE:-} != oidc ]]; then
  api_report 'G7_OIDC_EXTERNAL=oidc-auth-mode-required' >&2; exit 70
fi
if [[ $UVM_OIDC_DEPLOYMENT_MODE == local && ${UVM_AUTH_MODE:-} != local ]]; then
  api_report 'G7_LOCAL_AUTH=local-auth-mode-required' >&2; exit 70
fi
if [[ ${UVM_AUTH_MODE:-} == local ]]; then
  [[ $UVM_OIDC_DEPLOYMENT_MODE == local ]] || { api_report 'G7_LOCAL_AUTH=deployment-mode-mismatch' >&2; exit 70; }
  [[ ${UVM_LOCAL_AUTH_CONFIG_FILE:-} == /etc/volt/local-auth.json ]] || { api_report 'G7_LOCAL_AUTH=config-path-invalid' >&2; exit 70; }
  [[ ${UVM_LOCAL_RECOVERY_CONFIG_FILE:-} == /etc/volt/local-recovery.json ]] || { api_report 'G7_LOCAL_AUTH=recovery-config-path-invalid' >&2; exit 70; }
  [[ -s /run/secrets/local-auth.json && ! -L /run/secrets/local-auth.json ]] || { api_report 'G7_LOCAL_AUTH=config-missing-or-unsafe' >&2; exit 70; }
  [[ -s /run/secrets/local-recovery.json && ! -L /run/secrets/local-recovery.json ]] || { api_report 'G7_LOCAL_AUTH=recovery-config-missing-or-unsafe' >&2; exit 70; }
  for file in local-recovery-issuer.key local-recovery-issuer.pub local-recovery-operator.pub \
      local-recovery-material.key; do
    [[ -s "/run/secrets/$file" && ! -L "/run/secrets/$file" ]] || {
      api_report 'G7_LOCAL_AUTH=recovery-custody-file-missing-or-unsafe' >&2; exit 70;
    }
  done
  [[ -d /run/volt-restore-fence && ! -L /run/volt-restore-fence \
      && -s /run/volt-restore-fence/fence.json \
      && ! -L /run/volt-restore-fence/fence.json ]] || {
    api_report 'G7_LOCAL_AUTH=recovery-fence-missing-or-unsafe' >&2; exit 70;
  }
  install -d -o root -g uvm -m 0750 /etc/volt
  install -o uvm -g uvm -m 0600 /run/secrets/local-auth.json "$UVM_LOCAL_AUTH_CONFIG_FILE"
  install -o uvm -g uvm -m 0600 /run/secrets/local-recovery.json "$UVM_LOCAL_RECOVERY_CONFIG_FILE"
  install -d -o root -g uvm -m 0750 /run/uvm-local-recovery
  install -o uvm -g uvm -m 0600 /run/secrets/local-recovery-issuer.key /run/uvm-local-recovery/issuer.key
  install -o uvm -g uvm -m 0600 /run/secrets/local-recovery-issuer.pub /run/uvm-local-recovery/issuer.pub
  install -o uvm -g uvm -m 0600 /run/secrets/local-recovery-operator.pub /run/uvm-local-recovery/operator.pub
  install -o uvm -g uvm -m 0600 /run/secrets/local-recovery-material.key /run/uvm-local-recovery/material.key
  install -d -o uvm -g uvm -m 0700 /opt/uvm/state/scanner-evidence
  [[ ${UVM_SCANNER_EVIDENCE_DIR:-} == /opt/uvm/state/scanner-evidence ]] || {
    api_report 'G7_LOCAL_AUTH=scanner-evidence-path-invalid' >&2; exit 70;
  }
  [[ -d /run/volt-bootstrap && ! -L /run/volt-bootstrap ]] || { api_report 'G7_LOCAL_AUTH=bootstrap-delivery-missing' >&2; exit 70; }
  # Host owns this private delivery directory. Root maintenance alone writes it.
  [[ -s ${UVM_LOCAL_AUTH_CONFIG_FILE:-} ]] || { api_report 'G7_LOCAL_AUTH=config-missing' >&2; exit 70; }
  if [[ -n ${UVM_OIDC_FIXTURE_SUBJECT:-}${UVM_OIDC_FIXTURE_IDENTITIES:-}${UVM_GITHUB_PREVIEW_SECRET:-} ]]; then
    api_report 'G7_LOCAL_AUTH=synthetic-identity-settings-forbidden' >&2; exit 70
  fi
fi
if [[ -n ${UVM_OIDC_CONFIG_FILE:-} ]]; then
  [[ -s "$UVM_OIDC_CONFIG_FILE" ]] || { api_report 'G7_OIDC_CONFIG=file-missing' >&2; exit 70; }
  UVM_OIDC_CONFIG=$(exec 9>&-; cat "$UVM_OIDC_CONFIG_FILE")
  export UVM_OIDC_CONFIG
fi
if [[ ${UVM_AUTH_MODE:-bearer} == oidc ]]; then
  [[ -n ${UVM_OIDC_CONFIG:-} ]] || { api_report 'G7_OIDC_CONFIG=missing' >&2; exit 70; }
  install -d -o root -g uvm -m 0750 /run/uvm-g7-secrets
  for pair in 'oidc_client_secret:client_secret_file' 'oidc_sync_secret:sync_secret_file' 'oidc_operator_secret:operator_secret_file'; do
    source_name=${pair%%:*}
    config_name=${pair#*:}
    target=$(exec 9>&-; oidc_config_value "$config_name")
    case "$target" in /run/uvm-g7-secrets/*) ;; *) api_report 'G7_OIDC_SECRET_REFERENCE=invalid' >&2; exit 70 ;; esac
    install -o root -g uvm -m 0640 "/run/secrets/$source_name" "$target"
  done
  if [[ -f /run/secrets/github_webhook_secret_v1 && -f /run/secrets/github_webhook_secret_v2 ]]; then
    install -o uvm -g uvm -m 0600 /run/secrets/github_webhook_secret_v1 /run/uvm-g7-secrets/github_webhook_secret_v1
    install -o uvm -g uvm -m 0600 /run/secrets/github_webhook_secret_v2 /run/uvm-g7-secrets/github_webhook_secret_v2
    install -o root -g uvm -m 0640 /run/secrets/github_webhook_secret_version /run/uvm-g7-secrets/github_webhook_secret_version
  fi
  install -d -o uvm -g uvm -m 0700 /opt/uvm/state/scanner-evidence
  UVM_OIDC_ISSUER=$(exec 9>&-; oidc_config_value issuer)
  UVM_OIDC_CLIENT_ID=$(exec 9>&-; oidc_config_value client_id)
  UVM_OIDC_CALLBACK_URL=$(exec 9>&-; oidc_config_value callback_url)
  UVM_OIDC_PROVIDER_ID=$(exec 9>&-; oidc_config_value provider_id)
  UVM_OIDC_CLIENT_SECRET_FILE=$(exec 9>&-; oidc_config_value client_secret_file)
  UVM_OIDC_SYNC_SECRET_FILE=$(exec 9>&-; oidc_config_value sync_secret_file)
  UVM_OIDC_OPERATOR_SECRET_FILE=$(exec 9>&-; oidc_config_value operator_secret_file)
  if [[ $UVM_OIDC_DEPLOYMENT_MODE == demo ]]; then
    install -d -o uvm -g uvm -m 0700 /opt/uvm/state
    OIDC_PROVIDER_KEY=/opt/uvm/state/oidc-provider-private.pem
    if [[ ! -s "$OIDC_PROVIDER_KEY" ]]; then
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OIDC_PROVIDER_KEY" 2>/dev/null
      chown uvm:uvm "$OIDC_PROVIDER_KEY"
      chmod 0600 "$OIDC_PROVIDER_KEY"
    fi
    UVM_OIDC_FIXTURE_SUBJECT=${UVM_OIDC_FIXTURE_SUBJECT:?synthetic subject fixture is required in demo mode}
    UVM_OIDC_FIXTURE_IDENTITIES=${UVM_OIDC_FIXTURE_IDENTITIES:?synthetic identity fixture is required in demo mode}
  else
    if [[ -n ${UVM_OIDC_FIXTURE_SUBJECT:-}${UVM_OIDC_FIXTURE_IDENTITIES:-} ]]; then
      api_report 'G7_OIDC_EXTERNAL=synthetic-fixture-settings-forbidden' >&2
      exit 70
    fi
    UVM_AUTH_MODE=oidc UVM_OIDC_CONFIG="$UVM_OIDC_CONFIG" \
      UVM_OIDC_DEPLOYMENT_MODE=external /opt/uvm/venv/bin/python -c \
      'from uvm.auth.service import load_oidc_config; load_oidc_config()' || {
        api_report 'G7_OIDC_EXTERNAL=config-validation-failed' >&2; exit 70;
      }
  fi
fi
uvm_g7_stage_identity_material /run/secrets /run/uvm-g7-secrets /opt/uvm/state \
  "${UVM_AUTH_MODE:-bearer}" "$UVM_OIDC_DEPLOYMENT_MODE" \
  "${UVM_G7_VERIFICATION_ONLY:-0}" "${UVM_G7_RECOVERY_STAGE:-}"
UVM_PASSWORD_URL=$(exec 9>&-; printf %s "$UVM_PASSWORD" | urlpart)
CE_PASSWORD_URL=$(exec 9>&-; printf %s "$CE_PASSWORD" | urlpart)
export UVM_DB_URL="postgresql+psycopg://uvm_app:${UVM_PASSWORD_URL}@127.0.0.1:5432/uvm"
export DD_DATABASE_URL="postgresql://ce_app:${CE_PASSWORD_URL}@127.0.0.1:5432/defectdojo"
UVM_LOCAL_START_INITIAL=0
if [[ ${UVM_AUTH_MODE:-} == local && ${UVM_G7_VERIFICATION_ONLY:-0} != 1 ]]; then
  install -d -o root -g root -m 0700 /run/uvm-maintenance
  python - <<'ENVIRONMENT'
import json, os
from pathlib import Path
keys = ('UVM_DB_URL', 'UVM_AUTH_MODE', 'UVM_LOCAL_AUTH_CONFIG_FILE',
        'UVM_LOCAL_RECOVERY_CONFIG_FILE', 'UVM_CONNECTOR_LOCAL_KEY_FILE',
        'UVM_CONNECTOR_LOCAL_KEY_ID', 'UVM_SCANNER_EVIDENCE_DIR')
path = Path('/run/uvm-maintenance/environment.json')
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump({key: os.environ[key] for key in keys}, stream)
ENVIRONMENT
  recovery_maintenance() {
    /usr/local/bin/uvm-local-maintenance "$1" --config /etc/volt/local-auth.json
  }
  UVM_LOCAL_START_INITIAL=$(exec 9>&-; /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C UVM_LOCAL_START_IMAGE_ID="$UVM_LOCAL_START_IMAGE_ID" UVM_LOCAL_START_RESOURCES_SHA256="$UVM_LOCAL_START_RESOURCES_SHA256" /usr/local/bin/python3.14 -I -S /usr/local/libexec/volt-start-admission.py check)
fi
install -d -o root -g uvm -m 0750 /run/uvm-g7-secrets
install -o root -g uvm -m 0640 /run/secrets/uvm_db_password /run/uvm-g7-secrets/uvm_db_password
for recovery_material in recovery-server.crt recovery-server.key recovery-ca.crt; do
  [[ -s "/run/secrets/$recovery_material" ]] || { api_report "recovery TLS material is missing: $recovery_material" >&2; exit 70; }
done
install -o root -g uvm -m 0640 /run/secrets/recovery-server.crt /run/uvm-g7-secrets/recovery-server.crt
install -o root -g uvm -m 0640 /run/secrets/recovery-server.key /run/uvm-g7-secrets/recovery-server.key
install -o root -g uvm -m 0640 /run/secrets/recovery-ca.crt /run/uvm-g7-secrets/recovery-ca.crt
if [[ -n ${UVM_EXCEPTION_WARNING_DESTINATIONS:-} ]]; then
  install -d -o root -g uvm -m 0750 /run/uvm-g7-secrets/exception-warning
  while IFS= read -r secret_name; do
    [[ -z "$secret_name" ]] && continue
    [[ "$secret_name" =~ ^[A-Za-z0-9_.-]{1,100}$ ]] || { api_report 'exception warning secret reference is invalid' >&2; exit 70; }
    if [[ -f "/run/secrets/$secret_name" ]]; then
      install -o root -g uvm -m 0640 "/run/secrets/$secret_name" "/run/uvm-g7-secrets/exception-warning/$secret_name"
    fi
  done < <(UVM_EXCEPTION_WARNING_DESTINATIONS="$UVM_EXCEPTION_WARNING_DESTINATIONS" python -c 'import json,os,re; d=json.loads(os.environ["UVM_EXCEPTION_WARNING_DESTINATIONS"]); print("\n".join(sorted({v["secret_ref"][7:] for v in d.values() if isinstance(v,dict) and isinstance(v.get("secret_ref"),str) and v["secret_ref"].startswith("secret:")})))')
fi

if [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 && ! -s "$PGDATA/PG_VERSION" ]]; then
  api_report 'G7_RECOVERY_ERROR verification target has no restored PostgreSQL cluster' >&2
  exit 70
fi
if [[ ! -s "$PGDATA/PG_VERSION" ]]; then
  if [[ ${UVM_AUTH_MODE:-} == local && $UVM_LOCAL_START_INITIAL != 1 ]]; then
    api_report 'G7_LOCAL_START=configured-instance-missing-postgresql' >&2; exit 70
  fi
  install -d -o postgres -g postgres "$PGDATA"
  setpriv --reuid=postgres --regid=postgres --init-groups \
    /usr/lib/postgresql/18/bin/initdb -D "$PGDATA" --encoding=UTF8 --no-locale \
    --auth-local=peer --auth-host=scram-sha-256
  PG_CLUSTER_INITIALIZED=1
else
  PG_CLUSTER_INITIALIZED=0
fi
chown -R postgres:postgres "$PGDATA"
services_started=1
setpriv --reuid=postgres --regid=postgres --init-groups \
  /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" -l "$PGDATA/pg_ctl.log" \
  -o '-h 127.0.0.1 -p 5432' -w start
SERVICE_PIDS+=("pg")

install -d -o valkey -g valkey /var/lib/valkey
install -d -o valkey -g valkey /run/valkey
install -d -o 1001 -g 1337 -m 0750 /run/uwsgi
setpriv --reuid=valkey --regid=valkey --init-groups \
  valkey-server --bind 127.0.0.1 --port 6379 --dir /var/lib/valkey \
  --daemonize yes --pidfile /run/valkey/valkey.pid --logfile /run/valkey/valkey.log
SERVICE_PIDS+=("valkey")

wait_for() {
  local label=$1; shift
  for attempt in $(exec 9>&-; seq 1 90); do
    if (( shutdown_requested )); then
      api_report "G7_STARTUP_INTERRUPTED label=$label" >&2
      return 143
    fi
    "$@" 9>&- >/dev/null 2>&1 && return 0
    sleep 1
  done
  api_report "timed out waiting for $label" >&2; return 70
}
wait_for postgresql pg_isready -h 127.0.0.1 -p 5432 -U postgres
wait_for valkey valkey-cli -h 127.0.0.1 ping
abort_if_shutdown
case ${UVM_G7_TEST_FAULT:-} in
  startup-fail-after-broker)
    api_report 'G7_TEST_FAULT=startup-fail-after-broker' >&2
    exit 77
    ;;
  term-pause-after-broker)
    touch "$STATE/startup-paused"
    api_report 'G7_TEST_FAULT=term-pause-after-broker' >&2
    while (( ! shutdown_requested )); do sleep 0.2; done
    abort_if_shutdown
    ;;
  cleanup-fail-after-broker)
    api_report 'G7_TEST_FAULT=cleanup-fail-after-broker' >&2
    exit 0
    ;;
esac

psql_local() { setpriv --reuid=postgres --regid=postgres --init-groups psql -X -v ON_ERROR_STOP=1 -h /var/run/postgresql "$@"; }
G7_SCHEMA_MODE=${UVM_G7_SCHEMA_MODE:-normal}
G7_SCHEMA_DECLARED_HEAD=$(exec 9>&-; cat /etc/uvm-g7-schema-head)
G7_SCHEMA_COMPAT_ADMITTED=0
if [[ $G7_SCHEMA_MODE == upgrade-verification ]]; then
  [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 && ${UVM_G7_RECOVERY_STAGE:-} == control-only ]] || {
    api_report 'G7_SCHEMA_COMPATIBILITY_REJECTED reason=upgrade-mode-requires-control-only' >&2; exit 70;
  }
  PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence --check-schema-admission
  G7_SCHEMA_COMPAT_ADMITTED=1
fi
G7_SCHEMA_EMPTY_LOCAL_INSTALLATION=0
if (( PG_CLUSTER_INITIALIZED )); then
  G7_SCHEMA_HEADS='[]'
else
  if [[ $(exec 9>&-; psql_local -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname='uvm'") == 1 ]]; then
    if [[ $(exec 9>&-; psql_local -d uvm -Atc "SELECT to_regclass('public.alembic_version') IS NOT NULL") == t ]]; then
      G7_SCHEMA_HEADS=$(exec 9>&-; psql_local -d uvm -Atc "SELECT COALESCE(json_agg(version_num ORDER BY version_num)::text, '[]') FROM alembic_version")
    elif [[ ${UVM_AUTH_MODE:-} == local && $UVM_LOCAL_START_INITIAL == 1 && $G7_SCHEMA_MODE == normal \
        && ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_G7_RECOVERY_STAGE:-} != released \
        && $(exec 9>&-; psql_local -d uvm -Atc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S')") == 0 ]]; then
      # Interrupted first boot before migrations is distinct from an unsupported
      # existing schema. Only a validated generation0 local fence and an empty
      # application database admit this bounded resume path.
      setpriv --reuid=uvm --regid=uvm --init-groups \
        /opt/uvm/venv/bin/python -c 'from uvm.connectors.local_recovery import load_authority; a=load_authority(); assert a.fence["restore_generation"] == 0 and a.fence["recovery_epoch_id"] is None'
      G7_SCHEMA_HEADS='[]'
      G7_SCHEMA_EMPTY_LOCAL_INSTALLATION=1
    else
      api_report 'G7_SCHEMA_COMPATIBILITY_REJECTED reason=missing-version-table' >&2; exit 70
    fi
  elif [[ ${UVM_AUTH_MODE:-} == local && $UVM_LOCAL_START_INITIAL == 1 && $G7_SCHEMA_MODE == normal \
      && ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_G7_RECOVERY_STAGE:-} != released ]]; then
    # A protected, unacknowledged first preparation may have stopped after
    # initdb but before creating the application database.
    G7_SCHEMA_HEADS='[]'
    G7_SCHEMA_EMPTY_LOCAL_INSTALLATION=1
  else
    api_report 'G7_SCHEMA_COMPATIBILITY_REJECTED reason=existing-cluster-missing-uvm-database' >&2; exit 70
  fi
fi
/opt/uvm/venv/bin/python -m uvm.operations.schema_compatibility \
  --declared-head "$G7_SCHEMA_DECLARED_HEAD" --mode "$G7_SCHEMA_MODE" \
  --heads-json "$G7_SCHEMA_HEADS" \
  $(exec 9>&-; [[ ${PG_CLUSTER_INITIALIZED:-0} == 1 ]] && printf '%s' --empty-cluster) \
  $(exec 9>&-; [[ $G7_SCHEMA_EMPTY_LOCAL_INSTALLATION == 1 ]] && printf '%s' --empty-local-installation) \
  $(exec 9>&-; [[ $G7_SCHEMA_COMPAT_ADMITTED == 1 ]] && printf '%s' --compatibility-admitted)
if [[ ${UVM_AUTH_MODE:-} == local && ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && $UVM_LOCAL_START_INITIAL == 0 ]]; then
  # Existing-only validation precedes migrations and every local constructor.
  # This fixed backend operation cannot initialize a missing profile binding.
  recovery_maintenance apply-local-restore-fence > /run/uvm-maintenance/applied.json
  chmod 0600 /run/uvm-maintenance/applied.json
fi
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_G7_RECOVERY_STAGE:-} != released ]]; then
psql_local -d postgres -v uvm_password="$UVM_PASSWORD" -v ce_password="$CE_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE uvm_app LOGIN PASSWORD %L', :'uvm_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uvm_app') \gexec
ALTER ROLE uvm_app WITH LOGIN PASSWORD :'uvm_password';
SELECT format('CREATE ROLE ce_app LOGIN PASSWORD %L', :'ce_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ce_app') \gexec
ALTER ROLE ce_app WITH LOGIN PASSWORD :'ce_password';
SELECT 'CREATE DATABASE uvm OWNER uvm_app' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='uvm') \gexec
SELECT 'CREATE DATABASE defectdojo OWNER ce_app' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='defectdojo') \gexec
REVOKE CONNECT ON DATABASE uvm FROM PUBLIC;
REVOKE CONNECT ON DATABASE defectdojo FROM PUBLIC;
GRANT CONNECT ON DATABASE uvm TO uvm_app;
GRANT CONNECT ON DATABASE defectdojo TO ce_app;
SQL
fi
wait_for 'uvm database' env PGPASSWORD="$UVM_PASSWORD" psql -h 127.0.0.1 -U uvm_app -d uvm -c 'SELECT 1'
wait_for 'CE database' env PGPASSWORD="$CE_PASSWORD" psql -h 127.0.0.1 -U ce_app -d defectdojo -c 'SELECT 1'
export DD_CELERY_BROKER_URL=redis://127.0.0.1:6379/0 DD_CACHE_URL=redis://127.0.0.1:6379/1
export DD_DATABASE_HOST=127.0.0.1 DD_DATABASE_PORT=5432 DD_MEDIA_ROOT=/app/media

CE_INITIALIZE=true
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 || ${UVM_G7_RECOVERY_STAGE:-} == released ]]; then CE_INITIALIZE=false; fi
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_G7_RECOVERY_STAGE:-} != released ]]; then
api_report 'G7_INIT=CE initialize'
setpriv --reuid=1001 --regid=1337 --init-groups env -i PATH="$CE_PATH" HOME=/nonexistent \
  DD_DATABASE_URL="$DD_DATABASE_URL" DD_SECRET_KEY="$DD_SECRET_KEY" \
  DD_CREDENTIAL_AES_256_KEY="$DD_CREDENTIAL_AES_256_KEY" DD_ADMIN_PASSWORD="$DD_ADMIN_PASSWORD" \
  DD_ADMIN_USER="${DD_ADMIN_USER:-admin}" DD_ADMIN_MAIL="${DD_ADMIN_MAIL:-admin@defectdojo.local}" \
  DD_ADMIN_FIRST_NAME="${DD_ADMIN_FIRST_NAME:-Synthetic}" DD_ADMIN_LAST_NAME="${DD_ADMIN_LAST_NAME:-Operator}" \
  DD_ALLOWED_HOSTS="${DD_ALLOWED_HOSTS:-*}" DD_INITIALIZE=true \
  /entrypoint-initializer.sh /bin/true | sed -E 's/^(JIRA Webhook Secret:).*/\1 [REDACTED]/'
CE_INITIALIZE=false
abort_if_shutdown
fi
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_G7_RECOVERY_STAGE:-} != released ]]; then
api_report 'G7_INIT=UVM migrations'
setpriv --reuid=uvm --regid=uvm --init-groups env -i PATH="$PATH" HOME=/opt/uvm \
  PYTHONPATH=/opt/uvm/app UVM_DB_URL="$UVM_DB_URL" \
  sh -c 'cd /opt/uvm/app && exec python -m alembic -c alembic.ini upgrade head'
abort_if_shutdown
fi
if [[ ${UVM_AUTH_MODE:-} == local && ${UVM_G7_VERIFICATION_ONLY:-0} != 1 ]]; then
  if [[ $UVM_LOCAL_START_INITIAL == 1 ]]; then
    recovery_maintenance prepare-initial-installation >/dev/null
    recovery_maintenance validate-local-recovery > /run/uvm-maintenance/validated.json
    recovery_maintenance apply-local-restore-fence > /run/uvm-maintenance/applied.json
  fi
  chmod 0600 /run/uvm-maintenance/*.json
  recovery_maintenance initialize-scanner-rule >/dev/null
  api_report 'G7_LOCAL_START=awaiting-host-acknowledgement'
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C UVM_LOCAL_START_IMAGE_ID="$UVM_LOCAL_START_IMAGE_ID" UVM_LOCAL_START_RESOURCES_SHA256="$UVM_LOCAL_START_RESOURCES_SHA256" /usr/local/bin/python3.14 -I -S /usr/local/libexec/volt-start-admission.py wait-release
  api_report 'G7_LOCAL_START=host-release-validated'
  abort_if_shutdown
fi

# Fixed root broker helpers. Values cross only the private FIFO; no API-owned
# Python is imported as ROOT and no environment value/hash is stored or logged.
api_json_string() {
  local LC_ALL=C value=$1 character number index
  printf '"'
  for (( index=0; index<${#value}; index++ )); do
    character=${value:index:1}
    case "$character" in
      '"') printf '\\"' ;;
      '\') printf '\\\\' ;;
      *)
        printf -v number '%d' "'$character"
        if (( number < 32 )); then printf '\\u%04x' "$number"; else printf '%s' "$character"; fi ;;
    esac
  done
  printf '"'
}

emit_api_pair() {
  local LC_ALL=C key=$1 value=$2
  (( ${#value} <= 4096 )) || return 1
  API_INPUT_TOTAL=$(( API_INPUT_TOTAL + ${#key} + ${#value} ))
  (( API_INPUT_TOTAL <= 65536 )) || return 1
  printf '%s' "$API_INPUT_SEPARATOR"; API_INPUT_SEPARATOR=,
  api_json_string "$key"; printf ':'; api_json_string "$value"
}

api_broker_control() {
  case "$1" in
    launch-pid|ready|verification-health|api-stop-progress|signal-stop|signal-quiesce|signal-kill|orphan-cleanup|orphan-terminated|latch-quiesce|quiesce-surviving|quiesce-timeout) ;;
    *) printf '%s\n' 'route_check_failed:invalid_input' >&2; return 1 ;;
  esac
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/local/bin/python3.14 -I -S \
    /usr/local/libexec/volt-route-check-control.py "entrypoint-$1" 9>&-
}

emit_api_request() {
  local LC_ALL=C API_INPUT_TOTAL=0 API_INPUT_SEPARATOR='' port
  case "$UVM_API_PORT" in ''|*[!0-9]*) return 1 ;; esac
  (( ${#UVM_API_PORT} <= 5 )) || return 1
  port=$((10#$UVM_API_PORT)); (( port > 0 && port < 65536 )) || return 1
  printf '{"schema_version":1,"profile":"volt_main_api_launch_v1","main_bind":'
  api_json_string "$UVM_API_HOST"
  printf ',"main_port":%s,"api_environment":{' "$port"
  emit_api_pair 'PATH' "/opt/uvm/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" || return 1
  emit_api_pair 'HOME' "/opt/uvm" || return 1
  emit_api_pair 'UVM_G7_VERIFICATION_ONLY' "${UVM_G7_VERIFICATION_ONLY-0}" || return 1
  emit_api_pair 'UVM_G7_CONNECTOR_RECOVERY_ID' "${UVM_G7_CONNECTOR_RECOVERY_ID-}" || return 1
  emit_api_pair 'UVM_API_READ_SNAPSHOT_DIR' "$READ_SNAPSHOT_DIR" || return 1
  emit_api_pair 'PYTHONPATH' "/opt/uvm/app" || return 1
  emit_api_pair 'UVM_DB_URL' "$UVM_DB_URL" || return 1
  emit_api_pair 'UVM_API_CURSOR_SECRET' "$UVM_API_CURSOR_SECRET" || return 1
  emit_api_pair 'UVM_API_PRINCIPALS' "${UVM_API_PRINCIPALS-}" || return 1
  emit_api_pair 'UVM_G3_BOOTSTRAP_PRINCIPAL' "${UVM_G3_BOOTSTRAP_PRINCIPAL-}" || return 1
  emit_api_pair 'UVM_NATIVE_BOOTSTRAP_PRINCIPALS' "${UVM_NATIVE_BOOTSTRAP_PRINCIPALS-}" || return 1
  emit_api_pair 'UVM_NATIVE_GRANTABLE_ENVELOPE' "${UVM_NATIVE_GRANTABLE_ENVELOPE-}" || return 1
  emit_api_pair 'UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE' "${UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE-}" || return 1
  emit_api_pair 'UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS' "${UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS-}" || return 1
  emit_api_pair 'UVM_G7_HOST_KEY_ID' "${UVM_G7_HOST_KEY_ID-}" || return 1
  emit_api_pair 'UVM_G7_CONTROLLER_INSTANCE_ID' "${UVM_G7_CONTROLLER_INSTANCE_ID-}" || return 1
  emit_api_pair 'UVM_G7_RECOVERY_TLS_CERT_FILE' "${UVM_G7_RECOVERY_TLS_CERT_FILE-}" || return 1
  emit_api_pair 'UVM_G7_RECOVERY_TLS_KEY_FILE' "${UVM_G7_RECOVERY_TLS_KEY_FILE-}" || return 1
  emit_api_pair 'UVM_G7_RECOVERY_TLS_CA_FILE' "${UVM_G7_RECOVERY_TLS_CA_FILE-}" || return 1
  emit_api_pair 'UVM_G7_SOURCE_ADAPTER_PRINCIPAL' "${UVM_G7_SOURCE_ADAPTER_PRINCIPAL-}" || return 1
  emit_api_pair 'UVM_G7_DEPLOYMENT_ID' "${UVM_G7_DEPLOYMENT_ID-}" || return 1
  emit_api_pair 'UVM_G7_RECOVERY_EPOCH' "${UVM_G7_RECOVERY_EPOCH-}" || return 1
  emit_api_pair 'UVM_G7_STORAGE_GENERATION' "${UVM_G7_STORAGE_GENERATION-}" || return 1
  emit_api_pair 'UVM_G7_VOLUME_SET_DIGEST' "${UVM_G7_VOLUME_SET_DIGEST-}" || return 1
  emit_api_pair 'UVM_G7_PRESERVATION_PUBLIC_KEY_FILE' "${UVM_G7_PRESERVATION_PUBLIC_KEY_FILE-}" || return 1
  emit_api_pair 'UVM_G7_PRESERVATION_KEY_ID' "${UVM_G7_PRESERVATION_KEY_ID-}" || return 1
  emit_api_pair 'UVM_G7_PRESERVATION_REPORT_DIR' "${UVM_G7_PRESERVATION_REPORT_DIR-}" || return 1
  emit_api_pair 'UVM_G7_PRESERVATION_TRUST_DIR' "${UVM_G7_PRESERVATION_TRUST_DIR-}" || return 1
  emit_api_pair 'UVM_G7_PRESERVATION_ENVIRONMENT' "${UVM_G7_PRESERVATION_ENVIRONMENT-}" || return 1
  emit_api_pair 'UVM_G7_PRESERVATION_MAX_FUTURE_SKEW_SECONDS' "${UVM_G7_PRESERVATION_MAX_FUTURE_SKEW_SECONDS-}" || return 1
  emit_api_pair 'UVM_AUTH_MODE' "${UVM_AUTH_MODE-bearer}" || return 1
  emit_api_pair 'UVM_OIDC_CONFIG' "${UVM_OIDC_CONFIG-}" || return 1
  emit_api_pair 'UVM_LOCAL_AUTH_CONFIG_FILE' "${UVM_LOCAL_AUTH_CONFIG_FILE-}" || return 1
  emit_api_pair 'UVM_LOCAL_RECOVERY_CONFIG_FILE' "${UVM_LOCAL_RECOVERY_CONFIG_FILE-}" || return 1
  emit_api_pair 'UVM_SCANNER_EVIDENCE_DIR' "${UVM_SCANNER_EVIDENCE_DIR-}" || return 1
  emit_api_pair 'UVM_OIDC_DEPLOYMENT_MODE' "$UVM_OIDC_DEPLOYMENT_MODE" || return 1
  emit_api_pair 'SSL_CERT_FILE' "${SSL_CERT_FILE-}" || return 1
  emit_api_pair 'UVM_GITHUB_API_BASE_URL' "${UVM_GITHUB_API_BASE_URL-}" || return 1
  emit_api_pair 'UVM_GITHUB_APP_BASE_URL' "${UVM_GITHUB_APP_BASE_URL-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_PUBLIC_BASE_URL' "${UVM_CONNECTOR_PUBLIC_BASE_URL-}" || return 1
  emit_api_pair 'UVM_GITHUB_PREVIEW_SECRET' "${UVM_GITHUB_PREVIEW_SECRET-}" || return 1
  emit_api_pair 'UVM_GITHUB_TOKEN_FILE' "${UVM_GITHUB_TOKEN_FILE-}" || return 1
  emit_api_pair 'UVM_G7_DISPOSABLE_MODE' "${UVM_G7_DISPOSABLE_MODE-}" || return 1
  emit_api_pair 'UVM_G7_TEST_CLOCK_FILE' "${UVM_G7_TEST_CLOCK_FILE-}" || return 1
  emit_api_pair 'UVM_GITHUB_POLL_INTERVAL_SECONDS' "${UVM_GITHUB_POLL_INTERVAL_SECONDS:-86400}" || return 1
  emit_api_pair 'UVM_GITHUB_POLL_PRINCIPAL' "${UVM_GITHUB_POLL_PRINCIPAL-}" || return 1
  emit_api_pair 'UVM_GITHUB_POLL_COMPLETION_MARKER' "${UVM_GITHUB_POLL_COMPLETION_MARKER-}" || return 1
  emit_api_pair 'UVM_GITHUB_WEBHOOK_PRINCIPAL' "${UVM_GITHUB_WEBHOOK_PRINCIPAL-}" || return 1
  emit_api_pair 'UVM_GITHUB_WEBHOOK_SECRET_DIR' "${UVM_GITHUB_WEBHOOK_SECRET_DIR-}" || return 1
  emit_api_pair 'UVM_GITHUB_WEBHOOK_SECRET_VERSION_FILE' "${UVM_GITHUB_WEBHOOK_SECRET_VERSION_FILE-}" || return 1
  emit_api_pair 'UVM_GITHUB_WEBHOOK_CRASH_AFTER_COMMAND_COMMIT' "${UVM_GITHUB_WEBHOOK_CRASH_AFTER_COMMAND_COMMIT-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_FIXTURE_ID' "${UVM_CONNECTOR_FIXTURE_ID-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_FIXTURE_SOURCE_ID' "${UVM_CONNECTOR_FIXTURE_SOURCE_ID-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_FIXTURE_SOURCE_FAMILY' "${UVM_CONNECTOR_FIXTURE_SOURCE_FAMILY-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_FIXTURE_SOURCE_ACCOUNT_ID' "${UVM_CONNECTOR_FIXTURE_SOURCE_ACCOUNT_ID-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_FIXTURE_SCOPE_KEY' "${UVM_CONNECTOR_FIXTURE_SCOPE_KEY-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_ENVIRONMENT_LABEL' "${UVM_CONNECTOR_ENVIRONMENT_LABEL-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_LOCAL_KEY_FILE' "${UVM_CONNECTOR_LOCAL_KEY_FILE-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_LOCAL_KEY_ID' "${UVM_CONNECTOR_LOCAL_KEY_ID-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_RECOVERY_EPOCH_FILE' "${UVM_CONNECTOR_RECOVERY_EPOCH_FILE-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_ISSUER_LEDGER_FILE' "${UVM_CONNECTOR_ISSUER_LEDGER_FILE-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_ISSUER_KEY_FILE' "${UVM_CONNECTOR_ISSUER_KEY_FILE-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_OPERATOR_CLEARANCE_FILE' "${UVM_CONNECTOR_OPERATOR_CLEARANCE_FILE-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_OPERATOR_KEY_FILE' "${UVM_CONNECTOR_OPERATOR_KEY_FILE-}" || return 1
  emit_api_pair 'UVM_CONNECTOR_TEST_SUBMISSION_PAUSE_DIR' "${UVM_CONNECTOR_TEST_SUBMISSION_PAUSE_DIR-}" || return 1
  emit_api_pair 'UVM_EXCEPTION_WARNING_INSTALLATION_ID' "${UVM_EXCEPTION_WARNING_INSTALLATION_ID-}" || return 1
  emit_api_pair 'UVM_EXCEPTION_WARNING_SIGNING_SECRET_FILE' "${UVM_EXCEPTION_WARNING_SIGNING_SECRET_FILE-}" || return 1
  emit_api_pair 'UVM_INGRESS_ALLOWED_PEER_CIDRS' "${UVM_INGRESS_ALLOWED_PEER_CIDRS-}" || return 1
  emit_api_pair 'UVM_INGRESS_ALLOWED_HOSTS' "${UVM_INGRESS_ALLOWED_HOSTS-}" || return 1
  emit_api_pair 'UVM_UI_ROOT' /opt/uvm/ui || return 1
  emit_api_pair 'UVM_API_HOST' "$UVM_API_HOST" || return 1
  emit_api_pair 'UVM_API_PORT' "$UVM_API_PORT" || return 1
  printf '}}'
}



start_child() {
  local name=$1 uid=$2 gid=$3; shift 3
  setsid setpriv --reuid="$uid" --regid="$gid" --init-groups "$@" \
    >>"$STATE/$name.log" 2>&1 9>&- &
  local pid=$!
  CHILD_PIDS+=("$pid")
  CHILD_NAMES+=("$name")
  printf '%s\n' "$pid" >"$STATE/pid-$name" || { api_cleanup_poisoned=1; return 1; }
}
start_recovery_control() {
  # The control listener shares the persisted database. Local installations
  # must validate the same local identity and recovery binding as the product
  # listener; verification-only keeps this process from owning scanner work.
  local control_auth_mode=bearer
  local -a control_auth_environment=()
  if [[ ${UVM_AUTH_MODE:-bearer} == local ]]; then
    control_auth_mode=local
    control_auth_environment=(
      "UVM_LOCAL_AUTH_CONFIG_FILE=$UVM_LOCAL_AUTH_CONFIG_FILE"
      "UVM_LOCAL_RECOVERY_CONFIG_FILE=$UVM_LOCAL_RECOVERY_CONFIG_FILE"
      "UVM_CONNECTOR_LOCAL_KEY_FILE=$UVM_CONNECTOR_LOCAL_KEY_FILE"
      "UVM_CONNECTOR_LOCAL_KEY_ID=$UVM_CONNECTOR_LOCAL_KEY_ID"
      "UVM_SCANNER_EVIDENCE_DIR=$UVM_SCANNER_EVIDENCE_DIR"
      "UVM_INGRESS_ALLOWED_PEER_CIDRS=$UVM_INGRESS_ALLOWED_PEER_CIDRS"
      "UVM_INGRESS_ALLOWED_HOSTS=$UVM_INGRESS_ALLOWED_HOSTS"
    )
  fi
  start_child recovery-control 1800 1800 env -i PATH="$PATH" HOME=/opt/uvm \
    PYTHONPATH=/opt/uvm/app UVM_DB_URL="$UVM_DB_URL" \
    UVM_API_CURSOR_SECRET="$UVM_API_CURSOR_SECRET" \
    UVM_API_PRINCIPALS="${UVM_API_PRINCIPALS-}" \
    UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE="${UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE-}" \
    UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS="${UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS-}" \
    UVM_G7_HOST_KEY_ID="${UVM_G7_HOST_KEY_ID-}" \
    UVM_G7_CONTROLLER_INSTANCE_ID="${UVM_G7_CONTROLLER_INSTANCE_ID-}" \
    UVM_G7_RECOVERY_CONTROL_ONLY=1 UVM_G7_VERIFICATION_ONLY=1 \
    UVM_G7_DISPOSABLE_MODE="${UVM_G7_DISPOSABLE_MODE-}" \
    UVM_G7_RECOVERY_CONTROL_PORT="${UVM_G7_RECOVERY_CONTROL_PORT:-8002}" \
    UVM_API_HOST=0.0.0.0 UVM_API_PORT="${UVM_G7_RECOVERY_CONTROL_PORT:-8002}" \
    UVM_G7_RECOVERY_TLS_CERT_FILE="$RECOVERY_TLS_DIR/server.crt" \
    UVM_G7_RECOVERY_TLS_KEY_FILE="$RECOVERY_TLS_DIR/server.key" \
    UVM_G7_RECOVERY_TLS_CA_FILE="$RECOVERY_TLS_DIR/client-ca.crt" \
    UVM_AUTH_MODE="$control_auth_mode" "${control_auth_environment[@]}" \
    python -m uvicorn uvm.api.app:app --host 0.0.0.0 \
      --port "${UVM_G7_RECOVERY_CONTROL_PORT:-8002}" --workers 1 --no-proxy-headers \
      --ssl-certfile "$RECOVERY_TLS_DIR/server.crt" \
      --ssl-keyfile "$RECOVERY_TLS_DIR/server.key" \
      --ssl-ca-certs "$RECOVERY_TLS_DIR/client-ca.crt" --ssl-cert-reqs 2
}

if [[ ${UVM_G7_RECOVERY_STAGE:-} == control-only || ${UVM_G7_RECOVERY_STAGE:-} == released ]]; then
  [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 || ${UVM_G7_RECOVERY_STAGE:-} == released ]] || { api_report 'G7_RECOVERY_ERROR control-only requires verification-only mode' >&2; exit 70; }
  case ${UVM_AUTH_MODE:-bearer} in
    bearer|oidc|local) ;;
    *) api_report 'G7_RECOVERY_ERROR verification-only product API authentication mode is unsupported' >&2; exit 70 ;;
  esac
  : "${UVM_G7_STARTUP_FENCE_TOKEN:?signed startup-fence token is required}"
  : "${UVM_G7_HOST_PUBLIC_KEY_FILE:?host verification key is required}"
  : "${UVM_G7_DEPLOYMENT_ID:?deployment identity is required}"
  : "${UVM_G7_TARGET_IMAGE_DIGEST:?target image digest is required}"
  : "${UVM_G7_RECOVERY_VOLUME_IDS:?replacement volume identities are required}"
  : "${UVM_G7_ARCHIVE_DIGEST:?verified archive digest is required}"
  : "${UVM_G7_RECOVERY_EPOCH:?recovery epoch is required}"
  : "${UVM_G7_CONNECTOR_RECOVERY_ID:?connector recovery UUID is required}"
  [[ $UVM_G7_DEPLOYMENT_ID =~ ^[A-Za-z0-9._-]{1,128}$ ]] || { api_report 'G7_RECOVERY_ERROR deployment identity is invalid' >&2; exit 70; }
  PYTHONPATH=/opt/uvm/app python -m uvm.operations.startup_fence
fi

if [[ ${UVM_G7_RECOVERY_STAGE:-} == released ]]; then
  PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence --check-host-release || {
    api_report 'G7_RECOVERY_ERROR released startup lacks its signed durable admission' >&2; exit 70;
  }
fi

if [[ ${UVM_G7_RECOVERY_STAGE:-} == control-only ]]; then
  install -d -o 1800 -g 1800 -m 0700 /run/uvm-g7-recovery
  install -o 1800 -g 1800 -m 0644 "$UVM_G7_RECOVERY_TLS_CERT_FILE" /run/uvm-g7-recovery/server.crt
  install -o 1800 -g 1800 -m 0600 "$UVM_G7_RECOVERY_TLS_KEY_FILE" /run/uvm-g7-recovery/server.key
  install -o 1800 -g 1800 -m 0644 "$UVM_G7_RECOVERY_TLS_CA_FILE" /run/uvm-g7-recovery/client-ca.crt
  RECOVERY_TLS_DIR=/run/uvm-g7-recovery
  start_recovery_control
  wait_for 'recovery-control listener' env RECOVERY_CONTROL_PORT="${UVM_G7_RECOVERY_CONTROL_PORT:-8002}" \
    /opt/uvm/venv/bin/python -c 'import os,socket; s=socket.create_connection(("127.0.0.1",int(os.environ["RECOVERY_CONTROL_PORT"])),timeout=1); s.close()'
  printf '%s\n' control >"$STATE/runtime-mode" || { api_cleanup_poisoned=1; exit 70; }
  api_phase_marker ready || { api_cleanup_poisoned=1; exit 70; }
  api_report 'G7_READINESS=recovery-control-only'
  # The host performs authenticated resync and quarantine while this is the
  # only application listener. Product APIs and CE stay stopped until the
  # signed restored transition and the admitted migration head are durable.
  for attempt in $(exec 9>&-; seq 1 "${UVM_G7_RECOVERY_GATE_TIMEOUT_SECONDS:-1800}"); do
    if PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence \
        --check-admission >"$STATE/recovery-gate.json" 2>"$STATE/recovery-gate-query.stderr"; then
      recovery_state=restored
      break
    fi
    abort_if_shutdown
    sleep 1
  done
  [[ ${recovery_state:-} == restored ]] || {
    api_report 'G7_RECOVERY_ERROR host did not admit volumes_restored transition' >&2
    [[ ! -s "$STATE/recovery-gate-query.stderr" ]] || sed -n '1,5p' "$STATE/recovery-gate-query.stderr" >&2
    exit 70
  }
  if [[ -n ${UVM_G7_SCHEMA_MODE:-} && ${UVM_G7_SCHEMA_MODE} == upgrade-verification ]]; then
    schema_ready=0
    for attempt in $(exec 9>&-; seq 1 "${UVM_G7_RECOVERY_GATE_TIMEOUT_SECONDS:-1800}"); do
      if PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence \
          --check-schema-complete >"$STATE/schema-migration-gate.json" 2>"$STATE/schema-migration-gate-query.stderr"; then
        schema_ready=1
        break
      fi
      abort_if_shutdown
      sleep 1
    done
    (( schema_ready == 1 )) || {
      api_report 'G7_RECOVERY_ERROR admitted migration head was not complete' >&2
      [[ ! -s "$STATE/schema-migration-gate-query.stderr" ]] || sed -n '1,5p' "$STATE/schema-migration-gate-query.stderr" >&2
      exit 70
    }
  fi
  recovery_control_gate_passed=1
  api_remove_ready || { api_cleanup_poisoned=1; exit 70; }
fi

start_ce_web() {
start_child ce-web 1001 1337 env -i PATH="$CE_PATH" HOME=/nonexistent \
  UVM_G7_VERIFICATION_ONLY="${UVM_G7_VERIFICATION_ONLY-0}" \
  DD_DATABASE_URL="$DD_DATABASE_URL" DD_SECRET_KEY="$DD_SECRET_KEY" \
  DD_CREDENTIAL_AES_256_KEY="$DD_CREDENTIAL_AES_256_KEY" DD_ADMIN_PASSWORD="$DD_ADMIN_PASSWORD" \
  DD_ADMIN_USER="${DD_ADMIN_USER:-admin}" DD_ADMIN_MAIL="${DD_ADMIN_MAIL:-admin@defectdojo.local}" \
  DD_ADMIN_FIRST_NAME="${DD_ADMIN_FIRST_NAME:-Synthetic}" DD_ADMIN_LAST_NAME="${DD_ADMIN_LAST_NAME:-Operator}" \
  DD_ALLOWED_HOSTS="${DD_ALLOWED_HOSTS:-*}" DD_INITIALIZE="$CE_INITIALIZE" \
  DD_UWSGI_EXTRA_ARGS='--die-on-term --master-fifo=/run/uwsgi/uvm-g7.fifo' \
  DD_CELERY_BROKER_URL="$DD_CELERY_BROKER_URL" DD_CACHE_URL="$DD_CACHE_URL" \
  DD_DATABASE_HOST=127.0.0.1 DD_DATABASE_PORT=5432 DD_MEDIA_ROOT=/app/media \
  DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Generic Findings Import":"unique_id_from_tool"}' \
  DD_UWSGI_MODE=socket DD_UWSGI_ENDPOINT=127.0.0.1:3031 /entrypoint-uwsgi.sh
}
if [[ ${UVM_G7_RECOVERY_STAGE:-} != control-only || $recovery_control_gate_passed == 1 ]]; then
  start_ce_web
fi
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 ]]; then
start_child ce-worker 1001 1337 env -i PATH="$CE_PATH" HOME=/nonexistent \
  DD_DATABASE_URL="$DD_DATABASE_URL" DD_SECRET_KEY="$DD_SECRET_KEY" \
  DD_CREDENTIAL_AES_256_KEY="$DD_CREDENTIAL_AES_256_KEY" \
  DD_CELERY_BROKER_URL="$DD_CELERY_BROKER_URL" DD_CACHE_URL="$DD_CACHE_URL" \
  DD_DATABASE_HOST=127.0.0.1 DD_DATABASE_PORT=5432 DD_MEDIA_ROOT=/app/media \
  DD_CELERY_LOG_LEVEL=INFO DD_CELERY_WORKER_POOL_TYPE=solo \
  DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Generic Findings Import":"unique_id_from_tool"}' \
  /entrypoint-celery-worker.sh
start_child ce-beat 1001 1337 env -i PATH="$CE_PATH" HOME=/nonexistent \
  PYTHONPATH=/app:/opt/uvm/app \
  UVM_G7_DISPOSABLE_MODE="${UVM_G7_DISPOSABLE_MODE-}" \
  UVM_G7_SCHEDULER_PROGRESS_FILE=/run/uvm-g7-scheduler/progress.json \
  UVM_G7_SCHEDULER_STALL_FILE=/run/uvm-g7-scheduler/test-stall \
  DD_DATABASE_URL="$DD_DATABASE_URL" DD_SECRET_KEY="$DD_SECRET_KEY" \
  DD_CREDENTIAL_AES_256_KEY="$DD_CREDENTIAL_AES_256_KEY" \
  DD_CELERY_BROKER_URL="$DD_CELERY_BROKER_URL" DD_CACHE_URL="$DD_CACHE_URL" \
  DD_DATABASE_HOST=127.0.0.1 DD_DATABASE_PORT=5432 DD_MEDIA_ROOT=/app/media \
  DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Generic Findings Import":"unique_id_from_tool"}' \
  /entrypoint-celery-beat.sh
fi
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_AUTH_MODE:-bearer} == oidc && $UVM_OIDC_DEPLOYMENT_MODE == demo ]]; then
  provider_credential_env=()
  if [[ -n ${UVM_OIDC_DEMO_CREDENTIALS_FILE:-} ]]; then
    provider_credential_env=("UVM_OIDC_DEMO_CREDENTIALS_FILE=$UVM_OIDC_DEMO_CREDENTIALS_FILE")
  fi
  start_child oidc-provider 1800 1800 env -i PATH="$PATH" HOME=/opt/uvm \
    PYTHONPATH=/opt/uvm/app UVM_OIDC_ISSUER="$UVM_OIDC_ISSUER" \
    UVM_OIDC_CLIENT_ID="$UVM_OIDC_CLIENT_ID" UVM_OIDC_CALLBACK_URL="$UVM_OIDC_CALLBACK_URL" \
    UVM_OIDC_PROVIDER_ID="$UVM_OIDC_PROVIDER_ID" UVM_OIDC_CLIENT_SECRET_FILE="$UVM_OIDC_CLIENT_SECRET_FILE" \
    UVM_OIDC_SYNC_SECRET_FILE="$UVM_OIDC_SYNC_SECRET_FILE" \
    UVM_OIDC_OPERATOR_SECRET_FILE="$UVM_OIDC_OPERATOR_SECRET_FILE" \
    UVM_OIDC_BROWSER_AUTHORIZATION_ORIGIN="${UVM_OIDC_BROWSER_AUTHORIZATION_ORIGIN-}" \
    UVM_OIDC_INTERNAL_ENDPOINT_ORIGIN="${UVM_OIDC_INTERNAL_ENDPOINT_ORIGIN-}" \
    UVM_OIDC_PROVIDER_KEY_FILE=/opt/uvm/state/oidc-provider-private.pem \
    UVM_OIDC_PROVIDER_REVISION_FILE=/opt/uvm/state/oidc-provider-revision \
    UVM_OIDC_FIXTURE_HOLD_SYNC="${UVM_OIDC_FIXTURE_HOLD_SYNC-}" \
    UVM_OIDC_FIXTURE_SUBJECT="$UVM_OIDC_FIXTURE_SUBJECT" \
    UVM_OIDC_FIXTURE_IDENTITIES="$UVM_OIDC_FIXTURE_IDENTITIES" \
    "${provider_credential_env[@]}" \
    UVM_G7_DISPOSABLE_MODE="${UVM_G7_DISPOSABLE_MODE-}" \
    UVM_G7_TEST_CLOCK_FILE="${UVM_G7_TEST_CLOCK_FILE-}" \
    python -m uvicorn uvm.auth.synthetic_provider:app --host 0.0.0.0 --port "${UVM_OIDC_PROVIDER_PORT:-9000}" --workers 1 --no-proxy-headers
fi
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_AUTH_MODE:-bearer} == oidc ]]; then
  start_child oidc-sync-api 1800 1800 env -i PATH="$PATH" HOME=/opt/uvm \
    PYTHONPATH=/opt/uvm/app UVM_DB_URL="$UVM_DB_URL" \
    UVM_API_CURSOR_SECRET="$UVM_API_CURSOR_SECRET" UVM_API_PRINCIPALS="${UVM_API_PRINCIPALS-}" \
    UVM_G3_BOOTSTRAP_PRINCIPAL="${UVM_G3_BOOTSTRAP_PRINCIPAL-}" \
    UVM_AUTH_MODE=oidc UVM_OIDC_CONFIG="$UVM_OIDC_CONFIG" \
    UVM_GITHUB_API_BASE_URL="${UVM_GITHUB_API_BASE_URL-}" \
    UVM_GITHUB_TOKEN_FILE="${UVM_GITHUB_TOKEN_FILE-}" UVM_G7_DISPOSABLE_MODE="${UVM_G7_DISPOSABLE_MODE-}" \
    UVM_GITHUB_POLL_INTERVAL_SECONDS="${UVM_GITHUB_POLL_INTERVAL_SECONDS:-86400}" \
    UVM_GITHUB_POLL_PRINCIPAL="${UVM_GITHUB_POLL_PRINCIPAL-}" \
    UVM_GITHUB_POLL_COMPLETION_MARKER="${UVM_GITHUB_POLL_COMPLETION_MARKER-}" \
    UVM_INGRESS_ALLOWED_PEER_CIDRS="${UVM_INGRESS_ALLOWED_PEER_CIDRS-}" \
    UVM_INGRESS_ALLOWED_HOSTS="${UVM_INGRESS_ALLOWED_HOSTS-}" \
    python -m uvicorn uvm.auth.internal_app:app --host 127.0.0.1 --port 8001 --workers 1
fi
if [[ ${UVM_G7_DISPOSABLE_MODE:-0} == 1 && -n ${UVM_G7_TEST_CLOCK_FILE:-} ]]; then
  # Bind-mount permission translation may restore the host's private mode.
  # This synthetic clock contains no secrets and is enabled only in disposable
  # runs; make it readable by the API's uid 1800 before starting that process.
  chmod 0644 "$UVM_G7_TEST_CLOCK_FILE"
fi
# A worker replacement shares live cursors with its peers. Whole-container
# startup invalidates the volatile cache, preserving fail-closed restart rules.
READ_SNAPSHOT_DIR=/run/uvm-read-snapshots
install -d -o 1800 -g 1800 -m 0700 "$READ_SNAPSHOT_DIR"
find "$READ_SNAPSHOT_DIR" -mindepth 1 -maxdepth 1 -type f -delete
: "${UVM_G7_RECOVERY_TLS_CERT_FILE:?recovery TLS server cert is required}"
: "${UVM_G7_RECOVERY_TLS_KEY_FILE:?recovery TLS server key is required}"
: "${UVM_G7_RECOVERY_TLS_CA_FILE:?recovery TLS client CA is required}"
RECOVERY_TLS_DIR=/run/uvm-g7-recovery
install -d -o 1800 -g 1800 -m 0700 "$RECOVERY_TLS_DIR"
install -o 1800 -g 1800 -m 0644 "$UVM_G7_RECOVERY_TLS_CERT_FILE" "$RECOVERY_TLS_DIR/server.crt"
install -o 1800 -g 1800 -m 0600 "$UVM_G7_RECOVERY_TLS_KEY_FILE" "$RECOVERY_TLS_DIR/server.key"
install -o 1800 -g 1800 -m 0644 "$UVM_G7_RECOVERY_TLS_CA_FILE" "$RECOVERY_TLS_DIR/client-ca.crt"
# The direct critical child is the ROOT broker. pid-api is populated ONLY
# from the completed typed launch record, never from broker $! or a pid fallback.
# No filesystem transport is created. A legacy FIFO has unknown participants
# and is denied unchanged; root ownership/mode alone cannot authorize removal.
[[ ! -e "$STATE/api-launch-input" && ! -L "$STATE/api-launch-input" ]] || {
  api_report 'G7_API_LAUNCH=legacy-input-uncertain' >&2; exit 70;
}
begin_api_input_deadline
coproc API_INPUT {
  IFS= read -r -t 5 api_input_gate && [[ $api_input_gate == G ]] || exit 70
  emit_api_request
}
api_input_producer=$API_INPUT_PID
api_input_original_read=${API_INPUT[0]}
api_input_gate_fd=${API_INPUT[1]}
exec {api_input_read}<&"$api_input_original_read"
exec {api_input_original_read}<&-
unset api_input_original_read
# Process substitution's final exec retains the ORIGINAL direct Bash child.
# Only its read end becomes FD3; the parent alone opens reserved writer FD9.
exec 9> >(
  exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /usr/local/bin/python3.14 -I -S /usr/local/libexec/volt-main-api-launcher.py \
    3<&0 <&"$api_input_read" 9>&- >>"$STATE/api-broker.log" 2>&1
)
api_broker_pid=$!
api_terminal_active=1
CHILD_PIDS+=("$api_broker_pid")
CHILD_NAMES+=(api-broker)
printf '%s\n' "$api_broker_pid" >"$STATE/pid-api-broker" || { api_cleanup_poisoned=1; exit 70; }
printf 'G\n' >&"$api_input_gate_fd" || { api_report 'G7_API_LAUNCH=private-input-failed' >&2; exit 70; }
exec {api_input_gate_fd}>&-
unset api_input_gate_fd
exec {api_input_read}<&-
unset api_input_read
if ! close_api_input; then api_report 'G7_API_LAUNCH=private-input-invalid' >&2; exit 70; fi

api_launch_confirmed=0
for attempt in $(exec 9>&-; seq 1 200); do
  # Run the protected publisher as a DIRECT child of PID1. Command substitution
  # would add a subshell parent and violate its exact entrypoint identity join.
  if api_broker_control launch-pid >"$STATE/pid-api" 2>/dev/null; then
    IFS= read -r api_pid <"$STATE/pid-api"
    case "$api_pid" in ''|*[!0-9]*) api_report 'G7_API_LAUNCH=invalid-process' >&2; exit 70 ;; esac
    api_launch_confirmed=1; break
  fi
  kill -0 "$api_broker_pid" 2>/dev/null || break
  sleep 0.05
done
(( api_launch_confirmed )) || { api_report 'G7_API_LAUNCH=unconfirmed' >&2; exit 70; }

if [[ ${UVM_G7_RECOVERY_STAGE:-} != control-only ]]; then start_recovery_control; fi
if [[ ${UVM_EXCEPTION_WARNING_WORKER:-0} == 1 && ${UVM_G7_VERIFICATION_ONLY:-0} != 1 ]]; then
  if [[ ${UVM_G7_DISPOSABLE_MODE:-0} == 1 && -n ${UVM_EXCEPTION_WARNING_PAUSE_FILE:-} ]]; then
    # Test control is synthetic and contains no secrets. Make bind-mount mode
    # translation explicit before the worker drops to uid 1800.
    chmod 0777 "$(exec 9>&-; dirname "$UVM_EXCEPTION_WARNING_PAUSE_FILE")"
    if [[ -e "$UVM_EXCEPTION_WARNING_PAUSE_FILE" ]]; then
      chmod 0666 "$UVM_EXCEPTION_WARNING_PAUSE_FILE"
    fi
  fi
  warning_principals='{}'
  if [[ ${UVM_AUTH_MODE:-bearer} == oidc ]]; then
    warning_principals=$(exec 9>&-; UVM_API_PRINCIPALS="${UVM_API_PRINCIPALS-}" /opt/uvm/venv/bin/python -c '
import json, os
raw = json.loads(os.environ.get("UVM_API_PRINCIPALS", "{}"))
def scope_tuple(scope):
    if isinstance(scope, dict):
        scope = [scope.get(key) for key in ("source_family", "source_account_id", "scope_key")]
    if not isinstance(scope, (list, tuple)) or len(scope) != 3 or not all(isinstance(x, str) and x for x in scope):
        raise SystemExit("invalid service recipient source scope")
    return list(scope)
print(json.dumps({principal: {"actor_kind": record.get("actor_kind"),
    "scopes": [scope_tuple(scope) for scope in record.get("scopes", [])],
    "role_ids": list(record.get("role_ids", []))}
    for principal, record in raw.items() if isinstance(record, dict)
    and record.get("actor_kind") in {"service", "principal"}},
    sort_keys=True, separators=(",", ":")))
')
  fi
  start_child exception-warning-worker 1800 1800 env -i PATH="$PATH" HOME=/opt/uvm \
    PYTHONPATH=/opt/uvm/app UVM_DB_URL="$UVM_DB_URL" \
    UVM_AUTH_MODE="${UVM_AUTH_MODE-bearer}" \
    UVM_OIDC_CONFIG="${UVM_OIDC_CONFIG-}" \
    UVM_EXCEPTION_WARNING_PRINCIPALS="$warning_principals" \
    UVM_EXCEPTION_WARNING_INSTALLATION_ID="${UVM_EXCEPTION_WARNING_INSTALLATION_ID-}" \
    UVM_EXCEPTION_WARNING_APP_ID="${UVM_EXCEPTION_WARNING_APP_ID-}" \
    UVM_G7_TEST_CLOCK_FILE="${UVM_G7_TEST_CLOCK_FILE-}" \
    UVM_G7_DISPOSABLE_MODE="${UVM_G7_DISPOSABLE_MODE-}" \
    SSL_CERT_FILE="${SSL_CERT_FILE-}" \
    UVM_EXCEPTION_WARNING_USE_LOOPBACK_HTTP="${UVM_EXCEPTION_WARNING_USE_LOOPBACK_HTTP-}" \
    UVM_EXCEPTION_WARNING_PAUSE_FILE="${UVM_EXCEPTION_WARNING_PAUSE_FILE-}" \
    UVM_EXCEPTION_WARNING_DESTINATIONS="${UVM_EXCEPTION_WARNING_DESTINATIONS-}" \
    UVM_EXCEPTION_WARNING_POLL_SECONDS="${UVM_EXCEPTION_WARNING_POLL_SECONDS:-15}" \
    UVM_EXCEPTION_WARNING_BATCH_SIZE="${UVM_EXCEPTION_WARNING_BATCH_SIZE:-20}" \
    UVM_EXCEPTION_WARNING_ORPHAN_SECONDS="${UVM_EXCEPTION_WARNING_ORPHAN_SECONDS:-30}" \
    UVM_EXCEPTION_WARNING_START_DELAY_SECONDS="${UVM_EXCEPTION_WARNING_START_DELAY_SECONDS:-0}" \
    python -m uvm.assessment.exception_warning_worker
fi

wait_for 'CE web' curl --silent --output /dev/null http://127.0.0.1:8081/api/v2/
wait_for 'uWSGI master FIFO' test -p /run/uwsgi/uvm-g7.fifo
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_AUTH_MODE:-bearer} == oidc ]]; then
  if [[ $UVM_OIDC_DEPLOYMENT_MODE == demo ]]; then
    wait_for 'local OIDC provider' curl --fail --silent "http://127.0.0.1:${UVM_OIDC_PROVIDER_PORT:-9000}/healthz"
  fi
  wait_for 'loopback OIDC sync adapter' curl --fail --silent http://127.0.0.1:8001/healthz
fi
if [[ -n ${UVM_G7_OKTA_PUBLISHER_CONFIG_FILE:-} ]]; then
  uvm_g7_invalidate_publisher_readiness /opt/uvm/state/oidc-publisher 9>&-
  start_child okta-identity-publisher 1800 1800 env -i PATH="$PATH" HOME=/opt/uvm \
    PYTHONPATH=/opt/uvm/app UVM_OIDC_SYNC_SECRET_FILE=/run/uvm-g7-secrets/oidc_sync_secret \
    /opt/uvm/venv/bin/python -m uvm.auth.okta_publisher \
      --config "$UVM_G7_OKTA_PUBLISHER_CONFIG_FILE"
  wait_for 'Okta publisher first successful full snapshot' \
    /opt/uvm/venv/bin/python -m uvm.auth.okta_publisher \
      --config "$UVM_G7_OKTA_PUBLISHER_CONFIG_FILE" --status
fi
wait_for 'UVM API' curl --fail --silent http://127.0.0.1:8000/openapi.json
for pid in "${CHILD_PIDS[@]}"; do
  kill -0 "$pid" || { api_report "critical child exited during startup: $pid" >&2; exit 70; }
done
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 ]]; then
  printf '%s\n' verification >"$STATE/runtime-mode" || { api_cleanup_poisoned=1; exit 70; }
else
  printf '%s\n' runtime >"$STATE/runtime-mode" || { api_cleanup_poisoned=1; exit 70; }
fi
api_phase_marker ready || { api_cleanup_poisoned=1; exit 70; }
api_ready_confirmed=0
for ((attempt=0;attempt<200;attempt++)); do
  if [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 ]]; then api_ready_action=verification-health; else api_ready_action=ready; fi
  if api_broker_control "$api_ready_action" >/dev/null 2>&1; then api_ready_confirmed=1; break; fi
  kill -0 "$api_broker_pid" 2>/dev/null || break
  (( ! shutdown_requested )) || break
  sleep .05
done
(( api_ready_confirmed )) || { api_remove_ready || :; api_report 'G7_API_LAUNCH=ready-admission-failed' >&2; exit 70; }
api_report 'G7_READINESS=ready'
if [[ ${UVM_G7_RECOVERY_STAGE:-} == control-only ]]; then
  # The host must retain the signed acknowledgement and journal actual fence
  # release before explicitly asking this supervisor to start runtime effects.
  while [[ ! -f "$STATE/host-release" ]]; do
    abort_if_shutdown
    for pid in "${CHILD_PIDS[@]}"; do kill -0 "$pid" || exit 70; done
    sleep 0.2
  done
  PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence --check-host-release || exit 70
  cleanup_running=1
  stop_all || exit 71
  exec env UVM_G7_RECOVERY_STAGE=released UVM_G7_VERIFICATION_ONLY=0 "$0"
fi
trap 'handle_shutdown' TERM INT
exited_child_pid=
child_status=0
wait_bookkeeping_failed=0
while :; do
  exited_child_pid=
  # Bash5.2 wait-n does not register this process-substitution broker and can
  # skip an already completed ordinary job too. Poll ONLY original registered
  # children; the exact Bash wait result remains the completion authority.
  for pid in "${CHILD_PIDS[@]}"; do
    [[ ! ${REAPED_CHILDREN[$pid]+present} ]] || continue
    if kill -0 "$pid" 2>/dev/null; then continue; fi
    # A failed signal probe while a process still exists is uncertainty, not
    # permission to wait for/adopt a live or recycled numeric PID.
    if [[ -e /proc/$pid ]]; then
      api_cleanup_poisoned=1; wait_bookkeeping_failed=1; child_status=70
      record_api_stop_receipt || :
      api_report 'G7_WAIT_ERROR=unresolved-child' >&2 || :
      break
    fi
    while :; do
      wait_epoch=${api_input_wait_epoch:-0}
      if wait "$pid"; then child_status=0; else child_status=$?; fi
      # A trapped signal can interrupt a wait without reaping. The original
      # registered child is already absent above; retain registration and obtain
      # its actual cached completion, rather than crediting the signal return.
      if (( child_status > 128 && wait_epoch != ${api_input_wait_epoch:-0} )); then continue; fi
      break
    done
    if (( child_status == 127 )); then
      if [[ ${CHILD_EXIT_STATUS[$pid]+present} ]]; then
        child_status=${CHILD_EXIT_STATUS[$pid]}
      else
        api_cleanup_poisoned=1; wait_bookkeeping_failed=1; child_status=70
        UNRESOLVED_CHILDREN[$pid]=1
        record_api_stop_receipt || :
        api_report 'G7_WAIT_ERROR=unresolved-child' >&2 || :
        break
      fi
    fi
    exited_child_pid=$pid
    break
  done
  (( ! wait_bookkeeping_failed )) || break
  if [[ ${exited_child_pid:-} ]]; then
    CHILD_EXIT_STATUS[$exited_child_pid]=$child_status
    REAPED_CHILDREN[$exited_child_pid]=1
    api_cleanup_poisoned=1
    shutdown_status=1
    record_api_stop_receipt || :
    # Any independently reaped critical child is still a critical failure,
    # including while failed-quiesce is latched.
    break
  fi
  (( ! shutdown_requested )) || break
  if (( quiesce_requested )); then
    quiesce_requested=0
    if UVM_G7_QUIESCE_NO_KILL=1 staged_quiesce; then
      cleanup_running=1
      begin_api_stop || { api_cleanup_poisoned=1; exit 70; }
      api_stop_progress stop || { api_cleanup_poisoned=1; exit 70; }
      finish_api_terminal || { api_cleanup_poisoned=1; exit 70; }
      api_report 'G7_QUIESCE=complete' || exit 70
      exit 0
    fi
    (( ! shutdown_requested )) || break
    if (( ! ${quiesce_recoverable:-0} )); then api_cleanup_poisoned=1; fi
    quiesce_failed_latched=1
    api_phase_marker quiesce-failed || api_cleanup_poisoned=1
    api_broker_control latch-quiesce || :
    api_report 'G7_QUIESCE=failed-latched' >&2
    if ! api_broker_control quiesce-surviving; then
      child_status=70
      break
    fi
  fi
  (( ! shutdown_requested )) || break
  sleep .1 || :
done
api_remove_ready || { api_cleanup_poisoned=1; shutdown_status=1; }
if (( shutdown_requested )); then
  trap - TERM INT
  cleanup_running=1
  UVM_G7_QUIESCE_NO_KILL=0 stop_all || shutdown_status=1
  (( ! wait_bookkeeping_failed )) || shutdown_status=1
  if (( shutdown_status )); then api_cleanup_poisoned=1; fi
  finish_api_terminal || shutdown_status=1
  api_report "G7_SHUTDOWN=controlled service_cleanup_status=$shutdown_status" || shutdown_status=1
  (( ! api_cleanup_poisoned )) || shutdown_status=1
  exit "$shutdown_status"
fi
if [[ ! -e "$STATE/critical-failed" ]]; then
  api_cleanup_poisoned=1
  api_phase_marker critical-failed || shutdown_status=1
fi
api_report "G7_CRITICAL_CHILD_EXITED status=$child_status" >&2
for child_index in "${!CHILD_PIDS[@]}"; do
  if [[ ${CHILD_PIDS[$child_index]} == "${exited_child_pid:-}" && ${CHILD_NAMES[$child_index]} == api-broker ]]; then
    api_broker_control orphan-cleanup || shutdown_status=1
  fi
done
for child_index in "${!CHILD_PIDS[@]}"; do
  if [[ ${CHILD_PIDS[$child_index]} == "${exited_child_pid:-}" &&
        ${CHILD_NAMES[$child_index]} == ce-beat ]]; then
    api_report 'G7_CE_BEAT_FAILURE_LOG_BEGIN' >&2
    tail -n 80 "$STATE/ce-beat.log" | sed -E \
      's/((password|token|secret)([=: ]+))[^[:space:]]+/\1[REDACTED]/Ig' >&2
    api_report 'G7_CE_BEAT_FAILURE_LOG_END' >&2
  fi
done
trap - TERM INT
cleanup_running=1
api_cleanup_poisoned=1
UVM_G7_QUIESCE_NO_KILL=0 stop_all || shutdown_status=1
finish_api_terminal || shutdown_status=1
trap - EXIT
if (( shutdown_status )); then
  api_report 'G7_SHUTDOWN=failed_after_critical_exit' >&2
  exit 71
fi
if (( shutdown_requested )); then
  api_report 'G7_SHUTDOWN=controlled'
  exit 0
fi
exit 70
