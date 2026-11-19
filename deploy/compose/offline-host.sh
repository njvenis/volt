#!/bin/sh
# Authenticated package functions; sourced only after caller admission.
# No standalone action, verifier selection or authority flag exists here.

offline_data() {
  stdin_flag=''; [ "$1" != filter-shutdown ] || stdin_flag=-i
  docker run --platform "$PLATFORM" --pull=never --rm $stdin_flag --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$OFFLINE_OUTPUT,dst=/run/volt-offline-output,readonly" \
    --mount "type=bind,src=$OFFLINE_OBSERVATION,dst=/run/volt-offline-observation,readonly" \
    --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly" \
    --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.offline_lifecycle "$@"
}

offline_capture_shutdown() {
  started=$(offline_data queried-started-at) || fail 'actual StartedAt could not be decoded from saved inspection'
  fifo="$WORK/shutdown-log-stream"
  mkfifo "$fifo" || fail 'private bounded log stream could not be created'
  docker logs --tail 256 --since "$started" "${PROJECT}-volt-1" >"$fifo" 2>&1 &
  producer=$!
  if offline_data filter-shutdown --started-at "$started" <"$fifo" >"$OFFLINE_OBSERVATION/shutdown-evidence.json"; then
    filter_status=0
  else
    filter_status=$?
    kill "$producer" 2>/dev/null || :
  fi
  if wait "$producer"; then producer_status=0; else producer_status=$?; fi
  rm "$fifo"
  chmod 600 "$OFFLINE_OBSERVATION/shutdown-evidence.json"
  printf 'offline_shutdown_query_started_at=%s\noffline_shutdown_producer_exit=%s\noffline_shutdown_filter_exit=%s\n' \
    "$started" "$producer_status" "$filter_status"
  [ "$producer_status" -eq 0 ] && [ "$filter_status" -eq 0 ] \
    || fail 'bounded current-run shutdown evidence failed; Docker producer status was preserved'
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

offline_observe() {
  phase=$1
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
  if [ "$ACTION" = backup-record ]; then
    offline_capture_shutdown
  fi
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
  offline_data emit-observation --phase "$phase" >"$OFFLINE_INPUT/.next-phase" || fail 'closed offline observation emission failed'
  chmod 600 "$OFFLINE_INPUT/.next-phase"
  mv "$OFFLINE_INPUT/.next-phase" "$OFFLINE_INPUT/$phase.json"
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
  docker logs "$LOCK_NAME" || fail 'offline owner completion evidence is unavailable'
  printf 'offline_operation=%s\nstatus=complete\n' "$ACTION"
}

