#!/bin/bash
set -Eeuo pipefail
umask 077

STATE=/run/uvm-g7
CHILD_PIDS=()
CHILD_NAMES=()
SERVICE_PIDS=()
shutdown_requested=0
quiesce_requested=0
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
rm -f "$STATE/ready" "$STATE/critical-failed" "$STATE"/pid-*

handle_shutdown() { shutdown_requested=1; }
handle_quiesce() { quiesce_requested=1; }
cleanup_on_exit() {
  local original_status=$? cleanup_status=0
  trap - EXIT TERM INT
  if (( services_started && ! cleanup_running )); then
    cleanup_running=1
    stop_all || cleanup_status=$?
    echo "G7_STARTUP_CLEANUP=complete original_status=$original_status cleanup_status=$cleanup_status" >&2
    if (( original_status == 0 && cleanup_status != 0 )); then original_status=71; fi
  fi
  exit "$original_status"
}
trap cleanup_on_exit EXIT
trap handle_shutdown TERM INT
trap handle_quiesce USR1
printf '%s\n' "$$" >"$STATE/entrypoint-pid"

abort_if_shutdown() {
  if (( shutdown_requested )); then
    echo 'G7_STARTUP_INTERRUPTED phase=service-startup' >&2
    return 143
  fi
}

stop_phase() {
  local phase=$1 pid name status=0
  shift
  local -a selected=() selected_names=()
  for name in "$@"; do
    for i in "${!CHILD_NAMES[@]}"; do
      if [[ ${CHILD_NAMES[$i]} == "$name" ]]; then
        selected+=("${CHILD_PIDS[$i]}")
        selected_names+=("$name")
      fi
    done
  done
  for i in "${!selected[@]}"; do
    pid=${selected[$i]}
    if kill -0 "$pid" 2>/dev/null; then
      if [[ ${selected_names[$i]} == ce-web && -p /run/uwsgi/uvm-g7.fifo ]]; then
        printf q >/run/uwsgi/uvm-g7.fifo || { echo "G7_STOP_ERROR phase=$phase action=uwsgi-fifo name=ce-web" >&2; status=1; }
      else
        kill -TERM "$pid" || { echo "G7_STOP_ERROR phase=$phase action=term name=${selected_names[$i]} pid=$pid" >&2; status=1; }
      fi
    fi
  done
  for i in "${!selected[@]}"; do
    pid=${selected[$i]}
    local stopped=0 timed_out=0
    for attempt in $(seq 1 300); do
      if ! kill -0 "$pid" 2>/dev/null; then stopped=1; break; fi
      sleep 0.1
    done
    if (( ! stopped )); then
      echo "G7_STOP_ERROR phase=$phase action=timeout name=${selected_names[$i]} pid=$pid" >&2
      if [[ ${UVM_G7_QUIESCE_NO_KILL:-0} != 1 ]]; then
        kill -KILL -- "-$pid" 2>/dev/null || :
      else
        timed_out=1
      fi
      status=1
    fi
    if (( timed_out )); then continue; fi
    if wait "$pid"; then :; else
      rc=$?
      if (( rc != 143 && rc != 0 && rc != 127 )); then
        echo "G7_STOP_ERROR phase=$phase action=wait name=${selected_names[$i]} pid=$pid status=$rc" >&2
        status=1
      fi
    fi
    if [[ ${UVM_G7_QUIESCE_NO_KILL:-0} == 1 ]]; then
      group_processes=$(ps -eo pgid= | awk -v pgid="$pid" '$1 == pgid { count++ } END { print count+0 }')
      if [[ $group_processes != 0 ]]; then
        echo "G7_STOP_ERROR phase=$phase action=process-group-remains name=${selected_names[$i]}" >&2
        status=1
      fi
    fi
    echo "G7_STOP_CHILD_STOPPED phase=$phase name=${selected_names[$i]}"
  done
  echo "G7_STOP_PHASE=$phase status=$status"
  return "$status"
}
stop_all() {
  local status=0
  rm -f "$STATE/ready"
  stop_phase writers oidc-sync-api recovery-control api oidc-provider ce-web || status=1
  stop_phase workers exception-warning-worker ce-beat ce-worker || status=1
  if [[ -s /run/valkey/valkey.pid ]]; then
    valkey-cli -h 127.0.0.1 shutdown nosave >/dev/null 2>&1 || { echo 'G7_STOP_ERROR service=valkey' >&2; status=1; }
  fi
  if setpriv --reuid=postgres --regid=postgres --init-groups \
      /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
    setpriv --reuid=postgres --regid=postgres --init-groups \
      /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null 2>&1 || { echo 'G7_STOP_ERROR service=postgresql' >&2; status=1; }
    echo 'G7_STOP_DATABASE_STOPPED service=postgresql'
  fi
  if [[ ${UVM_G7_TEST_FAULT:-} == cleanup-fail-after-broker ]]; then
    echo 'G7_STOP_ERROR injected=cleanup-fail-after-broker' >&2
    status=1
  fi
  echo "G7_STOP_PHASE=databases status=$status"
  return "$status"
}

staged_quiesce() {
  local status=0 acknowledged=0
  rm -f "$STATE/ready"
  # Stop periodic producers before admission surfaces and side-effect dispatch.
  stop_phase quiesce-producers oidc-sync-api ce-beat || status=1
  stop_phase quiesce-admission recovery-control api oidc-provider ce-web || status=1
  stop_phase quiesce-effects exception-warning-worker || status=1
  if (( status )); then return 1; fi
  touch "$STATE/quiesce-writers-stopped"
  echo 'G7_QUIESCE=writers-stopped'
  for attempt in $(seq 1 "${UVM_G7_QUIESCE_TIMEOUT_SECONDS:-300}"); do
    if [[ -e "$STATE/quiesce-drain-complete" ]]; then acknowledged=1; break; fi
    if (( shutdown_requested )); then break; fi
    sleep 1
  done
  if (( ! acknowledged )); then
    echo 'G7_QUIESCE_ERROR=drain-not-acknowledged' >&2
    return 1
  fi
  stop_phase quiesce-consumers ce-worker || status=1
  [[ -s /run/valkey/valkey.pid ]] && {
    valkey-cli -h 127.0.0.1 shutdown nosave >/dev/null 2>&1 || status=1
    echo 'G7_STOP_DATABASE_STOPPED service=valkey'
  }
  if setpriv --reuid=postgres --regid=postgres --init-groups \
      /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
    setpriv --reuid=postgres --regid=postgres --init-groups \
      /usr/lib/postgresql/18/bin/pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null 2>&1 || status=1
    echo 'G7_STOP_DATABASE_STOPPED service=postgresql'
  fi
  (( status == 0 )) || return 1
  touch "$STATE/quiesce-services-stopped"
  echo 'G7_QUIESCE=services-stopped'
  for attempt in $(seq 1 "${UVM_G7_QUIESCE_TIMEOUT_SECONDS:-300}"); do
    [[ -e "$STATE/quiesce-capture-release" ]] && return 0
    (( shutdown_requested )) && break
    sleep 1
  done
  echo 'G7_QUIESCE_ERROR=capture-release-not-received' >&2
  return 1
}

secret() {
  local name=$1 path="/run/secrets/$1"
  [[ -s "$path" ]] || { echo "required secret file is absent: $path" >&2; exit 70; }
  cat "$path"
}
if [[ -n ${UVM_GITHUB_TOKEN_FILE:-} ]]; then
  [[ -f "$UVM_GITHUB_TOKEN_FILE" ]] || { echo 'configured GitHub token file is absent' >&2; exit 70; }
  install -d -o uvm -g uvm -m 0700 /run/uvm-github
  install -o uvm -g uvm -m 0600 "$UVM_GITHUB_TOKEN_FILE" /run/uvm-github/token
  UVM_GITHUB_TOKEN_FILE=/run/uvm-github/token
  export UVM_GITHUB_TOKEN_FILE
fi
if [[ -n ${UVM_CONNECTOR_LOCAL_KEY_FILE:-} ]]; then
  [[ -f "$UVM_CONNECTOR_LOCAL_KEY_FILE" ]] || { echo 'configured connector local key file is absent' >&2; exit 70; }
  install -d -o uvm -g uvm -m 0700 /run/uvm-connector
  install -o uvm -g uvm -m 0600 "$UVM_CONNECTOR_LOCAL_KEY_FILE" /run/uvm-connector/local-key
  UVM_CONNECTOR_LOCAL_KEY_FILE=/run/uvm-connector/local-key
  export UVM_CONNECTOR_LOCAL_KEY_FILE
fi
urlpart() { python -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().rstrip("\n"), safe=""))'; }
UVM_PASSWORD=$(secret uvm_db_password)
CE_PASSWORD=$(secret ce_db_password)
DD_ADMIN_PASSWORD=$(secret ce_admin_password)
DD_SECRET_KEY=$(secret ce_secret_key)
DD_CREDENTIAL_AES_256_KEY=$(secret ce_credential_key)
UVM_API_CURSOR_SECRET=$(secret uvm_cursor_secret)
export DD_ADMIN_PASSWORD DD_SECRET_KEY DD_CREDENTIAL_AES_256_KEY UVM_API_CURSOR_SECRET
if [[ -s /run/secrets/github_preview_secret ]]; then
  UVM_GITHUB_PREVIEW_SECRET=$(secret github_preview_secret)
  export UVM_GITHUB_PREVIEW_SECRET
fi

oidc_config_value() {
  local field=$1
  UVM_OIDC_CONFIG="$UVM_OIDC_CONFIG" python -c 'import json,os,sys; print(json.loads(os.environ["UVM_OIDC_CONFIG"])[sys.argv[1]])' "$field"
}
if [[ ${UVM_AUTH_MODE:-bearer} == oidc ]]; then
  [[ -n ${UVM_OIDC_CONFIG:-} ]] || { echo 'G7_OIDC_CONFIG=missing' >&2; exit 70; }
  install -d -o root -g uvm -m 0750 /run/uvm-g7-secrets
  for pair in 'oidc_client_secret:client_secret_file' 'oidc_sync_secret:sync_secret_file' 'oidc_operator_secret:operator_secret_file'; do
    source_name=${pair%%:*}
    config_name=${pair#*:}
    target=$(oidc_config_value "$config_name")
    case "$target" in /run/uvm-g7-secrets/*) ;; *) echo 'G7_OIDC_SECRET_REFERENCE=invalid' >&2; exit 70 ;; esac
    install -o root -g uvm -m 0640 "/run/secrets/$source_name" "$target"
  done
  if [[ -f /run/secrets/github_webhook_secret_v1 && -f /run/secrets/github_webhook_secret_v2 ]]; then
    install -o uvm -g uvm -m 0600 /run/secrets/github_webhook_secret_v1 /run/uvm-g7-secrets/github_webhook_secret_v1
    install -o uvm -g uvm -m 0600 /run/secrets/github_webhook_secret_v2 /run/uvm-g7-secrets/github_webhook_secret_v2
    install -o root -g uvm -m 0640 /run/secrets/github_webhook_secret_version /run/uvm-g7-secrets/github_webhook_secret_version
  fi
  install -d -o uvm -g uvm -m 0700 /opt/uvm/state
  OIDC_PROVIDER_KEY=/opt/uvm/state/oidc-provider-private.pem
  if [[ ! -s "$OIDC_PROVIDER_KEY" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OIDC_PROVIDER_KEY" 2>/dev/null
    chown uvm:uvm "$OIDC_PROVIDER_KEY"
    chmod 0600 "$OIDC_PROVIDER_KEY"
  fi
  UVM_OIDC_ISSUER=$(oidc_config_value issuer)
  UVM_OIDC_CLIENT_ID=$(oidc_config_value client_id)
  UVM_OIDC_CALLBACK_URL=$(oidc_config_value callback_url)
  UVM_OIDC_PROVIDER_ID=$(oidc_config_value provider_id)
  UVM_OIDC_CLIENT_SECRET_FILE=$(oidc_config_value client_secret_file)
  UVM_OIDC_SYNC_SECRET_FILE=$(oidc_config_value sync_secret_file)
  UVM_OIDC_OPERATOR_SECRET_FILE=$(oidc_config_value operator_secret_file)
  UVM_OIDC_FIXTURE_SUBJECT=${UVM_OIDC_FIXTURE_SUBJECT:?synthetic subject fixture is required}
  UVM_OIDC_FIXTURE_IDENTITIES=${UVM_OIDC_FIXTURE_IDENTITIES:?synthetic identity fixture is required}
fi
UVM_PASSWORD_URL=$(printf %s "$UVM_PASSWORD" | urlpart)
CE_PASSWORD_URL=$(printf %s "$CE_PASSWORD" | urlpart)
export UVM_DB_URL="postgresql+psycopg://uvm_app:${UVM_PASSWORD_URL}@127.0.0.1:5432/uvm"
export DD_DATABASE_URL="postgresql://ce_app:${CE_PASSWORD_URL}@127.0.0.1:5432/defectdojo"
install -d -o root -g uvm -m 0750 /run/uvm-g7-secrets
install -o root -g uvm -m 0640 /run/secrets/uvm_db_password /run/uvm-g7-secrets/uvm_db_password
for recovery_material in recovery-server.crt recovery-server.key recovery-ca.crt; do
  [[ -s "/run/secrets/$recovery_material" ]] || { echo "recovery TLS material is missing: $recovery_material" >&2; exit 70; }
done
install -o root -g uvm -m 0640 /run/secrets/recovery-server.crt /run/uvm-g7-secrets/recovery-server.crt
install -o root -g uvm -m 0640 /run/secrets/recovery-server.key /run/uvm-g7-secrets/recovery-server.key
install -o root -g uvm -m 0640 /run/secrets/recovery-ca.crt /run/uvm-g7-secrets/recovery-ca.crt
if [[ -n ${UVM_EXCEPTION_WARNING_DESTINATIONS:-} ]]; then
  install -d -o root -g uvm -m 0750 /run/uvm-g7-secrets/exception-warning
  while IFS= read -r secret_name; do
    [[ -z "$secret_name" ]] && continue
    [[ "$secret_name" =~ ^[A-Za-z0-9_.-]{1,100}$ ]] || { echo 'exception warning secret reference is invalid' >&2; exit 70; }
    if [[ -f "/run/secrets/$secret_name" ]]; then
      install -o root -g uvm -m 0640 "/run/secrets/$secret_name" "/run/uvm-g7-secrets/exception-warning/$secret_name"
    fi
  done < <(UVM_EXCEPTION_WARNING_DESTINATIONS="$UVM_EXCEPTION_WARNING_DESTINATIONS" python -c 'import json,os,re; d=json.loads(os.environ["UVM_EXCEPTION_WARNING_DESTINATIONS"]); print("\n".join(sorted({v["secret_ref"][7:] for v in d.values() if isinstance(v,dict) and isinstance(v.get("secret_ref"),str) and v["secret_ref"].startswith("secret:")})))')
fi

if [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 && ! -s "$PGDATA/PG_VERSION" ]]; then
  echo 'G7_RECOVERY_ERROR verification target has no restored PostgreSQL cluster' >&2
  exit 70
fi
if [[ ! -s "$PGDATA/PG_VERSION" ]]; then
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
  for attempt in $(seq 1 90); do
    if (( shutdown_requested )); then
      echo "G7_STARTUP_INTERRUPTED label=$label" >&2
      return 143
    fi
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "timed out waiting for $label" >&2; return 70
}
wait_for postgresql pg_isready -h 127.0.0.1 -p 5432 -U postgres
wait_for valkey valkey-cli -h 127.0.0.1 ping
abort_if_shutdown
case ${UVM_G7_TEST_FAULT:-} in
  startup-fail-after-broker)
    echo 'G7_TEST_FAULT=startup-fail-after-broker' >&2
    exit 77
    ;;
  term-pause-after-broker)
    touch "$STATE/startup-paused"
    echo 'G7_TEST_FAULT=term-pause-after-broker' >&2
    while (( ! shutdown_requested )); do sleep 0.2; done
    abort_if_shutdown
    ;;
  cleanup-fail-after-broker)
    echo 'G7_TEST_FAULT=cleanup-fail-after-broker' >&2
    exit 0
    ;;
esac

psql_local() { setpriv --reuid=postgres --regid=postgres --init-groups psql -X -v ON_ERROR_STOP=1 -h /var/run/postgresql "$@"; }
G7_SCHEMA_MODE=${UVM_G7_SCHEMA_MODE:-normal}
G7_SCHEMA_DECLARED_HEAD=$(cat /etc/uvm-g7-schema-head)
G7_SCHEMA_COMPAT_ADMITTED=0
if [[ $G7_SCHEMA_MODE == upgrade-verification ]]; then
  [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 && ${UVM_G7_RECOVERY_STAGE:-} == control-only ]] || {
    echo 'G7_SCHEMA_COMPATIBILITY_REJECTED reason=upgrade-mode-requires-control-only' >&2; exit 70;
  }
  PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence --check-schema-admission
  G7_SCHEMA_COMPAT_ADMITTED=1
fi
if (( PG_CLUSTER_INITIALIZED )); then
  G7_SCHEMA_HEADS='[]'
else
  if [[ $(psql_local -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname='uvm'") == 1 ]]; then
    G7_SCHEMA_QUERY=$(psql_local -d uvm -Atc "SELECT CASE WHEN to_regclass('public.alembic_version') IS NULL THEN '__MISSING__' ELSE COALESCE((SELECT json_agg(version_num ORDER BY version_num)::text FROM alembic_version), '[]') END")
    [[ $G7_SCHEMA_QUERY != __MISSING__ ]] || { echo 'G7_SCHEMA_COMPATIBILITY_REJECTED reason=missing-version-table' >&2; exit 70; }
    G7_SCHEMA_HEADS=$G7_SCHEMA_QUERY
  else
    echo 'G7_SCHEMA_COMPATIBILITY_REJECTED reason=existing-cluster-missing-uvm-database' >&2; exit 70
  fi
fi
/opt/uvm/venv/bin/python -m uvm.operations.schema_compatibility \
  --declared-head "$G7_SCHEMA_DECLARED_HEAD" --mode "$G7_SCHEMA_MODE" \
  --heads-json "$G7_SCHEMA_HEADS" \
  $([[ ${PG_CLUSTER_INITIALIZED:-0} == 1 ]] && printf '%s' --empty-cluster) \
  $([[ $G7_SCHEMA_COMPAT_ADMITTED == 1 ]] && printf '%s' --compatibility-admitted)
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
echo 'G7_INIT=CE initialize'
setpriv --reuid=1001 --regid=1337 --init-groups env -i PATH="$PATH" HOME=/nonexistent \
  DD_DATABASE_URL="$DD_DATABASE_URL" DD_SECRET_KEY="$DD_SECRET_KEY" \
  DD_CREDENTIAL_AES_256_KEY="$DD_CREDENTIAL_AES_256_KEY" DD_ADMIN_PASSWORD="$DD_ADMIN_PASSWORD" \
  DD_ADMIN_USER="${DD_ADMIN_USER:-admin}" DD_ADMIN_MAIL="${DD_ADMIN_MAIL:-admin@defectdojo.local}" \
  DD_ADMIN_FIRST_NAME="${DD_ADMIN_FIRST_NAME:-Synthetic}" DD_ADMIN_LAST_NAME="${DD_ADMIN_LAST_NAME:-Operator}" \
  DD_ALLOWED_HOSTS="${DD_ALLOWED_HOSTS:-*}" DD_INITIALIZE=true \
  /entrypoint-initializer.sh /bin/true
abort_if_shutdown
fi
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_G7_RECOVERY_STAGE:-} != released ]]; then
echo 'G7_INIT=UVM migrations'
setpriv --reuid=uvm --regid=uvm --init-groups env -i PATH="$PATH" HOME=/opt/uvm \
  PYTHONPATH=/opt/uvm/app UVM_DB_URL="$UVM_DB_URL" \
  sh -c 'cd /opt/uvm/app && exec python -m alembic -c alembic.ini upgrade head'
abort_if_shutdown
fi

start_child() {
  local name=$1 uid=$2 gid=$3; shift 3
  setsid setpriv --reuid="$uid" --regid="$gid" --init-groups "$@" \
    >>"$STATE/$name.log" 2>&1 &
  local pid=$!
  printf '%s\n' "$pid" >"$STATE/pid-$name"
  CHILD_PIDS+=("$pid")
  CHILD_NAMES+=("$name")
}
start_recovery_control() {
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
    UVM_AUTH_MODE=bearer python -m uvicorn uvm.api.app:app --host 0.0.0.0 \
      --port "${UVM_G7_RECOVERY_CONTROL_PORT:-8002}" --workers 1 --no-proxy-headers \
      --ssl-certfile "$RECOVERY_TLS_DIR/server.crt" \
      --ssl-keyfile "$RECOVERY_TLS_DIR/server.key" \
      --ssl-ca-certs "$RECOVERY_TLS_DIR/client-ca.crt" --ssl-cert-reqs 2
}

if [[ ${UVM_G7_RECOVERY_STAGE:-} == control-only || ${UVM_G7_RECOVERY_STAGE:-} == released ]]; then
  [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 || ${UVM_G7_RECOVERY_STAGE:-} == released ]] || { echo 'G7_RECOVERY_ERROR control-only requires verification-only mode' >&2; exit 70; }
  case ${UVM_AUTH_MODE:-bearer} in
    bearer|oidc) ;;
    *) echo 'G7_RECOVERY_ERROR verification-only product API requires bearer or restored OIDC session authentication' >&2; exit 70 ;;
  esac
  : "${UVM_G7_STARTUP_FENCE_TOKEN:?signed startup-fence token is required}"
  : "${UVM_G7_HOST_PUBLIC_KEY_FILE:?host verification key is required}"
  : "${UVM_G7_DEPLOYMENT_ID:?deployment identity is required}"
  : "${UVM_G7_TARGET_IMAGE_DIGEST:?target image digest is required}"
  : "${UVM_G7_RECOVERY_VOLUME_IDS:?replacement volume identities are required}"
  : "${UVM_G7_ARCHIVE_DIGEST:?verified archive digest is required}"
  : "${UVM_G7_RECOVERY_EPOCH:?recovery epoch is required}"
  : "${UVM_G7_CONNECTOR_RECOVERY_ID:?connector recovery UUID is required}"
  [[ $UVM_G7_DEPLOYMENT_ID =~ ^[A-Za-z0-9._-]{1,128}$ ]] || { echo 'G7_RECOVERY_ERROR deployment identity is invalid' >&2; exit 70; }
  PYTHONPATH=/opt/uvm/app python -m uvm.operations.startup_fence
fi

if [[ ${UVM_G7_RECOVERY_STAGE:-} == released ]]; then
  PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence --check-host-release || {
    echo 'G7_RECOVERY_ERROR released startup lacks its signed durable admission' >&2; exit 70;
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
  printf '%s\n' control >"$STATE/runtime-mode"
  touch "$STATE/ready"
  echo 'G7_READINESS=recovery-control-only'
  # The host performs authenticated resync and quarantine while this is the
  # only application listener. Product APIs and CE stay stopped until the
  # signed restored transition and the admitted migration head are durable.
  for attempt in $(seq 1 "${UVM_G7_RECOVERY_GATE_TIMEOUT_SECONDS:-1800}"); do
    if PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence \
        --check-admission >"$STATE/recovery-gate.json" 2>"$STATE/recovery-gate-query.stderr"; then
      recovery_state=restored
      break
    fi
    abort_if_shutdown
    sleep 1
  done
  [[ ${recovery_state:-} == restored ]] || {
    echo 'G7_RECOVERY_ERROR host did not admit volumes_restored transition' >&2
    [[ ! -s "$STATE/recovery-gate-query.stderr" ]] || sed -n '1,5p' "$STATE/recovery-gate-query.stderr" >&2
    exit 70
  }
  if [[ -n ${UVM_G7_SCHEMA_MODE:-} && ${UVM_G7_SCHEMA_MODE} == upgrade-verification ]]; then
    schema_ready=0
    for attempt in $(seq 1 "${UVM_G7_RECOVERY_GATE_TIMEOUT_SECONDS:-1800}"); do
      if PYTHONPATH=/opt/uvm/app /opt/uvm/venv/bin/python -m uvm.operations.startup_fence \
          --check-schema-complete >"$STATE/schema-migration-gate.json" 2>"$STATE/schema-migration-gate-query.stderr"; then
        schema_ready=1
        break
      fi
      abort_if_shutdown
      sleep 1
    done
    (( schema_ready == 1 )) || {
      echo 'G7_RECOVERY_ERROR admitted migration head was not complete' >&2
      [[ ! -s "$STATE/schema-migration-gate-query.stderr" ]] || sed -n '1,5p' "$STATE/schema-migration-gate-query.stderr" >&2
      exit 70
    }
  fi
  recovery_control_gate_passed=1
  rm -f "$STATE/ready"
fi

start_ce_web() {
start_child ce-web 1001 1337 env -i PATH="$PATH" HOME=/nonexistent \
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
start_child ce-worker 1001 1337 env -i PATH="$PATH" HOME=/nonexistent \
  DD_DATABASE_URL="$DD_DATABASE_URL" DD_SECRET_KEY="$DD_SECRET_KEY" \
  DD_CREDENTIAL_AES_256_KEY="$DD_CREDENTIAL_AES_256_KEY" \
  DD_CELERY_BROKER_URL="$DD_CELERY_BROKER_URL" DD_CACHE_URL="$DD_CACHE_URL" \
  DD_DATABASE_HOST=127.0.0.1 DD_DATABASE_PORT=5432 DD_MEDIA_ROOT=/app/media \
  DD_CELERY_LOG_LEVEL=INFO DD_CELERY_WORKER_POOL_TYPE=solo \
  DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Generic Findings Import":"unique_id_from_tool"}' \
  /entrypoint-celery-worker.sh
start_child ce-beat 1001 1337 env -i PATH="$PATH" HOME=/nonexistent \
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
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} != 1 && ${UVM_AUTH_MODE:-bearer} == oidc ]]; then
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
start_child api 1800 1800 env -i PATH="$PATH" HOME=/opt/uvm \
  UVM_G7_VERIFICATION_ONLY="${UVM_G7_VERIFICATION_ONLY-0}" \
  UVM_G7_CONNECTOR_RECOVERY_ID="${UVM_G7_CONNECTOR_RECOVERY_ID-}" \
  UVM_API_READ_SNAPSHOT_DIR="$READ_SNAPSHOT_DIR" \
  PYTHONPATH=/opt/uvm/app \
  UVM_DB_URL="$UVM_DB_URL" UVM_API_CURSOR_SECRET="$UVM_API_CURSOR_SECRET" \
  UVM_API_PRINCIPALS="${UVM_API_PRINCIPALS-}" \
  UVM_G3_BOOTSTRAP_PRINCIPAL="${UVM_G3_BOOTSTRAP_PRINCIPAL-}" \
  UVM_NATIVE_BOOTSTRAP_PRINCIPALS="${UVM_NATIVE_BOOTSTRAP_PRINCIPALS-}" \
  UVM_NATIVE_GRANTABLE_ENVELOPE="${UVM_NATIVE_GRANTABLE_ENVELOPE-}" \
  UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE="${UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE-}" \
  UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS="${UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS-}" \
  UVM_G7_HOST_KEY_ID="${UVM_G7_HOST_KEY_ID-}" \
  UVM_G7_CONTROLLER_INSTANCE_ID="${UVM_G7_CONTROLLER_INSTANCE_ID-}" \
  UVM_G7_RECOVERY_TLS_CERT_FILE="${UVM_G7_RECOVERY_TLS_CERT_FILE-}" \
  UVM_G7_RECOVERY_TLS_KEY_FILE="${UVM_G7_RECOVERY_TLS_KEY_FILE-}" \
  UVM_G7_RECOVERY_TLS_CA_FILE="${UVM_G7_RECOVERY_TLS_CA_FILE-}" \
  UVM_G7_SOURCE_ADAPTER_PRINCIPAL="${UVM_G7_SOURCE_ADAPTER_PRINCIPAL-}" \
  UVM_G7_DEPLOYMENT_ID="${UVM_G7_DEPLOYMENT_ID-}" \
  UVM_G7_RECOVERY_EPOCH="${UVM_G7_RECOVERY_EPOCH-}" \
  UVM_G7_STORAGE_GENERATION="${UVM_G7_STORAGE_GENERATION-}" \
  UVM_G7_VOLUME_SET_DIGEST="${UVM_G7_VOLUME_SET_DIGEST-}" \
  UVM_G7_PRESERVATION_PUBLIC_KEY_FILE="${UVM_G7_PRESERVATION_PUBLIC_KEY_FILE-}" \
  UVM_G7_PRESERVATION_KEY_ID="${UVM_G7_PRESERVATION_KEY_ID-}" \
  UVM_G7_PRESERVATION_REPORT_DIR="${UVM_G7_PRESERVATION_REPORT_DIR-}" \
  UVM_G7_PRESERVATION_TRUST_DIR="${UVM_G7_PRESERVATION_TRUST_DIR-}" \
  UVM_G7_PRESERVATION_ENVIRONMENT="${UVM_G7_PRESERVATION_ENVIRONMENT-}" \
  UVM_G7_PRESERVATION_MAX_FUTURE_SKEW_SECONDS="${UVM_G7_PRESERVATION_MAX_FUTURE_SKEW_SECONDS-}" \
  UVM_AUTH_MODE="${UVM_AUTH_MODE-bearer}" UVM_OIDC_CONFIG="${UVM_OIDC_CONFIG-}" \
  UVM_GITHUB_API_BASE_URL="${UVM_GITHUB_API_BASE_URL-}" \
  UVM_GITHUB_APP_BASE_URL="${UVM_GITHUB_APP_BASE_URL-}" \
  UVM_CONNECTOR_PUBLIC_BASE_URL="${UVM_CONNECTOR_PUBLIC_BASE_URL-}" \
  UVM_GITHUB_PREVIEW_SECRET="${UVM_GITHUB_PREVIEW_SECRET-}" \
  UVM_GITHUB_TOKEN_FILE="${UVM_GITHUB_TOKEN_FILE-}" UVM_G7_DISPOSABLE_MODE="${UVM_G7_DISPOSABLE_MODE-}" \
  UVM_G7_TEST_CLOCK_FILE="${UVM_G7_TEST_CLOCK_FILE-}" \
  UVM_GITHUB_POLL_INTERVAL_SECONDS="${UVM_GITHUB_POLL_INTERVAL_SECONDS:-86400}" \
  UVM_GITHUB_POLL_PRINCIPAL="${UVM_GITHUB_POLL_PRINCIPAL-}" \
  UVM_GITHUB_POLL_COMPLETION_MARKER="${UVM_GITHUB_POLL_COMPLETION_MARKER-}" \
  UVM_GITHUB_WEBHOOK_PRINCIPAL="${UVM_GITHUB_WEBHOOK_PRINCIPAL-}" \
  UVM_GITHUB_WEBHOOK_SECRET_DIR="${UVM_GITHUB_WEBHOOK_SECRET_DIR-}" \
  UVM_GITHUB_WEBHOOK_SECRET_VERSION_FILE="${UVM_GITHUB_WEBHOOK_SECRET_VERSION_FILE-}" \
  UVM_GITHUB_WEBHOOK_CRASH_AFTER_COMMAND_COMMIT="${UVM_GITHUB_WEBHOOK_CRASH_AFTER_COMMAND_COMMIT-}" \
  UVM_CONNECTOR_FIXTURE_ID="${UVM_CONNECTOR_FIXTURE_ID-}" \
  UVM_CONNECTOR_FIXTURE_SOURCE_ID="${UVM_CONNECTOR_FIXTURE_SOURCE_ID-}" \
  UVM_CONNECTOR_FIXTURE_SOURCE_FAMILY="${UVM_CONNECTOR_FIXTURE_SOURCE_FAMILY-}" \
  UVM_CONNECTOR_FIXTURE_SOURCE_ACCOUNT_ID="${UVM_CONNECTOR_FIXTURE_SOURCE_ACCOUNT_ID-}" \
  UVM_CONNECTOR_FIXTURE_SCOPE_KEY="${UVM_CONNECTOR_FIXTURE_SCOPE_KEY-}" \
  UVM_CONNECTOR_ENVIRONMENT_LABEL="${UVM_CONNECTOR_ENVIRONMENT_LABEL-}" \
  UVM_CONNECTOR_LOCAL_KEY_FILE="${UVM_CONNECTOR_LOCAL_KEY_FILE-}" \
  UVM_CONNECTOR_LOCAL_KEY_ID="${UVM_CONNECTOR_LOCAL_KEY_ID-}" \
  UVM_CONNECTOR_RECOVERY_EPOCH_FILE="${UVM_CONNECTOR_RECOVERY_EPOCH_FILE-}" \
  UVM_CONNECTOR_ISSUER_LEDGER_FILE="${UVM_CONNECTOR_ISSUER_LEDGER_FILE-}" \
  UVM_CONNECTOR_ISSUER_KEY_FILE="${UVM_CONNECTOR_ISSUER_KEY_FILE-}" \
  UVM_CONNECTOR_OPERATOR_CLEARANCE_FILE="${UVM_CONNECTOR_OPERATOR_CLEARANCE_FILE-}" \
  UVM_CONNECTOR_OPERATOR_KEY_FILE="${UVM_CONNECTOR_OPERATOR_KEY_FILE-}" \
  UVM_CONNECTOR_TEST_SUBMISSION_PAUSE_DIR="${UVM_CONNECTOR_TEST_SUBMISSION_PAUSE_DIR-}" \
  UVM_EXCEPTION_WARNING_INSTALLATION_ID="${UVM_EXCEPTION_WARNING_INSTALLATION_ID-}" \
  UVM_EXCEPTION_WARNING_SIGNING_SECRET_FILE="${UVM_EXCEPTION_WARNING_SIGNING_SECRET_FILE-}" \
  UVM_INGRESS_ALLOWED_PEER_CIDRS="${UVM_INGRESS_ALLOWED_PEER_CIDRS-}" \
  UVM_INGRESS_ALLOWED_HOSTS="${UVM_INGRESS_ALLOWED_HOSTS-}" \
  UVM_UI_ROOT=/opt/uvm/ui \
  UVM_API_HOST="$UVM_API_HOST" UVM_API_PORT="$UVM_API_PORT" \
  python -m uvicorn uvm.api.app:app --host "$UVM_API_HOST" --port "$UVM_API_PORT" --workers 2 --no-proxy-headers
if [[ ${UVM_G7_RECOVERY_STAGE:-} != control-only ]]; then start_recovery_control; fi
if [[ ${UVM_EXCEPTION_WARNING_WORKER:-0} == 1 && ${UVM_G7_VERIFICATION_ONLY:-0} != 1 ]]; then
  if [[ ${UVM_G7_DISPOSABLE_MODE:-0} == 1 && -n ${UVM_EXCEPTION_WARNING_PAUSE_FILE:-} ]]; then
    # Test control is synthetic and contains no secrets. Make bind-mount mode
    # translation explicit before the worker drops to uid 1800.
    chmod 0777 "$(dirname "$UVM_EXCEPTION_WARNING_PAUSE_FILE")"
    if [[ -e "$UVM_EXCEPTION_WARNING_PAUSE_FILE" ]]; then
      chmod 0666 "$UVM_EXCEPTION_WARNING_PAUSE_FILE"
    fi
  fi
  warning_principals='{}'
  if [[ ${UVM_AUTH_MODE:-bearer} == oidc ]]; then
    warning_principals=$(UVM_API_PRINCIPALS="${UVM_API_PRINCIPALS-}" /opt/uvm/venv/bin/python -c '
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
  wait_for 'local OIDC provider' curl --fail --silent "http://127.0.0.1:${UVM_OIDC_PROVIDER_PORT:-9000}/healthz"
  wait_for 'loopback OIDC sync adapter' curl --fail --silent http://127.0.0.1:8001/healthz
fi
wait_for 'UVM API' curl --fail --silent http://127.0.0.1:8000/openapi.json
for pid in "${CHILD_PIDS[@]}"; do
  kill -0 "$pid" || { echo "critical child exited during startup: $pid" >&2; exit 70; }
done
if [[ ${UVM_G7_VERIFICATION_ONLY:-0} == 1 ]]; then
  printf '%s\n' verification >"$STATE/runtime-mode"
else
  printf '%s\n' runtime >"$STATE/runtime-mode"
fi
touch "$STATE/ready"
echo 'G7_READINESS=ready'
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
set +e
exited_child_pid=
wait -n -p exited_child_pid "${CHILD_PIDS[@]}"
child_status=$?
set -e
if (( quiesce_requested )); then
  trap - USR1
  if staged_quiesce; then
    cleanup_running=1
    echo 'G7_QUIESCE=complete'
    exit 0
  fi
  exit 72
fi
rm -f "$STATE/ready"
if (( shutdown_requested )); then
  trap - TERM INT
  cleanup_running=1
  stop_all || shutdown_status=1
  echo "G7_SHUTDOWN=controlled service_cleanup_status=$shutdown_status"
  exit "$shutdown_status"
fi
if [[ ! -e "$STATE/critical-failed" ]]; then
  touch "$STATE/critical-failed"
fi
echo "G7_CRITICAL_CHILD_EXITED status=$child_status" >&2
for child_index in "${!CHILD_PIDS[@]}"; do
  if [[ ${CHILD_PIDS[$child_index]} == "$exited_child_pid" &&
        ${CHILD_NAMES[$child_index]} == ce-beat ]]; then
    echo 'G7_CE_BEAT_FAILURE_LOG_BEGIN' >&2
    tail -n 80 "$STATE/ce-beat.log" | sed -E \
      's/((password|token|secret)([=: ]+))[^[:space:]]+/\1[REDACTED]/Ig' >&2
    echo 'G7_CE_BEAT_FAILURE_LOG_END' >&2
  fi
done
trap - TERM INT
cleanup_running=1
stop_all || shutdown_status=1
trap - EXIT
if (( shutdown_status )); then
  echo 'G7_SHUTDOWN=failed_after_critical_exit' >&2
  exit 71
fi
if (( shutdown_requested )); then
  echo 'G7_SHUTDOWN=controlled'
  exit 0
fi
exit 70
