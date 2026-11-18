#!/bin/sh
# Signed RC4 host launcher. This is the only host-side VOLT controller: POSIX
# shell, Docker Engine and Compose. Python/OpenSSL run in the admitted image.
set -eu
umask 077
HOME=${HOME:-/}

VERIFIER_IMAGE='VOLT_VERIFIER_IMAGE_REFERENCE'
VERIFIER_NETWORK=''
case "$VERIFIER_IMAGE" in
  127.0.0.1:46150/volt-installer-verifier@sha256:*) VERIFIER_NETWORK='--network host' ;;
esac
SIGNER='https://github.com/njvenis/volt/.github/workflows/release-rc4.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'
VERSION='0.1.0-rc.4'
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
BUNDLE="$SELF_DIR/installer.bundle.tar.gz"
BUNDLE_SIG="$SELF_DIR/installer.bundle.sigstore.json"
WORK=''
LOCK_NAME=''
LOCK_CREATED=0
CREATED_NETWORK=''
INSTALLING=0

fail() { printf '%s\n' "volt installer: $*" >&2; exit 1; }
cleanup() {
  if [ -n "$LOCK_NAME" ] && [ "$LOCK_CREATED" -eq 1 ]; then
    lock_owner=$(docker container inspect "$LOCK_NAME" --format '{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "volt.compose.project"}}' 2>/dev/null || :)
    if [ "$lock_owner" = "$OWNER_TOKEN|$PROJECT" ]; then
      docker rm -f "$LOCK_NAME" >/dev/null 2>&1 || :
    fi
  fi
  if [ "$INSTALLING" -eq 1 ] && [ -n "$CREATED_NETWORK" ] && [ -n "$OWNER_TOKEN" ] \
      && [ ! -f "$STATE/instance.json" ]; then
    for volume in postgres media state; do
      name="${PROJECT}_$volume"
      owner=$(docker volume inspect "$name" --format '{{index .Labels "volt.compose.owner-token"}}' 2>/dev/null || :)
      if [ "$owner" = "$OWNER_TOKEN" ]; then docker volume rm "$name" >/dev/null 2>&1 || :; fi
    done
    owner=$(docker network inspect "$CREATED_NETWORK" --format '{{index .Labels "volt.compose.owner-token"}}' 2>/dev/null || :)
    if [ "$owner" = "$OWNER_TOKEN" ]; then docker network rm "$CREATED_NETWORK" >/dev/null 2>&1 || :; fi
  fi
  if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup 0 HUP INT TERM

need() { command -v "$1" >/dev/null 2>&1 || fail "required host command is missing: $1"; }
need docker
# Host binds are meaningful only when the CLI talks to the local engine whose
# filesystem is this host's. Reject TCP/SSH/named remote endpoints before any
# verifier pull, volume/network creation, or bind mount.
if [ -n "${DOCKER_HOST:-}" ]; then
  context_endpoint=$DOCKER_HOST
else
  context_name=${DOCKER_CONTEXT:-}
  if [ -z "$context_name" ]; then context_name=$(docker context show) || fail 'could not identify Docker context'; fi
  context_endpoint=$(docker context inspect "$context_name" --format '{{(index .Endpoints "docker").Host}}') \
    || fail 'could not inspect Docker context endpoint'
fi
case "$context_endpoint" in
  unix://*) ;;
  *) fail 'remote Docker contexts are unsupported because instance bind paths must exist on this host' ;;
esac
need tar
need mktemp
[ -f "$BUNDLE" ] && [ ! -L "$BUNDLE" ] || fail 'signed installer bundle is missing or unsafe'
[ -f "$BUNDLE_SIG" ] && [ ! -L "$BUNDLE_SIG" ] || fail 'installer bundle signature is missing or unsafe'
[ "${VOLT_EXPECTED_VERIFIER_IMAGE:-}" = "$VERIFIER_IMAGE" ] \
  || fail 'trusted bootstrap verifier pin is missing or differs from this authenticated launcher'
[ "${VOLT_BOOTSTRAP_VERIFIER_VERIFIED:-}" = 1 ] \
  || fail 'trusted bootstrap has not verified the independent verifier image'
[ "${VOLT_EXPECTED_VERSION:-}" = "$VERSION" ] \
  && [ "${VOLT_EXPECTED_SIGNER:-}" = "$SIGNER" ] \
  && [ "${VOLT_EXPECTED_ISSUER:-}" = "$ISSUER" ] \
  || fail 'trusted bootstrap release identity differs from this authenticated launcher'
case "$VERIFIER_IMAGE" in *@sha256:*) ;; *) fail 'independent verifier image reference is not pinned by digest' ;; esac

docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'
WORK=$(mktemp -d "${TMPDIR:-/tmp}/volt-installer.XXXXXXXX") || fail 'could not create private installer workspace'
chmod 700 "$WORK"
mkdir "$WORK/verified"
chmod 700 "$WORK/verified"

# The trusted bootstrap has authenticated this exact verifier image and its
# provenance before invoking the signed launcher. It verifies the bundle
# without extracting it and returns the immutable runtime ref.
docker pull "$VERIFIER_IMAGE" >/dev/null || fail 'could not fetch the independently pinned verifier image'
docker run --rm ${VERIFIER_NETWORK:-} --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m --env HOME=/tmp \
  --mount "type=bind,src=$SELF_DIR,dst=/package,readonly" \
  "$VERIFIER_IMAGE" --bundle /package/installer.bundle.tar.gz \
  --bundle-signature /package/installer.bundle.sigstore.json --bundle-only \
  --signer "$SIGNER" --issuer "$ISSUER" >"$WORK/bundle-admission.txt" \
  || fail 'signed installer bundle or closed inventory did not verify'
SIGNED_REFERENCE=''
SIGNED_BUNDLE_SHA256=''
while IFS='=' read -r key value; do
  case "$key" in
    reference) SIGNED_REFERENCE=$value ;;
    bundle_sha256) SIGNED_BUNDLE_SHA256=$value ;;
    *) fail 'independent verifier returned an unknown bundle admission field' ;;
  esac
done <"$WORK/bundle-admission.txt"
[ -n "$SIGNED_REFERENCE" ] && [ -n "$SIGNED_BUNDLE_SHA256" ] || fail 'independent verifier omitted bundle admission data'
IMAGE_REF=$SIGNED_REFERENCE

# Authenticate the exact runtime image and its signed SLSA provenance before
# executing any Python/OpenSSL helper from it. No Docker socket is mounted.
docker pull "$IMAGE_REF" >/dev/null || fail 'could not pull the authenticated runtime image'
docker image inspect "$IMAGE_REF" >"$WORK/runtime-image.json" || fail 'could not inspect the authenticated runtime image'
docker buildx imagetools inspect --raw "$IMAGE_REF" >"$WORK/runtime-index.json" || fail 'could not inspect the authenticated runtime index'
IMAGE_INSPECT=$(docker image inspect --format '{{.Id}}|{{.Os}}/{{.Architecture}}|{{index .Config.Labels "org.volt.compose.source-snapshot"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.version"}}|{{index .Config.Labels "org.volt.oidc-deployment-modes"}}|{{index .Config.Labels "org.volt.compose-install.contract"}}' "$IMAGE_REF")
IFS='|' read -r IMAGE_ID PLATFORM SOURCE_SNAPSHOT SOURCE_REVISION IMAGE_VERSION MODES INSTALL_CONTRACT <<EOF_INSPECT
$IMAGE_INSPECT
EOF_INSPECT
case "$IMAGE_ID" in sha256:*) ;; *) fail 'runtime has no immutable Docker image ID' ;; esac
case "$PLATFORM" in linux/amd64|linux/arm64) ;; *) fail 'runtime platform is unsupported' ;; esac
case "$SOURCE_SNAPSHOT" in sha256:*) ;; *) fail 'runtime is not bound to a source snapshot' ;; esac
case "$SOURCE_REVISION" in *[!0-9a-f]*|'') fail 'runtime source revision is malformed' ;; esac
[ "${#SOURCE_REVISION}" -eq 40 ] || fail 'runtime source revision is malformed'
[ "$IMAGE_VERSION" = "$VERSION" ] || fail 'runtime version does not match the signed package'
case ",$MODES," in *,local,*) ;; *) fail 'runtime does not declare persistent local-auth support' ;; esac
[ "$INSTALL_CONTRACT" = 1 ] || fail 'runtime lacks the Compose install contract'
chmod 0400 "$WORK/runtime-image.json" "$WORK/runtime-index.json"
docker run --rm ${VERIFIER_NETWORK:-} --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m --env HOME=/tmp --user 65532:65532 \
  --mount "type=bind,src=$SELF_DIR,dst=/package,readonly" \
  --mount "type=bind,src=$WORK,dst=/admission,readonly" \
  "$VERIFIER_IMAGE" --bundle /package/installer.bundle.tar.gz \
  --bundle-signature /package/installer.bundle.sigstore.json \
  --image-inspect /admission/runtime-image.json --index /admission/runtime-index.json \
  --output-dir /tmp/verified --reference "$IMAGE_REF" --signer "$SIGNER" --issuer "$ISSUER" \
  --source-revision "$SOURCE_REVISION" --source-snapshot "$SOURCE_SNAPSHOT" \
  --version "$IMAGE_VERSION" --platform "$PLATFORM" >"$WORK/graph-admission.json" \
  || fail 'independent verifier rejected the signed source, provenance, index, child or platform graph'

# Extraction is constrained to a private directory and occurs only after the
# signature check. Reject paths and inventories outside the one-level bundle.
ROOT=''
while IFS= read -r member; do
  case "$member" in
    /*|../*|*/../*|*/..|*/./*|./*) fail 'signed installer contains an unsafe archive path' ;;
  esac
  case "$member" in
    */*) candidate=${member%%/*}; [ -n "$candidate" ] || fail 'invalid archive root';;
    *) fail 'installer archive member is not under a versioned root' ;;
  esac
  if [ -z "$ROOT" ]; then ROOT=$candidate; else [ "$ROOT" = "$candidate" ] || fail 'installer archive has multiple roots'; fi
done <<EOF_MEMBERS
$(tar -tzf "$BUNDLE")
EOF_MEMBERS
[ -n "$ROOT" ] || fail 'installer archive is empty'
tar -tvzf "$BUNDLE" >"$WORK/installer-members.txt" || fail 'could not inspect signed installer member types'
while IFS= read -r entry; do
  member_type=${entry%${entry#?}}
  [ "$member_type" = '-' ] || fail 'signed installer may contain regular files only'
done <"$WORK/installer-members.txt"
tar -xzf "$BUNDLE" -C "$WORK/verified" --no-same-owner --no-same-permissions
PACKAGE="$WORK/verified/$ROOT"
[ -d "$PACKAGE" ] && [ ! -L "$PACKAGE" ] || fail 'installer package root is invalid'
[ "$(cat "$PACKAGE/VERSION")" = "$VERSION" ] || fail 'installer package version is not the pinned RC4 contract'
[ -f "$PACKAGE/release-image.ref" ] && [ ! -L "$PACKAGE/release-image.ref" ] || fail 'signed runtime reference is missing'
IMAGE_REF=$(cat "$PACKAGE/release-image.ref")
[ "$IMAGE_REF" = "$SIGNED_REFERENCE" ] || fail 'extracted runtime reference differs from the verified bundle'
case "$VERIFIER_IMAGE:$IMAGE_REF" in
  127.0.0.1:46150/volt-installer-verifier@sha256:*:127.0.0.1:46150/volt@sha256:*) ;;
  *:ghcr.io/njvenis/volt@sha256:*) ;;
  *) fail 'signed runtime reference is not the independently admitted immutable VOLT image' ;;
esac
IMAGE_DIGEST=${IMAGE_REF#*@sha256:}
case "$IMAGE_DIGEST" in *[!0-9a-f]*|'') fail 'signed runtime digest is malformed' ;; esac
[ "${#IMAGE_DIGEST}" -eq 64 ] || fail 'signed runtime digest is malformed'


# Runtime helper invocation: read-only authenticated image, no network, no
# Docker socket, exact package + private state binds, and only a data CLI.
helper() {
  state_dir=$1
  shift
  docker run --rm --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --env HOME=/tmp --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$state_dir,dst=/state" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" /package/setup.py "$@"
}

locked_compose() {
  clean_path="PATH=$PATH" clean_home="HOME=$HOME" clean_config="DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}"
  clean_host="DOCKER_HOST=${DOCKER_HOST-}" clean_context="DOCKER_CONTEXT=${DOCKER_CONTEXT-}"
  clean_tls="DOCKER_TLS_VERIFY=${DOCKER_TLS_VERIFY-}" clean_certs="DOCKER_CERT_PATH=${DOCKER_CERT_PATH-}"
  if [ "$RESTORE_PENDING" -eq 1 ] && { [ "$RESTORE_CAPABILITIES_REVOKED" -ne 1 ] || [ "$RESTORE_SESSIONS_REVOKED" -ne 1 ]; }; then
    env -i "$clean_path" "$clean_home" "$clean_config" "$clean_host" "$clean_context" "$clean_tls" "$clean_certs" \
      docker compose -f "$STATE/compose/compose.yaml" -f "$STATE/compose/local.yaml" \
        -f "$STATE/compose/local-restore.yaml" --env-file "$STATE/.env" -p "$PROJECT" "$@"
  else
    env -i "$clean_path" "$clean_home" "$clean_config" "$clean_host" "$clean_context" "$clean_tls" "$clean_certs" \
      docker compose -f "$STATE/compose/compose.yaml" -f "$STATE/compose/local.yaml" \
        --env-file "$STATE/.env" -p "$PROJECT" "$@"
  fi
}

read_instance() {
  INFO=$(helper "$STATE" host-validate /state --image "$IMAGE_REF") || fail 'private instance state failed runtime validation'
  PROJECT=''; OWNER_TOKEN=''; INSTANCE_PLATFORM=''; HTTP_PORT=''
  RESTORE_PENDING=0; RESTORE_IMPORTED=0; RESTORE_CAPABILITIES_REVOKED=0; RESTORE_SESSIONS_REVOKED=0
  while IFS='=' read -r key value; do
    case "$key" in
      project) PROJECT=$value ;;
      owner_token) OWNER_TOKEN=$value ;;
      platform) INSTANCE_PLATFORM=$value ;;
      http_port) HTTP_PORT=$value ;;
      restore_pending) RESTORE_PENDING=$value ;;
      restore_imported) RESTORE_IMPORTED=$value ;;
      restore_capabilities_revoked) RESTORE_CAPABILITIES_REVOKED=$value ;;
      restore_sessions_revoked) RESTORE_SESSIONS_REVOKED=$value ;;
      *) fail 'runtime returned an unknown instance field' ;;
    esac
  done <<EOF_INFO
$INFO
EOF_INFO
  case "$PROJECT" in [a-z][a-z0-9-]*) ;; *) fail 'instance project name is malformed' ;; esac
  case "$OWNER_TOKEN" in *[!0-9a-f]*|'') fail 'instance ownership token is malformed' ;; esac
  [ "${#OWNER_TOKEN}" -eq 64 ] || fail 'instance ownership token is malformed'
  [ "$INSTANCE_PLATFORM" = "$PLATFORM" ] || fail 'instance platform differs from admitted runtime'
  for flag in "$RESTORE_PENDING" "$RESTORE_IMPORTED" "$RESTORE_CAPABILITIES_REVOKED" "$RESTORE_SESSIONS_REVOKED"; do
    case "$flag" in 0|1) ;; *) fail 'instance restore fence metadata is malformed' ;; esac
  done
}

check_owned_resources() {
  actual=$(docker network inspect "${PROJECT}_network" --format '{{index .Labels "volt.compose.owner-token"}}' 2>/dev/null) || fail 'owned network is missing; refusing to recreate it'
  [ "$actual" = "$OWNER_TOKEN" ] || fail 'network ownership does not match this instance'
  for volume in postgres media state; do
    actual=$(docker volume inspect "${PROJECT}_$volume" --format '{{index .Labels "volt.compose.owner-token"}}' 2>/dev/null) || fail "owned $volume volume is missing; refusing to recreate it"
    [ "$actual" = "$OWNER_TOKEN" ] || fail "$volume volume ownership does not match this instance"
  done
  if docker container inspect "${PROJECT}-volt-1" >/dev/null 2>&1; then
    actual=$(docker container inspect "${PROJECT}-volt-1" --format '{{index .Config.Labels "volt.compose.owner-token"}}')
    [ "$actual" = "$OWNER_TOKEN" ] || fail 'container ownership does not match this instance'
  fi
}

take_lock() {
  LOCK_NAME="volt-lock-${PROJECT}-$$"
  docker run -d --name "$LOCK_NAME" --restart=no --network none --read-only \
    --label "volt.compose.owner-token=$OWNER_TOKEN" --label "volt.compose.project=$PROJECT" \
    --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$STATE,dst=/state" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.lock /state/.install.lock >/dev/null \
    || fail 'another lifecycle operation may already hold the private instance lock'
  LOCK_CREATED=1
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    if docker logs "$LOCK_NAME" 2>&1 | grep -q '^locked=1$'; then return; fi
    if ! docker inspect "$LOCK_NAME" >/dev/null 2>&1; then LOCK_NAME=''; fail 'private instance lock could not be acquired'; fi
    attempts=$((attempts + 1)); sleep 1
  done
  fail 'private instance lock did not become ready'
}

copy_capability() {
  destination=$1
  operation=$2
  document="$STATE/secrets/bootstrap-capability-document.json"
  temporary="$document.new.$$"
  locked_compose exec -T --user 0:0 volt cat /run/volt-bootstrap/capability >"$temporary" \
    || { rm -f "$temporary"; fail 'private capability delivery failed'; }
  chmod 600 "$temporary"
  mv -f "$temporary" "$document"
  helper "$STATE" extract-capability /state --operation "$operation" >"$WORK/capability-extract.stdout" \
    || { rm -f "$document"; fail 'private capability document did not match the maintenance operation'; }
  rm -f "$document"
  [ -f "$destination" ] && [ ! -L "$destination" ] && [ -s "$destination" ] \
    || fail 'runtime did not produce a private capability value'
}

show_capability() {
  file=$1
  [ -f "$file" ] && [ ! -L "$file" ] && [ -s "$file" ] || fail 'private capability file is missing'
  if [ -t 0 ] && [ -t 1 ]; then
    printf 'Setup URL: http://127.0.0.1:%s/\n' "$HTTP_PORT"
    printf 'One-use capability (private): '
    cat "$file"
  else
    printf 'capability_file=%s\n' "$file"
  fi
}

run_maintenance() {
  operation=$1; shift
  locked_compose exec -T --user 0:0 volt /opt/uvm/venv/bin/python \
    -m uvm.auth.maintenance "$operation" --config /etc/volt/local-auth.json "$@" \
    >/dev/null 2>"$WORK/maintenance.stderr" || fail 'local maintenance command failed'
  case "$operation" in
    prepare-setup|rotate-setup|create-account|issue-enrolment|issue-recovery)
      copy_capability "$STATE/secrets/bootstrap-capability-output" "$operation"
      show_capability "$STATE/secrets/bootstrap-capability-output" ;;
  esac
}

if [ "$#" -lt 1 ]; then fail 'usage: launcher.sh install|start|stop|status|setup|account [arguments]'; fi
ACTION=$1
shift
STATE=''
HTTP_PORT=8180
USERNAME=''
DISPLAY_NAME=''
OPERATION=''
PROJECT_PREFIX='volt-easy'
CONFIRM_PROJECT=''
REMOVE_STATE=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --directory) [ "$#" -ge 2 ] || fail '--directory needs a path'; STATE=$2; shift 2 ;;
    --port) [ "$#" -ge 2 ] || fail '--port needs a value'; HTTP_PORT=$2; shift 2 ;;
    --username) [ "$#" -ge 2 ] || fail '--username needs a value'; USERNAME=$2; shift 2 ;;
    --display-name) [ "$#" -ge 2 ] || fail '--display-name needs a value'; DISPLAY_NAME=$2; shift 2 ;;
    --project-prefix) [ "$#" -ge 2 ] || fail '--project-prefix needs a value'; PROJECT_PREFIX=$2; shift 2 ;;
    --confirm-project) [ "$#" -ge 2 ] || fail '--confirm-project needs a value'; CONFIRM_PROJECT=$2; shift 2 ;;
    --remove-state) REMOVE_STATE=1; shift ;;
    prepare-setup|rotate-setup|create-account|issue-enrolment|issue-recovery|disable-account|revoke-capabilities)
      [ -z "$OPERATION" ] || fail 'only one maintenance operation is allowed'; OPERATION=$1; shift ;;
    *) fail "unsupported argument: $1" ;;
  esac
done
case "$HTTP_PORT" in ''|*[!0-9]*) fail 'HTTP port must be a numeric TCP port' ;; esac
[ "$HTTP_PORT" -ge 1024 ] && [ "$HTTP_PORT" -le 65532 ] || fail 'HTTP port leaves no room for the recovery and reserved service ports'
if [ -n "$STATE" ]; then
  case "$STATE" in /*) ;; *) STATE="$PWD/$STATE" ;; esac
else
  [ -n "${HOME:-}" ] || fail 'HOME is not set; pass --directory explicitly'
  STATE="$HOME/.local/share/volt/instance"
fi
case "$STATE" in *,*|*:* ) fail 'instance path cannot contain commas or colons for Docker bind mounts' ;; esac

if [ "$ACTION" = install ]; then
  [ ! -e "$STATE" ] && [ ! -L "$STATE" ] || fail 'refusing an existing instance directory'
  parent=$(dirname -- "$STATE")
  mkdir -p "$parent"
  mkdir -m 700 "$STATE"
  INSTALLING=1
  mkdir -m 700 "$STATE/compose"
  cp "$PACKAGE/compose.yaml" "$PACKAGE/local.yaml" "$PACKAGE/local-restore.yaml" "$STATE/compose/"
  OWNER_TOKEN=$(docker run --rm --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -c 'import secrets; print(secrets.token_hex(32))')
  case "$OWNER_TOKEN" in *[!0-9a-f]*|'') fail 'runtime returned malformed resource ownership material' ;; esac
  [ "${#OWNER_TOKEN}" -eq 64 ] || fail 'runtime returned malformed resource ownership material'
  case "$PROJECT_PREFIX" in [a-z][a-z0-9-]*) ;; *) fail 'project prefix is malformed' ;; esac
  [ "${#PROJECT_PREFIX}" -le 19 ] || fail 'project prefix is too long'
  PROJECT="${PROJECT_PREFIX}-$(printf '%s' "$OWNER_TOKEN" | cut -c 1-12)"
  NETWORK=${PROJECT}_network
  if docker network inspect "$NETWORK" >/dev/null 2>&1; then fail 'generated network name already exists; refusing to adopt it'; fi
  docker network create --driver bridge --label "volt.compose.owner-token=$OWNER_TOKEN" \
    --label "com.docker.compose.project=$PROJECT" --label com.docker.compose.network=application "$NETWORK" >/dev/null \
    || fail 'could not create the privately owned application network'
  CREATED_NETWORK=$NETWORK
  for volume in postgres media state; do
    if docker volume inspect "${PROJECT}_$volume" >/dev/null 2>&1; then
      fail "generated volume name already exists; refusing to adopt ${PROJECT}_$volume"
    fi
    docker volume create --label "volt.compose.owner-token=$OWNER_TOKEN" \
      --label "com.docker.compose.project=$PROJECT" --label "com.docker.compose.volume=$volume" \
      "${PROJECT}_$volume" >/dev/null || fail "could not create privately owned $volume volume"
  done
  SUBNET=$(docker network inspect "$NETWORK" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
  GATEWAY=$(docker network inspect "$NETWORK" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
  case "$SUBNET" in *[!0-9./]*|'') fail 'Docker returned an invalid private network subnet' ;; esac
  case "$GATEWAY" in *[!0-9.]*|*..*|.*|*.|'') fail 'Docker returned an invalid private network gateway' ;; esac
  docker run --rm --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$STATE,dst=/state" --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" \
    /package/setup.py init /state --mode local --project "$PROJECT" --image "$IMAGE_REF" \
    --platform "$PLATFORM" --http-port "$HTTP_PORT" --recovery-port "$((HTTP_PORT + 1))" \
    --oidc-port "$((HTTP_PORT + 2))" --runtime-prepare --admitted-image-id "$IMAGE_ID" \
    --admitted-source-revision "$SOURCE_REVISION" --admitted-source-snapshot "$SOURCE_SNAPSHOT" \
    --admitted-version "$IMAGE_VERSION" --owner-token "$OWNER_TOKEN" \
    --network-subnet "$SUBNET" --network-gateway "$GATEWAY" \
    --runtime-compose-directory "$STATE/compose" --host-instance-directory "$STATE" \
    >/dev/null || fail 'private runtime preparation failed'
else
  [ -d "$STATE" ] && [ ! -L "$STATE" ] || fail 'instance directory is missing or unsafe'
  read_instance
fi

read_instance
take_lock
check_owned_resources
if [ "$ACTION" = install ]; then
  locked_compose config --quiet || fail 'resolved local Compose configuration failed validation'
  locked_compose up -d || fail 'VOLT Compose startup failed'
  tries=0
  while [ "$tries" -lt 180 ]; do
    health=$(docker container inspect "${PROJECT}-volt-1" --format '{{.State.Health.Status}}' 2>/dev/null || :)
    [ "$health" = healthy ] && break
    [ "$health" != unhealthy ] || fail 'VOLT container health check failed'
    tries=$((tries + 1)); sleep 2
  done
  [ "$health" = healthy ] || fail 'VOLT did not become healthy within six minutes'
  run_maintenance prepare-setup
  printf 'instance=%s\n' "$STATE"
elif [ "$ACTION" = start ]; then
  if [ "$RESTORE_PENDING" -eq 1 ]; then
    [ "$RESTORE_IMPORTED" -eq 1 ] || fail 'restored stores have not passed offline restore admission; runtime remains stopped'
    [ "$RESTORE_CAPABILITIES_REVOKED" -eq 1 ] && [ "$RESTORE_SESSIONS_REVOKED" -eq 1 ] \
      || fail 'restored capabilities and sessions have not both been revoked; ingress remains unpublished'
  fi
  locked_compose up -d
elif [ "$ACTION" = stop ]; then
  locked_compose stop --timeout 600
elif [ "$ACTION" = status ]; then
  locked_compose ps
elif [ "$ACTION" = setup ]; then
  [ "$RESTORE_PENDING" -eq 0 ] || fail 'local setup is unavailable until restored credentials and sessions are revoked'
  run_maintenance prepare-setup
elif [ "$ACTION" = account ]; then
  [ "$RESTORE_PENDING" -eq 0 ] || fail 'local account maintenance is unavailable until restored credentials and sessions are revoked'
  [ -n "$OPERATION" ] || fail 'account requires a maintenance operation'
  set --
  if [ -n "$USERNAME" ]; then set -- "$@" --username "$USERNAME"; fi
  if [ -n "$DISPLAY_NAME" ]; then set -- "$@" --display-name "$DISPLAY_NAME"; fi
  run_maintenance "$OPERATION" "$@"
elif [ "$ACTION" = destroy ]; then
  [ "$CONFIRM_PROJECT" = "$PROJECT" ] || fail 'destroy requires --confirm-project with the exact owned project name'
  locked_compose down --timeout 600 --volumes
  if [ "$REMOVE_STATE" -eq 1 ]; then
    [ -n "$STATE" ] && [ "$STATE" != / ] || fail 'refusing unsafe private-state removal'
    if [ -n "$LOCK_NAME" ]; then docker rm -f "$LOCK_NAME" >/dev/null; LOCK_NAME=''; fi
    rm -rf "$STATE"
  fi
else
  fail 'supported commands are install, start, stop, status, setup, account, and explicit destroy'
fi
