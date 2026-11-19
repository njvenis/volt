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
LOCK_ID=''
LOCK_CREATED=0
CREATED_NETWORK=''
INSTALLING=0

fail() { printf '%s\n' "volt installer: $*" >&2; exit 1; }
cleanup() {
  if [ -n "$LOCK_NAME" ] && [ "$LOCK_CREATED" -eq 1 ]; then
    lock_owner=$(docker container inspect "$LOCK_NAME" --format '{{.Id}}|{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "volt.compose.project"}}' 2>/dev/null || :)
    if [ "$lock_owner" = "$LOCK_ID|$OWNER_TOKEN|$PROJECT" ]; then
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

ENGINE_PLATFORM=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}') || fail 'could not identify the native Docker platform'
case "$ENGINE_PLATFORM" in linux/amd64|linux/arm64) ;; *) fail 'native Docker platform is unsupported' ;; esac
PLATFORM=$ENGINE_PLATFORM

OFFLINE_MODE=${VOLT_OFFLINE:-0}
case "$OFFLINE_MODE" in 0|1) ;; *) fail 'offline transport mode must be exactly 0 or 1' ;; esac
EARLY_ACTION=${1:-}
EARLY_STATE=''; early_directory=0
for argument do
  if [ "$early_directory" -eq 1 ]; then EARLY_STATE=$argument; early_directory=0
  elif [ "$argument" = --directory ]; then early_directory=1
  fi
done
[ "$early_directory" -eq 0 ] || fail '--directory needs a path'
CACHE_DIRECTORY=''; CACHE_STATE=''; CACHE_PARENT=''; CACHE_STAGE=''
INITIAL_PREPARATION=0

resolve_cache_location() {
  selected_state=$EARLY_STATE
  [ -n "$selected_state" ] || selected_state="$HOME/.local/share/volt/instance"
  case "$selected_state" in /*) ;; *) selected_state="$PWD/$selected_state" ;; esac
  while [ "$selected_state" != / ] && [ "${selected_state%/}" != "$selected_state" ]; do selected_state=${selected_state%/}; done
  case "$selected_state" in *,*|*:* ) fail 'selected instance path contains unsupported bind separators' ;; esac
  selected_parent=$(dirname -- "$selected_state")
  if [ "$EARLY_ACTION" = install ] && [ "$OFFLINE_MODE" -eq 0 ]; then mkdir -p "$selected_parent"; fi
  selected_parent=$(cd -P -- "$selected_parent" && pwd -P) || fail 'selected private instance parent is inaccessible'
  selected_name=${selected_state##*/}
  case "$selected_name" in ''|.|..) fail 'selected instance name is unsafe' ;; esac
  CACHE_STATE="$selected_parent/$selected_name"
  [ ! -L "$CACHE_STATE" ] || fail 'selected instance directory is linked'
  CACHE_PARENT="$CACHE_STATE.installer-artifacts"
  [ ! -L "$CACHE_PARENT" ] || fail 'dedicated verification anchor is linked'
  CACHE_DIRECTORY="$CACHE_PARENT/originals"
}

run_verifier() {
  verifier_operation=$1; shift
  set -- "$VERIFIER_IMAGE" "$@"
  case "$verifier_operation" in
    online) ;;
    offline|initial|publish) set -- --network none --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly" "$@" ;;
    intent) set -- --network none "$@" ;;
    export) set -- --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts" "$@" ;;
    *) fail 'unknown fixed independent verifier operation' ;;
  esac
  if [ "$verifier_operation" = online ] || [ "$verifier_operation" = export ]; then
    case "$VERIFIER_IMAGE" in 127.0.0.1:46150/*) set -- --network host "$@" ;; esac
  fi
  case "$verifier_operation" in
    offline|publish|intent)
      [ -f "$CACHE_STATE/instance.json" ] && [ ! -L "$CACHE_STATE/instance.json" ] \
        || fail 'selected private installer journal is missing or linked'
      set -- --mount "type=bind,src=$CACHE_STATE/instance.json,dst=/run/volt-selected-journal/instance.json,readonly" "$@" ;;
  esac
  if [ "$verifier_operation" = offline ]; then
    set -- --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly" "$@"
  fi
  if [ "$verifier_operation" = initial ]; then
    set -- --mount "type=bind,src=$WORK/runtime-init-request.json,dst=/run/volt-initialization/request.json,readonly" "$@"
  elif [ "$verifier_operation" = export ]; then
    set -- --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly" "$@"
  elif [ "$verifier_operation" = publish ]; then
    set -- --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent" \
      --mount "type=bind,src=$WORK/cache-mounts.json,dst=/run/volt-cache-observation/mounts.json,readonly" "$@"
  fi
  set -- docker run --platform "$PLATFORM" --pull=never --rm --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m --env HOME=/tmp \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$SELF_DIR,dst=/package,readonly" \
    --mount "type=bind,src=$WORK/runtime-image.json,dst=/admission/runtime-image.json,readonly" \
    --mount "type=bind,src=$WORK/runtime-index.json,dst=/admission/runtime-index.json,readonly" "$@"
  "$@"
}

graph_verifier() {
  graph_operation=$1; shift
  run_verifier "$graph_operation" --bundle /package/installer.bundle.tar.gz \
    --bundle-signature /package/installer.bundle.sigstore.json \
    --image-inspect /admission/runtime-image.json --index /admission/runtime-index.json \
    --output-dir /tmp/verified --reference "$IMAGE_REF" --signer "$SIGNER" --issuer "$ISSUER" \
    --source-revision "$SOURCE_REVISION" --source-snapshot "$SOURCE_SNAPSHOT" \
    --version "$IMAGE_VERSION" --platform "$PLATFORM" "$@"
}

refresh_installer_admission() {
  docker image inspect --platform "$PLATFORM" "$IMAGE_REF" >"$WORK/.next-runtime-image.json" \
    || fail 'cached selected runtime image is unavailable; no implicit pull is permitted'
  chmod 0400 "$WORK/.next-runtime-image.json"
  mv "$WORK/.next-runtime-image.json" "$WORK/runtime-image.json"
  graph_verifier offline --offline-artifacts --expected-verifier-reference "$VERIFIER_IMAGE" --require-installed-pin \
    >"$WORK/.next-graph-admission.json" || fail 'fresh complete original cache verification failed'
  chmod 600 "$WORK/.next-graph-admission.json"
  mv "$WORK/.next-graph-admission.json" "$WORK/graph-admission.json"
}

load_installer_intent() {
  intent=$(run_verifier intent --bundle /package/installer.bundle.tar.gz \
    --bundle-signature /package/installer.bundle.sigstore.json --bundle-only --inspect-cache-intent \
    --cache-state "$CACHE_STATE" --reference "$IMAGE_REF" --expected-verifier-reference "$VERIFIER_IMAGE" \
    --signer "$SIGNER" --issuer "$ISSUER" --source-revision "$SOURCE_REVISION" --source-snapshot "$SOURCE_SNAPSHOT" \
    --version "$IMAGE_VERSION" --platform "$PLATFORM") || fail 'durable selected installer intent is unavailable or contradictory'
  while IFS='=' read -r key value; do
    case "$key" in
      cache_stage) CACHE_STAGE=$value ;;
      project) PROJECT=$value ;;
      owner_token) OWNER_TOKEN=$value ;;
      initial_preparation) INITIAL_PREPARATION=$value ;;
      *) fail 'unknown selected installer intent field' ;;
    esac
  done <<EOF_INSTALLER_INTENT
$intent
EOF_INSTALLER_INTENT
  case "$INITIAL_PREPARATION" in 0|1) ;; *) fail 'initial preparation intent is malformed' ;; esac
}

# Fixed observation only: no Docker socket or daemon API reaches any helper.
collect_cache_mounts() {
  cache_containers=$(docker ps -aq --filter label=org.volt.compose-install.contract=1) \
    || fail 'actual API container inventory is unavailable'
  volume_names='|'
  {
    printf '{"containers":['; separator=''
    for container_id in $cache_containers; do
      case "$container_id" in *[!0-9a-f]*|'') fail 'Docker returned malformed API identity' ;; esac
      printf '%s{"Mounts":' "$separator"
      docker inspect "$container_id" --format '{{json .Mounts}}' || fail 'actual API mount inventory is unavailable'
      printf '}'; separator=','
    done
    printf '],"volumes":['; separator=''
    for container_id in $cache_containers; do
      names=$(docker inspect "$container_id" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}') \
        || fail 'actual API named-volume inventory is unavailable'
      for name in $names; do
        case "$name" in *[!A-Za-z0-9_.-]*|'') fail 'Docker returned malformed named-volume identity' ;; esac
        case "$volume_names" in *"|$name|"*) continue ;; esac
        volume_names="$volume_names$name|"
        printf '%s' "$separator"
        docker volume inspect "$name" --format '{"Name":{{json .Name}},"Driver":{{json .Driver}},"Options":{{json .Options}},"Mountpoint":{{json .Mountpoint}}}' \
          || fail 'actual API named-volume source cannot be established'
        separator=','
      done
    done
    printf ']}\n'
  } >"$WORK/cache-mounts.json"
  chmod 600 "$WORK/cache-mounts.json"
}

publish_installer_cache() {
  ensure_lock_owner
  collect_cache_mounts
  graph_verifier publish --offline-artifacts --expected-verifier-reference "$VERIFIER_IMAGE" --require-installed-pin \
    --publish-cache --cache-state "$CACHE_STATE" --cache-stage-name "$CACHE_STAGE" \
    >"$WORK/.next-graph-admission.json" || fail 'verified cache publication failed; existing keys and private staging are preserved'
  chmod 600 "$WORK/.next-graph-admission.json"
  mv "$WORK/.next-graph-admission.json" "$WORK/graph-admission.json"
  CACHE_DIRECTORY="$CACHE_PARENT/originals"
  ensure_lock_owner
}

: >"$WORK/runtime-image.json"; : >"$WORK/runtime-index.json"
if [ "$OFFLINE_MODE" -eq 1 ]; then
  [ "$EARLY_ACTION" != install ] || fail 'a verification cache cannot authorize a new installation'
  resolve_cache_location
  [ -d "$CACHE_DIRECTORY" ] && [ ! -L "$CACHE_DIRECTORY" ] || fail 'complete original verification cache is missing or linked'
fi

# The trusted bootstrap has authenticated this exact verifier image and its
# provenance before invoking the signed launcher. It verifies the bundle
# without extracting it and returns the immutable runtime ref.
if [ "$OFFLINE_MODE" -eq 0 ]; then
  docker pull --platform "$ENGINE_PLATFORM" "$VERIFIER_IMAGE" >/dev/null || fail 'could not fetch the independently pinned verifier image'
fi
if [ "$OFFLINE_MODE" -eq 1 ]; then
  verifier_transport=offline
else
  verifier_transport=online
fi
bundle_discovery() {
  if [ "$OFFLINE_MODE" -eq 1 ]; then set -- --offline-artifacts --expected-verifier-reference "$VERIFIER_IMAGE" --require-installed-pin; else set --; fi
  run_verifier "$verifier_transport" --bundle /package/installer.bundle.tar.gz \
  --bundle-signature /package/installer.bundle.sigstore.json --bundle-only \
    --signer "$SIGNER" --issuer "$ISSUER" "$@"
}
bundle_discovery >"$WORK/bundle-admission.txt" || fail 'signed installer bundle or closed inventory did not verify'
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
if [ "$OFFLINE_MODE" -eq 0 ]; then
  docker pull --platform "$ENGINE_PLATFORM" "$IMAGE_REF" >/dev/null || fail 'could not pull the authenticated runtime image'
fi
docker image inspect --platform "$ENGINE_PLATFORM" "$IMAGE_REF" >"$WORK/runtime-image.json" || fail 'could not inspect the authenticated runtime image'
if [ "$OFFLINE_MODE" -eq 1 ]; then
  # This is original cached data, not execution or trust from a cache pass.
  cp "$CACHE_DIRECTORY/runtime-index/blobs/sha256/${IMAGE_REF##*@sha256:}" "$WORK/runtime-index.json" \
    || fail 'original cached runtime index is missing'
else
  docker buildx imagetools inspect --raw "$IMAGE_REF" >"$WORK/runtime-index.json" || fail 'could not inspect the authenticated runtime index'
fi
IMAGE_INSPECT=$(docker image inspect --platform "$ENGINE_PLATFORM" --format '{{.Id}}|{{.Os}}/{{.Architecture}}|{{index .Config.Labels "org.volt.compose.source-snapshot"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.version"}}|{{index .Config.Labels "org.volt.oidc-deployment-modes"}}|{{index .Config.Labels "org.volt.compose-install.contract"}}' "$IMAGE_REF")
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
ENGINE_PLATFORM=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
[ "$ENGINE_PLATFORM" = "$PLATFORM" ] || fail 'selected runtime must match the native Docker engine platform'
IMAGE_ENGINE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_REF") || fail 'could not inspect the engine parent image identity'
if docker image inspect --help | grep -q -- --platform; then
  docker image inspect --platform "$PLATFORM" "$IMAGE_REF" >"$WORK/runtime-image.json" \
    || fail 'could not inspect the actual selected native platform image'
  IMAGE_ID=$(docker image inspect --platform "$PLATFORM" "$IMAGE_REF" --format '{{.Id}}')
fi
[ "$IMAGE_ENGINE_ID" = "$IMAGE_ID" ] || [ "$IMAGE_ENGINE_ID" = "${IMAGE_REF##*@}" ] \
  || fail 'engine parent image ID differs from the signed index or selected object'
chmod 0400 "$WORK/runtime-image.json" "$WORK/runtime-index.json"
if [ "$OFFLINE_MODE" -eq 1 ]; then
  load_installer_intent
  refresh_installer_admission
else
  graph_verifier online >"$WORK/graph-admission.json" \
    || fail 'independent verifier rejected the signed source, provenance, index, child or platform graph'
  resolve_cache_location
  if [ "$EARLY_ACTION" = install ]; then
    [ ! -e "$CACHE_STATE" ] && [ ! -L "$CACHE_STATE" ] || fail 'refusing an existing instance directory'
    [ ! -e "$CACHE_PARENT" ] && [ ! -L "$CACHE_PARENT" ] || fail 'retained verification anchor cannot recreate an installation'
    mkdir -m 700 "$CACHE_PARENT" || fail 'dedicated private verification anchor could not be created'
    CACHE_DIRECTORY=$(mktemp -d "$CACHE_PARENT/.originals.partial.XXXXXXXX") \
      || fail 'private original-artifact staging could not be created'
    CACHE_STAGE=${CACHE_DIRECTORY##*/}
    graph_verifier export --export-offline-artifacts --expected-verifier-reference "$VERIFIER_IMAGE" \
      --cache-state "$CACHE_STATE" --cache-stage-name "$CACHE_STAGE" \
      >"$WORK/graph-admission.json" || fail 'complete original authentication transport could not be exported and reverified'
  else
    load_installer_intent
    if [ ! -d "$CACHE_DIRECTORY" ]; then
      CACHE_DIRECTORY="$CACHE_PARENT/$CACHE_STAGE"
      [ -d "$CACHE_DIRECTORY" ] && [ ! -L "$CACHE_DIRECTORY" ] \
        || fail 'both committed cache and exact durable original staging are missing; no new stage or identity is adopted'
    fi
    [ ! -L "$CACHE_DIRECTORY" ] || fail 'committed verification material is linked'
    refresh_installer_admission
  fi
fi

# Complete independent graph admission precedes this first candidate execution.
docker run --platform "$PLATFORM" --pull=never --rm -i --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -c 'import json,sys; result=json.load(sys.stdin); r=result["runtime"]; print("image_id_kind="+r["image_id_kind"]); print("image_config_id="+r["image_config_id"]); print("selected_descriptor="+json.dumps(r["selected_descriptor"],sort_keys=True,separators=(",",":"))); print("installer_pin_json="+json.dumps(result["offline_artifacts"],sort_keys=True,separators=(",",":")))' \
  <"$WORK/graph-admission.json" >"$WORK/runtime-identity.txt" || fail 'admitted runtime identity inventory could not be decoded'
IMAGE_ID_KIND=''; IMAGE_CONFIG_ID=''; SELECTED_DESCRIPTOR=''; INSTALLER_PIN_JSON=''
while IFS='=' read -r key value; do
  case "$key" in
    image_id_kind) IMAGE_ID_KIND=$value ;;
    image_config_id) IMAGE_CONFIG_ID=$value ;;
    selected_descriptor) SELECTED_DESCRIPTOR=$value ;;
    installer_pin_json) INSTALLER_PIN_JSON=$value ;;
    *) fail 'unknown admitted runtime identity field' ;;
  esac
done <"$WORK/runtime-identity.txt"
case "$IMAGE_ID_KIND" in config|selected_manifest) ;; *) fail 'runtime object kind is not admitted' ;; esac

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
  docker run --platform "$PLATFORM" --pull=never --rm --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --env HOME=/tmp --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$state_dir,dst=/state" \
    --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly" \
    --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly" \
    --mount "type=bind,src=$WORK/graph-admission.json,dst=/run/volt-independent-admission/receipt.json,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" /package/setup.py "$@"
}

# Recovery preparation/validation runs in the admitted image with no network,
# Docker socket, or operator key exposed to the API container. JSON crosses the
# boundary as data on stdin/stdout; it is never evaluated as shell.
recovery_helper() {
  operation=$1
  case "$operation" in request|targets-request|prepare|validate|acknowledge|prepare-start) ;; *) fail 'invalid local recovery helper operation' ;; esac
  if [ "$operation" = request ] || [ "$operation" = targets-request ]; then
    docker run --platform "$PLATFORM" --pull=never --rm --network none --read-only --cap-drop=ALL \
      --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m \
      --user "$(id -u):$(id -g)" --mount "type=bind,src=$STATE,dst=/instance,readonly" \
      --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly" \
      --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly" \
      --mount "type=bind,src=$WORK/graph-admission.json,dst=/run/volt-independent-admission/receipt.json,readonly" \
      --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.recovery_authority \
      "$operation" --instance-root /instance
    return
  fi
  [ -s "$WORK/recovery-request.json" ] || fail 'closed local recovery request is missing'
  helper_user="$(id -u):$(id -g)"; helper_capabilities='--cap-drop=ALL'
  if [ "$operation" = prepare ]; then
    helper_user=0:0; helper_capabilities='--cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=DAC_OVERRIDE'
  fi
  case "$operation" in prepare|acknowledge|prepare-start) mount_access='' ;; validate) mount_access=',readonly' ;; esac
  docker run --platform "$PLATFORM" --pull=never --rm -i --network none --read-only $helper_capabilities \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --user "$helper_user" --mount "type=bind,src=$STATE,dst=/instance$mount_access" \
    --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly" \
    --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly" \
    --mount "type=bind,src=$WORK/graph-admission.json,dst=/run/volt-independent-admission/receipt.json,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.recovery_authority \
    "$operation" --request-stdin --instance-root /instance
}

prepare_local_custody() {
  [ "$MODE" = local ] || return 0
  recovery_helper request >"$WORK/recovery-request.json" || fail 'could not create closed local recovery request'
  chmod 600 "$WORK/recovery-request.json"
  recovery_helper prepare <"$WORK/recovery-request.json" >"$WORK/recovery-prepare.json" \
    || fail 'local recovery custody preparation failed'
  chmod 600 "$WORK/recovery-prepare.json"
}

validate_local_custody() {
  [ "$MODE" = local ] || return 0
  recovery_helper request >"$WORK/recovery-request.json" || fail 'local recovery identity request failed'
  chmod 600 "$WORK/recovery-request.json"
  recovery_helper validate <"$WORK/recovery-request.json" >"$WORK/recovery-validation.json" \
    || fail 'local recovery custody validation failed'
}

locked_compose() {
  clean_path="PATH=$PATH" clean_home="HOME=$HOME" clean_config="DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}"
  clean_host="DOCKER_HOST=${DOCKER_HOST-}" clean_context="DOCKER_CONTEXT=${DOCKER_CONTEXT-}"
  clean_tls="DOCKER_TLS_VERIFY=${DOCKER_TLS_VERIFY-}" clean_certs="DOCKER_CERT_PATH=${DOCKER_CERT_PATH-}"
  if [ "$START_CLOSED" -eq 1 ] || { [ "$RESTORE_PENDING" -eq 1 ] && { [ "$RESTORE_CAPABILITIES_REVOKED" -ne 1 ] || [ "$RESTORE_SESSIONS_REVOKED" -ne 1 ]; }; }; then
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
  set --
  [ "${ACTION:-}" != restore-provision ] || set -- --allow-restore-transition
  INFO=$(helper "$STATE" host-validate /state --image "$IMAGE_REF" "$@") || fail 'private instance state failed runtime validation'
  PROJECT=''; OWNER_TOKEN=''; MODE=''; INSTANCE_PLATFORM=''; HTTP_PORT=''
  START_CLOSED=1
  RESTORE_PENDING=0; RESTORE_IMPORTED=0; RESTORE_CAPABILITIES_REVOKED=0; RESTORE_SESSIONS_REVOKED=0
  while IFS='=' read -r key value; do
    case "$key" in
      project) PROJECT=$value ;;
      owner_token) OWNER_TOKEN=$value ;;
      mode) MODE=$value ;;
      platform) INSTANCE_PLATFORM=$value ;;
      http_port) HTTP_PORT=$value ;;
      start_closed) START_CLOSED=$value ;;
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
  [ "$MODE" = local ] || fail 'instance mode differs from this launcher contract'
  case "$OWNER_TOKEN" in *[!0-9a-f]*|'') fail 'instance ownership token is malformed' ;; esac
  [ "${#OWNER_TOKEN}" -eq 64 ] || fail 'instance ownership token is malformed'
  [ "$INSTANCE_PLATFORM" = "$PLATFORM" ] || fail 'instance platform differs from admitted runtime'
  for flag in "$START_CLOSED" "$RESTORE_PENDING" "$RESTORE_IMPORTED" "$RESTORE_CAPABILITIES_REVOKED" "$RESTORE_SESSIONS_REVOKED"; do
    case "$flag" in 0|1) ;; *) fail 'instance restore fence metadata is malformed' ;; esac
  done
}

. "$PACKAGE/offline-host.sh"

check_owned_resources() {
  actual=$(docker network inspect "${PROJECT}_network" --format '{{index .Labels "volt.compose.owner-token"}}' 2>/dev/null) || fail 'owned network is missing; refusing to recreate it'
  [ "$actual" = "$OWNER_TOKEN" ] || fail 'network ownership does not match this instance'
  for volume in postgres media state; do
    actual=$(docker volume inspect "${PROJECT}_$volume" --format '{{index .Labels "volt.compose.owner-token"}}' 2>/dev/null) || fail "owned $volume volume is missing; refusing to recreate it"
    [ "$actual" = "$OWNER_TOKEN" ] || fail "$volume volume ownership does not match this instance"
    driver=$(docker volume inspect "${PROJECT}_$volume" --format '{{.Driver}}|{{json .Options}}')
    case "$driver" in 'local|null'|'local|{}') ;; *) fail 'owned volume uses an unapproved host bind driver' ;; esac
  done
  if docker container inspect "${PROJECT}-volt-1" >/dev/null 2>&1; then
    actual=$(docker container inspect "${PROJECT}-volt-1" --format '{{index .Config.Labels "volt.compose.owner-token"}}')
    [ "$actual" = "$OWNER_TOKEN" ] || fail 'container ownership does not match this instance'
  fi
}

verify_actual_mounts() {
  container="${PROJECT}-volt-1"
  mounts=$(docker container inspect "$container" --format \
    '{{range .Mounts}}{{printf "%s|%s|%s|%s|%t\n" .Type .Name .Source .Destination .RW}}{{end}}') \
    || fail 'could not inspect the created VOLT container mount inventory'
  docker container inspect "$container" >"$WORK/container-inspect.json"
  docker volume inspect "${PROJECT}_postgres" "${PROJECT}_media" "${PROJECT}_state" >"$WORK/volume-inspect.json"
  {
    printf '{"containers":'
    cat "$WORK/container-inspect.json"
    printf ',"volumes":'
    cat "$WORK/volume-inspect.json"
    printf '}\n'
  } >"$WORK/actual-container.json"
  docker run --platform "$PLATFORM" --pull=never --rm -i --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$STATE,dst=/instance,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.runtime_mounts \
    --instance-root /instance --host-root "$STATE" <"$WORK/actual-container.json" \
    >"$WORK/actual-container-admission.txt" || fail 'actual API mounts violate host custody exclusions'
  seen_postgres=0 seen_media=0 seen_state=0 seen_oidc=0 seen_fence=0
  while IFS='|' read -r type name source target writable; do
    [ -n "$target" ] || continue
    case "$target" in
      /var/lib/postgresql/data)
        [ "$type" = volume ] && [ "$name" = "${PROJECT}_postgres" ] && [ "$writable" = true ] \
          || fail 'actual PostgreSQL mount differs from its owned named volume'
        seen_postgres=1 ;;
      /app/media)
        [ "$type" = volume ] && [ "$name" = "${PROJECT}_media" ] && [ "$writable" = true ] \
          || fail 'actual media mount differs from its owned named volume'
        seen_media=1 ;;
      /opt/uvm/state)
        [ "$type" = volume ] && [ "$name" = "${PROJECT}_state" ] && [ "$writable" = true ] \
          || fail 'actual application state mount differs from its owned named volume'
        seen_state=1 ;;
      /etc/volt/oidc.json)
        [ "$type" = bind ] && [ "$source" = "$STATE/oidc.json" ] && [ "$writable" = false ] \
          || fail 'actual OIDC configuration mount is not the admitted read-only file'
        seen_oidc=1 ;;
      /run/volt-bootstrap)
        [ "$type" = bind ] && [ "$source" = "$STATE/secrets/bootstrap-delivery" ] && [ "$writable" = true ] \
          || fail 'actual capability delivery mount is not the admitted private directory' ;;
      /run/volt-start-admission)
        [ "$type" = bind ] && [ "$source" = "$STATE/secrets/local-start-admission" ] && [ "$writable" = false ] \
          || fail 'actual start admission is not its narrow read-only directory' ;;
      /run/volt-restore-fence)
        [ "$type" = bind ] && [ "$source" = "$STATE/secrets/local-restore-fence" ] \
          && [ "$writable" = false ] || fail 'actual restore fence mount is not its narrow read-only directory'
        seen_fence=1 ;;
      /run/secrets/*)
        case "$target" in
          /run/secrets/uvm_db_password) rel=secrets/uvm_db_password ;;
          /run/secrets/ce_db_password) rel=secrets/ce_db_password ;;
          /run/secrets/ce_admin_password) rel=secrets/ce_admin_password ;;
          /run/secrets/ce_secret_key) rel=secrets/ce_secret_key ;;
          /run/secrets/ce_credential_key) rel=secrets/ce_credential_key ;;
          /run/secrets/uvm_cursor_secret) rel=secrets/uvm_cursor_secret ;;
          /run/secrets/oidc_client_secret) rel=secrets/oidc_client_secret ;;
          /run/secrets/oidc_sync_secret) rel=secrets/oidc_sync_secret ;;
          /run/secrets/oidc_operator_secret) rel=secrets/oidc_operator_secret ;;
          /run/secrets/recovery-server.crt) rel=secrets/recovery-server.crt ;;
          /run/secrets/recovery-server.key) rel=secrets/recovery-server.key ;;
          /run/secrets/recovery-ca.crt) rel=secrets/recovery-ca.crt ;;
          /run/secrets/local-auth.json) rel=local-auth.json ;;
          /run/secrets/local-auth-key) rel=secrets/local-auth-key ;;
          /run/secrets/local-recovery.json) rel=local-recovery.json ;;
          /run/secrets/local-recovery-issuer.key) rel=secrets/local-recovery-runtime/issuer.key ;;
          /run/secrets/local-recovery-issuer.pub) rel=secrets/local-recovery-runtime/issuer.pub ;;
          /run/secrets/local-recovery-operator.pub) rel=secrets/local-recovery-runtime/operator.pub ;;
          /run/secrets/local-recovery-material.key) rel=secrets/local-recovery-runtime/material.key ;;
          *) fail 'actual VOLT container has an unapproved API secret mount' ;;
        esac
        [ "$type" = bind ] && [ "$source" = "$STATE/$rel" ] && [ "$writable" = false ] \
          || fail 'actual API secret mount differs from the admitted read-only file'
        case "$source" in *local-recovery-authority*|*/operator.key|*/host.json) fail 'host operator authority is mounted into the API' ;; esac ;;
      *) fail "actual VOLT container has an unapproved mount target: $target" ;;
    esac
  done <<EOF_MOUNTS
$mounts
EOF_MOUNTS
  [ "$seen_postgres$seen_media$seen_state$seen_oidc$seen_fence" = 11111 ] \
    || fail 'actual VOLT container mount inventory is incomplete'
}

ensure_lock_owner() {
  [ -n "$LOCK_NAME" ] && [ -n "$LOCK_ID" ] || fail 'actual lifecycle FD owner is unavailable'
  owner=$(docker inspect "$LOCK_NAME" --format '{{.Id}}|{{.State.Running}}|{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "volt.compose.project"}}|{{.Config.Image}}') \
    || fail 'actual lifecycle FD owner disappeared'
  [ "$owner" = "$LOCK_ID|true|$OWNER_TOKEN|$PROJECT|$IMAGE_REF" ] || fail 'actual lifecycle FD owner changed or stopped'
}

take_lock() {
  if [ -n "$LOCK_NAME" ]; then ensure_lock_owner; return 0; fi
  LOCK_NAME="volt-lock-${PROJECT}-$$"
  init_request=${1:-}
  set -- docker run --platform "$PLATFORM" --pull=never -d --name "$LOCK_NAME" --restart=no --network none --read-only \
    --label "volt.compose.owner-token=$OWNER_TOKEN" --label "volt.compose.project=$PROJECT" \
    --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$STATE,dst=/state" \
    --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$CACHE_DIRECTORY,dst=/run/volt-offline-artifacts,readonly"
  if [ -n "$init_request" ]; then
    [ "$init_request" = "$WORK/runtime-init-request.json" ] || fail 'fixed initialization request path differs'
    set -- "$@" --mount "type=bind,src=$WORK/runtime-init-request.json,dst=/run/volt-initialization/request.json,readonly"
    set -- "$@" --mount "type=bind,src=$WORK/init-admission.json,dst=/run/volt-initialization-admission/receipt.json,readonly"
    set -- "$@" --mount "type=bind,src=$CACHE_PARENT,dst=/run/volt-cache-parent,readonly"
  fi
  set -- "$@" --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.lock /state/.install.lock
  if [ -n "$init_request" ]; then set -- "$@" --initialize-local; fi
  LOCK_ID=$("$@") || fail 'another lifecycle operation may already hold the private instance lock'
  case "$LOCK_ID" in *[!0-9a-f]*|'') fail 'actual lifecycle container ID is malformed' ;; esac
  [ "${#LOCK_ID}" -eq 64 ] || fail 'actual lifecycle container ID is malformed'
  LOCK_CREATED=1
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    ensure_lock_owner
    docker logs "$LOCK_NAME" >"$WORK/lock-owner.log" 2>&1 || fail 'actual lifecycle owner log command failed'
    if grep -q '^locked=1$' "$WORK/lock-owner.log"; then return; fi
    attempts=$((attempts + 1)); sleep 1
  done
  fail 'private instance lock did not become ready'
}

wait_healthy() {
  tries=0
  while [ "$tries" -lt 180 ]; do
    health=$(docker container inspect "${PROJECT}-volt-1" --format '{{.State.Health.Status}}' 2>/dev/null || :)
    [ "$health" = healthy ] && return
    [ "$health" != unhealthy ] || fail 'VOLT container health check failed'
    tries=$((tries + 1)); sleep 2
  done
  fail 'VOLT did not become healthy within six minutes'
}

acknowledge_start() {
  verify_actual_mounts
  locked_compose exec -T --user 0:0 volt cat /run/uvm-maintenance/applied.json >"$WORK/applied.json" \
    || fail 'backend restore acknowledgement is unavailable'
  chmod 600 "$WORK/applied.json"
  recovery_helper acknowledge <"$WORK/applied.json" >"$WORK/acknowledgement.txt" \
    || fail 'backend acknowledgement differs from independently validated host custody'
}

collect_start_resources() {
  docker inspect "${PROJECT}-volt-1" >"$WORK/start-container.json"
  docker volume inspect "${PROJECT}_postgres" "${PROJECT}_media" "${PROJECT}_state" >"$WORK/start-volumes.json"
  docker network inspect "${PROJECT}_network" >"$WORK/start-network.json"
  {
    printf '{"containers":'; cat "$WORK/start-container.json"
    printf ',"volumes":'; cat "$WORK/start-volumes.json"
    printf ',"networks":'; cat "$WORK/start-network.json"
    printf '}\n'
  } >"$WORK/start-resources.json"
}

prepare_start_container() {
  locked_compose create --force-recreate || fail 'local container preparation failed'
  verify_actual_mounts
  collect_start_resources
  recovery_helper prepare-start <"$WORK/start-resources.json" >"$WORK/prepare-start.txt" \
    || fail 'actual owned start resource admission failed'
  read_instance
  locked_compose create --force-recreate || fail 'admitted local container recreation failed'
  verify_actual_mounts
  collect_start_resources
  recovery_helper prepare-start <"$WORK/start-resources.json" >"$WORK/prepare-start.txt" \
    || fail 'recreated local container differs from start admission'
}

release_start() {
  tries=0
  while [ "$tries" -lt 360 ]; do
    if docker exec --user 0:0 "${PROJECT}-volt-1" cat /run/uvm-maintenance/applied.json >"$WORK/applied.json" 2>/dev/null \
        && [ -s "$WORK/applied.json" ]; then break; fi
    state=$(docker inspect "${PROJECT}-volt-1" --format '{{.State.Status}}')
    case "$state" in exited|dead|restarting) fail 'bootstrap maintenance exited before host acknowledgement' ;; esac
    tries=$((tries + 1)); sleep 1
  done
  [ "$tries" -lt 360 ] || fail 'bounded bootstrap acknowledgement timed out before workers'
  chmod 600 "$WORK/applied.json"
  verify_actual_mounts
  recovery_helper acknowledge <"$WORK/applied.json" >"$WORK/acknowledgement.txt" \
    || fail 'backend acknowledgement differs from independent host custody'
  read_instance
  docker exec -i --user 0:0 "${PROJECT}-volt-1" /opt/uvm/venv/bin/python \
    -m uvm.installer.start_admission release <"$STATE/secrets/local-start-admission/admission.json" \
    >"$WORK/host-release.txt" || fail 'host could not release the exact disarmed start'
  wait_healthy
}

start_local_instance() {
  publish_after_ack=$START_CLOSED
  prepare_start_container
  locked_compose start || fail 'bootstrap maintenance container start failed'
  release_start
  if [ "$publish_after_ack" -eq 1 ]; then
    prepare_start_container
    locked_compose start || fail 'configured local start failed'
    release_start
  fi
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

run_scanner_recovery_approval() {
  [ "$MODE" = local ] || fail 'scanner recovery approval is available only for local-auth instances'
  [ -n "$RECOVERY_SOURCE" ] && [ -n "$RECOVERY_RATIONALE" ] && [ -n "$RECOVERY_EVIDENCE_REF" ] \
    || fail 'recovery approval requires --source, --rationale and --evidence-ref'
  running=$(docker container inspect "${PROJECT}-volt-1" --format '{{.State.Running}}' 2>/dev/null) \
    || fail 'VOLT must be running before scanner recovery approval'
  [ "$running" = true ] || fail 'VOLT must be running before scanner recovery approval'
  verify_actual_mounts
  recovery_helper targets-request --instance-root /instance >"$WORK/targets-request.json" \
    || fail 'could not construct the private scanner-target request'
  chmod 600 "$WORK/targets-request.json"
  locked_compose exec -T --user 0:0 volt /usr/local/bin/uvm-local-maintenance \
    scanner-recovery-targets --config /etc/volt/local-auth.json --input - \
    <"$WORK/targets-request.json" >"$WORK/targets-response.json" \
    || fail 'local API did not return current scanner recovery targets'
  chmod 600 "$WORK/targets-response.json"
  docker run --platform "$PLATFORM" --pull=never --rm -i --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --mount "type=bind,src=$STATE,dst=/instance,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.recovery_authority \
    select-target --request-stdin --source "$RECOVERY_SOURCE" --rationale "$RECOVERY_RATIONALE" \
    --evidence-ref "$RECOVERY_EVIDENCE_REF" <"$WORK/targets-response.json" >"$WORK/recovery-request.json" \
    || fail 'source label did not identify exactly one scanner'
  chmod 600 "$WORK/recovery-request.json"
  locked_compose exec -T --user 0:0 volt /usr/local/bin/uvm-local-maintenance \
    scanner-recovery-request --config /etc/volt/local-auth.json --input - \
    <"$WORK/recovery-request.json" >"$WORK/approval-request.json" \
    || fail 'local API refused the fresh scanner recovery request'
  chmod 600 "$WORK/approval-request.json"
  docker run --platform "$PLATFORM" --pull=never --rm -i --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$STATE/secrets/local-recovery-authority/operator.key,dst=/authority/operator.key,readonly" \
    --mount "type=bind,src=$STATE/secrets/local-recovery-authority/operator.pub,dst=/authority/operator.pub,readonly" \
    --mount "type=bind,src=$STATE/secrets/local-recovery-authority/issuer.pub,dst=/authority/issuer.pub,readonly" \
    --mount "type=bind,src=$STATE/secrets/local-recovery-authority/host.json,dst=/authority/host.json,readonly" \
    --mount "type=bind,src=$STATE/secrets/local-restore-fence,dst=/authority/fence,readonly" \
    --mount "type=bind,src=$STATE/instance.json,dst=/authority/instance.json,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.recovery_authority \
    approve --request-stdin --authority-config /authority/host.json \
    <"$WORK/approval-request.json" >"$WORK/approval.json" \
    || fail 'offline host recovery authority rejected the request'
  chmod 600 "$WORK/approval.json"
  locked_compose exec -T --user 0:0 volt /usr/local/bin/uvm-local-maintenance \
    scanner-recovery-import --config /etc/volt/local-auth.json --input - \
    <"$WORK/approval.json" >"$WORK/import-receipt.json" \
    || fail 'local API rejected the signed operator approval'
  chmod 600 "$WORK/import-receipt.json"
  docker run --platform "$PLATFORM" --pull=never --rm -i --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" -m uvm.installer.recovery_authority \
    summarize-import --request-stdin --source "$RECOVERY_SOURCE" <"$WORK/import-receipt.json"
}

run_maintenance() {
  operation=$1; shift
  locked_compose exec -T --user 0:0 volt /usr/local/bin/uvm-local-maintenance "$operation" --config /etc/volt/local-auth.json "$@" \
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
RECOVERY_COMMAND=''
if [ "$ACTION" = recovery ]; then
  [ "$#" -ge 1 ] && [ "$1" = approve-scanner ] \
    || fail 'usage: recovery approve-scanner --source LABEL --rationale TEXT --evidence-ref TEXT'
  RECOVERY_COMMAND=$1
  shift
fi
STATE=''
HTTP_PORT=8180
USERNAME=''
DISPLAY_NAME=''
OPERATION=''
PROJECT_PREFIX='volt-easy'
CONFIRM_PROJECT=''
REMOVE_STATE=0
BACKUP_DIRECTORY=''
BACKUP_OPERATION_ID=''
BACKUP_IDENTITY_SHA256=''
RECOVERY_SOURCE=''
RECOVERY_RATIONALE=''
RECOVERY_EVIDENCE_REF=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --directory) [ "$#" -ge 2 ] || fail '--directory needs a path'; STATE=$2; shift 2 ;;
    --port) [ "$#" -ge 2 ] || fail '--port needs a value'; HTTP_PORT=$2; shift 2 ;;
    --username) [ "$#" -ge 2 ] || fail '--username needs a value'; USERNAME=$2; shift 2 ;;
    --display-name) [ "$#" -ge 2 ] || fail '--display-name needs a value'; DISPLAY_NAME=$2; shift 2 ;;
    --project-prefix) [ "$#" -ge 2 ] || fail '--project-prefix needs a value'; PROJECT_PREFIX=$2; shift 2 ;;
    --confirm-project) [ "$#" -ge 2 ] || fail '--confirm-project needs a value'; CONFIRM_PROJECT=$2; shift 2 ;;
    --source) [ "$#" -ge 2 ] || fail '--source needs a value'; RECOVERY_SOURCE=$2; shift 2 ;;
    --rationale) [ "$#" -ge 2 ] || fail '--rationale needs a value'; RECOVERY_RATIONALE=$2; shift 2 ;;
    --evidence-ref) [ "$#" -ge 2 ] || fail '--evidence-ref needs a value'; RECOVERY_EVIDENCE_REF=$2; shift 2 ;;
    --remove-state) REMOVE_STATE=1; shift ;;
    --backup-directory) [ "$#" -ge 2 ] || fail '--backup-directory needs a new path'; BACKUP_DIRECTORY=$2; shift 2 ;;
    --operation-id) [ "$#" -ge 2 ] || fail '--operation-id needs the original UUID'; BACKUP_OPERATION_ID=$2; shift 2 ;;
    --identity-sha256) [ "$#" -ge 2 ] || fail '--identity-sha256 needs the original identity digest'; BACKUP_IDENTITY_SHA256=$2; shift 2 ;;
    prepare-setup|rotate-setup|create-account|issue-enrolment|issue-recovery|disable-account|revoke-capabilities)
      [ -z "$OPERATION" ] || fail 'only one maintenance operation is allowed'; OPERATION=$1; shift ;;
    *) fail "unsupported argument: $1" ;;
  esac
done
if [ "$ACTION" != backup-status ] && { [ -n "$BACKUP_OPERATION_ID" ] || [ -n "$BACKUP_IDENTITY_SHA256" ]; }; then
  fail 'backup readback identities cannot select or authorize a writer'
fi
case "$HTTP_PORT" in ''|*[!0-9]*) fail 'HTTP port must be a numeric TCP port' ;; esac
[ "$HTTP_PORT" -ge 1024 ] && [ "$HTTP_PORT" -le 65532 ] || fail 'HTTP port leaves no room for the recovery and reserved service ports'
if [ -n "$STATE" ]; then
  case "$STATE" in /*) ;; *) STATE="$PWD/$STATE" ;; esac
else
  [ -n "${HOME:-}" ] || fail 'HOME is not set; pass --directory explicitly'
  STATE="$HOME/.local/share/volt/instance"
fi
while [ "$STATE" != / ] && [ "${STATE%/}" != "$STATE" ]; do STATE=${STATE%/}; done
case "$STATE" in *,*|*:* ) fail 'instance path cannot contain commas or colons for Docker bind mounts' ;; esac

if [ "$ACTION" = install ]; then
  parent=$(dirname -- "$STATE")
  mkdir -p "$parent"
  parent=$(cd -P -- "$parent" && pwd -P) || fail 'could not resolve the private instance parent directory'
  state_name=${STATE##*/}
  case "$state_name" in ''|.|..) fail 'instance directory name is unsafe' ;; esac
  STATE="$parent/$state_name"
  [ "$STATE" = "$CACHE_STATE" ] || fail 'canonical selected instance changed during independent admission'
  [ ! -e "$STATE" ] && [ ! -L "$STATE" ] || fail 'refusing an existing instance directory'
  mkdir -m 700 "$STATE"
  INSTALLING=1
  mkdir -m 700 "$STATE/compose"
  cp "$PACKAGE/compose.yaml" "$PACKAGE/local.yaml" "$PACKAGE/local-restore.yaml" "$STATE/compose/"
  OWNER_TOKEN=$(docker run --platform "$PLATFORM" --pull=never --rm --network none --read-only --cap-drop=ALL \
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
  docker run --platform "$PLATFORM" --pull=never --rm --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$PACKAGE,dst=/package,readonly" \
    --entrypoint /opt/uvm/venv/bin/python "$IMAGE_REF" \
    /package/setup.py init /state --mode local --project "$PROJECT" --image "$IMAGE_REF" \
    --platform "$PLATFORM" --http-port "$HTTP_PORT" --recovery-port "$((HTTP_PORT + 1))" \
    --oidc-port "$((HTTP_PORT + 2))" --runtime-prepare --emit-runtime-init-request --admitted-image-id "$IMAGE_ID" \
    --admitted-image-id-kind "$IMAGE_ID_KIND" --admitted-engine-image-id "$IMAGE_ENGINE_ID" \
    --admitted-image-config-id "$IMAGE_CONFIG_ID" --admitted-selected-descriptor "$SELECTED_DESCRIPTOR" \
    --admitted-source-revision "$SOURCE_REVISION" --admitted-source-snapshot "$SOURCE_SNAPSHOT" \
    --admitted-version "$IMAGE_VERSION" --owner-token "$OWNER_TOKEN" \
    --admitted-installer-json "$INSTALLER_PIN_JSON" --admitted-cache-stage "$CACHE_STAGE" \
    --network-subnet "$SUBNET" --network-gateway "$GATEWAY" \
    --runtime-compose-directory "$STATE/compose" --host-instance-directory "$STATE" \
    >"$WORK/runtime-init-request.json" || fail 'fixed initialization request emission failed'
  chmod 600 "$WORK/runtime-init-request.json"
  graph_verifier initial --offline-artifacts --expected-verifier-reference "$VERIFIER_IMAGE" --bind-initial-request \
    >"$WORK/init-admission.json" || fail 'fresh original graph does not bind this exact initial request'
  chmod 600 "$WORK/init-admission.json"
  take_lock "$WORK/runtime-init-request.json"
  publish_installer_cache
  MODE=local
  prepare_local_custody
else
  [ -d "$STATE" ] && [ ! -L "$STATE" ] || fail 'instance directory is missing or unsafe'
  parent=$(cd -P -- "$(dirname -- "$STATE")" && pwd -P) || fail 'could not resolve the private instance parent directory'
  state_name=${STATE##*/}
  case "$state_name" in ''|.|..) fail 'instance directory name is unsafe' ;; esac
  STATE="$parent/$state_name"
  [ "$STATE" = "$CACHE_STATE" ] || fail 'canonical selected instance changed during independent admission'
  if [ "$INITIAL_PREPARATION" -eq 1 ] || [ "$CACHE_DIRECTORY" != "$CACHE_PARENT/originals" ]; then
    take_lock
    refresh_installer_admission
    if [ "$CACHE_DIRECTORY" != "$CACHE_PARENT/originals" ]; then publish_installer_cache; fi
    if [ "$INITIAL_PREPARATION" -eq 1 ]; then MODE=local; prepare_local_custody; fi
  fi
  read_instance
fi

read_instance
case "$ACTION" in
  backup-status) run_backup_status; exit 0 ;;
  backup-record|restore-provision|restore-admit) run_offline_action; exit 0 ;;
esac
take_lock
refresh_installer_admission
read_instance
validate_local_custody
check_owned_resources
if [ "$ACTION" = install ]; then
  locked_compose config --quiet || fail 'resolved local Compose configuration failed validation'
  start_local_instance
  copy_capability "$STATE/secrets/bootstrap-capability-output" prepare-setup
  show_capability "$STATE/secrets/bootstrap-capability-output"
  printf 'instance=%s\n' "$STATE"
elif [ "$ACTION" = start ]; then
  if [ "$RESTORE_PENDING" -eq 1 ]; then
    [ "$RESTORE_IMPORTED" -eq 1 ] || fail 'restored stores lack offline admission; runtime remains stopped'
  fi
  start_local_instance
elif [ "$ACTION" = stop ]; then
  verify_actual_mounts
  locked_compose stop --timeout 600
elif [ "$ACTION" = status ]; then
  verify_actual_mounts
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
elif [ "$ACTION" = recovery ] && [ "$RECOVERY_COMMAND" = approve-scanner ]; then
  run_scanner_recovery_approval
elif [ "$ACTION" = destroy ]; then
  [ "$CONFIRM_PROJECT" = "$PROJECT" ] || fail 'destroy requires --confirm-project with the exact owned project name'
  locked_compose down --timeout 600 --volumes
  if [ "$REMOVE_STATE" -eq 1 ]; then
    [ -n "$STATE" ] && [ "$STATE" != / ] || fail 'refusing unsafe private-state removal'
    if [ -n "$LOCK_NAME" ]; then docker rm -f "$LOCK_NAME" >/dev/null; LOCK_NAME=''; fi
    rm -rf "$STATE"
  fi
else
  fail 'supported commands are install, start, stop, status, setup, account, recovery, and explicit destroy'
fi
