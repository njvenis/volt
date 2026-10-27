#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ ${1-} != --observer-settings-only || $# != 1 ]]; then
  echo 'usage: G7_EVIDENCE_DIR=/absolute/path bash tools/g7_container_journey.sh --observer-settings-only' >&2
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
CONTAINER=volt-g7-observer-journey
ANCHOR_CONTAINER=volt-g7-observer-anchor
IMAGE="volt-g7-observer-dev:$(git -C "$ROOT" rev-parse --short HEAD)"
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

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  for process_file in "$RUN_ROOT"/host/*.pid; do
    [[ -f $process_file ]] || continue
    kill "$(cat "$process_file")" >/dev/null 2>&1 || true
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
  if (( STARTED_CONTAINER )); then
    docker exec -u 0 "$CONTAINER" chmod -R a+rwX /run/uvm-g7-scheduler >/dev/null 2>&1 || true
    docker rm -fv "$CONTAINER" >/dev/null 2>&1
  fi
  if (( STARTED_ANCHOR )); then docker rm -fv "$ANCHOR_CONTAINER" >/dev/null 2>&1; fi
  if (( CREATED_IMAGE )); then docker image rm "$IMAGE" >/dev/null 2>&1; fi
  printf 'container_removed=%s\nanchor_removed=%s\nrunner_exit=%s\n' \
    "$STARTED_CONTAINER" "$STARTED_ANCHOR" "$rc" >"$EVIDENCE/owned-resource-cleanup.txt"
  chmod -R u+rwX "$RUN_ROOT" 2>/dev/null || true
  rm -rf "$RUN_ROOT"
  exit "$rc"
}
trap cleanup EXIT

printf '%s\n' 'G7_EVIDENCE_DIR=/tmp/volt-g7-observer-evidence bash tools/g7_container_journey.sh --observer-settings-only' \
  >"$EVIDENCE/journey-command.txt"
git -C "$ROOT" rev-parse HEAD >"$EVIDENCE/source-revision.txt"
git -C "$ROOT" status --porcelain=v1 >"$EVIDENCE/source-status.txt"
tar -C "$ROOT" --exclude=.git --exclude=node_modules --exclude=.venv \
  --exclude=dist --exclude=build --exclude=.pytest_cache -czf "$EVIDENCE/source-snapshot.tar.gz" .
sha256sum "$EVIDENCE/source-snapshot.tar.gz" >"$EVIDENCE/source-snapshot.sha256"

command -v docker >/dev/null || { echo 'Docker CLI unavailable' >&2; exit 69; }
command -v curl >/dev/null || { echo 'curl unavailable' >&2; exit 69; }
[[ -x /home/nicho/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome ]] || {
  echo 'Playwright Chromium 1228 executable unavailable' >&2; exit 69;
}
PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright node -e \
  "process.stdout.write(require('./ui/node_modules/playwright/package.json').version+'\\n')" \
  >"$EVIDENCE/playwright-version.txt"
df -Pk /tmp >"$EVIDENCE/tmp-space-preflight.txt"
for port in 8000 9000 "$ANCHOR_PORT"; do
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
  -p 127.0.0.1:8000:8000 -p 127.0.0.1:9000:9000 \
  --mount "type=bind,src=$RUN_ROOT/secrets,dst=/run/secrets,readonly" \
  --mount "type=bind,src=$RUN_ROOT/secrets/registry.json,dst=/run/uvm-g7-registry.json,readonly" \
  --mount "type=bind,src=$RUN_ROOT/secrets/host-pub.pem,dst=/run/uvm-g7-host-pub.pem,readonly" \
  --mount "type=bind,src=$RUN_ROOT/scheduler,dst=/run/uvm-g7-scheduler" \
  --env-file "$RUN_ROOT/container.env" "$IMAGE" >"$EVIDENCE/app-container-id.txt"

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

uv run python "$ROOT/tools/g7_observer_fixture.py" link-actor --root "$RUN_ROOT" \
  >"$EVIDENCE/oidc-link.stdout" 2>"$EVIDENCE/oidc-link.stderr"
uv run python "$ROOT/tools/g7_observer_fixture.py" host-config --root "$RUN_ROOT" --image "$IMAGE" --anchor-port "$ANCHOR_PORT" \
  >"$EVIDENCE/host-config.stdout" 2>"$EVIDENCE/host-config.stderr"
PLAYWRIGHT_BROWSERS_PATH=/home/nicho/.cache/ms-playwright \
  node "$ROOT/tools/g7_observer_journey_browser.mjs" \
  --origin http://127.0.0.1:8000 --evidence "$EVIDENCE" --fixture-root "$RUN_ROOT" \
  >"$EVIDENCE/browser-journey.stdout" 2>"$EVIDENCE/browser-journey.stderr"

echo 'G7 observer-settings-only journey completed' | tee "$EVIDENCE/result.txt"
