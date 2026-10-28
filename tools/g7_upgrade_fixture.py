#!/usr/bin/env python3
"""Materialize prior image A from an immutable public source plus a narrow guard overlay."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_once(data: bytes, old: bytes, new: bytes, label: str) -> bytes:
    count = data.count(old)
    if count != 1:
        raise ValueError(f"A overlay expected one {label} anchor, found {count}")
    return data.replace(old, new, 1)


def materialize(source: str, destination: Path, repo: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    source_epoch = int(subprocess.run(["git", "-C", str(repo), "show", "-s", "--format=%ct", source],
        check=True, stdout=subprocess.PIPE, text=True).stdout.strip())
    source_tar = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", source],
        check=True, stdout=subprocess.PIPE).stdout
    source_archive = destination / "source-A.tar"
    source_archive.write_bytes(source_tar)
    context = destination / "context"
    context.mkdir(mode=0o700)
    with tarfile.open(fileobj=__import__("io").BytesIO(source_tar), mode="r:") as archive:
        archive.extractall(context, filter="data")

    dockerfile = context / "Dockerfile.g7"
    old_docker = dockerfile.read_bytes()
    docker_anchor = b"COPY docker/g7/entrypoint.sh /usr/local/bin/uvm-g7-entrypoint\n"
    new_docker = replace_once(old_docker, docker_anchor,
        docker_anchor + b"COPY docker/g7/schema-head /etc/uvm-g7-schema-head\n",
        "runtime schema declaration copy")
    manifest_anchor = b"COPY --from=uvm-build --chown=uvm:uvm /build/alembic.ini ./alembic.ini\n"
    new_docker = replace_once(new_docker, manifest_anchor, manifest_anchor +
        b"COPY --from=uvm-build --chown=uvm:uvm /build/pyproject.toml ./pyproject.toml\n"
        b"COPY --from=uvm-build --chown=uvm:uvm /build/uv.lock ./uv.lock\n",
        "runtime package manifest copies")
    dockerfile.write_bytes(new_docker)

    entrypoint = context / "docker/g7/entrypoint.sh"
    old_entry = entrypoint.read_bytes()
    initdb_anchor = (b"    --auth-local=peer --auth-host=scram-sha-256\n"
        b"fi\nchown -R postgres:postgres \"$PGDATA\"")
    initdb_replacement = (b"    --auth-local=peer --auth-host=scram-sha-256\n"
        b"  PG_CLUSTER_INITIALIZED=1\nelse\n  PG_CLUSTER_INITIALIZED=0\nfi\n"
        b"chown -R postgres:postgres \"$PGDATA\"")
    new_entry = replace_once(old_entry, initdb_anchor, initdb_replacement,
        "empty-cluster initialization marker")
    psql_anchor = b"psql_local() { setpriv --reuid=postgres --regid=postgres --init-groups psql -X -v ON_ERROR_STOP=1 -h /var/run/postgresql \"$@\"; }\n"
    guard = b'''\
G7_SCHEMA_MODE=${UVM_G7_SCHEMA_MODE:-normal}
G7_SCHEMA_DECLARED_HEAD=$(cat /etc/uvm-g7-schema-head)
G7_SCHEMA_COMPAT_ADMITTED=0
if [[ $G7_SCHEMA_MODE != normal ]]; then
  echo 'G7_SCHEMA_COMPATIBILITY_REJECTED reason=prior-image-allows-normal-only' >&2; exit 70
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
/opt/uvm/venv/bin/python -m uvm.operations.schema_compatibility \\
  --declared-head "$G7_SCHEMA_DECLARED_HEAD" --mode "$G7_SCHEMA_MODE" \\
  --heads-json "$G7_SCHEMA_HEADS" \\
  $([[ ${PG_CLUSTER_INITIALIZED:-0} == 1 ]] && printf '%s' --empty-cluster)
'''
    new_entry = replace_once(new_entry, psql_anchor, psql_anchor + guard,
        "pre-initialization schema-head guard")
    entrypoint.write_bytes(new_entry)

    # The validator is a public build input from this candidate's narrow overlay.
    overlay = repo / "uvm/operations/schema_compatibility.py"
    (context / "uvm/operations/schema_compatibility.py").write_bytes(overlay.read_bytes())
    schema_head = b"0058\n"
    (context / "docker/g7/schema-head").write_bytes(schema_head)

    # Docker COPY layers include source mtimes. Normalize generated overlay
    # files and the extracted archive to the immutable source commit time.
    for path in context.rglob("*"):
        os.utime(path, (source_epoch, source_epoch), follow_symlinks=False)

    diff = "".join(difflib.unified_diff(old_docker.decode().splitlines(True),
        new_docker.decode().splitlines(True), fromfile="a/Dockerfile.g7", tofile="b/Dockerfile.g7"))
    diff += "".join(difflib.unified_diff(old_entry.decode().splitlines(True),
        new_entry.decode().splitlines(True), fromfile="a/docker/g7/entrypoint.sh",
        tofile="b/docker/g7/entrypoint.sh"))
    (destination / "overlay.patch").write_text(diff)
    (destination / "schema-compatibility.py").write_bytes(overlay.read_bytes())
    (destination / "schema-head").write_bytes(schema_head)
    context_tar = destination / "context-A.tar"
    with tarfile.open(context_tar, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(context.rglob("*")):
            def normalize(info):
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = source_epoch
                return info
            archive.add(path, arcname=path.relative_to(context), recursive=False, filter=normalize)
    manifest = {"schema_version": 1, "source_revision": source,
        "source_archive_sha256": sha(source_tar), "overlay_patch_sha256": sha(diff.encode()),
        "schema_compatibility_sha256": sha(overlay.read_bytes()),
        "schema_head_sha256": sha(schema_head), "context_archive_sha256": sha(context_tar.read_bytes()),
        "declared_schema_head": "0058", "label": "NO-GO historical development fixture"}
    (destination / "fixture-manifest.json").write_text(json.dumps(manifest,
        sort_keys=True, separators=(",", ":")) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = materialize(args.source, args.destination, args.repo.resolve())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
