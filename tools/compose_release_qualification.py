#!/usr/bin/env python3
"""Opt-in, one-image source-free Compose release qualification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def run(name: str, argv: list[str], evidence: Path, *, input_text: str | None = None,
        env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, text=True, input=input_text, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    (evidence / f"{name}.stdout").write_text(result.stdout)
    (evidence / f"{name}.stderr").write_text(result.stderr)
    (evidence / f"{name}.exit").write_text(f"{result.returncode}\n")
    if check and result.returncode:
        raise RuntimeError(f"{name} failed ({result.returncode}); see retained evidence")
    return result


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run_getpass(name: str, argv: list[str], evidence: Path, secret: str) -> subprocess.CompletedProcess:
    """Feed the protected prompt through a PTY without retaining the secret."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 1)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                _, status = os.waitpid(pid, 0)
                code = os.waitstatus_to_exitcode(status)
                text = output.decode(errors="replace")
                (evidence/f"{name}.stdout").write_text(text)
                (evidence/f"{name}.stderr").write_text("")
                (evidence/f"{name}.exit").write_text(f"{code}\n")
                if not sent or code:
                    raise RuntimeError(f"{name} failed ({code}); see retained evidence")
                return subprocess.CompletedProcess(argv, code, text, "")
            output.extend(chunk)
            if not sent and b"Authenticated uvm_session cookie value:" in output:
                os.write(fd, secret.encode() + b"\n")
                sent = True
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            code = os.waitstatus_to_exitcode(status)
            text = output.decode(errors="replace")
            (evidence/f"{name}.stdout").write_text(text)
            (evidence/f"{name}.stderr").write_text("")
            (evidence/f"{name}.exit").write_text(f"{code}\n")
            if not sent or code:
                raise RuntimeError(f"{name} failed ({code}); see retained evidence")
            return subprocess.CompletedProcess(argv, code, text, "")
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    text=output.decode(errors="replace")
    (evidence/f"{name}.stdout").write_text(text)
    (evidence/f"{name}.stderr").write_text("PTY prompt timed out or closed")
    (evidence/f"{name}.exit").write_text("124\n")
    raise RuntimeError(f"{name} timed out or closed before consuming the protected session cookie")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image-id", required=True)
    p.add_argument("--source-snapshot", required=True)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--version", default="0.1.0-rc.2")
    p.add_argument("--development-fixture", action="store_true",
                   help="label evidence as development-only when testing the runner against a non-RC2 image")
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    args = p.parse_args()
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}",args.image_id)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}",args.source_snapshot)
            or not re.fullmatch(r"[0-9a-f]{40}",args.source_commit)):
        p.error("immutable image ID and source snapshot SHA-256 are required")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(evidence, 0o700)
    private = Path(tempfile.mkdtemp(prefix="volt-rc2-compose-", dir="/tmp"))
    os.chmod(private, 0o700)
    project = f"volt-rc2-qual-{os.getpid()}"
    state = private / "instance"
    extracted = private / "bundle"
    cookie = private / "cookie"
    setup = None
    cleanup_result = 0
    started = False
    outcome = 0
    try:
        run("bundle-verify", [sys.executable, str(ROOT / "tools/build_compose_bundle.py"),
            "verify", "--archive", str(args.bundle)], evidence)
        shutil.unpack_archive(str(args.bundle), extracted, "gztar")
        candidates = list(extracted.glob("*/setup.py"))
        if len(candidates) != 1:
            raise RuntimeError("bundle did not extract to one source-free setup.py")
        setup = candidates[0]
        if ROOT in setup.parents:
            raise RuntimeError("source-free bundle extraction unexpectedly overlaps checkout")
        ports = [int(18000 + os.getpid() % 1000), int(19000 + os.getpid() % 1000), int(20000 + os.getpid() % 1000)]
        cli = [sys.executable, str(setup)]
        run("init", [*cli,"init",str(state),"--mode","demo","--project",project,
             "--http-port",str(ports[0]),"--recovery-port",str(ports[0]+1),"--oidc-port",str(ports[2]),"--image",args.image_id], evidence)
        info = json.loads((state / "instance.json").read_text())
        admission = info["image_admission"]
        bundle_version = (setup.parent/"VERSION").read_text().strip()
        if bundle_version != "0.1.0-rc.2":
            raise RuntimeError("qualification bundle must be the versioned RC2 Compose bundle")
        if (admission["id"] != args.image_id or admission["source_snapshot"] != args.source_snapshot
                or admission["source_revision"] != args.source_commit):
            raise RuntimeError("installed image admission did not match the candidate image/source snapshot/revision")
        if admission["version"] != args.version and not args.development_fixture:
            raise RuntimeError("release qualification requires an image built for the requested RC2 version")
        if info.get("mode") != "demo":
            raise RuntimeError("qualification must use the explicitly labelled synthetic demo mode")
        run("start", [*cli,"start",str(state)], evidence); started = True
        run("health", [sys.executable,"-c",f"import sys;sys.path.insert(0,{str(ROOT)!r});from deploy.compose.setup import load_instance,wait_until_ready;wait_until_ready(load_instance({str(state)!r})[1]);print('healthy')"],evidence)
        binding = run("private-loopback-binding", ["docker","port",f"{project}-volt-1","8000/tcp"],evidence)
        if not binding.stdout.strip().startswith("127.0.0.1:"):
            raise RuntimeError("Compose HTTP listener is not bound to loopback")
        ingress_info = {"container":f"{project}-volt-1","network":f"{project}_network",
                        "image":args.image_id,"owner_token":"volt-rc2-qualification-probe"}
        probe = (f"import sys;from pathlib import Path;sys.path.insert(0,{str(ROOT)!r});"
                 f"from tools.g7_local_preview import verify_private_ingress;"
                 f"verify_private_ingress({ingress_info!r},Path({str(evidence)!r}))")
        run("private-peer-ingress-denial",[sys.executable,"-c",probe],evidence)
        run("link-admin", [*cli,"link-admin",str(state)], evidence)
        origin = f"http://127.0.0.1:{ports[0]}"
        run("browser-login", ["node",str(ROOT/"tools/compose_release_login.mjs"),origin,str(cookie)], evidence)
        run_getpass("initialize-authority", [*cli,"initialize-authority",str(state)], evidence,
                    cookie.read_text())
        cookie.unlink(missing_ok=True)
        smoke = ["node",str(ROOT/"tools/g7_local_preview_smoke.mjs"),"--origin",origin,
                 "--issuer",f"http://127.0.0.1:{ports[2]}","--subject","volt-compose-demo-admin-subject",
                 "--principal","volt-compose-demo-admin","--evidence",str(evidence)]
        run("audited-operation", smoke, evidence)
        run("stop", [*cli,"stop",str(state)], evidence); started = False
        run("restart", [*cli,"start",str(state)], evidence); started = True
        run("restart-health", [sys.executable,"-c",f"import sys;sys.path.insert(0,{str(ROOT)!r});from deploy.compose.setup import load_instance,wait_until_ready;wait_until_ready(load_instance({str(state)!r})[1]);print('healthy')"],evidence)
        run("restart-readback", ["node",str(ROOT/"tools/g7_local_preview_smoke.mjs"),"--origin",origin,
            "--issuer",f"http://127.0.0.1:{ports[2]}","--subject","volt-compose-demo-admin-subject",
            "--principal","volt-compose-demo-admin","--evidence",str(evidence),"--readback"], evidence)
        run("cold-stop", [*cli,"stop",str(state)], evidence); started = False
        run("backup-record", [*cli,"backup-record",str(state)], evidence)
        inventories = json.loads((state/"instance.json").read_text())["backup_inventory"]
        (evidence/"store-inventories.json").write_text(json.dumps(inventories,sort_keys=True,indent=2)+"\n")
        backup = private/"backup"; backup.mkdir()
        for store in ("postgres","media","state"):
            name=f"{project}_{store}"
            run(f"backup-{store}",["docker","run","--rm","--network","none","--mount",f"type=volume,src={name},dst=/source,readonly",
                "--mount",f"type=bind,src={backup},dst=/backup","--entrypoint","/bin/bash",args.image_id,
                "-lc",f"cd /source && tar -cf /backup/{store}.tar ."],evidence)
        if any(not (backup/f"{store}.tar").is_file() or (backup/f"{store}.tar").stat().st_size == 0
               for store in ("postgres","media","state")):
            raise RuntimeError("cold backup did not create all three private store archives")
        saved_state = private/"established-instance"
        shutil.copytree(state,saved_state)
        wrong_image = json.loads((saved_state/"instance.json").read_text())
        wrong_image["image"] = "sha256:"+"0"*64
        (saved_state/"instance.json").write_text(json.dumps(wrong_image,indent=2)+"\n")
        image_negative = run("restore-image-binding-negative", [*cli,"restore-provision",str(saved_state)], evidence,check=False)
        if image_negative.returncode == 0:
            raise RuntimeError("restore provisioning accepted a different image identity")
        shutil.copy2(state/"instance.json", saved_state/"instance.json")
        run("destroy-before-restore", [*cli,"cleanup",str(state),"--remove-data","--confirm-project",project], evidence)
        if state.exists(): state.rmdir()
        shutil.copytree(saved_state,state)
        # Provision only the three uniquely owned volumes and network; imports precede admission/start.
        run("restore-provision", [*cli,"restore-provision",str(state)], evidence)
        corrupted = backup/"corrupt-state.tar"
        with tarfile.open(backup/"state.tar","r:*") as original, tarfile.open(corrupted,"w:gz") as damaged:
            for item in original.getmembers():
                if item.isfile(): damaged.addfile(item,original.extractfile(item))
                else: damaged.addfile(item)
            content=b"corruption-probe\n"; member=tarfile.TarInfo(".volt-corruption-probe")
            member.size=len(content); damaged.addfile(member,__import__("io").BytesIO(content))
        # Try an incomplete import first; it must fail closed before any writer starts.
        negative = run("restore-inventory-empty-negative", [*cli,"restore-admit",str(state)], evidence,check=False)
        if negative.returncode == 0:
            raise RuntimeError("restore admission accepted empty volumes before import")
        for store in ("postgres","media","state"):
            name=f"{project}_{store}"
            selected_archive = "corrupt-state.tar" if store == "state" else f"{store}.tar"
            run(f"restore-import-{store}",["docker","run","--rm","--network","none","--mount",f"type=volume,src={name},dst=/target",
                "--mount",f"type=bind,src={backup},dst=/backup,readonly","--entrypoint","/bin/bash",args.image_id,
                "-lc",f"cd /target && tar -xf /backup/{selected_archive}"],evidence)
        corrupted_check = run("restore-inventory-corruption-negative", [*cli,"restore-admit",str(state)], evidence,check=False)
        if corrupted_check.returncode == 0:
            raise RuntimeError("restore admission accepted corrupted store inventory")
        name=f"{project}_state"
        run("restore-clear-corrupt-state",["docker","run","--rm","--network","none","--mount",f"type=volume,src={name},dst=/target",
            "--entrypoint","/bin/bash",args.image_id,"-lc","find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +"],evidence)
        run("restore-import-state",["docker","run","--rm","--network","none","--mount",f"type=volume,src={name},dst=/target",
            "--mount",f"type=bind,src={backup},dst=/backup,readonly","--entrypoint","/bin/bash",args.image_id,
            "-lc","cd /target && tar -xf /backup/state.tar"],evidence)
        run("restore-admit", [*cli,"restore-admit",str(state)], evidence)
        run("restore-start", [*cli,"start",str(state)], evidence); started=True
        run("restore-health", [sys.executable,"-c",f"import sys;sys.path.insert(0,{str(ROOT)!r});from deploy.compose.setup import load_instance,wait_until_ready;wait_until_ready(load_instance({str(state)!r})[1]);print('healthy')"],evidence)
        run("restore-readback", ["node",str(ROOT/"tools/g7_local_preview_smoke.mjs"),"--origin",origin,
            "--issuer",f"http://127.0.0.1:{ports[2]}","--subject","volt-compose-demo-admin-subject",
            "--principal","volt-compose-demo-admin","--evidence",str(evidence),"--readback"], evidence)
        # The exact-owner cleanup below performs the final stop and removes only
        # this private project, avoiding a second graceful stop before cleanup.
        (evidence/"qualification.json").write_text(json.dumps({"result":"passed",
            "qualification_scope":"development_fixture" if args.development_fixture else "hosted_rc2_release",
            "release_version":bundle_version,"image_id":args.image_id,
            "source_revision":admission["source_revision"],"image_version":admission["version"],
            "source_snapshot":args.source_snapshot,"bundle_sha256":sha(args.bundle),"bundle_version":"0.1.0-rc.2",
            "project":project,"synthetic_demo":True,"health":"passed","audited_operation":"passed",
            "demo_mode":"passed","loopback_binding":"passed","private_peer_ingress_denial":"passed",
            "restart_readback":"passed","cold_backup_inventories":3,"image_binding_rejection":"passed",
            "corrupt_inventory_rejection":"passed","restore_readback":"passed"},indent=2)+"\n")
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        outcome = 1
    finally:
        cookie.unlink(missing_ok=True)
        if state.exists() and setup:
            try:
                # cleanup verifies per-resource owner labels and removes only this unique project.
                result=subprocess.run([sys.executable,str(setup),"cleanup",str(state),"--remove-data","--confirm-project",project],
                    text=True,capture_output=True)
                for suffix, value in (("stdout",result.stdout),("stderr",result.stderr)):
                    (evidence/f"owned-cleanup.{suffix}").write_text(value)
                (evidence/"owned-cleanup.exit").write_text(f"{result.returncode}\n")
                cleanup_result=result.returncode
            except Exception:
                cleanup_result=1
        shutil.rmtree(private,ignore_errors=True)
        if cleanup_result:
            print("owned Compose cleanup failed; inspect the exact project resources before retry",file=sys.stderr)
    return 1 if cleanup_result else outcome


if __name__ == "__main__":
    raise SystemExit(main())
