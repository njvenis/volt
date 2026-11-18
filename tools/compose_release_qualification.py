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
import secrets
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.release.easy_bootstrap import COSIGN_IMAGE, ISSUER, SIGNER


SUPPORTED_PLATFORMS = ("linux/amd64", "linux/arm64")
SUPPORTED_RELEASE_VERSIONS = ("0.1.0-rc.2", "0.1.0-rc.3")
SUPPORTED_IMAGE_VERSIONS = (*SUPPORTED_RELEASE_VERSIONS, "0.1.0-rc.4", "0.1.0-demo")


def qualification_scope(*, version: str, development_fixture: bool,
                        local_auth_fixture: bool = False,
                        environment: dict[str, str] | None = None) -> str:
    """Classify evidence from how it ran, never from the image's release label."""
    if development_fixture or local_auth_fixture:
        if version not in SUPPORTED_IMAGE_VERSIONS:
            raise ValueError("development fixture scope requires an explicitly supported fixture image version")
        return "development_fixture"
    if version not in SUPPORTED_RELEASE_VERSIONS:
        raise ValueError("release qualification scope requires a supported RC2 or RC3 version")
    context = os.environ if environment is None else environment
    release = version.removeprefix("0.1.0-").replace(".", "")
    if (context.get("GITHUB_ACTIONS", "").lower() == "true"
            and context.get("RUNNER_ENVIRONMENT", "").lower() == "github-hosted"):
        return f"hosted_{release}_release"
    return f"local_synthetic_{release}"


def verified_bundle_version(output: str) -> str:
    """Read the version reported by the maintained, closed-inventory verifier."""
    match = re.search(r"(?m)^verified_version=(0\.1\.0-rc\.[234])(?:\s|$)", output)
    if match is None:
        raise RuntimeError("verified Compose bundle did not report a supported release version")
    return match.group(1)


def admit_bundle_version(output: str, requested_version: str, *, development_fixture: bool = False,
                         local_auth_fixture: bool = False) -> str:
    """Accept only the exact requested RC version reported by bundle verification."""
    if requested_version not in SUPPORTED_IMAGE_VERSIONS:
        raise RuntimeError("qualification accepts only fixed RC2/RC3, local-auth RC4 fixture or explicit demo versions")
    if requested_version == "0.1.0-demo" and not development_fixture:
        raise RuntimeError("the demo image version requires explicit development-fixture mode")
    if requested_version == "0.1.0-rc.4" and not local_auth_fixture:
        raise RuntimeError("the future RC4 candidate is accepted only in local-auth fixture qualification")
    bundle_version = verified_bundle_version(output)
    if requested_version == "0.1.0-demo" and bundle_version != "0.1.0-rc.3":
        raise RuntimeError("the local demo must use the marked RC3 compatibility installer")
    if requested_version in SUPPORTED_RELEASE_VERSIONS and bundle_version != requested_version:
        raise RuntimeError(f"requested release {requested_version} does not match verified Compose bundle {bundle_version}")
    return bundle_version


def compose_bundle_verify_command(bundle: Path, *, version: str, development_fixture: bool,
                                  local_auth_fixture: bool) -> list[str]:
    """Return the fixed verifier argv, enabling demo compatibility only for its explicit fixture."""
    command = [sys.executable, str(ROOT / "tools/build_compose_bundle.py"),
               "verify", "--archive", str(bundle)]
    if local_auth_fixture:
        command.append("--local-admission-fixture")
    if version == "0.1.0-demo" and development_fixture and not local_auth_fixture:
        command.append("--allow-local-demo-compatibility")
    return command


def qualification_release_metadata(*, requested_version: str, bundle_version: str,
                                   image_version: str, image_id: str, platform: str,
                                   source_revision: str, source_snapshot: str,
                                   bundle_sha256: str, scope: str) -> dict[str, str]:
    """Keep requested release, verified bundle and admitted image identities distinct."""
    return {
        "qualification_scope": scope,
        "release_version": bundle_version,
        "requested_image_version": requested_version,
        "bundle_version": bundle_version,
        "image_version": image_version,
        "image_id": image_id,
        "platform": platform,
        "source_revision": source_revision,
        "source_snapshot": source_snapshot,
        "bundle_sha256": bundle_sha256,
    }


def platform_from_image_inspect(output: str, declared_platform: str | None = None) -> str:
    """Admit only an image whose Docker config matches the package platform."""
    try:
        rows = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Docker image inspection was not valid JSON") from exc
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("Docker image inspection did not identify exactly one image")
    platform = f"{rows[0].get('Os')}/{rows[0].get('Architecture')}"
    if platform not in SUPPORTED_PLATFORMS:
        raise RuntimeError(f"Docker image platform {platform} is not supported")
    if declared_platform is not None and declared_platform != platform:
        raise RuntimeError("verified package platform disagrees with Docker image inspection")
    return platform


def init_command(cli: list[str], state: Path, project: str, ports: list[int],
                 image_id: str, platform: str) -> list[str]:
    if platform not in SUPPORTED_PLATFORMS:
        raise RuntimeError("installer platform is not supported")
    return [*cli, "init", str(state), "--mode", "demo", "--project", project,
        "--http-port", str(ports[0]), "--recovery-port", str(ports[0] + 1),
        "--oidc-port", str(ports[2]), "--image", image_id, "--platform", platform,
        "--bootstrap-principal", "volt-compose-demo-admin", "--demo-subject",
        "volt-compose-demo-admin-subject", "--demo-admin-username", "qualification-admin"]


def run(name: str, argv: list[str], evidence: Path, *, input_text: str | None = None,
        env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    (evidence / f"{name}.argv.json").write_text(json.dumps(argv, indent=2) + "\n")
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


def render_fixture_launcher(source: Path, destination: Path, fixture: Path) -> str:
    """Copy an already pinned fixture launcher without changing signed bytes."""
    verifier_pin = fixture / "verifier.ref"
    if verifier_pin.is_symlink() or not verifier_pin.is_file():
        raise RuntimeError("fixture verifier ref must be independently provisioned before launcher rendering")
    reference = verifier_pin.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"127\.0\.0\.1:46150/volt-installer-verifier@sha256:[0-9a-f]{64}", reference):
        raise RuntimeError("fixture verifier ref is not a pinned image from the owned loopback registry")
    text = source.read_text(encoding="utf-8")
    marker = re.search(r"(?m)^VERIFIER_IMAGE='([^']+)'$", text)
    if marker is None or marker.group(1) != reference:
        raise RuntimeError("fixture launcher must already bind the external verifier digest before signing")
    shutil.copyfile(source, destination)
    destination.chmod(0o700)
    return sha(destination)


def scanner_stage_record() -> dict[str, object]:
    """Describe the selected scanner stage without implying a live integration."""
    return {
        "provider": "Qualys",
        "status": "pending",
        "activation_qualified": False,
        "reason": "No accepted packaged Qualys collector and VOLT ingest adapter is available in this candidate.",
    }


def run_getpass(name: str, argv: list[str], evidence: Path,
                secret: str | list[tuple[bytes, str]]) -> subprocess.CompletedProcess:
    """Feed protected prompts through a PTY without retaining their values."""
    (evidence / f"{name}.argv.json").write_text(json.dumps(argv, indent=2) + "\n")
    prompts = ([(b"Authenticated uvm_session cookie value:", secret)]
               if isinstance(secret, str) else secret)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    output = bytearray()
    sent = 0
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
                if sent != len(prompts) or code:
                    raise RuntimeError(f"{name} failed ({code}); see retained evidence")
                return subprocess.CompletedProcess(argv, code, text, "")
            output.extend(chunk)
            while sent < len(prompts) and prompts[sent][0] in output:
                os.write(fd, prompts[sent][1].encode() + b"\n")
                sent += 1
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            code = os.waitstatus_to_exitcode(status)
            text = output.decode(errors="replace")
            (evidence/f"{name}.stdout").write_text(text)
            (evidence/f"{name}.stderr").write_text("")
            (evidence/f"{name}.exit").write_text(f"{code}\n")
            if sent != len(prompts) or code:
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


def validate_admission_fixture(path: Path, *, image_id: str, source_snapshot: str,
                               source_commit: str, platform: str, bundle: Path,
                               version: str, evidence: Path) -> dict[str, str]:
    """Admit the real signed bundle/runtime graph with the independent verifier."""
    if path.is_symlink():
        raise RuntimeError("admission fixture path cannot be a symlink")
    root = path.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("admission fixture must be an independently provisioned directory")
    expected_files = {"fixture.pub", "trusted-root.json", "verifier.ref",
                      "launcher.sigstore.json", "installer.bundle.sigstore.json"}
    actual_files = {item.name for item in root.iterdir()}
    if actual_files != expected_files or any(item.is_symlink() or not item.is_file() for item in root.iterdir()):
        raise RuntimeError("admission fixture must contain only external trust material, a verifier pin, and signed launcher/bundle blobs")
    public_root = evidence / "fixture-trust-public"
    public_root.mkdir(mode=0o755)
    for name in expected_files - {"verifier.ref"}:
        shutil.copyfile(root / name, public_root / name)
        (public_root / name).chmod(0o444)
    verifier_reference = (root / "verifier.ref").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"127\.0\.0\.1:46150/volt-installer-verifier@sha256:[0-9a-f]{64}",
                        verifier_reference):
        raise RuntimeError("fixture verifier ref must be independently pinned in the owned loopback registry")
    for name, artifact, signature in (("installer-bundle", bundle,
            root / "installer.bundle.sigstore.json"),):
        argv = ["docker", "run", "--rm", "--network", "host", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--env", "HOME=/tmp", "--mount", f"type=bind,src={public_root},dst=/fixture,readonly",
        "--mount", f"type=bind,src={artifact},dst=/artifact,readonly", f"{COSIGN_IMAGE}",
        "verify-blob", "--key", "/fixture/fixture.pub", "--trusted-root", "/fixture/trusted-root.json",
        "--bundle", f"/fixture/{signature.name}", "/artifact"]
        run(f"fixture-{name}-signature", argv, evidence)
    # The verifier image itself is signed under the external fixture root. Its
    # provenance is also checked before any verifier code is executed.
    run("fixture-verifier-signature", ["docker", "run", "--rm", "--network", "host", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--mount", f"type=bind,src={public_root},dst=/fixture,readonly", COSIGN_IMAGE, "verify",
        "--key", "/fixture/fixture.pub", "--trusted-root", "/fixture/trusted-root.json",
        verifier_reference], evidence)
    run("fixture-verifier-provenance", ["docker", "run", "--rm", "--network", "host", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--mount", f"type=bind,src={public_root},dst=/fixture,readonly", COSIGN_IMAGE,
        "verify-attestation", "--type", "https://slsa.dev/provenance/v1", "--key", "/fixture/fixture.pub",
        "--trusted-root", "/fixture/trusted-root.json", verifier_reference], evidence)
    with tarfile.open(bundle, "r:gz") as archive:
        manifests = [item for item in archive.getmembers() if item.name.endswith("/manifest.json")]
        if len(manifests) != 1 or not manifests[0].isfile():
            raise RuntimeError("signed installer bundle has no unique regular manifest")
        manifest = json.loads(archive.extractfile(manifests[0]).read())
    if (not isinstance(manifest, dict) or manifest.get("bundle_version") != version
            or version != "0.1.0-rc.4" or manifest.get("verifier_reference") != verifier_reference
            or not isinstance(manifest.get("release_image"), str)
            or not re.fullmatch(r"127\.0\.0\.1:46150/volt@sha256:[0-9a-f]{64}", manifest["release_image"])):
        raise RuntimeError("signed bundle descriptor does not bind the pinned fixture verifier and loopback runtime")
    image_reference = manifest["release_image"]
    run("fixture-runtime-pull", ["docker", "pull", image_reference], evidence)
    inspected = run("fixture-runtime-inspect", ["docker", "image", "inspect", image_reference], evidence)
    try:
        image_row = json.loads(inspected.stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise RuntimeError("fixture runtime inspection did not return one image") from exc
    if image_row.get("Id") != image_id:
        raise RuntimeError("fixture runtime config ID differs from the requested candidate image ID")
    index = run("fixture-runtime-index", ["docker", "buildx", "imagetools", "inspect", "--raw",
        image_reference], evidence)
    image_json = evidence / "runtime-image-inspect.json"
    index_json = evidence / "runtime-image-index.json"
    image_json.write_text(inspected.stdout, encoding="utf-8")
    index_json.write_text(index.stdout, encoding="utf-8")
    admission_command = ["docker", "run", "--rm", "--network", "host",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m", "--env", "HOME=/tmp", "--mount",
        f"type=bind,src={public_root},dst=/fixture,readonly", "--mount",
        f"type=bind,src={bundle},dst=/bundle.tar.gz,readonly", "--mount",
        f"type=bind,src={public_root / 'installer.bundle.sigstore.json'},dst=/bundle.sigstore.json,readonly",
        "--mount", f"type=bind,src={image_json},dst=/runtime-image.json,readonly", "--mount",
        f"type=bind,src={index_json},dst=/runtime-index.json,readonly", verifier_reference,
        "--bundle", "/bundle.tar.gz", "--bundle-signature", "/bundle.sigstore.json",
        "--image-inspect", "/runtime-image.json", "--index", "/runtime-index.json",
        "--output-dir", "/tmp/verified", "--reference", image_reference, "--signer", "fixture",
        "--issuer", "fixture", "--source-revision", source_commit, "--source-snapshot", source_snapshot,
        "--version", version, "--platform", platform]
    admission_run = run("fixture-full-runtime-admission", admission_command, evidence)
    qualify_admission_negatives(admission_command, bundle, image_json, index_json, evidence)
    try:
        admitted = json.loads(admission_run.stdout)
        runtime = admitted["runtime"]
        bundle_admission = admitted["bundle"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError("independent verifier did not return a complete runtime graph") from exc
    if runtime.get("image_id") != image_id or runtime.get("platform") != platform:
        raise RuntimeError("independent verifier returned a different image ID or platform")
    result = {"bundle_version": version, "bundle_sha256": bundle_admission["bundle_sha256"],
        "image_id": runtime["image_id"], "image_reference": image_reference,
        "image_index_digest": runtime["image_index_digest"], "source_snapshot": source_snapshot,
        "source_commit": source_commit, "platform": platform,
        "verifier_reference": verifier_reference}
    result["fixture_directory"] = str(root)
    return result

def qualify_admission_negatives(command: list[str], bundle: Path, image_json: Path,
                                 index_json: Path, evidence: Path) -> None:
    """Exercise rejection by the independently admitted verifier before runtime execution."""
    directory = evidence / "admission-negatives"
    directory.mkdir(mode=0o755)
    cases = []
    for name, option, value in (("source-revision", "--source-revision", "0" * 40),
                                ("source-snapshot", "--source-snapshot", "sha256:" + "0" * 64),
                                ("version", "--version", "0.1.0-rc.3"),
                                ("platform", "--platform", "linux/arm64" if command[command.index("--platform") + 1] == "linux/amd64" else "linux/amd64")):
        candidate = list(command)
        candidate[candidate.index(option) + 1] = value
        cases.append((name, candidate))
    damaged_index = directory / "wrong-child-index.json"
    index = json.loads(index_json.read_text())
    index["manifests"][0]["digest"] = "sha256:" + "0" * 64
    damaged_index.write_text(json.dumps(index))
    damaged_image = directory / "wrong-image.json"
    inspected = json.loads(image_json.read_text())
    inspected[0]["Id"] = "sha256:" + "0" * 64
    damaged_image.write_text(json.dumps(inspected))
    damaged_bundle = directory / "tampered-bundle.tar.gz"
    content = bytearray(bundle.read_bytes())
    content[len(content) // 2] ^= 1
    damaged_bundle.write_bytes(content)
    for name, original, replacement in (("index-child", index_json, damaged_index),
                                        ("image-config", image_json, damaged_image),
                                        ("bundle-content", bundle, damaged_bundle)):
        candidate = [argument.replace(f"src={original},", f"src={replacement},") for argument in command]
        replacement.chmod(0o444)
        cases.append((name, candidate))
    for name, candidate in cases:
        result = run("admission-negative-" + name, candidate, evidence, check=False)
        if result.returncode == 0:
            raise RuntimeError(f"independent verifier accepted negative {name}")
    (evidence / "admission-negatives.json").write_text(json.dumps({
        "status": "passed", "before_candidate_execution": True,
        "cases": [name for name, _ in cases]}, sort_keys=True, indent=2) + "\n")


def trusted_launcher_environment(bin_directory: Path, admission: dict) -> dict[str, str]:
    environment = launcher_minimal_environment(bin_directory)
    environment.update({"VOLT_EXPECTED_VERIFIER_IMAGE": admission["verifier_reference"],
        "VOLT_EXPECTED_VERSION": "0.1.0-rc.4", "VOLT_EXPECTED_SIGNER": SIGNER,
        "VOLT_EXPECTED_ISSUER": ISSUER, "VOLT_BOOTSTRAP_VERIFIER_VERIFIED": "1"})
    return environment


def launcher_minimal_environment(bin_directory: Path) -> dict[str, str]:
    """Expose only POSIX utilities and Docker to the installed host launcher."""
    allowed = ("sh", "docker", "tar", "mktemp", "dirname", "mkdir", "chmod", "cp", "rm",
               "cat", "cut", "grep", "env", "id", "sleep", "mv")
    bin_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in allowed:
        source = shutil.which(name)
        if source is None:
            raise RuntimeError(f"launcher qualification host is missing required POSIX/Docker command: {name}")
        (bin_directory / name).symlink_to(source)
    environment = {"PATH": str(bin_directory), "HOME": str(Path.home())}
    for name in ("DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def wait_for_local(origin: str, evidence: Path) -> None:
    code = """import json,sys,time,urllib.error,urllib.request
origin=sys.argv[1]; deadline=time.monotonic()+360
while time.monotonic()<deadline:
 try:
  with urllib.request.urlopen(origin+'/api/v1/auth/config',timeout=3) as r: value=json.load(r)
  if value.get('mode')=='local': print('healthy=1'); raise SystemExit(0)
 except (OSError,urllib.error.URLError,ValueError): pass
 time.sleep(2)
raise SystemExit('local runtime readiness timed out')
"""
    run("local-runtime-health", [sys.executable, "-c", code, origin], evidence)


def protected_local_readback(origin: str, cookie_file: Path, expected_installation: str,
                             evidence: Path, name: str) -> None:
    if (cookie_file.is_symlink() or not cookie_file.is_file()
            or stat.S_IMODE(cookie_file.stat().st_mode) != 0o600):
        raise RuntimeError("browser companion did not create a private session cookie artifact")
    secret = cookie_file.read_text(encoding="utf-8")
    code = r'''import json,sys,urllib.request
value=json.load(sys.stdin); origin=value['origin']; cookie=value['cookie']
def get(path):
 req=urllib.request.Request(origin+path,headers={'Origin':origin,'Cookie':'uvm_session='+cookie})
 with urllib.request.urlopen(req,timeout=15) as response:return response.status,json.load(response)
session_status,session=get('/api/v1/auth/session')
deployment_status,deployment=get('/api/v1/deployment')
if session_status!=200 or session.get('credential_mode')!='local_session' or session.get('protected_admin') is not True:raise SystemExit('protected local session readback failed')
if deployment_status!=200 or deployment.get('schema_version')!=1 or deployment.get('installation_id')!=value['installation_id']:raise SystemExit('protected deployment readback failed')
connectors=deployment.get('connectors')
if not isinstance(connectors,list):raise SystemExit('deployment connector summaries are malformed')
required={'connector_id','lifecycle','connector_revision','configuration_revision','source_revision','environment_label','source'}
if any(not isinstance(item,dict) or not required.issubset(item) for item in connectors):raise SystemExit('nested connector summary is malformed')
print(json.dumps({'session':'local_session','protected_admin':True,'deployment':'readable','installation_id':deployment['installation_id'],'connectors':len(connectors)},sort_keys=True))
'''
    input_text = json.dumps({"origin": origin, "cookie": secret,
        "installation_id": expected_installation})
    result = run(name, [sys.executable, "-c", code], evidence, input_text=input_text)
    cookie_file.unlink(missing_ok=True)
    if "protected_admin" not in result.stdout:
        raise RuntimeError("protected browser session did not produce deployment readback evidence")


def qualify_local_runtime(*, package: Path, bundle: Path, admission: dict[str, str],
                          state: Path, private: Path, evidence: Path, password: str,
                          http_port: int, project_prefix: str) -> tuple[str, Path, dict[str, str]]:
    fixture = Path(admission["fixture_directory"])
    outer = private / "signed-package"
    outer.mkdir(mode=0o700)
    launcher_source = package / "launcher.sh"
    launcher = outer / "launcher.sh"
    rendered_hash = render_fixture_launcher(launcher_source, launcher, fixture)
    shutil.copyfile(bundle, outer / "installer.bundle.tar.gz")
    shutil.copyfile(fixture / "installer.bundle.sigstore.json", outer / "installer.bundle.sigstore.json")
    shutil.copyfile(fixture / "launcher.sigstore.json", outer / "launcher.sigstore.json")
    os.chmod(outer / "installer.bundle.tar.gz", 0o600)
    for path in (outer / "installer.bundle.sigstore.json", outer / "launcher.sigstore.json"):
        os.chmod(path, 0o600)
    run("fixture-trusted-launcher-signature", ["docker", "run", "--rm", "--network", "host",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m", "--mount", f"type=bind,src={evidence / 'fixture-trust-public'},dst=/fixture,readonly",
        "--mount", f"type=bind,src={launcher},dst=/launcher,readonly", COSIGN_IMAGE,
        "verify-blob", "--key", "/fixture/fixture.pub", "--trusted-root", "/fixture/trusted-root.json",
        "--bundle", "/fixture/launcher.sigstore.json", "/launcher"], evidence)
    (evidence / "fixture-render.json").write_text(json.dumps({
        "packaged_launcher_sha256": sha(launcher_source),
        "fixture_launcher_sha256": rendered_hash,
        "fixture_policy": "independently signed launcher and verifier pin; maintainer-only",
        "signed_launcher_was_mutated_after_signing": False,
    }, sort_keys=True, indent=2) + "\n")
    launcher_bin = private / "minimal-host-path"
    launcher_env = trusted_launcher_environment(launcher_bin, admission)
    run("minimal-host-compose-preflight", ["docker", "compose", "version"], evidence, env=launcher_env)
    run("minimal-host-launcher-syntax", ["sh", "-n", str(launcher)], evidence, env=launcher_env)
    origin = f"http://127.0.0.1:{http_port}"
    install = run("local-launcher-install", ["sh", str(launcher), "install", "--directory", str(state),
        "--port", str(http_port), "--project-prefix", project_prefix], evidence, env=launcher_env)
    info = json.loads((state / "instance.json").read_text(encoding="utf-8"))
    if (info.get("mode") != "local" or info.get("image_admission", {}).get("id") != admission["image_id"]
            or info.get("platform") != admission["platform"]
            or info.get("image_admission", {}).get("source_revision") != admission["source_commit"]
            or info.get("image_admission", {}).get("source_snapshot") != admission["source_snapshot"]):
        raise RuntimeError("packaged host launcher instance differs from signed source/runtime admission")
    project = info["project"]
    if not project.startswith(f"{project_prefix}-"):
        raise RuntimeError("installer project escaped its assigned resource namespace")
    info_mounts = json.loads(run("local-compose-config", ["docker", "compose", "-f",
        str(state / "compose/compose.yaml"), "-f", str(state / "compose/local.yaml"), "--env-file",
        str(state / ".env"), "-p", project, "config", "--format", "json"], evidence).stdout)
    if set(info_mounts.get("services", {})) != {"volt"}:
        raise RuntimeError("local auth Compose unexpectedly started a synthetic identity provider")
    port = run("local-loopback-binding", ["docker", "port", f"{project}-volt-1", "8000/tcp"], evidence)
    if not port.stdout.strip().startswith("127.0.0.1:"):
        raise RuntimeError("local VOLT application binding is not loopback-only")
    wait_for_local(origin, evidence)
    capability_file = state / "secrets/bootstrap-capability-output"
    if (capability_file.is_symlink() or not capability_file.is_file()
            or stat.S_IMODE(capability_file.stat().st_mode) != 0o600):
        raise RuntimeError("local installer did not deliver setup capability in a private file")
    capability = capability_file.read_text(encoding="utf-8").strip()
    if not capability:
        raise RuntimeError("local installer setup capability file is empty")
    ui_evidence = evidence / "browser-first-admin"
    ui_evidence.mkdir(mode=0o700)
    credentials = {"username": "qualification-admin", "password": password,
        "capability": capability, "display_name": "VOLT qualification administrator"}
    run("browser-first-admin", ["node", str(ROOT / "tools/g7_local_preview_smoke.mjs"), "--local",
        "--setup", "--origin", origin, "--evidence", str(ui_evidence), "--credentials-stdin"],
        evidence, input_text=json.dumps(credentials))
    capability = None
    capability_file.unlink(missing_ok=True)
    login = ["node", str(ROOT / "tools/compose_release_login.mjs"), origin, str(private / "cookie"), "--local-stdin"]
    run("browser-local-login", login, evidence,
        input_text=json.dumps({"username": "qualification-admin", "password": password}))
    local_config = json.loads((state / "local-auth.json").read_text(encoding="utf-8"))
    protected_local_readback(origin, private / "cookie", local_config["installation_id"],
                             evidence, "local-protected-deployment-readback")
    run("local-launcher-stop", ["sh", str(launcher), "stop", "--directory", str(state)], evidence, env=launcher_env)
    run("local-launcher-restart", ["sh", str(launcher), "start", "--directory", str(state)], evidence, env=launcher_env)
    wait_for_local(origin, evidence)
    run("browser-local-login-after-restart", login, evidence,
        input_text=json.dumps({"username": "qualification-admin", "password": password}))
    protected_local_readback(origin, private / "cookie", local_config["installation_id"],
                             evidence, "local-restart-protected-deployment-readback")
    (evidence / "local-auth-journey.json").write_text(json.dumps({
        "status": "passed",
        "host_runtime": "POSIX shell and Docker/Compose only; Python/OpenSSL executed inside digest-admitted runtime",
        "instance_outside_checkout": True,
        "source_revision": admission["source_commit"],
        "source_snapshot": admission["source_snapshot"],
        "bundle_sha256": admission["bundle_sha256"],
        "image_id": admission["image_id"],
        "platform": admission["platform"],
        "first_admin_browser_claim": "passed",
        "local_browser_sign_in": "passed",
        "protected_deployment_readback": "passed",
        "restart_account_readback": "passed",
        "scanner_stage": "pending",
        "restore_stage": "pending_backend_review_and_session_revocation_contract",
    }, sort_keys=True, indent=2) + "\n")
    return project, launcher, launcher_env

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image-id", required=True)
    p.add_argument("--source-snapshot", required=True)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--platform", choices=SUPPORTED_PLATFORMS,
                   help="optional package-manifest platform; checked against the loaded image config")
    p.add_argument("--version", choices=SUPPORTED_IMAGE_VERSIONS, default="0.1.0-rc.2",
                   help="expected image version (0.1.0-demo is permitted only with --development-fixture)")
    p.add_argument("--auth-mode", choices=("demo", "local"), default="demo",
                   help="qualify legacy synthetic demo or persistent local account mode")
    p.add_argument("--admission-fixture", type=Path,
                   help="external fixture root/public key, verifier digest and Cosign bundles (local mode only)")
    p.add_argument("--development-fixture", action="store_true",
                   help="label evidence as development-only when qualifying an explicitly selected fixture image")
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--private-tmp", type=Path, default=Path("/tmp"),
                   help="parent directory for private generated state and backup fixtures")
    p.add_argument("--bundle-tmp", type=Path, default=Path("/tmp"),
                   help="parent directory for the small source-free installer extraction")
    p.add_argument("--project-prefix", default="volt-rc2-qual",
                   help="unique Compose project prefix used for owned disposable resources")
    args = p.parse_args()
    if args.version == "0.1.0-demo" and not args.development_fixture:
        p.error("0.1.0-demo requires --development-fixture")
    if args.auth_mode == "local":
        if args.version != "0.1.0-rc.4" or args.admission_fixture is None:
            p.error("local auth qualification requires --version 0.1.0-rc.4 and --admission-fixture")
        if args.development_fixture:
            p.error("local auth fixture qualification is already explicitly development-scoped")
    elif args.admission_fixture is not None:
        p.error("--admission-fixture is only accepted with --auth-mode local")
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}",args.image_id)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}",args.source_snapshot)
            or not re.fullmatch(r"[0-9a-f]{40}",args.source_commit)):
        p.error("immutable image ID and source snapshot SHA-256 are required")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}", args.project_prefix):
        p.error("project prefix must be a short lowercase Compose-safe identifier")
    private_tmp = args.private_tmp.resolve(strict=True)
    bundle_tmp = args.bundle_tmp.resolve(strict=True)
    if not private_tmp.is_dir() or not bundle_tmp.is_dir():
        p.error("temporary parents must be existing directories")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(evidence, 0o700)
    if args.auth_mode == "local":
        # The selected first provider is Qualys, but no supported packaged
        # collector/import path is part of this installer candidate yet.
        # Preserve that as an explicit unqualified stage instead of allowing
        # the legacy synthetic OIDC editor to stand in for scanner handoff.
        (evidence / "scanner-stage.json").write_text(
            json.dumps(scanner_stage_record(), sort_keys=True, indent=2) + "\n")
    private = None
    extracted = None
    state = None
    cookie = None
    project = f"{args.project_prefix}-{os.getpid()}"
    password_value = None
    setup = None
    launcher_environment = None
    cleanup_result = 0
    started = False
    admission = None
    outcome = 0
    try:
        bundle_command = compose_bundle_verify_command(args.bundle, version=args.version,
            development_fixture=args.development_fixture, local_auth_fixture=args.auth_mode == "local")
        bundle_check = run("bundle-verify", bundle_command, evidence)
        bundle_version = admit_bundle_version(bundle_check.stdout, args.version,
            development_fixture=args.development_fixture, local_auth_fixture=args.auth_mode == "local")
        admission = None
        if args.auth_mode == "local":
            admission = validate_admission_fixture(args.admission_fixture, image_id=args.image_id,
                source_snapshot=args.source_snapshot, source_commit=args.source_commit,
                platform=args.platform or "linux/amd64", bundle=args.bundle,
                version=args.version, evidence=evidence)
            platform = admission["platform"]
        private = Path(tempfile.mkdtemp(prefix=f"{args.project_prefix}-state-", dir=private_tmp))
        os.chmod(private, 0o700)
        state = private / "instance"
        extracted = Path(tempfile.mkdtemp(prefix=f"{args.project_prefix}-bundle-", dir=bundle_tmp))
        os.chmod(extracted, 0o700)
        cookie = private / "cookie"
        password_value = secrets.token_urlsafe(32) + "A7!"
        shutil.unpack_archive(str(args.bundle), extracted, "gztar")
        candidates = list(extracted.glob("*/setup.py"))
        if len(candidates) != 1:
            raise RuntimeError("bundle did not extract to one source-free setup.py")
        setup = candidates[0]
        if ROOT in setup.parents:
            raise RuntimeError("source-free bundle extraction unexpectedly overlaps checkout")
        if args.auth_mode == "local":
            shutil.copy2(args.bundle, evidence / "installer.bundle.tar.gz")
            for name in ("fixture.pub", "trusted-root.json", "verifier.ref",
                         "launcher.sigstore.json", "installer.bundle.sigstore.json"):
                shutil.copy2(args.admission_fixture / name, evidence / name)
            package_root = setup.parent
            (evidence / "source-bundle-root.txt").write_text(str(package_root) + "\n")
            project, setup, launcher_environment = qualify_local_runtime(package=package_root,
                bundle=args.bundle, admission=admission, state=state, private=private,
                evidence=evidence, password=password_value, http_port=46180,
                project_prefix=args.project_prefix)
            started = True
            release_metadata = qualification_release_metadata(requested_version=args.version,
                bundle_version=bundle_version, image_version=args.version, image_id=args.image_id,
                platform=platform or "linux/amd64", source_revision=args.source_commit,
                source_snapshot=args.source_snapshot, bundle_sha256=sha(args.bundle),
                scope="development_fixture")
            (evidence / "qualification.json").write_text(json.dumps({
                "result": "incomplete", "full_qualification": False, **release_metadata,
                "project": project, "local_auth_process": "passed",
                "scanner_provider": "Qualys", "scanner_stage": "pending",
                "restore_stage": "pending_backend_session_revocation_review",
                "reason": "Provider ingestion and safe restored-session revocation remain unqualified.",
            }, sort_keys=True, indent=2) + "\n")
            outcome = 2
        else:
            image_inspect = run("image-platform-inspect", ["docker", "image", "inspect", args.image_id], evidence)
            platform = platform_from_image_inspect(image_inspect.stdout, args.platform)
            (evidence / "platform-admission.json").write_text(json.dumps({
                "image_id": args.image_id, "declared_platform": args.platform,
                "docker_config_platform": platform, "admitted_platform": platform}, sort_keys=True, indent=2) + "\n")
            ports = [int(18000 + os.getpid() % 1000), int(19000 + os.getpid() % 1000), int(20000 + os.getpid() % 1000)]
            cli = [sys.executable, str(setup)]
            run_getpass("init", init_command(cli, state, project, ports, args.image_id, platform), evidence,
                [(b"New local demo admin password", password_value),
                 (b"Confirm local demo admin password", password_value)])
            info = json.loads((state / "instance.json").read_text())
            admission = info["image_admission"]
            if (admission["id"] != args.image_id or admission["platform"] != platform
                    or admission["source_snapshot"] != args.source_snapshot
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
                            "image":args.image_id,"owner_token":str(uuid.uuid4())}
            probe = (f"import sys;from pathlib import Path;sys.path.insert(0,{str(ROOT)!r});"
                     f"from tools.g7_local_preview import verify_private_ingress;"
                     f"verify_private_ingress({ingress_info!r},Path({str(evidence)!r}))")
            run("private-peer-ingress-denial",[sys.executable,"-c",probe],evidence)
            run("link-admin", [*cli,"link-admin",str(state)], evidence)
            origin = f"http://127.0.0.1:{ports[0]}"
            run("browser-login", ["node",str(ROOT/"tools/compose_release_login.mjs"),origin,str(cookie),
                "qualification-admin"], evidence, input_text=password_value)
            run_getpass("initialize-authority", [*cli,"initialize-authority",str(state)], evidence,
                        cookie.read_text())
            cookie.unlink(missing_ok=True)
            smoke = ["node",str(ROOT/"tools/g7_local_preview_smoke.mjs"),"--origin",origin,
                     "--issuer",f"http://127.0.0.1:{ports[2]}","--subject","volt-compose-demo-admin-subject",
                     "--principal","volt-compose-demo-admin","--evidence",str(evidence),
                     "--username","qualification-admin","--password-stdin"]
            run("audited-operation", smoke, evidence, input_text=password_value)
            run("stop", [*cli,"stop",str(state)], evidence); started = False
            run("restart", [*cli,"start",str(state)], evidence); started = True
            run("restart-health", [sys.executable,"-c",f"import sys;sys.path.insert(0,{str(ROOT)!r});from deploy.compose.setup import load_instance,wait_until_ready;wait_until_ready(load_instance({str(state)!r})[1]);print('healthy')"],evidence)
            run("restart-readback", ["node",str(ROOT/"tools/g7_local_preview_smoke.mjs"),"--origin",origin,
                "--issuer",f"http://127.0.0.1:{ports[2]}","--subject","volt-compose-demo-admin-subject",
                "--principal","volt-compose-demo-admin","--evidence",str(evidence),"--readback",
                "--username","qualification-admin","--password-stdin"], evidence,
                input_text=password_value)
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
            run("destroy-before-restore", [*cli,"cleanup",str(state),"--remove-data","--confirm-project",project], evidence)
            if state.exists(): state.rmdir()
            shutil.copytree(saved_state,state)
            wrong_image = json.loads((state/"instance.json").read_text())
            wrong_id = "sha256:"+"0"*64
            wrong_image["image_admission"]["id"] = wrong_id
            env_path = state/".env"
            env_content = env_path.read_text()
            env_path.write_text(re.sub(r"(?m)^VOLT_IMAGE_ID=.*$", f"VOLT_IMAGE_ID={wrong_id}", env_content))
            wrong_image["env_sha256"] = hashlib.sha256(env_path.read_bytes()).hexdigest()
            (state/"instance.json").write_text(json.dumps(wrong_image,indent=2)+"\n")
            image_negative = run("restore-image-binding-negative", [*cli,"restore-provision",str(state)], evidence,check=False)
            if image_negative.returncode == 0 or "restore image differs from captured identity" not in image_negative.stderr:
                raise RuntimeError("restore image-binding negative did not fail at the captured image identity check")
            shutil.copy2(saved_state/"instance.json", state/"instance.json")
            shutil.copy2(saved_state/".env", state/".env")
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
                "--principal","volt-compose-demo-admin","--evidence",str(evidence),"--readback",
                "--username","qualification-admin","--password-stdin"], evidence,
                input_text=password_value)
            run("provider-group-removal-fresh-login", ["node",str(ROOT/"tools/g7_local_preview_smoke.mjs"),
                "--origin",origin,"--issuer",f"http://127.0.0.1:{ports[2]}",
                "--subject","volt-compose-demo-admin-subject","--principal","volt-compose-demo-admin",
                "--evidence",str(evidence),"--readback","--verify-provider-revocation",
                "--username","qualification-admin","--password-stdin",
                "--compose-directory",str(info["compose_directory"]),"--env-file",str(state/".env"),
                "--project",project], evidence, input_text=password_value)
            # The exact-owner cleanup below performs the final stop and removes only
            # this private project, avoiding a second graceful stop before cleanup.
            execution_environment = {key: os.environ[key] for key in ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT")
                                    if key in os.environ}
            release_metadata = qualification_release_metadata(requested_version=args.version,
                bundle_version=bundle_version, image_version=admission["version"], image_id=args.image_id,
                platform=platform, source_revision=admission["source_revision"],
                source_snapshot=args.source_snapshot, bundle_sha256=sha(args.bundle),
                scope=qualification_scope(version=args.version, development_fixture=args.development_fixture,
                                          local_auth_fixture=args.auth_mode == "local"))
            (evidence/"qualification.json").write_text(json.dumps({"result":"passed",
                **release_metadata,
                "execution_environment":execution_environment or {"kind": "local"},
                "project":project,"synthetic_demo":True,"health":"passed","audited_operation":"passed",
                "demo_mode":"passed","loopback_binding":"passed","private_peer_ingress_denial":"passed",
                "restart_readback":"passed","cold_backup_inventories":3,"image_binding_rejection":"passed",
                "corrupt_inventory_rejection":"passed","restore_readback":"passed",
                "provider_group_removal_old_cookie_revocation":"passed",
                "provider_group_removal_fresh_login_no_role_or_scope_recovery":"passed"},indent=2)+"\n")
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        outcome = 1
    finally:
        if cookie is not None:
            cookie.unlink(missing_ok=True)
        password_value = None
        preserve_private = False
        if args.auth_mode == "local" and state is not None and state.exists() and private is not None:
            launcher = private / "signed-package" / "launcher.sh"
            metadata = state / "instance.json"
            if metadata.is_file() and launcher.is_file():
                try:
                    project = json.loads(metadata.read_text(encoding="utf-8"))["project"]
                    if admission is None:
                        raise RuntimeError("no authenticated launcher context for cleanup")
                    minimal = trusted_launcher_environment(private / "minimal-host-path", admission)
                    result = subprocess.run(["sh", str(launcher), "destroy", "--directory", str(state),
                        "--confirm-project", project, "--remove-state"],
                        text=True, capture_output=True, env=minimal)
                    for suffix, value in (("stdout", result.stdout), ("stderr", result.stderr)):
                        (evidence / f"owned-cleanup.{suffix}").write_text(value)
                    (evidence / "owned-cleanup.argv.json").write_text(json.dumps(
                        ["sh", str(launcher), "destroy", "--directory", str(state),
                         "--confirm-project", project, "--remove-state"], indent=2) + "\n")
                    (evidence / "owned-cleanup.exit").write_text(f"{result.returncode}\n")
                    cleanup_result = result.returncode
                except Exception:
                    cleanup_result = 1
            elif metadata.exists():
                cleanup_result = 1
            if cleanup_result:
                preserve_private = True
        elif state is not None and state.exists() and setup:
            try:
                # Legacy demo cleanup retains its existing Python host controller.
                result=subprocess.run([sys.executable,str(setup),"cleanup",str(state),"--remove-data","--confirm-project",project],
                    text=True,capture_output=True)
                for suffix, value in (("stdout",result.stdout),("stderr",result.stderr)):
                    (evidence/f"owned-cleanup.{suffix}").write_text(value)
                (evidence/"owned-cleanup.exit").write_text(f"{result.returncode}\n")
                cleanup_result=result.returncode
            except Exception:
                cleanup_result=1
        if private is not None and not preserve_private:
            shutil.rmtree(private,ignore_errors=True)
        if extracted is not None:
            shutil.rmtree(extracted,ignore_errors=True)
        if cleanup_result:
            print(f"owned Compose cleanup failed; inspect exact project resources and retained private state: {private}",file=sys.stderr)
    return 1 if cleanup_result else outcome


if __name__ == "__main__":
    raise SystemExit(main())
