#!/usr/bin/env python3
"""Opt-in, one-image source-free Compose release qualification."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import shutil
import shlex
import signal
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
        argv = ["docker", "run", "--rm", "--platform", platform, "--network", "host", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--env", "HOME=/tmp", "--mount", f"type=bind,src={public_root},dst=/fixture,readonly",
        "--mount", f"type=bind,src={artifact},dst=/artifact,readonly", f"{COSIGN_IMAGE}",
        "verify-blob", "--key", "/fixture/fixture.pub", "--trusted-root", "/fixture/trusted-root.json",
        "--bundle", f"/fixture/{signature.name}", "/artifact"]
        run(f"fixture-{name}-signature", argv, evidence)
    # The verifier image itself is signed under the external fixture root. Its
    # provenance is also checked before any verifier code is executed.
    run("fixture-verifier-signature", ["docker", "run", "--rm", "--platform", platform, "--network", "host", "--read-only",
        "--cap-drop=ALL", "--user", f"{os.getuid()}:{os.getgid()}", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--mount", f"type=bind,src={public_root},dst=/fixture,readonly", COSIGN_IMAGE, "verify",
        "--key", "/fixture/fixture.pub", "--trusted-root", "/fixture/trusted-root.json",
        verifier_reference], evidence)
    run("fixture-verifier-provenance", ["docker", "run", "--rm", "--platform", platform, "--network", "host", "--read-only",
        "--cap-drop=ALL", "--user", f"{os.getuid()}:{os.getgid()}", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
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
    run("fixture-runtime-pull", ["docker", "pull", "--platform", platform, image_reference], evidence)
    inspected = run("fixture-runtime-inspect", ["docker", "image", "inspect", image_reference], evidence)
    try:
        image_row = json.loads(inspected.stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise RuntimeError("fixture runtime inspection did not return one image") from exc
    if (image_row.get("Descriptor") or {}).get("mediaType") in {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}:
        inspected = run("fixture-runtime-selected-inspect", ["docker", "image", "inspect", "--platform", platform, image_reference], evidence)
        image_row = json.loads(inspected.stdout)[0]
    if image_row.get("Id") != image_id:
        raise RuntimeError("fixture selected config/manifest ID differs from the requested candidate image object")
    native = run("native-engine-platform", ["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], evidence)
    if native.stdout.strip() != platform:
        raise RuntimeError("qualification requires the actual native engine platform; emulated execution is not admitted")
    index = run("fixture-runtime-index", ["docker", "buildx", "imagetools", "inspect", "--raw",
        image_reference], evidence)
    image_json = evidence / "runtime-image-inspect.json"
    index_json = evidence / "runtime-image-index.json"
    image_json.write_text(inspected.stdout, encoding="utf-8")
    index_json.write_text(index.stdout, encoding="utf-8")
    admission_command = ["docker", "run", "--rm", "--platform", platform, "--network", "host",
        "--read-only", "--cap-drop=ALL", "--user", f"{os.getuid()}:{os.getgid()}", "--security-opt=no-new-privileges", "--tmpfs",
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
        "image_id": runtime["image_id"], "image_id_kind": runtime["image_id_kind"],
        "image_config_id": runtime["image_config_id"], "image_reference": image_reference,
        "image_index_digest": runtime["image_index_digest"], "source_snapshot": source_snapshot,
        "source_commit": source_commit, "platform": platform,
        "verifier_reference": verifier_reference}
    result["fixture_directory"] = str(root)
    return result

def qualify_admission_negatives(command: list[str], bundle: Path, image_json: Path,
                                 index_json: Path, evidence: Path) -> None:
    """Exercise rejection by the independently admitted verifier before runtime execution."""
    for original in (bundle, image_json, index_json):
        if sum(f"src={original}," in argument for argument in command) != 1:
            raise RuntimeError(f"negative input must match exactly one admitted bind mount: {original.name}")
    directory = evidence / "admission-negatives"
    directory.mkdir(mode=0o755)
    cases = []
    verifier_arguments = command.index("--bundle")
    verifier_platform = command.index("--platform", verifier_arguments)
    for name, option, value in (("source-revision", "--source-revision", "0" * 40),
                                ("source-snapshot", "--source-snapshot", "sha256:" + "0" * 64),
                                ("version", "--version", "0.1.0-rc.3"),
                                ("platform", "--platform", "linux/arm64" if command[verifier_platform + 1] == "linux/amd64" else "linux/amd64")):
        candidate = list(command)
        candidate[candidate.index(option, verifier_arguments) + 1] = value
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
        if name == "platform" and (result.returncode != 2 or
                "verifier.py: error: selected runtime platform differs from the admitted engine platform"
                not in result.stderr):
            raise RuntimeError("platform negative did not reach the verifier's semantic platform rejection")
    (evidence / "admission-negatives.json").write_text(json.dumps({
        "status": "passed", "before_candidate_execution": True,
        "cases": [name for name, _ in cases]}, sort_keys=True, indent=2) + "\n")


def trusted_launcher_environment(bin_directory: Path, admission: dict) -> dict[str, str]:
    registries = {COSIGN_IMAGE.split('/', 1)[0], admission['verifier_reference'].split('/', 1)[0],
                  admission['image_reference'].split('/', 1)[0]}
    environment = launcher_minimal_environment(bin_directory, registries=tuple(sorted(registries)))
    environment.update({"VOLT_EXPECTED_VERIFIER_IMAGE": admission["verifier_reference"],
        "VOLT_EXPECTED_VERSION": "0.1.0-rc.4", "VOLT_EXPECTED_SIGNER": SIGNER,
        "VOLT_EXPECTED_ISSUER": ISSUER, "VOLT_BOOTSTRAP_VERIFIER_VERIFIED": "1"})
    return environment


def qualify_offline_fixture_entry(*, closure: Path, fixture: Path, verifier_reference: str,
                                 platform: str, private: Path, evidence: Path) -> None:
    """Exercise independent first-entry trust; never authorize a cached pass.

    This maintainer-only fixture controller is separate from production bootstrap.
    Expected verifier identity and trust directory come from its original external
    admission, not from the downloaded closure. All actual host commands execute
    with the existing restricted PATH and no implicit image pull.
    """
    if (not re.fullmatch(r'127\.0\.0\.1:46150/volt-installer-verifier@sha256:[0-9a-f]{64}', verifier_reference)
            or platform not in SUPPORTED_PLATFORMS or fixture.resolve() in (closure.resolve(), *closure.resolve().parents)
            or closure.resolve() in fixture.resolve().parents):
        raise ValueError('offline fixture entry requires independently selected verifier and separate trust material')
    for name in ('fixture.pub', 'trusted-root.json'):
        if (fixture / name).is_symlink() or not (fixture / name).is_file():
            raise ValueError('original independent fixture trust material is missing or unsafe')
    policies = private / 'offline-entry-policies'
    policies.mkdir(mode=0o700)
    expected_digest = verifier_reference.split('@sha256:')[1]
    signature_type = 'https://sigstore.dev/cosign/sign/v1'
    slsa_type = 'https://slsa.dev/provenance/v1'
    for name, predicate in (('signature', signature_type), ('slsa', slsa_type)):
        # This fixed expectation is evaluated against cryptographically verified
        # payloads INSIDE the externally pinned Cosign utility, before Python in
        # the cached verifier may execute. No host JSON interpreter is required.
        policy = f'predicateType: "{predicate}"\nsubject: [{{digest: {{sha256: "{expected_digest}"}}}}]\n'
        destination = policies / (name + '.cue')
        with destination.open('x') as stream:
            stream.write(policy)
        destination.chmod(0o600)
    environment = launcher_minimal_environment(private / 'offline-minimal-path', registries=())
    shutil.copyfile(private / 'minimal-host-tools.json', evidence / 'offline-entry-host-tools.json')
    base = ['docker', 'run', '--rm', '--platform', platform, '--pull=never', '--network', 'none',
        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--tmpfs',
        '/tmp:rw,noexec,nosuid,size=32m', '--env', 'HOME=/tmp', '--user', f'{os.getuid()}:{os.getgid()}']
    cosign = [*base, '--mount', f'type=bind,src={closure},dst=/closure,readonly',
        '--mount', f'type=bind,src={fixture},dst=/independent-trust,readonly',
        '--mount', f'type=bind,src={policies},dst=/independent-policy,readonly', COSIGN_IMAGE]
    for name, predicate in (('signature', signature_type), ('slsa', slsa_type)):
        run('offline-first-entry-verifier-' + name, [*cosign, 'verify-attestation', '--type', predicate,
            '--policy', '/independent-policy/' + name + '.cue', '--key', '/independent-trust/fixture.pub',
            '--trusted-root', '/independent-trust/trusted-root.json', '--local-image', '/closure/verifier'],
            evidence, env=environment)
    for artifact, signature in (('launcher.sh', 'launcher.sigstore.json'),
                                 ('installer.bundle.tar.gz', 'installer.bundle.sigstore.json')):
        run('offline-first-entry-' + artifact.replace('.', '-'), [*cosign, 'verify-blob',
            '--key', '/independent-trust/fixture.pub', '--trusted-root', '/independent-trust/trusted-root.json',
            '--bundle', '/closure/package/' + signature, '/closure/package/' + artifact], evidence, env=environment)
    # First verifier execution occurs only after its exact subject AND SLSA
    # authentication and original launcher verification. Help is deliberately a
    # bounded first-entry assertion, not offline graph/lifecycle qualification.
    run('offline-first-entry-authenticated-verifier-execution', [*base, verifier_reference, '--help'],
        evidence, env=environment)
    (evidence / 'offline-first-entry.json').write_text(json.dumps({
        'status': 'passed_fixture_first_entry', 'verifier_reference': verifier_reference,
        'native_platform': platform, 'network': 'none', 'image_pull_policy': 'never',
        'expected_subject_checked_inside_trusted_cosign': True,
        'independent_verifier_execution': 'help_only_after_authentication',
        'candidate_application_executed': False, 'offline_full_graph_qualified': False,
        'offline_lifecycle_qualified': False, 'production_keyless_qualified': False,
    }, sort_keys=True, indent=2) + '\n')




def restore_admit_observer_environment(*, capture: Path, environment: dict, info: dict,
                                       admission: dict) -> dict:
    """Test-only POSIX observation before the ORIGINAL exact helper removal.

    Commands/arguments/stdout/stderr/status always reach the installed Docker
    unchanged. Capture ambiguity disqualifies the evidence, never changes rm.
    This is explicitly instrumented cause proof, not unmodified-host certification.
    """
    if (info.get('image') != admission['image_reference']
            or info.get('image_admission', {}).get('id') != admission['image_id']
            or not re.fullmatch(r'[a-z][a-z0-9-]{1,62}', info.get('project', ''))
            or not re.fullmatch(r'[0-9a-f]{64}', info.get('owner_token', ''))):
        raise ValueError('owner observation requires the already admitted exact instance/image')
    capture.mkdir(mode=0o700)
    binary = capture / 'bin'; binary.mkdir(mode=0o700)
    pid_file = capture / 'caller.pid'
    with pid_file.open('x'): pass
    pid_file.chmod(0o600)
    real = shutil.which('docker', path=environment['PATH'])
    if real is None:
        raise ValueError('original installed Docker executable is missing')
    real = Path(real).resolve(strict=True)
    descriptor = info['image_admission']['selected_descriptor']
    values = {'REAL_DOCKER': str(real), 'CAPTURE': str(capture), 'PID_FILE': str(pid_file),
        'EXPECTED_PROJECT': info['project'], 'EXPECTED_OWNER': info['owner_token'],
        'EXPECTED_REFERENCE': admission['image_reference'], 'EXPECTED_ID': admission['image_id'],
        'EXPECTED_KIND': admission['image_id_kind'],
        'EXPECTED_ENGINE': info['image_admission']['engine_image_id'],
        'EXPECTED_CHILD': descriptor['digest'], 'EXPECTED_MEDIA': descriptor['mediaType'],
        'EXPECTED_SIZE': str(descriptor['size']), 'EXPECTED_PLATFORM': admission['platform']}
    script = '#!/bin/sh\nset -u\numask 077\n' + '\n'.join(
        key + '=' + shlex.quote(value) for key, value in values.items()) + r'''
observe_owned_removal() {
  [ "$#" -eq 3 ] && [ "$1" = rm ] && [ "$2" = -f ] || return 0
  IFS= read -r caller <"$PID_FILE" || return 0
  case "$caller" in ''|*[!0-9]*) return 0 ;; esac
  expected_name="volt-offline-$EXPECTED_PROJECT-$caller"
  [ "$3" = "$expected_name" ] || return 0
  if [ -e "$CAPTURE/guard.status" ]; then
    printf '%s\n' duplicate >"$CAPTURE/duplicate.status"; return 0
  fi
  identity=$("$REAL_DOCKER" inspect "$3" --format '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "volt.compose.project"}}|{{json .Config.Cmd}}|{{.Image}}|{{if .ImageManifestDescriptor}}{{.ImageManifestDescriptor.digest}}|{{.ImageManifestDescriptor.mediaType}}|{{.ImageManifestDescriptor.size}}|{{.ImageManifestDescriptor.platform.os}}/{{.ImageManifestDescriptor.platform.architecture}}{{end}}' 2>"$CAPTURE/identity.stderr") || {
    printf '%s\n' unavailable >"$CAPTURE/guard.status"; return 0;
  }
  printf '%s\n' "$identity" >"$CAPTURE/identity.txt"
  IFS='|' read -r cid name reference owner project command image child media size platform <<EOF_OWNER_ID
$identity
EOF_OWNER_ID
  case "$cid" in ''|*[!0-9a-f]*) printf '%s\n' invalid >"$CAPTURE/guard.status"; return 0 ;; esac
  [ "${#cid}" -eq 64 ] && [ "$name|$reference|$owner|$project|$command" = "/$expected_name|$EXPECTED_REFERENCE|$EXPECTED_OWNER|$EXPECTED_PROJECT|[\"-m\",\"uvm.installer.lock\",\"/state/.install.lock\",\"--offline-restore-admit\"]" ] || {
    printf '%s\n' contradiction >"$CAPTURE/guard.status"; return 0;
  }
  if [ "$image" != "$EXPECTED_ID" ]; then
    [ "$EXPECTED_KIND" = selected_manifest ] && [ "$image" = "$EXPECTED_ENGINE" ] &&
      [ "$child|$media|$size|$platform" = "$EXPECTED_CHILD|$EXPECTED_MEDIA|$EXPECTED_SIZE|$EXPECTED_PLATFORM" ] || {
      printf '%s\n' wrong_image >"$CAPTURE/guard.status"; return 0;
    }
  fi
  input=$("$REAL_DOCKER" inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/run/volt-offline-input"}}{{.Source}}{{end}}{{end}}') || return 0
  output=$("$REAL_DOCKER" inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/run/volt-offline-output"}}{{.Source}}{{end}}{{end}}') || return 0
  case "$input" in /tmp/volt-installer.????????/offline-input) ;; *) printf '%s\n' wrong_exchange >"$CAPTURE/guard.status"; return 0 ;; esac
  [ "$output" = "${input%/offline-input}/offline-output" ] || { printf '%s\n' wrong_exchange >"$CAPTURE/guard.status"; return 0; }
  for pair in "$input/request.json:request.json" "$output/plan.json:plan.json" "$input/observed.json:observed.json"; do
    original=${pair%:*}; copied=${pair##*:}
    [ -f "$original" ] && [ ! -L "$original" ] && cp -- "$original" "$CAPTURE/$copied" || {
      printf '%s\n' missing_phase >"$CAPTURE/guard.status"; return 0;
    }
    chmod 600 "$CAPTURE/$copied"
  done
  "$REAL_DOCKER" inspect "$cid" --format '{"id":{{json .Id}},"name":{{json .Name}},"image_ref":{{json .Config.Image}},"image":{{json .Image}},"selected_witness":{{json .ImageManifestDescriptor}},"labels":{{json .Config.Labels}},"cmd":{{json .Config.Cmd}},"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},"exit_code":{{json .State.ExitCode}}}' >"$CAPTURE/owner.json" 2>"$CAPTURE/owner-inspect.stderr" || return 0
  printf '%s\n' "$REAL_DOCKER" logs --timestamps --tail 128 "$cid" >"$CAPTURE/logs.argv.txt"
  if "$REAL_DOCKER" logs --timestamps --tail 128 "$cid" >"$CAPTURE/owner.stdout" 2>"$CAPTURE/owner.stderr"; then
    printf '%s\n' 0 >"$CAPTURE/logs.exit"; printf '%s\n' captured >"$CAPTURE/guard.status"
  else
    printf '%s\n' "$?" >"$CAPTURE/logs.exit"; printf '%s\n' logs_failed >"$CAPTURE/guard.status"
  fi
}
# Observation may fail; ORIGINAL Docker command/result is never replaced/skipped.
( observe_owned_removal "$@" ) >"$CAPTURE/observer.stdout" 2>"$CAPTURE/observer.stderr" || :
exec "$REAL_DOCKER" "$@"
'''
    destination = binary / 'docker'
    with destination.open('x') as stream: stream.write(script)
    destination.chmod(0o700)
    (capture / 'instrumentation.json').write_text(json.dumps({
        'scope': 'test-only POSIX before-removal observation; NOT unmodified Docker certification',
        'shim_sha256': sha(destination), 'original_docker': str(real), 'original_docker_sha256': sha(real),
        'expected_image': admission['image_reference'], 'expected_project': info['project'],
        'operation': 'restore-admit', 'original_command_results_unchanged': True,
        'UUID_and_predecessor_binding': 'validated from exact captured plan/observed bytes before evidence credit',
    }, sort_keys=True, indent=2) + '\n')
    return {**environment, 'PATH': str(binary) + os.pathsep + environment['PATH']}


def qualify_inventory_rejection(*, kind: str, launcher: Path, state: Path, private: Path,
                                evidence: Path, environment: dict, admission: dict) -> None:
    """Require the real exact bound owner's specific empty/corrupt inventory cause."""
    if kind not in ('empty', 'corrupt'):
        raise ValueError('only fixed empty/corrupt inventory probes are supported')
    info = json.loads((state / 'instance.json').read_text())
    capture = private / ('inventory-owner-' + kind)
    observed_env = restore_admit_observer_environment(capture=capture, environment=environment,
        info=info, admission=admission)
    command = ['sh', str(launcher), 'restore-admit', '--directory', str(state)]
    # This POSIX instrumentation wrapper only records its OWN PID before exec.
    # Public action argv and the installed Docker command results are unchanged.
    argv = ['sh', '-c', 'umask 077; printf "%s\n" "$$" >"$1"; shift; exec "$@"',
        'fixed-inventory-owner-observer', str(capture / 'caller.pid'), *command]
    name = 'inventory-' + kind + '-specific-denial'
    record = {'argv': argv, 'public_command': command, 'cwd': str(private),
        'environment_overrides': {'PATH': observed_env['PATH']}, 'private_capture': str(capture),
        'scope': 'instrumented current-source inventory cause replay; not original9657 run',
        'recorded_at': time.time()}
    (evidence / (name + '.invocation.json')).write_text(json.dumps(record, indent=2) + '\n')
    with (evidence / (name + '.stdout')).open('x') as stdout, (evidence / (name + '.stderr')).open('x') as stderr:
        process = subprocess.Popen(argv, cwd=private, env=observed_env, stdout=stdout, stderr=stderr,
            start_new_session=True)
        code = process.wait(timeout=900)
    (evidence / (name + '.exit')).write_text(str(code) + '\n')
    if code == 0 or (capture / 'caller.pid').read_text().strip() != str(process.pid):
        raise RuntimeError('negative inventory action or exact caller identity was not established')
    if (not (capture / 'guard.status').is_file() or (capture / 'guard.status').read_text().strip() != 'captured'
            or (capture / 'duplicate.status').exists()):
        raise RuntimeError('exact owner logs were not captured before original removal; no cause credit')
    plan_raw = (capture / 'plan.json').read_bytes()
    plan = host_dependency_json(capture / 'plan.json')
    observed = host_dependency_json(capture / 'observed.json')
    request = host_dependency_json(capture / 'request.json')
    owner = host_dependency_json(capture / 'owner.json')
    operation = plan.get('operation_id')
    if (not isinstance(operation, str) or str(uuid.UUID(operation)) != operation or uuid.UUID(operation).version != 4
            or plan.get('operation') != 'restore-admit' or plan.get('phase') != 'plan'
            or observed.get('operation_id') != operation or observed.get('operation') != 'restore-admit'
            or observed.get('phase') != 'observed' or observed.get('identity') != plan.get('identity')
            or observed.get('predecessor_sha256') != 'sha256:' + hashlib.sha256(plan_raw).hexdigest()
            or request.get('profile') != 'volt_offline_request_v1'
            or plan['identity'].get('source_revision') != admission['source_commit']
            or plan['identity'].get('source_snapshot') != admission['source_snapshot']
            or owner.get('name') != '/volt-offline-' + info['project'] + '-' + str(process.pid)):
        raise RuntimeError('captured owner request/plan/current-operation/source binding contradicts the replay')
    required = ('offline store inventory is malformed' if kind == 'empty'
                else 'offline imports differ from captured store inventories')
    messages = []
    for path in (capture / 'owner.stdout', capture / 'owner.stderr'):
        if path.stat().st_size > 8 * 1024 * 1024:
            raise RuntimeError('bounded fixed-owner log capture exceeded its contract')
        for line in path.read_text().splitlines():
            if 'offline-lifecycle-failed: ' in line:
                messages.append(line.split('offline-lifecycle-failed: ', 1)[1])
    actual = observed['data']['inventories']
    if (messages != [required] or kind == 'empty' and actual['postgres']['postgres_version'] is not None
            or kind == 'corrupt' and actual['state'] == info['backup_inventory']['state']):
        raise RuntimeError('observed denial did not prove the exact expected inventory rejection cause')
    (evidence / (name + '-cause.json')).write_text(json.dumps({
        'status': 'specific_inventory_cause_proved', 'kind': kind, 'backend_message': required,
        'actual_owner_CID': owner['id'], 'actual_owner_started_at': owner['started_at'],
        'actual_owner_finished_at': owner['finished_at'], 'operation_id': operation,
        'source_revision': admission['source_commit'], 'source_snapshot': admission['source_snapshot'],
        'owner_stdout_sha256': sha(capture / 'owner.stdout'), 'owner_stderr_sha256': sha(capture / 'owner.stderr'),
        'plan_sha256': 'sha256:' + hashlib.sha256(plan_raw).hexdigest(),
        'instrumentation': 'POSIX Docker observation forwards ORIGINAL removal/commands/results unchanged',
    }, sort_keys=True, indent=2) + '\n')

def create_offline_fixture_entry(*, state: Path, admission: dict, private: Path) -> Path:
    """Provision the maintainer's EXTERNAL fixed fixture entry, never package code.

    Every expectation below comes from this controller's independently selected
    original release admission. Cache/journal bytes cannot select a key, policy,
    verifier, runtime, source, command or another instance. Production is closed.
    The generated POSIX entry runs in the same restricted host environment as
    the online launcher; the controller's Python never runs on that target path.
    """
    state = state.resolve(strict=True)
    closure = state.parent / (state.name + '.installer-artifacts') / 'originals'
    fixture = Path(admission['fixture_directory']).resolve(strict=True)
    verifier = admission['verifier_reference']
    runtime = admission['image_reference']
    platform = admission['platform']
    if (platform not in SUPPORTED_PLATFORMS
            or not re.fullmatch(r'127\.0\.0\.1:46150/volt-installer-verifier@sha256:[0-9a-f]{64}', verifier)
            or not re.fullmatch(r'127\.0\.0\.1:46150/volt@sha256:[0-9a-f]{64}', runtime)
            or not re.fullmatch(r'[0-9a-f]{40}', admission['source_commit'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', admission['source_snapshot'])
            or admission['bundle_version'] != '0.1.0-rc.4'):
        raise ValueError('external offline entry requires the exact original independently admitted fixture release')
    for path in (private, state, closure.parent, fixture):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('external entry private material custody differs')
    if any(parent in (state, closure.parent, closure) for parent in (fixture, *fixture.parents)):
        raise ValueError('external trust material overlaps downloaded cache or instance')
    policies = private / 'public-offline-entry-policies'
    policies.mkdir(mode=0o700)
    for name, predicate in (('signature', 'https://sigstore.dev/cosign/sign/v1'),
                            ('slsa', 'https://slsa.dev/provenance/v1')):
        destination = policies / (name + '.cue')
        with destination.open('x') as stream:
            stream.write(f'predicateType: "{predicate}"\nsubject: [{{digest: {{sha256: "{verifier.split("@sha256:")[1]}"}}}}]\n')
        destination.chmod(0o600)
    base = ['docker', 'run', '--rm', '--platform', platform, '--pull=never', '--network', 'none',
        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--tmpfs',
        '/tmp:rw,noexec,nosuid,size=32m', '--env', 'HOME=/tmp', '--user', f'{os.getuid()}:{os.getgid()}']
    cosign = [*base, '--mount', f'type=bind,src={closure},dst=/closure,readonly',
        '--mount', f'type=bind,src={fixture},dst=/independent-trust,readonly',
        '--mount', f'type=bind,src={policies},dst=/independent-policy,readonly', COSIGN_IMAGE]
    lines = ['#!/bin/sh', 'set -eu', 'umask 077',
        'fail() { printf "%s\\n" "external offline entry: $*" >&2; exit 1; }',
        '[ "$#" -ge 3 ] || fail "fixed action and selected directory required"',
        'action=$1; shift',
        'case "$action" in verify-cache|stop|start|status|logs|diagnose|setup|backup-record|backup-status|restore-provision|restore-admit|destroy) ;; *) fail "unsupported fixed lifecycle action" ;; esac',
        '[ "$1" = --directory ] || fail "selected directory is mandatory"',
        '[ "$2" = ' + shlex.quote(str(state)) + ' ] || fail "different instance refused"', 'shift 2',
        'for argument do [ "$argument" != --directory ] || fail "duplicate directory selector"; done',
        'CLOSURE=' + shlex.quote(str(closure)),
        'if [ ! -e "$CLOSURE" ] && [ ! -L "$CLOSURE" ]; then',
        '  count=0',
        '  for candidate in ' + shlex.quote(str(closure.parent)) + '/.originals.partial.????????; do',
        '    [ -e "$candidate" ] || [ -L "$candidate" ] || continue',
        '    name=${candidate##*/}; suffix=${name#.originals.partial.}',
        '    case "$suffix" in *[!A-Za-z0-9]*|\'\') fail "malformed retained stage name" ;; esac',
        '    [ -d "$candidate" ] && [ ! -L "$candidate" ] || fail "linked retained stage"',
        '    count=$((count + 1)); CLOSURE=$candidate',
        '  done',
        '  [ "$count" -eq 1 ] || fail "single exact retained stage required"',
        'fi',
        '[ -d "$CLOSURE" ] && [ ! -L "$CLOSURE" ] || fail "original cache transport unavailable"']
    for name, predicate in (('signature', 'https://sigstore.dev/cosign/sign/v1'),
                            ('slsa', 'https://slsa.dev/provenance/v1')):
        lines.append(shlex.join([*cosign, 'verify-attestation', '--type', predicate,
            '--policy', '/independent-policy/' + name + '.cue', '--key', '/independent-trust/fixture.pub',
            '--trusted-root', '/independent-trust/trusted-root.json', '--local-image', '/closure/verifier']) + ' >/dev/null')
    for name, signature in (('launcher.sh', 'launcher.sigstore.json'),
                             ('installer.bundle.tar.gz', 'installer.bundle.sigstore.json')):
        lines.append(shlex.join([*cosign, 'verify-blob', '--key', '/independent-trust/fixture.pub',
            '--trusted-root', '/independent-trust/trusted-root.json', '--bundle',
            '/closure/package/' + signature, '/closure/package/' + name]) + ' >/dev/null')
    lines += ['WORK=$(mktemp -d "${TMPDIR:-/tmp}/volt-external-offline.XXXXXXXX")',
        'chmod 700 "$WORK"', "trap 'rm -rf \"$WORK\"' 0 HUP INT TERM",
        shlex.join(['docker', 'image', 'inspect', '--platform', platform, runtime]) + ' >"$WORK/runtime-image.json"',
        shlex.join(['cp', str(closure / 'runtime-index/blobs/sha256' / runtime.split('@sha256:')[1])]) + ' "$WORK/runtime-index.json"',
        'chmod 400 "$WORK/runtime-image.json" "$WORK/runtime-index.json"']
    lines.append('set -- ' + shlex.join(base) +
        ' --mount "type=bind,src=$WORK,dst=/admission,readonly" ' + shlex.join([
            '--mount', f'type=bind,src={closure},dst=/run/volt-offline-artifacts,readonly',
            '--mount', f'type=bind,src={closure.parent},dst=/run/volt-cache-parent,readonly']))
    # verify-cache is the full external authentication BEFORE archive extraction;
    # all lifecycle actions additionally compare the RESTORED/current pin. The
    # missing journal exception never calls a launcher or creates an identity.
    lines += ['if [ "$action" != verify-cache ]; then',
        '  [ -f ' + shlex.quote(str(state / 'instance.json')) + ' ] && [ ! -L ' + shlex.quote(str(state / 'instance.json')) + ' ] || fail "current selected journal missing"',
        '  set -- "$@" ' + shlex.join(['--mount', f'type=bind,src={state / "instance.json"},dst=/run/volt-selected-journal/instance.json,readonly']),
        'fi',
        'set -- "$@" ' + shlex.join([verifier, '--offline-artifacts', '--expected-verifier-reference', verifier,
            '--bundle', '/run/volt-offline-artifacts/package/installer.bundle.tar.gz',
            '--bundle-signature', '/run/volt-offline-artifacts/package/installer.bundle.sigstore.json',
            '--image-inspect', '/admission/runtime-image.json', '--index', '/admission/runtime-index.json',
            '--output-dir', '/tmp/verified', '--reference', runtime, '--signer', SIGNER, '--issuer', ISSUER,
            '--source-revision', admission['source_commit'], '--source-snapshot', admission['source_snapshot'],
            '--version', admission['bundle_version'], '--platform', platform]),
        'if [ "$action" != verify-cache ]; then set -- "$@" --require-installed-pin; fi',
        '"$@" >/dev/null',
        'if [ "$action" = verify-cache ]; then printf "%s\\n" "external_full_graph_verified=1"; exit 0; fi',
        'export VOLT_OFFLINE=1 VOLT_BOOTSTRAP_VERIFIER_VERIFIED=1',
        'export VOLT_EXPECTED_VERIFIER_IMAGE=' + shlex.quote(verifier),
        'export VOLT_EXPECTED_VERSION=' + shlex.quote(admission['bundle_version']),
        'export VOLT_EXPECTED_SIGNER=' + shlex.quote(SIGNER),
        'export VOLT_EXPECTED_ISSUER=' + shlex.quote(ISSUER),
        'exec sh ' + shlex.quote(str(closure / 'package/launcher.sh')) + ' "$action" --directory ' + shlex.quote(str(state)) + ' "$@"']
    # Isolate AUTHENTICATION diagnostics from the signed launcher's terminal
    # result. Successful Cosign noise, including claimed-looking artifact text,
    # can never become a backend maintenance denial. All first failures retain
    # their original exit code and stop before the candidate shell.
    verify_start = next(i for i, line in enumerate(lines) if line.startswith('WORK='))
    verify_end = lines.index('"$@" >/dev/null')
    crypto_start = next(i for i, line in enumerate(lines) if ' verify-attestation ' in line)
    prefix = lines[:crypto_start]
    crypto = [line + ' || return "$?"' for line in lines[crypto_start:verify_start]]
    graph = lines[verify_start + 3:verify_end + 1]
    graph = [line.replace('$WORK/runtime-', '$WORK/admission/runtime-')
        .replace('src=$WORK,dst=/admission', 'src=$WORK/admission,dst=/admission') for line in graph]
    for i, line in enumerate(graph):
        if (line.startswith('docker image inspect ') or line.startswith('cp ')
                or line.startswith('chmod ') or line == '"$@" >/dev/null'):
            graph[i] = line + ' || return "$?"'
    auth_root = private / 'public-offline-authentication'
    auth_root.mkdir(mode=0o700)
    setup = [lines[verify_start], lines[verify_start + 1], lines[verify_start + 2],
        'mkdir -m 700 "$WORK/admission"', 'AUTH_ROOT=' + shlex.quote(str(auth_root)),
        'AUTH_RECORD=$(mktemp -d "$AUTH_ROOT/entry.XXXXXXXX")', 'chmod 700 "$AUTH_RECORD"',
        'mkfifo "$WORK/auth.stderr.pipe"',
        'dd if="$WORK/auth.stderr.pipe" of="$AUTH_RECORD/authentication.stderr" bs=1 count=65536 2>"$AUTH_RECORD/reader.stderr" &',
        'AUTH_READER=$!']
    authentication = ['verify_graph() {', *graph, '}', 'authenticate_originals() {',
        *crypto, 'verify_graph || return "$?"', '}', 'authentication_exit=0',
        'authenticate_originals 2>"$WORK/auth.stderr.pipe" || authentication_exit=$?',
        'reader_exit=0; wait "$AUTH_READER" || reader_exit=$?',
        'printf "%s\\n" "$authentication_exit" >"$AUTH_RECORD/authentication.exit"',
        'printf "%s\\n" "$reader_exit" >"$AUTH_RECORD/reader.exit"',
        'if [ "$authentication_exit" -ne 0 ]; then printf "%s\\n" "external offline authentication failed" >&2; exit "$authentication_exit"; fi',
        'if [ "$reader_exit" -ne 0 ]; then printf "%s\\n" "external offline authentication diagnostic capture failed" >&2; exit 1; fi',
        'rm -rf "$WORK"; WORK=; trap - 0 HUP INT TERM']
    lines = [*prefix, *setup, *authentication, *lines[verify_end + 1:]]
    wrapper = private / 'trusted-offline-entry.sh'
    with wrapper.open('x') as stream:
        script = '\n'.join(lines) + '\n'
        # Only these fixed cache transport arguments expand the selected view;
        # all external trust/identity/release expectations remain literals.
        for destination in ('/closure', '/run/volt-offline-artifacts'):
            argument = f'type=bind,src={closure},dst={destination},readonly'
            script = script.replace(shlex.quote(argument), f'"type=bind,src=$CLOSURE,dst={destination},readonly"')
        for suffix in ('runtime-index/blobs/sha256/' + runtime.split('@sha256:')[1], 'package/launcher.sh'):
            script = script.replace(shlex.quote(str(closure / suffix)), '"$CLOSURE/' + suffix + '"')
        stream.write(script)
    wrapper.chmod(0o700)
    return wrapper


@contextmanager
def owned_registry_outage(evidence: Path):
    """Stop/restart ONLY the previously inspected owned disposable registry."""
    registry = 'volt-easy-delivery-registry'
    rows = json.loads(run('offline-registry-owned-before', ['docker', 'inspect', registry], evidence).stdout)
    expected_image = 'registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
    expected_data = '/tmp/volt-easy-install-20261118/evidence/delivery/trust-positive/registry-data'
    if len(rows) != 1:
        raise RuntimeError('owned registry identity is ambiguous')
    row = rows[0]
    mounts = row.get('Mounts', [])
    if (row.get('Name') != '/' + registry or row.get('Config', {}).get('Image') != expected_image
            or row.get('State', {}).get('Running') is not True
            or row.get('HostConfig', {}).get('PortBindings') !=
                {'5000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '46150'}]}
            or len(mounts) != 1 or mounts[0].get('Type') != 'bind'
            or mounts[0].get('Source') != expected_data or mounts[0].get('Destination') != '/var/lib/registry'
            or not re.fullmatch(r'[0-9a-f]{64}', row.get('Id', ''))):
        raise RuntimeError('registry outage refuses an unowned or contradictory listener/data binding')
    identity = row['Id']
    try:
        run('offline-registry-stop-exact-owned', ['docker', 'stop', identity], evidence)
        stopped = run('offline-registry-stopped', ['docker', 'inspect', identity, '--format', '{{.State.Running}}'], evidence)
        if stopped.stdout.strip() != 'false':
            raise RuntimeError('owned registry outage did not occur')
        yield
    finally:
        run('offline-registry-restore-exact-owned', ['docker', 'start', identity], evidence)
        running = run('offline-registry-restored', ['docker', 'inspect', identity, '--format', '{{.State.Running}}'], evidence)
        if running.stdout.strip() != 'true':
            raise RuntimeError('owned registry did not restart after the outage test')

def host_dependency_json(path: Path) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 1024 * 1024:
            raise ValueError('host dependency metadata is not a bounded regular file')
        raw = stream.read(1024 * 1024 + 1)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) != before.st_size or any(getattr(before, field) != getattr(after, field)
                for after in (os.fstat(stream.fileno()), path.stat(follow_symlinks=False)) for field in fields)):
            raise ValueError('host dependency metadata changed during read')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError('host dependency metadata must be an object')
        return value


def docker_credential_helper_selection(registries: tuple[str, ...]) -> dict:
    """Read only helper selection, never retain Docker authentication values."""
    config_path = Path(os.environ.get('DOCKER_CONFIG', str(Path.home() / '.docker'))) / 'config.json'
    config = {}
    if config_path.exists() or config_path.is_symlink():
        try:
            config = host_dependency_json(config_path)
        except (OSError, ValueError):
            raise RuntimeError('trusted host Docker credential configuration is invalid') from None
    per_registry = config.get('credHelpers', {})
    if not isinstance(per_registry, dict):
        raise RuntimeError('trusted host Docker credential helper selection is invalid')
    selected = []
    for registry in registries:
        field = 'credHelpers' if registry in per_registry else 'credsStore'
        suffix = per_registry.get(registry) if field == 'credHelpers' else config.get('credsStore')
        if suffix in (None, ''):
            continue
        if not isinstance(suffix, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', suffix):
            raise RuntimeError('trusted host Docker credential helper name is invalid')
        selected.append({'registry': registry, 'config_field': field, 'executable': 'docker-credential-' + suffix})
    return {'config_path': str(config_path), 'selections': selected}


def launcher_minimal_environment(bin_directory: Path, *, registries: tuple[str, ...] = ()) -> dict[str, str]:
    """Expose POSIX/Docker plus its exact configured credential dependencies."""
    allowed = ("sh", "docker", "tar", "gzip", "dd", "mktemp", "mkfifo", "dirname", "mkdir", "chmod", "cp", "rm",
               "cat", "cut", "grep", "env", "id", "sleep", "mv")
    selection = docker_credential_helper_selection(registries)
    names = (*allowed, *sorted({item['executable'] for item in selection['selections']}))
    if bin_directory.is_symlink():
        raise RuntimeError('minimal host binary directory cannot be a symlink')
    bin_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = bin_directory.stat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid() or any(item.name not in names for item in bin_directory.iterdir())):
        raise RuntimeError('minimal host binary directory custody or inventory differs')
    tools = []
    for name in names:
        source = shutil.which(name)
        if source is None:
            raise RuntimeError(f"launcher qualification host is missing required POSIX/Docker command: {name}")
        selected = Path(source).absolute()
        resolved = selected.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
            raise RuntimeError('required host Docker/POSIX dependency is not executable')
        link = bin_directory / name
        if link.exists() or link.is_symlink():
            if (not link.is_symlink() or os.readlink(link) != str(selected)
                    or link.resolve(strict=True) != resolved):
                raise RuntimeError('existing minimal host executable contradicts its trusted target')
        else:
            link.symlink_to(selected)
        tools.append({'name': name, 'selected_path': str(selected), 'resolved_path': str(resolved),
            'sha256': sha(resolved), 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid})
    record = {'schema_version': 1, 'registries': list(registries), 'credential_helper_selection': selection,
              'tools': tools}
    record_path = bin_directory.parent / 'minimal-host-tools.json'
    if record_path.is_symlink():
        raise RuntimeError('minimal host dependency record cannot be a symlink')
    if record_path.exists() and host_dependency_json(record_path) != record:
        raise RuntimeError('minimal host Docker/POSIX dependencies changed during the lifecycle')
    if not record_path.exists():
        descriptor = os.open(record_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(record, stream, sort_keys=True, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
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


def qualify_runtime_custody(*, state: Path, project: str, admission: dict, evidence: Path) -> None:
    """Prove the real API UID reads only the live, read-only, host-owned fence."""
    container = project + '-volt-1'
    script = r'''
import json,os,stat
from pathlib import Path
from uvm.connectors.local_recovery import load_authority
value=load_authority(); directory=Path('/run/volt-restore-fence'); file=directory/'fence.json'
d=directory.stat(); f=file.stat(); owner=value.config['restore_fence_custody']['owner_uid']
if os.geteuid()!=1800 or os.getegid()!=1800 or owner==1800:raise SystemExit('distinct host/runtime UID proof missing')
if (d.st_uid,d.st_gid,stat.S_IMODE(d.st_mode))!=(owner,1800,0o710):raise SystemExit('runtime directory mapping differs')
if (f.st_uid,f.st_gid,stat.S_IMODE(f.st_mode))!=(owner,1800,0o640):raise SystemExit('runtime file mapping differs')
try:
 with file.open('ab'):pass
except OSError:pass
else:raise SystemExit('API can write host fence')
print(json.dumps({'runtime_uid':os.geteuid(),'runtime_gid':os.getegid(),'host_uid':owner,
 'directory_mode':'0710','file_mode':'0640','live_fence':'readable','write':'denied'}))
'''
    command = ['docker', 'exec', '--user', '1800:1800', container, '/opt/uvm/venv/bin/python', '-c', script]
    run('actual-nonroot-live-fence', command, evidence)
    directory = state / 'secrets/local-restore-fence'
    original = (directory / 'fence.json').read_text()
    inode = directory.stat().st_ino
    writer = r'''
import os,sys,secrets
from pathlib import Path
root=Path('/fence'); data=sys.stdin.buffer.read(); owner=root.stat().st_uid
if data==b'REMOVE':(root/'fence.json').unlink()
else:
 temp=root/('.probe-'+secrets.token_hex(8)); fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 os.fchmod(fd,0o640);os.fchown(fd,owner,1800)
 with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
 os.replace(temp,root/'fence.json')
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
'''
    mutate = ['docker', 'run', '--rm', '-i', '--platform', admission['platform'], '--network', 'none', '--read-only', '--cap-drop=ALL',
        '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--security-opt=no-new-privileges',
        '--user', '0:0', '--mount', f'type=bind,src={directory},dst=/fence',
        '--entrypoint', '/opt/uvm/venv/bin/python', admission['image_reference'], '-c', writer]
    try:
        wrong = json.loads(original)
        wrong['installation_id'] = str(uuid.uuid4())
        run('host-atomic-contradictory-fence', mutate, evidence, input_text=json.dumps(wrong))
        rejected = run('actual-live-fence-contradiction-negative', command, evidence, check=False)
        if rejected.returncode == 0:
            raise RuntimeError('API reads a stale copy after host atomic replacement')
        run('host-remove-fence', mutate, evidence, input_text='REMOVE')
        rejected = run('actual-live-fence-removal-negative', command, evidence, check=False)
        if rejected.returncode == 0:
            raise RuntimeError('API accepts missing authoritative live fence')
    finally:
        run('host-restore-current-fence', mutate, evidence, input_text=original)
    if directory.stat().st_ino != inode:
        raise RuntimeError('live fence directory inode was replaced')
    run('actual-nonroot-live-fence-restored', command, evidence)


def matching_publication_commit(output: str, expected: dict) -> bool:
    """Require the actual owner's exact post-parent-fsync marker, once."""
    found = 0
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and 'offline_publication_committed' in value:
            if value != expected:
                raise RuntimeError('owner publication marker conflicts with the exact operation/capture')
            found += 1
    if found > 1:
        raise RuntimeError('owner repeated the publication commit marker')
    return found == 1


def qualify_backup_owner_loss(*, setup: Path, launcher: Path | None, launcher_env: dict,
                             state: Path, backup_parent: Path, evidence: Path) -> None:
    """Kill only this test's real FD owner on each side of public publication.

    The controller may observe private exchange paths; the target host still
    executes only its admitted public command. No product fault switch exists.
    """
    info = json.loads((state / 'instance.json').read_text())
    prefix = ([sys.executable, str(setup)] if launcher is None else ['sh', str(launcher)])
    location = [str(state)] if launcher is None else ['--directory', str(state)]
    for timing in ('before', 'after'):
        name = 'backup-owner-loss-' + timing
        destination = backup_parent / name
        command = [*prefix, 'backup-record', *location, '--backup-directory', str(destination)]
        (evidence / (name + '.argv.json')).write_text(json.dumps(command, indent=2) + '\n')
        owner = None
        process = None
        with (evidence / (name + '.stdout')).open('x') as stdout, (evidence / (name + '.stderr')).open('x') as stderr:
            try:
                process = subprocess.Popen(command, env=launcher_env, stdout=stdout, stderr=stderr, start_new_session=True)
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(name + ' public controller ended before fault acquisition')
                    listing = subprocess.run(['docker', 'ps', '-a', '--filter',
                        'name=^/volt-offline-' + info['project'] + '-[0-9]+$',
                        '--filter', 'label=volt.compose.owner-token=' + info['owner_token'],
                        '--format', '{{.ID}}'], capture_output=True, text=True, check=True)
                    ids = listing.stdout.split()
                    if len(ids) > 1:
                        raise RuntimeError('owner-loss test refuses ambiguous existing owners')
                    if ids:
                        inspected = json.loads(run(name + '-owner-mounts', ['docker', 'inspect', ids[0],
                            '--format', '{"name":{{json .Name}},"mounts":{{json .Mounts}}}'], evidence).stdout)
                        shell_pid = int(inspected['name'].rsplit('-', 1)[1])
                        if os.getpgid(shell_pid) != process.pid:
                            raise RuntimeError('fault target was not created by this public caller process group')
                        owner = ids[0]
                        mounts = inspected['mounts']
                        incoming = [row['Source'] for row in mounts if row['Destination'] == '/run/volt-offline-input']
                        outgoing = [row['Source'] for row in mounts if row['Destination'] == '/run/volt-offline-output']
                        if len(incoming) != 1 or len(outgoing) != 1 or Path(incoming[0]).parent != Path(outgoing[0]).parent:
                            raise RuntimeError('actual owner has contradictory fixed exchange mounts')
                        break
                    time.sleep(0.05)
                if owner is None:
                    raise RuntimeError('public backup did not create its actual FD owner')
                target_phase = Path(incoming[0]) / 'captured.json' if timing == 'after' else Path(outgoing[0]) / 'capture.json'
                while not target_phase.is_file():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(name + ' did not reach the required actual phase')
                    time.sleep(0.005)
                if timing == 'after':
                    # Stop the host group AFTER it supplied capture evidence.
                    # The independently running Docker FD owner can validate and
                    # publish; the stopped caller cannot receive completion.
                    os.killpg(process.pid, signal.SIGSTOP)
                    while not destination.is_dir():
                        if time.monotonic() >= deadline:
                            raise RuntimeError('owner did not publish after actual capture input')
                        time.sleep(0.005)
                    captured = json.loads(target_phase.read_text())
                    identity_bytes = (json.dumps(captured['identity'], sort_keys=True, separators=(',', ':')) + '\n').encode()
                    expected_marker = {'offline_publication_committed': destination.name,
                        'operation_id': captured['operation_id'],
                        'identity_sha256': 'sha256:' + hashlib.sha256(identity_bytes).hexdigest(),
                        'completion_sha256': 'sha256:' + sha(destination / 'completion.json')}
                    attempt = 0
                    while True:
                        attempt += 1
                        logs = run(name + '-durable-owner-marker-' + str(attempt), ['docker', 'logs', owner], evidence)
                        if matching_publication_commit(logs.stdout, expected_marker):
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError('owner never confirmed matching durable post-fsync publication')
                        time.sleep(0.05)
                elif destination.exists():
                    raise RuntimeError('prepublication fault was acquired too late')
                run(name + '-kill-actual-owner', ['docker', 'kill', '--signal', 'KILL', owner], evidence)
                if timing == 'after':
                    os.killpg(process.pid, signal.SIGKILL)
                code = process.wait(timeout=180)
                (evidence / (name + '.exit')).write_text(str(code) + '\n')
                if code == 0:
                    raise RuntimeError('owner loss unexpectedly returned public success')
            finally:
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=30)
                if process is not None and not (evidence / (name + '.exit')).exists():
                    (evidence / (name + '.exit')).write_text(str(process.returncode) + '\n')
                if owner is not None:
                    # Exact ID selected above by the owned project/token/name;
                    # no unrelated container is adopted or removed.
                    run(name + '-owner-cleanup', ['docker', 'rm', '-f', owner], evidence, check=False)
        output = (evidence / (name + '.stdout')).read_text()
        correlation = {}
        for key in ('operation_id', 'identity_sha256'):
            matches = re.findall(r'(?m)^offline_' + key + r'=([^\r\n]+)$', output)
            if len(matches) != 1:
                raise RuntimeError('faulted public caller did not retain original correlation')
            correlation[key] = matches[0]
        if re.search(r'(?m)^status=complete$', output):
            raise RuntimeError('owner-loss test did not prevent host completion receipt')
        status_command = [*prefix, 'backup-status', *location, '--backup-directory', str(destination),
            '--operation-id', correlation['operation_id'], '--identity-sha256', correlation['identity_sha256']]
        result = run(name + '-public-readback', status_command, evidence, env=launcher_env, check=False)
        if timing == 'before':
            if destination.exists() or result.returncode == 0 or not list(backup_parent.glob('.' + name + '.partial.*')):
                raise RuntimeError('precommit owner loss did not preserve private partial-only state')
        else:
            value = json.loads(result.stdout) if result.returncode == 0 else {}
            if (not destination.is_dir() or value.get('status') != 'completed_capture'
                    or any(value.get(key) != expected for key, expected in correlation.items())
                    or value.get('host_response_acknowledgement') != 'not_inferred'
                    or value.get('restore_authority') is not False):
                raise RuntimeError('postcommit owner loss lost exact read-only completed capture')
        (evidence / (name + '-outcome.json')).write_text(json.dumps({
            'timing': ('after_durable_publication_before_host_response' if timing == 'after'
                else 'after_capture_authorization_before_publication'),
            'public_exit': code, 'original_correlation': correlation,
            'published': destination.exists(), 'host_completion_received': False,
            'readback_exit': result.returncode, 'scope': 'actual public-path owner loss; admission scope inherited from caller'},
            indent=2) + '\n')


def qualify_local_restore(*, setup: Path, launcher: Path | None, launcher_env: dict, state: Path,
                          private: Path, evidence: Path, admission: dict, project: str,
                          origin: str, password: str, consumed_capability: str,
                          installation_id: str) -> None:
    """Run cold backup/import/admission and the real closed-ingress restore path."""
    cli = [sys.executable, str(setup)]
    # Component development exercises the same maintained storage/session
    # assertions through the existing setup CLI. The full entry point always
    # supplies its independently authenticated source-free launcher.
    stop = [*cli, 'stop', str(state)] if launcher is None else ['sh', str(launcher), 'stop', '--directory', str(state)]
    run('local-cold-stop', stop, evidence, env=launcher_env)
    backup_parent = private / 'backups'
    backup_parent.mkdir(mode=0o700)
    qualify_backup_owner_loss(setup=setup, launcher=launcher, launcher_env=launcher_env,
        state=state, backup_parent=backup_parent, evidence=evidence)
    backup = backup_parent / 'cold-backup'
    capture = ([*cli, 'backup-record', str(state), '--backup-directory', str(backup)] if launcher is None
        else ['sh', str(launcher), 'backup-record', '--directory', str(state), '--backup-directory', str(backup)])
    captured = run('local-backup-record', capture, evidence, env=launcher_env)
    correlation = {}
    for key in ('operation_id', 'identity_sha256'):
        values = re.findall(r'(?m)^offline_' + key + r'=([^\r\n]+)$', captured.stdout)
        if len(values) != 1:
            raise RuntimeError('backup did not retain one exact pre-publication ' + key)
        correlation[key] = values[0]
    status = ([*cli, 'backup-status', str(state)] if launcher is None else
        ['sh', str(launcher), 'backup-status', '--directory', str(state)])
    status += ['--backup-directory', str(backup), '--operation-id', correlation['operation_id'],
        '--identity-sha256', correlation['identity_sha256']]
    reconciled = json.loads(run('local-backup-status', status, evidence, env=launcher_env).stdout)
    if (reconciled.get('status') != 'completed_capture'
            or any(reconciled.get(key) != value for key, value in correlation.items())
            or reconciled.get('read_only_reconciliation') is not True
            or reconciled.get('restore_authority') is not False
            or reconciled.get('host_response_acknowledgement') != 'not_inferred'):
        raise RuntimeError('completed capture readback did not match the original operation')
    wrong_status = status.copy()
    wrong_status[wrong_status.index('--operation-id') + 1] = str(uuid.uuid4())
    if run('local-backup-status-cross-operation-negative', wrong_status, evidence,
            env=launcher_env, check=False).returncode == 0:
        raise RuntimeError('capture readback accepted another operation UUID')
    inventory = json.loads((state / 'instance.json').read_text())['backup_inventory']
    (evidence / 'local-cold-store-inventories.json').write_text(json.dumps(inventory, sort_keys=True, indent=2) + '\n')
    image = admission['image_reference']
    (evidence / 'local-backup-digests.json').write_text(json.dumps({
        name: sha(backup / (name + '.tar')) for name in ('postgres', 'media', 'state', 'instance')},
        sort_keys=True, indent=2) + '\n')
    destroy = ([*cli, 'cleanup', str(state), '--confirm-project', project, '--remove-data'] if launcher is None
        else ['sh', str(launcher), 'destroy', '--directory', str(state), '--confirm-project', project, '--remove-state'])
    run('local-destroy-before-restore', destroy, evidence, env=launcher_env)
    if launcher is not None:
        run('local-pre-extraction-external-full-graph', ['sh', str(launcher), 'verify-cache',
            '--directory', str(state)], evidence, env=launcher_env)
    state.mkdir(mode=0o700)
    run('local-restore-instance', ['docker', 'run', '--rm', '--pull=never', '--platform', admission['platform'], '--network', 'none',
        '--mount', f'type=bind,src={state},dst=/target',
        '--mount', f'type=bind,src={backup},dst=/backup,readonly', '--entrypoint', '/bin/bash', image,
        '-c', 'tar --numeric-owner -xpf /backup/instance.tar -C /target'], evidence)
    provision = ([*cli, 'restore-provision', str(state)] if launcher is None
        else ['sh', str(launcher), 'restore-provision', '--directory', str(state)])
    admit = ([*cli, 'restore-admit', str(state)] if launcher is None
        else ['sh', str(launcher), 'restore-admit', '--directory', str(state)])
    run('local-restore-provision', provision, evidence, env=launcher_env)
    expected = json.loads((state / 'instance.json').read_text())['local_recovery_custody']
    negative = run('local-restore-empty-import-negative', admit, evidence, env=launcher_env, check=False)
    if negative.returncode == 0:
        raise RuntimeError('local restore accepted empty stores')
    for store in ('postgres', 'media', 'state'):
        run('local-restore-import-' + store, ['docker', 'run', '--rm', '--pull=never', '--platform', admission['platform'], '--network', 'none',
            '--mount', f'type=volume,src={project}_{store},dst=/target',
            '--mount', f'type=bind,src={backup},dst=/backup,readonly', '--entrypoint', '/bin/bash', image,
            '-c', f'tar --numeric-owner -xpf /backup/{store}.tar -C /target'], evidence)
    # A real corruption is detected before runtime execution, then removed.
    run('local-restore-corrupt-state', ['docker', 'run', '--rm', '--pull=never', '--platform', admission['platform'], '--network', 'none',
        '--mount', f'type=volume,src={project}_state,dst=/target', '--entrypoint', '/bin/bash', image,
        '-c', 'printf corrupt > /target/.volt-qualification-corruption'], evidence)
    negative = run('local-restore-corruption-negative', admit, evidence, env=launcher_env, check=False)
    if negative.returncode == 0:
        raise RuntimeError('local restore accepted corrupted store')
    run('local-restore-remove-corruption', ['docker', 'run', '--rm', '--pull=never', '--platform', admission['platform'], '--network', 'none',
        '--mount', f'type=volume,src={project}_state,dst=/target', '--entrypoint', '/bin/bash', image,
        '-c', 'rm /target/.volt-qualification-corruption'], evidence)
    run('local-restore-admit', admit, evidence, env=launcher_env)
    start = [*cli, 'start', str(state)] if launcher is None else ['sh', str(launcher), 'start', '--directory', str(state)]
    run('local-restore-start', start, evidence, env=launcher_env)
    qualify_restored_local_public_state(setup=setup, launcher=launcher, launcher_env=launcher_env,
        state=state, private=private, evidence=evidence, origin=origin, password=password,
        consumed_capability=consumed_capability, installation_id=installation_id, expected=expected)
    (evidence / 'local-restore-journey.json').write_text(json.dumps({'status': 'passed',
        'execution_scope': 'component_existing_setup' if launcher is None else 'source_free_signed_launcher',
        'three_store_cold_backup': 'passed', 'offline_inventory_admission': 'passed',
        'empty_and_corrupt_import_rejection': 'passed',
        'public_outcomes': json.loads((evidence / 'local-restore-public-outcomes.json').read_text())},
        sort_keys=True, indent=2) + '\n')



def require_claimed_setup_denial(result: subprocess.CompletedProcess) -> None:
    """Only the isolated signed-launcher terminal result can prove this cause."""
    if (result.returncode != 1 or result.stdout != ''
            or result.stderr != 'volt installer: initial setup is already claimed\n'):
        raise RuntimeError('claimed-state backend maintenance denial was not explicitly established')


def qualify_restored_local_public_state(*, setup: Path, launcher: Path | None, launcher_env: dict,
        state: Path, private: Path, evidence: Path, origin: str, password: str,
        consumed_capability: str, installation_id: str, expected: dict) -> None:
    """Verify the public outcomes after the maintained offline restore/start."""
    cli = [sys.executable, str(setup)]
    wait_for_local(origin, evidence)
    restored = json.loads((state / 'instance.json').read_text())
    acknowledgement = restored.get('local_recovery_acknowledgement', {})
    if (restored.get('restore_pending') or not restored.get('restore_sessions_revoked')
            or not restored.get('restore_capabilities_revoked')
            or any(acknowledgement.get(key) != value for key, value in expected.items())):
        raise RuntimeError('normal ingress lacks an exact host-journalled restore acknowledgement')
    (evidence / 'local-restore-acknowledgement.json').write_text(json.dumps(acknowledgement, sort_keys=True, indent=2) + '\n')
    session_evidence = evidence / 'browser-restored-session'
    session_evidence.mkdir(mode=0o700)
    run('browser-restored-session-revocation', ['node', str(ROOT / 'tools/g7_local_preview_smoke.mjs'),
        '--local', '--origin', origin, '--evidence', str(session_evidence), '--verify-restored-session',
        '--browser-state', str(private / 'pre-restore-browser.json')], evidence)
    setup_evidence = evidence / 'browser-restored-setup-closed'
    setup_evidence.mkdir(mode=0o700)
    run('browser-restored-setup-consumed', ['node', str(ROOT / 'tools/g7_local_preview_smoke.mjs'),
        '--local', '--origin', origin, '--evidence', str(setup_evidence), '--verify-setup-closed',
        '--credentials-stdin'], evidence, input_text=json.dumps({
            'capability': consumed_capability, 'username': 'probe-' + uuid.uuid4().hex[:16],
            'display_name': 'Restore denial probe', 'password': secrets.token_urlsafe(32) + 'A7!'}))
    login = ['node', str(ROOT / 'tools/compose_release_login.mjs'), origin, str(private / 'cookie'), '--local-stdin']
    run('browser-local-login-after-restore', login, evidence,
        input_text=json.dumps({'username': 'qualification-admin', 'password': password}))
    protected_local_readback(origin, private / 'cookie', installation_id, evidence, 'local-restored-protected-readback')
    setup_again = ([*cli, 'prepare-setup', str(state), '--unattended'] if launcher is None
        else ['sh', str(launcher), 'setup', '--directory', str(state)])
    negative = run('local-restored-setup-maintenance-negative', setup_again,
        evidence, env=launcher_env, check=False)
    require_claimed_setup_denial(negative)
    (evidence / 'local-restore-public-outcomes.json').write_text(json.dumps({'status': 'passed',
        'execution_scope': 'component_existing_setup' if launcher is None else 'source_free_signed_launcher',
        'exact_host_ack_before_ingress': 'passed',
        'session_revocation': 'passed', 'consumed_setup_preserved': 'passed',
        'protected_account_readback': 'passed'}, sort_keys=True, indent=2) + '\n')


def qualify_inventory_cause_fixture(*, bundle: Path, fixture: Path, image_id: str,
        source_revision: str, source_snapshot: str, platform: str, private: Path,
        evidence: Path) -> None:
    """Focused CURRENT-source public cold fixture; retain until cause review.

    No account/capability manipulation, browser/session suite or SQL. The one
    real supported startup supplies a legitimate current backup for the two
    inventory probes after the original qualification cleaned its fixtures.
    """
    admission = validate_admission_fixture(fixture, image_id=image_id,
        source_snapshot=source_snapshot, source_commit=source_revision,
        platform=platform, bundle=bundle, version='0.1.0-rc.4', evidence=evidence)
    extracted = private / 'extracted'; extracted.mkdir(mode=0o700)
    shutil.unpack_archive(str(bundle), extracted, 'gztar')
    package = extracted / 'volt-compose-0.1.0-rc.4'
    outer = private / 'signed-package'; outer.mkdir(mode=0o700)
    launcher = outer / 'launcher.sh'
    render_fixture_launcher(package / 'launcher.sh', launcher, fixture)
    shutil.copyfile(bundle, outer / 'installer.bundle.tar.gz')
    for name in ('installer.bundle.sigstore.json', 'launcher.sigstore.json'):
        shutil.copyfile(fixture / name, outer / name)
    for path in outer.iterdir(): path.chmod(0o600)
    public = evidence / 'fixture-trust-public'
    run('focused-trusted-launcher-signature', ['docker', 'run', '--rm', '--platform', platform,
        '--pull=never', '--network', 'host', '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
        '--user', f'{os.getuid()}:{os.getgid()}', '--mount', f'type=bind,src={public},dst=/fixture,readonly',
        '--mount', f'type=bind,src={launcher},dst=/launcher,readonly', COSIGN_IMAGE,
        'verify-blob', '--key', '/fixture/fixture.pub', '--trusted-root', '/fixture/trusted-root.json',
        '--bundle', '/fixture/launcher.sigstore.json', '/launcher'], evidence)
    environment = trusted_launcher_environment(private / 'minimal-host-path', admission)
    state = private / 'instance'
    run('focused-public-install', ['sh', str(launcher), 'install', '--directory', str(state),
        '--port', '46180', '--project-prefix', 'volt-easy-delivery'], evidence, env=environment)
    wait_for_local('http://127.0.0.1:46180', evidence)
    info = json.loads((state / 'instance.json').read_text()); project = info['project']
    if (info['image_admission']['source_revision'] != source_revision
            or info['image_admission']['source_snapshot'] != source_snapshot):
        raise RuntimeError('focused public instance differs from the original admitted current source')
    # Retain immediately, including if a later assertion fails; no auto teardown
    # may erase the very owner/backup evidence this focused replay is collecting.
    (evidence / 'retained-fixture.json').write_text(json.dumps({'private': str(private),
        'state': str(state), 'original_signed_launcher': str(launcher), 'project': project,
        'admission': admission, 'runtime_source_revision': source_revision,
        'scope': 'CURRENT-source inventory cause fixture; no claimed-state/account/session proof',
        'cleanup': 'retain until independent cause review, then exact public owned destroy'}, indent=2) + '\n')
    offline = create_offline_fixture_entry(state=state, admission=admission, private=private)
    run('focused-public-cold-stop', ['sh', str(offline), 'stop', '--directory', str(state)], evidence, env=environment)
    parent = private / 'backups'; parent.mkdir(mode=0o700); backup = parent / 'cold-backup'
    run('focused-public-backup', ['sh', str(offline), 'backup-record', '--directory', str(state),
        '--backup-directory', str(backup)], evidence, env=environment)
    run('focused-public-destroy-before-restore', ['sh', str(offline), 'destroy', '--directory', str(state),
        '--confirm-project', project, '--remove-state'], evidence, env=environment)
    run('focused-external-verify-before-extract', ['sh', str(offline), 'verify-cache', '--directory', str(state)], evidence, env=environment)
    state.mkdir(mode=0o700)
    image = admission['image_reference']
    base = ['docker', 'run', '--rm', '--platform', platform, '--pull=never', '--network', 'none']
    run('focused-instance-extract', [*base, '--mount', f'type=bind,src={state},dst=/target',
        '--mount', f'type=bind,src={backup},dst=/backup,readonly', '--entrypoint', '/bin/bash', image,
        '-c', 'tar --numeric-owner -xpf /backup/instance.tar -C /target'], evidence)
    run('focused-public-restore-provision', ['sh', str(offline), 'restore-provision', '--directory', str(state)], evidence, env=environment)
    qualify_inventory_rejection(kind='empty', launcher=offline, state=state, private=private,
        evidence=evidence, environment=environment, admission=admission)
    for store in ('postgres', 'media', 'state'):
        run('focused-store-import-' + store, [*base, '--mount', f'type=volume,src={project}_{store},dst=/target',
            '--mount', f'type=bind,src={backup},dst=/backup,readonly', '--entrypoint', '/bin/bash', image,
            '-c', f'tar --numeric-owner -xpf /backup/{store}.tar -C /target'], evidence)
    run('focused-state-corruption', [*base, '--mount', f'type=volume,src={project}_state,dst=/target',
        '--entrypoint', '/bin/bash', image, '-c', 'printf corrupt > /target/.volt-qualification-corruption'], evidence)
    qualify_inventory_rejection(kind='corrupt', launcher=offline, state=state, private=private,
        evidence=evidence, environment=environment, admission=admission)
    run('focused-remove-state-corruption', [*base, '--mount', f'type=volume,src={project}_state,dst=/target',
        '--entrypoint', '/bin/bash', image, '-c', 'rm /target/.volt-qualification-corruption'], evidence)
    run('focused-public-valid-admit', ['sh', str(offline), 'restore-admit', '--directory', str(state)], evidence, env=environment)
    (evidence / 'focused-inventory-cause-outcome.json').write_text(json.dumps({
        'status': 'empty_corrupt_specific_causes_and_valid_admission_passed',
        'runtime_source_revision': source_revision, 'runtime_source_snapshot': source_snapshot,
        'fixture_retained_for_review': True, 'private': str(private),
        'instrumentation': 'read-only POSIX owner-log capture before ORIGINAL Docker removal; no command/result changes',
        'account_operations': False, 'browser_or_session_regression': False,
        'original9657_full_journey_records_unchanged': True,
    }, indent=2) + '\n')


def claim_first_admin_for_maintenance(*, state: Path, private: Path, evidence: Path) -> None:
    """One genuine claim; retain credentials privately and never capture cookies."""
    import urllib.request
    from uvm.installer.lock import _bounded_file
    origin = 'http://127.0.0.1:46180'
    capability = _bounded_file(state / 'secrets/bootstrap-capability-output', 4096, private=True).decode().strip()
    if not capability:
        raise RuntimeError('genuine public setup capability is missing')
    payload = json.dumps({'capability': capability, 'username': 'maintenance-proof-admin',
        'display_name': 'Maintenance proof administrator',
        'password': secrets.token_urlsafe(32) + 'A7!'}).encode()
    destination = private / 'setup-credentials.json'
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    request = urllib.request.Request(origin + '/api/v1/auth/setup/claim', data=payload,
        headers={'Content-Type': 'application/json', 'Origin': origin}, method='POST')
    # No environment proxy, CookieJar, redirect, login or cookie persistence.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            status = response.status; raw = response.read(65537)
        if status != 201 or len(raw) > 65536:
            raise ValueError('public claim status or response bound differs')
        result = json.loads(raw)
        principal = str(uuid.UUID(result['principal_id'])); receipt = str(uuid.UUID(result['receipt_id']))
        if result.get('authenticated') is not True or result.get('credential_mode') != 'local_session':
            raise ValueError('public claim response is not an authenticated local claim')
    except Exception:
        raise RuntimeError('the one supported public first-admin claim failed; private response suppressed') from None
    (evidence / 'focused-public-first-admin-claim.json').write_text(json.dumps({
        'method': 'POST', 'path': '/api/v1/auth/setup/claim', 'origin': origin,
        'status': status, 'principal_id': principal, 'receipt_id': receipt,
        'genuine_issued_capability': True, 'cookie_saved_or_reused': False,
        'credentials': 'retained only in private0600 setup-credentials.json',
    }, indent=2) + '\n')


def qualify_claimed_setup_fixture(*, bundle: Path, fixture: Path, image_id: str,
        source_revision: str, source_snapshot: str, platform: str, private: Path,
        evidence: Path) -> None:
    """Narrow signed-package claimed maintenance proof, with one public claim.

    No browser/login/session/readback suite or inventory fault replay. Preserve
    the owned fixture for independent review of the exact backend diagnostic.
    """
    admission = validate_admission_fixture(fixture, image_id=image_id,
        source_snapshot=source_snapshot, source_commit=source_revision,
        platform=platform, bundle=bundle, version='0.1.0-rc.4', evidence=evidence)
    extracted = private / 'extracted'; extracted.mkdir(mode=0o700)
    shutil.unpack_archive(str(bundle), extracted, 'gztar')
    package = extracted / 'volt-compose-0.1.0-rc.4'
    outer = private / 'signed-package'; outer.mkdir(mode=0o700)
    launcher = outer / 'launcher.sh'
    render_fixture_launcher(package / 'launcher.sh', launcher, fixture)
    shutil.copyfile(bundle, outer / 'installer.bundle.tar.gz')
    for name in ('installer.bundle.sigstore.json', 'launcher.sigstore.json'):
        shutil.copyfile(fixture / name, outer / name)
    for path in outer.iterdir(): path.chmod(0o600)
    public = evidence / 'fixture-trust-public'
    run('focused-trusted-launcher-signature', ['docker', 'run', '--rm', '--platform', platform,
        '--pull=never', '--network', 'host', '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
        '--user', f'{os.getuid()}:{os.getgid()}', '--mount', f'type=bind,src={public},dst=/fixture,readonly',
        '--mount', f'type=bind,src={launcher},dst=/launcher,readonly', COSIGN_IMAGE,
        'verify-blob', '--key', '/fixture/fixture.pub', '--trusted-root', '/fixture/trusted-root.json',
        '--bundle', '/fixture/launcher.sigstore.json', '/launcher'], evidence)
    environment = trusted_launcher_environment(private / 'minimal-host-path', admission)
    state = private / 'instance'
    run('focused-public-install', ['sh', str(launcher), 'install', '--directory', str(state),
        '--port', '46180', '--project-prefix', 'volt-easy-delivery'], evidence, env=environment)
    wait_for_local('http://127.0.0.1:46180', evidence)
    info = json.loads((state / 'instance.json').read_text()); project = info['project']
    if (info['image_admission']['source_revision'] != source_revision
            or info['image_admission']['source_snapshot'] != source_snapshot):
        raise RuntimeError('focused public instance differs from the original admitted current source')
    # Retain immediately, including if a later assertion fails; no auto teardown
    # may erase the very owner/backup evidence this focused replay is collecting.
    (evidence / 'retained-fixture.json').write_text(json.dumps({'private': str(private),
        'state': str(state), 'original_signed_launcher': str(launcher), 'project': project,
        'admission': admission, 'runtime_source_revision': source_revision,
        'scope': 'CURRENT-source one genuine public claim and exact setup denial before/after cold restore',
        'cleanup': 'retain until independent cause review, then exact public owned destroy'}, indent=2) + '\n')
    claim_first_admin_for_maintenance(state=state, private=private, evidence=evidence)
    offline = create_offline_fixture_entry(state=state, admission=admission, private=private)
    before = run('focused-claimed-setup-before-restore', ['sh', str(offline), 'setup', '--directory', str(state)], evidence, env=environment, check=False)
    require_claimed_setup_denial(before)
    run('focused-public-cold-stop', ['sh', str(offline), 'stop', '--directory', str(state)], evidence, env=environment)
    parent = private / 'backups'; parent.mkdir(mode=0o700); backup = parent / 'cold-backup'
    run('focused-public-backup', ['sh', str(offline), 'backup-record', '--directory', str(state),
        '--backup-directory', str(backup)], evidence, env=environment)
    run('focused-public-destroy-before-restore', ['sh', str(offline), 'destroy', '--directory', str(state),
        '--confirm-project', project, '--remove-state'], evidence, env=environment)
    run('focused-external-verify-before-extract', ['sh', str(offline), 'verify-cache', '--directory', str(state)], evidence, env=environment)
    state.mkdir(mode=0o700)
    image = admission['image_reference']
    base = ['docker', 'run', '--rm', '--platform', platform, '--pull=never', '--network', 'none']
    run('focused-instance-extract', [*base, '--mount', f'type=bind,src={state},dst=/target',
        '--mount', f'type=bind,src={backup},dst=/backup,readonly', '--entrypoint', '/bin/bash', image,
        '-c', 'tar --numeric-owner -xpf /backup/instance.tar -C /target'], evidence)
    run('focused-public-restore-provision', ['sh', str(offline), 'restore-provision', '--directory', str(state)], evidence, env=environment)
    for store in ('postgres', 'media', 'state'):
        run('focused-store-import-' + store, [*base, '--mount', f'type=volume,src={project}_{store},dst=/target',
            '--mount', f'type=bind,src={backup},dst=/backup,readonly', '--entrypoint', '/bin/bash', image,
            '-c', f'tar --numeric-owner -xpf /backup/{store}.tar -C /target'], evidence)
    run('focused-public-valid-admit', ['sh', str(offline), 'restore-admit', '--directory', str(state)], evidence, env=environment)
    run('focused-public-restored-start', ['sh', str(offline), 'start', '--directory', str(state)], evidence, env=environment)
    wait_for_local('http://127.0.0.1:46180', evidence)
    after = run('focused-claimed-setup-after-restore', ['sh', str(offline), 'setup', '--directory', str(state)], evidence, env=environment, check=False)
    require_claimed_setup_denial(after)
    (evidence / 'focused-claimed-setup-outcome.json').write_text(json.dumps({
        'status': 'exact_claimed_setup_denial_before_and_after_public_cold_restore',
        'runtime_source_revision': source_revision, 'runtime_source_snapshot': source_snapshot,
        'fixture_retained_for_review': True, 'private': str(private),
        'public_claims': 1, 'browser_login_session_readback_suite': False,
        'terminal': {'exit': 1, 'stdout': '', 'stderr': 'volt installer: initial setup is already claimed\n'},
        'original9657_records_unchanged': True,
    }, indent=2) + '\n')


def qualify_public_readonly_diagnostics(*, package: Path, bundle: Path, admission: dict[str, str],
                          state: Path, private: Path, evidence: Path,
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
    run("fixture-trusted-launcher-signature", ["docker", "run", "--rm", "--platform", admission["platform"], "--network", "host",
        "--read-only", "--cap-drop=ALL", "--user", f"{os.getuid()}:{os.getgid()}", "--security-opt=no-new-privileges", "--tmpfs",
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
    shutil.copyfile(private / 'minimal-host-tools.json', evidence / 'minimal-host-tools.json')
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
    qualify_runtime_custody(state=state, project=project, admission=admission, evidence=evidence)
    offline_entry = create_offline_fixture_entry(state=state, admission=admission, private=private)
    from uvm.installer.lock import _bounded_file
    paths = [state/'instance.json', state/'.env', state/'local-auth.json', state/'local-recovery.json']
    paths += [p for p in (state/'secrets').rglob('*') if p.is_file() and not p.is_symlink()
              and p.stat().st_uid == os.getuid() and stat.S_IMODE(p.stat().st_mode) in (0o600,0o640)]
    def fingerprints():
        return {str(p.relative_to(state)): hashlib.sha256(_bounded_file(p,1024*1024,private=False)).hexdigest() for p in paths}
    before = fingerprints()
    with owned_registry_outage(evidence):
        denied = run('diagnostics-registry-fetch-denied', ['docker','buildx','imagetools','inspect','--raw',admission['image_reference']], evidence,env=launcher_env,check=False)
        if denied.returncode == 0: raise RuntimeError('owned registry outage was not effective')
        for phase in ('running','stopped'):
            if phase == 'stopped':
                run('diagnostics-public-cold-stop',['sh',str(offline_entry),'stop','--directory',str(state)],evidence,env=launcher_env)
            for action in ('status','diagnose','logs'):
                result = run('diagnostics-'+phase+'-'+action,['sh',str(offline_entry),action,'--directory',str(state)],evidence,env=launcher_env)
                if action == 'diagnose':
                    value=json.loads(result.stdout)
                    if (set(value) != {'schema_version','profile','release','instance','container','resources','private_checks'}
                            or value['profile'] != 'volt_instance_diagnostics_v1'
                            or value['instance']['project'] != project
                            or value['release']['source_revision'] != admission['source_commit']
                            or value['container']['running'] is not (phase == 'running')
                            or value['container']['status'] != ('running' if phase == 'running' else 'exited')
                            or value['resources']['network_internal'] is not False):
                        raise RuntimeError('public diagnostic projection differs from current admitted running/stopped instance')
                elif action == 'logs':
                    value=json.loads(result.stdout)
                    if (value['profile'] != 'volt_redacted_runtime_markers_v1' or not value['markers']
                            or value['producer_exit'] != 0 or value['reader_exit'] != 0
                            or value['reader_outcome'] != 'complete' or value['truncated'] is not False):
                        raise RuntimeError('public current-run logs did not preserve successful producer/reader outcomes')
            if fingerprints() != before: raise RuntimeError('read-only diagnostics changed observed host private state')
    cache=state.parent/(state.name+'.installer-artifacts')/'originals'
    from uvm.installer.offline_artifacts import Closure
    material=Closure(fixture=None,custody_root=cache)
    if material.hash != info['installer_admission']['closure_sha256']:
        raise RuntimeError('actual installed verification material differs from the journal pin')
    retained=evidence/'actual-installed-originals';shutil.copytree(cache,retained)
    for path in retained.rglob('*'):path.chmod(0o700 if path.is_dir() else 0o600)
    retained.chmod(0o700);material.assert_unchanged()
    if Closure(fixture=None,custody_root=retained).hash != material.hash:
        raise RuntimeError('retained original verification material differs')
    (evidence/'public-diagnostics-outcome.json').write_text(json.dumps({
        'status':'running_and_stopped_public_diagnose_logs_status_passed_under_registry_outage',
        'runtime_source':admission['source_commit'],'source_snapshot':admission['source_snapshot'],
        'observed_host_fingerprints':before,'complete_runtime_private_byte_coverage':False,
        'observed_host_private_bytes_unchanged':True,'no_account_browser_or_session_operations':True,
        'actual_installed_closure_sha256':material.hash,'full_qualification':False,
    },indent=2)+'\n')
    return project, launcher, launcher_env

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
    run("fixture-trusted-launcher-signature", ["docker", "run", "--rm", "--platform", admission["platform"], "--network", "host",
        "--read-only", "--cap-drop=ALL", "--user", f"{os.getuid()}:{os.getgid()}", "--security-opt=no-new-privileges", "--tmpfs",
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
    shutil.copyfile(private / 'minimal-host-tools.json', evidence / 'minimal-host-tools.json')
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
    qualify_runtime_custody(state=state, project=project, admission=admission, evidence=evidence)
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
    consumed_capability = capability
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
    run("browser-local-login-after-restart", [*login, "--save-browser-state", str(private / "pre-restore-browser.json")], evidence,
        input_text=json.dumps({"username": "qualification-admin", "password": password}))
    protected_local_readback(origin, private / "cookie", local_config["installation_id"],
                             evidence, "local-restart-protected-deployment-readback")
    offline_entry = create_offline_fixture_entry(state=state, admission=admission, private=private)
    run('external-offline-entry-syntax', ['sh', '-n', str(offline_entry)], evidence, env=launcher_env)
    with owned_registry_outage(evidence):
        unavailable = run('offline-owned-registry-fetch-denied', ['docker', 'buildx', 'imagetools',
            'inspect', '--raw', admission['image_reference']], evidence, env=launcher_env, check=False)
        if unavailable.returncode == 0:
            raise RuntimeError('owned registry metadata unexpectedly available during the outage')
        qualify_local_restore(setup=package / "setup.py", launcher=offline_entry, launcher_env=launcher_env,
            state=state, private=private, evidence=evidence, admission=admission, project=project,
            origin=origin, password=password, consumed_capability=consumed_capability,
            installation_id=local_config["installation_id"])
    (evidence / "local-auth-journey.json").write_text(json.dumps({
        "status": "passed",
        "host_runtime": "Restricted POSIX shell and Docker/Compose; externally authenticated complete cached graph and public cold restore under owned registry outage",
        "minimal_host_cold_restore_qualified": True,
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
        "restore_stage": "passed_cold_restore_authentication",
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
    p.add_argument("--diagnostics-only", action="store_true",
                   help="focused local public read-only diagnostics/status/logs under owned registry outage; no account/browser journey")
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--private-tmp", type=Path, default=Path("/tmp"),
                   help="parent directory for private generated state and backup fixtures")
    p.add_argument("--bundle-tmp", type=Path, default=Path("/tmp"),
                   help="parent directory for the small source-free installer extraction")
    p.add_argument("--project-prefix", default="volt-rc2-qual",
                   help="unique Compose project prefix used for owned disposable resources")
    args = p.parse_args()
    if args.diagnostics_only and args.auth_mode != "local":
        p.error("--diagnostics-only requires independently admitted local RC4 qualification")
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
            if args.diagnostics_only:
                project, setup, launcher_environment = qualify_public_readonly_diagnostics(package=package_root,
                    bundle=args.bundle, admission=admission, state=state, private=private,
                    evidence=evidence, http_port=46180, project_prefix=args.project_prefix)
            else:
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
            if args.diagnostics_only:
                (evidence / "qualification.json").write_text(json.dumps({
                    "result":"passed_focused_read_only_diagnostics", "full_qualification":False,
                    **release_metadata,"project":project,"scope":"development_fixture",
                    "account_browser_session_journey":False,"scanner_stage":"pending",
                    "read_only_diagnostics":"passed_running_stopped_registry_outage",
                },sort_keys=True,indent=2)+"\n")
                outcome=0
            else:
                (evidence / "qualification.json").write_text(json.dumps({
                    "result": "incomplete", "full_qualification": False, **release_metadata,
                    "project": project, "local_auth_process": "passed",
                    "scanner_provider": "Qualys", "scanner_stage": "pending",
                    "restore_stage": "passed_cold_restore_authentication",
                    "reason": "Provider ingestion and scanner recovery remain unqualified.",
                }, sort_keys=True, indent=2) + "\n")
                outcome=2
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
