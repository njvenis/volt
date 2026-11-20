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


def fixture_inspect_argv(reference: str, platform: str, *, inspect_platform: bool) -> list[str]:
    """Choose once from advertised/API capability; never retry a failed inspect.

    Ordinary inspection is still full JSON, admitted by the same independent Q
    against the exact platform/config/selected descriptor and original cache.
    """
    if (type(inspect_platform)is not bool or platform not in SUPPORTED_PLATFORMS
            or not re.fullmatch(r'127\.0\.0\.1:46150/volt@sha256:[0-9a-f]{64}',reference)):
        raise ValueError('fixed runtime inspection context required')
    return ['docker','image','inspect',*(['--platform',platform]if inspect_platform else []),reference]


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
    from tools.release.native_runtime_probe import audit_docker_cli
    capabilities = audit_docker_cli(lambda label, argv: run('fixture-capability-' + label, argv, evidence))
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
    inspected = run("fixture-runtime-inspect", fixture_inspect_argv(image_reference,platform,inspect_platform=capabilities["inspect_platform"]), evidence)
    try:
        image_row = json.loads(inspected.stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise RuntimeError("fixture runtime inspection did not return one image") from exc
    if (image_row.get("Descriptor") or {}).get("mediaType") in {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}:
        if not capabilities['inspect_platform']:
            raise RuntimeError('ordinary inspection cannot select an ambiguous runtime index')
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
    result["docker_inspect_platform"] = capabilities["inspect_platform"]
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
  mode=before_removal
  if [ "$#" -eq 1 ] && [ "$1" = --volt-capture-retained-restore-owner ]; then
    mode=retained_after_caller; target=''
  else
    [ "$#" -eq 3 ] && [ "$1" = rm ] && [ "$2" = -f ] || return 0
    target=$3
  fi
  IFS= read -r caller <"$PID_FILE" || return 0
  case "$caller" in ''|*[!0-9]*) return 0 ;; esac
  expected_name="volt-offline-$EXPECTED_PROJECT-$caller"
  if [ "$mode" = before_removal ] && [ "$target" != "$expected_name" ]; then
    case "$target" in ''|*[!0-9a-f]*) return 0 ;; esac
    [ "${#target}" -eq 64 ] || return 0
  fi
  if [ -e "$CAPTURE/guard.status" ]; then
    printf '%s\n' duplicate >"$CAPTURE/duplicate.status"; return 0
  fi
  identity=$("$REAL_DOCKER" inspect "$expected_name" --format '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "volt.compose.project"}}|{{json .Config.Cmd}}|{{.Image}}|{{if .ImageManifestDescriptor}}{{.ImageManifestDescriptor.digest}}|{{.ImageManifestDescriptor.mediaType}}|{{.ImageManifestDescriptor.size}}|{{.ImageManifestDescriptor.platform.os}}/{{.ImageManifestDescriptor.platform.architecture}}{{end}}' 2>"$CAPTURE/identity.stderr") || {
    printf '%s\n' unavailable >"$CAPTURE/guard.status"; return 0;
  }
  printf '%s\n' "$identity" >"$CAPTURE/identity.txt"
  IFS='|' read -r cid name reference owner project command image child media size platform <<EOF_OWNER_ID
$identity
EOF_OWNER_ID
  case "$cid" in ''|*[!0-9a-f]*) printf '%s\n' invalid >"$CAPTURE/guard.status"; return 0 ;; esac
  if [ "$mode" = before_removal ] && [ "$target" != "$expected_name" ] && [ "$target" != "$cid" ]; then return 0; fi
  [ "${#cid}" -eq 64 ] && [ "$name|$reference|$owner|$project|$command" = "/$expected_name|$EXPECTED_REFERENCE|$EXPECTED_OWNER|$EXPECTED_PROJECT|[\"-m\",\"uvm.installer.lock\",\"/state/.install.lock\",\"--offline-restore-admit\"]" ] || {
    printf '%s\n' contradiction >"$CAPTURE/guard.status"; return 0;
  }
  if [ "$image" != "$EXPECTED_ID" ]; then
    [ "$EXPECTED_KIND" = selected_manifest ] && [ "$image" = "$EXPECTED_ENGINE" ] &&
      [ "$child|$media|$size|$platform" = "$EXPECTED_CHILD|$EXPECTED_MEDIA|$EXPECTED_SIZE|$EXPECTED_PLATFORM" ] || {
      printf '%s\n' wrong_image >"$CAPTURE/guard.status"; return 0;
    }
  fi
  retained_identity=''
  if [ "$mode" = retained_after_caller ]; then
    retained_identity=$("$REAL_DOCKER" inspect "$cid" --format '{{.Id}}|{{.Created}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Running}}|{{.State.Paused}}|{{.State.Restarting}}|{{.State.ExitCode}}') || return 0
    case "$retained_identity" in "$cid|"*'|false|false|false|'*) ;; *) printf '%s\n' not_stopped >"$CAPTURE/guard.status"; return 0 ;; esac
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
    printf '%s\n' 0 >"$CAPTURE/logs.exit"
    if [ "$mode" = retained_after_caller ]; then
      after=$("$REAL_DOCKER" inspect "$cid" --format '{{.Id}}|{{.Created}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Running}}|{{.State.Paused}}|{{.State.Restarting}}|{{.State.ExitCode}}') || return 0
      [ "$after" = "$retained_identity" ] || { printf '%s\n' changed >"$CAPTURE/guard.status"; return 0; }
    fi
    printf '%s\n' "$mode" >"$CAPTURE/capture-timing"
    printf '%s\n' captured >"$CAPTURE/guard.status"
  else
    printf '%s\n' "$?" >"$CAPTURE/logs.exit"; printf '%s\n' logs_failed >"$CAPTURE/guard.status"
  fi
}
# Fixed test-only read-only recovery after the original caller has completed.
# This private observer command is never forwarded as a Docker command.
if [ "$#" -eq 1 ] && [ "$1" = --volt-capture-retained-restore-owner ]; then
  ( ulimit -f 16384 && observe_owned_removal "$@" ) >"$CAPTURE/observer.stdout" 2>"$CAPTURE/observer.stderr"
  [ -f "$CAPTURE/guard.status" ] && [ "$(cat "$CAPTURE/guard.status")" = captured ]
  exit "$?"
fi
# Observation may fail; ORIGINAL Docker command/result is never replaced/skipped.
( ulimit -f 16384 && observe_owned_removal "$@" ) >"$CAPTURE/observer.stdout" 2>"$CAPTURE/observer.stderr" || :
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
    if not (capture / 'guard.status').exists():
        # Full-pin cleanup correctly retains a stopped owner. Observe it only
        # AFTER this exact original caller's actual wait; never replay denial.
        recover = subprocess.run([str(capture / 'bin/docker'), '--volt-capture-retained-restore-owner'],
            cwd=private, env=observed_env, capture_output=True, timeout=30)
        (capture / 'retained-observer.exit').write_text(str(recover.returncode) + '\n')
    validate_inventory_rejection_capture(kind=kind, capture=capture, info=info,
        admission=admission, evidence=evidence, name=name, caller_pid=process.pid, caller_exit=code)


def validate_inventory_rejection_capture(*, kind: str, capture: Path, info: dict,
                                        admission: dict, evidence: Path, name: str,
                                        caller_pid: int, caller_exit: int) -> None:
    """Validate bound original records, including separately recovered retained owners."""
    if kind not in ('empty', 'corrupt') or type(caller_pid) is not int or caller_pid <= 0 or type(caller_exit) is not int or caller_exit == 0:
        raise ValueError('original exact failed caller and fixed inventory case required')
    if ((capture / 'caller.pid').read_text().strip() != str(caller_pid)
            or not (capture / 'guard.status').is_file()
            or (capture / 'guard.status').read_text().strip() != 'captured'
            or (capture / 'duplicate.status').exists()):
        raise RuntimeError('exact original owner logs were not captured; no cause credit')
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
            or owner.get('name') != '/volt-offline-' + info['project'] + '-' + str(caller_pid)):
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
        'instrumentation': 'POSIX observation of exact original owner; Docker commands/results unchanged',
        'capture_timing': (capture / 'capture-timing').read_text().strip() if (capture / 'capture-timing').exists() else 'legacy_before_removal',
        'original_caller_exit': caller_exit,
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
    inspection = fixture_inspect_argv(runtime,platform,inspect_platform=admission.get('docker_inspect_platform'))
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
        shlex.join(inspection) + ' >"$WORK/runtime-image.json"',
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





def qualify_terminal_bash_job_component(*, image: str, image_digest: str, source_revision: str,
        source_snapshot: str, evidence: Path, registered_poll: bool = False) -> None:
    """Fixed no-state native-Bash job semantics; never a lifecycle assertion."""
    if evidence.is_symlink() or stat.S_IMODE(evidence.stat().st_mode)!=0o700 or evidence.stat().st_uid!=os.getuid():
        raise RuntimeError('private owned evidence required')
    if (not re.fullmatch(r'volt-easy-delivery-route-component:[0-9a-f]{12}',image)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',image_digest)
            or not re.fullmatch(r'[0-9a-f]{40}',source_revision)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',source_snapshot)):
        raise RuntimeError('exact component image/source required')
    if type(registered_poll)is not bool:raise RuntimeError('closed component case required')
    old=os.umask(0o077)
    def capture(name,argv):
        (evidence/(name+'.invocation.json')).write_text(json.dumps({'argv':argv,'cwd':str(ROOT),
            'before_invocation':True,'timeout':15,'max_each_stream_bytes':131072},indent=2))
        import resource
        with(evidence/(name+'.stdout')).open('xb')as a,(evidence/(name+'.stderr')).open('xb')as b:
            r=subprocess.run(argv,cwd=ROOT,stdout=a,stderr=b,timeout=15,
                preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(131072,131072)))
        (evidence/(name+'.exit')).write_text(str(r.returncode)+'\n')
        if r.returncode:raise RuntimeError('fixed Bash component producer failed')
        return (evidence/(name+'.stdout')).read_bytes()
    def document(name,argv):return json.loads(capture(name,argv))
    try:
        endpoint=capture('endpoint',['docker','context','inspect','--format','{{.Endpoints.docker.Host}}']).decode().strip()
        if not endpoint.startswith('unix://'):raise RuntimeError('local Unix daemon required')
        server=capture('server',['docker','info','--format','{{.ID}}']).decode().strip()
        selected=document('selected',['docker','image','inspect','--platform','linux/amd64',image])[0]
        labels=selected['Config']['Labels'];immutable=image.split(':')[0]+'@'+image_digest
        if (selected['Os']!='linux' or selected['Architecture']!='amd64' or immutable not in selected['RepoDigests']
                or labels.get('org.opencontainers.image.revision')!=source_revision
                or labels.get('org.volt.compose.source-snapshot')!=source_snapshot):raise RuntimeError('source/image differs')
        common=r'''
set -u
printf 'bash_version=%s\n' "$BASH_VERSION"
scenario() (
  mode=$1
  parent=$BASHPID
  interrupted=0
  trap 'interrupted=1' TERM
  LAUNCH
  (sleep .8;exit 0) 9>&- &
  other=$!
  if [[ $mode == signal ]];then (sleep .1;kill -TERM "$parent") 9>&- & signaler=$!;fi
  # Match startup's separately registered/reaped input producer.
  coproc INPUT { printf G; }
  input_pid=$INPUT_PID
  exec {reader}<&"${INPUT[0]}"
  exec {INPUT[0]}<&-
  exec {INPUT[1]}>&-
  read -r -N 1 value <&"$reader"
  exec {reader}<&-
  wait "$input_pid"
  if [[ $mode == completed ]];then sleep .6;fi
  for attempt in 1 2;do
    completed=''
    if wait -n -p completed "$broker" "$other";then result=0;else result=$?;fi
    actor=unknown
    if [[ ${completed:-} == "$broker" ]];then actor=broker;elif [[ ${completed:-} == "$other" ]];then actor=other;fi
    printf 'scenario=%s attempt=%s actor=%s status=%s interrupted=%s\n' "$mode" "$attempt" "$actor" "$result" "$interrupted"
    [[ $actor != broker ]] || break
    [[ $result == 143 && $interrupted == 1 ]] || break
  done
  exec 9>&-
  if wait "$broker";then result=0;else result=$?;fi
  printf 'scenario=%s exact_broker_wait=%s\n' "$mode" "$result"
  wait "$other" || :
  if [[ $mode == signal ]];then wait "$signaler" || :;fi
)
scenario live
scenario completed
scenario signal
'''
        recipes={'process-substitution':r'''exec 9> >(sleep .4;exit 7)
  broker=$!''', 'coproc-final-exec':r'''coproc BROKER { exec /bin/bash --noprofile --norc -c 'sleep .4;exit 7'; }
  broker=$BROKER_PID
  exec 9>&"${BROKER[1]}"
  exec {BROKER[0]}<&-
  exec {BROKER[1]}>&-'''}
        scripts={role:common.replace('LAUNCH',recipe)for role,recipe in recipes.items()}
        if registered_poll:
            entry=(ROOT/'docker/g7/entrypoint.sh').read_text()
            handlers=entry[entry.index('record_api_stop_receipt() {'):entry.index('\ncleanup_on_exit() {')]
            begin=entry.index("trap 'handle_shutdown' TERM INT\nexited_child_pid=")
            loop=entry[begin:entry.index('\napi_remove_ready || { api_cleanup_poisoned=1; shutdown_status=1; }',begin)]
            script='''set -Eeuo pipefail
printf 'bash_version=%s\\n' "$BASH_VERSION"
'''+handlers+'''
scenario() (
  mode=$1;code=$2;parent=$BASHPID
  CHILD_PIDS=();declare -A REAPED_CHILDREN=() CHILD_EXIT_STATUS=() UNRESOLVED_CHILDREN=()
  shutdown_requested=0;quiesce_requested=0;quiesce_failed_latched=0;shutdown_status=0
  api_report() { printf '%s\\n' "$1" >&2; }
  if [[ $mode == unavailable ]];then
    (sleep .05;exit 0)& broker=$!
    builtin wait "$broker"
    builtin wait
  else
    exec 9> >(sleep .05;exit "$code")
    broker=$!
  fi
  CHILD_PIDS=("$broker")
  if [[ $mode == completed ]];then sleep .1;fi
  if [[ $mode == term-race ]];then
    wait() { local rc=0;builtin wait "$@" || rc=$?;kill -TERM "$parent";return "$rc"; }
  fi
'''+loop+'''
  if [[ $mode == unavailable ]];then
    [[ $wait_bookkeeping_failed == 1 && $api_cleanup_poisoned == 1 && ! ${exited_child_pid:-} ]]
    printf 'scenario=unavailable unresolved=1\\n'
  else
    [[ $exited_child_pid == "$broker" && $child_status == "$code" && $api_cleanup_poisoned == 1 ]]
    [[ $wait_bookkeeping_failed == 0 && ${CHILD_EXIT_STATUS[$broker]} == "$code" ]]
    if [[ $mode == term-race ]];then [[ $shutdown_requested == 1 ]];fi
    printf 'scenario=%s actual_broker_wait=%s sticky=1 term=%s\\n' "$mode" "$child_status" "$shutdown_requested"
    exec 9>&-
  fi
)
for mode in live completed term-race;do for code in 0 7;do scenario "$mode" "$code";done;done
scenario unavailable 0
'''
            scripts={'registered-poll':script}
        for role,code in scripts.items():
            token=uuid.uuid4().hex;name='volt-terminal-bash-'+token[:16]
            tmpfs={destination:'rw,noexec,nosuid,nodev,size=1m'for destination in
                ('/app/media','/opt/uvm/state','/var/lib/postgresql/data','/tmp')}
            command=['-i','PATH=/usr/bin:/bin','LC_ALL=C','/bin/bash','--noprofile','--norc','-c',code]
            argv=['docker','create','--platform','linux/amd64','--pull=never','--name',name,'--restart=no',
                '--network','none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user','0:0',
                '--label','volt.delivery.test-uuid='+token,'--label','volt.delivery.role=terminal-bash-'+role]
            for destination,options in tmpfs.items():argv+=['--tmpfs',destination+':'+options]
            argv+=['--entrypoint','/usr/bin/env',immutable,*command]
            cid=capture(role+'-create',argv).decode().strip()
            if not re.fullmatch('[0-9a-f]{64}',cid):raise RuntimeError('full component CID required')
            def guard(label):
                rows=document(role+'-'+label,['docker','inspect',cid])
                if len(rows)!=1:raise RuntimeError('ambiguous component')
                r=rows[0];h=r['HostConfig'];c=r['Config'];w=r.get('ImageManifestDescriptor')or{}
                if (r['Id']!=cid or r['Name']!='/'+name or c['Image']!=immutable or c['User']!='0:0'
                        or c['Entrypoint']!=['/usr/bin/env'] or c['Cmd']!=command
                        or c['Labels'].get('volt.delivery.test-uuid')!=token
                        or c['Labels'].get('volt.delivery.role')!='terminal-bash-'+role
                        or h['NetworkMode']!='none' or h['ReadonlyRootfs']is not True or h['Privileged']is not False
                        or h.get('CapAdd')not in(None,[]) or h.get('CapDrop')!=['ALL']
                        or h.get('PortBindings')not in(None,{}) or h['RestartPolicy']['Name']!='no'
                        or h.get('Tmpfs')!=tmpfs or h.get('SecurityOpt')not in(['no-new-privileges'],['no-new-privileges:true'])
                        or any(m['Type']!='tmpfs' or m['Destination']not in tmpfs for m in r['Mounts'])
                        or r['Image']!=selected['Id']and(r['Image']!=image_digest or any(w.get(k)!=(selected.get('Descriptor')or{}).get(k)for k in('digest','mediaType','size','platform')))):
                    raise RuntimeError('registered component recipe/image/custody differs; retain')
                return r
            guard('created')
            try:
                capture(role+'-actual',['docker','start','-a',cid])
            finally:
                current=guard('cleanup-guard')
                if current['State']['Running']is not False:raise RuntimeError('component unexpectedly alive; retain')
                if (capture(role+'-cleanup-server',['docker','info','--format','{{.ID}}']).decode().strip()!=server
                        or capture(role+'-cleanup-endpoint',['docker','context','inspect','--format','{{.Endpoints.docker.Host}}']).decode().strip()!=endpoint):
                    raise RuntimeError('component daemon changed; retain')
                capture(role+'-exact-remove',['docker','rm',cid])
    finally:os.umask(old)


def qualify_terminal_lifecycle_component(*, image: str, image_digest: str, source_revision: str,
        source_snapshot: str, private: Path, evidence: Path, image_config_id: str, continuation_evidence: Path | None = None,
        custody_retry_evidence: Path | None = None) -> None:
    """ONE legitimate unclaimed LOCAL development CLI journey, not signed admission.

    Host Python is this controller; no minimum-host or public offline-backup
    acceptance. Retain state/resources on any assertion failure for exact review.
    """
    import resource
    from uvm.auth import route_check_records as wire
    from uvm.installer import route_check as delivery
    from uvm.installer.runtime_mounts import validate, validate_start_context
    if (not re.fullmatch(r'volt-easy-delivery-route-component:[0-9a-f]{12}',image)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',image_digest)
            or not re.fullmatch(r'[0-9a-f]{40}',source_revision)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',source_snapshot)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',image_config_id)):
        raise RuntimeError('fixed local component source/image required')
    for directory in (private,evidence):
        value=directory.lstat()
        if not stat.S_ISDIR(value.st_mode) or directory.is_symlink() or value.st_uid!=os.getuid() or stat.S_IMODE(value.st_mode)!=0o700:
            raise RuntimeError('new private component custody required')
    state=private/'instance'
    if custody_retry_evidence is not None and continuation_evidence is None:
        raise RuntimeError('custody retry requires the exact original initial failure')
    if continuation_evidence is None and (state.exists() or state.is_symlink()):raise RuntimeError('component must not adopt any prior instance')
    previous_umask=os.umask(0o077);last_step='preflight';cid=None;info=None
    def capture(name,argv,*,timeout=30,limit=4*1024*1024,check=True,input_bytes=None):
        nonlocal last_step
        last_step=name
        (evidence/(name+'.invocation.json')).write_text(json.dumps({'argv':argv,'cwd':str(ROOT),
            'timeout_seconds':timeout,'max_each_stream_bytes':limit,'before_invocation':True,
            'stdin_sha256':None if input_bytes is None else hashlib.sha256(input_bytes).hexdigest()},indent=2))
        with(evidence/(name+'.stdout')).open('xb')as stdout,(evidence/(name+'.stderr')).open('xb')as stderr:
            process=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.PIPE if input_bytes is not None else None,
                stdout=stdout,stderr=stderr,start_new_session=True,
                preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit)))
            start_fd_observed=False
            if name=='supported-start':
                deadline=time.monotonic()+8
                lock=state/'.install.lock';identity=lock.stat(follow_symlinks=False)
                device=f'{os.major(identity.st_dev):02x}:{os.minor(identity.st_dev):02x}:{identity.st_ino}'
                while process.poll() is None and time.monotonic()<deadline:
                    with open('/proc/locks','r')as locks:
                        rows=locks.read(1024*1024+1)
                    if len(rows)>1024*1024:break
                    for line in rows.splitlines():
                        fields=line.split()
                        if len(fields)>=8 and fields[1:5]==['FLOCK','ADVISORY','WRITE',str(process.pid)] and fields[5]==device:
                            start_fd_observed=True
                            (evidence/'actual-public-start-new-owned-FD.json').write_text(json.dumps({
                                'producer':wire.validated_proc_identity(process.pid),'kernel_lock_row':line,
                                'inode':identity.st_ino,'device':identity.st_dev,
                                'scope':'observed new public-start owner at acquisition; not continuous liveness'},indent=2))
                            break
                    if start_fd_observed:break
                    time.sleep(.01)
            try:
                if input_bytes is not None:process.communicate(input_bytes,timeout=timeout);code=process.returncode
                else:code=process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10);code=124
            stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
        (evidence/(name+'.exit')).write_text(str(code)+'\n')
        if check and code:raise RuntimeError('owned component command failed; retained private raw')
        if name=='supported-start' and not start_fd_observed:
            raise RuntimeError('new public-start kernel FD ownership was not observed')
        return (evidence/(name+'.stdout')).read_bytes(),code
    def document(name,argv):
        raw,_=capture(name,argv);return json.loads(raw)
    try:
        context=os.environ.get('DOCKER_CONTEXT')
        endpoint=os.environ.get('DOCKER_HOST')
        if not endpoint:
            if not context:context=capture('context',['docker','context','show'])[0].decode().strip()
            endpoint=capture('endpoint',['docker','context','inspect',context,'--format','{{(index .Endpoints "docker").Host}}'])[0].decode().strip()
        if not endpoint.startswith('unix://'):raise RuntimeError('component requires the unchanged local Unix daemon')
        server=capture('server',['docker','info','--format','{{.ID}}'])[0].decode().strip()
        image_rows=document('selected-image',['docker','image','inspect','--platform','linux/amd64',image])
        if len(image_rows)!=1:raise RuntimeError('one selected native component image required')
        selected=image_rows[0];labels=selected.get('Config',{}).get('Labels')or{}
        immutable='volt-easy-delivery-route-component@'+image_digest
        if (selected.get('Os')!='linux' or selected.get('Architecture')!='amd64'
                or labels.get('org.opencontainers.image.revision')!=source_revision
                or labels.get('org.volt.compose.source-snapshot')!=source_snapshot
                or selected.get('RepoDigests',[]).count(immutable)!=1):
            raise RuntimeError('component immutable source/native selection differs')
        retained=None
        if continuation_evidence is not None:
            if continuation_evidence.is_symlink() or continuation_evidence.resolve()!=continuation_evidence:
                raise RuntimeError('retained first evidence path linked')
            retained=json.loads((continuation_evidence/'plan-before-init.json').read_bytes())
            if ((continuation_evidence/'supported-init.exit').read_text().strip()!='0'
                    or (continuation_evidence/'supported-start.exit').read_text().strip()!='1'
                    or (continuation_evidence/'supported-start.stderr').read_bytes()!=b'local recovery custody journal is missing or inconsistent\n'
                    or any(retained[key]!=expected for key,expected in
                        (('state',str(state)),('image_reference',immutable),('source_revision',source_revision),
                         ('source_snapshot',source_snapshot),('daemon',server),('endpoint',endpoint)))):
                raise RuntimeError('continuation differs from the original bounded initial failure')
            project=retained['project']
        else:project='volt-terminal-'+uuid.uuid4().hex[:16]
        cli=[sys.executable,str(ROOT/'deploy/compose/setup.py')]
        plan={'scope':'LOCAL AMD64 development full-entrypoint component; NOT signed/minimal-host/full-backup',
            'image_reference':immutable,'selected_image':selected,'source_revision':source_revision,
            'source_snapshot':source_snapshot,'daemon':server,'endpoint':endpoint,'project':project,
            'state':str(state),'no_accounts_or_browser':True,'retain_fixture':True}
        (evidence/'plan-before-init.json').write_text(json.dumps(plan,indent=2))
        if retained is None:
            capture('supported-init',[*cli,'init',str(state),'--mode','local','--project',project,
                '--image',immutable,'--platform','linux/amd64','--http-port','46180','--recovery-port','46181','--oidc-port','46182'],timeout=120)
        info=json.loads((state/'instance.json').read_bytes())
        if info['project']!=project or info['image']!=immutable or info['mode']!='local':raise RuntimeError('new legitimate namespace differs')
        owner=info['owner_token'];expected_name=project+'-volt-1'
        def guard(name):
            nonlocal cid,info
            rows=document(name,['docker','inspect',expected_name])
            if len(rows)!=1:raise RuntimeError('exact registered API absent')
            row=rows[0]
            if (not re.fullmatch('[0-9a-f]{64}',row['Id']) or cid is not None and cid!=row['Id']
                    or row['Name']!='/'+expected_name or row['Config']['Image']!=immutable
                    or row['Config']['Labels'].get('volt.compose.owner-token')!=owner
                    or row['Config']['Labels'].get('com.docker.compose.project')!=project):
                raise RuntimeError('component API identity/ownership changed')
            cid=row['Id'];info=json.loads((state/'instance.json').read_bytes())
            volumes=document(name+'-volumes',['docker','volume','inspect',*[project+'_'+store for store in ('postgres','media','state')]])
            validate(state,state,info,row,volumes);validate_start_context(info,row)
            for store in ('postgres','media','state'):
                users=capture(name+'-users-'+store,['docker','ps','-a','--filter','volume='+project+'_'+store,'--format','{{.ID}}','--no-trunc'])[0].decode().splitlines()
                if set(users)!={cid}:raise RuntimeError('owned store has a foreign attachment; retain')
            return row
        if retained is not None or info.get('local_recovery_custody') is None:
            # This is ONLY the specifically authorised 21-file unestablished
            # development continuation, never general instance/cache adoption.
            import fcntl
            from uvm.installer.lock import _bounded_file
            from uvm.installer import recovery_authority
            prior_custody=None
            if custody_retry_evidence is not None:
                if custody_retry_evidence.is_symlink() or custody_retry_evidence.resolve()!=custody_retry_evidence:
                    raise RuntimeError('prior custody evidence path linked')
                prior_custody=json.loads((custody_retry_evidence/'actual-initial-custody-host-FD.json').read_bytes())
                previous_plan=json.loads((custody_retry_evidence/'plan-before-init.json').read_bytes())
                failure=json.loads((custody_retry_evidence/'failure.json').read_bytes())
                if (failure.get('failed_step')!='custody-prepare-created' or previous_plan!=plan
                        or (custody_retry_evidence/'custody-request-actual.exit').read_text().strip()!='0'
                        or (custody_retry_evidence/'custody-prepare-actual.invocation.json').exists()):
                    raise RuntimeError('not the exact rejected unstarted helper continuation')
            before={}
            public_certs={'secrets/recovery-ca.crt','secrets/recovery-server.crt','secrets/recovery-client.crt'}
            for file in state.rglob('*'):
                if file.is_symlink():raise RuntimeError('initial development input linked')
                if file.is_file():
                    relative=str(file.relative_to(state))
                    if relative=='.install.lock' and prior_custody is not None:continue
                    raw=_bounded_file(file,1024*1024,private=relative not in public_certs);st=file.stat()
                    if stat.S_IMODE(st.st_mode)!=(0o644 if relative in public_certs else 0o600):raise RuntimeError('original initial file mode differs')
                    before[relative]={'sha256':hashlib.sha256(raw).hexdigest(),
                        'bytes':len(raw),'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)}
            if (len(before)!=21 or '.install.lock'in before or info.get('established')is not False
                    or info.get('local_recovery_acknowledgement')is not None or info.get('local_recovery_custody')is not None
                    or info.get('local_recovery_inventory')is not None or info.get('installer_contract_version')is not None):
                raise RuntimeError('not the exact fresh pre-custody development boundary')
            if prior_custody is not None and before!=json.loads((custody_retry_evidence/'before-initial-custody-current-21-files.json').read_bytes()):
                raise RuntimeError('original 21-file fingerprints differ from the failed guarded attempt')
            (evidence/'before-initial-custody-current-21-files.json').write_text(json.dumps(before,indent=2))
            with tarfile.open(evidence/'before-initial-custody-21-files.tar','x')as saved:
                for name in sorted(before):saved.add(state/name,arcname=name,recursive=False)
            for kind,names in (('container',[expected_name]),('volume',[project+'_'+v for v in ('postgres','media','state')]),('network',[project+'_network'])):
                for number,name in enumerate(names):
                    raw,code=capture('initial-absence-'+kind+'-'+str(number),['docker',kind,'inspect',name],check=False)
                    error=(evidence/('initial-absence-'+kind+'-'+str(number)+'.stderr')).read_text()
                    if code==0 or not re.search(r'no such|not found',error,re.I):raise RuntimeError('initial exact namespace absence unproved')
            lock=state/'.install.lock'
            flags=os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
            if prior_custody is None:flags|=os.O_CREAT|os.O_EXCL
            fd=os.open(lock,flags,0o600)
            fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            identity=os.fstat(fd)
            def held():
                current=lock.stat(follow_symlinks=False)
                if (not stat.S_ISREG(current.st_mode) or stat.S_IMODE(current.st_mode)!=0o600
                        or current.st_uid!=os.getuid() or current.st_nlink!=1 or current.st_size!=0
                        or any(getattr(current,key)!=getattr(identity,key)for key in fields)):
                    raise RuntimeError('original host lifecycle inode changed')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            try:
                if prior_custody is not None and any(getattr(identity,key)!=prior_custody['inode'][key]for key in fields):
                    raise RuntimeError('recorded original lock inode/custody changed')
                held();os.fsync(fd)
                parent=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent)
                finally:os.close(parent)
                (evidence/'actual-initial-custody-host-FD.json').write_text(json.dumps({
                    'owner_process':wire.validated_proc_identity(os.getpid()),'uid':os.getuid(),'gid':os.getgid(),
                    'fd':fd,'inode':{key:getattr(identity,key)for key in fields},
                    'kernel_fdinfo':Path(f'/proc/self/fdinfo/{fd}').read_text(),
                    'held_only_through_request_prepare_validate':'not continuous through subsequent public start'},indent=2))
                for name,value in before.items():
                    file=state/name;current=file.stat(follow_symlinks=False)
                    if (hashlib.sha256(_bounded_file(file,1024*1024,private=name not in public_certs)).hexdigest()!=value['sha256']
                            or (current.st_dev,current.st_ino,current.st_uid,current.st_gid,stat.S_IMODE(current.st_mode))!=
                            tuple(value[key]for key in('device','inode','uid','gid','mode'))):
                        raise RuntimeError('original 21-file input changed before actual-FD initialization')
                def helper(action,body=None):
                    name=project+'-custody-'+action
                    capabilities=['CHOWN','SETUID','DAC_OVERRIDE']if action=='prepare'else[]
                    user='0:0'if action=='prepare'else f'{os.getuid()}:{os.getgid()}'
                    target=['docker','create','--platform','linux/amd64','--pull=never','--name',name,'--restart=no',
                        '--network','none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
                        '--label','volt.delivery.test-owner='+owner,'--label','volt.delivery.project='+project,
                        '--label','volt.delivery.role=development-initial-custody','--user',user,
                        '--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--tmpfs','/app/media:rw,noexec,nosuid,nodev,size=1m',
                        '--tmpfs','/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
                        '--mount',f'type=bind,src={state},dst=/instance'+(''if action=='prepare'else',readonly')]
                    for capability in capabilities:target+=['--cap-add='+capability]
                    if body is not None:target+=['-i']
                    target+=['--entrypoint','/opt/uvm/venv/bin/python',immutable,'-m','uvm.installer.recovery_authority',action]
                    if action!='request':target+=['--request-stdin']
                    target+=['--instance-root','/instance']
                    helper_id=None
                    def observed(label):
                        rows=document('custody-'+action+'-'+label,['docker','inspect',helper_id]);item=rows[0]
                        h=item['HostConfig'];c=item['Config'];mounts=item['Mounts']
                        binds=[m for m in mounts if m['Type']=='bind']
                        expected_command=['-m','uvm.installer.recovery_authority',action]+([]if action=='request'else['--request-stdin'])+['--instance-root','/instance']
                        expected_tmpfs={'/tmp':'rw,noexec,nosuid,size=16m','/app/media':'rw,noexec,nosuid,nodev,size=1m',
                            '/opt/uvm/state':'rw,noexec,nosuid,nodev,size=1m','/var/lib/postgresql/data':'rw,noexec,nosuid,nodev,size=1m'}
                        if (len(rows)!=1 or item['Id']!=helper_id or item['Name']!='/'+name or c['Image']!=immutable
                                or c['User']!=user or c['Entrypoint']!=['/opt/uvm/venv/bin/python']
                                or c['Cmd']!=expected_command
                                or c['Labels'].get('volt.delivery.test-owner')!=owner or c['Labels'].get('volt.delivery.project')!=project
                                or c['Labels'].get('volt.delivery.role')!='development-initial-custody'
                                or h['NetworkMode']!='none' or h['ReadonlyRootfs']is not True or h['Privileged']is not False
                                or sorted(h.get('CapAdd')or[])!=sorted('CAP_'+value for value in capabilities) or h.get('CapDrop')!=['ALL']
                                or h.get('PortBindings')not in(None,{}) or h['RestartPolicy']['Name']!='no'
                                or h.get('Tmpfs')!=expected_tmpfs
                                or h.get('SecurityOpt')not in(['no-new-privileges'],['no-new-privileges:true'])
                                or len(binds)!=1 or binds[0]['Source']!=str(state)or binds[0]['Destination']!='/instance'
                                or binds[0]['RW']is not(action=='prepare')or any(m['Type']not in('bind','tmpfs')
                                    or m['Type']=='tmpfs'and m['Destination']not in expected_tmpfs for m in mounts)):
                            raise RuntimeError('exact initial custody helper recipe/ROI differs')
                        witness=item.get('ImageManifestDescriptor')or{}
                        if item['Image']!=selected['Id']and(item['Image']!=image_digest or any(witness.get(k)!=(selected.get('Descriptor')or{}).get(k)for k in('digest','mediaType','size','platform'))):
                            raise RuntimeError('custody helper selected image witness differs')
                        return item
                    if action=='prepare' and prior_custody is not None:
                        prior_rows=json.loads((custody_retry_evidence/'custody-prepare-created.stdout').read_bytes())
                        prior_argv=json.loads((custody_retry_evidence/'custody-prepare-create.invocation.json').read_bytes())['argv']
                        if len(prior_rows)!=1 or prior_argv!=target:raise RuntimeError('registered Created helper recipe changed')
                        original=prior_rows[0];helper_id=original['Id']
                        if not re.fullmatch('[0-9a-f]{64}',helper_id):raise RuntimeError('registered helper full CID malformed')
                        current=observed('retry-registered-created');held()
                        zero='0001-01-01T00:00:00Z'
                        if (any(current.get(key)!=original.get(key)for key in
                                ('Id','Name','Created','Config','HostConfig','Mounts','NetworkSettings','Image','ImageManifestDescriptor','Platform','Path','Args','State'))
                                or current['State']['Status']!='created' or current['State']['Running']is not False
                                or current['State']['Pid']!=0 or current['State']['StartedAt']!=zero
                                or current['State']['FinishedAt']!=zero or current['State']['ExitCode']!=0):
                            raise RuntimeError('registered helper no longer exact unstarted Created identity')
                        capture('custody-prepare-retry-exact-created-remove',['docker','rm',helper_id])
                    helper_id=capture('custody-'+action+'-create',target)[0].decode().strip()
                    if not re.fullmatch('[0-9a-f]{64}',helper_id):raise RuntimeError('custody helper full CID malformed')
                    observed('created');held()
                    output,code=capture('custody-'+action+'-actual',['docker','start','-a',*(['-i']if body is not None else[]),helper_id],input_bytes=body,check=False,timeout=60)
                    result=observed('completed');held()
                    if code!=0 or result['State']['Running']is not False or result['State']['ExitCode']!=0:
                        if result['State']['Running']is True:
                            # Bound only this already registered exact helper;
                            # no further instance writes may outlive host FD.
                            observed('before-uncertain-helper-termination')
                            capture('custody-'+action+'-uncertain-stop',['docker','kill','--signal','KILL',helper_id],check=False)
                        raise RuntimeError('initial custody helper rejected; retain exact layer without repair')
                    observed('before-exact-remove')
                    capture('custody-'+action+'-exact-remove',['docker','rm',helper_id])
                    return output
                request=helper('request')
                (evidence/'initial-request-sha256.txt').write_text(hashlib.sha256(request).hexdigest()+'\n')
                helper('prepare',request)
                helper('validate',request)
                held()
                after=json.loads((state/'instance.json').read_bytes())
                if set(after)!=set(info)|{'local_recovery_custody','local_recovery_inventory'}or any(after[key]!=value for key,value in info.items()):
                    raise RuntimeError('initial helper changed unexpected authority metadata')
                for name,value in before.items():
                    if name!='instance.json'and hashlib.sha256(_bounded_file(state/name,1024*1024,private=name not in public_certs)).hexdigest()!=value['sha256']:
                        raise RuntimeError('initial helper changed pre-existing key/config bytes')
                (evidence/'initial-custody-commit.json').write_text(json.dumps({'existing_21_files_preserved_except_legitimate_journal_commit':True,
                    'actual_original_host_FD_still_held':True,'no_established_backfill':True,'request_sha256':hashlib.sha256(request).hexdigest()},indent=2))
                info=after
            finally:os.close(fd)
            (evidence/'initial-host-FD-released-before-public-start.json').write_text(json.dumps({'released':True,
                'next_supported_start_must_acquire_its_own_FD':True},indent=2))
        capture('supported-start',[*cli,'start',str(state)],timeout=1200)
        running=guard('running-current');started=running['State']['StartedAt']
        if not running['State']['Running'] or running['State'].get('Health',{}).get('Status')!='healthy':raise RuntimeError('actual global health unavailable')
        public_config=document('actual-unclaimed-three-field-config',['docker','exec','--user','1800:1800',cid,
            'curl','--fail','--silent','--show-error','http://127.0.0.1:8000/api/v1/auth/config'])
        if public_config!={'schema_version':1,'mode':'local','setup_state':'required'}:
            raise RuntimeError('legitimate fresh unclaimed public state was not observed')
        capture('protected-root-copy',['docker','exec','--user','0:0',cid,'/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C',
            '/usr/local/bin/python3.14','-I','-S','/usr/local/libexec/volt-check-protected-python.py'])
        script='import json,os,sys;sys.path.insert(0,"/usr/local/lib/volt-private");import volt_route_check_records as r\nwith r.locked_store(role="root") as s:\n l=s.read_launch();t=s.read_launch_status();v=s.read_supervisor();r.validate_launch_processes(l)\n assert l["readiness_profile"]=="normal_local_loopback" and s.read_broker_ready() and not s.read_verification_health() and s.read_boot() is None and s.read_seen() is None\n print(json.dumps({"launch":l,"status":t,"supervisor":v,"broker_ready":True,"verification_health":False,"boot_absent":True},sort_keys=True))'
        active=document('actual-original-launch',['docker','exec','--user','0:0',cid,'/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C',
            '/usr/local/bin/python3.14','-I','-S','-c',script])
        uid_script='import hashlib,json,os;from pathlib import Path;from uvm.auth.route_check import _load_records;r=_load_records();p=Path(r.__file__);assert os.geteuid()==1800;print(json.dumps({"uid":os.geteuid(),"file":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}))'
        physical=document('actual-API-UID-protected-copy',['docker','exec','--user','1800:1800',cid,'/opt/uvm/venv/bin/python','-c',uid_script])
        if physical['file']!='/usr/local/lib/volt-private/volt_route_check_records.py' or physical['sha256']!=sha(ROOT/'uvm/auth/route_check_records.py'):
            raise RuntimeError('API/root canonical physical bytes differ')
        capture('supported-controlled-stop',[*cli,'stop',str(state)],timeout=650)
        stopped=guard('stopped-current')
        if (stopped['State']['Running']is not False or stopped['State']['StartedAt']!=started
                or stopped['State']['ExitCode']!=0 or stopped['State']['OOMKilled']is not False or stopped['State']['Error']):
            raise RuntimeError('current controlled container completion failed')
        waited,_=capture('actual-current-Docker-wait',['docker','wait',cid],timeout=15)
        if waited!=b'0\n':raise RuntimeError('current Docker kernel completion is not zero')
        tar_raw,_=capture('stopped-private-records',['docker','cp',cid+':/run/uvm-route-check/.','-'],timeout=10,limit=128*1024)
        records=delivery.stopped_tar_records(tar_raw)
        launch=wire.validate_record('launch',records['launch.json']);status=wire.validate_record('launch_status',records['launch-status.json'])
        if launch!=active['launch'] or any(wire.canonical(v)!=records[n] for n,v in (('launch.json',launch),('launch-status.json',status))):raise RuntimeError('stopped launch/canonical identity changed')
        log_raw,_=capture('bounded-current-private-logs',['docker','logs','--tail','256','--since',started,cid],timeout=10,limit=1024*1024)
        matches=[]
        for line in log_raw.splitlines(keepends=True):
            if b'volt_main_api_completion_v1' not in line:continue
            if not line.endswith(b'\n') or len(line)>2049:raise RuntimeError('private completion line truncated/oversized')
            raw=line[:-1];envelope=wire.validate_completion_envelope(raw,launch=launch,status=status)
            matches.append(envelope)
        if len(matches)!=1:raise RuntimeError('exactly ONE current private completion required')
        # This comparison executes in the SAME immutable image's protected
        # module, not a source-tree shared-module substitution. Independent
        # expected config comes from the pre-recorded local build metadata.
        from uvm.installer.offline_lifecycle import project_observation
        from uvm.installer.stopped_transport import encode as encode_stop
        after=guard('cold-proof-post-current')
        initial_projection=project_observation({'image':[selected],'containers':[stopped],'volumes':[],'networks':[]})['containers'][0]
        post_projection=project_observation({'image':[selected],'containers':[after],'volumes':[],'networks':[]})['containers'][0]
        outcomes=dict.fromkeys(('docker_wait_producer_exit','docker_wait_filter_exit','routing_tar_producer_exit',
            'routing_tar_filter_exit','docker_logs_producer_exit','docker_logs_filter_exit','post_inspect_producer_exit','post_inspect_filter_exit'),0)
        # Actual producers above all exited0; actual parser/shared shape checks
        # above completed. No boolean-only candidate can replace those records.
        proof=encode_stop(initial_projection,waited,tar_raw,wire.canonical(matches[0]),post_projection,outcomes).encode()
        runtime={'container_id':cid,'started_at':started,'image':{'kind':info['image_admission']['id_kind'],
            'id':info['image_admission']['id'],'config_id':image_config_id},
            'resources_sha256':info['local_start_admission']['resources_sha256']}
        code='import sys,json;from uvm.installer import stopped_transport as t,route_check as r\nvalue,tar,envelope=t.decode(sys.stdin.buffer.read(262145).decode("utf-8"))\nexpected='+repr(runtime)+'\nassert value["queried_container_id"]==expected["container_id"] and value["queried_started_at"]==expected["started_at"]\nprint(json.dumps(r.validate_stopped_snapshot(tar,expected,envelope,0),sort_keys=True))'
        name=project+'-cold-reader'
        target=['docker','create','--platform','linux/amd64','--pull=never','--name',name,'--restart=no','--network','none',
            '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
            '--label','volt.delivery.test-owner='+owner,'--label','volt.delivery.project='+project,'--label','volt.delivery.role=development-cold-reader',
            '--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--tmpfs','/app/media:rw,noexec,nosuid,nodev,size=1m',
            '--tmpfs','/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
            '-i','--entrypoint','/opt/uvm/venv/bin/python',immutable,'-c',code]
        reader_id=capture('native-cold-reader-create',target)[0].decode().strip()
        if not re.fullmatch('[0-9a-f]{64}',reader_id):raise RuntimeError('full cold-reader CID malformed')
        def cold_reader_guard(label):
            rows=document('native-cold-reader-'+label,['docker','inspect',reader_id])
            if len(rows)!=1:raise RuntimeError('cold-reader identity ambiguous')
            r=rows[0];h=r['HostConfig'];c=r['Config']
            if (r['Id']!=reader_id or r['Name']!='/'+name or c['Image']!=immutable
                    or c['User']!=f'{os.getuid()}:{os.getgid()}' or c['Entrypoint']!=['/opt/uvm/venv/bin/python'] or c['Cmd']!=['-c',code]
                    or c['Labels'].get('volt.delivery.test-owner')!=owner or c['Labels'].get('volt.delivery.project')!=project
                    or c['Labels'].get('volt.delivery.role')!='development-cold-reader'
                    or h['NetworkMode']!='none' or h['ReadonlyRootfs']is not True or h['Privileged']is not False
                    or h.get('CapAdd')not in(None,[]) or h.get('CapDrop')!=['ALL'] or h.get('PortBindings')not in(None,{})
                    or h['RestartPolicy']['Name']!='no' or h.get('SecurityOpt')not in(['no-new-privileges'],['no-new-privileges:true'])
                    or h.get('Tmpfs')!={'/tmp':'rw,noexec,nosuid,size=16m','/app/media':'rw,noexec,nosuid,nodev,size=1m',
                        '/opt/uvm/state':'rw,noexec,nosuid,nodev,size=1m','/var/lib/postgresql/data':'rw,noexec,nosuid,nodev,size=1m'}
                    or any(m['Type']!='tmpfs'for m in r['Mounts'])):
                raise RuntimeError('cold-reader fixed no-state recipe differs')
            witness=r.get('ImageManifestDescriptor')or{}
            if r['Image']!=selected['Id']and(r['Image']!=image_digest or any(witness.get(k)!=(selected.get('Descriptor')or{}).get(k)for k in('digest','mediaType','size','platform'))):
                raise RuntimeError('cold-reader selected image witness differs')
            return r
        cold_reader_guard('created')
        capture('native-cold-reader-actual',['docker','start','-a','-i',reader_id],input_bytes=proof,timeout=20)
        cold=cold_reader_guard('completed')
        if cold['State']['Running']is not False or cold['State']['ExitCode']!=0:raise RuntimeError('native cold-reader rejected current completion')
        cold_reader_guard('before-exact-remove');capture('native-cold-reader-exact-remove',['docker','rm',reader_id])
        if capture('final-server',['docker','info','--format','{{.ID}}'])[0].decode().strip()!=server:raise RuntimeError('daemon changed')
        (evidence/'outcome.json').write_text(json.dumps({'scope':plan['scope'],'actual_global_health':True,
            'actual_current_container_wait':0,'same_launch_and_started_at':True,'canonical_private_completion':matches[0],
            'installation_unclaimed':True,'state_and_resources_retained':str(state),
            'candidate_files_alone_not_authority':True,'public_offline_backup_not_executed':True,'same_image_strict_four_argument_cold_reader':True,
            'development_CLI_marker_gate_not_public_installer_acceptance':True},indent=2))
    except BaseException as error:
        (evidence/'failure.json').write_text(json.dumps({'failed_step':last_step,'error_type':type(error).__name__,
            'private_state_retained':str(state),'no_acceptance':True},indent=2))
        # No force removal, state repair or adoption. Preserve the first failure
        # and attempt ONLY the supported stop after exact registered guards.
        if info is not None:
            try:
                guard('failure-before-supported-stop')
                capture('failure-supported-stop',[*cli,'stop',str(state)],timeout=650,check=False)
                capture('failure-bounded-logs',['docker','logs','--tail','256',cid],timeout=10,check=False)
            except BaseException:
                (evidence/'cleanup-retained.txt').write_text('supported guarded stop unavailable; retain exact fixture\n')
        raise
    finally:os.umask(previous_umask)


def qualify_protected_launch_component(*, image: str, image_digest: str, source_revision: str,
        source_snapshot: str, component: Path, evidence: Path) -> None:
    """Maintained fresh local IMAGE exec/COPY component, never signed admission."""
    if not re.fullmatch(r'volt-easy-delivery-route-component:[0-9a-f]{12}', image):
        raise RuntimeError('only registered fresh local component image allowed')
    endpoint = os.environ.get('DOCKER_HOST')
    if not endpoint:
        context = os.environ.get('DOCKER_CONTEXT') or run('protected-component-context',
            ['docker','context','show'], evidence).stdout.strip()
        endpoint = run('protected-component-endpoint',['docker','context','inspect',context,
            '--format','{{(index .Endpoints "docker").Host}}'],evidence).stdout.strip()
    if not endpoint.startswith('unix://'):
        raise RuntimeError('fresh component requires local Unix daemon')
    server=run('protected-component-server',['docker','info','--format','{{.ID}}'],evidence).stdout.strip()
    rows=json.loads(run('protected-component-image',['docker','image','inspect','--platform','linux/amd64',image],evidence).stdout)
    if len(rows)!=1 or rows[0]['Os']!='linux'or rows[0]['Architecture']!='amd64':
        raise RuntimeError('fresh component platform differs')
    labels=rows[0].get('Config',{}).get('Labels')or{}
    if labels.get('org.opencontainers.image.revision')!=source_revision or labels.get('org.volt.compose.source-snapshot')!=source_snapshot:
        raise RuntimeError('fresh component image source differs')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',image_digest):
        raise RuntimeError('fresh build index digest malformed')
    immutable='volt-easy-delivery-route-component@'+image_digest
    if rows[0].get('RepoDigests',[]).count(immutable)!=1:
        raise RuntimeError('fresh build immutable repository digest absent/contradictory')
    selected=rows[0].get('Descriptor')or{}
    if (selected.get('digest')!=rows[0]['Id'] or selected.get('mediaType')!='application/vnd.oci.image.manifest.v1+json'
            or selected.get('platform')!={'os':'linux','architecture':'amd64'} or type(selected.get('size'))is not int or selected['size']<=0):
        raise RuntimeError('fresh build selected child descriptor unavailable')
    token=uuid.uuid4().hex;name='volt-easy-delivery-protected-launch-'+token
    command=['docker','create','--platform','linux/amd64','--pull=never','--name',name,
        '--network','none','--user','0:0','--security-opt','no-new-privileges',
        '--label','volt.delivery.test-owner='+token,'--label','volt.delivery.role=protected-launch-component',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=8m','--tmpfs','/app/media:rw,noexec,nosuid,nodev,size=1m',
        '--tmpfs','/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
        '--mount',f'type=bind,src={component},dst=/run/component/driver.py,readonly',
        '--entrypoint','/usr/bin/env',immutable,'-i','PATH=/usr/bin:/bin','LC_ALL=C',
        '/usr/local/bin/python3.14','-I','-S','/run/component/driver.py']
    cid=run('protected-component-create',command,evidence).stdout.strip()
    if not re.fullmatch('[0-9a-f]{64}',cid):raise RuntimeError('registered component CID malformed')
    def inspect(label):
        row=json.loads(run(label,['docker','inspect',cid,'--format',
            '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"engine_image":{{json .Image}},"descriptor":{{json (index . "ImageManifestDescriptor")}},"labels":{{json .Config.Labels}},"owner":{{json (index .Config.Labels "volt.delivery.test-owner")}},"role":{{json (index .Config.Labels "volt.delivery.role")}},"state":{{json .State}},"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}},"network":{{json .HostConfig.NetworkMode}},"privileged":{{json .HostConfig.Privileged}},"caps_add":{{json .HostConfig.CapAdd}},"caps_drop":{{json .HostConfig.CapDrop}},"ports":{{json .HostConfig.PortBindings}}}'],evidence).stdout)
        if (row['id']!=cid or row['name']!='/'+name or row['image']!=immutable or row['owner']!=token
                or row['role']!='protected-launch-component' or row['network']!='none' or row['privileged']is not False
                or row['descriptor']!=selected or row['engine_image']not in(image_digest,selected['digest'])
                or row['labels'].get('org.opencontainers.image.revision')!=source_revision
                or row['labels'].get('org.volt.compose.source-snapshot')!=source_snapshot
                or row['caps_add']not in(None,[])or row['caps_drop']not in(None,[])or row['ports']not in(None,{})
                or len(row['mounts'])!=1 or row['mounts'][0]['Type']!='bind'
                or row['mounts'][0]['Source']!=str(component)or row['mounts'][0]['Destination']!='/run/component/driver.py'
                or row['mounts'][0]['RW']is not False):
            raise RuntimeError('fresh component identity/no-state/capability shape differs')
        _validate_route_visibility_tmpfs({'mounts':[],'tmpfs':row['tmpfs']})
        return row
    try:
        inspect('protected-component-before')
        run('protected-component-start',['docker','start','-a',cid],evidence,check=False)
        stopped=inspect('protected-component-after')
        if stopped['state']['Running']or stopped['state']['ExitCode']!=0:
            raise RuntimeError('fresh protected component assertion failed; original output retained')
        value=json.loads((evidence/'protected-component-start.stdout').read_text())
        (evidence/'protected-component-outcome.json').write_text(json.dumps(value,indent=2))
    finally:
        inspect('protected-component-before-exact-cleanup')
        if run('protected-component-final-server',['docker','info','--format','{{.ID}}'],evidence).stdout.strip()!=server:
            raise RuntimeError('fresh component daemon changed before cleanup')
        run('protected-component-exact-remove',['docker','rm','-f',cid],evidence)

def _validate_route_visibility_tmpfs(value: dict) -> None:
    expected = {'/tmp':'rw,noexec,nosuid,size=8m', '/app/media':'rw,noexec,nosuid,nodev,size=1m',
        '/opt/uvm/state':'rw,noexec,nosuid,nodev,size=1m',
        '/var/lib/postgresql/data':'rw,noexec,nosuid,nodev,size=1m'}
    mounts = value['mounts']
    if (value['tmpfs'] != expected or not isinstance(mounts, list)
            or len({m.get('Destination') for m in mounts}) != len(mounts)
            or any(m.get('Type') != 'tmpfs' or m.get('Destination') not in expected for m in mounts)):
        raise RuntimeError('component tmpfs mask/actual mount shape differs')

def qualify_route_process_visibility(*, admission: dict, selected: dict, evidence: Path,
                                     retained_evidence: Path | None = None) -> None:
    """Actual Linux permission prerequisite ONLY; no app/DB/TLS or route claim.

    Uses the retained independently admitted native runtime, default runtime
    capabilities, no state/ports/network and a fixed own UID1800 sleep child.
    New controller source and OLD runtime source are recorded separately.
    """
    endpoint = os.environ.get('DOCKER_HOST')
    if not endpoint:
        context = os.environ.get('DOCKER_CONTEXT') or run('route-visibility-context',
            ['docker', 'context', 'show'], evidence).stdout.strip()
        endpoint = run('route-visibility-endpoint', ['docker', 'context', 'inspect', context,
            '--format', '{{(index .Endpoints "docker").Host}}'], evidence).stdout.strip()
    if not endpoint.startswith('unix://'):
        raise RuntimeError('route process prerequisite requires local Unix daemon')
    server = run('route-visibility-server', ['docker', 'info', '--format', '{{.ID}}'], evidence).stdout.strip()
    image = admission['image_reference']; platform = admission['platform']
    if platform != 'linux/amd64' or not re.fullmatch(r'127\.0\.0\.1:46150/volt@sha256:[0-9a-f]{64}', image):
        raise RuntimeError('route process prerequisite requires owned admitted AMD64 runtime')
    rows = json.loads(run('route-visibility-native-image',
        ['docker', 'image', 'inspect', '--platform', platform, image], evidence).stdout)
    if len(rows) != 1:
        raise RuntimeError('native image is ambiguous')
    row = rows[0]; descriptor = row.get('Descriptor') or {}; labels = row.get('Config', {}).get('Labels') or {}
    if (row.get('Id') not in (admission['image_config_id'], admission['image_reference'].split('@')[1])
            and descriptor.get('digest') != admission['image_id']):
        raise RuntimeError('native runtime lacks selected object witness')
    if (labels.get('org.opencontainers.image.revision') != admission['source_commit']
            or labels.get('org.volt.compose.source-snapshot') != admission['source_snapshot']
            or row.get('Os') != 'linux' or row.get('Architecture') != 'amd64'):
        raise RuntimeError('native runtime source/platform mismatch')
    script = r'''import os,subprocess,time,signal,json
signal.alarm(15)
expected=['/opt/uvm/venv/bin/python','-c','import time;time.sleep(30)']
child=subprocess.Popen(['setpriv','--reuid=1800','--regid=1800','--init-groups',*expected],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
result={'root_uid':os.geteuid(),'child_uid_gid':None,'exact_argv':False,'exact_executable':False,'exe_observation':'not_attempted','own_child_cleanup':False}
try:
 deadline=time.monotonic()+5
 while time.monotonic()<deadline:
  if child.poll()is not None:raise RuntimeError('own child exited')
  status=open('/proc/'+str(child.pid)+'/status').read()
  ids={line.split(':',1)[0]:line.split(':',1)[1].split()for line in status.splitlines()if ':'in line}
  if ids.get('Uid')==['1800']*4 and ids.get('Gid')==['1800']*4:break
  time.sleep(.01)
 else:raise RuntimeError('own child did not reach fixed UID')
 result['child_uid_gid']=[1800,1800]
 result['cap_eff']=next(line.split(':',1)[1].strip()for line in open('/proc/self/status')if line.startswith('CapEff:'))
 argv=[x.decode()for x in open('/proc/'+str(child.pid)+'/cmdline','rb').read(8193).split(b'\0')if x]
 result['exact_argv']=argv==expected
 try:
  actual=os.stat('/proc/'+str(child.pid)+'/exe');declared=os.stat('/opt/uvm/venv/bin/python')
  result['exact_executable']=(actual.st_dev,actual.st_ino)==(declared.st_dev,declared.st_ino)
  result['exe_observation']='readable'
 except PermissionError:result['exe_observation']='permission_denied'
 except OSError:result['exe_observation']='unavailable'
finally:
 if child.poll()is None:child.terminate()
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:child.kill();child.wait(timeout=2)
 result['own_child_cleanup']=True
print(json.dumps(result,sort_keys=True))
raise SystemExit(0 if result['root_uid']==0 and result['child_uid_gid']==[1800,1800]and result['exact_argv']and result['exact_executable']else 2)
'''
    token = uuid.uuid4().hex
    if retained_evidence is not None:
        original = json.loads((retained_evidence / 'route-visibility-create.argv.json').read_text())
        labels = [original[i+1] for i, arg in enumerate(original[:-1]) if arg == '--label']
        owners = [value.split('=',1)[1] for value in labels if value.startswith('volt.delivery.test-owner=')]
        if len(owners) != 1 or not re.fullmatch('[0-9a-f]{32}', owners[0]):
            raise RuntimeError('exact registered component owner unavailable')
        token = owners[0]
    name = 'volt-easy-delivery-route-visibility-' + token
    create = ['docker', 'create', '--platform', platform, '--pull=never', '--name', name,
        '--network', 'none', '--read-only', '--security-opt', 'no-new-privileges', '--user', '0:0',
        '--label', 'volt.delivery.test-owner=' + token, '--label', 'volt.delivery.role=route-process-visibility',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m',
        '--tmpfs', '/app/media:rw,noexec,nosuid,nodev,size=1m',
        '--tmpfs', '/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m',
        '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
        '--entrypoint', '/opt/uvm/venv/bin/python', image, '-c', script]
    if retained_evidence is None:
        cid = run('route-visibility-create', create, evidence).stdout.strip()
    else:
        if original != create or (retained_evidence / 'route-visibility-server.stdout').read_text().strip() != server:
            raise RuntimeError('registered original component argv/daemon differs')
        cid = (retained_evidence / 'route-visibility-create.stdout').read_text().strip()
        (evidence / 'registered-original-binding.json').write_text(json.dumps({
            'original_evidence': str(retained_evidence), 'original_argv_sha256': sha(retained_evidence / 'route-visibility-create.argv.json'),
            'fullCID': cid, 'same_original_create_argv': True, 'same_daemon': True}, indent=2))
    if not re.fullmatch(r'[0-9a-f]{64}', cid):
        raise RuntimeError('registered component fullCID unavailable')
    def inspect(label):
        value = json.loads(run(label, ['docker', 'inspect', cid, '--format',
            '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"descriptor":{{json (index . "ImageManifestDescriptor")}},"owner":{{json (index .Config.Labels "volt.delivery.test-owner")}},"role":{{json (index .Config.Labels "volt.delivery.role")}},"state":{{json .State}},"mounts":{{json .Mounts}},"network":{{json .HostConfig.NetworkMode}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},"ports":{{json .HostConfig.PortBindings}},"tmpfs":{{json .HostConfig.Tmpfs}},"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}},"user":{{json .Config.User}}}'], evidence).stdout)
        if (value['id'] != cid or value['name'] != '/' + name or value['image'] != image
                or value['owner'] != token or value['role'] != 'route-process-visibility'
                or value['descriptor'] != selected or selected.get('digest') != admission['image_id']
                or value['network'] != 'none' or value['readonly'] is not True or value['privileged'] is not False
                or value['cap_add'] not in (None, []) or value['cap_drop'] not in (None, [])
                or value['ports'] not in (None, {})
                or value['user'] != '0:0' or value['entrypoint'] != ['/opt/uvm/venv/bin/python']
                or value['command'] != ['-c', script]
):
            raise RuntimeError('component ownership/default-capability/no-state shape differs')
        _validate_route_visibility_tmpfs(value)
        return value
    try:
        before = inspect('route-visibility-before-start')
        if before['state']['Status'] != 'created' or before['state']['Running'] or before['state']['Pid'] != 0:
            raise RuntimeError('ONLY never-started registered component may execute once')
        run('route-visibility-start-attached', ['docker', 'start', '-a', cid], evidence, check=False)
        stopped = inspect('route-visibility-after')
        if stopped['state']['Running'] or stopped['state']['ExitCode'] not in (0, 2):
            raise RuntimeError('component failed outside exact visibility assertion')
        result = json.loads((evidence / 'route-visibility-start-attached.stdout').read_text())
        result.update(runtime_source=admission['source_commit'], runtime_snapshot=admission['source_snapshot'],
            claim='Linux permission prerequisite only; not new root-helper/API/backend/TLS or installed-state qualification',
            outcome='VISIBLE' if stopped['state']['ExitCode']==0 else 'BLOCKED_PERMISSION_PREREQUISITE')
        (evidence / 'route-process-visibility-outcome.json').write_text(json.dumps(result, indent=2))
    finally:
        inspect('route-visibility-before-exact-cleanup')
        if run('route-visibility-final-server', ['docker', 'info', '--format', '{{.ID}}'], evidence).stdout.strip() != server:
            raise RuntimeError('component daemon changed before cleanup')
        run('route-visibility-exact-remove', ['docker', 'rm', '-f', cid], evidence)
    if result['outcome'] != 'VISIBLE':
        raise RuntimeError('root publisher cannot prove the admitted executable with normal runtime permissions')

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


def initial_resume_observer_environment(*, capture: Path, state: Path, environment: dict,
        admission: dict, engine_id: str, selected: dict, project_prefix: str) -> dict:
    '''Private POSIX readiness barrier; no product fault flag or authority.

    The ORIGINAL Docker logs result is captured once, then held BEFORE its
    ready line reaches the signed launcher. Thus cache publication cannot race
    the parent observation. Outside this single owned initial holder, commands,
    arguments, streams and status are forwarded unchanged.
    '''
    capture.mkdir(mode=0o700)
    real = Path(shutil.which('docker', path=environment['PATH'])).resolve(strict=True)
    executable = capture/'docker'
    constants = {'REAL_DOCKER':str(real),'CAPTURE':str(capture),'EXPECTED_STATE':str(state),
        'EXPECTED_REF':admission['image_reference'],'EXPECTED_ID':admission['image_id'],
        'EXPECTED_KIND':admission['image_id_kind'],'EXPECTED_ENGINE':engine_id,
        'EXPECTED_CHILD':selected['digest'],'EXPECTED_MEDIA':selected['mediaType'],
        'EXPECTED_SIZE':str(selected['size']),'EXPECTED_PLATFORM':admission['platform'],
        'EXPECTED_PREFIX':project_prefix}
    header='#!/bin/sh\nset -eu\numask 077\n'+''.join(key+'='+shlex.quote(value)+'\n' for key,value in constants.items())
    body=r'''
pass_original() { exec "$REAL_DOCKER" "$@"; }
[ "$#" -eq 2 ] && [ "$1" = logs ] || pass_original "$@"
[ -f "$CAPTURE/caller.pid" ] && [ ! -L "$CAPTURE/caller.pid" ] || pass_original "$@"
IFS= read -r caller <"$CAPTURE/caller.pid"
case "$caller" in ''|*[!0-9]*) pass_original "$@" ;; esac
case "$2" in "volt-lock-${EXPECTED_PREFIX}-"*"-$caller") ;; *) pass_original "$@" ;; esac
# This is a Linux test observer, not a new host product prerequisite.
read -r actual_pid process_name process_state parent_pid group_id session_id rest <"/proc/$caller/stat"
[ "$actual_pid|$group_id|$session_id" = "$caller|$caller|$caller" ] || exit 76
identity=$("$REAL_DOCKER" inspect "$2" --format '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Running}}|{{index .Config.Labels "volt.compose.owner-token"}}|{{index .Config.Labels "volt.compose.project"}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{.Image}}|{{if .ImageManifestDescriptor}}{{.ImageManifestDescriptor.digest}}|{{.ImageManifestDescriptor.mediaType}}|{{.ImageManifestDescriptor.size}}|{{.ImageManifestDescriptor.platform.os}}/{{.ImageManifestDescriptor.platform.architecture}}{{end}}')
IFS='|' read -r cid name reference running owner project entry command network readonly privileged image child media size platform <<EOF_RESUME_ID
$identity
EOF_RESUME_ID
valid=1
[ "$name|$reference|$running|$network|$readonly|$privileged" = "/volt-lock-$project-$caller|$EXPECTED_REF|true|none|true|false" ] || valid=0
[ "$entry" = '["/opt/uvm/venv/bin/python"]' ] && [ "$command" = '["-m","uvm.installer.lock","/state/.install.lock","--initialize-local"]' ] || valid=0
case "$owner:$cid" in *[!0-9a-f:]*) valid=0 ;; esac
[ "${#owner}" -eq 64 ] && [ "${#cid}" -eq 64 ] || valid=0
case "$project" in "$EXPECTED_PREFIX-"*) ;; *) valid=0 ;; esac
if [ "$image" != "$EXPECTED_ID" ]; then
 [ "$EXPECTED_KIND|$image|$child|$media|$size|$platform" = "selected_manifest|$EXPECTED_ENGINE|$EXPECTED_CHILD|$EXPECTED_MEDIA|$EXPECTED_SIZE|$EXPECTED_PLATFORM" ] || valid=0
fi
state_bind=$("$REAL_DOCKER" inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/state"}}{{.Source}}|{{.RW}}{{end}}{{end}}')
request=$("$REAL_DOCKER" inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/run/volt-initialization/request.json"}}{{.Source}}{{end}}{{end}}')
[ "$state_bind" = "$EXPECTED_STATE|true" ] || valid=0
case "$request" in /tmp/volt-installer.????????/runtime-init-request.json) ;; *) valid=0 ;; esac
if [ "$valid" -ne 1 ]; then printf '%s\n' contradiction >"$CAPTURE/guard.status"; exit 76; fi
# The trusted fixed helper emits bounded initialization/readiness records.
# A hard file limit bounds both streams; a limit failure cannot become ready.
set +e
( ulimit -f 64; "$REAL_DOCKER" "$@" ) >"$CAPTURE/owner.stdout" 2>"$CAPTURE/owner.stderr"
original_exit=$?
set -e
printf '%s\n' "$original_exit" >"$CAPTURE/logs.exit"
if [ "$original_exit" -eq 0 ] && grep -q '^locked=1$' "$CAPTURE/owner.stdout"; then
 "$REAL_DOCKER" inspect "$cid" >"$CAPTURE/holder.json"
 printf '%s\n' "$identity" >"$CAPTURE/identity"
 printf '%s\n' "$request" >"$CAPTURE/request.path"
 printf '%s\n' "$cid" >"$CAPTURE/gate.ready"
 attempts=0
 while [ "$attempts" -lt 120 ]; do
  # Only a controller cleanup/release can end this test-only barrier. No
  # readiness byte has yet been forwarded to the actual public launcher.
  [ ! -f "$CAPTURE/release" ] || break
  attempts=$((attempts + 1)); sleep 1
 done
 [ "$attempts" -lt 120 ] || { printf '%s\n' expired >"$CAPTURE/guard.status"; exit 75; }
fi
cat "$CAPTURE/owner.stdout"
cat "$CAPTURE/owner.stderr" >&2
exit "$original_exit"
'''
    executable.write_text(header+body);executable.chmod(0o700)
    (capture/'observer-binding.json').write_text(json.dumps({'script_sha256':sha(executable),
        'real_docker':str(real),'real_docker_sha256':sha(real),'state':str(state),
        'runtime_reference':admission['image_reference'],'image_id':admission['image_id'],
        'engine_id':engine_id,'selected_descriptor':selected,
        'scope':'TEST observation/readiness hold only; original Docker result held before forwarding, Linux proc caller-group guard; not unmodified-Docker certification'},indent=2)+'\n')
    return {**environment,'PATH':str(capture)+os.pathsep+environment['PATH'],'RESUME_CAPTURE':str(capture)}


def initial_resume_fd_probe() -> str:
    """Fixed read-only probe, separately compiled before any actual invocation."""
    return "import os,json,stat\nfrom pathlib import Path\nroot=os.stat('/state/.install.lock'); found=[]\nfor p in Path('/proc/1/fd').iterdir():\n try:\n  if os.readlink(p)!='/state/.install.lock':continue\n  target=p.stat(); text=(Path('/proc/1/fdinfo')/p.name).read_text()\n  if (root.st_dev,root.st_ino)!=(target.st_dev,target.st_ino) or stat.S_IMODE(root.st_mode)!=0o600 or root.st_uid!=os.getuid() or root.st_size!=0:raise SystemExit('actual lock inode/custody differs')\n  if not any('FLOCK' in line.split() and 'WRITE' in line.split() for line in text.splitlines()):raise SystemExit('actual exclusive FD lock missing')\n  found.append({'fd':int(p.name),'inode':target.st_ino,'uid':root.st_uid,'mode':'0600','size':root.st_size,'fdinfo':text})\n except FileNotFoundError:continue\nif len(found)!=1:raise SystemExit('exactly one actual held lock FD required')\nprint(json.dumps({'actual_exclusive_fd':found}))\n\n"


def qualify_initial_resume_fixture(*, bundle: Path, fixture: Path, image_id: str,
        source_revision: str, source_snapshot: str, platform: str, private: Path,
        evidence: Path) -> None:
    """One real prepared/pre-publication interruption, then existing public start.

    POSIX readiness withholding is TEST instrumentation, not a product fault
    switch or an unmodified-Docker certification. Original initial authority,
    journal, request, stage and keys come only from the actual signed producer.
    """
    from uvm.installer.lock import _bounded_file
    from uvm.installer.offline_artifacts import Closure, digest
    admission=validate_admission_fixture(fixture,image_id=image_id,source_snapshot=source_snapshot,
        source_commit=source_revision,platform=platform,bundle=bundle,version='0.1.0-rc.4',evidence=evidence)
    extracted=private/'extracted';extracted.mkdir(mode=0o700);shutil.unpack_archive(str(bundle),extracted,'gztar')
    package=extracted/'volt-compose-0.1.0-rc.4';outer=private/'signed-package';outer.mkdir(mode=0o700)
    launcher=outer/'launcher.sh';render_fixture_launcher(package/'launcher.sh',launcher,fixture)
    shutil.copyfile(bundle,outer/'installer.bundle.tar.gz')
    for name in ('installer.bundle.sigstore.json','launcher.sigstore.json'):shutil.copyfile(fixture/name,outer/name)
    for path in outer.iterdir():path.chmod(0o600)
    public=evidence/'fixture-trust-public'
    run('resume-trusted-launcher-signature',['docker','run','--rm','--platform',platform,'--pull=never',
        '--network','host','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--user',f'{os.getuid()}:{os.getgid()}',
        '--mount',f'type=bind,src={public},dst=/fixture,readonly','--mount',f'type=bind,src={launcher},dst=/launcher,readonly',
        COSIGN_IMAGE,'verify-blob','--key','/fixture/fixture.pub','--trusted-root','/fixture/trusted-root.json',
        '--bundle','/fixture/launcher.sigstore.json','/launcher'],evidence)
    environment=trusted_launcher_environment(private/'minimal-host-path',admission);state=private/'instance'
    engine=run('resume-admitted-engine-id',['docker','image','inspect',admission['image_reference'],'--format','{{.Id}}'],evidence).stdout.strip()
    if engine not in {admission['image_id'],admission['image_index_digest']}:raise RuntimeError('resume observer engine mapping differs from authenticated index/selected object')
    selected=json.loads((evidence/'fixture-full-runtime-admission.stdout').read_text())['runtime']['selected_descriptor']
    capture=private/'initial-observer';observed=initial_resume_observer_environment(capture=capture,state=state,
        environment=environment,admission=admission,engine_id=engine,selected=selected,project_prefix='volt-easy-delivery')
    original_command=['sh',str(launcher),'install','--directory',str(state),'--port','46180','--project-prefix','volt-easy-delivery']
    wrapper='umask 077; printf "%s\\n" "$$" >"$RESUME_CAPTURE/caller.pid"; exec sh "$0" "$@"'
    command=['sh','-c',wrapper,str(launcher),*original_command[2:]]
    (evidence/'initial-install-invocation.json').write_text(json.dumps({'argv':command,'original_supported_argv':original_command,
        'cwd':str(ROOT),'environment_PATH':observed['PATH'],'start_new_session':True,'instrumentation':'private POSIX actual-readiness withholding before publication; source unchanged'},indent=2))
    (evidence/'retained-fixture.json').write_text(json.dumps({'private':str(private),'state':str(state),
        'admission':admission,'runtime_source_revision':source_revision,'cleanup':'RETAIN initial/resumed fixture and private original material until review'},indent=2))
    with (evidence/'initial-install.stdout').open('x')as stdout,(evidence/'initial-install.stderr').open('x')as stderr:
        caller=subprocess.Popen(command,cwd=ROOT,env=observed,stdout=stdout,stderr=stderr,start_new_session=True)
        (capture/'registered-caller.json').write_text(json.dumps({'pid':caller.pid,'pgid':os.getpgid(caller.pid),'sid':os.getsid(caller.pid)}))
        try:
            deadline=time.monotonic()+180
            while time.monotonic()<deadline and not (capture/'gate.ready').exists():
                if caller.poll() is not None:break
                if (capture/'guard.status').exists():break
                time.sleep(.05)
            if not (capture/'gate.ready').exists():
                if caller.poll()is None and os.getpgid(caller.pid)==caller.pid:os.killpg(caller.pid,signal.SIGTERM)
                try:code=caller.wait(timeout=30)
                except subprocess.TimeoutExpired:os.killpg(caller.pid,signal.SIGKILL);code=caller.wait()
                (evidence/'initial-install.exit').write_text(str(code))
                raise RuntimeError('actual prepared readiness boundary was not held; no interruption pass, preserve first failure')
            if (capture/'caller.pid').read_text().strip()!=str(caller.pid) or os.getpgid(caller.pid)!=caller.pid or os.getsid(caller.pid)!=caller.pid:
                raise RuntimeError('initial observer caller/process group differs; no signal authorised')
            cid=(capture/'gate.ready').read_text().strip();row=json.loads((capture/'holder.json').read_text())[0]
            if (row['Id']!=cid or row['Config']['Image']!=admission['image_reference'] or row['State']['Running']is not True
                    or row['Config']['Cmd']!=['-m','uvm.installer.lock','/state/.install.lock','--initialize-local']):
                raise RuntimeError('held initialization observer identity differs')
            raw=_bounded_file(state/'instance.json',1024*1024,private=True);info=json.loads(raw)
            project=info['project'];owner=info['owner_token'];anchor=private/'instance.installer-artifacts';stage=anchor/info['installer_cache_stage']
            if (info.get('installer_phase')!='prepared' or info.get('initialized')is not True or info.get('established')is not False
                    or info.get('local_recovery_acknowledgement')is not None or info.get('restore_pending')
                    or set(p.name for p in anchor.iterdir())!={stage.name}
                    or row['Config']['Labels'].get('volt.compose.owner-token')!=owner
                    or row['Config']['Labels'].get('volt.compose.project')!=project):
                raise RuntimeError('actual initial phase/publication/owner contradicts intended pre-ack boundary')
            request_path=Path((capture/'request.path').read_text().strip());request=_bounded_file(request_path,65536,private=True)
            document=json.loads(request)
            if (digest(request)!=info['installer_initial_request_sha256'] or document['profile']!='volt_local_runtime_init_v1'
                    or document['setup_sha256']!=digest((package/'setup.py').read_bytes())
                    or document['arguments']['owner_token']!=owner):
                raise RuntimeError('actual initial request differs from durable pin/selected producer')
            (capture/'original-request.json').write_bytes(request);(capture/'original-request.json').chmod(0o600)
            (capture/'original-journal.json').write_bytes(raw);(capture/'original-journal.json').chmod(0o600)
            material=capture/'initial-material';material.mkdir(mode=0o700);files={}
            for name,value in info['installer_initial_files'].items():
                data=_bounded_file(state/name,1024*1024,private=False)
                if digest(data)!=value['sha256'] or len(data)!=value['bytes']:raise RuntimeError('actual committed initial file changed before interruption')
                destination=material/name;destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                for parent in destination.parents:
                    if parent == material:break
                    parent.chmod(0o700)
                destination.write_bytes(data);destination.chmod(0o600)
                files[name]={'sha256':digest(data),'bytes':len(data),'mode':stat.S_IMODE((state/name).stat().st_mode)}
            closure=Closure(fixture=None,custody_root=stage)
            if closure.hash!=info['installer_admission']['closure_sha256']:raise RuntimeError('actual retained initial stage differs from pin')
            stage_identity=[stage.stat().st_dev,stage.stat().st_ino]
            probe=run('initial-before-ack-api-absent',['docker','container','inspect',project+'-volt-1'],evidence,check=False)
            if probe.returncode==0 or 'no such'not in probe.stderr.lower():raise RuntimeError('initial boundary did not precede API/worker creation')
            proc_script=initial_resume_fd_probe()
            run('actual-initial-holder-exclusive-fd',['docker','exec','--user',f'{os.getuid()}:{os.getgid()}',cid,
                '/opt/uvm/venv/bin/python','-c',proc_script],evidence)
            (evidence/'actual-prepared-boundary.json').write_text(json.dumps({'holder_id':cid,'caller_pid':caller.pid,
                'project':project,'operation':'initialize-local','request_sha256':digest(request),'journal_sha256':digest(raw),
                'installation_id':info['installation_id'],'initial_files':files,'stage_name':stage.name,
                'stage_inode':stage_identity,'closure_sha256':closure.hash,'cache_published':False,'ack_present':False,
                'API_present':False,'runtime_source':source_revision,'scope':'REAL signed producer/actual FD; private readiness result held BEFORE forwarding; no metadata editing'},indent=2))
            os.killpg(caller.pid,signal.SIGTERM)
            try:code=caller.wait(timeout=30)
            except subprocess.TimeoutExpired:os.killpg(caller.pid,signal.SIGKILL);code=caller.wait()
            (evidence/'initial-install.exit').write_text(str(code))
        finally:
            # This Popen is the registered private controller child. Never
            # signal a process group learned from Docker or observed names.
            if caller.poll() is None:
                if os.getpgid(caller.pid) != caller.pid or os.getsid(caller.pid) != caller.pid:
                    raise RuntimeError('registered caller session changed; no group signal authorised')
                os.killpg(caller.pid, signal.SIGTERM)
                try: caller.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(caller.pid, signal.SIGKILL); caller.wait()
    remaining=run('initial-held-owner-after-interruption',['docker','inspect',cid],evidence,check=False)
    if remaining.returncode==0:
        current=json.loads(remaining.stdout)[0]
        if current['Config']['Image']!=admission['image_reference'] or current['Config']['Labels'].get('volt.compose.owner-token')!=owner or current['Config']['Labels'].get('volt.compose.project')!=project:
            raise RuntimeError('interrupted holder changed; no cleanup authorised')
        run('initial-exact-owned-holder-remove',['docker','rm','-f',cid],evidence)
    elif 'no such'not in remaining.stderr.lower():raise RuntimeError('interrupted holder absence is unproved')
    resume_preserved_initial_fixture(private=private, evidence=evidence, admission=admission,
        source_revision=source_revision, source_snapshot=source_snapshot)


def resume_preserved_initial_fixture(*, private: Path, evidence: Path, admission: dict,
        source_revision: str, source_snapshot: str) -> None:
    """Continue ONLY this controller's original interrupted fixture; no init/reset.

    Original captured bytes are comparison evidence, never admission authority.
    The existing public start independently authenticates and validates the stage
    and actual new lock FD before any transition. All originals stay private.
    """
    from uvm.installer.lock import _bounded_file
    from uvm.installer.offline_artifacts import Closure, digest
    capture=private/'initial-observer';state=private/'instance'
    raw=_bounded_file(capture/'original-journal.json',1024*1024,private=True)
    info=json.loads(raw);anchor=private/'instance.installer-artifacts';stage=anchor/info['installer_cache_stage']
    if (info.get('installer_phase')!='prepared' or info.get('initialized')is not True
            or info.get('established')is not False or info.get('local_recovery_acknowledgement')is not None
            or info.get('restore_pending') or set(p.name for p in anchor.iterdir())!={stage.name}):
        raise RuntimeError('retained original is not the exact interrupted initial phase')
    files={}
    for name,value in info['installer_initial_files'].items():
        original=_bounded_file(capture/'initial-material'/name,1024*1024,private=True)
        if digest(original)!=value['sha256'] or len(original)!=value['bytes']:
            raise RuntimeError('retained original initial material contradicts its producer inventory')
        files[name]={'sha256':digest(original),'bytes':len(original)}
    closure=Closure(fixture=None,custody_root=stage)
    if closure.hash!=info['installer_admission']['closure_sha256']:
        raise RuntimeError('retained original stage contradicts producer pin')
    stage_identity=[stage.stat().st_dev,stage.stat().st_ino]
    environment=trusted_launcher_environment(private/'minimal-host-path',admission)
    (evidence/'retained-before-public-resume.json').write_text(json.dumps({
        'journal_sha256':digest(raw),'original_material_files':len(files),'stage_inode_observed_now':stage_identity,
        'original_preinterruption_fd_probe_exit':(evidence/'actual-initial-holder-exclusive-fd.exit').read_text().strip(),
        'scope':'CURRENT retained-state comparison before public resume; not retrospective pre-interruption FD proof'},indent=2))
    if _bounded_file(state/'instance.json',1024*1024,private=True)!=raw or not stage.is_dir() or (anchor/'originals').exists():
        raise RuntimeError('interruption did not preserve exact initial journal/stage before publication')
    for name,value in files.items():
        if digest(_bounded_file(state/name,1024*1024,private=False))!=value['sha256']:raise RuntimeError('interruption changed original private material')
    offline=create_offline_fixture_entry(state=state,admission=admission,private=private)
    run('supported-public-initial-resume',['sh',str(offline),'start','--directory',str(state)],evidence,env=environment)
    wait_for_local('http://127.0.0.1:46180',evidence)
    after=json.loads(_bounded_file(state/'instance.json',1024*1024,private=True));originals=anchor/'originals'
    if (after['installation_id']!=info['installation_id'] or after['installer_initial_request_sha256']!=info['installer_initial_request_sha256']
            or after['installer_admission']!=info['installer_admission'] or after['installer_initial_files']!=info['installer_initial_files']
            or after.get('established')is not True or not after.get('local_recovery_acknowledgement')
            or set(p.name for p in anchor.iterdir())!={'originals'} or [originals.stat().st_dev,originals.stat().st_ino]!=stage_identity
            or Closure(fixture=None,custody_root=originals).hash!=closure.hash):
        raise RuntimeError('supported resume changed initial identity/pin/stage or lacks exact establishment')
    for name,value in files.items():
        data=_bounded_file(state/name,1024*1024,private=False)
        if name=='.env':
            if hashlib.sha256(data).hexdigest()!=after['env_sha256']:raise RuntimeError('resumed environment differs from durable CURRENT transition')
        elif digest(data)!=value['sha256']:raise RuntimeError('supported resume regenerated original private material')
    run('resume-supported-controlled-stop',['sh',str(offline),'stop','--directory',str(state)],evidence,env=environment)
    (evidence/'initial-resume-outcome.json').write_text(json.dumps({'status':'actual_prepared_prepublication_interruption_and_public_resume_passed',
        'runtime_source':source_revision,'source_snapshot':source_snapshot,'installation_id':after['installation_id'],
        'original_initial_private_bytes_preserved_except_existing_env_transition':True,'original_initial_request_and_pin_preserved':True,
        'exact_stage_inode_renamed_to_originals':True,'normal_health':True,'stopped_retained_fixture':str(private),
        'no_accounts_browser_or_SQL':True,'instrumentation':'private bounded readiness withholding; no production fault switch'},indent=2))


@contextmanager
def initial_resume_private_fault(*, state: Path, retention: Path, case: str):
    """TEST ONLY fixed reversible faults; originals are moved, never recreated."""
    import fcntl
    from uvm.installer.lock import _bounded_file
    choices={'missing-key':('secrets/local-auth-key',None),
        'changed-key':('secrets/local-auth-key','key'),
        'changed-config':('local-auth.json','config'),
        'unsafe-key-mode':('secrets/local-auth-key','mode'),
        'missing-journal':('instance.json',None),
        'missing-pin':('instance.json','pin'),
        'missing-originals':(None,None)}
    if case not in choices:raise ValueError('unsupported fixed initial-resume private fault')
    relative,alter=choices[case]
    target=state/relative if relative else state.parent/(state.name+'.installer-artifacts')/'originals'
    held=retention/'original';replacement=None
    # This host controller guard is test isolation, not a product admission.
    # The subsequent public command obtains its own actual product lock FD.
    @contextmanager
    def controller_guard():
        fd=os.open(state/'.install.lock',os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd);current=(state/'.install.lock').lstat()
            if (not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=0
                    or (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino)):
                raise RuntimeError('test controller lock custody differs')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        finally:os.close(fd)
    with controller_guard():
        info=target.lstat()
        if (target.is_symlink()or info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)!=(0o600 if relative else 0o700)
                or (relative and(not stat.S_ISREG(info.st_mode)or info.st_nlink!=1))
                or (not relative and not stat.S_ISDIR(info.st_mode))):
            raise RuntimeError('original fixed test input custody differs')
        original=_bounded_file(target,1024*1024,private=True)if relative else None
        identity=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
        changed=None
        if alter:
            if alter=='key':
                if len(original)!=32:raise RuntimeError('original local key size differs')
                changed=bytes([original[0]^1])+original[1:]
            elif alter=='config':changed=original+b'\n'
            elif alter=='mode':changed=original
            else:
                value=json.loads(original);del value['installer_admission']
                changed=json.dumps(value,sort_keys=True).encode()+b'\n'
        retention.mkdir(mode=0o700)
        os.rename(target,held)
        if alter:
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb')as stream:stream.write(changed);stream.flush();os.fsync(stream.fileno())
            if alter=='mode':target.chmod(0o640)
            changed_info=target.lstat();replacement=(changed_info.st_dev,changed_info.st_ino,digest_bytes(changed),stat.S_IMODE(changed_info.st_mode))
        for parent in (target.parent,retention):
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
    try:
        yield {'case':case,'original_inode':identity[:2],'original_mode':oct(identity[4]),
            'original_sha256':digest_bytes(original)if relative else None,
            'changed_sha256':replacement[2]if replacement else None}
    finally:
        with controller_guard():
            current=held.lstat()
            if (current.st_dev,current.st_ino,current.st_uid,current.st_gid,stat.S_IMODE(current.st_mode))!=identity:
                raise RuntimeError('retained original changed; no restoration/adoption authorised')
            if replacement is None:
                if target.exists()or target.is_symlink():raise RuntimeError('missing input was recreated; never overwrite/adopt it')
            else:
                current=target.lstat()
                if ((current.st_dev,current.st_ino)!=(replacement[0],replacement[1])or
                        stat.S_IMODE(current.st_mode)!=replacement[3] or
                        digest_bytes(_bounded_file(target,1024*1024,private=False))!=replacement[2]):
                    raise RuntimeError('test replacement changed; never remove an unexpected input')
                target.unlink()
            os.rename(held,target)
            restored=target.lstat()
            if ((restored.st_dev,restored.st_ino,restored.st_uid,restored.st_gid,stat.S_IMODE(restored.st_mode))!=identity
                    or relative and _bounded_file(target,1024*1024,private=True)!=original):
                raise RuntimeError('original input restoration differs')
            for parent in (target.parent,retention):
                fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)


def digest_bytes(raw: bytes) -> str:
    return 'sha256:'+hashlib.sha256(raw).hexdigest()


def qualify_initial_private_denials(*, private: Path, evidence: Path, admission: dict) -> None:
    """Six fixed authority-input boundaries on the SAME stopped resumed fixture.

    No new install/account, ack/capability edits, image change or pin backfill.
    Controller Python performs deliberate reversible TEST faults only. Target
    commands remain the existing externally authenticated minimal-host start.
    """
    from uvm.installer.lock import _bounded_file
    state=private/'instance';raw=_bounded_file(state/'instance.json',1024*1024,private=True);info=json.loads(raw)
    if (info.get('established')is not True or not info.get('local_recovery_acknowledgement')
            or info['image']!=admission['image_reference']):raise RuntimeError('same established resumed fixture required')
    entry=private/'trusted-offline-entry.sh'
    if entry.is_symlink()or not entry.is_file():raise RuntimeError('existing independent fixed entry missing')
    environment=trusted_launcher_environment(private/'minimal-host-path',admission)
    paths=set(info['installer_initial_files'])|set(info['local_recovery_inventory'])|{'instance.json','secrets/local-start-admission/admission.json','secrets/local-restore-fence/fence.json'}
    def fingerprints():
        return {name:{'sha256':digest_bytes(_bounded_file(state/name,1024*1024,private=False)),
            'inode':[(state/name).lstat().st_dev,(state/name).lstat().st_ino],
            'mode':stat.S_IMODE((state/name).lstat().st_mode)}for name in sorted(paths)}
    def observed(name, expected_identity=None):
        template='{"id":{{json .Id}},"reference":{{json .Config.Image}},"owner":{{json (index .Config.Labels "volt.compose.owner-token")}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"state":{{json .State}}}'
        row=json.loads(run(name,['docker','inspect',info['project']+'-volt-1','--format',template],evidence).stdout)
        if (row['reference']!=admission['image_reference']or row['owner']!=info['owner_token']
                or row['project']!=info['project']):
            raise RuntimeError('exact resumed owned API identity differs')
        if row['state']['Running']is not False:
            if expected_identity and row['id']==expected_identity['id']:
                run(name+'-unexpected-exact-owned-stop',['docker','stop','--time','10',row['id']],evidence,check=False)
            raise RuntimeError('exact resumed owned API unexpectedly started; negative is NOT accepted')
        return {key:row[key]for key in ('id','reference')}|{'StartedAt':row['state']['StartedAt'],'Running':False}
    before=fingerprints();identity=observed('private-denials-before-stopped')
    expected={'missing-key':('terminal','local auth configuration, encryption key or bootstrap delivery directory is missing or unsafe'),
        'changed-key':('terminal','local recovery committed fingerprints changed'),
        'changed-config':('terminal','local recovery committed fingerprints changed'),
        'missing-journal':('authentication','external offline entry: current selected journal missing'),
        'missing-pin':('authentication','verifier.py: error: closed original installed-artifact pin is missing or contradicts fixed publisher expectations'),
        'missing-originals':('terminal','external offline entry: single exact retained stage required')}
    retention=private/'private-input-test-originals';retention.mkdir(mode=0o700)
    outcomes=[];auth=private/'public-offline-authentication'
    for case,(layer,message)in expected.items():
        if fingerprints()!=before or observed(case+'-before-stopped')!=identity:raise RuntimeError('fixture changed before deliberate test fault')
        prior=set(auth.iterdir())
        with initial_resume_private_fault(state=state,retention=retention/case,case=case)as fault:
            result=run('private-denial-'+case,['sh',str(entry),'start','--directory',str(state)],evidence,env=environment,check=False)
            after=observed(case+'-after-stopped',identity)
            new=set(auth.iterdir())-prior
            diagnostics=result.stderr
            if layer=='authentication':
                if len(new)!=1:raise RuntimeError('exact new private authentication record required')
                record=next(iter(new));diagnostics=_bounded_file(record/'authentication.stderr',65536,private=True).decode()
            if(result.returncode==0 or after!=identity or message not in diagnostics.splitlines()):
                raise RuntimeError('private-input denial did not reach exact documented boundary before workers')
            # The target is still deliberately missing/changed here; all other
            # observed originals must match before restoring its exact inode.
            excluded={'missing-key':'secrets/local-auth-key','changed-key':'secrets/local-auth-key',
                'changed-config':'local-auth.json','missing-journal':'instance.json','missing-pin':'instance.json'}.get(case)
            for name,value in before.items():
                if name==excluded:continue
                data=_bounded_file(state/name,1024*1024,private=False)
                if digest_bytes(data)!=value['sha256']:raise RuntimeError('public denial mutated another original private input')
            outcomes.append({**fault,'exit':result.returncode,'actual_failure_layer':layer,
                'exact_complete_diagnostic_line':message,'API_identity_and_StartedAt_unchanged':True})
        if fingerprints()!=before:raise RuntimeError('exact original bytes/modes/inodes not restored')
    (evidence/'initial-private-denials-outcome.json').write_text(json.dumps({'status':'passed','cases':outcomes,
        'observed_fingerprints':before,'same_stopped_API':identity,'original_bytes_modes_inodes_restored':True,
        'scope':'six deliberately reversible TEST faults, actual signed minimal-host public start denials; fixed host-readable inputs only, runtime capability coverage NOT claimed; no account/SQL/ack/cap changes'},indent=2))


def guard_extra_qualification_network(row: dict, *, network_id: str, owner: str,
        project: str, test_id: str, api_id: str) -> None:
    """TEST cleanup guard: never disconnect/remove foreign or original resources."""
    if (row.get('Id')!=network_id or row.get('Name')!='volt-easy-delivery-extra-'+test_id
            or row.get('Driver')!='bridge' or row.get('Internal')is not True
            or row.get('Options')not in(None,{}, {'com.docker.network.enable_ipv4':'true','com.docker.network.enable_ipv6':'false'})
            or row.get('Labels')!={'volt.compose.owner-token':owner,
                'volt.delivery.project':project,'volt.delivery.test':test_id}
            or not isinstance(row.get('Containers'),dict)
            or not set(row['Containers']).issubset({api_id})):
        raise RuntimeError('extra qualification network identity/ownership/attachments differ; no mutation authorised')


def unsupported_upgrade_test_entry(original: Path, destination: Path) -> None:
    """TEST entry permits ONE unsupported literal through to signed CLI denial.

    No product launcher, trust, source, image, arguments or authentication changes.
    This cannot establish any upgrade capability or schema-upgrade coverage.
    """
    from uvm.installer.lock import _bounded_file
    source=_bounded_file(original,256*1024,private=False).decode()
    guard='case "$action" in verify-cache|stop|start|status|logs|diagnose|setup|backup-record|backup-status|restore-provision|restore-admit|destroy) ;; *) fail "unsupported fixed lifecycle action" ;; esac'
    if source.count(guard)!=1:raise RuntimeError('exact original test-entry whitelist is absent/ambiguous')
    changed=source.replace(guard,guard.replace('|destroy)', '|destroy|upgrade)'))
    with destination.open('x')as stream:stream.write(changed)
    destination.chmod(0o700)


def qualify_public_failclosed_checks(*, private: Path, evidence: Path, admission: dict) -> None:
    """Existing signed resource/preflight/action checks; no original recreation."""
    from uvm.installer.lock import _bounded_file
    state=private/'instance';raw=_bounded_file(state/'instance.json',1024*1024,private=True);info=json.loads(raw)
    if info.get('established')is not True or info['image']!=admission['image_reference']:
        raise RuntimeError('same established reviewed1002 fixture required')
    entry=private/'trusted-offline-entry.sh';environment=trusted_launcher_environment(private/'minimal-host-path',admission)
    paths=set(info['installer_initial_files'])|set(info['local_recovery_inventory'])|{'instance.json','secrets/local-start-admission/admission.json','secrets/local-restore-fence/fence.json'}
    def fingerprints():
        return {name:(digest_bytes(_bounded_file(state/name,1024*1024,private=False)),
            (state/name).lstat().st_dev,(state/name).lstat().st_ino,stat.S_IMODE((state/name).lstat().st_mode))for name in sorted(paths)}
    def observed(name):
        template='{"id":{{json .Id}},"reference":{{json .Config.Image}},"owner":{{json (index .Config.Labels "volt.compose.owner-token")}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"running":{{json .State.Running}},"started":{{json .State.StartedAt}},"networks":{{json .NetworkSettings.Networks}}}'
        row=json.loads(run(name,['docker','inspect',info['project']+'-volt-1','--format',template],evidence).stdout)
        if(row['reference']!=admission['image_reference']or row['owner']!=info['owner_token']
                or row['project']!=info['project']or row['running']is not False):
            raise RuntimeError('exact owned stopped original API required; no mutation authorised')
        return row
    baseline=fingerprints();original=observed('failclosed-original-stopped')
    if set(original['networks'])!={info['project']+'_network'}:raise RuntimeError('original API already has contradictory attachments')
    def intact(name):
        if fingerprints()!=baseline or observed(name)!=original:
            raise RuntimeError('original API/networks/private bytes/inodes/modes changed')
    results=[]
    # Existing wrapper performs independent Q/launcher/fullgraph authentication.
    run('failclosed-initial-original-auth',['sh',str(entry),'verify-cache','--directory',str(state)],evidence,env=environment)
    with initial_resume_private_fault(state=state,retention=private/'unsafe-key-mode-original',case='unsafe-key-mode')as fault:
        result=run('failclosed-private-key-mode',['sh',str(entry),'status','--directory',str(state)],evidence,env=environment,check=False)
        message='local auth configuration, encryption key or bootstrap delivery directory is missing or unsafe'
        if result.returncode!=1 or message not in result.stderr.splitlines():raise RuntimeError('private-mode test missed actual signed instance validator')
        results.append({'case':'private-key-mode','exit':1,'layer':'signed host-validate','exact_line':message,'fault':fault})
    intact('private-mode-restored-stopped')
    for name,command,message in [('unconfirmed-destroy','destroy','volt installer: destroy requires --confirm-project with the exact owned project name'),
            ('unsupported-upgrade','upgrade','volt installer: supported commands are install, start, stop, status, diagnose, logs, setup, account, recovery, and explicit destroy')]:
        selected=entry
        if command=='upgrade':
            selected=private/'trusted-negative-upgrade-entry.sh';unsupported_upgrade_test_entry(entry,selected)
            (evidence/'negative-upgrade-entry-binding.json').write_text(json.dumps({'original_sha256':sha(entry),
                'test_entry_sha256':sha(selected),'change':'ONLY literal upgrade passes closed TEST guard, original full authentication unchanged',
                'scope':'current signedCLI unsupported-action denial ONLY, not upgrade capability'},indent=2))
        result=run('failclosed-'+name,['sh',str(selected),command,'--directory',str(state)],evidence,env=environment,check=False)
        if result.returncode!=1 or message not in result.stderr.splitlines():raise RuntimeError(name+' missed exact signed product boundary')
        intact(name+'-unchanged-stopped');results.append({'case':name,'exit':1,'layer':'signed launcher terminal','exact_line':message})
    # Original launcher/Q/cache are authenticated BEFORE either direct preflight.
    # A synthetic NON-NETWORK scheme is never given to the normal auth wrapper.
    launcher=state.parent/(state.name+'.installer-artifacts')/'originals/package/launcher.sh'
    direct={**environment,'VOLT_OFFLINE':'1'}
    capture=private/'nonnetwork-context-observation';capture.mkdir(mode=0o700);shim=capture/'docker'
    shim.write_text('#!/bin/sh\nset -eu\numask 077\nprintf "%s\\n" attempted >>'+shlex.quote(str(capture/'calls'))+'\nexit 97\n');shim.chmod(0o700)
    invalid={**direct,'PATH':str(capture)+os.pathsep+environment['PATH'],'DOCKER_HOST':'blocked-nonnetwork-context://sentinel'}
    result=run('failclosed-synthetic-nonnetwork-context',['sh',str(launcher),'status','--directory',str(state)],evidence,env=invalid,check=False)
    message='volt installer: remote Docker contexts are unsupported because instance bind paths must exist on this host'
    if result.returncode!=1 or message not in result.stderr.splitlines()or(capture/'calls').exists():
        raise RuntimeError('synthetic context preflight did not reject before ZERO Docker calls')
    intact('nonnetwork-context-unchanged-stopped')
    results.append({'case':'synthetic-nonnetwork-context','exit':1,'layer':'authenticated original signed launcher preflight',
        'exact_line':message,'Docker_calls':0,'scope':'synthetic nonnetwork endpoint observation ONLY, not real remote-engine integration'})
    missing=private/'minimal-path-without-docker';missing.mkdir(mode=0o700)
    for utility in Path(environment['PATH']).iterdir():
        if utility.name=='docker':continue
        if not utility.is_symlink()or not utility.resolve().is_file():raise RuntimeError('minimal utility source differs')
        (missing/utility.name).symlink_to(utility.resolve())
    result=run('failclosed-missing-docker',['sh',str(launcher),'status','--directory',str(state)],evidence,
        env={**direct,'PATH':str(missing)},check=False)
    message='volt installer: required host command is missing: docker'
    if result.returncode!=1 or message not in result.stderr.splitlines():raise RuntimeError('missing Docker test missed signed preflight')
    intact('missing-docker-unchanged-stopped');results.append({'case':'missing-docker','exit':1,
        'layer':'authenticated original signed launcher preflight','exact_line':message,'scope':'minimal PATH dependency absence; no daemon change'})
    test_id=uuid.uuid4().hex;name='volt-easy-delivery-extra-'+test_id
    argv=['docker','network','create','--internal','--driver','bridge','--label','volt.compose.owner-token='+info['owner_token'],
        '--label','volt.delivery.project='+info['project'],'--label','volt.delivery.test='+test_id,name]
    network_id=run('extra-owned-network-create',argv,evidence).stdout.strip()
    if re.fullmatch(r'[0-9a-f]{64}',network_id)is None:raise RuntimeError('created extra-network full identity unavailable')
    result=qualify_retained_extra_network_denial(private=private,evidence=evidence,admission=admission,
        network_id=network_id,test_id=test_id,expected_original=original,expected_fingerprints=baseline)
    results.append(result)
    (evidence/'public-failclosed-outcome.json').write_text(json.dumps({'status':'completed','cases':results,
        'observed_host_files':len(baseline),'original_private_bytes_modes_inodes_unchanged':True,
        'original_API_and_resources_preserved':True,'no_start_or_original_recreation':True,
        'scope':'AMD64 developmentfixture1002; explicit TEST mode/context/PATH/unsupported-action instrumentation; no real remote endpoint, new accounts/SQL or broader upgrade capability'},indent=2))


def qualify_retained_extra_network_denial(*, private: Path, evidence: Path, admission: dict,
        network_id: str, test_id: str, expected_original: dict, expected_fingerprints: dict) -> dict:
    """Continue ONLY a retained explicitly owned test network; no new creation.

    Expected snapshots are comparison evidence, never product authority. All
    actual owner/project/image/fullCID/closed test labels are checked again.
    """
    from uvm.installer.lock import _bounded_file
    state=private/'instance';info=json.loads(_bounded_file(state/'instance.json',1024*1024,private=True))
    if (re.fullmatch(r'[0-9a-f]{64}',network_id)is None or re.fullmatch(r'[0-9a-f]{32}',test_id)is None
            or info['image']!=admission['image_reference']or info.get('established')is not True):
        raise RuntimeError('retained fixed network/instance admission differs')
    name='volt-easy-delivery-extra-'+test_id;entry=private/'trusted-offline-entry.sh'
    environment=trusted_launcher_environment(private/'minimal-host-path',admission)
    original=expected_original;baseline={key:tuple(value)for key,value in expected_fingerprints.items()}
    paths=set(info['installer_initial_files'])|set(info['local_recovery_inventory'])|{'instance.json','secrets/local-start-admission/admission.json','secrets/local-restore-fence/fence.json'}
    def fingerprints():
        return {key:(digest_bytes(_bounded_file(state/key,1024*1024,private=False)),
            (state/key).lstat().st_dev,(state/key).lstat().st_ino,stat.S_IMODE((state/key).lstat().st_mode))for key in sorted(paths)}
    def observed(label):
        template='{"id":{{json .Id}},"reference":{{json .Config.Image}},"owner":{{json (index .Config.Labels "volt.compose.owner-token")}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"running":{{json .State.Running}},"started":{{json .State.StartedAt}},"networks":{{json .NetworkSettings.Networks}}}'
        row=json.loads(run(label,['docker','inspect',info['project']+'-volt-1','--format',template],evidence).stdout)
        if(row['reference']!=admission['image_reference']or row['owner']!=info['owner_token']
                or row['project']!=info['project']or row['running']is not False or row['id']!=original['id']):
            raise RuntimeError('original exact owned API changed; no mutation authorised')
        return row
    def intact(label):
        if fingerprints()!=baseline or observed(label)!=original:raise RuntimeError('retained original resources/private state changed')
    results=[]
    def network_row(label):
        row=json.loads(run(label,['docker','network','inspect',network_id],evidence).stdout)[0]
        guard_extra_qualification_network(row,network_id=network_id,owner=info['owner_token'],
            project=info['project'],test_id=test_id,api_id=original['id'])
        return row
    try:
        network_row('extra-owned-network-before-connect');intact('extra-network-before-original-stopped')
        connected=run('extra-network-connect-stopped',['docker','network','connect',network_id,original['id']],evidence,check=False)
        after=observed('extra-network-after-connect-stopped')
        if connected.returncode!=0:
            if after!=original:raise RuntimeError('failed stopped attach has uncertain side effects')
            results.append({'case':'extra-network','status':'BLOCKED stopped attachment unsupported','exit':connected.returncode,
                'scope':'no actual network-attachment rejection coverage'})
        else:
            if (set(after['networks'])!=set(original['networks'])|{name}
                    or any(after[k]!=original[k]for k in original if k!='networks')
                    or after['networks'][info['project']+'_network']!=original['networks'][info['project']+'_network']):
                raise RuntimeError('actual stopped attachment preconditions differ')
            result=run('failclosed-extra-network-status',['sh',str(entry),'status','--directory',str(state)],evidence,env=environment,check=False)
            message='ValueError: actual network attachment inventory differs'
            if result.returncode!=1 or message not in result.stderr.splitlines():raise RuntimeError('extra network did not reach actual signed attachment rejection')
            if fingerprints()!=baseline or observed('extra-network-after-denial-stopped')!=after:raise RuntimeError('attachment denial changed original state')
            results.append({'case':'extra-network','exit':1,'layer':'signed runtime_mounts actual container validator','exact_line':message})
    finally:
        row=network_row('extra-owned-network-before-cleanup');current=observed('extra-network-cleanup-original-stopped')
        if name in current['networks']:
            disconnected=run('extra-exact-owned-network-disconnect',['docker','network','disconnect',network_id,original['id']],evidence,check=False)
            if disconnected.returncode!=0:
                network_row('extra-owned-network-before-forced-disconnect')
                run('extra-exact-owned-network-forced-disconnect',['docker','network','disconnect','--force',network_id,original['id']],evidence)
        intact('extra-network-original-restored-stopped')
        if network_row('extra-owned-network-empty-before-remove')['Containers']:
            raise RuntimeError('extra network still attached; never remove it')
        run('extra-exact-owned-network-remove',['docker','network','rm',network_id],evidence)
    intact('all-failclosed-checks-original-stopped')
    return results[0]


def network_snapshot_projection(container: dict, volumes: list[dict]) -> dict:
    """TEST projection of EVERY input read by the signed mount validator.

    Mount/volume lists alone are semantically unordered; require uniqueness
    before sorting. Preserve all other values and list ordering exactly.
    """
    mounts=container.get('Mounts')
    if(not isinstance(mounts,list)or len(mounts)>128 or any(not isinstance(m,dict)or not isinstance(m.get('Destination'),str)for m in mounts)
            or len({m['Destination']for m in mounts})!=len(mounts)
            or not isinstance(volumes,list)or len(volumes)!=3 or len({v.get('Name')for v in volumes})!=3):
        raise RuntimeError('private observed mount/volume snapshot is malformed or ambiguous')
    return {'Image':container.get('Image'),'ImageManifestDescriptor':container.get('ImageManifestDescriptor'),
        'Labels':container.get('Config',{}).get('Labels'),'Mounts':sorted(mounts,key=lambda m:m['Destination']),
        'NetworkMode':container.get('HostConfig',{}).get('NetworkMode'),
        'Networks':container.get('NetworkSettings',{}).get('Networks'),
        'State':container.get('State'),'Id':container.get('Id'),
        'volumes':sorted(volumes,key=lambda v:v['Name'])}


def qualify_network_causal_replay(*, private: Path, evidence: Path, admission: dict,
        expected_fingerprints: dict) -> None:
    """ONE guarded replay: public generic denial + separate signed cause proof."""
    import resource
    from uvm.installer.lock import _bounded_file
    state=private/'instance';info=json.loads(_bounded_file(state/'instance.json',1024*1024,private=True))
    entry=private/'trusted-offline-entry.sh';environment=trusted_launcher_environment(private/'minimal-host-path',admission)
    if info['image']!=admission['image_reference']or info.get('established')is not True:raise RuntimeError('same admitted established fixture required')
    expected={name:tuple(value)for name,value in expected_fingerprints.items()}
    def fingerprints():
        return {name:(digest_bytes(_bounded_file(state/name,1024*1024,private=False)),(state/name).stat().st_dev,
            (state/name).stat().st_ino,stat.S_IMODE((state/name).stat().st_mode))for name in expected}
    if fingerprints()!=expected:raise RuntimeError('original private inputs changed before replay')
    run('network-replay-fresh-external-auth',['sh',str(entry),'verify-cache','--directory',str(state)],evidence,env=environment)
    snapshots=private/'network-causal-replay-snapshots';snapshots.mkdir(mode=0o700)
    def capture(label, fault):
        directory=snapshots/label;directory.mkdir(mode=0o700);binding={}
        for name,argv in [('container',['docker','inspect',info['project']+'-volt-1']),
                ('volumes',['docker','volume','inspect',*[info['project']+'_'+s for s in ('postgres','media','state')]])]:
            destination=directory/(name+'.json');errors=directory/(name+'.stderr')
            (evidence/(label+'-'+name+'-capture.json')).write_text(json.dumps({'argv':argv,'private_capture':True,
                'max_each_stream_bytes':2*1024*1024,'timeout_seconds':20,'recorded_before_invocation':True},indent=2))
            with destination.open('xb')as stdout,errors.open('xb')as stderr:
                destination.chmod(0o600);errors.chmod(0o600)
                try:
                    result=subprocess.run(argv,stdout=stdout,stderr=stderr,env=environment,timeout=20,
                        preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024*1024,2*1024*1024)))
                    code=result.returncode
                except subprocess.TimeoutExpired:code=124
                stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
            binding[name]={'exit':code,'sha256':sha(destination),'bytes':destination.stat().st_size,
                'stderr_sha256':sha(errors),'stderr_bytes':errors.stat().st_size,'private_raw_retained':True}
            (evidence/(label+'-private-capture-binding.json')).write_text(json.dumps(binding,indent=2))
            if code!=0:raise RuntimeError('bounded private Docker observation failed; no snapshot credit')
        rows=json.loads(_bounded_file(directory/'container.json',2*1024*1024,private=True));volumes=json.loads(_bounded_file(directory/'volumes.json',2*1024*1024,private=True))
        if not isinstance(rows,list)or len(rows)!=1:raise RuntimeError('one actual original API required')
        row=rows[0]
        if(row['Config']['Image']!=admission['image_reference']or row['Config']['Labels'].get('volt.compose.owner-token')!=info['owner_token']
                or row['Config']['Labels'].get('com.docker.compose.project')!=info['project']or row['State']['Running']is not False):
            raise RuntimeError('actual owned API must remain stopped')
        return directory,row,volumes
    original_dir,original,original_volumes=capture('baseline',False)
    original_projection=network_snapshot_projection(original,original_volumes)
    if set(original_projection['Networks'])!={info['project']+'_network'}:raise RuntimeError('baseline already has extra attachments')
    code="""import json,sys
from pathlib import Path
from uvm.installer.runtime_mounts import validate
rows=json.loads(Path('/input/container.json').read_text());volumes=json.loads(Path('/input/volumes.json').read_text());info=json.loads(Path('/instance/instance.json').read_text())
try: validate(Path('/instance'),Path(sys.argv[1]),info,rows[0],volumes)
except ValueError as exc:
 if str(exc)=='actual network attachment inventory differs':print('component_actual_mounts=network_attachment_mismatch');raise SystemExit(2)
 print('component_actual_mounts=unexpected_rejection');raise SystemExit(3)
print('component_actual_mounts=admitted')
"""
    def component(label,directory):
        return run(label,['docker','run','--rm','--platform',admission['platform'],'--pull=never','--network','none','--read-only',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
            '--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
            '--tmpfs','/app/media:rw,noexec,nosuid,nodev,size=1m','--tmpfs','/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m',
            '--user',f'{os.getuid()}:{os.getgid()}',
            '--mount',f'type=bind,src={state},dst=/instance,readonly','--mount',f'type=bind,src={directory},dst=/input,readonly',
            '--entrypoint','/opt/uvm/venv/bin/python',admission['image_reference'],'-c',code,str(state)],evidence,check=False)
    valid=component('signed-native-original-snapshot-component',original_dir)
    if valid.returncode!=0 or valid.stdout!='component_actual_mounts=admitted\n':raise RuntimeError('baseline signed-native validator did not admit exact observed inputs')
    test_id=uuid.uuid4().hex;name='volt-easy-delivery-extra-'+test_id
    network_id=run('causal-extra-owned-network-create',['docker','network','create','--internal','--driver','bridge',
        '--label','volt.compose.owner-token='+info['owner_token'],'--label','volt.delivery.project='+info['project'],
        '--label','volt.delivery.test='+test_id,name],evidence).stdout.strip()
    def network(label):
        row=json.loads(run(label,['docker','network','inspect',network_id],evidence).stdout)[0]
        guard_extra_qualification_network(row,network_id=network_id,owner=info['owner_token'],project=info['project'],test_id=test_id,api_id=original['Id']);return row
    try:
        network('causal-extra-network-before-connect')
        run('causal-extra-connect-stopped',['docker','network','connect',network_id,original['Id']],evidence)
        fault_dir,fault,fault_volumes=capture('fault',True)
        projection=network_snapshot_projection(fault,fault_volumes)
        without_network={k:v for k,v in projection.items()if k!='Networks'}
        if(without_network!={k:v for k,v in original_projection.items()if k!='Networks'}
                or set(projection['Networks'])!=set(original_projection['Networks'])|{name}
                or any(projection['Networks'][key]!=value for key,value in original_projection['Networks'].items())):
            raise RuntimeError('observed validator inputs changed beyond one exact network attachment')
        (evidence/'actual-snapshot-redacted-difference.json').write_text(json.dumps({'field':'NetworkSettings.Networks',
            'added_attachment_count':1,'removed_attachment_count':0,'original_entries_exact':True,
            'ALL_other_validator_inputs_exact':True,'mount_destinations_unique_and_only_mountlist_sorted':True,
            'volume_names_unique_and_only_volumelist_sorted':True,'environment_and_private_values_excluded':True,
            'snapshot_scope':'actual bounded private snapshots captured BEFORE public status/removal'},indent=2))
        causal=component('signed-native-fault-snapshot-component',fault_dir)
        if causal.returncode!=2 or causal.stdout!='component_actual_mounts=network_attachment_mismatch\n':raise RuntimeError('same actual snapshot did not yield exact signed-native component cause')
        denied=run('causal-public-extra-network-status',['sh',str(entry),'status','--directory',str(state)],evidence,env=environment,check=False)
        expected_lines=['actual API container custody admission failed','volt installer: actual API mounts violate host custody exclusions']
        if denied.returncode!=1 or any(line not in denied.stderr.splitlines()for line in expected_lines):raise RuntimeError('public generic custody boundary not reached')
        if fingerprints()!=expected:raise RuntimeError('public custody denial changed observed original private inputs')
        denied_dir,denied_container,denied_volumes=capture('after-public',True)
        if network_snapshot_projection(denied_container,denied_volumes)!=projection:
            raise RuntimeError('public denial changed actual faulted validator inputs')
    finally:
        row=network('causal-extra-network-before-cleanup')
        if original['Id']in row['Containers']or name in json.loads(run('causal-extra-network-actual-attachments',['docker','inspect',original['Id'],'--format','{{json .NetworkSettings.Networks}}'],evidence).stdout):
            run('causal-extra-exact-disconnect',['docker','network','disconnect',network_id,original['Id']],evidence)
        if network('causal-extra-network-empty-before-remove')['Containers']:raise RuntimeError('injected network still has attachments; no removal')
        run('causal-extra-exact-remove',['docker','network','rm',network_id],evidence)
    restored_dir,restored,restored_volumes=capture('restored',False)
    if network_snapshot_projection(restored,restored_volumes)!=original_projection or fingerprints()!=expected:
        raise RuntimeError('original private/actual API state was not restored')
    run('restored-public-status-after-network',['sh',str(entry),'status','--directory',str(state)],evidence,env=environment)
    if fingerprints()!=expected:raise RuntimeError('restored public status changed original private inputs')
    (evidence/'network-causal-replay-outcome.json').write_text(json.dumps({'status':'passed','public_status_exit':1,
        'public_failure_layer':'GENERIC actual container custody admission ONLY; no per-field public diagnostic claimed',
        'separate_signed_native_component_exit':2,'component_reason':'actual network attachment inventory differs',
        'same_actual_private_snapshot':True,'all_other_validator_inputs_unchanged':True,'restored_public_status_exit':0,
        'observed_host_fingerprints_unchanged':len(expected),'API_original_identity_and_StartedAt_unchanged':True,
        'injected_network_disconnected_removed':True,'private_snapshot_max_each_stream_bytes':2*1024*1024,
        'scope':'ONE focused extra-attachment replay; public generic denial + separately labelled signed-native readonly function cause; no product output/authority change'},indent=2))


def volume_fault_observer_environment(*, capture: Path, state: Path, environment: dict,
        admission: dict, case: str, device: Path | None) -> dict:
    """Linux TEST producer race; ONE exact absent-volume create, original result."""
    if case not in ('foreign-owner','bind-options'):raise ValueError('only fixed producer volume faults supported')
    capture.mkdir(mode=0o700);real=Path(shutil.which('docker',path=environment['PATH'])).resolve(strict=True)
    stat_exe=Path(shutil.which('stat')).resolve(strict=True);test_id=uuid.uuid4().hex
    device_meta='';device_path=''
    if case=='bind-options':
        if device is None or device.is_symlink()or device.resolve()!=device or list(device.iterdir()):raise RuntimeError('fresh canonical empty test device required')
        info=device.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError('test bind device custody differs')
        cache=state.parent/(state.name+'.installer-artifacts')
        if any(device==p or device in p.parents or p in device.parents for p in (state,cache)):raise RuntimeError('test device overlaps instance/cache authority')
        device_path=str(device);device_meta=f'{info.st_dev}:{info.st_ino}:{info.st_uid}:{info.st_gid}:700'
    values={'REAL_DOCKER':str(real),'STAT_EXE':str(stat_exe),'CAPTURE':str(capture),'EXPECTED_STATE':str(state),
        'IMAGE_REF':admission['image_reference'],'PLATFORM':admission['platform'],'EXPECTED_USER':f'{os.getuid()}:{os.getgid()}',
        'EXPECTED_UID':str(os.getuid()),'PREFIX':'volt-easy-delivery','TEST_CASE':case,'TEST_ID':test_id,
        'FOREIGN_OWNER':secrets.token_hex(32),'DEVICE':device_path,'DEVICE_META':device_meta,
        'BIND_OPTIONS':json.dumps({'device':device_path,'o':'bind','type':'none'},sort_keys=True,separators=(',',':'))}
    script='#!/bin/sh\nset -eu\numask 077\n'+''.join(k+'='+shlex.quote(v)+'\n'for k,v in values.items())+r'''
pass_original() { exec "$REAL_DOCKER" "$@"; }
guard_session() {
 [ -f "$CAPTURE/caller.pid" ] && [ ! -L "$CAPTURE/caller.pid" ] || exit 76
 IFS= read -r caller <"$CAPTURE/caller.pid"
 case "$caller" in ''|*[!0-9]*) exit 76 ;; esac
 read -r actual comm state parent group session rest <"/proc/$caller/stat"
 [ "$actual|$group|$session" = "$caller|$caller|$caller" ] || exit 76
 ancestor=$PPID; steps=0
 while [ "$ancestor" != "$caller" ] && [ "$steps" -lt 8 ]; do
  read -r actual comm state parent group session rest <"/proc/$ancestor/stat"
  [ "$group|$session" = "$caller|$caller" ] || exit 76
  ancestor=$parent; steps=$((steps+1))
 done
 [ "$ancestor" = "$caller" ] || exit 76
}
owned_name() {
 case "$1" in "$PREFIX-"????????????_postgres) ;; *) return 1 ;; esac
 project=${1%_postgres}; suffix=${project#"$PREFIX-"}
 case "$suffix" in *[!0-9a-f]*) return 1 ;; esac
}
original_result() {
 label=$1; shift; set +e
 (ulimit -f 64; "$REAL_DOCKER" "$@") >"$CAPTURE/$label.stdout" 2>"$CAPTURE/$label.stderr"
 result=$?; set -e; printf '%s\n' "$result" >"$CAPTURE/$label.exit"
 cat "$CAPTURE/$label.stdout"; cat "$CAPTURE/$label.stderr" >&2
 return "$result"
}
if [ "$#" -eq 3 ] && [ "$1|$2" = 'volume|inspect' ] && owned_name "$3" && [ ! -e "$CAPTURE/injected" ]; then
 guard_session
 set +e
 (ulimit -f 64; "$REAL_DOCKER" "$@") >"$CAPTURE/absence.stdout" 2>"$CAPTURE/absence.stderr"
 result=$?; set -e; printf '%s\n' "$result" >"$CAPTURE/absence.exit"
 if [ "$result" -eq 1 ] && [ "$(cat "$CAPTURE/absence.stdout")" = '[]' ] \
   && [ "$(cat "$CAPTURE/absence.stderr")" = "Error response from daemon: get $3: no such volume" ]; then
  printf '%s\n' "$3" >"$CAPTURE/absence.name"
 fi
 cat "$CAPTURE/absence.stdout";cat "$CAPTURE/absence.stderr" >&2;exit "$result"
fi
if [ "$#" -eq 9 ] && [ "$1|$2|$3|$5|$7" = 'volume|create|--label|--label|--label' ] && owned_name "$9"; then
 guard_session
 [ ! -e "$CAPTURE/injected" ] || exit 76
 name=$9; project=${name%_postgres}; owner=${4#volt.compose.owner-token=}
 case "$owner" in ''|*[!0-9a-f]*) exit 76 ;; esac
 [ "${#owner}" -eq 64 ] && [ "$4" = "volt.compose.owner-token=$owner" ] || exit 76
 [ "$project" = "$PREFIX-$(printf '%s' "$owner" | cut -c 1-12)" ] || exit 76
 [ "$6|$8" = "com.docker.compose.project=$project|com.docker.compose.volume=postgres" ] || exit 76
 [ "$(cat "$CAPTURE/absence.name")" = "$name" ] && [ "$(cat "$CAPTURE/absence.exit")" = 1 ] || exit 76
 [ -d "$EXPECTED_STATE/compose" ] && [ ! -e "$EXPECTED_STATE/instance.json" ] && [ ! -e "$EXPECTED_STATE/secrets" ] || exit 76
 [ "$("$STAT_EXE" -c '%u:%a' "$EXPECTED_STATE")" = "$EXPECTED_UID:700" ] || exit 76
 set +e
 "$REAL_DOCKER" volume inspect "$name" >"$CAPTURE/recheck.stdout" 2>"$CAPTURE/recheck.stderr"
 absent=$?;set -e
 [ "$absent" -eq 1 ] && [ "$(cat "$CAPTURE/recheck.stdout")" = '[]' ] \
  && [ "$(cat "$CAPTURE/recheck.stderr")" = "Error response from daemon: get $name: no such volume" ] || exit 76
 printf '%s\n' "$@" >"$CAPTURE/original-create.argv-lines"
 printf '%s\n' "$owner" >"$CAPTURE/original-owner";printf '%s\n' "$project" >"$CAPTURE/project"
 injected_owner=$owner
 if [ "$TEST_CASE" = foreign-owner ]; then
  [ "$FOREIGN_OWNER" != "$owner" ] || exit 76;injected_owner=$FOREIGN_OWNER
 else
  [ -d "$DEVICE" ] && [ ! -L "$DEVICE" ] && [ "$(cd -P "$DEVICE" && pwd -P)" = "$DEVICE" ] || exit 76
  [ "$("$STAT_EXE" -c '%d:%i:%u:%g:%a' "$DEVICE")" = "$DEVICE_META" ] || exit 76
  for child in "$DEVICE"/* "$DEVICE"/.[!.]* "$DEVICE"/..?*; do
   if [ -e "$child" ] || [ -L "$child" ]; then exit 76;fi
  done
 fi
 if [ "$TEST_CASE" = foreign-owner ]; then
  "$REAL_DOCKER" volume create --label "volt.compose.owner-token=$injected_owner" --label "$6" --label "$8" \
    --label "volt.delivery.test-owner=$TEST_ID" --label "volt.delivery.case=$TEST_CASE" "$name" \
    >"$CAPTURE/injection.stdout" 2>"$CAPTURE/injection.stderr" || exit 76
 else
  "$REAL_DOCKER" volume create --label "volt.compose.owner-token=$injected_owner" --label "$6" --label "$8" \
    --label "volt.delivery.test-owner=$TEST_ID" --label "volt.delivery.case=$TEST_CASE" \
    --opt type=none --opt o=bind --opt "device=$DEVICE" "$name" \
    >"$CAPTURE/injection.stdout" 2>"$CAPTURE/injection.stderr" || exit 76
 fi
 (ulimit -f 64; "$REAL_DOCKER" volume inspect "$name") >"$CAPTURE/injected-volume.json" 2>"$CAPTURE/injected-inspect.stderr" || exit 76
 identity=$("$REAL_DOCKER" volume inspect "$name" --format '{{.Name}}|{{.Driver}}|{{index .Labels "volt.compose.owner-token"}}|{{index .Labels "com.docker.compose.project"}}|{{index .Labels "com.docker.compose.volume"}}|{{index .Labels "volt.delivery.test-owner"}}|{{index .Labels "volt.delivery.case"}}|{{json .Options}}')
 base="$name|local|$injected_owner|$project|postgres|$TEST_ID|$TEST_CASE"
 if [ "$TEST_CASE" = foreign-owner ];then
  [ "$identity" = "$base|{}" ] || [ "$identity" = "$base|null" ] || exit 76
 else [ "$identity" = "$base|$BIND_OPTIONS" ] || exit 76;fi
 printf '%s\n' "$identity" >"$CAPTURE/injected-identity";printf '%s\n' "$TEST_ID" >"$CAPTURE/injected"
 set +e;original_result original-create "$@";result=$?;set -e;exit "$result"
fi
if [ "$#" -gt 5 ] && [ "$1" = run ] && [ -f "$CAPTURE/injected" ]; then
 t0=;t1=;t2=;t3=;t4=;request=;seen_state=0;seen_image=0;previous=;entry=;network=;user=;platform=;holder=;detached=0;readonly=0;owner_labels=0;project_labels=0;roles=0
 expected_owner=$(cat "$CAPTURE/original-owner");expected_project=$(cat "$CAPTURE/project")
 for argument do
  case "$previous" in --entrypoint) entry=$argument ;; --network) network=$argument ;; --user) user=$argument ;; --platform) platform=$argument ;; --name) holder=$argument ;; esac
  case "$argument" in -d) detached=$((detached+1)) ;; --read-only) readonly=$((readonly+1)) ;; --privileged|--privileged=*) exit 76 ;; esac
  [ "$argument" != "volt.compose.owner-token=$expected_owner" ] || owner_labels=$((owner_labels+1))
  [ "$argument" != "volt.compose.project=$expected_project" ] || project_labels=$((project_labels+1))
  [ "$argument" != org.volt.compose-install.role=host-lifecycle-lock ] || roles=$((roles+1))
  previous=$argument
  t4=$t3;t3=$t2;t2=$t1;t1=$t0;t0=$argument
  [ "$argument" != "$IMAGE_REF" ] || seen_image=$((seen_image+1))
  [ "$argument" != "type=bind,src=$EXPECTED_STATE,dst=/state" ] || seen_state=$((seen_state+1))
  case "$argument" in type=bind,src=/tmp/volt-installer.????????/runtime-init-request.json,dst=/run/volt-initialization/request.json,readonly)
   [ -z "$request" ] || exit 76;request=${argument#type=bind,src=};request=${request%,dst=/run/volt-initialization/request.json,readonly} ;;
  esac
 done
 if [ "$t0" = --initialize-local ];then
  guard_session
  [ "$t4|$t3|$t2|$t1|$t0" = "$IMAGE_REF|-m|uvm.installer.lock|/state/.install.lock|--initialize-local" ] || exit 76
  [ "$seen_state|$seen_image|$detached|$readonly|$owner_labels|$project_labels|$roles" = '1|1|1|1|1|1|1' ] || exit 76
  [ "$entry|$network|$user|$platform|$holder" = "/opt/uvm/venv/bin/python|none|$EXPECTED_USER|$PLATFORM|volt-lock-$expected_project-$caller" ] || exit 76
  [ -n "$request" ] && [ ! -L "$request" ] || exit 76
  [ "$("$STAT_EXE" -c '%u:%a' "$request")" = "$EXPECTED_UID:600" ] || exit 76
  size=$("$STAT_EXE" -c '%s' "$request");[ "$size" -le 65536 ] || exit 76
  dd if="$request" of="$CAPTURE/runtime-init-request.json" bs=1 count=65537 2>"$CAPTURE/request-copy.stderr"
  chmod 600 "$CAPTURE/runtime-init-request.json";printf '%s\n' "$@" >"$CAPTURE/actual-initial-owner.argv-lines"
 fi
fi
pass_original "$@"
'''
    destination=capture/'docker';destination.write_text(script);destination.chmod(0o700)
    binding={'script_sha256':sha(destination),'real_docker':str(real),'real_docker_sha256':sha(real),
        'stat_observer':str(stat_exe),'stat_observer_sha256':sha(stat_exe),'case':case,'test_id':test_id,
        'device':device_path,'device_identity':device_meta,'expected_state':str(state),'expected_image':admission['image_reference'],
        'scope':'POSIX/Linux TEST producer race, stat/proc observation explicit; original commands/results forwarded; not unmodified-Docker certification'}
    (capture/'observer-binding.json').write_text(json.dumps(binding,indent=2));return {**environment,'PATH':str(capture)+os.pathsep+environment['PATH'],'VOLUME_CAPTURE':str(capture)}


def qualify_initial_volume_fault(*, bundle: Path, fixture: Path, image_id: str, source_revision: str,
        source_snapshot: str, platform: str, private: Path, evidence: Path, case: str) -> None:
    """One legitimate fresh public install + one absent-volume TEST race."""
    from uvm.installer.lock import _bounded_file
    import resource
    admission=validate_admission_fixture(fixture,image_id=image_id,source_snapshot=source_snapshot,
        source_commit=source_revision,platform=platform,bundle=bundle,version='0.1.0-rc.4',evidence=evidence)
    extracted=private/'extracted';extracted.mkdir(mode=0o700);shutil.unpack_archive(str(bundle),extracted,'gztar')
    package=extracted/'volt-compose-0.1.0-rc.4';outer=private/'signed-package';outer.mkdir(mode=0o700)
    launcher=outer/'launcher.sh';render_fixture_launcher(package/'launcher.sh',launcher,fixture)
    shutil.copyfile(bundle,outer/'installer.bundle.tar.gz')
    for name in ('installer.bundle.sigstore.json','launcher.sigstore.json'):shutil.copyfile(fixture/name,outer/name)
    for path in outer.iterdir():path.chmod(0o600)
    public=evidence/'fixture-trust-public'
    run('volume-fault-original-launcher-auth',['docker','run','--rm','--platform',platform,'--pull=never','--network','host','--read-only',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--user',f'{os.getuid()}:{os.getgid()}',
        '--mount',f'type=bind,src={public},dst=/fixture,readonly','--mount',f'type=bind,src={launcher},dst=/launcher,readonly',COSIGN_IMAGE,
        'verify-blob','--key','/fixture/fixture.pub','--trusted-root','/fixture/trusted-root.json','--bundle','/fixture/launcher.sigstore.json','/launcher'],evidence)
    environment=trusted_launcher_environment(private/'minimal-host-path',admission);state=private/'instance';capture=private/'volume-observer'
    device=None
    if case=='bind-options':device=private/'bind-device';device.mkdir(mode=0o700)
    observed=volume_fault_observer_environment(capture=capture,state=state,environment=environment,admission=admission,case=case,device=device)
    command=['sh','-c','umask 077; printf "%s\\n" "$$" >"$VOLUME_CAPTURE/caller.pid"; exec sh "$0" "$@"',str(launcher),
        'install','--directory',str(state),'--port','46180','--project-prefix','volt-easy-delivery']
    (evidence/'retained-fixture.json').write_text(json.dumps({'private':str(private),'state':str(state),'case':case,'admission':admission,'retained':True},indent=2))
    (evidence/'volume-fault-install-invocation.json').write_text(json.dumps({'argv':command,'cwd':str(ROOT),'environment_PATH':observed['PATH'],'start_new_session':True,'before_invocation':True},indent=2))
    with(evidence/'volume-fault-install.stdout').open('x')as stdout,(evidence/'volume-fault-install.stderr').open('x')as stderr:
        caller=subprocess.Popen(command,cwd=ROOT,env=observed,stdout=stdout,stderr=stderr,start_new_session=True,
            preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024*1024,2*1024*1024)))
        (capture/'registered-caller.json').write_text(json.dumps({'pid':caller.pid,'pgid':os.getpgid(caller.pid),'sid':os.getsid(caller.pid)}))
        try:code=caller.wait(timeout=300)
        except subprocess.TimeoutExpired:
            if os.getpgid(caller.pid)!=caller.pid or os.getsid(caller.pid)!=caller.pid:raise RuntimeError('case caller session differs; no signal authorised')
            os.killpg(caller.pid,signal.SIGTERM)
            try:caller.wait(timeout=30)
            except subprocess.TimeoutExpired:os.killpg(caller.pid,signal.SIGKILL);caller.wait()
            code=124
    (evidence/'volume-fault-install.exit').write_text(str(code))
    if not(capture/'injected').exists():raise RuntimeError('fixed volume race did not inject; preserve precise failed instrumentation layer')
    project=(capture/'project').read_text().strip();owner=(capture/'original-owner').read_text().strip()
    injected=json.loads(_bounded_file(capture/'injected-volume.json',65536,private=True))[0]
    current=json.loads(run('fault-volume-after-public-failure',['docker','volume','inspect',injected['Name']],evidence).stdout)[0]
    if current!=injected:raise RuntimeError('injected volume metadata changed; no repair/adoption or comparison credit')
    api=run('volume-fault-api-absence',['docker','container','inspect',project+'-volt-1','--format',
        '{"id":{{json .Id}},"image":{{json .Config.Image}},"owner":{{json (index .Config.Labels "volt.compose.owner-token")}},"project":{{json (index .Config.Labels "com.docker.compose.project")}}}'],evidence,check=False)
    if api.returncode==0:
        row=json.loads(api.stdout)
        if row['image']==admission['image_reference']and row['owner']==owner and row['project']==project:
            run('unexpected-exact-owned-new-API-stop',['docker','stop','--time','10',row['id']],evidence,check=False)
        raise RuntimeError('unexpected API creation; comparison NOT credited, retain exact owned fixture')
    if 'no such'not in api.stderr.lower():raise RuntimeError('API absence unproved')
    request_present=(capture/'runtime-init-request.json').exists();journal_present=(state/'instance.json').exists()
    if code==1 and int((capture/'original-create.exit').read_text())!=0:
        (evidence/'volume-fault-outcome.json').write_text(json.dumps({'status':'prior_engine_volume_create_rejection','case':case,
            'product_owner_or_options_comparison_credit':False,'closed_request_present':request_present,'journal_present':journal_present,
            'actual_layer':'original Docker volume create failed before later signed comparison; no waiver','retained_fixture':str(private)},indent=2));return
    expected='volt installer: postgres volume ownership does not match this instance'if case=='foreign-owner'else'volt installer: owned volume uses an unapproved host bind driver'
    if code!=1 or expected not in(evidence/'volume-fault-install.stderr').read_text().splitlines():raise RuntimeError('volume fault did not reach exact signed owner/options boundary')
    request=_bounded_file(capture/'runtime-init-request.json',65536,private=True);document=json.loads(request);journal_raw=_bounded_file(state/'instance.json',1024*1024,private=True);info=json.loads(journal_raw)
    if(document['arguments']['project']!=project or document['arguments']['owner_token']!=owner
            or document['arguments']['admitted_image_id']!=admission['image_id']or info['owner_token']!=owner
            or info['project']!=project or info['installer_initial_request_sha256']!=digest_bytes(request)):
        raise RuntimeError('actual legitimate closed request/initial identity binding differs')
    if device and(list(device.iterdir())or device.is_symlink()):raise RuntimeError('fresh bind test device changed')
    (evidence/'volume-fault-outcome.json').write_text(json.dumps({'status':'passed','case':case,'exact_signed_diagnostic':expected,
        'original_create_exit':int((capture/'original-create.exit').read_text()),'public_install_exit':code,'API_created':False,
        'request_sha256':digest_bytes(request),'journal_sha256':digest_bytes(journal_raw),'installation_id':info['installation_id'],
        'legitimate_initial_keys_already_created':True,'prekey_denial_claimed':False,'initial_private_files':info['installer_initial_files'],
        'injected_metadata_unchanged':True,'retained_fixture':str(private),'scope':'separate legitimate public initial intent with ONE explicitly labelled absent-volume TEST race; no original replacement/repair/adoption/account/SQL'},indent=2))


def occupied_port_daemon_error(text: str) -> bool:
    """Fixed observed endpoint + daemon bind semantics, never generic failure."""
    for line in text.splitlines():
        value=line.lower()
        if ('127.0.0.1:46180'in value and any(reason in value for reason in
                ('address already in use','port is already allocated','ports are not available'))
                and any(context in value for context in ('failed to set up container networking',
                    'failed programming external connectivity','failed to bind host port','ports are not available',
                    'bind for 127.0.0.1:46180 failed','listen tcp 127.0.0.1:46180'))):return True
    return False


def occupied_port_binder_program() -> str:
    return "import os,socket,json,sys,time,signal\nfrom pathlib import Path\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('127.0.0.1',46180));s.listen(1)\nvalue={'pid':os.getpid(),'start':Path('/proc/self/stat').read_text().split()[21],'netns':os.readlink('/proc/self/ns/net'),'fd':s.fileno(),'inode':os.fstat(s.fileno()).st_ino,'endpoint':list(s.getsockname()),'reuseaddr':s.getsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR),'reuseport':s.getsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT)}\np=Path(sys.argv[1]);temporary=p.with_suffix('.temporary');fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(fd,'w')as f:json.dump(value,f);f.flush();os.fsync(f.fileno())\nos.rename(temporary,p)\ndef stop(signum,frame):s.close();raise SystemExit(0)\nsignal.signal(signal.SIGTERM,stop)\nend=time.monotonic()+900\nwhile time.monotonic()<end:time.sleep(1)\ns.close()\n"


def qualify_initial_occupied_port(*, bundle: Path, fixture: Path, image_id: str, source_revision: str,
        source_snapshot: str, platform: str, private: Path, evidence: Path) -> None:
    """One held exclusive host socket; prove Docker publishing conflict FIRST.

    If Desktop does not expose a matching daemon bind failure, no public install
    runs and no namespace-sharing or product port-denial credit is claimed.
    """
    import errno
    import socket
    import resource
    from uvm.installer.lock import _bounded_file
    admission=validate_admission_fixture(fixture,image_id=image_id,source_snapshot=source_snapshot,
        source_commit=source_revision,platform=platform,bundle=bundle,version='0.1.0-rc.4',evidence=evidence)
    extracted=private/'extracted';extracted.mkdir(mode=0o700);shutil.unpack_archive(str(bundle),extracted,'gztar')
    package=extracted/'volt-compose-0.1.0-rc.4';outer=private/'signed-package';outer.mkdir(mode=0o700)
    launcher=outer/'launcher.sh';render_fixture_launcher(package/'launcher.sh',launcher,fixture)
    shutil.copyfile(bundle,outer/'installer.bundle.tar.gz')
    for name in ('installer.bundle.sigstore.json','launcher.sigstore.json'):shutil.copyfile(fixture/name,outer/name)
    for path in outer.iterdir():path.chmod(0o600)
    public=evidence/'fixture-trust-public'
    run('occupied-original-launcher-auth',['docker','run','--rm','--platform',platform,'--pull=never','--network','host','--read-only',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--user',f'{os.getuid()}:{os.getgid()}',
        '--mount',f'type=bind,src={public},dst=/fixture,readonly','--mount',f'type=bind,src={launcher},dst=/launcher,readonly',COSIGN_IMAGE,
        'verify-blob','--key','/fixture/fixture.pub','--trusted-root','/fixture/trusted-root.json','--bundle','/fixture/launcher.sigstore.json','/launcher'],evidence)
    environment=trusted_launcher_environment(private/'minimal-host-path',admission);state=private/'instance'
    (evidence/'retained-fixture.json').write_text(json.dumps({'private':str(private),'state':str(state),'admission':admission,
        'scope':'occupied-port CASE; no installation state unless same-host publisher conflict proven'},indent=2))
    record=private/'binder.json';program=occupied_port_binder_program();compile(program,'<fixed-binder>','exec')
    command=[sys.executable,'-c',program,str(record)]
    (evidence/'binder-invocation.json').write_text(json.dumps({'argv':command,'before_invocation':True,'start_new_session':True,
        'socket':'exclusive127.0.0.1:46180/TCP, no reuse, no accept/read/HTTP route','program_sha256':digest_bytes(program.encode())},indent=2))
    with(private/'binder.stdout').open('x')as stdout,(private/'binder.stderr').open('x')as stderr:
        binder=subprocess.Popen(command,stdout=stdout,stderr=stderr,start_new_session=True)
    try:
        deadline=time.monotonic()+10
        while not record.exists()and time.monotonic()<deadline and binder.poll()is None:time.sleep(.01)
        if not record.exists():raise RuntimeError('owned exclusive binder did not start; no occupied-port attribution')
        bound=json.loads(_bounded_file(record,16384,private=True))
        def held(label):
            if(binder.poll()is not None or bound['pid']!=binder.pid or os.getpgid(binder.pid)!=binder.pid or os.getsid(binder.pid)!=binder.pid
                    or Path(f'/proc/{binder.pid}/stat').read_text().split()[21]!=bound['start']
                    or os.readlink(f'/proc/{binder.pid}/fd/{bound["fd"]}')!=f'socket:[{bound["inode"]}]'
                    or os.readlink(f'/proc/{binder.pid}/ns/net')!=bound['netns']
                    or bound['endpoint']!=['127.0.0.1',46180]or bound['reuseaddr']!=0 or bound['reuseport']!=0):
                raise RuntimeError('registered binder PID/start/socket identity changed; no port credit')
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as check:
                try:check.bind(('127.0.0.1',46180))
                except OSError as exc:
                    if exc.errno!=errno.EADDRINUSE:raise
                else:raise RuntimeError('registered binder is not exclusive in controller host namespace')
            (evidence/(label+'.json')).write_text(json.dumps({'PID':binder.pid,'start':bound['start'],'netns':bound['netns'],
                'socket_inode':bound['inode'],'endpoint':bound['endpoint'],'reuseaddr':0,'reuseport':0,'second_host_bind_errno':errno.EADDRINUSE},indent=2))
        test_id=uuid.uuid4().hex;test_owner=secrets.token_hex(32);test_project='volt-port-proof-'+test_id[:12]
        network_id='';probe_id='';sharing=False
        held('exclusive-binder-before-Docker-probe')
        network_id=run('port-proof-internal-network-create',['docker','network','create','--internal','--driver','bridge',
            '--label','volt.compose.owner-token='+test_owner,'--label','volt.delivery.project='+test_project,
            '--label','volt.delivery.test='+test_id,'volt-easy-delivery-extra-'+test_id],evidence).stdout.strip()
        probe_name='volt-easy-delivery-port-proof-'+test_id
        args=['docker','create','--platform',platform,'--pull=never','--name',probe_name,'--network',network_id,
            '--label','volt.delivery.test-owner='+test_id,'--label','volt.delivery.role=occupied-port-namespace-proof',
            '--publish','127.0.0.1:46180:8000','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--tmpfs','/tmp:rw,noexec,nosuid,size=8m','--tmpfs','/app/media:rw,noexec,nosuid,nodev,size=1m',
            '--tmpfs','/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
            '--user',f'{os.getuid()}:{os.getgid()}','--entrypoint','/opt/uvm/venv/bin/python',admission['image_reference'],'-c','import time;time.sleep(90)']
        probe_id=run('port-proof-container-create',args,evidence).stdout.strip()
        if re.fullmatch(r'[0-9a-f]{64}',probe_id)is None:raise RuntimeError('namespace-proof exact fullCID missing')
        def probe(label):
            template='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"object":{{json .Image}},"descriptor":{{json .ImageManifestDescriptor}},"labels":{{json .Config.Labels}},"bindings":{{json .HostConfig.PortBindings}},"command":{{json .Config.Cmd}},"entrypoint":{{json .Config.Entrypoint}},"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"state":{{json .State}}}'
            row=json.loads(run(label,['docker','inspect',probe_id,'--format',template],evidence).stdout)
            selected=json.loads((evidence/'fixture-full-runtime-admission.stdout').read_text())['runtime']['selected_descriptor']
            engine=run(label+'-engine-identity',['docker','image','inspect',admission['image_reference'],'--format','{{.Id}}'],evidence).stdout.strip()
            witnessed=(row['object']==admission['image_id']or(admission['image_id_kind']=='selected_manifest'and
                engine in(admission['image_id'],admission['image_index_digest'])and row['object']==engine
                and isinstance(row['descriptor'],dict)and all(row['descriptor'].get(k)==selected.get(k)for k in ('digest','mediaType','size','platform'))))
            if(not witnessed or row['id']!=probe_id or row['name']!='/'+probe_name or row['image']!=admission['image_reference']
                    or row['labels'].get('volt.delivery.test-owner')!=test_id or row['labels'].get('volt.delivery.role')!='occupied-port-namespace-proof'
                    or row['bindings']!={'8000/tcp':[{'HostIp':'127.0.0.1','HostPort':'46180'}]}
                    or row['command']!=['-c','import time;time.sleep(90)']or row['entrypoint']!=['/opt/uvm/venv/bin/python']
                    or row['user']!=f'{os.getuid()}:{os.getgid()}'or row['readonly']is not True or row['privileged']is not False):
                raise RuntimeError('exact admitted publisher proof identity differs; no mutation authorised')
            return row
        try:
            probe('port-proof-before-start');started=run('port-proof-actual-Docker-start',['docker','start',probe_id],evidence,check=False)
            held('exclusive-binder-after-Docker-probe');after=probe('port-proof-after-start')
            sharing=(started.returncode!=0 and occupied_port_daemon_error(started.stderr+'\n'+after['state'].get('Error','')))
            (evidence/'port-namespace-precondition.json').write_text(json.dumps({'Docker_start_exit':started.returncode,
                'endpoint_specific_daemon_bind_failure':sharing,'owned_host_socket_held':True,'same_host_publishing_conflict_proven':sharing,
                'scope':'admitted image sleep-only no-state/no-HTTP-route helper; not publicinstaller port-denial proof'},indent=2))
        finally:
            probe('port-proof-before-exact-remove');run('port-proof-exact-container-remove',['docker','rm','-f',probe_id],evidence)
            network=json.loads(run('port-proof-network-before-remove',['docker','network','inspect',network_id],evidence).stdout)[0]
            guard_extra_qualification_network(network,network_id=network_id,owner=test_owner,project=test_project,test_id=test_id,api_id=probe_id)
            if network['Containers']:raise RuntimeError('proof network still has users; no removal')
            run('port-proof-exact-network-remove',['docker','network','rm',network_id],evidence)
        if not sharing:
            (evidence/'occupied-port-outcome.json').write_text(json.dumps({'status':'BLOCKED_environment_same_host_publisher_namespace_unproved',
                'public_install_attempted':False,'state_created':state.exists(),'precise_dependency':'exclusive registered HOST socket was held but Docker publisher provided no endpoint-specific daemon bind failure; do not infer Desktop/WSL namespace sharing or product denial',
                'no_generic_timeout_credit':True,'probe_cleaned':True},indent=2));return
        held('exclusive-binder-before-public-install')
        args=['sh',str(launcher),'install','--directory',str(state),'--port','46180','--project-prefix','volt-easy-delivery']
        with(evidence/'occupied-public-install.stdout').open('x')as stdout,(evidence/'occupied-public-install.stderr').open('x')as stderr:
            (evidence/'occupied-public-install-invocation.json').write_text(json.dumps({'argv':args,'before_invocation':True,'start_new_session':True,'cwd':str(ROOT),'environment_PATH':environment['PATH']},indent=2))
            caller=subprocess.Popen(args,cwd=ROOT,env=environment,stdout=stdout,stderr=stderr,start_new_session=True,
                preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024*1024,2*1024*1024)))
            (evidence/'occupied-public-caller.json').write_text(json.dumps({'PID':caller.pid,'PGID':os.getpgid(caller.pid),'SID':os.getsid(caller.pid)}))
            try:code=caller.wait(timeout=780)
            except subprocess.TimeoutExpired:
                if os.getpgid(caller.pid)!=caller.pid:raise RuntimeError('owned public caller identity changed')
                os.killpg(caller.pid,signal.SIGTERM);caller.wait(timeout=30);code=124
        (evidence/'occupied-public-install.exit').write_text(str(code));held('exclusive-binder-after-public-failure')
        info=json.loads(_bounded_file(state/'instance.json',1024*1024,private=True))
        template='{"id":{{json .Id}},"image":{{json .Config.Image}},"owner":{{json (index .Config.Labels "volt.compose.owner-token")}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"state":{{json .State}},"bindings":{{json .HostConfig.PortBindings}}}'
        row=json.loads(run('occupied-failed-configured-API',['docker','inspect',info['project']+'-volt-1','--format',template],evidence).stdout)
        if(row['image']!=admission['image_reference']or row['owner']!=info['owner_token']or row['project']!=info['project']):raise RuntimeError('actual failed public API identity differs')
        actual_error=row['state'].get('Error','')
        if code!=1 or row['state']['Running']is not False or (actual_error and not occupied_port_daemon_error(actual_error))or not occupied_port_daemon_error((evidence/'occupied-public-install.stderr').read_text()):
            if row['state']['Running']:run('unexpected-exact-owned-portcase-stop',['docker','stop','--time','10',row['id']],evidence,check=False)
            raise RuntimeError('occupied public action lacks actual same-endpoint daemon bind failure; no product credit')
        (evidence/'occupied-port-outcome.json').write_text(json.dumps({'status':'observed_late_public_failure_pending_unheld_namespace_control','public_install_exit':code,'same_host_namespace_precondition_requires_control':True,
            'endpoint_specific_actual_Docker_state_error':actual_error,'registered_binder_held_through_failure':True,'initial_keys_already_created':True,
            'backend_ack_present':bool(info.get('local_recovery_acknowledgement')),'established':info.get('established'),
            'prekey_preack_preworker_denial_claimed':False,'scope':'separate legitimate unclaimed publicinstall, late configured port failure; no account/browser/SQL or repaired/adopted resources'},indent=2))
    finally:
        if binder.poll()is None:
            if os.getpgid(binder.pid)!=binder.pid or os.getsid(binder.pid)!=binder.pid:
                raise RuntimeError('registered binder session changed; no release signal authorised')
            os.kill(binder.pid,signal.SIGTERM)
            try:binder.wait(timeout=10)
            except subprocess.TimeoutExpired:os.kill(binder.pid,signal.SIGKILL);binder.wait()
        (evidence/'owned-binder.exit').write_text(str(binder.returncode))


def qualify_unheld_port_control(*, private: Path, evidence: Path, admission: dict,
        selected: dict, original_port_evidence: Path) -> None:
    """ONE A/B/A host socket control, never another public installation."""
    import socket
    import errno
    from uvm.installer.lock import _bounded_file
    if(original_port_evidence/'owned-binder.exit').read_text().strip()!='0':raise RuntimeError('original registered binder release0 required')
    prior=json.loads(_bounded_file(private/'binder.json',16384,private=True))
    if prior['netns']!=os.readlink('/proc/self/ns/net'):raise RuntimeError('controller host namespace differs from original binder; no control inference')
    state=private/'instance';entry=create_offline_fixture_entry(state=state,admission=admission,private=private)
    environment=trusted_launcher_environment(private/'minimal-host-path',admission)
    run('unheld-control-fresh-external-cache-auth',['sh',str(entry),'verify-cache','--directory',str(state)],evidence,env=environment)
    def host_bind(label):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as check:
            try:check.bind(('127.0.0.1',46180));code=0
            except OSError as exc:
                if exc.errno!=errno.EADDRINUSE:raise
                code=exc.errno
            (evidence/(label+'.json')).write_text(json.dumps({'actual_errno':code,'endpoint':['127.0.0.1',46180],
                'controller_PID':os.getpid(),'controller_start':Path('/proc/self/stat').read_text().split()[21],
                'controller_netns':os.readlink('/proc/self/ns/net'),'socket_inode':os.fstat(check.fileno()).st_ino,
                'reuseaddr':check.getsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR),
                'scope':'actual HOST bind observation, no connection/HTTP/account operation'},indent=2))
            return code
    if host_bind('unheld-before-publish-host-free')!=0:raise RuntimeError('host endpoint not free after old binder release; stop control, no retries')
    test_id=uuid.uuid4().hex;owner=secrets.token_hex(32);project='volt-unheld-proof-'+test_id[:12]
    network_id=run('unheld-owned-internal-network-create',['docker','network','create','--internal','--driver','bridge',
        '--label','volt.compose.owner-token='+owner,'--label','volt.delivery.project='+project,'--label','volt.delivery.test='+test_id,
        'volt-easy-delivery-extra-'+test_id],evidence).stdout.strip()
    name='volt-easy-delivery-unheld-proof-'+test_id
    args=['docker','create','--platform',admission['platform'],'--pull=never','--name',name,'--network',network_id,
        '--label','volt.delivery.test-owner='+test_id,'--label','volt.delivery.role=unheld-port-control',
        '--publish','127.0.0.1:46180:8000','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=8m','--tmpfs','/app/media:rw,noexec,nosuid,nodev,size=1m',
        '--tmpfs','/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
        '--user',f'{os.getuid()}:{os.getgid()}','--entrypoint','/opt/uvm/venv/bin/python',admission['image_reference'],'-c','import time;time.sleep(90)']
    cid=run('unheld-owned-publisher-create',args,evidence).stdout.strip()
    if re.fullmatch(r'[0-9a-f]{64}',cid)is None:raise RuntimeError('unheld exact owned fullCID unavailable')
    def observed(label):
        template='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"object":{{json .Image}},"descriptor":{{json .ImageManifestDescriptor}},"labels":{{json .Config.Labels}},"command":{{json .Config.Cmd}},"entrypoint":{{json .Config.Entrypoint}},"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"bindings":{{json .HostConfig.PortBindings}},"mounts":{{json .Mounts}},"state":{{json .State}}}'
        row=json.loads(run(label,['docker','inspect',cid,'--format',template],evidence).stdout)
        engine=run(label+'-engine',['docker','image','inspect',admission['image_reference'],'--format','{{.Id}}'],evidence).stdout.strip()
        witness=(row['object']==admission['image_id']or(admission['image_id_kind']=='selected_manifest'
            and engine in(admission['image_id'],admission['image_index_digest'])and row['object']==engine
            and isinstance(row['descriptor'],dict)and all(row['descriptor'].get(k)==selected.get(k)for k in('digest','mediaType','size','platform'))))
        if(not witness or row['id']!=cid or row['name']!='/'+name or row['image']!=admission['image_reference']
                or row['labels'].get('volt.delivery.test-owner')!=test_id or row['labels'].get('volt.delivery.role')!='unheld-port-control'
                or row['command']!=['-c','import time;time.sleep(90)']or row['entrypoint']!=['/opt/uvm/venv/bin/python']
                or row['user']!=f'{os.getuid()}:{os.getgid()}'or row['readonly']is not True or row['privileged']is not False
                or row['bindings']!={'8000/tcp':[{'HostIp':'127.0.0.1','HostPort':'46180'}]}
                or any(m.get('Type')!='tmpfs'or m.get('Source')not in('',None)for m in row['mounts'])):
            raise RuntimeError('unheld exact admitted no-state publisher guard differs')
        return row
    started=None;during=None
    try:
        observed('unheld-before-start')
        started=run('unheld-actual-Docker-start',['docker','start',cid],evidence,check=False)
        row=observed('unheld-after-start')
        if started.returncode==0 and row['state']['Running']is True:during=host_bind('unheld-while-Docker-published-host-bind')
    finally:
        observed('unheld-before-exact-remove');run('unheld-exact-publisher-remove',['docker','rm','-f',cid],evidence)
        row=json.loads(run('unheld-network-before-exact-remove',['docker','network','inspect',network_id],evidence).stdout)[0]
        guard_extra_qualification_network(row,network_id=network_id,owner=owner,project=project,test_id=test_id,api_id=cid)
        if row['Containers']:raise RuntimeError('unheld owned network has users; no removal')
        run('unheld-exact-network-remove',['docker','network','rm',network_id],evidence)
    restored=host_bind('unheld-after-remove-host-free')
    proven=started is not None and started.returncode==0 and during==errno.EADDRINUSE and restored==0
    info=json.loads(_bounded_file(state/'instance.json',1024*1024,private=True))
    (evidence/'unheld-port-control-outcome.json').write_text(json.dumps({'status':'same_host_publisher_namespace_proven'if proven else'BLOCKED_Desktop_host_publisher_namespace_unproven',
        'Docker_start_exit':started.returncode if started else None,'host_bind_while_published_errno':during,
        'host_bind_after_cleanup_errno':restored,'same_host_namespace_as_original_registered_binder':True,
        'no_public_install_or_DB_repeat':True,'no_HTTP_route_or_state_mounted':True,'probe_and_network_cleanup':0,
        'earlier_public_phase':{'journal_established':info.get('established'),'backend_ack_present':bool(info.get('local_recovery_acknowledgement')),
            'initial_keys_already_created':True,'prekey_preack_preworker_denial_claimed':False},
        'scope':'ONE unheld A/B/A HOST socket control. Original728controllerEXIT1/State.Error-empty and daemon/publicfailure preserved; no invented State.Error. If unproven, STOP port approach without loops/daemon change.'},indent=2))


def exact_daemon_reservation_error(text: str) -> bool:
    return any('127.0.0.1:46180'in line and any(reason in line.lower()for reason in
        ('port is already allocated','address already in use'))for line in text.splitlines())


def qualify_daemon_reserved_port(*, private: Path, evidence: Path, admission: dict, selected: dict) -> None:
    """Materially different daemon-reservation case; NEVER host-kernel credit."""
    from uvm.installer.lock import _bounded_file
    state=private/'instance';before=json.loads(_bounded_file(state/'instance.json',1024*1024,private=True))
    if private.is_symlink()or private.resolve()!=private or private.parent!=Path('/tmp')or not private.name.startswith('volt-easy-delivery-occupied-port-'):
        raise RuntimeError('ONLY retained728port B allowed, never original1002/C6')
    if before.get('established')is not True or not before.get('local_recovery_acknowledgement')or before.get('restore_pending')or before['image']!=admission['image_reference']:
        raise RuntimeError('retained728 B is not normally established; no repair or new namespace permitted')
    entry=private/'trusted-offline-entry.sh'
    if not entry.is_file()or entry.is_symlink():raise RuntimeError('existing independent fixed entry absent')
    environment=trusted_launcher_environment(private/'minimal-host-path',admission)
    def daemon(label):
        endpoint=environment.get('DOCKER_HOST')
        if not endpoint:
            context=environment.get('DOCKER_CONTEXT')or run(label+'-context',['docker','context','show'],evidence,env=environment).stdout.strip()
            endpoint=run(label+'-endpoint',['docker','context','inspect',context,'--format','{{(index .Endpoints "docker").Host}}'],evidence,env=environment).stdout.strip()
        if not endpoint.startswith('unix://'):raise RuntimeError('only unchanged local Unix daemon allowed')
        server=run(label+'-server-ID',['docker','info','--format','{{.ID}}'],evidence,env=environment).stdout.strip()
        if not re.fullmatch(r'[A-Za-z0-9:-]{8,128}',server):raise RuntimeError('exact daemon ServerID unavailable')
        return endpoint,server
    original_daemon=daemon('daemon-holder-initial')
    ready=run('retained-B-normal-public-status',['sh',str(entry),'status','--directory',str(state)],evidence,env=environment,check=False)
    if ready.returncode!=0:raise RuntimeError('retained B cannot normally admit unchanged state; stop before holder, never repair')
    immutable=((set(before['installer_initial_files'])|set(before['local_recovery_inventory']))-{'.env'})|{'secrets/local-restore-fence/fence.json'}
    keys={name:(digest_bytes(_bounded_file(state/name,1024*1024,private=False)),(state/name).stat().st_ino,stat.S_IMODE((state/name).stat().st_mode))for name in sorted(immutable)}
    def preserved():
        current=json.loads(_bounded_file(state/'instance.json',1024*1024,private=True))
        for field in ('installation_id','owner_token','project','installer_admission','installer_initial_request_sha256','local_recovery_custody'):
            if current[field]!=before[field]:raise RuntimeError('existing B identity/key/pin/fence tuple changed')
        for name,value in keys.items():
            path=state/name
            if(digest_bytes(_bounded_file(path,1024*1024,private=False)),path.stat().st_ino,stat.S_IMODE(path.stat().st_mode))!=value:
                raise RuntimeError('immutable B key/configuration changed or regenerated')
        if hashlib.sha256((state/'.env').read_bytes()).hexdigest()!=current['env_sha256']:raise RuntimeError('B environment differs from durable CURRENT transition')
        record=json.loads(_bounded_file(state/'secrets/local-start-admission/admission.json',16384,private=True))
        if record!=current['local_start_admission']or record['initial_preparation']is not False:raise RuntimeError('B start record differs from normal durable journal projection')
        return current
    token=uuid.uuid4().hex;owner=secrets.token_hex(32);project='volt-daemon-holder-'+token[:12]
    network_id=run('holder-A-internal-network-create',['docker','network','create','--internal','--driver','bridge',
        '--label','volt.compose.owner-token='+owner,'--label','volt.delivery.project='+project,'--label','volt.delivery.test='+token,
        'volt-easy-delivery-extra-'+token],evidence,env=environment).stdout.strip()
    name='volt-easy-delivery-daemon-holder-'+token
    args=['docker','create','--platform',admission['platform'],'--pull=never','--name',name,'--restart=no','--no-healthcheck','--network',network_id,
        '--label','volt.delivery.test-owner='+token,'--label','volt.delivery.role=daemon-reservation-holder',
        '--publish','127.0.0.1:46180:8000','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=8m','--tmpfs','/app/media:rw,noexec,nosuid,nodev,size=1m',
        '--tmpfs','/opt/uvm/state:rw,noexec,nosuid,nodev,size=1m','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m',
        '--user',f'{os.getuid()}:{os.getgid()}','--entrypoint','/opt/uvm/venv/bin/python',admission['image_reference'],'-c','import time;time.sleep(600)']
    cid=run('holder-A-exact-create',args,evidence,env=environment).stdout.strip()
    if re.fullmatch(r'[0-9a-f]{64}',cid)is None:raise RuntimeError('holder registered fullCID missing')
    def holder(label, running=False):
        template='{"id":{{json .Id}},"name":{{json .Name}},"created":{{json .Created}},"image":{{json .Config.Image}},"object":{{json .Image}},"descriptor":{{json .ImageManifestDescriptor}},"labels":{{json .Config.Labels}},"command":{{json .Config.Cmd}},"entrypoint":{{json .Config.Entrypoint}},"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"requested":{{json .HostConfig.PortBindings}},"effective":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}},"state":{{json .State}}}'
        row=json.loads(run(label,['docker','inspect',cid,'--format',template],evidence,env=environment).stdout)
        engine=run(label+'-engine',['docker','image','inspect',admission['image_reference'],'--format','{{.Id}}'],evidence,env=environment).stdout.strip()
        witness=(row['object']==admission['image_id']or(admission['image_id_kind']=='selected_manifest'and engine in(admission['image_id'],admission['image_index_digest'])and row['object']==engine
            and isinstance(row['descriptor'],dict)and all(row['descriptor'].get(k)==selected.get(k)for k in('digest','mediaType','size','platform'))))
        mapping={'8000/tcp':[{'HostIp':'127.0.0.1','HostPort':'46180'}]}
        effective={k:v for k,v in(row['effective']or{}).items()if v}
        if(not witness or row['id']!=cid or row['name']!='/'+name or row['image']!=admission['image_reference']
                or row['labels'].get('volt.delivery.test-owner')!=token or row['labels'].get('volt.delivery.role')!='daemon-reservation-holder'
                or row['command']!=['-c','import time;time.sleep(600)']or row['entrypoint']!=['/opt/uvm/venv/bin/python']
                or row['user']!=f'{os.getuid()}:{os.getgid()}'or row['readonly']is not True or row['privileged']is not False
                or row['requested']!=mapping or any(m.get('Type')!='tmpfs'or m.get('Source')not in('',None)for m in row['mounts'])
                or running and(row['state']['Running']is not True or effective!=mapping)):
            raise RuntimeError('registered A identity/image/no-state/effective port mapping drift; STOP unproven')
        return row
    capture=private/'daemon-reservation-observer';capture.mkdir(mode=0o700);real=Path(shutil.which('docker',path=environment['PATH'])).resolve(strict=True)
    constants={'REAL':str(real),'CAPTURE':str(capture),'STATE':str(state),'PROJECT':before['project'],'SERVER':original_daemon[1],'ENDPOINT':original_daemon[0],'HOLDER':cid}
    script='#!/bin/sh\nset -eu\numask 077\n'+''.join(k+'='+shlex.quote(v)+'\n'for k,v in constants.items())+r'''
pass_original() { exec "$REAL" "$@"; }
[ "$#" -eq 10 ] && [ "$1|$2|$3|$4|$5|$6|$7|$8|$9|${10}" = "compose|-f|$STATE/compose/compose.yaml|-f|$STATE/compose/local.yaml|--env-file|$STATE/.env|-p|$PROJECT|start" ] || pass_original "$@"
IFS= read -r caller <"$CAPTURE/caller.pid";case "$caller" in ''|*[!0-9]*)exit 76;;esac
read -r pid comm status parent group session rest <"/proc/$caller/stat"
[ "$pid|$group|$session" = "$caller|$caller|$caller" ] || exit 76
ancestor=$PPID;steps=0
while [ "$ancestor" != "$caller" ] && [ "$steps" -lt 8 ];do
 read -r pid comm status parent group session rest <"/proc/$ancestor/stat"
 [ "$group|$session" = "$caller|$caller" ] || exit 76;ancestor=$parent;steps=$((steps+1))
done
[ "$ancestor" = "$caller" ] && [ ! -e "$CAPTURE/producer.exit" ] || exit 76
[ "$("$REAL" info --format '{{.ID}}')" = "$SERVER" ] || exit 76
endpoint=${DOCKER_HOST:-}
if [ -z "$endpoint" ];then context=${DOCKER_CONTEXT:-};[ -n "$context" ] || context=$("$REAL" context show);endpoint=$("$REAL" context inspect "$context" --format '{{(index .Endpoints "docker").Host}}');fi
[ "$endpoint" = "$ENDPOINT" ] || exit 76
[ "$("$REAL" inspect "$HOLDER" --format '{{.Id}}|{{.State.Running}}')" = "$HOLDER|true" ] || exit 76
printf '%s\n' "$@" >"$CAPTURE/producer.argv-lines"
set +e
(ulimit -f 128; "$REAL" "$@") >"$CAPTURE/producer.stdout" 2>"$CAPTURE/producer.stderr"
code=$?;set -e;printf '%s\n' "$code" >"$CAPTURE/producer.exit"
cat "$CAPTURE/producer.stdout";cat "$CAPTURE/producer.stderr" >&2;exit "$code"
'''
    shim=capture/'docker';shim.write_text(script);shim.chmod(0o700)
    run('holder-compose-observer-shell',['sh','-n',str(shim)],evidence)
    conflict=False
    try:
        holder('holder-A-before-start');run('holder-A-start',['docker','start',cid],evidence,env=environment)
        live=holder('holder-A-reserved-before-B',True)
        if daemon('daemon-before-B')!=original_daemon:raise RuntimeError('daemon/context changed before conflict')
        argv=['sh','-c','umask 077; printf "%s\\n" "$$" >"$DAEMON_CAPTURE/caller.pid"; exec sh "$0" "$@"',str(entry),'start','--directory',str(state)]
        observed={**environment,'PATH':str(capture)+os.pathsep+environment['PATH'],'DAEMON_CAPTURE':str(capture)}
        (evidence/'public-B-conflict-invocation.json').write_text(json.dumps({'argv':argv,'before_invocation':True,'cwd':str(ROOT),'start_new_session':True,'source_observer_sha256':sha(shim),'PATH':observed['PATH']},indent=2))
        with(evidence/'public-B-conflict.stdout').open('x')as stdout,(evidence/'public-B-conflict.stderr').open('x')as stderr:
            caller=subprocess.Popen(argv,cwd=ROOT,env=observed,stdout=stdout,stderr=stderr,start_new_session=True)
            (capture/'registered-caller.json').write_text(json.dumps({'PID':caller.pid,'PGID':os.getpgid(caller.pid),'SID':os.getsid(caller.pid)}))
            try:code=caller.wait(timeout=300)
            except subprocess.TimeoutExpired:
                if os.getpgid(caller.pid)!=caller.pid:raise RuntimeError('registered B caller changed')
                os.killpg(caller.pid,signal.SIGTERM);caller.wait(timeout=30);code=124
        (evidence/'public-B-conflict.exit').write_text(str(code))
        after=holder('holder-A-still-reserved-after-B',True)
        if after['created']!=live['created']or after['state']['StartedAt']!=live['state']['StartedAt']or daemon('daemon-after-B')!=original_daemon:raise RuntimeError('holder/daemon changed through conflict')
        terminal=(evidence/'public-B-conflict.stderr').read_text()
        producer=_bounded_file(capture/'producer.stderr',65536,private=True).decode()
        conflict=(code==1 and(capture/'producer.exit').read_text().strip()=='1'and exact_daemon_reservation_error(producer)
            and 'volt installer: bootstrap maintenance container start failed'in terminal.splitlines())
        preserved()
        (evidence/'daemon-conflict-layer.json').write_text(json.dumps({'public_exit':code,'producer_exit':(capture/'producer.exit').read_text().strip(),
            'exact_allocated_or_address_in_use':exact_daemon_reservation_error(producer),'generic_ports_unavailable_500_insufficient':True,
            'holder_running_with_exact_effective_mapping_through_failure':True,'same_daemon_context':True,'daemon_reservation_credit_pending_control':conflict},indent=2))
    finally:
        holder('holder-A-before-exact-remove');run('holder-A-exact-remove',['docker','rm','-f',cid],evidence,env=environment)
        row=json.loads(run('holder-A-network-before-remove',['docker','network','inspect',network_id],evidence,env=environment).stdout)[0]
        guard_extra_qualification_network(row,network_id=network_id,owner=owner,project=project,test_id=token,api_id=cid)
        if row['Containers']:raise RuntimeError('holder network has users; no removal')
        run('holder-A-exact-network-remove',['docker','network','rm',network_id],evidence,env=environment)
    if not conflict:
        (evidence/'daemon-reservation-outcome.json').write_text(json.dumps({'status':'STOP_UNPROVEN_conflict_layer','no_more_start_or_probes':True,
            'host_kernel_class_remains_BLOCKED':True,'holder_cleanup':0},indent=2));return
    run('B-after-holder-release-supported-start',['sh',str(entry),'start','--directory',str(state)],evidence,env=environment)
    wait_for_local('http://127.0.0.1:46180',evidence)
    preserved()
    run('B-after-control-supported-stop',['sh',str(entry),'stop','--directory',str(state)],evidence,env=environment)
    final=preserved()
    if daemon('daemon-after-control')!=original_daemon:raise RuntimeError('daemon changed during sensitivity control')
    (evidence/'daemon-reservation-outcome.json').write_text(json.dumps({'status':'passed','scope':'ONE Docker-daemon reserved published endpoint ONLY, not HOST kernel socket collision',
        'same_daemon_context':original_daemon,'exact_conflicting_start_exit':1,'after_release_supported_start_exit':0,'normal_health_exit':0,'controlled_stop_exit':0,
        'same_installation_identity_keys_pin':True,'immutable_observed_key_config_count':len(keys),'normal_journal_CURRENT_environment_transitions_only':True,
        'backend_ack_present':bool(final.get('local_recovery_acknowledgement')),'prekey_preack_preworker_denial_claimed':False,
        'host_kernel_class_remains_BLOCKED':True,'holder_exact_cleanup':0,'retained_B_fixture':str(private)},indent=2))


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
