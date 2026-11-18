#!/usr/bin/env python3
"""Execute pinned Gitleaks positive/negative contracts without exposing values."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import uuid
import subprocess
import tempfile

HISTORICAL_COMMIT = "11fab25894046bf7f9b339753755f308f9d32fbd"
AFFECTED_PATH = "tests/operations/test_demo_password_login.py"
FINGERPRINT = f"{HISTORICAL_COMMIT}:{AFFECTED_PATH}:generic-api-key:29"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    source = args.source.resolve()
    evidence = args.evidence.resolve()
    if evidence == source or source in evidence.parents:
        parser.error("private evidence must be outside the source checkout")
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    records = []
    forbidden_values = []

    def run(label, argv, *, cwd=source, expected=0, env=None, retain_stdout=True):
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, env=env)
        # Defence in depth in addition to the scanner's --redact=100.
        stdout, stderr = result.stdout, result.stderr
        for value in forbidden_values:
            stdout, stderr = stdout.replace(value, "REDACTED"), stderr.replace(value, "REDACTED")
        (evidence / f"{label}.stdout").write_text(stdout if retain_stdout else "source fixture loaded privately; see source bundle\n")
        (evidence / f"{label}.stderr").write_text(stderr)
        (evidence / f"{label}.exit").write_text(str(result.returncode) + "\n")
        records.append({"label": label, "argv": argv, "cwd": str(cwd), "exit": result.returncode,
                        "expected_exit": expected})
        (evidence / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode != expected:
            raise RuntimeError(f"{label}: unexpected exit; inspect private redacted evidence")
        return result.stdout.strip()

    revision = run("revision", ["git", "rev-parse", "HEAD"])
    if run("initial-clean", ["git", "status", "--porcelain"]):
        raise RuntimeError("journey requires clean committed source")
    entries = [line for line in (source / ".gitleaksignore").read_text().splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    if entries != [FINGERPRINT]:
        raise RuntimeError("exact approved one-entry disposition required")
    pin = next(line.split("=", 1)[1] for line in (source / "tools/release/tools.lock").read_text().splitlines()
               if line.startswith("gitleaks_image="))
    historical = run("historical-fixture", ["git", "show", f"{HISTORICAL_COMMIT}:{AFFECTED_PATH}"], retain_stdout=False)
    tree = ast.parse(historical)
    credential = ast.literal_eval(next(node for node in ast.walk(tree)
        if isinstance(node, ast.Dict) and node.lineno == 27))
    marker = credential["password_hash"]
    forbidden_values.extend((marker, credential["salt"]))
    run("source-bundle", ["git", "bundle", "create", str(evidence / "source-all.bundle"), "--all"])
    summary = []

    with tempfile.TemporaryDirectory(prefix="volt-gitleaks-private-", dir=evidence) as temporary:
        private = Path(temporary)
        snapshot = private / "source"
        snapshot.mkdir()
        # Preserve every ref exactly, but materialise an ordinary .git checkout
        # so the actual workflow commands and automatic ignore discovery run.
        run("mirror", ["git", "clone", "--mirror", str(evidence / "source-all.bundle"), str(snapshot / ".git")])
        run("unbare", ["git", "config", "core.bare", "false"], cwd=snapshot)
        run("checkout", ["git", "checkout", "--force", "--detach", revision], cwd=snapshot)
        run("captured-refs", ["git", "show-ref"], cwd=snapshot)

        def scan(label, checkout, mode, expected, *, control=False):
            report = evidence / f"{label}.json"
            argv = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                    "-v", f"{checkout}:/repo:ro", "-v", f"{evidence}:/evidence",
                    "-w", "/repo", pin, mode, ".", "--config", "tools/release/gitleaks.toml",
                    "--redact=100", "--report-format", "json", "--report-path", f"/evidence/{report.name}"]
            if mode == "git":
                argv.append("--log-opts=--all")
            ignore = checkout / ".gitleaksignore"
            retained_ignore = ignore.read_bytes() if control else None
            if control:
                # Explicitly remove the disposition only in this disposable
                # checkout; an empty override path may retain auto-discovery.
                ignore.unlink()
            try:
                run(label, argv, expected=expected)
            finally:
                if retained_ignore is not None:
                    ignore.write_bytes(retained_ignore)
            raw = report.read_text()
            if any(value in raw for value in forbidden_values):
                report.write_text("[]\n")
                raise RuntimeError("scanner report redaction failed")
            findings = json.loads(raw)
            safe = [{key: row.get(key) for key in ("RuleID", "File", "StartLine", "Commit", "Fingerprint")}
                    for row in findings]
            (evidence / f"{label}.safe.json").write_text(json.dumps(safe, indent=2) + "\n")
            summary.append({"label": label, "exit": expected, "findings": safe})
            return safe

        if scan("directory", snapshot, "dir", 0):
            raise RuntimeError("corrected current source has directory findings")
        if scan("history", snapshot, "git", 0):
            raise RuntimeError("approved historical disposition did not close history")
        control = scan("history-no-disposition-control", snapshot, "git", 1, control=True)
        if len(control) != 1 or control[0]["Fingerprint"] != FINGERPRINT:
            raise RuntimeError("control must expose exactly the approved historical occurrence")
        # Public UUID/hash-based test markers have credential-like syntax but
        # are never issued credentials or secret key material.
        generic = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        independent = "ghp_" + uuid.uuid4().hex + uuid.uuid4().hex[:4]
        forbidden_values.extend((generic, independent))
        cases = [
            ("same-marker-new-commit", AFFECTED_PATH, historical + "\n", 29, "generic-api-key"),
            ("same-marker-other-path", "tests/operations/fingerprint-other.py", historical + "\n", 29, "generic-api-key"),
            ("same-marker-other-line", AFFECTED_PATH, "\n" + historical + "\n", 30, "generic-api-key"),
            ("independent-generic-marker", AFFECTED_PATH, "\n" * 28 + f'api_key = "{generic}"\n', 29, "generic-api-key"),
            ("independent-default-rule", AFFECTED_PATH, "\n" * 28 + f'github_token = "{independent}"\n', 29, "github-pat"),
        ]
        for label, path, payload, line, rule in cases:
            checkout = private / label
            run(label + "-clone", ["git", "clone", "--quiet", "--no-hardlinks", str(snapshot), str(checkout)])
            target = checkout / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(payload)
            run(label + "-add", ["git", "add", "--", path], cwd=checkout)
            run(label + "-commit", ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-qm", "Synthetic scanner isolation fixture"], cwd=checkout)
            commit = run(label + "-revision", ["git", "rev-parse", "HEAD"], cwd=checkout)
            run(label + "-bundle", ["git", "bundle", "create", str(evidence / f"{label}.bundle"), "--all"], cwd=checkout)
            findings = scan(label, checkout, "git", 1)
            if not any(row["RuleID"] == rule and row["File"] == path and row["StartLine"] == line
                       and row["Commit"] == commit and row["Fingerprint"] != FINGERPRINT for row in findings):
                raise RuntimeError(f"{label}: expected isolated detection missing")
            if label == "independent-generic-marker":
                findings = scan("live-directory-injection", checkout, "dir", 1)
                if not any(row["RuleID"] == rule and row["File"] == path and row["StartLine"] == line for row in findings):
                    raise RuntimeError("directory injection was incorrectly exempted")
        private_path = str(private)
    if Path(private_path).exists():
        raise RuntimeError("owned private fixture cleanup failed")
    result = {"revision": revision, "gitleaks_image": pin, "policy_sha256": hashlib.sha256(
        (source / "tools/release/gitleaks.toml").read_bytes()).hexdigest(),
        "scope": "all refs preserved in source-all.bundle; actual workflow scanner commands", "scans": summary,
        "cleanup": "owned private fixture directory removed; Docker containers used --rm", "result": "passed"}
    (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: {len(summary)} pinned redacted scanner contracts; owned fixtures removed; source {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
