"""Check all files in a candidate tree for public-source hygiene and links."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import subprocess
from pathlib import Path

LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{15,}\b"),
)
ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"Rar!", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b", b"BZh")
APPROVED_PNG_PATH = Path("docs/assets/volt-logo.png")
APPROVED_PNG_SHA256 = "c4cde9e35d1f4e7ef9993875e0e294e91a6dd6144f16a0d85f1f9ae82be7cf90"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
REPOSITORY_PREFIXES = (
    ".github/", "design/", "docs/", "docker/", "migrations/", "openspec/",
    "tests/", "tools/", "ui/", "uvm/",
)
ROOT_FILES = {
    ".gitignore", "CONTRIBUTING.md", "Dockerfile.g7", "GATES.md", "LICENSE",
    "README.md", "REQUIREMENTS.md", "RUNBOOK.md", "SECURITY.md",
    "THIRD-PARTY-NOTICES.md", "TRACEABILITY.md", "alembic.ini", "pyproject.toml", "uv.lock",
}

def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or "git ls-files failed")
    return [root / Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item]


def is_approved_logo_png(rel: Path, raw: bytes) -> bool:
    """Allow only the exact user-approved upstream VOLT logo PNG."""
    return (
        rel == APPROVED_PNG_PATH
        and raw.startswith(PNG_MAGIC)
        and hashlib.sha256(raw).hexdigest() == APPROVED_PNG_SHA256
    )


def main(root: Path, private_denylist: Path | None = None) -> int:
    errors: list[str] = []
    text_files: list[tuple[Path, str]] = []
    approved_pngs = 0
    denied: tuple[str, ...] = ()
    if private_denylist is not None:
        try:
            denied = tuple(
                line.strip().casefold()
                for line in private_denylist.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        except OSError as exc:
            print(f"Public source check failed: cannot read private verification list: {exc}")
            return 1
    try:
        paths = tracked_files(root)
    except (OSError, RuntimeError) as exc:
        print(f"Public source check failed: cannot enumerate tracked files: {exc}")
        return 1
    for path in paths:
        rel = path.relative_to(root)
        if path.is_symlink():
            errors.append(f"{rel}: symbolic links are not approved for the public source tree")
            continue
        if not path.is_file():
            errors.append(f"{rel}: tracked file is missing from the working tree")
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            errors.append(f"{rel}: cannot read file")
            continue
        if path.suffix.lower() in ARCHIVE_SUFFIXES or raw.startswith(ARCHIVE_MAGIC):
            errors.append(f"{rel}: archive is not approved for the public source tree")
            continue
        if is_approved_logo_png(rel, raw):
            approved_pngs += 1
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{rel}: non-UTF-8/binary file is not approved for the public source tree")
            continue
        if "\0" in content:
            errors.append(f"{rel}: binary content is not approved for the public source tree")
            continue
        text_files.append((path, content))
        for line_no, line in enumerate(content.splitlines(), 1):
            for address in EMAIL.findall(line):
                domain = address.rsplit("@", 1)[1].casefold()
                if not domain.endswith((".invalid", ".example", ".local")):
                    errors.append(f"{rel}:{line_no}: email address found")
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                errors.append(f"{rel}:{line_no}: credential-shaped secret found")
            folded_line = line.casefold()
            if any(marker in folded_line for marker in denied):
                errors.append(f"{rel}:{line_no}: private verification marker found")

    for path, content in text_files:
        if path.suffix.lower() != ".md":
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            targets = list(LINK.findall(line))
            targets.extend(
                value.strip().strip(".,;:")
                for value in re.findall(r"`([^`]+)`", line)
                if value.startswith(REPOSITORY_PREFIXES) or value in ROOT_FILES
            )
            for target in targets:
                target = target.strip().split()[0].strip("<>")
                if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                local = target.split("#", 1)[0].split("?", 1)[0]
                if local:
                    repo_relative = local.startswith(REPOSITORY_PREFIXES) or local in ROOT_FILES
                    destination = (root / local) if repo_relative else (path.parent / local)
                    if destination.resolve().exists():
                        continue
                    errors.append(f"{path.relative_to(root)}:{line_no}: broken local link: {target}")

    if errors:
        print("Public source check failed:")
        print("\n".join(errors))
        return 1
    binary_note = f" and {approved_pngs} exact approved PNG asset" if approved_pngs else ""
    print(f"Public source check passed: scanned {len(text_files)} UTF-8 files{binary_note}; other binaries and archives absent; local Markdown links resolve.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Git worktree to scan")
    parser.add_argument("--private-denylist", type=Path, help="external private verification list; do not add to source")
    args = parser.parse_args()
    raise SystemExit(main(Path(args.root).resolve(), args.private_denylist))
