"""Synthetic Debian/PGDG trust inputs retained by the real notice collector."""
from pathlib import Path
from tools.notices.collect import copy_disposition_evidence, digest


def retained_trust_material(source: Path, output: Path) -> dict[str, bytes]:
    source.mkdir()
    dispositions = {}
    for repository, packages in (("debian-trixie", ("apt", "libapt-pkg7.0")),
                                 ("postgresql-pgdg", ("postgresql-18", "postgresql-common"))):
        trust = source / repository
        trust.mkdir()
        shared = {}
        for field, name in (("inrelease", "InRelease"), ("index", "Sources.xz"), ("keyring", "archive-keyring.gpg")):
            path = trust / name
            path.write_bytes(f"synthetic {repository} shared {name} bytes\n".encode())
            shared[field + "_path"] = str(path)
            shared[field + "_sha256"] = digest(path)
        for package in packages:
            tar = source / f"{package}_1.0.orig.tar.xz"
            dsc = source / f"{package}_1.0.dsc"
            tar.write_bytes(f"synthetic {package} source bytes\n".encode())
            dsc.write_bytes(f"synthetic {package} dsc bytes\n".encode())
            dispositions[package, "1.0"] = {"decision": "source-bundle", "source_bundle": {
                "path": str(tar), "sha256": digest(tar), "signed_dsc_path": str(dsc),
                "signed_dsc_sha256": digest(dsc), "index_authentication": dict(shared)}}
    copy_disposition_evidence(dispositions, output)
    retained = {}
    for disposition in dispositions.values():
        bundle = disposition["source_bundle"]
        for field in ("inrelease_path", "index_path", "keyring_path"):
            path = output / bundle["index_authentication"][field]
            assert path.stat().st_nlink >= 3, "fixture must exercise real package-specific hardlinks"
            retained[path.relative_to(output).as_posix()] = path.read_bytes()
    return retained
