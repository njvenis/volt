#!/usr/bin/env python3
"""Strict expected-byte checks for the G7 replacement media/state markers."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


class MarkerFailure(Exception):
    def __init__(self, classifier: str, path: Path):
        super().__init__(classifier)
        self.classifier = classifier
        self.path = path


def verify(expected_path: Path, media_path: Path, state_path: Path) -> dict:
    try:
        expected = expected_path.read_bytes()
    except FileNotFoundError as error:
        raise MarkerFailure("expected_marker_missing", expected_path) from error
    except OSError as error:
        raise MarkerFailure("expected_marker_read_failed", expected_path) from error
    if not expected:
        raise MarkerFailure("expected_marker_empty", expected_path)
    values = {}
    for name, path in (("media", media_path), ("state", state_path)):
        try:
            values[name] = path.read_bytes()
        except FileNotFoundError as error:
            raise MarkerFailure("marker_missing", path) from error
        except OSError as error:
            raise MarkerFailure("marker_read_failed", path) from error
        if values[name] != expected:
            raise MarkerFailure("marker_value_mismatch", path)
    return {"result": "passed", "expected_sha256": hashlib.sha256(expected).hexdigest(),
        "media_sha256": hashlib.sha256(values["media"]).hexdigest(),
        "state_sha256": hashlib.sha256(values["state"]).hexdigest(),
        "bytes": len(expected)}


def self_test(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    expected = root / "expected"
    expected.write_bytes(b"g7-marker-self-test-v1\n")
    media, state = root / "media", root / "state"
    cases = {}
    for name, media_data, state_data, classifier in (
            ("both_missing", None, None, "marker_missing"),
            ("one_missing", b"g7-marker-self-test-v1\n", None, "marker_missing"),
            ("one_read_failed", b"g7-marker-self-test-v1\n", "directory", "marker_read_failed"),
            ("mismatched", b"changed\n", b"g7-marker-self-test-v1\n", "marker_value_mismatch")):
        for path in (media, state):
            if path.is_dir():
                path.rmdir()
            path.unlink(missing_ok=True)
        for path, value in ((media, media_data), (state, state_data)):
            if value == "directory":
                path.mkdir()
            elif value is not None:
                path.write_bytes(value)
        try:
            verify(expected, media, state)
        except MarkerFailure as failure:
            cases[name] = failure.classifier
        else:
            raise SystemExit(f"false-pass marker case: {name}")
        if cases[name] != classifier:
            raise SystemExit(f"marker classifier mismatch: {name}: {cases[name]}")
    expected.unlink(missing_ok=True)
    for path in (media, state):
        if path.is_dir():
            path.rmdir()
        path.unlink(missing_ok=True)
    return {"result": "passed", "negative_classifiers": cases}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test-dir", type=Path)
    parser.add_argument("expected", nargs="?", type=Path)
    parser.add_argument("media", nargs="?", type=Path)
    parser.add_argument("state", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.self_test_dir:
            if any((args.expected, args.media, args.state)):
                parser.error("self-test mode does not accept marker paths")
            result = self_test(args.self_test_dir)
        else:
            if not all((args.expected, args.media, args.state)):
                parser.error("expected, media and state paths are required")
            result = verify(args.expected, args.media, args.state)
    except MarkerFailure as failure:
        print(json.dumps({"result": "denied", "classifier": failure.classifier,
            "path": str(failure.path)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
