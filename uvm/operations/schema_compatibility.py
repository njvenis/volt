"""Fail-closed schema-head admission for the image's declared runtime mode."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def validate_heads(*, declared_head: str, heads: list[str], mode: str,
        empty_cluster: bool = False, compatibility_admitted: bool = False) -> None:
    """Accept only the image's exact runtime head, except an admitted 0058→0059 check."""
    if declared_head not in {"0058", "0059", "0061"}:
        raise ValueError("image schema declaration is invalid")
    if empty_cluster:
        if heads or mode != "normal":
            raise ValueError("empty-cluster initialization is not valid in this mode")
        return
    if len(heads) != 1 or not heads[0]:
        raise ValueError("database has missing or multiple schema heads")
    if heads == [declared_head] and mode == "normal":
        return
    if (declared_head == "0059" and heads == ["0059"]
            and mode == "upgrade-verification" and compatibility_admitted):
        return
    if (declared_head == "0059" and heads == ["0058"]
            and mode == "upgrade-verification" and compatibility_admitted):
        return
    if (declared_head == "0061" and len(heads) == 1
            and heads[0] in {"0059", "0060", "0061"}
            and mode == "upgrade-verification" and compatibility_admitted):
        return
    raise ValueError("database schema is incompatible with this image and startup mode")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--declared-head", required=True)
    parser.add_argument("--mode", choices=("normal", "upgrade-verification"), default="normal")
    parser.add_argument("--heads-json", required=True)
    parser.add_argument("--empty-cluster", action="store_true")
    parser.add_argument("--compatibility-admitted", action="store_true")
    args = parser.parse_args()
    try:
        heads = json.loads(args.heads_json)
        if not isinstance(heads, list) or any(not isinstance(head, str) for head in heads):
            raise ValueError("schema head query result is invalid")
        validate_heads(declared_head=args.declared_head, heads=heads, mode=args.mode,
            empty_cluster=args.empty_cluster,
            compatibility_admitted=args.compatibility_admitted)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"G7_SCHEMA_COMPATIBILITY_REJECTED reason={exc}", file=sys.stderr)
        return 1
    print(json.dumps({"accepted": True, "mode": args.mode,
        "declared_head": args.declared_head, "heads": heads,
        "empty_cluster": args.empty_cluster}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
