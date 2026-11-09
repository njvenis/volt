#!/usr/bin/env python3
"""Export the application's API schema using only synthetic, disposable state.

This constructs routes; it does not start a server or exercise external services.
Ambient deployment configuration is excluded before importing the app factory.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch


def export_schema() -> dict:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("UVM_")}
    environment["UVM_AUTH_MODE"] = "bearer"
    with patch.dict(os.environ, environment, clear=True):
        import sqlalchemy as sa
        from uvm.api.app import create_app

        engine = sa.create_engine("sqlite+pysqlite:///:memory:")
        try:
            app = create_app(
                engine,
                principals={},
                cursor_secret="synthetic-openapi-export-not-a-credential",
                utc_now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            )
            return app.openapi()
        finally:
            engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(export_schema(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    main()
