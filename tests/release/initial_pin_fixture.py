"""Synthetic pre-admission data ONLY; real FD/key guards are not substituted.

No production fixture flag or installed authority is created by this helper.
Actual cryptographic/native/package qualification remains a separate runner.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from tests.release import test_offline_graph_policy as graph_tests
from uvm.installer import offline_artifacts as artifacts, verifier, installed_artifacts


def prepared_graph(parent: Path):
    parent.mkdir(mode=0o700)
    graph = graph_tests.OfflineGraphPolicyTests()
    args, cache, policy = graph.fixture(parent)
    document = json.loads((cache / 'closure.json').read_text())
    document['release'].update(signer=installed_artifacts.SIGNER, issuer=installed_artifacts.ISSUER)
    (cache / 'closure.json').write_bytes(artifacts.canonical(document))
    args.signer, args.issuer = installed_artifacts.SIGNER, installed_artifacts.ISSUER
    with patch.object(artifacts, 'ROOT', cache), patch.object(verifier, 'FIXTURE_POLICY', policy), \
            patch.object(artifacts.subprocess, 'run', side_effect=graph.crypto):
        result = verifier.verify_offline(args)
    return args, cache, result
