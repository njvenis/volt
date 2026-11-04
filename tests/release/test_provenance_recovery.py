from __future__ import annotations

import copy
import unittest

from tools.release import provenance


class RecoveryProvenanceTests(unittest.TestCase):
    def predicate(self):
        source = "a" * 40
        return {
            "buildDefinition": {
                "buildType": provenance.BUILD_TYPE,
                "externalParameters": {
                    "workflow": {"repository": provenance.REPOSITORY, "ref": provenance.WORKFLOW_REF},
                    "source": {"uri": provenance.REPOSITORY, "ref": source},
                },
                "internalParameters": {"voltReleaseController": {
                    "commit": "b" * 40,
                    "workflow_ref": provenance.WORKFLOW_REF,
                    "candidate_source_commit": source,
                    "candidate_run_id": "41892440449",
                    "publication_run_id": "41896116006",
                    "artifact_id": "13353554349",
                    "artifact_digest": "sha256:" + "c" * 64,
                    "candidate_archive_sha256": "d" * 64,
                    "recovery_mode": True,
                }},
                "resolvedDependencies": [{"uri": "git+" + provenance.REPOSITORY,
                                          "digest": {"gitCommit": source}}],
            }
        }, source

    def test_controller_is_distinct_and_candidate_binding_is_validated(self):
        predicate, source = self.predicate()
        provenance.validate(predicate, source, expected_controller_commit="b" * 40)
        mutations = (
            ("commit", "e" * 40),
            ("workflow_ref", "other/workflow"),
            ("candidate_source_commit", "f" * 40),
            ("candidate_run_id", "../123"),
            ("publication_run_id", ""),
            ("artifact_id", "not-numeric"),
            ("artifact_digest", "sha256:bad"),
            ("candidate_archive_sha256", "bad"),
            ("recovery_mode", "true"),
        )
        for key, value in mutations:
            bad = copy.deepcopy(predicate)
            bad["buildDefinition"]["internalParameters"]["voltReleaseController"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                provenance.validate(bad, source, expected_controller_commit="b" * 40)


if __name__ == "__main__":
    unittest.main()
