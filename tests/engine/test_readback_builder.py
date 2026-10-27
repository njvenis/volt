import hashlib
import json
import unittest
from dataclasses import replace

from tests.engine import test_manifest as _manifest
from uvm.engine.ce_read_client import CEReadClient, JSONError, ScopeError
from uvm.engine.manifest import ManifestBindingRegistry
from uvm.engine.association import EndpointIdentityV1
from uvm.engine.readback_builder import ReadbackError, build_readback


def body(value):
    return json.dumps(value, separators=(",", ":")).encode()


class Fake:
    def __init__(self, values):
        self.values = values

    def __call__(self, method, url, headers, timeout, *, follow_redirects):
        assert method == "GET"
        assert not follow_redirects
        return 200, {"Content-Type": "application/json"}, self.values[url]


def fixture(*, reverse=(101,), shared=False, endpoint_id=11,
            endpoint_ids=(11,)):
    values = {}

    def add(path, value):
        values["https://dojo.test" + path] = body(value)

    add("/api/v2/tests/7/", {"id": 7, "engagement": 2})
    add("/api/v2/findings/?test=7", {"count": 2, "next": "https://dojo.test/api/v2/findings/?offset=1&test=7", "results": [{"id": 101, "test": 7}]})
    add("/api/v2/findings/?offset=1&test=7", {"count": 2, "next": None, "results": [{"id": 102, "test": 7}]})
    add("/api/v2/findings/101/", {"id": 101, "test": 7, "endpoints": list(endpoint_ids), "verified": False})
    add("/api/v2/findings/102/", {"id": 102, "test": 7, "endpoints": [11] if shared else [], "verified": False})
    endpoint = {"id": endpoint_id}
    if reverse is not None:
        endpoint["findings"] = list(reverse)
    add("/api/v2/endpoints/11/", endpoint)
    return values


def setup(values=None):
    # Use the approved manifest builder, not a SimpleNamespace authority.
    args = _manifest.ManifestContractTests().good_arguments()
    operation = replace(args[-1], request_kind="reimport", test_id="7")
    manifest = _manifest.ManifestContractTests().build(*args[:-1], operation)
    registry = ManifestBindingRegistry()
    registry.bind(manifest)
    return CEReadClient("https://dojo.test", Fake(values or fixture())), operation, manifest, registry


def setup_first_import(values=None):
    args = _manifest.ManifestContractTests().good_arguments()
    operation = replace(args[-1], post_issued=True, response_ref="resp", response_test_id="7")
    manifest = _manifest.ManifestContractTests().build(*args[:-1], operation)
    registry = ManifestBindingRegistry()
    registry.bind(manifest)
    return CEReadClient("https://dojo.test", Fake(values or fixture())), operation, manifest, registry


def read(client, operation, manifest, registry):
    return build_readback(client, operation, manifest, ce_release="3.3.100", evidence_ref="retained://rb", source_kind="synthetic-fixture", engagement_id=2, manifest_registry=registry)


class ReadbackBuilderTests(unittest.TestCase):
    def test_first_import_binds_post_response_to_unbound_pre_post_manifest(self):
        client, operation, manifest, registry = setup_first_import()
        self.assertIsNone(manifest.bound_test_id)
        self.assertEqual(read(client, operation, manifest, registry).test_id, 7)

    def test_collects_two_pages_and_consistent_forward_reverse_links(self):
        client, operation, manifest, registry = setup()
        bundle = read(client, operation, manifest, registry)
        self.assertEqual(bundle.finding_ids, (101, 102))
        self.assertEqual(bundle.endpoint_ids, (11,))
        self.assertEqual(bundle.mapping_status, "pending")
        self.assertEqual(bundle.finding_page_sha256[0], hashlib.sha256(bundle.finding_pages[0].body).hexdigest())

    def test_host_only_ambiguous_pair_remains_pending(self):
        client, operation, manifest, registry = setup(fixture(reverse=(101, 102), shared=True))
        self.assertEqual(read(client, operation, manifest, registry).mapping_status, "pending")

    def test_finding_forward_edge_plus_exact_endpoint_identity_is_sufficient(self):
        client, operation, manifest, registry = setup(fixture(reverse=None))
        bundle = read(client, operation, manifest, registry)
        self.assertEqual(bundle.finding_associations[0].endpoint_ids, (11,))
        self.assertIsInstance(bundle.endpoint_associations[0], EndpointIdentityV1)
        self.assertEqual(bundle.endpoint_associations[0].endpoint_id, 11)

    def test_missing_or_mismatched_endpoint_identity_fails_closed(self):
        client, operation, manifest, registry = setup(fixture(reverse=None, endpoint_id=12))
        with self.assertRaises(ScopeError):
            read(client, operation, manifest, registry)

    def test_present_reverse_endpoint_membership_must_still_match_forward(self):
        client, operation, manifest, registry = setup(fixture(reverse=()))
        with self.assertRaises(ReadbackError):
            read(client, operation, manifest, registry)

    def test_duplicate_forward_endpoint_ids_remain_ambiguous_and_fail_closed(self):
        client, operation, manifest, registry = setup(fixture(reverse=None, endpoint_ids=(11, 11)))
        with self.assertRaises(ValueError):
            read(client, operation, manifest, registry)

    def test_requires_explicit_engagement_scope(self):
        client, operation, manifest, registry = setup()
        with self.assertRaises(ReadbackError):
            build_readback(client, operation, manifest, ce_release="3.3.100", evidence_ref="retained://rb", source_kind="synthetic-fixture", engagement_id=None, manifest_registry=registry)

    def test_rejects_response_test_conflict(self):
        client, operation, manifest, registry = setup()
        with self.assertRaises(ReadbackError):
            read(client, replace(operation, post_issued=True, response_ref="resp", response_test_id="8"), manifest, registry)

    def test_rejects_manifest_run_or_payload_conflict(self):
        client, operation, manifest, registry = setup()
        with self.assertRaises(ReadbackError):
            read(client, replace(operation, source_run_id="other-run"), manifest, registry)
        with self.assertRaises(ReadbackError):
            read(client, replace(operation, payload_sha256="cd" * 32), manifest, registry)

    def test_rejects_duplicate_count_in_retained_finding_page(self):
        values = fixture()
        requested = "https://dojo.test/api/v2/findings/?test=7"
        malformed = b'{"count":2,"count":2,"next":null,"results":[]}'
        values[requested] = malformed
        client, operation, manifest, registry = setup(values)
        with self.assertRaises(JSONError) as ctx:
            read(client, operation, manifest, registry)
        self.assertEqual(ctx.exception.response.body, malformed)
        self.assertEqual(ctx.exception.response.url, requested)
        self.assertEqual(ctx.exception.response.status, 200)

    def test_rejects_duplicate_key_in_test_detail(self):
        values = fixture()
        requested = "https://dojo.test/api/v2/tests/7/"
        malformed = b'{"id":7,"id":7,"engagement":2}'
        values[requested] = malformed
        client, operation, manifest, registry = setup(values)
        with self.assertRaises(JSONError) as ctx:
            read(client, operation, manifest, registry)
        self.assertEqual(ctx.exception.response.body, malformed)
        self.assertEqual(ctx.exception.response.url, requested)
        self.assertEqual(ctx.exception.response.status, 200)

    def test_zero_findings_cannot_cover_included_manifest_row(self):
        values = fixture()
        values["https://dojo.test/api/v2/findings/?test=7"] = body({"count": 0, "next": None, "results": []})
        client, operation, manifest, registry = setup(values)
        with self.assertRaises(ReadbackError):
            read(client, operation, manifest, registry)

    def test_bundle_replacement_rejects_verified_status_and_wrong_digests(self):
        client, operation, manifest, registry = setup()
        bundle = read(client, operation, manifest, registry)
        with self.assertRaises(ReadbackError):
            replace(bundle, mapping_status="verified")
        with self.assertRaises(ReadbackError):
            replace(bundle, test_sha256="0" * 64)

    def test_rejects_non_finite_json_in_test_and_finding_page(self):
        values = fixture()
        requested = "https://dojo.test/api/v2/tests/7/"
        malformed = b'{"id":7,"engagement":2,"ignored":NaN}'
        values[requested] = malformed
        client, operation, manifest, registry = setup(values)
        with self.assertRaises(JSONError) as ctx:
            read(client, operation, manifest, registry)
        self.assertEqual(ctx.exception.response.body, malformed)
        self.assertEqual(ctx.exception.response.url, requested)
        self.assertEqual(ctx.exception.response.status, 200)

        values = fixture()
        requested = "https://dojo.test/api/v2/findings/?test=7"
        malformed = b'{"count":2,"next":null,"results":[{"id":101,"test":7},{"id":102,"test":7}],"ignored":Infinity}'
        values[requested] = malformed
        client, operation, manifest, registry = setup(values)
        with self.assertRaises(JSONError) as ctx:
            read(client, operation, manifest, registry)
        self.assertEqual(ctx.exception.response.body, malformed)
        self.assertEqual(ctx.exception.response.url, requested)
        self.assertEqual(ctx.exception.response.status, 200)

    def test_requires_pre_registered_shared_manifest_binding(self):
        client, operation, manifest, registry = setup()
        with self.assertRaises(ReadbackError):
            read(client, operation, manifest, ManifestBindingRegistry())

    def test_rejects_ce_release_mismatch_before_transport(self):
        client, operation, manifest, registry = setup()
        with self.assertRaises(ReadbackError):
            build_readback(
                client,
                operation,
                manifest,
                ce_release="different-release",
                evidence_ref="retained://rb",
                source_kind="synthetic-fixture",
                engagement_id=2,
                manifest_registry=registry,
            )


if __name__ == "__main__":
    unittest.main()
