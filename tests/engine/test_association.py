"""Focused behavioural tests for the FindingDetailAssociationV1
per-Finding read-back normaliser.

Synthetic fixtures only: no HTTP, no persistence, no live engine.
Proves the association stays per-Finding (f1 cannot claim f2's
Endpoint), a shared CVE reference does not merge components, the Qualys
host-only Endpoint shape and the Sysdig endpoint-less component shape
stay distinct, and malformed or partial read-backs can never yield a
trusted association. The CE ``verified`` flag is treated as CE's manual
vulnerability verification only — never as read-back or association
trust — and ``evidence_sha256`` is bound to the raw read-back bytes.
"""

from __future__ import annotations

import hashlib
import json
import unittest

from uvm.engine.association import (
    SCHEMA_VERSION,
    EndpointFindingAssociationV1,
    EndpointIdentityV1,
    FindingDetailAssociationV1,
    findings_readback_covers,
    parse_endpoint_detail,
    parse_endpoint_identity_detail,
    parse_finding_detail,
)

REL = "3.3.100"
REF = "evidence/synthetic/finding-detail"
SRC = "synthetic-fixture"


def _raw(body):
    return json.dumps(body, sort_keys=True).encode("utf-8")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def qualys_body(id_=1, test=1, endpoints=(1,), component=None, version=None,
                verified=True, vulns=()):
    """A Qualys-style host-only Finding detail: endpoints present, no
    component, port only in the description text."""
    body = {
        "id": id_,
        "test": test,
        "endpoints": list(endpoints),
        "component_name": component,
        "component_version": version,
        "verified": verified,
        "title": f"QID-1001 | Vuln {id_}",
        "description": "synthetic threat\n\nQID: qid_1001\n\nPort: 443\n",
    }
    if vulns:
        body["vulnerability_ids"] = [
            {"vulnerability_id": v} for v in vulns
        ]
    return body


def sysdig_body(id_=7, test=2, name="openssl", version="1.1.1k",
                verified=False):
    """A Sysdig-style component Finding detail: no endpoints, known
    component."""
    return {
        "id": id_,
        "test": test,
        "endpoints": [],
        "component_name": name,
        "component_version": version,
        "verified": verified,
        "title": "CVE-2024-0002 | vulnerable component",
        "vulnerability_ids": [{"vulnerability_id": "CVE-2024-0002"}],
    }


def _parse(body, id_=None, test=None, **kw):
    raw = _raw(body)
    kw.setdefault("ce_release", REL)
    kw.setdefault("evidence_ref", REF)
    kw.setdefault("evidence_sha256", _digest(raw))
    kw.setdefault("source_kind", SRC)
    return parse_finding_detail(
        raw,
        requested_finding_id=id_ if id_ is not None else body["id"],
        requested_test_id=test if test is not None else body["test"],
        **kw,
    )


class TestPerFindingAssociation(unittest.TestCase):
    def test_qualys_host_only_shape_parses(self):
        dto = _parse(qualys_body())
        self.assertEqual(dto.ce_release, REL)
        self.assertEqual(dto.finding_id, 1)
        self.assertEqual(dto.test_id, 1)
        self.assertEqual(dto.endpoint_ids, (1,))
        self.assertIsNone(dto.component_name)
        self.assertIsNone(dto.component_version)
        self.assertTrue(dto.ce_verified)
        self.assertEqual(dto.evidence_ref, REF)
        # evidence_sha256 is the digest of the actual read-back bytes,
        # not an arbitrary ref.
        self.assertEqual(dto.evidence_sha256, _digest(_raw(qualys_body())))

    def test_sysdig_endpointless_component_shape_parses(self):
        dto = _parse(sysdig_body())
        self.assertEqual(dto.finding_id, 7)
        self.assertEqual(dto.endpoint_ids, ())
        self.assertEqual(dto.component_name, "openssl")
        self.assertEqual(dto.component_version, "1.1.1k")
        self.assertFalse(dto.ce_verified)

    def test_qualys_and_sysdig_shapes_stay_distinct(self):
        qualys = _parse(qualys_body())
        sysdig = _parse(sysdig_body())
        # Different shape, different association: one is host-only
        # endpoint without component, the other a component without
        # endpoints. Neither field conflates with the other.
        self.assertNotEqual(qualys, sysdig)
        self.assertEqual(qualys.endpoint_ids, (1,))
        self.assertIsNone(qualys.component_name)
        self.assertEqual(sysdig.endpoint_ids, ())
        self.assertEqual(sysdig.component_name, "openssl")

    def test_description_port_is_never_inferred(self):
        # The description names Port 443 and a QID; the DTO must keep
        # the component unknown and carry no port or occurrence field.
        dto = _parse(qualys_body())
        self.assertIsNone(dto.component_name)
        self.assertFalse(hasattr(dto, "port"))
        self.assertFalse(hasattr(dto, "occurrence_id"))

    def test_missing_component_key_stays_unknown(self):
        body = qualys_body()
        body.pop("component_name")
        body.pop("component_version")
        dto = _parse(body)
        self.assertIsNone(dto.component_name)
        self.assertIsNone(dto.component_version)

    def test_ce_verified_is_manual_verification_not_readback_trust(self):
        # CE's ``verified`` is its manual vulnerability verification
        # flag. It must be carried as ``ce_verified`` and the DTO must
        # not expose it as a read-back/association trust: the bounded
        # source_kind labels inert retained-artifact origin only.
        dto = _parse(qualys_body(verified=True), source_kind=SRC)
        self.assertTrue(dto.ce_verified)
        self.assertFalse(hasattr(dto, "verified"))
        self.assertEqual(dto.source_kind, SRC)

    def test_source_kind_is_explicit_and_bounded(self):
        body = qualys_body()
        raw = _raw(body)
        with self.assertRaises((ValueError, TypeError)):
            parse_finding_detail(
                raw, ce_release=REL,
                requested_finding_id=1, requested_test_id=1,
                evidence_ref=REF, evidence_sha256=_digest(raw),
            )
        with self.assertRaises(ValueError):
            _parse(body, source_kind="")
        # A caller-controlled label must never imply a trusted live
        # read-back: only the bounded kinds are accepted, and none of
        # them carries trust or liveness language.
        for label in ("trusted-live-readback", "live-api-readback",
                      "verified-live", "trusted"):
            with self.assertRaises(ValueError, msg=label):
                _parse(body, source_kind=label)

    def test_source_kind_equality_spoof_is_rejected(self):
        class EqualitySpoof:
            def __eq__(self, other):
                return other == "retained-artifact"

        with self.assertRaises(ValueError):
            _parse(qualys_body(), source_kind=EqualitySpoof())


class TestRawBodySingleSource(unittest.TestCase):
    """The raw body bytes are the ONLY source of parsed fields and
    digest; no separate divergent body input exists."""

    def test_no_separate_body_input_is_accepted(self):
        # The old two-input form (decoded mapping plus raw bytes) must
        # no longer be callable: the raw bytes alone are the source.
        body = qualys_body()
        raw = _raw(body)
        with self.assertRaises(TypeError):
            parse_finding_detail(
                body, body_bytes=raw, ce_release=REL,
                requested_finding_id=1, requested_test_id=1,
                evidence_ref=REF, evidence_sha256=_digest(raw),
                source_kind=SRC,
            )

    def test_fields_come_from_the_retained_bytes(self):
        # A divergent decoded mapping is not an input: the DTO fields
        # are exactly those in the retained raw bytes.
        body = qualys_body(id_=3, endpoints=(9,))
        raw = _raw(body)
        dto = parse_finding_detail(
            raw, ce_release=REL, requested_finding_id=3,
            requested_test_id=1, evidence_ref=REF,
            evidence_sha256=_digest(raw), source_kind=SRC,
        )
        self.assertEqual(dto.finding_id, 3)
        self.assertEqual(dto.endpoint_ids, (9,))
        self.assertEqual(dto.evidence_sha256, _digest(raw))

    def test_raw_bytes_must_be_valid_json(self):
        for bad in (b"not json", b"", b"\xff\xfe{\"id\": 1}"):
            with self.assertRaises(ValueError, msg=bad):
                parse_finding_detail(
                    bad, ce_release=REL, requested_finding_id=1,
                    requested_test_id=1, evidence_ref=REF,
                    evidence_sha256=hashlib.sha256(bad).hexdigest(),
                    source_kind=SRC,
                )

    def test_raw_non_object_json_is_rejected(self):
        for bad in (b"[1, 2]", b'"a string"', b"42"):
            with self.assertRaises(ValueError, msg=bad):
                parse_finding_detail(
                    bad, ce_release=REL, requested_finding_id=1,
                    requested_test_id=1, evidence_ref=REF,
                    evidence_sha256=hashlib.sha256(bad).hexdigest(),
                    source_kind=SRC,
                )

    def test_raw_non_finite_json_constants_are_rejected(self):
        # The shared decoder policy applies to Finding details too: a
        # non-finite constant in an unrelated field is invalid JSON even
        # when the association fields and digest match.
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            raw = (
                b'{"id": 1, "test": 1, "endpoints": [], '
                b'"component_name": null, "component_version": null, '
                b'"verified": false, "metadata": ' + constant + b'}'
            )
            with self.assertRaises(ValueError, msg=constant):
                parse_finding_detail(
                    raw, ce_release=REL, requested_finding_id=1,
                    requested_test_id=1, evidence_ref=REF,
                    evidence_sha256=_digest(raw), source_kind=SRC,
                )

    def test_duplicate_json_keys_are_rejected(self):
        # Conflicting duplicate keys in the raw bytes must not be silently
        # resolved last-wins: {"id": 1, "id": 999} would otherwise decode to
        # id=999 and pass the id/test match. Duplicate keys are malformed.
        raw = (b'{"id": 1, "test": 1, "endpoints": [1], '
               b'"component_name": null, "component_version": null, '
               b'"verified": true, "id": 999}')
        with self.assertRaises(ValueError):
            parse_finding_detail(
                raw, ce_release=REL, requested_finding_id=999,
                requested_test_id=1, evidence_ref=REF,
                evidence_sha256=hashlib.sha256(raw).hexdigest(),
                source_kind=SRC,
            )
        # A duplicate key is rejected even when the values agree, and a
        # nested duplicate is rejected too — any duplicate object key is
        # malformed, not a conflict-only rule.
        for body in (
            b'{"id": 1, "id": 1, "test": 1, "endpoints": [], '
            b'"component_name": null, "component_version": null, '
            b'"verified": false}',
            b'{"id": 1, "test": 1, "endpoints": [1], '
            b'"component_name": null, "component_version": null, '
            b'"verified": false, "vulnerability_ids": '
            b'[{"vulnerability_id": 1, "vulnerability_id": 2}]}',
        ):
            with self.assertRaises(ValueError, msg=body):
                parse_finding_detail(
                    body, ce_release=REL, requested_finding_id=1,
                    requested_test_id=1, evidence_ref=REF,
                    evidence_sha256=hashlib.sha256(body).hexdigest(),
                    source_kind=SRC,
                )


class TestFindingEndpointBinding(unittest.TestCase):
    def test_f1_cannot_claim_f2_endpoints(self):
        f1 = _parse(qualys_body(id_=1, endpoints=(1,)))
        f2 = _parse(qualys_body(id_=2, endpoints=(2,), vulns=("CVE-2024-0001",)))
        # Each DTO carries exactly its own Finding's Endpoint set.
        self.assertEqual(f1.endpoint_ids, (1,))
        self.assertEqual(f2.endpoint_ids, (2,))
        self.assertNotIn(2, f1.endpoint_ids)
        self.assertNotIn(1, f2.endpoint_ids)
        # f1's read-back cannot be re-bound to f2: the mismatch is
        # malformed, never relabelled.
        with self.assertRaises(ValueError):
            _parse(qualys_body(id_=1, endpoints=(1,)), id_=2)
        # And f2's read-back cannot claim f1's endpoints.
        with self.assertRaises(ValueError):
            _parse(qualys_body(id_=2, endpoints=(2,)), id_=1)

    def test_mismatched_test_id_is_malformed(self):
        with self.assertRaises(ValueError):
            _parse(qualys_body(test=1), test=2)

    def test_shared_cve_does_not_merge_components(self):
        # Two Findings reference the same CVE but carry distinct
        # components. The normaliser never consumes the CVE reference:
        # each association keeps its own component, nothing merges.
        a = _parse(
            qualys_body(id_=1, endpoints=(1,), component="alpha",
                        version="1.0", vulns=("CVE-2024-0001",))
        )
        b = _parse(
            qualys_body(id_=5, endpoints=(2,), component="beta",
                        version="2.0", vulns=("CVE-2024-0001",))
        )
        self.assertEqual(a.component_name, "alpha")
        self.assertEqual(b.component_name, "beta")
        self.assertNotEqual(a.component_name, b.component_name)
        self.assertNotEqual(a, b)
        # No CVE-derived identity field exists to merge on.
        self.assertFalse(hasattr(a, "vulnerability_ids"))

    def test_missing_vs_empty_endpoints_are_distinct(self):
        body = qualys_body()
        body.pop("endpoints")
        with self.assertRaises(ValueError):
            _parse(body)
        empty = _parse(qualys_body(endpoints=()))
        self.assertEqual(empty.endpoint_ids, ())


class TestEndpointReverseFindingAssociation(unittest.TestCase):
    def test_reverse_parser_rejects_digest_endpoint_and_duplicate_mismatches(self):
        body = {"id": 1, "findings": [1, 2]}
        raw = _raw(body)
        cases = (
            (dict(evidence_sha256=_digest(b'{"id": 9}')), "digest"),
            (dict(requested_endpoint_id=9), "endpoint"),
            (dict(body=dict(body, findings=[1, 1])), "duplicate"),
        )
        for overrides, label in cases:
            case_body = overrides.pop("body", body)
            case_raw = _raw(case_body)
            kwargs = dict(
                ce_release=REL, requested_endpoint_id=1,
                evidence_ref=REF, evidence_sha256=_digest(case_raw),
                source_kind=SRC,
            )
            kwargs.update(overrides)
            with self.assertRaises(ValueError, msg=label):
                parse_endpoint_detail(case_raw, **kwargs)

    def test_reverse_parser_rejects_cross_shape_and_missing_or_malformed_fields(self):
        for body in (
            {"id": 1, "findings": [{"id": 1}]},
            {"id": 1, "finding_ids": [1]},
            {"id": 1, "findings": "1"},
            {"id": 1, "findings": [True]},
            {"id": 1},
        ):
            raw = _raw(body)
            with self.assertRaises(ValueError):
                parse_endpoint_detail(
                    raw, ce_release=REL, requested_endpoint_id=1,
                    evidence_ref=REF, evidence_sha256=_digest(raw),
                    source_kind=SRC,
                )

    def test_reverse_parser_rejects_duplicate_json_keys_and_untrusted_source(self):
        raw = b'{"id": 1, "findings": [1], "findings": [2]}'
        with self.assertRaises(ValueError):
            parse_endpoint_detail(
                raw, ce_release=REL, requested_endpoint_id=1,
                evidence_ref=REF, evidence_sha256=_digest(raw), source_kind=SRC,
            )
        raw = _raw({"id": 1, "findings": [1]})
        with self.assertRaises(ValueError):
            parse_endpoint_detail(
                raw, ce_release=REL, requested_endpoint_id=1,
                evidence_ref=REF, evidence_sha256=_digest(raw),
                source_kind="live-api-readback",
            )

    def test_reverse_parser_rejects_source_kind_equality_spoof(self):
        class EqualitySpoof:
            def __eq__(self, other):
                return other == "retained-artifact"

        raw = _raw({"id": 1, "findings": [1]})
        with self.assertRaises(ValueError):
            parse_endpoint_detail(
                raw, ce_release=REL, requested_endpoint_id=1,
                evidence_ref=REF, evidence_sha256=_digest(raw),
                source_kind=EqualitySpoof(),
            )

    def test_reverse_parser_rejects_non_finite_json_constants(self):
        # Python's default JSON decoder accepts NaN, Infinity and -Infinity.
        # They are not valid JSON and must not hide in an unrelated field
        # while the association's IDs and digest otherwise match.
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            raw = b'{"id": 1, "findings": [1], "metadata": ' + constant + b'}'
            with self.assertRaises(ValueError, msg=constant):
                parse_endpoint_detail(
                    raw, ce_release=REL, requested_endpoint_id=1,
                    evidence_ref=REF, evidence_sha256=_digest(raw),
                    source_kind=SRC,
                )

    def test_endpoint_identity_parser_proves_only_exact_returned_id(self):
        raw = _raw({"id": 11, "host": "synthetic.example.test"})
        dto = parse_endpoint_identity_detail(
            raw, ce_release=REL, requested_endpoint_id=11,
            evidence_ref=REF, evidence_sha256=_digest(raw), source_kind=SRC,
        )
        self.assertIsInstance(dto, EndpointIdentityV1)
        self.assertEqual(dto.endpoint_id, 11)
        self.assertFalse(hasattr(dto, "finding_ids"))

    def test_endpoint_identity_rejects_missing_wrong_or_reverse_shape(self):
        for body, requested in (({"host": "synthetic.example.test"}, 11),
                                ({"id": 12}, 11),
                                ({"id": 11, "findings": []}, 11)):
            raw = _raw(body)
            with self.assertRaises(ValueError):
                parse_endpoint_identity_detail(
                    raw, ce_release=REL, requested_endpoint_id=requested,
                    evidence_ref=REF, evidence_sha256=_digest(raw), source_kind=SRC,
                )


class TestEvidenceDigestBinding(unittest.TestCase):
    """evidence_sha256 must be the digest of the actual raw bytes."""

    def _body(self):
        return qualys_body()

    def test_non_digest_is_rejected(self):
        for bad in ("retained-artifact", "", "ab" * 31, "AB" * 32,
                    "ab" * 32 + "0", "not a digest"):
            with self.assertRaises(ValueError, msg=bad):
                _parse(self._body(), evidence_sha256=bad)

    def test_mismatched_digest_is_rejected(self):
        body = self._body()
        other_bytes = b'{"id": 999}'
        with self.assertRaises(ValueError):
            _parse(body, evidence_sha256=_digest(other_bytes))

    def test_digest_of_different_bytes_is_rejected(self):
        # The digest must match the retained bytes the body was
        # decoded from, not any other payload.
        body = self._body()
        mutated = dict(body, endpoints=(2,))
        with self.assertRaises(ValueError):
            _parse(body, evidence_sha256=_digest(_raw(mutated)))

    def test_body_bytes_must_be_raw_bytes(self):
        body = self._body()
        raw = _raw(body)
        for bad in (raw.decode("utf-8"), bytearray(raw), None, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                parse_finding_detail(
                    bad, ce_release=REL,
                    requested_finding_id=1, requested_test_id=1,
                    evidence_ref=REF,
                    evidence_sha256=_digest(raw if bad is not None else b""),
                    source_kind=SRC,
                )

    def test_constructor_rejects_non_digest_sha256(self):
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=SCHEMA_VERSION, ce_release=REL, test_id=1,
                finding_id=1, endpoint_ids=(), component_name=None,
                component_version=None, evidence_ref=REF,
                evidence_sha256="retained-artifact", ce_verified=True,
                source_kind=SRC,
            )

    def test_public_constructor_rejects_unbound_digest(self):
        # A syntactically valid digest of an UNRELATED body plus arbitrary
        # fields must not yield a body-verified association: the parser is
        # the only verified construction path, and it binds evidence_sha256
        # to the raw read-back bytes it parsed. Direct public construction
        # cannot prove that binding, so it is rejected.
        unrelated = hashlib.sha256(b'{"id": 999}').hexdigest()
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=SCHEMA_VERSION, ce_release=REL, test_id=1,
                finding_id=1, endpoint_ids=(1,), component_name=None,
                component_version=None, evidence_ref=REF,
                evidence_sha256=unrelated, ce_verified=True,
                source_kind=SRC,
            )


class TestMalformedAndPartial(unittest.TestCase):
    def _malformed(self, mutate):
        body = qualys_body(verified=True)
        mutate(body)
        with self.assertRaises(ValueError):
            _parse(body, id_=1, test=1)

    def test_partial_readbacks_cannot_yield_trusted_dto(self):
        # Each of these would otherwise carry CE's verified=true
        # flag; every one must raise, never yield a DTO.
        self._malformed(lambda b: b.pop("endpoints"))
        self._malformed(lambda b: b.pop("verified"))
        self._malformed(lambda b: b.update(id="1"))
        self._malformed(lambda b: b.update(id=True))
        self._malformed(lambda b: b.update(id=None))
        self._malformed(lambda b: b.update(test=2))
        self._malformed(lambda b: b.update(endpoints="1"))
        self._malformed(lambda b: b.update(endpoints={"id": 1}))
        self._malformed(lambda b: b.update(endpoints=[1, "x"]))
        self._malformed(lambda b: b.update(endpoints=[1, True]))
        self._malformed(lambda b: b.update(endpoints=[1, 1]))
        self._malformed(lambda b: b.update(component_name=443))
        self._malformed(lambda b: b.update(component_name=""))
        self._malformed(lambda b: b.update(verified="true"))
        self._malformed(lambda b: b.update(verified=1))
        # A retained read-back whose raw bytes decode to a non-object
        # is malformed: it never yields a DTO.
        non_object = json.dumps(["not", "an", "object"]).encode("utf-8")
        with self.assertRaises(ValueError):
            parse_finding_detail(
                non_object, ce_release=REL,
                requested_finding_id=1, requested_test_id=1,
                evidence_ref=REF,
                evidence_sha256=hashlib.sha256(non_object).hexdigest(),
                source_kind=SRC,
            )

    def test_explicit_false_verified_stays_false(self):
        dto = _parse(qualys_body(verified=False))
        self.assertFalse(dto.ce_verified)

    def test_constructor_guards(self):
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=2, ce_release=REL, test_id=1, finding_id=1,
                endpoint_ids=(), component_name=None, component_version=None,
                evidence_ref=REF, evidence_sha256=_digest(b"x"),
                ce_verified=True, source_kind=SRC,
            )
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=SCHEMA_VERSION, ce_release=REL, test_id=1,
                finding_id=1, endpoint_ids=(), component_name=None,
                component_version=None, evidence_ref="",
                evidence_sha256=_digest(b"x"), ce_verified=True,
                source_kind=SRC,
            )
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=SCHEMA_VERSION, ce_release=REL, test_id=1,
                finding_id=1, endpoint_ids=(1, 1), component_name=None,
                component_version=None, evidence_ref=REF,
                evidence_sha256=_digest(b"x"), ce_verified=True,
                source_kind=SRC,
            )
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=SCHEMA_VERSION, ce_release=REL, test_id=1,
                finding_id=1, endpoint_ids=(1,), component_name=None,
                component_version=None, evidence_ref=REF,
                evidence_sha256=_digest(b"x"), ce_verified="true",
                source_kind=SRC,
            )
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=SCHEMA_VERSION, ce_release=REL, test_id=1,
                finding_id=1, endpoint_ids=[1], component_name=None,
                component_version=None, evidence_ref=REF,
                evidence_sha256=_digest(b"x"), ce_verified=True,
                source_kind=SRC,
            )
        with self.assertRaises(ValueError):
            FindingDetailAssociationV1(
                schema_version=SCHEMA_VERSION, ce_release=REL, test_id=1,
                finding_id=1, endpoint_ids=(), component_name=None,
                component_version=None, evidence_ref=REF,
                evidence_sha256=_digest(b"x"), ce_verified=True,
                source_kind="trusted-live-readback",
            )


def _page(count, results, nxt, test=1):
    return {"count": count, "next": nxt, "previous": None,
            "results": [{"id": i, "test": test} for i in results],
            "prefetch": {}}


class TestReadbackCoverage(unittest.TestCase):
    def test_single_final_page_covers(self):
        ok, reason = findings_readback_covers(
            [_page(3, [1, 2, 3], None)], (1, 2, 3), 1
        )
        self.assertTrue(ok, reason)

    def test_multi_page_covers(self):
        ok, reason = findings_readback_covers(
            [_page(4, [1, 2], "http://x/p2"), _page(4, [3, 4], None)],
            (1, 2, 3, 4), 1,
        )
        self.assertTrue(ok, reason)

    def test_incomplete_expected_set(self):
        ok, _ = findings_readback_covers(
            [_page(3, [1, 2, 3], None)], (1, 2), 1
        )
        self.assertFalse(ok)

    def test_extra_finding_not_expected(self):
        ok, _ = findings_readback_covers(
            [_page(3, [1, 2, 3], None)], (1, 2, 4), 1
        )
        self.assertFalse(ok)

    def test_count_mismatch(self):
        ok, _ = findings_readback_covers(
            [_page(4, [1, 2, 3], None)], (1, 2, 3), 1
        )
        self.assertFalse(ok)

    def test_page_counts_must_agree_across_pages(self):
        # A later page reporting a different total count cannot be
        # complete even when the IDs look right.
        ok, _ = findings_readback_covers(
            [_page(4, [1, 2], "http://x/p2"), _page(5, [3, 4], None)],
            (1, 2, 3, 4), 1,
        )
        self.assertFalse(ok)

    def test_mixed_test_ids_cannot_be_complete(self):
        # A row belonging to a different Test contaminates the
        # read-back: it is not a cover of the requested Test.
        page = _page(3, [1, 2, 3], None)
        page["results"][1] = {"id": 2, "test": 99}
        ok, _ = findings_readback_covers([page], (1, 2, 3), 1)
        self.assertFalse(ok)

    def test_row_without_test_id_is_not_complete(self):
        page = _page(2, [1, 2], None)
        page["results"][0] = {"id": 1}
        ok, _ = findings_readback_covers([page], (1, 2), 1)
        self.assertFalse(ok)

    def test_requested_test_id_must_be_valid(self):
        ok, _ = findings_readback_covers(
            [_page(1, [1], None)], (1,), "1"
        )
        self.assertFalse(ok)

    def test_last_page_not_final(self):
        ok, _ = findings_readback_covers(
            [_page(3, [1, 2, 3], "http://x/p2")], (1, 2, 3), 1
        )
        self.assertFalse(ok)

    def test_nonfinal_next_must_be_nonempty_link(self):
        # A non-final page whose next is false, empty, or not a string
        # cannot signal a continuation: false or empty cannot stand in
        # for a link, so the read-back is never complete.
        for bad_next in (False, "", None, 0, ["http://x/p2"]):
            pages = [
                {"count": 2, "next": bad_next, "previous": None,
                 "results": [{"id": 1, "test": 1}], "prefetch": {}},
                {"count": 2, "next": None, "previous": "http://x/p1",
                 "results": [{"id": 2, "test": 1}], "prefetch": {}},
            ]
            ok, reason = findings_readback_covers(pages, (1, 2), 1)
            self.assertFalse(ok, (bad_next, reason))

    def test_final_page_missing_next_key_is_not_complete(self):
        # A final page without the explicit ``next`` key is a partial
        # read-back: missing and null are distinct, and missing never
        # satisfies coverage.
        page = {"count": 3, "previous": None,
                "results": [{"id": i, "test": 1} for i in (1, 2, 3)],
                "prefetch": {}}
        ok, reason = findings_readback_covers([page], (1, 2, 3), 1)
        self.assertFalse(ok)
        self.assertIn("next", reason)
        # Same for the final page of a multi-page run.
        ok, _ = findings_readback_covers(
            [_page(4, [1, 2], "http://x/p2"),
             {"count": 4, "previous": None,
              "results": [{"id": 3, "test": 1}, {"id": 4, "test": 1}],
              "prefetch": {}}],
            (1, 2, 3, 4), 1,
        )
        self.assertFalse(ok)

    def test_final_page_declared_early(self):
        ok, _ = findings_readback_covers(
            [_page(3, [1, 2, 3], None), _page(3, [4], None)],
            (1, 2, 3, 4), 1,
        )
        self.assertFalse(ok)

    def test_duplicate_id_across_pages(self):
        ok, _ = findings_readback_covers(
            [_page(2, [1], "http://x/p2"), _page(2, [1], None)], (1,), 1
        )
        self.assertFalse(ok)

    def test_malformed_page(self):
        for pages, expected, tid in (
            ([], (1,), 1),
            (["nope"], (1,), 1),
            ([_page(1, [1], None)], ["1"], 1),
            ([{"count": "1", "next": None,
               "results": [{"id": 1, "test": 1}]}], (1,), 1),
            ([_page(1, [{"id": "1", "test": 1}], None)], (1,), 1),
            ([_page(1, [{"id": True, "test": 1}], None)], (1,), 1),
            ([_page(1, [1], None)], True, 1),
        ):
            ok, _ = findings_readback_covers(pages, expected, tid)
            self.assertFalse(ok, pages)


# Read-only smoke against the retained G1 comparison artifacts. This is
# separate from the synthetic proof above: it only re-parses bodies
# already captured and labelled as evidence of CE 3.3.200 comparison-run
# behaviour; it makes no live API or external-system claim.
if __name__ == "__main__":
    unittest.main()
