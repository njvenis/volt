import unittest

from tools.g7_container_audit_export import audit_union_state
from uvm.operations.preservation import _valid_class_dto, _valid_members, unknown_class


def member(kind, key, *, state="verified", reasons=None, record="a" * 64,
           legacy=None, version=None, representation=None):
    return {"record_key":key,"record_kind":kind,"retained_at":"2026-10-28T19:00:00Z",
        "state":state,"reasons":reasons or [],"expected_sha256":None,"actual_sha256":None,
        "record_sha256":record,"byte_bearing":False,"evidence_id":None,
        "legacy_payload_sha256":legacy,"canonicalization_version":version,
        "representation_metadata":representation}


def audit_dto(state, *, reasons=None, verified=0, missing=0, changed=0,
              expected_events=0, matching_events=0, missing_events=0, changed_events=0,
              expected_receipts=0, matching_receipts=0, missing_receipts=0,
              changed_receipts=0, pending=0):
    reasons = reasons or []
    expected = verified + missing + changed
    digest = "sha256:" + "c" * 64
    return {"class_id":"product.audit_history","minimum_period":"P1Y","state":state,
        "reasons":reasons,"expected_records":expected,"verified_records":verified,
        "missing_records":missing,"changed_records":changed,"unreadable_records":0,
        "unexpected_records":0,"oldest_retained_at":"2026-10-28T19:00:00Z",
        "baseline_digest":digest,"audit_copy":{"state":state,"reasons":reasons,
            "expected_events":expected_events,"matching_events":matching_events,
            "missing_events":missing_events,"changed_events":changed_events,"unexpected_events":0,
            "expected_receipts":expected_receipts,"matching_receipts":matching_receipts,
            "missing_receipts":missing_receipts,"changed_receipts":changed_receipts,
            "unexpected_receipts":0,"pending_receipts":pending,
            "checked_at":"2026-10-28T19:00:00Z"}}


class PreservationNegativeStateTests(unittest.TestCase):
    def test_gap_precedes_unrelated_first_ack_pending(self):
        self.assertEqual(audit_union_state(changed=True, unexpected=False, pending_receipts=1), "gap")
        self.assertEqual(audit_union_state(changed=False, unexpected=True, pending_receipts=1), "gap")

    def test_pending_only_keeps_complete_counts_and_member_facts_unknown(self):
        reasons=["source_checkpoint_missing"]
        rows=[member("audit_attribution","audit_attribution:event:deployment-v1")]
        dto=audit_dto("unknown",reasons=reasons,verified=1,expected_events=1,
            matching_events=1,pending=1)
        self.assertTrue(_valid_class_dto(dto,"product.audit_history"))
        self.assertTrue(_valid_members(rows,"product.audit_history",dto))
        self.assertEqual(dto["audit_copy"]["expected_receipts"],0)
        self.assertEqual(dto["audit_copy"]["pending_receipts"],1)

    def test_missing_established_receipt_is_gap_and_has_no_observed_record_digest(self):
        rows=[member("audit_attribution","audit_attribution:event:deployment-v1"),
            member("audit_copy_receipt_established","audit_copy_receipt_established:event:sink:abc",
                state="missing",reasons=["receipt_missing"],record=None)]
        dto=audit_dto("gap",reasons=["receipt_missing"],verified=1,missing=1,
            expected_events=1,matching_events=1,expected_receipts=1,missing_receipts=1)
        self.assertTrue(_valid_class_dto(dto,"product.audit_history"))
        self.assertTrue(_valid_members(rows,"product.audit_history",dto))

    def test_source_byte_corruption_is_changed_even_if_record_metadata_is_separate(self):
        digest="d"*64
        row={"record_key":"evidence_registration:object","record_kind":"evidence_registration",
            "retained_at":"2026-10-28T19:00:00Z","state":"changed","reasons":["bytes_changed"],
            "expected_sha256":"a"*64,"actual_sha256":"b"*64,"record_sha256":digest,
            "byte_bearing":True,"evidence_id":"00000000-0000-4000-8000-000000000001"}
        dto={"class_id":"product.source_evidence","minimum_period":"P1Y","state":"gap",
            "reasons":["bytes_changed"],"expected_records":1,"verified_records":0,
            "missing_records":0,"changed_records":1,"unreadable_records":0,"unexpected_records":0,
            "oldest_retained_at":"2026-10-28T19:00:00Z","baseline_digest":"sha256:"+"e"*64,
            "audit_copy":None}
        self.assertTrue(_valid_class_dto(dto,"product.source_evidence"))
        self.assertTrue(_valid_members([row],"product.source_evidence",dto))

    def test_incomplete_inventory_remains_unknown_with_null_counts(self):
        dto=unknown_class("product.audit_history","P1Y","audit_scope_incomplete")
        self.assertTrue(_valid_class_dto(dto,"product.audit_history"))
        self.assertTrue(_valid_members([],"product.audit_history",dto))


if __name__ == "__main__":
    unittest.main()
