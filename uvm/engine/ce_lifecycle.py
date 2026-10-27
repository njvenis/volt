"""Durable supported-API CE import, reconciliation and settlement flow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from uvm.engine.api_codec import (
    EngineRequestV1,
    ScanContextV1,
    build_import_request,
    build_reimport_request,
    parse_response,
)
from uvm.engine.ce_read_client import CEReadClient, RawResponse
from uvm.engine.context import CEObservedResponseV1
from uvm.engine.manifest import ManifestBindingRegistry
from uvm.engine.readback_builder import ReadbackBundleV1, build_readback
from uvm.persistence.engine_operation_store import (
    EngineOperationStore,
    OperationConflictError,
    OperationWriteResult,
)


class CEWriteTransport(Protocol):
    def __call__(self, request: EngineRequestV1) -> RawResponse: ...


@dataclass(frozen=True)
class CEImportLifecycleResult:
    operation: OperationWriteResult
    readback: ReadbackBundleV1 | None
    write_response: RawResponse | None


class CEImportLifecycle:
    """Coordinate durable operation writes with the supported CE API.

    The caller must register and verify the CE context before invoking this
    service. A transport exception after issue is always treated as uncertain;
    first imports reconcile the complete Test inventory, while reimports are
    quarantined and never retried automatically.
    """

    def __init__(self, operations: EngineOperationStore) -> None:
        self.operations = operations

    def first_import(
        self,
        operation,
        manifest,
        payload: bytes,
        context: ScanContextV1,
        *,
        filename: str,
        registration_id: str,
        verification_id: str,
        read_client: CEReadClient,
        write_transport: CEWriteTransport,
        manifest_registry: ManifestBindingRegistry,
        post_evidence_ref: str,
        uncertain_evidence_ref: str,
        readback_evidence_ref: str,
        cli_request_binding: dict | None = None,
    ) -> CEImportLifecycleResult:
        configured = self._verified_configuration(registration_id, verification_id)
        self._require_read_client_deployment(read_client, configured.ce_base_url)
        reserved = self.operations.register(
            operation, manifest,
            registration_id=registration_id,
            verification_id=verification_id,
            cli_request_binding=cli_request_binding)
        if reserved.status not in ("registered", "duplicate"):
            raise OperationConflictError("first-import reservation was not retained")
        current = self.operations.load(operation.operation_id).operation
        if current.post_issued or current.status != "pending":
            raise OperationConflictError(
                "first-import operation is already issued or quarantined")
        self.operations.capture_first_import_baseline(
            operation.operation_id, read_client)
        self.operations.mark_issued(operation.operation_id, post_evidence_ref)
        request = build_import_request(
            operation, payload, context, filename=filename,
            deduplication_execution_mode="sync")
        try:
            response = write_transport(request)
        except (ConnectionError, TimeoutError) as exc:
            self.operations.mark_uncertain(
                operation.operation_id,
                evidence_ref=uncertain_evidence_ref,
                reason=f"supported import POST response uncertain: {type(exc).__name__}")
            checkpoint = self.operations.capture_first_import_reconciliation(
                operation.operation_id, read_client)
            if (checkpoint.record.operation.status != "quarantined"
                    or len(checkpoint.record.operation.reconciliation_evidence_ref or "") == 0):
                raise OperationConflictError(
                    "lost-response inventory did not remain durably quarantined") from exc
            evidence = self.operations.context_store.read_first_import_reconciliation(
                operation.operation_id,
                checkpoint.record.operation.reconciliation_evidence_ref)
            if evidence.count != 1 or len(evidence.candidate_test_ids) != 1:
                return CEImportLifecycleResult(checkpoint, None, None)
            test = read_client.get_test(
                evidence.candidate_test_ids[0],
                engagement_id=evidence.engagement_id)
            binding = self.operations.context_store.bind_first_import_test(
                operation.operation_id,
                CEObservedResponseV1(
                    "test", test.response, test.response.body,
                    test.response.sha256))
            readback = self._readback(
                operation, manifest, context, read_client,
                manifest_registry, binding.test_id,
                readback_evidence_ref, evidence.engagement_id,
                configured.ce_base_url)
            settled = self.operations.settle_readback(
                operation.operation_id, readback)
            return CEImportLifecycleResult(settled, readback, None)

        if not isinstance(response, RawResponse):
            raise TypeError("CE write transport must return exact RawResponse bytes")
        if response.status < 200 or response.status >= 300:
            raise OperationConflictError(
                f"CE import returned known HTTP status {response.status}; not reconciling as lost response")
        self.operations.record_response(operation.operation_id, response.body)
        parsed = parse_response(response.body)
        if parsed.test_id is None:
            raise OperationConflictError("first-import response lacks Test ID")
        test = read_client.get_test(int(parsed.test_id))
        self.operations.context_store.bind_first_import_test(
            operation.operation_id,
            CEObservedResponseV1(
                "test", test.response, test.response.body,
                test.response.sha256))
        current = self.operations.load(operation.operation_id).operation
        if parsed.deduplication_complete is not True:
            return CEImportLifecycleResult(
                OperationWriteResult("pending", self.operations.load(operation.operation_id)),
                None, response)
        registered_context = self.operations.context_store.read_verified_context(
            registration_id, verification_id)
        readback = self._readback(
            operation, manifest, context, read_client, manifest_registry,
            parsed.test_id, readback_evidence_ref,
            registered_context.engagement_id, configured.ce_base_url)
        settled = self.operations.settle_readback(operation.operation_id, readback)
        return CEImportLifecycleResult(settled, readback, response)

    def reimport(
        self,
        operation,
        manifest,
        payload: bytes,
        *,
        filename: str,
        registration_id: str,
        verification_id: str,
        read_client: CEReadClient,
        write_transport: CEWriteTransport,
        manifest_registry: ManifestBindingRegistry,
        post_evidence_ref: str,
        uncertain_evidence_ref: str,
        readback_evidence_ref: str,
        engagement_id: int,
        do_not_reactivate: bool | None = None,
        cli_request_binding: dict | None = None,
    ) -> CEImportLifecycleResult:
        configured = self._verified_configuration(registration_id, verification_id)
        self._require_read_client_deployment(read_client, configured.ce_base_url)
        reserved = self.operations.register(
            operation, manifest,
            registration_id=registration_id,
            verification_id=verification_id,
            cli_request_binding=cli_request_binding)
        if reserved.status not in ("registered", "duplicate"):
            raise OperationConflictError("reimport reservation was not retained")
        current = self.operations.load(operation.operation_id).operation
        if current.post_issued or current.status != "pending":
            raise OperationConflictError(
                "reimport was already issued or quarantined; refusing a second POST")
        self.operations.mark_issued(operation.operation_id, post_evidence_ref)
        request = build_reimport_request(
            operation, payload, filename=filename,
            deduplication_execution_mode="sync",
            do_not_reactivate=do_not_reactivate)
        try:
            response = write_transport(request)
        except (ConnectionError, TimeoutError) as exc:
            quarantined = self.operations.mark_uncertain(
                operation.operation_id,
                evidence_ref=uncertain_evidence_ref,
                reason=f"supported reimport POST response uncertain: {type(exc).__name__}")
            return CEImportLifecycleResult(quarantined, None, None)
        if not isinstance(response, RawResponse):
            raise TypeError("CE write transport must return exact RawResponse bytes")
        if response.status < 200 or response.status >= 300:
            raise OperationConflictError(
                f"CE reimport returned known HTTP status {response.status}; not retrying")
        self.operations.record_response(operation.operation_id, response.body)
        parsed = parse_response(response.body)
        if parsed.test_id is None:
            raise OperationConflictError("reimport response lacks Test ID")
        if parsed.test_id != str(operation.test_id):
            raise OperationConflictError("reimport response Test differs from registered Test")
        if parsed.deduplication_complete is not True:
            return CEImportLifecycleResult(
                OperationWriteResult("pending", self.operations.load(operation.operation_id)),
                None, response)
        readback = self._readback(
            operation, manifest, context=None, read_client=read_client,
            manifest_registry=manifest_registry,
            test_id=parsed.test_id,
            evidence_ref=readback_evidence_ref,
            engagement_id=engagement_id,
            expected_ce_base_url=configured.ce_base_url)
        settled = self.operations.settle_readback(operation.operation_id, readback)
        return CEImportLifecycleResult(settled, readback, response)

    def _readback(
        self, operation, manifest, context, read_client,
        manifest_registry, test_id, evidence_ref, engagement_id,
        expected_ce_base_url,
    ):
        # The Test ID for recovery comes from the durable one-candidate
        # reconciliation and Test binding. It is not inferred from Finding
        # similarity or a caller-supplied title.
        if test_id is not None:
            from dataclasses import replace
            operation = replace(operation, bound_test_id=str(test_id))
        return build_readback(
            read_client, operation, manifest,
            ce_release=operation.engine_release,
            evidence_ref=evidence_ref,
            source_kind="retained-artifact",
            engagement_id=engagement_id,
            manifest_registry=manifest_registry,
            expected_ce_base_url=expected_ce_base_url)

    def _verified_configuration(self, registration_id, verification_id):
        context_store = self.operations.context_store
        if context_store is None:
            raise OperationConflictError("verified CE context is required before reading")
        evidence = context_store.read_verified_context(
            registration_id, verification_id)
        return context_store.read(
            evidence.deployment_key, evidence.deployment_config_revision
        ).snapshot.configured

    @staticmethod
    def _require_read_client_deployment(read_client, ce_base_url):
        if getattr(read_client, "base_url", None) != ce_base_url.rstrip("/"):
            raise OperationConflictError(
                "CE read client does not match the verified deployment URL")
