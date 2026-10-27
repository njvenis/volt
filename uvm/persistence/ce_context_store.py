"""Durable, versioned local DefectDojo deployment configuration snapshots.

The store records caller-supplied local operator configuration only.  It does
not discover or prove the identity of a live DefectDojo deployment.  Artifact
publication precedes the database transaction; a database failure can
therefore leave unreferenced content-addressed bytes, which are retained for
later recovery rather than deleted here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import Select, and_, select, text
from sqlalchemy.engine import Engine

from uvm.persistence.ce_context_artifacts import CEContextArtifactStore
from uvm.persistence.ce_deployment_config import (
    LOCAL_OPERATOR_CONFIGURATION_SNAPSHOT,
    LocalCEDeploymentConfigSnapshotV1,
)
from uvm.persistence.engine_operation_schema import ce_deployment_configurations
from uvm.persistence.engine_operation_schema import (
    ce_context_registrations,
    ce_context_test_bindings,
    ce_context_verifications,
    engine_operation_requests,
    engine_operation_manifests,
    engine_operation_states,
    engine_operation_transitions,
)
from uvm.engine.context import (
    CEDeploymentMismatchError,
    CEContextObservationV1,
    CEObservedResponseV1,
    CEContextRegistrationV1,
    ConfiguredCEDeploymentV1,
)
from uvm.engine.api_codec import parse_response
from uvm.engine.ce_read_client import CEReadClient, Collection, RawResponse


class CEContextStoreError(Exception):
    """Base class for fail-closed configuration store errors."""


class CEContextRevisionConflict(CEContextStoreError, ValueError):
    """The requested revision is not the exact next immutable revision."""


class CEContextConfigurationNotFound(CEContextStoreError, LookupError):
    """No configuration row exists for the requested deployment/revision."""


class CEContextArtifactMismatch(CEContextStoreError, ValueError):
    """The stored artifact does not reproduce the immutable row metadata."""


class CEContextRegistrationConflict(CEContextStoreError, ValueError):
    """The candidate conflicts with an existing durable CE context."""


class CEContextEvidenceNotFound(CEContextStoreError, LookupError):
    """No exact registration and verification pair exists."""


class CEContextTestBindingConflict(CEContextStoreError, ValueError):
    """A first-import Test cannot be bound to this durable context."""


@dataclass(frozen=True)
class CEContextEvidenceRecord:
    """Durable local registration and its synthetic GET evidence references."""

    registration_id: str
    verification_id: str
    deployment_key: str
    context_key: str
    product_id: int
    engagement_id: int
    test_id: int | None
    deployment_config_revision: int
    product_body_ref: str
    product_body_sha256: str
    engagement_body_ref: str
    engagement_body_sha256: str
    test_body_ref: str | None
    test_body_sha256: str | None
    verified_at: datetime

    @property
    def provenance(self) -> str:
        return "caller-provided configuration + synthetic GET result; durable local record"


@dataclass(frozen=True)
class CEDeploymentConfigurationRecord:
    """A persisted row plus its verified local configuration snapshot."""

    configuration_id: str
    deployment_key: str
    revision: int
    recorded_at: datetime
    snapshot: LocalCEDeploymentConfigSnapshotV1

    @property
    def configured(self):
        return self.snapshot.configured

    @property
    def provenance(self) -> str:
        return self.snapshot.provenance


@dataclass(frozen=True)
class CEContextTestBindingRecord:
    """The immutable result of one first-import Test read-back binding."""

    binding_id: str
    registration_id: str
    originating_operation_id: str
    deployment_key: str
    test_id: int
    test_body_ref: str
    test_body_sha256: str
    deployment_config_revision: int
    bound_at: datetime


@dataclass(frozen=True)
class CEFirstImportBaselineRecord:
    """Retained complete synthetic Test inventory captured before first POST."""

    baseline_ref: str
    baseline_sha256: str
    registration_id: str
    verification_id: str
    deployment_key: str
    context_key: str
    engagement_id: int
    deployment_config_revision: int
    request_url: str
    pages: tuple[RawResponse, ...]
    count: int
    candidate_test_ids: tuple[int, ...]

    @property
    def provenance(self) -> str:
        return "configured CEReadClient + synthetic transport; durable local artifact"


@dataclass(frozen=True)
class CEFirstImportReconciliationRecord:
    """Complete retained Test inventory for a quarantined first import."""

    reconciliation_ref: str
    reconciliation_sha256: str
    operation_id: str
    registration_id: str
    verification_id: str
    deployment_key: str
    context_key: str
    engagement_id: int
    deployment_config_revision: int
    baseline_ref: str
    request_url: str
    pages: tuple[RawResponse, ...]
    count: int
    candidate_test_ids: tuple[int, ...]

    @property
    def classification(self) -> str:
        if not self.candidate_test_ids:
            return "zero_candidates"
        if len(self.candidate_test_ids) == 1:
            return "one_candidate"
        return "multiple_candidates"

    @property
    def provenance(self) -> str:
        return "configured CEReadClient + synthetic transport; durable local artifact"


class CEContextStore:
    """Persist and retrieve immutable local CE deployment configuration rows."""

    def __init__(self, engine: Engine, artifact_store: CEContextArtifactStore) -> None:
        self.engine = engine
        self.artifact_store = artifact_store

    @staticmethod
    def _canonical_bytes(snapshot: LocalCEDeploymentConfigSnapshotV1) -> bytes:
        # The loader already supplies canonical bytes.  Re-serialising from
        # the validated DTO prevents callers from smuggling extra fields when
        # constructing the immutable DTO directly.
        configured = snapshot.configured
        return json.dumps(
            {
                "schema_version": configured.schema_version,
                "deployment_key": configured.deployment_key,
                "ce_base_url": configured.ce_base_url,
                "ce_release": configured.ce_release,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _validated_payload(cls, snapshot: LocalCEDeploymentConfigSnapshotV1) -> tuple[bytes, str]:
        if not isinstance(snapshot, LocalCEDeploymentConfigSnapshotV1):
            raise TypeError("snapshot must be LocalCEDeploymentConfigSnapshotV1")
        if snapshot.provenance != LOCAL_OPERATOR_CONFIGURATION_SNAPSHOT:
            raise ValueError("snapshot must be recorded local operator configuration")
        payload = cls._canonical_bytes(snapshot)
        digest = hashlib.sha256(payload).hexdigest()
        if payload != snapshot.config_bytes or digest != snapshot.config_sha256:
            raise ValueError("snapshot bytes are not canonical or do not match digest")
        return payload, digest

    def _read_history(self, deployment_key: str) -> list[dict[str, Any]]:
        """Return and verify the complete append-only writer history.

        The writer/API protects append order, and replay catches gaps or
        row/artifact mismatches.  Direct privileged database mutations are
        outside this store's trust boundary and can remain undetected; this
        is not proof of tamper-proof database history.
        """
        with self.engine.begin() as connection:
            rows = connection.execute(
                select(ce_deployment_configurations)
                .where(ce_deployment_configurations.c.deployment_key == deployment_key)
                .order_by(ce_deployment_configurations.c.revision.asc())
            ).mappings().all()
        if [row["revision"] for row in rows] != list(range(1, len(rows) + 1)):
            raise CEContextRevisionConflict(
                f"configuration history for {deployment_key!r} is not contiguous"
            )
        for row in rows:
            self._snapshot_from_row(row)
        return rows

    def _snapshot_from_row(self, row: Any) -> LocalCEDeploymentConfigSnapshotV1:
        payload = self.artifact_store.get(row["config_ref"], row["config_sha256"])
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CEContextArtifactMismatch("configuration artifact is not valid JSON") from exc
        if (
            document.get("schema_version") != row["schema_version"]
            or document.get("deployment_key") != row["deployment_key"]
            or document.get("ce_base_url") != row["ce_base_url"]
            or document.get("ce_release") != row["ce_release"]
        ):
            raise CEContextArtifactMismatch("artifact metadata does not match database row")
        from uvm.engine.context import ConfiguredCEDeploymentV1
        try:
            configured = ConfiguredCEDeploymentV1(**document)
            snapshot = LocalCEDeploymentConfigSnapshotV1(
                configured=configured,
                config_bytes=payload,
                config_sha256=row["config_sha256"],
            )
        except (TypeError, ValueError) as exc:
            raise CEContextArtifactMismatch("artifact is not a valid configuration snapshot") from exc
        if payload != self._canonical_bytes(snapshot):
            raise CEContextArtifactMismatch("artifact bytes are not canonical")
        return snapshot

    def provision(
        self,
        snapshot: LocalCEDeploymentConfigSnapshotV1,
        *,
        revision: int,
        expected_predecessor: int | None = None,
    ) -> CEDeploymentConfigurationRecord:
        """Publish and durably record one exact next configuration revision."""
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise CEContextRevisionConflict("revision must be a positive integer")
        if expected_predecessor is not None and (
            not isinstance(expected_predecessor, int)
            or isinstance(expected_predecessor, bool)
            or expected_predecessor < 1
        ):
            raise CEContextRevisionConflict("expected predecessor must be a positive integer or None")
        payload, digest = self._validated_payload(snapshot)
        configured = snapshot.configured
        if revision == 1:
            if expected_predecessor is not None:
                raise CEContextRevisionConflict("revision 1 cannot have a predecessor")
        elif expected_predecessor != revision - 1:
            raise CEContextRevisionConflict("revision must name its exact predecessor")

        config_ref, stored_digest = self.artifact_store.put(payload)
        if stored_digest != digest:
            raise CEContextArtifactMismatch("artifact store returned an unexpected digest")
        if self.artifact_store.get(config_ref, digest) != payload:
            raise CEContextArtifactMismatch("artifact read-back does not match snapshot")

        # Validate every earlier revision before recording the candidate.  This
        # prevents a healthy-looking head from extending a broken chain while
        # retaining the store's publish-before-transaction rollback contract.
        self._read_history(configured.deployment_key)

        recorded_at = datetime.now(timezone.utc)
        configuration_id = str(uuid.uuid4())
        try:
            with self.engine.begin() as connection:
                latest = connection.execute(
                    select(ce_deployment_configurations.c.revision)
                    .where(ce_deployment_configurations.c.deployment_key == configured.deployment_key)
                    .order_by(ce_deployment_configurations.c.revision.desc())
                    .limit(1)
                ).scalar_one_or_none()
                expected_latest = revision - 1 if revision > 1 else None
                if latest != expected_latest:
                    raise CEContextRevisionConflict(
                        f"expected predecessor {expected_latest!r}, found {latest!r}"
                    )
                connection.execute(ce_deployment_configurations.insert().values(
                    configuration_id=configuration_id,
                    schema_version=1,
                    deployment_key=configured.deployment_key,
                    revision=revision,
                    ce_base_url=configured.ce_base_url,
                    ce_release=configured.ce_release,
                    config_ref=config_ref,
                    config_sha256=digest,
                    recorded_at=recorded_at,
                ))
        except Exception:
            # Do not delete content-addressed bytes: the database transaction
            # may have rolled back after publication and recovery can inspect
            # the unreferenced artifact safely.
            raise
        return CEDeploymentConfigurationRecord(
            configuration_id=configuration_id,
            deployment_key=configured.deployment_key,
            revision=revision,
            recorded_at=recorded_at,
            snapshot=snapshot,
        )

    def read(
        self, deployment_key: str, revision: int | None = None
    ) -> CEDeploymentConfigurationRecord:
        """Read a row and verify its exact content-addressed snapshot."""
        rows = self._read_history(deployment_key)
        if not rows:
            raise CEContextConfigurationNotFound(
                f"no configuration for deployment {deployment_key!r} revision {revision!r}"
            )
        row = rows[-1] if revision is None else next(
            (candidate for candidate in rows if candidate["revision"] == revision), None
        )
        if row is None:
            raise CEContextConfigurationNotFound(
                f"no configuration for deployment {deployment_key!r} revision {revision!r}"
            )
        snapshot = self._snapshot_from_row(row)
        return CEDeploymentConfigurationRecord(
            configuration_id=row["configuration_id"],
            deployment_key=row["deployment_key"],
            revision=row["revision"],
            recorded_at=row["recorded_at"],
            snapshot=snapshot,
        )

    @staticmethod
    def _json_object(body: bytes, resource: str) -> dict[str, Any]:
        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON object key: {key}")
                result[key] = value

            return result

        def reject_non_finite(value: str) -> Any:
            raise ValueError(f"non-finite JSON constant: {value}")

        def reject_non_finite_number(value: str) -> float:
            number = float(value)
            if not math.isfinite(number):
                raise ValueError(f"non-finite JSON number: {value}")
            return number

        try:
            value = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_non_finite,
                parse_float=reject_non_finite_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CEContextArtifactMismatch(f"{resource} body is not valid JSON") from exc
        if not isinstance(value, dict):
            raise CEContextArtifactMismatch(f"{resource} body must be a JSON object")
        return value

    @staticmethod
    def _positive_id(value: Any, field: str) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    @classmethod
    def _related_id(cls, value: Any, field: str) -> int:
        if isinstance(value, dict):
            value = value.get("id")
        if not cls._positive_id(value, field):
            raise CEContextArtifactMismatch(f"{field} must be a positive integer")
        return value

    @classmethod
    def _validate_observation(
        cls,
        registration: CEContextRegistrationV1,
        observation: CEContextObservationV1,
        configured: ConfiguredCEDeploymentV1,
    ) -> tuple[tuple[str, str, str, bytes], ...]:
        if not isinstance(registration, CEContextRegistrationV1):
            raise TypeError("registration must be CEContextRegistrationV1")
        if not isinstance(observation, CEContextObservationV1):
            raise TypeError("observation must be CEContextObservationV1")
        for name in ("deployment_key", "ce_base_url", "ce_release"):
            if getattr(registration, name) != getattr(configured, name):
                raise CEContextRegistrationConflict(f"registration {name} disagrees with configuration")
            if getattr(observation, name) != getattr(configured, name):
                raise CEContextRegistrationConflict(f"observation {name} disagrees with configuration")
        for name in ("deployment_key", "product_id", "engagement_id", "test_id"):
            if getattr(observation, name) != getattr(registration, name):
                raise CEContextRegistrationConflict(f"observation {name} disagrees with registration")

        expected_resources = ("product", "engagement") + (("test",) if registration.test_id is not None else ())
        if tuple(item.resource for item in observation.responses) != expected_resources:
            raise CEContextArtifactMismatch("observation resources are not in the required order")
        results = []
        for item, resource in zip(observation.responses, expected_resources):
            if item.resource != resource or item.response.status < 200 or item.response.status >= 300:
                raise CEContextArtifactMismatch(f"invalid {resource} GET response")
            if item.response.body != item.body or item.body_sha256 != hashlib.sha256(item.body).hexdigest():
                raise CEContextArtifactMismatch(f"{resource} body digest is inconsistent")
            expected_url = f"{configured.ce_base_url}/api/v2/{resource}s/"
            expected_id = getattr(registration, f"{resource}_id", None)
            if resource == "engagement":
                expected_url = f"{configured.ce_base_url}/api/v2/engagements/{registration.engagement_id}/"
            elif resource == "test":
                expected_url = f"{configured.ce_base_url}/api/v2/tests/{registration.test_id}/"
            else:
                expected_url = f"{configured.ce_base_url}/api/v2/products/{registration.product_id}/"
            if item.response.url != expected_url:
                raise CEContextArtifactMismatch(f"{resource} GET URL is inconsistent")
            document = cls._json_object(item.body, resource)
            if cls._related_id(document.get("id"), f"{resource}.id") != expected_id:
                raise CEContextArtifactMismatch(f"{resource} id does not match registration")
            if resource == "engagement":
                if cls._related_id(document.get("product"), "engagement.product") != registration.product_id:
                    raise CEContextArtifactMismatch("engagement parent does not match registration")
            elif resource == "test":
                if cls._related_id(document.get("engagement"), "test.engagement") != registration.engagement_id:
                    raise CEContextArtifactMismatch("test parent does not match registration")
            results.append((resource, item.body_sha256, item.body_sha256, item.body))
        return tuple(results)

    def register_verified_context(
        self,
        registration: CEContextRegistrationV1,
        observation: CEContextObservationV1,
        *,
        configuration_revision: int,
    ) -> CEContextEvidenceRecord:
        """Durably register one verified candidate against a local config revision."""
        if not isinstance(configuration_revision, int) or isinstance(configuration_revision, bool) or configuration_revision < 1:
            raise CEContextRegistrationConflict("configuration_revision must be a positive integer")
        configuration = self.read(registration.deployment_key, configuration_revision)
        configured = configuration.snapshot.configured
        evidence = self._validate_observation(registration, observation, configured)

        refs: dict[str, tuple[str, str]] = {}
        for resource, _unused, digest, body in evidence:
            ref, stored_digest = self.artifact_store.put(body)
            if stored_digest != digest or self.artifact_store.get(ref, digest) != body:
                raise CEContextArtifactMismatch(f"{resource} artifact read-back does not match GET body")
            refs[resource] = (ref, digest)
        registration_values = dict(
            registration_id=registration.registration_id, schema_version=1,
            deployment_key=registration.deployment_key, context_key=registration.context_key,
            product_id=registration.product_id, engagement_id=registration.engagement_id,
            test_id=registration.test_id,
        )
        verification_id = str(uuid.uuid4())
        verified_at = datetime.now(timezone.utc)
        verification_values = dict(
            verification_id=verification_id, schema_version=1,
            registration_id=registration.registration_id, deployment_key=registration.deployment_key,
            deployment_config_revision=configuration_revision,
            product_body_ref=refs["product"][0], product_body_sha256=refs["product"][1],
            engagement_body_ref=refs["engagement"][0], engagement_body_sha256=refs["engagement"][1],
            test_body_ref=refs.get("test", (None, None))[0],
            test_body_sha256=refs.get("test", (None, None))[1], verified_at=verified_at,
        )
        with self.engine.begin() as connection:
            if registration.test_id is not None:
                self._lock_test_collision(
                    connection, registration.deployment_key, registration.test_id
                )
            existing = connection.execute(
                select(ce_context_registrations).where(
                    ce_context_registrations.c.deployment_key == registration.deployment_key,
                    ce_context_registrations.c.context_key == registration.context_key,
                )
            ).mappings().one_or_none()
            if existing is not None:
                if any(existing[key] != registration_values[key] for key in registration_values):
                    raise CEContextRegistrationConflict("existing context registration conflicts")
                raise CEContextRegistrationConflict("context registration already exists")
            if registration.test_id is not None:
                binding = connection.execute(
                    select(ce_context_test_bindings.c.binding_id).where(
                        ce_context_test_bindings.c.deployment_key == registration.deployment_key,
                        ce_context_test_bindings.c.test_id == registration.test_id,
                    )
                ).scalar_one_or_none()
                if binding is not None:
                    raise CEContextRegistrationConflict(
                        "Test is already bound by a first-import operation"
                    )
            connection.execute(ce_context_registrations.insert().values(registration_values))
            connection.execute(ce_context_verifications.insert().values(verification_values))
        return CEContextEvidenceRecord(
            registration_id=registration.registration_id,
            verification_id=verification_id,
            deployment_key=registration.deployment_key, context_key=registration.context_key,
            product_id=registration.product_id, engagement_id=registration.engagement_id,
            test_id=registration.test_id, deployment_config_revision=configuration_revision,
            product_body_ref=refs["product"][0], product_body_sha256=refs["product"][1],
            engagement_body_ref=refs["engagement"][0], engagement_body_sha256=refs["engagement"][1],
            test_body_ref=refs.get("test", (None, None))[0],
            test_body_sha256=refs.get("test", (None, None))[1], verified_at=verified_at,
        )

    def append_verified_context(
        self,
        registration: CEContextRegistrationV1,
        observation: CEContextObservationV1,
        *,
        configuration_revision: int,
    ) -> CEContextEvidenceRecord:
        """Append current GET evidence without replacing context provenance.

        The original registration and first-import Test binding remain
        immutable. If a binding exists, the current observation must include
        that same Test and its exact Engagement parent; it cannot substitute a
        new Test or context to recover after endpoint rotation.
        """
        if (not isinstance(configuration_revision, int)
                or isinstance(configuration_revision, bool)
                or configuration_revision < 1):
            raise CEContextRegistrationConflict(
                "configuration_revision must be a positive integer")
        if not isinstance(registration, CEContextRegistrationV1):
            raise TypeError("registration must be CEContextRegistrationV1")
        configuration = self.read(registration.deployment_key, configuration_revision)
        if self.read(registration.deployment_key).revision != configuration_revision:
            raise CEContextRevisionConflict(
                "new context verification must use the current configuration revision")

        with self.engine.begin() as connection:
            existing = connection.execute(
                select(ce_context_registrations).where(
                    ce_context_registrations.c.registration_id == registration.registration_id
                )
            ).mappings().one_or_none()
            binding = connection.execute(
                select(ce_context_test_bindings).where(
                    ce_context_test_bindings.c.registration_id == registration.registration_id
                )
            ).mappings().one_or_none()
        if existing is None:
            raise CEContextEvidenceNotFound(
                "cannot append verification without the original context registration")
        immutable_fields = (
            "schema_version", "registration_id", "deployment_key", "context_key",
            "product_id", "engagement_id", "test_id",
        )
        if any(existing[field] != getattr(registration, field) for field in immutable_fields):
            raise CEContextRegistrationConflict(
                "appended verification must preserve the original registration")

        effective_test_id = existing["test_id"]
        if binding is not None:
            if (binding["deployment_key"] != existing["deployment_key"]
                    or binding["test_id"] <= 0):
                raise CEContextArtifactMismatch(
                    "first-import Test binding has inconsistent deployment or ID")
            if effective_test_id is not None and effective_test_id != binding["test_id"]:
                raise CEContextArtifactMismatch(
                    "registration Test and first-import binding disagree")
            effective_test_id = binding["test_id"]
        effective_registration = CEContextRegistrationV1(
            schema_version=existing["schema_version"],
            registration_id=existing["registration_id"],
            deployment_key=existing["deployment_key"],
            context_key=existing["context_key"],
            product_id=existing["product_id"],
            engagement_id=existing["engagement_id"],
            test_id=effective_test_id,
            ce_base_url=configuration.configured.ce_base_url,
            ce_release=configuration.configured.ce_release,
        )
        evidence = self._validate_observation(
            effective_registration, observation, configuration.configured)
        refs: dict[str, tuple[str, str]] = {}
        for resource, _unused, digest, body in evidence:
            ref, stored_digest = self.artifact_store.put(body)
            if stored_digest != digest or self.artifact_store.get(ref, digest) != body:
                raise CEContextArtifactMismatch(
                    f"{resource} artifact read-back does not match GET body")
            refs[resource] = (ref, digest)

        verification_id = str(uuid.uuid4())
        verified_at = datetime.now(timezone.utc)
        connection = self._binding_transaction(self.engine)
        try:
            if connection.dialect.name == "postgresql":
                # Hold the configuration head stable through evidence insert.
                connection.exec_driver_sql(
                    "LOCK TABLE ce_deployment_configurations IN SHARE MODE")
            locked = connection.execute(
                select(ce_context_registrations).where(
                    ce_context_registrations.c.registration_id == registration.registration_id
                ).with_for_update()
            ).mappings().one_or_none()
            locked_binding = connection.execute(
                select(ce_context_test_bindings).where(
                    ce_context_test_bindings.c.registration_id == registration.registration_id
                ).with_for_update()
            ).mappings().one_or_none()
            latest = connection.execute(
                select(ce_deployment_configurations.c.revision).where(
                    ce_deployment_configurations.c.deployment_key == registration.deployment_key
                ).order_by(ce_deployment_configurations.c.revision.desc()).limit(1)
            ).scalar_one_or_none()
            binding_changed = (locked_binding is None) != (binding is None)
            if binding is not None and locked_binding is not None:
                binding_changed = binding_changed or any(
                    locked_binding[field] != binding[field]
                    for field in ("binding_id", "test_id", "deployment_config_revision",
                                  "test_body_ref", "test_body_sha256")
                )
            if (locked is None or any(locked[field] != existing[field]
                                      for field in immutable_fields)
                    or binding_changed):
                raise CEContextRegistrationConflict(
                    "context registration or Test binding changed while appending verification")
            if latest != configuration_revision:
                raise CEContextRevisionConflict(
                    "configuration head changed while appending verification")
            same_revision = connection.execute(
                select(ce_context_verifications.c.verification_id).where(
                    ce_context_verifications.c.registration_id == registration.registration_id,
                    ce_context_verifications.c.deployment_config_revision == configuration_revision,
                )
            ).scalar_one_or_none()
            if same_revision is not None:
                raise CEContextRevisionConflict(
                    "context already has verification evidence for this configuration revision")
            connection.execute(ce_context_verifications.insert().values(
                verification_id=verification_id,
                schema_version=1,
                registration_id=registration.registration_id,
                deployment_key=registration.deployment_key,
                deployment_config_revision=configuration_revision,
                product_body_ref=refs["product"][0],
                product_body_sha256=refs["product"][1],
                engagement_body_ref=refs["engagement"][0],
                engagement_body_sha256=refs["engagement"][1],
                test_body_ref=refs.get("test", (None, None))[0],
                test_body_sha256=refs.get("test", (None, None))[1],
                verified_at=verified_at,
            ))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return CEContextEvidenceRecord(
            registration_id=registration.registration_id,
            verification_id=verification_id,
            deployment_key=registration.deployment_key,
            context_key=registration.context_key,
            product_id=registration.product_id,
            engagement_id=registration.engagement_id,
            test_id=effective_test_id,
            deployment_config_revision=configuration_revision,
            product_body_ref=refs["product"][0],
            product_body_sha256=refs["product"][1],
            engagement_body_ref=refs["engagement"][0],
            engagement_body_sha256=refs["engagement"][1],
            test_body_ref=refs.get("test", (None, None))[0],
            test_body_sha256=refs.get("test", (None, None))[1],
            verified_at=verified_at,
        )

    def read_verified_context(
        self,
        registration_id: str,
        verification_id: str,
        *,
        require_current_configuration: bool = False,
    ) -> CEContextEvidenceRecord:
        """Read and validate one exact durable context verification pair.

        The returned record describes caller-provided configuration and
        synthetic GET bodies retained locally.  It does not prove live CE
        identity or retain URL/status/header provenance.
        """
        if not isinstance(registration_id, str) or not isinstance(verification_id, str):
            raise CEContextEvidenceNotFound("registration and verification IDs must be strings")
        with self.engine.begin() as connection:
            registration = connection.execute(
                select(ce_context_registrations).where(
                    ce_context_registrations.c.registration_id == registration_id,
                )
            ).mappings().one_or_none()
            verification = connection.execute(
                select(ce_context_verifications).where(
                    ce_context_verifications.c.registration_id == registration_id,
                    ce_context_verifications.c.verification_id == verification_id,
                )
            ).mappings().one_or_none()
            binding = connection.execute(
                select(ce_context_test_bindings).where(
                    ce_context_test_bindings.c.registration_id == registration_id,
                )
            ).mappings().one_or_none()
        if registration is None or verification is None:
            raise CEContextEvidenceNotFound(
                "no exact registration and verification pair exists"
            )

        try:
            stored_registration = CEContextRegistrationV1(
                schema_version=registration["schema_version"],
                registration_id=registration["registration_id"],
                deployment_key=registration["deployment_key"],
                context_key=registration["context_key"],
                product_id=registration["product_id"],
                engagement_id=registration["engagement_id"],
                test_id=registration["test_id"],
            )
            if verification["schema_version"] != 1:
                raise ValueError("unsupported verification schema")
            uuid.UUID(verification["verification_id"])
        except (TypeError, ValueError, AttributeError) as exc:
            raise CEContextArtifactMismatch("stored context identity is malformed") from exc

        if verification["registration_id"] != stored_registration.registration_id:
            raise CEContextArtifactMismatch("verification registration is inconsistent")
        if verification["deployment_key"] != stored_registration.deployment_key:
            raise CEContextArtifactMismatch("verification deployment is inconsistent")
        try:
            configuration = self.read(
                stored_registration.deployment_key,
                verification["deployment_config_revision"],
            )
        except (TypeError, ValueError, LookupError) as exc:
            raise CEContextArtifactMismatch("referenced configuration is invalid") from exc
        configured = configuration.snapshot.configured
        if configured.deployment_key != verification["deployment_key"]:
            raise CEContextArtifactMismatch("configuration deployment is inconsistent")
        if require_current_configuration:
            current = self.read(stored_registration.deployment_key)
            if current.revision != configuration.revision:
                raise CEContextRevisionConflict(
                    "stored verification does not reference the current configuration"
                )

        refs = (
            ("product", verification["product_body_ref"], verification["product_body_sha256"]),
            ("engagement", verification["engagement_body_ref"], verification["engagement_body_sha256"]),
        )
        if (verification["test_body_ref"] is None) != (verification["test_body_sha256"] is None):
            raise CEContextArtifactMismatch("Test artifact reference and digest must be paired")
        effective_test_id = stored_registration.test_id
        verified_test_id = effective_test_id
        if binding is not None:
            if (binding["deployment_key"] != stored_registration.deployment_key
                    or (effective_test_id is not None
                        and effective_test_id != binding["test_id"])):
                raise CEContextArtifactMismatch("first-import Test binding disagrees with registration")
            effective_test_id = binding["test_id"]
        if effective_test_id is not None:
            if verification["test_body_ref"] is None:
                # The first-import verification predates and intentionally
                # remains independent of the append-only binding.
                if binding is None:
                    raise CEContextArtifactMismatch("registered Test is missing its artifact")
                verified_test_id = stored_registration.test_id
            else:
                refs += (("test", verification["test_body_ref"], verification["test_body_sha256"]),)
                verified_test_id = effective_test_id
        elif verification["test_body_ref"] is not None:
            raise CEContextArtifactMismatch("unregistered Test has stored evidence")

        for resource, reference, digest in refs:
            try:
                body = self.artifact_store.get(reference, digest)
            except Exception as exc:
                raise CEContextArtifactMismatch(
                    f"{resource} artifact cannot be read or verified"
                ) from exc
            document = self._json_object(body, resource)
            expected_id = effective_test_id if resource == "test" else getattr(stored_registration, f"{resource}_id")
            if self._related_id(document.get("id"), f"{resource}.id") != expected_id:
                raise CEContextArtifactMismatch(f"{resource} id does not match registration")
            if resource == "engagement" and self._related_id(
                document.get("product"), "engagement.product"
            ) != stored_registration.product_id:
                raise CEContextArtifactMismatch("engagement parent does not match registration")
            if resource == "test" and self._related_id(
                document.get("engagement"), "test.engagement"
            ) != stored_registration.engagement_id:
                raise CEContextArtifactMismatch("test parent does not match registration")

        return CEContextEvidenceRecord(
            registration_id=stored_registration.registration_id,
            verification_id=verification["verification_id"],
            deployment_key=stored_registration.deployment_key,
            context_key=stored_registration.context_key,
            product_id=stored_registration.product_id,
            engagement_id=stored_registration.engagement_id,
            test_id=verified_test_id,
            deployment_config_revision=configuration.revision,
            product_body_ref=verification["product_body_ref"],
            product_body_sha256=verification["product_body_sha256"],
            engagement_body_ref=verification["engagement_body_ref"],
            engagement_body_sha256=verification["engagement_body_sha256"],
            test_body_ref=verification["test_body_ref"],
            test_body_sha256=verification["test_body_sha256"],
            verified_at=verification["verified_at"],
        )

    @staticmethod
    def _baseline_page_document(body: bytes) -> dict[str, Any]:
        document = CEContextStore._json_object(body, "Test inventory page")
        if ("next" not in document or document.get("count") != 0
                or document.get("results") != []
                or document.get("next") is not None):
            raise CEContextArtifactMismatch(
                "retained pre-import Test page does not prove an empty complete inventory"
            )
        return document

    def _baseline_operation_context(self, operation_id: str) -> tuple[dict[str, Any], dict[str, Any], CEContextEvidenceRecord, Any]:
        with self.engine.connect() as connection:
            request = connection.execute(
                select(engine_operation_requests).where(
                    engine_operation_requests.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
            state = connection.execute(
                select(engine_operation_states).where(
                    engine_operation_states.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
        if request is None or state is None:
            raise CEContextEvidenceNotFound("first-import operation does not exist")
        if (request["request_kind"] != "import" or request["test_id"] is not None
                or state["status"] != "pending" or state["post_issued"]
                or state["revision"] != 1 or state["first_import_baseline_ref"] is not None):
            raise CEContextTestBindingConflict(
                "baseline capture requires a clean, unbaselined first import"
            )
        if request["registration_id"] is None or request["verification_id"] is None:
            raise CEContextEvidenceNotFound("first import lacks registered context evidence")
        evidence = self.read_verified_context(
            request["registration_id"], request["verification_id"]
        )
        if (evidence.context_key != request["context_key"]
                or state["context_key"] != request["context_key"]
                or evidence.test_id is not None):
            raise CEContextArtifactMismatch(
                "first-import baseline context does not match exact registered context"
            )
        configuration = self.read(
            evidence.deployment_key, evidence.deployment_config_revision
        )
        return dict(request), dict(state), evidence, configuration

    @staticmethod
    def _baseline_expected_url(configured: ConfiguredCEDeploymentV1, engagement_id: int) -> str:
        return f"{configured.ce_base_url}/api/v2/tests/?engagement={engagement_id}"

    def capture_first_import_baseline(
        self, operation_id: str, reader: CEReadClient
    ) -> CEFirstImportBaselineRecord:
        """Retain the exact complete-empty pre-POST Test inventory from a configured reader.

        A synthetic/injected transport remains synthetic provenance.  Empty
        booleans, candidate lists and references are never accepted as input.
        """
        if not isinstance(operation_id, str) or not operation_id:
            raise CEContextTestBindingConflict("operation_id must be a non-empty string")
        if not isinstance(reader, CEReadClient):
            raise TypeError("reader must be a configured CEReadClient capability")
        request, _state, evidence, configuration = self._baseline_operation_context(operation_id)
        configured = configuration.snapshot.configured
        if reader.base_url != configured.ce_base_url:
            raise CEDeploymentMismatchError("reader does not match registered CE deployment")
        collection = reader.list_tests(engagement_id=evidence.engagement_id)
        if (not isinstance(collection, Collection) or collection.count != 0
                or collection.items != () or not collection.pages):
            raise CEContextArtifactMismatch(
                "pre-import Test inventory is not a complete verified empty collection"
            )
        expected_url = self._baseline_expected_url(configured, evidence.engagement_id)
        retained_pages: list[dict[str, Any]] = []
        for page in collection.pages:
            parsed_url = urlsplit(page.url)
            expected = urlsplit(expected_url)
            if (page.url != expected_url
                    or (parsed_url.scheme.lower(), parsed_url.netloc.lower(), parsed_url.path)
                    != (expected.scheme, expected.netloc, expected.path)
                    or parse_qs(parsed_url.query, keep_blank_values=True).get("engagement")
                    != [str(evidence.engagement_id)]):
                raise CEContextArtifactMismatch(
                    "pre-import Test page URL is not scoped to the registered Engagement"
                )
            if not (200 <= page.status < 300):
                raise CEContextArtifactMismatch("pre-import Test page is not a successful GET")
            self._baseline_page_document(page.body)
            retained_pages.append({
                "status": page.status,
                "url": page.url,
                "body_base64": base64.b64encode(page.body).decode("ascii"),
                "body_sha256": page.sha256,
            })
        if len(retained_pages) != 1:
            raise CEContextArtifactMismatch(
                "empty pre-import inventory must have exactly one complete page"
            )
        document = {
            "schema_version": 1,
            "operation_id": operation_id,
            "registration_id": evidence.registration_id,
            "verification_id": evidence.verification_id,
            "deployment_key": evidence.deployment_key,
            "context_key": evidence.context_key,
            "engagement_id": evidence.engagement_id,
            "deployment_config_revision": evidence.deployment_config_revision,
            "request_url": expected_url,
            "count": collection.count,
            "candidate_test_ids": [],
            "pages": retained_pages,
            "provenance": "configured CEReadClient + synthetic transport",
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        reference, digest = self.artifact_store.put(payload)
        if digest != hashlib.sha256(payload).hexdigest() or self.artifact_store.get(reference, digest) != payload:
            raise CEContextArtifactMismatch("baseline artifact read-back does not match captured bytes")
        return CEFirstImportBaselineRecord(
            reference, digest, evidence.registration_id, evidence.verification_id,
            evidence.deployment_key, evidence.context_key, evidence.engagement_id,
            evidence.deployment_config_revision, expected_url, tuple(collection.pages),
            collection.count, tuple(item["id"] for item in collection.items),
        )

    def _decode_first_import_baseline(
        self,
        operation_id: str,
        reference: str,
        digest: str,
        *,
        expected_document: dict[str, Any] | None = None,
    ) -> CEFirstImportBaselineRecord:
        try:
            payload = self.artifact_store.get(reference, digest)
            document = self._json_object(payload, "first-import baseline")
            if expected_document is not None and document != expected_document:
                raise ValueError("baseline artifact changed after publication")
            request, _state, evidence, configuration = self._baseline_operation_context_for_read(operation_id)
            configured = configuration.snapshot.configured
            expected = {
                "schema_version": 1,
                "operation_id": operation_id,
                "registration_id": evidence.registration_id,
                "verification_id": evidence.verification_id,
                "deployment_key": evidence.deployment_key,
                "context_key": request["context_key"],
                "engagement_id": evidence.engagement_id,
                "deployment_config_revision": evidence.deployment_config_revision,
                "request_url": self._baseline_expected_url(configured, evidence.engagement_id),
                "count": 0,
                "candidate_test_ids": [],
                "provenance": "configured CEReadClient + synthetic transport",
            }
            if any(document.get(key) != value for key, value in expected.items()):
                raise ValueError("baseline artifact is not bound to the registered operation context")
            pages = document.get("pages")
            if not isinstance(pages, list) or len(pages) != 1:
                raise ValueError("baseline artifact must retain exactly one empty page")
            raw_pages = []
            expected_url = expected["request_url"]
            for page in pages:
                body = base64.b64decode(page["body_base64"], validate=True)
                if hashlib.sha256(body).hexdigest() != page["body_sha256"]:
                    raise ValueError("retained baseline page digest does not match bytes")
                parsed = urlsplit(page["url"])
                if (page["url"] != expected_url or not 200 <= page["status"] < 300
                        or parsed.query != f"engagement={evidence.engagement_id}"):
                    raise ValueError("retained baseline page URL or status is invalid")
                self._baseline_page_document(body)
                raw_pages.append(RawResponse(page["status"], {}, body, page["url"]))
        except Exception as exc:
            if isinstance(exc, CEContextStoreError):
                raise
            raise CEContextArtifactMismatch("first-import baseline artifact is invalid") from exc
        return CEFirstImportBaselineRecord(
            reference, digest, evidence.registration_id, evidence.verification_id,
            evidence.deployment_key, evidence.context_key, evidence.engagement_id,
            evidence.deployment_config_revision, expected_url, tuple(raw_pages), 0, (),
        )

    def _baseline_operation_context_for_read(self, operation_id: str):
        with self.engine.connect() as connection:
            request = connection.execute(
                select(engine_operation_requests).where(
                    engine_operation_requests.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
            state = connection.execute(
                select(engine_operation_states).where(
                    engine_operation_states.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
        if request is None or state is None:
            raise CEContextEvidenceNotFound("first-import operation does not exist")
        if (request["request_kind"] != "import" or request["test_id"] is not None
                or state["first_import_baseline_ref"] is None):
            raise CEContextTestBindingConflict("operation has no recorded first-import baseline")
        evidence = self.read_verified_context(
            request["registration_id"], request["verification_id"]
        )
        configuration = self.read(evidence.deployment_key, evidence.deployment_config_revision)
        return dict(request), dict(state), evidence, configuration

    def read_first_import_baseline(self, operation_id: str) -> CEFirstImportBaselineRecord:
        """Re-read the baseline reference committed on the operation state."""
        request, state, _evidence, _configuration = self._baseline_operation_context_for_read(operation_id)
        reference = state["first_import_baseline_ref"]
        if not isinstance(reference, str) or ":" not in reference:
            raise CEContextArtifactMismatch("baseline reference is malformed")
        digest = reference.rsplit(":", 1)[-1]
        return self._decode_first_import_baseline(operation_id, reference, digest)

    def _reconciliation_operation_context(
        self, operation_id: str, *, allow_settled: bool = False
    ):
        with self.engine.connect() as connection:
            request = connection.execute(
                select(engine_operation_requests).where(
                    engine_operation_requests.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
            state = connection.execute(
                select(engine_operation_states).where(
                    engine_operation_states.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
        if request is None or state is None:
            raise CEContextEvidenceNotFound("first-import operation does not exist")
        status_valid = (
            state["status"] == "quarantined"
            or (allow_settled and state["status"] == "settled"
                and state["reconciled"]
                and state["reconciliation_evidence_ref"] is not None)
        )
        if (request["request_kind"] != "import" or request["test_id"] is not None
                or not status_valid or not state["post_issued"]
                or state["response_ref"] is not None
                or state["first_import_baseline_ref"] is None):
            raise CEContextTestBindingConflict(
                "reconciliation requires an uncertain quarantined first import with a verified baseline"
            )
        if request["registration_id"] is None or request["verification_id"] is None:
            raise CEContextEvidenceNotFound("first import lacks registered context evidence")
        evidence = self.read_verified_context(
            request["registration_id"], request["verification_id"]
        )
        if evidence.context_key != request["context_key"] or evidence.test_id is not None:
            raise CEContextArtifactMismatch(
                "reconciliation context does not match exact registered first-import context"
            )
        configuration = self.read(
            evidence.deployment_key, evidence.deployment_config_revision
        )
        baseline = self.read_first_import_baseline(operation_id)
        if (baseline.context_key != evidence.context_key
                or baseline.registration_id != evidence.registration_id
                or baseline.verification_id != evidence.verification_id
                or baseline.engagement_id != evidence.engagement_id
                or baseline.deployment_config_revision != evidence.deployment_config_revision
                or baseline.count != 0 or baseline.candidate_test_ids):
            raise CEContextArtifactMismatch(
                "reconciliation operation baseline is not a verified empty matching context"
            )
        return dict(request), dict(state), evidence, configuration, baseline

    @staticmethod
    def _inventory_page(body: bytes, engagement_id: int) -> tuple[int, Any, list[int]]:
        document = CEContextStore._json_object(body, "Test reconciliation page")
        if ("count" not in document or isinstance(document["count"], bool)
                or not isinstance(document["count"], int) or document["count"] < 0
                or "next" not in document
                or (document["next"] is not None and
                    (not isinstance(document["next"], str) or not document["next"]))
                or not isinstance(document.get("results"), list)):
            raise CEContextArtifactMismatch(
                "Test reconciliation page lacks complete count, next or results fields"
            )
        ids: list[int] = []
        for item in document["results"]:
            if not isinstance(item, dict):
                raise CEContextArtifactMismatch("Test inventory contains a non-object result")
            test_id = item.get("id")
            scoped = item.get("engagement")
            if isinstance(scoped, dict):
                scoped = scoped.get("id")
            if (isinstance(test_id, bool) or not isinstance(test_id, int) or test_id <= 0
                    or isinstance(scoped, bool) or scoped != engagement_id):
                raise CEContextArtifactMismatch(
                    "Test inventory candidate lacks a supported ID or exact Engagement scope"
                )
            ids.append(test_id)
        return document["count"], document["next"], ids

    @staticmethod
    def _validate_inventory_collection(collection, configured, engagement_id: int) -> tuple[int, ...]:
        if not isinstance(collection, Collection) or not collection.pages:
            raise CEContextArtifactMismatch("Test reconciliation inventory is incomplete")
        expected_origin = urlsplit(configured.ce_base_url)
        expected_path = f"{urlsplit(configured.ce_base_url).path.rstrip('/')}/api/v2/tests/"
        expected_first_url = CEContextStore._baseline_expected_url(
            configured, engagement_id
        )
        candidate_ids: list[int] = []
        retained_count: int | None = None
        for index, page in enumerate(collection.pages):
            parsed = urlsplit(page.url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            if ((parsed.scheme.lower(), parsed.netloc.lower()) !=
                    (expected_origin.scheme.lower(), expected_origin.netloc.lower())
                    or parsed.path != expected_path
                    or query.get("engagement") != [str(engagement_id)]
                    or (index == 0 and page.url != expected_first_url)
                    or not 200 <= page.status < 300):
                raise CEContextArtifactMismatch(
                    "Test reconciliation page URL or status is outside the registered Engagement"
                )
            count, next_url, page_ids = CEContextStore._inventory_page(
                page.body, engagement_id
            )
            if retained_count is None:
                retained_count = count
            elif retained_count != count:
                raise CEContextArtifactMismatch("Test inventory pages report conflicting counts")
            expected_next = (
                collection.pages[index + 1].url
                if index + 1 < len(collection.pages) else None
            )
            if next_url != expected_next:
                raise CEContextArtifactMismatch(
                    "Test inventory pagination is incomplete or page links disagree"
                )
            candidate_ids.extend(page_ids)
        if (retained_count != collection.count or len(candidate_ids) != retained_count
                or len(set(candidate_ids)) != len(candidate_ids)
                or tuple(candidate_ids) != tuple(item.get("id") for item in collection.items)):
            raise CEContextArtifactMismatch(
                "Test inventory count or candidate IDs do not match retained complete pages"
            )
        return tuple(candidate_ids)

    def capture_first_import_reconciliation(
        self, operation_id: str, reader: CEReadClient
    ) -> CEFirstImportReconciliationRecord:
        """Capture exact complete supported Test inventory after a lost first POST response."""
        if not isinstance(operation_id, str) or not operation_id:
            raise CEContextTestBindingConflict("operation_id must be a non-empty string")
        if not isinstance(reader, CEReadClient):
            raise TypeError("reader must be a configured CEReadClient capability")
        request, _state, evidence, configuration, baseline = \
            self._reconciliation_operation_context(operation_id)
        configured = configuration.snapshot.configured
        if reader.base_url != configured.ce_base_url:
            raise CEDeploymentMismatchError("reader does not match registered CE deployment")
        collection = reader.list_tests(engagement_id=evidence.engagement_id)
        candidate_ids = self._validate_inventory_collection(
            collection, configured, evidence.engagement_id
        )
        request_url = self._baseline_expected_url(configured, evidence.engagement_id)
        pages = [{
            "status": page.status,
            "url": page.url,
            "body_base64": base64.b64encode(page.body).decode("ascii"),
            "body_sha256": page.sha256,
        } for page in collection.pages]
        document = {
            "schema_version": 1,
            "operation_id": operation_id,
            "registration_id": evidence.registration_id,
            "verification_id": evidence.verification_id,
            "deployment_key": evidence.deployment_key,
            "context_key": evidence.context_key,
            "engagement_id": evidence.engagement_id,
            "deployment_config_revision": evidence.deployment_config_revision,
            "baseline_ref": baseline.baseline_ref,
            "request_url": request_url,
            "count": collection.count,
            "candidate_test_ids": list(candidate_ids),
            "pages": pages,
            "provenance": "configured CEReadClient + synthetic transport",
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        reference, digest = self.artifact_store.put(payload)
        if (digest != hashlib.sha256(payload).hexdigest()
                or self.artifact_store.get(reference, digest) != payload):
            raise CEContextArtifactMismatch(
                "reconciliation artifact read-back does not match captured bytes"
            )
        return CEFirstImportReconciliationRecord(
            reference, digest, operation_id, evidence.registration_id,
            evidence.verification_id, evidence.deployment_key, evidence.context_key,
            evidence.engagement_id, evidence.deployment_config_revision,
            baseline.baseline_ref, request_url, tuple(collection.pages),
            collection.count, candidate_ids,
        )

    def read_first_import_reconciliation(
        self, operation_id: str, reference: str
    ) -> CEFirstImportReconciliationRecord:
        request, _state, evidence, configuration, baseline = \
            self._reconciliation_operation_context(operation_id, allow_settled=True)
        try:
            if not isinstance(reference, str) or ":" not in reference:
                raise ValueError("reconciliation reference is malformed")
            digest = reference.rsplit(":", 1)[-1]
            payload = self.artifact_store.get(reference, digest)
            document = self._json_object(payload, "first-import reconciliation")
            expected = {
                "schema_version": 1, "operation_id": operation_id,
                "registration_id": evidence.registration_id,
                "verification_id": evidence.verification_id,
                "deployment_key": evidence.deployment_key,
                "context_key": request["context_key"],
                "engagement_id": evidence.engagement_id,
                "deployment_config_revision": evidence.deployment_config_revision,
                "baseline_ref": baseline.baseline_ref,
                "request_url": self._baseline_expected_url(
                    configuration.snapshot.configured, evidence.engagement_id
                ),
                "provenance": "configured CEReadClient + synthetic transport",
            }
            if any(document.get(key) != value for key, value in expected.items()):
                raise ValueError("reconciliation artifact binding does not match operation")
            pages_doc = document.get("pages")
            if not isinstance(pages_doc, list) or not pages_doc:
                raise ValueError("reconciliation artifact contains no retained pages")
            raw_pages = []
            candidate_ids: list[int] = []
            retained_count = None
            configured = configuration.snapshot.configured
            expected_origin = urlsplit(configured.ce_base_url)
            expected_path = f"{expected_origin.path.rstrip('/')}/api/v2/tests/"
            expected_first_url = self._baseline_expected_url(
                configured, evidence.engagement_id
            )
            for index, page in enumerate(pages_doc):
                body = base64.b64decode(page["body_base64"], validate=True)
                if hashlib.sha256(body).hexdigest() != page["body_sha256"]:
                    raise ValueError("retained reconciliation page digest does not match bytes")
                raw = RawResponse(page["status"], {}, body, page["url"])
                parsed = urlsplit(raw.url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                if ((parsed.scheme.lower(), parsed.netloc.lower()) !=
                        (expected_origin.scheme.lower(), expected_origin.netloc.lower())
                        or parsed.path != expected_path
                        or query.get("engagement") != [str(evidence.engagement_id)]
                        or (index == 0 and raw.url != expected_first_url)
                        or not 200 <= raw.status < 300):
                    raise ValueError("retained reconciliation page scope or status is invalid")
                count, next_url, ids = self._inventory_page(body, evidence.engagement_id)
                if retained_count is None:
                    retained_count = count
                elif retained_count != count:
                    raise ValueError("retained reconciliation page counts disagree")
                expected_next = (
                    pages_doc[index + 1].get("url")
                    if index + 1 < len(pages_doc) else None
                )
                if next_url != expected_next:
                    raise ValueError("retained reconciliation page links disagree")
                candidate_ids.extend(ids)
                raw_pages.append(raw)
            if (document.get("count") != retained_count
                    or document.get("candidate_test_ids") != candidate_ids
                    or len(candidate_ids) != retained_count
                    or len(set(candidate_ids)) != len(candidate_ids)):
                raise ValueError("reconciliation summary disagrees with retained pages")
        except Exception as exc:
            if isinstance(exc, CEContextStoreError):
                raise
            raise CEContextArtifactMismatch("first-import reconciliation artifact is invalid") from exc
        return CEFirstImportReconciliationRecord(
            reference, digest, operation_id, evidence.registration_id,
            evidence.verification_id, evidence.deployment_key, evidence.context_key,
            evidence.engagement_id, evidence.deployment_config_revision,
            baseline.baseline_ref, expected["request_url"], tuple(raw_pages),
            retained_count, tuple(candidate_ids),
        )

    @staticmethod
    def _binding_transaction(engine):
        """Open the writer transaction used by the 0009 cross-table guard."""
        connection = engine.connect()
        try:
            if connection.dialect.name == "sqlite":
                # SQLite has no row/table lock that can protect the gap between
                # the legacy registration table and the new binding table.
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                connection.begin()
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _lock_test_collision(connection, deployment_key: str, test_id: int) -> None:
        """Serialise legacy registrations and 0009 bindings for one Test."""
        if connection.dialect.name == "postgresql":
            connection.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))",
                ),
                {"lock_key": f"uvm:ce-test:{deployment_key}:{test_id}"},
            )

    @staticmethod
    def _require_first_import_history(
        state, transitions, manifest_ref: str, baseline_ref: str | None = None
    ) -> None:
        """Accept the exact legacy or baselined first-import writer history."""
        ordered = sorted(transitions, key=lambda row: row["to_revision"])
        if baseline_ref is None:
            expected = (
                (None, 1, None, "pending", "reservation registered", manifest_ref),
                (1, 2, "pending", "pending", "POST issued", None),
                (2, 3, "pending", "pending", "response recorded", state["response_ref"]),
            )
            expected_revision = 3
        else:
            expected = (
                (None, 1, None, "pending", "reservation registered", manifest_ref),
                (1, 2, "pending", "pending", "first-import baseline recorded", baseline_ref),
                (2, 3, "pending", "pending", "POST issued", None),
                (3, 4, "pending", "pending", "response recorded", state["response_ref"]),
            )
            expected_revision = 4
        if state["revision"] != expected_revision or len(ordered) != len(expected):
            raise CEContextTestBindingConflict("first import has incomplete operation history")
        for row, (from_rev, to_rev, from_status, to_status, reason, evidence_ref) in zip(
            ordered, expected
        ):
            if (
                row["from_revision"] != from_rev
                or row["to_revision"] != to_rev
                or row["from_status"] != from_status
                or row["to_status"] != to_status
                or row["transition_reason"] != reason
                or (evidence_ref is not None and row["evidence_ref"] != evidence_ref)
            ):
                raise CEContextTestBindingConflict("first import operation history is inconsistent")
        post_transition_index = 1 if baseline_ref is None else 2
        post_evidence = ordered[post_transition_index]["evidence_ref"]
        if (not isinstance(post_evidence, str) or not post_evidence.strip()) or any(
            later["occurred_at"] < earlier["occurred_at"]
            for earlier, later in zip(ordered, ordered[1:])
        ):
            raise CEContextTestBindingConflict("first import operation history is out of order")

    def bind_first_import_test(
        self,
        operation_id: str,
        response: CEObservedResponseV1,
    ) -> CEContextTestBindingRecord:
        """Bind an issued first-import response to one exact CE Test.

        The operation candidate and response artifact are authoritative only
        when already durable in the operation ledger.  The supplied response
        is the supported-API Test GET read-back; its exact bytes are published
        before the 0009 transaction and are never accepted as caller-provided
        provenance on their own.
        """
        if not isinstance(operation_id, str) or not operation_id:
            raise CEContextTestBindingConflict("operation_id must be a non-empty string")
        if not isinstance(response, CEObservedResponseV1):
            raise TypeError("response must be CEObservedResponseV1")
        if response.resource != "test":
            raise CEContextArtifactMismatch("Test binding requires a Test GET response")
        if response.response.status < 200 or response.response.status >= 300:
            raise CEContextArtifactMismatch("invalid Test GET response")

        # Validate the durable 0007/0008 chain before publishing bytes.  This
        # also checks all referenced Product/Engagement/Test artifacts and the
        # exact configuration revision.
        with self.engine.begin() as connection:
            request = connection.execute(
                select(engine_operation_requests).where(
                    engine_operation_requests.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
            state = connection.execute(
                select(engine_operation_states).where(
                    engine_operation_states.c.operation_id == operation_id
                )
            ).mappings().one_or_none()
        if request is None or state is None:
            raise CEContextEvidenceNotFound("operation request/state does not exist")
        if request["request_kind"] != "import" or request["test_id"] is not None:
            raise CEContextTestBindingConflict("only an unbound first import can bind a Test")
        if request["registration_id"] is None or request["verification_id"] is None:
            raise CEContextEvidenceNotFound("first import lacks registration/verification")
        if state["operation_id"] != operation_id or state["context_key"] != request["context_key"]:
            raise CEContextArtifactMismatch("operation request/state identity is inconsistent")
        baseline_ref = state["first_import_baseline_ref"]
        if baseline_ref is not None:
            self.read_first_import_baseline(operation_id)
        reconciled = state["response_ref"] is None
        parsed = None
        if reconciled:
            if (state["status"] != "quarantined" or not state["post_issued"]
                    or baseline_ref is None
                    or not state["reconciliation_evidence_ref"]):
                raise CEContextTestBindingConflict(
                    "a lost first import needs issued, quarantined complete reconciliation evidence"
                )
            reconciliation = self.read_first_import_reconciliation(
                operation_id, state["reconciliation_evidence_ref"]
            )
            if (reconciliation.count != 1
                    or len(reconciliation.candidate_test_ids) != 1
                    or reconciliation.candidate_test_ids[0] in
                    self.read_first_import_baseline(operation_id).candidate_test_ids):
                raise CEContextTestBindingConflict(
                    "lost first import must have exactly one fresh reconciliation candidate"
                )
            candidate = str(reconciliation.candidate_test_ids[0])
        else:
            if not state["post_issued"]:
                raise CEContextTestBindingConflict("first import has no issued durable response")
            response_ref = state["response_ref"]
            candidate = state["response_test_id"]
            if not isinstance(candidate, str) or not candidate.isdigit() or int(candidate) <= 0:
                raise CEContextTestBindingConflict("first import has no valid response Test candidate")
            try:
                response_body = self.artifact_store.get(
                    response_ref, response_ref.rsplit(":", 1)[-1]
                )
                parsed = parse_response(response_body)
            except Exception as exc:
                raise CEContextArtifactMismatch("first-import response artifact is invalid") from exc
            if (parsed.test_id != candidate
                    or parsed.deduplication_complete != state["response_deduplication_complete"]
                    or parsed.deduplication_complete != state["deduplication_complete"]):
                raise CEContextArtifactMismatch("response artifact does not match Test candidate")

        evidence = self.read_verified_context(
            request["registration_id"], request["verification_id"]
        )
        if evidence.test_id is not None:
            raise CEContextTestBindingConflict("registration already has a Test binding")
        configuration = self.read(evidence.deployment_key, evidence.deployment_config_revision)
        configured = configuration.snapshot.configured
        if request["engine_release"] != configured.ce_release:
            raise CEContextRegistrationConflict(
                "operation engine release disagrees with configured deployment release"
            )
        expected_url = f"{configured.ce_base_url}/api/v2/tests/{int(candidate)}/"
        if response.response.url != expected_url:
            raise CEContextArtifactMismatch("Test GET URL does not match configured deployment")
        document = self._json_object(response.body, "test")
        if self._related_id(document.get("id"), "test.id") != int(candidate):
            raise CEContextArtifactMismatch("Test GET ID does not match response candidate")
        if self._related_id(document.get("engagement"), "test.engagement") != evidence.engagement_id:
            raise CEContextArtifactMismatch("Test GET parent does not match registration")

        test_ref, test_digest = self.artifact_store.put(response.body)
        if test_digest != response.body_sha256 or self.artifact_store.get(test_ref, test_digest) != response.body:
            raise CEContextArtifactMismatch("Test artifact read-back does not match GET body")

        binding_id = str(uuid.uuid4())
        bound_at = datetime.now(timezone.utc)
        connection = self._binding_transaction(self.engine)
        try:
            self._lock_test_collision(connection, evidence.deployment_key, int(candidate))
            # Re-read all mutable operation state while holding the collision
            # lock.  A replay or concurrent response cannot be upgraded here.
            request = connection.execute(
                select(engine_operation_requests).where(
                    engine_operation_requests.c.operation_id == operation_id
                ).with_for_update()
            ).mappings().one_or_none()
            state = connection.execute(
                select(engine_operation_states).where(
                    engine_operation_states.c.operation_id == operation_id
                ).with_for_update()
            ).mappings().one_or_none()
            if (request is None or state is None
                    or request["registration_id"] != evidence.registration_id
                    or request["verification_id"] != evidence.verification_id
                    or state["context_key"] != request["context_key"]):
                raise CEContextTestBindingConflict("operation changed before Test binding")
            normal_response_matches = (
                not reconciled and state["status"] == "pending"
                and state["response_ref"] == response_ref
                and state["response_test_id"] == candidate
                and state["response_deduplication_complete"] == parsed.deduplication_complete
                and state["deduplication_complete"] == parsed.deduplication_complete
            ) if not reconciled else False
            reconciliation_matches = (
                reconciled and state["status"] == "quarantined"
                and state["response_ref"] is None
                and state["response_test_id"] is None
                and state["reconciliation_evidence_ref"] ==
                reconciliation.reconciliation_ref
            ) if reconciled else False
            if (request["request_kind"] != "import"
                    or request["test_id"] is not None
                    or not state["post_issued"]
                    or not (normal_response_matches or reconciliation_matches)):
                raise CEContextTestBindingConflict(
                    "operation is not the exact issued first-import candidate"
                )
            manifest_ref = connection.execute(
                select(engine_operation_manifests.c.manifest_ref).where(
                    engine_operation_manifests.c.operation_id == operation_id
                )
            ).scalar_one_or_none()
            transitions = connection.execute(
                select(engine_operation_transitions).where(
                    engine_operation_transitions.c.operation_id == operation_id,
                )
            ).mappings().all()
            if manifest_ref is None:
                raise CEContextTestBindingConflict("first import has no durable manifest")
            if reconciled:
                ordered = sorted(transitions, key=lambda row: row["to_revision"])
                if (len(ordered) != 5 or state["revision"] != 5
                        or [(row["from_revision"], row["to_revision"])
                            for row in ordered] !=
                        [(None, 1), (1, 2), (2, 3), (3, 4), (4, 5)]
                        or [row["transition_reason"] for row in ordered[:3]] !=
                        ["reservation registered", "first-import baseline recorded", "POST issued"]
                        or not ordered[3]["transition_reason"].startswith("uncertain response: ")
                        or ordered[4]["transition_reason"] != "reconciliation inventory recorded"
                        or ordered[0]["evidence_ref"] != manifest_ref
                        or ordered[1]["evidence_ref"] != baseline_ref
                        or ordered[4]["evidence_ref"] != reconciliation.reconciliation_ref
                        or any(a["occurred_at"] > b["occurred_at"]
                               for a, b in zip(ordered, ordered[1:]))):
                    raise CEContextTestBindingConflict(
                        "lost first-import history is incomplete or inconsistent"
                    )
            else:
                self._require_first_import_history(
                    state, transitions, manifest_ref, baseline_ref
                )
            registration = connection.execute(
                select(ce_context_registrations).where(
                    ce_context_registrations.c.registration_id == evidence.registration_id
                ).with_for_update()
            ).mappings().one_or_none()
            if registration is None or registration["test_id"] is not None:
                raise CEContextTestBindingConflict("registration is already Test-bound")
            collision = connection.execute(
                select(ce_context_registrations.c.registration_id).where(
                    and_(
                        ce_context_registrations.c.deployment_key == evidence.deployment_key,
                        ce_context_registrations.c.test_id == int(candidate),
                    )
                )
            ).scalar_one_or_none()
            if collision is not None:
                raise CEContextTestBindingConflict("Test is already registered for this deployment")
            existing = connection.execute(
                select(ce_context_test_bindings).where(
                    (ce_context_test_bindings.c.originating_operation_id == operation_id)
                    | (
                        (ce_context_test_bindings.c.deployment_key == evidence.deployment_key)
                        & (ce_context_test_bindings.c.test_id == int(candidate))
                    )
                )
            ).mappings().first()
            if existing is not None:
                raise CEContextTestBindingConflict("Test binding already exists or conflicts")
            connection.execute(ce_context_test_bindings.insert().values(
                binding_id=binding_id, schema_version=1,
                registration_id=evidence.registration_id,
                originating_operation_id=operation_id,
                deployment_key=evidence.deployment_key, test_id=int(candidate),
                test_body_ref=test_ref, test_body_sha256=test_digest,
                deployment_config_revision=evidence.deployment_config_revision,
                bound_at=bound_at,
            ))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return CEContextTestBindingRecord(
            binding_id=binding_id, registration_id=evidence.registration_id,
            originating_operation_id=operation_id, deployment_key=evidence.deployment_key,
            test_id=int(candidate), test_body_ref=test_ref, test_body_sha256=test_digest,
            deployment_config_revision=evidence.deployment_config_revision, bound_at=bound_at,
        )

    bind_test = bind_first_import_test


LocalCEContextStore = CEContextStore
