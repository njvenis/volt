"""Immutable DefectDojo CE context registration contract (G1)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from .ce_read_client import CEReadClient, RawResponse, Resource


class CEContextVerificationError(ValueError):
    """The supplied CE client/configuration cannot establish this scope."""


class CEDeploymentMismatchError(CEContextVerificationError):
    """The client is not the configured CE deployment."""


def canonical_base_url(value: str) -> str:
    if not isinstance(value, str) or "?" in value or "#" in value:
        raise ValueError("ce_base_url must be an absolute HTTP(S) URL without query or fragment")
    parsed = urlsplit(value.rstrip("/"))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("ce_base_url must be an absolute HTTP(S) URL without query or fragment")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("ce_base_url must not contain user information")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"


@dataclass(frozen=True)
class ConfiguredCEDeploymentV1:
    """Caller-supplied deployment identity, not proof of a live deployment."""

    schema_version: int
    deployment_key: str
    ce_base_url: str
    ce_release: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        for name in ("deployment_key", "ce_release"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        object.__setattr__(self, "deployment_key", self.deployment_key.strip())
        object.__setattr__(self, "ce_release", self.ce_release.strip())
        object.__setattr__(self, "ce_base_url", canonical_base_url(self.ce_base_url))


# Short aliases keep the boundary discoverable for callers that use the
# deployment/configuration terminology; both names denote the same DTO.
CEDeploymentConfigV1 = ConfiguredCEDeploymentV1
ConfiguredDeploymentV1 = ConfiguredCEDeploymentV1


@dataclass(frozen=True)
class CEObservedResponseV1:
    resource: str
    response: RawResponse
    body: bytes
    body_sha256: str

    def __post_init__(self) -> None:
        response = RawResponse(
            self.response.status,
            dict(self.response.headers),
            bytes(self.response.body),
            self.response.url,
        )
        body = bytes(self.body)
        if body != response.body or self.body_sha256 != response.sha256:
            raise ValueError("observation bytes and digest must match the exact RawResponse")
        object.__setattr__(self, "response", response)
        object.__setattr__(self, "body", body)


@dataclass(frozen=True)
class CEContextObservationV1:
    """Synthetic, read-only observation; it is not durable or live evidence."""

    schema_version: int
    deployment_key: str
    ce_base_url: str
    ce_release: str
    product_id: int
    engagement_id: int
    test_id: int | None
    responses: tuple[CEObservedResponseV1, ...]
    provenance: str = "caller-provided configuration + synthetic GET result"
    trusted_runtime_config: bool = False
    durable_evidence: bool = False
    live_provenance: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        if self.provenance != "caller-provided configuration + synthetic GET result":
            raise ValueError("unsupported observation provenance")
        if self.trusted_runtime_config or self.durable_evidence or self.live_provenance:
            raise ValueError("synthetic observation cannot claim trusted, durable or live provenance")
        object.__setattr__(self, "ce_base_url", canonical_base_url(self.ce_base_url))
        object.__setattr__(self, "responses", tuple(
            CEObservedResponseV1(
                item.resource,
                item.response,
                item.body,
                item.body_sha256,
            )
            for item in self.responses
        ))


def _observed(resource: str, result: Resource) -> CEObservedResponseV1:
    return CEObservedResponseV1(resource, result.response, result.response.body, result.response.sha256)


def verify_ce_context(
    configured: ConfiguredCEDeploymentV1,
    client: CEReadClient,
    *,
    context_key: str,
    product_id: int,
    engagement_id: int,
    test_id: int | None = None,
    registration_id: str | None = None,
) -> tuple[CEContextRegistrationV1, CEContextObservationV1]:
    """Read and validate a Product → Engagement → optional Test chain.

    Numeric IDs are only scoped by the supported CE parent checks; they never
    establish deployment identity.  The returned registration is a candidate
    for a separate durable writer and the observation is synthetic evidence.
    """
    if not isinstance(client, CEReadClient) or client.base_url != configured.ce_base_url:
        raise CEDeploymentMismatchError("provided CE client does not match configured base URL")
    product = client.get_product(product_id)
    engagement = client.get_engagement(engagement_id, product_id=product_id)
    test = client.get_test(test_id, engagement_id=engagement_id) if test_id is not None else None
    responses = [_observed("product", product), _observed("engagement", engagement)]
    if test is not None:
        responses.append(_observed("test", test))
    registration = CEContextRegistrationV1(
        schema_version=1,
        registration_id=registration_id or str(uuid.uuid4()),
        deployment_key=configured.deployment_key,
        context_key=context_key,
        product_id=product_id,
        engagement_id=engagement_id,
        test_id=test_id,
        ce_base_url=configured.ce_base_url,
        ce_release=configured.ce_release,
    )
    observation = CEContextObservationV1(
        schema_version=1,
        deployment_key=configured.deployment_key,
        ce_base_url=configured.ce_base_url,
        ce_release=configured.ce_release,
        product_id=product_id,
        engagement_id=engagement_id,
        test_id=test_id,
        responses=tuple(responses),
    )
    return registration, observation


verify_context = verify_ce_context


@dataclass(frozen=True)
class CEContextRegistrationV1:
    """The durable identity of one CE Product/Engagement context.

    ``test_id`` is deliberately optional for the first import.  It may be
    bound once, after supported-API confirmation; a second or changed binding
    is rejected here and must never be represented as an update in storage.
    Cross-context CE relationship checks remain a writer/read-back invariant.
    """

    schema_version: int
    registration_id: str
    deployment_key: str
    context_key: str
    product_id: int
    engagement_id: int
    test_id: int | None = None
    ce_base_url: str | None = None
    ce_release: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        try:
            uuid.UUID(self.registration_id)
        except (ValueError, AttributeError, TypeError):
            raise ValueError("registration_id must be a UUID") from None
        for name in ("deployment_key", "context_key"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty")
        for name in ("product_id", "engagement_id"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.test_id is not None and (
            not isinstance(self.test_id, int)
            or isinstance(self.test_id, bool)
            or self.test_id <= 0
        ):
            raise ValueError("test_id must be null or a positive integer")
        if self.ce_base_url is not None:
            object.__setattr__(self, "ce_base_url", canonical_base_url(self.ce_base_url))
        if self.ce_release is not None and (not isinstance(self.ce_release, str) or not self.ce_release.strip()):
            raise ValueError("ce_release must be null or non-empty")
        if isinstance(self.ce_release, str):
            object.__setattr__(self, "ce_release", self.ce_release.strip())

    def bind_test(self, test_id: int) -> "CEContextRegistrationV1":
        """Return the one permitted Test binding; refuse rebinding."""
        if not isinstance(test_id, int) or isinstance(test_id, bool) or test_id <= 0:
            raise ValueError("test_id must be a positive integer")
        if self.test_id is not None:
            raise ValueError("CE Test binding is once-only")
        return replace(self, test_id=test_id)
