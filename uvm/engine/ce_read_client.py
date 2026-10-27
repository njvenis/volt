"""Small, GET-only, supported-API reader for the retained CE 3.3.100 routes.

This module deliberately owns no persistence and makes no live-environment or
G1 claim.  The transport is injected so callers can retain the exact response
bytes and tests never need a CE server.
"""
from __future__ import annotations

import json
import hashlib
import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qs, quote, urlencode, urlsplit


class CEReadError(Exception):
    """Base class for typed read-client failures."""

    def __init__(self, message: str, response: "RawResponse | None" = None) -> None:
        self.response = response
        super().__init__(message)


class TransportError(CEReadError):
    def __init__(self, message: str, response: "RawResponse | None" = None) -> None:
        super().__init__(message, response)


class HTTPError(CEReadError):
    def __init__(self, response: "RawResponse") -> None:
        super().__init__(f"DefectDojo GET returned HTTP {response.status}", response)


class JSONError(CEReadError):
    pass


class ShapeError(CEReadError):
    pass


class ScopeError(CEReadError):
    pass


class PaginationError(CEReadError):
    pass


@dataclass(frozen=True)
class RawResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str

    def __post_init__(self) -> None:
        header_items = tuple(self.headers.items())
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in header_items):
            raise TypeError("response header names and values must be strings")
        object.__setattr__(self, "headers", MappingProxyType(dict(header_items)))
        if not isinstance(self.body, bytes):
            object.__setattr__(self, "body", bytes(self.body))

    @property
    def sha256(self) -> str:
        """Digest of the exact bytes returned by CE."""
        return hashlib.sha256(self.body).hexdigest()

    @property
    def body_sha256(self) -> str:
        return self.sha256


@dataclass(frozen=True)
class Resource:
    data: Mapping[str, Any]
    response: RawResponse


@dataclass(frozen=True)
class Collection:
    items: tuple[Mapping[str, Any], ...]
    pages: tuple[RawResponse, ...]
    count: int


class Transport(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        *,
        follow_redirects: bool,
    ) -> Any: ...


ROUTES = {
    "products": "/api/v2/products/",
    "engagements": "/api/v2/engagements/",
    "tests": "/api/v2/tests/",
    "findings": "/api/v2/findings/",
    "endpoints": "/api/v2/endpoints/",
}
DETAIL_ROUTES = {name: path + "{id}/" for name, path in ROUTES.items()}


def _id(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ShapeError(f"{name} must be a positive integer")
    return value


def _related_id(value: Any, name: str) -> int:
    if isinstance(value, dict):
        value = value.get("id")
    return _id(value, name)


def _scope_checker(
    field: str,
    expected: int,
    relation: str,
    message: str,
) -> Callable[[Mapping[str, Any]], None]:
    def check(item: Mapping[str, Any]) -> None:
        if _related_id(item.get(field), relation) != expected:
            raise ScopeError(message)

    return check


class CEReadClient:
    """Injected-transport GET client for CE 3.3.100's allowlisted routes."""

    def __init__(
        self,
        base_url: str,
        transport: Transport | Callable[..., Any],
        *,
        token: str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 10.0,
        max_pages: int = 1000,
    ) -> None:
        if "?" in base_url or "#" in base_url:
            raise ValueError("base_url must be an absolute http(s) URL without query or fragment")
        parsed = urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("base_url must be an absolute http(s) URL without query or fragment")
        if timeout <= 0 or timeout > 300:
            raise ValueError("timeout must be greater than 0 and no more than 300 seconds")
        if max_pages <= 0:
            raise ValueError("max_pages must be positive")
        if token is not None and (not isinstance(token, str) or not token):
            raise ValueError("token must be a non-empty string when supplied")
        if token is not None and ("\r" in token or "\n" in token):
            raise ValueError("token must not contain newlines")
        supplied = dict(headers or {})
        if any("\r" in k or "\n" in k or "\r" in str(v) or "\n" in str(v) for k, v in supplied.items()):
            raise ValueError("header names and values must not contain newlines")
        if any(k.lower() == "authorization" for k in supplied) and token is not None:
            raise ValueError("supply authentication through token or headers, not both")
        self._origin = (parsed.scheme.lower(), parsed.netloc.lower())
        self._base_path = parsed.path.rstrip("/")
        self._base = f"{self._origin[0]}://{self._origin[1]}{self._base_path}"
        self._transport = transport
        self._headers = supplied
        if token is not None:
            self._headers["Authorization"] = f"Token {token}"
        self._timeout = float(timeout)
        self._max_pages = max_pages

    @property
    def base_url(self) -> str:
        """Canonical configured CE base URL; callers cannot alter client state."""
        return self._base

    @property
    def normalized_base_url(self) -> str:
        return self._base

    def _url(self, path: str, params: Mapping[str, Any] | None = None) -> str:
        detail_allowed = any(
            path.startswith(route) and path[len(route):-1].isdigit() and path.endswith("/")
            for route in ROUTES.values()
        )
        if path not in ROUTES.values() and not detail_allowed:
            raise ValueError("route is not in the CE 3.3.100 GET allowlist")
        return self._base + path + ("?" + urlencode(params, doseq=True) if params else "")

    def _next_url(
        self,
        kind: str,
        value: Any,
        fixed_params: Mapping[str, Any],
    ) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            raise PaginationError("next must be null or a non-empty URL")
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or parsed.fragment:
            raise PaginationError("next link is not an absolute HTTP(S) URL")
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self._origin:
            raise PaginationError("next link crosses the configured origin")
        expected_path = self._base_path + ROUTES[kind]
        if parsed.path != expected_path:
            raise PaginationError("next link leaves the configured collection or base path")
        expected_query = parse_qs(urlencode(fixed_params, doseq=True), keep_blank_values=True)
        actual_query = parse_qs(parsed.query, keep_blank_values=True)
        for key, expected_values in expected_query.items():
            if actual_query.get(key) != expected_values:
                raise PaginationError("next link changes a fixed collection filter")
        return value

    def _request(self, url: str) -> RawResponse:
        try:
            result = self._transport(
                "GET",
                url,
                dict(self._headers),
                self._timeout,
                follow_redirects=False,
            )
        except CEReadError:
            raise
        except Exception as exc:
            raise TransportError("DefectDojo GET transport failed") from exc
        try:
            if isinstance(result, RawResponse):
                response = result
            elif isinstance(result, tuple) and len(result) == 3:
                response = RawResponse(int(result[0]), dict(result[1]), bytes(result[2]), url)
            else:
                response = RawResponse(
                    int(result.status),
                    dict(result.headers),
                    bytes(result.body),
                    str(getattr(result, "url", url)),
                )
        except Exception as exc:
            raise TransportError("transport returned an invalid response") from exc
        if response.url != url:
            raise TransportError(
                "transport followed a redirect or returned an unexpected effective URL",
                response,
            )
        if response.status < 200 or response.status >= 300:
            raise HTTPError(response)
        return response

    @staticmethod
    def _json(response: RawResponse) -> Any:
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
            return json.loads(
                response.body.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_non_finite,
                parse_float=reject_non_finite_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise JSONError("CE response body is not valid UTF-8 JSON", response) from exc

    @staticmethod
    def _attach_response(error: CEReadError, response: RawResponse) -> None:
        if error.response is None:
            error.response = response

    def _detail(self, kind: str, item_id: int) -> Resource:
        path = ROUTES[kind] + quote(str(_id(item_id, f"{kind} id")), safe="") + "/"
        response = self._request(self._url(path))
        try:
            data = self._json(response)
            if not isinstance(data, dict):
                raise ShapeError(f"{kind} detail must be a JSON object")
            if _related_id(data.get("id"), f"{kind} id") != item_id:
                raise ScopeError(f"{kind} detail id does not match requested id")
        except CEReadError as exc:
            self._attach_response(exc, response)
            raise
        return Resource(data, response)

    def _collection(
        self,
        kind: str,
        params: Mapping[str, Any] | None = None,
        *,
        scope_checker: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> Collection:
        fixed_params = dict(params or {})
        url = self._url(ROUTES[kind], fixed_params)
        pages: list[RawResponse] = []
        items: list[Mapping[str, Any]] = []
        seen_urls: set[str] = set()
        count: int | None = None
        while url is not None:
            if url in seen_urls:
                raise PaginationError("pagination loop detected", pages[-1] if pages else None)
            if len(pages) >= self._max_pages:
                raise PaginationError("pagination exceeded max_pages", pages[-1] if pages else None)
            seen_urls.add(url)
            response = self._request(url)
            try:
                data = self._json(response)
                if not isinstance(data, dict) or isinstance(data.get("results"), (str, bytes)) or not isinstance(data.get("results"), list):
                    raise ShapeError(f"{kind} collection must contain a results list")
                reported = data.get("count")
                if isinstance(reported, bool) or not isinstance(reported, int) or reported < 0:
                    raise ShapeError("collection count must be a non-negative integer")
                if count is None:
                    count = reported
                elif count != reported:
                    raise PaginationError("collection page counts disagree")
                for item in data["results"]:
                    if not isinstance(item, dict):
                        raise ShapeError("collection results must be JSON objects")
                    item_id = item.get("id")
                    _id(item_id, f"{kind} result id")
                    if scope_checker is not None:
                        scope_checker(item)
                    if any(existing.get("id") == item_id for existing in items):
                        raise PaginationError("duplicate item id across collection pages")
                    items.append(item)
                pages.append(response)
                url = self._next_url(kind, data.get("next"), fixed_params)
            except CEReadError as exc:
                self._attach_response(exc, response)
                raise
        assert count is not None
        if len(items) != count:
            raise PaginationError(f"collection count {count} does not cover {len(items)} results", pages[-1] if pages else None)
        return Collection(tuple(items), tuple(pages), count)

    def list_products(self, **params: Any) -> Collection:
        return self._collection("products", params)

    def list_engagements(self, *, product_id: int | None = None, **params: Any) -> Collection:
        if product_id is not None:
            params["product"] = _id(product_id, "product_id")
        return self._collection(
            "engagements",
            params,
            scope_checker=(
                _scope_checker(
                    "product",
                    product_id,
                    "engagement product",
                    "engagement collection contains a different Product",
                )
                if product_id is not None
                else None
            ),
        )

    def list_tests(self, *, engagement_id: int | None = None, **params: Any) -> Collection:
        if engagement_id is not None:
            params["engagement"] = _id(engagement_id, "engagement_id")
        return self._collection(
            "tests",
            params,
            scope_checker=(
                _scope_checker(
                    "engagement",
                    engagement_id,
                    "test engagement",
                    "test collection contains a different Engagement",
                )
                if engagement_id is not None
                else None
            ),
        )

    def list_findings(self, *, test_id: int, **params: Any) -> Collection:
        params["test"] = _id(test_id, "test_id")
        return self._collection(
            "findings",
            params,
            scope_checker=_scope_checker(
                "test",
                test_id,
                "finding test",
                "finding collection contains a different Test",
            ),
        )

    def list_endpoints(self, *, product_id: int | None = None, **params: Any) -> Collection:
        if "product" in params:
            raise ShapeError("use product_id for the endpoint product filter")
        if product_id is not None:
            params["product"] = _id(product_id, "product_id")
        return self._collection(
            "endpoints",
            params,
            scope_checker=(
                _scope_checker(
                    "product",
                    product_id,
                    "endpoint product",
                    "endpoint collection contains a different Product",
                )
                if product_id is not None
                else None
            ),
        )

    def get_product(self, product_id: int) -> Resource:
        return self._detail("products", product_id)

    def get_engagement(self, engagement_id: int, *, product_id: int | None = None) -> Resource:
        engagement_id = _id(engagement_id, "engagement id")
        expected_product_id = _id(product_id, "product_id") if product_id is not None else None
        result = self._detail("engagements", engagement_id)
        try:
            if expected_product_id is not None and _related_id(result.data.get("product"), "engagement product") != expected_product_id:
                raise ScopeError("engagement belongs to a different Product", result.response)
        except CEReadError as exc:
            self._attach_response(exc, result.response)
            raise
        return result

    def get_test(self, test_id: int, *, engagement_id: int | None = None) -> Resource:
        test_id = _id(test_id, "test id")
        expected_engagement_id = _id(engagement_id, "engagement_id") if engagement_id is not None else None
        result = self._detail("tests", test_id)
        try:
            if expected_engagement_id is not None and _related_id(result.data.get("engagement"), "test engagement") != expected_engagement_id:
                raise ScopeError("test belongs to a different Engagement", result.response)
        except CEReadError as exc:
            self._attach_response(exc, result.response)
            raise
        return result

    def get_finding(self, finding_id: int, *, test_id: int) -> Resource:
        finding_id = _id(finding_id, "finding id")
        test_id = _id(test_id, "test_id")
        result = self._detail("findings", finding_id)
        try:
            if _related_id(result.data.get("test"), "finding test") != test_id:
                raise ScopeError("finding belongs to a different Test", result.response)
        except CEReadError as exc:
            self._attach_response(exc, result.response)
            raise
        return result

    def get_endpoint(self, endpoint_id: int, *, product_id: int | None = None) -> Resource:
        endpoint_id = _id(endpoint_id, "endpoint id")
        expected_product_id = _id(product_id, "product_id") if product_id is not None else None
        result = self._detail("endpoints", endpoint_id)
        try:
            if expected_product_id is not None and _related_id(result.data.get("product"), "endpoint product") != expected_product_id:
                raise ScopeError("endpoint belongs to a different Product", result.response)
        except CEReadError as exc:
            self._attach_response(exc, result.response)
            raise
        return result
