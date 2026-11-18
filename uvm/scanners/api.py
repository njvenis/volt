"""Provider-owned scanner routes; backend supplies the reviewed bridge instance."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from uvm.scanners.service import ScannerService
from uvm.scanners.qualys_vm import QualysError
from uvm.scanners.store import OperationError


class _DuplicateKey(ValueError):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _error(status, code):
    return JSONResponse(status_code=status, content={'schema_version': 1, 'error': {
        'code': code, 'message': 'Scanner request could not be completed',
        'correlation_id': str(uuid.uuid4()), 'details': {}}}, headers={'Cache-Control': 'no-store'})


async def _invoke(function, *args, **kwargs):
    try:
        value = await run_in_threadpool(function, *args, **kwargs)
        content, status = value if isinstance(value, tuple) else (value, 200)
        return JSONResponse(status_code=status, content=content, headers={'Cache-Control': 'no-store'})
    except QualysError as exc:
        return _error(409, exc.code)
    except OperationError as exc:
        status = (404 if exc.code == 'not_found' else 503 if exc.code in
            {'outcome_unknown', 'persistence_unavailable', 'scanner_worker_unavailable',
             'scanner_worker_already_running', 'scanner_state_unavailable', 'startup_recovery_required'} else 422 if exc.code in
            {'invalid_request', 'invalid_settings', 'invalid_cursor'} else 409)
        return _error(status, exc.code)
    except HTTPException as exc:
        # Preserve denial/status while preventing backend/provider text disclosure.
        code = {401: 'authentication_required', 403: 'forbidden', 404: 'not_found',
            409: 'revision_conflict'}.get(exc.status_code, 'request_failed')
        return _error(exc.status_code, code)
    except (SQLAlchemyError, OSError, ValueError):
        return _error(503, 'persistence_unavailable')
    except Exception:
        return _error(503, 'outcome_unknown')


def scanner_router(service: ScannerService, *, public_origin: str) -> APIRouter:
    origin = urlsplit(public_origin)
    if (origin.scheme not in {'http', 'https'} or not origin.netloc
            or origin.path or origin.query or origin.fragment or origin.username or origin.password):
        raise ValueError('invalid_public_origin')
    router = APIRouter(prefix='/api/v1/scanners')

    @router.get('/{connector_id}')
    async def view(connector_id: str, request: Request, source_id: str | None = None):
        return await _invoke(service.view, request, connector_id, source_id)

    @router.post('/{connector_id}/commands')
    async def command(connector_id: str, request: Request):
        # CSRF token validation and fresh session checks belong to backend's
        # transaction/local-auth service; no duplicate auth policy here.
        if request.headers.get('origin') != public_origin or not request.headers.get('x-csrf-token'):
            return _error(403, 'csrf_failed')
        if request.headers.get('content-type', '').lower().split(';')[0].strip() != 'application/json':
            return _error(422, 'invalid_request')
        declared = request.headers.get('content-length')
        if declared is not None:
            try:
                if not 0 <= int(declared) <= 65536:
                    return _error(422, 'invalid_request')
            except ValueError:
                return _error(422, 'invalid_request')
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 65536:
                return _error(422, 'invalid_request')
        try:
            parsed = json.loads(bytes(body), object_pairs_hook=_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeDecodeError):
            return _error(422, 'invalid_request')
        return await _invoke(service.command, request, connector_id, parsed)

    @router.get('/{connector_id}/operations/{operation_id}')
    async def operation(connector_id: str, operation_id: str, request: Request, source_id: str | None = None):
        return await _invoke(service.operation, request, connector_id, source_id, operation_id)

    @router.get('/{connector_id}/runs/{run_id}/detections')
    async def detections(connector_id: str, run_id: str, request: Request, source_id: str | None = None,
                         limit: str = '50', cursor: str | None = None):
        try:
            page_size = int(limit)
        except ValueError:
            return _error(422, 'invalid_request')
        return await _invoke(service.detection_page, request, connector_id, source_id,
            run_id, limit=page_size, cursor=cursor)

    return router


def install_scanner_routes(app, service: ScannerService, *, public_origin: str):
    """Side-effect-free route composition: no DB/recovery or lifecycle replacement.

    Backend composes scanner_worker_lifespan AFTER migrations/state validation in
    its existing app lifespan, and supplies current-session/CSRF middleware.
    No fixture bridge/transport is selected from installation config/environment.
    """
    app.include_router(scanner_router(service, public_origin=public_origin))

    @app.middleware('http')
    async def scanner_no_store(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith('/api/v1/scanners'):
            response.headers['Cache-Control'] = 'no-store'
        return response


@asynccontextmanager
async def scanner_worker_lifespan(service: ScannerService):
    """Compose inside the existing backend lifespan after migrations/state setup.

    Does not replace/register any application hooks. Startup fails closed if a
    live worker owns the provider lock. Yield is the startup recovery count.
    """
    with service.worker_lifetime() as recovered:
        yield recovered
