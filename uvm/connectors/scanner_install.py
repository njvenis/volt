"""Backend composition of the scanner bridge with the existing app lifespan."""
from contextlib import asynccontextmanager

from uvm.connectors.scanner_runtime import SharedScannerRuntime
from uvm.scanners.api import install_scanner_routes, scanner_worker_lifespan
from uvm.scanners.evidence import PrivateEvidenceStore
from uvm.scanners.service import ScannerService


def install_shared_scanners(app, *, private_evidence_directory, public_origin):
    """Compose routes without DB/private-state reads or constructor recovery.

    Existing lifecycle runs first (including restore/private-state hooks).
    Worker startup then validates provider tables/private directory and acquires
    exclusive process-lifetime ownership before recovering interrupted work.
    """
    app.state.scanner_runtime = SharedScannerRuntime(app)
    service = ScannerService(engine=app.state.engine, adapters=app.state.scanner_runtime,
        evidence=PrivateEvidenceStore(private_evidence_directory))
    app.state.scanner_service = service
    install_scanner_routes(app, service, public_origin=public_origin)
    previous_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def scanner_lifespan(application):
        async with previous_lifespan(application) as state:
            async with scanner_worker_lifespan(application.state.scanner_service):
                yield state

    app.router.lifespan_context = scanner_lifespan
    return service
