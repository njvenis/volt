"""UVM persistence: separate UVM database; no DefectDojo tables (CR-01)."""

# Register additive G2 ingestion tables whenever the package metadata is
# loaded (Alembic imports the package's schema modules through this package).
from uvm.persistence import ingestion_schema as _ingestion_schema  # noqa: F401,E402

from uvm.persistence.identity_repository import (  # noqa: F401,E402
    DurableIdentityRepository, IdentityRepository, DurableIdentityError,
    ResolutionRequestConflict,
)
