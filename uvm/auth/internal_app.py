"""Loopback-only provider sync listener, separate from the public API socket."""
from fastapi import FastAPI

from uvm.api.app import app as public_app

service = getattr(public_app.state, "oidc_auth", None)
if service is None:
    raise RuntimeError("OIDC loopback sync listener requires OIDC authentication mode")

app = FastAPI(title="UVM internal OIDC sync adapter")
service.install_sync_route(app)
