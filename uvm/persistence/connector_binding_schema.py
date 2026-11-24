"""User-facing identity metadata for exact source bindings."""
from sqlalchemy import Column, ForeignKey, JSON, String, Table

from uvm.persistence.schema import uvm_metadata

connector_bindings = Table(
    "g7_connector_bindings", uvm_metadata,
    Column("connector_id", String(36), ForeignKey("g7_connectors.connector_id"), primary_key=True),
    Column("display_name", String(120), nullable=False),
    Column("registration", JSON, nullable=True),
)
