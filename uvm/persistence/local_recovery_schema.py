"""Private local-only recovery bindings, attestations and approval consumption."""
from sqlalchemy import Column, DateTime, Integer, JSON, String, Table, UniqueConstraint
from uvm.persistence.schema import uvm_metadata

local_recovery_installation = Table('local_recovery_installation', uvm_metadata,
    Column('installation_id', String(36), primary_key=True),
    Column('configuration_digest', String(64), nullable=False),
    Column('key_fingerprints', JSON, nullable=False),
    Column('journal_id', String(36), nullable=False),
    Column('applied_restore_generation', Integer, nullable=False),
    Column('applied_recovery_epoch_id', String(36)),
    Column('applied_at', DateTime(timezone=True), nullable=False))
local_recovery_attestations = Table('local_recovery_attestations', uvm_metadata,
    Column('attestation_id', String(36), primary_key=True),
    Column('installation_id', String(36), nullable=False),
    Column('connector_id', String(36), nullable=False),
    Column('secret_id', String(36), nullable=False),
    Column('version_id', String(36), nullable=False),
    Column('recovery_epoch_id', String(36), nullable=False),
    Column('document', JSON, nullable=False),
    Column('issued_at', DateTime(timezone=True), nullable=False),
    UniqueConstraint('connector_id','secret_id','version_id','recovery_epoch_id', name='local_recovery_attestation_version_epoch'))
local_recovery_approvals = Table('local_recovery_approvals', uvm_metadata,
    Column('approval_id', String(36), primary_key=True),
    Column('installation_id', String(36), nullable=False),
    Column('connector_id', String(36), nullable=False),
    Column('document', JSON, nullable=False),
    Column('acknowledgement', JSON, nullable=False),
    Column('consumed_command_id', String(36), unique=True),
    Column('superseded_at', DateTime(timezone=True)),
    Column('issued_at', DateTime(timezone=True), nullable=False),
    Column('expires_at', DateTime(timezone=True), nullable=False))
