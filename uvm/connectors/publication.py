"""Shared-reader promotion fences for registered local Qualys checkpoints."""
from __future__ import annotations

import sqlalchemy as sa

from uvm.auth.schema import AUTHORITY_CONTEXT
from uvm.persistence.connector_schema import connectors
from uvm.persistence.connector_binding_schema import connector_bindings
from uvm.persistence.ingestion_schema import collection_runs
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.lineage_schema import identity_resolutions
from uvm.persistence.schema import groups, occurrences, exposures
from uvm.scanners.store import publications, operations


def _local(context=None):
    context = context if context is not None else AUTHORITY_CONTEXT.get()
    return context is not None and context.credential_mode == 'local_session'


def run_is_published_clause(run, context=None):
    """Non-local readers retain their existing contract; local Qualys fails closed."""
    if not _local(context):
        return sa.true()
    registry = connectors.alias('publication_connector')
    binding = connector_bindings.alias('publication_binding')
    publication = publications.alias('shared_publication')
    operation = operations.alias('publication_operation')
    published = sa.exists(sa.select(1).select_from(publication.join(registry,
        sa.and_(registry.c.connector_id == publication.c.connector_id,
            registry.c.source_id == publication.c.source_id)).join(binding,
        binding.c.connector_id == registry.c.connector_id).join(operation,
        sa.and_(operation.c.operation_id == publication.c.operation_id,
            operation.c.run_id == publication.c.run_id,
            operation.c.connector_id == registry.c.connector_id,
            operation.c.source_id == registry.c.source_id))).where(
        sa.cast(publication.c.run_id, sa.String) == sa.cast(run.c.run_id, sa.String),
        registry.c.source_family == run.c.source_family,
        registry.c.source_account_id == run.c.source_account_id,
        registry.c.scope_key == run.c.scope_key,
        binding.c.registration['product'].as_string() == 'qualys_vm',
        operation.c.status.in_(('succeeded', 'partial'))))
    return sa.or_(run.c.source_family != 'qualys', published)


def observation_is_published_clause(observation, context=None):
    if not _local(context):
        return sa.true()
    run = collection_runs.alias('publication_source_run')
    return sa.or_(observation.c.source_family != 'qualys', sa.exists(
        sa.select(1).select_from(run).where(
            sa.cast(run.c.run_id, sa.String) == observation.c.run_id,
            run.c.source_family == observation.c.source_family,
            run.c.source_account_id == observation.c.source_account_id,
            run_is_published_clause(run, context))))


def group_is_published(connection, group_id, context=None):
    if not _local(context):
        return True
    family = connection.execute(sa.select(groups.c.source_family).where(
        groups.c.group_id == group_id)).scalar_one_or_none()
    if family != 'qualys':
        return True
    observation = source_observations.alias('publication_group_observation')
    resolved = sa.exists(sa.select(1).select_from(identity_resolutions).where(
        identity_resolutions.c.observation_id == observation.c.observation_id,
        identity_resolutions.c.group_id == group_id))
    exposed = sa.exists(sa.select(1).select_from(occurrences.join(exposures,
        occurrences.c.exposure_id == exposures.c.exposure_id)).where(
        occurrences.c.occurrence_id == observation.c.occurrence_id,
        exposures.c.group_id == group_id))
    associated = sa.or_(resolved, exposed)
    known = connection.execute(sa.select(observation.c.observation_id).where(
        associated).limit(1)).first()
    if known is None:
        return False
    # Generic finding projections aggregate their retained histories. Deny the
    # projection if any associated checkpoint is unpublished, avoiding leaked
    # new observations through an older published group identity.
    hidden = connection.execute(sa.select(observation.c.observation_id).where(
        associated, ~observation_is_published_clause(observation, context)).limit(1)).first()
    return hidden is None
