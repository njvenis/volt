"""Atomic admission of signed independent backup status projections."""
from datetime import timedelta, timezone
import hashlib
import os
import re
import uuid

import sqlalchemy as sa
from fastapi import HTTPException
from uvm.operations.backup_host import parse_utc, validate_policy, verify_signature
from uvm.persistence.backup_settings_schema import (g7_backup_host_records,
    g7_backup_settings_revisions, g7_backup_state)
from uvm.persistence.assessment_schema import assessment_policy
from uvm.assessment.policy_lock import lock_policy
from uvm.auth.native_authority import native_state


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError('invalid exact status object')


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise ValueError('invalid digest')
    return value[7:]


def _uuid(value):
    if str(uuid.UUID(value)) != value:
        raise ValueError('invalid UUID')


def _failure(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', value)):
        raise ValueError('invalid failure code')


def admit_status(engine, deployment_id, body, entry, now):
    try:
        _exact(body, 'schema_version deployment_id report_id sequence controller_instance_id report_kind host_policy desired settings_application completed_archive freshness restore_verification recovery_epoch observed_at fresh_until signature')
        if (type(body['schema_version']) is not int or body['schema_version'] != 1 or
                body['deployment_id'] != deployment_id or body['report_kind'] != 'status' or
                body['controller_instance_id'] != os.environ['UVM_G7_CONTROLLER_INSTANCE_ID'] or
                type(body['sequence']) is not int or body['sequence'] < 1 or
                type(body['recovery_epoch']) is not int or body['recovery_epoch'] < 0):
            raise ValueError('invalid status identity')
        _uuid(body['report_id']); _uuid(body['controller_instance_id'])
        policy = validate_policy(body['host_policy'])
        observed, fresh_until = parse_utc(body['observed_at']), parse_utc(body['fresh_until'])
        if fresh_until != observed + timedelta(seconds=policy['maximum_report_age_seconds']):
            raise ValueError('invalid signed freshness')
        key_id = os.environ['UVM_G7_HOST_KEY_ID']
        raw, signature = verify_signature(body, entry['verification_key_file'], key_id)
        desired = body['desired']
        if desired is not None:
            _exact(desired, 'revision digest')
            if type(desired['revision']) is not int or desired['revision'] < 1:
                raise ValueError('invalid desired revision')
            _digest(desired['digest'])
        application = body['settings_application']
        if application is not None:
            _exact(application, 'state requested_revision requested_digest intent_id host_policy_revision active_revision active_digest reported_at failure_code')
            if application['state'] not in {'pending', 'applied', 'failed', 'uncertain', 'unknown'}:
                raise ValueError('invalid application state')
            for name in ('requested_revision', 'host_policy_revision'):
                if name == 'host_policy_revision' and application[name] is None:
                    continue
                if type(application[name]) is not int or application[name] < 1:
                    raise ValueError('invalid application revision')
            _digest(application['requested_digest'])
            if application['intent_id'] is not None: _uuid(application['intent_id'])
            if application['active_revision'] is not None:
                if type(application['active_revision']) is not int or application['active_revision'] < 1:
                    raise ValueError('invalid active revision')
                _digest(application['active_digest'])
            elif application['active_digest'] is not None: raise ValueError('unpaired active digest')
            if application['reported_at'] is not None: parse_utc(application['reported_at'])
            _failure(application['failure_code'])
        archive = body['completed_archive']
        _exact(archive, 'archive_id completed_at manifest_digest outcome')
        if archive['outcome'] not in {None, 'complete', 'failed', 'uncertain'}:
            raise ValueError('invalid archive outcome')
        if archive['archive_id'] is not None: _uuid(archive['archive_id'])
        completed = parse_utc(archive['completed_at']) if archive['completed_at'] is not None else None
        if archive['manifest_digest'] is not None: _digest(archive['manifest_digest'])
        if archive['outcome'] == 'complete' and (not completed or not archive['archive_id'] or not archive['manifest_digest']):
            raise ValueError('incomplete archive descriptor')
        freshness = body['freshness']
        _exact(freshness, 'state evaluated_at age_seconds basis_completed_at maximum_backup_age_seconds')
        if freshness['state'] not in {'fresh', 'stale', 'unknown'}: raise ValueError('invalid archive freshness')
        for name in ('age_seconds', 'maximum_backup_age_seconds'):
            if freshness[name] is not None and (type(freshness[name]) is not int or freshness[name] < 0):
                raise ValueError('invalid archive age')
        for name in ('evaluated_at', 'basis_completed_at'):
            if freshness[name] is not None: parse_utc(freshness[name])
        restore = body['restore_verification']
        _exact(restore, 'state archive_id recovery_epoch verified_at failure_code')
        if (restore['state'] not in {'verified', 'failed', 'uncertain', 'unknown'} or
                type(restore['recovery_epoch']) is not int or restore['recovery_epoch'] != body['recovery_epoch']):
            raise ValueError('invalid restore status')
        if restore['archive_id'] is not None: _uuid(restore['archive_id'])
        if restore['verified_at'] is not None: parse_utc(restore['verified_at'])
        _failure(restore['failure_code'])
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(400, {'code': 'invalid_request', 'message': 'Signed backup status is invalid'}) from None
    with engine.begin() as connection:
        lock_policy(connection)
        current_policy = connection.execute(sa.select(assessment_policy).where(
            assessment_policy.c.policy_id == 1).with_for_update()).mappings().one()
        state = connection.execute(sa.select(g7_backup_state).where(
            g7_backup_state.c.deployment_id == deployment_id).with_for_update()).mappings().first()
        prior = connection.execute(sa.select(g7_backup_host_records).where(
            g7_backup_host_records.c.record_id == body['report_id'])).mappings().first()
        record_digest = hashlib.sha256(raw).hexdigest()
        if prior:
            if prior['record_digest'] != record_digest or prior['document'] != body:
                raise HTTPException(409, {'code': 'command_conflict', 'message': 'Report ID conflicts'})
            return prior['response']
        floor = connection.execute(sa.select(sa.func.max(g7_backup_host_records.c.recovery_epoch)).where(
            g7_backup_host_records.c.deployment_id == deployment_id,
            g7_backup_host_records.c.record_kind == 'resync')).scalar_one() or 0
        if (not state or state['host_policy_document'] != policy or
                body['sequence'] != int(state['latest_sequence'] or 0) + 1 or
                body['recovery_epoch'] != int(state['recovery_epoch'] or 0) or
                body['recovery_epoch'] < floor or
                observed > now + timedelta(seconds=policy['maximum_future_skew_seconds'])):
            raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Status policy, sequence, epoch or clock changed'})
        response = {'schema_version': 1, 'deployment_id': deployment_id,
            'report_id': body['report_id'], 'sequence': body['sequence'], 'accepted': True,
            'report_kind': 'status', 'policy_revision': current_policy['revision'],
            'authority_revision': int(native_state(current_policy['document']).get('revision', 0)),
            'host_policy_revision': policy['revision'], 'policy_digest': policy['digest'],
            'desired_revision': desired['revision'] if desired else None,
            'desired_digest': desired['digest'] if desired else None,
            'accepted_at': now.isoformat().replace('+00:00', 'Z')}
        updates = {'latest_sequence': body['sequence'], 'updated_at': now}
        evidence_links = {}
        policy_observed = state['host_policy_observed_at']
        if policy_observed and policy_observed.tzinfo is None:
            policy_observed = policy_observed.replace(tzinfo=timezone.utc)
        last_observed = state['latest_report_at']
        if last_observed and last_observed.tzinfo is None:
            last_observed = last_observed.replace(tzinfo=timezone.utc)
        fresh = (now <= fresh_until and policy_observed is not None and
            now <= policy_observed + timedelta(seconds=policy['maximum_report_age_seconds']) and
            (last_observed is None or observed >= last_observed))
        if fresh:
            updates.update(latest_report_id=body['report_id'], latest_report_at=observed)
            current_desired = {'revision': state['requested_revision'],
                'digest': 'sha256:' + state['requested_digest']} if state['requested_revision'] else None
            if desired == current_desired and application is not None:
                if (application['requested_revision'] != state['requested_revision'] or
                        application['requested_digest'] != current_desired['digest'] or
                        application['intent_id'] != state['application_intent_id'] or
                        (application['host_policy_revision'] != policy['revision'] and
                            (application['state'] != state['application_status'] or
                                application['active_revision'] != state['effective_revision'] or
                                application['active_digest'] != ('sha256:' + state['effective_digest'] if state['effective_digest'] else None)))):
                    raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Application intent differs'})
                if application['host_policy_revision'] is None:
                    from uvm.operations.backup_settings import admitted_application_evidence, projection_evidence
                    admitted = admitted_application_evidence(connection, deployment_id,
                        projection_evidence(connection, deployment_id).get('application_evidence_record_id'))
                    if (application['reported_at'] is not None or
                            (admitted is not None and admitted['host_policy_revision'] is not None) or
                            application['state'] != state['application_status'] or
                            application['active_revision'] != state['effective_revision'] or
                            application['active_digest'] != ('sha256:' + state['effective_digest'] if state['effective_digest'] else None)):
                        raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Unknown application provenance may only carry unchanged legacy state'})
                elif application['host_policy_revision'] != policy['revision']:
                    old_acks = connection.execute(sa.select(g7_backup_host_records.c.document).where(
                        g7_backup_host_records.c.deployment_id == deployment_id,
                        g7_backup_host_records.c.record_kind == 'ack')).scalars()
                    if not any(ack['intent_id'] == application['intent_id'] and
                            ack['host_policy_revision'] == application['host_policy_revision'] and
                            ack['observed_at'] == application['reported_at'] and
                            ack['outcome'] == application['state'] and
                            ack['active_revision'] == application['active_revision'] and
                            ack['active_digest'] == application['active_digest'] for ack in old_acks):
                        raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Historical application policy lacks its exact acknowledgement'})
                reported_at = parse_utc(application['reported_at']) if application['reported_at'] else None
                if reported_at and reported_at > now + timedelta(seconds=policy['maximum_future_skew_seconds']):
                    raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Application evidence is future dated'})
                if reported_at is None or now - reported_at > timedelta(seconds=policy['maximum_report_age_seconds']):
                    from uvm.operations.backup_settings import admitted_application_evidence, projection_evidence
                    admitted = admitted_application_evidence(connection, deployment_id,
                        projection_evidence(connection, deployment_id).get('application_evidence_record_id'))
                    unchanged_without_evidence = (reported_at is None and admitted is None and
                        application['host_policy_revision'] is None and
                        application['state'] == state['application_status'] and
                        application['active_revision'] == state['effective_revision'] and
                        application['active_digest'] == ('sha256:' + state['effective_digest'] if state['effective_digest'] else None))
                    if application != admitted and not unchanged_without_evidence:
                        raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Application evidence expired before first delivery'})
                if application['state'] == 'applied':
                    if (application['active_revision'] != application['requested_revision'] or
                            application['active_digest'] != application['requested_digest']):
                        raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Applied status differs from desired'})
                    updates.update(effective_revision=application['active_revision'],
                        effective_digest=_digest(application['active_digest']))
                    evidence_links['effective_evidence_record_id'] = body['report_id']
                updates.update(application_status=application['state'], latest_failure_code=application['failure_code'])
                evidence_links['application_evidence_record_id'] = body['report_id']
            effective_revision = updates.get('effective_revision', state['effective_revision'])
            effective = connection.execute(sa.select(g7_backup_settings_revisions).where(
                g7_backup_settings_revisions.c.deployment_id == deployment_id,
                g7_backup_settings_revisions.c.revision == effective_revision)).mappings().first() if effective_revision else None
            if freshness['state'] != 'unknown':
                evaluated = parse_utc(freshness['evaluated_at']) if freshness['evaluated_at'] else None
                maximum = effective['values']['maximum_backup_age_seconds'] if effective else None
                age = int((evaluated - completed).total_seconds()) if evaluated and completed else None
                if (maximum is None or age is None or age < 0 or
                        evaluated > now + timedelta(seconds=policy['maximum_future_skew_seconds']) or
                        evaluated != observed or
                        freshness['maximum_backup_age_seconds'] != maximum or
                        freshness['age_seconds'] != age or
                        freshness['basis_completed_at'] != archive['completed_at'] or
                        freshness['state'] != ('fresh' if age <= maximum else 'stale')):
                    raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Archive freshness has an invalid effective-settings basis'})
            previous_completed = state['archive_completed_at']
            if previous_completed and previous_completed.tzinfo is None:
                previous_completed = previous_completed.replace(tzinfo=timezone.utc)
            if archive['outcome'] == 'complete' and completed <= now and (not previous_completed or completed >= previous_completed):
                updates.update(archive_id=archive['archive_id'], archive_completed_at=completed,
                    archive_manifest_digest=_digest(archive['manifest_digest']), archive_outcome='complete')
                if effective:
                    age = int((now - completed).total_seconds())
                    maximum = effective['values']['maximum_backup_age_seconds']
                    updates.update(freshness_state='fresh' if age <= maximum else 'stale',
                        freshness_age_seconds=age, freshness_max_age_seconds=maximum)
                else: updates.update(freshness_state='unknown', freshness_age_seconds=None, freshness_max_age_seconds=None)
            # Recovery events own the transition graph. A status report cannot
            # invent verification or clear its retained failure state.
            expected_restore = 'verified' if state['restore_state'] == 'released' else state['restore_state']
            if restore['state'] == 'verified' and (expected_restore != 'verified' or
                    restore['archive_id'] != state['restore_archive_id']):
                raise HTTPException(409, {'code': 'revision_conflict', 'message': 'Restore verification lacks its admitted event'})
        connection.execute(g7_backup_host_records.insert().values(record_id=body['report_id'],
            deployment_id=deployment_id, record_kind='status', sequence=body['sequence'],
            recovery_epoch=body['recovery_epoch'], record_digest=record_digest, signature=signature,
            document=body, response=response, received_at=now))
        connection.execute(g7_backup_state.update().where(
            g7_backup_state.c.deployment_id == deployment_id).values(**updates))
        if evidence_links:
            from uvm.operations.backup_settings import bind_projection_evidence
            bind_projection_evidence(connection, deployment_id, **evidence_links)
        return response
