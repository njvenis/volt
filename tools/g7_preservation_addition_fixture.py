#!/usr/bin/env python3
"""Test-only actual writers/exporter for post-baseline copied-store probes."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import runpy
import sys
import uuid

import sqlalchemy as sa


def main():
    mode=sys.argv[1]
    url=sa.engine.make_url(os.environ['UVM_DB_URL'])
    if os.environ.get('UVM_G7_DISPOSABLE_MODE')!='1' or not (url.database or '').startswith('g7_copy_'):
        raise RuntimeError('addition_fixture_requires_disposable_copy')
    if mode=='complete':
        runpy.run_path('/fixture/seed.py',run_name='__main__')
        return
    if mode=='pending-export':
        from tools.g7_container_audit_export import configure_source
        from uvm.audit_export.exporter import AuditExporter
        from uvm.audit_export.integrity import AuditAnchorAuthority
        source=configure_source()
        class FirstAcknowledgementUnavailable(RuntimeError):pass
        def unavailable(*args,**kwargs):raise FirstAcknowledgementUnavailable('fixture first acknowledgement unavailable')
        source.acknowledge_sink_export=unavailable
        try:
            AuditExporter(os.environ['G7_SIEM_DSN'],source,anchor_authority=AuditAnchorAuthority(
                os.environ['G7_AUDIT_ANCHOR_DSN'],deployment_id='g7-local')).export_authorised_history_once()
        except FirstAcknowledgementUnavailable:
            print(json.dumps({'sink_commit_before_acknowledgement_failure':True,'source_acknowledgement_written':False}))
            return
        raise RuntimeError('pending_fixture_did_not_reach_first_acknowledgement')
    if mode!='pending':raise RuntimeError('unknown_addition_fixture_mode')
    from uvm.ingestion.run import CollectionScheduleV1
    from uvm.ingestion.scheduled_collector import ScheduledCollector,ConfiguredFixtureClient,FileFixtureEvidenceSink
    from uvm.persistence.ingestion_store import IngestionStore
    class StoppedAfterReservation(BaseException):pass
    class LocalClient(ConfiguredFixtureClient):
        source_family='local'
        def fetch(self,cursor):raise StoppedAfterReservation()
    now=datetime.now(timezone.utc);run_id=str(uuid.uuid4())
    schedule=CollectionScheduleV1('g7-preservation-synthetic-source',1,'local','g7-local','all',
        expected_run_grace=timedelta(minutes=5),max_attempts=1,max_page_attempts=1,
        total_deadline=timedelta(minutes=1),freshness_rule_ref='g7-synthetic-fixture')
    engine=sa.create_engine(os.environ['UVM_DB_URL'])
    try:
        try:
            ScheduledCollector(IngestionStore(engine),schedule,LocalClient({}),clock=lambda:now,
                evidence_sink=FileFixtureEvidenceSink('/opt/uvm/state/source-evidence')).collect(now,run_id=run_id)
        except StoppedAfterReservation:pass
        from uvm.persistence.ingestion_schema import collection_runs,expected_run_events,collection_request_reservations
        from uvm.persistence.assessment_schema import assessment_audit_events
        with engine.connect() as c:
            revision_count=c.execute(sa.select(sa.func.count()).select_from(collection_runs).where(collection_runs.c.run_id==run_id)).scalar_one()
            event_count=c.execute(sa.select(sa.func.count()).select_from(assessment_audit_events).where(assessment_audit_events.c.target_id==run_id)).scalar_one()
            reservation_count=c.execute(sa.select(sa.func.count()).select_from(collection_request_reservations).where(collection_request_reservations.c.run_id==run_id)).scalar_one()
            expected_id=c.execute(sa.select(collection_runs.c.expected_run_id).where(collection_runs.c.run_id==run_id)).scalar_one()
            transitions=c.execute(sa.select(sa.func.count()).select_from(expected_run_events).where(expected_run_events.c.expected_run_id==expected_id)).scalar_one()
        if (revision_count,event_count,reservation_count,transitions)!=(1,1,1,2):
            raise RuntimeError('pending_writer_checkpoint_shape_changed')
        print(json.dumps({'run_id':run_id,'run_revision_count':1,'audit_event_count':1,'reservation_count':1,
            'expected_run_count':1,'expected_transition_count':2,'scanner_members_added':4,'source_members_added':0}))
    finally:engine.dispose()

if __name__=='__main__':main()
