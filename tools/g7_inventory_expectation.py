"""Derive the only admitted inventory from baseline plus journaled API submissions.

Replay is offline in disposable SQLite using the real control handlers and exact
acknowledgement clocks. Candidate database contents never define allowances.
"""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import inspect
from unittest.mock import patch
from pathlib import Path
import sqlalchemy as sa
from fastapi import FastAPI, Request
from tools.g7_product_inventory import canon, digest

REPLAY_TABLES = {"g7_backup_state", "g7_backup_host_records", "g7_backup_settings_revisions",
    "g7_backup_connector_quarantine", "assessment_policy", "g7_connectors"}


def expected_inventory(source, receipts, public_key):
    from uvm.operations.api import install_observer_settings_routes
    from uvm.persistence.backup_settings_schema import (g7_backup_state, g7_backup_host_records,
        g7_backup_settings_revisions, g7_backup_connector_quarantine)
    from uvm.persistence.assessment_schema import assessment_policy
    from uvm.persistence.connector_schema import connectors
    tables = [g7_backup_state, g7_backup_host_records, g7_backup_settings_revisions,
        g7_backup_connector_quarantine, assessment_policy, connectors]
    engine = sa.create_engine("sqlite://")
    expected = copy.deepcopy(source)
    def read(table):
        with engine.connect() as conn:
            rows = []
            for row in conn.execute(sa.select(table)).mappings():
                item = dict(row)
                for c in table.columns:
                    if isinstance(item[c.name], datetime):
                        item[c.name] = item[c.name].replace(tzinfo=timezone.utc)
                payload = canon(item)
                rows.append({"key": [payload[c.name] for c in table.primary_key.columns],
                    "payload_sha256": digest(payload), "payload": payload})
            return {str(r['key']): r for r in rows}
    try:
        for table in tables:
            table.create(engine)
            with engine.begin() as conn:
                for row in source["uvm"][table.name]["rows"]:
                    values = copy.deepcopy(row['payload'])
                    if digest(values) != row['payload_sha256']:
                        raise ValueError("baseline replay payload digest mismatch")
                    for col in table.columns:
                        value = values[col.name]
                        if isinstance(col.type, sa.DateTime) and value is not None:
                            values[col.name] = datetime.fromisoformat(value)
                        elif isinstance(col.type, sa.LargeBinary) and value is not None:
                            # Old signature bytes aren't consulted by the handlers. Preserve
                            # original inventory bytes for every untouched historical row.
                            values[col.name] = None
                    if values: conn.execute(table.insert().values(**values))
        if source["uvm"]["g7_connectors"]["rows"]:
            raise ValueError("this zero-product-write fixture requires no configured connectors")
        initial = {t.name: read(t) for t in tables}
        app = FastAPI(); app.state.engine = engine; app.state.principals = {}
        install_observer_settings_routes(app)
        permitted = {"sequence-resync", "reports", "recovery-events", "connector-quarantine"}
        for receipt in receipts:
            path, body, response = receipt['path'], receipt['request'], receipt['response']
            prior = next((r['payload'] for r in source['uvm']['g7_backup_host_records']['rows']
                if r['key'] == [body.get('report_id') or body.get('event_id') or body.get('resync_id') or body.get('ack_id')]), None)
            if prior is not None:
                if prior['document'] != body or prior['response'] != response:
                    raise ValueError('baseline control receipt mismatch')
                continue
            if path not in permitted or response.get('accepted') is not True:
                raise ValueError("unadmitted control submission")
            if path == 'reports' and body.get('report_kind') != 'policy':
                raise ValueError('only policy renewal admitted in this journey')
            if path == 'recovery-events' and body.get('event_type') not in {'restore_started','volumes_restored'}:
                raise ValueError('B must remain in verification')
            app.state.utc_now = lambda: datetime.fromisoformat(response['accepted_at'].replace('Z','+00:00'))
            endpoint = next(r.endpoint for r in app.routes if r.path == '/recovery-control/v1/{deployment_id}/'+path)
            kwargs = {'deployment_id': body['deployment_id'], 'body': body,
                'identity': ('host', {'deployment_id': body['deployment_id'], 'verification_key_file': str(public_key)})}
            if 'request' in inspect.signature(endpoint).parameters:
                kwargs['request'] = Request({'type':'http', 'headers':[]})
            instances={r['payload']['document'].get('controller_instance_id')
                for r in source['uvm']['g7_backup_host_records']['rows']} - {None}
            key_ids={r['payload']['host_policy_key_id'] for r in source['uvm']['g7_backup_state']['rows']}
            if len(instances) != 1 or len(key_ids) != 1:
                raise ValueError('baseline controller/key binding is ambiguous')
            with patch.dict('os.environ', {'UVM_G7_CONTROLLER_INSTANCE_ID':next(iter(instances)),
                    'UVM_G7_HOST_KEY_ID':next(iter(key_ids))}):
                actual = endpoint(**kwargs)
            if actual != response: raise ValueError('journaled acknowledgement differs from replay')
        for table in tables:
            final = read(table); old = initial[table.name]
            if table.name in {"g7_backup_settings_revisions","assessment_policy","g7_connectors"} and final != old:
                raise ValueError("recovery must not change desired configuration or product state")
            retained = {str(r['key']): r for r in expected['uvm'][table.name]['rows']}
            for key in set(old) | set(final):
                if old.get(key) == final.get(key): continue
                if key in final: retained[key] = final[key]
                else: retained.pop(key, None)
            rows = sorted(retained.values(), key=lambda r: __import__('json').dumps(r['key'],sort_keys=True,separators=(',',':')))
            expected['uvm'][table.name]['rows'] = rows
            expected['uvm'][table.name]['row_count'] = len(rows)
        # Exact reviewed 0058->0059 migration; no desired revision mutation.
        table = expected['uvm']['alembic_version']
        if [r['key'] for r in table['rows']] != [['0058']]:
            raise ValueError('baseline must be exactly 0058')
        table['rows'] = [{'key':['0059'], 'payload_sha256':digest({'version_num':'0059'})}]
        columns = [{'name':'deployment_id','type':'VARCHAR(256)','nullable':False,'primary_key':True,'default':None},
            {'name':'application_evidence_record_id','type':'VARCHAR(36)','nullable':True,'primary_key':False,'default':None},
            {'name':'effective_evidence_record_id','type':'VARCHAR(36)','nullable':True,'primary_key':False,'default':None}]
        if 'g7_backup_projection_evidence' in expected['uvm']:
            raise ValueError('baseline unexpectedly contains 0059 table')
        constraints={'primary_key':['deployment_id'],'checks':[],'unique':[],'foreign_keys':[],'indexes':[]}
        expected['uvm']['g7_backup_projection_evidence'] = {'columns':columns,'constraints':constraints,
            'schema_sha256':digest({'columns':columns,'constraints':constraints}), 'rows':[], 'row_count':0}
        return expected
    finally:
        engine.dispose()
