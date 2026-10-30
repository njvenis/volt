"""Derive the only admitted inventory from baseline plus journaled API submissions.

Replay is offline in disposable SQLite using the real control handlers and exact
acknowledgement clocks. Candidate database contents never define allowances.
"""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import inspect
import json
import re
from unittest.mock import patch
from pathlib import Path
import sqlalchemy as sa
from tools.g7_product_inventory import canon, digest

REPLAY_TABLES = {"g7_backup_state", "g7_backup_host_records", "g7_backup_settings_revisions",
    "g7_backup_connector_quarantine", "assessment_policy", "g7_connectors"}


def _migration_table_record(table):
    """Render a migration-created table expectation from checked-in metadata."""
    def type_name(value):
        if isinstance(value, sa.Uuid): return "UUID"
        if isinstance(value, sa.String): return "VARCHAR" + (f"({value.length})" if value.length else "")
        if isinstance(value, sa.BigInteger): return "BIGINT"
        if isinstance(value, sa.Integer): return "INTEGER"
        if isinstance(value, sa.DateTime):
            return "TIMESTAMP WITH TIME ZONE" if value.timezone else "TIMESTAMP WITHOUT TIME ZONE"
        return str(value).upper()
    columns = [{"name": column.name, "type": type_name(column.type),
        "nullable": column.nullable, "primary_key": column.primary_key,
        "default": str(column.server_default.arg) if column.server_default else None}
        for column in table.columns]
    primary_key = list(table.primary_key.columns.keys())
    checks = sorted(re.sub(r"length\(([A-Za-z_][A-Za-z_0-9]*)\)",
        r"length(\1::text)", str(item.sqltext)) for item in table.constraints
        if isinstance(item, sa.CheckConstraint))
    unique_constraints = [item for item in table.constraints
        if isinstance(item, sa.UniqueConstraint)]
    unique = sorted([list(item.columns.keys()) for item in unique_constraints])
    foreign_keys = []
    for item in table.foreign_key_constraints:
        foreign_keys.append({"constrained_columns": list(item.column_keys),
            "referred_schema": "public", "referred_table": item.elements[0].column.table.name,
            "referred_columns": [element.column.name for element in item.elements], "options": {},
            "comment": None})
    indexes = [{"column_names": list(item.columns.keys()),
        "dialect_options": {"postgresql_include": []},
        "duplicates_constraint": item.name, "include_columns": [], "unique": True}
        for item in unique_constraints]
    constraints = {"primary_key": primary_key, "checks": checks, "unique": unique,
        "foreign_keys": canon(sorted(foreign_keys, key=lambda value:
            json.dumps(value, sort_keys=True))),
        "indexes": canon(sorted(indexes, key=lambda value: json.dumps(value, sort_keys=True)))}
    return {"columns": columns, "constraints": constraints,
        "schema_sha256": digest({"columns": columns, "constraints": constraints}),
        "rows": [], "row_count": 0}


def _append_0061_byte_size_expectation(evidence):
    if not isinstance(evidence, dict) or not isinstance(evidence.get('columns'), list) or \
            not isinstance(evidence.get('constraints'), dict) or \
            not isinstance(evidence.get('rows'), list) or 'byte_size' in {c['name'] for c in evidence['columns']}:
        raise ValueError('0058 baseline ingestion_evidence schema is unexpected')
    names = [c.get('name') for c in evidence['columns']]
    if len(names) != len(set(names)) or any(not isinstance(n, str) for n in names):
        raise ValueError('0058 ingestion_evidence baseline columns are ambiguous')
    primary_key = [c['name'] for c in evidence['columns'] if c.get('primary_key')]
    seen = set()
    for row in evidence['rows']:
        payload = row.get('payload')
        if not isinstance(payload, dict) or set(payload) != set(names):
            raise ValueError('0058 ingestion_evidence baseline lacks complete row payloads')
        if digest(payload) != row.get('payload_sha256'):
            raise ValueError('0058 ingestion_evidence baseline payload digest mismatch')
        key = [payload[name] for name in primary_key]
        if row.get('key') != key:
            raise ValueError('0058 ingestion_evidence baseline primary-key binding mismatch')
        encoded = json.dumps(key, sort_keys=True, separators=(',', ':'))
        if encoded in seen:
            raise ValueError('0058 ingestion_evidence baseline has duplicate primary keys')
        seen.add(encoded)
    if evidence.get('row_count') != len(evidence['rows']):
        raise ValueError('0058 ingestion_evidence baseline row count mismatch')
    evidence['columns'].append({'name':'byte_size','type':'BIGINT','nullable':True,
        'primary_key':False,'default':None})
    evidence['constraints']['checks'] = sorted([*evidence['constraints']['checks'],
        'byte_size IS NULL OR byte_size >= 0 AND byte_size <= 16777216'])
    for row in evidence['rows']:
        payload = copy.deepcopy(row['payload'])
        if 'byte_size' in payload:
            raise ValueError('0058 ingestion_evidence payload unexpectedly has byte_size')
        payload['byte_size'] = None
        row['payload'] = payload
        row['payload_sha256'] = digest(payload)
    evidence['schema_sha256'] = digest({'columns':evidence['columns'],
        'constraints':evidence['constraints']})
    return evidence


def _append_0062_context_expectation(evidence):
    if not isinstance(evidence, dict) or not isinstance(evidence.get('columns'), list) or \
            not isinstance(evidence.get('constraints'), dict) or \
            not isinstance(evidence.get('rows'), list) or 'workload_context_fields' in {
                c.get('name') for c in evidence['columns']}:
        raise ValueError('0058 baseline identity_rule_definitions schema is unexpected')
    names = [column.get('name') for column in evidence['columns']]
    if len(names) != len(set(names)) or any(not isinstance(name, str) for name in names):
        raise ValueError('identity rule baseline columns are ambiguous')
    primary_key = [column['name'] for column in evidence['columns'] if column.get('primary_key')]
    seen = set()
    for row in evidence['rows']:
        payload = row.get('payload')
        if not isinstance(payload, dict) or set(payload) != set(names) or digest(payload) != row.get('payload_sha256'):
            raise ValueError('identity rule baseline row does not match its exact preimage')
        key = [payload[name] for name in primary_key]
        if row.get('key') != key:
            raise ValueError('identity rule baseline primary key mismatch')
        encoded = json.dumps(key, sort_keys=True, separators=(',', ':'))
        if encoded in seen:
            raise ValueError('identity rule baseline has duplicate keys')
        seen.add(encoded)
        payload['workload_context_fields'] = []
        row['payload_sha256'] = digest(payload)
    evidence['columns'].append({'name': 'workload_context_fields',
        'type': 'JSONB', 'nullable': False, 'primary_key': False, 'default': "'[]'::jsonb"})
    evidence['schema_sha256'] = digest({'columns': evidence['columns'],
        'constraints': evidence['constraints']})
    return evidence


def expected_inventory(source, receipts, public_key):
    from fastapi import FastAPI, Request
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
        # Exact current-image 0058->0062 migration, independently derived from
        # migration-owned metadata and source payloads rather than candidate state.
        table = expected['uvm']['alembic_version']
        if [r['key'] for r in table['rows']] != [['0058']]:
            raise ValueError('baseline must be exactly 0058')
        table['rows'] = [{'key':['0062'], 'payload_sha256':digest({'version_num':'0062'})}]
        if any(name in expected['uvm'] for name in
                ('g7_backup_projection_evidence', 'collection_request_reservations')):
            raise ValueError('0058 baseline unexpectedly contains a post-0058 migration table')
        from uvm.persistence.backup_settings_schema import g7_backup_projection_evidence
        from uvm.persistence.ingestion_schema import collection_request_reservations
        from uvm.persistence.lineage_schema import identity_rule_definitions
        expected['uvm']['g7_backup_projection_evidence'] = _migration_table_record(
            g7_backup_projection_evidence)
        expected['uvm']['collection_request_reservations'] = _migration_table_record(
            collection_request_reservations)
        _append_0061_byte_size_expectation(expected['uvm'].get('ingestion_evidence'))
        _append_0062_context_expectation(expected['uvm'].get('identity_rule_definitions'))
        return expected
    finally:
        engine.dispose()
