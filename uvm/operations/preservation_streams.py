"""Independent append-only preservation streams. Application consumers only read.

The controller provisions pins and current heads in a separately mounted trust
store. Signed objects are immutable and content addressed; GET never writes.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
from uuid import UUID, uuid5
from uvm.operations.preservation import canonical_json, _read_regular, _verify, CONTRACT

INVENTORY = 'expected-inventory-v1'
REPORT = 'readcheck-report-v1'
CONTROLLER = 'deployment-controller-v1'
NAMESPACE = UUID('3df304fc-e834-5eb4-a2a5-0a6d0d4c721a')


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def namespace(deployment, purpose, scope, class_id):
    return [deployment, purpose, *scope, class_id]


def sign(payload, key, key_id):
    purpose = payload['purpose']
    raw = b'VOLT-G7-PRESERVATION\0' + purpose.encode() + b'\0' + canonical_json(payload)
    return {'payload': payload, 'signature': {'algorithm': 'Ed25519',
        'key_id': key_id, 'value': base64.b64encode(key.sign(raw)).decode()}}


def immutable(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    raw = canonical_json(value) + b'\n'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        if _read_regular(path, 32 * 1024 * 1024) != raw:
            raise ValueError('preservation_publication_conflict')
        return
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())


def replace_head(path, value):
    # Caller holds the trust-store lock. Only the independent publisher writes.
    temporary = path.with_suffix('.pending')
    with open(temporary, 'wb') as out:
        os.fchmod(out.fileno(), 0o644)
        out.write(canonical_json(value) + b'\n'); out.flush(); os.fsync(out.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def _inventory_members(content):
    if not isinstance(content, dict) or content.get('complete') is not True or not isinstance(content.get('members'), list):
        raise ValueError('inventory_completeness_invalid')
    result = {}
    for item in content['members']:
        if not isinstance(item, dict) or not isinstance(item.get('member'), dict):
            raise ValueError('inventory_member_invalid')
        member = item['member']; key = member.get('record_key')
        if not isinstance(key, str) or key in result or member.get('state') != 'verified':
            raise ValueError('inventory_member_identity_invalid')
        result[key] = item
    return result


def read_stream(root, public_key, ns, *, selected_digest=None, key_id=None):
    root = Path(root); stream = digest(ns)
    pin = json.loads(_read_regular(root / 'pins' / (stream + '.json'), 65536))
    head = json.loads(_read_regular(root / 'heads' / (stream + '.json'), 65536))
    current_digest = head['digest']; current_sequence = head['sequence']
    if type(current_sequence) is not int or current_sequence < 0:
        raise ValueError('invalid_stream_sequence')
    selected = None
    newer_inventory = None; stream_key_id = None
    for sequence in range(current_sequence, -1, -1):
        document = json.loads(_read_regular(root / 'objects' / (current_digest + '.json'), 32 * 1024 * 1024))
        if digest(document) != current_digest:
            raise ValueError('stream_digest_mismatch')
        payload = _verify(document, Path(public_key), ns[1])
        if key_id is not None and document['signature']['key_id'] != key_id:
            raise ValueError('stream_key_mismatch')
        if stream_key_id is None: stream_key_id = document['signature']['key_id']
        if document['signature']['key_id'] != stream_key_id or payload.get('purpose') != ns[1]:
            raise ValueError('stream_key_or_purpose_mismatch')
        if ns[1] == INVENTORY and sequence > 0:
            inventory = _inventory_members(payload.get('content'))
            if newer_inventory is not None and any(newer_inventory.get(key) != item for key,item in inventory.items()):
                raise ValueError('inventory_history_removed_or_changed')
            newer_inventory = inventory
        if payload.get('namespace') != ns or type(payload.get('sequence')) is not int or payload.get('sequence') != sequence or payload.get('contract_id') != CONTRACT:
            raise ValueError('stream_binding_mismatch')
        if (selected_digest is None and selected is None) or current_digest == selected_digest:
            selected = (payload, current_digest)
        if sequence == 0:
            if current_digest != pin['genesis_digest'] or payload.get('predecessor') is not None or payload.get('genesis') is not True:
                raise ValueError('stream_genesis_mismatch')
        else:
            current_digest = payload['predecessor']
    if selected is None:
        raise ValueError("selected_record_not_in_independent_chain")
    return selected


def publish(root, key, key_id, ns, content):
    root = Path(root); stream = digest(ns)
    for name in ('pins', 'heads', 'objects'):
        (root / name).mkdir(parents=True, exist_ok=True, mode=0o755)
        (root / name).chmod(0o755)
    head_path = root / 'heads' / (stream + '.json')
    if not head_path.exists():
        genesis = sign({'contract_id': CONTRACT, 'purpose': ns[1], 'namespace': ns,
            'sequence': 0, 'predecessor': None, 'genesis': True}, key, key_id)
        genesis_digest = digest(genesis)
        immutable(root / 'objects' / (genesis_digest + '.json'), genesis)
        immutable(root / 'pins' / (stream + '.json'), {'genesis_digest': genesis_digest})
        replace_head(head_path, {'sequence': 0, 'digest': genesis_digest})
    head = json.loads(_read_regular(head_path, 65536))
    if head['sequence']:
        old = json.loads(_read_regular(root / 'objects' / (head['digest'] + '.json'), 32 * 1024 * 1024))
        if old['payload']['content'] == content:
            return head
        if ns[1] == INVENTORY:
            before = _inventory_members(old['payload']['content']); after = _inventory_members(content)
            if any(after.get(key) != item for key,item in before.items()):
                raise ValueError('inventory_history_removed_or_changed')
    payload = {'contract_id': CONTRACT, 'purpose': ns[1], 'namespace': ns,
        'sequence': head['sequence'] + 1, 'predecessor': head['digest'], 'content': content}
    doc = sign(payload, key, key_id); current = digest(doc)
    immutable(root / 'objects' / (current + '.json'), doc)
    result = {'sequence': payload['sequence'], 'digest': current}
    replace_head(head_path, result)
    return result


def snapshot_id(scope, generation, bindings):
    return str(uuid5(NAMESPACE, canonical_json([list(scope), generation, bindings]).decode()))


def validate_bindings(payload, root, public_key, key_id, *, now, allow_previous=False):
    """Verify current independent heads, controller and composed snapshot identity."""
    from datetime import datetime
    root = Path(root)
    controller_document = json.loads(_read_regular(root / 'controller.json', 65536))
    current_controller_digest = digest(controller_document)
    if allow_previous and current_controller_digest != payload.get('controller_digest'):
        controller_document = json.loads(_read_regular(root / 'objects' / (payload['controller_digest'] + '.json'), 65536))
    controller = _verify(controller_document, Path(public_key), CONTROLLER)
    if controller_document['signature']['key_id'] != key_id or digest(controller_document) != payload.get('controller_digest'):
        raise ValueError('controller_key_or_digest_mismatch')
    for field in ('deployment_id', 'recovery_epoch', 'storage_generation', 'volume_set_digest', 'schema_head_digest'):
        if controller.get(field) != payload.get(field):
            raise ValueError('controller_context_mismatch')
    start, end = (datetime.fromisoformat(controller[field].replace('Z', '+00:00'))
        for field in ('key_valid_from', 'key_valid_until'))
    checked = datetime.fromisoformat(payload['checked_at'].replace('Z', '+00:00'))
    expires = datetime.fromisoformat(payload['valid_until'].replace('Z', '+00:00'))
    if not start <= checked < end or not start <= now < end or expires > end:
        raise ValueError('key_validity_mismatch')
    expected_bindings = []
    check_times, expiries = [], []
    supplied = {binding[0]: binding for binding in payload['stream_bindings']}
    for entry in payload['classes']:
        class_id = entry['class_id']
        inventory, inventory_digest = read_stream(root, public_key,
            namespace(payload['deployment_id'], INVENTORY, payload['scope'], class_id),
            selected_digest=supplied[class_id][1] if allow_previous else None, key_id=key_id)
        report, report_digest = read_stream(root, public_key,
            namespace(payload['deployment_id'], REPORT, payload['scope'], class_id),
            selected_digest=supplied[class_id][3] if allow_previous else None, key_id=key_id)
        content = report['content']
        baseline = inventory['content']
        captured = datetime.fromisoformat(baseline['captured_at'].replace('Z', '+00:00'))
        if (type(baseline.get('schema_version')) is not int or baseline['schema_version'] != 1
                or baseline.get('class_id') != class_id or baseline.get('schema_head_digest') != payload['schema_head_digest']
                or baseline.get('key_valid_from') != controller['key_valid_from']
                or baseline.get('key_valid_until') != controller['key_valid_until']
                or not isinstance(baseline.get('source_watermark'), dict)
                or str(UUID(baseline['capture_id'])) != baseline['capture_id']
                or not start <= captured < end):
            raise ValueError('inventory_capture_binding_mismatch')
        if (content['inventory_digest'] != inventory_digest or content['entry'] != entry
                or content['controller_digest'] != payload['controller_digest']
                or content['checked_at'] != payload['class_checked_at'][class_id]):
            raise ValueError('class_head_mismatch')
        class_checked = datetime.fromisoformat(content['checked_at'].replace('Z', '+00:00'))
        class_expiry = datetime.fromisoformat(content['valid_until'].replace('Z', '+00:00'))
        if not start <= class_checked < end or captured > class_checked or class_checked > now or class_expiry > end:
            raise ValueError('class_check_time_invalid')
        check_times.append(class_checked); expiries.append(class_expiry)
        expected_bindings.append([class_id, inventory_digest, report['sequence'], report_digest])
    if checked != min(check_times) or expires != min(expiries):
        raise ValueError('summary_time_composition_invalid')
    if payload.get('stream_bindings') != expected_bindings or payload['snapshot_id'] != snapshot_id(
            payload['scope'], payload['storage_generation'], expected_bindings):
        raise ValueError('snapshot_head_mismatch')


def admitted_evidence(root, public_key, deployment, scope, evidence_id, *, key_id=None):
    """Read independent expected byte identity, never mutable source registration."""
    matches = []
    for class_id in ('product.source_evidence', 'operational.scanner_collection'):
        try:
            inventory, _ = read_stream(root, public_key, namespace(deployment, INVENTORY, scope, class_id), key_id=key_id)
        except FileNotFoundError:
            continue
        if not inventory.get('content', {}).get('complete'):
            continue
        for item in inventory['content']['members']:
            member = item['member']
            if member['evidence_id'] == evidence_id:
                matches.append((member['expected_sha256'], item['byte_size']))
    if not matches:
        return None
    if len(set(matches)) != 1:
        raise ValueError('independent_evidence_conflict')
    return matches[0]


def reconcile_members(expected, observed):
    current = {item["record_key"]: item for item in observed}
    result = []
    for original in expected:
        before = original["member"]
        now = current.pop(before["record_key"], None)
        if now is None and before["record_kind"] in {"audit_event", "audit_anchor", "audit_copy_receipt_established"}:
            identity = before["record_key"].split(":")[1]
            candidates = [item for item in current.values() if item["record_kind"] == before["record_kind"]
                and item["record_key"].split(":")[1] == identity]
            if len(candidates) == 1:
                candidate = candidates[0]; current.pop(candidate["record_key"])
                now = {**candidate, "record_key": before["record_key"], "state": "changed",
                    "reasons": ["receipt_changed" if before["record_kind"] == "audit_copy_receipt_established"
                        else "sink_record_changed"]}
        if now is None:
            now = {**before, "state": "missing", "reasons": ["record_missing"],
                "actual_sha256": None, "record_sha256": None}
        elif now["state"] not in {"missing", "unreadable"} and (now["record_sha256"] != before["record_sha256"]
                or now["expected_sha256"] != before["expected_sha256"]
                or now["retained_at"] != before["retained_at"]):
            now = {**now, "state": "changed", "reasons": sorted(set(now["reasons"]) | {"bytes_changed"}
                if before["byte_bearing"] and now["actual_sha256"] != before["expected_sha256"]
                else set(now["reasons"]) | {"evidence_changed"}), "expected_sha256": before["expected_sha256"]}
        result.append(now)
    result.extend({**item, "state": "unexpected", "reasons": ["unexpected_member"],
        "expected_sha256": None} for item in current.values())
    return sorted(result, key=lambda item: (item["record_kind"].encode(), item["record_key"].encode()))
