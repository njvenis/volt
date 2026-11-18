"""Concrete scanner wire schemas, with strict request validation and no DB access."""
from __future__ import annotations

from copy import deepcopy
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from uvm.scanners import contracts as dto

UUIDText = Annotated[str, Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
Revision = Annotated[int, Field(strict=True, ge=0)]
Text = Annotated[str, Field(min_length=1, max_length=2048, pattern=r'\S')]


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class RevisionVector(_Strict):
    target: Revision
    policy: Revision
    identity_membership: Revision
    owners: Revision
    authority: Revision
    connector: Revision
    source: Revision
    secret_source: Revision
    secret: None


class AccountVisibleScope(_Strict):
    kind: Literal['account_visible']


class QualysSettings(_Strict):
    product: Literal['qualys_vm']
    api_version: Literal['2.0']
    platform_id: Literal['us1', 'us2', 'us3', 'eu1', 'eu2', 'in1']
    scope: AccountVisibleScope
    collection_mode: Literal['manual']


class SourcePayload(_Strict):
    source_id: UUIDText
    rationale: Text
    evidence_ref: Text


class SavePayload(SourcePayload):
    settings: QualysSettings


class OperationPayload(SourcePayload):
    configuration_revision: Annotated[int, Field(strict=True, ge=1)]
    credential_version_id: UUIDText


class ActivatePayload(OperationPayload):
    validation_operation_id: UUIDText


class _Envelope(_Strict):
    schema_version: Annotated[int, Field(strict=True, ge=1, le=1)]
    command_id: UUIDText
    target_id: UUIDText
    membership_ids: Annotated[list[str], Field(max_length=0)]
    expected_revisions: RevisionVector


class SaveCommand(_Envelope):
    action: Literal['scanner.configuration.save']
    payload: SavePayload


class TestCommand(_Envelope):
    action: Literal['scanner.connection.test']
    payload: OperationPayload


class ActivateCommand(_Envelope):
    action: Literal['scanner.configuration.activate']
    payload: ActivatePayload


class CollectCommand(_Envelope):
    action: Literal['scanner.collection.start']
    payload: OperationPayload


class DisableCommand(_Envelope):
    action: Literal['scanner.configuration.disable']
    payload: SourcePayload


ScannerCommand = Annotated[Union[SaveCommand, TestCommand, ActivateCommand,
    CollectCommand, DisableCommand], Field(discriminator='action')]
COMMAND_ADAPTER = TypeAdapter(ScannerCommand)


def _inline(schema):
    """Self-contained OpenAPI3.1 schema: no unresolved local $defs references."""
    definitions = schema.get('$defs', {})
    def visit(value):
        if isinstance(value, list):
            return [visit(item) for item in value]
        if not isinstance(value, dict):
            return value
        if '$ref' in value:
            return visit(definitions[value['$ref'].rsplit('/', 1)[-1]])
        result = {key: visit(item) for key, item in value.items()
            if key not in {'$defs', 'discriminator'}}
        if result.get('type') == 'object' and 'properties' in result:
            result['additionalProperties'] = False
            result['required'] = list(result['properties'])
        if result.get('type') == 'integer':
            result['minimum'] = max(0, result.get('minimum', 0))
        return result
    return visit(schema)


def schema_for(value):
    return _inline(TypeAdapter(value).json_schema())


COMMAND_SCHEMA = _inline(COMMAND_ADAPTER.json_schema())
SCANNER_VIEW_SCHEMA = schema_for(dto.ScannerView)
SCANNER_VIEW_SCHEMA['properties']['expected_revisions']['properties']['secret'] = {'type': 'null'}
DETECTION_PAGE_SCHEMA = schema_for(dto.DetectionPage)
_BASE_OPERATION = schema_for(dto.OperationView)


def _operation(status, receipt):
    value = deepcopy(_BASE_OPERATION)
    value['properties']['status'] = status
    value['properties']['receipt_id'] = receipt
    value['properties']['started_at'] = {'type': 'string', 'format': 'date-time'}
    value['properties']['finished_at'] = ({'type': 'null'} if status.get('const') == 'running'
        else {'type': 'string', 'format': 'date-time'})
    return value


_NULL = {'type': 'null'}
_RECEIPT_ID = {'type': 'string', 'minLength': 1}
_TERMINAL_STATUS = {'type': 'string', 'enum': ['failed', 'partial', 'interrupted']}
RUNNING_OPERATION_SCHEMA = _operation({'type': 'string', 'const': 'running'}, _NULL)
TERMINAL_RECEIPTLESS_SCHEMA = _operation(_TERMINAL_STATUS, _NULL)
OPERATION_SCHEMA = {'oneOf': [RUNNING_OPERATION_SCHEMA,
    _operation({'type': 'string', 'const': 'succeeded'}, _RECEIPT_ID),
    _operation(_TERMINAL_STATUS, {'anyOf': [_NULL, _RECEIPT_ID]})]}
COMMAND_200_SCHEMA = {'oneOf': [schema_for(receipt) for receipt in (
    dto.SaveConfigurationReceipt, dto.TestConnectionReceipt,
    dto.ActivateConfigurationReceipt, dto.CollectReceipt,
    dto.DisableConfigurationReceipt)] + [TERMINAL_RECEIPTLESS_SCHEMA]}


def response(schema, description):
    return {'description': description,
        'content': {'application/json': {'schema': deepcopy(schema)}}}
