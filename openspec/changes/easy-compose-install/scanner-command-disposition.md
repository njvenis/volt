# Adopted scanner command disposition amendment

Root adopts the bounded protocol below to close the reviewed stale pre-admission command deadlock within the already authorised scanner lifecycle. Implementation, independent review and executed acceptance remain distinct. Backend retains exclusive shared ledger/audit ownership; provider retains routes, strict DTOs and coordinator ownership; UI retains held-request/replacement behaviour. No grant widening, new network operation or fresh-admission authorisation is implied.

The original proposal is retained unchanged below as contract provenance; references to proposed or unimplemented work describe the checkpoint state, not a completed feature.

# Scanner command abandonment/disposition proposal — root adoption before implementation

Wire corrections are preserved at eb80eab0dc442b459c4f427f90e179eac58ec068; required slot metadata at98a5f1a. This is the next concrete contract, not implemented endpoint or backend bypass. No backend/UI/migration edits made for this proposal.

## Route and immutable request

POST /api/v1/scanners/{connector_id}/commands/{command_id}/abandon

Request exactly `{schema_version:1, command:<the ORIGINAL strict ScannerCommand object>, rationale:<nonempty <=2048>, evidence_ref:<nonempty <=2048>}`. Path IDs must equal command.target_id/command.command_id; scope comes from command.payload.source_id. Preserve original action, settings, expected_revisions and actor/body digest verbatim, including stale fences and scanner secret:null. No rewritten command or server-filled revisions. Normal session, exact configured Origin/JSON, real CSRF and CURRENT exact source connector.configure are required. The abandoned request is never issued to Qualys.

Use the ORIGINAL scanner action in `adapters.transaction(request=...,action=command.action,connector_id=...,source_id=...,expected_revisions=None)`. This reuses current source/CSRF authority without evaluating stale admission fences. It does not authorize a fresh collection or local configuration write. No new grant/action expansion is requested.

## Disjoint 200 disposition DTOs

All variants share schema_version1,command_id,connector_id,source_id,action(original ScannerAction),actor_id,request_digest. Request digest is exactly current actor + original public ScannerCommand using existing command_digest; no input normalization.

* `disposition:"not_committed"`, audit_event_id,occurred_at: issued ONLY after an audited terminal tombstone commits. This is the sole definitive noncommit/replacement proof. UI may release the frozen command and submit edited content with a NEW command ID. Identical abandonment replay returns the original proof/audit event. It never retries network.
* `disposition:"committed"`, receipt: the original audited ScannerCommandReceipt. Current-authorized exact receipt recovery; no replacement or new network request.
* `disposition:"admitted"`, operation: the original safe OperationView (running, or failed/partial/interrupted without receipt). UI continues recovery/readback using that original operation; it must not treat this as noncommit. Succeeded without its required receipt is503 inconsistent_operation. No counts/finding details included.

Original command mismatch/changed actor/action/source/body returns409 command_conflict, not noncommit. Current denial401/403, revision/conflict409, absence404 or persistence503 NEVER releases held content. Any uncertain outcome remains held and retries SAME abandonment request. Same original command returns first committed proof; abandonment rationale/evidence are first audit metadata and never rewritten on retry. UI should freeze that abandonment body during uncertainty as well.

## Serialization and race boundary

Inside the SAME current-authorized policy/connector transaction: lookup the original command identity, then either return its retained receipt/operation, return an existing matching tombstone, or atomically append audit + terminal tombstone. Policy lock and existing global command-id uniqueness serialize this against ordinary scanner admission. No HTTP or independent repository commit inside the transaction.

Before every new scanner admission/local-command commit, existing `read_command` must check matching global tombstones. A tombstoned command cannot later admit; matching retries return409 command_terminal (proof still obtained through abandon route), changed content/source/actor conflicts. If concurrent admission wins first, abandonment returns committed/admitted recovery. If tombstone wins first, the delayed admission returns terminal without HTTP. Existing provider operation store.scoped_operation(tx.connection,...) supplies safe metadata; no network replay. Original successful receipts remain immutable and take current-authorized recovery semantics.

## Minimal missing shared bridge addition (cannot be implemented by provider)

Reuse existing0065 `assessment_command_abandonments` and shared audit tables, avoiding a duplicate ledger or new provider migration/table. Backend owns them. Existing `record_audited_intent` requires fresh admission fences and operation IDs for test/collect, and `record_audited_receipt` only supports the five actual command result variants. Neither can truthfully audit a stale pre-admission cancellation. Do NOT synthesize an operation, replace stale fences with current values in the original request, or call audit SQL from provider.

Proposed provider-owned declarations after root adoption:

```python
@dataclass(frozen=True)
class ScannerCommandAbandonment:
    command_id: str
    principal_id: str
    action: ScannerAction
    request_digest: str
    audit_event_id: str
    occurred_at: str

# One additive return variant on existing lookup:
ScannerTransaction.read_command(
    *, command_id: str, request_digest: str
) -> ScannerCommandState | ScannerCommandAbandonment | None

# One narrow new shared write primitive, SAME tx.connection/authority lock:
ScannerTransaction.record_audited_abandonment(
    *, command_id: str, request_digest: str,
    rationale: str, evidence_ref: str
) -> ScannerCommandAbandonment
```

Backend derives principal/action/source from the live handle, rechecks there is no committed receipt or admitted intent, and writes existing0065 tombstone plus audit atomically. Abandonment lookup validates actor/action/digest before returning a tombstone; command digest binds connector/source IDs even though0065 stores no duplicate scope columns. Both tombstone and receipt/intent for one ID is inconsistent, never definitive noncommit. Ordinary provider command `_replay` handles this extra lookup variant by terminal rejection; the new abandon handler renders it as not_committed proof. All receipt/operation recovery still goes through current exact authorization and matches the original body. No broader policy evaluator, cryptography, arbitrary audit-write API or lifecycle framework.

## Decisive tests after adoption

Actual serialized disposition schemas; stale-vector409 preserves frozen content; matching audited tombstone permits NEW ID only; delayed original command after tombstone causes zero HTTP; changed actor/content/source conflicts; admission-vs-abandon race yields one truthful outcome; committed receipt and running/interrupted operation recovery cause no HTTP; audit failure rolls back tombstone and leaves uncertainty; current source revocation denies disposition/readback. Use real shared bridge + committed owned PG and local HTTPS, and keep injected-only tests labelled. Backend/UI changes remain with their owners.

## Required amendment: shared command-ID occupancy

The initial proposal's assumption of uniform global command-ID exclusion was not established. This amendment supersedes that assumption before executable disposition acceptance.

Every writer sharing the command-ID ledger namespace SHALL check current occupancy and terminal tombstones under the same policy lock, including assessment command and abandonment writers, connector command receipts/intents, scanner command receipts/intents/abandonment, and pending secret submissions and their reconciliation/settlement writers. A command ID occupied by another family, actor, action or request digest SHALL conflict without changing either command. A tombstone SHALL fence every delayed admission or completion that could otherwise resurrect that ID. Exact current-authorised replay returns only the original family's retained result. An inconsistent pre-existing mixed state SHALL fail closed and SHALL NOT become definitive non-commit proof.

Use the existing tables and shared lock; no new permission, duplicate ledger, synthetic operation or table is authorised by this amendment. Backend owns shared occupancy/admission/settlement enforcement. Provider consumes the typed lookup/write contract and must not query shared audit tables directly.

Acceptance SHALL include cross-family ID collision and concurrent admission/abandonment cases involving assessment registration, ordinary connector commands, scanner operations, and pending secret submissions. Verify both race orders, audit rollback, delayed secret completion/reconciliation fencing and no scanner HTTP after a winning tombstone. Current authorisation and exact original-body binding remain required before recovery. Family-specific terminal/replay semantics remain explicit; identifier occupancy alone is never an authorisation grant or proof of non-commit.
