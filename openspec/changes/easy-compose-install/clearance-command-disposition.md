# Adopted clearance command disposition amendment

Root adopts this narrow contract to close the reviewed recovery UI stale/expired-command deadlock within the authorised recovery scope. Implementation and independent executable acceptance remain pending. Original checkpoint text follows as provenance; no generic abandon authority or new ledger is introduced.

# Clearance-family audited disposition checkpoint

Backend516 scoped GO/evidence remains unchanged. This narrow additive contract
uses the EXISTING POST /api/v1/assessment/commands/{command_id}/abandon route;
existing protected registration semantics and responses remain unchanged. No
scanner DTO/provider/installer/UI edit, new table/permission or generic abandon
operation. Implementation/proof pending at this checkpoint.

## Exact request and authority

Outer object exactly schema_version=1,command,rationale,evidence_ref. `command`
is the ORIGINAL complete V1 connector.recovery.clearance.apply object, unmodified:
schema_version=1,command_id matching path,action,target_id exactly
00000000-0000-4000-8000-000000000000,membership_ids=[],expected_revisions,payload.
The revision object has exactly target,policy,identity_membership,owners,authority,
connector,source,secret_source,secret; nonnegative integers, never bool/null.
Payload exactly connector_id,source_id,secret_id,version_id,recovery_epoch_id,
rationale,evidence_ref. All identifiers canonical UUIDs; text nonempty.
No other connector/scanner family is dispatched by this addition.

Normal current local browser authentication, Origin/JSON/CSRF and CURRENT exact
connector.configure/source grant required, including replay. Resolve registered
Qualys connector/source and allocated Basic slot on the SAME policy-first live
Connection. Bootstrap status is no bypass. The command's revision vector,
version, epoch, approval validity/currentness are NOT fresh admission predicates
for disposition: they remain original retained bytes bound by the exact digest.
No normalization, rebase, replacement approval, active-version substitution or
stale fresh-vector check. Current profile/host custody must remain valid.

Digest is the existing connector command digest:
SHA256(json.dumps({"principal_id":CURRENT_ACTOR,**ORIGINAL_COMMAND},
sort_keys=True,separators=(",",":")).encode("utf-8")); default ASCII escaping,
no newline. Identical to admission; proof metadata does not change that digest.

## Exact HTTP200 proof unions for this additional family

Committed response has EXACT fields:

```
{schema_version:1,command_id,action:"connector.recovery.clearance.apply",
 actor_id,request_digest,disposition:"committed",receipt:ORIGINAL_COMMITTED_RECEIPT}
```

Not-committed response has EXACT fields:

```
{schema_version:1,command_id,action:"connector.recovery.clearance.apply",
 actor_id,request_digest,disposition:"not_committed",audit_event_id,committed_at}
```

No definitive response exists without successful transaction commit. Exact replay
returns the original receipt or original audit/timestamp proof, with actor/action/
command/digest binding. Changed actor/body/source/action conflicts409. Different
family ID conflicts409. Audit/receipt/intent/consumption/tombstone inconsistencies
fail503; partial or independently pending state is NEVER not_committed.
Ordinary409/404/error envelopes are NOT disposition proofs and NEVER authorize
UI to discard retained bytes. Forbidden403/current session401 remain failures.
Existing global error sanitizer envelopes remain authoritative on actual wire.
UI must validate the whole200 union against original command/current actor/digest
before releasing its held request; a committed result is historical receipt,
not permission to infer current recovery state without refresh.

## Existing ledger/fences and partial-state handling

Use existing0065 assessment_command_abandonments plus assessment audit event;
retain original action, actor, command ID and exact digest. Audit is fixed action
connector.recovery.clearance.abandoned, target=resolved connector, source/slot/
version/original epoch in safe audit metadata. The existing shared occupancy
helper must classify this action as connector family in tombstones, just as its
receipt is connector family. Later original admission is command_terminal before
its stale vector can matter. All other family writers remain excluded.

Synchronous clearance writes its intent+audit+receipt+approval consumption in one
transaction. There is NO legitimate separately pending admission to cancel.
Add original command_id/action/request_digest to the existing backend-owned
clearance intent payload for exact shared lookup, no migration/new ledger.
Extend shared occupancy to recognise that intent plus existing approval
consumption footprint; incomplete or mixed states fail closed. Existing516
complete receipts/intents are still readable through receipt intent references
and consumed_command_id; do not invent a missing historical digest. Any legacy
unbound clearance intent lacking a coherent complete receipt on the affected
connector is indeterminate and blocks noncommit proof, not silently ignored.

Before returning committed, verify exact receipt/actor/action/digest/connector/
source/slot/version/epoch plus its original audit, complete referenced intent and
approval-consumption binding. Before writing tombstone, atomically exclude all
shared occupancy, clearance-specific audit/intent/consumption footprints under
the same policy lock. Existing mixed receipt+tombstone fails closed. Audit and
tombstone insertion roll back together; caller never receives proof on failure.

## Required maintained public verification

Stale vector and expired/replaced approval cannot admit, but can produce exact
current-authorised audited noncommit proof. Commit-first returns immutable receipt;
tombstone-first fences delayed original, including races. Audit/tombstone failure
rolls back proof; cross-family collisions and changed content/actor/source denied;
current grant revocation denied even replay; partial/mixed intent fails503 without
proof. Validate actual HTTP error envelopes and closed OpenAPI request/response
unions. Existing registration behavior and full maintained regression retained.
Capture clean complete source/archive/hashes before invocation. Actual host
signer/cold restore/private mounts remain independently unverified.
