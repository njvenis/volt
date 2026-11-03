# G7 observer host runtime

This is the host-side runtime contract for `g7-observer-settings/v1`. It is a
development implementation and selects no production timings, endpoint,
deployment, service identity, or host policy. See
[`g7-observer-settings-contract.md`](g7-observer-settings-contract.md) for the
public API and transaction contract.

## Trust boundary

Run `tools/g7_host_observer.py` as three separate host processes: `controller`,
`observer`, and `supervisor`. They read a host-owned policy file. Keep that
file, the bearer token file, Ed25519 private key, active snapshot, durable
journal, consumer state/readbacks, scheduler progress bind mount, and anchor
database credentials outside every application-writable mount. The application
receives only its deployment registry and the corresponding Ed25519 public key.
It must not receive a Docker socket or host signing/anchor credentials.

The disposable journey can inject audit, intent, and receipt write failures by
setting `X-UVM-G7-Fixture-Failpoint` on a public publish request. The API honors
that header only when `UVM_G7_DISPOSABLE_MODE=1` and only for the three named
stages. It raises inside the active transaction after the preceding writes, so
the public 503, unchanged revision, absent receipt, and unchanged bounded audit
count verify rollback. Production deployments do not enable the fixture mode.

The host policy is an exact schema-v1 object validated on each process start.
Its timing bounds and controller cadence/deadlines are independent host policy;
all seven public timing fields require explicit integer min/max bounds. The
policy digest is SHA-256 over canonical JSON of every field except
`host_policy_digest`. `anchor_read_dsn` grants read-only access to the
independent `uvm_audit_anchor.inventory` table. The observer uses the API's
bounded deployment telemetry endpoint and then queries only the returned event
IDs from that inventory. It does not read or write DefectDojo tables.

## Application and acknowledgement

The controller pulls `GET /host/desired`, validates deployment, host-policy
revision, exact fields, seven bounded values and the canonical digest. It
persists a candidate separately from `last_good`, atomically installs one
snapshot, and waits until the real observer and supervisor each publish the
same revision and digest after performing their work. Only then is the signed
host report marked `applied`. A timeout is `uncertain`; the previous verified
snapshot is restored when available. A durable pending report is retried with
the same identity so an accepted response lost in transit is idempotent. A
definitively expired report refreshes observation timestamps while retaining
its report identity and sequence.

The observer's request deadline controls its HTTP timeout; its observation
interval controls its cadence. Scheduler health is based on a completed Celery
beat tick, not process liveness. Anchor export and incident projection are
labelled and fail closed when their bounded telemetry is incomplete, missing,
future-dated or inconsistent. The supervisor measures the observer's durable
completed-loop heartbeat using the configured freshness and future-skew limits.
These health observations do not change the meaning of `applied`.

## Development invocation

The maintained integration entry point is:

```sh
G7_EVIDENCE_DIR="${TMPDIR:-/tmp}/volt-g7-observer-evidence/run-id" \
  bash tools/g7_container_journey.sh --observer-settings-only
```

Evidence and disposable host secrets belong in `/tmp`, never in Git. This
contract does not itself establish that the integrated Docker journey has run
or that a G7 gate has passed.
