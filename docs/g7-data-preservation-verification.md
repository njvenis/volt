# G7 preservation implementation and local verification

This implements the accepted bounded contract in `g7-data-preservation-contract.md` for FR-AU-01, FR-AU-02, G7-AU-01, G7-RET-01 and CR-09. The contract's original proposed-milestone heading is historical; implementation authority is the explicitly adopted scope, not that heading or an unchecked gate task. Independent candidate review and the separate G7 decision remain required. No verified OpenSpec capability is populated or archived by this implementation.

The independent host retains separate append-only expected-inventory and readcheck streams for each exact deployment, tuple and class. Every stream verifies its pinned genesis, consecutive predecessors, current head, configured public key and key ID. Inventory successors may append verified new members; they cannot change or remove earlier expected members. Readchecks bind their selected inventory, actual input times and watermarks, controller generation, recovery epoch, volume set and schema head. Repeated GETs do not publish or advance these stores.

`--provision-controller` is an explicit host action. `--provision-controller-only` advances the signed controller without reading a source or changing any class head; replacement performs it before starting the new generation. `--admit-new-members` is an explicit additive capture, not a loss-recovery operation. A new installation's expected membership must be admitted from its known original state. Replacing an established inventory with surviving rows after loss does not establish preservation.

Source attribution uses observations' own family/account and authoritative run scope; unresolved attribution prevents completeness. Scanner inventories include durable reservation facts. Each scanner checkpoint and its operational audit event share one transaction. An audit-write failure rolls back the checkpoint before the scanner fetch proceeds. Historical revision readback excludes later transitions.

Audit export captures a fixed committed watermark and canonical member digests under the current policy coordination lock. Pages and acknowledgements retain that exact deployment, tuple, service, policy, sequence, digest, watermark and receipt context. Source-target audit coverage uses native grant selectors and denies, independently from deployment audit permission. An unchanged admitted event may retain its captured source attribution after current lineage disappears; unknown attribution never becomes a deployment grant. Proven foreign events are excluded only when they were not already admitted in the selected namespace.

Both summary and record reads use the shared complete validator. Audit permission is checked before expiry diagnostics. Evidence downloads compare the actual bytes and mutable registration against independently admitted digest/size. Established absence or change is a gap; inability to complete the dependency read is failed with null counts. Public missing/untrusted responses normalize an absent environment to null and retain applicable environment and whole-audit masking reasons.

New anchors use v2 normalization. Stored v1 anchors and their digests are never rewritten. V1 reconstruction requires independently retained `legacy_time_preimage` metadata for both event timestamp fields: their original datetime/string kinds and, for strings, safe precision/offset/zone format facts. Actual values come from an authorized readable copy. Missing metadata yields unknown with `legacy_preimage_unavailable`; candidate representations are never guessed by trying hashes. Complete reconstruction with changed content yields a gap and an integrity observation. No raw preimage is put in a manifest.

## Reproduce the bounded local journey

Use the locked dependencies, approved Docker route and installed Chromium described by the maintained runner:

```sh
G7_EVIDENCE_DIR=/tmp/volt-g7-preservation-audit-evidence/<unique-run> \
  bash tools/g7_container_journey.sh --data-preservation-audit-only
```

The runner retains the complete source snapshot, image/configuration bindings, commands, raw exits, signed reports, independent heads/genesis, public verifier key, browser readback/download evidence and exact owned-resource cleanup. Credentials in retained inspection artifacts are structurally redacted, including URI passwords; original/redacted hashes and safe identity bindings are retained. Private signing keys and copied runtime secrets are not retained in the evidence packet.

Its copied-store probes run the actual collector, exporter, independent observer, producer and public consumers against isolated source, sink, receipt, anchor and byte-store copies. They cover membership loss, tampering, dependency outage, legitimate additive admission followed by loss, pending first receipt, unexpected sink-only membership and equivalent v2 timestamp representation. Expectations are independent prior admitted membership plus verified legitimate writer additions; they are not regenerated from damaged reports.

The copied normal API has startup/shutdown hooks disabled only by its test launcher, a request fence permitting preservation reads and the read-only source-snapshot operation, and recorded restricted copy roles. A separate copy-only writer exercises the real collector. Its frozen copied identity state has an explicit test-only 900-second lease covering the bounded matrix; stored heartbeat and source/report input check times are unchanged. This does not alter application startup, production recovery or production identity policy. Docker forwarding retries are bounded to explicit bind/forward errors and verify failed-create ownership and absence before retrying.

Focused local checks use the existing unittest suites and pinned tools:

```sh
.venv/bin/python -m unittest discover -s tests/operations -v
.venv/bin/python -m unittest discover -s tests/ingestion -v
node ui/tests/preservation-contract.test.mjs
npm --prefix ui run build
tools/g0_ci/openspec/node_modules/.bin/openspec validate --all --strict
.venv/bin/python -m unittest discover -s tests/public_check -v
.venv/bin/python tools/public_check.py .
git diff --check
```

SQLite query/timestamp adaptations are isolated test fixtures. They are not production verifier fallbacks. The retained candidate packet distinguishes these focused tests from executed PostgreSQL, browser and container evidence.

This is local synthetic evidence only. `elapsed_preservation` remains `unverified`; no elapsed year/quarter, public deployment, production provider/SIEM, disposal, pruning or deletion claim follows. External integration, production policy, visual/product decisions and gate approval retain their existing owners and boundaries.
