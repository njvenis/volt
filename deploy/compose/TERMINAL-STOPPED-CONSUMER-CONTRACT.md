# Adopted stopped-completion transport

Adopted 2026-11-19 after independent implementation-ready review of exact source SHA256 e0ffe3ec466dee2251a7061820f9f70733bb9c1e70aefb5b026d76b40ad8cfcd. The closed nested observation transport and preserved 1 MiB/10-second host-log limit with original 600-second cutoff are authorised for Delivery implementation. Pending/proposed wording below is retained as provenance; this adoption governs wire authority. No new issuer, mount, candidate-only authority or legacy-marker fallback is permitted.

Reader implementation remains held on BOM/unsupported-encoding classification until corrected and reviewed. Public wiring, actual FD-held acquisition, current stopped joins, clean-stop and backup remain unverified. Contract acceptance is not runtime or gate acceptance.

---

# Private stopped completion consumer

The fixed Docker-cp input is at most 128 KiB, never extracted. Its exact directory inventory is the root0710/gid1800 directory, root0640/gid1800 empty single lock and launch.json, launch-status.json, supervisor.json, state.json, plus the UID1800 api0700 directory. No API observation or temporary entry is admitted for completion. All private record bytes must be their canonical encoding.

validate_stopped_snapshot requires FOUR positional inputs: original tar bytes, the current host-validated closed runtime tuple, the exact LF-stripped canonical private completion-envelope bytes, and the actual current Docker wait result as integer0. There is no old-marker or candidate-only fallback. The shared validators check the existing launch/status/envelope schemas; the Delivery reader checks same3R, stopped/clean_stop, stopped supervisor, current StartedAt versus recorded exec UTC, exact raw launch/status hashes, disarm and profile-appropriate purpose. Only normal_local_loopback or normal_local_https may reach local-backup purpose. Loopback needs no synthetic HTTPS boot or receipt. HTTPS disarm must bind the current runtime tuple and original API; neither profile may retain boot/seen/temp entries.

The reader cannot observe historical kernel waits. Its wait argument is comparison data from the trusted same-operation host controller, which must execute Docker wait against the SAME full CID, retain producer exit0 and exact stdout0, and bind the original current CID/StartedAt/typed image/resources to both the tar acquisition and bounded private Docker-log acquisition. The private envelope is emitted only through the original Bash adapter0, broker0, post-reap producer0 chain. Files, envelope literal0 or this pure reader alone grant no installation, backup or clean-stop authority. An uncertain producer, truncated/duplicate/noncanonical envelope, current-context mismatch or nonzero wait denies. No new completion file, authority issuer, API mount or signature/time-policy exception exists.

A separately labelled component controller may validate this reader against an older exact image's output; that is not a new-source package or public offline-backup qualification. Public offline exchange wiring and the maintained signed/minimal-host journey must use a truthful coherent source before acceptance.

## Proposed public offline transport amendment (not implemented or activated)

This section pins the proposed internal transport for review before production wiring. The existing offline exchange profile and its eight observation keys remain unchanged: image, containers, volumes, networks, logs, logs_since, inventories, independent_admission. For backup observations ONLY, logs becomes a PRIVATE canonical UTF-8 JSON string, never generic log text. Restore still requires logs empty and logs_since null. New backup code rejects the old five-marker representation; there is no compatibility fallback.

The JSON string is at most 262144 encoded UTF-8 bytes and has EXACTLY these fields (no duplicate or unknown keys, no whitespace/noncanonical alternative):

| Field | Exact type and bound |
| --- | --- |
| schema_version | integer 1; boolean rejected |
| profile | literal volt_stopped_completion_observation_v1 |
| queried_container_id | full lowercase 64-hex current Docker CID |
| queried_started_at | the existing strictly parsed Docker StartedAt, equal to outer logs_since and the current stopped inspection |
| docker_wait_stdout_b64 | canonical standard padded Base64 of EXACT two bytes `0` followed by LF; no other output |
| docker_wait_producer_exit | integer 0; boolean rejected |
| docker_wait_filter_exit | integer 0; boolean rejected |
| routing_tar_b64 | canonical standard padded Base64 of the EXACT original Docker-cp tar, decoded length 1..131072 bytes, encoded length at most 174764 bytes |
| routing_tar_producer_exit | integer 0; boolean rejected |
| routing_tar_filter_exit | integer 0; boolean rejected |
| completion_envelope_b64 | canonical standard padded Base64 of the exact LF-stripped canonical whole envelope, decoded length 1..2048 bytes, encoded length at most 2732 bytes |
| docker_logs_producer_exit | integer 0; boolean rejected |
| docker_logs_filter_exit | integer 0; boolean rejected |
| post_container | exact current projected container object described below, canonical encoding at most 65536 UTF-8 bytes |
| post_inspect_producer_exit | integer 0; boolean rejected |
| post_inspect_filter_exit | integer 0; boolean rejected |

Base64 must validate and round-trip byte-for-byte to the original spelling. The complete outer exchange, including this string and all other resources/receipts, remains bounded by the EXISTING 8 MiB MAX_INPUT. No limit is raised and no decoded temporary archive is extracted. The string limit applies before JSON parsing; all decoded limits apply before record parsing. The tar and envelope must individually pass the existing strict validators, not merely their length checks.

post_container has EXACTLY the existing container projection fields: Name, Id, Image, ImageManifestDescriptor, Config, HostConfig, NetworkSettings, Mounts, State. Config contains ONLY Labels; HostConfig ONLY NetworkMode; NetworkSettings ONLY Networks, whose existing fixed attachment records contain NetworkID and DriverOpts. Each Mounts row has ONLY Type, Name, Source, Destination, Driver, RW. State has ONLY Running, Paused, Restarting, OOMKilled, ExitCode, Error, StartedAt. This is the same projection as the initial observation, not a new context selector. The owner validates both against current instance custody/admission/resource rules, requires the same full CID/StartedAt and compares every projected value. ONLY semantically unordered mount collections may be sorted by unique Destination using the existing canonical_resources rules; duplicates, unexpected fields and any changed identity deny. Both observations must be stopped, unpaused, not restarting, not OOM-killed, Error empty, and integer ExitCode0.

The trusted host retains the original actual lifecycle FD owner across collection and all archive/capture/final acknowledgements. It derives the queried full CID and StartedAt from the saved current observation, uses that FULL CID for Docker wait, Docker cp of the fixed /run/uvm-route-check/. directory, and Docker logs --tail256 --since the saved StartedAt. After all three acquisitions it inspects that SAME full CID again. It retains independent producer and reader outcomes for EACH acquisition; no pipe's last status, substring match, candidate literal or successful parser substitutes for a producer result. It never selects a path from the archive, completion line or journal. No instance/cache/socket/API mount is added.

Root's bounds choice for this revision preserves the adopted HOSTLOG limit: at most 1048576 bytes (1 MiB) of Docker log payload and 10 seconds TOTAL through EOF, including controlled stop. This is an input limit, not merely an output-envelope limit. There is NO 120-second log allowance, larger-stream exception, long-line bypass or extension of the ordinary600-second stop deadline. Reads are at most65536 bytes; retained raw input is bounded by1 MiB in private memory and is never a public log artifact. Every logical line, including unrelated records, is at most2048 bytes excluding LF, at most1024 lines are accepted, and EVERY nonempty line must end in LF. Unterminated unmarked tails and incomplete pre-marker JSON tails deny even after an earlier valid completion.

Candidate recognition decodes each JSON object record BEFORE comparing its decoded profile with the shared completion profile. Duplicate keys, escaped profile names/values, whitespace alternatives, malformed JSON-looking records and unknown fields in a candidate cannot evade canonical/schema validation. Exactly ONE whole canonical shared completion record is required. Raw marker presence can cause additional rejection but can NEVER be the sole profile-recognition or success predicate. A second escaped/noncanonical completion record denies instead of being silently treated as unrelated text. The shared validator and final strict current-launch/status join remain authoritative; no new schema alias is introduced.

All acquisitions use the existing private FIFO/reader model with independent producer/reader outcomes and an absolute host-collection cutoff. Separate maxima are: Docker wait0.5s through exact two bytes plus EOF; fixed private tar1s through at most131073 input bytes (the last byte detects a131072-byte overflow) and strict transport parsing; current post-inspection0.5s through EOF/closed projection; Docker logs10s through EOF/record validation. The sum of these maxima is12s. During ordinary stop every producer, reader, parser, recheck and reap is ALSO clamped to the ORIGINAL T0+600s deadline, leaving at most the already reserved13s after T0+587 for these actions and their overhead. Deadlines never restart the600s clock or borrow earlier broker/cleanup time. If startup/transport/reap overhead leaves less time, the current operation fails closed rather than extending a deadline. A current already-stopped/cold observation uses the same bounded acquisitions and requires the retained exact original stop/completion evidence; it does not fabricate missing original waits or reset an earlier stop budget into authority.

The final current-inspect projection has its separate0.5s total above and the EXISTING observation MAX_INPUT byte bound, with canonical projected output at most65536 UTF-8 bytes. No Docker output is buffered to an unbounded disk file. Real input descriptors use readiness/deadline-checked reads including EOF; the module's BytesIO path is explicitly only in-memory component input. Reader timeout/error, no EOF, byte/line/record overflow, producer nonzero, unexpected live producer, uncertain reap or lost outcome denies and retains private evidence; no successful partial output is promoted. Exact registered producer completion and descriptor closure remain mandatory, and producer failure cannot be hidden by a valid parsed candidate. All acquisition files and the logs string are private0600 under owned0700 temporary custody; raw tar, private process records, CID/3R and envelope never appear in public diagnostics/stdout. A fixed data-only encoder may serialize captured files/statuses into the existing observation; it cannot run helpers, issue identities, infer outcomes or manufacture a historical wait.

Inside the actual FD holder, validate_observation first authenticates the fresh independent receipt/cache, exact admitted image/selected descriptor, instance custody and current stopped resources. It then decodes this mandatory transport, validates all independent zero statuses and the matching post-inspection. The runtime tuple is derived ONLY from that validated initial current container full CID/StartedAt, the instance's authenticated typed image admission (kind/id/config_id), and its current admitted local-start resources_sha256. Neither the envelope nor post_container may supply replacement expectations. The owner calls existing validate_stopped_snapshot with the exact tar bytes, that derived runtime, the exact canonical envelope bytes, and the actual host-observed Docker wait0. The reader joins original3R/raw launch/status hashes, stopped/clean_stop, supervisor, disarm and profile-specific backup purpose. Normal loopback needs no HTTPS observation; no generic terminal completion grants HTTPS routing authority.

A transport/parser success is not proof by itself: only this same-operation host collection and actual FD-holder validation chain may gate capture. Missing cold/already-stopped evidence denies; no completion/backfill, missing-pin reconstruction, new issuer, repair/adoption or signature/time-policy exception is introduced. The existing before/after-capture revalidation and atomic publication protocol remain mandatory.

## Failed read-only host-client retention boundary

On an unknown/live read-only child at the original absolute host cutoff, the host returns NONZERO (124 deadline or255 unavailable completion), retains the private original PID/proc-start-ticks/job gates/statuses/workspace and any exact registered read-only helper, and does NOT claim it killed or reaped that child. No numeric PID/process-group signals or check-then-kill substitution for pidfd is used. Actual original child and guard waits are required ONLY for a positive result; an uncertain result is never encoded as a zero producer status. Temporary gate/cancel/negative-timeout files are host mechanics, not completion authority or new shared schema. An unreleased gate remains closed on uncertainty; after FIFO opening the child rechecks the original deadline before executing its fixed read-only command. A previously released read-only client can remain pending after failure; its eventual bytes cannot authorize a later operation. Private output and original identities remain for a future independently guarded cleanup decision. Pending clients prohibit workspace deletion and success. Future cleanup must revalidate the exact retained identity/current context and use an actually safe kernel handle or exact owned Docker full CID; it cannot adopt a numeric PID or unrelated helper.

The retained route is restricted to fixed read-only Docker wait/inspect/logs/cp, cache/receipt verification, data filtering/encoding, fixed read-only host-stop comparison and reporting. It cannot run Compose lifecycle mutations, archive capture/publication, identity/key creation or any writer. The existing synchronous physical Compose STOP has a separately explicit UNRESOLVED hard-host-startup-deadline limitation; a check after it returns is not proof of a hard600s host cutoff. No new timeout executable or mandatory host dependency has been adopted, and this failure-retention route cannot authorize leaving a mutating command pending. Ordinary stop acceptance remains held on that separate boundary. The existing original stop clock is nevertheless anchored before Compose and is never reset for read-only acquisition.

Retention remains set through owner completion, original producer/report waits, final ownership acknowledgment AND final successful status output. A reporting/logging failure after valid proof or durable backup publication remains nonzero and keeps the private workspace; it never deletes or overwrites a committed backup. No additional raw log or private process record is printed by timeout/error paths.


### Standalone backup inventory preparation

For standalone `backup-record` on an already stopped instance, with no ordinary
stop clock, the three fixed read-only store inventories are a separate bounded
preparation phase. Captured-phase preparation additionally inventories the
instance only when that existing phase requires it. Each helper retains its
single original read-only mount and runs its existing owner/driver/options
checks inside an independently tracked job. All exact original producer and
guard waits must succeed within one finite 13-second preparation cutoff.
Failure retains evidence and cannot start the stopped-proof snapshot.

The same pinned actual lifecycle holder is rechecked at the boundary. Only
successful preparation clears that preparation clock. A fresh snapshot then
starts the existing 13-second stopped-proof acquisition/assembly window;
current CID/StartedAt, post-inspection joins, independent producer/filter
outcomes and final owner validation remain mandatory. No preparation result
acknowledges a phase, commits metadata or permits capture/publication. Observed
and captured inventory validation and the existing archive/publication seals
are unchanged. This separation does not reset, borrow from, or extend the
ordinary public-stop T+600 clock or its 13-second reserve; attempting preparation
with any existing acquisition or ordinary stop clock denies. Public stop and
all fixed stream/parser limits are unchanged. Restore-provision adds no helper;
restore-admit retains its existing required imported-store inventories.
