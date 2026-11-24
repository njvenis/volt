# Adopted live-fence custody mapping

Root adopts the fence-only mapping below following the same Reviewer's explicit design GO. It supersedes only the earlier fence directory/file modes and adds the closed custody field; signing keys, material keys, authority/config files and generic private-file rules remain unchanged. This is implementation authority, not executed acceptance.

Required implementation conditions:

- Every prepare, restore and repair writer publishes only a correctly owned/mapped fence. Use the admitted helper where assigning fixed GID1800 requires privilege. Never expose an intermediate wrong-group or0600 replacement.
- Derive owner_uid from the validated selected instance owner and bind it in the committed inventory, closed backend config and persisted profile. Never learn/adopt it from a contradictory live file.
- Bounded no-follow descriptor validation checks directory and file exact owner/group/mode/type; reopen the current envelope for every authority check. Do not cache a staged copy.
- Keep the directory inode stable; atomically replace only fence.json. Replacing/restoring the directory requires stopped workers and renewed actual mount admission.
- Prove actual ordinary host ownership distinct from runtime1800. Unsupported daemon UID/GID mappings fail closed. Runtime receives group read/traverse only and a read-only mount, with no operator-private ancestor.

Original readiness proposal follows verbatim as provenance; its provisional wording is superseded by this adoption and the conditions above. Backend owns the closed config/binding/reader; delivery owns all writers, inventory, mounts and actual container proof.

# Proposed narrow live-fence mapping amendment

Concrete producer/runtime incompatibility found by delivery Senior fbde5bc3: independent host custody must keep the selected ordinary host UID, but runtime uvm UID/GID1800 cannot traverse/read a dedicated live host fence kept0700/0600. Chown to1800 breaks host ownership, while copying makes the fence stale. Backend's current generic private_read rejects group-readable fences. No implementation change is implied by this checkpoint; backend owner and same Reviewer must check the narrow mapping below before root records final contract.

Keep the dedicated live fence directory owned by the selected host UID, with group1800 and exact mode0710; its sole regular fence.json is the same owner/group with exact mode0640. Group1800 has traversal/read only, never write; other permissions are zero. It is mounted read-only as the dedicated directory, not copied. This is a custody envelope containing identity/generation/epoch, not a credential or signing key. Host directory ownership and exclusive atomic replacement remain unchanged; parent instance/secrets directories stay0700 and are never API-mounted. The helper may set this exact group through its admitted root preparation operation on the narrowly owned instance mount. No host setfacl or user/group installation dependency.

Add one closed validated local-recovery config object restore_fence_custody={owner_uid:<actual selected host UID>,runtime_gid:1800}. Fields are nonnegative integers excluding bool; runtime_gid is fixed1800, not caller-selected authority. Preparation and committed host inventory bind these values; staged private config remains0600 and the persisted backend profile binding includes them. Existing deployments require exact new contract and fail closed on mismatched/missing custody, never silent rewrite/backfill.

Only the fence-specific descriptor reader accepts this exact0710/0640 mapping and configured owner/group, bounded/no-symlink reads, regular-file identity, non-world access and no group writes. All keys, material, authority config, credential/config inputs and the existing generic private_read retain0600 private-owner rules. Exact live mount and actual container inspection are still required, including operator-private ancestor exclusion. No broad group-readable secret exception, new signing root or dynamic runtime UID change.

Acceptance: actual host UID distinct from runtime1800; host prepare/validate/resume all retain custody; actual non-root uvm can read the live envelope; host atomic replacement/removal/contradiction is observed and denied by backend fence checks; wrong UID/GID/mode/symlink/writeable group/world inputs denied; configuration/key bytes remain inventory-bound; operator material never API-mounted. External/demo/G7 semantics unchanged. If backend implementation makes this mapping unsafe, return the exact conflict and smallest alternative before product edits.
