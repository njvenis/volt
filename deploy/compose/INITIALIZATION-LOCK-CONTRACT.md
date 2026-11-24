# Fixed initialization by the lifecycle lock owner

This closes the packaged empty-root/lock-file ordering defect. It introduces no
API authority, token, source-path selector or arbitrary command executor.

The host first stages the closed Compose assets. The data-only request emitter
runs in the digest-admitted image with no network, no capabilities, readonly
rootfs and readonly package; it has no instance-root mount. Its only output is
public initialization metadata to a new host-owned0600 file under the private
WORK directory. It creates no identity, secret, journal or instance file.

The detached admitted lock holder receives that one file readonly at the fixed
container path /run/volt-initialization/request.json and the authenticated
package readonly at /package. There is no request-path argument. The fixed
--initialize-local action first opens the current lifecycle inode with
O_NONBLOCK/O_NOFOLLOW, validates host UID, regular single-link0600/size0 and
stable identity, and actually acquires its exclusive nonblocking flock. An
unrelated holder causes exit75 before reading the request or initialization.
It never replaces/unlinks the lock inode or repairs its permissions.

Only then does it read bounded request bytes (64KiB), requiring a regular,
current, single-link0600 host-owned file with no links/FIFO. JSON duplicate or
unknown fields are denied. Exact top-level fields are schema_version (integer1,
not boolean), profile (literal volt_local_runtime_init_v1), setup_sha256
(sha256 plus64 lowercase hex), and arguments (the closed object below).
The fixed readonly package setup bytes are descriptor-read and hashed against
setup_sha256 before loading. No request supplies code, command or setup path.

The exact arguments keys are directory, project, image, platform, http_port,
recovery_port, oidc_port, admitted_image_id, admitted_image_id_kind,
admitted_engine_image_id, admitted_image_config_id,
admitted_selected_descriptor, admitted_source_revision,
admitted_source_snapshot, admitted_version, owner_token, network_subnet,
network_gateway, runtime_compose_directory, and host_instance_directory.
Directory is the fixed container instance root /state. The three ports are
strict integers1–65535; the other values are nonempty NUL-free bounded strings.
Existing exact image/source/platform/network/local-RC4 checks still apply.
No credential, capability, signing seed, cookie or arbitrary mode belongs to
this request. The descriptor JSON is data, never evaluated.

The holder calls the fixed local initializer in the same process with the
actual owned lock FD. The initializer validates that FD against the current
host-owned single-link0600/size0 lifecycle inode and reasserts exclusive flock
ownership before any identity/secret/journal mutation. The only allowed initial
instance inventory is the three closed Compose files plus the held lock inode:
root entries are exactly compose and .install.lock. A direct runtime-prepare
CLI call has no FD and is denied even if somebody else holds a lock. A failed
acquire, owner label, filename or flag is never proof of ownership.

Initialization completes before locked=1 readiness is emitted. The same FD
remains open and locked for the rest of the lifecycle. Initialization failure
emits no readiness and cannot start custody preparation, workers or ingress;
partial initialization stays closed. Tests must cover actual child-owner
success, unrelated held-lock/concurrent denial, direct preparation denial,
request nonmutation, malformed/symlink/FIFO requests and lock-inode custody.
