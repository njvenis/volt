# Private main broker bootstrap transport

The fixed main-API recipe receives the existing closed launch JSON on anonymous
inherited stdin. PATH/LC_ALL, the 512 KiB encoded input bound and five-second
broker input deadline are unchanged. The root producer is a registered direct
Bash coprocess: a five-second one-byte gate lets PID1 retain its PID and pipe
descriptors before emission. PID1 starts the fixed broker directly, retains its
actual `$!`, releases the producer, closes its own descriptors, then waits/reaps
the exact producer. A separately registered fixed five-second deadline child interrupts PID1 if
input emission/completion is still pending, including after gate release and
reader backpressure. PID1 retains producer registration across signal-interrupted
waits and clears it only after an actual wait result; unknown/expired completion
causes bounded nonzero PID1/container termination with registration retained.
The deadline child itself is reaped before normal startup proceeds. Closing
descriptors releases EOF/SIGPIPE where possible; producer failure denies startup. No signal or descendant
lookup selects a producer, and no payload/environment is persisted or logged.

No new startup creates `api-launch-input` on disk. Any existing object at that
legacy name, including a FIFO, regular file or symlink, denies startup unchanged.
Its original participants were never recorded, so ownership/mode alone cannot
prove safe removal. This is not migration or positive legacy repair authority.

Component interruption tests cover the anonymous gate/reader death, exact child
parentage, reaping, no persistent transport after interruption/restart, and
legacy-object preservation. Extracted-shell tests with a substituted reader do
not establish the protected broker, full image entrypoint or public restart.
The fresh-image interruption proof remains a separate execution dependency.

Internal entrypoint operations use the fixed protected control script and its
closed entrypoint dispatcher. They do not generate Python source or choose an
arbitrary function. Expected typed errors map to their finite static code;
unexpected exceptions map to cleanup_failed without messages or traceback.
Nonzero cleanup results still cannot skip the original-process stop attempts.
