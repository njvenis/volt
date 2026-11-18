# Backend auth and command-reconciliation repair evidence

Date: 2026-11-18. Source parent: `30a2d7cbe7f98cf2e640932f5e4d6d5f30c49eec` (review found material issues). This repair does not verify packaged Compose installation, release/publication, deployment, or live Qualys behavior.

## Runtime and database

- Python 3.13.15: `/var/tmp/volt-portable-demo-20261117/auth/.venv/bin/python`.
- uv 0.12.18, SQLAlchemy 2.1.8, FastAPI 0.162.0, cryptography 50.0.2.
- Command environment came from `/var/tmp/volt-easy-install-20261118/env.sh`; `UV_CACHE_DIR` and `TMPDIR` were redirected to task-owned paths under this worktree because the shared uv cache was read-only. Commands used `uv run --active --no-sync` because the environment had no network access to fetch a missing wheel.
- PostgreSQL: task-owned container `volt-easy-auth-postgres`, image `volt-g7-identity-dev:EtRXJ1`, image ID `sha256:14013d476c098a4f76374f2a5032ba51ebe0f5f8b8bacac5b2a1663e78c6578b`, PostgreSQL 18.6, loopback-only `127.0.0.1:45432`.
- Dedicated database: `volt_easy_auth_test`; DSN `postgresql+psycopg://postgres@127.0.0.1:45432/volt_easy_auth_test` (no password). The maintained test checks both database name and PostgreSQL major version and resets only its `public` schema.
- No shared database, container volume, Docker daemon configuration, network endpoint, or other task’s resource was changed. The owned unittest process was stopped after the final expanded run remained idle during Alembic setup; the PostgreSQL container was left running and all test connections were released.

## Passing real-PostgreSQL and schema evidence

The last complete maintained command that passed was:

```sh
uv run --active --no-sync python -m unittest \
  tests.operations.test_local_accounts_postgres \
  tests.operations.test_export_openapi -v
```

It passed 18 tests in 88.150 seconds. Full output: `repair-pg-openapi-final.log`.

That run covered real PostgreSQL setup-claim competition and rollback, setup authority intent and receipt atomicity, durable independent username/peer throttles, recovery/login race fencing, protected deployment inventory denial, local-mode fallback denial, password NFC/PHC/account-name policy, session disable/re-enable and restore revocation, repeat-safe setup preparation, strict runtime registration/abandon envelopes, allocated-ID receipt shape, registration/abandonment race, and bearer/OIDC/local OpenAPI declarations.

Four later-added focused assertions also passed against the same PostgreSQL database in 3.182 seconds: password-change/login race fencing, local grant-group/source pairing, rejection of remote HTTP/unsupported scheme/host-mismatched local configuration, and database-error log redaction. Output: `repair-remaining-findings-focused.log`.

The two recovery-startup regressions that failed in a combined 66-test run because a legacy SQLite fixture has no `local_auth_installation` table passed when rerun directly after the compatibility correction. Output: `repair-legacy-auth-schema-compat.log` (2 tests, exit 0).

Exporter tests passed again after regenerating `openapi-comprehensive.json`: `repair-openapi-final3.log` (2 tests, exit 0). Focused Python compile checks completed with exit 0 after the last source changes. Pinned OpenSpec 1.11.0 `validate --all --strict` passed all 4 changes; output: `repair-openspec-final.log`.

## Reproduced failure and repair

The added throttle reproducer first failed against PostgreSQL: an invalid login returned 401 while the committed attempt count remained zero. Raw failure: `repair-failure-throttle-repro.log`. The handler had raised inside `engine.begin()`, rolling back its own counter write.

The repaired handler uses independent user and peer buckets, PostgreSQL conflict-safe bucket initialization, transaction-committed failure counts, 5-attempt user and 30-attempt peer thresholds, and a four-slot Argon2 KDF bound. The persistent counter and independent-bucket assertions passed in the complete PostgreSQL run. Earlier intermediate code/test failures remain in `repair-pg-batch-*.log` and were not counted as passing evidence.

## Expanded-suite stall and limits

An expanded rerun including the four additional PostgreSQL assertions is retained as `repair-pg-openapi-final2.log`. It passed the tests through restore-session revocation and reached `test_user_and_peer_buckets_are_independent_with_separate_limits`, but did not finish. The runner was stopped with exit 130 after more than four minutes without further output. A read-only `pg_stat_activity` inspection during that stall showed one backend `idle in transaction`, `wait_event=ClientRead`, with its last statement `CREATE TABLE collection_runs`; there was no PostgreSQL lock wait. After stopping the owned runner, a follow-up activity query showed zero remaining test-database backends. This is reported as incomplete migration-side verification, not a passing run or an application assertion failure.

The focused existing regression batch ran 66 cases and had 64 pass plus two SQLite startup errors caused by `install_auth` querying `local_auth_installation` without checking the legacy test schema. The two failing cases then passed directly after adding table-existence handling. Combined output: `repair-auth-regressions-complete.log` and `repair-legacy-auth-schema-compat.log`.

The demo-password attempt-limit regression did not complete: a minimal plain FastAPI `TestClient` GET also hung in the supplied environment. Faulthandler evidence in `repair-demo-throttle-faulthandler.log` shows the caller blocked waiting in `Starlette TestClient` while its AnyIO portal event loop was idle. The demo flow remains unverified; this does not represent a local-auth end-to-end claim. Partial attempts are retained as `repair-auth-regressions-final.log` and `repair-demo-throttle-focused.log`.

## Scope limits

No packaged Compose acceptance, external deployment, public registry publication, merge, release, live tenant access, or live Qualys API behavior was performed. The separate scanner owner retains `uvm/scanners/`, `tests/scanners/`, and migration `0066`; this repair does not claim scanner registration is configurable or activatable.


## Original source archive retention

The original b31 backend repair archive is retained outside the public source tree at `/tmp/volt-easy-install-20261118/evidence/backend-senior/pre-pr-public-check/b31-original-source.tar.gz`. Its SHA-256 is `af8c05f848e4d314b031503e0a1f92ba353fa65a3bd78d3ad91284cec6be5fba`. The complete original bytes were copied and their hash verified before removing the tracked archive. This private task-evidence path is not a public download or a portable repository artifact. Prior verification outcomes above are unchanged.
