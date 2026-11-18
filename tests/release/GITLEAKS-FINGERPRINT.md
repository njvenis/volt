# One historical synthetic-verifier disposition

The user explicitly decided **"approve exception"** on 2026-11-18 after the root explained the failed current/history scans and exact proposed exception. This supersedes the earlier automatic approval-review rejection of a prompt lacking that explicit authority; the earlier rejection and diagnosis remain retained. The root delivered the new authority in packet `2a6efcc9-4665-4225-8a36-1a9075c47b4a`.

The sole `.gitleaksignore` entry identifies `generic-api-key` at `tests/operations/test_demo_password_login.py:29` in immutable commit `11fab25894046bf7f9b339753755f308f9d32fbd`. Private redacted evidence at `/var/tmp/volt-release-rc3-20261117/evidence/senior-gitleaks-history/` established that this is the synthetic salted scrypt verifier used by the disposable password-login tests. An in-memory recomputation from test login inputs matched it; it is not an issued credential. No verifier, password or salt is reproduced in the disposition. The current auth fixture now generates its verifier at runtime.

This is an exact historical finding disposition. Default rules, the TOML policy, directory and full reachable-history scan scope, failing exit codes and the pinned image remain unchanged. There are no wildcard, rule-wide, path-wide, whole-commit or future-value exceptions, and no history rewrite. Gitleaks v8.30.1's documented fingerprint mechanism is pinned by image digest; a future tool upgrade must recheck its semantics.

Executable regression journey (Docker and Git required; private evidence outside the source tree):

```
python3 tests/release/gitleaks_fingerprint_journey.py --source "$PWD" --evidence /private/path/to/new-evidence-directory
```

The journey requires a clean committed source, preserves all reachable refs in a bundle and scans an isolated checkout with the unchanged pinned tool. It exercises actual directory/history passes, the no-disposition historical control, same-marker reintroduction in a new commit at the same position, different path and different line, independent generated generic/default-rule credential-like markers, and a live-directory injection. Negative/control scans must fail with the expected safe finding metadata. Values are never printed; reports/logs are redacted and generated fixtures are private, retained as source bundles, then their disposable working copies are removed. Unit policy checks supplement these scanner executions.

Passing local scanner checks does not establish hosted Security status, main-source native RC3 preparation, publication or human environment approval. Root owns those separate operations.
