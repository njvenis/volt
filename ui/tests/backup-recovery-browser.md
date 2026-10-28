# Backup browser handoff

The backend-owned `tools/g7_container_journey.sh --backup-recovery-only` journey can import `runBackupBrowserStep` from `ui/tests/backup-recovery-browser.mjs` and pass its existing authenticated Playwright page. The helper navigates the actual App, discovers and selects the deployment, operates rendered controls, and checks all six independent readback dimensions. It does not start containers, operate the host controller, grant permissions, or provide API response fixtures.

```js
import {runBackupBrowserStep} from '../ui/tests/backup-recovery-browser.mjs';
await runBackupBrowserStep({page, origin, expectations: step, evidenceDirectory});
```

Alternatively, use an existing disposable environment's authenticated Playwright storage-state file:

```sh
node ui/tests/backup-recovery-browser.mjs \
  --origin "$UVM_ORIGIN" \
  --storage-state "$AUTH_STATE" \
  --expectations "$STEP_JSON" \
  --evidence "$G7_EVIDENCE_DIR/browser"
```

The caller creates the expected stage JSON from its named fixture and signed host policy. The following values illustrate the helper interface only; they are not deployment policy or automatically selected defaults:

```json
{
  "schema_version": 1,
  "id": "publish-1",
  "deployment_id": "g7-local",
  "action": "publish",
  "rationale": "Disposable backup recovery journey",
  "evidence_ref": "g7-local-browser-journey",
  "values": {
    "interval_seconds": 3600,
    "timeout_seconds": 900,
    "maximum_backup_age_seconds": 90000,
    "restore_verification_timeout_seconds": 1800,
    "archive_target_ref": "archive-target-local-a",
    "recovery_profile_ref": "recovery-profile-local-a"
  },
  "lose_acknowledgement": false,
  "timeout_ms": 90000,
  "expect": {
    "desired_revision": 1,
    "effective_revision": 1,
    "application": "applied",
    "archive": "unknown",
    "freshness": "unknown",
    "restore": "unknown"
  }
}
```

All six `expect` members are required. Revision expectations are positive integers or null. UI state strings are lowercase; an all-null archive is `unknown`. `id` is a safe filename component and must be unique per stage.

Use another `publish` step to change settings. Set `lose_acknowledgement:true` on that step to forward exactly one real command, require its successful HTTP response, drop that response before the UI receives it, reload the App, and recover through the rendered receipt button. The report checks exactly one original POST, its full six-field values or rollback revision, exact rationale/evidence, UUID, action and all four revision tokens against the pre-write public readback, plus one receipt read; it never replaces the server receipt with a fabricated success.

For rollback, use `action:"rollback"` and `rollback_revision` instead of `values`, plus a new reason, nullable evidence reference and complete expected status object. The browser reads immutable history and clicks **Roll back as new revision**. The expected desired revision must be the newly published revision, not the copied revision.

Use `action:"read"` for initial, host-applied, archive-complete/stale, and restored stages. Only `schema_version`, `id`, `deployment_id`, `action` and `expect` are required for a read. The backend journey controls and verifies host transitions between browser calls; the browser refreshes until its explicit expected states appear or the bounded timeout fails. A read asserts zero backup-command POSTs across navigation, discovery, refresh and capture, including commands targeting another deployment. It does not initiate any backup, restore or host operation.

Each call writes `<id>-browser.json` with expected/observed states, full observed command payloads, expected write payload, target paths and publication tokens, discovery page count, receipt recovery counts, accessibility results and pass/failure. It also captures 1440/390/320 screenshots. The CLI closes its own browser; an imported helper leaves the caller-owned page/context open and removes its request listener and acknowledgement-loss route.

Current execution evidence uses a synthetic local HTTP fixture (`ui/tests/backup-settings.test.mjs`). That verifies the helper and rendered App, including a real HTTP POST whose acknowledgement is lost, but does not establish the named container/DefectDojo/host recovery journey. The backend runner must retain its source revision, environment, expectations, raw browser output and process exit alongside its own evidence.
