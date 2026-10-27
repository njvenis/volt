# Requirement traceability

This map identifies the main implementation areas. It does not claim that every scenario has passed.

| Requirement area | Main implementation and coverage |
|---|---|
| CR-01 DefectDojo boundary | `uvm/engine/`, `uvm/ingestion/`, `tests/engine/` |
| CR-02–04 identity and occurrence continuity | `uvm/identity/`, `uvm/persistence/`, `migrations/`, `tests/identity/` |
| CR-05–09 assessment, permission and audit | `uvm/assessment/`, `uvm/auth/`, `uvm/audit_export/`, `tests/engine/`, `tests/identity/` |
| CR-10–11 honest evidence and data boundary | portable CI, synthetic fixtures, `tools/public_check.py`, `SECURITY.md` |
| FR-ME metrics and reporting | `uvm/assessment/metrics_api.py`, `ui/src/report-api.ts`, `ui/src/report-model.ts` |
| FR-UI workflows and states | `ui/`, `docs/ui-requirements.md`, UI build and synthetic G4 fixture checks |
| G7 packaging and operations | `Dockerfile.g7`, `docker/g7/`, `openspec/changes/g7-enterprise-rollout/` |

Use the active OpenSpec scenarios and relevant test modules to identify acceptance behaviour. Report the exact command, source revision, fixture/service environment and result for any verification claim.
