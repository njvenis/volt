// Proposed connector v1 contract: reviewed design 40ffb425. Backend integration pending.
export type UUID=string;
export type DecimalID=string;
export type Rev=number;
export type UTC=string;
export type Text=string;
export type Schema = {schema_version: 1};
export type Source = {
  source_id: UUID; revision: Rev;
  source_family: Text; source_account_id: Text; scope_key: Text;
};
export type Revisions = {
  target: Rev; policy: Rev; identity_membership: 0; owners: 0;
  authority: Rev; connector: Rev; source: Rev; secret_source: Rev;
  secret: Rev | null;
};
export type Permission = "connector.read" | "connector.configure" |
  "connector.secret.manage" | "github.repository.configure";
export type PermissionView = Schema & {
  connector_id: UUID; source: Source; principal_id: Text;
  revisions: Revisions; allowed: Record<Permission, boolean>;
};
export type Provider = null |
  {kind: "encrypted_local_v1"; secret_source_id: UUID;
   revision: Rev; key_binding_id: UUID} |
  {kind: "onepassword_v1"; secret_source_id: UUID; revision: Rev;
   account_id: Text; vault_id: Text; bootstrap_binding_id: UUID};
export type SecretRef = {secret_id: UUID; secret_revision: Rev; version_id: UUID};
export type App = {app_id: DecimalID; client_id: Text; slug: Text};
export type Installation = {flow_id: UUID; installation_id: DecimalID;
  account_id: DecimalID};
export type Settings = {
  environment_label: Text;
  authentication_mode: "legacy_token_file" | "github_app_v1";
  secret_source: Provider;
  credentials: {
    private_key: SecretRef | null; oauth_client_secret: SecretRef | null;
    webhook_secret: SecretRef | null; preview_secret: SecretRef | null;
    rest_token: SecretRef | null;
  };
  github: {host: "github.com"; api_version: "2022-11-28";
    app: App | null; installation: Installation | null;
    repository_ids: DecimalID[]; audience_revisions: Record<DecimalID, Rev>};
};
export type Failure = "credentials_unavailable" | "provider_unavailable" |
  "decryption_failed" | "permission_missing" | "scope_changed" |
  "audience_incomplete" | "audience_unapproved" | "installation_invalid" | "installation_suspended" |
  "callback_invalid" | "flow_expired" | "credential_revoked" |
  "restore_quarantined" | "reconciliation_failed" | "outcome_unknown";
export type Validation = {status: "unverified" | "valid" | "stale" | "failed";
  checked_at: UTC | null; intent_id: UUID | null;
  configuration_revision: Rev | null; reason: Failure | null};
export type Recovery = {
  state: "clear" | "quarantined" | "awaiting_activation";
  recovery_epoch_id: UUID | null; operator_clearance_present: boolean;
  requires_fresh_credentials: boolean; reason: "restore_quarantined" | null;
};
export type RemoteRevocation = {status: "not_requested" | "pending" | "confirmed" |
  "failed" | "unknown"; intent_id: UUID | null;
  observed_at: UTC | null; expires_at: UTC | null; reason: Failure | null};
export type SecretVersion = {
  version_id: UUID; state: "inactive" | "active" | "revoked";
  present: boolean; created_at: UTC; revoked_at: UTC | null;
  quarantine: "clear" | "restored_version";
  usable: boolean; validation_eligible: boolean; remote_revocation: RemoteRevocation;
};
export type Secret = {secret_id: UUID; revision: Rev;
  purpose: "private_key" | "oauth_client_secret" | "webhook_secret" |
    "preview_secret" | "rest_token";
  versions: SecretVersion[]};
export type IntentStatus = "pending" | "complete" | "failed" | "outcome_unknown";
export type ConnectorView = Schema & {
  connector_id: UUID; source: Source; revisions: Revisions;
  configuration_revision: Rev; active_configuration_revision: Rev | null;
  lifecycle: "staged" | "active" | "disabled";
  settings: Settings; validation: Validation; recovery: Recovery;
  reconciliation: {status: IntentStatus; intent_id: UUID | null;
    reason: Failure | null};
  secrets: Secret[]; updated_at: UTC;
};

export type BasePayload = {connector_id: UUID; source_id: UUID;
  rationale: Text; evidence_ref: Text};
export type MetadataAction = "connector.configuration.stage" |
  "connector.configuration.validate" | "connector.configuration.activate" |
  "connector.configuration.disable" | "connector.configuration.rollback" |
  "connector.secret.version.revoke" | "connector.secret.submission.reconcile";
export type ReceiptAction = MetadataAction | "connector.secret.submit" |
  "connector.installation.start" | "connector.installation.verify";
export type Command<P> = Schema & {
  command_id: UUID; action: MetadataAction;
  target_id: "00000000-0000-4000-8000-000000000000";
  membership_ids: []; expected_revisions: Revisions; payload: BasePayload & P;
};
export type Effect = "connector_configuration_committed" |
  "connector_validation_requested" | "connector_secret_submitted" |
  "connector_secret_revoked" | "connector_secret_submission_reconciled" |
  "connector_installation_started" | "connector_installation_verified";
export type SubmissionOutcome = "committed" | "not_committed" | "unknown";
export type Receipt = Schema & {
  command_id: UUID; action: ReceiptAction;
  target_id: "00000000-0000-4000-8000-000000000000";
  policy_revision: Rev; decision_id: UUID; audit_event_id: UUID;
  intents: {intent_id: UUID; kind: "connector.validate" | "connector.reconcile" |
    "connector.remote_revoke" | "connector.installation.verify";
    target_id: UUID; authority_revision: Rev; status: IntentStatus}[];
  result: {effect: Effect; connector_id: UUID; source_id: UUID;
    revisions: Revisions; configuration_revision: Rev;
    active_configuration_revision: Rev | null;
    lifecycle: "staged" | "active" | "disabled";
    secret_id: UUID | null; version_id: UUID | null;
    version_state: "inactive" | "active" | "revoked" | null;
    submission_id: UUID | null; submission_outcome: SubmissionOutcome | null;
    flow_id: UUID | null; recovery: Recovery};
};
export type ValidationResult = {configuration_revision: Rev; source_revision: Rev;
  secret_source_revision: Rev; credentials: SecretRef[];
  installation: Installation | null; repository_ids: DecimalID[];
  audience_revisions: Record<DecimalID, Rev>; checked_at: UTC;
  valid: boolean; reason: Failure | null};
export type IntentView = Schema & {
  connector_id: UUID; source_id: UUID; intent_id: UUID;
  kind: "connector.validate" | "connector.reconcile" |
    "connector.remote_revoke" | "connector.installation.verify";
  status: IntentStatus; attempts: Rev; last_error: Failure | null;
  next_attempt_at: UTC | null; completed_at: UTC | null;
  validation_result: ValidationResult | null;
  observed_remote_revocation: RemoteRevocation | null;
};

export type CandidateAudienceRequest = Schema & {
  github_host: "github.com"; owner: Text; name: Text;
  expected_audience_revision: Rev; reader_account_ids: DecimalID[];
  team_slugs: Text[]; data_access_approved: true; rationale: Text;
  control_evidence_ref: Text; included_group_ids: UUID[];
  connector_validation: {connector_id: UUID; source_id: UUID;
    configuration_revision: Rev; expected_revisions: Revisions};
};
export type CandidateAudienceResponse = Schema & {
  repository_id: DecimalID; audience_revision: Rev;
  audience_approved: true; audience_sha256: string;
};

export type StartFlow = Schema & {command_id: UUID; source_id: UUID;
  configuration_revision: Rev; expected_revisions: Revisions;
  rationale: Text; evidence_ref: Text};
export type Repository = {repository_id: DecimalID; owner: Text; name: Text;
  private: boolean; installation_access: boolean;
  audience_status: "unapproved" | "approved" | "stale";
  audience_revision: Rev | null};
export type FlowView = Schema & {
  flow_id: UUID; connector_id: UUID; source_id: UUID;
  configuration_revision: Rev; initiating_principal_id: Text;
  status: "awaiting_installation" | "awaiting_authorization" | "verifying" |
    "verified" | "failed" | "expired";
  expires_at: UTC; reason: Failure | null;
  app: App; installation: Installation | null;
  granted_permissions: {issues: "none" | "read" | "write";
    metadata: "none" | "read"; administration: "none" | "read" | "write";
    members: "none" | "read" | "write"};
  repositories: Repository[]; repositories_complete: boolean;
  verification_receipt: Receipt | null;
};
export type StartFlowResponse = Schema & {flow: FlowView;
  redirect_url: string; receipt: Receipt};

export type SubmitSecret = Schema & {
  submission_id: UUID; version_id: UUID; source_id: UUID;
  purpose: Secret["purpose"]; expected_revisions: Revisions;
  rationale: Text; evidence_ref: Text;
  input: {kind: "value"; value: Text} |
    {kind: "reference"; reference: Text};
};
export type SubmissionLookup = Schema & {
  submission_id: UUID; connector_id: UUID; source_id: UUID;
  secret_id: UUID; version_id: UUID; outcome: SubmissionOutcome;
  receipt: Receipt | null; retry_allowed: boolean; poll_after_ms: 1000 | null;
};

export type ErrorView = Schema & {error: {
  code: "authentication_required" | "csrf_failed" | "forbidden" |
    "source_scope_forbidden" | "not_found" | "invalid_request" |
    "revision_conflict" | "command_conflict" | "submission_conflict" |
    "credential_revoked" | "restore_quarantined" | "callback_invalid" |
    "validation_required" | "dependency_unavailable" | "outcome_unknown";
  message: Text; correlation_id: UUID;
  details: {outcome: "not_committed" | "unknown";
    expected_revisions: Revisions | null; current_revisions: Revisions | null;
    lookup_url: string | null};
}};
