export function requireSession(session, expected) {
  const authority = session?.authority;
  if (!session?.authenticated || session.credential_mode !== 'oidc_session'
      || session.principal_id !== expected.principal
      || authority?.issuer !== expected.issuer || authority?.subject !== expected.subject) {
    throw new Error('synthetic_browser_login_identity_mismatch');
  }
}

export function requireAdminRendered(state) {
  if (state.error) throw new Error('administration_view_error');
  if (state.loading || !state.headingVisible || !state.createButtonVisible || !state.createButtonEnabled) {
    throw new Error('administration_view_not_ready');
  }
}

export function requireReceipt(receipt, expected) {
  if (!receipt || typeof receipt !== 'object' || receipt.schema_version !== 1
      || receipt.command_id !== expected.commandId || receipt.action !== 'access_group.create'
      || receipt.target_id !== expected.targetId || !isUuid(receipt.decision_id)
      || !isUuid(receipt.audit_event_id) || !Number.isInteger(receipt.committed_revision)
      || receipt.committed_revision < 1 || receipt.policy_revision !== receipt.committed_revision
      || receipt.result?.policy_revision !== receipt.committed_revision
      || receipt.result?.object_kind !== 'access_group'
      || receipt.result?.object_id !== expected.groupId
      || !Number.isInteger(receipt.result?.object_revision) || receipt.result.object_revision < 1
      || receipt.result.authority_mode !== 'uvm_native_v1') {
    throw new Error('public_admin_command_receipt_mismatch');
  }
}

export function requireAudit(item, event, expected) {
  if (!item || item.access_group_id !== expected.groupId || item.display_name !== expected.displayName
      || item.revision !== expected.objectRevision || !event
      || event.event_id !== expected.auditEventId || event.action !== 'access_group.create'
      || event.actor_id !== expected.actorId || event.after_value?.access_group_id !== expected.groupId
      || event.after_value?.revision !== expected.objectRevision
      || event.after_value?.display_name !== item.display_name
      || event.after_value?.description !== item.description || event.after_value?.enabled !== item.enabled) {
    throw new Error('public_admin_audit_or_object_mismatch');
  }
}

export function requirePersistedState(item, event, state) {
  if (!item || !event || event.event_id !== state.receipt.audit_event_id
      || event.action !== 'access_group.create' || event.actor_id !== state.principal_id
      || JSON.stringify(event.after_value) !== JSON.stringify(state.audit_after_value)
      || item.access_group_id !== state.object.access_group_id
      || item.display_name !== state.object.display_name || item.description !== state.object.description
      || item.enabled !== state.object.enabled || item.revision !== state.object.revision) {
    throw new Error('restart_persisted_object_or_audit_mismatch');
  }
}

function isUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
