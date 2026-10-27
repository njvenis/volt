import type {Duties,TargetScope} from './assessment-api';
import type {AdminCatalogue,Grantable,NativeLimits,NativePermission,SourceScope} from './native-admin-api';

// Form validation of the server's explicit ceilings. This does not grant authority:
// the command endpoint still authorises the actor and rechecks current revisions.
export const isDeploymentSettingsAction=(action:string)=>['observer.timing.read','observer.timing.configure','backup.settings.read','backup.settings.configure'].includes(action);
export const isObserverTimingAction=(action:string)=>['observer.timing.read','observer.timing.configure'].includes(action);
// Deployment IDs are opaque exact matches. Even "*" is not a wildcard here.
export function validDeploymentScopes(value:unknown):value is string[] {
  return Array.isArray(value)&&value.every(v=>typeof v==='string'&&v.trim().length>0&&v.length<=256&&!/[\x00-\x1f]/.test(v))&&new Set(value).size===value.length;
}
export function deploymentScopesWithin(value:unknown,ceiling:unknown,allowEmpty=false):boolean {
  return validDeploymentScopes(value)&&validDeploymentScopes(ceiling)&&(allowEmpty||value.length>0)&&value.every(v=>ceiling.includes(v));
}
export const severityOrder=['informational','low','medium','high','critical'];
export function severityChoices(ceiling:string|null):string[] {
  return ceiling===null?[]:severityOrder.slice(0,severityOrder.indexOf(ceiling)+1).reverse();
}
export function sourceScopeKey(scope:SourceScope):string {
  return JSON.stringify([scope.source_family,scope.source_account_id,scope.scope_key]);
}
export function hasGrantable(value:AdminCatalogue['caller']['grantable']):value is Grantable {
  return Array.isArray(value.actions)&&!!value.target_scope&&!!value.limits&&
    Array.isArray(value.source_scopes)&&!!value.separation_of_duties&&
    (value.deployment_scopes===undefined||validDeploymentScopes(value.deployment_scopes));
}
function subset(values:string[],allowed:string[]):boolean {
  return values.every(v=>typeof v==='string'&&v.trim().length>0)&&
    new Set(values).size===values.length&&values.every(v=>allowed.includes('*')||allowed.includes(v));
}
export function scopeWithin(value:TargetScope,ceiling:TargetScope):boolean {
  return (['group_ids','source_families','environments','service_ids'] as const)
    .every(key=>subset(value[key],ceiling[key]))&&
    (value.membership_mode==='explicit'||value.membership_mode==='all_current'&&ceiling.membership_mode==='all_current');
}
function numberWithin(value:number|null,ceiling:number|null,minimum:number):boolean {
  return ceiling===null?value===null:
    value!==null&&Number.isSafeInteger(value)&&value>=minimum&&value<=ceiling;
}
export function limitsWithin(value:NativeLimits,ceiling:NativeLimits):boolean {
  return numberWithin(value.maximum_acceptance_days,ceiling.maximum_acceptance_days,1)&&
    numberWithin(value.maximum_sla_duration_seconds,ceiling.maximum_sla_duration_seconds,0)&&
    numberWithin(value.maximum_deadline_extension_seconds,ceiling.maximum_deadline_extension_seconds,0)&&
    (ceiling.maximum_severity===null?value.maximum_severity===null:
      value.maximum_severity!==null&&severityChoices(ceiling.maximum_severity).includes(value.maximum_severity))&&
    (!value.whole_group_confirmation||ceiling.whole_group_confirmation)&&
    (!value.allow_sla_backfill||ceiling.allow_sla_backfill)&&
    (['allowed_environments','allowed_service_ids','allowed_sla_clock_bases','allowed_sla_severities','allowed_sla_start_sources'] as const)
      .every(key=>subset(value[key],ceiling[key]))&&
    Object.entries(value.allowed_identity_scalar_fields).every(([action,fields])=>
      subset(fields,ceiling.allowed_identity_scalar_fields[action]??[]));
}
function dutiesWithin(value:Duties,ceiling:Duties):boolean {
  return (!ceiling.approval_requires_distinct_actor||value.approval_requires_distinct_actor)&&
    (!ceiling.prohibit_requester_approval||value.prohibit_requester_approval)&&
    Number.isSafeInteger(value.required_approver_count)&&value.required_approver_count>=ceiling.required_approver_count&&
    ceiling.prohibited_action_pairs.every(pair=>value.prohibited_action_pairs.some(v=>JSON.stringify(v)===JSON.stringify(pair)));
}
export function permissionWithin(value:NativePermission,catalogue:AdminCatalogue):boolean {
  const envelope=catalogue.caller.grantable;
  const action=catalogue.selectable_actions.find(a=>a.action===value.action);
  return hasGrantable(envelope)&&!!action&&
    (envelope.actions.includes('*')||envelope.actions.includes(value.action))&&
    (isDeploymentSettingsAction(value.action)?
      deploymentScopesWithin(value.deployment_scopes,action.deployment_scopes)&&deploymentScopesWithin(value.deployment_scopes,envelope.deployment_scopes):
      value.deployment_scopes===undefined)&&
    scopeWithin(value.target_scope,action.target_scope)&&scopeWithin(value.target_scope,envelope.target_scope)&&
    limitsWithin(value.limits,action.limits)&&limitsWithin(value.limits,envelope.limits)&&
    dutiesWithin(value.separation_of_duties,envelope.separation_of_duties);
}
export function accessDraftErrors(catalogue:AdminCatalogue,scopes:string[],permissions:NativePermission[]):string[] {
  const envelope=catalogue.caller.grantable;
  if(!catalogue.caller.can_manage_access_groups||!hasGrantable(envelope))return ['The current access-management envelope is unavailable.'];
  const errors:string[]=[];
  const allowed=new Set(envelope.source_scopes.map(sourceScopeKey));
  if(!scopes.length||new Set(scopes).size!==scopes.length||scopes.some(key=>!allowed.has(key)))
    errors.push('Choose distinct exact source scopes from the current envelope.');
  if(new Set(permissions.map(p=>p.permission_id)).size!==permissions.length)
    errors.push('Each permission must have a distinct stable ID.');
  permissions.forEach(p=>{if(isDeploymentSettingsAction(p.action)&&(!deploymentScopesWithin(p.deployment_scopes,envelope.deployment_scopes)||!deploymentScopesWithin(p.deployment_scopes,catalogue.selectable_actions.find(a=>a.action===p.action)?.deployment_scopes)))errors.push(p.action+': choose at least one exact deployment from the current server ceiling.');if(!permissionWithin(p,catalogue))errors.push(p.action+': review its scope, limits and separation of duties against the current ceiling.');});
  return errors;
}
