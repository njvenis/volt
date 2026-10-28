import {sessionFetch, errorCode} from './session';
import {hasGrantable,scopeWithin,limitsWithin,isDeploymentSettingsAction,validDeploymentScopes,deploymentScopesWithin} from './native-admin-validation';
import type {ApprovalLimits, Duties, TargetScope} from './assessment-api';

export type AuthorityMode = 'legacy' | 'uvm_native_v1';
export type NativeLimits = ApprovalLimits & {allowed_sla_clock_bases:string[];allowed_sla_severities:string[];allowed_sla_start_sources:string[];maximum_sla_duration_seconds:number|null;maximum_deadline_extension_seconds:number|null;allow_sla_backfill:boolean;allowed_identity_scalar_fields:Record<string,string[]>};
export type Grantable = {actions:string[];target_scope:TargetScope;limits:NativeLimits;source_scopes:SourceScope[];separation_of_duties:Duties;deployment_scopes?:string[]};
export type Principal = {principal_id:string;display_name:string;enabled:boolean;actor_kind:string;membership_eligibility:{access_group:boolean;ownership_team:boolean;reason:string|null}};
export type AdminCatalogue = {schema_version:1;authority_mode:AuthorityMode;policy_revision:number;authority_revision:number;ownership_revision:number;selectable_actions:{action:string;target_scope:TargetScope;limits:NativeLimits;deployment_scopes?:string[]}[];caller:{principal_id:string;can_manage_access_groups:boolean;can_manage_ownership_teams:boolean;grantable:Grantable|Record<string,never>}};
export type OwnershipPrincipal = {principal_id:string;display_name:string;enabled:boolean;membership_eligibility:{ownership_team:boolean;reason:string|null}};
export type OwnershipPrincipals = {schema_version:1;team_id:string;policy_revision:number;ownership_revision:number;principals:OwnershipPrincipal[]};
export type NativeMembership = {principal_id:string;effective_from:string;effective_until:string|null;enabled:boolean;revision:number};
export type NativeHistory = {event_id:string;action:string;actor_id:string;occurred_at:string;rationale:string;before_value:unknown;after_value:unknown};
export type NativePermission = {permission_id:string;role_id:string;action:string;target_scope:TargetScope;limits:NativeLimits;separation_of_duties:Duties;deployment_scopes?:string[]};
export type SourceScope = {source_family:string;source_account_id:string;scope_key:string};
export type NativeTeam = {team_id:string;display_name:string;enabled:boolean;revision:number;memberships:NativeMembership[];history:NativeHistory[]};
export type NativeAccessGroup = Omit<NativeTeam,'team_id'> & {access_group_id:string;description:string;source_scopes:SourceScope[];permissions:NativePermission[]};
export type AccessGroups = {schema_version:1;authority_mode:AuthorityMode;policy_revision:number;authority_revision:number;principals:Principal[];items:NativeAccessGroup[]};
export type OwnershipTeams = {schema_version:1;policy_revision:number;ownership_revision:number;items:NativeTeam[]};
export type NativeIntent = {intent_id:string;kind:'administration.authority.reconcile'|'administration.ownership.reconcile';target_id:string;authority_revision:number;status:string};
export type NativeReceipt = {schema_version:1;command_id:string;action:string;target_id:string;policy_revision:number;decision_id:string;audit_event_id:string;intents:NativeIntent[];result?:unknown};
export class NativeAdminError extends Error {
  constructor(public status:number,public code:string,public uncertain=false){super(uncertain?'The save outcome is unknown. Retry the same request before starting another change.':status===409?'These records have changed. Refresh and review the current versions.':status===403?'Administration access is denied.':status===401?'Sign in again to continue.':status===422?'Check the required fields and the current grantable envelope.':'Administration information is unavailable. Refresh to try again.');}
}
const obj=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const text=(v:unknown):v is string=>typeof v==='string';
const id=(v:unknown):v is string=>text(v)&&v.trim().length>0;
const uuid=(v:unknown):v is string=>text(v)&&v.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const intentStatus=(v:unknown)=>text(v)&&['pending','running','failed','complete'].includes(v);
const integer=(v:unknown)=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const bool=(v:unknown)=>typeof v==='boolean';
const time=(v:unknown)=>text(v)&&v.endsWith('Z')&&Number.isFinite(Date.parse(v));
const strings=(v:unknown)=>Array.isArray(v)&&v.every(id)&&new Set(v).size===v.length;
const rows=(v:unknown,test:(r:Record<string,unknown>)=>boolean)=>Array.isArray(v)&&v.every(r=>obj(r)&&test(r));
const unique=(v:unknown,key:string)=>Array.isArray(v)&&new Set(v.map(r=>r[key])).size===v.length;
const mode=(v:unknown)=>v==='legacy'||v==='uvm_native_v1';
function scope(v:unknown):boolean{return obj(v)&&['group_ids','source_families','environments','service_ids'].every(k=>strings(v[k]))&&['explicit','all_current'].includes(String(v.membership_mode));}
function limits(v:unknown):boolean{return obj(v)&&(v.maximum_acceptance_days===null||integer(v.maximum_acceptance_days)&&Number(v.maximum_acceptance_days)>0)&&(v.maximum_severity===null||['critical','high','medium','low','informational'].includes(String(v.maximum_severity)))&&bool(v.whole_group_confirmation)&&['allowed_environments','allowed_service_ids','allowed_sla_clock_bases','allowed_sla_severities','allowed_sla_start_sources'].every(k=>strings(v[k]))&&['maximum_sla_duration_seconds','maximum_deadline_extension_seconds'].every(k=>v[k]===null||integer(v[k]))&&bool(v.allow_sla_backfill)&&obj(v.allowed_identity_scalar_fields)&&Object.entries(v.allowed_identity_scalar_fields).every(([k,fields])=>['identity.workload_field_correct','identity.incarnation_locator_correct'].includes(k)&&strings(fields)&&Array.isArray(fields)&&fields.every(f=>f!=='*'&&(k!=='identity.incarnation_locator_correct'||f==='host_locator')))&&Array.isArray(v.allowed_sla_clock_bases)&&v.allowed_sla_clock_bases.every(b=>['elapsed_utc_seconds','calendar_days_utc'].includes(b))&&Array.isArray(v.allowed_sla_severities)&&v.allowed_sla_severities.every(s=>['critical','high','medium','low','informational'].includes(s))&&Array.isArray(v.allowed_sla_start_sources)&&v.allowed_sla_start_sources.every(s=>['source_observation_v1','uvm_ingest_commit_v1'].includes(s));}
function source(v:Record<string,unknown>):boolean{return ['source_family','source_account_id','scope_key'].every(k=>id(v[k]));}
function grantable(v:unknown):boolean{return obj(v)&&(Object.keys(v).length===0||strings(v.actions)&&scope(v.target_scope)&&limits(v.limits)&&rows(v.source_scopes,source)&&duties(v.separation_of_duties)&&(v.deployment_scopes===undefined||validDeploymentScopes(v.deployment_scopes)));}
function duties(v:unknown):boolean{return obj(v)&&bool(v.approval_requires_distinct_actor)&&bool(v.prohibit_requester_approval)&&integer(v.required_approver_count)&&Number(v.required_approver_count)>0&&Array.isArray(v.prohibited_action_pairs)&&v.prohibited_action_pairs.every(p=>strings(p)&&p.length===2);}
function membership(v:Record<string,unknown>):boolean{return id(v.principal_id)&&time(v.effective_from)&&(v.effective_until===null||time(v.effective_until)&&Date.parse(String(v.effective_until))>Date.parse(String(v.effective_from)))&&bool(v.enabled)&&integer(v.revision);}
function history(v:Record<string,unknown>):boolean{return ['event_id','action','actor_id'].every(k=>id(v[k]))&&time(v.occurred_at)&&text(v.rationale)&&'before_value'in v&&'after_value'in v;}
function item(v:Record<string,unknown>):boolean{return id(v.display_name)&&bool(v.enabled)&&integer(v.revision)&&rows(v.memberships,membership)&&rows(v.history,history)&&unique(v.history,'event_id');}
function permission(v:Record<string,unknown>):boolean{return ['permission_id','role_id','action'].every(k=>id(v[k]))&&(isDeploymentSettingsAction(String(v.action))?validDeploymentScopes(v.deployment_scopes)&&v.deployment_scopes.length>0:v.deployment_scopes===undefined)&&scope(v.target_scope)&&limits(v.limits)&&duties(v.separation_of_duties);}
function base(v:unknown):v is Record<string,unknown>{return obj(v)&&v.schema_version===1&&integer(v.policy_revision);}
export async function adminRequest(path:string,signal?:AbortSignal,body?:unknown):Promise<unknown>{
  const write=body!==undefined;let response:Response;
  try{response=await sessionFetch('/api/v1/assessment/'+path,{method:write?'POST':'GET',headers:{Accept:'application/json',...(write?{'Content-Type':'application/json'}:{})},...(write?{body:JSON.stringify(body)}:{}),signal:signal?AbortSignal.any([signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000)});}
  catch(error){if(signal?.aborted)throw error;throw new NativeAdminError(0,'unavailable',write);}
  const data:unknown=await response.json().catch(()=>{throw new NativeAdminError(response.status,'unsupported_response',write);});
  if(!response.ok)throw new NativeAdminError(response.status,errorCode(data),write&&response.status>=500);
  return data;
}
export async function getAdminCatalogue(principalId:string,signal?:AbortSignal):Promise<AdminCatalogue>{
  const v=await adminRequest('administration/catalogue',signal);
  if(!base(v)||!mode(v.authority_mode)||!integer(v.authority_revision)||!integer(v.ownership_revision)||!obj(v.caller)||v.caller.principal_id!==principalId||!bool(v.caller.can_manage_access_groups)||!bool(v.caller.can_manage_ownership_teams)||!grantable(v.caller.grantable)||!rows(v.selectable_actions,a=>id(a.action)&&scope(a.target_scope)&&limits(a.limits)&&(isDeploymentSettingsAction(String(a.action))?validDeploymentScopes(a.deployment_scopes):a.deployment_scopes===undefined))||!unique(v.selectable_actions,'action'))throw new NativeAdminError(502,'unsupported_response');
  const catalogue=v as AdminCatalogue;
  const envelope=catalogue.caller.grantable;
  if(!hasGrantable(envelope)){
    if(catalogue.caller.can_manage_access_groups||catalogue.selectable_actions.length)throw new NativeAdminError(502,'unsupported_response');
  }else if(catalogue.selectable_actions.some(action=>
    !(envelope.actions.includes('*')||envelope.actions.includes(action.action))||
    !scopeWithin(action.target_scope,envelope.target_scope)||!limitsWithin(action.limits,envelope.limits)||
    isDeploymentSettingsAction(action.action)&&!deploymentScopesWithin(action.deployment_scopes,envelope.deployment_scopes??[],true)))throw new NativeAdminError(502,'unsupported_response');
  return catalogue;
}
export async function getAccessGroups(catalogue:AdminCatalogue,signal?:AbortSignal):Promise<AccessGroups>{
  const v=await adminRequest('access-groups',signal);
  if(!base(v)||v.authority_mode!==catalogue.authority_mode||!integer(v.authority_revision)||!rows(v.principals,p=>id(p.principal_id)&&id(p.display_name)&&bool(p.enabled)&&id(p.actor_kind)&&obj(p.membership_eligibility)&&p.membership_eligibility.access_group===p.enabled&&p.membership_eligibility.ownership_team===p.enabled&&p.membership_eligibility.reason===(p.enabled?null:'principal_disabled'))||!unique(v.principals,'principal_id')||!rows(v.items,r=>item(r)&&id(r.access_group_id)&&text(r.description)&&rows(r.source_scopes,s=>['source_family','source_account_id','scope_key'].every(k=>id(s[k])))&&rows(r.permissions,permission)&&unique(r.permissions,'permission_id'))||!unique(v.items,'access_group_id'))throw new NativeAdminError(502,'unsupported_response');
  if(v.policy_revision!==catalogue.policy_revision||v.authority_revision!==catalogue.authority_revision)throw new NativeAdminError(409,'stale_read');
  return v as AccessGroups;
}
export async function getOwnershipTeams(catalogue:AdminCatalogue,signal?:AbortSignal):Promise<OwnershipTeams>{
  const v=await adminRequest('ownership-teams',signal);
  if(!base(v)||!integer(v.ownership_revision)||!rows(v.items,r=>item(r)&&id(r.team_id))||!unique(v.items,'team_id'))throw new NativeAdminError(502,'unsupported_response');
  if(v.policy_revision!==catalogue.policy_revision||v.ownership_revision!==catalogue.ownership_revision)throw new NativeAdminError(409,'stale_read');
  return v as OwnershipTeams;
}

export async function getOwnershipPrincipals(teamId:string,catalogue:AdminCatalogue,signal?:AbortSignal):Promise<OwnershipPrincipals>{
  const v=await adminRequest('ownership-teams/'+encodeURIComponent(teamId)+'/principals',signal);
  if(!base(v)||v.team_id!==teamId||!integer(v.ownership_revision)||
    !rows(v.principals,p=>id(p.principal_id)&&id(p.display_name)&&bool(p.enabled)&&
      obj(p.membership_eligibility)&&p.membership_eligibility.ownership_team===p.enabled&&
      p.membership_eligibility.reason===(p.enabled?null:'principal_disabled'))||!unique(v.principals,'principal_id'))
    throw new NativeAdminError(502,'unsupported_response');
  if(v.policy_revision!==catalogue.policy_revision||v.ownership_revision!==catalogue.ownership_revision)
    throw new NativeAdminError(409,'stale_read');
  return v as OwnershipPrincipals;
}

export type NativeCommand = {command_id:string;action:string;target_id:string;membership_ids:string[];expected_revisions:Record<string,number>;payload:Record<string,unknown>};
export type DeletionImpact = {schema_version:1;access_group_id:string;group_revision:number;policy_revision:number;authority_revision:number;enabled:boolean;active_memberships:Omit<NativeMembership,'enabled'|'revision'>[];permission_count:number;affected_principals:string[];remaining_access_groups_by_principal:Record<string,string[]>;withdrawn_actions:string[];expected_intent:{kind:string;status:string}};
export type IntentRead = NativeIntent & {schema_version:1;attempts:number;last_error:string|null;created_at:string;updated_at:string};
export function nativeCommand(c:AdminCatalogue,action:string,payload:Record<string,unknown>,item?:NativeTeam|NativeAccessGroup):NativeCommand{return {command_id:crypto.randomUUID(),action,target_id:'00000000-0000-4000-8000-000000000000',membership_ids:[],expected_revisions:{target:c.policy_revision,identity_membership:0,policy:c.policy_revision,owners:0,authority:c.authority_revision,ownership:c.ownership_revision,...(item?('team_id'in item?{team:item.revision}:{access_group:item.revision}):{})},payload};}
export async function saveNativeCommand(command:NativeCommand):Promise<NativeReceipt>{
 const v=await adminRequest('commands',undefined,command);
 // Policy commands address the reserved target; reconciliation addresses the changed object.
 // The public writer returns a flat receipt; an unused result extension is not proof of commit.
 const team=['ownership.team.create','ownership.team.update','ownership.team.membership.set'].includes(command.action);
 const access=['access_group.create','access_group.update','access_group.membership.set'].includes(command.action);
 const activation=command.action==='native.authority.activate';
 const target=team?command.payload.team_id:access?command.payload.access_group_id:activation?command.target_id:undefined;
 const kind=team?'administration.ownership.reconcile':'administration.authority.reconcile';
 if(!uuid(target)||!uuid(command.command_id)||!uuid(command.target_id)||!base(v)||
   v.command_id!==command.command_id||v.action!==command.action||v.target_id!==command.target_id||
   !uuid(v.decision_id)||!uuid(v.audit_event_id)||
   !rows(v.intents,i=>uuid(i.intent_id)&&i.kind===kind&&i.target_id===target&&integer(i.authority_revision)&&intentStatus(i.status))||
   !Array.isArray(v.intents)||v.intents.length!==1||
   ('intent_id'in v&&v.intent_id!==v.intents[0].intent_id)||
   ('committed_revision'in v&&v.committed_revision!==v.policy_revision))
   throw new NativeAdminError(502,'unsupported_receipt',true);
 return v as NativeReceipt;
}
export async function getDeletionImpact(group:NativeAccessGroup,c:AdminCatalogue,signal?:AbortSignal):Promise<DeletionImpact>{
 const v=await adminRequest('access-groups/'+encodeURIComponent(group.access_group_id)+'/deletion-impact',signal);
 if(!base(v)||v.access_group_id!==group.access_group_id||!integer(v.group_revision)||!integer(v.authority_revision)||!bool(v.enabled)||!integer(v.permission_count)||!strings(v.affected_principals)||!strings(v.withdrawn_actions)||!obj(v.remaining_access_groups_by_principal)||!Object.values(v.remaining_access_groups_by_principal).every(strings)||!rows(v.active_memberships,m=>id(m.principal_id)&&time(m.effective_from)&&(m.effective_until===null||time(m.effective_until)))||!obj(v.expected_intent)||v.expected_intent.kind!=='administration.authority.reconcile'||v.expected_intent.status!=='pending')throw new NativeAdminError(502,'unsupported_response');
 if(!(v.affected_principals as string[]).every(id=>group.memberships.some(m=>m.principal_id===id))||!Object.keys(v.remaining_access_groups_by_principal as object).every(id=>(v.affected_principals as string[]).includes(id))||!(v.active_memberships as DeletionImpact['active_memberships']).every(m=>group.memberships.some(retained=>retained.principal_id===m.principal_id&&retained.effective_from===m.effective_from&&retained.effective_until===m.effective_until)))throw new NativeAdminError(502,'unsupported_response');
 if(v.policy_revision!==c.policy_revision||v.authority_revision!==c.authority_revision||v.group_revision!==group.revision)throw new NativeAdminError(409,'stale_preview');
 return v as DeletionImpact;
}
export async function getNativeIntent(expected:NativeIntent,signal?:AbortSignal):Promise<IntentRead>{
 const v=await adminRequest('administration/intents/'+encodeURIComponent(expected.intent_id),signal);
 if(!obj(v)||v.schema_version!==1||!uuid(v.intent_id)||v.intent_id!==expected.intent_id||v.kind!==expected.kind||!uuid(v.target_id)||v.target_id!==expected.target_id||v.authority_revision!==expected.authority_revision||!intentStatus(v.status)||!integer(v.attempts)||(v.last_error!==null&&v.last_error!=='reconciliation_failed')||!time(v.created_at)||!time(v.updated_at))throw new NativeAdminError(502,'unsupported_response');
 return v as IntentRead;
}
