import {sessionFetch, errorCode} from './session';
import type { JsonValue } from './api';
import { validG4View, type G4View, type ExposureGuard } from './github-model';

export type Revisions={target:number;identity_membership:number;policy:number;owners:number};
export type Command={command_id:string;action:string;target_id:string;membership_ids:string[];expected_revisions:Revisions;expected_exposures?:ExposureGuard[];expected_evaluations?:EvaluationGuard[];payload:Record<string,JsonValue>};
export type Receipt={schema_version:1;command_id:string;decision_id:string;audit_event_id:string;intent_id:string|null;committed_revision:number;projection:string};
export type Owner={owner_id:string;owner_type:string;display_name:string};
export type Portion={portion_id:string;revision:number;owner_ids:string[];membership_ids:string[];completed_membership_ids:string[];outstanding_membership_ids:string[];active:boolean;created_at:string;updated_at?:string};
export type Reconciliation={resolution_id:string;predecessor_occurrence_id:string;successor_occurrence_id:string|null;observation_id:string|null;resolution_status:string|null;resolution_outcome:string|null;proof_reference:string|null;permitted:boolean;reason:string|null;workload_id:string|null;component_locator:string|null;accepted:boolean;actor_id:string;at:string;rationale:string};
export type CoverageInvalidation={resolution_id:string;predecessor_occurrence_id:string;successor_occurrence_id:string;reason:'identity_correspondence_changed'};
export type EvaluationGuard={episode_id:string;occurrence_id:string;evaluation_id:string;revision:number};
export type ExceptionPause={occurrence_id:string;episode_id:string;event_id:string;approved_at:string;expires_at:string;remaining_seconds:number|null;previously_breached:boolean;original_deadline_at:string|null;pre_pause_deadline_at:string|null};
export type ExceptionClock={occurrence_id:string;state:string;target_at:string|null;remaining_seconds:number|null;frozen_sla_seconds:number|null;prior_breach:boolean;currently_breached:boolean;event_id:string|null};
export type ExceptionWarning={intent_id:string;decision_id:string;expiry_revision:number;offset_seconds:number;channel:'slack'|'email';destination_ref:string;status:'pending'|'sending'|'sent'|'failed'|'uncertain'|'missed'|'suppressed';suppression_reason:string|null;next_attempt_at:string|null;route_revision?:number|null;provider_receipt_basis?:'slack_api_accepted'|'smtp_accepted'|null;due_at?:string;retry:{attempts:number;max_attempts:number;base_delay_seconds:number};acknowledged_at:string|null;acknowledged_by:string|null;attempts:{attempt_number:number;attempted_at:string;finished_at:string|null;outcome:'sending'|'sent'|'failed'|'uncertain';receipt:string|null;error:string|null}[]};
export type WarningFailureAlert={alert_id:string;intent_id:string;attempt_id:string;channel:'slack'|'email';status:ExceptionWarning['status'];reason:string;created_at:string};
export type WarningAcknowledgement={schema_version:1;intent_id:string;acknowledged_at:string;acknowledged_by:string;effect:'receipt_only'};
export async function getExceptionWarnings(id:string,token:string,signal?:AbortSignal):Promise<ExceptionWarning[]>{
  const data=await request('groups/'+encodeURIComponent(id)+'/exception-warnings',token,undefined,signal);
  // The published v1 empty response omits group_id when there are no decisions.
  if(!obj(data)||data.schema_version!==1||!Array.isArray(data.items)||!rows(data.items,w=>
    fields(w,['intent_id','decision_id'],uuid)&&fields(w,['expiry_revision','offset_seconds'],num)&&Number(w.expiry_revision)>0&&Number.isSafeInteger(Number(w.offset_seconds)*1000)&&Number(w.offset_seconds)*1000<=8640000000000000&&
    str(w.channel)&&['slack','email'].includes(w.channel)&&str(w.destination_ref)&&!!w.destination_ref.trim()&&
    str(w.status)&&['pending','sending','sent','failed','uncertain','missed','suppressed'].includes(w.status)&&
    fields(w,['suppression_reason','acknowledged_by'],nullableString)&&fields(w,['next_attempt_at','acknowledged_at'],nullableTime)&&
    (w.acknowledged_at===null)===(w.acknowledged_by===null)&&obj(w.retry)&&fields(w.retry,['attempts','max_attempts','base_delay_seconds'],num)&&
    Array.isArray(w.attempts)&&rows(w.attempts,a=>num(a.attempt_number)&&Number(a.attempt_number)>0&&time(a.attempted_at)&&nullableTime(a.finished_at)&&
      str(a.outcome)&&['sending','sent','failed','uncertain'].includes(a.outcome)&&fields(a,['receipt','error'],nullableString))&&w.retry.attempts===w.attempts.length&&
    new Set(w.attempts.map(a=>a.attempt_number)).size===w.attempts.length&&validWarningProvider(w))||
    !(data.group_id===id||data.group_id===undefined&&data.items.length===0))throw new AssessmentError(502,'unsupported_response');
  if(new Set(data.items.map(w=>w.intent_id.toLowerCase())).size!==data.items.length)throw new AssessmentError(502,'unsupported_response');
  return data.items as ExceptionWarning[];
}
function validWarningProvider(w:Record<string,unknown>):boolean {
  // The original v1 read had none of these fields. Preserve historical reads,
  // but never silently downgrade a partial or malformed protocol-era response.
  if(!['route_revision','provider_receipt_basis','due_at'].some(key=>key in w))return true;
  return (w.route_revision===null||num(w.route_revision)&&Number(w.route_revision)>0)&&time(w.due_at)&&
    (w.provider_receipt_basis===null||
      w.status==='sent'&&num(w.route_revision)&&Number(w.route_revision)>0&&
      (w.channel==='slack'&&w.provider_receipt_basis==='slack_api_accepted'||w.channel==='email'&&w.provider_receipt_basis==='smtp_accepted'));
}
export async function getWarningFailureAlerts(id:string,token:string,signal?:AbortSignal):Promise<WarningFailureAlert[]> {
  const data=await request('groups/'+encodeURIComponent(id)+'/exception-warning-failure-alerts',token,undefined,signal);
  if(!obj(data)||data.schema_version!==1||data.group_id!==id||!rows(data.items,a=>
    fields(a,['alert_id','intent_id','attempt_id'],uuid)&&str(a.channel)&&['slack','email'].includes(a.channel)&&
    str(a.status)&&['pending','sending','sent','failed','uncertain','missed','suppressed'].includes(a.status)&&
    str(a.reason)&&!!a.reason.trim()&&time(a.created_at)))throw new AssessmentError(502,'unsupported_response');
  const items=data.items as WarningFailureAlert[];
  if(new Set(items.map(a=>a.alert_id.toLowerCase())).size!==items.length)throw new AssessmentError(502,'unsupported_response');
  return items;
}
export async function acknowledgeWarning(groupId:string,intentId:string,token:string):Promise<WarningAcknowledgement> {
  const data=await request('groups/'+encodeURIComponent(groupId)+'/exception-warnings/'+encodeURIComponent(intentId)+'/acknowledge',token,{});
  if(!obj(data)||data.schema_version!==1||data.intent_id!==intentId||data.effect!=='receipt_only'||
    !time(data.acknowledged_at)||!str(data.acknowledged_by)||!data.acknowledged_by.trim())throw new AssessmentError(502,'outcome_unknown',true);
  return data as WarningAcknowledgement;
}
export type Acceptance={exception_contract_version?:1;request_revision?:number;requester_id?:string;submitted_at?:string;approved_at?:string;proposed_expires_at?:string;compensating_controls?:string;context?:{group_id:string;membership_ids:string[];submitted_context:Record<string,JsonValue>};sla_clock?:ExceptionClock[];pause_snapshots?:ExceptionPause[];approvals?:{actor_id:string;at:string;rationale:string;expiry?:string;request_revision?:number}[];acceptance_id:string;state:'pending'|'active'|'suspended'|'rejected'|'expired'|'revoked';membership_ids:string[];accountable_owner_id:string;rationale:string;expires_at:string;continuity_allowed:boolean;predecessor_id:string|null;history:JsonValue[];successor_coverage:Reconciliation[];effective_membership_ids:string[];reconciliation_history:Reconciliation[];coverage_invalidations:CoverageInvalidation[]};
export type RoutingOverride={override_id:string;owner_ids:string[];rationale:string;evidence_ref:string;expires_at:string|null;actor_id:string;created_at:string;status:'active'|'expired'};
export type DeadlineReference={schema_version:1;reference_id:string;occurrence_id:string;deadline_at:string|null;policy_ref:string|null;evidence_ref:string;evidence_sha256:string;supersedes_reference_id:string|null;rationale:string};
export type OccurrenceClock={occurrence_id:string;first_observed_at:string|null;deadline_at:string|null;deadline_status:string;policy_ref:string|null;deadline_reference_revision:number;deadline_reference:DeadlineReference|null};
export type RoutingEvidence={rule_id:string;match:{source_family:string};matched:boolean;owner_ids:string[];outcome:'matched'|'unmatched'|'conflicting'|'owner_unavailable'};
export type GroupView=G4View&{schema_version:1;group:{group_id:string;source_family:string;native_id_scheme:string;native_id_authority:string;native_id_value:string;identity_revision:number};assessment:{revision:number;policy_revision:number;owner_revision:number;native_severity:{value:string;source:string;observed_at:string|null}|null;assessed_severity:{value:string;rationale:string;actor_id:string;updated_at:string}|null;owners:Owner[];portions:Portion[];routing:{status:string;owner_ids:string[];override:RoutingOverride|null;evaluated_policy_revision:number;evidence:RoutingEvidence[]};acceptances:Acceptance[];membership:{revision:number;actionable_ids:string[];outstanding_ids:string[];completed_ids:string[];reconciliation_pending_ids:string[]};clocks:OccurrenceClock[];latest_receipt:Receipt|null;pending_projection_intents:JsonValue[]};audit:{next_cursor:string|null}};
export type BulkResult={command_id:string;target_id:string;status:'committed'|'denied'|'conflict'|'invalid'|'unavailable';code:string;receipt:Receipt|null;error:{code:string;message:string;details:Record<string,JsonValue>}|null};
export type BulkResponse={schema_version:1;results:BulkResult[]};
export type TargetScope={group_ids:string[];source_families:string[];environments:string[];service_ids:string[];membership_mode:'explicit'|'all_current'};
export type ApprovalLimits={maximum_acceptance_days:number|null;maximum_severity:string|null;whole_group_confirmation:boolean;allowed_environments:string[];allowed_service_ids:string[]};
export type Duties={approval_requires_distinct_actor:boolean;prohibit_requester_approval:boolean;required_approver_count:number;prohibited_action_pairs:string[][]};
export type PolicyGrant={grant_id:string;role_id:string;principal_id:string;actions:string[];target_scope:TargetScope;limits:ApprovalLimits;separation_of_duties:Duties;effective_from?:string|null;effective_until?:string|null};
export type DelegationEnvelope={actions:string[];target_scope:TargetScope;limits:ApprovalLimits;separation_of_duties:Duties};
export type Permissions={schema_version:1;group_id:string;policy_revision:number;effective_actions:string[];grants:PolicyGrant[];denies:{deny_id:string;principal_id:string;actions:string[];target_ids:string[]}[];delegation_envelope:DelegationEnvelope;owner_directory:(Owner&{enabled:boolean})[]};
export type AuditEvent={event_id:string;actor_id:string;actor_kind:string;origin:string;action:string;target_id:string;before_value:JsonValue;after_value:JsonValue;membership_ids:string[];membership_revision:number;rationale:string;evidence_ref:string;policy_revision:number;identity_revision:number;occurred_at:string;received_at:string;correlation_id:string;command_id:string};
export type AuditPage={schema_version:1;group_id:string;items:AuditEvent[];next_cursor:string|null};
export class AssessmentError extends Error {
  constructor(public status:number,public code:string,public uncertain=false){super(errorText(status,code));}
}
function errorText(status:number,code:string){
  if(code==='outcome_unknown')return 'VOLT could not confirm whether your change was saved. Check or retry this same save to avoid creating a duplicate.';
  if(code==='sla_clock_gap')return 'Current SLA versions are unavailable for one or more selected instances. An administrator must check their SLA coverage before this exception can proceed.';
  if(status===409)return 'The affected instances or access rules have changed. Refresh, review the updated details and confirm them before saving again.';
  if(status===403)return 'You do not have access to make this change. Ask an administrator to check your permissions.';
  if(status===401)return 'Sign in again to continue.';
  if(status===422)return 'The change could not be saved. Check the selected instances and required fields.';
  if(status===404)return 'This finding could not be found within your access.';
  if(code==='unsupported_response')return 'Some finding details are missing or unsupported. Refresh or contact your administrator if this continues.';
  return 'VOLT could not save or load this information. Please try again.';
}
async function request(path:string,token:string,body?:unknown,signal?:AbortSignal):Promise<unknown>{
  const write=body!==undefined;
  let response:Response;
  try{response=await sessionFetch('/api/v1/assessment/'+path,{method:write?'POST':'GET',headers:{...(write?{'Content-Type':'application/json'}:{})},...(write?{body:JSON.stringify(body)}:{}),cache:'no-store',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000)});}
  catch(error){if(signal?.aborted)throw error;throw new AssessmentError(0,write?'outcome_unknown':'unavailable',write);}
  let data:unknown;
  try{data=await response.json();}catch{throw new AssessmentError(response.status,write?'outcome_unknown':'unsupported_response',write);}
  if(!response.ok){const code=errorCode(data);throw new AssessmentError(response.status,code,write&&code==='outcome_unknown');}
  return data;
}
export async function getGroup(id:string,token:string,signal?:AbortSignal):Promise<GroupView>{
  const data=await request('groups/'+encodeURIComponent(id),token,undefined,signal);
  if(!validGroup(data)||data.group.group_id!==id)throw new AssessmentError(502,'unsupported_response');
  return data;
}
export async function getPermissions(id:string,token:string,signal?:AbortSignal):Promise<Permissions>{
  const data=await request('permissions?group_id='+encodeURIComponent(id),token,undefined,signal);
  if(!obj(data)||data.schema_version!==1||data.group_id!==id||!num(data.policy_revision)||!strings(data.effective_actions)||!rows(data.owner_directory,o=>fields(o,['owner_id','display_name'],str)&&['person','team'].includes(String(o.owner_type))&&typeof o.enabled==='boolean')||!rows(data.grants,g=>fields(g,['grant_id','role_id','principal_id'],str)&&validPolicy(g))||!rows(data.denies,d=>fields(d,['deny_id','principal_id'],str)&&fields(d,['actions','target_ids'],strings))||!validPolicy(data.delegation_envelope))throw new AssessmentError(502,'unsupported_response');
  return data as Permissions;
}
export async function getAudit(id:string,token:string,cursor:string|null,signal?:AbortSignal):Promise<AuditPage>{
  const data=await request('audit?group_id='+encodeURIComponent(id)+(cursor?'&cursor='+encodeURIComponent(cursor):''),token,undefined,signal);
  if(!obj(data)||data.schema_version!==1||data.group_id!==id||!nullableString(data.next_cursor)||!rows(data.items,e=>fields(e,['event_id','actor_id','actor_kind','origin','action','target_id','rationale','evidence_ref','correlation_id','command_id'],str)&&fields(e,['membership_revision','policy_revision','identity_revision'],num)&&fields(e,['occurred_at','received_at'],time)&&strings(e.membership_ids)&&'before_value' in e&&'after_value' in e))throw new AssessmentError(502,'unsupported_response');
  return data as AuditPage;
}
export async function sendCommand(command:Command,token:string):Promise<Receipt>{
  const data=await request('commands',token,command);
  if(!validCommandReceipt(data,command))throw new AssessmentError(502,'outcome_unknown',true);
  return data;
}
export async function sendBulk(commands:Command[],token:string):Promise<BulkResponse>{
  const data=await request('commands/bulk',token,{commands});
  if(!obj(data)||data.schema_version!==1||!Array.isArray(data.results)||data.results.length!==commands.length||!data.results.every((row,i)=>validBulkResult(row,commands[i])))throw new AssessmentError(502,'outcome_unknown',true);
  return data as BulkResponse;
}
export function revisions(view:GroupView):Revisions{return {target:view.assessment.revision,identity_membership:view.assessment.membership.revision,policy:view.assessment.policy_revision,owners:view.assessment.owner_revision};}
export function exposureGuards(view:GroupView,membership:string[]):ExposureGuard[]{
  if(membership.some(id=>!view.episodes.some(e=>e.members.some(m=>m.membership_id===id))))throw new AssessmentError(502,'unsupported_response');
  return view.episodes.filter(e=>e.members.some(m=>membership.includes(m.membership_id))).map(({exposure_id,episode_id,state_revision})=>({exposure_id,episode_id,state_revision}));
}
export function newCommand(view:GroupView,action:string,membership:string[],payload:Record<string,JsonValue>):Command{return {command_id:crypto.randomUUID(),action,target_id:view.group.group_id,membership_ids:[...membership],expected_revisions:revisions(view),...(action.startsWith('remediation.')?{expected_exposures:exposureGuards(view,membership)}:{}),payload};}
export function newPolicyCommand(policyRevision:number,action:string,payload:Record<string,JsonValue>):Command{return {command_id:crypto.randomUUID(),action,target_id:'00000000-0000-4000-8000-000000000000',membership_ids:[],expected_revisions:{target:policyRevision,identity_membership:0,policy:policyRevision,owners:0},payload};}

const obj=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const str=(v:unknown):v is string=>typeof v==='string';
const num=(v:unknown)=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const strings=(v:unknown):v is string[]=>Array.isArray(v)&&v.every(str);
const nullableString=(v:unknown)=>v===null||str(v);
const time=(v:unknown)=>str(v)&&v.endsWith('Z')&&Number.isFinite(Date.parse(v));
const sourceTime=(v:unknown)=>v===null||str(v)&&/(Z|[+-]\d{2}:\d{2})$/.test(v)&&Number.isFinite(Date.parse(v));
const nullableTime=(v:unknown)=>v===null||time(v);
// Acceptance and routing expiry are supplied RFC 3339 UTC instants; zero offset is UTC.
const utcExpiry=(v:unknown)=>time(v)||(str(v)&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+00:00$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19));
const fields=(v:Record<string,unknown>,keys:string[],test:(x:unknown)=>boolean)=>keys.every(k=>test(v[k]));
const rows=(v:unknown,test:(x:Record<string,unknown>)=>boolean)=>Array.isArray(v)&&v.every(x=>obj(x)&&test(x));
function validPolicy(v:unknown):boolean{return obj(v)&&strings(v.actions)&&obj(v.target_scope)&&fields(v.target_scope,['group_ids','source_families','environments','service_ids'],strings)&&['explicit','all_current'].includes(String(v.target_scope.membership_mode))&&obj(v.limits)&&(v.limits.maximum_acceptance_days===null||num(v.limits.maximum_acceptance_days))&&nullableString(v.limits.maximum_severity)&&typeof v.limits.whole_group_confirmation==='boolean'&&fields(v.limits,['allowed_environments','allowed_service_ids'],strings)&&obj(v.separation_of_duties)&&fields(v.separation_of_duties,['approval_requires_distinct_actor','prohibit_requester_approval'],x=>typeof x==='boolean')&&num(v.separation_of_duties.required_approver_count)&&Array.isArray(v.separation_of_duties.prohibited_action_pairs)&&v.separation_of_duties.prohibited_action_pairs.every(pair=>strings(pair)&&pair.length===2);}
const uuid=(v:unknown):v is string=>str(v)&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const globalActions=['policy.role.create','policy.role.assign','policy.role.update','principal.update'];
function validReceipt(v:unknown):v is Receipt{return obj(v)&&v.schema_version===1&&fields(v,['command_id','decision_id','audit_event_id'],uuid)&&num(v.committed_revision)&&Number(v.committed_revision)>0&&((v.projection==='pending'&&uuid(v.intent_id))||(v.projection==='none'&&v.intent_id===null));}
function validCommandReceipt(v:unknown,c:Command):v is Receipt{
  if(!validReceipt(v)||v.command_id!==c.command_id)return false;
  const r=c.expected_revisions;
  // These four existing global pairings remain subject to the human policy decision.
  if(globalActions.includes(c.action))return c.target_id==='00000000-0000-4000-8000-000000000000'&&c.membership_ids.length===0&&r.target===r.policy&&r.identity_membership===0&&r.owners===0&&v.projection==='none'&&v.intent_id===null&&v.committed_revision===r.policy+1;
  return c.target_id!=='00000000-0000-4000-8000-000000000000'&&v.projection==='pending'&&uuid(v.intent_id)&&v.committed_revision===r.target+1;
}
function validBulkResult(v:unknown,c:Command):boolean{
  if(!obj(v)||v.command_id!==c.command_id||v.target_id!==c.target_id||!str(v.code)||!str(v.status)||!['committed','denied','conflict','invalid','unavailable'].includes(v.status))return false;
  if(v.status==='committed')return v.code==='decision_committed'&&v.error===null&&validCommandReceipt(v.receipt,c);
  if(v.receipt!==null||!obj(v.error)||v.error.code!==v.code||!str(v.error.message)||!obj(v.error.details))return false;
  const statusByCode:Record<string,string>={authentication_required:'denied',forbidden:'denied',invalid_command:'invalid',command_id_reused:'conflict',revision_conflict:'conflict',persistence_unavailable:'unavailable',outcome_unknown:'unavailable'};
  return Object.hasOwn(statusByCode,v.code)&&statusByCode[v.code]===v.status;
}
export function validGroup(v:unknown):v is GroupView{
  if(!obj(v)||!validG4View(v)||v.schema_version!==1||!obj(v.group)||!fields(v.group,['group_id','source_family','native_id_scheme','native_id_authority','native_id_value'],str)||!num(v.group.identity_revision)||!obj(v.assessment)||!obj(v.audit)||!nullableString(v.audit.next_cursor))return false;
  const a=v.assessment;
  return fields(a,['revision','policy_revision','owner_revision'],num)
    &&(a.native_severity===null||(obj(a.native_severity)&&fields(a.native_severity,['value','source'],str)&&sourceTime(a.native_severity.observed_at)))
    &&(a.assessed_severity===null||(obj(a.assessed_severity)&&fields(a.assessed_severity,['value','rationale','actor_id'],str)&&time(a.assessed_severity.updated_at)))
    &&rows(a.owners,o=>fields(o,['owner_id','owner_type','display_name'],str))
    &&rows(a.portions,p=>str(p.portion_id)&&num(p.revision)&&fields(p,['owner_ids','membership_ids','completed_membership_ids','outstanding_membership_ids'],strings)&&typeof p.active==='boolean'&&time(p.created_at)&&(!('updated_at' in p)||time(p.updated_at)))
    &&obj(a.routing)&&['assigned','unresolved'].includes(String(a.routing.status))&&strings(a.routing.owner_ids)&&num(a.routing.evaluated_policy_revision)&&Array.isArray(a.routing.evidence)&&rows(a.routing.evidence,validRoutingEvidence)&&new Set(a.routing.evidence.map(r=>r.rule_id)).size===a.routing.evidence.length&&(a.routing.override===null||validRoutingOverride(a.routing.override))
    &&rows(a.acceptances,x=>validException(x)&&fields(x,['acceptance_id','state','accountable_owner_id','rationale'],str)&&['pending','active','suspended','rejected','expired','revoked'].includes(String(x.state))&&strings(x.membership_ids)&&utcExpiry(x.expires_at)&&typeof x.continuity_allowed==='boolean'&&nullableString(x.predecessor_id)&&Array.isArray(x.history)&&strings(x.effective_membership_ids)&&rows(x.successor_coverage,r=>validReconciliation(r)&&r.accepted===true&&r.permitted===true)&&rows(x.reconciliation_history,validReconciliation)&&rows(x.coverage_invalidations,r=>fields(r,['resolution_id','predecessor_occurrence_id','successor_occurrence_id'],uuid)&&r.reason==='identity_correspondence_changed'))
    &&obj(a.membership)&&num(a.membership.revision)&&fields(a.membership,['actionable_ids','outstanding_ids','completed_ids','reconciliation_pending_ids'],strings)
    &&rows(a.clocks,validClock)
    &&(a.latest_receipt===null||validReceipt(a.latest_receipt)&&a.latest_receipt.projection==='pending')&&Array.isArray(a.pending_projection_intents);
}

function validRoutingOverride(v:unknown):v is RoutingOverride{return obj(v)&&fields(v,['override_id','rationale','evidence_ref','actor_id'],str)&&strings(v.owner_ids)&&(v.expires_at===null||utcExpiry(v.expires_at))&&time(v.created_at)&&['active','expired'].includes(String(v.status));}

function validReconciliation(v:Record<string,unknown>):boolean{return fields(v,['resolution_id','predecessor_occurrence_id','actor_id','rationale'],str)&&fields(v,['successor_occurrence_id','observation_id','resolution_status','resolution_outcome','proof_reference','reason','workload_id','component_locator'],nullableString)&&typeof v.permitted==='boolean'&&typeof v.accepted==='boolean'&&time(v.at);}

function validRoutingEvidence(v:Record<string,unknown>):boolean{return str(v.rule_id)&&v.rule_id.length>0&&obj(v.match)&&str(v.match.source_family)&&v.match.source_family.length>0&&typeof v.matched==='boolean'&&strings(v.owner_ids)&&v.owner_ids.length>0&&v.owner_ids.every(id=>id.length>0)&&new Set(v.owner_ids).size===v.owner_ids.length&&['matched','unmatched','conflicting','owner_unavailable'].includes(String(v.outcome))&&(v.outcome==='unmatched'?!v.matched:v.matched);}
function validClock(c:Record<string,unknown>):boolean{
  const policy=(v:unknown)=>v===null||str(v)&&v.length>0;
  if(!uuid(c.occurrence_id)||!nullableTime(c.first_observed_at)||!nullableTime(c.deadline_at)||!policy(c.policy_ref)||!num(c.deadline_reference_revision))return false;
  if(c.deadline_reference===null)return c.deadline_reference_revision===0&&c.deadline_at===null&&c.policy_ref===null&&['unknown','not_applicable'].includes(String(c.deadline_status));
  const r=c.deadline_reference;
  return Number(c.deadline_reference_revision)>0&&obj(r)&&r.schema_version===1&&fields(r,['reference_id','occurrence_id'],uuid)&&r.occurrence_id===c.occurrence_id&&nullableTime(r.deadline_at)&&policy(r.policy_ref)&&r.deadline_at===c.deadline_at&&r.policy_ref===c.policy_ref&&c.deadline_status===(r.deadline_at===null?'unknown':'known')&&str(r.evidence_ref)&&r.evidence_ref.length>0&&str(r.evidence_sha256)&&/^[0-9a-f]{64}$/i.test(r.evidence_sha256)&&(Number(c.deadline_reference_revision)===1?r.supersedes_reference_id===null:uuid(r.supersedes_reference_id)&&r.supersedes_reference_id!==r.reference_id)&&str(r.rationale);
}

function validException(x:Record<string,unknown>):boolean {
  if(x.exception_contract_version===undefined)return true;
  const duration=(v:unknown)=>v===null||typeof v==='number'&&Number.isFinite(v)&&v>=0;
  return x.exception_contract_version===1&&num(x.request_revision)&&Number(x.request_revision)>0
    &&fields(x,['requester_id','compensating_controls'],str)&&sourceTime(x.submitted_at)&&utcExpiry(x.proposed_expires_at)
    &&obj(x.context)&&str(x.context.group_id)&&strings(x.context.membership_ids)&&obj(x.context.submitted_context)
    &&rows(x.sla_clock,c=>str(c.occurrence_id)&&['gap','running','paused','completed','completed_during_exception'].includes(String(c.state))&&sourceTime(c.target_at)&&duration(c.remaining_seconds)&&duration(c.frozen_sla_seconds)&&typeof c.prior_breach==='boolean'&&typeof c.currently_breached==='boolean'&&nullableString(c.event_id))
    &&(x.pause_snapshots===undefined||rows(x.pause_snapshots,p=>fields(p,['occurrence_id','episode_id','event_id'],str)&&fields(p,['approved_at','expires_at'],utcExpiry)&&fields(p,['original_deadline_at','pre_pause_deadline_at'],sourceTime)&&duration(p.remaining_seconds)&&typeof p.previously_breached==='boolean'))
    &&(x.approved_at===undefined||sourceTime(x.approved_at))
    &&(x.approvals===undefined||rows(x.approvals,a=>fields(a,['actor_id','rationale'],str)&&sourceTime(a.at)));
}
