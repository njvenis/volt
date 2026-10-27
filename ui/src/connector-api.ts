import {sessionFetch} from './session';
import type {ConnectorView, PermissionView, Revisions, Settings, Receipt, MetadataAction, Command, SubmitSecret, SubmissionLookup, FlowView, StartFlow, StartFlowResponse, IntentView, CandidateAudienceRequest, CandidateAudienceResponse, App, Secret} from './connector-types';
export const POLICY_TARGET='00000000-0000-4000-8000-000000000000' as const;
type Check=(value:unknown)=>boolean;
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const text:Check=v=>typeof v==='string'&&v.trim().length>0;
const uuid:Check=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const decimal:Check=v=>typeof v==='string'&&/^[1-9][0-9]*$/.test(v);
const rev:Check=v=>Number.isSafeInteger(v)&&Number(v)>=0;
const utc:Check=v=>typeof v==='string'&&v.endsWith('Z')&&Number.isFinite(Date.parse(v));
const bool:Check=v=>typeof v==='boolean';
const one=(...values:unknown[]):Check=>v=>values.includes(v);
const nullable=(check:Check):Check=>v=>v===null||check(v);
const array=(check:Check):Check=>v=>Array.isArray(v)&&v.every(check);
const dict=(key:Check,check:Check):Check=>v=>object(v)&&Object.entries(v).every(([k,x])=>key(k)&&check(x));
const shape=(fields:Record<string,Check>):Check=>v=>object(v)&&Object.keys(v).length===Object.keys(fields).length&&Object.entries(fields).every(([k,c])=>c(v[k]));
const schema=one(1);
const source=shape({source_id:uuid,revision:rev,source_family:text,source_account_id:text,scope_key:text});
const revisions:Check=v=>shape({target:rev,policy:rev,identity_membership:one(0),owners:one(0),authority:rev,connector:rev,source:rev,secret_source:rev,secret:nullable(rev)})(v)&&object(v)&&v.target===v.policy;
const permissions=shape({'connector.read':bool,'connector.configure':bool,'connector.secret.manage':bool,'github.repository.configure':bool});
const provider:Check=v=>v===null||shape({kind:one('encrypted_local_v1'),secret_source_id:uuid,revision:rev,key_binding_id:uuid})(v)||shape({kind:one('onepassword_v1'),secret_source_id:uuid,revision:rev,account_id:text,vault_id:text,bootstrap_binding_id:uuid})(v);
const reference=shape({secret_id:uuid,secret_revision:rev,version_id:uuid});
const app=shape({app_id:decimal,client_id:text,slug:text});
const installation=shape({flow_id:uuid,installation_id:decimal,account_id:decimal});
const settings=shape({environment_label:text,authentication_mode:one('legacy_token_file','github_app_v1'),secret_source:provider,credentials:shape({private_key:nullable(reference),oauth_client_secret:nullable(reference),webhook_secret:nullable(reference),preview_secret:nullable(reference),rest_token:nullable(reference)}),github:shape({host:one('github.com'),api_version:one('2022-11-28'),app:nullable(app),installation:nullable(installation),repository_ids:array(decimal),audience_revisions:dict(decimal,rev)})});
const failure=one('credentials_unavailable','provider_unavailable','decryption_failed','permission_missing','scope_changed','audience_incomplete','audience_unapproved','installation_invalid','installation_suspended','callback_invalid','flow_expired','credential_revoked','restore_quarantined','reconciliation_failed','outcome_unknown');
const recovery=shape({state:one('clear','quarantined','awaiting_activation'),recovery_epoch_id:nullable(uuid),operator_clearance_present:bool,requires_fresh_credentials:bool,reason:nullable(one('restore_quarantined'))});
const remote=shape({status:one('not_requested','pending','confirmed','failed','unknown'),intent_id:nullable(uuid),observed_at:nullable(utc),expires_at:nullable(utc),reason:nullable(failure)});
const version:Check=v=>shape({version_id:uuid,state:one('inactive','active','revoked'),present:bool,created_at:utc,revoked_at:nullable(utc),quarantine:one('clear','restored_version'),usable:bool,validation_eligible:bool,remote_revocation:remote})(v)&&object(v)&&(!(v.state==='revoked'||v.quarantine==='restored_version')||v.usable===false&&v.validation_eligible===false)&&(!(v.state==='inactive')||v.usable===false);
const secret=shape({secret_id:uuid,revision:rev,purpose:one('private_key','oauth_client_secret','webhook_secret','preview_secret','rest_token'),versions:array(version)});
const status=one('pending','complete','failed','outcome_unknown');
const lifecycle=one('staged','active','disabled');
const validation=shape({status:one('unverified','valid','stale','failed'),checked_at:nullable(utc),intent_id:nullable(uuid),configuration_revision:nullable(rev),reason:nullable(failure)});
export const validConnector:Check=v=>shape({schema_version:schema,connector_id:uuid,source,revisions,configuration_revision:rev,active_configuration_revision:nullable(rev),lifecycle,settings,validation,recovery,reconciliation:shape({status,intent_id:nullable(uuid),reason:nullable(failure)}),secrets:array(secret),updated_at:utc})(v);
const kind=one('connector.validate','connector.reconcile','connector.remote_revoke','connector.installation.verify');
const action=one('connector.configuration.stage','connector.configuration.validate','connector.configuration.activate','connector.configuration.disable','connector.configuration.rollback','connector.secret.version.revoke','connector.secret.submission.reconcile','connector.secret.submit','connector.installation.start','connector.installation.verify');
const outcome=one('committed','not_committed','unknown');
const effect=one('connector_configuration_committed','connector_validation_requested','connector_secret_submitted','connector_secret_revoked','connector_secret_submission_reconciled','connector_installation_started','connector_installation_verified');
const receipt=shape({schema_version:schema,command_id:uuid,action,target_id:one(POLICY_TARGET),policy_revision:rev,decision_id:uuid,audit_event_id:uuid,intents:array(shape({intent_id:uuid,kind,target_id:uuid,authority_revision:rev,status})),result:shape({effect,connector_id:uuid,source_id:uuid,revisions,configuration_revision:rev,active_configuration_revision:nullable(rev),lifecycle,secret_id:nullable(uuid),version_id:nullable(uuid),version_state:nullable(one('inactive','active','revoked')),submission_id:nullable(uuid),submission_outcome:nullable(outcome),flow_id:nullable(uuid),recovery})});
function installationReceipt(v:unknown,verb:'start'|'verify',cid:unknown,sid:unknown,fid:unknown,configuration:unknown):boolean {
 return receipt(v)&&object(v)&&v.action==='connector.installation.'+verb&&object(v.result)&&
  v.result.effect===(verb==='start'?'connector_installation_started':'connector_installation_verified')&&
  v.result.connector_id===cid&&v.result.source_id===sid&&v.result.flow_id===fid&&v.result.configuration_revision===configuration&&
  Array.isArray(v.intents)&&v.intents.every(i=>object(i)&&i.target_id===cid);
}
const flow:Check=v=>shape({schema_version:schema,flow_id:uuid,connector_id:uuid,source_id:uuid,configuration_revision:rev,initiating_principal_id:text,status:one('awaiting_installation','awaiting_authorization','verifying','verified','failed','expired'),expires_at:utc,reason:nullable(failure),app,installation:nullable(installation),granted_permissions:shape({issues:one('none','read','write'),metadata:one('none','read'),administration:one('none','read','write'),members:one('none','read','write')}),repositories:array(shape({repository_id:decimal,owner:text,name:text,private:bool,installation_access:bool,audience_status:one('unapproved','approved','stale'),audience_revision:nullable(rev)})),repositories_complete:bool,verification_receipt:nullable(receipt)})(v)&&object(v)&&
 (v.installation===null||object(v.installation)&&v.installation.flow_id===v.flow_id)&&
 (v.verification_receipt===null||installationReceipt(v.verification_receipt,'verify',v.connector_id,v.source_id,v.flow_id,v.configuration_revision))&&
 (v.status!=='verified'||v.repositories_complete===true&&v.installation!==null&&v.verification_receipt!==null);
const result=shape({configuration_revision:rev,source_revision:rev,secret_source_revision:rev,credentials:array(reference),installation:nullable(installation),repository_ids:array(decimal),audience_revisions:dict(decimal,rev),checked_at:utc,valid:bool,reason:nullable(failure)});
const intent=shape({schema_version:schema,connector_id:uuid,source_id:uuid,intent_id:uuid,kind,status,attempts:rev,last_error:nullable(failure),next_attempt_at:nullable(utc),completed_at:nullable(utc),validation_result:nullable(result),observed_remote_revocation:nullable(remote)});
const safeErrors=['authentication_required','csrf_failed','forbidden','source_scope_forbidden','not_found','invalid_request','revision_conflict','command_conflict','submission_conflict','credential_revoked','restore_quarantined','callback_invalid','validation_required','dependency_unavailable','outcome_unknown'];
const errorEnvelope=shape({schema_version:schema,error:shape({code:one(...safeErrors),message:text,correlation_id:uuid,details:shape({outcome:one('not_committed','unknown'),expected_revisions:nullable(revisions),current_revisions:nullable(revisions),lookup_url:nullable(v=>typeof v==='string')})})});
const errorStatuses:Record<string,number>={authentication_required:401,csrf_failed:403,forbidden:403,source_scope_forbidden:403,not_found:404,invalid_request:400,callback_invalid:400,revision_conflict:409,command_conflict:409,submission_conflict:409,credential_revoked:409,restore_quarantined:409,validation_required:409,dependency_unavailable:503,outcome_unknown:503};
export class ConnectorError extends Error {
  constructor(public code:string,public uncertain=false){super(code==='revision_conflict'?'These settings or permissions have changed. Refresh and review before saving again.':code==='restore_quarantined'?'Recovery quarantine prevents use. An independent recovery operator must verify fresh issuance.':code==='credential_revoked'?'This credential version is revoked and cannot be used again.':code==='forbidden'||code==='source_scope_forbidden'||code==='csrf_failed'?'Current access does not permit this operation.':code==='authentication_required'?'Sign in again to continue.':uncertain?'The save outcome is unknown. Check the retained operation before making another change.':code==='unsupported_response'?'The server response is incomplete or unsupported. No success has been assumed.':'Connector information is unavailable. Refresh or check the required fields.');}
}
async function request(path:string,check:Check,body?:unknown,method='POST'):Promise<unknown>{
  const write=body!==undefined;let response:Response;
  try{response=await sessionFetch(path,{method:write?method:'GET',headers:{Accept:'application/json',...(write?{'Content-Type':'application/json'}:{})},...(write?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(15000)});}catch{throw new ConnectorError(write?'outcome_unknown':'dependency_unavailable',write);}
  let value:unknown;try{value=await response.json();}catch{throw new ConnectorError('unsupported_response',write);}
  if(!response.ok){
    if(!errorEnvelope(value)||!object(value)||!object(value.error)||!object(value.error.details)||
      errorStatuses[String(value.error.code)]!==response.status)throw new ConnectorError('unsupported_response',write);
    const code=String(value.error.code);
    const known=value.error.details.outcome==='not_committed'&&code!=='outcome_unknown';
    throw new ConnectorError(code,write&&(!known||code==='submission_conflict'));
  }
  if(!check(value))throw new ConnectorError('unsupported_response',write);
  return value;
}
const root=(id:string)=>'/api/v1/connectors/'+encodeURIComponent(id);
const scope=(sid:string)=>'?source_id='+encodeURIComponent(sid);
export async function listConnectors(cursor?:string):Promise<{schema_version:1;items:ConnectorView[];next_cursor:string|null}>{return await request('/api/v1/connectors?limit=25'+(cursor?'&cursor='+encodeURIComponent(cursor):''),shape({schema_version:schema,items:array(validConnector),next_cursor:nullable(text)})) as never;}
export async function readConnector(id:string,sid:string):Promise<ConnectorView>{return await request(root(id)+scope(sid),v=>validConnector(v)&&object(v)&&v.connector_id===id&&object(v.source)&&v.source.source_id===sid) as ConnectorView;}
export async function readPermissions(id:string,sid:string,actor:string):Promise<PermissionView>{return await request(root(id)+'/permissions'+scope(sid),v=>shape({schema_version:schema,connector_id:one(id),source,revisions,principal_id:one(actor),allowed:permissions})(v)&&object(v)&&object(v.source)&&v.source.source_id===sid) as PermissionView;}
export function command(view:ConnectorView,verb:MetadataAction,rationale:string,evidence_ref:string,fields:Record<string,unknown>={},secretRevision:number|null=null):Command<Record<string,unknown>>{return {schema_version:1,command_id:crypto.randomUUID(),action:verb,target_id:POLICY_TARGET,membership_ids:[],expected_revisions:{...view.revisions,secret:secretRevision},payload:{connector_id:view.connector_id,source_id:view.source.source_id,rationale,evidence_ref,...fields}};}
function matchesReceipt(v:unknown,id:string,cid:string,sid:string,verb:string):boolean{return receipt(v)&&object(v)&&v.command_id===id&&v.action===verb&&object(v.result)&&v.result.connector_id===cid&&v.result.source_id===sid&&Array.isArray(v.intents)&&v.intents.every(i=>object(i)&&i.target_id===cid);}
export async function saveCommand(cmd:Command<Record<string,unknown>>):Promise<Receipt>{
 const expectedEffect=cmd.action==='connector.configuration.validate'?'connector_validation_requested':cmd.action==='connector.secret.version.revoke'?'connector_secret_revoked':cmd.action==='connector.secret.submission.reconcile'?'connector_secret_submission_reconciled':'connector_configuration_committed';
 return await request('/api/v1/assessment/commands',v=>matchesReceipt(v,cmd.command_id,cmd.payload.connector_id,cmd.payload.source_id,cmd.action)&&object(v)&&object(v.result)&&v.result.effect===expectedEffect&&
  (cmd.action!=='connector.secret.version.revoke'||v.result.secret_id===cmd.payload.secret_id&&v.result.version_id===cmd.payload.version_id&&v.result.version_state==='revoked')&&
  (cmd.action!=='connector.secret.submission.reconcile'||v.result.submission_id===cmd.payload.submission_id&&v.result.secret_id===cmd.payload.secret_id&&v.result.version_id===cmd.payload.version_id&&outcome(v.result.submission_outcome)),cmd) as Receipt;
}
export type PendingSecret={submission_id:string;connector_id:string;source_id:string;secret_id:string;version_id:string};
export async function submitSecret(pending:PendingSecret,body:SubmitSecret):Promise<Receipt>{return await request(root(pending.connector_id)+'/secrets/'+pending.secret_id+'/versions',v=>matchesReceipt(v,pending.submission_id,pending.connector_id,pending.source_id,'connector.secret.submit')&&object(v)&&object(v.result)&&v.result.secret_id===pending.secret_id&&v.result.version_id===pending.version_id&&v.result.submission_id===pending.submission_id&&v.result.submission_outcome==='committed'&&v.result.version_state==='inactive'&&v.result.effect==='connector_secret_submitted',body) as Receipt;}
export async function lookupSecret(p:PendingSecret):Promise<SubmissionLookup>{return await request(root(p.connector_id)+'/secret-submissions/'+p.submission_id+scope(p.source_id)+'&secret_id='+p.secret_id+'&version_id='+p.version_id,v=>shape({schema_version:schema,submission_id:one(p.submission_id),connector_id:one(p.connector_id),source_id:one(p.source_id),secret_id:one(p.secret_id),version_id:one(p.version_id),outcome,receipt:nullable(receipt),retry_allowed:bool,poll_after_ms:nullable(one(1000))})(v)&&object(v)&&(v.outcome==='committed'?v.retry_allowed===false&&v.poll_after_ms===null&&matchesReceipt(v.receipt,p.submission_id,p.connector_id,p.source_id,'connector.secret.submit')&&object(v.receipt)&&object(v.receipt.result)&&v.receipt.result.secret_id===p.secret_id&&v.receipt.result.version_id===p.version_id&&v.receipt.result.submission_id===p.submission_id&&v.receipt.result.submission_outcome==='committed'&&v.receipt.result.effect==='connector_secret_submitted':v.receipt===null&&(v.outcome==='unknown'?v.retry_allowed===false&&v.poll_after_ms===1000:v.retry_allowed===true&&v.poll_after_ms===null))) as SubmissionLookup;}
export async function readReceipt(cid:string,sid:string,id:string):Promise<Receipt>{return await request(root(cid)+'/receipts/'+id+scope(sid),v=>receipt(v)&&object(v)&&v.command_id===id&&object(v.result)&&v.result.connector_id===cid&&v.result.source_id===sid) as Receipt;}
export async function readIntent(cid:string,sid:string,id:string):Promise<IntentView>{return await request(root(cid)+'/intents/'+id+scope(sid),v=>intent(v)&&object(v)&&v.connector_id===cid&&v.source_id===sid&&v.intent_id===id) as IntentView;}
export async function readFlow(cid:string,sid:string,id:string):Promise<FlowView>{return await request(root(cid)+'/installation-flows/'+encodeURIComponent(id)+scope(sid),v=>flow(v)&&object(v)&&v.connector_id===cid&&v.source_id===sid&&v.flow_id===id) as FlowView;}
export async function startFlow(cid:string,body:StartFlow,expected:{app:App;actorId:string}):Promise<StartFlowResponse>{
 return await request(root(cid)+'/installation-flows',v=>shape({schema_version:schema,flow,redirect_url:text,receipt})(v)&&object(v)&&object(v.flow)&&
  v.flow.connector_id===cid&&v.flow.source_id===body.source_id&&v.flow.configuration_revision===body.configuration_revision&&
  (v.flow.initiating_principal_id===expected.actorId&&sameApp(v.flow.app,expected.app))&&
  matchesReceipt(v.receipt,body.command_id,cid,body.source_id,'connector.installation.start')&&
  installationReceipt(v.receipt,'start',cid,body.source_id,v.flow.flow_id,body.configuration_revision),body) as StartFlowResponse;
}
export async function readInstallationReceipt(cid:string,body:StartFlow):Promise<Receipt>{
 return await request(root(cid)+'/receipts/'+body.command_id+scope(body.source_id),v=>receipt(v)&&object(v)&&object(v.result)&&uuid(v.result.flow_id)&&
  v.command_id===body.command_id&&installationReceipt(v,'start',cid,body.source_id,v.result.flow_id,body.configuration_revision)) as Receipt;
}
export const sameApp=(value:unknown,expected:App)=>object(value)&&value.app_id===expected.app_id&&value.client_id===expected.client_id&&value.slug===expected.slug;
// Metadata only: no credential input, redirect URL, OAuth state/code or verifier.
export type PendingInstallation={request:StartFlow;app:App};
export function validPendingInstallation(value:unknown,sid:string):value is PendingInstallation {
 return shape({request:shape({schema_version:schema,command_id:uuid,source_id:one(sid),configuration_revision:rev,expected_revisions:revisions,rationale:text,evidence_ref:text}),app})(value);
}
// Permission flags remain server-owned. This only identifies which selected
// references would resolve an inactive version; unrelated retained versions do not count.
export function selectedCredentialAccess(view:ConnectorView,candidate:Settings=view.settings,purposes:(keyof Settings['credentials'])[]=Object.keys(candidate.credentials) as Secret['purpose'][]){
 const versions=purposes.flatMap(p=>{const ref=candidate.credentials[p];if(!ref)return [];return [view.secrets.find(s=>s.secret_id===ref.secret_id&&s.purpose===p)?.versions.find(v=>v.version_id===ref.version_id)];});
 return {requiresSecretManagement:versions.some(v=>v?.state==='inactive'),blocked:versions.some(v=>!v||v.state==='revoked'||v.quarantine!=='clear')};
}

export async function approveAudience(id:string,body:CandidateAudienceRequest):Promise<CandidateAudienceResponse>{return await request('/api/v1/github/repositories/'+id,shape({schema_version:schema,repository_id:one(id),audience_revision:rev,audience_approved:one(true),audience_sha256:v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)}),body,'PUT') as CandidateAudienceResponse;}
export async function readConfiguration(cid:string,sid:string,revision:number):Promise<{settings:Settings;configuration_revision:number;created_at:string}>{return await request(root(cid)+'/configurations/'+revision+scope(sid),v=>shape({schema_version:schema,connector_id:one(cid),source,revisions,configuration_revision:one(revision),settings,created_at:utc})(v)&&object(v)&&object(v.source)&&v.source.source_id===sid) as never;}
