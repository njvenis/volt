import {sessionFetch} from './session';
import type {Paths} from './generated/api';
export const deploymentTarget='00000000-0000-0000-0000-000000000000';
export type ConnectorSummary={connector_id:string;source:{source_id:string;source_family:string;source_account_id:string;scope_key:string};environment_label:string;lifecycle:string;source_revision:number;connector_revision:number;configuration_revision:number};
export type Deployment={schema_version:1;installation_id:string;connector_registry_revision:number;can_register_connector:boolean;connectors:ConnectorSummary[];policy_revision:number;authority_revision:number};
export type Registration=Extract<Paths['/api/v1/assessment/commands']['post']['request']['body'],{action:'connector.binding.register'}>;
export type RegistrationPayload=Registration['payload'];
export type RegistrationReceipt={allocated_ids:RegistrationResult;connector_registry_revision:number;source_tuple:{source_family:'qualys';source_account_id:string;scope_key:string};credential_slots:{qualys_vm_basic:{secret_id:string}}};
export type Abandonment={disposition:'committed';receipt:RegistrationReceipt}|{disposition:'not_committed';command_id:string;request_digest:string;actor_id:string;audit_event_id:string;committed_at:string};
export type RegistrationResult={connector_id:string;source_id:string;access_group_id:string;role_id:string};
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0;
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const revision=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
export class DeploymentError extends Error {constructor(public status:number,public uncertain=false){super(status===403?'Administrator access is required.':status===401?'Your session has expired. Sign in again.':status===409?'The deployment changed or this scanner is already registered. Refresh and review the current state.':status===422?'Check the scanner details and supported adapter values.':status===429?'Too many requests. Wait before trying again.':uncertain?'Registration outcome is unknown. Keep this command and retry it unchanged to recover its receipt.':'Deployment information is unavailable. Retry the access check.');}}
export function parseDeployment(v:unknown):Deployment {
 if(!object(v)||v.schema_version!==1||!uuid(v.installation_id)||!revision(v.connector_registry_revision)||!revision(v.policy_revision)||!revision(v.authority_revision)||typeof v.can_register_connector!=='boolean'||!Array.isArray(v.connectors)||!v.connectors.every(c=>object(c)&&uuid(c.connector_id)&&object(c.source)&&uuid(c.source.source_id)&&['source_family','source_account_id','scope_key'].every(k=>text((c.source as Record<string,unknown>)[k]))&&text(c.environment_label)&&['staged','active','disabled'].includes(String(c.lifecycle))&&['source_revision','connector_revision','configuration_revision'].every(k=>revision(c[k])))||new Set(v.connectors.map(c=>c.connector_id)).size!==v.connectors.length)throw new DeploymentError(502);
 return v as Deployment;
}
export function isRegistration(v:unknown):v is Registration {
 return object(v)&&Object.keys(v).sort().join(',')==='action,command_id,expected_authority_revision,expected_connector_registry_revision,expected_policy_revision,membership_ids,payload,schema_version,target_id'&&v.schema_version===1&&uuid(v.command_id)&&v.action==='connector.binding.register'&&v.target_id===deploymentTarget&&Array.isArray(v.membership_ids)&&v.membership_ids.length===0&&['expected_policy_revision','expected_authority_revision','expected_connector_registry_revision'].every(k=>revision(v[k]))&&object(v.payload)&&Object.keys(v.payload).sort().join(',')==='account_label,display_name,environment_label,evidence_ref,grant_initial_read,platform_id,product,rationale,scope,source_family'&&v.payload.source_family==='qualys'&&v.payload.product==='qualys_vm'&&['us1','us2','us3','eu1','eu2','in1'].includes(String(v.payload.platform_id))&&object(v.payload.scope)&&Object.keys(v.payload.scope).length===1&&v.payload.scope.kind==='account_visible'&&['display_name','account_label','environment_label','rationale','evidence_ref'].every(k=>text((v.payload as Record<string,unknown>)[k]))&&typeof v.payload.grant_initial_read==='boolean';
}
export async function readDeployment(signal?:AbortSignal):Promise<Deployment>{
 let response:Response;
 try{response=await sessionFetch('/api/v1/deployment',{signal:signal?AbortSignal.any([signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000)});}catch{throw new DeploymentError(0);}
 if(!response.ok)throw new DeploymentError(response.status);
 return parseDeployment(await response.json().catch(()=>null));
}
export function registration(deployment:Deployment,payload:RegistrationPayload):Registration{return {schema_version:1,command_id:crypto.randomUUID(),action:'connector.binding.register',target_id:deploymentTarget,membership_ids:[],expected_policy_revision:deployment.policy_revision,expected_authority_revision:deployment.authority_revision,expected_connector_registry_revision:deployment.connector_registry_revision,payload:{...payload}};}
export async function registerScanner(command:Registration):Promise<RegistrationReceipt>{
 let response:Response;
 try{response=await sessionFetch('/api/v1/assessment/commands',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(command),signal:AbortSignal.timeout(20000)});}catch{throw new DeploymentError(0,true);}
 if(!response.ok)throw new DeploymentError(response.status,response.status>=500);
 return parseRegistrationReceipt(await response.json().catch(()=>null),command);
}
export function parseRegistrationReceipt(v:unknown,command:Registration):RegistrationReceipt {
 if(!object(v)||v.schema_version!==1||v.command_id!==command.command_id||v.action!==command.action||v.target_id!==command.target_id||!uuid(v.decision_id)||!uuid(v.audit_event_id)||!object(v.result)||v.result.effect!=='native_administration_state_committed'||!revision(v.result.policy_revision)||!revision(v.result.authority_revision)||!revision(v.result.connector_registry_revision)||v.result.connector_registry_revision<=command.expected_connector_registry_revision||!object(v.result.allocated_ids)||!['connector_id','source_id','access_group_id','role_id'].every(k=>uuid((v.result as Record<string,Record<string,unknown>>).allocated_ids[k])))throw new DeploymentError(502,true);
 if(v.result.lifecycle!=='disabled'||!object(v.result.source_tuple)||v.result.source_tuple.source_family!=='qualys'||!uuid(v.result.source_tuple.source_account_id)||!uuid(v.result.source_tuple.scope_key)||!object(v.result.credential_slots)||!object(v.result.credential_slots.qualys_vm_basic)||!uuid(v.result.credential_slots.qualys_vm_basic.secret_id))throw new DeploymentError(502,true);
 return {allocated_ids:v.result.allocated_ids as RegistrationResult,connector_registry_revision:v.result.connector_registry_revision,source_tuple:v.result.source_tuple as RegistrationReceipt['source_tuple'],credential_slots:v.result.credential_slots as RegistrationReceipt['credential_slots']};
}

// Matches the backend assessment _digest: sorted compact JSON, ASCII escaped,
// including the principal. A response for another command/actor is not a disposition.
export async function registrationDigest(command:Registration,actorId:string):Promise<string>{
 function canonical(value:unknown):string {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(object(value))return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';
  const encoded=JSON.stringify(value);if(encoded===undefined)throw new DeploymentError(502,true);return encoded;
 }
 const raw=canonical({...command,principal_id:actorId}).replace(/[\u007f-\uffff]/g,char=>'\\u'+char.charCodeAt(0).toString(16).padStart(4,'0'));
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw));
 return Array.from(new Uint8Array(digest),byte=>byte.toString(16).padStart(2,'0')).join('');
}
export async function abandonRegistration(command:Registration,actorId:string,rationale:string,evidenceRef:string):Promise<Abandonment>{
 const digest=await registrationDigest(command,actorId);
 let response:Response;
 try{response=await sessionFetch('/api/v1/assessment/commands/'+encodeURIComponent(command.command_id)+'/abandon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schema_version:1,command,rationale,evidence_ref:evidenceRef}),signal:AbortSignal.timeout(20000)});}catch{throw new DeploymentError(0,true);}
 if(!response.ok)throw new DeploymentError(response.status,true);
 const v:unknown=await response.json().catch(()=>null);
 if(!object(v)||v.schema_version!==1||v.command_id!==command.command_id||v.request_digest!==digest)throw new DeploymentError(502,true);
 if(v.disposition==='committed')return {disposition:'committed',receipt:parseRegistrationReceipt(v.receipt,command)};
 if(v.disposition!=='not_committed'||v.actor_id!==actorId||!uuid(v.audit_event_id)||typeof v.committed_at!=='string'||!v.committed_at.endsWith('Z')||!Number.isFinite(Date.parse(v.committed_at)))throw new DeploymentError(502,true);
 return {disposition:'not_committed',command_id:command.command_id,request_digest:digest,actor_id:actorId,audit_event_id:v.audit_event_id,committed_at:v.committed_at};
}
