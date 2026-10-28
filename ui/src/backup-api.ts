import {sessionFetch} from './session';

export const durationFields = [
  ['interval_seconds', 'Backup interval'],
  ['timeout_seconds', 'Backup timeout'],
  ['maximum_backup_age_seconds', 'Maximum backup age'],
  ['restore_verification_timeout_seconds', 'Restore verification timeout'],
] as const;
export const referenceFields = [
  ['archive_target_ref', 'Archive target'], ['recovery_profile_ref', 'Recovery profile'],
] as const;
export type DurationKey = typeof durationFields[number][0];
export type ReferenceKey = typeof referenceFields[number][0];
export type Values = Record<DurationKey, number> & Record<ReferenceKey, string>;
export type Revisions = {configuration: number; policy: number; authority: number; host_policy: number};
type BaseCommand = {schema_version: 1; command_id: string; expected_revisions: Revisions; rationale: string; evidence_ref: string | null};
export type Command = BaseCommand & ({action: 'backup.settings.publish'; values: Values} | {action: 'backup.settings.rollback'; rollback_revision: number});
export type Receipt = {schema_version: 1; command_id: string; deployment_id: string; actor_id: string; action: Command['action']; request_digest: string; settings_digest: string; desired_revision: number; evaluated_revisions: Revisions; audit_id: string; intent_id: string; committed_at: string; outcome: 'desired_committed'};
export type Historical = {schema_version: 1; deployment_id: string; revision: number; digest: string; values: Values; publication_revisions: Revisions; command_id: string; actor_id: string; rationale: string; evidence_ref: string | null; committed_at: string; audit_id: string};
export type Application = {state: 'pending' | 'applied' | 'failed' | 'uncertain' | 'unknown'; requested_revision: number | null; requested_digest: string | null; intent_id: string | null; host_policy_revision: number | null; active_revision: number | null; active_digest: string | null; reported_at: string | null; failure_code: string | null};
export type Settings = {
  schema_version: 1; deployment_id: string; revisions: Revisions & {recovery_epoch: number};
  desired: {revision: number; digest: string; values: Values; command_id: string; committed_at: string} | null;
  effective: {revision: number; digest: string; verified_at: string | null} | null;
  status: {
    settings_application: Application | null;
    completed_archive: {archive_id: string | null; completed_at: string | null; manifest_digest: string | null; outcome: 'complete' | 'failed' | 'uncertain' | null};
    freshness: {state: 'fresh' | 'stale' | 'unknown'; evaluated_at: string | null; age_seconds: number | null; basis_completed_at: string | null; maximum_backup_age_seconds: number | null};
    restore_verification: {state: 'verified' | 'failed' | 'uncertain' | 'unknown'; archive_id: string | null; recovery_epoch: number; verified_at: string | null; failure_code: string | null};
  };
  host_policy: {revision: number; digest: string; bounds: Record<DurationKey, {min: number; max: number}>; archive_target_refs: string[]; recovery_profile_refs: string[]; maximum_report_age_seconds: number; maximum_future_skew_seconds: number; observed_at: string; fresh_until: string; freshness: 'fresh' | 'stale' | 'unknown'} | null;
  can_configure: boolean;
};
export type Deployment = {deployment_id: string; label: string; can_configure: boolean};
export type Deployments = {schema_version: 1; deployments: Deployment[]; next_cursor: string | null};
const messages: Record<string,string> = {
  revision_conflict: 'Settings or permissions changed. Refresh and review the current revision before saving again.',
  command_conflict: 'This command conflicts with retained content. Check the original command receipt.',
  host_policy_unavailable: 'A fresh signed host policy is required. Refresh before trying again.',
  invalid_values: 'Review all six settings against the current host bounds and registered references.',
  forbidden: 'Current permissions do not allow this operation.',
  not_found: 'No disclosable record was found. An unknown command remains unresolved.',
  invalid_response: 'The server response could not be verified. No successful outcome is inferred.',
  unavailable: 'The request could not be confirmed. Check the retained command receipt before making a new change.',
};
export class BackupError extends Error {
  constructor(public code: string, public status=0, public unknown=false) {
    super(messages[code] ?? messages[status===403?'forbidden':status===404?'not_found':status===409?'revision_conflict':'unavailable']);
  }
}
function requireValue(ok: unknown): asserts ok {if (!ok) throw new BackupError('invalid_response');}
function obj(raw: unknown): Record<string,unknown> {requireValue(!!raw && typeof raw==='object' && !Array.isArray(raw));return raw as Record<string,unknown>;}
function exact(raw: unknown, names: string[]): Record<string,unknown> {const v=obj(raw);requireValue(Object.keys(v).length===names.length && names.every(k=>Object.hasOwn(v,k)));return v;}
const integer=(v: unknown)=>typeof v==='number' && Number.isSafeInteger(v) && v>=0;
const text=(v: unknown)=>typeof v==='string' && v.trim().length>0;
const uuid=(v: unknown)=>typeof v==='string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const digest=(v: unknown)=>typeof v==='string' && /^sha256:[0-9a-f]{64}$/.test(v);
const time=(v: unknown)=>typeof v==='string' && /(?:Z|\+00:00)$/.test(v) && Number.isFinite(Date.parse(v));
const nullable=(v: unknown, check: (v: unknown)=>boolean)=>v===null || check(v);
const choice=(v: unknown, choices: unknown[])=>choices.includes(v);
const code=(v: unknown)=>typeof v==='string' && /^[a-z][a-z0-9_]{0,99}$/.test(v);
function revisions(raw: unknown, epoch=false) {const v=exact(raw,['configuration','policy','authority','host_policy',...(epoch?['recovery_epoch']:[])]);requireValue(Object.values(v).every(integer));return v;}
function values(raw: unknown) {const v=exact(raw,[...durationFields,...referenceFields].map(([k])=>k));requireValue(durationFields.every(([k])=>integer(v[k])) && referenceFields.every(([k])=>text(v[k])));}
function envelope(raw: unknown, deployment?: string) {const v=obj(raw);requireValue(v.schema_version===1 && (deployment===undefined || v.deployment_id===deployment));return v;}
export function parseCommand(raw: unknown): Command {
  const c=envelope(raw);
  exact(c,['schema_version','command_id','action','expected_revisions','rationale','evidence_ref',c.action==='backup.settings.publish'?'values':'rollback_revision']);
  requireValue(uuid(c.command_id) && text(c.rationale) && nullable(c.evidence_ref,text));revisions(c.expected_revisions);
  if(c.action==='backup.settings.publish')values(c.values);
  else requireValue(c.action==='backup.settings.rollback' && integer(c.rollback_revision) && Number(c.rollback_revision)>0);
  return c as unknown as Command;
}
export function parseSettings(raw: unknown, deployment: string): Settings {
  const v=envelope(raw,deployment);exact(v,['schema_version','deployment_id','revisions','desired','effective','status','host_policy','can_configure']);
  const tokens=revisions(v.revisions,true);requireValue(typeof v.can_configure==='boolean');
  if(v.desired!==null){const d=exact(v.desired,['revision','digest','values','command_id','committed_at']);requireValue(integer(d.revision)&&Number(d.revision)>0&&d.revision===tokens.configuration&&digest(d.digest)&&uuid(d.command_id)&&time(d.committed_at));values(d.values);}else requireValue(tokens.configuration===0);
  if(v.effective!==null){const e=exact(v.effective,['revision','digest','verified_at']);requireValue(integer(e.revision)&&Number(e.revision)>0&&Number(e.revision)<=Number(tokens.configuration)&&digest(e.digest)&&nullable(e.verified_at,time));}
  if(v.host_policy!==null){const p=exact(v.host_policy,['revision','digest','bounds','archive_target_refs','recovery_profile_refs','maximum_report_age_seconds','maximum_future_skew_seconds','observed_at','fresh_until','freshness']);requireValue(integer(p.revision)&&p.revision===tokens.host_policy&&digest(p.digest)&&integer(p.maximum_report_age_seconds)&&integer(p.maximum_future_skew_seconds)&&time(p.observed_at)&&time(p.fresh_until)&&Date.parse(String(p.fresh_until))>=Date.parse(String(p.observed_at))&&choice(p.freshness,['fresh','stale','unknown']));const b=exact(p.bounds,durationFields.map(([k])=>k));for(const [k] of durationFields){const bound=exact(b[k],['min','max']);requireValue(integer(bound.min)&&integer(bound.max)&&Number(bound.min)<=Number(bound.max));}for(const k of ['archive_target_refs','recovery_profile_refs'])requireValue(Array.isArray(p[k])&&(p[k] as unknown[]).every(text)&&new Set(p[k] as unknown[]).size===(p[k] as unknown[]).length);}else requireValue(tokens.host_policy===0&&!v.can_configure);
  const s=exact(v.status,['settings_application','completed_archive','freshness','restore_verification']);
  if(s.settings_application!==null){const a=exact(s.settings_application,['state','requested_revision','requested_digest','intent_id','host_policy_revision','active_revision','active_digest','reported_at','failure_code']);requireValue(choice(a.state,['pending','applied','failed','uncertain','unknown'])&&nullable(a.requested_revision,integer)&&nullable(a.active_revision,integer)&&nullable(a.host_policy_revision,integer)&&nullable(a.requested_digest,digest)&&nullable(a.active_digest,digest)&&nullable(a.intent_id,uuid)&&nullable(a.reported_at,time)&&nullable(a.failure_code,code));if(a.state==='applied'){const d=obj(v.desired),e=obj(v.effective);requireValue(a.requested_revision===d.revision&&a.active_revision===d.revision&&e.revision===d.revision&&a.requested_digest===d.digest&&a.active_digest===d.digest&&e.digest===d.digest);}}
  const a=exact(s.completed_archive,['archive_id','completed_at','manifest_digest','outcome']);requireValue(nullable(a.archive_id,uuid)&&nullable(a.completed_at,time)&&nullable(a.manifest_digest,digest)&&choice(a.outcome,['complete','failed','uncertain',null]));if(a.outcome==='complete')requireValue(uuid(a.archive_id)&&time(a.completed_at)&&digest(a.manifest_digest));
  const f=exact(s.freshness,['state','evaluated_at','age_seconds','basis_completed_at','maximum_backup_age_seconds']);requireValue(choice(f.state,['fresh','stale','unknown'])&&nullable(f.evaluated_at,time)&&nullable(f.age_seconds,integer)&&nullable(f.basis_completed_at,time)&&nullable(f.maximum_backup_age_seconds,integer));if(f.state!=='unknown')requireValue(v.effective!==null&&time(f.evaluated_at)&&integer(f.age_seconds)&&time(f.basis_completed_at)&&integer(f.maximum_backup_age_seconds));
  // Validate the server's evidence binding; freshness policy remains server-owned.
  if(f.state==='fresh')requireValue(a.outcome==='complete'&&uuid(a.archive_id)&&time(a.completed_at)&&digest(a.manifest_digest)&&Date.parse(String(f.basis_completed_at))===Date.parse(String(a.completed_at)));
  const r=exact(s.restore_verification,['state','archive_id','recovery_epoch','verified_at','failure_code']);requireValue(choice(r.state,['verified','failed','uncertain','unknown'])&&nullable(r.archive_id,uuid)&&integer(r.recovery_epoch)&&nullable(r.verified_at,time)&&nullable(r.failure_code,code));if(r.state==='verified')requireValue(uuid(r.archive_id)&&time(r.verified_at));
  return v as unknown as Settings;
}
export function parseReceipt(raw: unknown, deployment: string, command: Command, expectedActorId: string): Receipt {
  const r=envelope(raw,deployment);exact(r,['schema_version','command_id','deployment_id','actor_id','action','request_digest','settings_digest','desired_revision','evaluated_revisions','audit_id','intent_id','committed_at','outcome']);
  requireValue(r.command_id===command.command_id&&r.action===command.action&&text(expectedActorId)&&r.actor_id===expectedActorId&&digest(r.request_digest)&&digest(r.settings_digest)&&r.desired_revision===command.expected_revisions.configuration+1&&uuid(r.audit_id)&&uuid(r.intent_id)&&time(r.committed_at)&&r.outcome==='desired_committed');
  const evaluated=revisions(r.evaluated_revisions);for(const k of Object.keys(command.expected_revisions) as (keyof Revisions)[])requireValue(evaluated[k]===command.expected_revisions[k]);return r as unknown as Receipt;
}
const root='/api/v1/operations/backup-settings';
async function request(path: string, body?: Command): Promise<unknown> {
  let response: Response;try{response=await sessionFetch(root+path,{method:body?'POST':'GET',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(15000)});}catch{throw new BackupError('unavailable',0,!!body);}
  let raw: unknown;try{raw=await response.json();}catch{throw new BackupError('invalid_response',response.status,!!body);}
  if(!response.ok){let code='unavailable',unknown=!!body;try{const error=obj(envelope(raw).error),details=obj(error.details);requireValue(text(error.code)&&choice(details.outcome,['unknown','not_committed']));code=String(error.code);unknown=details.outcome==='unknown';}catch{/* An unverified error cannot establish that a write failed. */}throw new BackupError(code,response.status,unknown);}
  return raw;
}
const path=(deployment: string)=>'/'+encodeURIComponent(deployment);
export async function readSettings(deployment: string){return parseSettings(await request(path(deployment)),deployment);}
export async function readHistory(deployment: string, revision: number): Promise<Historical> {
  const r=envelope(await request(path(deployment)+'/revisions/'+revision),deployment);exact(r,['schema_version','deployment_id','revision','digest','values','publication_revisions','command_id','actor_id','rationale','evidence_ref','committed_at','audit_id']);requireValue(r.revision===revision&&integer(r.revision)&&digest(r.digest)&&uuid(r.command_id)&&text(r.actor_id)&&text(r.rationale)&&nullable(r.evidence_ref,text)&&time(r.committed_at)&&uuid(r.audit_id));values(r.values);const tokens=revisions(r.publication_revisions);requireValue(tokens.configuration===revision);return r as unknown as Historical;
}
export async function save(deployment: string, command: Command, expectedActorId: string){parseCommand(command);const raw=await request(path(deployment)+'/commands',command);try{return parseReceipt(raw,deployment,command,expectedActorId);}catch{throw new BackupError('invalid_response',200,true);}}
export async function receipt(deployment: string, command: Command, expectedActorId: string){const raw=await request(path(deployment)+'/receipts/'+encodeURIComponent(command.command_id));try{return parseReceipt(raw,deployment,command,expectedActorId);}catch{throw new BackupError('invalid_response',200,true);}}

export function parseDeployments(raw: unknown): Deployments {
  const r=envelope(raw);exact(r,['schema_version','deployments','next_cursor']);
  requireValue(Array.isArray(r.deployments)&&r.deployments.length<=50&&nullable(r.next_cursor,text));
  const seen=new Set<string>();
  for(const row of r.deployments){const d=exact(row,['deployment_id','label','can_configure']);requireValue(text(d.deployment_id)&&text(d.label)&&typeof d.can_configure==='boolean'&&!seen.has(String(d.deployment_id)));seen.add(String(d.deployment_id));}
  requireValue(r.deployments.length>0||r.next_cursor===null);
  return r as unknown as Deployments;
}
export async function listDeployments(cursor?: string){return parseDeployments(await request(cursor===undefined?'':'?cursor='+encodeURIComponent(cursor)));}
