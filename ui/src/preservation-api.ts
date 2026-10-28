import {errorCode, sessionFetch} from './session';

export const classIds = ['product.source_evidence', 'product.audit_history', 'operational.scanner_collection'] as const;
export type ClassId = typeof classIds[number];
export type Scope = {source_family:string; source_account_id:string; scope_key:string};
export type CheckState = 'verified'|'gap'|'unknown'|'failed';
export const classLabels:Record<ClassId,string> = {'product.source_evidence':'Source evidence','product.audit_history':'Audit history','operational.scanner_collection':'Scanner collection history'};
export const recordKinds:Record<ClassId,string[]> = {
 'product.source_evidence':['observation','observation_linkage','retention_receipt','evidence_registration'],
 'product.audit_history':['audit_event','audit_attribution','audit_copy_receipt_established','audit_anchor'],
 'operational.scanner_collection':['expected_run','run_revision','attempt','page','expected_transition'],
};
export const reasonCodes = 'baseline_missing baseline_incomplete baseline_untrusted baseline_discontinuous baseline_replay baseline_expired legacy_preimage_unavailable coverage_unsupported scope_incomplete audit_scope_incomplete environment_unlabelled record_missing bytes_changed bytes_unreadable receipt_missing receipt_changed sink_record_missing sink_record_changed unexpected_member source_unavailable sink_unavailable evidence_store_unavailable evidence_missing evidence_changed evidence_unreadable source_checkpoint_missing report_expired cursor_expired snapshot_expired authority_changed trust_key_unavailable trust_config_mismatch schema_mismatch future_timestamp internal_check_failed'.split(' ');
const countFields = ['expected_records','verified_records','missing_records','changed_records','unreadable_records','unexpected_records'] as const;
const copyCounts = ['expected_events','matching_events','missing_events','changed_events','unexpected_events','expected_receipts','matching_receipts','missing_receipts','changed_receipts','unexpected_receipts','pending_receipts'] as const;
export type AuditCopy = Record<typeof copyCounts[number],number|null> & {state:CheckState;reasons:string[];checked_at:string|null};
export type PreservationClass = Record<typeof countFields[number],number|null> & {class_id:ClassId; minimum_period:'P1Y'|'P3M';state:CheckState;reasons:string[];oldest_retained_at:string|null;baseline_digest:string|null;audit_copy:AuditCopy|null};
export type Summary = {schema_version:1;scope:Scope;snapshot_id:string|null;checked_at:string|null;response_at:string;valid_until:string|null;authority_fingerprint:string;audit_authority_fingerprint:string|null;mask_reasons:string[];environment:string|null;classes:PreservationClass[];uncovered_classes:ClassId[];elapsed_preservation:'unverified'};
export type RecordItem = {record_key:string;record_kind:string;retained_at:string|null;state:'verified'|'missing'|'changed'|'unreadable'|'unexpected';reasons:string[];expected_sha256:string|null;actual_sha256:string|null;record_sha256:string|null;readback_url:string|null};
export type RecordPage = {schema_version:1;snapshot_id:string;class_id:ClassId;items:RecordItem[];next_cursor:string|null};
const messages:Record<string,string> = {
 not_found:'This source or record is unavailable to your current access. No existence or count is disclosed.',
 invalid_response:'The response does not match the preservation contract. No successful check is inferred.',
 invalid_cursor:'The page binding is no longer valid. Reload the current source report before browsing again.',
 cursor_expired:'This page has expired. Reload the current source report before browsing again.',
 snapshot_expired:'The signed report has expired or changed. Reload the current source report before browsing again.',
 evidence_missing:'The registered evidence bytes are missing.',evidence_changed:'The evidence bytes do not match the registered digest.',
 evidence_unreadable:'The evidence cannot be read safely.',evidence_store_unavailable:'The evidence store is unavailable.',
 dependency_unavailable:'A required service is unavailable. No current counts can be established.',
 unavailable:'The read could not be completed. Refresh to try again.',forbidden:'Your session cannot access this information.',
};
export class PreservationError extends Error {
 constructor(public code:string, public status=0){super(messages[code]??messages.unavailable);}
 get reset(){return ['invalid_cursor','cursor_expired','snapshot_expired'].includes(this.code);}
}
function requireValue(condition:unknown):asserts condition {if(!condition)throw new PreservationError('invalid_response');}
const object=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(v:unknown,keys:readonly string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const safeText=(v:unknown,max=512):v is string=>typeof v==='string'&&v.length>0&&!/[\x00-\x1f\x7f]/.test(v)&&new TextEncoder().encode(v).length<=max;
const integer=(v:unknown)=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const nullable=(v:unknown,check:(v:unknown)=>boolean)=>v===null||check(v);
const time=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const digest=(v:unknown):v is string=>typeof v==='string'&&/^(?:sha256:)?[0-9a-f]{64}$/.test(v);
const baseline=(v:unknown)=>typeof v==='string'&&/^sha256:[0-9a-f]{64}$/.test(v);
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const state=(v:unknown)=>['verified','gap','unknown','failed'].includes(v as string);
const sortedUnique=(v:unknown,allowed:readonly string[]):v is string[]=>Array.isArray(v)&&v.every((s,i)=>typeof s==='string'&&allowed.includes(s)&&(i===0||v[i-1]<s));
const reasons=(v:unknown)=>sortedUnique(v,reasonCodes);
export const scopeKey=(s:Scope)=>JSON.stringify([s.source_family,s.source_account_id,s.scope_key]);
function validScope(s:unknown):s is Scope{return exact(s,['source_family','source_account_id','scope_key'])&&Object.values(s).every(v=>safeText(v)&&v!=='*');}
// Candidates are not entitlements. Never combine or inspect action grants here.
export function sessionCandidates(body:unknown):Scope[]{
 requireValue(object(body));
 const authority=object(body.authority)?body.authority:{};
 const result=new Map<string,Scope>();
 const groups=authority.group_scopes??{};requireValue(object(groups));
 for(const tuples of [body.source_scopes??[],...Object.values(groups)]){
  requireValue(Array.isArray(tuples));
  for(const tuple of tuples){requireValue(Array.isArray(tuple)&&tuple.length===3&&tuple.every(v=>safeText(v)&&v!=='*'));
   const scope={source_family:tuple[0],source_account_id:tuple[1],scope_key:tuple[2]};result.set(scopeKey(scope),scope);
  }
 }
 return [...result.values()];
}
function allCounts(value:Record<string,unknown>,keys:readonly string[]):boolean {
 requireValue(keys.every(k=>nullable(value[k],integer)));
 const complete=keys.every(k=>value[k]!==null);requireValue(complete||keys.every(k=>value[k]===null));return complete;
}
function parseCopy(raw:unknown):AuditCopy {
 requireValue(exact(raw,['state','reasons',...copyCounts,'checked_at'])&&state(raw.state)&&reasons(raw.reasons)&&nullable(raw.checked_at,time));
 const complete=allCounts(raw,copyCounts);const c=raw as AuditCopy;
 if(complete){
  requireValue(c.expected_events===c.matching_events!+c.missing_events!+c.changed_events!&&c.expected_receipts===c.matching_receipts!+c.missing_receipts!+c.changed_receipts!);
  // Event/receipt counters do not count every established attribution or anchor member.
  const anomalyReasons=['record_missing','bytes_changed','bytes_unreadable','receipt_missing','receipt_changed','sink_record_missing','sink_record_changed','unexpected_member','evidence_missing','evidence_changed','evidence_unreadable'];
  const gap=[c.missing_events,c.changed_events,c.unexpected_events,c.missing_receipts,c.changed_receipts,c.unexpected_receipts].some(n=>n!>0)||c.reasons.some(r=>anomalyReasons.includes(r));
  requireValue(c.checked_at!==null&&c.state===(gap?'gap':c.pending_receipts!>0?'unknown':'verified'));
  if(c.pending_receipts!>0&&!gap)requireValue(c.reasons.includes('source_checkpoint_missing'));
 }else requireValue(['unknown','failed'].includes(c.state));
 if(c.state==='verified')requireValue(c.reasons.length===0);else requireValue(c.reasons.length>0);
 return c;
}
function parseClass(raw:unknown):PreservationClass {
 requireValue(exact(raw,['class_id','minimum_period','state','reasons',...countFields,'oldest_retained_at','baseline_digest','audit_copy'])&&classIds.includes(raw.class_id as ClassId)&&state(raw.state)&&reasons(raw.reasons)&&nullable(raw.oldest_retained_at,time)&&nullable(raw.baseline_digest,baseline));
 const c=raw as PreservationClass;requireValue(c.minimum_period===(c.class_id==='operational.scanner_collection'?'P3M':'P1Y'));
 if(c.class_id==='product.audit_history'){c.audit_copy=parseCopy(c.audit_copy);}else requireValue(c.audit_copy===null);
 const complete=allCounts(raw,countFields);
 const unknownReasons=['baseline_missing','baseline_incomplete','baseline_untrusted','baseline_discontinuous','baseline_replay','baseline_expired','legacy_preimage_unavailable','coverage_unsupported','scope_incomplete','audit_scope_incomplete','environment_unlabelled','report_expired','trust_key_unavailable','trust_config_mismatch','schema_mismatch','future_timestamp'];
 if(c.reasons.some(r=>unknownReasons.includes(r)))requireValue(c.state==='unknown'&&!complete);
 if(c.expected_records===0)requireValue(c.oldest_retained_at===null);
 if(complete){
  requireValue(c.baseline_digest!==null&&c.expected_records===c.verified_records!+c.missing_records!+c.changed_records!+c.unreadable_records!);
  const gap=[c.missing_records,c.changed_records,c.unreadable_records,c.unexpected_records].some(n=>n!>0)||c.audit_copy?.state==='gap';
  requireValue(c.state===(gap?'gap':c.audit_copy?.state==='unknown'?'unknown':'verified'));
  if(c.audit_copy)requireValue(c.audit_copy.expected_events!==null&&c.audit_copy.state!=='failed'&&(!gap||c.audit_copy.state==='gap'));
 }else{
  requireValue(['unknown','failed'].includes(c.state)&&c.oldest_retained_at===null);
  if(c.audit_copy)requireValue(c.audit_copy.expected_events===null);
 }
 if(c.state==='verified')requireValue(c.reasons.length===0);
 if(c.state!=='verified')requireValue(c.reasons.length>0);
 if(c.reasons.includes('audit_scope_incomplete'))requireValue(c.class_id==='product.audit_history'&&c.state==='unknown'&&!complete&&c.baseline_digest===null&&c.audit_copy?.state==='unknown'&&c.audit_copy.checked_at===null&&c.reasons.length===1&&c.audit_copy.reasons.length===1&&c.audit_copy.reasons[0]==='audit_scope_incomplete');
 return c;
}
export function parseSummary(raw:unknown,scope:Scope):Summary {
 requireValue(exact(raw,['schema_version','scope','snapshot_id','checked_at','response_at','valid_until','authority_fingerprint','audit_authority_fingerprint','mask_reasons','environment','classes','uncovered_classes','elapsed_preservation']));
 requireValue(raw.schema_version===1&&validScope(raw.scope)&&scopeKey(raw.scope)===scopeKey(scope)&&nullable(raw.snapshot_id,uuid)&&nullable(raw.checked_at,time)&&time(raw.response_at)&&nullable(raw.valid_until,time)&&digest(raw.authority_fingerprint)&&nullable(raw.audit_authority_fingerprint,digest)&&reasons(raw.mask_reasons)&&nullable(raw.environment,v=>safeText(v,256))&&raw.elapsed_preservation==='unverified');
 requireValue(Array.isArray(raw.classes)&&raw.classes.length===3);const classes=raw.classes.map(parseClass);
 requireValue(new Set(classes.map(c=>c.class_id)).size===3&&sortedUnique(raw.uncovered_classes,classIds));
 requireValue(JSON.stringify(raw.uncovered_classes)===JSON.stringify(classes.filter(c=>c.state!=='verified').map(c=>c.class_id).sort()));
 const s={...raw,classes} as Summary;
 if(s.snapshot_id===null)requireValue(s.checked_at===null&&s.valid_until===null&&classes.every(c=>c.state==='unknown'&&c.expected_records===null&&c.baseline_digest===null));
 requireValue((s.checked_at===null)===(s.valid_until===null));
 if(s.checked_at!==null&&s.valid_until!==null)requireValue(Date.parse(s.checked_at)<=Date.parse(s.valid_until));
 const audit=classes.find(c=>c.class_id==='product.audit_history')!;
 const auditMasked=audit.reasons.includes('audit_scope_incomplete');
 requireValue((s.audit_authority_fingerprint===null)===auditMasked&&s.mask_reasons.includes('audit_scope_incomplete')===auditMasked&&audit.audit_copy!.reasons.includes('audit_scope_incomplete')===auditMasked);
 if(classes.every(c=>c.state==='verified'))requireValue(s.checked_at!==null&&s.valid_until!==null);
 if(s.environment===null)requireValue(classes.every(c=>c.state==='unknown'&&c.expected_records===null&&c.reasons.includes('environment_unlabelled')));
 if(s.valid_until!==null&&Date.parse(s.valid_until)<Date.parse(s.response_at))requireValue(classes.every(c=>c.state==='unknown'&&c.expected_records===null&&c.reasons.includes('report_expired')));
 return s;
}
export function safeEvidencePath(value:unknown):value is string {
 return typeof value==='string'&&/^\/api\/v1\/operations\/preservation\/evidence\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
}
const byteKinds=['observation','evidence_registration'];
function parseItem(raw:unknown,classId:ClassId):RecordItem {
 requireValue(exact(raw,['record_key','record_kind','retained_at','state','reasons','expected_sha256','actual_sha256','record_sha256','readback_url'])&&safeText(raw.record_key)&&recordKinds[classId].includes(raw.record_kind as string)&&nullable(raw.retained_at,time)&&['verified','missing','changed','unreadable','unexpected'].includes(raw.state as string)&&reasons(raw.reasons));
 requireValue(['expected_sha256','actual_sha256','record_sha256'].every(k=>nullable(raw[k],digest))&&nullable(raw.readback_url,safeEvidencePath));
 const r=raw as RecordItem;const bytes=byteKinds.includes(r.record_kind);
 if(!bytes)requireValue(r.expected_sha256===null&&r.actual_sha256===null&&r.readback_url===null);
 if(r.readback_url!==null)requireValue(r.record_kind==='evidence_registration');
 if(r.state==='missing')requireValue(r.actual_sha256===null&&r.record_sha256===null);
 else requireValue(r.record_sha256!==null);
 if(r.state==='unreadable')requireValue(r.actual_sha256===null);
 if(r.state==='unexpected')requireValue(r.expected_sha256===null);
 if(r.state==='verified'){requireValue(r.reasons.length===0);if(bytes)requireValue(r.expected_sha256!==null&&r.expected_sha256===r.actual_sha256);}
 if(r.state==='changed'&&bytes&&r.expected_sha256!==null&&r.actual_sha256!==null)requireValue((r.expected_sha256!==r.actual_sha256)===r.reasons.includes('bytes_changed'));
 return r;
}
function utf8Order(a:string,b:string){const x=new TextEncoder().encode(a),y=new TextEncoder().encode(b);for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]-y[i];return x.length-y.length;}
export function compareRecords(a:RecordItem,b:RecordItem){return utf8Order(a.record_kind,b.record_kind)||utf8Order(a.record_key,b.record_key);}
export function parsePage(raw:unknown,snapshot:string,classId:ClassId,limit=50):RecordPage {
 requireValue(exact(raw,['schema_version','snapshot_id','class_id','items','next_cursor'])&&raw.schema_version===1&&raw.snapshot_id===snapshot&&raw.class_id===classId&&Array.isArray(raw.items)&&raw.items.length<=limit&&nullable(raw.next_cursor,v=>safeText(v,16384)));
 const items=raw.items.map(r=>parseItem(r,classId));requireValue(new Set(items.map(r=>r.record_key)).size===items.length&&items.every((r,i)=>i===0||compareRecords(items[i-1],r)<0));
 requireValue(items.length>0||raw.next_cursor===null);return {...raw,items} as RecordPage;
}
async function get(path:string,signal?:AbortSignal):Promise<unknown>{
 try{const response=await sessionFetch(path,{signal:signal?AbortSignal.any([signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000),headers:{Accept:'application/json'}});if(!response.ok){const code=await response.json().then(errorCode).catch(()=>'unavailable');throw new PreservationError(Object.hasOwn(messages,code)?code:response.status===404?'not_found':response.status===403?'forbidden':'unavailable',response.status);}return await response.json();}
 catch(error){if(error instanceof PreservationError||signal?.aborted)throw error;throw new PreservationError('unavailable');}
}
export const readSummary=async(scope:Scope,signal?:AbortSignal)=>parseSummary(await get('/api/v1/operations/preservation?'+new URLSearchParams(scope),signal),scope);
export const readRecords=async(snapshot:string,classId:ClassId,cursor:string|null,signal?:AbortSignal)=>parsePage(await get('/api/v1/operations/preservation/records?'+new URLSearchParams({snapshot_id:snapshot,class_id:classId,limit:'50',...(cursor?{cursor}:{})}),signal),snapshot,classId);
// Fetch only after an explicit click; never render or retain private payload text.
export async function downloadEvidence(path:string,admittedRawDigest:string|null,signal?:AbortSignal):Promise<void>{
 if(!safeEvidencePath(path)||!digest(admittedRawDigest))throw new PreservationError('invalid_response');
 const response=await sessionFetch(path,{signal:signal?AbortSignal.any([signal,AbortSignal.timeout(30000)]):AbortSignal.timeout(30000),headers:{Accept:'application/octet-stream'}});
 if(!response.ok){const code=await response.json().then(errorCode).catch(()=>'unavailable');throw new PreservationError(Object.hasOwn(messages,code)?code:response.status===404?'not_found':'unavailable',response.status);}
 const disposition=response.headers.get('content-disposition')??'';
 requireValue(response.headers.get('content-type')==='application/octet-stream'&&response.headers.get('x-content-type-options')==='nosniff'&&/^attachment;/.test(disposition)&&/^sha-256=:[A-Za-z0-9+/]{43}=:$/ .test(response.headers.get('content-digest')??''));
 // This digest was admitted with the selected report item, independently of this response.
 const admittedHex=admittedRawDigest!.replace(/^sha256:/,'');
 const admittedHeader='sha-256=:'+btoa(String.fromCharCode(...admittedHex.match(/../g)!.map(byte=>parseInt(byte,16))))+':';
 if(response.headers.get('content-digest')!==admittedHeader)throw new PreservationError('evidence_changed');
 const bytes=await response.arrayBuffer();requireValue(response.headers.get('content-length')===String(bytes.byteLength));
 signal?.throwIfAborted();
 const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));if('sha-256=:'+btoa(String.fromCharCode(...hash))+':'!==admittedHeader)throw new PreservationError('evidence_changed');
 signal?.throwIfAborted();
 const url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));const link=document.createElement('a');link.href=url;link.download='evidence-'+path.split('/').pop()+'.bin';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
