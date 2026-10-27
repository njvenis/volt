import {sessionFetch, errorCode} from './session';
export type Quality = { status: string; reasons: string[] };
export type Run = { run_id: string; revision: number; source_family: string; source_account_id: string; scope_key: string; state: string; expected_at: string | null; started_at: string | null; ended_at: string | null; quality: {retrieval: Quality; coverage: Quality; freshness: Quality}; ce_operation: {status: string; operation_id: string} | null };
export type Health = {event_id:string; condition:string; severity:string; state:string; detected_at:string; observed_at:string; run_id:string|null; expected_run_id:string|null; notification:{intent:string|null; delivery:string|null}};
export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
export type CandidateExplanation = {reason:string; [key:string]:JsonValue} & ({workload_id:string} | {field:string;value:JsonValue});
export type Unresolved = {resolution_id:string; revision:number; observation_id:string; group_id:string|null; outcome:string; reason:string; candidate_workload_ids:string[]; candidate_explanations:CandidateExplanation[]; evaluated_at:string; temporal_status:string; manifest_associations:ManifestAssociation[]};
export type ManifestAssociation = {manifest_id:string; disposition:string; resolution_id:string|null; resolution_revision:number|null; occurrence_id:string|null; blocked_reason:string|null; source_run_operation:{operation_id:string;status:string;revision:number}; occurrence_links:{link_id:string;occurrence_id:string;mapping_revision:number;test_id:number;finding_id:number;endpoint_id:number|null;recorded_at:string}[]};
export type Page<T> = {schema_version:1; as_of:string; items:T[]; next_cursor:string|null};
export type Detail = {schema_version:1; as_of:string; run: Omit<Run,'quality'|'ce_operation'> & {retrieval_status:string;retrieval_reasons:string[];coverage_status:string;coverage_reasons:string[];freshness_status:string;freshness_reasons:string[]}; attempts:{attempt_no:number; started_at:string; finished_at:string|null; response_class:string; success:boolean; error_code:string|null; retry_after_microseconds:number|null}[]; pages:{ordinal:number; attempt_no:number; response_class:string; record_count:number; failed:boolean; is_terminal:boolean; evidence_digest:string; page_ref:string; cursor:string|null;next_cursor:string|null}[]; evidence:{evidence_id:string;evidence_ref:string;sha256:string;kind:string}[]; ce_operations:{operation_id:string;status:string;revision:number;test_id:string|null;bound_test_id:string|null;mapping_revision:number|null;error_code:string|null;post_issued:boolean;reconciled:boolean}[]; observations:{observation_id:string;source_record_ordinal:number;observed_at:string|null;collected_at:string}[];observations_next_cursor:string|null};
export class ApiError extends Error { constructor(public status:number, message:string, public code='request_failed') {super(message);} get restartPagination(){return this.code==='invalid_cursor'||this.code==='read_snapshot_too_large';} }
export async function read<T>(path:string, token:string, signal:AbortSignal):Promise<T> {
  let response:Response;
  try { response=await sessionFetch('/api/v1/'+path,{method:'GET',headers:{},cache:'no-store',signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])}); }
  catch(e) { if(signal.aborted) throw e; throw new ApiError(0,'VOLT could not be reached. Check your connection and try again.'); }
  if(!response.ok) {
    let code='request_failed';
    try {const body=await response.json();code=errorCode(body);} catch { /* Error body is never exposed as raw text. */ }
    const message=code==='invalid_cursor'?'This saved page has expired or is no longer available.':code==='read_snapshot_too_large'?'This list can no longer be continued. Reload it to see current results.':code==='read_dependency_unavailable'?'The service is temporarily unavailable. Try again.':response.status===403?'You do not have access to this information.':response.status===401?'Your session has ended. Sign in again.':response.status===409?'The data has changed. Refresh and try again.':response.status===400?'The request is invalid.':response.status===404?'This run was not found.':'VOLT could not load this information. Try again.';
    throw new ApiError(response.status,message,code);
  }
  let data;
  try {data=await response.json();} catch {throw new ApiError(502,'VOLT returned information this page could not read. Refresh or contact your administrator if this continues.');}
  if(!validPayload(path,data)) throw new ApiError(502,'Some information needed by this page is missing or unsupported. Refresh or contact your administrator if this continues.');
  return data as T;
}

// Validate the display boundary before rendering. This checks shape only; all
// quality, identity, temporal and permission decisions remain server-owned.
type JsonObject = Record<string, unknown>;
const object = (x:unknown):x is JsonObject => x !== null && typeof x==='object' && !Array.isArray(x);
const string = (x:unknown):x is string => typeof x==='string';
const nullableString = (x:unknown) => x===null || string(x);
const number = (x:unknown) => typeof x==='number' && Number.isFinite(x);
const timestamp = (x:unknown) => string(x) && x.endsWith('Z') && Number.isFinite(Date.parse(x));
const nullableTime = (x:unknown) => x===null || timestamp(x);
const strings = (x:unknown) => Array.isArray(x) && x.every(string);
const fields = (x:JsonObject,names:string[],test:(value:unknown)=>boolean) => names.every(k=>test(x[k]));
const rows = (x:unknown,test:(value:JsonObject)=>boolean) => Array.isArray(x) && x.every(r=>object(r)&&test(r));
const quality = (x:unknown) => object(x) && string(x.status) && strings(x.reasons);
const runFields = (x:JsonObject) => fields(x,['run_id','source_family','source_account_id','scope_key','state'],string) && number(x.revision) && fields(x,['expected_at','started_at','ended_at'],nullableTime);
function validPayload(path:string,x:unknown):boolean {
  if(!object(x) || x.schema_version!==1 || !timestamp(x.as_of)) return false;
  if(path.startsWith('ingestion/runs/')) return object(x.run) && runFields(x.run)
    && fields(x.run,['retrieval_status','coverage_status','freshness_status'],string)
    && fields(x.run,['retrieval_reasons','coverage_reasons','freshness_reasons'],strings)
    && rows(x.attempts,a=>number(a.attempt_no)&&timestamp(a.started_at)&&nullableTime(a.finished_at)&&string(a.response_class)&&typeof a.success==='boolean'&&nullableString(a.error_code)&&(a.retry_after_microseconds===null||number(a.retry_after_microseconds)))
    && rows(x.pages,p=>fields(p,['ordinal','attempt_no','record_count'],number)&&fields(p,['response_class','evidence_digest','page_ref'],string)&&fields(p,['cursor','next_cursor'],nullableString)&&typeof p.failed==='boolean'&&typeof p.is_terminal==='boolean')
    && rows(x.evidence,e=>fields(e,['evidence_id','evidence_ref','sha256','kind'],string))
    && rows(x.ce_operations,o=>fields(o,['operation_id','status'],string)&&number(o.revision)&&fields(o,['test_id','bound_test_id'],nullableString)&&(o.mapping_revision===null||number(o.mapping_revision))&&nullableString(o.error_code)&&typeof o.post_issued==='boolean'&&typeof o.reconciled==='boolean')
    && nullableString(x.observations_next_cursor) && rows(x.observations,o=>string(o.observation_id)&&number(o.source_record_ordinal)&&nullableTime(o.observed_at)&&timestamp(o.collected_at));
  if(!nullableString(x.next_cursor)) return false;
  if(path.startsWith('ingestion/runs?')) return rows(x.items,r=>runFields(r)&&object(r.quality)&&quality(r.quality.retrieval)&&quality(r.quality.coverage)&&quality(r.quality.freshness)&&(r.ce_operation===null||(object(r.ce_operation)&&fields(r.ce_operation,['operation_id','status'],string))));
  if(path.startsWith('integrations/health?')) return rows(x.items,h=>fields(h,['event_id','condition','severity','state'],string)&&fields(h,['detected_at','observed_at'],timestamp)&&fields(h,['run_id','expected_run_id'],nullableString)&&object(h.notification)&&fields(h.notification,['intent','delivery'],nullableString));
  if(path.startsWith('unresolved?')) return rows(x.items,u=>fields(u,['resolution_id','observation_id','outcome','reason','temporal_status'],string)&&number(u.revision)&&timestamp(u.evaluated_at)&&nullableString(u.group_id)&&strings(u.candidate_workload_ids)&&rows(u.candidate_explanations,explanation)&&rows(u.manifest_associations,association));
  return false;
}

function association(a:JsonObject):boolean {
 return fields(a,['manifest_id','disposition'],string)&&fields(a,['resolution_id','occurrence_id','blocked_reason'],nullableString)&&(a.resolution_revision===null||number(a.resolution_revision))
   &&object(a.source_run_operation)&&fields(a.source_run_operation,['operation_id','status'],string)&&number(a.source_run_operation.revision)
   &&rows(a.occurrence_links,l=>fields(l,['link_id','occurrence_id'],string)&&fields(l,['mapping_revision','test_id','finding_id'],number)&&(l.endpoint_id===null||number(l.endpoint_id))&&timestamp(l.recorded_at));
}

// Resolver explanations can concern a field without selecting any workload.
// Preserve every JSON evidence member, including null and structured values.
function jsonValue(value:unknown):boolean {
 return value===null || string(value) || typeof value==='boolean' || number(value)
  || (Array.isArray(value)?value.every(jsonValue):object(value)&&Object.values(value).every(jsonValue));
}
function explanation(value:JsonObject):boolean {
 const hasField='field' in value, hasValue='value' in value;
 return string(value.reason) && Object.values(value).every(jsonValue)
  && (!('workload_id' in value)||string(value.workload_id))
  && hasField===hasValue && (!hasField||string(value.field))
  && (string(value.workload_id)||(hasField&&hasValue));
}
