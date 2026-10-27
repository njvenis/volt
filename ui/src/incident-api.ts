import {ApiError} from './api';
import {errorCode, sessionFetch} from './session';

export type IncidentTransition = {
  transition_id:string; deployment_id:string; subject_id:string; condition:string;
  transition_sequence:number; predecessor_id:string|null; episode_id:string;
  opening_transition_id:string; episode_generation:number; configuration_revision:number;
  transition_kind:'opened'|'observed'|'recovered'; first_detected_at:string;
  observed_at:string; recovered_at:string|null; evidence_refs:string[];
  notification:{state:'pending'|'accepted'|'failed'|'uncertain'|null;
    attempts:{attempt_id:string; outcome:'pending'|'accepted'|'failed'|'uncertain'; attempted_at:string}[]};
};
export type IncidentPage = {schema_version:1; items:IncidentTransition[]; next_offset:number|null};
const object=(x:unknown):x is Record<string,unknown>=>!!x&&typeof x==='object'&&!Array.isArray(x);
const string=(x:unknown)=>typeof x==='string'&&x.length>0;
const time=(x:unknown)=>typeof x==='string'&&x.endsWith('Z')&&Number.isFinite(Date.parse(x));
const integer=(x:unknown)=>Number.isSafeInteger(x)&&Number(x)>0;
const outcomes=['pending','accepted','failed','uncertain'];
export function isIncidentPage(x:unknown):x is IncidentPage {
  return object(x)&&x.schema_version===1&&(x.next_offset===null||integer(x.next_offset))&&Array.isArray(x.items)&&x.items.every(i=>
    object(i)&&['transition_id','deployment_id','subject_id','condition','episode_id','opening_transition_id'].every(k=>string(i[k]))&&
    ['transition_sequence','episode_generation','configuration_revision'].every(k=>integer(i[k]))&&
    (i.predecessor_id===null||string(i.predecessor_id))&&typeof i.transition_kind==='string'&&['opened','observed','recovered'].includes(i.transition_kind)&&
    time(i.first_detected_at)&&time(i.observed_at)&&(i.recovered_at===null||time(i.recovered_at))&&
    (i.transition_kind==='recovered')===(i.recovered_at!==null)&&Array.isArray(i.evidence_refs)&&i.evidence_refs.every(string)&&
    object(i.notification)&&(i.notification.state===null||typeof i.notification.state==='string'&&outcomes.includes(i.notification.state))&&
    Array.isArray(i.notification.attempts)&&i.notification.attempts.every(a=>object(a)&&string(a.attempt_id)&&typeof a.outcome==='string'&&outcomes.includes(a.outcome)&&time(a.attempted_at)));
}
export async function readIncidents(query:URLSearchParams,signal:AbortSignal):Promise<IncidentPage>{
  let response:Response;
  try{response=await sessionFetch('/api/v1/integrations/incidents?'+query,{method:'GET',cache:'no-store',signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])});}
  catch(error){if(signal.aborted)throw error;throw new ApiError(0,'The incident service could not be reached. Observation and recovery remain unverified.');}
  if(!response.ok){let code='request_failed';try{code=errorCode(await response.json());}catch{/* Never display untrusted diagnostics. */}
    throw new ApiError(response.status,response.status===403?'Your current access does not allow this incident view.':response.status===401?'Sign in again to read incidents.':response.status===409||code==='invalid_cursor'||code==='invalid_pagination'?'This page can no longer be continued. Reload the first page.':'Incidents could not be loaded. Try again.',code);}
  let data:unknown;try{data=await response.json();}catch{throw new ApiError(502,'The incident response could not be read.');}
  if(!isIncidentPage(data))throw new ApiError(502,'The incident response is incomplete or unsupported. Observation remains unverified.');
  return data;
}
