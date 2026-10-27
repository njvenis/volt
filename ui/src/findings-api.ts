import {AssessmentError, validGroup, type GroupView, type Owner} from './assessment-api';
import {reportRequest} from './report-api';

export type FindingListItem={group:GroupView;cves:string[];occurrence_count:number;outstanding_count:number};
export type FindingListDTO={schema_version:1;as_of:string;items:FindingListItem[];total_groups:number;total_occurrences:number;next_cursor:string|null;filter_options:{source_families:string[];cves:string[];owners:Owner[]}};
export const findingQueryKeys=['native_id','source_family','cve','native_severity','assessed_severity','owner_id','queue','report_id','limit','cursor'] as const;
export function findingQuery(params:URLSearchParams){
  const query=new URLSearchParams();
  for(const key of findingQueryKeys){const value=params.get(key);if(value!==null&&value!=='')query.set(key,value);}
  if(!query.has('limit'))query.set('limit','25');
  return query;
}
const object=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const string=(v:unknown):v is string=>typeof v==='string';
const count=(v:unknown):v is number=>Number.isSafeInteger(v)&&Number(v)>=0;
const strings=(v:unknown):v is string[]=>Array.isArray(v)&&v.every(string)&&new Set(v).size===v.length;
const owners=(v:unknown):v is Owner[]=>Array.isArray(v)&&v.every(o=>object(o)&&string(o.owner_id)&&string(o.display_name)&&['person','team'].includes(String(o.owner_type)))&&new Set(v.map(o=>o.owner_id)).size===v.length;
export function validFindingList(v:unknown):v is FindingListDTO{
  if(!object(v)||v.schema_version!==1||!string(v.as_of)||!/(Z|\+00:00)$/.test(v.as_of)||!Number.isFinite(Date.parse(v.as_of))||!count(v.total_groups)||!count(v.total_occurrences)||!(v.next_cursor===null||string(v.next_cursor)&&v.next_cursor.length>0)||!Array.isArray(v.items)||!object(v.filter_options))return false;
  if(!strings(v.filter_options.source_families)||!strings(v.filter_options.cves)||!owners(v.filter_options.owners))return false;
  if(!v.items.every(item=>object(item)&&validGroup(item.group)&&strings(item.cves)&&count(item.occurrence_count)&&count(item.outstanding_count)))return false;
  const items=v.items as FindingListItem[];
  return new Set(items.map(item=>item.group.group.group_id)).size===items.length&&items.length<=v.total_groups;
}
export async function getFindings(params:URLSearchParams,token:string,signal?:AbortSignal):Promise<FindingListDTO>{
  const query=findingQuery(params),data=await reportRequest('assessment/groups?'+query,token,undefined,signal);
  if(!validFindingList(data))throw new AssessmentError(502,'unsupported_response');
  // Reject a broken category contract wholesale; never silently refilter it and
  // present changed counts as though the server supplied them.
  if(query.get('queue')==='sync_conflict'&&data.items.some(item=>item.group.github.state!=='conflict'))throw new AssessmentError(502,'unsupported_response');
  if(query.get('queue')==='missing_owner'&&data.items.some(item=>item.group.assessment.owners.length!==0))throw new AssessmentError(502,'unsupported_response');
  return data;
}
