import {useEffect, useRef, useState} from 'react';
import {ApiError} from './api';
import {readIncidents, type IncidentPage, type IncidentTransition} from './incident-api';
import './incidents.css';

const conditions:Record<string,string>={source_integrity:'Audit source integrity',siem_integrity:'SIEM record integrity',siem_export:'SIEM export',container_availability:'Application availability',observer_heartbeat:'Observer heartbeat',notification_failure:'Notification delivery',incident_projection:'Incident projection'};
function Time({value}:{value:string|null}){return value?<time dateTime={value}>{new Date(value).toLocaleString('en-GB',{timeZone:'UTC',year:'numeric',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false})} UTC</time>:<>Not recorded</>;}
function Notification({item}:{item:IncidentTransition}){
 const state=item.notification.state;
 const explanation=state==='accepted'?'The provider accepted this notification. Human acknowledgement is not established.':state==='uncertain'?'Delivery is uncertain. Reconciliation is required before any resend.':state==='failed'?'The delivery attempt failed. Recovery is not established.':state==='pending'?'Notification is pending. Delivery is not established.':'No notification outcome is recorded.';
 return <div className="incident-delivery"><strong>Notification: {state??'unverified'}</strong><p>{explanation}</p></div>;
}
function Transition({item}:{item:IncidentTransition}){
 const recovered=item.transition_kind==='recovered';
 return <article className={'incident-card '+(recovered?'incident-recovered':'incident-active')} aria-labelledby={'incident-'+item.transition_id}>
  <div className="incident-card-heading"><div><div className="eyebrow">{item.transition_kind==='opened'?'EPISODE OPENED':recovered?'RECOVERY RECORDED':'FURTHER OBSERVATION'}</div><h3 id={'incident-'+item.transition_id}>{conditions[item.condition]??'Operational condition'}</h3></div><span className={'badge '+(recovered?'success':'warning')}><span aria-hidden="true">{recovered?'✓':'△'}</span>{recovered?'Recovered at observation':'Active at observation'}</span></div>
  <p className="incident-subject"><strong>{item.deployment_id}</strong><span>{item.subject_id}</span></p>
  <dl className="incident-times"><div><dt>First detected</dt><dd><Time value={item.first_detected_at}/></dd></div><div><dt>Observed</dt><dd><Time value={item.observed_at}/></dd></div><div><dt>Recovery recorded</dt><dd><Time value={item.recovered_at}/></dd></div></dl>
  <Notification item={item}/>
  <details><summary>Episode, notification history & evidence</summary><div className="incident-detail">
   <dl className="incident-identifiers"><div><dt>Episode ID</dt><dd>{item.episode_id}</dd></div><div><dt>Episode generation</dt><dd>{item.episode_generation}</dd></div><div><dt>Transition ID</dt><dd>{item.transition_id}</dd></div><div><dt>Stream sequence</dt><dd>{item.transition_sequence}</dd></div><div><dt>Opening transition</dt><dd>{item.opening_transition_id}</dd></div><div><dt>Previous transition</dt><dd>{item.predecessor_id??'First in stream'}</dd></div><div><dt>Configuration revision</dt><dd>{item.configuration_revision}</dd></div><div><dt>Condition code</dt><dd>{item.condition}</dd></div></dl>
   <h4>Notification attempts</h4>{item.notification.attempts.length?<ul>{item.notification.attempts.map(a=><li key={a.attempt_id}><strong>{a.outcome}</strong> · <Time value={a.attempted_at}/><code>{a.attempt_id}</code></li>)}</ul>:<p>No attempts are recorded in this response.</p>}
   <h4>Permitted evidence references</h4><p>References are shown as text. They are not downloaded or treated as proof of coverage.</p>{item.evidence_refs.length?<ul>{item.evidence_refs.map((ref,index)=><li key={index}><code>{ref}</code></li>)}</ul>:<p>No evidence references are recorded.</p>}
  </div></details>
 </article>;
}
export default function OperationsIncidents({refresh,query,onContext}:{refresh:number;query:URLSearchParams;onContext:(updates:Record<string,string|null>)=>void}){
 const offset=Number(query.get('offset')??0),limit=['10','25','50'].includes(query.get('limit')??'')?query.get('limit')!:'25';
 const params=new URLSearchParams({limit,offset:String(Number.isSafeInteger(offset)&&offset>=0&&offset<=10000?offset:0)});
 for(const key of ['deployment_id','group_id'])if(query.get(key))params.set(key,query.get(key)!);
 const path=params.toString(),[retry,setRetry]=useState(0),key=JSON.stringify([path,refresh,retry]);
 const [state,setState]=useState<{key:string;data?:IncidentPage;error?:ApiError}>({key:''});
 const pagingFocus=useRef(false),first=useRef<HTMLButtonElement>(null),next=useRef<HTMLButtonElement>(null);
 const current=state.key===key?state:undefined,loading=!current;
 useEffect(()=>{const controller=new AbortController();setState({key:''});readIncidents(new URLSearchParams(path),controller.signal).then(data=>{if(!controller.signal.aborted)setState({key,data});}).catch(e=>{if(!controller.signal.aborted)setState({key,error:e instanceof ApiError?e:new ApiError(502,'Incidents could not be displayed.')});});return()=>controller.abort();},[key,path]);
 useEffect(()=>{if(current&&pagingFocus.current){(current.data?.next_offset!==null&&current.data?next.current:first.current)?.focus();pagingFocus.current=false;}},[current]);
 function reload(){onContext({offset:null,cursor:null});setRetry(n=>n+1);}
 return <section className="incidents-workspace" aria-label="Operations incidents">
  <div className="incident-coverage"><div><div className="eyebrow">OBSERVATION BOUNDARY</div><h2>Coverage remains unverified</h2><p>Only previously anchored events can be checked against independent history. Events lost before anchoring may be undetectable.</p></div><dl><div><dt>Anchoring coverage</dt><dd>Unverified · not supplied</dd></div><div><dt>Last successful observation</dt><dd>Unverified · not supplied</dd></div><div><dt>Projection freshness / backlog</dt><dd>Unverified · not supplied</dd></div></dl></div>
  <div className="incident-toolbar"><div><h2>Incident history</h2><p>Authorised transitions · all times UTC</p></div><div className="row wrap"><label>Transitions per page <select value={limit} onChange={e=>onContext({limit:e.target.value,offset:null,cursor:null})}><option>10</option><option>25</option><option>50</option></select></label><button onClick={reload} disabled={loading}>Reload incidents</button></div></div>
  {(params.has('deployment_id')||params.has('group_id'))&&<p className="incident-filter">Filtered incident view <button onClick={()=>onContext({deployment_id:null,group_id:null,offset:null})}>Clear filters</button></p>}
  <p className="incident-boundary">Each entry records an episode at its observation time, not its current status. Later transitions may be on another page. Refresh rechecks current access; this is not a live monitoring feed.</p>
  <div role="status" aria-live="polite">{loading?'Loading authorised incidents…':current?.error?'Incident information is unavailable.':`${current?.data?.items.length??0} authorised transitions on this page.`}</div>
  {loading&&<div className="panel skeleton" aria-hidden="true"><div/><div/><div/></div>}
  {current?.error&&<div role="alert" className="incident-error"><h3>{current.error.status===403?'Access denied':current.error.status===401?'Session ended':current.error.status===409||current.error.restartPagination||current.error.code==='invalid_pagination'?'Reload this incident history':'Unable to load incidents'}</h3><p>{current.error.message}</p><p>Previously displayed records have been cleared. No recovery or healthy state is implied.</p><button onClick={reload}>Reload first page</button></div>}
  {current?.data&&<>{current.data.items.length?current.data.items.map(item=><Transition key={item.transition_id} item={item}/>):<div className="panel empty"><h3>No visible incident transitions</h3><p>No records are available to this session on this page. This does not establish health, complete observation or recovery.</p></div>}
   <div className="table-foot"><span>Page contents only · no global incident count</span><div className="row"><button ref={first} onClick={()=>{pagingFocus.current=true;reload();}}>First incident page</button><button ref={next} disabled={current.data.next_offset===null||current.data.next_offset>10000} onClick={()=>{pagingFocus.current=true;onContext({offset:String(current.data!.next_offset),cursor:null});}}>Next incidents →</button></div></div>
   {current.data.next_offset!==null&&current.data.next_offset>10000&&<p role="status">The API paging limit has been reached. History remains incomplete; narrow the scope or reload.</p>}</>}
  <p className="footnote">Provider acceptance is separate from human acknowledgement. Acknowledgement does not recover an incident. This read-only workspace does not reassess findings. Outage observations may arrive after the application recovers; detection times remain unchanged.</p>
 </section>;
}
