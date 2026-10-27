import {useEffect, useRef, useState, type FormEvent} from 'react';
import {AssessmentError} from './assessment-api';
import {DataTable, EvidenceLink, Message, Status, UTC} from './assessment-components';
import {emptyFindingFilters, FindingListFrame, FindingsFilters, type FindingFilters} from './FindingsControls';
import {findingQuery, getFindings, type FindingListDTO, type FindingListItem} from './findings-api';
import {getReport, type ReadyReportDTO} from './report-api';

function errorDetails(error:AssessmentError){
  const kind=error.status===401||error.status===403?'forbidden':error.status===409?'stale':error.status===400?'invalid':'unavailable';
  const message=error.status===401?'Your session has ended. Sign in again to continue.':error.status===403?'Your current permissions do not allow this view. No finding or report contents are shown.':error.status===409?'The saved page, underlying data or access rules have changed.':error.status===400?'The filters or saved page are not valid. Reload the first page or change the filters.':error.code==='unsupported_response'?'Some finding details are missing or unsupported. Reload or contact your administrator.':'The findings service could not be reached. Your filters are kept; try again when it is available.';
  return {kind,message} as const;
}
function FindingRow({item,href,selected}:{item:FindingListItem;href:string;selected:boolean}){
  const view=item.group,a=view.assessment;
  return <tr data-finding-group-id={view.group.group_id} data-selected={selected||undefined}>
    <td><span className="finding-source">{view.group.source_family} · {view.group.native_id_scheme}</span><a className="finding-row-link" href={href} data-finding-link={view.group.group_id}>{view.group.native_id_value}</a><small>{view.group.native_id_authority}</small><details><summary>Vulnerability ID</summary><code>{view.group.group_id}</code></details><div className="finding-cves">{item.cves.length?<ul className="finding-reference-list">{item.cves.map(cve=><li key={cve}><a href={'https://www.cve.org/CVERecord?id='+encodeURIComponent(cve)} target="_blank" rel="noopener noreferrer">{cve}<span className="sr-only"> (opens in a new tab)</span></a></li>)}</ul>:<span className="muted">No CVE reference recorded</span>}</div></td>
    <td><Status value={a.native_severity?.value??'unknown'}/><small>Assessed: <Status value={a.assessed_severity?.value??'not assessed'}/></small></td>
    <td>{a.owners.length?<ul className="finding-owner-list">{a.owners.map(owner=><li key={owner.owner_id}><strong>{owner.display_name}</strong><small>{owner.owner_type}</small></li>)}</ul>:<span className="muted">No recorded owners</span>}</td>
    <td><strong data-occurrence-count>{item.occurrence_count}</strong> affected<small><span data-outstanding-count>{item.outstanding_count}</span> still need a fix</small></td>
    <td><details><summary>Instance dates ({a.clocks.length})</summary><p>Dates belong to individual instances. Recorded deadlines alone do not establish SLA compliance.</p>{a.clocks.length?<ul className="finding-clock-list">{a.clocks.map(clock=><li key={clock.occurrence_id}><code>{clock.occurrence_id}</code><dl><dt>First detected</dt><dd><UTC value={clock.first_observed_at}/></dd><dt>Recorded deadline</dt><dd><UTC value={clock.deadline_at}/><small>{clock.deadline_status.replaceAll('_',' ')}</small></dd><dt>Recorded policy</dt><dd>{clock.policy_ref??'Not recorded'}</dd>{clock.deadline_reference&&<><dt>Deadline evidence</dt><dd><EvidenceLink value={clock.deadline_reference.evidence_ref}/></dd></>}</dl></li>)}</ul>:<p>No instance dates available.</p>}</details></td>
    <td><Status value={view.github.state}/>{view.github.discrepancy_codes.length>0&&<details><summary>Update details</summary><ul>{view.github.discrepancy_codes.map(code=><li key={code}>{code.replaceAll('_',' ')}</li>)}</ul></details>}</td>
  </tr>;
}

export default function FindingsWorkspace({token,query,refresh,onContext,groupHref}:{token:string;query:URLSearchParams;refresh:number;onContext:(updates:Record<string,string|null>)=>void;groupHref:(id:string)=>string}){
  const [reload,setReload]=useState(0),[lookup,setLookup]=useState(''),[reportInput,setReportInput]=useState(query.get('report_id')??'');
  const root=useRef<HTMLDivElement>(null),restored=useRef('');
  const canonical=findingQuery(query).toString(),queue=query.get('queue'),needsReport=queue==='sla_gap'&&!query.get('report_id');
  const key=JSON.stringify([token,canonical,refresh,reload]);
  const [result,setResult]=useState<{key?:string;data?:FindingListDTO;report?:ReadyReportDTO;error?:AssessmentError;loading:boolean}>({loading:true});
  const current=result.key===key?result:{loading:!needsReport};
  const data=current.data,report=current.report;
  const values=Object.fromEntries(Object.keys(emptyFindingFilters).map(key=>[key,query.get(key)??''])) as FindingFilters;
  const limit=Number(query.get('limit')??25) as 10|25|50;
  const state=needsReport?'needs-report':current.loading?'loading':current.error?'error':data?'ready':'idle';
  useEffect(()=>{setReportInput(query.get('report_id')??'');},[query.get('report_id')]);
  useEffect(()=>{
    const controller=new AbortController();setResult({key,loading:!needsReport});if(needsReport)return()=>controller.abort();
    const params=new URLSearchParams(canonical);
    Promise.all([getFindings(params,token,controller.signal),params.get('queue')==='sla_gap'?getReport(params.get('report_id')!,token,controller.signal):Promise.resolve(null)]).then(([data,report])=>{
      if(controller.signal.aborted)return;
      if(report&&(report.status!=='ready'||!report.metrics.some(metric=>metric.key==='sla_gaps'&&metric.unit==='atoms')))throw new AssessmentError(report.status==='ready'?502:409,report.status==='ready'?'unsupported_response':'projection_not_ready');
      setResult({key,data,...(report?.status==='ready'?{report}:{}),loading:false});
    }).catch(error=>{if(!controller.signal.aborted)setResult({key,error:error instanceof AssessmentError?error:new AssessmentError(502,'unsupported_response'),loading:false});});
    return()=>controller.abort();
  },[key]);
  useEffect(()=>{
    const selected=query.get('selected');if(!data||!selected||restored.current===key)return;
    const link=[...root.current!.querySelectorAll<HTMLAnchorElement>('[data-finding-link]')].find(link=>link.dataset.findingLink===selected);
    if(link){restored.current=key;link.focus({preventScroll:true});link.scrollIntoView({block:'nearest',inline:'nearest'});}
  },[data,key]);
  function apply(filters:FindingFilters){onContext({...Object.fromEntries(Object.entries(filters).map(([key,value])=>[key,value||null])),cursor:null,selected:null});setReload(n=>n+1);}
  function restart(){onContext({cursor:null});setReload(n=>n+1);}
  function openGroup(event:FormEvent){event.preventDefault();location.hash=groupHref(lookup.trim());}
  const title=queue==='missing_owner'?'Findings without recorded owners':queue==='sync_conflict'?'Findings with sync conflicts':queue==='sla_gap'?'Findings with reported SLA gaps':'Grouped findings';
  const gap=report?.metrics.find(metric=>metric.key==='sla_gaps');
  return <div ref={root} className="findings-workspace" data-findings-state={state} data-findings-query={canonical} data-total-groups={data?.total_groups} data-total-occurrences={data?.total_occurrences} aria-busy={current.loading}>
    {!queue&&<details className="finding-direct-lookup"><summary>Open a finding by ID</summary><form onSubmit={openGroup}><label>Finding ID<input value={lookup} onChange={event=>setLookup(event.target.value)} required autoComplete="off"/></label><button type="submit">Open finding</button></form></details>}
    {queue==='missing_owner'&&<Message title="Recorded ownership">These findings have no current recorded group owners. This is separate from effective ownership coverage in SLA reports.</Message>}
    {queue==='sync_conflict'&&<Message title="Conflicts need review" tone="warning">These findings have a recorded GitHub conflict. Pending, failed and uncertain updates have separate statuses and are not included as conflicts.</Message>}
    {queue==='sla_gap'&&<section className="panel finding-report-choice"><h2>Choose a saved report</h2><p>SLA gaps come from an issued report. They are not recalculated by opening this queue.</p><form onSubmit={event=>{event.preventDefault();onContext({report_id:reportInput,cursor:null,selected:null});setReload(n=>n+1);}}><label>Report ID for SLA gaps<input value={reportInput} onChange={event=>setReportInput(event.target.value)} required autoComplete="off"/></label><button type="submit" disabled={current.loading}>Load SLA gaps</button></form></section>}
    {needsReport?<Message title="A saved report is required">Choose a report you can access before reviewing SLA coverage gaps. No selected report does not mean there are no gaps.</Message>:<>
      <FindingsFilters value={values} sources={data?.filter_options.source_families??[]} owners={data?.filter_options.owners??[]} busy={current.loading} onApply={apply}/>
      {current.error?.code==='projection_not_ready'?<Message title="Report results are not ready">No gap results are shown. Wait for the saved report to finish, then <button onClick={restart}>Check report and gaps</button>.</Message>:<FindingListFrame title={title} loading={current.loading} error={current.error?errorDetails(current.error):undefined} summary={data?{asOf:data.as_of,totalGroups:data.total_groups,totalOccurrences:data.total_occurrences}:undefined} hasRows={!!data?.items.length} onRefresh={restart} onFirst={restart} onNext={()=>onContext({cursor:data?.next_cursor??null,selected:null})} hasPrevious={query.has('cursor')} hasNext={!!data?.next_cursor} limit={limit} onLimit={limit=>onContext({limit:String(limit),cursor:null,selected:null})} context={report&&<section className="notice info" aria-label="Saved SLA gap context"><div><strong>Saved report · SLA coverage gaps</strong><p><span data-report-gap-count>{gap!.numerator}</span> gap findings in the full saved report, counted as {gap!.unit}. These frozen findings are distinct from the current affected-instance totals below; filters may narrow the groups shown.</p><dl className="facts"><div><dt>Report</dt><dd><a href={'#reports?report='+encodeURIComponent(report.report_id)}>{report.report_id}</a></dd></div><div><dt>Risk assessed at</dt><dd><UTC value={report.context.as_of} timezone={report.context.display_timezone}/></dd></div><div><dt>Information available by</dt><dd><UTC value={report.context.known_at} timezone={report.context.display_timezone}/></dd></div></dl></div></section>}>
        <DataTable label="Grouped findings" heads={['Native finding / CVE references','Scanner / assessed severity','People & team owners','Affected instances','Detection / recorded deadlines','GitHub update']}>
          {data?.items.map(item=><FindingRow key={item.group.group.group_id} item={item} href={groupHref(item.group.group.group_id)} selected={query.get('selected')===item.group.group.group_id}/>)}
        </DataTable>
      </FindingListFrame>}
    </>}
  </div>;
}
