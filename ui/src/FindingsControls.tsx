import {useEffect, useId, useState, type FormEvent, type ReactNode} from 'react';
import type {Owner} from './assessment-api';
import {Empty, Message, UTC} from './assessment-components';
import './findings.css';

// Request controls use the reviewed G6 list contract and literal versioned DTO.
export type FindingFilters = {
  native_id:string;
  source_family:string;
  cve:string;
  native_severity:string;
  assessed_severity:string;
  owner_id:string;
};
export const emptyFindingFilters:FindingFilters={native_id:'',source_family:'',cve:'',native_severity:'',assessed_severity:'',owner_id:''};
const severities=[['critical','Critical'],['high','High'],['medium','Medium'],['low','Low'],['informational','Informational']];

export function FindingsFilters({value,sources,owners,busy,onApply}:{value:FindingFilters;sources:string[];owners:Owner[];busy:boolean;onApply:(filters:FindingFilters)=>void}) {
  const [draft,setDraft]=useState(value);
  const id=useId();
  const valueKey=JSON.stringify(value);
  useEffect(()=>{setDraft(value);},[valueKey]);
  function update(key:keyof FindingFilters,value:string){setDraft(previous=>({...previous,[key]:value}));}
  function submit(event:FormEvent){event.preventDefault();if(!busy)onApply({...draft});}
  // Keep exact CVE/owner values. Client controls do not normalise identifiers,
  // calculate effective severity, decide access or filter an already paged list.
  const ownerAvailable=!draft.owner_id||owners.some(owner=>owner.owner_id===draft.owner_id);
  const sourceAvailable=!draft.source_family||sources.includes(draft.source_family);
  return <section className="panel finding-filters" aria-labelledby={id+'-heading'}>
    <div className="panel-head"><div><h2 id={id+'-heading'}>Filter findings</h2><p>Combine filters to narrow the vulnerabilities you can access.</p></div><span className="finding-sort">Native identifier · A–Z</span></div>
    <form aria-labelledby={id+'-heading'} onSubmit={submit}>
      <div className="finding-filter-grid finding-filter-primary">
        <label htmlFor={id+'-native'}>Native identifier<input id={id+'-native'} aria-label="Native identifier" type="search" value={draft.native_id} onChange={event=>update('native_id',event.target.value)} placeholder="Search a scanner vulnerability ID" autoComplete="off"/></label>
        <label htmlFor={id+'-source'}>Scanner source<select id={id+'-source'} aria-label="Scanner source" value={draft.source_family} onChange={event=>update('source_family',event.target.value)}><option value="">All visible sources</option>{!sourceAvailable&&<option value={draft.source_family}>Current filter: {draft.source_family}</option>}{sources.map(source=><option key={source} value={source}>{source}</option>)}</select></label>
      </div>
      <details className="finding-more-filters" open={!!(value.cve||value.owner_id||value.native_severity||value.assessed_severity)}><summary>More filters · CVE, owner and severity</summary><div className="finding-filter-grid">
        <label htmlFor={id+'-cve'}>CVE reference<input id={id+'-cve'} aria-label="CVE reference" type="search" value={draft.cve} onChange={event=>update('cve',event.target.value)} placeholder="Exact CVE reference" autoComplete="off" aria-describedby={id+'-cve-hint'}/><small id={id+'-cve-hint'}>Exact match, including letter case. Shared references keep separate vulnerabilities.</small></label>
        <label htmlFor={id+'-owner'}>Person or team owner<select id={id+'-owner'} aria-label="Person or team owner" aria-describedby={id+'-owner-hint'} value={draft.owner_id} onChange={event=>update('owner_id',event.target.value)}><option value="">All owners and unassigned</option>{!ownerAvailable&&<option value={draft.owner_id}>Current filter: {draft.owner_id}</option>}{owners.map(owner=><option key={owner.owner_id} value={owner.owner_id}>{owner.display_name} ({owner.owner_type})</option>)}</select><small id={id+'-owner-hint'}>Filters recorded group ownership.</small></label>
        <label htmlFor={id+'-native-severity'}>Scanner severity<select id={id+'-native-severity'} aria-label="Scanner severity" value={draft.native_severity} onChange={event=>update('native_severity',event.target.value)}><option value="">Any scanner severity</option>{severities.map(([value,label])=><option key={value} value={value}>{label}</option>)}<option value="unknown">Unknown</option></select></label>
        <label htmlFor={id+'-assessed-severity'}>Assessed severity<select id={id+'-assessed-severity'} aria-label="Assessed severity" value={draft.assessed_severity} onChange={event=>update('assessed_severity',event.target.value)}><option value="">Any assessed severity</option>{severities.map(([value,label])=><option key={value} value={value}>{label}</option>)}<option value="not_assessed">Not assessed</option></select></label>
      </div></details>
      <div className="finding-filter-actions"><p>Scanner severity and assessed severity are separate filters.</p><div className="row wrap"><button type="button" disabled={busy} onClick={()=>{setDraft({...emptyFindingFilters});onApply({...emptyFindingFilters});}}>Clear filters</button><button type="submit" className="primary" disabled={busy}>Apply filters</button></div></div>
    </form>
  </section>;
}

export type UnresolvedCategory='identity'|'missing_owner'|'sla_gap'|'sync_conflict';
const categories:Array<[UnresolvedCategory,string]>=[['identity','Identity matches'],['missing_owner','Missing ownership'],['sla_gap','SLA coverage gaps'],['sync_conflict','Sync conflicts']];
export function UnresolvedCategories({value,onChange}:{value:UnresolvedCategory;onChange:(category:UnresolvedCategory)=>void}) {
  return <nav className="tabs unresolved-categories" aria-label="Unresolved categories">{categories.map(([category,label])=><button key={category} aria-current={category===value?'page':undefined} onClick={()=>onChange(category)}>{label}</button>)}</nav>;
}

export function FindingListFrame({title='Grouped findings',loading,error,summary,hasRows,children,onRefresh,onFirst,onNext,hasPrevious,hasNext,limit,onLimit,context}:{title?:string;loading:boolean;error?:{kind:'forbidden'|'stale'|'invalid'|'unavailable';message:string};summary?:{asOf:string;totalGroups:number;totalOccurrences:number};hasRows:boolean;children:ReactNode;onRefresh:()=>void;onFirst:()=>void;onNext:()=>void;hasPrevious:boolean;hasNext:boolean;limit:10|25|50;onLimit:(value:10|25|50)=>void;context?:ReactNode}) {
  const resultTitle=error?.kind==='forbidden'?'Access denied':error?.kind==='stale'?'These results have changed':error?.kind==='invalid'?'Review the selected filters':'Unable to load findings';
  return <section className="finding-list" aria-label={title}>
    {!loading&&!error&&context}
    <div role="status" aria-live="polite" className="load-status">{loading?'Loading authorised findings…':error?'Findings could not be loaded.':summary?`${summary.totalGroups} vulnerabilities · ${summary.totalOccurrences} affected instances in this selection.`:''}</div>
    {error&&<Message alert title={resultTitle} tone={error.kind==='stale'?'warning':'danger'}><p>{error.message}</p>{error.kind==='stale'&&<p>Refresh before continuing. Your filters are kept; access and results will be checked again.</p>}{error.kind!=='forbidden'&&<div className="card-actions"><button onClick={onRefresh}>Reload findings</button></div>}</Message>}
    {loading&&<div className="panel skeleton" aria-hidden="true"><div/><div/><div/></div>}
    {!loading&&!error&&summary&&<div className="panel"><div className="panel-head"><h2>{title}</h2><span className="muted">Results at <UTC value={summary.asOf}/></span></div>
      {hasRows?children:<Empty title="No findings match this selection">Change or clear the filters to see other findings you can access. An empty result does not establish remediation or SLA compliance.</Empty>}
      <div className="table-foot"><label className="finding-page-size">Vulnerabilities per page<select aria-label="Vulnerabilities per page" value={limit} onChange={event=>onLimit(Number(event.target.value) as 10|25|50)}><option value={10}>10</option><option value={25}>25</option><option value={50}>50</option></select></label><div className="row wrap"><button disabled={!hasPrevious} onClick={onFirst}>First findings page</button><button disabled={!hasNext} onClick={onNext}>Next findings page</button></div></div>
    </div>}
  </section>;
}
