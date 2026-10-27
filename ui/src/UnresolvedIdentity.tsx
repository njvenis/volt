import {useEffect, useRef} from 'react';
import type {CandidateExplanation, ManifestAssociation, Page, Unresolved} from './api';
import {DataTable, Message, Status, UTC} from './assessment-components';

const matchingReasons:Record<string,string>={
  'reused asset locator; incarnation unresolved':'The source reused an asset identifier, but its uniqueness has not been verified.',
  'missing native identifier key':'The scanner’s native vulnerability identifier is missing.',
  'ambiguous workload correspondence; queued, no match guessed':'More than one workload fits the recorded evidence. No match has been selected.',
  'no stable workload attributes supplied; no match guessed':'The source did not supply stable workload attributes that could support a match.'
};
const matchingReason=(reason:string)=>matchingReasons[reason]??reason;

function MatchStatus({outcome}:{outcome:string}) {
  return <span className="badge warning"><span aria-hidden="true">△</span>{outcome==='ambiguous'?'Several possible matches':outcome==='unresolved'?'Match unresolved':outcome.replaceAll('_',' ')}</span>;
}

export function IdentityEvidence({items}:{items:CandidateExplanation[]}) {
  return items.length?<ol className="identity-evidence">{items.map((item,index)=><li key={index} data-explanation>
    <p>{item.reason}</p>
    {'workload_id' in item&&<p className="candidate-reference">Candidate workload <code>{String(item.workload_id)}</code></p>}
    <details><summary>Matching evidence fields</summary><dl>{Object.entries(item).map(([key,value])=><div key={key}><dt>{key}</dt><dd>{key==='reason'?String(value):<code>{JSON.stringify(value)}</code>}</dd></div>)}</dl></details>
  </li>)}</ol>:<p className="muted">No matching evidence was supplied for this record. No workload is selected.</p>;
}

export function ImportAssociations({items}:{items:ManifestAssociation[]}) {
  if(!items.length)return <Message title="No related import records">This view has no import association for this scan record. That does not establish whether it was imported into DefectDojo or matched to an instance.</Message>;
  return <div className="identity-imports">{items.map(a=><article key={a.manifest_id} data-manifest-id={a.manifest_id}>
    <div className="identity-import-summary"><div><h4>This scan record</h4><Status value={a.disposition}/><p>{a.disposition==='blocked'?'Blocked from this import.':a.disposition==='excluded_reviewed'?'Excluded from this import after review.':a.disposition==='included'?'Included in this import record.':'Inclusion is not confirmed by this disposition.'} {['blocked','excluded_reviewed'].includes(a.disposition)&&'This is not proof of import or remediation.'}</p>{a.blocked_reason&&<p>Recorded reason: {a.blocked_reason}</p>}</div>
      <div><h4>Whole source-run import</h4><Status value={a.source_run_operation.status}/><p>A completed import does not establish a match for this scan record.</p></div></div>
    <p className="permission-note">{a.occurrence_links.length?'Verified import links are retained evidence. They do not replace the current unresolved matching result.':'No verified instance link is supplied for this association.'}</p>
    <details><summary>Import and instance-link evidence</summary><dl className="facts">
      <div><dt>Import record ID</dt><dd><code>{a.manifest_id}</code></dd></div>
      <div><dt>Matching record / revision</dt><dd><code>{a.resolution_id??'Not recorded'}</code> / {a.resolution_revision??'Not recorded'}</dd></div>
      <div><dt>Imported instance ID</dt><dd><code>{a.occurrence_id??'Not recorded'}</code></dd></div>
      <div><dt>Import operation / revision</dt><dd><code>{a.source_run_operation.operation_id}</code> / {a.source_run_operation.revision}</dd></div>
    </dl>{a.occurrence_links.map(link=><dl className="facts" key={link.link_id}>
      <div><dt>Verified link ID</dt><dd><code>{link.link_id}</code></dd></div><div><dt>Instance ID</dt><dd><code>{link.occurrence_id}</code></dd></div><div><dt>Match version</dt><dd>{link.mapping_revision}</dd></div>
      <div><dt>CE Test / Finding / Endpoint</dt><dd>{link.test_id} / {link.finding_id} / {link.endpoint_id??'Not recorded'}</dd></div><div><dt>Link recorded</dt><dd><UTC value={link.recorded_at}/></dd></div>
    </dl>)}</details>
  </article>)}</div>;
}

export default function UnresolvedIdentity({data,selectedId,onInspect,groupHref}:{data:Page<Unresolved>;selectedId:string|null;onInspect:(id:string|null)=>void;groupHref:(id:string)=>string}) {
  const root=useRef<HTMLDivElement>(null), heading=useRef<HTMLHeadingElement>(null), previous=useRef(selectedId);
  const selected=data.items.find(item=>item.resolution_id===selectedId);
  function trigger(id:string){return [...(root.current?.querySelectorAll<HTMLButtonElement>('[data-identity-trigger]')??[])].find(button=>button.dataset.identityTrigger===id);}
  useEffect(()=>{
    if(selected){if(previous.current===selectedId)trigger(selected.resolution_id)?.focus({preventScroll:true});else heading.current?.focus();}
    previous.current=selectedId;
  },[selectedId,data]);
  return <div ref={root} className="identity-review">
    <DataTable label="Unresolved identities" heads={['Matching record','Why review is needed','Possible workloads','Evaluated at (UTC)']}>
      {data.items.map(item=><tr key={item.resolution_id} data-resolution-id={item.resolution_id} data-selected={selectedId===item.resolution_id||undefined}>
        <td><button className="text-button identity-record-link" data-identity-trigger={item.resolution_id} aria-label={'Inspect matching record '+item.resolution_id} aria-expanded={selectedId===item.resolution_id} aria-controls={selectedId===item.resolution_id?'identity-review-detail':undefined} onClick={()=>onInspect(item.resolution_id)}><code>{item.resolution_id}</code></button><small>Revision {item.revision}</small><small>{item.group_id?'Finding link available':'No finding identified'}</small></td>
        <td><MatchStatus outcome={item.outcome}/><p className="identity-reason">{matchingReason(item.reason)}</p></td>
        <td><strong>{item.candidate_workload_ids.length}</strong> candidate{item.candidate_workload_ids.length===1?'':'s'}<small>No instance selected</small></td>
        <td><UTC value={item.evaluated_at}/><small>Matching evaluation, not scanner observation</small></td>
      </tr>)}
    </DataTable>
    {selectedId&&!selected&&<div className="panel-content"><Message title="Selected matching record is not on this page">Use the current list to inspect a record. Refreshing or changing pages does not establish that an earlier unresolved match is resolved.</Message></div>}
    {selected&&<section id="identity-review-detail" className="identity-inspector" aria-labelledby="identity-review-title" data-inspected-resolution={selected.resolution_id}>
      <header className="identity-inspector-head"><div><div className="eyebrow">IDENTITY / READ-ONLY REVIEW</div><h3 id="identity-review-title" ref={heading} tabIndex={-1}>Matching details</h3><code>{selected.resolution_id}</code></div><button onClick={()=>{trigger(selected.resolution_id)?.focus();onInspect(null);}}>Close details</button></header>
      <div className="identity-inspector-body"><div className="identity-review-main">
        <section aria-label="Matching outcome"><h4>Why this needs review</h4><MatchStatus outcome={selected.outcome}/><p className="identity-reason">{matchingReason(selected.reason)}</p><details className="identity-recorded-reason"><summary>Recorded matching reason</summary><code>{selected.reason}</code></details><p>No instance has been selected by this result. Reviewing it does not change identity, lineage or fix status.</p></section>
        <section aria-label="Candidate workloads"><h4>Possible workload matches</h4>{selected.candidate_workload_ids.length?<ul className="membership-list">{selected.candidate_workload_ids.map(id=><li key={id}><code>{id}</code><small>Candidate only · not selected</small></li>)}</ul>:<p>No candidate workloads recorded. The workload remains unknown.</p>}</section>
        <section aria-label="Matching explanations"><h4>Why these matches were considered</h4><IdentityEvidence items={selected.candidate_explanations}/></section>
        <section aria-label="Related import evidence"><h4>Import and instance matching</h4><ImportAssociations items={selected.manifest_associations}/></section>
      </div><aside className="identity-review-context" aria-label="Matching record context">
        <section><h4>Record and timing</h4><dl className="facts"><div><dt>Scan record ID</dt><dd><code>{selected.observation_id}</code></dd></div><div><dt>Matching revision</dt><dd>{selected.revision}</dd></div><div><dt>Evaluated at</dt><dd><UTC value={selected.evaluated_at}/></dd></div><div><dt>Scan time check</dt><dd><Status value={selected.temporal_status}/></dd></div><div><dt>Scanner observation time</dt><dd>Not supplied in this view</dd></div><div><dt>First detection and lineage</dt><dd>Not established by this matching result</dd></div></dl><p>The evaluation time is not a scanner observation or a new first-detection date.</p></section>
        <section><h4>Related finding</h4>{selected.group_id?<><code className="identity-group-id">{selected.group_id}</code><a className="identity-finding-link" href={groupHref(selected.group_id)}>Open linked finding →</a><p>The native finding is known; the instance match is still unresolved.</p></>:<><p>No finding link available</p><p>A native finding has not been identified. No group or workload is inferred from this record.</p></>}</section>
      </aside></div>
    </section>}
  </div>;
}
