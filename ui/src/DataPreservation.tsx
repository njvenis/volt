import {useEffect,useRef,useState} from 'react';
import {classIds,classLabels,compareRecords,downloadEvidence,PreservationError,readRecords,readSummary,scopeKey,type ClassId,type PreservationClass,type RecordPage,type Scope,type Summary} from './preservation-api';
import './preservation.css';

const human=(value:string)=>value.replaceAll('_',' ');
const number=(value:number|null)=>value===null?'Not established':String(value);
function Time({value}:{value:string|null}){return value?<time dateTime={value}>{value.replace('T',' ').replace('Z',' UTC')}</time>:<>Not established</>;}
function Status({state}:{state:string}){return <span className={'preservation-state '+state}><span aria-hidden="true">{state==='verified'?'✓':state==='failed'?'!':'△'}</span> {human(state)}</span>;}
function Reasons({reasons}:{reasons:string[]}){return reasons.length?<ul className="preservation-reasons">{reasons.map(r=><li key={r}>{human(r)}</li>)}</ul>:null;}
function Failure({error,onReset}:{error:PreservationError;onReset?:()=>void}){return <div className="notice danger" role="alert"><div><strong>{error.reset?'Reload the current report':error.status===404?'Unavailable or not permitted':'Read unavailable'}</strong><p>{error.message}</p>{error.reset&&onReset&&<button onClick={onReset}>Reload current source report</button>}</div></div>;}
const asError=(error:unknown)=>error instanceof PreservationError?error:new PreservationError('unavailable');
function ClassCard({value,onSelect,selected,stale}:{value:PreservationClass;onSelect:()=>void;selected:boolean;stale:boolean}){
 return <section className={'preservation-card '+(selected?'selected':'')} data-class={value.class_id} aria-label={classLabels[value.class_id]}>
  <div className="eyebrow">{value.minimum_period==='P1Y'?'ONE YEAR':'THREE MONTHS'} · REQUIRED MINIMUM</div><h3>{classLabels[value.class_id]}</h3><Status state={value.state}/><Reasons reasons={value.reasons}/>
  <dl className="preservation-counts">{(['expected_records','verified_records','missing_records','changed_records','unreadable_records','unexpected_records'] as const).map(key=><div key={key}><dt>{human(key.replace('_records',''))}</dt><dd data-count={key}>{number(value[key])}</dd></div>)}</dl>
  <p className="preservation-oldest">Oldest verified retained time<br/><Time value={value.oldest_retained_at}/></p>
  <button onClick={onSelect} aria-pressed={selected} disabled={stale||value.expected_records===null}>Browse {classLabels[value.class_id].toLowerCase()}</button>
  {stale&&<small>Reload before browsing an expired observation.</small>}{value.expected_records===null&&<small>Record coverage is not established or is withheld.</small>}
 </section>;
}
function AuditCopy({value}:{value:PreservationClass}){
 const copy=value.audit_copy!;const masked=value.reasons.includes('audit_scope_incomplete');
 return <section className="panel preservation-copy" aria-labelledby="copy-title"><div><div className="eyebrow">SEPARATE FROM UVM HISTORY</div><h3 id="copy-title">Independent audit copy</h3><Status state={copy.state}/><p>The signed check compares independently retained events and receipts. Viewing this page does not export or repair an event.</p><Reasons reasons={copy.reasons}/></div>
 {masked?<p className="notice warning">Audit counts, timestamps and provenance are withheld because complete audit scope is not authorised. No partial totals are disclosed.</p>:<><dl className="preservation-copy-counts">{(['expected_events','matching_events','missing_events','changed_events','unexpected_events','expected_receipts','matching_receipts','missing_receipts','changed_receipts','unexpected_receipts','pending_receipts'] as const).map(key=><div key={key}><dt>{human(key)}</dt><dd data-copy-count={key}>{number(copy[key])}</dd></div>)}</dl><p>Independent signed check: <Time value={copy.checked_at}/></p></>}
 </section>;
}
function Records({summary,classId,reload}:{summary:Summary;classId:ClassId;reload:()=>void}){
 const [cursor,setCursor]=useState<string|null>(null),[result,setResult]=useState<{page?:RecordPage;error?:PreservationError;loading:boolean}>({loading:true});
 const [download,setDownload]=useState<{id?:string;error?:PreservationError;done?:boolean}>({});
 const seen=useRef(new Set<string>()),seenKeys=useRef(new Set<string>()),last=useRef<RecordPage['items'][number]|undefined>(undefined),controller=useRef<AbortController|undefined>(undefined);
 const heading=useRef<HTMLHeadingElement>(null);
 useEffect(()=>{heading.current?.focus();return()=>controller.current?.abort();},[]);
 useEffect(()=>{const abort=new AbortController();setResult({loading:true});setDownload({});controller.current?.abort();
  readRecords(summary.snapshot_id!,classId,cursor,abort.signal).then(page=>{
   if(abort.signal.aborted)return;
   if(page.items.some(item=>seenKeys.current.has(item.record_key))||(cursor&&last.current&&page.items[0]&&compareRecords(last.current,page.items[0])>=0)||(page.next_cursor&&seen.current.has(page.next_cursor)))throw new PreservationError('invalid_response');
   setResult({page,loading:false});
  }).catch(error=>{if(!abort.signal.aborted)setResult({error:asError(error),loading:false});});return()=>abort.abort();
 },[summary.snapshot_id,classId,cursor]);
 async function retrieve(path:string,id:string){controller.current?.abort();const abort=new AbortController();controller.current=abort;setDownload({id});try{await downloadEvidence(path,abort.signal);if(!abort.signal.aborted)setDownload({id,done:true});}catch(error){if(!abort.signal.aborted)setDownload({id,error:asError(error)});}}
 function next(){const page=result.page!;last.current=page.items.at(-1);for(const item of page.items)seenKeys.current.add(item.record_key);seen.current.add(page.next_cursor!);setCursor(page.next_cursor);}
 return <section className="panel preservation-records" aria-labelledby="records-title"><div className="panel-head"><div><h3 id="records-title" ref={heading} tabIndex={-1}>{classLabels[classId]} records</h3><p>One immutable signed snapshot. Digests describe different evidence and are never interchangeable.</p></div></div>
 <div role="status">{result.loading?'Loading retained records…':result.page?`${result.page.items.length} records on this page.`:''}</div>
 {result.error&&<Failure error={result.error} onReset={reload}/>}
 {download.error&&<Failure error={download.error}/>}{download.done&&<p role="status">Verified evidence download prepared. Private bytes are not displayed here.</p>}
 {result.page&&<>{!result.page.items.length?<p className="empty">No records in this signed class snapshot. This does not establish coverage before the baseline.</p>:<div className="table-scroll" tabIndex={0} role="region" aria-label="Retained record details"><table><caption className="sr-only">Retained record details</caption><thead><tr>{['Record / retained time','Readback result','Digest provenance / permitted evidence'].map(h=><th scope="col" key={h}>{h}</th>)}</tr></thead><tbody>{result.page.items.map(item=><tr key={item.record_key} data-record-key={item.record_key}><td><strong>{human(item.record_kind)}</strong><code>{item.record_key}</code><Time value={item.retained_at}/></td><td><Status state={item.state}/><Reasons reasons={item.reasons}/></td><td><details><summary>Digest provenance</summary><dl>{(['expected_sha256','actual_sha256','record_sha256'] as const).map(key=><div key={key}><dt>{key==='expected_sha256'?'Expected raw bytes':key==='actual_sha256'?'Observed raw bytes':'Canonical record'}</dt><dd><code>{item[key]??'Not established / not applicable'}</code></dd></div>)}</dl></details>{item.readback_url?<button onClick={()=>void retrieve(item.readback_url!,item.record_key)} disabled={!!download.id&&!download.done&&!download.error} aria-label={'Download evidence for '+item.record_key}>{download.id===item.record_key&&!download.done&&!download.error?'Checking evidence…':'Download verified evidence'}</button>:<small>No permitted evidence download</small>}</td></tr>)}</tbody></table></div>}
 <div className="table-foot"><span>Snapshot <code>{summary.snapshot_id}</code></span><button onClick={next} disabled={!result.page.next_cursor}>Next records page</button></div></>}
 </section>;
}
export default function DataPreservation({candidates,refresh,query,onContext}:{candidates:Scope[];refresh:number;query:URLSearchParams;onContext:(values:Record<string,string|null>)=>void}){
 const requested={source_family:query.get('source_family')??'',source_account_id:query.get('source_account_id')??'',scope_key:query.get('scope_key')??''};
 const selected=candidates.find(c=>scopeKey(c)===scopeKey(requested));const selectedKey=selected?scopeKey(selected):'';
 const [reload,setReload]=useState(0),[result,setResult]=useState<{key:string;data?:Summary;error?:PreservationError;loading:boolean}>({key:'',loading:false});
 const [classId,setClassId]=useState<ClassId|null>(null),[now,setNow]=useState(Date.now());
 const key=JSON.stringify([selectedKey,refresh,reload]);const current=result.key===key?result:{key,loading:!!selected};
 useEffect(()=>{const timer=setInterval(()=>setNow(Date.now()),1000);return()=>clearInterval(timer);},[]);
 useEffect(()=>{const abort=new AbortController();setClassId(null);setResult({key,loading:!!selected});if(selected)readSummary(selected,abort.signal).then(data=>{if(!abort.signal.aborted)setResult({key,data,loading:false});}).catch(error=>{if(!abort.signal.aborted)setResult({key,error:asError(error),loading:false});});return()=>abort.abort();},[key]);
 const summary=current.data;const stale=!!summary?.valid_until&&Date.parse(summary.valid_until)<=now;
 const masked=summary?.classes.find(c=>c.class_id==='product.audit_history')?.reasons.includes('audit_scope_incomplete');
 const doRefresh=()=>{setClassId(null);setReload(n=>n+1);};
 return <div className="preservation" aria-busy={current.loading}><section className="preservation-intro"><div><div className="eyebrow">READ-ONLY / RETAINED DATA</div><h2>Data preservation</h2><p>Inspect retained evidence, collection history and independent audit copies for one exact source.</p></div><div className="preservation-limit"><strong>Elapsed preservation: unverified</strong><p>A current readback check does not prove that one year or three months has elapsed.</p></div></section>
 <div className="preservation-controls"><label>Source scope<select aria-label="Source scope" value={selectedKey} onChange={event=>{const scope=candidates.find(c=>scopeKey(c)===event.target.value);setClassId(null);onContext(scope?{...scope}:{source_family:null,source_account_id:null,scope_key:null});}}><option value="">Choose an exact source scope</option>{candidates.map(c=><option value={scopeKey(c)} key={scopeKey(c)}>{c.source_family} / {c.source_account_id} / {c.scope_key}</option>)}</select></label><button onClick={doRefresh} disabled={!selected||current.loading}>Refresh preservation report</button></div>
 <p className="muted">The session supplies candidate sources. VOLT checks current access on every read. Refresh reads an existing signed observation; it never runs a check, export or repair.</p>
 {!candidates.length&&<div className="notice warning">No source candidates were returned for this session. No preservation coverage is inferred.</div>}
 {!selected&&candidates.length>0&&<p className="empty">Select a source to check access and read its current preservation report.</p>}
 <div role="status">{current.loading?'Loading the signed preservation observation…':summary?'Preservation response loaded. Observation time remains separate from response time.':''}</div>
 {current.error&&<Failure error={current.error} onReset={doRefresh}/>}
 {summary&&<><section className="panel preservation-observation" aria-label="Signed observation"><div><h3>Signed observation</h3><p>{summary.snapshot_id?'Current report identity':'No valid report is available'}</p><code data-snapshot-id>{summary.snapshot_id??'Not established'}</code></div><dl><div><dt>Observer checked at</dt><dd data-checked-at><Time value={summary.checked_at}/></dd></div><div><dt>Observation valid until</dt><dd><Time value={summary.valid_until}/></dd></div><div><dt>API response at</dt><dd><Time value={summary.response_at}/></dd></div><div><dt>Configured environment</dt><dd>{summary.environment??'Not labelled'}</dd></div></dl></section>
 {stale&&<div className="notice warning" role="alert"><div><strong>Stale signed observation</strong><p>The validity time has elapsed. The statuses below describe that retained observation, not fresh verified coverage. Reload to request the current report.</p><button onClick={doRefresh}>Reload current source report</button></div></div>}
 <div className="preservation-cards">{classIds.map(id=><ClassCard key={id} value={summary.classes.find(c=>c.class_id===id)!} selected={classId===id} stale={stale} onSelect={()=>setClassId(id)}/>)}</div>
 <section className="notice warning preservation-coverage" aria-label="Coverage limits"><div><strong>Coverage limits</strong><p data-uncovered>Uncovered classes: {summary.uncovered_classes.length?summary.uncovered_classes.map(id=>classLabels[id]).join(', '):'None in this signed observation'}.</p><p>Generic application and access logs, failures before a collection reservation, live scanner or SIEM compatibility, legal holds and deletion policy are outside this check. No disposal or pruning is performed.</p></div></section>
 <AuditCopy value={summary.classes.find(c=>c.class_id==='product.audit_history')!}/>
 <details className="panel preservation-provenance"><summary>Report provenance and access masking</summary><dl><div><dt>Current access fingerprint</dt><dd><code>{summary.authority_fingerprint}</code></dd></div><div><dt>Audit access fingerprint</dt><dd><code>{summary.audit_authority_fingerprint??'Withheld'}</code></dd></div>{summary.classes.filter(c=>!(masked&&c.class_id==='product.audit_history')).map(c=><div key={c.class_id}><dt>{classLabels[c.class_id]} baseline</dt><dd><code>{c.baseline_digest??'Not established'}</code></dd></div>)}</dl><Reasons reasons={summary.mask_reasons}/></details>
 {classId&&!stale&&summary.snapshot_id&&summary.classes.find(c=>c.class_id===classId)?.expected_records!==null&&<Records key={key+classId} summary={summary} classId={classId} reload={doRefresh}/>}
 </>}
 </div>;
}
