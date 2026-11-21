import {useEffect,useRef,useState,type FormEvent} from 'react';
import {DeploymentError,abandonRegistration,isRegistration,readDeployment,registerScanner,registration,type Deployment,type Registration,type RegistrationPayload,type RegistrationReceipt,type Abandonment} from './deployment-api';
import './deployment.css';
import {readScanner} from './scanner-api';
export default function DeploymentOnboarding({actorId,refresh}:{actorId:string;refresh:number}){
 const [deployment,setDeployment]=useState<Deployment|null>(null),[error,setError]=useState(''),[loading,setLoading]=useState(true),[reload,setReload]=useState(0);
 useEffect(()=>{const controller=new AbortController();setLoading(true);setError('');setDeployment(null);readDeployment(controller.signal).then(v=>{if(!controller.signal.aborted)setDeployment(v);}).catch(e=>{if(!controller.signal.aborted)setError(e instanceof Error?e.message:'Deployment unavailable.');}).finally(()=>{if(!controller.signal.aborted)setLoading(false);});return()=>controller.abort();},[refresh,reload,actorId]);
 if(loading)return <section className="panel deployment-panel" aria-busy="true"><p role="status">Checking protected deployment access…</p></section>;
 if(error||!deployment)return <section className="panel deployment-panel"><h2>Deployment unavailable</h2><p role="alert">{error}</p><button onClick={()=>setReload(x=>x+1)}>Retry deployment access</button></section>;
 return <DeploymentContents key={actorId+deployment.installation_id} initial={deployment} actorId={actorId}/>;
}
function DeploymentContents({initial,actorId}:{initial:Deployment;actorId:string}){
 const [deployment,setDeployment]=useState(initial),[adding,setAdding]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[stale,setStale]=useState(false);
 const [reviewAbandon,setReviewAbandon]=useState(false),[reviewAck,setReviewAck]=useState(false),[terminal,setTerminal]=useState<Extract<Abandonment,{disposition:'not_committed'}>|null>(null),[replacement,setReplacement]=useState<RegistrationPayload|null>(null);
 const formHeading=useRef<HTMLHeadingElement>(null),outcome=useRef<HTMLParagraphElement>(null),abandonHeading=useRef<HTMLHeadingElement>(null);
 useEffect(()=>{if(adding)formHeading.current?.focus();},[adding,replacement]);
 useEffect(()=>{if(reviewAbandon)abandonHeading.current?.focus();},[reviewAbandon]);
 useEffect(()=>{if(notice)outcome.current?.focus();},[notice]);
 const storageKey='volt.scanner.registration:'+actorId+':'+initial.installation_id;
 const [held,setHeld]=useState<{command:Registration|null;corrupt:boolean}>(()=>{try{const raw=sessionStorage.getItem(storageKey);if(!raw)return {command:null,corrupt:false};const value:unknown=JSON.parse(raw);return isRegistration(value)?{command:value,corrupt:false}:{command:null,corrupt:true};}catch{return {command:null,corrupt:true};}});
 const locked=busy||stale||held.command!==null||held.corrupt;
 useEffect(()=>{if(!held.command&&!held.corrupt)return;const warn=(e:BeforeUnloadEvent)=>e.preventDefault();addEventListener('beforeunload',warn);return()=>removeEventListener('beforeunload',warn);},[held]);
 async function reconcile(command:Registration,receipt:RegistrationReceipt){
  const allocated=receipt.allocated_ids;
  const latest=await readDeployment();
  const row=latest.connectors.find(c=>c.connector_id===allocated.connector_id&&c.source.source_id===allocated.source_id);
  if(latest.installation_id!==initial.installation_id||!row||row.source.source_family!==command.payload.source_family||row.source.source_account_id!==receipt.source_tuple.source_account_id||row.source.scope_key!==receipt.source_tuple.scope_key||latest.connector_registry_revision<receipt.connector_registry_revision)throw new DeploymentError(502,true);
  let scanner;try{scanner=await readScanner(allocated.connector_id,allocated.source_id);}catch{throw new DeploymentError(502,true);}
  if(scanner.source_tuple.source_family!==receipt.source_tuple.source_family||scanner.source_tuple.source_account_id!==receipt.source_tuple.source_account_id||scanner.source_tuple.scope_key!==receipt.source_tuple.scope_key||scanner.credential.secret_id!==receipt.credential_slots.qualys_vm_basic.secret_id||scanner.platform_id!==command.payload.platform_id||scanner.product!==command.payload.product||scanner.scope.kind!==command.payload.scope.kind)throw new DeploymentError(502,true);
  setDeployment(latest);sessionStorage.removeItem(storageKey);setHeld({command:null,corrupt:false});setAdding(false);setTerminal(null);setReviewAbandon(false);setReplacement(null);
  setNotice(`Registration confirmed. Current connection state: ${row.lifecycle}. This reflects the latest server state; registration does not itself activate a connection.`);
 }
 async function send(command:Registration,wasHeld:boolean){
  setBusy(true);setError('');setNotice('');
  try{
   sessionStorage.setItem(storageKey,JSON.stringify(command));setHeld({command,corrupt:false});
  }catch{setError('This browser cannot retain the registration for safe retry. Allow session storage before registering.');setBusy(false);return;}
  let committed=false;
  try{
   const receipt=await registerScanner(command);committed=true;
   await reconcile(command,receipt);
  }catch(e){
   if(!wasHeld&&!committed&&e instanceof DeploymentError&&!e.uncertain){sessionStorage.removeItem(storageKey);setHeld({command:null,corrupt:false});}
   if(e instanceof DeploymentError&&e.status===409)setStale(true);
   setError(e instanceof Error?e.message:'Registration could not be confirmed.');
  }finally{setBusy(false);}
 }
 async function resolveHeld(event:FormEvent<HTMLFormElement>){
  event.preventDefault();if(busy||!held.command||!reviewAck||terminal||!deployment.can_register_connector)return;
  const fields=new FormData(event.currentTarget),command=held.command;
  setBusy(true);setError('');setNotice('');setReviewAck(false);
  try{
   const result=await abandonRegistration(command,actorId,String(fields.get('rationale')??'').trim(),String(fields.get('evidence_ref')??'').trim());
   if(result.disposition==='committed')await reconcile(command,result.receipt);
   else{setTerminal(result);setReviewAbandon(false);setNotice('The server confirmed that the original registration did not commit and can never commit. Review any replacement as a separate registration.');}
  }catch(e){setError(e instanceof Error?e.message:'Reconciliation could not be confirmed. The original command is retained.');}
  finally{setBusy(false);}
 }
 async function prepareReplacement(){
  if(busy||!held.command||!terminal||terminal.command_id!==held.command.command_id)return;
  setBusy(true);setError('');
  try{
   const latest=await readDeployment();
   if(latest.installation_id!==initial.installation_id||!latest.can_register_connector)throw new DeploymentError(403);
   // Terminal proof permits discarding this ID, but never auto-submitting a new one.
   sessionStorage.removeItem(storageKey);setReplacement({...held.command.payload});setHeld({command:null,corrupt:false});setTerminal(null);setDeployment(latest);setStale(false);setAdding(true);
   setNotice('Review the replacement details against the refreshed deployment. Submitting creates a new command; the abandoned command stays terminal.');
  }catch(e){setError(e instanceof Error?e.message:'Current deployment could not be loaded. No replacement is available.');}
  finally{setBusy(false);}
 }
 async function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();if(locked||!deployment.can_register_connector)return;const data=new FormData(event.currentTarget);const field=(name:string)=>String(data.get(name)??'').trim();const payload:RegistrationPayload={display_name:field('display_name'),source_family:'qualys',account_label:field('account_label'),product:'qualys_vm',platform_id:field('platform_id') as RegistrationPayload['platform_id'],scope:{kind:'account_visible'},environment_label:field('environment_label'),rationale:field('rationale'),evidence_ref:field('evidence_ref'),grant_initial_read:data.get('grant_initial_read')==='on'};await send(registration(deployment,payload),false);}
 async function refresh(){if(busy)return;setBusy(true);setError('');try{setDeployment(await readDeployment());setStale(false);}catch(e){setError(e instanceof Error?e.message:'Deployment unavailable.');}finally{setBusy(false);}}
 return <section className="deployment-panel" aria-label="Deployment overview" aria-busy={busy}>
  <div className="deployment-welcome"><div className="eyebrow">YOUR WORKSPACE</div><h2>{deployment.connectors.length?'Connected scanners':'Your workspace is ready for its first scanner'}</h2><p>{deployment.connectors.length?'Review the registered sources and their current configuration state.':'No scanners are registered. No vulnerability data or risk metrics are available yet.'}</p><p>Registration creates a disabled connection. Collection and external validation are separate actions.</p></div>
  {error&&<p role="alert">{error}</p>}{notice&&<p ref={outcome} tabIndex={-1} role="status">{notice}</p>}
  {held.corrupt&&<div className="panel"><h3>Registration recovery required</h3><p role="alert">The retained registration is malformed or uses an unsupported envelope. It has not been changed or resent. New registrations are blocked. Ask your operator to reconcile the original command before clearing this browser’s session data.</p></div>}
  {held.command&&<div className="panel registration-resolution"><h3>{terminal?'Registration did not commit':'Registration awaiting confirmation'}</h3><p>{terminal?'The server has permanently closed the original command. Its details are retained for your replacement review.':'The original command, scanner details and revisions are retained. Retrying recovers that same operation; it does not create a new request.'}</p><dl><dt>Scanner</dt><dd>{held.command.payload.display_name}</dd><dt>Requested account and scope</dt><dd>{held.command.payload.source_family} / {held.command.payload.account_label} / {held.command.payload.platform_id} / account-visible</dd><dt>Original command</dt><dd className="break">{held.command.command_id}</dd></dl>
   {!terminal?<div className="row wrap"><button disabled={busy} onClick={()=>held.command&&void send(held.command,true)}>Retry same registration</button><button disabled={busy||!deployment.can_register_connector} onClick={()=>{setReviewAbandon(x=>!x);setReviewAck(false);}}>Review abandonment</button></div>:<><p>Terminal non-commit confirmed. Audit reference: {terminal.audit_event_id}</p><button disabled={busy} onClick={()=>void prepareReplacement()}>Review replacement with current revisions</button></>}
   {reviewAbandon&&!terminal&&<form className="registration-form" onSubmit={resolveHeld}><h4 ref={abandonHeading} tabIndex={-1}>Resolve this registration before replacing it</h4><p>If the original registration committed, VOLT recovers its receipt. Otherwise this action permanently prevents that command from committing and records an audit event. It does not submit a replacement.</p><fieldset disabled={busy}><label>Reason for reconciliation<textarea name="rationale" required maxLength={1000}/></label><label>Reconciliation evidence reference<input name="evidence_ref" required maxLength={512}/></label><label className="registration-check"><input type="checkbox" required checked={reviewAck} onChange={e=>setReviewAck(e.target.checked)}/><span>I reviewed the original registration and authorise permanent abandonment only if it has not committed.</span></label><button type="submit" disabled={!reviewAck}>Confirm abandonment if not committed</button></fieldset></form>}</div>}
  <div className="row wrap"><button disabled={busy} onClick={()=>void refresh()}>Refresh deployment</button>{deployment.can_register_connector&&<button className="primary" disabled={locked} onClick={()=>setAdding(x=>!x)}>{adding?'Cancel registration':'Register scanner'}</button>}</div>
  {!deployment.can_register_connector&&<p role="status">Scanner registration is not currently permitted. Access is checked by the server for each operation.</p>}
  {adding&&<form key={replacement?'replacement':'new'} className="panel registration-form" onSubmit={submit}><h3 ref={formHeading} tabIndex={-1}>{replacement?'Review replacement registration':'Register a scanner'}</h3><p>Current revisions: policy {deployment.policy_revision}, authority {deployment.authority_revision}, registry {deployment.connector_registry_revision}.</p><p>Qualys VMDR · Host Detection List. VOLT generates the source identity. Labels help people recognise this connection; they do not establish subscription identity.</p><fieldset disabled={locked||!deployment.can_register_connector}>
   <label>Display name<input name="display_name" defaultValue={replacement?.display_name??''} required maxLength={120}/></label>
   <label>Account label<input name="account_label" defaultValue={replacement?.account_label??''} required maxLength={120}/></label>
   <label>Qualys platform<select name="platform_id" defaultValue={replacement?.platform_id??'us1'}>{[['us1','United States 1'],['us2','United States 2'],['us3','United States 3'],['eu1','Europe 1'],['eu2','Europe 2'],['in1','India 1']].map(([id,label])=><option key={id} value={id}>{label}</option>)}</select></label>
   <p>Account-visible scope: collect hosts visible to a dedicated Qualys Reader/API account. Vendor permissions limit visibility. A successful test does not prove subscription identity or complete asset coverage. A different platform or intended scope requires another connection.</p>
   <label>Environment label<input name="environment_label" defaultValue={replacement?.environment_label??''} required maxLength={128}/></label>
   <label>Reason for registration<textarea name="rationale" defaultValue={replacement?.rationale??''} required maxLength={1000}/></label><label>Evidence reference<input name="evidence_ref" defaultValue={replacement?.evidence_ref??''} required maxLength={512} aria-describedby="scanner-evidence-help"/></label><small id="scanner-evidence-help">A non-secret change or approval reference.</small>
   <label className="registration-check"><input type="checkbox" name="grant_initial_read" defaultChecked={replacement?.grant_initial_read??true}/><span>Grant me read access to findings and audit history from this exact source.</span></label><p>This choice grants no assessment changes, approvals or remediation confirmations. Connector configuration and secret management are scoped to this connection.</p>
   <button className="primary" type="submit">Register disabled scanner</button>
  </fieldset></form>}
  <div className="connector-grid">{deployment.connectors.map(c=><article className="panel deployment-connector" key={c.connector_id}><div className="eyebrow">{c.environment_label}</div><h3>{c.source.source_family}</h3><p>{c.source.source_account_id} · {c.source.scope_key}</p><p>Status: <strong>{c.lifecycle}</strong> · Configuration {c.configuration_revision}</p><a href={'#scanner?connector_id='+encodeURIComponent(c.connector_id)+'&source_id='+encodeURIComponent(c.source.source_id)}>Open Qualys source</a></article>)}</div>
 </section>;
}
