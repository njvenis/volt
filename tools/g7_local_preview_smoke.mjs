import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import process from 'node:process';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {exact,uuid,protectedInput,publicOrigin,privateRead,privateWrite,privateDestination,savedSession,recoveryState,authenticationDenied,restoredSessionDenied,cookieLifetime} from '../ui/scripts/local-companion-state.mjs';
import {scannerSnapshot,scannerRequest,scannerResponse,credentialFence,credentialRequest,credentialReceipt,observedPost} from '../ui/scripts/scanner-companion-contract.mjs';
import {policyExpectedRevisions,requireAdminRendered,requireAudit,requirePersistedState,requireReceipt,requireSession} from './g7_local_preview_smoke_checks.mjs';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`);return process.argv[i+1];}
const localMode=process.argv.includes('--local');
const verifyRestoredSession=process.argv.includes('--verify-restored-session'),verifySetupClosed=process.argv.includes('--verify-setup-closed'),recoveryPrepare=process.argv.includes('--recovery-prepare'),recoveryComplete=process.argv.includes('--recovery-complete');
const specialMode=verifyRestoredSession||verifySetupClosed||recoveryPrepare||recoveryComplete;
const localSetup=localMode&&process.argv.includes('--setup');
const registerLocalScanner=localMode&&process.argv.includes('--register-scanner');
const origin=arg('--origin'), issuer=localMode?null:arg('--issuer'), subject=localMode?null:arg('--subject'), principal=localMode?null:arg('--principal'), evidence=arg('--evidence');
const deploymentLabel=process.argv.includes('--deployment-label')?arg('--deployment-label'):'Synthetic local demo';
const readbackOnly=process.argv.includes('--readback');
const verifyProviderRevocation=process.argv.includes('--verify-provider-revocation');
const legacyUsername=localMode?null:arg('--username');
if(!verifyRestoredSession&&!process.argv.includes(localMode?'--credentials-stdin':'--password-stdin'))throw new Error('missing protected stdin flag');
let credentials;
try {
  const input=verifyRestoredSession?'{}':await protectedInput();
  credentials=localMode?JSON.parse(input):{username:legacyUsername,password:input};
  if(!verifyRestoredSession){
  if(!credentials||typeof credentials!=='object'||Array.isArray(credentials)||
      typeof credentials.username!=='string'||typeof credentials.password!=='string'||
      !credentials.username||!credentials.password)throw new Error();
  if(localSetup&&(!credentials.capability||typeof credentials.capability!=='string'||!credentials.display_name||typeof credentials.display_name!=='string'))throw new Error();
  if(registerLocalScanner&&(!credentials.scanner||typeof credentials.scanner!=='object'||Array.isArray(credentials.scanner)||!['display_name','account_label','platform_id','environment_label','rationale','evidence_ref','username','password'].every(k=>typeof credentials.scanner[k]==='string'&&credentials.scanner[k].length>0)||typeof credentials.scanner.grant_initial_read!=='boolean'||!['us1','us2','us3','eu1','eu2','in1'].includes(credentials.scanner.platform_id)))throw new Error();
  if(verifySetupClosed&&(!exact(credentials,['username','password','display_name','capability'])||!['display_name','capability'].every(k=>typeof credentials[k]==='string'&&credentials[k].length>0)))throw new Error();
  if(recoveryPrepare||recoveryComplete){const fields=recoveryPrepare?['display_name','account_label','environment_label','username','password','rationale','evidence_ref']:['rationale','evidence_ref'];if(!exact(credentials,['username','password','scanner'])||!exact(credentials.scanner,fields)||!fields.every(k=>typeof credentials.scanner[k]==='string'&&credentials.scanner[k].length>0))throw new Error();}
  }
} catch {
  // JSON parser diagnostics can quote the input. Never expose their error/cause.
  process.stderr.write('Invalid credential input.\n');
  process.exit(1);
}
const {username,password}=credentials;
let capturedSession,capturedRecovery;
try{
 publicOrigin(origin);
 if([verifyRestoredSession,verifySetupClosed,recoveryPrepare,recoveryComplete].filter(Boolean).length>1||specialMode&&(!localMode||localSetup||registerLocalScanner||readbackOnly||verifyProviderRevocation)||verifyRestoredSession&&process.argv.includes('--credentials-stdin'))throw new Error();
 if(verifyRestoredSession)capturedSession=savedSession(await privateRead(arg('--browser-state')),origin);
 if(recoveryComplete)capturedRecovery=recoveryState(await privateRead(arg('--recovery-state')),origin);
 if(recoveryPrepare)await privateDestination(arg('--recovery-state'));
}catch{process.stderr.write('Invalid companion mode or private state.\n');process.exit(1);}

await mkdir(evidence,{recursive:true,mode:0o700});
const launchOptions={headless:true};
if(process.env.CHROMIUM_EXECUTABLE_PATH)launchOptions.executablePath=process.env.CHROMIUM_EXECUTABLE_PATH;
if(process.env.VOLT_SMOKE_HOST_RESOLVER_RULES)launchOptions.args=[`--host-resolver-rules=${process.env.VOLT_SMOKE_HOST_RESOLVER_RULES}`];
let browser,context,page;
try{browser=await chromium.launch(launchOptions);context=await browser.newContext({ignoreHTTPSErrors:true,...(capturedSession?{storageState:capturedSession.storage_state}:{})});page=await context.newPage();}catch(error){await browser?.close();if(!localMode)throw error;process.stderr.write('Local browser verification failed.\n');process.exit(1);}
const zero='00000000-0000-4000-8000-000000000000';
// Temporary, opt-in diagnosis. Never retain cookies, CSRF tokens or credential headers.
const diagnostic=verifyProviderRevocation&&!localMode;
let phase='initial', requestSequence=0;
const trace=[], pendingCaptures=new Set(), requestIds=new WeakMap();
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
const safeUrl=value=>{try{const u=new URL(value);return u.origin+u.pathname+(u.hash||'');}catch{return '[non-url]';}};
const safeSession=body=>({schema_version:body?.schema_version,authenticated:body?.authenticated,
  credential_mode:body?.credential_mode,principal_id:body?.principal_id,authority:body?.authority,
  code:body?.detail?.code??body?.error?.code??body?.code??null});
function track(work){pendingCaptures.add(work);work.catch(error=>trace.push({kind:'capture-error',name:error.name})).finally(()=>pendingCaptures.delete(work));}
async function snapshot(label){
 if(!diagnostic)return;
 const cookies=(await context.cookies()).map(({value,...metadata})=>({...metadata,value_sha256:digest(value)}));
 const dom=await page.evaluate(()=>({url:location.origin+location.pathname+location.hash,title:document.title,readyState:document.readyState,
   timeOrigin:performance.timeOrigin,navigation:performance.getEntriesByType('navigation').map(n=>({type:n.type,startTime:n.startTime,domContentLoadedEventEnd:n.domContentLoadedEventEnd,transferSize:n.transferSize})),
   root:!!document.querySelector('#root'),sessionPanel:document.querySelector('.session-panel')?.textContent??null,
   visibleText:document.body.innerText,scripts:[...document.scripts].map(s=>s.src?new URL(s.src).pathname:'inline')}));
 trace.push({kind:'snapshot',label,phase,at:Date.now(),cookies,dom});
 await writeFile(evidence+'/session-trace.json',JSON.stringify(trace,null,2)+'\n',{mode:0o600});
}
if(diagnostic){
 page.on('request',request=>{
  const id=++requestSequence;requestIds.set(request,id);const at=Date.now(),requestPhase=phase;
  track((async()=>{
   const headers=await request.allHeaders();const cookieFingerprints=(headers.cookie??'').split(';').filter(Boolean).map(pair=>{const i=pair.indexOf('=');return {name:pair.slice(0,i).trim(),value_sha256:digest(pair.slice(i+1))};});
   trace.push({kind:'request',id,at,phase:requestPhase,url:safeUrl(request.url()),resource:request.resourceType(),method:request.method(),cookieFingerprints,
    accept:headers.accept,cacheControl:headers['cache-control']});
  })());
 });
 page.on('response',response=>{
  const request=response.request(),id=requestIds.get(request),at=Date.now(),responsePhase=phase;
  track((async()=>{
   const url=new URL(response.url()),headers=await response.allHeaders();
   const row={kind:'response',id,at,phase:responsePhase,url:safeUrl(response.url()),status:response.status(),
    contentType:headers['content-type'],cacheControl:headers['cache-control'],age:headers.age,etag:headers.etag,fromServiceWorker:response.fromServiceWorker()};
   if(url.pathname==='/api/v1/auth/session'){try{row.session=safeSession(await response.json());}catch{row.sessionParseFailed=true;}}
   if(request.resourceType()==='script'||request.resourceType()==='stylesheet'||request.resourceType()==='document'&&url.origin===origin&&url.pathname==='/'){
    const body=await response.body();row.body_sha256=digest(body);row.bytes=body.length;
    if(request.resourceType()==='document')row.body=body.toString().replace(/value="[^"]*"/g,'value="[redacted]"');
   }
   trace.push(row);
  })());
 });
 page.on('requestfailed',request=>trace.push({kind:'requestfailed',id:requestIds.get(request),at:Date.now(),phase,url:safeUrl(request.url()),failure:request.failure()?.errorText}));
 page.on('pageerror',error=>trace.push({kind:'pageerror',at:Date.now(),phase,name:error.name,message:error.message.replace(/https?:\/\/[^\s]+/g,'[url]')}));
 page.on('console',message=>trace.push({kind:'console',at:Date.now(),phase,type:message.type(),text_sha256:digest(message.text()),location:{...message.location(),url:safeUrl(message.location().url)}}));
}

function ensure(ok,label){if(!ok)throw new Error(label);}
async function api(path,{method='GET',body,write=false}={}){
  return page.evaluate(async({path,method,body,write})=>{
    const session=write?await(await fetch('/api/v1/auth/session',{cache:'no-store'})).json():null;
    const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{}),...(write?{'X-CSRF-Token':session.csrf_token}:{})},...(body?{body:JSON.stringify(body)}:{})});
    let value=null;try{value=await response.json();}catch{}return{status:response.status,body:value};
  },{path,method,body,write});
}
// SESSION_POLL_START
// Await each network result explicitly: an async waitForFunction predicate is
// itself truthy before it resolves and must not establish a session transition.
async function waitForSession(page,{status,authenticated,timeoutMs=30000,intervalMs=250}){
 const deadline=Date.now()+timeoutMs;let last;
 do{
  last=await page.evaluate(async()=>{
   const response=await fetch('/api/v1/auth/session',{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'},signal:AbortSignal.timeout(10000)});
   let body=null;try{body=await response.json();}catch{}
   return {status:response.status,authenticated:body?.authenticated===true};
  });
  if(last.status===status&&(authenticated===undefined||last.authenticated===authenticated))return last;
  if(Date.now()>=deadline)break;
  await new Promise(resolve=>setTimeout(resolve,Math.min(intervalMs,Math.max(0,deadline-Date.now()))));
 }while(Date.now()<deadline);
 throw new Error('session_transition_not_observed_'+JSON.stringify({expected:{status,authenticated},last}));
}
// SESSION_POLL_END
async function scannerClick(cid,source,label,action){
 const snapshot=await readScanner(cid,source),url=origin+'/api/v1/scanners/'+cid+'/commands';
 const first=await observedPost(page,url,()=>page.getByRole('button',{name:label,exact:true}).click(),body=>scannerRequest(body,snapshot,action));
 let value=await first.response.json(),status=scannerResponse(value,first.response.status(),first.request),operation=status==='running'?value.operation_id:null;
 const deadline=Date.now()+150000;
 while(status==='running'&&Date.now()<deadline){
  const next=await observedPost(page,url,()=>page.getByRole('button',{name:'Check original scanner command',exact:true}).click(),body=>scannerRequest(body,snapshot,action),first.raw);
  value=await next.response.json();status=scannerResponse(value,next.response.status(),first.request,operation);if(status==='running')await page.waitForTimeout(1000);
 }
 ensure(status==='committed','scanner_audited_receipt_missing');await page.locator('.scanner-workspace[aria-busy=false]').waitFor();return value;
}

async function sessionRead(){const response=await context.request.get(origin+'/api/v1/auth/session',{headers:{Accept:'application/json'},timeout:15000});return {status:response.status(),body:await response.json()};}
async function claimedUi(){
 const config=await api('/api/v1/auth/config');ensure(config.status===200&&exact(config.body,['schema_version','mode','setup_state'])&&config.body.schema_version===1&&config.body.mode==='local'&&config.body.setup_state==='claimed','setup_not_claimed');
 await page.getByRole('heading',{name:'Sign in to VOLT',exact:true}).waitFor();ensure(await page.getByRole('button',{name:'Set up administrator',exact:true}).count()===0&&await page.getByRole('button',{name:'Create administrator account',exact:true}).count()===0&&await page.getByRole('button',{name:'Sign out',exact:true}).count()===0,'claimed_ui_not_closed');
}
async function readScanner(cid,source){const result=await api('/api/v1/scanners/'+cid+'?source_id='+source);ensure(result.status===200&&result.body?.schema_version===1&&result.body.connector_id===cid&&result.body.source_id===source&&result.body.source_tuple?.source_family==='qualys','scanner_readback_failed');return scannerSnapshot(result.body,cid,source);}
async function sourcePage(cid,source){await page.goto(origin+'/#scanner?connector_id='+cid+'&source_id='+source,{waitUntil:'domcontentloaded'});await page.locator('.scanner-workspace[aria-busy=false]').waitFor();}
async function freshCredential(cid,source){
 const scanner=await readScanner(cid,source),slot=await api('/api/v1/connectors/'+cid+'/secrets/'+scanner.credential.secret_id+'?source_id='+source);ensure(slot.status===200,'secret_slot_unavailable');const fence=credentialFence(slot.body,scanner);
 await page.getByLabel('Qualys username',{exact:true}).fill(credentials.scanner.username);await page.getByLabel('Qualys password',{exact:true}).fill(credentials.scanner.password);
 const observed=await observedPost(page,origin+'/api/v1/connectors/'+cid+'/secrets/'+scanner.credential.secret_id+'/versions',()=>page.getByRole('button',{name:'Save Qualys credentials',exact:true}).click(),body=>credentialRequest(body,scanner,fence,{username:credentials.scanner.username,password:credentials.scanner.password}));
 ensure(await page.getByLabel('Qualys username',{exact:true}).inputValue()===''&&await page.getByLabel('Qualys password',{exact:true}).inputValue()==='','credential_fields_retained');
 ensure(observed.response.status()===201,'credential_upload_failed');const receipt=credentialReceipt(await observed.response.json(),observed.request,scanner);observed.request.input.value='';observed.raw='';
 await page.getByRole('status').filter({hasText:'Credential version recorded'}).waitFor();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();return receipt;
}

function sameSource(view,state){return view.connector_id===state.connector_id&&view.source_id===state.source_id&&view.source_tuple.source_family===state.source_tuple.source_family&&view.source_tuple.source_account_id===state.source_tuple.source_account_id&&view.source_tuple.scope_key===state.source_tuple.scope_key;}
async function recoveryJourney(session){
 ensure(uuid(session.principal_id),'recovery_actor_missing');let cid,source,scanner;
 if(recoveryPrepare){
  const matches=[];let cursor=null;const seen=new Set();
  for(let pageNumber=0;pageNumber<100;pageNumber++){
   const list=await api('/api/v1/connectors?limit=25'+(cursor?'&cursor='+encodeURIComponent(cursor):''));ensure(list.status===200&&list.body?.schema_version===1&&Array.isArray(list.body.items),'source_discovery_failed');
   for(const item of list.body.items){if(item.source?.source_family!=='qualys')continue;ensure(uuid(item.connector_id)&&uuid(item.source.source_id),'source_discovery_identity_missing');const candidate=await readScanner(item.connector_id,item.source.source_id);if(candidate.display_name===credentials.scanner.display_name&&candidate.account_label===credentials.scanner.account_label&&candidate.environment_label===credentials.scanner.environment_label)matches.push(candidate);}
   cursor=list.body.next_cursor;if(cursor===null)break;ensure(typeof cursor==='string'&&cursor.length>0&&!seen.has(cursor)&&pageNumber<99,'source_discovery_incomplete');seen.add(cursor);
  }
  ensure(matches.length===1,'source_labels_not_unique');scanner=matches[0];cid=scanner.connector_id;source=scanner.source_id;
 }else{ensure(capturedRecovery.principal_id===session.principal_id,'recovery_actor_changed');cid=capturedRecovery.connector_id;source=capturedRecovery.source_id;scanner=await readScanner(cid,source);ensure(sameSource(scanner,capturedRecovery),'recovery_source_changed');}
 await sourcePage(cid,source);await page.getByRole('heading',{name:scanner.display_name,exact:true}).waitFor();
 await page.getByLabel('Reason for scanner action').fill(credentials.scanner.rationale);await page.getByLabel('Scanner evidence reference').fill(credentials.scanner.evidence_ref);
 ensure(scanner.recovery?.state==='quarantined'&&scanner.recovery.fresh_credentials_required===true&&uuid(scanner.recovery.epoch_id),'recovery_quarantine_missing');
 if(recoveryPrepare){
  ensure(scanner.recovery.fresh_version_ready===false,'fresh_credential_precondition_missing');
  const receipt=await freshCredential(cid,source,scanner);const current=await readScanner(cid,source);
  ensure(sameSource(current,scanner)&&current.recovery.state==='quarantined'&&current.recovery.fresh_version_ready===true&&current.recovery.clearance_state==='missing'&&current.recovery.epoch_id===scanner.recovery.epoch_id&&current.credential.version_id===receipt.result.version_id&&current.credential.secret_id===scanner.credential.secret_id,'fresh_credential_readback_failed');
  const state=recoveryState({schema_version:1,kind:'scanner_recovery',origin,principal_id:session.principal_id,connector_id:cid,source_id:source,source_tuple:current.source_tuple,secret_id:current.credential.secret_id,version_id:current.credential.version_id,recovery_epoch_id:current.recovery.epoch_id,configuration_revision:current.configuration_revision},origin);
  await privateWrite(arg('--recovery-state'),JSON.stringify(state));await page.screenshot({path:evidence+'/recovery-fresh-credential.png',fullPage:true});return 'fresh_credential_confirmed_awaiting_external_host_approval';
 }
 ensure(scanner.credential.secret_id===capturedRecovery.secret_id&&scanner.credential.version_id===capturedRecovery.version_id&&scanner.recovery.epoch_id===capturedRecovery.recovery_epoch_id&&scanner.configuration_revision===capturedRecovery.configuration_revision&&scanner.recovery.fresh_version_ready===true&&scanner.recovery.clearance_state==='available'&&uuid(scanner.recovery.approval_id)&&Date.parse(scanner.recovery.approval_expires_at)>Date.now(),'host_approval_binding_unavailable');
 const slot=await api('/api/v1/connectors/'+cid+'/secrets/'+scanner.credential.secret_id+'?source_id='+source);ensure(slot.status===200&&slot.body?.secret?.secret_id===scanner.credential.secret_id&&slot.body?.source?.source_id===source&&slot.body?.revisions?.secret===scanner.credential.revision,'public_secret_fence_missing');
 const observed=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/assessment/commands'&&r.request().method()==='POST');await page.getByRole('button',{name:'Apply host clearance',exact:true}).click();const response=await observed;ensure(response.status()===200,'clearance_not_committed');const receipt=await response.json(),sent=response.request().postDataJSON();
 ensure(sent.schema_version===1&&sent.action==='connector.recovery.clearance.apply'&&sent.target_id==='00000000-0000-4000-8000-000000000000'&&uuid(sent.command_id)&&JSON.stringify(Object.entries(sent.expected_revisions).sort())===JSON.stringify(Object.entries(slot.body.revisions).sort())&&sent.payload?.connector_id===cid&&sent.payload?.source_id===source&&sent.payload?.secret_id===capturedRecovery.secret_id&&sent.payload?.version_id===capturedRecovery.version_id&&sent.payload?.recovery_epoch_id===capturedRecovery.recovery_epoch_id,'clearance_fence_mismatch');
 ensure(receipt.command_id===sent.command_id&&receipt.action===sent.action&&uuid(receipt.audit_event_id)&&receipt.result?.connector_id===cid&&receipt.result?.source_id===source&&receipt.result?.version_id===capturedRecovery.version_id&&receipt.result?.recovery?.state==='awaiting_activation','clearance_receipt_mismatch');await page.getByRole('status').filter({hasText:'Clearance applied'}).waitFor();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();
 const tested=await scannerClick(cid,source,'Test connection','scanner.connection.test');await page.locator('.scanner-workspace[aria-busy=false]').waitFor();await scannerClick(cid,source,'Activate configuration','scanner.configuration.activate');await page.locator('.scanner-workspace[aria-busy=false]').waitFor();
 await page.reload({waitUntil:'domcontentloaded'});await page.locator('.scanner-workspace[aria-busy=false]').waitFor();const persisted=await readScanner(cid,source);
 ensure(sameSource(persisted,capturedRecovery)&&persisted.recovery?.state==='clear'&&persisted.lifecycle==='active'&&persisted.configuration_revision===capturedRecovery.configuration_revision&&persisted.active_configuration_revision===capturedRecovery.configuration_revision&&persisted.credential.secret_id===capturedRecovery.secret_id&&persisted.credential.version_id===capturedRecovery.version_id&&persisted.validation?.status==='succeeded'&&persisted.validation?.operation_id===tested.result.operation_id&&persisted.validation?.configuration_revision===capturedRecovery.configuration_revision&&persisted.validation?.credential_version_id===capturedRecovery.version_id,'recovery_persisted_readback_failed');
 ensure(await page.getByLabel('Qualys username',{exact:true}).inputValue()===''&&await page.getByLabel('Qualys password',{exact:true}).inputValue()==='','credential_fields_retained');await page.screenshot({path:evidence+'/recovery-clear-active.png',fullPage:true});return 'clearance_test_activation_persisted';
}

async function waitAdminReady(){
  const heading=page.getByText('Access groups grant actions',{exact:true});
  const create=page.getByRole('button',{name:'Create access group',exact:true});
  await heading.waitFor({state:'visible',timeout:30000});
  await create.waitFor({state:'visible',timeout:30000});
  requireAdminRendered({loading:false,error:null,headingVisible:await heading.isVisible(),createButtonVisible:await create.isVisible(),createButtonEnabled:!(await create.isDisabled())});
  return create;
}
async function cardFor(groupId,revision){
  const card=page.locator('section[aria-label="Access group records"] article').filter({hasText:'Local preview audit smoke'});
  await card.waitFor({state:'visible',timeout:30000});
  const text=await card.innerText();
  ensure(text.includes(groupId)&&new RegExp(`Revision\\s+${revision}(?:\\D|$)`).test(text),'rendered_admin_object_mismatch');
  return card;
}
try{
  if(verifyRestoredSession){
    await restoredSessionDenied(page,capturedSession,origin);
    await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});await claimedUi();ensure(authenticationDenied(await api('/api/v1/deployment')),'saved_session_retained_admin');
    cookieLifetime(capturedSession);await page.screenshot({path:evidence+'/restored-session-rejected.png',fullPage:true});cookieLifetime(capturedSession);console.log(JSON.stringify({restored_session:'rejected',status:401,setup:'claimed',fresh_login:'not performed'}));
  }else if(verifySetupClosed){
    ensure(authenticationDenied(await sessionRead())&&(await context.cookies()).length===0,'anonymous_precondition_missing');await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});await claimedUi();
    const rejected=await api('/api/v1/auth/setup/claim',{method:'POST',body:{capability:credentials.capability,username,password,display_name:credentials.display_name}});ensure(authenticationDenied(rejected),'consumed_setup_not_rejected');
    ensure((await context.cookies()).every(c=>c.name!=='uvm_session')&&authenticationDenied(await sessionRead())&&authenticationDenied(await api('/api/v1/deployment')),'setup_created_session');
    const login=await api('/api/v1/auth/local/login',{method:'POST',body:{username,password}});ensure(authenticationDenied(login),'probe_account_authenticated');ensure((await context.cookies()).every(c=>c.name!=='uvm_session'),'probe_account_created_session');await page.reload();await claimedUi();await page.screenshot({path:evidence+'/restored-setup-closed.png',fullPage:true});console.log(JSON.stringify({restored_setup:'claimed',claim:'rejected',probe_login:'rejected',session:'absent',status:401}));
  }else{
  await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});
  if(localMode){
    await page.getByRole('heading',{name:localSetup?'Set up your VOLT account':'Sign in to VOLT'}).waitFor();
    if(localSetup){await page.getByLabel('One-use capability',{exact:true}).fill(credentials.capability);await page.getByLabel('Display name',{exact:true}).fill(credentials.display_name);}
    await page.getByLabel('Username',{exact:true}).fill(username);
    await page.getByLabel(localSetup?'New password':'Password',{exact:true}).fill(password);
    await page.getByRole('button',{name:localSetup?'Create administrator account':'Sign in',exact:true}).click();
    await waitForSession(page,{status:200,authenticated:true});
    const localSession=(await api('/api/v1/auth/session')).body;
    ensure(localSession?.credential_mode==='local_session','local_session_mode_required');
    await page.getByRole('button',{name:'Sign out',exact:true}).waitFor();
    ensure(await page.locator('input[type=password]').count()===0,'credential_form_not_cleared');
    if(localSetup){ensure(localSession.protected_admin===true,'setup_admin_not_confirmed');await page.getByRole('heading',{name:'Your workspace is ready for its first scanner'}).waitFor();}
    await page.screenshot({path:`${evidence}/local-signed-in.png`,fullPage:true});
    if(registerLocalScanner){
      ensure(localSession.protected_admin===true,'registration_admin_required');
      await page.getByRole('link',{name:'Overview',exact:true}).click();
      await page.getByRole('button',{name:'Register scanner',exact:true}).click();
      for(const [label,key] of [['Display name','display_name'],['Account label','account_label'],['Environment label','environment_label'],['Reason for registration','rationale'],['Evidence reference','evidence_ref']])await page.getByLabel(label,{exact:true}).fill(credentials.scanner[key]);
      await page.getByLabel('Qualys platform',{exact:true}).selectOption(credentials.scanner.platform_id);
      await page.getByRole('checkbox',{name:'Grant me read access'}).setChecked(credentials.scanner.grant_initial_read);
      const registrationResponse=page.waitForResponse(r=>r.url().endsWith('/api/v1/assessment/commands')&&r.request().method()==='POST');
      await page.getByRole('button',{name:'Register disabled scanner',exact:true}).click();
      const registrationHttp=await registrationResponse;ensure(registrationHttp.status()===200,'registration_response_failed');
      const registered=(await registrationHttp.json()).result;ensure(registered?.lifecycle==='disabled'&&registered?.source_tuple?.source_family==='qualys'&&registered?.credential_slots?.qualys_vm_basic?.secret_id,'registration_identity_missing');
      await page.getByRole('status').filter({hasText:'Registration confirmed. Current connection state: disabled'}).waitFor();
      const cid=registered.allocated_ids.connector_id,source=registered.allocated_ids.source_id;
      await page.locator('a[href="#scanner?connector_id='+encodeURIComponent(cid)+'&source_id='+encodeURIComponent(source)+'"]').click();
      await page.getByRole('heading',{name:credentials.scanner.display_name,exact:true}).waitFor();
      let scanner=(await api('/api/v1/scanners/'+cid+'?source_id='+source)).body;
      ensure(scanner?.source_tuple?.source_account_id===registered.source_tuple.source_account_id&&scanner?.source_tuple?.scope_key===registered.source_tuple.scope_key&&scanner?.credential?.secret_id===registered.credential_slots.qualys_vm_basic.secret_id,'scanner_identity_mismatch');
      await page.getByLabel('Reason for scanner action').fill(credentials.scanner.rationale);
      await page.getByLabel('Scanner evidence reference').fill(credentials.scanner.evidence_ref);
      await scannerClick(cid,source,'Save Qualys configuration','scanner.configuration.save');
      await freshCredential(cid,source);
      await scannerClick(cid,source,'Test connection','scanner.connection.test');
      await scannerClick(cid,source,'Activate configuration','scanner.configuration.activate');
      const collected=await scannerClick(cid,source,'Collect now','scanner.collection.start');
      const detections=await api('/api/v1/scanners/'+cid+'/runs/'+collected.result.run_id+'/detections?source_id='+source+'&limit=50');
      ensure(detections.status===200&&detections.body?.items?.length>0&&detections.body.coverage?.status==='unknown'&&detections.body.source_freshness?.status==='unknown','persisted_source_observations_missing');
      await page.getByRole('cell',{name:detections.body.items[0].qid}).first().waitFor();
      await page.screenshot({path:`${evidence}/local-qualys-observations.png`,fullPage:true});
    }
    const recoveryOutcome=recoveryPrepare||recoveryComplete?await recoveryJourney(localSession):'not requested';
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await waitForSession(page,{status:401,authenticated:false});
    await page.getByRole('heading',{name:'Sign in to VOLT'}).waitFor();
    console.log(JSON.stringify({browser_login:'passed',mode:'local',logout:'confirmed',recovery:recoveryOutcome,setup:localSetup?'confirmed':'not requested',registration:registerLocalScanner?'Qualys registration, configuration, credential, test, activation, collection and persisted observations confirmed':'not requested'}));
  }else{
  await page.getByText(deploymentLabel,{exact:true}).waitFor({state:'visible',timeout:10000});
  await page.getByRole('link',{name:/sign in/i}).click({timeout:10000});
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button',{name:'Sign in'}).click();
  await waitForSession(page,{status:200,authenticated:true});
  const session=(await api('/api/v1/auth/session')).body;
  requireSession(session,{issuer,subject,principal});
  if(process.argv.includes('--initialize-development')){
    const bootstrap=await api('/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,body:{policy:{grants:[],denies:[],owner_directory:[{owner_id:principal,owner_type:'person',display_name:'Synthetic Local Preview Administrator',enabled:true}],acceptance_material_changes:{},exception_warning_routes:[]}}});
    ensure([200,409].includes(bootstrap.status),`initial_policy_bootstrap_failed_${bootstrap.status}`);
    let catalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    ensure(catalogue.caller?.principal_id===principal,'bootstrap_administrator_not_authorised');
    if(catalogue.authority_mode==='legacy'){
      const activation=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,membership_ids:[],action:'native.authority.activate',expected_revisions:{target:catalogue.policy_revision,policy:catalogue.policy_revision,authority:catalogue.authority_revision,identity_membership:0,owners:0},payload:{mapping_revision:1,rationale:'Activate native authority for the private synthetic local preview',evidence_ref:'local-preview-bootstrap'}}});
      ensure(activation.status===200,`native_authority_activation_failed_${activation.status}`);
    }
  }
  let saved,createReceipt,membershipReceipt;
  if(!readbackOnly){
    await page.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
    const createButton=await waitAdminReady();
    await page.screenshot({path:`${evidence}/admin-initial.png`,fullPage:true});
    const latestCatalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    const envelope=latestCatalogue.caller?.grantable;
    ensure(latestCatalogue.authority_mode==='uvm_native_v1'&&latestCatalogue.caller?.principal_id===principal,'native_admin_catalogue_identity_or_mode_mismatch');
    ensure(envelope?.actions?.includes('access_group.read'),'local_bootstrap_action_envelope_missing');
    const groupId=crypto.randomUUID(), commandId=crypto.randomUUID(), permissionId=crypto.randomUUID();
    const roleId='00000000-0000-4000-8000-000000000002';
    const created=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:commandId,target_id:zero,membership_ids:[],action:'access_group.create',expected_revisions:{target:latestCatalogue.policy_revision,policy:latestCatalogue.policy_revision,authority:latestCatalogue.authority_revision,ownership:latestCatalogue.ownership_revision,identity_membership:0,owners:0},payload:{access_group_id:groupId,display_name:'Local preview audit smoke',description:'Synthetic local administrator smoke operation',enabled:true,source_scopes:[{source_family:'local',source_account_id:'volt-local-preview',scope_key:'all'}],permissions:[{permission_id:permissionId,role_id:roleId,action:'access_group.read',target_scope:{group_ids:[groupId],source_families:['local'],environments:[],service_ids:[],membership_mode:'explicit'},limits:envelope.limits,separation_of_duties:envelope.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,required_approver_count:1,prohibited_action_pairs:[]}}],rationale:'Verify a public audited administrator operation in the synthetic local preview',evidence_ref:'local-preview-smoke'}}});
    ensure(created.status===200,`public_admin_create_failed_${created.status}_${JSON.stringify(created.body)}`);
    createReceipt=created.body;
    requireReceipt(createReceipt,{commandId,targetId:zero,groupId,action:'access_group.create',objectRevision:1});
    const membershipCatalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    const membershipCommandId=crypto.randomUUID();
    const membership=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:membershipCommandId,target_id:zero,membership_ids:[],action:'access_group.membership.set',expected_revisions:policyExpectedRevisions(membershipCatalogue,createReceipt.result.object_revision),payload:{access_group_id:groupId,principal_id:principal,effective_from:new Date(Date.now()+1000).toISOString(),effective_until:null,enabled:true,rationale:'Bind the local administrator to the native group for provider-cap qualification',evidence_ref:'local-preview-provider-cap'}}});
    ensure(membership.status===200,`native_membership_create_failed_${membership.status}_${JSON.stringify(membership.body)}`);
    membershipReceipt=membership.body;
    requireReceipt(membershipReceipt,{commandId:membershipCommandId,targetId:zero,
      groupId,action:'access_group.membership.set'});
    ensure(membershipReceipt.result.object_revision===createReceipt.result.object_revision+1,
      'native_membership_receipt_did_not_advance_group_revision');
    const refresh=page.getByRole('button',{name:'Refresh administration',exact:true});
    await refresh.click();
    await cardFor(groupId,membershipReceipt.result.object_revision);
    await page.screenshot({path:`${evidence}/admin-operation.png`,fullPage:true});
    const readback=await api('/api/v1/assessment/access-groups');
    ensure(readback.status===200,'public_access_group_readback_failed');
    const item=readback.body.items?.find(x=>x.access_group_id===groupId);
    const createAudit=item?.history?.find(x=>x.event_id===createReceipt.audit_event_id);
    const membershipAudit=item?.history?.find(x=>x.event_id===membershipReceipt.audit_event_id);
    requireAudit(item,createAudit,{groupId,action:'access_group.create',displayName:'Local preview audit smoke',description:'Synthetic local administrator smoke operation',enabled:true,objectRevision:createReceipt.result.object_revision,auditEventId:createReceipt.audit_event_id,actorId:principal});
    requireAudit(item,membershipAudit,{groupId,action:'access_group.membership.set',membershipPrincipal:principal,objectRevision:membershipReceipt.result.object_revision,auditEventId:membershipReceipt.audit_event_id,actorId:principal});
    ensure(item.revision===membershipReceipt.result.object_revision,'public_object_revision_does_not_match_membership_receipt');
    saved={schema_version:1,issuer,subject,principal_id:principal,
      receipts:{create:createReceipt,membership:membershipReceipt},
      object:{access_group_id:item.access_group_id,display_name:item.display_name,description:item.description,enabled:item.enabled,revision:item.revision},
      audit_after_values:{create:createAudit.after_value,membership:membershipAudit.after_value}};
    await writeFile(`${evidence}/smoke-state.json`,JSON.stringify(saved,null,2)+'\n',{mode:0o600});
    await writeFile(`${evidence}/public-admin-command-receipts.json`,JSON.stringify(saved.receipts,null,2)+'\n',{mode:0o600});
  }else{
    saved=JSON.parse(await readFile(`${evidence}/smoke-state.json`,'utf8'));
    ensure(saved.issuer===issuer&&saved.subject===subject&&saved.principal_id===principal,'persisted_smoke_identity_binding_mismatch');
    createReceipt=saved.receipts?.create;
    membershipReceipt=saved.receipts?.membership;
    ensure(createReceipt&&membershipReceipt,'persisted_smoke_receipts_missing');
    requireReceipt(createReceipt,{commandId:createReceipt?.command_id,targetId:zero,groupId:saved.object.access_group_id,action:'access_group.create'});
    requireReceipt(membershipReceipt,{commandId:membershipReceipt?.command_id,targetId:zero,groupId:saved.object.access_group_id,action:'access_group.membership.set'});
    await page.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
    await waitAdminReady();
    const refresh=page.getByRole('button',{name:'Refresh administration',exact:true});
    await refresh.click();
    await cardFor(saved.object.access_group_id,saved.object.revision);
    await page.screenshot({path:`${evidence}/admin-restart.png`,fullPage:true});
  }
  const readback=await api('/api/v1/assessment/access-groups');
  ensure(readback.status===200,'public_access_group_readback_failed');
  const item=readback.body.items?.find(x=>x.access_group_id===saved.object.access_group_id);
  const createAudit=item?.history?.find(x=>x.event_id===createReceipt.audit_event_id);
  const membershipAudit=item?.history?.find(x=>x.event_id===membershipReceipt.audit_event_id);
  if(readbackOnly){
    requireReceipt(createReceipt,{commandId:createReceipt.command_id,targetId:zero,groupId:item.access_group_id,action:'access_group.create',objectRevision:saved.audit_after_values.create.revision});
    requireReceipt(membershipReceipt,{commandId:membershipReceipt.command_id,targetId:zero,groupId:item.access_group_id,action:'access_group.membership.set',objectRevision:saved.object.revision});
    requireAudit(item,createAudit,{groupId:item.access_group_id,action:'access_group.create',displayName:saved.object.display_name,description:saved.object.description,enabled:saved.object.enabled,objectRevision:createReceipt.result.object_revision,auditEventId:createReceipt.audit_event_id,actorId:principal});
    requireAudit(item,membershipAudit,{groupId:item.access_group_id,action:'access_group.membership.set',membershipPrincipal:principal,objectRevision:membershipReceipt.result.object_revision,auditEventId:membershipReceipt.audit_event_id,actorId:principal});
    requirePersistedState(item,createAudit,membershipAudit,saved);
    await writeFile(`${evidence}/public-admin-smoke-restart.json`,JSON.stringify({environment:'local synthetic OIDC container',principal_id:principal,issuer,subject,credential_mode:'oidc_session',group_id:item.access_group_id,create_command_id:createReceipt.command_id,create_receipt_audit_event_id:createReceipt.audit_event_id,membership_command_id:membershipReceipt.command_id,membership_receipt_audit_event_id:membershipReceipt.audit_event_id,public_readback_status:readback.status,object_revision:item.revision,create_audit_event_id:createAudit.event_id,membership_audit_event_id:membershipAudit.event_id,restart_readback:true},null,2)+'\n',{mode:0o600});
  }else{
    requireAudit(item,createAudit,{groupId:saved.object.access_group_id,action:'access_group.create',displayName:saved.object.display_name,description:saved.object.description,enabled:saved.object.enabled,objectRevision:createReceipt.result.object_revision,auditEventId:createReceipt.audit_event_id,actorId:principal});
    requireAudit(item,membershipAudit,{groupId:saved.object.access_group_id,action:'access_group.membership.set',membershipPrincipal:principal,objectRevision:membershipReceipt.result.object_revision,auditEventId:membershipReceipt.audit_event_id,actorId:principal});
    ensure(item.revision===membershipReceipt.result.object_revision,'public_object_revision_does_not_match_membership_receipt');
    await writeFile(`${evidence}/public-admin-smoke.json`,JSON.stringify({environment:'local synthetic OIDC container',principal_id:principal,issuer,subject,credential_mode:'oidc_session',group_id:item.access_group_id,create_command_id:createReceipt.command_id,create_receipt_audit_event_id:createReceipt.audit_event_id,membership_command_id:membershipReceipt.command_id,membership_receipt_audit_event_id:membershipReceipt.audit_event_id,public_readback_status:readback.status,object_revision:item.revision,create_audit_event_id:createAudit.event_id,membership_audit_event_id:membershipAudit.event_id,restart_readback:false},null,2)+'\n',{mode:0o600});
  }
  if(verifyProviderRevocation){
    ensure(readbackOnly,'provider revocation proof must follow the persisted readback phase');
    phase='before-removal';await snapshot('before-provider-removal');
    const before=(await api('/api/v1/auth/session')).body;
    ensure(before.authority?.role_ids?.includes('00000000-0000-4000-8000-000000000002'),'native_role_not_present_before_provider_removal');
    ensure(before.authority?.source_scopes?.some(s=>s[0]==='local'&&s[1]==='volt-local-preview'&&s[2]==='all'),'native_scope_not_present_before_provider_removal');
    const composeDirectory=arg('--compose-directory'), envFile=arg('--env-file'), project=arg('--project');
    const controlScript="import json,pathlib,sys,urllib.request; token=pathlib.Path('/run/uvm-g7-secrets/oidc_operator_secret').read_text().strip(); body=json.loads(sys.argv[1]); req=urllib.request.Request('http://127.0.0.1:9000/__fixture/failure',data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}); response=urllib.request.urlopen(req,timeout=10); print(response.status)";
    phase='provider-removal';
    const control=execFileSync('docker',['compose','-f',path.join(composeDirectory,'compose.yaml'),'-f',path.join(composeDirectory,'demo.yaml'),'--env-file',envFile,'-p',project,'exec','-T','volt','/opt/uvm/venv/bin/python','-c',controlScript,JSON.stringify({mode:null,identities:[{subject,groups:[]}]})],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
    ensure(control.trim().split(/\r?\n/).at(-1)==='200','synthetic_provider_fixture_update_failed');
    phase='old-session-probe';
    const revoked=await waitForSession(page,{status:401});
    ensure(revoked.status===401,'old_session_revocation_not_observed');
    // The current URL may only differ by hash from '/', so goto('/') can be
    // same-document navigation and preserve the revoked in-memory session.
    await snapshot('old-session-401');phase='reload';
    const reloadResponse=await page.reload({waitUntil:'domcontentloaded'});
    trace.push({kind:'reload-result',at:Date.now(),status:reloadResponse?.status(),url:reloadResponse?safeUrl(reloadResponse.url()):null});
    await snapshot('after-reload');
    try{await page.getByRole('link',{name:/sign in/i}).click({timeout:30000});}
    catch(error){
      await snapshot('sign-in-link-missing');
      const observed=await page.evaluate(async()=>{
        const response=await fetch('/api/v1/auth/session',{credentials:'same-origin',cache:'no-store'});
        let session=null;try{session=await response.json();}catch{}
        return {url:location.href,title:document.title,readyState:document.readyState,
          session_status:response.status,session_authenticated:session?.authenticated??null,
          session_code:session?.detail?.code??session?.code??null,
          visible_text:document.body.innerText,
          links:[...document.querySelectorAll('a')].map(a=>({text:a.innerText,href:a.getAttribute('href'),visible:!!(a.offsetWidth||a.offsetHeight||a.getClientRects().length)})),
          buttons:[...document.querySelectorAll('button')].map(b=>({text:b.innerText,disabled:b.disabled,visible:!!(b.offsetWidth||b.offsetHeight||b.getClientRects().length)}))};
      });
      await page.screenshot({path:`${evidence}/provider-removal-fresh-login-state.png`,fullPage:true});
      await writeFile(`${evidence}/provider-removal-fresh-login-state.json`,JSON.stringify(observed,null,2)+'\n',{mode:0o600});
      throw error;
    }
    await page.getByLabel('Username').fill(username);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button',{name:'Sign in'}).click();
    await waitForSession(page,{status:200,authenticated:true});
    const after=(await api('/api/v1/auth/session')).body;
    ensure(after.authority?.role_ids?.length===0,'fresh_signin_recovered_native_role_after_provider_group_removal');
    ensure(after.authority?.source_scopes?.length===0,'fresh_signin_recovered_native_scope_after_provider_group_removal');
    ensure(after.authority?.access_groups?.includes(saved.object.access_group_id),'provider_removal_erased_native_membership_history');
    await writeFile(`${evidence}/provider-group-removal.json`,JSON.stringify({environment:'local synthetic OIDC Compose process',old_cookie_revoked:true,fresh_code_flow_authenticated:true,retained_native_access_group:true,effective_role_ids:after.authority.role_ids,effective_source_scopes:after.authority.source_scopes},null,2)+'\n',{mode:0o600});
  }
  console.log(JSON.stringify({browser_login:'passed',issuer,subject,principal_id:principal,admin_view:'loaded',admin_control:'enabled',...(readbackOnly?{restart_readback:readback.status}:{public_admin_readback:readback.status}),audited:true,create_audit_event_id:createReceipt.audit_event_id,membership_audit_event_id:membershipReceipt.audit_event_id,object_revision:item.revision,group_id:item.access_group_id,create_command_id:createReceipt.command_id,membership_command_id:membershipReceipt.command_id}));
  }
}
}catch(error){if(!localMode)throw error;process.stderr.write('Local browser verification failed.\n');process.exitCode=1;}finally{if(diagnostic){await Promise.allSettled([...pendingCaptures]);await snapshot('final');}await context.close();await browser.close();}
