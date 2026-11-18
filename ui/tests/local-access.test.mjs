// Rendered synthetic API coverage, not persistent authentication evidence.
import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {chromium} from 'playwright';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {scannerView,sourceTuple,sid,detectionPage,recoveryView,recoverySlot,legacyRecovery,clearanceReceipt,connectorError,clearanceDispositionError} from './scanner-fixture.mjs';
import {conformsToRegistrationContract} from './registration-contract.mjs';
import {mkdtemp,readFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
let directory,server,browser,origin;
before(async()=>{
 directory=await mkdtemp(join(tmpdir(),'volt-local-ui-'));
 await build({stdin:{contents:`import {createRoot} from 'react-dom/client';import LocalAccess from './LocalAccess';import App from './App';import './tokens.css';import './styles.css';createRoot(document.getElementById('root')).render(location.search==='?app'?<App/>:<LocalAccess config={{schema_version:1,mode:'local',setup_state:'required'}} onAuthenticated={()=>{document.querySelector('h1').textContent='Session refresh requested';}}/>);`,resolveDir:resolve(import.meta.dirname,'../src'),loader:'tsx'},jsx:'automatic',bundle:true,format:'esm',outfile:join(directory,'app.js'),logLevel:'silent'});
 server=createServer(async(req,res)=>{if(['/app.js','/app.css'].includes(req.url)){res.setHeader('Content-Type',req.url.endsWith('css')?'text/css':'text/javascript');res.end(await readFile(join(directory,req.url)));return;}res.setHeader('Content-Type','text/html');res.end('<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Synthetic local access</title><link rel="stylesheet" href="/app.css"></head><body><main><h1>Synthetic local access</h1><div id="root"></div></main><script type="module" src="/app.js"></script></body></html>');});
 await new Promise(r=>server.listen(46380,'127.0.0.1',r));origin='http://127.0.0.1:46380';browser=await chromium.launch({headless:true});
});
after(async()=>{await browser?.close();if(server)await new Promise(r=>server.close(r));if(directory)await rm(directory,{recursive:true,force:true});});
async function fixture(t,status=201){const context=await browser.newContext();t.after(()=>context.close());const page=await context.newPage();page.setDefaultTimeout(5000);let submitted;await page.route('**/api/**',async route=>{submitted={path:new URL(route.request().url()).pathname,body:route.request().postDataJSON()};await route.fulfill({status,headers:{'Retry-After':'60'},...(status===204?{}:{json:{schema_version:1}})});});await page.goto(origin);return {page,submitted:()=>submitted};}
async function setup(page){await page.getByLabel('One-use capability').fill('synthetic-capability');await page.getByLabel('Username',{exact:true}).fill('reviewer');await page.getByLabel('Display name').fill('Synthetic reviewer');await page.getByLabel('New password').fill('synthetic password for tests');}
test('first claim contains only capability and human account fields; clears secrets',async t=>{const {page,submitted}=await fixture(t);await setup(page);await page.getByRole('button',{name:'Create administrator account'}).click();await page.getByRole('heading',{name:'Session refresh requested'}).waitFor();assert.equal(submitted().path,'/api/v1/auth/setup/claim');assert.deepEqual(Object.keys(submitted().body).sort(),['capability','display_name','password','username']);assert.equal(await page.getByLabel('One-use capability').inputValue(),'');assert.equal(await page.getByLabel('New password').inputValue(),'');assert.deepEqual(await page.evaluate(()=>[localStorage.length,sessionStorage.length]),[0,0]);});
for(const [status,copy] of [[401,'not accepted'],[409,'already been used'],[429,'60 seconds'],[503,'unavailable']])test(`claim ${status} renders safe feedback and clears secrets`,async t=>{const {page}=await fixture(t,status);await setup(page);await page.getByRole('button',{name:'Create administrator account'}).click();await page.getByRole('alert').filter({hasText:copy}).waitFor();assert.equal(await page.getByLabel('New password').inputValue(),'');});
for(const [label,path] of [['Recover account','recovery'],['Activate account','enrol']])test(`${path} is purpose separated and returns to normal sign-in`,async t=>{const {page,submitted}=await fixture(t,204);await page.getByRole('button',{name:'Back to sign in'}).click();await page.getByRole('button',{name:label}).click();await page.getByLabel('One-use capability').fill('synthetic');await page.getByLabel('New password').fill('synthetic password for tests');await page.getByRole('button',{name:'Save password',exact:true}).click();await page.getByRole('heading',{name:'Sign in to VOLT'}).waitFor();assert.equal(submitted().path,'/api/v1/auth/local/'+path);assert.deepEqual(Object.keys(submitted().body).sort(),['capability','new_password']);});
test('keyboard focus, responsive reflow and zero WCAG axe violations with no secrets',async t=>{const {page}=await fixture(t);await page.getByRole('button',{name:'Back to sign in'}).click();assert.equal(await page.locator(':focus').textContent(),'Sign in to VOLT');await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});const evidence=process.env.VOLT_UI_EVIDENCE; if(evidence)await mkdir(evidence,{recursive:true});for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>v.id)),[]);if(evidence)await page.screenshot({path:join(evidence,`synthetic-login-${width}.png`),fullPage:true});}});

async function assertNoStoredSecrets(page){
 assert.deepEqual(await page.locator('input[type="password"]').evaluateAll(inputs=>inputs.map(input=>input.value)),await page.locator('input[type="password"]').evaluateAll(inputs=>inputs.map(()=>'')));
 assert.deepEqual(await page.evaluate(()=>[localStorage.length,sessionStorage.length]),[0,0]);
 assert.equal((await page.content()).includes('synthetic password for tests'),false);
 assert.equal((await page.content()).includes('synthetic-capability'),false);
}
test('hanging setup request clears fields immediately while preserving the captured request',async t=>{
 const {page}=await fixture(t);let release;
 const intercepted=new Promise(resolve=>{release=resolve;});
 await page.route('**/api/v1/auth/setup/claim',route=>{release(route);});
 await setup(page);
 await page.getByRole('button',{name:'Create administrator account'}).click();
 const request=await intercepted;
 t.after(()=>request.abort().catch(()=>{}));
 assert.equal(request.request().postDataJSON().password,'synthetic password for tests');
 assert.equal(request.request().postDataJSON().capability,'synthetic-capability');
 assert.equal(await page.getByRole('button',{name:'Please wait…'}).isDisabled(),true);
 await assertNoStoredSecrets(page);
 assert.equal(await page.getByLabel('Username',{exact:true}).inputValue(),'');
});
async function appFixture(t,signedIn){
 const context=await browser.newContext();t.after(()=>context.close());
 const page=await context.newPage();page.setDefaultTimeout(5000);
 await page.route('**/api/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/api/v1/auth/session')return route.fulfill({status:signedIn?200:401,json:signedIn?{schema_version:1,authenticated:true,credential_mode:'local_session',principal_id:'synthetic-local-user',csrf_token:'synthetic-csrf',source_scopes:[]}:{schema_version:1}});
  if(path==='/api/v1/auth/config')return route.fulfill({json:{schema_version:1,mode:'local',setup_state:signedIn?'claimed':'required'}});
  // Other workspaces may show an unsupported-response error. No authority is fabricated.
  return route.fulfill({json:{schema_version:1}});
 });
 await page.goto(origin+'/?app');return page;
}
test('populated setup form is remounted without secrets on workspace navigation',async t=>{
 const page=await appFixture(t,false);await setup(page);
 await page.getByRole('link',{name:'Reports',exact:true}).click();
 await page.getByRole('heading',{name:'Reports',exact:true}).waitFor();
 await assertNoStoredSecrets(page);
 assert.equal(await page.getByLabel('Username',{exact:true}).inputValue(),'');
 await page.goBack();await page.getByRole('heading',{name:'Findings',exact:true}).waitFor();
 await assertNoStoredSecrets(page);
});
test('populated password change closes on navigation and reopening has no retained credentials',async t=>{
 const page=await appFixture(t,true);
 await page.getByRole('button',{name:'Change password',exact:true}).click();
 await page.getByLabel('Current password').fill('synthetic-capability');
 await page.getByLabel('New password').fill('synthetic password for tests');
 await page.getByRole('link',{name:'Reports',exact:true}).click();
 await page.getByRole('heading',{name:'Reports',exact:true}).waitFor();
 assert.equal(await page.locator('input[type="password"]').count(),0);
 await page.getByRole('button',{name:'Change password',exact:true}).click();
 await page.getByLabel('Current password').waitFor();
 await assertNoStoredSecrets(page);
 await page.goBack();await page.getByRole('heading',{name:'Findings',exact:true}).waitFor();
 assert.equal(await page.locator('input[type="password"]').count(),0);
});
test('hanging authenticated password request clears both passwords before any response',async t=>{
 const page=await appFixture(t,true);let release;
 const intercepted=new Promise(resolve=>{release=resolve;});
 await page.route('**/api/v1/auth/local/password',route=>{release(route);});
 await page.getByRole('button',{name:'Change password',exact:true}).click();
 await page.getByLabel('Current password').fill('synthetic-capability');
 await page.getByLabel('New password').fill('synthetic password for tests');
 await page.getByRole('button',{name:'Change password and sign out',exact:true}).click();
 const request=await intercepted;t.after(()=>request.abort().catch(()=>{}));
 assert.equal(request.request().postDataJSON().current_password,'synthetic-capability');
 assert.equal(request.request().postDataJSON().new_password,'synthetic password for tests');
 assert.equal(await page.getByRole('button',{name:'Please wait…'}).isDisabled(),true);
 await assertNoStoredSecrets(page);
 await page.getByRole('link',{name:'Reports',exact:true}).click();
 await page.getByRole('heading',{name:'Reports',exact:true}).waitFor();
 assert.equal(await page.locator('input[type="password"]').count(),0);
});
const syntheticIds={installation:'00000000-0000-4000-8000-000000000001',connector:'00000000-0000-4000-8000-000000000002',source:'00000000-0000-4000-8000-000000000003',group:'00000000-0000-4000-8000-000000000004',role:'00000000-0000-4000-8000-000000000005'};
async function deploymentFixture(t,{admin=true,mode='normal',abandonMode='not_committed',retained=null}={}){
 const context=await browser.newContext();t.after(()=>context.close());const page=await context.newPage();page.setDefaultTimeout(5000);
 if(retained)await context.addInitScript(value=>sessionStorage.setItem('volt.scanner.registration:synthetic-local-user:00000000-0000-4000-8000-000000000001',value),retained);
 const calls=[],commands=[],abandonments=[];let committed=false,policyRevision=1;
 const receipt=cmd=>({schema_version:1,command_id:cmd.command_id,decision_id:syntheticIds.group,audit_event_id:syntheticIds.role,action:cmd.action,target_id:cmd.target_id,result:{effect:'native_administration_state_committed',policy_revision:policyRevision+1,authority_revision:policyRevision+1,connector_registry_revision:1,lifecycle:'disabled',source_tuple:sourceTuple,credential_slots:{qualys_vm_basic:{secret_id:sid(22)}},allocated_ids:{connector_id:syntheticIds.connector,source_id:syntheticIds.source,access_group_id:syntheticIds.group,role_id:syntheticIds.role}}});
 const summary={connector_id:syntheticIds.connector,source:{source_id:syntheticIds.source,source_family:'qualys',source_account_id:sourceTuple.source_account_id,scope_key:sourceTuple.scope_key},environment_label:'Test',lifecycle:'disabled',source_revision:1,connector_revision:1,configuration_revision:1};
 await page.route('**/api/**',async route=>{
  const path=new URL(route.request().url()).pathname;calls.push(path);
  if(path==='/api/v1/auth/session')return route.fulfill({json:{schema_version:1,authenticated:true,credential_mode:'local_session',principal_id:'synthetic-local-user',csrf_token:'synthetic-csrf',protected_admin:admin,source_scopes:[]}});
  if(path==='/api/v1/auth/config')return route.fulfill({json:{schema_version:1,mode:'local',setup_state:'claimed'}});
  if(path==='/api/v1/scanners/'+syntheticIds.connector)return route.fulfill({json:{...scannerView(),lifecycle:summary.lifecycle}});
  if(path==='/api/v1/deployment')return route.fulfill(mode==='forbidden'?{status:403,json:{detail:{code:'forbidden'}}}:mode==='unavailable'?{status:503,json:{detail:{code:'persistence_unavailable'}}}:{json:{schema_version:1,installation_id:syntheticIds.installation,connector_registry_revision:committed?1:0,can_register_connector:admin,connectors:committed?[summary]:[],policy_revision:committed?policyRevision+1:policyRevision,authority_revision:committed?policyRevision+1:policyRevision}});
  if(path.endsWith('/abandon')){
   const body=route.request().postDataJSON();abandonments.push(body);
   assert.equal(conformsToRegistrationContract(body.command),true,'abandonment must preserve the versioned public command contract');
   assert.equal(body.schema_version,1);
   assert.deepEqual(body.command,commands[0],'abandonment carries the exact original envelope');
   assert.equal(path,'/api/v1/assessment/commands/'+commands[0].command_id+'/abandon');
   assert.equal(route.request().headers()['x-csrf-token'],'synthetic-csrf');
   assert.deepEqual(Object.keys(body).sort(),['command','evidence_ref','rationale','schema_version']);
   if(abandonMode==='network')return route.abort();
   if(['409','404','503'].includes(abandonMode))return route.fulfill({status:Number(abandonMode),json:{schema_version:1,error:{code:'revision_conflict',message:'SYNTHETIC_RAW_ERROR_DO_NOT_RENDER',details:{outcome:'not_committed'}}}});
   const sort=value=>Array.isArray(value)?value.map(sort):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])])):value;
   const canonical=JSON.stringify(sort({...body.command,principal_id:'synthetic-local-user'})).replace(/[\u007f-\uffff]/g,char=>'\\u'+char.charCodeAt(0).toString(16).padStart(4,'0'));
   const digest=createHash('sha256').update(canonical).digest('hex');
   let result={schema_version:1,command_id:body.command.command_id,request_digest:digest,disposition:'not_committed',actor_id:'synthetic-local-user',audit_event_id:syntheticIds.role,committed_at:'2026-11-18T12:00:00Z'};
   if(abandonMode.startsWith('committed')){committed=true;summary.lifecycle='active';summary.configuration_revision=2;result={schema_version:1,command_id:body.command.command_id,request_digest:digest,disposition:'committed',receipt:receipt(body.command)};}
   if(abandonMode==='wrong_actor')result.actor_id='different-actor';
   if(abandonMode==='wrong_command')result.command_id=syntheticIds.source;
   if(abandonMode==='wrong_digest')result.request_digest='0'.repeat(64);
   if(abandonMode==='wrong_audit')result.audit_event_id='invalid';
   if(abandonMode==='wrong_time')result.committed_at='invalid';
   if(abandonMode==='committed_wrong_receipt')result.receipt.command_id=syntheticIds.source;
   if(abandonMode==='committed_wrong_source')summary.source.scope_key='other-scope';
   return route.fulfill({json:result});
  }
  if(path==='/api/v1/assessment/commands'){
   const cmd=route.request().postDataJSON();commands.push(cmd);
   if(!conformsToRegistrationContract(cmd))return route.fulfill({status:422,json:{schema_version:1,error:{code:'invalid_command'}}});
   if(mode==='lost-before-commit'&&cmd.command_id===commands[0].command_id){if(commands.length===1){policyRevision=2;return route.abort();}return route.fulfill({status:409,json:{schema_version:1,error:{code:'revision_conflict',details:{outcome:'not_committed'}}}});}
   if(mode==='conflict')return route.fulfill({status:409,json:{detail:{code:'revision_conflict'}}});
   committed=true;
   if(['lost','activated-after-commit'].includes(mode)&&commands.length===1)return route.abort();
   if(mode==='activated-after-commit'){summary.lifecycle='active';summary.configuration_revision=2;}
   if(mode==='mismatched-source')summary.source.scope_key='another-scope';
   return route.fulfill({json:{schema_version:1,command_id:cmd.command_id,decision_id:syntheticIds.group,audit_event_id:syntheticIds.role,action:cmd.action,target_id:cmd.target_id,result:{effect:'native_administration_state_committed',policy_revision:2,authority_revision:2,connector_registry_revision:1,lifecycle:'disabled',source_tuple:sourceTuple,credential_slots:{qualys_vm_basic:{secret_id:sid(22)}},allocated_ids:{connector_id:syntheticIds.connector,source_id:syntheticIds.source,access_group_id:syntheticIds.group,role_id:syntheticIds.role}}}});
  }
  return route.fulfill({json:{schema_version:1}});
 });
 await page.goto(origin+'/?app');return {page,calls,commands,abandonments};
}
async function fillRegistration(page){
 await page.getByRole('button',{name:'Register scanner',exact:true}).click();
 for(const [label,value] of [['Display name','Synthetic scanner'],['Account label','Synthetic account'],['Environment label','Test'],['Reason for registration','Synthetic browser coverage'],['Evidence reference','synthetic:test']])await page.getByLabel(label,{exact:true}).fill(value);
}
test('protected local administrator lands on honest empty dashboard without querying findings',async t=>{
 const {page,calls}=await deploymentFixture(t);await page.getByRole('heading',{name:'Your workspace is ready for its first scanner'}).waitFor();
 assert.equal(calls.some(path=>path.includes('/findings')||path.includes('/assessment/groups')||path.includes('/ingestion/')),false);
 await page.getByText('No scanners are registered. No vulnerability data or risk metrics are available yet.').waitFor();
});
test('normal local session never reads protected deployment even when overview is requested',async t=>{
 const {page,calls}=await deploymentFixture(t,{admin:false});await page.getByRole('button',{name:'Sign out',exact:true}).waitFor();
 await page.evaluate(()=>{location.hash='overview';});await page.getByRole('alert').filter({hasText:'Protected administrator access is required'}).waitFor();
 assert.equal(calls.includes('/api/v1/deployment'),false);
});
for(const read of [true,false])test(`registration read grant ${read} is explicit; readback stays disabled without activation`,async t=>{
 const {page,commands,calls}=await deploymentFixture(t);await fillRegistration(page);
 const choice=page.getByRole('checkbox',{name:'Grant me read access'});assert.equal(await choice.isChecked(),true);if(!read)await choice.uncheck();
 await page.getByRole('button',{name:'Register disabled scanner'}).click();await page.getByRole('status').filter({hasText:'Registration confirmed. Current connection state: disabled'}).waitFor();
 assert.equal(commands.length,1);assert.equal(commands[0].payload.grant_initial_read,read);assert.equal(commands[0].target_id,'00000000-0000-0000-0000-000000000000');assert.deepEqual(commands[0].membership_ids,[]);
 assert.deepEqual([commands[0].expected_policy_revision,commands[0].expected_authority_revision,commands[0].expected_connector_registry_revision],[1,1,0]);
 assert.equal(calls.some(p=>/activation|validation|secrets/.test(p)),false);
 await page.getByRole('link',{name:'Open Qualys source'}).waitFor();assert.equal(await page.evaluate(()=>sessionStorage.length),0);
});
test('lost registration response survives reload with frozen UUID, payload and revisions',async t=>{
 const {page,commands}=await deploymentFixture(t,{mode:'lost'});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();
 await page.getByRole('button',{name:'Retry same registration'}).waitFor();await page.reload();await page.getByRole('button',{name:'Retry same registration'}).click();
 await page.getByRole('status').filter({hasText:'Registration confirmed. Current connection state: disabled'}).waitFor();assert.equal(commands.length,2);assert.deepEqual(commands[1],commands[0]);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
});
test('registration conflict is visible and does not claim a scanner exists',async t=>{
 const {page,commands}=await deploymentFixture(t,{mode:'conflict'});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();
 await page.getByRole('alert').filter({hasText:'deployment changed'}).waitFor();assert.equal(commands.length,1);assert.equal(await page.getByRole('button',{name:'Configure connection'}).count(),0);
});
test('protected empty dashboard and registration reflow with zero WCAG axe violations',async t=>{
 const {page}=await deploymentFixture(t);await fillRegistration(page);await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});
 for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>v.id)),[]);if(process.env.VOLT_UI_EVIDENCE)await page.screenshot({path:join(process.env.VOLT_UI_EVIDENCE,`synthetic-registration-${width}.png`),fullPage:true});}
});

test('Qualys registration never opens the GitHub App configuration editor',async t=>{
 const {page,commands,calls}=await deploymentFixture(t);await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();
 await page.getByRole('link',{name:'Open Qualys source'}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Configure connection'}).count(),0);
 assert.equal(await page.getByRole('heading',{name:'Validate, then activate'}).count(),0);
 assert.equal(calls.some(path=>path.startsWith('/api/v1/connectors/')),false);
 assert.equal(commands.length,1);assert.equal(commands[0].action,'connector.binding.register');
});
test('confirmed registration survives subsequent activation and reports current lifecycle',async t=>{
 const {page,commands}=await deploymentFixture(t,{mode:'activated-after-commit'});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();
 await page.getByRole('button',{name:'Retry same registration'}).waitFor();await page.reload();await page.getByRole('button',{name:'Retry same registration'}).click();
 await page.getByRole('status').filter({hasText:'Registration confirmed. Current connection state: active'}).waitFor();
 assert.equal(commands.length,2);assert.deepEqual(commands[1],commands[0]);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
 assert.equal(await page.getByRole('button',{name:'Retry same registration'}).count(),0);
 assert.equal(await page.getByRole('button',{name:'Register scanner',exact:true}).isEnabled(),true);
});
test('lost-before-commit then generic policy conflict cannot discard the held command',async t=>{
 const {page,commands}=await deploymentFixture(t,{mode:'lost-before-commit'});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();
 await page.getByRole('button',{name:'Retry same registration'}).click();await page.getByRole('alert').filter({hasText:'deployment changed'}).waitFor();
 assert.equal(commands.length,2);assert.deepEqual(commands[1],commands[0]);
 assert.equal(await page.evaluate(()=>sessionStorage.length),1);
 await page.getByRole('button',{name:'Refresh deployment'}).click();
 await page.getByRole('button',{name:'Retry same registration'}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Cancel registration',exact:true}).isDisabled(),true);
 assert.equal(await page.evaluate(()=>sessionStorage.length),1);
});
test('a receipt for allocated IDs does not reconcile a different source tuple',async t=>{
 const {page}=await deploymentFixture(t,{mode:'mismatched-source'});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();
 await page.getByRole('alert').filter({hasText:'Registration outcome is unknown'}).waitFor();
 assert.equal(await page.evaluate(()=>sessionStorage.length),1);
 assert.equal(await page.getByRole('status').filter({hasText:'Registration confirmed'}).count(),0);
});

for(const mode of ['forbidden','unavailable'])test(`deployment ${mode} never becomes a false empty dashboard`,async t=>{
 const {page}=await deploymentFixture(t,{mode});await page.getByRole('alert').first().waitFor();assert.equal(await page.getByRole('heading',{name:'Your workspace is ready for its first scanner'}).count(),0);assert.equal(await page.getByRole('button',{name:'Register scanner',exact:true}).count(),0);
});

async function reviewAbandonment(page){
 await page.getByRole('button',{name:'Review abandonment',exact:true}).click();
 await page.getByLabel('Reason for reconciliation',{exact:true}).fill('Synthetic operator reconciliation');
 await page.getByLabel('Reconciliation evidence reference',{exact:true}).fill('synthetic:reconcile');
 await page.getByRole('checkbox',{name:'I reviewed the original registration'}).check();
}
test('terminal abandonment requires explicit review then separate fresh-revision replacement',async t=>{
 const {page,commands,abandonments}=await deploymentFixture(t,{mode:'lost-before-commit'});await fillRegistration(page);
 await page.getByRole('checkbox',{name:'Grant me read access'}).uncheck();
 await page.getByRole('button',{name:'Register disabled scanner'}).click();await page.getByRole('button',{name:'Retry same registration'}).click();await page.getByRole('alert').filter({hasText:'deployment changed'}).waitFor();
 assert.equal(abandonments.length,0);await reviewAbandonment(page);assert.equal(abandonments.length,0);
 await page.getByRole('button',{name:'Confirm abandonment if not committed'}).click();
 await page.getByRole('button',{name:'Review replacement with current revisions'}).waitFor();
 assert.equal(abandonments.length,1);assert.equal(commands.length,2);assert.equal(await page.evaluate(()=>sessionStorage.length),1);
 assert.equal(await page.getByRole('button',{name:'Retry same registration'}).count(),0);
 await page.getByRole('button',{name:'Review replacement with current revisions'}).click();
 await page.getByRole('heading',{name:'Review replacement registration'}).waitFor();
 assert.equal(commands.length,2);assert.equal(await page.getByLabel('Display name',{exact:true}).inputValue(),'Synthetic scanner');
 assert.equal(await page.getByRole('checkbox',{name:'Grant me read access'}).isChecked(),false);
 await page.getByRole('button',{name:'Register disabled scanner'}).click();await page.getByRole('status').filter({hasText:'Registration confirmed'}).waitFor();
 assert.equal(commands.length,3);assert.notEqual(commands[2].command_id,commands[0].command_id);assert.deepEqual(commands[2].payload,commands[0].payload);
 assert.deepEqual([commands[2].expected_policy_revision,commands[2].expected_authority_revision,commands[2].expected_connector_registry_revision],[2,2,0]);
});
test('abandonment returns an exact committed receipt and reconciles later activation without replacement',async t=>{
 const {page,commands}=await deploymentFixture(t,{mode:'lost',abandonMode:'committed'});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();await reviewAbandonment(page);
 await page.getByRole('button',{name:'Confirm abandonment if not committed'}).click();await page.getByRole('status').filter({hasText:'Registration confirmed. Current connection state: active'}).waitFor();
 assert.equal(commands.length,1);assert.equal(await page.evaluate(()=>sessionStorage.length),0);assert.equal(await page.getByRole('button',{name:'Review replacement with current revisions'}).count(),0);
});
for(const abandonMode of ['network','404','409','503','wrong_actor','wrong_command','wrong_digest','wrong_audit','wrong_time','committed_wrong_receipt','committed_wrong_source'])test(`abandonment ${abandonMode} preserves the original and never enables replacement`,async t=>{
 const {page,commands,abandonments}=await deploymentFixture(t,{mode:'lost-before-commit',abandonMode});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();await reviewAbandonment(page);
 await page.getByRole('button',{name:'Confirm abandonment if not committed'}).click();await page.getByRole('alert').first().waitFor();
 assert.equal(commands.length,1);assert.equal(abandonments.length,1);assert.equal(await page.evaluate(()=>sessionStorage.length),1);
 assert.equal(await page.getByRole('button',{name:'Review replacement with current revisions'}).count(),0);
 assert.equal((await page.locator('body').innerText()).includes('SYNTHETIC_RAW_ERROR_DO_NOT_RENDER'),false);
});
test('abandonment review is keyboard accessible and has zero axe violations at required widths',async t=>{
 const {page,abandonments}=await deploymentFixture(t,{mode:'lost'});await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();
 await page.getByRole('button',{name:'Review abandonment'}).click();assert.equal(await page.locator(':focus').textContent(),'Resolve this registration before replacing it');
 assert.equal(await page.getByRole('button',{name:'Confirm abandonment if not committed'}).isDisabled(),true);assert.equal(abandonments.length,0);
 await page.keyboard.press('Tab');assert.equal(await page.getByLabel('Reason for reconciliation',{exact:true}).evaluate(el=>el===document.activeElement),true);
 await page.keyboard.press('Tab');assert.equal(await page.getByLabel('Reconciliation evidence reference',{exact:true}).evaluate(el=>el===document.activeElement),true);
 await page.keyboard.press('Tab');await page.keyboard.press('Space');assert.equal(await page.getByRole('checkbox',{name:'I reviewed the original registration'}).isChecked(),true);assert.equal(abandonments.length,0);
 await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});
 for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>v.id)),[]);if(process.env.VOLT_UI_EVIDENCE)await page.screenshot({path:join(process.env.VOLT_UI_EVIDENCE,`synthetic-abandonment-${width}.png`),fullPage:true});}
});
test('synthetic registration server rejects missing version instead of issuing a permissive receipt',async t=>{
 const {page,commands}=await deploymentFixture(t);await fillRegistration(page);await page.getByRole('button',{name:'Register disabled scanner'}).click();await page.getByRole('status').filter({hasText:'Registration confirmed'}).waitFor();
 const invalid=structuredClone(commands[0]);delete invalid.schema_version;
 const response=await page.evaluate(async body=>{const r=await fetch('/api/v1/assessment/commands',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.status;},invalid);
 assert.equal(response,422);
});
for(const format of ['missing_version','wrong_version','unknown_field'])test(`retained ${format} stays byte-identical and blocked without submission or migration`,async t=>{
 const value={schema_version:1,command_id:syntheticIds.connector,action:'connector.binding.register',target_id:'00000000-0000-0000-0000-000000000000',membership_ids:[],expected_policy_revision:1,expected_authority_revision:1,expected_connector_registry_revision:0,payload:{display_name:'Synthetic retained scanner',source_family:'qualys',source_account_id:sourceTuple.source_account_id,scope_key:sourceTuple.scope_key,environment_label:'Test',rationale:'Prior attempt',evidence_ref:'synthetic:test',grant_initial_read:false}};
 if(format==='missing_version')delete value.schema_version;if(format==='wrong_version')value.schema_version=2;if(format==='unknown_field')value.extra='unsupported';
 const retained=JSON.stringify(value);const {page,commands,abandonments}=await deploymentFixture(t,{retained});
 await page.getByRole('alert').filter({hasText:'malformed or uses an unsupported envelope'}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Register scanner',exact:true}).isDisabled(),true);
 assert.equal(await page.getByRole('button',{name:'Review abandonment'}).count(),0);
 assert.equal(commands.length,0);assert.equal(abandonments.length,0);
 assert.equal(await page.evaluate(()=>sessionStorage.getItem('volt.scanner.registration:synthetic-local-user:00000000-0000-4000-8000-000000000001')),retained);
});

async function scannerFixture(t,{unconfigured=false,denied=false,readDenied=false,quarantined=false,hanging=false,lost=false,partial=false,configure=true,manage=true,terminal='succeeded',permissionsDenied=false,denialDelay=null,permissionStatus=403,permissionCode='forbidden',receiptless=false,stale=false,disposition='not_committed',recovery=null,clearanceResult='ok',reused=false,slotDenied=false,clearanceDisposition='not_committed',lostClearanceReplacement=false}={}){
 const context=await browser.newContext();t.after(()=>context.close());const page=await context.newPage();page.setDefaultTimeout(5000);const current=scannerView();
 if(!unconfigured)current.credential={secret_id:sid(22),version_id:sid(23),state:quarantined?'quarantined':'active',revision:1};
 if(quarantined)current.recovery=recoveryView();if(recovery){current.recovery=recovery;current.configuration_revision=1;}
 const clearances=[],clearanceAbandonments=[],clearanceProofs=new Map();
 const calls=[],commands=[],secrets=[],abandonments=[],operations=new Map(),proofs=new Map();let resolveSiblings;const siblingResponses=[];const siblings=new Promise(resolve=>{resolveSiblings=resolve;});page.on('response',response=>{const path=new URL(response.url()).pathname;if(path==='/api/v1/scanners/'+sid(2)||path==='/api/v1/connectors/'+sid(2)+'/permissions'){siblingResponses.push(response.status());if(siblingResponses.length===2)resolveSiblings([...siblingResponses]);}});let secretRevision=unconfigured?0:1,pendingRoute,receipts=new Map();
 await page.route('**/api/**',async route=>{
  const req=route.request(),url=new URL(req.url()),path=url.pathname;calls.push(path);
  if(path==='/api/v1/auth/session')return route.fulfill({json:{schema_version:1,authenticated:true,credential_mode:'local_session',principal_id:'synthetic-local-user',csrf_token:'synthetic-csrf',protected_admin:false,source_scopes:[]}});
  if(path==='/api/v1/auth/config')return route.fulfill({json:{schema_version:1,mode:'local',setup_state:'claimed'}});
  if(path==='/api/v1/connectors')return route.fulfill({json:{schema_version:1,items:[{schema_version:1,connector_id:sid(2),source:{source_id:sid(3),revision:1,...sourceTuple},lifecycle:current.lifecycle,configuration_revision:current.configuration_revision,settings:{environment_label:'Test'}}],next_cursor:null}});
  if(denialDelay==='scanner'&&path==='/api/v1/scanners/'+sid(2)||denialDelay==='permissions'&&path.endsWith('/permissions'))await new Promise(resolve=>setTimeout(resolve,40));
  if(path==='/api/v1/scanners/'+sid(2))return route.fulfill(denied?{status:403,json:{error:{code:'forbidden',message:'MUST_NOT_RENDER'}}}:{json:current});
  if(path.endsWith('/permissions')&&permissionsDenied)return route.fulfill({status:permissionStatus,json:{schema_version:1,error:{code:permissionCode,message:'MUST_NOT_RENDER',correlation_id:sid(90),details:{outcome:'not_committed',expected_revisions:null,current_revisions:null,lookup_url:null}}}});
  if(path.endsWith('/permissions'))return route.fulfill({json:{schema_version:1,connector_id:sid(2),source:{source_id:sid(3),revision:1,...sourceTuple},principal_id:'synthetic-local-user',revisions:current.expected_revisions,allowed:{'connector.read':true,'connector.configure':configure,'connector.secret.manage':manage,'github.repository.configure':false}}});
  if(path==='/api/v1/connectors/'+sid(2))return route.fulfill({json:{schema_version:1,connector_id:sid(2),source:{source_id:sid(3),...sourceTuple},secrets:unconfigured?[]:[{secret_id:sid(22),purpose:'qualys_vm_basic',revision:secretRevision}]}});
  if(path==='/api/v1/connectors/'+sid(2)+'/secrets/'+sid(22))return route.fulfill(slotDenied?{status:403,json:{schema_version:1,error:{code:'source_scope_forbidden',message:'MUST_NOT_RENDER',correlation_id:sid(90),details:{outcome:'not_committed',expected_revisions:null,current_revisions:null,lookup_url:null}}}}:{json:recoverySlot(current)});
  if(path.startsWith('/api/v1/assessment/commands/')&&path.endsWith('/abandon')){
   const body=req.postDataJSON();clearanceAbandonments.push(body);const original=clearances.find(c=>c.command_id===body.command.command_id);assert.deepEqual(body.command,original);assert.equal(path,'/api/v1/assessment/commands/'+original.command_id+'/abandon');assert.deepEqual(Object.keys(body).sort(),['command','evidence_ref','rationale','schema_version']);assert.equal(body.schema_version,1);assert.equal(req.headers()['x-csrf-token'],'synthetic-csrf');if(clearanceAbandonments.length>1)assert.deepEqual(body,clearanceAbandonments.find(x=>x.command.command_id===original.command_id));
   if(['403','404','409','503'].includes(clearanceDisposition))return route.fulfill({status:Number(clearanceDisposition),json:clearanceDispositionError({'403':'forbidden','404':'not_found','409':'command_conflict','503':'dependency_unavailable'}[clearanceDisposition])});
   if(clearanceDisposition==='partial')return route.fulfill({status:503,json:clearanceDispositionError('inconsistent_operation')});
   if(clearanceDisposition==='network')return route.abort();
   const sort=v=>Array.isArray(v)?v.map(sort):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sort(v[k])])):v;
   const digest=createHash('sha256').update(JSON.stringify(sort({principal_id:'synthetic-local-user',...body.command})).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))).digest('hex');
   let proof=clearanceProofs.get(original.command_id)??{schema_version:1,command_id:original.command_id,action:original.action,actor_id:'synthetic-local-user',request_digest:digest,disposition:'not_committed',audit_event_id:sid(92),committed_at:'2026-11-18T12:00:00Z'};
   if(clearanceDisposition==='committed'){delete proof.audit_event_id;delete proof.committed_at;proof.disposition='committed';proof.receipt=receipts.get(original.command_id);}
   if(clearanceDisposition==='wrong_actor')proof.actor_id='other-actor';if(clearanceDisposition==='wrong_digest')proof.request_digest='0'.repeat(64);if(clearanceDisposition==='wrong_action')proof.action='connector.configuration.stage';if(clearanceDisposition==='bad_audit')proof.audit_event_id='invalid';if(clearanceDisposition==='bad_time')proof.committed_at='invalid';if(clearanceDisposition==='admitted')proof.disposition='admitted';
   clearanceProofs.set(original.command_id,structuredClone(proof));if(clearanceDisposition==='lost'&&clearanceAbandonments.length===1)return route.abort();return route.fulfill({json:proof});
  }
  if(path==='/api/v1/assessment/commands'){
   const body=req.postDataJSON();clearances.push(body);assert.equal(body.action,'connector.recovery.clearance.apply');assert.equal(body.schema_version,1);assert.equal(body.target_id,'00000000-0000-4000-8000-000000000000');assert.deepEqual(Object.keys(body.payload).sort(),['connector_id','evidence_ref','rationale','recovery_epoch_id','secret_id','source_id','version_id']);assert.equal(req.headers()['x-csrf-token'],'synthetic-csrf');
   if(clearanceResult==='hanging'){pendingRoute=route;return;}
   if(['403','404','409'].includes(clearanceResult))return route.fulfill({status:Number(clearanceResult),json:connectorError(clearanceResult==='403'?'forbidden':clearanceResult==='404'?'not_found':'revision_conflict')});
   if(clearanceResult==='stale'&&body.command_id===clearances[0].command_id){current.expected_revisions.connector++;return route.fulfill({status:409,json:connectorError('revision_conflict')});}
   if(clearanceResult==='expired'&&body.command_id===clearances[0].command_id){
    if(clearances.length===1){current.recovery.clearance_state='expired';current.recovery.approval_expires_at='2020-01-01T00:00:00Z';return route.fulfill({status:409,json:connectorError('restore_quarantined')});}
    return route.fulfill({status:409,json:connectorError('revision_conflict')});
   }
   if(receipts.has(body.command_id))return route.fulfill({json:receipts.get(body.command_id)});
   assert.deepEqual(body.expected_revisions,recoverySlot(current).revisions);assert.equal(body.payload.recovery_epoch_id,current.recovery.epoch_id);assert.equal(body.payload.secret_id,current.credential.secret_id);assert.equal(body.payload.version_id,current.credential.version_id);
   const receipt=clearanceReceipt(body,current);current.recovery={...current.recovery,state:'awaiting_activation',clearance_state:'applied'};current.lifecycle='disabled';current.active_configuration_revision=null;current.validation=null;current.expected_revisions.connector++;receipts.set(body.command_id,structuredClone(receipt));
   if(clearanceResult==='lost'||lostClearanceReplacement&&clearances.length===2)return route.abort();if(clearanceResult==='wrong-epoch')receipt.result.recovery.recovery_epoch_id=sid(99);
   return route.fulfill({json:receipt});
  }
  if(path.endsWith('/versions')){
   const body=req.postDataJSON();secrets.push(body);assert.equal(body.purpose,'qualys_vm_basic');assert.equal(body.expected_revisions.secret,secretRevision);assert.equal(path,'/api/v1/connectors/'+sid(2)+'/secrets/'+sid(22)+'/versions');assert.deepEqual(Object.keys(JSON.parse(body.input.value)).sort(),['password','username']);
   if(hanging){pendingRoute=route;return;}
   if(reused)return route.fulfill({status:409,json:{schema_version:1,error:{code:'credential_material_reused',message:'MUST_NOT_RENDER',correlation_id:sid(90),details:{outcome:'not_committed',expected_revisions:null,current_revisions:null,lookup_url:null}}}});
   secretRevision++;current.credential.revision=secretRevision;current.credential.version_id=body.version_id;current.credential.state='active';current.lifecycle=current.configuration_revision?'staged':'disabled';current.active_configuration_revision=null;current.expected_revisions.connector++;current.validation=null;
   if(current.recovery.state!=='clear'){current.recovery={...current.recovery,state:'quarantined',fresh_version_ready:true,clearance_state:'missing',approval_id:null,approval_expires_at:null};current.lifecycle='disabled';}
   return route.fulfill({status:201,json:{schema_version:1,command_id:body.submission_id,action:'connector.secret.submit',target_id:'00000000-0000-4000-8000-000000000000',policy_revision:2,decision_id:sid(50),audit_event_id:sid(51),intents:[],result:{effect:'connector_secret_submitted',connector_id:sid(2),source_id:sid(3),revisions:{...current.expected_revisions,secret:secretRevision},configuration_revision:current.configuration_revision,active_configuration_revision:null,lifecycle:current.lifecycle,secret_id:sid(22),version_id:body.version_id,version_state:'active',submission_id:body.submission_id,submission_outcome:'committed',flow_id:null,recovery:legacyRecovery(current)}}});
  }
  if(path.endsWith('/abandon')&&path.startsWith('/api/v1/scanners/')){
   const body=req.postDataJSON();abandonments.push(body);const original=commands.find(c=>c.command_id===body.command.command_id);assert.deepEqual(body.command,original);assert.deepEqual(Object.keys(body).sort(),['command','evidence_ref','rationale','schema_version']);assert.equal(body.schema_version,1);assert.equal(req.headers()['x-csrf-token'],'synthetic-csrf');assert.equal(path,'/api/v1/scanners/'+sid(2)+'/commands/'+body.command.command_id+'/abandon');
   if(abandonments.length>1)assert.deepEqual(body,abandonments[0],'uncertain abandonment retains first reason/evidence and complete original');
   if(['403','404','409','503'].includes(disposition))return route.fulfill({status:Number(disposition),json:{error:{code:disposition==='403'?'forbidden':'command_conflict',message:'MUST_NOT_RENDER'}}});
   if(disposition==='network')return route.abort();
   const sort=v=>Array.isArray(v)?v.map(sort):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sort(v[k])])):v;
   const digest=createHash('sha256').update(JSON.stringify(sort({principal_id:'synthetic-local-user',command:body.command})).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))).digest('hex');
   let proof=proofs.get(body.command.command_id)??{schema_version:1,command_id:body.command.command_id,connector_id:sid(2),source_id:sid(3),action:body.command.action,actor_id:'synthetic-local-user',request_digest:digest,disposition:'not_committed',audit_event_id:sid(90),occurred_at:'2026-11-18T12:00:00Z'};
   if(disposition==='committed'){delete proof.audit_event_id;delete proof.occurred_at;proof.disposition='committed';proof.receipt=receipts.get(body.command.command_id);}
   if(disposition==='admitted'){delete proof.audit_event_id;delete proof.occurred_at;proof.disposition='admitted';proof.operation=receipts.get(body.command.command_id);}
   if(disposition==='wrong_actor')proof.actor_id='other-actor';if(disposition==='wrong_digest')proof.request_digest='0'.repeat(64);if(disposition==='wrong_source')proof.source_id=sid(91);if(disposition==='wrong_action')proof.action='scanner.configuration.disable';if(disposition==='bad_audit')proof.audit_event_id='invalid';if(disposition==='bad_time')proof.occurred_at='invalid';
   proofs.set(body.command.command_id,structuredClone(proof));if(disposition==='lost-abandon'&&abandonments.length===1)return route.abort();
   return route.fulfill({json:proof});
  }
  if(path==='/api/v1/scanners/'+sid(2)+'/commands'){
   const body=req.postDataJSON();commands.push(body);assert.deepEqual(Object.keys(body).sort(),['action','command_id','expected_revisions','membership_ids','payload','schema_version','target_id']);assert.equal(body.schema_version,1);assert.equal(body.target_id,sid(2));assert.deepEqual(body.membership_ids,[]);assert.equal(body.payload.source_id,sid(3));assert.equal(body.expected_revisions.secret,null);assert.equal(req.headers()['x-csrf-token'],'synthetic-csrf');
   if(stale&&body.command_id===commands[0].command_id){current.expected_revisions={...current.expected_revisions,target:3,policy:3,authority:3,connector:2};return route.fulfill({status:409,json:{error:{code:'revision_conflict'}}});}
   if(receipts.has(body.command_id))return route.fulfill({json:receipts.get(body.command_id)});
   let result;
   if(body.action==='scanner.configuration.save'){assert.deepEqual(body.payload.settings,{product:'qualys_vm',api_version:'2.0',platform_id:'us1',scope:{kind:'account_visible'},collection_mode:'manual'});current.configuration_revision++;current.expected_revisions.connector++;current.lifecycle='staged';current.active_configuration_revision=null;current.validation=null;result={lifecycle:'staged',configuration_revision:current.configuration_revision};}
   else if(body.action==='scanner.configuration.activate'){assert.equal(body.payload.validation_operation_id,current.validation.operation_id);assert.equal(body.payload.credential_version_id,current.credential.version_id);current.lifecycle='active';if(current.recovery.state==='awaiting_activation')current.recovery={...current.recovery,state:'clear',fresh_credentials_required:false};current.active_configuration_revision=current.configuration_revision;current.expected_revisions.connector++;result={lifecycle:'active',configuration_revision:current.configuration_revision,active_configuration_revision:current.configuration_revision};}
   else if(body.action==='scanner.configuration.disable'){current.lifecycle='disabled';current.active_configuration_revision=null;current.expected_revisions.connector++;result={lifecycle:'disabled',configuration_revision:current.configuration_revision};}
   else{assert.equal(body.payload.configuration_revision,current.configuration_revision);assert.equal(body.payload.credential_version_id,current.credential.version_id);const kind=body.action==='scanner.connection.test'?'test':'collect',now=new Date().toISOString();const id=sid(kind==='test'?60:61),run=kind==='collect'?sid(62):null;const status=kind==='collect'&&partial?'partial':terminal;operations.set(id,{schema_version:1,operation_id:id,command_id:body.command_id,kind,status,configuration_revision:current.configuration_revision,credential_version_id:current.credential.version_id,started_at:now,finished_at:now,run_id:run,error_code:status==='partial'?'page_limit':null,receipt_id:body.command_id});if(kind==='test')current.validation={status:status==='succeeded'?'succeeded':'failed',checked_at:now,configuration_revision:current.configuration_revision,credential_version_id:current.credential.version_id,operation_id:id,error_code:null};else{assert.equal(current.lifecycle,'active');current.latest_attempt_run_id=run;current.latest_complete_run_id=partial?sid(63):run;current.collection_recency={status:'recent',as_of:now,last_complete_at:now};}result={operation_id:id,...(run?{run_id:run}:{}),status,error_code:status==='partial'?'page_limit':null};}
   if(receiptless&&result.operation_id){const operation={...operations.get(result.operation_id),receipt_id:null};receipts.set(body.command_id,operation);return route.fulfill({status:200,json:operation});}
   const receipt={schema_version:1,command_id:body.command_id,action:body.action,target_id:body.target_id,decision_id:sid(64),audit_event_id:sid(65),intent_id:sid(66),committed_revision:current.expected_revisions.connector,projection:{status:'committed',connector_id:sid(2),source_id:sid(3),expected_revisions:current.expected_revisions},policy_revision:2,intents:[],occurred_at:new Date().toISOString(),result};receipts.set(body.command_id,structuredClone(receipt));if(lost&&commands.length===1)return route.abort();return route.fulfill({json:receipt});
  }
  if(path.includes('/operations/'))return route.fulfill({json:operations.get(path.split('/').at(-1))});
  if(path.endsWith('/detections'))return route.fulfill(readDenied?{status:403,json:{error:{code:'source_scope_forbidden',message:'MUST_NOT_RENDER'}}}:{json:detectionPage(path.split('/').at(-2),partial&&path.includes(sid(62))?'partial':'complete')});
  return route.fulfill({status:404,json:{schema_version:1}});
 });
 t.after(async()=>{if(pendingRoute)await pendingRoute.abort().catch(()=>{});});
 await page.goto(origin+'/?app#scanner?connector_id='+sid(2)+'&source_id='+sid(3));
 if(!denied&&!permissionsDenied)await page.getByRole('heading',{name:'Synthetic scanner',exact:true}).waitFor();
 return {page,calls,commands,secrets,current,siblings,abandonments,clearances,clearanceAbandonments};
}
async function scannerReason(page){await page.getByLabel('Reason for scanner action').fill('Synthetic authorised manual collection');await page.getByLabel('Scanner evidence reference').fill('synthetic:qualys');}
async function scannerAction(page,label,result){await page.getByRole('button',{name:label,exact:true}).click();await page.getByRole('status').filter({hasText:result}).first().waitFor();}
test('synthetic Qualys save, credential rotation, explicit test, activation and collect render persisted lineage',async t=>{
 const {page,commands,secrets,calls}=await scannerFixture(t);await scannerReason(page);
 await scannerAction(page,'Save Qualys configuration','Configuration staged');assert.deepEqual(commands.map(c=>c.action),['scanner.configuration.save']);
 await page.getByLabel('Qualys username',{exact:true}).fill('reader');await page.getByLabel('Qualys password',{exact:true}).fill('  synthetic external password  ');
 await scannerAction(page,'Save Qualys credentials','Credential version recorded');assert.equal(JSON.parse(secrets[0].input.value).password,'  synthetic external password  ');assert.equal(await page.getByLabel('Qualys password',{exact:true}).inputValue(),'');
 assert.equal(commands.length,1);assert.equal(await page.getByRole('button',{name:'Activate configuration',exact:true}).isDisabled(),true);
 await scannerAction(page,'Test connection','Operation succeeded');assert.equal(commands.length,2);assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isDisabled(),true);
 await scannerAction(page,'Activate configuration','Configuration active');await scannerAction(page,'Collect now','Operation succeeded');await page.getByRole('cell',{name:'105015'}).waitFor();await page.getByText('Host host-17',{exact:true}).waitFor();await page.getByRole('cell',{name:'443 / tcp / 1',exact:true}).waitFor();
 assert.deepEqual(commands.map(c=>c.action),['scanner.configuration.save','scanner.connection.test','scanner.configuration.activate','scanner.collection.start']);assert.equal(calls.includes('/api/v1/deployment'),false);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
 await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(await page.evaluate(async()=>(await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>v.id)),[]);if(process.env.VOLT_UI_EVIDENCE)await page.screenshot({path:join(process.env.VOLT_UI_EVIDENCE,`synthetic-qualys-${width}.png`),fullPage:true});}
});
test('first Qualys credential submission uses the explicit server revision zero and complete public fence',async t=>{const {page,secrets,calls,current}=await scannerFixture(t,{unconfigured:true});await scannerReason(page);const expected={...current.expected_revisions,secret:current.credential.revision};await page.getByLabel('Qualys username').fill('synthetic-reader');await page.getByLabel('Qualys password').fill('  synthetic-first-password  ');await scannerAction(page,'Save Qualys credentials','Credential version recorded');assert.equal(secrets.length,1);assert.deepEqual(secrets[0].expected_revisions,expected);assert.equal(secrets[0].expected_revisions.secret,0);assert.equal(JSON.parse(secrets[0].input.value).password,'  synthetic-first-password  ');assert.equal(calls.includes('/api/v1/connectors/'+sid(2)),false);assert.equal(await page.getByLabel('Qualys password').inputValue(),'');});
test('hanging Qualys credential request clears DOM immediately and retains only identifiers',async t=>{const {page,secrets}=await scannerFixture(t,{hanging:true});await scannerReason(page);await page.getByLabel('Qualys username').fill('synthetic-reader-marker');await page.getByLabel('Qualys password').fill(' synthetic-password-marker ');await page.getByRole('button',{name:'Save Qualys credentials'}).click();assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');assert.equal(JSON.parse(secrets[0].input.value).password,' synthetic-password-marker ');const stored=await page.evaluate(()=>JSON.stringify({...sessionStorage,...localStorage}));assert.equal(/synthetic-reader-marker|synthetic-password-marker/.test(stored),false);await page.getByRole('link',{name:'Reports',exact:true}).click();await page.getByRole('heading',{name:'Reports',exact:true}).waitFor();assert.equal(await page.locator('input[type=password]').count(),0);});
test('populated Qualys credential form is cleared on navigation and does not reappear',async t=>{const {page}=await scannerFixture(t);await scannerReason(page);await page.getByLabel('Qualys username').fill('synthetic-reader-marker');await page.getByLabel('Qualys password').fill('synthetic-password-marker');await page.getByRole('link',{name:'Reports',exact:true}).click();await page.getByRole('heading',{name:'Reports',exact:true}).waitFor();await page.goBack();await page.getByRole('heading',{name:'Synthetic scanner',exact:true}).waitFor();assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');});
test('uncertain scanner command survives reload and reuses original UUID and revision vector',async t=>{const {page,commands}=await scannerFixture(t,{lost:true});await scannerReason(page);await page.getByRole('button',{name:'Save Qualys configuration'}).click();await page.getByRole('alert').filter({hasText:'operation outcome is unknown'}).waitFor();await page.reload();await scannerAction(page,'Check original scanner command','Configuration staged');assert.equal(commands.length,2);assert.deepEqual(commands[0],commands[1]);assert.equal(await page.evaluate(()=>sessionStorage.length),0);});
test('source denial is never rendered as an empty source',async t=>{const {page,calls}=await scannerFixture(t,{denied:true});await page.getByRole('alert').filter({hasText:'denied'}).waitFor();assert.equal(await page.getByText('No collection attempt is recorded.',{exact:false}).count(),0);assert.equal(calls.includes('/api/v1/deployment'),false);});
test('partial latest attempt remains beside last complete and observation denial is explicit',async t=>{const {page}=await scannerFixture(t,{partial:true,readDenied:true});await scannerReason(page);await scannerAction(page,'Save Qualys configuration','Configuration staged');await scannerAction(page,'Test connection','Operation succeeded');await scannerAction(page,'Activate configuration','Configuration active');await scannerAction(page,'Collect now','Operation partial');await page.getByRole('heading',{name:'Latest attempt',exact:true}).waitFor();await page.getByRole('heading',{name:'Last complete collection',exact:true}).waitFor();await page.getByRole('alert').filter({hasText:'Read denial is not empty data'}).first().waitFor();assert.equal(await page.getByRole('cell',{name:'105015'}).count(),0);});
test('quarantine and current permission discovery block scanner writes without bypass',async t=>{const {page,commands,secrets}=await scannerFixture(t,{quarantined:true,configure:false,manage:false});await scannerReason(page);await page.getByRole('alert').filter({hasText:'Recovery quarantine'}).waitFor();for(const label of ['Save Qualys configuration','Test connection','Activate configuration','Collect now','Save Qualys credentials'])assert.equal(await page.getByRole('button',{name:label,exact:true}).isDisabled(),true);assert.equal(commands.length+secrets.length,0);});

test('ordinary scoped connector discovery opens Qualys without deployment inventory or GitHub editor',async t=>{const {page,calls}=await scannerFixture(t);await page.getByRole('link',{name:'Administration',exact:true}).click();await page.getByRole('link',{name:'Connectors',exact:true}).click();await page.getByRole('button',{name:/QUALYS VMDR.*Open Qualys source/}).click();await page.getByRole('heading',{name:'Synthetic scanner',exact:true}).waitFor();assert.equal(calls.includes('/api/v1/deployment'),false);assert.equal(await page.getByRole('heading',{name:'Validate, then activate'}).count(),0);});
for(const terminal of ['failed','interrupted'])test(`Qualys connection test ${terminal} remains visible and cannot enable activation`,async t=>{const {page,commands}=await scannerFixture(t,{terminal});await scannerReason(page);await scannerAction(page,'Save Qualys configuration','Configuration staged');await scannerAction(page,'Test connection','Operation '+terminal);assert.equal(await page.getByRole('button',{name:'Activate configuration',exact:true}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isDisabled(),true);assert.equal(commands.length,2);});

for(const denialDelay of ['scanner','permissions'])test(`both scanner and permissions scoped 403 stay local (${denialDelay} resolves last)`,async t=>{
 const {page,calls,siblings}=await scannerFixture(t,{denied:true,permissionsDenied:true,denialDelay});
 await page.getByRole('alert').filter({hasText:/denied|does not permit/}).waitFor();
 assert.deepEqual(await siblings,[403,403]); // Observe both actual responses, including the delayed sibling.
 assert.equal(calls.includes('/api/v1/scanners/'+sid(2)),true);assert.equal(calls.includes('/api/v1/connectors/'+sid(2)+'/permissions'),true);
 assert.equal(await page.getByRole('button',{name:'Refresh source access'}).count(),1);
 assert.equal(await page.getByRole('button',{name:'Change password',exact:true}).count(),1);
 assert.equal((await page.content()).includes('MUST_NOT_RENDER'),false);
 await page.getByRole('link',{name:'Reports',exact:true}).click();await page.getByRole('heading',{name:'Reports',exact:true}).waitFor();
 assert.equal(calls.includes('/api/v1/deployment'),false);
});
for(const [permissionStatus,permissionCode] of [[401,'authentication_required'],[403,'csrf_failed'],[403,'session_revoked']])test(`permissions ${permissionStatus}/${permissionCode} still fails the session`,async t=>{
 const {page}=await scannerFixture(t,{permissionsDenied:true,permissionStatus,permissionCode});
 await page.getByRole('alert').first().waitFor();await page.getByRole('button',{name:'Refresh source access'}).waitFor({state:'detached'});
 assert.equal(await page.getByRole('button',{name:'Change password',exact:true}).count(),0);
});
test('source refresh clears populated credentials before both unresolved requests and failed readback',async t=>{
 const {page}=await scannerFixture(t);await scannerReason(page);await page.getByLabel('Qualys username').fill('refresh-username-marker');await page.getByLabel('Qualys password').fill(' refresh-password-marker ');
 const held=[];let observed;const requests=new Promise(resolve=>{observed=resolve;});
 const intercept=async route=>{held.push(route);assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');if(held.length===2)observed();};
 await page.route('**/api/v1/scanners/'+sid(2)+'?*',intercept);await page.route('**/api/v1/connectors/'+sid(2)+'/permissions?*',intercept);
 t.after(async()=>{for(const route of held)await route.abort().catch(()=>{});});
 await page.getByRole('button',{name:'Refresh source access'}).click();await requests;
 assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');assert.equal(await page.getByRole('button',{name:'Save Qualys credentials'}).isDisabled(),true);
 assert.equal(/refresh-(?:username|password)-marker/.test(await page.evaluate(()=>JSON.stringify({...sessionStorage,...localStorage}))),false);
 await Promise.all(held.map(route=>route.fulfill({status:503,json:{schema_version:1,error:{code:'persistence_unavailable'}}})));
 await page.getByRole('alert').first().waitFor();assert.equal(await page.locator('input[type=password]').count(),0);
 await page.unroute('**/api/v1/scanners/'+sid(2)+'?*',intercept);await page.unroute('**/api/v1/connectors/'+sid(2)+'/permissions?*',intercept);
 await page.getByRole('button',{name:'Refresh source access'}).click();await page.getByRole('heading',{name:'Synthetic scanner',exact:true}).waitFor();assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');
});
for(const terminal of ['failed','partial','interrupted'])test(`HTTP 200 receipt-less ${terminal} readback stays operational and preserves the original command`,async t=>{
 const {page,commands}=await scannerFixture(t,{terminal,receiptless:true});await scannerReason(page);await scannerAction(page,'Save Qualys configuration','Configuration staged');await scannerAction(page,'Test connection','No audited completion receipt is available');
 const retained=await page.evaluate(()=>Object.values(sessionStorage)[0]);assert.deepEqual(JSON.parse(retained),commands[1]);assert.equal(await page.getByRole('button',{name:'Activate configuration'}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Save Qualys configuration'}).isDisabled(),true);
 await scannerAction(page,'Check original scanner command','No audited completion receipt is available');assert.deepEqual(commands[2],commands[1]);assert.equal(await page.evaluate(()=>Object.values(sessionStorage)[0]),retained);
});

async function openScannerAbandonment(page){await page.getByRole('button',{name:'Review scanner abandonment',exact:true}).click();await page.getByLabel('Reason for scanner abandonment',{exact:true}).fill('Reviewed stale command');await page.getByLabel('Scanner abandonment evidence reference',{exact:true}).fill('synthetic:disposition');await page.getByRole('checkbox',{name:'I reviewed the original scanner command'}).check();}
async function staleScanner(t,options={}){const fixture=await scannerFixture(t,{stale:true,...options});await scannerReason(fixture.page);await fixture.page.getByRole('button',{name:'Save Qualys configuration',exact:true}).click();await fixture.page.getByRole('alert').filter({hasText:'source, credential or authority changed'}).waitFor();return fixture;}
test('stale scanner 409 requires explicit audited abandonment then separate refreshed new-UUID replacement',async t=>{
 const {page,commands,abandonments}=await staleScanner(t);const original=JSON.stringify(commands[0]);assert.equal(abandonments.length,0);await openScannerAbandonment(page);assert.equal(abandonments.length,0);await page.getByRole('button',{name:'Confirm scanner abandonment',exact:true}).click();await page.getByRole('status').filter({hasText:'Audited non-commit confirmed'}).waitFor();assert.equal(commands.length,1);assert.equal(await page.getByRole('button',{name:'Check original scanner command'}).count(),0);
 await page.getByRole('button',{name:'Review replacement scanner command',exact:true}).click();await page.getByRole('heading',{name:'Review replacement against current source'}).waitFor();assert.equal(commands.length,1);for(const action of ['Test connection','Activate configuration','Collect now'])assert.equal(await page.getByRole('option',{name:action,exact:true}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Submit reviewed replacement'}).isDisabled(),true);await page.getByLabel('Reason for replacement',{exact:true}).fill('Reviewed replacement at current revisions');await page.getByRole('checkbox',{name:'I reviewed this replacement action'}).check();await page.getByRole('button',{name:'Submit reviewed replacement'}).click();await page.getByRole('status').filter({hasText:'Configuration staged'}).waitFor();assert.equal(commands.length,2);assert.notEqual(commands[1].command_id,commands[0].command_id);assert.equal(commands[1].expected_revisions.policy,3);assert.equal(commands[1].expected_revisions.connector,2);assert.equal(commands[1].expected_revisions.secret,null);assert.equal(JSON.stringify(commands[0]),original);assert.deepEqual(abandonments[0].command,commands[0]);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
});
test('lost abandonment response survives reload with exact original body and first audit metadata',async t=>{
 const {page,commands,abandonments}=await staleScanner(t,{disposition:'lost-abandon'});await openScannerAbandonment(page);await page.getByRole('button',{name:'Confirm scanner abandonment'}).click();await page.getByRole('alert').filter({hasText:'outcome is unknown'}).waitFor();const saved=await page.evaluate(()=>Object.fromEntries(Object.entries(sessionStorage)));await page.reload();await page.getByRole('button',{name:'Check original scanner disposition'}).click();await page.getByRole('status').filter({hasText:'Audited non-commit confirmed'}).waitFor();assert.deepEqual(abandonments[1],abandonments[0]);assert.equal(commands.length,1);assert.deepEqual(await page.evaluate(()=>Object.fromEntries(Object.entries(sessionStorage))),saved);
});
for(const disposition of ['404','409','503','network','wrong_actor','wrong_digest','wrong_source','wrong_action','bad_audit','bad_time'])test(`scanner disposition ${disposition} preserves both frozen requests and cannot enable replacement`,async t=>{
 const {page,commands,abandonments}=await staleScanner(t,{disposition});await openScannerAbandonment(page);await page.getByRole('button',{name:'Confirm scanner abandonment'}).click();await page.getByRole('alert').first().waitFor();assert.equal(await page.getByRole('button',{name:'Review replacement scanner command'}).count(),0);const saved=await page.evaluate(()=>Object.values(sessionStorage).map(x=>JSON.parse(x)));assert.equal(saved.length,2);assert.ok(saved.some(x=>x.command_id===commands[0].command_id));assert.ok(saved.some(x=>x.command?.command_id===commands[0].command_id));assert.equal(abandonments.length,1);assert.equal((await page.content()).includes('MUST_NOT_RENDER'),false);assert.equal(commands.length,1);
});
test('scanner abandonment denial preserves original requests through session revalidation',async t=>{const {page,commands}=await staleScanner(t,{disposition:'403'});await openScannerAbandonment(page);await page.getByRole('button',{name:'Confirm scanner abandonment'}).click();await page.getByRole('button',{name:'Refresh source access'}).waitFor({state:'detached'});const saved=await page.evaluate(()=>Object.fromEntries(Object.entries(sessionStorage)));assert.equal(Object.keys(saved).length,2);await page.reload();await page.getByRole('button',{name:'Check original scanner disposition'}).waitFor();assert.deepEqual(await page.evaluate(()=>Object.fromEntries(Object.entries(sessionStorage))),saved);assert.equal(commands.length,1);});
test('committed scanner disposition recovers original receipt without replacement or another command',async t=>{const {page,commands}=await scannerFixture(t,{lost:true,disposition:'committed'});await scannerReason(page);await page.getByRole('button',{name:'Save Qualys configuration'}).click();await page.getByRole('alert').filter({hasText:'outcome is unknown'}).waitFor();await openScannerAbandonment(page);await page.getByRole('button',{name:'Confirm scanner abandonment'}).click();await page.getByRole('status').filter({hasText:'Original audited receipt recovered'}).waitFor();assert.equal(commands.length,1);assert.equal(await page.evaluate(()=>sessionStorage.length),0);assert.equal(await page.getByRole('button',{name:'Review replacement scanner command'}).count(),0);});
test('admitted interrupted scanner disposition cannot become non-commit or enable replacement',async t=>{const {page,commands}=await scannerFixture(t,{receiptless:true,terminal:'interrupted',disposition:'admitted'});await scannerReason(page);await scannerAction(page,'Save Qualys configuration','Configuration staged');await scannerAction(page,'Test connection','No audited completion receipt');await openScannerAbandonment(page);await page.getByRole('button',{name:'Confirm scanner abandonment'}).click();await page.getByRole('status').filter({hasText:'Admission is not non-commit proof'}).waitFor();assert.equal(commands.length,2);assert.equal(await page.getByRole('button',{name:'Review replacement scanner command'}).count(),0);assert.equal(await page.evaluate(()=>sessionStorage.length),2);});
test('scanner replacement review supports keyboard focus and zero WCAG violations at required widths',async t=>{const {page}=await staleScanner(t);await openScannerAbandonment(page);await page.getByRole('button',{name:'Confirm scanner abandonment'}).click();await page.getByRole('button',{name:'Review replacement scanner command'}).click();await page.getByRole('heading',{name:'Review replacement against current source'}).waitFor();assert.equal(await page.locator(':focus').textContent(),'Review replacement against current source');await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(await page.evaluate(async()=>(await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>v.id)),[]);if(process.env.VOLT_UI_EVIDENCE)await page.screenshot({path:join(process.env.VOLT_UI_EVIDENCE,`synthetic-disposition-review-${width}.png`),fullPage:true});}});

// Synthetic recovery transitions exercise the actual rendered application; no host proof is produced here.
const readyRecovery=()=>recoveryView({fresh_version_ready:true,clearance_state:'available',approval_id:sid(81),approval_expires_at:new Date(Date.now()+600000).toISOString()});
test('recovery quarantine permits fresh upload but requires host approval before clearance, test and activation',async t=>{
 const {page,current,secrets,commands,clearances}=await scannerFixture(t,{quarantined:true,recovery:recoveryView()});await scannerReason(page);
 assert.equal(await page.getByRole('button',{name:'Save Qualys credentials',exact:true}).isEnabled(),true);
 for(const name of ['Apply host clearance','Test connection','Activate configuration','Collect now'])assert.equal(await page.getByRole('button',{name,exact:true}).isDisabled(),true);
 await page.getByLabel('Qualys username').fill('synthetic-user');await page.getByLabel('Qualys password').fill('  fresh-synthetic-password  ');await scannerAction(page,'Save Qualys credentials','Host operator approval is still required');
 assert.equal(JSON.parse(secrets[0].input.value).password,'  fresh-synthetic-password  ');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');assert.equal(await page.getByRole('button',{name:'Apply host clearance'}).isDisabled(),true);assert.equal(commands.length+clearances.length,0);
 current.recovery=readyRecovery();await page.getByRole('button',{name:'Refresh source access'}).click();await page.getByRole('button',{name:'Apply host clearance'}).waitFor();await scannerAction(page,'Apply host clearance','Clearance applied');
 assert.equal(clearances.length,1);assert.equal(commands.length,0);assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Activate configuration',exact:true}).isDisabled(),true);
 await scannerAction(page,'Test connection','Operation succeeded');assert.equal(commands.length,1);assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isDisabled(),true);
 await scannerAction(page,'Activate configuration','Configuration active');assert.equal(current.recovery.state,'clear');assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isEnabled(),true);
 current.recovery.clearance_state='expired';current.recovery.approval_expires_at='2020-01-01T00:00:00Z';await page.getByRole('button',{name:'Refresh source access'}).click();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();await page.getByRole('region',{name:'Source recovery'}).getByText('expired',{exact:true}).waitFor();await page.getByText('Recovery is clear.',{exact:false}).waitFor();assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isEnabled(),true);
});
test('reused password rejection clears both fields and offers safe fresh credential guidance',async t=>{
 const {page,secrets}=await scannerFixture(t,{quarantined:true,recovery:recoveryView(),reused:true});await scannerReason(page);await page.getByLabel('Qualys username').fill('changed-user-marker');await page.getByLabel('Qualys password').fill('retained-password-marker');await page.getByRole('button',{name:'Save Qualys credentials'}).click();await page.getByRole('alert').filter({hasText:'This password was previously retained'}).waitFor();assert.equal(secrets.length,1);assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');assert.equal(await page.evaluate(()=>sessionStorage.length),0);assert.equal((await page.content()).includes('MUST_NOT_RENDER'),false);
});
test('lost clearance response retains frozen full command across reload, recovers receipt without auto test',async t=>{
 const {page,clearances,commands}=await scannerFixture(t,{recovery:readyRecovery(),clearanceResult:'lost'});await scannerReason(page);await page.getByRole('button',{name:'Apply host clearance'}).click();await page.getByRole('alert').filter({hasText:'outcome is unknown'}).waitFor();await page.reload();await scannerAction(page,'Check original clearance command','Clearance applied');assert.deepEqual(clearances[0],clearances[1]);assert.equal(clearances.length,2);assert.equal(commands.length,0);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
});
for(const clearanceResult of ['409','404','wrong-epoch','hanging'])test(`clearance ${clearanceResult} retains original and blocks other writes`,async t=>{
 const {page,clearances,commands}=await scannerFixture(t,{recovery:readyRecovery(),clearanceResult});await scannerReason(page);await page.getByLabel('Qualys username').fill('clearance-user-marker');await page.getByLabel('Qualys password').fill('clearance-password-marker');await page.getByRole('button',{name:'Apply host clearance'}).click();await page.getByRole('button',{name:'Check original clearance command'}).waitFor();if(clearanceResult==='409'||clearanceResult==='404'){await page.getByRole('alert').filter({hasText:clearanceResult==='409'?'settings or permissions have changed':'Connector information is unavailable'}).waitFor();assert.equal(await page.getByText('The server response is incomplete or unsupported.',{exact:false}).count(),0);assert.equal((await page.content()).includes('SYNTHETIC_RAW_ERROR_DO_NOT_RENDER'),false);}assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');const retained=await page.evaluate(()=>JSON.stringify({...sessionStorage}));assert.equal(/clearance-user-marker|clearance-password-marker/.test(retained),false);assert.equal(clearances.length,1);assert.equal(commands.length,0);for(const name of ['Save Qualys configuration','Test connection','Activate configuration','Collect now','Save Qualys credentials'])assert.equal(await page.getByRole('button',{name,exact:true}).isDisabled(),true);
});
for(const clearance_state of ['missing','expired','invalidated'])test(`closed recovery with ${clearance_state} approval cannot test, activate or collect`,async t=>{
 const {page}=await scannerFixture(t,{recovery:{...readyRecovery(),state:'awaiting_activation',clearance_state}});await scannerReason(page);for(const name of ['Apply host clearance','Test connection','Activate configuration','Collect now'])assert.equal(await page.getByRole('button',{name,exact:true}).isDisabled(),true);await page.getByText('Host approval is '+clearance_state+'.',{exact:false}).waitFor();
});
test('approval expiry while page is open disables test and activation until refresh, never clearance inference',async t=>{
 const {page}=await scannerFixture(t,{recovery:{...readyRecovery(),state:'awaiting_activation',clearance_state:'applied',approval_expires_at:new Date(Date.now()+2500).toISOString()}});await scannerReason(page);assert.equal(await page.getByRole('button',{name:'Test connection',exact:true}).isEnabled(),true);await page.getByRole('alert').filter({hasText:'displayed approval has expired'}).waitFor();assert.equal(await page.getByRole('button',{name:'Test connection',exact:true}).isDisabled(),true);
});
test('denied secret slot read preserves scoped session and never creates clearance command',async t=>{
 const {page,clearances}=await scannerFixture(t,{recovery:readyRecovery(),slotDenied:true});await scannerReason(page);await page.getByRole('button',{name:'Apply host clearance'}).click();await page.getByRole('alert').filter({hasText:'Current access does not permit'}).waitFor();assert.equal(clearances.length,0);assert.equal(await page.getByRole('heading',{name:'Synthetic scanner',exact:true}).count(),1);assert.equal(await page.getByRole('button',{name:'Refresh session access'}).count(),0);
});
test('recovery controls have keyboard focus, reflow and zero existing WCAG axe thresholds with empty credentials',async t=>{
 const {page}=await scannerFixture(t,{recovery:readyRecovery()});await scannerReason(page);await scannerAction(page,'Apply host clearance','Clearance applied');assert.match(await page.locator(':focus').innerText(),/Clearance applied/);await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});const evidence=process.env.VOLT_UI_EVIDENCE;if(evidence)await mkdir(evidence,{recursive:true});for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.getByLabel('Qualys password').inputValue(),'');assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>v.id)),[]);if(evidence)await page.screenshot({path:join(evidence,`synthetic-recovery-${width}.png`),fullPage:true});}
});
test('clearance requires current configure permission, while applying approved metadata needs no secret-management grant',async t=>{
 const denied=await scannerFixture(t,{recovery:readyRecovery(),configure:false});await scannerReason(denied.page);assert.equal(await denied.page.getByRole('button',{name:'Apply host clearance'}).isDisabled(),true);assert.equal(denied.clearances.length,0);
 const allowed=await scannerFixture(t,{recovery:readyRecovery(),manage:false});await scannerReason(allowed.page);assert.equal(await allowed.page.getByRole('button',{name:'Save Qualys credentials'}).isDisabled(),true);await scannerAction(allowed.page,'Apply host clearance','Clearance applied');assert.equal(allowed.clearances.length,1);assert.equal(allowed.secrets.length+allowed.commands.length,0);
});
test('simultaneous retained scanner and clearance commands cannot cross the shared command ledger',async t=>{
 const {page,clearances,commands}=await scannerFixture(t,{recovery:readyRecovery(),clearanceResult:'lost'});await scannerReason(page);await page.getByRole('button',{name:'Apply host clearance'}).click();await page.getByRole('alert').filter({hasText:'outcome is unknown'}).waitFor();const original=await page.evaluate(()=>JSON.stringify({...sessionStorage}));
 const old={schema_version:1,command_id:sid(99),action:'scanner.configuration.disable',target_id:sid(2),membership_ids:[],expected_revisions:{target:2,policy:2,identity_membership:0,owners:0,authority:2,connector:1,source:1,secret_source:1,secret:null},payload:{source_id:sid(3),rationale:'Review old action',evidence_ref:'synthetic:old'}};
 await page.evaluate(({key,value})=>sessionStorage.setItem(key,JSON.stringify(value)),{key:'volt.scanner.command:synthetic-local-user:'+sid(2)+':'+sid(3),value:old});await page.reload();await page.getByRole('button',{name:'Check original scanner command'}).waitFor();assert.equal(await page.getByRole('button',{name:'Check original scanner command'}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Check original clearance command'}).isDisabled(),true);assert.equal(commands.length,0);assert.equal(clearances.length,1);const retained=await page.evaluate(()=>({...sessionStorage}));for(const [key,value] of Object.entries(JSON.parse(original)))assert.equal(retained[key],value);
});
for(const state of ['quarantined','awaiting_activation'])test(`closed ${state} prevents a new save while retaining exact original lookup and abandonment`,async t=>{
 const {page,current,commands,abandonments}=await staleScanner(t);const original=structuredClone(commands[0]);current.recovery={...readyRecovery(),state,clearance_state:state==='awaiting_activation'?'applied':'available'};current.configuration_revision=1;
 await page.getByRole('button',{name:'Refresh source access'}).click();await page.getByText('Finish fresh credential approval, the connection test and activation before editing configuration.',{exact:false}).waitFor();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();assert.equal(await page.getByRole('button',{name:'Save Qualys configuration',exact:true}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Check original scanner command',exact:true}).isEnabled(),true);
 const checked=page.waitForResponse(r=>r.url().endsWith('/api/v1/scanners/'+sid(2)+'/commands')&&r.request().method()==='POST');await page.getByRole('button',{name:'Check original scanner command'}).click();assert.equal((await checked).status(),409);await page.getByRole('alert').filter({hasText:'source, credential or authority changed'}).waitFor();assert.deepEqual(commands,[original,original]);
 await openScannerAbandonment(page);await page.getByRole('button',{name:'Confirm scanner abandonment'}).click();await page.getByRole('status').filter({hasText:'Audited non-commit confirmed'}).waitFor();assert.equal(abandonments.length,1);assert.deepEqual(abandonments[0].command,original);assert.equal(commands.length,2);assert.equal(await page.getByRole('button',{name:'Save Qualys configuration',exact:true}).isDisabled(),true);
});
test('historical clearance receipt recovery reports current clear active state without another test or activation',async t=>{
 const {page,current,clearances,commands}=await scannerFixture(t,{recovery:readyRecovery(),clearanceResult:'lost'});await scannerReason(page);await page.getByRole('button',{name:'Apply host clearance'}).click();await page.getByRole('alert').filter({hasText:'outcome is unknown'}).waitFor();current.lifecycle='active';current.active_configuration_revision=current.configuration_revision;current.recovery={...current.recovery,state:'clear',fresh_credentials_required:false,clearance_state:'expired',approval_expires_at:'2020-01-01T00:00:00Z'};
 await page.reload();await scannerAction(page,'Check original clearance command','Clearance applied');await page.locator('.scanner-workspace[aria-busy=false]').waitFor();await scannerReason(page);assert.match(await page.getByRole('status').filter({hasText:'Clearance applied'}).innerText(),/did not submit a test or activation/);assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isEnabled(),true);assert.deepEqual(clearances[0],clearances[1]);assert.equal(commands.length,0);
});

// Known disposition dependency: ordinary non-commit-labelled errors do not fence the command.
for(const clearanceResult of ['stale','expired'])test(`valid backend ${clearanceResult} clearance error preserves frozen command through changed approval and revisions`,async t=>{
 const {page,current,clearances,commands}=await scannerFixture(t,{recovery:readyRecovery(),clearanceResult});await scannerReason(page);
 await page.getByRole('button',{name:'Apply host clearance'}).click();await page.getByRole('alert').filter({hasText:clearanceResult==='stale'?'settings or permissions have changed':'Recovery quarantine prevents use'}).waitFor();const original=structuredClone(clearances[0]);const before=await page.evaluate(()=>({...sessionStorage}));assert.equal(Object.keys(before).length,1);assert.deepEqual(JSON.parse(Object.values(before)[0]),original);
 current.recovery={...readyRecovery(),approval_id:sid(82)};current.expected_revisions.connector++;
 await page.getByRole('button',{name:'Refresh source access'}).click();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();await page.getByRole('button',{name:'Check original clearance command'}).click();await page.getByRole('alert').filter({hasText:'settings or permissions have changed'}).waitFor();assert.deepEqual(clearances,[original,original]);assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),before);assert.equal(commands.length,0);assert.equal(await page.getByRole('button',{name:'Apply host clearance',exact:true}).count(),0);assert.equal(await page.getByRole('button',{name:'Save Qualys credentials',exact:true}).isDisabled(),true);assert.equal((await page.content()).includes('SYNTHETIC_RAW_ERROR_DO_NOT_RENDER'),false);
 await page.reload();await page.getByRole('button',{name:'Check original clearance command'}).waitFor();assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),before);
});

async function openClearanceAbandonment(page){await page.getByRole('button',{name:'Review clearance abandonment'}).click();await page.getByLabel('Reason for clearance abandonment').fill('Review stale clearance Café');await page.getByLabel('Clearance abandonment evidence reference').fill('synthetic:clearance-review');await page.getByRole('checkbox',{name:'I reviewed the original clearance command'}).check();}
async function staleClearance(t,options={}){const fixture=await scannerFixture(t,{recovery:readyRecovery(),clearanceResult:'stale',...options});await scannerReason(fixture.page);await fixture.page.getByRole('button',{name:'Apply host clearance'}).click();await fixture.page.getByRole('alert').filter({hasText:options.clearanceResult==='expired'?'Recovery quarantine prevents use':'settings or permissions have changed'}).waitFor();return fixture;}
for(const clearanceResult of ['stale','expired'])test(`${clearanceResult} clearance requires audited disposition and separate reviewed new UUID with current fences`,async t=>{
 const {page,current,clearances,commands,clearanceAbandonments}=await staleClearance(t,{clearanceResult});const old=structuredClone(clearances[0]);await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('status').filter({hasText:'Audited clearance non-commit confirmed'}).waitFor();assert.equal(clearances.length,1);assert.deepEqual(clearanceAbandonments[0].command,old);assert.equal(await page.getByText('Clearance outcome awaiting confirmation.',{exact:false}).count(),0);await page.getByText('The original clearance command is terminally not committed.',{exact:false}).waitFor();
 current.recovery={...readyRecovery(),approval_id:sid(83)};current.expected_revisions.connector++;const expected=recoverySlot(current).revisions;
 await page.getByRole('button',{name:'Review replacement clearance'}).click();await page.getByRole('heading',{name:'Review replacement clearance against current source'}).waitFor();assert.equal(await page.getByRole('heading',{name:'Review replacement clearance against current source'}).evaluate(el=>el===document.activeElement),true);assert.equal(clearances.length,1);assert.equal(await page.getByRole('button',{name:'Submit reviewed clearance replacement'}).isDisabled(),true);
 await page.getByRole('checkbox',{name:'I reviewed this replacement clearance'}).check();await page.getByRole('button',{name:'Submit reviewed clearance replacement'}).click();await page.getByRole('status').filter({hasText:'Clearance applied'}).waitFor();assert.equal(clearances.length,2);assert.notEqual(clearances[1].command_id,old.command_id);assert.deepEqual(clearances[1].expected_revisions,expected);assert.equal(clearances[1].payload.version_id,current.credential.version_id);assert.deepEqual(clearances[0],old);assert.equal(commands.length,0);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
});
test('uncertain clearance abandonment freezes outer review body and original through reload',async t=>{
 const {page,clearances,clearanceAbandonments}=await staleClearance(t,{clearanceDisposition:'lost'});await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('alert').filter({hasText:'save outcome is unknown'}).waitFor();const before=await page.evaluate(()=>({...sessionStorage}));assert.equal(Object.keys(before).length,2);await page.reload();await page.getByRole('button',{name:'Check original clearance disposition'}).click();await page.getByRole('status').filter({hasText:'Audited clearance non-commit confirmed'}).waitFor();assert.deepEqual(clearanceAbandonments[0],clearanceAbandonments[1]);assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),before);assert.equal(clearances.length,1);
});
for(const clearanceDisposition of ['404','409','503','partial','network','wrong_actor','wrong_digest','wrong_action','bad_audit','bad_time','admitted'])test(`clearance disposition ${clearanceDisposition} preserves both bodies without replacement`,async t=>{
 const {page,clearances}=await staleClearance(t,{clearanceDisposition});await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('button',{name:'Check original clearance disposition'}).waitFor();await page.getByRole('alert').filter({hasText:({'404':'original clearance disposition is unavailable','409':'retained clearance command conflicts','503':'Clearance disposition is unavailable',partial:'clearance record is incomplete or inconsistent'})[clearanceDisposition]??'save outcome is unknown'}).waitFor();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();const before=await page.evaluate(()=>({...sessionStorage}));assert.equal(Object.keys(before).length,2);assert.equal(await page.getByRole('button',{name:'Review replacement clearance',exact:true}).count(),0);assert.equal(await page.getByRole('button',{name:'Finish clearance reconciliation',exact:true}).count(),0);assert.equal(clearances.length,1);assert.equal((await page.content()).includes('SYNTHETIC_RAW_ERROR_DO_NOT_RENDER'),false);await page.reload();await page.getByRole('button',{name:'Check original clearance disposition'}).waitFor();assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),before);
});
test('committed clearance disposition recovers historical receipt then displays current lifecycle',async t=>{
 const {page,current,clearances,commands}=await scannerFixture(t,{recovery:readyRecovery(),clearanceResult:'lost',clearanceDisposition:'committed'});await scannerReason(page);await page.getByRole('button',{name:'Apply host clearance'}).click();await page.getByRole('alert').filter({hasText:'save outcome is unknown'}).waitFor();current.lifecycle='active';current.active_configuration_revision=current.configuration_revision;current.recovery={...current.recovery,state:'clear',fresh_credentials_required:false,clearance_state:'expired',approval_expires_at:'2020-01-01T00:00:00Z'};
 await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('status').filter({hasText:'Original audited clearance receipt recovered'}).waitFor();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isEnabled(),true);assert.equal(clearances.length,1);assert.equal(commands.length,0);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
});
test('clearance replacement review requires currently available unexpired approval and current source access',async t=>{
 const {page,current,clearances}=await staleClearance(t);await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('status').filter({hasText:'Audited clearance non-commit confirmed'}).waitFor();current.recovery.clearance_state='expired';current.recovery.approval_expires_at='2020-01-01T00:00:00Z';await page.getByRole('button',{name:'Review replacement clearance'}).click();await page.getByRole('alert').filter({hasText:'settings or permissions have changed'}).waitFor();assert.equal(await page.getByRole('button',{name:'Submit reviewed clearance replacement'}).count(),0);assert.equal(clearances.length,1);assert.equal(await page.evaluate(()=>sessionStorage.length),2);
});
test('clearance disposition review and replacement reflow with focus and zero WCAG thresholds',async t=>{
 const {page}=await staleClearance(t);await openClearanceAbandonment(page);assert.match(await page.locator(':focus').getAttribute('type'),/checkbox/);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('status').filter({hasText:'Audited clearance non-commit confirmed'}).waitFor();await page.getByRole('button',{name:'Review replacement clearance'}).click();await page.getByRole('heading',{name:'Review replacement clearance against current source'}).waitFor();await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});const evidence=process.env.VOLT_UI_EVIDENCE;if(evidence)await mkdir(evidence,{recursive:true});for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.getByLabel('Qualys username').inputValue(),'');assert.equal(await page.getByLabel('Qualys password').inputValue(),'');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>v.id)),[]);if(evidence)await page.screenshot({path:join(evidence,`synthetic-clearance-replacement-${width}.png`),fullPage:true});}
});

test('clearance abandonment 403 preserves both frozen requests through session revalidation',async t=>{const {page,clearances}=await staleClearance(t,{clearanceDisposition:'403'});await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('button',{name:'Refresh source access'}).waitFor({state:'detached'});const saved=await page.evaluate(()=>({...sessionStorage}));assert.equal(Object.keys(saved).length,2);await page.reload();await page.getByRole('button',{name:'Check original clearance disposition'}).waitFor();assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),saved);assert.equal(clearances.length,1);});
test('lost reviewed clearance replacement retains only the new exact command and never rewrites old terminal metadata',async t=>{
 const {page,clearances,clearanceAbandonments}=await staleClearance(t,{lostClearanceReplacement:true});await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('status').filter({hasText:'Audited clearance non-commit confirmed'}).waitFor();await page.getByRole('button',{name:'Review replacement clearance'}).click();await page.getByRole('heading',{name:'Review replacement clearance against current source'}).waitFor();await page.getByRole('checkbox',{name:'I reviewed this replacement clearance'}).check();await page.getByRole('button',{name:'Submit reviewed clearance replacement'}).click();await page.getByRole('alert').filter({hasText:'save outcome is unknown'}).waitFor();const saved=await page.evaluate(()=>({...sessionStorage}));assert.equal(Object.keys(saved).length,1);assert.deepEqual(JSON.parse(Object.values(saved)[0]),clearances[1]);assert.notEqual(clearances[0].command_id,clearances[1].command_id);assert.deepEqual(clearanceAbandonments[0].command,clearances[0]);await page.reload();await scannerAction(page,'Check original clearance command','Clearance applied');assert.deepEqual(clearances[2],clearances[1]);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
});

async function terminalClearance(t){
 const fixture=await staleClearance(t);const {page}=fixture;
 assert.equal(await page.getByRole('button',{name:'Finish clearance reconciliation',exact:true}).count(),0);
 await openClearanceAbandonment(page);await page.getByRole('button',{name:'Confirm clearance abandonment'}).click();await page.getByRole('status').filter({hasText:'Audited clearance non-commit confirmed'}).waitFor();return fixture;
}
test('finish clearance reconciliation returns to already clear active source without submitting any command',async t=>{
 const {page,current,clearances,commands,secrets,clearanceAbandonments,calls}=await terminalClearance(t);const original=structuredClone(clearances[0]),outer=structuredClone(clearanceAbandonments[0]);
 current.lifecycle='active';current.active_configuration_revision=current.configuration_revision;current.expected_revisions.connector++;current.recovery={...current.recovery,state:'clear',fresh_credentials_required:false,clearance_state:'expired',approval_expires_at:'2020-01-01T00:00:00Z'};
 const reads=calls.length,writes=[];page.on('request',r=>{if(r.method()!=='GET')writes.push(r.url());});
 await scannerAction(page,'Finish clearance reconciliation','Clearance reconciliation finished');await page.locator('.scanner-workspace[aria-busy=false]').waitFor();
 assert.deepEqual(calls.slice(reads).sort(),['/api/v1/connectors/'+sid(2)+'/permissions','/api/v1/scanners/'+sid(2)].sort());assert.deepEqual(writes,[]);assert.equal(clearances.length,1);assert.equal(commands.length,0);assert.equal(secrets.length,0);assert.deepEqual(clearances[0],original);assert.deepEqual(clearanceAbandonments[0],outer);assert.equal(await page.evaluate(()=>sessionStorage.length),0);assert.equal(await page.getByRole('heading',{name:'Retained clearance command'}).count(),0);assert.equal(await page.getByRole('button',{name:'Collect now',exact:true}).isEnabled(),true);assert.equal(await page.getByRole('button',{name:'Apply host clearance',exact:true}).isDisabled(),true);assert.equal(await page.getByRole('status').filter({hasText:'Clearance reconciliation finished'}).evaluate(el=>el===document.activeElement),true);
 await page.reload();await page.getByRole('heading',{name:'Synthetic scanner',exact:true}).waitFor();assert.equal(await page.getByRole('heading',{name:'Retained clearance command'}).count(),0);assert.equal(clearances.length,1);
});
test('finish clearance reconciliation permits required fresh upload then separate new clearance with current fences',async t=>{
 const {page,current,clearances,commands,secrets,clearanceAbandonments}=await terminalClearance(t);const original=structuredClone(clearances[0]);current.recovery=recoveryView({epoch_id:current.recovery.epoch_id});current.credential.state='quarantined';current.expected_revisions.connector++;
 await scannerAction(page,'Finish clearance reconciliation','Clearance reconciliation finished');assert.equal(await page.evaluate(()=>sessionStorage.length),0);assert.equal(clearances.length,1);assert.equal(commands.length,0);assert.equal(secrets.length,0);assert.equal(await page.getByRole('button',{name:'Save Qualys credentials',exact:true}).isEnabled(),true);assert.equal(await page.getByRole('button',{name:'Apply host clearance',exact:true}).isDisabled(),true);
 await page.getByLabel('Qualys username',{exact:true}).fill('synthetic-reader');await page.getByLabel('Qualys password',{exact:true}).fill('  synthetic fresh external password  ');await scannerAction(page,'Save Qualys credentials','Credential version recorded');assert.equal(secrets.length,1);assert.equal(JSON.parse(secrets[0].input.value).password,'  synthetic fresh external password  ');assert.equal(await page.getByLabel('Qualys password',{exact:true}).inputValue(),'');assert.equal(clearances.length,1);assert.equal(commands.length,0);assert.equal(await page.getByRole('button',{name:'Apply host clearance',exact:true}).isDisabled(),true);
 current.recovery={...readyRecovery(),approval_id:sid(83)};current.expected_revisions.connector++;const expected=recoverySlot(current).revisions;
 await page.getByRole('button',{name:'Refresh source access',exact:true}).click();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();assert.equal(clearances.length,1);await page.getByLabel('Reason for scanner action').fill('Reviewed fresh credential and current approval');await scannerAction(page,'Apply host clearance','Clearance applied');assert.equal(clearances.length,2);assert.notEqual(clearances[1].command_id,original.command_id);assert.deepEqual(clearances[1].expected_revisions,expected);assert.equal(clearances[1].payload.version_id,current.credential.version_id);assert.equal(clearances[1].payload.rationale,'Reviewed fresh credential and current approval');assert.deepEqual(clearances[0],original);assert.deepEqual(clearanceAbandonments[0].command,original);assert.equal(commands.length,0);
});
for(const failure of ['network','scanner_denied','permissions_denied','configure_revoked','actor_mismatch','source_mismatch','malformed'])test(`finish clearance reconciliation ${failure} readback preserves both requests and blocks writes`,async t=>{
 const {page,current,clearances,commands,secrets}=await terminalClearance(t),before=await page.evaluate(()=>({...sessionStorage}));let observed=0;
 const match=url=>url.pathname==='/api/v1/scanners/'+sid(2)||url.pathname==='/api/v1/connectors/'+sid(2)+'/permissions';
 const intercept=async route=>{observed++;const scanner=new URL(route.request().url()).pathname.startsWith('/api/v1/scanners/');
  if(scanner){if(failure==='network')return route.abort();if(failure==='scanner_denied')return route.fulfill({status:403,json:clearanceDispositionError('source_scope_forbidden')});const body=structuredClone(current);if(failure==='malformed')delete body.recovery;if(failure==='source_mismatch')body.source_tuple.scope_key=sid(99);return route.fulfill({json:body});}
  if(failure==='permissions_denied')return route.fulfill({status:403,json:connectorError('source_scope_forbidden')});
  return route.fulfill({json:{schema_version:1,connector_id:sid(2),source:{source_id:sid(3),revision:1,...sourceTuple,...(failure==='source_mismatch'?{scope_key:sid(99)}:{})},principal_id:failure==='actor_mismatch'?'other-actor':'synthetic-local-user',revisions:current.expected_revisions,allowed:{'connector.read':true,'connector.configure':failure!=='configure_revoked','connector.secret.manage':true,'github.repository.configure':false}}});
 };
 await page.route(match,intercept);await page.getByRole('button',{name:'Finish clearance reconciliation',exact:true}).click();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();assert.equal(observed,2);assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),before);assert.equal(await page.getByRole('status').filter({hasText:'Clearance reconciliation finished'}).count(),0);assert.equal(await page.getByRole('button',{name:'Save Qualys credentials',exact:true}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Apply host clearance',exact:true}).count(),0);assert.equal(clearances.length,1);assert.equal(commands.length,0);assert.equal(secrets.length,0);assert.equal((await page.content()).includes('SYNTHETIC_RAW_ERROR_DO_NOT_RENDER'),false);
 await page.unroute(match,intercept);await page.getByRole('button',{name:'Refresh source access',exact:true}).click();await page.locator('.scanner-workspace[aria-busy=false]').waitFor();assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),before);assert.equal(await page.getByRole('button',{name:'Finish clearance reconciliation',exact:true}).isEnabled(),true);
});
test('finish clearance reconciliation hanging readback clears autofilled credentials before network and keeps both bodies',async t=>{
 const {page,clearances}=await terminalClearance(t),before=await page.evaluate(()=>({...sessionStorage}));let received;
 const request=new Promise(resolve=>{received=resolve;});let heldRoute;
 await page.route(url=>url.pathname==='/api/v1/scanners/'+sid(2),route=>{heldRoute=route;received();});t.after(()=>heldRoute?.abort().catch(()=>{}));
 await page.getByLabel('Qualys username',{exact:true}).evaluate(el=>el.value='synthetic-autofill');await page.getByLabel('Qualys password',{exact:true}).evaluate(el=>el.value='synthetic-autofill-secret');await page.getByRole('button',{name:'Finish clearance reconciliation',exact:true}).click();await request;
 assert.equal(await page.getByLabel('Qualys username',{exact:true}).inputValue(),'');assert.equal(await page.getByLabel('Qualys password',{exact:true}).inputValue(),'');assert.deepEqual(await page.evaluate(()=>({...sessionStorage})),before);assert.equal(await page.locator('.scanner-workspace').getAttribute('aria-busy'),'true');assert.equal(await page.getByRole('status').filter({hasText:'Clearance reconciliation finished'}).count(),0);assert.equal(clearances.length,1);
});
