// Rendered synthetic API coverage, not persistent authentication evidence.
import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {chromium} from 'playwright';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {scannerView,sourceTuple,sid,detectionPage} from './scanner-fixture.mjs';
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

async function scannerFixture(t,{unconfigured=false,denied=false,readDenied=false,quarantined=false,hanging=false,lost=false,partial=false,configure=true,manage=true,terminal='succeeded',permissionsDenied=false,denialDelay=null,permissionStatus=403,permissionCode='forbidden',receiptless=false}={}){
 const context=await browser.newContext();t.after(()=>context.close());const page=await context.newPage();page.setDefaultTimeout(5000);const current=scannerView();
 if(!unconfigured)current.credential={secret_id:sid(22),version_id:sid(23),state:quarantined?'quarantined':'active',revision:1};
 const calls=[],commands=[],secrets=[],operations=new Map();let resolveSiblings;const siblingResponses=[];const siblings=new Promise(resolve=>{resolveSiblings=resolve;});page.on('response',response=>{const path=new URL(response.url()).pathname;if(path==='/api/v1/scanners/'+sid(2)||path==='/api/v1/connectors/'+sid(2)+'/permissions'){siblingResponses.push(response.status());if(siblingResponses.length===2)resolveSiblings([...siblingResponses]);}});let secretRevision=unconfigured?0:1,pendingRoute,receipts=new Map();
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
  if(path.endsWith('/versions')){
   const body=req.postDataJSON();secrets.push(body);assert.equal(body.purpose,'qualys_vm_basic');assert.equal(body.expected_revisions.secret,secretRevision);assert.equal(path,'/api/v1/connectors/'+sid(2)+'/secrets/'+sid(22)+'/versions');assert.deepEqual(Object.keys(JSON.parse(body.input.value)).sort(),['password','username']);
   if(hanging){pendingRoute=route;return;}
   secretRevision++;current.credential.revision=secretRevision;current.credential.version_id=body.version_id;current.credential.state='active';current.lifecycle=current.configuration_revision?'staged':'disabled';current.active_configuration_revision=null;current.expected_revisions.connector++;current.validation=null;
   return route.fulfill({status:201,json:{schema_version:1,command_id:body.submission_id,action:'connector.secret.submit',target_id:'00000000-0000-4000-8000-000000000000',policy_revision:2,decision_id:sid(50),audit_event_id:sid(51),intents:[],result:{effect:'connector_secret_submitted',connector_id:sid(2),source_id:sid(3),revisions:{...current.expected_revisions,secret:secretRevision},configuration_revision:current.configuration_revision,active_configuration_revision:null,lifecycle:current.lifecycle,secret_id:sid(22),version_id:body.version_id,version_state:'active',submission_id:body.submission_id,submission_outcome:'committed',flow_id:null,recovery:{state:'clear',recovery_epoch_id:null,operator_clearance_present:false,requires_fresh_credentials:false,reason:null}}}});
  }
  if(path==='/api/v1/scanners/'+sid(2)+'/commands'){
   const body=req.postDataJSON();commands.push(body);assert.deepEqual(Object.keys(body).sort(),['action','command_id','expected_revisions','membership_ids','payload','schema_version','target_id']);assert.equal(body.schema_version,1);assert.equal(body.target_id,sid(2));assert.deepEqual(body.membership_ids,[]);assert.equal(body.payload.source_id,sid(3));assert.equal(body.expected_revisions.secret,null);assert.equal(req.headers()['x-csrf-token'],'synthetic-csrf');
   if(receipts.has(body.command_id))return route.fulfill({json:receipts.get(body.command_id)});
   let result;
   if(body.action==='scanner.configuration.save'){assert.deepEqual(body.payload.settings,{product:'qualys_vm',api_version:'2.0',platform_id:'us1',scope:{kind:'account_visible'},collection_mode:'manual'});current.configuration_revision++;current.expected_revisions.connector++;current.lifecycle='staged';current.active_configuration_revision=null;current.validation=null;result={lifecycle:'staged',configuration_revision:current.configuration_revision};}
   else if(body.action==='scanner.configuration.activate'){assert.equal(body.payload.validation_operation_id,current.validation.operation_id);assert.equal(body.payload.credential_version_id,current.credential.version_id);current.lifecycle='active';current.active_configuration_revision=current.configuration_revision;current.expected_revisions.connector++;result={lifecycle:'active',configuration_revision:current.configuration_revision,active_configuration_revision:current.configuration_revision};}
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
 return {page,calls,commands,secrets,current,siblings};
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
