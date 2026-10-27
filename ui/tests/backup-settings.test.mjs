// Synthetic browser fixtures. No host, database, OIDC or recovery integration claim.
import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {chromium} from 'playwright';
import {createServer} from 'node:http';
import {mkdtemp,readFile,rm,mkdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
const root='/api/v1/operations/backup-settings';
const deployment='backup-ui-fixture';
const keys=['interval_seconds','timeout_seconds','maximum_backup_age_seconds','restore_verification_timeout_seconds'];
const labels=['Backup interval','Backup timeout','Maximum backup age','Restore verification timeout'];
const values={interval_seconds:3600,timeout_seconds:900,maximum_backup_age_seconds:90000,restore_verification_timeout_seconds:1800,archive_target_ref:'archive-a',recovery_profile_ref:'recovery-a'};
const digest='sha256:'+'a'.repeat(64),oldDigest='sha256:'+'b'.repeat(64);
function settings(application='failed') {
 const now=new Date().toISOString();
 return {schema_version:1,deployment_id:deployment,revisions:{configuration:4,policy:5,authority:7,host_policy:3,recovery_epoch:0},
  desired:{revision:4,digest,values:{...values},command_id:randomUUID(),committed_at:now},
  effective:{revision:application==='applied'?4:3,digest:application==='applied'?digest:oldDigest,verified_at:now},
  status:{settings_application:{state:application,requested_revision:4,requested_digest:digest,intent_id:randomUUID(),host_policy_revision:3,active_revision:application==='applied'?4:3,active_digest:application==='applied'?digest:oldDigest,reported_at:now,failure_code:application==='failed'?'host_policy_rejected':null},completed_archive:{archive_id:null,completed_at:null,manifest_digest:null,outcome:null},freshness:{state:'unknown',evaluated_at:null,age_seconds:null,basis_completed_at:null,maximum_backup_age_seconds:null},restore_verification:{state:'unknown',archive_id:null,recovery_epoch:0,verified_at:null,failure_code:null}},
  host_policy:{revision:3,digest,bounds:Object.fromEntries(keys.map(key=>[key,{min:1,max:key==='timeout_seconds'?800:100000}])),archive_target_refs:['archive-a','archive-b'],recovery_profile_refs:['recovery-a','recovery-b'],maximum_report_age_seconds:300,maximum_future_skew_seconds:30,observed_at:now,fresh_until:new Date(Date.now()+60000).toISOString(),freshness:'fresh'},can_configure:true};
}
let directory,server,browser,origin;
before(async()=>{
 directory=await mkdtemp(join(tmpdir(),'volt-backup-ui-'));
 await build({stdin:{contents:`import {createRoot} from 'react-dom/client';
 import BackupSettings from './BackupSettings';
 import {useState} from 'react';
 import NativePermissionEditor from './NativePermissionEditor';
 import {permissionWithin} from './native-admin-validation';
 function Permissions(){const [value,setValue]=useState([]);return <><NativePermissionEditor catalogue={window.fixtureCatalogue} value={value} onChange={setValue}/><output id="permissions-state">{JSON.stringify({value,valid:value.every(p=>permissionWithin(p,window.fixtureCatalogue))})}</output></>;}
 import './tokens.css';import './styles.css';
 createRoot(document.getElementById('root')).render(location.pathname==='/permissions'?<Permissions/>:<BackupSettings actorId="fixture-actor" refresh={0} deploymentId="${deployment}"/>);`,resolveDir:resolve(import.meta.dirname,'../src'),loader:'tsx'},jsx:'automatic',bundle:true,format:'esm',outfile:join(directory,'app.js'),logLevel:'silent'});
 server=createServer(async(req,res)=>{
  if(req.url==='/app.js'||req.url==='/app.css'){res.setHeader('Content-Type',req.url.endsWith('css')?'text/css':'text/javascript');res.end(await readFile(join(directory,req.url)));return;}
  res.setHeader('Content-Type','text/html');res.end('<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Backup UI fixture</title><link rel="stylesheet" href="/app.css"></head><body><main><h1>Administration</h1><div id="root"></div></main><script type="module" src="/app.js"></script></body></html>');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin=`http://127.0.0.1:${server.address().port}`;
 browser=await chromium.launch({...(process.env.CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.CHROMIUM_EXECUTABLE_PATH}:{}),headless:true});
});
after(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));if(directory)await rm(directory,{recursive:true,force:true});});
async function fixture(t,state=settings(),retained=null,options={}) {
 const context=await browser.newContext({viewport:{width:1440,height:1000}});t.after(()=>context.close());
 if(retained)await context.addInitScript(({key,command})=>sessionStorage.setItem(key,JSON.stringify(command)),{key:'volt.backup.command:'+JSON.stringify(['fixture-actor',deployment]),command:retained});
 const page=await context.newPage();page.setDefaultTimeout(5000);const errors=[];page.on('pageerror',e=>errors.push(e.message));t.after(()=>assert.deepEqual(errors,[]));
 const commands=[];let receipt;
 const history={schema_version:1,deployment_id:deployment,revision:2,digest:oldDigest,values:{...values,timeout_seconds:700},publication_revisions:options.historyTokens??{configuration:2,policy:4,authority:6,host_policy:2},command_id:randomUUID(),actor_id:'historical-actor',rationale:'Previous immutable settings',evidence_ref:null,committed_at:new Date().toISOString(),audit_id:randomUUID()};
 await page.route('**/api/**',async route=>{
  const url=new URL(route.request().url());let body,status=200;
  const error=(code,outcome='not_committed')=>({schema_version:1,error:{code,message:code,details:{outcome}}});
  if(url.pathname===root+'/'+deployment){if(options.readDenied){status=403;body=error('forbidden');}else body=state;}
  else if(url.pathname===root+'/'+deployment+'/revisions/2')body=history;
  else if(url.pathname.includes('/receipts/')){if(receipt)body={...receipt,actor_id:options.receiptActor??receipt.actor_id};else{status=404;body=error('not_found');}}
  else if(url.pathname===root+'/'+deployment+'/commands'){
   const command=route.request().postDataJSON();commands.push(command);
   if(options.commandError){status=options.commandError;body=error(status===409?'revision_conflict':'forbidden');}
   else {
    const {recovery_epoch,...expected}=state.revisions;
    assert.deepEqual(command.expected_revisions,expected);
    assert.equal(command.schema_version,1);assert.ok(Object.hasOwn(command,'evidence_ref'));
    assert.equal(Object.keys(command).length,7);
    assert.ok(!['pending','uncertain','unknown'].includes(state.status.settings_application?.state));assert.ok(state.can_configure);
    const appliedValues=command.action==='backup.settings.rollback'?history.values:command.values;
    for(const key of keys)assert.ok(appliedValues[key]>=state.host_policy.bounds[key].min&&appliedValues[key]<=state.host_policy.bounds[key].max);
    assert.ok(state.host_policy.archive_target_refs.includes(appliedValues.archive_target_ref));assert.ok(state.host_policy.recovery_profile_refs.includes(appliedValues.recovery_profile_ref));
    state.revisions.configuration++;
    state.desired={revision:state.revisions.configuration,digest,values:appliedValues,command_id:command.command_id,committed_at:new Date().toISOString()};
    const intent=randomUUID();state.status.settings_application={state:'pending',requested_revision:state.revisions.configuration,requested_digest:digest,intent_id:intent,host_policy_revision:3,active_revision:state.effective?.revision??null,active_digest:state.effective?.digest??null,reported_at:null,failure_code:null};
    receipt={schema_version:1,deployment_id:deployment,command_id:command.command_id,actor_id:'fixture-actor',action:command.action,request_digest:digest,settings_digest:digest,desired_revision:state.revisions.configuration,evaluated_revisions:command.expected_revisions,audit_id:randomUUID(),intent_id:intent,committed_at:new Date().toISOString(),outcome:'desired_committed'};
    if(options.dropResponse){await route.abort('failed');return;}body=options.invalidReceipt?{...receipt,outcome:'applied'}:{...receipt,actor_id:options.saveActor??receipt.actor_id};status=201;
   }
  }else throw new Error('Unexpected synthetic route '+url.pathname);
  await route.fulfill({status,json:body});
 });
 await page.goto(origin);await page.getByRole('button',{name:'Refresh backup state',exact:true}).waitFor();
 if(options.readDenied)await page.getByText('Current permissions do not allow this operation.',{exact:true}).waitFor();
 else if(options.invalidRead)await page.getByText('The server response could not be verified. No successful outcome is inferred.',{exact:true}).waitFor();
 else await page.locator('.observer-state').waitFor();
 return {page,state,commands,options};
}
async function correction(page){await page.getByLabel('Backup timeout',{exact:true}).fill('800');await page.getByLabel('Reason for change',{exact:true}).fill('Correct rejected backup settings');}
const saveButton=page=>page.getByRole('button',{name:'Save backup settings',exact:true});

test('six-field correction uses exact four-token command; keyboard Save commits desired and retains separate effective state',async t=>{
 const {page,commands}=await fixture(t);assert.match(await page.locator('.observer-summary').innerText(),/Revision 4[\s\S]*Revision 3/);
 await page.getByLabel('Reason for change',{exact:true}).fill('Correct rejected settings');assert.equal(await saveButton(page).isDisabled(),true);
 assert.equal(await page.getByText('Review values outside the host bounds',{exact:true}).count(),1);
 await page.getByLabel('Backup timeout',{exact:true}).focus();await page.keyboard.press('ControlOrMeta+A');await page.keyboard.type('800');
 await page.getByLabel('Archive target',{exact:true}).selectOption('archive-b');await page.getByLabel('Recovery profile',{exact:true}).selectOption('recovery-b');
 await page.getByLabel('Evidence reference (optional)',{exact:true}).fill('change-42');await page.keyboard.press('Tab');
 assert.equal(await saveButton(page).evaluate(el=>el===document.activeElement),true);
 const focus=await page.evaluate(()=>({style:getComputedStyle(document.activeElement).outlineStyle,width:getComputedStyle(document.activeElement).outlineWidth}));assert.notEqual(focus.style,'none');assert.notEqual(focus.width,'0px');
 await page.keyboard.press('Enter');await page.getByText(/Desired revision 5 recorded/).waitFor();
 assert.equal(commands.length,1);assert.equal(commands[0].values.timeout_seconds,800);assert.equal(commands[0].values.archive_target_ref,'archive-b');assert.equal(commands[0].values.recovery_profile_ref,'recovery-b');assert.equal(commands[0].evidence_ref,'change-42');
 assert.match(await page.locator('.observer-summary').innerText(),/Revision 5[\s\S]*Revision 3/);assert.equal(await saveButton(page).isDisabled(),true);
});
for(const state of ['pending','uncertain','unknown'])test(state+' application blocks an overtaking publication',async t=>{const {page,commands}=await fixture(t,settings(state));assert.equal(await page.getByLabel('Backup timeout',{exact:true}).isDisabled(),true);assert.equal(await saveButton(page).isDisabled(),true);assert.equal(commands.length,0);});
test('applied settings keep archive, freshness and restore unknown',async t=>{const {page}=await fixture(t,settings('applied'));assert.equal(await page.locator('.backup-state').allTextContents().then(x=>x.map(t=>t.toLowerCase())).then(x=>x.every(t=>t==='unknown')),true);assert.match(await page.locator('.observer-summary').innerText(),/Revision 4[\s\S]*Revision 4/);assert.equal(await page.getByText('Applied settings do not establish a usable backup.',{exact:true}).count(),1);});
test('completed stale archive and failed restore are independent of applied settings',async t=>{
 const state=settings('applied'),now=new Date().toISOString(),archive=randomUUID();state.status.completed_archive={archive_id:archive,completed_at:now,manifest_digest:digest,outcome:'complete'};state.status.freshness={state:'stale',evaluated_at:now,age_seconds:90001,basis_completed_at:now,maximum_backup_age_seconds:90000};state.status.restore_verification={state:'failed',archive_id:archive,recovery_epoch:1,verified_at:null,failure_code:'readback_failed'};state.revisions.recovery_epoch=1;
 const {page}=await fixture(t,state);assert.deepEqual(await page.locator('.backup-state').allTextContents(),['complete','stale','failed']);
});
test('unconfigured state has no invented defaults and missing host policy blocks Save',async t=>{
 const state=settings();state.revisions.configuration=0;state.revisions.host_policy=0;state.desired=null;state.effective=null;state.status.settings_application=null;state.host_policy=null;state.can_configure=false;
 const {page}=await fixture(t,state);assert.equal(await page.getByRole('heading',{name:'Not configured',exact:true}).count(),1);assert.equal(await page.getByLabel('Backup interval',{exact:true}).inputValue(),'');assert.equal(await saveButton(page).isDisabled(),true);
});
for(const freshness of ['stale','unknown'])test(freshness+' host policy prevents publication despite configure=true',async t=>{const state=settings();state.host_policy.freshness=freshness;const {page}=await fixture(t,state);assert.equal(await saveButton(page).isDisabled(),true);assert.equal(await page.getByLabel('Archive target',{exact:true}).isDisabled(),true);});
test('expired host-policy timestamp blocks publication',async t=>{const state=settings();state.host_policy.observed_at=new Date(Date.now()-60000).toISOString();state.host_policy.fresh_until=new Date(Date.now()-1000).toISOString();const {page}=await fixture(t,state);assert.equal(await saveButton(page).isDisabled(),true);});
test('read-only grants and forbidden reads do not offer editable settings',async t=>{const state=settings();state.can_configure=false;const {page}=await fixture(t,state);assert.equal(await saveButton(page).isDisabled(),true);const denied=await fixture(t,settings(),null,{readDenied:true});assert.equal(await denied.page.locator('form').count(),0);});
test('changed revision retains rationale and requires explicit refreshed review',async t=>{const {page,state,commands}=await fixture(t);await correction(page);state.revisions.host_policy++;state.host_policy.revision++;
 await page.getByRole('button',{name:'Refresh backup state',exact:true}).click();await page.getByText('Review the current revision',{exact:true}).waitFor();assert.equal(await saveButton(page).isDisabled(),true);await page.getByRole('button',{name:'Use latest saved values',exact:true}).click();assert.equal(await page.getByLabel('Reason for change',{exact:true}).inputValue(),'Correct rejected backup settings');await correction(page);await saveButton(page).click();await page.getByText(/Desired revision 5 recorded/).waitFor();assert.equal(commands[0].expected_revisions.host_policy,4);
});
test('HTTP 409 requires refresh before a new command',async t=>{const {page,options,commands}=await fixture(t,settings(),null,{commandError:409});await correction(page);await saveButton(page).click();await page.getByText('Review changed settings',{exact:true}).waitFor();assert.equal(await page.getByRole('button',{name:'Use latest saved values',exact:true}).isDisabled(),true);options.commandError=null;await page.getByRole('button',{name:'Refresh backup state',exact:true}).click();await page.getByRole('button',{name:'Use latest saved values',exact:true}).click();await correction(page);await saveButton(page).click();await page.getByText(/Desired revision 5 recorded/).waitFor();assert.equal(commands.length,2);assert.notEqual(commands[0].command_id,commands[1].command_id);});
test('lost response survives reload, recovers exact receipt without another POST',async t=>{const {page,commands}=await fixture(t,settings(),null,{dropResponse:true});await correction(page);await saveButton(page).click();await page.getByText('Command outcome needs recovery',{exact:true}).waitFor();await page.reload();await page.getByText('Command outcome needs recovery',{exact:true}).waitFor();await page.getByRole('button',{name:'Check command receipt',exact:true}).click();await page.getByText(/Desired revision 5 recorded/).waitFor();assert.equal(commands.length,1);assert.equal(await page.getByText('Command outcome needs recovery',{exact:true}).count(),0);});
test('missing receipt and denied replay preserve the unresolved original command',async t=>{const state=settings();const {recovery_epoch,...revisions}=state.revisions;const original={schema_version:1,command_id:randomUUID(),action:'backup.settings.publish',expected_revisions:revisions,rationale:'Unconfirmed',evidence_ref:null,values:{...values,timeout_seconds:800}};const {page,commands}=await fixture(t,state,original,{commandError:403});await page.getByRole('button',{name:'Check command receipt',exact:true}).click();await page.getByText(/No disclosable record/).waitFor();assert.equal(await saveButton(page).isDisabled(),true);await page.getByRole('button',{name:'Retry same command',exact:true}).click();await page.getByText('Current permissions do not allow this operation.',{exact:true}).waitFor();assert.equal(await page.getByText('Command outcome needs recovery',{exact:true}).count(),1);assert.deepEqual(commands,[original]);});
test('history preserves immutable values and rollback publishes a new revision',async t=>{const {page,commands}=await fixture(t);await page.getByLabel('Historical revision',{exact:true}).fill('2');await page.getByRole('button',{name:'Read historical revision',exact:true}).click();await page.getByText('Previous immutable settings',{exact:true}).waitFor();await page.getByLabel('Reason for change',{exact:true}).fill('Return to retained settings');await page.getByRole('button',{name:'Roll back as new revision',exact:true}).click();await page.getByText(/Desired revision 5 recorded/).waitFor();assert.equal(commands[0].rollback_revision,2);assert.equal(commands[0].action,'backup.settings.rollback');assert.equal('values' in commands[0],false);assert.equal(commands[0].evidence_ref,null);});
test('revoked reference needs a current registered replacement',async t=>{const state=settings();state.desired.values.archive_target_ref='revoked-target';const {page}=await fixture(t,state);await correction(page);assert.equal(await saveButton(page).isDisabled(),true);assert.equal(await page.getByLabel('Archive target',{exact:true}).getAttribute('aria-invalid'),'true');await page.getByLabel('Archive target',{exact:true}).selectOption('archive-b');assert.equal(await saveButton(page).isEnabled(),true);});
test('axe and reflow at 1440, 390 and 320; captures are labelled synthetic',async t=>{const {page}=await fixture(t);await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});const results=[];for(const width of [1440,390,320]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`reflow ${width}`);const violations=await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations);assert.deepEqual(violations,[],`axe ${width}`);results.push({width,overflow:false,violations});if(process.env.BACKUP_UI_EVIDENCE_DIR){await mkdir(process.env.BACKUP_UI_EVIDENCE_DIR,{recursive:true});await page.screenshot({path:join(process.env.BACKUP_UI_EVIDENCE_DIR,`synthetic-backup-${width}.png`),fullPage:true});}}
 if(process.env.BACKUP_UI_EVIDENCE_DIR)await writeFile(join(process.env.BACKUP_UI_EVIDENCE_DIR,'synthetic-accessibility.json'),JSON.stringify({environment:'synthetic browser fixtures; no host/database/OIDC',results},null,2));
});

test('invalid successful response holds the command until its exact receipt is verified',async t=>{const {page,commands}=await fixture(t,settings(),null,{invalidReceipt:true});await correction(page);await saveButton(page).click();await page.getByText('Command outcome needs recovery',{exact:true}).waitFor();await page.getByRole('button',{name:'Check command receipt',exact:true}).click();await page.getByText(/Desired revision 5 recorded/).waitFor();assert.equal(commands.length,1);});
test('corrupt retained command blocks new publications',async t=>{const {page,commands}=await fixture(t,settings(),{schema_version:99,command_id:randomUUID()});await page.getByText('Stored operation cannot be verified',{exact:true}).waitFor();assert.equal(await saveButton(page).isDisabled(),true);assert.equal(commands.length,0);});
test('native permission editor selects separate backup read/configure grants and preserves observer grant',async t=>{
 const context=await browser.newContext();t.after(()=>context.close());
 const scope={group_ids:['*'],source_families:['*'],environments:['*'],service_ids:['*'],membership_mode:'all_current'};
 const limits={maximum_acceptance_days:null,maximum_severity:null,whole_group_confirmation:false,allowed_environments:[],allowed_service_ids:[],allowed_sla_clock_bases:[],allowed_sla_severities:[],allowed_sla_start_sources:[],maximum_sla_duration_seconds:null,maximum_deadline_extension_seconds:null,allow_sla_backfill:false,allowed_identity_scalar_fields:{}};
 const duties={approval_requires_distinct_actor:false,prohibit_requester_approval:false,required_approver_count:1,prohibited_action_pairs:[]};
 const actions=['backup.settings.read','backup.settings.configure','observer.timing.read'];
 const catalogue={schema_version:1,authority_mode:'uvm_native_v1',policy_revision:1,authority_revision:2,ownership_revision:1,caller:{principal_id:'actor',can_manage_access_groups:true,can_manage_ownership_teams:false,grantable:{actions,target_scope:scope,limits,source_scopes:[],separation_of_duties:duties,deployment_scopes:['deployment-a','deployment-b']}},selectable_actions:actions.map(action=>({action,target_scope:scope,limits,deployment_scopes:['deployment-a','deployment-b']}))};
 await context.addInitScript(catalogue=>window.fixtureCatalogue=catalogue,catalogue);const page=await context.newPage();page.setDefaultTimeout(5000);await page.goto(origin+'/permissions');
 for(const action of actions){await page.getByLabel('Add action').selectOption(action);await page.getByRole('button',{name:'Add permission',exact:true}).click();}
 const current=()=>page.locator('#permissions-state').textContent().then(JSON.parse);
 const prior=await current();assert.equal(prior.valid,true);assert.deepEqual(prior.value.map(p=>p.action),actions);
 const read=page.getByRole('group',{name:'Exact deployments for backup.settings.read',exact:true});await read.getByRole('checkbox',{name:'deployment-b',exact:true}).uncheck();
 const configure=page.getByRole('group',{name:'Exact deployments for backup.settings.configure',exact:true});await configure.getByRole('checkbox',{name:'deployment-a',exact:true}).uncheck();
 let result=await current();assert.deepEqual(result.value[0].deployment_scopes,['deployment-a']);assert.deepEqual(result.value[1].deployment_scopes,['deployment-b']);assert.deepEqual(result.value[2],prior.value[2]);assert.equal(result.valid,true);
 await configure.getByRole('checkbox',{name:'deployment-b',exact:true}).uncheck();result=await current();assert.equal(result.valid,false);assert.equal(await page.getByText('Select a deployment',{exact:true}).count(),1);
});

test('Save and receipt recovery reject another actor and preserve the exact retained command',async t=>{
 const {page,commands,options}=await fixture(t,settings(),null,{saveActor:'different-actor',receiptActor:'different-actor'});
 await correction(page);await saveButton(page).click();await page.getByText('Command outcome needs recovery',{exact:true}).waitFor();
 const stored=()=>page.evaluate(key=>JSON.parse(sessionStorage.getItem(key)),'volt.backup.command:'+JSON.stringify(['fixture-actor',deployment]));
 assert.deepEqual(await stored(),commands[0]);assert.equal(await page.getByText(/Desired revision 5 recorded/).count(),0);
 await page.getByRole('button',{name:'Check command receipt',exact:true}).click();await page.getByText('The server response could not be verified. No successful outcome is inferred.',{exact:true}).waitFor();
 assert.deepEqual(await stored(),commands[0]);assert.equal(await page.getByText('Command outcome needs recovery',{exact:true}).count(),1);assert.equal(await page.getByText(/Desired revision 5 recorded/).count(),0);assert.equal(await saveButton(page).isDisabled(),true);
 options.receiptActor='fixture-actor';await page.getByRole('button',{name:'Check command receipt',exact:true}).click();await page.getByText(/Desired revision 5 recorded/).waitFor();assert.equal(await stored(),null);assert.equal(commands.length,1);
});
function freshArchiveState(){const state=settings('applied'),completed=new Date(Date.now()-10000).toISOString();state.status.completed_archive={archive_id:randomUUID(),completed_at:completed,manifest_digest:digest,outcome:'complete'};state.status.freshness={state:'fresh',evaluated_at:new Date().toISOString(),age_seconds:10,basis_completed_at:completed,maximum_backup_age_seconds:90000};return state;}
for(const [name,mutate] of [
 ['incomplete archive',s=>s.status.completed_archive={archive_id:null,completed_at:null,manifest_digest:null,outcome:null}],
 ['failed archive',s=>s.status.completed_archive.outcome='failed'],
 ['nonmatching archive time',s=>s.status.freshness.basis_completed_at=new Date(Date.now()-20000).toISOString()],
])test('contradictory fresh readback is hidden: '+name,async t=>{const state=freshArchiveState();mutate(state);const {page}=await fixture(t,state,null,{invalidRead:true});assert.equal(await page.locator('.backup-state').count(),0);assert.equal(await saveButton(page).count(),0);assert.equal(await page.locator('.observer-summary').count(),0);});
test('valid complete archive displays server freshness while restore remains unknown',async t=>{const {page}=await fixture(t,freshArchiveState());assert.deepEqual(await page.locator('.backup-state').allTextContents(),['complete','fresh','unknown']);});
test('history revision token labels are independent of JSON member order',async t=>{const {page}=await fixture(t,settings(),null,{historyTokens:{authority:17,host_policy:19,policy:13,configuration:2}});await page.getByLabel('Historical revision',{exact:true}).fill('2');await page.getByRole('button',{name:'Read historical revision',exact:true}).click();await page.getByText('Previous immutable settings',{exact:true}).waitFor();const tokens=page.locator('dl > div').filter({has:page.getByText('Publication tokens (configuration / policy / authority / host policy)',{exact:true})});assert.equal(await tokens.locator('dd').textContent(),'2 / 13 / 17 / 19');});
