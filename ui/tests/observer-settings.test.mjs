// Synthetic browser contract coverage; no host, OIDC or database verification.
import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {chromium} from 'playwright';
import {createServer} from 'node:http';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';

const root='/api/v1/operations/observer-settings';
const deployment='observer-ui-fixture';
const names=['Observation interval','Request deadline','Heartbeat freshness','Maximum future skew','Anchor export lag','Incident projection deadline','Scheduler progress freshness'];
const keys=['observation_interval_seconds','request_deadline_seconds','heartbeat_freshness_seconds','maximum_future_skew_seconds','anchor_export_lag_seconds','incident_projection_deadline_seconds','scheduler_progress_freshness_seconds'];
const values=Object.fromEntries(keys.map((key,i)=>[key,[1,9,3,1,30,11,15][i]]));
const digest='sha256:'+'a'.repeat(64);
function settings(status='failed') {
 const now=new Date().toISOString();
 return {schema_version:1,deployment_id:deployment,revisions:{configuration:4,policy:1,authority:2,host_policy:2},
  desired:{revision:4,digest,values:{...values},command_id:randomUUID(),committed_at:now},
  effective:{revision:3,digest:'sha256:'+'b'.repeat(64),verified_at:now},
  application:{status,operation_id:randomUUID(),latest_report_id:randomUUID(),failure_code:status==='failed'?'host_policy_rejected':null},
  host_policy:{revision:2,digest,bounds:Object.fromEntries(keys.map(key=>[key,{min:key==='maximum_future_skew_seconds'?0:1,max:key==='request_deadline_seconds'?8:3600}])),observed_at:now,fresh_until:new Date(Date.now()+60000).toISOString(),freshness:'fresh'},can_configure:true};
}
let directory,server,browser,origin;
before(async()=>{
 directory=await mkdtemp(join(tmpdir(),'volt-observer-ui-'));
 await build({stdin:{contents:`import {createRoot} from 'react-dom/client';
 import ObserverSettings from './ObserverSettings';
 import './tokens.css';import './styles.css';
 createRoot(document.getElementById('root')).render(<ObserverSettings actorId="fixture-actor" refresh={0} deploymentId="${deployment}" onDeployment={()=>{}}/>);`,resolveDir:resolve(import.meta.dirname,'../src'),loader:'tsx'},jsx:'automatic',bundle:true,format:'esm',outfile:join(directory,'app.js'),logLevel:'silent'});
 server=createServer(async(req,res)=>{
  if(req.url==='/app.js'||req.url==='/app.css'){
   res.setHeader('Content-Type',req.url.endsWith('css')?'text/css':'text/javascript');res.end(await readFile(join(directory,req.url)));return;
  }
  res.setHeader('Content-Type','text/html');res.end('<!doctype html><html lang="en"><head><title>Observer UI fixture</title><link rel="stylesheet" href="/app.css"></head><body><main><h1>Administration</h1><div id="root"></div></main><script type="module" src="/app.js"></script></body></html>');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin=`http://127.0.0.1:${server.address().port}`;
 browser=await chromium.launch({...(process.env.CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.CHROMIUM_EXECUTABLE_PATH}:{}),headless:true});
});
after(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));if(directory)await rm(directory,{recursive:true,force:true});});
async function fixture(t,state=settings(),retained=null){
 const context=await browser.newContext({viewport:{width:1440,height:1000}});t.after(()=>context.close());
 if(retained)await context.addInitScript(({key,command})=>sessionStorage.setItem(key,JSON.stringify(command)),{key:'uvm.observer.command:'+JSON.stringify(['fixture-actor',deployment]),command:retained});
 const page=await context.newPage();page.setDefaultTimeout(5000);page.on('pageerror',error=>console.error(error));const commands=[];let receipt;
 await page.route('**/api/**',async route=>{
  const url=new URL(route.request().url());
  let body;
  if(url.pathname===root)body={schema_version:1,deployments:[{deployment_id:deployment,label:'Synthetic observer fixture',can_configure:state.can_configure}],next_cursor:null};
  else if(url.pathname===root+'/'+deployment)body=state;
  else if(url.pathname===root+'/'+deployment+'/commands'){
   const command=route.request().postDataJSON();commands.push(command);
   assert.deepEqual(command.expected_revisions,state.revisions);
   assert.ok(!['pending','uncertain'].includes(state.application.status));
   assert.ok(state.can_configure);
   for(const key of keys)assert.ok(command.values[key]>=state.host_policy.bounds[key].min&&command.values[key]<=state.host_policy.bounds[key].max);
   state.revisions.configuration++;
   state.desired={...state.desired,revision:state.revisions.configuration,values:command.values,command_id:command.command_id};
   state.application={...state.application,status:'pending',latest_report_id:null,failure_code:null};
   const {configuration,...evaluated_revisions}=command.expected_revisions;
   receipt={schema_version:1,deployment_id:deployment,command_id:command.command_id,action:command.action,effect:'desired_committed',request_digest:digest,configuration_revision:configuration+1,configuration_digest:digest,evaluated_revisions,audit_id:randomUUID(),intent_id:randomUUID(),committed_at:new Date().toISOString()};body=receipt;
  }else throw new Error('Unexpected synthetic API route '+url.pathname);
  await route.fulfill({status:route.request().method()==='POST'?201:200,json:body});
 });
 await page.goto(origin);
 await page.locator('.observer-state').waitFor();
 return {page,commands,state};
}
async function correction(page){
 await page.getByLabel('Request deadline',{exact:true}).fill('8');
 await page.getByLabel('Reason for change',{exact:true}).fill('Correct rejected timing against signed policy');
}

test('failed desired revision explains invalid values and permits keyboard correction to a new publication',async t=>{
 const {page,commands}=await fixture(t);
 assert.match(await page.locator('.observer-summary').innerText(),/Revision 4[\s\S]*Revision 3/);
 await page.getByLabel('Reason for change',{exact:true}).fill('Correct rejected timing');
 assert.equal(await page.getByRole('button',{name:'Save timing settings',exact:true}).isDisabled(),true);
 // Regression: previously Save silently stayed disabled with no correction guidance.
 assert.equal(await page.getByText('Review values outside the host bounds',{exact:true}).count(),1);
 assert.equal(await page.getByLabel('Request deadline',{exact:true}).getAttribute('aria-invalid'),'true');
 await page.getByLabel('Request deadline',{exact:true}).focus();
 await page.keyboard.press('ControlOrMeta+A');await page.keyboard.type('8');
 assert.equal(await page.getByLabel('Request deadline',{exact:true}).getAttribute('aria-invalid'),'false');
 await page.getByLabel('Evidence reference (optional)',{exact:true}).focus();await page.keyboard.press('Tab');
 assert.equal(await page.getByRole('button',{name:'Save timing settings',exact:true}).evaluate(el=>el===document.activeElement),true);
 const focus=await page.evaluate(()=>({style:getComputedStyle(document.activeElement).outlineStyle,width:getComputedStyle(document.activeElement).outlineWidth}));
 assert.notEqual(focus.style,'none');assert.notEqual(focus.width,'0px');
 await page.keyboard.press('Enter');await page.getByText(/Desired revision 5 recorded/).waitFor();
 assert.equal(commands.length,1);assert.equal(commands[0].values.request_deadline_seconds,8);
 assert.equal(commands[0].expected_revisions.host_policy,2);
 assert.match(await page.locator('.observer-summary').innerText(),/Revision 5[\s\S]*Revision 3/);
 assert.equal(await page.getByRole('button',{name:'Save timing settings',exact:true}).isDisabled(),true);
});

for(const status of ['pending','uncertain'])test(status+' retains the publication hold',async t=>{
 const {page,commands}=await fixture(t,settings(status));
 assert.equal(await page.getByLabel('Request deadline',{exact:true}).isDisabled(),true);
 await page.getByLabel('Reason for change',{exact:true}).fill('Cannot overtake unresolved application');
 assert.equal(await page.getByRole('button',{name:'Save timing settings',exact:true}).isDisabled(),true);
 assert.equal(commands.length,0);
});

test('failed host state does not bypass a retained command receipt',async t=>{
 const state=settings();const command={schema_version:1,command_id:randomUUID(),action:'observer.timing.publish',expected_revisions:state.revisions,rationale:'Unconfirmed command',values};
 const {page,commands}=await fixture(t,state,command);
 await page.getByText('Command outcome needs recovery',{exact:true}).waitFor();
 assert.equal(await page.getByLabel('Request deadline',{exact:true}).isDisabled(),true);
 assert.equal(await page.getByRole('button',{name:'Save timing settings',exact:true}).isDisabled(),true);
 assert.equal(commands.length,0);
});

test('changed host policy requires explicit draft review before recovery',async t=>{
 const {page,state,commands}=await fixture(t);await correction(page);
 state.revisions.host_policy=3;state.host_policy.revision=3;
 await page.getByRole('button',{name:'Refresh observer state',exact:true}).click();
 await page.getByText('Review the current revision',{exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Save timing settings',exact:true}).isDisabled(),true);
 await page.getByRole('button',{name:'Use latest saved values',exact:true}).click();await correction(page);
 await page.getByRole('button',{name:'Save timing settings',exact:true}).click();
 await page.getByText(/Desired revision 5 recorded/).waitFor();
 assert.equal(commands[0].expected_revisions.host_policy,3);
});

test('failed recovery remains read-only without current configure authority',async t=>{
 const state=settings();state.can_configure=false;const {page,commands}=await fixture(t,state);
 await page.getByText('Settings are read-only',{exact:true}).waitFor();
 assert.equal(await page.getByLabel('Request deadline',{exact:true}).isDisabled(),true);
 assert.equal(await page.getByRole('button',{name:'Save timing settings',exact:true}).isDisabled(),true);
 assert.equal(commands.length,0);
});

test('failed recovery has axe coverage and no page overflow at 1440, 390 and 320 pixels',async t=>{
 const {page}=await fixture(t);await page.addScriptTag({path:resolve(import.meta.dirname,'../node_modules/axe-core/axe.min.js')});
 for(const width of [1440,390,320]){
  await page.setViewportSize({width,height:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`reflow ${width}`);
  const violations=await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations);
  assert.deepEqual(violations,[],`axe ${width}`);
 }
});
