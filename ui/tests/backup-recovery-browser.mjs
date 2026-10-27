// Browser handoff for the maintained container journey. No API fixtures or host operations.
// Import runBackupBrowserStep with the journey's authenticated Playwright Page, or use the CLI.
import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';
const durations={interval_seconds:'Backup interval',timeout_seconds:'Backup timeout',maximum_backup_age_seconds:'Maximum backup age',restore_verification_timeout_seconds:'Restore verification timeout'};
const references={archive_target_ref:'Archive target',recovery_profile_ref:'Recovery profile'};
const statusKeys=['desired_revision','effective_revision','application','archive','freshness','restore'];
function validate(e){
 assert.equal(e.schema_version,1);assert.ok(typeof e.deployment_id==='string'&&e.deployment_id);assert.match(e.id,/^[a-zA-Z0-9_-]+$/);
 assert.ok(['read','publish','rollback'].includes(e.action));assert.deepEqual(Object.keys(e.expect).sort(),[...statusKeys].sort());
 for(const key of ['desired_revision','effective_revision'])assert.ok(e.expect[key]===null||Number.isSafeInteger(e.expect[key])&&e.expect[key]>=1);
 assert.ok(['pending','applied','failed','uncertain','unknown'].includes(e.expect.application));assert.ok(['complete','failed','uncertain','unknown'].includes(e.expect.archive));assert.ok(['fresh','stale','unknown'].includes(e.expect.freshness));assert.ok(['verified','failed','uncertain','unknown'].includes(e.expect.restore));
 if(e.action!=='read'){assert.ok(typeof e.rationale==='string'&&e.rationale.trim());assert.ok(e.evidence_ref===null||typeof e.evidence_ref==='string');assert.ok(Number.isSafeInteger(e.expect.desired_revision));}
 if(e.action==='publish'){assert.deepEqual(Object.keys(e.values).sort(),[...Object.keys(durations),...Object.keys(references)].sort());for(const k of Object.keys(durations))assert.ok(Number.isSafeInteger(e.values[k])&&e.values[k]>=0);for(const k of Object.keys(references))assert.ok(typeof e.values[k]==='string'&&e.values[k]);}
 if(e.action==='rollback')assert.ok(Number.isSafeInteger(e.rollback_revision)&&e.rollback_revision>=1);
 assert.ok(e.lose_acknowledgement===undefined||typeof e.lose_acknowledgement==='boolean');assert.ok(!e.lose_acknowledgement||e.action!=='read');
}
function assertCommand(command,e,expectedRevisions){
 assert.ok(command&&typeof command==='object','Expected a JSON backup command');
 assert.match(command.command_id,/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
 assert.deepEqual(Object.keys(command.expected_revisions).sort(),['authority','configuration','host_policy','policy']);
 for(const value of Object.values(command.expected_revisions))assert.ok(Number.isSafeInteger(value)&&value>=0);
 assert.equal(command.expected_revisions.configuration,e.expect.desired_revision-1);
 const expected={schema_version:1,command_id:command.command_id,action:'backup.settings.'+(e.action==='rollback'?'rollback':'publish'),expected_revisions:expectedRevisions,rationale:e.rationale,evidence_ref:e.evidence_ref,...(e.action==='publish'?{values:e.values}:{rollback_revision:e.rollback_revision})};
 assert.deepEqual(command,expected,'Observed backup command payload differs from the expected command');
 return expected;
}
async function enabled(locator,timeout){await locator.waitFor();await locator.evaluate((el,timeout)=>new Promise((resolve,reject)=>{const start=Date.now();const check=()=>{if(!el.isConnected)return reject(new Error('Control was replaced'));if(!el.disabled)return resolve();if(Date.now()-start>=timeout)return reject(new Error('Control remains disabled'));setTimeout(check,50);};check();}),timeout);}
async function snapshot(page){
 const summaries=page.locator('.backup-settings .observer-summary section');
 const revision=async index=>{const value=await summaries.nth(index).locator('h3').innerText();return value.startsWith('Revision ')?Number(value.slice(9)):null;};
 const states=await page.locator('.backup-settings .backup-state').allTextContents();
 return {desired_revision:await revision(0),effective_revision:await revision(1),application:(await page.locator('.backup-settings .observer-state').innerText()).replace(/^[^A-Za-z]+/,'').trim().toLowerCase(),archive:states[0]?.toLowerCase(),freshness:states[1]?.toLowerCase(),restore:states[2]?.toLowerCase()};
}
export async function runBackupBrowserStep({page,origin,expectations:e,evidenceDirectory}){
 validate(e);await mkdir(evidenceDirectory,{recursive:true,mode:0o700});
 const timeout=e.timeout_ms??90000;assert.ok(Number.isSafeInteger(timeout)&&timeout>=1000&&timeout<=180000);page.setDefaultTimeout(timeout);
 const report={schema_version:1,id:e.id,deployment_id:e.deployment_id,action:e.action,environment:'Caller-provided authenticated product endpoint; this browser handoff does not validate host/container provenance',origin,discovery_pages:0,commands:[],command_paths:[],receipt_reads:0,lost_acknowledgements:0,expected:e.expect,observed:null,accessibility:[],passed:false};
 const commandPath='/api/v1/operations/backup-settings/'+encodeURIComponent(e.deployment_id)+'/commands';
 const observe=request=>{const url=new URL(request.url());if(/^\/api\/v1\/operations\/backup-settings\/[^/]+\/commands\/?$/.test(url.pathname)&&request.method()==='POST'){let command;try{command=request.postDataJSON();}catch{command=null;}report.commands.push(command);report.command_paths.push(url.pathname);}if(url.pathname.startsWith(commandPath.replace(/\/commands$/,'/receipts/')))report.receipt_reads++;};
 const assertReadOnly=()=>{if(e.action==='read')assert.equal(report.commands.length,0,'Read-only browser step sent a backup-command POST');};
 page.on('request',observe);const commandRoute=url=>url.pathname===commandPath;let interceptor,intercepted,interceptionFailure;
 try{
  await page.goto(new URL('/#administration?section=backup-settings',origin).href);
  const selection=page.getByLabel('Deployment',{exact:true});await enabled(selection,timeout);report.discovery_pages++;
  while(!await selection.locator('option').evaluateAll((options,id)=>options.some(option=>option.value===id),e.deployment_id)){
   const more=page.getByRole('button',{name:'Load more deployments',exact:true});assert.ok(await more.count(),'Expected deployment absent from authorized discovery');await enabled(more,timeout);await more.click();await enabled(selection,timeout);report.discovery_pages++;assert.ok(report.discovery_pages<=100,'Discovery exceeded bounded page count');
  }
  const readbackResponse=page.waitForResponse(response=>new URL(response.url()).pathname===commandPath.replace(/\/commands$/,'')&&response.request().method()==='GET'&&response.status()===200);
  await selection.selectOption(e.deployment_id);const readback=await (await readbackResponse).json();await page.locator('.backup-settings .observer-summary').waitFor();assertReadOnly();
  const {configuration,policy,authority,host_policy}=readback.revisions;const expectedRevisions={configuration,policy,authority,host_policy};
  if(e.action!=='read'){
   if(e.action==='publish'){
    for(const [key,label] of Object.entries(durations))await page.getByLabel(label,{exact:true}).fill(String(e.values[key]));
    for(const [key,label] of Object.entries(references))await page.getByLabel(label,{exact:true}).selectOption(e.values[key]);
   }else{
    await page.getByLabel('Historical revision',{exact:true}).fill(String(e.rollback_revision));await page.getByRole('button',{name:'Read historical revision',exact:true}).click();await page.getByRole('button',{name:'Roll back as new revision',exact:true}).waitFor();
   }
   await page.getByLabel('Reason for change',{exact:true}).fill(e.rationale);await page.getByLabel('Evidence reference (optional)',{exact:true}).fill(e.evidence_ref??'');
   if(e.lose_acknowledgement){
    let finish;intercepted=new Promise(resolve=>{finish=resolve;});
    interceptor=async route=>{try{const response=await route.fetch();if(![200,201].includes(response.status())){interceptionFailure='Real command returned '+response.status()+' before acknowledgement loss';await route.fulfill({response});}else{report.lost_acknowledgements++;await route.abort('failed');}}catch(error){interceptionFailure=error.message;await route.abort('failed').catch(()=>{});}finally{finish();}};
    await page.route(commandRoute,interceptor,{times:1});
   }
   const button=page.getByRole('button',{name:e.action==='publish'?'Save backup settings':'Roll back as new revision',exact:true});await enabled(button,timeout);await button.click();
   if(e.lose_acknowledgement){
    let timer;try{await Promise.race([intercepted,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('No forwarded command completed before timeout')),timeout);})]);}finally{clearTimeout(timer);}assert.equal(interceptionFailure,undefined);
    await page.getByText('Command outcome needs recovery',{exact:true}).waitFor();await page.reload();await page.getByText('Command outcome needs recovery',{exact:true}).waitFor();const recover=page.getByRole('button',{name:'Check command receipt',exact:true});await enabled(recover,timeout);await recover.click();
   }
   await page.getByText('Desired revision '+e.expect.desired_revision+' recorded. Host application is checked independently below.',{exact:true}).waitFor();
   assert.equal(report.commands.length,1,'Each browser write step must send exactly one original command');
   assert.equal(report.command_paths[0],commandPath);
   report.expected_command=assertCommand(report.commands[0],e,expectedRevisions);
   if(e.lose_acknowledgement){assert.equal(report.lost_acknowledgements,1);assert.equal(report.receipt_reads,1);}
  }
  const until=Date.now()+timeout;
  do{
   await page.locator('.backup-settings .observer-summary').waitFor();assertReadOnly();report.observed=await snapshot(page);
   if(statusKeys.every(key=>report.observed[key]===e.expect[key]))break;
   assert.ok(Date.now()<until,'Readback did not match expected independent states: '+JSON.stringify(report.observed));
   await page.waitForTimeout(500);const refresh=page.getByRole('button',{name:'Refresh backup state',exact:true});await enabled(refresh,timeout);await refresh.click();await enabled(refresh,timeout);
  }while(true);
  assert.deepEqual(report.observed,e.expect);
  await page.addScriptTag({path:fileURLToPath(new URL('../node_modules/axe-core/axe.min.js',import.meta.url))});
  for(const width of [1440,390,320]){
   await page.setViewportSize({width,height:1000});
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);if(overflow){report.overflow_elements=await page.evaluate(()=>[...document.querySelectorAll('body *')].filter(el=>el.getBoundingClientRect().right>innerWidth+1).map(el=>({tag:el.tagName,className:el.className,right:el.getBoundingClientRect().right})).slice(0,20));await page.screenshot({path:join(evidenceDirectory,e.id+'-overflow-'+width+'.png'),fullPage:true});}assert.equal(overflow,false,'Horizontal overflow at '+width+': '+JSON.stringify(report.overflow_elements??[]));
   const violations=await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations);
   assert.deepEqual(violations,[],'Accessibility violations at '+width);report.accessibility.push({width,overflow,violations});
   await page.screenshot({path:join(evidenceDirectory,e.id+'-'+width+'.png'),fullPage:true});
  }
  assertReadOnly();if(e.action!=='read')assert.equal(report.commands.length,1,'Each browser write step must send exactly one original command');report.passed=true;return report;
 }catch(error){report.failure=error.message;throw error;}
 finally{page.off('request',observe);if(interceptor)await page.unroute(commandRoute,interceptor);await writeFile(join(evidenceDirectory,e.id+'-browser.json'),JSON.stringify(report,null,2)+'\n');}
}
async function cli(){
 const arg=name=>{const index=process.argv.indexOf(name);assert.ok(index>=0&&process.argv[index+1],'Missing '+name);return process.argv[index+1];};
 const origin=arg('--origin'),evidenceDirectory=resolve(arg('--evidence')),expectations=JSON.parse(await readFile(arg('--expectations'),'utf8')),storageState=arg('--storage-state');
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.CHROMIUM_EXECUTABLE_PATH}:{})});
 try{const context=await browser.newContext({storageState,viewport:{width:1440,height:1000}});const page=await context.newPage();await runBackupBrowserStep({page,origin,expectations,evidenceDirectory});}
 finally{await browser.close();}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await cli();
