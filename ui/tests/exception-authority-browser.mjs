// Synthetic rendered-form proof. Every request is intercepted; no real API or provider.
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {chromium} from 'playwright';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fixture} from './exception-authority-fixtures.mjs';
const evidence=resolve(process.env.G7_UI_EVIDENCE_DIR??'/tmp/volt-exception-authority-ui');
await mkdir(evidence,{recursive:true});
const built=await build({stdin:{contents:`
import React,{useState,useEffect} from 'react';import {createRoot} from 'react-dom/client';
import AssessmentCommand from './AssessmentCommand';import {getGroup} from './assessment-api';
function Fixture(){const [view,setView]=useState(),[open,setOpen]=useState(false),[error,setError]=useState('');
 async function refresh(){setView(await getGroup(window.fixture.view.group.group_id,''));}
 useEffect(()=>{refresh().catch(e=>setError(e.message));},[]);
 return <main><h1>Synthetic exception authority proof</h1>{error&&<p role="alert">{error}</p>}<button disabled={!view} onClick={()=>setOpen(true)}>Open exception form</button>{view&&open&&<AssessmentCommand context={{action:window.action,exception:true,...(window.action==='acceptance.approve'?{acceptance:window.fixture.acceptance}:{})}} view={view} directory={view.assessment.owners} token="" actorId="synthetic-approver" onClose={()=>setOpen(false)} onRefresh={refresh} onCommitted={r=>window.receipt=r} onQueue={()=>{throw Error('Unexpected queue');}} onUnknown={()=>{}}/>}</main>;
}createRoot(document.getElementById('root')).render(<Fixture/>);`,resolveDir:resolve(import.meta.dirname,'../src'),loader:'tsx'},bundle:true,write:false,format:'iife',platform:'browser',jsx:'automatic',logLevel:'silent'});
const css=(await Promise.all(['tokens.css','styles.css','assessment.css','exception-warnings.css'].map(name=>readFile(new URL('../src/'+name,import.meta.url),'utf8')))).join('\n');
const axe=await readFile(new URL('../node_modules/axe-core/axe.min.js',import.meta.url),'utf8');
const browser=await chromium.launch({headless:true});
const results=[];
try{
 for(const action of ['acceptance.submit','acceptance.approve']){
  const f=fixture(),context=await browser.newContext({viewport:{width:1280,height:800}}),page=await context.newPage();page.setDefaultTimeout(10000);page.on('pageerror',error=>console.error('BROWSER',error.message));
  let current=structuredClone(f.view),conflict=true;const commands=[],requests=[];
  await page.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url());requests.push({method:req.method(),path:url.pathname});
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:`<!doctype html><html lang="en"><head><title>Synthetic exception authority</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>${css}</style></head><body><div id="root"></div><script>window.fixture=${JSON.stringify(f)};window.action=${JSON.stringify(action)};</script><script>${built.outputFiles[0].text}</script></body></html>`});
   if(url.pathname==='/api/v1/assessment/groups/'+f.view.group.group_id)return route.fulfill({json:current});
   if(url.pathname==='/api/v1/reports/sla-policies')return route.fulfill({json:f.catalogue});
   if(url.pathname==='/api/v1/assessment/commands'){
    const command=req.postDataJSON();commands.push(command);
    if(conflict)return route.fulfill({status:409,json:{detail:{code:'revision_conflict',message:'Exception authority revision changed'}}});
    return route.fulfill({json:{schema_version:1,command_id:command.command_id,decision_id:'33333333-3333-4333-8333-333333333333',audit_event_id:'44444444-4444-4444-8444-444444444444',committed_revision:command.expected_revisions.target+1,intent_id:'55555555-5555-4555-8555-555555555555',projection:'pending'}});
   }
   throw Error('Unexpected request '+req.url());
  });
  await page.goto('https://exception.fixture.invalid/');
  await page.getByRole('button',{name:'Open exception form'}).click();
  const dialog=page.getByRole('dialog'),ack=dialog.getByRole('checkbox',{name:/I have reviewed/}),save=dialog.getByRole('button',{name:'Save decision',exact:true});
  async function selectMembership(){if(action==='acceptance.submit')for(const id of f.ids)await dialog.getByRole('checkbox',{name:id,exact:true}).check();}
  await selectMembership();
  if(action==='acceptance.submit'){
   await dialog.getByLabel('Accountable owner',{exact:true}).selectOption(f.view.assessment.owners[0].owner_id);
   await dialog.getByLabel('Resource context',{exact:true}).fill('Synthetic service context');
   await dialog.getByLabel('Compensating controls',{exact:true}).fill('Synthetic restricted access');
   await dialog.getByLabel('Proposed expiry (UTC)',{exact:true}).fill('2026-11-01T12:00');
  }else await dialog.getByLabel('Approved expiry (UTC)',{exact:true}).fill('2026-11-01T12:00');
  await dialog.getByLabel('Reason',{exact:true}).fill('Keep this rationale after conflict');
  await ack.check();
  await save.focus();await page.keyboard.press('Enter');
  await dialog.getByText('Please review again',{exact:true}).waitFor();
  assert.equal(commands.length,1);assert.equal(commands[0].expected_revisions.authority,7);
  assert.equal(await ack.isChecked(),false);assert.equal(await save.isEnabled(),false);
  assert.equal(await dialog.getByLabel('Reason',{exact:true}).inputValue(),'Keep this rationale after conflict');
  current.assessment.authority_revision=8;conflict=false;
  await dialog.getByRole('button',{name:'Refresh instance list',exact:true}).click();
  await dialog.getByText('Review the updated instances',{exact:true}).waitFor();
  await selectMembership();await ack.check();
  // Existing modal keyboard trap and return-focus behavior remain intact.
  await dialog.getByRole('button',{name:/Close .*exception/}).focus();await page.keyboard.press('Shift+Tab');
  assert.equal(await save.evaluate(el=>el===document.activeElement),true);
  await page.keyboard.press('Tab');assert.equal(await dialog.getByRole('button',{name:/Close .*exception/}).evaluate(el=>el===document.activeElement),true);
  await page.addScriptTag({content:axe});
  const accessibility=await page.evaluate(async()=>await axe.run(document.querySelector('dialog'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}}));
  await writeFile(join(evidence,action+'-axe.json'),JSON.stringify(accessibility,null,2));
  assert.deepEqual(accessibility.violations.map(v=>({id:v.id,impact:v.impact})),[]);
  await page.screenshot({path:join(evidence,action+'-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  const reflow=await dialog.evaluate(el=>({width:el.clientWidth,scroll:el.scrollWidth,body:document.documentElement.scrollWidth,viewport:innerWidth}));
  assert.ok(reflow.scroll<=reflow.width+1,JSON.stringify(reflow));assert.ok(reflow.body<=reflow.viewport+1,JSON.stringify(reflow));
  await page.screenshot({path:join(evidence,action+'-narrow.png'),fullPage:true});
  await save.focus();await page.keyboard.press('Enter');
  await dialog.getByRole('region',{name:'Saved decision'}).waitFor();
  assert.equal(commands.length,2);const command=commands[1];
  assert.equal(command.expected_revisions.authority,8);assert.notEqual(command.command_id,commands[0].command_id);
  assert.deepEqual(command.membership_ids,f.ids);
  assert.deepEqual(command.expected_exposures,f.catalogue.current_heads.episodes.map(({exposure_id,episode_id,state_revision})=>({exposure_id,episode_id,state_revision})));
  assert.deepEqual(command.expected_evaluations,f.catalogue.current_heads.evaluations.map(({episode_id,occurrence_id,evaluation_id,revision})=>({episode_id,occurrence_id,evaluation_id,revision})));
  assert.equal(command.payload.rationale,'Keep this rationale after conflict');
  if(action==='acceptance.approve')assert.equal(command.payload.expected_request_revision,1);
  const receipt=await page.evaluate(()=>window.receipt);assert.equal(receipt.command_id,command.command_id);
  await page.keyboard.press('Escape');await dialog.waitFor({state:'hidden'});
  assert.equal(await page.getByRole('button',{name:'Open exception form'}).evaluate(el=>el===document.activeElement),true);
  // A historical DTO may render, but never enables an unguarded G7 command.
  delete current.assessment.authority_revision;
  await page.reload();await page.getByRole('button',{name:'Open exception form'}).click();
  await dialog.getByText('Current access rules unavailable',{exact:true}).waitFor();
  assert.equal(await save.isEnabled(),false);assert.equal(commands.length,2);
  current.assessment.authority_revision=9;
  await dialog.getByRole('button',{name:'Refresh access rules',exact:true}).click();
  await dialog.getByText('Current access rules unavailable',{exact:true}).waitFor({state:'hidden'});
  assert.equal(await ack.isChecked(),false);
  assert.equal(requests.some(r=>r.path.includes('administration')),false);
  await writeFile(join(evidence,action+'-wire.json'),JSON.stringify({environment:'synthetic intercepted browser requests',commands,requests,receipt,reflow},null,2));
  results.push({action,conflictRefresh:'passed',missingAuthority:'blocked until refresh',keyboard:'passed',reflow,axeViolations:0});
  console.log('PASS synthetic rendered '+action+': authority, conflict/refresh, guards, receipt, missing revision, keyboard, axe and reflow');
  await context.close();
 }
 await writeFile(join(evidence,'result.json'),JSON.stringify({environment:'synthetic browser only; no real API, Docker or provider',results},null,2));
}finally{await browser.close();console.log('CLEANUP synthetic browser closed; no services started');}
