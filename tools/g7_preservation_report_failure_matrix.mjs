import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {chromium} from '../ui/node_modules/playwright/index.mjs';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`);return process.argv[i+1];}
const origin=arg('--origin'),state=arg('--storage-state'),expectedPath=arg('--expect'),output=arg('--output');
const expected=JSON.parse(await readFile(expectedPath,'utf8'));
const scope={source_family:'local',source_account_id:'g7-local',scope_key:'all'};
const browser=await chromium.launch({headless:true});
try{
 const context=await browser.newContext({storageState:state});const page=await context.newPage();
 await page.goto(origin+'/#runs',{waitUntil:'domcontentloaded'});
 const getSummary=()=>page.evaluate(async scope=>{
  const response=await fetch('/api/v1/operations/preservation?'+new URLSearchParams(scope),{credentials:'same-origin'});
  const body=await response.json();return {status:response.status,body};
 },scope);
 const summary=await getSummary();assert.equal(summary.status,200);
 const classes=Object.fromEntries(summary.body.classes.map(item=>[item.class_id,item]));
 for(const [classId,stateValue] of Object.entries(expected.states))assert.equal(classes[classId]?.state,stateValue,`${classId} state`);
 for(const classId of expected.nullCountClasses??[]){
  assert.equal(classes[classId]?.expected_records,null,`${classId} count must be null`);
  if(classes[classId]?.audit_copy)for(const key of ['expected_events','matching_events','missing_events','changed_events',
      'unexpected_events','expected_receipts','matching_receipts','missing_receipts','changed_receipts',
      'unexpected_receipts','pending_receipts'])assert.equal(classes[classId].audit_copy[key],null,`audit_copy.${key} must be null`);
 }
 for(const [classId,count] of Object.entries(expected.counts??{}))assert.equal(classes[classId]?.expected_records,count,`${classId} count`);
 for(const [classId,reason] of Object.entries(expected.reasons??{}))assert.ok(classes[classId]?.reasons?.includes(reason),`${classId} reason ${reason}`);
 if(expected.auditCopy){const copy=classes['product.audit_history']?.audit_copy;assert.ok(copy);
  for(const [key,value] of Object.entries(expected.auditCopy))assert.equal(copy[key],value,`audit_copy.${key}`);}
 let recordResult=null;
 if(expected.recordClass){
  const response=await page.evaluate(async ({snapshot_id,class_id})=>{
   const url='/api/v1/operations/preservation/records?'+new URLSearchParams({snapshot_id,class_id,limit:'100'});
   const r=await fetch(url,{credentials:'same-origin'});return {status:r.status,body:await r.json()};
  },{snapshot_id:summary.body.snapshot_id,class_id:expected.recordClass});
  assert.equal(response.status,200);
    const items=[...response.body.items];
  if(expected.paginateAll){
   items.length=0;let cursor=null;let pages=0;
   do{
    const result=await page.evaluate(async ({snapshot_id,class_id,cursor})=>{
     const q=new URLSearchParams({snapshot_id,class_id,limit:'7'});if(cursor)q.set('cursor',cursor);
     const r=await fetch('/api/v1/operations/preservation/records?'+q,{credentials:'same-origin'});return {status:r.status,body:await r.json()};
    },{snapshot_id:summary.body.snapshot_id,class_id:expected.recordClass,cursor});
    assert.equal(result.status,200);items.push(...result.body.items);cursor=result.body.next_cursor;pages++;assert.ok(pages<1000);
   }while(cursor);
   assert.equal(items.length,classes[expected.recordClass].expected_records);
   assert.equal(new Set(items.map(x=>x.record_key)).size,items.length);assert.ok(pages>1);
   expected.observedRecordPages=pages;
  }
  if(expected.recordState){const item=items.find(row=>row.state===expected.recordState&&row.reasons.includes(expected.recordReason));assert.ok(item,'expected state/reason member missing');
   if(expected.recordDigestNull)assert.equal(item.record_sha256,null);
   if(expected.rawHashesEqual)assert.equal(item.expected_sha256,item.actual_sha256);
   if(expected.noByteChangedReason)assert.ok(!item.reasons.includes('bytes_changed'));
   if(expected.rawHashesDiffer)assert.notEqual(item.expected_sha256,item.actual_sha256);
   if(expected.recordKind)assert.equal(item.record_kind,expected.recordKind);
  }
  if(expected.allRecordsMissing){assert.ok(items.length>0);assert.ok(items.every(row=>row.state==='missing'&&row.record_sha256===null&&row.actual_sha256===null));}
  const expectedKinds=expected.allExpectedKindsMissing??{};
  for(const [kind,count] of Object.entries(expectedKinds)){
   const rows=items.filter(row=>row.record_kind===kind);assert.equal(rows.length,count,`${kind} expected count`);
   assert.ok(rows.every(row=>row.state==='missing'&&row.record_sha256===null),`${kind} rows should be missing`);
  }
  recordResult={status:response.status,item_count:items.length,state_counts:Object.fromEntries(
   [...new Set(items.map(row=>row.state))].map(name=>[name,items.filter(row=>row.state===name).length])),
   kind_state_counts:Object.fromEntries([...new Set(items.map(row=>row.record_kind))].map(kind=>[kind,
    Object.fromEntries([...new Set(items.filter(row=>row.record_kind===kind).map(row=>row.state))]
     .map(name=>[name,items.filter(row=>row.record_kind===kind&&row.state===name).length]))]))};
 }
 let renderedPending=null;
 if(expected.renderedPending){
  // Transparent GET-only fixture proxy: UI/scope discovery from the normal app,
  // preservation routes from the copied app. Responses are never substituted.
  const server=http.createServer((request,response)=>{
   if(request.method!=='GET'){response.writeHead(405);response.end();return;}
   const target=new URL(request.url,request.url.startsWith('/api/v1/operations/preservation')?origin:expected.uiOrigin);
   if(target.pathname==='/api/v1/operations/preservation/records')target.searchParams.set('limit','7');
   const forwarded=http.request(target,{method:'GET',headers:{...request.headers,host:target.host}},upstream=>{
    response.writeHead(upstream.statusCode,upstream.headers);upstream.pipe(response);
   });forwarded.on('error',()=>{response.writeHead(502);response.end();});forwarded.end();
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
   const args=['tools/g7_preservation_browser_handoff.mjs','--origin','http://127.0.0.1:'+server.address().port,
    '--storage-state',state,'--signed-report',expected.reportPath,'--source-metadata',expected.metadataPath,'--evidence',expected.browserEvidence];
   renderedPending=await new Promise((resolve,reject)=>{const process=spawn('node',args,{cwd:new URL('..',import.meta.url).pathname,env:globalThis.process.env});let stdout='',stderr='';process.stdout.on('data',x=>stdout+=x);process.stderr.on('data',x=>stderr+=x);process.on('close',code=>code===0?resolve(JSON.parse(stdout)):reject(new Error('pending_rendered_browse_failed: '+stderr)));});
  }finally{await new Promise(resolve=>server.close(resolve));}
 }
 let cursorBound=false;
 if(expected.cursorBinding){
  const first=await page.evaluate(async ({snapshot_id,class_id})=>{
   const url='/api/v1/operations/preservation/records?'+new URLSearchParams({snapshot_id,class_id,limit:'1'});
   const r=await fetch(url,{credentials:'same-origin'});return {status:r.status,body:await r.json()};
  },{snapshot_id:summary.body.snapshot_id,class_id:expected.cursorBinding.sourceClass});
  assert.equal(first.status,200);assert.equal(typeof first.body.next_cursor,'string');
  const rejected=await page.evaluate(async ({snapshot_id,class_id,cursor})=>{
   const url='/api/v1/operations/preservation/records?'+new URLSearchParams({snapshot_id,class_id,limit:'1',cursor});
   const r=await fetch(url,{credentials:'same-origin'});return {status:r.status,body:await r.json()};
  },{snapshot_id:summary.body.snapshot_id,class_id:expected.cursorBinding.otherClass,cursor:first.body.next_cursor});
  assert.equal(rejected.status,400);
  assert.equal(rejected.body.error?.code??rejected.body.detail?.code,'invalid_cursor');cursorBound=true;
 }
 const result={schema_version:1,case:expected.case,summary_status:summary.status,
  snapshot_id:summary.body.snapshot_id,class_states:Object.fromEntries(Object.entries(classes).map(([k,v])=>[k,v.state])),
  class_counts:Object.fromEntries(Object.entries(classes).map(([k,v])=>[k,v.expected_records])),
  audit_copy:classes['product.audit_history']?.audit_copy??null,
  class_reasons:Object.fromEntries(Object.entries(classes).map(([k,v])=>[k,v.reasons])),
  record_readback:recordResult,record_pages:expected.observedRecordPages??null,rendered_pending:renderedPending,cursor_binding_rejected:cursorBound};
 await writeFile(output,JSON.stringify(result,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify(result));
}finally{await browser.close();}
