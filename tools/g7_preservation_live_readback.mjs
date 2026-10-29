import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {readFile,writeFile} from 'node:fs/promises';
import process from 'node:process';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`);return process.argv[i+1];}
const origin=arg('--origin'),state=arg('--storage-state'),output=arg('--output');
const scope={source_family:'local',source_account_id:'g7-local',scope_key:'all'};
const query=new URLSearchParams(scope).toString();
const browser=await chromium.launch({headless:true});
try{
 const context=await browser.newContext({storageState:state});const page=await context.newPage();
 let writeObserved=false;context.on('request',request=>{if(!['GET','HEAD','OPTIONS'].includes(request.method()))writeObserved=true;});
 await page.goto(origin+'/#runs',{waitUntil:'domcontentloaded'});
 const summary=await page.evaluate(async query=>{
  const response=await fetch('/api/v1/operations/preservation?'+query,{credentials:'same-origin'});
  const body=await response.json();return {status:response.status,body,
    correlation_id:response.headers.get('x-correlation-id'),
    request_id:response.headers.get('x-request-id')};
 },query);
 await writeFile(output+'.summary-response.json',JSON.stringify(summary,null,2)+'\n',{mode:0o600});
 if(summary.status!==200)throw new Error('public_summary_not_authorized');
 if(summary.body.scope?.source_family!==scope.source_family
    ||summary.body.scope?.source_account_id!==scope.source_account_id
    ||summary.body.scope?.scope_key!==scope.scope_key)throw new Error('public_summary_scope_mismatch');
 const classes=Object.fromEntries(summary.body.classes.map(item=>[item.class_id,item]));
 if(classes['product.source_evidence']?.state!=='verified'
   ||classes['operational.scanner_collection']?.state!=='verified')throw new Error('public_source_readcheck_not_verified');
 const firstPage=await page.evaluate(async snapshot_id=>{
  const r=await fetch('/api/v1/operations/preservation/records?'+new URLSearchParams({snapshot_id,class_id:'product.source_evidence',limit:'1'}),{credentials:'same-origin'});
  return {status:r.status,body:await r.json()};
 },summary.body.snapshot_id);
 if(firstPage.status!==200||typeof firstPage.body.next_cursor!=='string')throw new Error('source_cursor_not_captured');
 const cursorProbe={snapshot_id:summary.body.snapshot_id,class_id:'product.source_evidence',limit:1,cursor:firstPage.body.next_cursor};
 let previousSnapshotProbe=null;
 const previousAt=process.argv.indexOf('--previous-readback');
 if(previousAt>=0){
  const previous=JSON.parse(await readFile(process.argv[previousAt+1],'utf8'));
  if(!previous.cursor_probe?.cursor)throw new Error('previous_cursor_missing');
  const fetchRecords=parameters=>page.evaluate(async parameters=>{
   const r=await fetch('/api/v1/operations/preservation/records?'+new URLSearchParams(parameters),{credentials:'same-origin'});
   const body=await r.json();return {status:r.status,code:body.error?.code??body.detail?.code??null};
  },parameters);
  const base={snapshot_id:previous.snapshot_id,class_id:'product.source_evidence',limit:'1'};
  const oldSnapshot=await fetchRecords(base);
  const oldCursor=await fetchRecords({...base,cursor:previous.cursor_probe.cursor});
  const splicedCursor=await fetchRecords({...base,snapshot_id:summary.body.snapshot_id,cursor:previous.cursor_probe.cursor});
  if(oldSnapshot.status!==409||oldSnapshot.code!=='snapshot_expired'||oldCursor.status!==409||oldCursor.code!=='snapshot_expired'
      ||splicedCursor.status!==400||splicedCursor.code!=='invalid_cursor')throw new Error('replacement_snapshot_cursor_binding_failed:'+JSON.stringify({oldSnapshot,oldCursor,splicedCursor}));
  previousSnapshotProbe={old_snapshot:oldSnapshot,old_cursor:oldCursor,spliced_cursor:splicedCursor};
 }
 const audit=classes['product.audit_history'];
 if(audit?.state!=='verified'||audit.audit_copy?.state!=='verified'
    ||audit.audit_copy?.expected_events!==audit.audit_copy?.matching_events
    ||audit.audit_copy?.expected_receipts!==audit.audit_copy?.matching_receipts
    ||audit.audit_copy?.pending_receipts!==0)throw new Error('deployment_audit_union_not_verified');
 let recordPages=0,evidence=null;const publicRecordPages=[];
 for(const classId of ['product.source_evidence','product.audit_history','operational.scanner_collection']){
  const response=await page.evaluate(async ({summaryId,classId})=>{
   const url='/api/v1/operations/preservation/records?'+new URLSearchParams({snapshot_id:summaryId,class_id:classId,limit:'100'});
   const value=await fetch(url,{credentials:'same-origin'});return {status:value.status,body:await value.json(),
     correlation_id:value.headers.get('x-correlation-id'),request_id:value.headers.get('x-request-id')};
  },{summaryId:summary.body.snapshot_id,classId});
  if(response.status!==200||response.body.snapshot_id!==summary.body.snapshot_id)throw new Error('public_record_readback_failed');
  publicRecordPages.push({status:response.status,class_id:response.body.class_id,
    correlation_id:response.correlation_id,request_id:response.request_id,body:response.body});
  recordPages++;
  if(classId==='product.source_evidence'){
   const item=response.body.items.find(value=>value.readback_url);
   if(!item)throw new Error('source_evidence_link_missing');
   evidence=await page.evaluate(async url=>{
    const response=await fetch(url,{credentials:'same-origin'});const bytes=await response.arrayBuffer();
    const digest=await crypto.subtle.digest('SHA-256',bytes);
    const hex=[...new Uint8Array(digest)].map(v=>v.toString(16).padStart(2,'0')).join('');
    return {status:response.status,size:bytes.byteLength,sha256:hex,
      content_digest:response.headers.get('content-digest')};
   },item.readback_url);
   const expectedHeader='sha-256=:'+btoa(String.fromCharCode(...Buffer.from(item.actual_sha256,'hex')))+':';
   if(evidence.status!==200||evidence.size!==550||evidence.sha256!==item.actual_sha256
      ||evidence.content_digest!==expectedHeader)throw new Error('public_evidence_bytes_unverified');
  }
 }
 const denied=await page.evaluate(async()=>{
  const url='/api/v1/operations/preservation?'+new URLSearchParams({source_family:'local',source_account_id:'g7-local',scope_key:'denied'});
  return (await fetch(url,{credentials:'same-origin'})).status;
 });
 if(denied!==404)throw new Error('unauthorised_scope_not_masked');
 const report={schema_version:1,scope,summary_status:summary.status,
  snapshot_id:summary.body.snapshot_id,checked_at:summary.body.checked_at,cursor_probe:cursorProbe,previous_snapshot_probe:previousSnapshotProbe,
  class_states:Object.fromEntries(Object.entries(classes).map(([key,value])=>[key,value.state])),
  class_counts:Object.fromEntries(Object.entries(classes).map(([key,value])=>[key,value.expected_records])),
  audit_copy:{state:audit.audit_copy.state,expected_events:audit.audit_copy.expected_events,
   matching_events:audit.audit_copy.matching_events,missing_events:audit.audit_copy.missing_events,
   changed_events:audit.audit_copy.changed_events,expected_receipts:audit.audit_copy.expected_receipts,
   matching_receipts:audit.audit_copy.matching_receipts,missing_receipts:audit.audit_copy.missing_receipts,
   changed_receipts:audit.audit_copy.changed_receipts,pending_receipts:audit.audit_copy.pending_receipts},
  record_pages:evidence?recordPages:recordPages,evidence,denied_scope_status:denied,
  write_methods_observed:writeObserved,public_summary:summary.body,
  summary_response_context:{status:summary.status,correlation_id:summary.correlation_id,
    request_id:summary.request_id,error_code:summary.body?.detail?.code??summary.body?.error?.code??null},
  public_record_pages:publicRecordPages};
 if(writeObserved)throw new Error('public_readback_performed_write');
 await writeFile(output,JSON.stringify(report,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({summary_status:report.summary_status,class_states:report.class_states,
  class_counts:report.class_counts,record_pages:recordPages,evidence_verified:!!evidence,denied_scope_status:denied}));
}finally{await browser.close();}
