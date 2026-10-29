// Invoke the UI Builder's real-browser handoff from the maintained G7 journey.
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {runPreservationBrowserStep} from '../ui/tests/preservation-audit-browser.mjs';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error('missing_argument');return process.argv[i+1];}
const origin=arg('--origin'), state=arg('--storage-state'), reportPath=arg('--signed-report');
const metadataPath=arg('--source-metadata'), evidenceDirectory=resolve(arg('--evidence'));
const signed=JSON.parse(await readFile(reportPath,'utf8')).payload;
const sourceMetadata=JSON.parse(await readFile(metadataPath,'utf8'));
const scope=signed.scope_object;
if(sourceMetadata.schema_version!==1||!scope||signed.deployment_id!=='g7-local')throw new Error('independent_expectation_binding_invalid');
const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.CHROMIUM_EXECUTABLE_PATH}:{})});
try{
 const context=await browser.newContext({storageState:state,acceptDownloads:true,viewport:{width:1440,height:1000}});
 const page=await context.newPage();await page.goto(new URL('/#runs',origin).href);
 await mkdir(evidenceDirectory,{recursive:true,mode:0o700});
 const current=await page.evaluate(async query=>{const r=await fetch('/api/v1/operations/preservation?'+query,{credentials:'same-origin'});return {status:r.status,body:await r.json()};},new URLSearchParams(scope).toString());
 if(current.status!==200||current.body.snapshot_id!==signed.snapshot_id)throw new Error('signed_public_summary_binding_mismatch');
 await writeFile(resolve(evidenceDirectory,'public-summary-diagnostic.json'),JSON.stringify(current.body,null,2)+'\n',{mode:0o600});
 const recordsDiagnostic=await page.evaluate(async snapshot=>{const q=new URLSearchParams({snapshot_id:snapshot,class_id:'product.source_evidence',limit:'50'});const r=await fetch('/api/v1/operations/preservation/records?'+q,{credentials:'same-origin'});return {status:r.status,body:await r.json()};},signed.snapshot_id);
 await writeFile(resolve(evidenceDirectory,'public-records-diagnostic.json'),JSON.stringify(recordsDiagnostic,null,2)+'\n',{mode:0o600});
 const signedClasses=new Map(signed.classes.map(item=>[item.class_id,item]));
 const summary={...current.body,
   snapshot_id:signed.snapshot_id,checked_at:signed.checked_at,valid_until:signed.valid_until,
   environment:signed.environment,
   classes:current.body.classes.map(item=>signedClasses.get(item.class_id)?.dto??item),
   uncovered_classes:signed.classes.filter(item=>item.dto.state!=='verified').map(item=>item.class_id).sort()};
 const records={},evidence=[];
 for(const item of signed.classes){
  if(item.dto.expected_records===null)continue;
  const projected=item.members.map(member=>{
   const readback=member.record_kind==='evidence_registration'&&member.byte_bearing&&member.evidence_id
     ?'/api/v1/operations/preservation/evidence/'+member.evidence_id:null;
   if(readback&&member.actual_sha256){
    const size=sourceMetadata.byte_sizes[member.record_key];
    if(!Number.isSafeInteger(size)||size<0)throw new Error('independent_evidence_size_missing');
    evidence.push({class_id:item.class_id,record_key:member.record_key,status:200,
      sha256:member.actual_sha256,size});
   }
   return {record_key:member.record_key,record_kind:member.record_kind,retained_at:member.retained_at,
    state:member.state,reasons:member.reasons,expected_sha256:member.expected_sha256,
    actual_sha256:member.actual_sha256,record_sha256:member.record_sha256,readback_url:readback};
  });
  records[item.class_id]=projected;
 }
 // Authority fingerprints are response-local. The signed principal-neutral report
 // independently supplies every class fact, membership and expected record.
 const expectations={schema_version:1,id:'g7-local-preservation',synthetic_labels:true,
  scope,status:200,summary,records,evidence};
 const result=await runPreservationBrowserStep({page,origin,expectations,evidenceDirectory});
 console.log(JSON.stringify({passed:result.passed,summary_reads:result.summary_reads,
  record_pages:result.record_pages,evidence_reads:result.evidence_reads,write_requests:result.write_requests,
  accessibility:result.accessibility}));
 await context.close();
}finally{await browser.close();}
