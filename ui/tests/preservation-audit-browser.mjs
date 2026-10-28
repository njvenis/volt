// Maintained handoff: consumes real responses, never mocks or mutates product APIs.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';
const classes=['product.source_evidence','product.audit_history','operational.scanner_collection'];
const labels=['Source evidence','Audit history','Scanner collection history'];
const endpoint='/api/v1/operations/preservation';
const query=s=>new URLSearchParams(s).toString();
const withoutResponseTime=s=>{const result=structuredClone(s);delete result.response_at;return result;};
function check(value,message){if(!value)throw new Error(message);}
function equal(actual,expected,message){try{assert.deepEqual(actual,expected);}catch{throw new Error(message);}}
export function validateExpectations(e){
 check(e?.schema_version===1&&/^[a-zA-Z0-9_-]+$/.test(e.id),'invalid_expectations');
 check(e.synthetic_labels===true,'synthetic_labels_required_for_screenshots');
 check(e.scope&&Object.keys(e.scope).sort().join(',')==='scope_key,source_account_id,source_family'&&Object.values(e.scope).every(v=>typeof v==='string'&&v&&v!=='*'),'invalid_scope');
 check([200,404,503].includes(e.status),'invalid_expected_status');
 check(Number.isInteger(e.timeout_ms??30000)&&(e.timeout_ms??30000)>=1000&&(e.timeout_ms??30000)<=180000,'invalid_timeout');
 if(e.status===200){check(e.summary?.schema_version===1&&Array.isArray(e.summary.classes)&&e.summary.classes.length===3,'expected_summary_required');equal(e.summary.scope,e.scope,'expected_scope_mismatch');check(e.records&&typeof e.records==='object','expected_records_required');for(const c of e.summary.classes){check(classes.includes(c.class_id),'invalid_class');if(c.expected_records!==null)check(Array.isArray(e.records[c.class_id]),'exact_record_inventory_required');else check(e.records[c.class_id]===undefined,'masked_or_unknown_records_forbidden');}}
 else check(typeof e.error_code==='string','expected_error_code_required');
 check(Array.isArray(e.evidence??[]),'invalid_evidence_expectations');
}
async function ready(locator){await locator.waitFor();await locator.evaluate(el=>new Promise((resolve,reject)=>{const start=Date.now();const check=()=>{if(!el.disabled)return resolve();if(Date.now()-start>30000)return reject(new Error('control_unavailable'));setTimeout(check,25);};check();}));}
export async function runPreservationBrowserStep({page,origin,expectations:e,evidenceDirectory}){
 validateExpectations(e);await mkdir(evidenceDirectory,{recursive:true,mode:0o700});page.setDefaultTimeout(e.timeout_ms??30000);
 const report={schema_version:1,id:e.id,environment:'Synthetic labels; caller-owned authenticated endpoint. Browser proof only.',read_requests:0,write_requests:0,summary_reads:0,record_pages:0,evidence_reads:0,accessibility:[],passed:false,phase:'navigation'};
 let write=false;const observe=request=>{if(!['GET','HEAD','OPTIONS'].includes(request.method())){write=true;report.write_requests++;}else report.read_requests++;};
 const context=page.context();context.on('request',observe);const readonly=()=>check(!write,'unexpected_write_request');
 const waitSummary=()=>page.waitForResponse(r=>new URL(r.url()).pathname===endpoint&&r.request().method()==='GET');
 const checkSummary=async response=>{report.summary_reads++;equal(response.status(),e.status,'summary_status_mismatch');const url=new URL(response.url());equal(Object.fromEntries(url.searchParams),e.scope,'request_scope_mismatch');const body=await response.json();if(e.status===200)equal(withoutResponseTime(body),withoutResponseTime(e.summary),'summary_content_mismatch');else equal(body.detail?.code??body.error?.code,e.error_code,'error_code_mismatch');readonly();};
 try{
  // Enter through rendered Integrations navigation, after authentication was supplied by caller.
  await page.goto(new URL('/#runs',origin).href);
  await page.getByRole('navigation',{name:'Integration views'}).getByRole('link',{name:'Data preservation',exact:true}).click();
  report.phase='selection';const selection=page.getByLabel('Source scope',{exact:true});await ready(selection);
  const selected=JSON.stringify([e.scope.source_family,e.scope.source_account_id,e.scope.scope_key]);
  report.phase='summary';const initial=waitSummary();await selection.selectOption(selected);await checkSummary(await initial);
  const refresh=page.getByRole('button',{name:'Refresh preservation report',exact:true});await ready(refresh);
  const refreshed=waitSummary();await refresh.click();await checkSummary(await refreshed);await ready(refresh);equal(await selection.inputValue(),selected,'refresh_changed_scope');
  if(e.status!==200){await page.getByRole('alert').filter({hasText:e.status===404?'Unavailable or not permitted':'Read unavailable'}).waitFor();check(await page.locator('[data-class]').count()===0,'denied_counts_disclosed');}
  else{
   await page.locator('[data-snapshot-id]').waitFor();equal(await page.locator('[data-snapshot-id]').innerText(),e.summary.snapshot_id??'Not established','rendered_snapshot_mismatch');
   const checkedTime=page.locator('[data-checked-at] time');if(e.summary.checked_at===null)equal(await checkedTime.count(),0,'rendered_check_time_mismatch');else equal(await checkedTime.getAttribute('datetime'),e.summary.checked_at,'rendered_check_time_mismatch');
   for(const c of e.summary.classes){const card=page.locator('[data-class="'+c.class_id+'"]');equal((await card.locator('.preservation-state').innerText()).replace(/^[^a-z]+/i,'').trim().toLowerCase(),c.state,'rendered_class_state_mismatch');for(const k of ['expected_records','verified_records','missing_records','changed_records','unreadable_records','unexpected_records'])equal(await card.locator('[data-count="'+k+'"]').innerText(),c[k]===null?'Not established':String(c[k]),'rendered_class_count_mismatch');}
   await page.getByText('Elapsed preservation: unverified',{exact:true}).waitFor();await page.getByRole('region',{name:'Coverage limits'}).waitFor();
   equal(await page.locator('[data-uncovered]').innerText(),'Uncovered classes: '+(e.summary.uncovered_classes.length?e.summary.uncovered_classes.map(id=>labels[classes.indexOf(id)]).join(', '):'None in this signed observation')+'.','rendered_uncovered_mismatch');
   const audit=e.summary.classes.find(c=>c.class_id===classes[1]);equal((await page.locator('.preservation-copy .preservation-state').innerText()).replace(/^[^a-z]+/i,'').trim().toLowerCase(),audit.audit_copy.state,'rendered_copy_state_mismatch');
   if(audit.reasons.includes('audit_scope_incomplete')){equal(await page.locator('[data-copy-count]').count(),0,'masked_copy_counts_disclosed');await page.getByText('Audit counts, timestamps and provenance are withheld', {exact:false}).waitFor();}
   else for(const [key,value] of Object.entries(audit.audit_copy).filter(([k])=>!['state','reasons','checked_at'].includes(k)))equal(await page.locator('[data-copy-count="'+key+'"]').innerText(),value===null?'Not established':String(value),'rendered_copy_count_mismatch');
   for(const classId of classes.filter(id=>Object.hasOwn(e.records,id))){
    const expected=e.records[classId],observed=[];let pages=0;
    const waitPage=()=>page.waitForResponse(r=>new URL(r.url()).pathname===endpoint+'/records');
    let responsePromise=waitPage();await page.getByRole('button',{name:'Browse '+labels[classes.indexOf(classId)].toLowerCase(),exact:true}).click();
    while(true){const response=await responsePromise;equal(response.status(),200,'record_status_mismatch');const body=await response.json();equal(body.snapshot_id,e.summary.snapshot_id,'record_snapshot_mismatch');equal(body.class_id,classId,'record_class_mismatch');check(Array.isArray(body.items),'invalid_record_page');report.record_pages++;pages++;check(pages<=1000,'record_page_limit');observed.push(...body.items);
     await page.getByRole('button',{name:'Next records page',exact:true}).waitFor();
     const keys=body.items.map(x=>x.record_key);await page.waitForFunction(keys=>JSON.stringify([...document.querySelectorAll('[data-record-key]')].map(el=>el.getAttribute('data-record-key')))===JSON.stringify(keys),keys);
     for(const item of body.items){const row=page.locator('[data-record-key]').filter({has:page.locator('code',{hasText:item.record_key})});equal((await row.locator('.preservation-state').innerText()).replace(/^[^a-z]+/i,'').trim().toLowerCase(),item.state,'rendered_record_state_mismatch');const download=row.getByRole('button',{name:'Download evidence for '+item.record_key,exact:true});equal(await download.count(),item.readback_url?1:0,'evidence_permission_mismatch');
      const expectedItem=expected.find(record=>record.record_key===item.record_key);equal(item,expectedItem,'record_inventory_content_mismatch');
      const detail=row.locator('details');await detail.getByText('Digest provenance',{exact:true}).click();check(await detail.getAttribute('open')!==null,'digest_provenance_not_open');
      const renderedDigests=await detail.locator('dl > div').evaluateAll(nodes=>nodes.map(node=>({label:node.querySelector('dt')?.innerText,value:node.querySelector('dd')?.innerText})));
      equal(renderedDigests,[['Expected raw bytes','expected_sha256'],['Observed raw bytes','actual_sha256'],['Canonical record','record_sha256']].map(([label,key])=>({label,value:expectedItem[key]??'Not established / not applicable'})),'rendered_digest_provenance_mismatch');
      const evidence=(e.evidence??[]).find(x=>x.class_id===classId&&x.record_key===item.record_key);if(evidence){check(!!item.readback_url,'expected_evidence_link_missing');const result=page.waitForResponse(r=>new URL(r.url()).pathname===item.readback_url);const downloaded=evidence.status===200?page.waitForEvent('download'):null;await download.click();const res=await result;report.evidence_reads++;equal(res.status(),evidence.status,'evidence_status_mismatch');if(downloaded){const file=await downloaded,stream=await file.createReadStream();const hash=createHash('sha256');let size=0;for await(const chunk of stream){hash.update(chunk);size+=chunk.length;}equal(size,evidence.size,'evidence_size_mismatch');equal(hash.digest('hex'),evidence.sha256.replace(/^sha256:/,''),'evidence_digest_mismatch');await file.delete();}else await page.locator('.preservation-records [role=alert]').waitFor();}
     }
     readonly();if(!body.next_cursor)break;responsePromise=waitPage();await page.getByRole('button',{name:'Next records page',exact:true}).click();
    }
    equal(observed,expected,'record_inventory_content_mismatch');
   }
  }
  equal(report.evidence_reads,(e.evidence??[]).length,'evidence_expectations_not_exercised');
  // Keyboard interaction and focus are checked independently of mouse navigation.
  await selection.focus();await page.keyboard.press('Tab');equal(await refresh.evaluate(el=>document.activeElement===el),true,'keyboard_focus_missing');
  const focus=await refresh.evaluate(el=>getComputedStyle(el).outlineStyle);check(focus!=='none','focus_indicator_missing');
  await page.addScriptTag({path:fileURLToPath(new URL('../node_modules/axe-core/axe.min.js',import.meta.url))});
  for(const width of [1440,390,320]){await page.setViewportSize({width,height:1000});check(!await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),'horizontal_overflow_'+width);const violations=await page.evaluate(async()=> (await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}})).violations.map(v=>({id:v.id,impact:v.impact})));equal(violations,[],'axe_violations_'+width);report.accessibility.push({width,violations});await page.screenshot({path:join(evidenceDirectory,e.id+'-'+width+'.png'),fullPage:true});}
  readonly();report.passed=true;return report;
 }catch(error){await page.screenshot({path:join(evidenceDirectory,e.id+'-failure.png'),fullPage:true}).catch(()=>{});report.failure=error instanceof Error&&/^[a-z0-9_]+$/.test(error.message)?error.message:'browser_assertion_failed';throw new Error(report.failure);}
 finally{context.off('request',observe);await writeFile(join(evidenceDirectory,e.id+'-browser.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});}
}
async function cli(){const arg=name=>{const index=process.argv.indexOf(name);check(index>=0&&process.argv[index+1],'missing_cli_argument');return process.argv[index+1];};
 const origin=arg('--origin'),storageState=arg('--storage-state'),expectations=JSON.parse(await readFile(arg('--expectations'),'utf8')),evidenceDirectory=resolve(arg('--evidence'));
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.CHROMIUM_EXECUTABLE_PATH}:{})});
 try{const context=await browser.newContext({storageState,acceptDownloads:true,viewport:{width:1440,height:1000}});await runPreservationBrowserStep({page:await context.newPage(),origin,expectations,evidenceDirectory});}finally{await browser.close();}}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))cli().catch(()=>{process.stderr.write('Preservation browser verification failed; see bounded browser evidence.\n');process.exitCode=1;});
