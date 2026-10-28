import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createRequire} from 'node:module';
import {fixture,masked,unknown,scope,snapshot,digest,canonical,page,classIds,countFields} from './preservation-fixtures.mjs';
const dir=await mkdtemp(join(tmpdir(),'volt-preservation-contract-'));
await build({entryPoints:[resolve(import.meta.dirname,'../src/preservation-api.ts')],bundle:true,platform:'node',format:'cjs',outfile:join(dir,'parser.cjs'),logLevel:'silent'});
const api=createRequire(import.meta.url)(join(dir,'parser.cjs'));after(()=>rm(dir,{recursive:true,force:true}));
test('signed observation and response times remain distinct with exact three classes',()=>{const s=fixture();assert.deepEqual(api.parseSummary(s,scope),s);assert.notEqual(s.checked_at,s.response_at);});
test('masking withholds every audit count and baseline while retaining other classes',()=>{const s=masked();assert.deepEqual(api.parseSummary(s,scope),s);});
test('absent report is unknown rather than empty or a new check',()=>{const s=unknown();assert.deepEqual(api.parseSummary(s,scope),s);});
test('candidates include every exact session and group tuple regardless of action grants',()=>{assert.deepEqual(api.sessionCandidates({source_scopes:[Object.values(scope)],authority:{group_scopes:{a:[['s','a','other']],b:[Object.values(scope)]},actions:[]}}),[scope,{source_family:'s',source_account_id:'a',scope_key:'other'}]);});
for(const [name,mutate] of [
 ['impossible calendar time',s=>s.response_at='2026-02-31T00:00:00Z'],['incomplete baseline with gap counts',s=>{s.classes[0].state='gap';s.classes[0].verified_records=1;s.classes[0].missing_records=1;s.classes[0].reasons=['baseline_incomplete'];s.uncovered_classes=[classIds[0]];}],['masked existence reason',s=>{Object.assign(s,masked());s.classes[1].audit_copy.reasons=['record_missing'];}],['wrong scope',s=>s.scope.scope_key='different'],['boolean schema',s=>s.schema_version=true],['extra DTO field',s=>s.private_path='/private'],['duplicate class',s=>s.classes[2]=structuredClone(s.classes[0])],['wrong period',s=>s.classes[0].minimum_period='P3M'],['negative counts',s=>s.classes[0].missing_records=-1],['partial counts',s=>s.classes[0].verified_records=null],['invented verified count',s=>s.classes[0].verified_records=3],['zero substituted for null',s=>{Object.assign(s,unknown());s.classes[0].verified_records=0;}],['gap labelled verified',s=>{s.classes[0].verified_records=1;s.classes[0].missing_records=1;}],['failed with complete counts',s=>s.classes[0].state='failed'],['wrong uncovered list',s=>s.uncovered_classes=[classIds[0]]],['raw private reason',s=>s.classes[0].reasons=['private exception']],['copy count partition',s=>s.classes[1].audit_copy.matching_receipts=0],['pending copy labelled verified',s=>s.classes[1].audit_copy.pending_receipts=1],['audit fingerprint missing without masking',s=>s.audit_authority_fingerprint=null],['masked baseline leaked',s=>{Object.assign(s,masked());s.classes[1].baseline_digest=digest;}],['masked copy time leaked',s=>{Object.assign(s,masked());s.classes[1].audit_copy.checked_at=s.checked_at;}],['masked total leaked',s=>{Object.assign(s,masked());s.classes[1].expected_records=2;}],['expired report verified',s=>{s.checked_at='2020-01-01T00:00:00Z';s.valid_until='2020-01-02T00:00:00Z';}],['unlabelled environment verified',s=>s.environment=null],['fresh check invented without report',s=>s.snapshot_id=null],['elapsed retention asserted',s=>s.elapsed_preservation='verified'],
])test('rejects '+name,()=>{const s=fixture();mutate(s);assert.throws(()=>api.parseSummary(s,scope),{code:'invalid_response'});});
test('pending acknowledgement is unknown with complete counts, existing gaps take precedence',()=>{const s=fixture(),a=s.classes[1];a.audit_copy.pending_receipts=1;a.audit_copy.state='unknown';a.audit_copy.reasons=['source_checkpoint_missing'];a.state='unknown';a.reasons=['source_checkpoint_missing'];s.uncovered_classes=[classIds[1]];api.parseSummary(s,scope);a.audit_copy.matching_receipts=0;a.audit_copy.missing_receipts=1;a.audit_copy.state='gap';a.audit_copy.reasons=['receipt_missing','source_checkpoint_missing'];a.state='gap';a.reasons=['receipt_missing','source_checkpoint_missing'];api.parseSummary(s,scope);});
test('canonical record digest is not the raw byte digest',()=>{const p=page();assert.notEqual(digest,canonical);assert.deepEqual(api.parsePage(p,snapshot,classIds[0]),p);});
test('changed metadata can retain identical raw bytes',()=>{const p=page();p.items[0].state='changed';p.items[0].reasons=['record_missing'];api.parsePage(p,snapshot,classIds[0]);});
for(const [name,mutate] of [
 ['wrong snapshot',p=>p.snapshot_id='wrong'],['wrong class',p=>p.class_id=classIds[1]],['canonical digest as raw observed bytes',p=>p.items[0].actual_sha256=canonical],['unknown field',p=>p.items[0].payload='secret'],['metadata raw digest',p=>p.items[0].record_kind='observation_linkage'],['missing canonical digest for observed record',p=>p.items[0].record_sha256=null],['missing member with observed bytes',p=>p.items[0].state='missing'],['unreadable member with observed bytes',p=>p.items[0].state='unreadable'],['unexpected member with expected bytes',p=>p.items[0].state='unexpected'],['duplicate member',p=>p.items.push(structuredClone(p.items[0]))],['unsorted page',p=>{p.items.push({...p.items[0],record_key:'a'});}],['unknown kind',p=>p.items[0].record_kind='secret'],['control in key',p=>p.items[0].record_key='bad\nkey'],['oversize key',p=>p.items[0].record_key='é'.repeat(257)],['empty continuing page',p=>{p.items=[];p.next_cursor='more';}],['changed raw bytes without bytes_changed',p=>{p.items[0].state='changed';p.items[0].actual_sha256=canonical;}],
])test('records reject '+name,()=>{const p=page();mutate(p);assert.throws(()=>api.parsePage(p,snapshot,classIds[0]),{code:'invalid_response'});});
for(const url of ['https://evil.invalid/bytes','//evil.invalid/bytes','javascript:alert(1)','/api/v1/operations/preservation/evidence/../secret','/api/v1/operations/preservation/evidence/%2e%2e','/api/v1/operations/preservation/evidence/22222222-2222-4222-8222-222222222222?token=secret','/api/v1/ingestion/runs/private'])test('rejects unsafe evidence URL '+url,()=>{const p=page();p.items[0].readback_url=url;assert.throws(()=>api.parsePage(p,snapshot,classIds[0]),{code:'invalid_response'});});
test('candidate wildcard selectors are rejected',()=>assert.throws(()=>api.sessionCandidates({source_scopes:[['*','a','s']]}),{code:'invalid_response'}));
test('scope cancellation prevents an evidence download after the body arrives',async()=>{
 const controller=new AbortController(),prior=globalThis.fetch,bytes=new TextEncoder().encode('synthetic');
 const {createHash}=await import('node:crypto');
 globalThis.fetch=async()=>{const response=new Response(bytes,{headers:{'content-type':'application/octet-stream','content-length':String(bytes.length),'content-disposition':'attachment; filename="opaque.bin"','x-content-type-options':'nosniff','content-digest':'sha-256=:'+createHash('sha256').update(bytes).digest('base64')+':'}});response.arrayBuffer=async()=>{controller.abort();return bytes.buffer;};return response;};
 try{await assert.rejects(api.downloadEvidence('/api/v1/operations/preservation/evidence/22222222-2222-4222-8222-222222222222',createHash('sha256').update(bytes).digest('hex'),controller.signal),{name:'AbortError'});}finally{globalThis.fetch=prior;}
});
for(const reason of ['record_missing','receipt_changed','bytes_changed','unexpected_member'])test('audit member anomaly remains a gap with matching event and receipt counters: '+reason,()=>{
 const s=fixture(),a=s.classes[1];a.state='gap';a.reasons=[reason];a.verified_records=1;a.missing_records=1;a.audit_copy.state='gap';a.audit_copy.reasons=[reason];s.uncovered_classes=[classIds[1]];
 assert.deepEqual(api.parseSummary(s,scope),s);
 a.audit_copy.pending_receipts=1;a.audit_copy.reasons=[reason,'source_checkpoint_missing'].sort();assert.deepEqual(api.parseSummary(s,scope),s);
 a.audit_copy.state='verified';assert.throws(()=>api.parseSummary(s,scope),{code:'invalid_response'});
});
for(const [name,mutate] of [
 ['class mask without envelope',s=>{s.audit_authority_fingerprint=digest;s.mask_reasons=[];}],
 ['class mask without fingerprint masking',s=>s.audit_authority_fingerprint=digest],
 ['class mask without envelope reason',s=>s.mask_reasons=[]],
 ['envelope mask without class mask',s=>{s.classes[1]=fixture().classes[1];s.uncovered_classes=[];}],
 ['copy mask without class mask',s=>{s.classes[1].reasons=['baseline_missing'];s.audit_authority_fingerprint=digest;s.mask_reasons=[];}],
])test('rejects inconsistent '+name,()=>{const s=masked();mutate(s);assert.throws(()=>api.parseSummary(s,scope),{code:'invalid_response'});});
test('wholly verified report requires signed observation times',()=>{const s=fixture();s.checked_at=s.valid_until=null;assert.throws(()=>api.parseSummary(s,scope),{code:'invalid_response'});});
test('partially unknown report may lack composite observation times',()=>{const s=fixture();s.classes[0]=unknown().classes[0];s.uncovered_classes=[classIds[0]];s.checked_at=s.valid_until=null;assert.deepEqual(api.parseSummary(s,scope),s);});
test('download rejects wrong bytes with their own matching header, without preparing an attachment',async()=>{
 const {createHash}=await import('node:crypto');const admitted=createHash('sha256').update('admitted bytes').digest('hex'),wrong=new TextEncoder().encode('different self-consistent evidence');
 const priorFetch=globalThis.fetch,priorDocument=globalThis.document;let prepared=false;
 globalThis.document={createElement:()=>{prepared=true;return {click(){prepared=true;}};}};
 globalThis.fetch=async()=>new Response(wrong,{headers:{'content-type':'application/octet-stream','content-length':String(wrong.length),'content-disposition':'attachment; filename="opaque.bin"','x-content-type-options':'nosniff','content-digest':'sha-256=:'+createHash('sha256').update(wrong).digest('base64')+':'}});
 try{await assert.rejects(api.downloadEvidence('/api/v1/operations/preservation/evidence/22222222-2222-4222-8222-222222222222',admitted),{code:'evidence_changed'});assert.equal(prepared,false);}finally{globalThis.fetch=priorFetch;globalThis.document=priorDocument;}
});
test('download rejects wrong body under the admitted header',async()=>{
 const {createHash}=await import('node:crypto');const admitted=createHash('sha256').update('admitted bytes'),hex=admitted.copy().digest('hex'),wrong=new TextEncoder().encode('different bytes');const prior=globalThis.fetch;
 globalThis.fetch=async()=>new Response(wrong,{headers:{'content-type':'application/octet-stream','content-length':String(wrong.length),'content-disposition':'attachment; filename="opaque.bin"','x-content-type-options':'nosniff','content-digest':'sha-256=:'+admitted.digest('base64')+':'}});
 try{await assert.rejects(api.downloadEvidence('/api/v1/operations/preservation/evidence/22222222-2222-4222-8222-222222222222','sha256:'+hex),{code:'evidence_changed'});}finally{globalThis.fetch=prior;}
});
test('download without an admitted raw digest fails before issuing a request',async()=>{
 const prior=globalThis.fetch;let requested=false;globalThis.fetch=async()=>{requested=true;throw new Error('must not fetch');};
 try{await assert.rejects(api.downloadEvidence('/api/v1/operations/preservation/evidence/22222222-2222-4222-8222-222222222222',null),{code:'invalid_response'});assert.equal(requested,false);}finally{globalThis.fetch=prior;}
});

test('matching event and receipt counters cannot verify the copy when an established audit member is missing',()=>{const s=fixture(),a=s.classes[1];a.state='gap';a.reasons=['record_missing'];a.verified_records=1;a.missing_records=1;s.uncovered_classes=[classIds[1]];assert.throws(()=>api.parseSummary(s,scope),{code:'invalid_response'});});
