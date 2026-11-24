// Frontend serialization + strict public DTO guards; synthetic replies, no host/runtime claim.
import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {createRequire} from 'node:module';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {scannerView,sid,recoveryView,recoverySlot,clearanceReceipt,connectorError,clearanceDispositionError} from './scanner-fixture.mjs';
const dir=await mkdtemp(join(tmpdir(),'volt-recovery-ui-'));
await build({stdin:{contents:"export * from './connector-api';export {validScanner,validRecovery} from './scanner-api';",resolveDir:resolve(import.meta.dirname,'../src'),loader:'ts'},bundle:true,platform:'node',format:'cjs',outfile:join(dir,'api.cjs'),logLevel:'silent'});
const api=createRequire(import.meta.url)(join(dir,'api.cjs'));after(()=>rm(dir,{recursive:true,force:true}));
const view=()=>({...scannerView(),configuration_revision:1,credential:{secret_id:sid(22),version_id:sid(23),state:'active',revision:7},recovery:recoveryView({fresh_version_ready:true,clearance_state:'available',approval_id:sid(81),approval_expires_at:new Date(Date.now()+600000).toISOString()})});
function mock(t,fn){const previous=globalThis.fetch;globalThis.fetch=fn;t.after(()=>{globalThis.fetch=previous;});}
for(const field of Object.keys(recoveryView()))test(`required recovery field ${field} cannot be omitted or defaulted`,()=>{const v=view();delete v.recovery[field];assert.equal(api.validScanner(v),false);});
test('required recovery rejects extra proof material and malformed safe metadata',()=>{for(const patch of [{proof:'private'},{state:'ready'},{epoch_id:'invalid'},{fresh_version_ready:1},{approval_expires_at:'bad'},{approval_id:'bad'}]){const v=view();Object.assign(v.recovery,patch);assert.equal(api.validScanner(v),false);}assert.equal(api.validScanner(scannerView()),true);});
test('actual clearance serialization copies exact public secret vector and passes backend payload parser',async t=>{
 const v=view(),slot=recoverySlot(v),outgoing=[];const cmd=api.clearanceCommand(slot,v,'Reviewed recovery','synthetic:review');
 mock(t,async(path,init)=>{outgoing.push({path,body:JSON.parse(init.body)});return Response.json(clearanceReceipt(cmd,v));});
 await api.saveCommand(cmd);await api.saveCommand(cmd);if(process.env.VOLT_UI_EVIDENCE)await writeFile(join(process.env.VOLT_UI_EVIDENCE,'serialized-clearance-metadata.json'),JSON.stringify({outgoing,slot,receipt:clearanceReceipt(cmd,v)},null,2));assert.deepEqual(outgoing[0],outgoing[1]);assert.equal(outgoing[0].path,'/api/v1/assessment/commands');assert.deepEqual(cmd.expected_revisions,slot.revisions);assert.equal(cmd.expected_revisions.secret,7);assert.deepEqual(Object.keys(cmd).sort(),['action','command_id','expected_revisions','membership_ids','payload','schema_version','target_id']);assert.deepEqual(Object.keys(cmd.payload).sort(),['connector_id','evidence_ref','rationale','recovery_epoch_id','secret_id','source_id','version_id']);
 const result=spawnSync('uv',['run','--locked','python','-c',"import json,sys\nfrom uvm.connectors.api import _request_shape\nb=json.load(sys.stdin)\n_request_shape(b['action'],b['payload'])\nprint('accepted')"],{cwd:resolve(import.meta.dirname,'../..'),input:JSON.stringify(cmd),encoding:'utf8',timeout:30000});assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),'accepted');
 const schema=JSON.parse(await readFile(resolve(import.meta.dirname,'../openapi.json'),'utf8'));const cases=[{schema:schema.paths['/api/v1/scanners/{connector_id}'].get.responses['200'].content['application/json'].schema,value:v}];
 const validate=spawnSync('/usr/bin/python3',['-c',"import json,sys\nfrom jsonschema import Draft202012Validator,FormatChecker\nfor x in json.load(sys.stdin): Draft202012Validator(x['schema'],format_checker=FormatChecker()).validate(x['value'])\nprint('accepted')"],{input:JSON.stringify(cases),encoding:'utf8'});assert.equal(validate.status,0,validate.stderr);
});
for(const [name,change] of [
 ['source tuple',s=>s.source.scope_key=sid(99)],['slot',s=>s.secret.secret_id=sid(99)],['slot revision',s=>s.secret.revision++],['policy fence',s=>{s.revisions.policy++;s.revisions.target++;}],['credential version',s=>s.secret.versions[0].version_id=sid(99)],['restore epoch',s=>s.recovery.recovery_epoch_id=sid(99)],['revoked version',s=>s.secret.versions[0].state='revoked']
])test(`clearance builder rejects changed ${name} rather than guessing or repairing`,()=>{const v=view(),slot=recoverySlot(v);change(slot);const before=JSON.stringify(slot);assert.throws(()=>api.clearanceCommand(slot,v,'Review','synthetic'),api.ConnectorError);assert.equal(JSON.stringify(slot),before);});
for(const [name,change] of [
 ['epoch',r=>r.result.recovery.recovery_epoch_id=sid(99)],['slot',r=>r.result.secret_id=sid(99)],['version',r=>r.result.version_id=sid(99)],['command',r=>r.command_id=sid(99)],['action',r=>r.action='connector.configuration.stage'],['audit',r=>r.audit_event_id='invalid'],['activation',r=>r.result.lifecycle='active'],['intent',r=>r.intents=[]],['proof missing',r=>delete r.result.recovery.approval_id]
])test(`clearance ${name} mismatch is uncertain and never success`,async t=>{const v=view(),cmd=api.clearanceCommand(recoverySlot(v),v,'Review','synthetic'),r=clearanceReceipt(cmd,v);change(r);mock(t,async()=>Response.json(r));await assert.rejects(api.saveCommand(cmd),e=>e instanceof api.ConnectorError&&e.uncertain);});
test('public secret read preserves full fence and rejects a missing or inconsistent revision',async t=>{const v=view(),slot=recoverySlot(v);mock(t,async()=>Response.json(slot));assert.deepEqual(await api.readRecoverySlot(v.connector_id,v.source_id,v.credential.secret_id),slot);slot.revisions.secret=null;await assert.rejects(api.readRecoverySlot(v.connector_id,v.source_id,v.credential.secret_id));});
test('malformed retained clearance stays unchanged and cannot be repaired from current view',()=>{const v=view(),cmd=api.clearanceCommand(recoverySlot(v),v,'Review','synthetic');assert.equal(api.validClearanceCommand(cmd,v.connector_id,v.source_id),true);delete cmd.expected_revisions.secret;const before=JSON.stringify(cmd);assert.equal(api.validClearanceCommand(cmd,v.connector_id,v.source_id),false);assert.equal(JSON.stringify(cmd),before);});

for(const [status,code] of [[409,'revision_conflict'],[409,'restore_quarantined'],[404,'not_found']])test(`complete backend ${status}/${code} envelope reaches production error parser unchanged`,async t=>{
 const v=view(),cmd=api.clearanceCommand(recoverySlot(v),v,'Review','synthetic'),original=JSON.stringify(cmd),body=connectorError(code);mock(t,async()=>Response.json(body,{status}));
 await assert.rejects(api.saveCommand(cmd),e=>e instanceof api.ConnectorError&&e.code===code&&e.uncertain===false&&!e.message.includes(body.error.message));assert.equal(JSON.stringify(cmd),original);
});
test('incomplete backend error remains a distinct unsupported-response regression',async t=>{
 const v=view(),cmd=api.clearanceCommand(recoverySlot(v),v,'Review','synthetic');mock(t,async()=>Response.json({error:{code:'revision_conflict'}},{status:409}));await assert.rejects(api.saveCommand(cmd),e=>e.code==='unsupported_response'&&e.uncertain===true);
});
test('clearance error fixtures match the actual backend exception adapter for each endpoint',()=>{
 const cases=[...[[409,'revision_conflict'],[409,'restore_quarantined'],[404,'not_found'],[403,'forbidden']].map(([status,code])=>({status,code,path:'/api/v1/assessment/commands',body:connectorError(code)})),...[[409,'command_conflict'],[404,'not_found'],[403,'forbidden'],[503,'inconsistent_operation'],[503,'dependency_unavailable']].map(([status,code])=>({status,code,path:'/api/v1/assessment/commands/'+sid(91)+'/abandon',body:clearanceDispositionError(code)}))];
 const script=`import asyncio,json,os,sys
for k in list(os.environ):
 if k.startswith('UVM_'): del os.environ[k]
import sqlalchemy as sa
from fastapi import HTTPException
from starlette.requests import Request
from uvm.api.app import create_app
# Factory-only in-memory schema discovery; no tables, lifespan, server or external DB.
engine=sa.create_engine('sqlite+pysqlite:///:memory:')
app=create_app(engine,principals={},cursor_secret='synthetic-contract-only')
async def check():
 result=[]
 for case in json.load(sys.stdin):
  body=case['body'];scope={'type':'http','method':'POST','scheme':'http','server':('127.0.0.1',46380),'path':case['path'],'query_string':b'','headers':[(b'x-correlation-id',body['error']['correlation_id'].encode())]}
  response=await app.exception_handlers[HTTPException](Request(scope),HTTPException(case['status'],{'code':case['code'],'message':body['error']['message']}))
  result.append({'status':response.status_code,'body':json.loads(response.body)})
 print(json.dumps(result))
try: asyncio.run(check())
finally: engine.dispose()
`;
 const result=spawnSync('uv',['run','--locked','python','-c',script],{cwd:resolve(import.meta.dirname,'../..'),input:JSON.stringify(cases),encoding:'utf8',timeout:30000});assert.equal(result.status,0,result.stderr);assert.deepEqual(JSON.parse(result.stdout),cases.map(({status,body})=>({status,body})));
});
const dispositionCase=()=>{const v=view(),command=api.clearanceCommand(recoverySlot(v),v,'Apply Café 🔒','synthetic:apply');return {v,body:{schema_version:1,command,rationale:'Review Café 🔒',evidence_ref:'synthetic:abandon'}};};
async function clearanceProof(body,actor='operator-ä'){return {schema_version:1,command_id:body.command.command_id,action:'connector.recovery.clearance.apply',actor_id:actor,request_digest:await api.clearanceDigest(body.command,actor),disposition:'not_committed',audit_event_id:sid(91),committed_at:'2026-11-18T12:00:00Z'};}
test('clearance disposition serialization and original connector digest preserve full Unicode command and frozen outer body',async t=>{
 const {body}=dispositionCase(),proof=await clearanceProof(body),sent=[];mock(t,async(path,init)=>{sent.push({path,body:JSON.parse(init.body)});return Response.json(proof);});const before=JSON.stringify(body);assert.deepEqual(await api.abandonClearance(body,'operator-ä'),proof);await api.abandonClearance(body,'operator-ä');assert.deepEqual(sent[0],sent[1]);assert.equal(sent[0].path,'/api/v1/assessment/commands/'+body.command.command_id+'/abandon');assert.equal(JSON.stringify(body),before);assert.deepEqual(sent[0].body.command,body.command);
 const canonical=spawnSync('uv',['run','--locked','python','-c',"import hashlib,json,sys\nx=json.load(sys.stdin)\nprint(hashlib.sha256(json.dumps({'principal_id':x['actor'],**x['command']},sort_keys=True,separators=(',',':')).encode()).hexdigest())"],{cwd:resolve(import.meta.dirname,'../..'),input:JSON.stringify({actor:'operator-ä',command:body.command}),encoding:'utf8',timeout:30000});assert.equal(canonical.status,0,canonical.stderr);assert.equal(proof.request_digest,canonical.stdout.trim());if(process.env.VOLT_UI_EVIDENCE)await writeFile(join(process.env.VOLT_UI_EVIDENCE,'serialized-clearance-disposition.json'),JSON.stringify({sent,proof},null,2));
});
for(const [field,value] of [['actor_id','other'],['command_id',sid(99)],['action','connector.configuration.stage'],['request_digest','0'.repeat(64)],['audit_event_id','invalid'],['committed_at','invalid'],['disposition','admitted'],['schema_version',2],['extra',true]])test(`clearance disposition rejects ${field} mismatch without proof`,async t=>{const {body}=dispositionCase(),proof=await clearanceProof(body);proof[field]=value;mock(t,async()=>Response.json(proof));await assert.rejects(api.abandonClearance(body,'operator-ä'),e=>e.code==='unsupported_response'&&e.uncertain);});
for(const [status,code] of [[401,'authentication_required'],[403,'forbidden'],[404,'not_found'],[409,'command_conflict'],[503,'dependency_unavailable'],[503,'inconsistent_operation']])test(`clearance disposition ${status}/${code} is never an audited noncommit proof`,async t=>{const {body}=dispositionCase(),original=JSON.stringify(body);mock(t,async()=>Response.json(clearanceDispositionError(code),{status}));const previous=globalThis.dispatchEvent;globalThis.dispatchEvent=()=>true;t.after(()=>{if(previous)globalThis.dispatchEvent=previous;else delete globalThis.dispatchEvent;});await assert.rejects(api.abandonClearance(body,'operator-ä'),e=>e instanceof api.ConnectorError&&e.code===code&&e.uncertain===true&&!e.message.includes('SYNTHETIC_RAW_ERROR_DO_NOT_RENDER'));assert.equal(JSON.stringify(body),original);});
test('clearance disposition requires HTTP200 even for an otherwise exact proof',async t=>{const {body}=dispositionCase(),proof=await clearanceProof(body);mock(t,async()=>Response.json(proof,{status:201}));await assert.rejects(api.abandonClearance(body,'operator-ä'),e=>e.uncertain);});
test('committed disposition verifies original receipt slot/version/epoch and rejects admitted variant',async t=>{
 const {v,body}=dispositionCase(),base=await clearanceProof(body);delete base.audit_event_id;delete base.committed_at;const receipt=clearanceReceipt(body.command,v),proof={...base,disposition:'committed',receipt};mock(t,async()=>Response.json(proof));assert.deepEqual((await api.abandonClearance(body,'operator-ä')).receipt,receipt);receipt.result.version_id=sid(99);await assert.rejects(api.abandonClearance(body,'operator-ä'),e=>e.uncertain);
});
test('disposition request rejects changed original body, source, omitted schema or new outer fields without repair',()=>{
 const {body}=dispositionCase();assert.equal(api.validClearanceAbandonment(body,body.command),true);for(const change of [b=>b.command.expected_revisions.connector++,b=>b.command.payload.source_id=sid(99),b=>delete b.command.schema_version,b=>b.proof='not-admitted',b=>b.rationale=' ']){const altered=structuredClone(body);change(altered);const before=JSON.stringify(altered);assert.equal(api.validClearanceAbandonment(altered,body.command),false);assert.equal(JSON.stringify(altered),before);}
});
test('actual emitted clearance disposition request and both proofs conform to the actual merged backend parser and generated schema',async t=>{
 const {v,body}=dispositionCase(),terminal=await clearanceProof(body),committed={...terminal,disposition:'committed',receipt:clearanceReceipt(body.command,v)};delete committed.audit_event_id;delete committed.committed_at;let outgoing;
 mock(t,async(path,init)=>{outgoing=JSON.parse(init.body);return Response.json(terminal);});await api.abandonClearance(body,'operator-ä');
 const parsed=spawnSync('uv',['run','--locked','python','-c',"import json,sys\nfrom uvm.connectors.clearance_disposition import parse_original\nx=json.load(sys.stdin)\nprint(json.dumps(parse_original(x['command']['command_id'],x)))"],{cwd:resolve(import.meta.dirname,'../..'),input:JSON.stringify(outgoing),encoding:'utf8',timeout:30000});assert.equal(parsed.status,0,parsed.stderr);assert.deepEqual(JSON.parse(parsed.stdout),body.command);
 const schema=JSON.parse(await readFile(resolve(import.meta.dirname,'../openapi.json'),'utf8')),route=schema.paths['/api/v1/assessment/commands/{command_id}/abandon'].post;
 const checked=spawnSync('/usr/bin/python3',['-c',"import json,sys\nfrom jsonschema import Draft202012Validator,FormatChecker\nfor x in json.load(sys.stdin): Draft202012Validator(x['schema'],format_checker=FormatChecker()).validate(x['value'])\nprint('accepted')"],{input:JSON.stringify([{schema:route.requestBody.content['application/json'].schema,value:outgoing},...[terminal,committed].map(value=>({schema:route.responses['200'].content['application/json'].schema,value}))]),encoding:'utf8'});assert.equal(checked.status,0,checked.stderr);
});
test('retained disposition admits nonnegative original fences without fresh admission inference or rewriting',async t=>{
 const {body}=dispositionCase();Object.assign(body.command.expected_revisions,{target:8,policy:3,identity_membership:5,owners:6,secret:0});const before=JSON.stringify(body);assert.equal(api.validClearanceCommand(body.command,body.command.payload.connector_id,body.command.payload.source_id),true);assert.equal(api.validClearanceAbandonment(body,body.command),true);mock(t,async()=>Response.json(await clearanceProof(body)));await api.abandonClearance(body,'operator-ä');assert.equal(JSON.stringify(body),before);
 for(const invalid of [null,true,-1,1.5]){const changed=structuredClone(body);changed.command.expected_revisions.secret=invalid;assert.equal(api.validClearanceCommand(changed.command,body.command.payload.connector_id,body.command.payload.source_id),false);}
});

test('abandonment generic error support cannot loosen the clearance admission error contract',async t=>{
 const {body}=dispositionCase();mock(t,async()=>Response.json(clearanceDispositionError('command_conflict'),{status:409}));await assert.rejects(api.saveCommand(body.command),e=>e.code==='unsupported_response'&&e.uncertain===true);
});
for(const mutate of [b=>b.error.details={outcome:'not_committed'},b=>delete b.error.correlation_id,b=>b.error.extra=true,b=>b.error.code='unrecognised',b=>b.extra=true])test('disposition error reader rejects missing/extra/unadopted fields and never infers noncommit',async t=>{
 const {body}=dispositionCase(),error=clearanceDispositionError('command_conflict');mutate(error);mock(t,async()=>Response.json(error,{status:409}));await assert.rejects(api.abandonClearance(body,'operator-ä'),e=>e.code==='unsupported_response'&&e.uncertain===true);
});
