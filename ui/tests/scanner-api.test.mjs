// Actual frontend transport and response guards; fetch responses are synthetic.
import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {scannerView,sid} from './scanner-fixture.mjs';
const dir=await mkdtemp(join(tmpdir(),'volt-scanner-contract-'));
await build({stdin:{contents:"export * from './scanner-api';export {sessionFetch,SESSION_EVENT} from './session';",resolveDir:resolve(import.meta.dirname,'../src'),loader:'ts'},bundle:true,platform:'node',format:'cjs',outfile:join(dir,'scanner.cjs'),logLevel:'silent'});
const api=createRequire(import.meta.url)(join(dir,'scanner.cjs'));after(()=>rm(dir,{recursive:true,force:true}));
const view={...scannerView(),configuration_revision:1,credential:{secret_id:sid(22),version_id:sid(23),state:'active',revision:7}};
const command=api.scannerCommand(view,'scanner.connection.test','Synthetic review','synthetic:test');
const operation=(status='running')=>({schema_version:1,operation_id:sid(60),command_id:command.command_id,kind:'test',status,configuration_revision:1,credential_version_id:sid(23),started_at:'2026-11-18T12:00:00Z',finished_at:status==='running'?null:'2026-11-18T12:01:00Z',run_id:null,error_code:null,receipt_id:null});
function mock(t,value,status){const previous=globalThis.fetch;globalThis.fetch=async()=>Response.json(value,{status});t.after(()=>{globalThis.fetch=previous;});}
test('credential revision is required, accepts explicit zero and preserves nonzero without inference',()=>{
 assert.equal(api.validScanner(scannerView()),true);assert.equal(api.validScanner(view),true);
 for(const bad of [undefined,null,-1,1.5,'0',false]){const v=structuredClone(view);if(bad===undefined)delete v.credential.revision;else v.credential.revision=bad;assert.equal(api.validScanner(v),false);}
 assert.equal(command.expected_revisions.secret,null,'scanner command must not adopt the secret-specific fence');
});
for(const [status,value] of [[202,operation()],...["failed","partial","interrupted"].map(state=>[200,operation(state)])])test(`command accepts ${status}/${value.status} only as typed operational readback`,async t=>{mock(t,value,status);assert.deepEqual(await api.sendScanner(command),value);});
for(const [label,status,value] of [
 ['succeeded without receipt',200,operation('succeeded')],['running on 200',200,operation()],['terminal on 202',202,operation('failed')],
 ['terminal with receipt reference instead of receipt',200,{...operation('failed'),receipt_id:sid(80)}],
 ['running with receipt reference',202,{...operation(),receipt_id:sid(80)}],['terminal with no finish',200,{...operation('failed'),finished_at:null}],
 ['wrong command',200,{...operation('failed'),command_id:sid(81)}],['wrong credential',200,{...operation('failed'),credential_version_id:sid(82)}],
 ['wrong configuration',200,{...operation('failed'),configuration_revision:2}],['wrong operation kind',200,{...operation('failed'),kind:'collect'}],
])test(`command rejects ${label} without confirming an audited commit`,async t=>{mock(t,value,status);await assert.rejects(api.sendScanner(command),e=>e instanceof api.ScannerError&&e.uncertain===true);});
test('GET succeeded operation metadata remains valid with its receipt reference',async t=>{const value={...operation('succeeded'),receipt_id:command.command_id};mock(t,value,200);assert.deepEqual(await api.readOperation(sid(2),sid(3),sid(60)),value);});
test('real serialized scanner request preserves vector and original bytes across replay',async t=>{
 const previous=globalThis.fetch;t.after(()=>{globalThis.fetch=previous;});const bodies=[];
 globalThis.fetch=async(path,init)=>{assert.equal(path,'/api/v1/scanners/'+sid(2)+'/commands');bodies.push(JSON.parse(init.body));return Response.json(operation('interrupted'),{status:200});};
 const before=JSON.stringify(command);await api.sendScanner(command);await api.sendScanner(command);assert.deepEqual(bodies,[command,command]);assert.equal(JSON.stringify(command),before);assert.equal(bodies[0].expected_revisions.secret,null);
});
for(const [label,path,method,status,code,globalFailure] of [
 ['scoped permissions','/api/v1/connectors/'+sid(2)+'/permissions?source_id='+sid(3),'GET',403,'forbidden',false],
 ['source scope permissions','/api/v1/connectors/'+sid(2)+'/permissions?source_id='+sid(3),'GET',403,'source_scope_forbidden',false],
 ['scanner sibling','/api/v1/scanners/'+sid(2)+'?source_id='+sid(3),'GET',403,'forbidden',false],
 ['authentication','/api/v1/connectors/'+sid(2)+'/permissions?source_id='+sid(3),'GET',401,'authentication_required',true],
 ['csrf','/api/v1/connectors/'+sid(2)+'/permissions?source_id='+sid(3),'GET',403,'csrf_failed',true],
 ['session revocation','/api/v1/connectors/'+sid(2)+'/permissions?source_id='+sid(3),'GET',403,'session_revoked',true],
 ['identity failure','/api/v1/connectors/'+sid(2)+'/permissions?source_id='+sid(3),'GET',503,'identity_unavailable',true],
 ['write denial','/api/v1/connectors/'+sid(2)+'/permissions?source_id='+sid(3),'POST',403,'forbidden',true],
 ['unscoped permissions','/api/v1/connectors/'+sid(2)+'/permissions','GET',403,'forbidden',true],
 ['other connector endpoint','/api/v1/connectors/'+sid(2)+'/secrets?source_id='+sid(3),'GET',403,'forbidden',true],
])test(`session failure boundary: ${label}`,async t=>{mock(t,{error:{code}},status);const previous=globalThis.dispatchEvent;t.after(()=>{if(previous)globalThis.dispatchEvent=previous;else delete globalThis.dispatchEvent;});const events=[];globalThis.dispatchEvent=e=>{events.push(e);return true;};const r=await api.sessionFetch(path,{method});assert.equal(r.status,status);assert.equal(events.length,globalFailure?1:0);if(events.length)assert.equal(events[0].type,api.SESSION_EVENT);});

const abandonment={schema_version:1,command,rationale:'Review Café 🔒 cancellation',evidence_ref:'synthetic:review'};
async function dispositionBase(actor='operator-ä'){return {schema_version:1,command_id:command.command_id,connector_id:command.target_id,source_id:command.payload.source_id,action:command.action,actor_id:actor,request_digest:await api.scannerDigest(command,actor)};}
async function terminalProof(){return {...await dispositionBase(),disposition:'not_committed',audit_event_id:sid(90),occurred_at:'2026-11-18T12:00:00Z'};}
test('actual abandonment transport and generated request/response schema match provider parsing and canonical digest',async t=>{
 const proof=await terminalProof(),outgoing=[];const previous=globalThis.fetch;t.after(()=>{globalThis.fetch=previous;});
 globalThis.fetch=async(path,init)=>{const req=new Request(new URL(path,'https://synthetic.example.invalid'),init);outgoing.push({path:new URL(req.url).pathname,body:await req.json()});return Response.json(proof);};
 const original=JSON.stringify(abandonment);await api.abandonScanner(abandonment,'operator-ä');await api.abandonScanner(abandonment,'operator-ä');assert.equal(JSON.stringify(abandonment),original);assert.deepEqual(outgoing[0],outgoing[1]);assert.deepEqual(outgoing[0].body,abandonment);assert.equal(outgoing[0].path,'/api/v1/scanners/'+command.target_id+'/commands/'+command.command_id+'/abandon');
 const script=`import json,sys
from uvm.scanners.wire import ABANDON_ADAPTER
from uvm.scanners.store import command_digest
v=json.load(sys.stdin)
parsed=ABANDON_ADAPTER.validate_python(v['body']).model_dump()
print(json.dumps({'body':parsed,'digest':command_digest(v['actor'],parsed['command'])}))`;
 const parsed=spawnSync('uv',['run','--locked','python','-c',script],{cwd:resolve(import.meta.dirname,'../..'),input:JSON.stringify({body:outgoing[0].body,actor:'operator-ä'}),encoding:'utf8',timeout:30000});assert.equal(parsed.status,0,parsed.stderr);assert.deepEqual(JSON.parse(parsed.stdout),{body:abandonment,digest:proof.request_digest});
 const schema=JSON.parse(await readFile(new URL('../openapi.json',import.meta.url),'utf8')).paths['/api/v1/scanners/{connector_id}/commands/{command_id}/abandon'].post;
 const cases=[{schema:schema.requestBody.content['application/json'].schema,value:outgoing[0].body},{schema:schema.responses['200'].content['application/json'].schema,value:proof},{schema:schema.responses['200'].content['application/json'].schema,value:{...await dispositionBase(),disposition:'admitted',operation:operation('interrupted')}}];
 const validate=`import json,sys
from jsonschema import Draft202012Validator,FormatChecker
values=json.load(sys.stdin)
print(json.dumps([not list(Draft202012Validator(v['schema'],format_checker=FormatChecker()).iter_errors(v['value'])) for v in values]))`;
 const result=spawnSync('/usr/bin/python3',['-c',validate],{input:JSON.stringify(cases),encoding:'utf8',timeout:30000});assert.equal(result.status,0,result.stderr);assert.deepEqual(JSON.parse(result.stdout),[true,true,true]);
});
for(const [field,value] of [['actor_id','another'],['request_digest','0'.repeat(64)],['source_id',sid(91)],['connector_id',sid(91)],['command_id',sid(91)],['action','scanner.collection.start'],['audit_event_id','invalid'],['occurred_at','invalid'],['disposition','admitted']])test(`abandonment rejects mismatched or incomplete ${field} proof`,async t=>{const proof={...await terminalProof(),[field]:value};mock(t,proof,200);await assert.rejects(api.abandonScanner(abandonment,'operator-ä'),e=>e instanceof api.ScannerError&&e.uncertain);});
for(const status of [401,403,404,409,429,503])test(`abandonment HTTP ${status} is never definitive noncommit`,async t=>{mock(t,{error:{code:'command_conflict'}},status);const previous=globalThis.dispatchEvent;globalThis.dispatchEvent=()=>true;t.after(()=>{if(previous)globalThis.dispatchEvent=previous;else delete globalThis.dispatchEvent;});const original=JSON.stringify(abandonment);await assert.rejects(api.abandonScanner(abandonment,'operator-ä'));assert.equal(JSON.stringify(abandonment),original);});
test('retained abandonment requires identical original command and does not repair changed content',()=>{assert.equal(api.validScannerAbandonment(abandonment,command),true);for(const v of [{...abandonment,command:{...command,expected_revisions:{...command.expected_revisions,policy:99}}},{...abandonment,extra:true},{...abandonment,rationale:' '},{...abandonment,evidence_ref:'x'.repeat(2049)}]){const original=JSON.stringify(v);assert.equal(api.validScannerAbandonment(v,command),false);assert.equal(JSON.stringify(v),original);}});
test('admitted proof preserves exact operation binding and never accepts receipt-less succeeded',async t=>{mock(t,{...await dispositionBase(),disposition:'admitted',operation:operation('succeeded')},200);await assert.rejects(api.abandonScanner(abandonment,'operator-ä'),e=>e.uncertain);});
