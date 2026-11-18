// Actual frontend transport and response guards; fetch responses are synthetic.
import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {createRequire} from 'node:module';
import {mkdtemp,rm} from 'node:fs/promises';
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
