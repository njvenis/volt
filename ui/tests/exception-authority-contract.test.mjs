import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {createRequire} from 'node:module';
import {fixture} from './exception-authority-fixtures.mjs';
const dir=await mkdtemp(join(tmpdir(),'volt-exception-authority-contract-'));
await build({stdin:{contents:`export * from './assessment-api';`,resolveDir:resolve(import.meta.dirname,'../src')},bundle:true,platform:'node',format:'cjs',outfile:join(dir,'consumer.cjs'),logLevel:'silent'});
const api=createRequire(import.meta.url)(join(dir,'consumer.cjs'));
after(()=>rm(dir,{recursive:true,force:true}));
const payload=(f,action)=>action==='acceptance.submit'?{exception_contract_version:1,rationale:'Synthetic request'}:{acceptance_id:f.acceptance.acceptance_id,expected_request_revision:1,rationale:'Synthetic approval'};
for(const action of ['acceptance.submit','acceptance.approve']){
 for(const revision of [0,7,Number.MAX_SAFE_INTEGER])test(`${action} carries exact authority ${revision} and existing revisions`,()=>{
  const f=fixture(revision);assert.equal(api.validGroup(f.view),true);
  const c=api.newCommand(f.view,action,f.ids,payload(f,action));
  assert.deepEqual(c.expected_revisions,{...api.revisions(f.view),authority:revision});
  assert.deepEqual(c.membership_ids,f.ids);assert.equal(c.target_id,f.view.group.group_id);
 });
 test(`${action} rejects absent authority; never defaults to zero`,()=>{
  const f=fixture();delete f.view.assessment.authority_revision;
  assert.equal(api.validGroup(f.view),true); // Historical reads remain compatible.
  assert.throws(()=>api.newCommand(f.view,action,f.ids,payload(f,action)),{code:'authority_revision_unavailable'});
 });
 for(const value of [-1,true,false,null,'7',1.5,Number.MAX_SAFE_INTEGER+1,NaN,Infinity,undefined])test(`${action} rejects malformed authority ${String(value)}`,()=>{
  const f=fixture(value);f.view.assessment.authority_revision=value;
  assert.equal(api.validGroup(f.view),false);
  assert.throws(()=>api.newCommand(f.view,action,f.ids,payload(f,action)),{code:'authority_revision_unavailable'});
 });
 test(`${action} uses refreshed authority without mutating an earlier command`,()=>{
  const f=fixture(7),p=payload(f,action),first=api.newCommand(f.view,action,f.ids,p);
  f.view.assessment.authority_revision=8;
  const second=api.newCommand(f.view,action,f.ids,p);
  assert.equal(first.expected_revisions.authority,7);assert.equal(second.expected_revisions.authority,8);
  assert.notEqual(first.command_id,second.command_id);assert.deepEqual(first.payload,second.payload);
 });
}
test('other commands and legacy acceptance retain their previous revision envelope',()=>{
 const f=fixture();delete f.view.assessment.authority_revision;
 for(const action of ['owners.assign','acceptance.submit','acceptance.reject','acceptance.revoke','severity.override'])assert.deepEqual(api.newCommand(f.view,action,f.ids,{}).expected_revisions,api.revisions(f.view));
 delete f.acceptance.exception_contract_version;
 assert.deepEqual(api.newCommand(f.view,'acceptance.approve',f.ids,{acceptance_id:f.acceptance.acceptance_id}).expected_revisions,api.revisions(f.view));
});
test('actual scoped group parser accepts current authority and rejects malformed values',async()=>{
 const original=globalThis.fetch;
 try{for(const value of [0,8,-1,true,null,'8']){
  const f=fixture(value);globalThis.fetch=async path=>{assert.equal(path,'/api/v1/assessment/groups/'+f.view.group.group_id);return Response.json(f.view);};
  if(typeof value==='number'&&value>=0)assert.equal((await api.getGroup(f.view.group.group_id,'')).assessment.authority_revision,value);
  else await assert.rejects(()=>api.getGroup(f.view.group.group_id,''),{code:'unsupported_response'});
 }}finally{globalThis.fetch=original;}
});
