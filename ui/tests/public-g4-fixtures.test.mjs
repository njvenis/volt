// Public synthetic contract inputs only; never contact GitHub or a live API.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {build} from 'esbuild';
const fixtures=resolve(import.meta.dirname,'fixtures/g4');
const provenance=JSON.parse(await readFile(join(fixtures,'provenance.json'),'utf8'));
const inputs=await Promise.all(provenance.inputs.map(async input=>{const bytes=await readFile(resolve(fixtures,input.fixture));return {...input,bytes,data:JSON.parse(bytes)};}));
const partial=inputs.find(x=>x.fixture==='partial-group-dto.json').data;
const template=inputs.find(x=>x.fixture==='g4-live-journey.json').data.partial_command.preview;
const groups=inputs.flatMap(({fixture,data})=>fixture==='partial-group-dto.json'?[data]:data.stages?Object.values(data.stages):data.group?[data.group]:[]);
const directory=await mkdtemp(join(tmpdir(),'volt-g4-contract-'));
let consumer;
try{
 const outfile=join(directory,'consumer.cjs');
 await build({stdin:{contents:`import React from 'react';
 import {renderToStaticMarkup} from 'react-dom/server';
 import {GitHubContext} from './GitHubContext';
 export {getGroup} from './assessment-api';
 export {getSignedPreview,githubCommand,commandComment} from './github-api';
 export const render=view=>renderToStaticMarkup(<GitHubContext view={view} loading={false} onRefresh={()=>{}}/>);`,resolveDir:resolve(import.meta.dirname,'../src'),loader:'tsx'},bundle:true,platform:'node',format:'cjs',outfile,logLevel:'silent'});
 consumer=createRequire(import.meta.url)(outfile);
}finally{await rm(directory,{recursive:true,force:true});}

test('all six fixture digests match the current sanitised bytes',()=>{
 assert.equal(inputs.length,6);
 for(const input of inputs)assert.equal(createHash('sha256').update(input.bytes).digest('hex'),input.fixture_sha256,input.fixture);
});
test('all GitHub identity fields are synthetic and links use the reserved fixture origin',()=>{
 let accounts=0,repositories=0,links=0;
 function visit(value){
  if(Array.isArray(value))return value.forEach(visit);
  if(!value||typeof value!=='object')return;
  for(const [key,item]of Object.entries(value)){
   if(['account_id','github_account_id'].includes(key)){assert.equal(item,'900000001');accounts++;}
   if(key==='repository_id'){assert.equal(item,'900000002');repositories++;}
   if(key==='issue_node_id')assert.equal(item,'I_SYNTHETIC_VOLT_G4_101');
   if(key==='link_id')assert.equal(item,'40000000-0000-4000-8000-000000000101');
   if(key==='issue_number')assert.ok([101,102,103,104].includes(item));
   if(key==='issue_url'){assert.equal(item,`https://github.example.invalid/volt-fixture/repository/issues/${value.issue_number}`);links++;}
   visit(item);
  }
 }
 inputs.forEach(({data})=>visit(data));
 assert.equal(groups.length,9);assert.equal(accounts,10);assert.equal(repositories,19);assert.equal(links,9);
 assert.equal(template.repository_id,partial.github.repository_id);
 assert.equal(template.github_account_id,partial.github_identity.account_id);
 assert.equal(template.issue_number,partial.github.issue_number);
});
test('every unchanged scenario still passes the actual GroupView consumer and renders its synthetic issue link',async()=>{
 const originalFetch=globalThis.fetch;
 try{
  for(const group of groups){
   globalThis.fetch=async path=>{assert.equal(path,'/api/v1/assessment/groups/'+group.group.group_id);return Response.json(group);};
   assert.deepEqual(await consumer.getGroup(group.group.group_id,''),group);
   const html=consumer.render(group);
   assert.ok(html.includes(`href="${group.github.issue_url}"`));
   assert.ok(html.includes('900000002'));assert.ok(html.includes('900000001'));
  }
 }finally{globalThis.fetch=originalFetch;}
});
test('synthetic preview still binds the exact account, repository and issue; wrong identities fail closed',async()=>{
 const view=partial;
 const command={command_id:'40000000-0000-4000-8000-000000000102',action:'remediation.confirm_group',target_id:view.group.group_id,membership_ids:view.assessment.membership.outstanding_ids,expected_revisions:{target:view.assessment.revision,identity_membership:view.assessment.membership.revision,policy:view.assessment.policy_revision,owners:view.assessment.owner_revision},expected_exposures:view.episodes.map(({exposure_id,episode_id,state_revision})=>({exposure_id,episode_id,state_revision})),payload:{rationale:'Synthetic fixture scope verification'}};
 const proposal=consumer.githubCommand(command);
 const preview={...template,preview_id:'40000000-0000-4000-8000-000000000103',command:proposal,command_digest:'0'.repeat(64),expected_revisions:proposal.expected_revisions,expected_exposures:proposal.expected_exposures,expires_at:'2099-01-01T00:00:00Z'};
 const originalFetch=globalThis.fetch;let response=preview;
 try{
  globalThis.fetch=async(path,init)=>{assert.equal(path,'/api/v1/github/commands/preview');assert.equal(init.method,'POST');assert.deepEqual(JSON.parse(init.body),{command:proposal,issue_number:101,repository_id:'900000002'});return Response.json(response);};
  assert.deepEqual(await consumer.getSignedPreview(command,view,''),preview);
  assert.match(consumer.commandComment(preview),/^\/uvm v1\n```json\n/);
  for(const mismatch of [{github_account_id:'900000099'},{repository_id:'900000099'},{issue_number:999}]){
   response={...preview,...mismatch};
   await assert.rejects(consumer.getSignedPreview(command,view,''),error=>error.code==='preview_invalid');
  }
 }finally{globalThis.fetch=originalFetch;}
});
