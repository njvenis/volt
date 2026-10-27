import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {createRequire} from 'node:module';
import {randomUUID} from 'node:crypto';
const dir=await mkdtemp(join(tmpdir(),'volt-backup-contract-'));
await build({stdin:{contents:`export * from './backup-api';export * from './native-admin-validation';`,resolveDir:resolve(import.meta.dirname,'../src')},bundle:true,platform:'node',format:'cjs',outfile:join(dir,'consumer.cjs'),logLevel:'silent'});
const api=createRequire(import.meta.url)(join(dir,'consumer.cjs'));
after(()=>rm(dir,{recursive:true,force:true}));
const values={interval_seconds:3600,timeout_seconds:900,maximum_backup_age_seconds:90000,restore_verification_timeout_seconds:1800,archive_target_ref:'registered-archive',recovery_profile_ref:'registered-recovery'};
const tokens={configuration:2,policy:5,authority:7,host_policy:3};
const command={schema_version:1,command_id:randomUUID(),action:'backup.settings.publish',expected_revisions:tokens,rationale:'Synthetic contract check',evidence_ref:null,values};
const digest='sha256:'+'c'.repeat(64);
const receipt={schema_version:1,deployment_id:'fixture',command_id:command.command_id,actor_id:'stable-non-uuid-actor',action:command.action,request_digest:digest,settings_digest:digest,desired_revision:3,evaluated_revisions:tokens,audit_id:randomUUID(),intent_id:randomUUID(),committed_at:new Date().toISOString(),outcome:'desired_committed'};
test('complete six-field publication and nullable evidence use exact reviewed DTO',()=>assert.deepEqual(api.parseCommand(command),command));
for(const [name,mutate] of [
 ['missing sixth field',c=>delete c.values.recovery_profile_ref],
 ['unknown write field',c=>c.values.path='/host/archive'],
 ['boolean duration',c=>c.values.interval_seconds=true],
 ['missing nullable evidence',c=>delete c.evidence_ref],
 ['epoch is not a publication token',c=>c.expected_revisions.recovery_epoch=1],
 ['incomplete four-token precondition',c=>delete c.expected_revisions.authority],
 ['publish and rollback together',c=>c.rollback_revision=1],
])test('reject '+name,()=>{const c=structuredClone(command);mutate(c);assert.throws(()=>api.parseCommand(c));});
test('receipt binds exact identity and all evaluated tokens; actor is not assumed UUID',()=>{assert.deepEqual(api.parseReceipt(receipt,'fixture',command,'stable-non-uuid-actor'),receipt);for(const key of Object.keys(tokens)){const r=structuredClone(receipt);r.evaluated_revisions[key]++;assert.throws(()=>api.parseReceipt(r,'fixture',command,'stable-non-uuid-actor'));}assert.throws(()=>api.parseReceipt({...receipt,command_id:randomUUID()},'fixture',command,'stable-non-uuid-actor'));assert.throws(()=>api.parseReceipt(receipt,'other-deployment',command,'stable-non-uuid-actor'));assert.throws(()=>api.parseReceipt({...receipt,outcome:'applied'},'fixture',command,'stable-non-uuid-actor'));});
const scope={group_ids:['*'],source_families:['*'],environments:['*'],service_ids:['*'],membership_mode:'all_current'};
const limits={maximum_acceptance_days:null,maximum_severity:null,whole_group_confirmation:false,allowed_environments:[],allowed_service_ids:[],allowed_sla_clock_bases:[],allowed_sla_severities:[],allowed_sla_start_sources:[],maximum_sla_duration_seconds:null,maximum_deadline_extension_seconds:null,allow_sla_backfill:false,allowed_identity_scalar_fields:{}};
const duties={approval_requires_distinct_actor:false,prohibit_requester_approval:false,required_approver_count:1,prohibited_action_pairs:[]};
const actions=['backup.settings.read','backup.settings.configure','observer.timing.read','observer.timing.configure','assessment.severity.override'];
const catalogue={schema_version:1,authority_mode:'uvm_native_v1',policy_revision:1,authority_revision:2,ownership_revision:1,caller:{principal_id:'actor',can_manage_access_groups:true,can_manage_ownership_teams:false,grantable:{actions,target_scope:scope,limits,source_scopes:[],separation_of_duties:duties,deployment_scopes:['fixture','*']}},selectable_actions:actions.map(action=>({action,target_scope:scope,limits,...(action.startsWith('assessment.')?{}:{deployment_scopes:['fixture','*']})}))};
for(const action of actions)test(action+' retains exact deployment/ordinary scope semantics',()=>{const deploymentAction=!action.startsWith('assessment.');const permission={permission_id:randomUUID(),role_id:randomUUID(),action,target_scope:scope,limits,separation_of_duties:duties,...(deploymentAction?{deployment_scopes:['fixture']}:{})};assert.equal(api.permissionWithin(permission,catalogue),true);if(deploymentAction){assert.equal(api.permissionWithin({...permission,deployment_scopes:[]},catalogue),false);assert.equal(api.permissionWithin({...permission,deployment_scopes:['other']},catalogue),false);assert.equal(api.permissionWithin({...permission,deployment_scopes:['fixture','fixture']},catalogue),false);}else assert.equal(api.permissionWithin({...permission,deployment_scopes:['fixture']},catalogue),false);});
test('asterisk deployment ceiling never grants a different deployment',()=>assert.equal(api.deploymentScopesWithin(['other'],['*']),false));

test('receipt rejects a different actor and requires the current session actor',()=>{for(const actor of ['other-actor','',undefined])assert.throws(()=>api.parseReceipt(receipt,'fixture',command,actor),{code:'invalid_response'});});
function freshSettings(){const now='2026-10-27T12:00:00Z';return {schema_version:1,deployment_id:'fixture',revisions:{...tokens,host_policy:0,recovery_epoch:0},desired:{revision:2,digest,values,command_id:command.command_id,committed_at:now},effective:{revision:1,digest,verified_at:now},status:{settings_application:null,completed_archive:{archive_id:randomUUID(),completed_at:now,manifest_digest:digest,outcome:'complete'},freshness:{state:'fresh',evaluated_at:'2026-10-27T12:00:10Z',age_seconds:10,basis_completed_at:now,maximum_backup_age_seconds:120},restore_verification:{state:'unknown',archive_id:null,recovery_epoch:0,verified_at:null,failure_code:null}},host_policy:null,can_configure:false};}
test('accepts complete server freshness evidence without substituting desired policy or local time',()=>{const state=freshSettings();assert.deepEqual(api.parseSettings(state,'fixture'),state);state.status.freshness.basis_completed_at='2026-10-27T12:00:00+00:00';assert.deepEqual(api.parseSettings(state,'fixture'),state);});
for(const [name,mutate] of [
 ['missing archive identity',s=>s.status.completed_archive.archive_id=null],
 ['missing archive time',s=>s.status.completed_archive.completed_at=null],
 ['missing manifest digest',s=>s.status.completed_archive.manifest_digest=null],
 ['unknown archive outcome',s=>s.status.completed_archive.outcome=null],
 ['failed archive outcome',s=>s.status.completed_archive.outcome='failed'],
 ['uncertain archive outcome',s=>s.status.completed_archive.outcome='uncertain'],
 ['nonmatching completion basis',s=>s.status.freshness.basis_completed_at='2026-10-27T11:59:59Z'],
])test('freshness fails closed for '+name,()=>{const state=freshSettings();mutate(state);assert.throws(()=>api.parseSettings(state,'fixture'),{code:'invalid_response'});});
