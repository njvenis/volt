import { chromium } from '../ui/node_modules/playwright/index.mjs';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

function arg(name) {
  const at = process.argv.indexOf(name);
  if (at < 0 || !process.argv[at + 1]) throw new Error(`missing ${name}`);
  return process.argv[at + 1];
}
const origin = arg('--origin');
const storageState = arg('--storage-state');
await mkdir(path.dirname(storageState), {recursive:true, mode:0o700});
const browser = await chromium.launch({headless:true});
const context = await browser.newContext({viewport:{width:1440,height:1000}});
const page = await context.newPage();

async function api(route, {method='GET', body, write=false}={}) {
  return page.evaluate(async ({route,method,body,write}) => {
    const session = await (await fetch('/api/v1/auth/session',{credentials:'same-origin'})).json();
    const response = await fetch(route,{method,credentials:'same-origin',
      headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{}),
        ...(write?{'X-CSRF-Token':session.csrf_token}:{})},
      ...(body?{body:JSON.stringify(body)}:{})});
    let value; try {value=await response.json();} catch {value=null;}
    return {status:response.status,body:value};
  },{route,method,body,write});
}
function ensure(condition, code) { if (!condition) throw new Error(code); }

try {
  await page.goto(origin + '/api/v1/auth/login',{waitUntil:'domcontentloaded',timeout:30000});
  await page.waitForFunction(async()=>{
    const response=await fetch('/api/v1/auth/session');
    if(!response.ok)return false;
    const session=await response.json();
    return session.authenticated===true&&session.credential_mode==='oidc_session';
  },null,{timeout:30000});

  const bootstrap=await api('/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,
    body:{policy:{grants:[],denies:[],acceptance_material_changes:{},exception_warning_routes:[]}}});
  ensure([200,409].includes(bootstrap.status),'bootstrap_policy_failed');
  const zero='00000000-0000-4000-8000-000000000000';
  const activation=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{
    command_id:crypto.randomUUID(),target_id:zero,action:'native.authority.activate',membership_ids:[],
    expected_revisions:{target:1,policy:1,authority:0,identity_membership:0,owners:0},
    payload:{mapping_revision:1,rationale:'Activate exact-scope G7 preservation fixture authority',
      evidence_ref:'g7-preservation-fixture'}}});
  if(activation.status===409){
    const check=await api('/api/v1/assessment/administration/catalogue');
    ensure(check.status===200&&check.body.authority_mode==='uvm_native_v1','native_authority_unavailable');
  } else ensure(activation.status===200,'native_activation_failed');

  const catalogue=await api('/api/v1/assessment/administration/catalogue');
  ensure(catalogue.status===200,'authority_catalogue_unavailable');
  const grant=catalogue.body.caller?.grantable;
  ensure(grant&&Array.isArray(grant.actions),'grant_envelope_unavailable');
  const wanted=['preservation.read','preservation.evidence.read','audit.read',
    'audit.read.deployment'];
  ensure(wanted.every(action=>grant.actions.includes(action)),'required_preservation_grants_unavailable');
  const groupId=crypto.randomUUID();
  const sourceScope={source_family:'local',source_account_id:'g7-local',scope_key:'all'};
  const targetScope={group_ids:['*'],source_families:['local'],environments:['*'],service_ids:['*'],membership_mode:'all_current'};
  const limits={...grant.limits,
    allowed_environments:grant.limits.allowed_environments?.length?grant.limits.allowed_environments:['*'],
    allowed_service_ids:grant.limits.allowed_service_ids?.length?grant.limits.allowed_service_ids:['*']};
  const duties=grant.separation_of_duties??{approval_requires_distinct_actor:true,
    prohibit_requester_approval:true,required_approver_count:1,prohibited_action_pairs:[]};
  const permissions=wanted.map(action=>({permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action,
    target_scope:targetScope,limits,separation_of_duties:duties,
    ...(action==='audit.read.deployment'||action==='audit.export.deployment'?{deployment_scopes:['g7-local']}: {})}));
  const create=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{
    command_id:crypto.randomUUID(),target_id:zero,action:'access_group.create',membership_ids:[],
    expected_revisions:{target:catalogue.body.policy_revision,policy:catalogue.body.policy_revision,
      authority:catalogue.body.authority_revision,identity_membership:0,owners:0},
    payload:{access_group_id:groupId,display_name:'G7 preservation fixture operators',
      description:'Synthetic exact-scope preservation and deployment audit authority',enabled:true,
      source_scopes:[sourceScope],permissions,rationale:'Create bounded local preservation fixture grants',
      evidence_ref:'g7-preservation-fixture'}}});
  ensure(create.status===200,'preservation_group_create_failed');

  for(const principalId of ['g7-actor','g7-preservation-source']){
    const current=await api('/api/v1/assessment/administration/catalogue');
    const groups=await api('/api/v1/assessment/access-groups');
    ensure(current.status===200&&groups.status===200,'authority_revision_read_failed');
    const group=groups.body.items?.find(item=>item.access_group_id===groupId);
    ensure(group,'preservation_group_missing');
    const result=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{
      command_id:crypto.randomUUID(),target_id:zero,action:'access_group.membership.set',membership_ids:[],
      expected_revisions:{target:current.body.policy_revision,policy:current.body.policy_revision,
        authority:current.body.authority_revision,identity_membership:0,owners:0,access_group:group.revision},
      payload:{access_group_id:groupId,principal_id:principalId,
        effective_from:new Date(Date.now()+1000).toISOString(),enabled:true,
        rationale:'Grant exact local preservation fixture access',evidence_ref:'g7-preservation-fixture'}}});
    ensure(result.status===200,'preservation_membership_failed');
  }
  await page.waitForTimeout(1500);
  const logout=await api('/api/v1/auth/logout',{method:'POST',write:true,body:{}});
  ensure(logout.status===200,'fixture_session_refresh_failed');
  await page.goto(origin+'/api/v1/auth/login',{waitUntil:'domcontentloaded',timeout:30000});
  await page.waitForFunction(async()=>{
    const response=await fetch('/api/v1/auth/session');
    if(!response.ok)return false;
    const session=await response.json();
    return session.authenticated===true&&session.credential_mode==='oidc_session';
  },null,{timeout:30000});
  const session=await api('/api/v1/auth/session');
  ensure(session.status===200&&session.body.access_groups?.includes(groupId),
    'fresh_session_missing_preservation_group');
  await context.storageState({path:storageState});
  console.log(JSON.stringify({authority:'current_exact_scope',group_id:groupId,
    session_state:'saved',source_service_member:true},null,0));
} finally {
  await browser.close();
}
