import { chromium } from '../ui/node_modules/playwright/index.mjs';
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

function arg(name) { const i=process.argv.indexOf(name); if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`); return process.argv[i+1]; }
const origin=arg('--origin'), evidence=arg('--evidence'), fixtureRoot=arg('--fixture-root'), appContainer=arg('--app-container');
const operatorSecret=(await readFile(path.join(fixtureRoot,'secrets','oidc_operator_secret'),'utf8')).trim();
await mkdir(evidence,{recursive:true,mode:0o700});
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH??'/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome'});
const admin=await browser.newContext({viewport:{width:1440,height:1000}}), user=await browser.newContext({viewport:{width:1440,height:1000}});
const zero='00000000-0000-4000-8000-000000000000';
const scope={source_family:'local',source_account_id:'g7-local',scope_key:'all'};
let membershipFrom;
let membershipUntil;
function ensure(ok,label){if(!ok)throw new Error(label);}
async function freshMembershipWindow(page,leadSeconds=30){const session=(await api(page,'/api/v1/auth/session')).body;const start=Date.parse(session.authority.evaluated_at)+leadSeconds*1000;return{from:new Date(start).toISOString(),until:new Date(start+86400000).toISOString()};}
function databaseProbe(code,...args){return execFileSync('docker',['exec',appContainer,'bash','-lc','export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; exec /opt/uvm/venv/bin/python -c "$1" "$2" "$3" "$4" "$5" "$6" "$7"','g7-probe',code,...args],{encoding:'utf8',timeout:15000}).trim();}
async function login(context,subject='g7-actor-subject',expectDenied=false){
  const page=await context.newPage();
  if(subject!=='g7-actor-subject') await context.route('**/api/v1/auth/login',async route=>{
    const response=await route.fetch({maxRedirects:0});const headers=response.headers();
    const url=new URL(headers.location);url.searchParams.set('fixture_subject',subject);
    await route.fulfill({response,headers:{...headers,location:url.toString()}});
  });
  await page.goto(origin+'/api/v1/auth/login',{waitUntil:'domcontentloaded',timeout:30000});
  if(expectDenied){await page.waitForURL(url=>url.pathname==='/auth/failure'&&url.searchParams.get('status')==='forbidden',{timeout:10000});return null;}
  await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session');if(!r.ok)return false;return (await r.json()).authenticated===true;},null,{timeout:20000});
  const session=await api(page,'/api/v1/auth/session');
  ensure(session.body.authority.subject===subject,`oidc_fixture_subject_mismatch_${subject}_${session.body.authority.subject}`);
  return page;
}
async function api(page,route,{method='GET',body=null,write=false}={}){
  return page.evaluate(async({route,method,body,write})=>{
    const session=await(await fetch('/api/v1/auth/session',{credentials:'same-origin',cache:'no-store'})).json();
    const response=await fetch(route,{method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{}),...(write?{'X-CSRF-Token':session.csrf_token}:{})},...(body?{body:JSON.stringify(body)}:{})});
    let value=null;try{value=await response.json();}catch{}return{status:response.status,body:value};
  },{route,method,body,write});
}
const adminPage=await login(admin);
try{
  await adminPage.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
  await adminPage.getByRole('link',{name:/Access & ownership/}).waitFor({timeout:15000});
  await adminPage.screenshot({path:path.join(evidence,'admin-access-ownership.png'),fullPage:true});
  ensure((await adminPage.title()).length>0,'admin_rendered_administration_failed');

  const bootstrap=await api(adminPage,'/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,body:{policy:{grants:[],denies:[],acceptance_material_changes:{},exception_warning_routes:[]}}});
  ensure([200,409].includes(bootstrap.status),'bootstrap_policy_failed');
  let cat=(await api(adminPage,'/api/v1/assessment/administration/catalogue')).body;
  ensure(cat.authority_mode==='legacy'||cat.authority_mode==='uvm_native_v1','catalogue_unavailable');
  if(cat.authority_mode==='legacy'){
    const activation=await api(adminPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,action:'native.authority.activate',membership_ids:[],expected_revisions:{target:cat.policy_revision,policy:cat.policy_revision,authority:cat.authority_revision,identity_membership:0,owners:0},payload:{mapping_revision:1,rationale:'Activate native G7 identity fixture authority',evidence_ref:'g7-identity-access-ownership-fixture'}}});
    ensure(activation.status===200,'native_authority_activation_failed');
  }
  cat=(await api(adminPage,'/api/v1/assessment/administration/catalogue')).body;
  const grant=cat.caller?.grantable;ensure(grant&&Array.isArray(grant.actions),'admin_grant_envelope_unavailable');
  ensure(['access_group.read','ownership.team.read','ownership.team.manage'].every(a=>grant.actions.includes(a)),'identity_fixture_grants_missing');
  const duties=grant.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,required_approver_count:1,prohibited_action_pairs:[]};
  const limits=grant.limits;
  const teamId=crypto.randomUUID(), accessId=crypto.randomUUID();
  async function current(){return (await api(adminPage,'/api/v1/assessment/administration/catalogue')).body;}
  async function command(action,target,payload,extra={},commandId=crypto.randomUUID()){
    const c=await current();const body={command_id:commandId,target_id:target,membership_ids:[],action,expected_revisions:{target:c.policy_revision,policy:c.policy_revision,authority:c.authority_revision,ownership:c.ownership_revision,identity_membership:0,owners:0,...extra},payload:{...payload,rationale:payload.rationale??'Exercise current native G7 authority',evidence_ref:payload.evidence_ref??'g7-identity-access-ownership-fixture'}};
    return api(adminPage,'/api/v1/assessment/commands',{method:'POST',write:true,body});
  }
  const managerGroupId=crypto.randomUUID();
  let result=await command('access_group.create',zero,{access_group_id:managerGroupId,display_name:'G7 ownership manager',description:'Exact local team administration',enabled:true,source_scopes:[scope],permissions:[{permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action:'ownership.team.manage',target_scope:{group_ids:['*'],source_families:['*'],environments:['*'],service_ids:['*'],membership_mode:'all_current'},limits,separation_of_duties:duties}]});
  ensure(result.status===200,`bootstrap_team_manager_group_create_failed_${result.status}_${JSON.stringify(result.body)}`);
  let adminGroups=(await api(adminPage,'/api/v1/assessment/access-groups')).body;let adminManager=adminGroups.items.find(x=>x.access_group_id===managerGroupId);
  const serverSession=(await api(adminPage,'/api/v1/auth/session')).body;
  membershipFrom=new Date(Date.parse(serverSession.authority.evaluated_at)+5000).toISOString();
  membershipUntil=new Date(Date.parse(serverSession.authority.evaluated_at)+86400000).toISOString();
  result=await command('access_group.membership.set',zero,{access_group_id:managerGroupId,principal_id:'g7-actor',effective_from:membershipFrom,enabled:true},{access_group:adminManager.revision,authority:adminGroups.authority_revision});
  ensure(result.status===200,`bootstrap_team_manager_membership_failed_${result.status}_${JSON.stringify(result.body)}`);
  adminGroups=(await api(adminPage,'/api/v1/assessment/access-groups')).body;adminManager=adminGroups.items.find(x=>x.access_group_id===managerGroupId);
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'admin-manager-membership.json'),JSON.stringify({authority_revision:adminGroups.authority_revision,memberships:adminManager.memberships.map(x=>({principal_id:x.principal_id,effective_from:x.effective_from,effective_until:x.effective_until,enabled:x.enabled,revision:x.revision}))}));
  const managerRoleId=adminManager.permissions[0].role_id;
  await adminPage.waitForFunction(start=>Date.now()>=Date.parse(start),membershipFrom,{timeout:20000});
  const adminAuthority=(await api(adminPage,'/api/v1/auth/session')).body;
  const adminAuthorityReadback={principal_id:adminAuthority.principal_id,policy_revision:adminAuthority.authority.policy_revision,evaluated_at:adminAuthority.authority.evaluated_at,access_groups:adminAuthority.access_groups,group_roles:adminAuthority.authority.group_roles,manager_group:managerGroupId,manager_role:managerRoleId,membership_from:membershipFrom};
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'admin-authority-readback.json'),JSON.stringify(adminAuthorityReadback));
  ensure(adminAuthority.access_groups.includes(managerGroupId)&&adminAuthority.authority.group_roles?.[managerGroupId]?.includes(managerRoleId),'bootstrap_manager_authority_not_effective_'+JSON.stringify(adminAuthorityReadback));
  result=await command('ownership.team.create',zero,{team_id:teamId,display_name:'G7 Identity Ownership Team'});
  ensure(result.status===200,`ownership_team_create_failed_${result.status}_${JSON.stringify(result.body)}`);
  let teams=(await api(adminPage,'/api/v1/assessment/ownership-teams')).body;
  let team=teams.items.find(x=>x.team_id===teamId);ensure(team,'ownership_team_readback_missing');
  ({from:membershipFrom,until:membershipUntil}=await freshMembershipWindow(adminPage,8));
  const effectiveFrom=membershipFrom, effectiveUntil=membershipUntil;
  result=await command('ownership.team.membership.set',zero,{team_id:teamId,principal_id:'g7-identity-user',effective_from:effectiveFrom,effective_until:effectiveUntil,enabled:true},{ownership:teams.ownership_revision,team:team.revision});
  ensure(result.status===200,`ownership_membership_create_failed_${result.status}_${JSON.stringify(result.body)}`);
  teams=(await api(adminPage,'/api/v1/assessment/ownership-teams')).body;
  team=teams.items.find(x=>x.team_id===teamId);
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'owner-membership-readback.json'),JSON.stringify({ownership_revision:teams.ownership_revision,team}));
  ensure(team?.memberships.some(x=>x.principal_id==='g7-identity-user'&&Date.parse(x.effective_from)===Date.parse(effectiveFrom)&&Date.parse(x.effective_until)===Date.parse(effectiveUntil)),'effective_dated_owner_readback_missing');

  async function createAccessGroup(id,name,permission){
    const c=await current();const perm={permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action:permission.action,target_scope:permission.target_scope,limits,separation_of_duties:duties};
    const res=await command('access_group.create',zero,{access_group_id:id,display_name:name,description:'Exact-scope G7 identity acceptance grant',enabled:true,source_scopes:[scope],permissions:[perm]});
    ensure(res.status===200,`access_group_create_failed_${permission.action}`);return res;
  }
  await createAccessGroup(accessId,'G7 access-group reader',{action:'access_group.read',target_scope:{group_ids:[accessId],source_families:['local'],environments:[],service_ids:[],membership_mode:'explicit'}});
  const ownerGrantId=crypto.randomUUID();
  await createAccessGroup(ownerGrantId,'G7 ownership reader',{action:'ownership.team.read',target_scope:{group_ids:[teamId],source_families:[],environments:[],service_ids:[],membership_mode:'explicit'}});
  // Keep a distinct team-management grant with the removable access-group grant to exercise stale-command denial.
  const userManagerGroupId=crypto.randomUUID();
  await createAccessGroup(userManagerGroupId,'G7 ownership manager for user',{action:'ownership.team.manage',target_scope:{group_ids:[teamId],source_families:[],environments:[],service_ids:[],membership_mode:'explicit'}});

  ({from:membershipFrom,until:membershipUntil}=await freshMembershipWindow(adminPage,8));
  for(const groupId of [accessId,ownerGrantId,userManagerGroupId]){
    const c=await current();const listed=(await api(adminPage,'/api/v1/assessment/access-groups')).body;
    const group=listed.items.find(x=>x.access_group_id===groupId);ensure(group,'created_access_group_missing');
    result=await command('access_group.membership.set',zero,{access_group_id:groupId,principal_id:'g7-identity-user',effective_from:membershipFrom,enabled:true},{access_group:group.revision,authority:listed.authority_revision});
    ensure(result.status===200,`access_membership_failed_${groupId}`);
  }
  const readGroup=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(x=>x.access_group_id===accessId);
  ensure(readGroup?.memberships.some(x=>x.principal_id==='g7-identity-user'&&x.enabled),'access_membership_readback_missing');

  const unlinked=await login(user,'g7-identity-unlinked-subject').catch(()=>null);
  ensure(!unlinked,'unlinked_subject_unexpectedly_authenticated');
  const userPage=await login(user,'g7-identity-user-subject');
  await userPage.waitForFunction(start=>Date.now()>=Date.parse(start),membershipFrom,{timeout:30000});
  const activationSession=(await api(userPage,'/api/v1/auth/session')).body;
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'user-membership-activation-readback.json'),JSON.stringify(activationSession));
  ensure([accessId,ownerGrantId,userManagerGroupId].every(group=>activationSession.access_groups.includes(group)),'user_native_memberships_not_effective_'+JSON.stringify({from:membershipFrom,at:activationSession.authority.evaluated_at,groups:activationSession.access_groups,expected:[accessId,ownerGrantId,userManagerGroupId]}));
  const signed=await api(userPage,'/api/v1/auth/session');
  ensure(signed.status===200&&signed.body.principal_id==='g7-identity-user','linked_oidc_subject_wrong_principal');
  ensure(signed.body.access_groups.includes(accessId)&&signed.body.access_groups.includes(ownerGrantId)&&signed.body.access_groups.includes(userManagerGroupId),'exact_native_memberships_missing');
  const userAccess=(await api(userPage,'/api/v1/assessment/access-groups')).body;
  ensure(userAccess.items.some(x=>x.access_group_id===accessId),'scoped_access_group_read_denied');
  const userTeams=await api(userPage,'/api/v1/assessment/ownership-teams');
  ensure(userTeams.status===200&&userTeams.body.items.some(x=>x.team_id===teamId&&x.memberships.some(m=>m.principal_id==='g7-identity-user'&&Date.parse(m.effective_until)===Date.parse(effectiveUntil))),'user_ownership_readback_failed');
  await userPage.goto(origin+'/#administration?section=ownership-teams',{waitUntil:'domcontentloaded'});
  await userPage.getByRole('button',{name:'G7 Identity Ownership Team'}).waitFor({timeout:10000});
  await userPage.screenshot({path:path.join(evidence,'user-scoped-ownership-before-withdrawal.png'),fullPage:true});
  const captured={policy_revision:signed.body.authority.policy_revision,authority_revision:signed.body.authority.group_revision,issuer:signed.body.authority.issuer,link_id:signed.body.authority.link_id,link_revision:signed.body.authority.link_revision,access_groups:signed.body.access_groups};

  // The access group is soft-disabled; only its permissions disappear. Independent ownership read remains available.
  const c=await current();const all=(await api(adminPage,'/api/v1/assessment/access-groups')).body;const toDisable=all.items.find(x=>x.access_group_id===accessId);
  result=await command('access_group.update',zero,{access_group_id:accessId,display_name:toDisable.display_name,description:toDisable.description,enabled:false,source_scopes:toDisable.source_scopes,permissions:toDisable.permissions},{access_group:toDisable.revision,authority:c.authority_revision});
  ensure(result.status===200,'access_group_withdrawal_failed');
  const afterSession=await api(userPage,'/api/v1/auth/session');
  ensure(afterSession.status===200&&!afterSession.body.access_groups.includes(accessId)&&afterSession.body.access_groups.includes(ownerGrantId)&&afterSession.body.access_groups.includes(userManagerGroupId),'withdrawal_did_not_preserve_unrelated_current_grants');
  const accessAfterWithdrawal=await api(userPage,'/api/v1/assessment/access-groups');ensure(accessAfterWithdrawal.status===200&&!accessAfterWithdrawal.body.items.some(x=>x.access_group_id===accessId),'withdrawn_access_group_still_visible');
  const ownershipStill=await api(userPage,'/api/v1/assessment/ownership-teams');ensure(ownershipStill.status===200&&ownershipStill.body.items.some(x=>x.team_id===teamId),'unrelated_ownership_grant_stopped_working');
  await userPage.goto(origin+'/#administration?section=ownership-teams',{waitUntil:'domcontentloaded'});
  await userPage.getByRole('button',{name:'G7 Identity Ownership Team'}).waitFor({timeout:10000});
  await userPage.screenshot({path:path.join(evidence,'user-scoped-ownership-after-withdrawal.png'),fullPage:true});
  const staleCommand=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,action:'ownership.team.membership.set',membership_ids:[],expected_revisions:{target:captured.policy_revision,policy:captured.policy_revision,authority:captured.authority_revision,ownership:teams.ownership_revision,team:team.revision,identity_membership:0,owners:0},payload:{team_id:teamId,principal_id:'g7-identity-user',effective_from:effectiveFrom,effective_until:effectiveUntil,enabled:false,rationale:'Probe stale command after grant withdrawal',evidence_ref:'g7-identity-stale-command'}}});
  ensure(staleCommand.status===403||staleCommand.status===409,'withdrawn_grant_stale_command_committed');

  const operatorHeaders={'Authorization':'Bearer '+operatorSecret,'Content-Type':'application/json'};
  const revoked=await fetch(origin+'/api/v1/auth/operator/links/'+encodeURIComponent(captured.link_id)+'/revoke',{method:'POST',headers:operatorHeaders,body:JSON.stringify({expected_revision:captured.link_revision,rationale:'Revoke disposable G7 identity link',evidence_ref:'g7-identity-link-revocation'})});
  ensure(revoked.status===200,'subject_link_revocation_failed');
  const oldSession=await api(userPage,'/api/v1/auth/session');ensure(oldSession.status===401,'old_session_survived_subject_link_revocation');
  const relogin=await login(user,'g7-identity-user-subject',true);ensure(!relogin,'revoked_subject_signed_in_again');
  const relink=await fetch(origin+'/api/v1/auth/operator/links',{method:'POST',headers:operatorHeaders,body:JSON.stringify({issuer:captured.issuer,subject:'g7-identity-user-subject',principal_id:'g7-identity-user',display_label:'Synthetic G7 Identity User',rationale:'Relink for separate account revocation proof',evidence_ref:'g7-identity-account-revocation'})});
  ensure(relink.status===200,'subject_relink_for_account_revocation_failed');
  const accountContext=await browser.newContext();const accountPage=await login(accountContext,'g7-identity-user-subject');
  const beforeDisable=await api(adminPage,'/api/v1/assessment/administration/catalogue');
  const disable=await api(adminPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,action:'principal.update',membership_ids:[],expected_revisions:{target:beforeDisable.body.policy_revision,policy:beforeDisable.body.policy_revision,authority:beforeDisable.body.authority_revision,identity_membership:0,owners:0},payload:{principal_id:'g7-identity-user',enabled:false,rationale:'Revoke disposable G7 account access'}}});
  ensure(disable.status===200,'account_revocation_failed');
  const disabledSession=await api(accountPage,'/api/v1/auth/session');ensure(disabledSession.status===401,'old_session_survived_account_revocation');
  const accountRelogin=await login(accountContext,'g7-identity-user-subject',true);ensure(!accountRelogin,'disabled_account_signed_in_again');
  await accountContext.close();

  // Force persistence failures at each row in the same native command transaction.
  const failureGroup=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(x=>x.access_group_id===managerGroupId);
  const triggerSql=`import sys,sqlalchemy as sa
mode,command_id,target_id=sys.argv[1:4]
engine=sa.create_engine(__import__('os').environ['UVM_DB_URL'])
tables={'audit':('assessment_audit_events',f"NEW.command_id = '{command_id}'::uuid"),'receipt':('assessment_command_receipts',f"NEW.command_id = '{command_id}'::uuid"),'intent':('administration_reconciliation_intents',f"NEW.target_id = '{target_id}'::uuid")}
table,condition=tables[mode]
suffix=command_id.replace('-','')[:20]
fn='g7_identity_abort_'+suffix;tr='g7_identity_fail_'+suffix
with engine.begin() as c:
 c.exec_driver_sql(f"CREATE OR REPLACE FUNCTION public.{fn}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'g7_injected_native_persistence_failure' USING ERRCODE='P0001'; END $$")
 c.exec_driver_sql(f"CREATE TRIGGER {tr} BEFORE INSERT ON public.{table} FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION public.{fn}()")
print(__import__('json').dumps({'mode':mode,'table':table,'trigger':tr,'command_id':command_id}))`;
  const dropTriggerSql=`import sys,sqlalchemy as sa,os
mode,command_id,target_id=sys.argv[1:4]
engine=sa.create_engine(os.environ['UVM_DB_URL'])
tables={'audit':'assessment_audit_events','receipt':'assessment_command_receipts','intent':'administration_reconciliation_intents'}
suffix=command_id.replace('-','')[:20];fn='g7_identity_abort_'+suffix;tr='g7_identity_fail_'+suffix
with engine.begin() as c:c.exec_driver_sql(f"DROP TRIGGER IF EXISTS {tr} ON public.{tables[mode]}");c.exec_driver_sql(f"DROP FUNCTION IF EXISTS public.{fn}()")
print(__import__('json').dumps({'dropped':tr}))`;
  const countsSql=`import sys,sqlalchemy as sa,os,json
command_id=sys.argv[1];engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.connect() as c:
 a=c.exec_driver_sql('SELECT count(*) FROM assessment_audit_events WHERE command_id=%s::uuid',(command_id,)).scalar_one()
 r=c.exec_driver_sql('SELECT count(*) FROM assessment_command_receipts WHERE command_id=%s::uuid',(command_id,)).scalar_one()
 i=c.exec_driver_sql('SELECT count(*) FROM administration_reconciliation_intents i JOIN assessment_audit_events a ON a.event_id=i.audit_event_id WHERE a.command_id=%s::uuid',(command_id,)).scalar_one()
 print(json.dumps({'audit':a,'receipt':r,'intent':i}))`;
  const failureResults=[];
  for(const mode of ['audit','receipt','intent']){
    const commandId=crypto.randomUUID();
    const beforePolicy=(await current()).policy_revision;
    const beforeGroup=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(x=>x.access_group_id===managerGroupId);
    const beforeCounts=JSON.parse(databaseProbe(countsSql,commandId,'', ''));
    databaseProbe(triggerSql,mode,commandId,managerGroupId);
    let failed;
    try{failed=await command('access_group.update',zero,{access_group_id:managerGroupId,display_name:beforeGroup.display_name+' failure-probe',description:beforeGroup.description,enabled:beforeGroup.enabled,source_scopes:beforeGroup.source_scopes,permissions:beforeGroup.permissions},{access_group:beforeGroup.revision},commandId);}
    finally{databaseProbe(dropTriggerSql,mode,commandId,managerGroupId);}
    const afterPolicy=(await current()).policy_revision;
    const afterGroup=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(x=>x.access_group_id===managerGroupId);
    const afterCounts=JSON.parse(databaseProbe(countsSql,commandId,'',''));
    const proof={mode,command_id:commandId,status:failed.status,error:failed.body,before_policy_revision:beforePolicy,after_policy_revision:afterPolicy,before_group_revision:beforeGroup.revision,after_group_revision:afterGroup.revision,before_history_count:beforeGroup.history.length,after_history_count:afterGroup.history.length,before_counts:beforeCounts,after_counts:afterCounts};
    await (await import('node:fs/promises')).writeFile(path.join(evidence,`persistence-failure-${mode}.json`),JSON.stringify(proof));
    ensure(failed.status===503&&beforePolicy===afterPolicy&&beforeGroup.revision===afterGroup.revision&&beforeGroup.history.length===afterGroup.history.length&&Object.values(afterCounts).every(n=>n===0),`native_${mode}_failure_did_not_roll_back_${JSON.stringify(proof)}`);
    failureResults.push(proof);
  }
  // Hold a real PostgreSQL advisory lock inside the first command's audit trigger.
  // Release only after the competing writer is observed waiting on the policy row lock.
  const raceId=crypto.randomUUID(), contenderId=crypto.randomUUID(), lockKey=731942018351;
  const raceSuffix=raceId.replaceAll('-','').slice(0,20), raceTrigger='g7_identity_race_'+raceSuffix, raceFunction='g7_identity_race_fn_'+raceSuffix;
  const readyPath=`/tmp/${raceTrigger}.ready`, releasePath=`/tmp/${raceTrigger}.release`;
  const holderCode=`import os,sys,time,sqlalchemy as sa
from pathlib import Path
engine=sa.create_engine(os.environ['UVM_DB_URL']);connection=engine.connect();key=int(sys.argv[1]);ready=Path(sys.argv[2]);release=Path(sys.argv[3])
connection.exec_driver_sql('SELECT pg_advisory_lock(%s)',(key,));ready.touch()
deadline=time.monotonic()+90
while not release.exists() and time.monotonic()<deadline: time.sleep(.02)
connection.exec_driver_sql('SELECT pg_advisory_unlock(%s)',(key,));connection.close()`;
  const installRaceSql=`import sys,sqlalchemy as sa,os
command_id,group_id,lock_key,trigger,fn=sys.argv[1:6]
engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.begin() as c:
 c.exec_driver_sql(f"CREATE OR REPLACE FUNCTION public.{fn}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({int(lock_key)}); RETURN NEW; END $$")
 c.exec_driver_sql(f"CREATE TRIGGER {trigger} BEFORE INSERT ON public.assessment_audit_events FOR EACH ROW WHEN (NEW.command_id = '{command_id}'::uuid) EXECUTE FUNCTION public.{fn}()")
print(__import__('json').dumps({'trigger':trigger,'command_id':command_id,'lock_key':int(lock_key)}))`;
  const dropRaceSql=`import sys,sqlalchemy as sa,os
trigger,fn=sys.argv[1:3]
engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.begin() as c:c.exec_driver_sql(f"DROP TRIGGER IF EXISTS {trigger} ON public.assessment_audit_events");c.exec_driver_sql(f"DROP FUNCTION IF EXISTS public.{fn}()")`;
  const lockWaitSql=`import sqlalchemy as sa,os,json
engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.connect() as c: print(json.dumps({'advisory_waiters':c.exec_driver_sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND wait_event='advisory'").scalar_one(),'lock_waiters':c.exec_driver_sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock'").scalar_one(),'activity':[list(row) for row in c.exec_driver_sql("SELECT state,wait_event_type,wait_event,left(query,120) FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND pid<>pg_backend_pid() ORDER BY pid").fetchall()]}))`;
  const advisoryProbeSql=`import sys,sqlalchemy as sa,os,json
key=int(sys.argv[1]);engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.connect() as c:
 acquired=c.exec_driver_sql('SELECT pg_try_advisory_lock(%s)',(key,)).scalar_one()
 if acquired:c.exec_driver_sql('SELECT pg_advisory_unlock(%s)',(key,))
 print(json.dumps({'held_by_barrier':not acquired}))`;
  const raceRead=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(x=>x.access_group_id===managerGroupId);
  const racePolicy=(await current()).policy_revision;
  execFileSync('docker',['exec','-d',appContainer,'bash','-lc','export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; exec /opt/uvm/venv/bin/python -c "$1" "$2" "$3" "$4" "$5" "$6" "$7"','g7-race-holder',holderCode,String(lockKey),readyPath,releasePath],{encoding:'utf8',timeout:15000});
  const pollDatabase=async(sql,accept,timeout=30000,...args)=>{const until=Date.now()+timeout;let last=null;while(Date.now()<until){last=JSON.parse(databaseProbe(sql,...args));if(accept(last))return last;await new Promise(resolve=>setTimeout(resolve,100));}throw new Error('deterministic_database_barrier_timeout_'+JSON.stringify(last));};
  await pollDatabase(advisoryProbeSql,value=>value.held_by_barrier,30000,String(lockKey));
  databaseProbe(installRaceSql,raceId,managerGroupId,String(lockKey),raceTrigger,raceFunction);
  const raceFirstBody={command_id:raceId,target_id:zero,membership_ids:[],action:'access_group.update',expected_revisions:{target:racePolicy,policy:racePolicy,authority:(await current()).authority_revision,ownership:(await current()).ownership_revision,access_group:raceRead.revision,identity_membership:0,owners:0},payload:{access_group_id:managerGroupId,display_name:raceRead.display_name+' race winner',description:raceRead.description,enabled:raceRead.enabled,source_scopes:raceRead.source_scopes,permissions:raceRead.permissions,rationale:'Exercise ordered G7 native writer race',evidence_ref:'g7-identity-lock-order-race'}};
  const raceContenderBody={...raceFirstBody,command_id:contenderId,payload:{...raceFirstBody.payload,display_name:raceRead.display_name+' stale contender'}};
  let firstPromise,secondPromise,raceOutcome;
  try{
    firstPromise=api(adminPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:raceFirstBody});
    const firstBarrier=await Promise.race([pollDatabase(lockWaitSql,value=>value.advisory_waiters>=1).then(value=>({barrier:value})),firstPromise.then(response=>({response}))]);
    if(firstBarrier.response)throw new Error('first_race_command_returned_before_advisory_wait_'+JSON.stringify(firstBarrier.response));
    const baselineAdvisoryWaiters=firstBarrier.barrier.advisory_waiters;
    const contenderPage=await admin.newPage();
    await contenderPage.goto(origin,{waitUntil:'domcontentloaded'});
    secondPromise=api(contenderPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:raceContenderBody});
    await pollDatabase(lockWaitSql,value=>value.advisory_waiters>=baselineAdvisoryWaiters+1);
    execFileSync('docker',['exec',appContainer,'touch',releasePath],{encoding:'utf8',timeout:15000});
    const [first,second]=await Promise.all([firstPromise,secondPromise]);
    const afterRacePolicy=(await current()).policy_revision;
    const afterRaceGroup=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(x=>x.access_group_id===managerGroupId);
    const firstRows=JSON.parse(databaseProbe(countsSql,raceId,'',''));
    const secondRows=JSON.parse(databaseProbe(countsSql,contenderId,'',''));
    raceOutcome={first_status:first.status,second_status:second.status,before_policy_revision:racePolicy,after_policy_revision:afterRacePolicy,before_group_revision:raceRead.revision,after_group_revision:afterRaceGroup.revision,final_display_name:afterRaceGroup.display_name,first_rows:firstRows,second_rows:secondRows,barrier:{first_advisory_waiters:baselineAdvisoryWaiters,after_contender:'advisory waiter count increased by one while first audit trigger held the policy transaction'}};
    await (await import('node:fs/promises')).writeFile(path.join(evidence,'native-command-lock-order-race.json'),JSON.stringify(raceOutcome));
    ensure(first.status===200&&second.status===409&&afterRacePolicy===racePolicy+1&&afterRaceGroup.revision===raceRead.revision+1&&afterRaceGroup.display_name===raceFirstBody.payload.display_name&&firstRows.audit===1&&firstRows.receipt===1&&firstRows.intent===1&&Object.values(secondRows).every(n=>n===0),'native_writer_lock_order_race_failed_'+JSON.stringify(raceOutcome));
    await contenderPage.close();
  } finally {
    execFileSync('docker',['exec',appContainer,'touch',releasePath],{encoding:'utf8',timeout:15000});
    try{databaseProbe(dropRaceSql,raceTrigger,raceFunction,'','');}catch{}
  }
  await adminPage.screenshot({path:path.join(evidence,'admin-access-withdrawal.png'),fullPage:true});
  console.log(JSON.stringify({environment:'local-labelled-fake-oidc-container',principal:'g7-identity-user',persistence_failures:failureResults.map(x=>({mode:x.mode,status:x.status,rollback:true})),policy_revision_before:captured.policy_revision,authority_revision_before:captured.authority_revision,withdrawn_access_group:accessId,remaining_groups:[ownerGrantId,userManagerGroupId],access_groups_after_withdrawal_status:accessAfterWithdrawal.status,ownership_after_withdrawal_status:ownershipStill.status,stale_command_status:staleCommand.status,old_session_after_link_revocation:oldSession.status,new_signin_after_link_revocation:'denied',old_session_after_account_revocation:disabledSession.status,new_signin_after_account_revocation:'denied',ownership:{team_id:teamId,effective_from:effectiveFrom,effective_until:effectiveUntil}},null,0));
} finally {await browser.close();}
