import { chromium } from '../ui/node_modules/playwright/index.mjs';
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

function arg(name) { const i=process.argv.indexOf(name); if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`); return process.argv[i+1]; }
const origin=arg('--origin'), evidence=arg('--evidence'), fixtureRoot=arg('--fixture-root'), appContainer=arg('--app-container');
const operatorSecret=(await readFile(path.join(fixtureRoot,'secrets','oidc_operator_secret'),'utf8')).trim();
const ownerFindingFixture=JSON.parse(await readFile(path.join(evidence,'identity-owner-finding-fixture.stdout'),'utf8'));
await mkdir(evidence,{recursive:true,mode:0o700});
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH??'/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome'});
const admin=await browser.newContext({viewport:{width:1440,height:1000}}), user=await browser.newContext({viewport:{width:1440,height:1000}});
const zero='00000000-0000-4000-8000-000000000000';
const scope={source_family:'local',source_account_id:'g7-local',scope_key:'all'};
let membershipFrom;
let membershipUntil;
function ensure(ok,label){if(!ok)throw new Error(label);}
function stableJson(value){if(Array.isArray(value))return value.map(stableJson);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,stableJson(value[key])]));return value;}
async function freshMembershipWindow(page,leadSeconds=30){const session=(await api(page,'/api/v1/auth/session')).body;const start=Date.parse(session.authority.evaluated_at)+leadSeconds*1000;return{from:new Date(start).toISOString(),until:new Date(start+86400000).toISOString()};}
function databaseProbe(code,...args){return execFileSync('docker',['exec',appContainer,'bash','-lc','export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; exec /opt/uvm/venv/bin/python -c "$1" "$2" "$3" "$4" "$5" "$6" "$7"','g7-probe',code,...args],{encoding:'utf8',timeout:15000}).trim();}
async function login(context,subject='g7-actor-subject',expectDenied=false){
  const page=await context.newPage();
  let callbackResponse=null;
  page.on('response',response=>{if(new URL(response.url()).pathname==='/api/v1/auth/callback')callbackResponse={status:response.status(),location:response.headers()['location']??null};});
  if(subject!=='g7-actor-subject') await context.route('**/api/v1/auth/login',async route=>{
    const response=await route.fetch({maxRedirects:0});const headers=response.headers();
    const url=new URL(headers.location);url.searchParams.set('fixture_subject',subject);
    await route.fulfill({response,headers:{...headers,location:url.toString()}});
  });
  await page.goto(origin+'/api/v1/auth/login',{waitUntil:'domcontentloaded',timeout:30000});
  if(expectDenied){
    await page.waitForURL(url=>url.pathname==='/auth/failure'&&url.searchParams.get('status')==='forbidden',{timeout:10000});
    const denial={callback_url:page.url(),provider_callback:callbackResponse,session_status:(await api(page,'/api/v1/auth/session')).status};
    ensure(denial.provider_callback&&denial.provider_callback.status>=300&&denial.provider_callback.status<400,'expected_oidc_callback_not_received_'+JSON.stringify(denial));
    ensure(denial.session_status===401,'denied_oidc_login_created_session_'+JSON.stringify(denial));
    return {page,denial};
  }
  await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session');if(!r.ok)return false;return (await r.json()).authenticated===true;},null,{timeout:20000});
  const session=await api(page,'/api/v1/auth/session');
  ensure(session.body.authority.subject===subject,`oidc_fixture_subject_mismatch_${subject}_${session.body.authority.subject}`);
  return page;
}
async function api(page,route,{method='GET',body=null,write=false,csrfToken=null,barrierCommandId=null}={}){
  return page.evaluate(async({route,method,body,write,csrfToken,barrierCommandId})=>{
    const session=write&&!csrfToken?await(await fetch('/api/v1/auth/session',{credentials:'same-origin',cache:'no-store'})).json():null;
    const response=await fetch(route,{method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{}),...(write?{'X-CSRF-Token':csrfToken??session.csrf_token}:{}),...(barrierCommandId?{'X-UVM-G7-Barrier-Command':barrierCommandId}:{})},...(body?{body:JSON.stringify(body)}:{})});
    let value=null;try{value=await response.json();}catch{}return{status:response.status,body:value};
  },{route,method,body,write,csrfToken,barrierCommandId});
}
async function waitFindingLoaded(page,name){
  await page.locator('.assessment-workspace').waitFor({timeout:15000});
  await page.waitForFunction(()=>{const status=document.querySelector('.assessment-workspace .load-status')?.textContent??'';return status.length>0&&!status.includes('Loading finding assessment');},null,{timeout:20000});
  const text=await page.locator('.assessment-workspace').innerText();
  await (await import('node:fs/promises')).writeFile(path.join(evidence,`${name}.txt`),text);
  await page.screenshot({path:path.join(evidence,`${name}.png`),fullPage:true});
  ensure(text.includes('Finding assessment loaded.'),`${name}_not_loaded_${text}`);
}
let adminPage=await login(admin);
try{
  await adminPage.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
  await adminPage.getByRole('link',{name:/Access & ownership/}).waitFor({timeout:15000});
  await adminPage.screenshot({path:path.join(evidence,'admin-access-ownership.png'),fullPage:true});
  ensure((await adminPage.title()).length>0,'admin_rendered_administration_failed');

  const denyOwnerId='g7-identity-deny-user';
  const stableTeamId='00000000-0000-4000-8000-000000000083';
  const bootstrap=await api(adminPage,'/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,body:{policy:{grants:[],denies:[{deny_id:'g7-explicit-access-group-deny',principal_id:denyOwnerId,actions:['access_group.read'],target_ids:['*']}],owner_directory:[{owner_id:'g7-identity-user',owner_type:'person',display_name:'Synthetic Identity User',enabled:true},{owner_id:'g7-actor',owner_type:'person',display_name:'Synthetic G7 Operator',enabled:true},{owner_id:stableTeamId,owner_type:'team',display_name:'G7 Identity Ownership Team',enabled:true}],acceptance_material_changes:{},exception_warning_routes:[]}}});
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
  const teamId=stableTeamId, accessId=crypto.randomUUID();
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
  result=await command('access_group.membership.set',zero,{access_group_id:managerGroupId,principal_id:'g7-identity-deny-user',effective_from:membershipFrom,enabled:true},{access_group:adminManager.revision,authority:adminGroups.authority_revision});
  ensure(result.status===200,`explicit_deny_team_manager_membership_failed_${result.status}_${JSON.stringify(result.body)}`);
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
  const findingGrantId=crypto.randomUUID();
  const findingPermissions=['assessment.read','audit.read','owners.directory.read','owners.assign','portion.define'].map(action=>({
    permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action,
    target_scope:{group_ids:[ownerFindingFixture.group],source_families:['local'],environments:[],service_ids:[],membership_mode:'explicit'},
    limits,separation_of_duties:duties}));
  result=await command('access_group.create',zero,{access_group_id:findingGrantId,display_name:'G7 exact finding owner reviewer',description:'Exact target access for the retained local owner and portion fixture',enabled:true,source_scopes:[scope],permissions:findingPermissions});
  ensure(result.status===200,`finding_review_grant_create_failed_${result.status}_${JSON.stringify(result.body)}`);

  ({from:membershipFrom,until:membershipUntil}=await freshMembershipWindow(adminPage,8));
  for(const groupId of [accessId,ownerGrantId,userManagerGroupId,findingGrantId]){
    const c=await current();const listed=(await api(adminPage,'/api/v1/assessment/access-groups')).body;
    const group=listed.items.find(x=>x.access_group_id===groupId);ensure(group,'created_access_group_missing');
    result=await command('access_group.membership.set',zero,{access_group_id:groupId,principal_id:'g7-identity-user',effective_from:membershipFrom,enabled:true},{access_group:group.revision,authority:listed.authority_revision});
    ensure(result.status===200,`access_membership_failed_${groupId}`);
  }
  const readGroup=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(x=>x.access_group_id===accessId);
  ensure(readGroup?.memberships.some(x=>x.principal_id==='g7-identity-user'&&x.enabled),'access_membership_readback_missing');

  const unlinked=await login(user,'g7-identity-unlinked-subject',true);
  ensure(unlinked.denial.session_status===401,'unlinked_subject_denial_missing');
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'unlinked-login-denial.json'),JSON.stringify(unlinked.denial));
  await unlinked.page.close();
  let userPage=await login(user,'g7-identity-user-subject');
  await userPage.waitForFunction(start=>Date.now()>=Date.parse(start),membershipFrom,{timeout:30000});
  const activationSession=(await api(userPage,'/api/v1/auth/session')).body;
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'user-membership-activation-readback.json'),JSON.stringify(activationSession));
  ensure([accessId,ownerGrantId,userManagerGroupId,findingGrantId].every(group=>activationSession.access_groups.includes(group)),'user_native_memberships_not_effective_'+JSON.stringify({from:membershipFrom,at:activationSession.authority.evaluated_at,groups:activationSession.access_groups,expected:[accessId,ownerGrantId,userManagerGroupId,findingGrantId]}));
  const signed=await api(userPage,'/api/v1/auth/session');
  ensure(signed.status===200&&signed.body.principal_id==='g7-identity-user','linked_oidc_subject_wrong_principal');
  ensure(signed.body.access_groups.includes(accessId)&&signed.body.access_groups.includes(ownerGrantId)&&signed.body.access_groups.includes(userManagerGroupId)&&signed.body.access_groups.includes(findingGrantId),'exact_native_memberships_missing');
  const userAccess=(await api(userPage,'/api/v1/assessment/access-groups')).body;
  ensure(userAccess.items.some(x=>x.access_group_id===accessId),'scoped_access_group_read_denied');
  const deniedContext=await browser.newContext({viewport:{width:1440,height:1000}});
  const deniedManagerPage=await login(deniedContext,'g7-identity-deny-subject');
  await deniedManagerPage.waitForFunction(start=>Date.now()>=Date.parse(start),membershipFrom,{timeout:30000});
  const explicitDeniedAccess=await api(deniedManagerPage,'/api/v1/assessment/access-groups');
  ensure(explicitDeniedAccess.status===403,'explicit_access_group_deny_was_bypassed_by_team_manage_'+explicitDeniedAccess.status);
  const deniedTeams=await api(deniedManagerPage,'/api/v1/assessment/ownership-teams');
  const deniedPicker=await api(deniedManagerPage,`/api/v1/assessment/ownership-teams/${teamId}/principals`);
  ensure(deniedTeams.status===200&&deniedTeams.body.items.some(x=>x.team_id===teamId),'explicit_deny_user_lost_team_read');
  ensure(deniedPicker.status===200&&deniedPicker.body.team_id===teamId,'explicit_deny_user_lost_team_picker');
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'explicit-access-group-deny.json'),JSON.stringify({principal_id:'g7-identity-deny-user',action:'access_group.read',status:explicitDeniedAccess.status,team_read_status:deniedTeams.status,team_picker_status:deniedPicker.status}));
  const userTeams=await api(userPage,'/api/v1/assessment/ownership-teams');
  ensure(userTeams.status===200&&userTeams.body.items.some(x=>x.team_id===teamId&&x.memberships.some(m=>m.principal_id==='g7-identity-user'&&Date.parse(m.effective_until)===Date.parse(effectiveUntil))),'user_ownership_readback_failed');

  const findingViewBeforeResponse=await api(userPage,`/api/v1/assessment/groups/${ownerFindingFixture.group}`);
  ensure(findingViewBeforeResponse.status===200,'owner_fixture_finding_read_failed_'+findingViewBeforeResponse.status);
  let findingView=findingViewBeforeResponse.body;
  const findingMembers=findingView.assessment.clocks.map(clock=>clock.occurrence_id);
  ensure(findingMembers.includes(ownerFindingFixture.occurrence),'owner_fixture_occurrence_missing_from_public_finding_'+JSON.stringify(findingMembers));
  const ownerDirectory=await api(userPage,`/api/v1/assessment/permissions?group_id=${encodeURIComponent(ownerFindingFixture.group)}`);
  ensure(ownerDirectory.status===200&&['g7-identity-user','g7-actor',teamId].every(id=>ownerDirectory.body.owner_directory.some(owner=>owner.owner_id===id)),'stable_owner_directory_ids_missing');
  const ownerEntries=[{owner_id:'g7-identity-user',owner_type:'person'},{owner_id:'g7-actor',owner_type:'person'},{owner_id:teamId,owner_type:'team'}];
  const ownersCommandId=crypto.randomUUID();
  const ownersCommand={command_id:ownersCommandId,target_id:ownerFindingFixture.group,membership_ids:findingMembers,action:'owners.assign',expected_revisions:{target:findingView.assessment.revision,policy:findingView.assessment.policy_revision,identity_membership:findingView.assessment.membership.revision,owners:findingView.assessment.owner_revision},payload:{owners:ownerEntries,rationale:'Retain multiple accountable identities for the local G7 owner portion'}};
  const ownersReceipt=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:ownersCommand});
  ensure(ownersReceipt.status===200&&ownersReceipt.body.command_id===ownersCommandId,'finding_owner_assignment_failed_'+JSON.stringify(ownersReceipt));
  findingView=(await api(userPage,`/api/v1/assessment/groups/${ownerFindingFixture.group}`)).body;
  ensure(ownerEntries.every(owner=>findingView.assessment.owners.some(current=>current.owner_id===owner.owner_id&&current.owner_type===owner.owner_type)),'finding_owner_ids_not_retained_'+JSON.stringify(findingView.assessment.owners));
  const portionId=crypto.randomUUID();
  const portionCommand={command_id:crypto.randomUUID(),target_id:ownerFindingFixture.group,membership_ids:findingMembers,action:'portion.define',expected_revisions:{target:findingView.assessment.revision,policy:findingView.assessment.policy_revision,identity_membership:findingView.assessment.membership.revision,owners:findingView.assessment.owner_revision},payload:{portion_id:portionId,owner_ids:ownerEntries.map(owner=>owner.owner_id),membership_ids:findingMembers,rationale:'Retain the exact finding portion and accountable owner set'}};
  const portionReceipt=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:portionCommand});
  ensure(portionReceipt.status===200,'finding_owner_portion_create_failed_'+JSON.stringify(portionReceipt));
  findingView=(await api(userPage,`/api/v1/assessment/groups/${ownerFindingFixture.group}`)).body;
  const portionBefore=findingView.assessment.portions.find(portion=>portion.portion_id===portionId);
  ensure(portionBefore&&portionBefore.active&&portionBefore.membership_ids.length===findingMembers.length&&ownerEntries.every(owner=>portionBefore.owner_ids.includes(owner.owner_id)),'finding_owner_portion_readback_failed_'+JSON.stringify(portionBefore));
  const ownerAssignmentBefore={finding_group_id:ownerFindingFixture.group,occurrence_ids:findingMembers,policy_revision:findingView.assessment.policy_revision,assessment_revision:findingView.assessment.revision,owner_revision:findingView.assessment.owner_revision,owners:findingView.assessment.owners.map(({owner_id,owner_type})=>({owner_id,owner_type})),portion:{portion_id:portionBefore.portion_id,revision:portionBefore.revision,active:portionBefore.active,owner_ids:portionBefore.owner_ids,membership_ids:portionBefore.membership_ids},team_directory_memberships:team.memberships.map(({principal_id,effective_from,effective_until,enabled,revision})=>({principal_id,effective_from,effective_until,enabled,revision}))};
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'owner-assignment-before-withdrawal.json'),JSON.stringify(ownerAssignmentBefore));
  const findingReadWait=userPage.waitForResponse(response=>new URL(response.url()).pathname===`/api/v1/assessment/groups/${ownerFindingFixture.group}`&&response.request().method()==='GET',{timeout:15000});
  userPage.on('response',async response=>{const url=new URL(response.url());if(url.pathname.includes('/api/v1/assessment/')){try{await (await import('node:fs/promises')).appendFile(path.join(evidence,'finding-ui-api-responses.jsonl'),JSON.stringify({url:url.pathname,status:response.status(),body:await response.json()})+'\n');}catch{}}});
  await userPage.goto(origin+`/#findings?group=${encodeURIComponent(ownerFindingFixture.group)}&section=ownership`,{waitUntil:'domcontentloaded'});
  const renderedFindingResponse=await findingReadWait;
  const renderedFindingBody=await renderedFindingResponse.json();
  ensure(renderedFindingResponse.status()===200&&renderedFindingBody.assessment.owner_revision===ownerAssignmentBefore.owner_revision&&renderedFindingBody.assessment.portions.some(portion=>portion.portion_id===portionId),'current_postwithdrawal_finding_response_did_not_preserve_owner_portion');
  await waitFindingLoaded(userPage,'finding-owner-portion-before-withdrawal-page');
  await userPage.getByRole('button',{name:'Owners & assigned sets'}).click();
  await userPage.locator(`[data-portion-id="${portionId}"]`).waitFor({timeout:10000});
  const renderedOwnerPortion=await userPage.locator('.assessment-workspace').innerText();
  ensure(ownerEntries.every(owner=>renderedOwnerPortion.includes(owner.owner_id))&&renderedOwnerPortion.includes(portionId),'finding_owner_portion_not_rendered');
  await userPage.screenshot({path:path.join(evidence,'finding-owner-portion-before-withdrawal.png'),fullPage:true});
  await userPage.goto(origin+'/#administration?section=ownership-teams',{waitUntil:'domcontentloaded'});
  await userPage.getByRole('button',{name:'G7 Identity Ownership Team'}).waitFor({timeout:10000});
  await userPage.screenshot({path:path.join(evidence,'user-scoped-ownership-before-withdrawal.png'),fullPage:true});
  const captured={policy_revision:signed.body.authority.policy_revision,authority_revision:signed.body.authority.group_revision,issuer:signed.body.authority.issuer,link_id:signed.body.authority.link_id,link_revision:signed.body.authority.link_revision,access_groups:signed.body.access_groups};

  // The access group is soft-disabled; only its permissions disappear. Independent ownership read remains available.
  const c=await current();const all=(await api(adminPage,'/api/v1/assessment/access-groups')).body;const toDisable=all.items.find(x=>x.access_group_id===accessId);
  result=await command('access_group.update',zero,{access_group_id:accessId,display_name:toDisable.display_name,description:toDisable.description,enabled:false,source_scopes:toDisable.source_scopes,permissions:toDisable.permissions},{access_group:toDisable.revision,authority:c.authority_revision});
  ensure(result.status===200,'access_group_withdrawal_failed');
  const afterSession=await api(userPage,'/api/v1/auth/session');
  ensure(afterSession.status===200&&!afterSession.body.access_groups.includes(accessId)&&afterSession.body.access_groups.includes(ownerGrantId)&&afterSession.body.access_groups.includes(userManagerGroupId)&&afterSession.body.access_groups.includes(findingGrantId),'withdrawal_did_not_preserve_unrelated_current_grants');
  const accessAfterWithdrawal=await api(userPage,'/api/v1/assessment/access-groups');
  ensure(accessAfterWithdrawal.status===403,'access_group_directory_read_survived_read_grant_withdrawal_'+accessAfterWithdrawal.status);
  const ownershipStill=await api(userPage,'/api/v1/assessment/ownership-teams');
  ensure(ownershipStill.status===200&&ownershipStill.body.items.some(x=>x.team_id===teamId),'unrelated_ownership_grant_stopped_working');
  const pickerAfterWithdrawal=await api(userPage,`/api/v1/assessment/ownership-teams/${teamId}/principals`);
  ensure(pickerAfterWithdrawal.status===200&&pickerAfterWithdrawal.body.team_id===teamId,'team_picker_failed_after_access_group_withdrawal');
  const freshTeam=ownershipStill.body.items.find(x=>x.team_id===teamId);
  const updateSession=afterSession.body;
  const teamUpdateId=crypto.randomUUID();
  const updatedTeamName='G7 Identity Ownership Team manager readback';
  const teamUpdateBody={command_id:teamUpdateId,target_id:zero,membership_ids:[],action:'ownership.team.update',expected_revisions:{target:ownershipStill.body.policy_revision,policy:ownershipStill.body.policy_revision,authority:updateSession.authority.group_revision,ownership:ownershipStill.body.ownership_revision,team:freshTeam.revision,identity_membership:0,owners:0},payload:{team_id:teamId,display_name:updatedTeamName,rationale:'Prove exact team manager remains available after access group withdrawal',evidence_ref:'g7-identity-team-manager-readback'}};
  const commandCountsSql=`import sys,sqlalchemy as sa,os,json
command_id=sys.argv[1];engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.connect() as c:
 a=c.exec_driver_sql('SELECT count(*) FROM assessment_audit_events WHERE command_id=%s::uuid',(command_id,)).scalar_one()
 r=c.exec_driver_sql('SELECT count(*) FROM assessment_command_receipts WHERE command_id=%s::uuid',(command_id,)).scalar_one()
 i=c.exec_driver_sql('SELECT count(*) FROM administration_reconciliation_intents i JOIN assessment_audit_events a ON a.event_id=i.audit_event_id WHERE a.command_id=%s::uuid',(command_id,)).scalar_one()
 print(json.dumps({'audit':a,'receipt':r,'intent':i}))`;
  const teamUpdateReceipt=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:teamUpdateBody,csrfToken:updateSession.csrf_token});
  ensure(teamUpdateReceipt.status===200&&teamUpdateReceipt.body.command_id===teamUpdateId,'team_manage_write_failed_after_access_group_withdrawal_'+JSON.stringify(teamUpdateReceipt));
  const teamReplay=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:teamUpdateBody,csrfToken:updateSession.csrf_token});
  ensure(teamReplay.status===200&&JSON.stringify(stableJson(teamReplay.body))===JSON.stringify(stableJson(teamUpdateReceipt.body)),'exact_command_replay_changed_receipt');
  const changedReplay=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:{...teamUpdateBody,payload:{...teamUpdateBody.payload,display_name:updatedTeamName+' changed'}},csrfToken:updateSession.csrf_token});
  ensure(changedReplay.status===409,'changed_payload_same_command_id_did_not_conflict_'+changedReplay.status);
  const updatedTeams=await api(userPage,'/api/v1/assessment/ownership-teams');
  const updatedTeam=updatedTeams.body.items.find(x=>x.team_id===teamId);
  ensure(updatedTeam?.display_name===updatedTeamName&&updatedTeam.memberships.some(m=>m.principal_id==='g7-identity-user'&&Date.parse(m.effective_from)===Date.parse(effectiveFrom)&&Date.parse(m.effective_until)===Date.parse(effectiveUntil)),'postwithdrawal_team_readback_changed_owner_membership');
  const teamAudit=updatedTeam.history.find(event=>event.event_id===teamUpdateReceipt.body.audit_event_id);
  ensure(teamAudit&&teamAudit.actor_id==='g7-identity-user'&&teamAudit.after_value.display_name===updatedTeamName&&teamAudit.after_value.revision===teamUpdateReceipt.body.result.object_revision&&updatedTeams.body.policy_revision===teamUpdateReceipt.body.policy_revision&&updatedTeams.body.ownership_revision===teamUpdateReceipt.body.result.ownership_revision&&teamUpdateReceipt.body.result.policy_revision===teamUpdateReceipt.body.policy_revision&&teamUpdateReceipt.body.result.object_id===teamId&&teamUpdateReceipt.body.result.authority_revision===afterSession.body.authority.group_revision,'public_team_audit_history_missing_committed_authority_or_revision');
  const nativeIntent=teamUpdateReceipt.body.intents[0];
  ensure(nativeIntent&&nativeIntent.intent_id===teamUpdateReceipt.body.intent_id&&nativeIntent.kind==='administration.ownership.reconcile'&&nativeIntent.target_id===teamId&&nativeIntent.authority_revision===updatedTeams.body.ownership_revision,'native_team_receipt_missing_exact_intent_or_authority_revision');
  const intentRead=await api(userPage,`/api/v1/assessment/administration/intents/${nativeIntent.intent_id}`);
  ensure(intentRead.status===200&&intentRead.body.kind==='administration.ownership.reconcile'&&intentRead.body.target_id===teamId&&intentRead.body.authority_revision===nativeIntent.authority_revision&&['pending','complete'].includes(intentRead.body.status),'public_native_intent_readback_invalid_'+JSON.stringify(intentRead));
  if(intentRead.body.status==='complete')ensure(intentRead.body.result?.effect==='ownership_projection_refresh'&&intentRead.body.result.team_id===teamId&&intentRead.body.result.team_revision===updatedTeam.revision,'completed_intent_result_does_not_match_team_readback');
  const teamCommandCounts=JSON.parse(databaseProbe(commandCountsSql,teamUpdateId,'',''));
  ensure(JSON.stringify(teamCommandCounts)===JSON.stringify({audit:1,receipt:1,intent:1}),'team_command_receipt_audit_intent_counts_wrong_'+JSON.stringify(teamCommandCounts));
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'team-command-replay-and-intent.json'),JSON.stringify({actor_id:'g7-identity-user',command:teamUpdateBody,first_receipt:teamUpdateReceipt.body,replayed_receipt:teamReplay.body,changed_payload_status:changedReplay.status,public_audit_history:teamAudit,public_intent:intentRead.body,command_rows:teamCommandCounts}));
  const staleCommandId=crypto.randomUUID();
  const staleCommandBody={...teamUpdateBody,command_id:staleCommandId,expected_revisions:{...teamUpdateBody.expected_revisions,target:teamUpdateBody.expected_revisions.target-1,policy:teamUpdateBody.expected_revisions.policy-1},payload:{...teamUpdateBody.payload,display_name:updatedTeamName+' stale attempt'}};
  const staleCommand=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:staleCommandBody,csrfToken:updateSession.csrf_token});
  const staleCommandRows=JSON.parse(databaseProbe(commandCountsSql,staleCommandId,'',''));
  ensure(staleCommand.status===409&&JSON.stringify(staleCommandRows)===JSON.stringify({audit:0,receipt:0,intent:0}),'stale_native_command_committed_or_wrong_status_'+JSON.stringify({status:staleCommand.status,staleCommandRows}));
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'stale-command-rejected.json'),JSON.stringify({actor_id:'g7-identity-user',command:staleCommandBody,status:staleCommand.status,response:staleCommand.body,rows:staleCommandRows}));

  const postWithdrawalFinding=await api(userPage,`/api/v1/assessment/groups/${ownerFindingFixture.group}`);
  ensure(postWithdrawalFinding.status===200,'finding_read_lost_after_access_group_withdrawal');
  const findingViewAfter=postWithdrawalFinding.body;
  const portionAfter=findingViewAfter.assessment.portions.find(portion=>portion.portion_id===portionId);
  ensure(findingViewAfter.assessment.owner_revision===ownerAssignmentBefore.owner_revision&&ownerEntries.every(owner=>findingViewAfter.assessment.owners.some(current=>current.owner_id===owner.owner_id&&current.owner_type===owner.owner_type))&&portionAfter?.active&&JSON.stringify([...portionAfter.owner_ids].sort())===JSON.stringify([...ownerAssignmentBefore.portion.owner_ids].sort())&&JSON.stringify([...portionAfter.membership_ids].sort())===JSON.stringify([...ownerAssignmentBefore.portion.membership_ids].sort()),'finding_ownership_or_portion_changed_after_access_withdrawal');
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'owner-assignment-after-withdrawal.json'),JSON.stringify({finding_group_id:ownerFindingFixture.group,policy_revision:findingViewAfter.assessment.policy_revision,assessment_revision:findingViewAfter.assessment.revision,owner_revision:findingViewAfter.assessment.owner_revision,owners:findingViewAfter.assessment.owners.map(({owner_id,owner_type})=>({owner_id,owner_type})),portion:{portion_id:portionAfter.portion_id,revision:portionAfter.revision,active:portionAfter.active,owner_ids:portionAfter.owner_ids,membership_ids:portionAfter.membership_ids},team_directory_memberships:updatedTeam.memberships.map(({principal_id,effective_from,effective_until,enabled,revision})=>({principal_id,effective_from,effective_until,enabled,revision}))}));
  await userPage.goto(origin+`/#findings?group=${encodeURIComponent(ownerFindingFixture.group)}&section=ownership`,{waitUntil:'domcontentloaded'});
  await waitFindingLoaded(userPage,'finding-owner-portion-after-withdrawal-page');
  await userPage.getByRole('button',{name:'Owners & assigned sets'}).click();
  await userPage.locator(`[data-portion-id="${portionId}"]`).waitFor({timeout:10000});
  const renderedAfterWithdrawal=await userPage.locator('.assessment-workspace').innerText();
  ensure(ownerEntries.every(owner=>renderedAfterWithdrawal.includes(owner.owner_id))&&renderedAfterWithdrawal.includes(portionId)&&renderedAfterWithdrawal.includes(`${findingViewAfter.assessment.revision} / ${findingViewAfter.assessment.policy_revision} / ${findingViewAfter.assessment.owner_revision}`),'finding_owner_portion_or_current_revisions_not_rendered_after_withdrawal');
  await userPage.screenshot({path:path.join(evidence,'finding-owner-portion-after-withdrawal.png'),fullPage:true});

  const teamResponseWait=userPage.waitForResponse(response=>new URL(response.url()).pathname==='/api/v1/assessment/ownership-teams'&&response.request().method()==='GET',{timeout:15000});
  await userPage.goto(origin+'/#administration?section=ownership-teams',{waitUntil:'domcontentloaded'});
  const currentTeamResponse=await teamResponseWait;
  const currentTeamUIRead=await currentTeamResponse.json();
  ensure(currentTeamUIRead.policy_revision===updatedTeams.body.policy_revision&&currentTeamUIRead.ownership_revision===updatedTeams.body.ownership_revision,'postwithdrawal_UI_used_stale_ownership_response');
  await userPage.getByRole('button',{name:updatedTeamName,exact:true}).click();
  const teamDetail=await userPage.locator('dialog').innerText();
  const formatUTC=value=>new Date(value).toLocaleString('en-GB',{timeZone:'UTC',dateStyle:'medium',timeStyle:'short'})+' UTC';
  ensure(teamDetail.includes(teamId)&&teamDetail.includes('Revision '+updatedTeam.revision)&&teamDetail.includes('g7-identity-user')&&teamDetail.includes(formatUTC(effectiveFrom))&&teamDetail.includes(formatUTC(effectiveUntil)),'postwithdrawal_team_detail_ID_period_revision_missing_'+teamDetail);
  await userPage.screenshot({path:path.join(evidence,'user-scoped-ownership-after-withdrawal.png'),fullPage:true});

  const explicitDeniedAfter=await api(deniedManagerPage,'/api/v1/assessment/access-groups');
  const deniedTeamAfter=await api(deniedManagerPage,'/api/v1/assessment/ownership-teams');
  const deniedPickerAfter=await api(deniedManagerPage,`/api/v1/assessment/ownership-teams/${teamId}/principals`);
  ensure(explicitDeniedAfter.status===403&&deniedTeamAfter.status===200&&deniedPickerAfter.status===200,'explicit_deny_or_dedicated_team_scope_changed_after_withdrawal');

  const managerGroupNow=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(group=>group.access_group_id===userManagerGroupId);
  const revocationCatalogue=await current();
  const revocationCommandId=crypto.randomUUID();
  const queuedWriterCommandId=crypto.randomUUID();
  const revocationBody={command_id:revocationCommandId,target_id:zero,membership_ids:[],action:'access_group.update',expected_revisions:{target:revocationCatalogue.policy_revision,policy:revocationCatalogue.policy_revision,authority:revocationCatalogue.authority_revision,ownership:revocationCatalogue.ownership_revision,access_group:managerGroupNow.revision,identity_membership:0,owners:0},payload:{access_group_id:userManagerGroupId,display_name:managerGroupNow.display_name,description:managerGroupNow.description,enabled:false,source_scopes:managerGroupNow.source_scopes,permissions:managerGroupNow.permissions,rationale:'Revoke the exact user team-management grant at the public command boundary',evidence_ref:'g7-identity-revocation-race'}};
  const raceUserSession=(await api(userPage,'/api/v1/auth/session')).body;
  const queuedWriterBody={command_id:queuedWriterCommandId,target_id:zero,membership_ids:[],action:'ownership.team.update',expected_revisions:{target:updatedTeams.body.policy_revision,policy:updatedTeams.body.policy_revision,authority:raceUserSession.authority.group_revision,ownership:updatedTeams.body.ownership_revision,team:updatedTeam.revision,identity_membership:0,owners:0},payload:{team_id:teamId,display_name:'Must not commit after manager-grant revocation',rationale:'Queue authorized write behind exact grant revocation',evidence_ref:'g7-identity-revocation-race'}};
  await Promise.all([adminPage.close(),userPage.close(),deniedManagerPage.close()]);
  adminPage=await admin.newPage();userPage=await user.newPage();
  await Promise.all([adminPage.goto(origin+'/api/v1/auth/session',{waitUntil:'domcontentloaded'}),userPage.goto(origin+'/api/v1/auth/session',{waitUntil:'domcontentloaded'})]);
  const revocationLockKey=1731202029;
  const revocationSuffix=revocationCommandId.replaceAll('-','').slice(0,18);
  const revocationTrigger='g7_revocation_hold_'+revocationSuffix;
  const revocationFunction='g7_revocation_hold_fn_'+revocationSuffix;
  const holderPidPath=`/tmp/${revocationTrigger}.pid`;
  const holderProgram=`import os,sys,signal,sqlalchemy as sa
engine=sa.create_engine(os.environ['UVM_DB_URL']);connection=engine.connect();connection.exec_driver_sql('SELECT pg_advisory_lock(%s)',(int(sys.argv[1]),));open(sys.argv[2],'w').write(str(os.getpid()));signal.pause();connection.close()`;
  execFileSync('docker',['exec','-d',appContainer,'bash','-lc','export UVM_DB_URL="postgresql+psycopg://uvm_app:$(cat /run/secrets/uvm_db_password)@127.0.0.1:5432/uvm"; exec /opt/uvm/venv/bin/python -c "$1" "$2" "$3" "$4" "$5" "$6" "$7"','g7-revocation-lock-holder',holderProgram,String(revocationLockKey),holderPidPath],{encoding:'utf8',timeout:15000});
  const probeUntil=async(sql,accept,timeoutMs=30000,...args)=>{const deadline=Date.now()+timeoutMs;let last=null;while(Date.now()<deadline){last=JSON.parse(databaseProbe(sql,...args));if(accept(last))return last;await new Promise(resolve=>setImmediate(resolve));}throw new Error('revocation_lock_barrier_timeout_'+JSON.stringify(last));};
  const advisoryHeldSql=`import sys,sqlalchemy as sa,os,json
key=int(sys.argv[1]);engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.connect() as c:
 acquired=c.exec_driver_sql('SELECT pg_try_advisory_lock(%s)',(key,)).scalar_one()
 if acquired:c.exec_driver_sql('SELECT pg_advisory_unlock(%s)',(key,))
 print(json.dumps({'held_by_holder':not acquired,'key':key}))`;
  await probeUntil(advisoryHeldSql,value=>value.held_by_holder,30000,String(revocationLockKey));
  const installRevocationBarrierSql=`import sys,sqlalchemy as sa,os,json
command_id,lock_key,trigger,fn=sys.argv[1:5];engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.begin() as c:
 c.exec_driver_sql(f"CREATE OR REPLACE FUNCTION public.{fn}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({int(lock_key)}); RETURN NEW; END $$")
 c.exec_driver_sql(f"CREATE TRIGGER {trigger} BEFORE INSERT ON public.assessment_audit_events FOR EACH ROW WHEN (NEW.command_id = '{command_id}'::uuid) EXECUTE FUNCTION public.{fn}()")
print(json.dumps({'command_id':command_id,'trigger':trigger,'function':fn,'lock_key':int(lock_key)}))`;
  databaseProbe(installRevocationBarrierSql,revocationCommandId,String(revocationLockKey),revocationTrigger,revocationFunction);
  const revokerWaitSql=`import sys,sqlalchemy as sa,os,json
key=int(sys.argv[1]);application_name=sys.argv[2];engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.connect() as c:
 rows=c.exec_driver_sql("SELECT a.pid,a.datname,a.application_name,a.state,a.wait_event_type,a.wait_event,a.query,l.locktype,l.classid,l.objid,l.objsubid,l.granted FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() AND a.usename=current_user AND a.application_name=%s AND l.locktype='advisory' AND l.granted=false AND l.objsubid=1 AND l.classid=0 AND l.objid=%s",(application_name,key)).mappings().all()
 print(json.dumps({'lock_key':key,'waiters':[dict(row) for row in rows]},default=str))`;
  const adminSession=(await api(adminPage,'/api/v1/auth/session')).body;
  let revocationPromise,queuedWriterPromise,revocationRaceProof;
  let revocationHolderPid=null;
  const removeBarrierSql=`import sys,sqlalchemy as sa,os
trigger,fn=sys.argv[1:3];engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.begin() as c:c.exec_driver_sql(f"DROP TRIGGER IF EXISTS {trigger} ON public.assessment_audit_events");c.exec_driver_sql(f"DROP FUNCTION IF EXISTS public.{fn}()")`;
  const exactWaiterSql=`import sys,sqlalchemy as sa,os,json
blocker=int(sys.argv[1]);application_name=sys.argv[2];engine=sa.create_engine(os.environ['UVM_DB_URL'])
with engine.connect() as c:
 rows=c.exec_driver_sql("SELECT a.pid,a.datname,a.application_name,a.state,a.wait_event_type,a.wait_event,a.query,pg_blocking_pids(a.pid) AS blockers FROM pg_stat_activity a WHERE a.datname=current_database() AND a.usename=current_user AND a.application_name=%s AND a.pid<>pg_backend_pid() AND a.state='active' AND a.wait_event_type='Lock' AND %s=ANY(pg_blocking_pids(a.pid))",(application_name,blocker)).mappings().all()
 lock_rows=[]
 for row in rows:
  lock_rows.extend([dict(item) for item in c.exec_driver_sql("SELECT locktype,database,relation,page,tuple,virtualxid,transactionid,classid,objid,objsubid,mode,granted FROM pg_locks WHERE pid=%s",(row['pid'],)).mappings().all()])
 print(json.dumps({'blocker_pid':blocker,'waiters':[dict(row) for row in rows],'waiter_locks':lock_rows},default=str))`;
  try{
    revocationPromise=api(adminPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:revocationBody,csrfToken:adminSession.csrf_token,barrierCommandId:revocationCommandId});
    const revokerBarrier=await probeUntil(revokerWaitSql,value=>value.waiters.length===1,30000,String(revocationLockKey),'g7cmd:'+revocationCommandId);
    const revoker=revokerBarrier.waiters[0];revocationHolderPid=Number(execFileSync('docker',['exec',appContainer,'cat',holderPidPath],{encoding:'utf8'}).trim());
    ensure(revoker.query.includes('assessment_audit_events')&&revoker.wait_event==='advisory','revocation_command_not_held_at_target_audit_barrier_'+JSON.stringify(revoker));
    const policyLockQueueBaseline=JSON.parse(databaseProbe(exactWaiterSql,String(revoker.pid),'g7cmd:'+queuedWriterCommandId));
    ensure(policyLockQueueBaseline.waiters.length===0,'new_command_id_had_preexisting_database_waiters_'+JSON.stringify(policyLockQueueBaseline));
    let observedWriterRequest={method:'POST',path:'/api/v1/assessment/commands',command_id:queuedWriterCommandId,action:queuedWriterBody.action,body:queuedWriterBody,actor_principal_id:raceUserSession.principal_id,source:'the immediately following browser fetch; baseline showed no lock waiters for the revoker backend'};
    userPage.on('request',request=>{if(request.method()==='POST'&&new URL(request.url()).pathname==='/api/v1/assessment/commands'){
      try{const body=request.postDataJSON();if(body.command_id===queuedWriterCommandId)observedWriterRequest={method:request.method(),path:new URL(request.url()).pathname,command_id:body.command_id,action:body.action,body};}catch{}
    }});
    queuedWriterPromise=api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:queuedWriterBody,csrfToken:raceUserSession.csrf_token,barrierCommandId:queuedWriterCommandId});
    const userWriterOrEarlyResponse=await Promise.race([probeUntil(exactWaiterSql,value=>value.waiters.length===1,30000,String(revoker.pid),'g7cmd:'+queuedWriterCommandId).then(barrier=>({barrier})),queuedWriterPromise.then(response=>({response}))]);
    ensure(userWriterOrEarlyResponse.barrier,'authorized_user_post_returned_before_lock_wait_'+JSON.stringify(userWriterOrEarlyResponse.response));
    const userWriterBarrier=userWriterOrEarlyResponse.barrier;
    const waiter=userWriterBarrier.waiters[0];
    ensure(userWriterBarrier.waiters.length===1&&waiter.application_name==='g7cmd:'+queuedWriterCommandId&&observedWriterRequest?.command_id===queuedWriterCommandId&&waiter.blockers.map(Number).includes(Number(revoker.pid))&&waiter.datname&&waiter.wait_event_type==='Lock'&&waiter.query.includes('pg_advisory_xact_lock')&&userWriterBarrier.waiter_locks.some(lock=>lock.locktype==='advisory'&&Number(lock.classid)===5592653&&Number(lock.objid)===4673587&&!lock.granted),'authorized_user_post_not_queued_behind_revocation_'+JSON.stringify({observedWriterRequest,revoker,waiter,userWriterBarrier}));
    revocationRaceProof={environment:'local-labelled-fake-oidc-container',revocation_actor:'g7-actor',revocation_command_id:revocationCommandId,revoked_access_group_id:userManagerGroupId,queued_actor:'g7-identity-user',queued_subject:'g7-identity-user-subject',queued_request_id:queuedWriterCommandId,queued_request:observedWriterRequest,barrier:{advisory_lock_key:revocationLockKey,revoker_backend:revoker,queued_writer_backend:waiter,queued_writer_locks:userWriterBarrier.waiter_locks,policy_lock_queue_baseline:policyLockQueueBaseline},effective_linearization:'the grant revocation transaction commits before the queued writer can acquire assessment_policy row lock'};
    await (await import('node:fs/promises')).writeFile(path.join(evidence,'revocation-race-barrier.json'),JSON.stringify(revocationRaceProof));
    execFileSync('docker',['exec',appContainer,'kill','-TERM',String(revocationHolderPid)],{encoding:'utf8',timeout:15000});revocationHolderPid=null;
    const [revocationResult,queuedWriterResult]=await Promise.all([revocationPromise,queuedWriterPromise]);
    const revocationCounts=JSON.parse(databaseProbe(commandCountsSql,revocationCommandId,'',''));
    const queuedWriterCounts=JSON.parse(databaseProbe(commandCountsSql,queuedWriterCommandId,'',''));
    const teamAfterQueuedWriter=(await api(userPage,'/api/v1/assessment/ownership-teams')).body.items.find(item=>item.team_id===teamId);
    ensure(revocationResult.status===200&&(queuedWriterResult.status===403||queuedWriterResult.status===409)&&teamAfterQueuedWriter.display_name===updatedTeamName&&JSON.stringify(queuedWriterCounts)===JSON.stringify({audit:0,receipt:0,intent:0})&&JSON.stringify(revocationCounts)===JSON.stringify({audit:1,receipt:1,intent:1}),'revocation_race_commit_or_no_effect_assertion_failed_'+JSON.stringify({revocation_status:revocationResult.status,queued_writer_status:queuedWriterResult.status,revocationCounts,queuedWriterCounts,team_name:teamAfterQueuedWriter.display_name}));
    const revokedManagerRead=(await api(adminPage,'/api/v1/assessment/access-groups')).body.items.find(item=>item.access_group_id===userManagerGroupId);
    ensure(revokedManagerRead&&!revokedManagerRead.enabled,'revoked_manager_group_not_publicly_read_back_disabled');
    const revocationIntent=revocationResult.body.intents[0];
    const revocationIntentRead=await api(adminPage,`/api/v1/assessment/administration/intents/${revocationIntent.intent_id}`);
    ensure(revocationIntentRead.status===200&&revocationIntentRead.body.target_id===userManagerGroupId&&revocationIntentRead.body.kind===revocationIntent.kind,'revocation_intent_public_readback_mismatch');
    const replayAfterGrantRemoval=await api(userPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:teamUpdateBody,csrfToken:raceUserSession.csrf_token});
    const teamCountsAfterDeniedReplay=JSON.parse(databaseProbe(commandCountsSql,teamUpdateId,'',''));
    ensure(replayAfterGrantRemoval.status===403&&JSON.stringify(teamCountsAfterDeniedReplay)===JSON.stringify({audit:1,receipt:1,intent:1}),'replay_not_denied_after_current_write_grant_removal_'+JSON.stringify({status:replayAfterGrantRemoval.status,teamCountsAfterDeniedReplay}));
    revocationRaceProof={...revocationRaceProof,revocation_status:revocationResult.status,revocation_receipt:revocationResult.body,revocation_intent_readback:revocationIntentRead.body,queued_writer_status:queuedWriterResult.status,queued_writer_response:queuedWriterResult.body,revocation_command_rows:revocationCounts,queued_command_rows:queuedWriterCounts,team_after_queued_writer:teamAfterQueuedWriter,replay_after_write_grant_removal_status:replayAfterGrantRemoval.status,original_receipt_rows_after_denied_replay:teamCountsAfterDeniedReplay};
    await (await import('node:fs/promises')).writeFile(path.join(evidence,'revocation-race-barrier.json'),JSON.stringify(revocationRaceProof));
  } finally {
    if(revocationHolderPid!==null){try{execFileSync('docker',['exec',appContainer,'kill','-TERM',String(revocationHolderPid)],{encoding:'utf8',timeout:15000});}catch{}}
    try{databaseProbe(removeBarrierSql,revocationTrigger,revocationFunction,'','');}catch{}
  }

  const operatorHeaders={'Authorization':'Bearer '+operatorSecret,'Content-Type':'application/json'};
  const revoked=await fetch(origin+'/api/v1/auth/operator/links/'+encodeURIComponent(captured.link_id)+'/revoke',{method:'POST',headers:operatorHeaders,body:JSON.stringify({expected_revision:captured.link_revision,rationale:'Revoke disposable G7 identity link',evidence_ref:'g7-identity-link-revocation'})});
  ensure(revoked.status===200,'subject_link_revocation_failed');
  const oldSession=await api(userPage,'/api/v1/auth/session');ensure(oldSession.status===401,'old_session_survived_subject_link_revocation');
  const relogin=await login(user,'g7-identity-user-subject',true);ensure(relogin.denial.session_status===401,'revoked_subject_signed_in_again');
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'link-revoked-login-denial.json'),JSON.stringify(relogin.denial));
  await relogin.page.close();
  const relink=await fetch(origin+'/api/v1/auth/operator/links',{method:'POST',headers:operatorHeaders,body:JSON.stringify({issuer:captured.issuer,subject:'g7-identity-user-subject',principal_id:'g7-identity-user',display_label:'Synthetic G7 Identity User',rationale:'Relink for separate account revocation proof',evidence_ref:'g7-identity-account-revocation'})});
  ensure(relink.status===200,'subject_relink_for_account_revocation_failed');
  const accountContext=await browser.newContext();const accountPage=await login(accountContext,'g7-identity-user-subject');
  const beforeDisable=await api(adminPage,'/api/v1/assessment/administration/catalogue');
  const disable=await api(adminPage,'/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,action:'principal.update',membership_ids:[],expected_revisions:{target:beforeDisable.body.policy_revision,policy:beforeDisable.body.policy_revision,authority:beforeDisable.body.authority_revision,identity_membership:0,owners:0},payload:{principal_id:'g7-identity-user',enabled:false,rationale:'Revoke disposable G7 account access'}}});
  ensure(disable.status===200,'account_revocation_failed');
  const disabledSession=await api(accountPage,'/api/v1/auth/session');ensure(disabledSession.status===401,'old_session_survived_account_revocation');
  const accountRelogin=await login(accountContext,'g7-identity-user-subject',true);ensure(accountRelogin.denial.session_status===401,'disabled_account_signed_in_again');
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'account-disabled-login-denial.json'),JSON.stringify(accountRelogin.denial));
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
  await adminPage.screenshot({path:path.join(evidence,'admin-access-withdrawal.png'),fullPage:true});
  console.log(JSON.stringify({environment:'local-labelled-fake-oidc-container',principal:'g7-identity-user',persistence_failures:failureResults.map(x=>({mode:x.mode,status:x.status,rollback:true})),policy_revision_before:captured.policy_revision,authority_revision_before:captured.authority_revision,withdrawn_access_group:accessId,remaining_groups:[ownerGrantId,userManagerGroupId],access_groups_after_withdrawal_status:accessAfterWithdrawal.status,ownership_after_withdrawal_status:ownershipStill.status,stale_command_status:staleCommand.status,revocation_race:revocationRaceProof,old_session_after_link_revocation:oldSession.status,new_signin_after_link_revocation:'denied',old_session_after_account_revocation:disabledSession.status,new_signin_after_account_revocation:'denied',ownership:{team_id:teamId,effective_from:effectiveFrom,effective_until:effectiveUntil}}));
} finally {await browser.close();}
