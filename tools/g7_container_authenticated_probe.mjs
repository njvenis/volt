import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import process from 'node:process';
import crypto from 'node:crypto';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`);return process.argv[i+1];}
const origin=arg('--origin'), evidence=arg('--evidence'), fixtureRoot=arg('--fixture-root'), phase=arg('--phase');
if(!['before','after'].includes(phase))throw new Error('phase must be before or after');
await mkdir(evidence,{recursive:true,mode:0o700});
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH??'/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome'});
const zero='00000000-0000-4000-8000-000000000000';
function ensure(ok,label){if(!ok)throw new Error(label);}
function stable(value){if(Array.isArray(value))return value.map(stable);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])]));return value;}
async function login(context,subject){
  const page=await context.newPage();
  if(subject!=='g7-actor-subject') await context.route('**/api/v1/auth/login',async route=>{
    const response=await route.fetch({maxRedirects:0});const headers=response.headers();
    const url=new URL(headers.location);url.searchParams.set('fixture_subject',subject);
    await route.fulfill({response,headers:{...headers,location:url.toString()}});
  });
  await page.goto(origin+'/api/v1/auth/login',{waitUntil:'domcontentloaded',timeout:30000});
  await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session');if(!r.ok)return false;return (await r.json()).authenticated===true;},null,{timeout:25000});
  const response=await page.evaluate(async()=>{const r=await fetch('/api/v1/auth/session',{cache:'no-store'});return {status:r.status,body:await r.json()};});
  ensure(response.body.credential_mode==='oidc_session'&&response.body.authority?.subject===subject,
    `unexpected OIDC principal ${JSON.stringify({status:response.status,principal:response.body.principal_id,subject:response.body.authority?.subject,credential_mode:response.body.credential_mode})}`);
  return {page,response};
}
async function api(page,path,options={}){
  return page.evaluate(async({path,options})=>{
    const session=await(await fetch('/api/v1/auth/session',{cache:'no-store'})).json();
    const response=await fetch(path,{credentials:'same-origin',cache:'no-store',...options,
      headers:{Accept:'application/json',...(options.body?{'Content-Type':'application/json'}:{}),
        ...(options.write?{'X-CSRF-Token':session.csrf_token}:{}),...(options.headers??{})}});
    let body;try{body=await response.json();}catch{body=null;}return{status:response.status,body};
  },{path,options});
}
const adminContext=await browser.newContext(),allowedContext=await browser.newContext(),deniedContext=await browser.newContext();
try{
  const admin=await login(adminContext,'g7-actor-subject');
  const beforePath=`${evidence}/container-auth-before.json`;
  const afterPath=`${evidence}/container-auth-after.json`;
  let groupId,expected;
  if(phase==='before'){
    const deniedPrincipal='g7-identity-deny-user';
    const bootstrapBody={policy:{grants:[],
      denies:[{deny_id:'g7-container-explicit-reader-deny',principal_id:deniedPrincipal,
        actions:['access_group.read'],target_ids:['*']}],
      owner_directory:[{owner_id:'g7-actor',owner_type:'person',display_name:'Synthetic G7 Operator',enabled:true},
        {owner_id:'g7-identity-user',owner_type:'person',display_name:'Synthetic G7 Identity User',enabled:true},
        {owner_id:deniedPrincipal,owner_type:'person',display_name:'Synthetic G7 Denied User',enabled:true}],
      acceptance_material_changes:{},exception_warning_routes:[]}};
    const bootstrap=await api(admin.page,'/api/v1/assessment/bootstrap-policy',
      {method:'POST',write:true,body:JSON.stringify(bootstrapBody)});
    ensure([200,409].includes(bootstrap.status),`native_policy_bootstrap_denied_${bootstrap.status}`);
    let catalogue=(await api(admin.page,'/api/v1/assessment/administration/catalogue')).body;
    if(catalogue.authority_mode==='legacy'){
      const activateBody={command_id:crypto.randomUUID(),target_id:zero,action:'native.authority.activate',
        membership_ids:[],expected_revisions:{target:catalogue.policy_revision,policy:catalogue.policy_revision,
          authority:catalogue.authority_revision,identity_membership:0,owners:0},
        payload:{mapping_revision:1,rationale:'Activate bounded fake-OIDC container boundary grant',
          evidence_ref:'g7-container-boundary-auth-fixture'}};
      const activate=await api(admin.page,'/api/v1/assessment/commands',
        {method:'POST',write:true,body:JSON.stringify(activateBody)});
      ensure(activate.status===200,`native_authority_activation_denied_${activate.status}`);
      catalogue=(await api(admin.page,'/api/v1/assessment/administration/catalogue')).body;
    }
    const grant=catalogue.caller?.grantable;
    ensure(grant?.actions?.includes('access_group.read')&&grant.source_scopes?.some(scope=>scope.source_family==='local'&&scope.source_account_id==='g7-local'&&scope.scope_key==='all'),
      'current_bootstrap_grant_does_not_allow_local_access_group_read');
    const groupSource={source_family:'local',source_account_id:'g7-local',scope_key:'all'};
    groupId=crypto.randomUUID();
    const command={command_id:crypto.randomUUID(),target_id:zero,membership_ids:[],action:'access_group.create',expected_revisions:{target:catalogue.policy_revision,policy:catalogue.policy_revision,authority:catalogue.authority_revision,ownership:catalogue.ownership_revision,identity_membership:0,owners:0},payload:{access_group_id:groupId,display_name:'G7 Container Boundary Reader',description:'Exact local disposable ingress acceptance grant',enabled:true,source_scopes:[groupSource],permissions:[{permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action:'access_group.read',target_scope:{group_ids:[groupId],source_families:['local'],environments:[],service_ids:[],membership_mode:'explicit'},limits:grant.limits,separation_of_duties:grant.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,required_approver_count:1,prohibited_action_pairs:[]}}],rationale:'Grant a synthetic local identity exact read access for G7 container boundary proof',evidence_ref:'g7-container-boundary-auth-fixture'}};
    const created=await api(admin.page,'/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify(command)});
    ensure(created.status===200,`public_native_access_group_create_failed_${created.status}_${JSON.stringify(created.body)}`);
    const listed=(await api(admin.page,'/api/v1/assessment/access-groups')).body;
    const createdGroup=listed.items?.find(item=>item.access_group_id===groupId);
    ensure(createdGroup,'created_reader_grant_not_in_public_readback');
    const session=admin.response.body;
    const start=new Date(Date.parse(session.authority.evaluated_at)+1500).toISOString();
    const currentCatalogue=(await api(admin.page,'/api/v1/assessment/administration/catalogue')).body;
    const membershipCommand={command_id:crypto.randomUUID(),target_id:zero,membership_ids:[],action:'access_group.membership.set',expected_revisions:{target:currentCatalogue.policy_revision,policy:currentCatalogue.policy_revision,authority:currentCatalogue.authority_revision,ownership:currentCatalogue.ownership_revision,identity_membership:0,owners:0,access_group:createdGroup.revision},payload:{access_group_id:groupId,principal_id:'g7-identity-user',effective_from:start,enabled:true,rationale:'Grant the fake OIDC user the exact local reader role',evidence_ref:'g7-container-boundary-auth-fixture'}};
    const member=await api(admin.page,'/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify(membershipCommand)});
    ensure(member.status===200,`public_reader_membership_create_failed_${member.status}_${JSON.stringify(member.body)}`);
    await admin.page.waitForTimeout(1800);
  }else{
    const prior=JSON.parse(await readFile(beforePath,'utf8'));groupId=prior.group_id;expected=prior.expected_group;
  }
  const allowed=await login(allowedContext,'g7-identity-user-subject');
  ensure(allowed.response.body.principal_id==='g7-identity-user','OIDC_authorized_principal_id_mismatch');
  const allowedRead=await api(allowed.page,'/api/v1/assessment/access-groups');
  ensure(allowedRead.status===200,`authenticated_granted_public_read_denied_${allowedRead.status}_${JSON.stringify(allowedRead.body)}`);
  const groups=allowedRead.body.items?.filter(item=>item.access_group_id===groupId)??[];
  ensure(groups.length===1,`exact_granted_group_missing_or_duplicated_${groups.length}`);
  const group=groups[0];
  const normalized={access_group_id:group.access_group_id,display_name:group.display_name,enabled:group.enabled,
    revision:group.revision,source_scopes:group.source_scopes,permissions:group.permissions.map(permission=>({action:permission.action,target_scope:permission.target_scope})),
    memberships:group.memberships.map(member=>({principal_id:member.principal_id,enabled:member.enabled,effective_from:member.effective_from}))};
  if(phase==='before'){
    expected=normalized;
    const capture={phase,environment:'local fake OIDC container',principal_id:allowed.response.body.principal_id,
      subject:allowed.response.body.authority.subject,credential_mode:allowed.response.body.credential_mode,
      authenticated:true,route:'/api/v1/assessment/access-groups',status:allowedRead.status,group_id:groupId,expected_group:expected};
    await writeFile(beforePath,JSON.stringify(capture)+'\n',{mode:0o600});
  }else{
    ensure(JSON.stringify(stable(normalized))===JSON.stringify(stable(expected)),'authorized_public_group_readback_changed_across_replacement');
    const capture={phase,environment:'local fake OIDC container',principal_id:allowed.response.body.principal_id,
      subject:allowed.response.body.authority.subject,credential_mode:allowed.response.body.credential_mode,
      authenticated:true,route:'/api/v1/assessment/access-groups',status:allowedRead.status,group_id:groupId,expected_group:expected};
    await writeFile(afterPath,JSON.stringify(capture)+'\n',{mode:0o600});
  }
  const denied=await login(deniedContext,'g7-identity-deny-subject');
  ensure(denied.response.body.principal_id==='g7-identity-deny-user','OIDC_denied_principal_id_mismatch');
  const deniedRead=await api(denied.page,'/api/v1/assessment/access-groups');
  ensure(deniedRead.status===403&&deniedRead.body?.error?.code==='forbidden',
    `authenticated_ungranted_public_read_not_denied_by_authority_${deniedRead.status}_${JSON.stringify(deniedRead.body)}`);
  const negative={phase,principal_id:denied.response.body.principal_id,subject:denied.response.body.authority.subject,
    authenticated:true,credential_mode:denied.response.body.credential_mode,route:'/api/v1/assessment/access-groups',
    status:deniedRead.status,error_code:deniedRead.body.error.code};
  await writeFile(`${evidence}/container-auth-${phase}-denied.json`,JSON.stringify(negative)+'\n',{mode:0o600});
  await adminContext.close();await allowedContext.close();await deniedContext.close();
  await browser.close();
  console.log(JSON.stringify({phase,authorized:{principal_id:allowed.response.body.principal_id,subject:allowed.response.body.authority.subject,status:allowedRead.status,group_id:groupId},unauthorized:{principal_id:denied.response.body.principal_id,status:deniedRead.status,error_code:deniedRead.body.error.code}}));
}catch(error){await browser.close();throw error;}
