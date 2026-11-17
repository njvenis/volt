import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import process from 'node:process';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {requireAdminRendered,requireAudit,requirePersistedState,requireReceipt,requireSession} from './g7_local_preview_smoke_checks.mjs';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`);return process.argv[i+1];}
const origin=arg('--origin'), issuer=arg('--issuer'), subject=arg('--subject'), principal=arg('--principal'), evidence=arg('--evidence');
const deploymentLabel=process.argv.includes('--deployment-label')?arg('--deployment-label'):'Synthetic local demo';
const readbackOnly=process.argv.includes('--readback');
const verifyProviderRevocation=process.argv.includes('--verify-provider-revocation');
const username=arg('--username'), password=await readFile(arg('--password-file'),'utf8');
await mkdir(evidence,{recursive:true,mode:0o700});
const launchOptions={headless:true};
if(process.env.CHROMIUM_EXECUTABLE_PATH)launchOptions.executablePath=process.env.CHROMIUM_EXECUTABLE_PATH;
if(process.env.VOLT_SMOKE_HOST_RESOLVER_RULES)launchOptions.args=[`--host-resolver-rules=${process.env.VOLT_SMOKE_HOST_RESOLVER_RULES}`];
const browser=await chromium.launch(launchOptions);
const context=await browser.newContext({ignoreHTTPSErrors:true});
const page=await context.newPage();
const zero='00000000-0000-4000-8000-000000000000';
function ensure(ok,label){if(!ok)throw new Error(label);}
async function api(path,{method='GET',body,write=false}={}){
  return page.evaluate(async({path,method,body,write})=>{
    const session=write?await(await fetch('/api/v1/auth/session',{cache:'no-store'})).json():null;
    const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{}),...(write?{'X-CSRF-Token':session.csrf_token}:{})},...(body?{body:JSON.stringify(body)}:{})});
    let value=null;try{value=await response.json();}catch{}return{status:response.status,body:value};
  },{path,method,body,write});
}
async function waitAdminReady(){
  const heading=page.getByText('Access groups grant actions',{exact:true});
  const create=page.getByRole('button',{name:'Create access group',exact:true});
  await heading.waitFor({state:'visible',timeout:30000});
  await create.waitFor({state:'visible',timeout:30000});
  requireAdminRendered({loading:false,error:null,headingVisible:await heading.isVisible(),createButtonVisible:await create.isVisible(),createButtonEnabled:!(await create.isDisabled())});
  return create;
}
async function cardFor(groupId,revision){
  const card=page.locator('section[aria-label="Access group records"] article').filter({hasText:'Local preview audit smoke'});
  await card.waitFor({state:'visible',timeout:30000});
  const text=await card.innerText();
  ensure(text.includes(groupId)&&new RegExp(`Revision\\s+${revision}(?:\\D|$)`).test(text),'rendered_admin_object_mismatch');
  return card;
}
try{
  await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});
  await page.getByText(deploymentLabel,{exact:true}).waitFor({state:'visible',timeout:10000});
  await page.getByRole('link',{name:/sign in/i}).click({timeout:10000});
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button',{name:'Sign in'}).click();
  await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session',{cache:'no-store'});if(!r.ok)return false;return (await r.json()).authenticated===true;},null,{timeout:30000});
  const session=(await api('/api/v1/auth/session')).body;
  requireSession(session,{issuer,subject,principal});
  if(process.argv.includes('--initialize-development')){
    const bootstrap=await api('/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,body:{policy:{grants:[],denies:[],owner_directory:[{owner_id:principal,owner_type:'person',display_name:'Synthetic Local Preview Administrator',enabled:true}],acceptance_material_changes:{},exception_warning_routes:[]}}});
    ensure([200,409].includes(bootstrap.status),`initial_policy_bootstrap_failed_${bootstrap.status}`);
    let catalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    ensure(catalogue.caller?.principal_id===principal,'bootstrap_administrator_not_authorised');
    if(catalogue.authority_mode==='legacy'){
      const activation=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,membership_ids:[],action:'native.authority.activate',expected_revisions:{target:catalogue.policy_revision,policy:catalogue.policy_revision,authority:catalogue.authority_revision,identity_membership:0,owners:0},payload:{mapping_revision:1,rationale:'Activate native authority for the private synthetic local preview',evidence_ref:'local-preview-bootstrap'}}});
      ensure(activation.status===200,`native_authority_activation_failed_${activation.status}`);
    }
  }
  let saved,createReceipt,membershipReceipt;
  if(!readbackOnly){
    await page.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
    const createButton=await waitAdminReady();
    await page.screenshot({path:`${evidence}/admin-initial.png`,fullPage:true});
    const latestCatalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    const envelope=latestCatalogue.caller?.grantable;
    ensure(latestCatalogue.authority_mode==='uvm_native_v1'&&latestCatalogue.caller?.principal_id===principal,'native_admin_catalogue_identity_or_mode_mismatch');
    ensure(envelope?.actions?.includes('access_group.read'),'local_bootstrap_action_envelope_missing');
    const groupId=crypto.randomUUID(), commandId=crypto.randomUUID(), permissionId=crypto.randomUUID();
    const roleId='00000000-0000-4000-8000-000000000002';
    const created=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:commandId,target_id:zero,membership_ids:[],action:'access_group.create',expected_revisions:{target:latestCatalogue.policy_revision,policy:latestCatalogue.policy_revision,authority:latestCatalogue.authority_revision,ownership:latestCatalogue.ownership_revision,identity_membership:0,owners:0},payload:{access_group_id:groupId,display_name:'Local preview audit smoke',description:'Synthetic local administrator smoke operation',enabled:true,source_scopes:[{source_family:'local',source_account_id:'volt-local-preview',scope_key:'all'}],permissions:[{permission_id:permissionId,role_id:roleId,action:'access_group.read',target_scope:{group_ids:[groupId],source_families:['local'],environments:[],service_ids:[],membership_mode:'explicit'},limits:envelope.limits,separation_of_duties:envelope.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,required_approver_count:1,prohibited_action_pairs:[]}}],rationale:'Verify a public audited administrator operation in the synthetic local preview',evidence_ref:'local-preview-smoke'}}});
    ensure(created.status===200,`public_admin_create_failed_${created.status}_${JSON.stringify(created.body)}`);
    createReceipt=created.body;
    requireReceipt(createReceipt,{commandId,targetId:zero,groupId,action:'access_group.create',objectRevision:1});
    const membershipCatalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    const membershipCommandId=crypto.randomUUID();
    const membership=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:membershipCommandId,target_id:zero,membership_ids:[],action:'access_group.membership.set',expected_revisions:{target:membershipCatalogue.policy_revision,policy:membershipCatalogue.policy_revision,authority:membershipCatalogue.authority_revision,access_group:createReceipt.result.object_revision,identity_membership:0},payload:{access_group_id:groupId,principal_id:principal,effective_from:new Date(Date.now()+1000).toISOString(),effective_until:null,enabled:true,rationale:'Bind the local administrator to the native group for provider-cap qualification',evidence_ref:'local-preview-provider-cap'}}});
    ensure(membership.status===200,`native_membership_create_failed_${membership.status}_${JSON.stringify(membership.body)}`);
    membershipReceipt=membership.body;
    requireReceipt(membershipReceipt,{commandId:membershipCommandId,targetId:zero,
      groupId,action:'access_group.membership.set'});
    ensure(membershipReceipt.result.object_revision===createReceipt.result.object_revision+1,
      'native_membership_receipt_did_not_advance_group_revision');
    const refresh=page.getByRole('button',{name:'Refresh administration',exact:true});
    await refresh.click();
    await cardFor(groupId,membershipReceipt.result.object_revision);
    await page.screenshot({path:`${evidence}/admin-operation.png`,fullPage:true});
    const readback=await api('/api/v1/assessment/access-groups');
    ensure(readback.status===200,'public_access_group_readback_failed');
    const item=readback.body.items?.find(x=>x.access_group_id===groupId);
    const createAudit=item?.history?.find(x=>x.event_id===createReceipt.audit_event_id);
    const membershipAudit=item?.history?.find(x=>x.event_id===membershipReceipt.audit_event_id);
    requireAudit(item,createAudit,{groupId,action:'access_group.create',displayName:'Local preview audit smoke',description:'Synthetic local administrator smoke operation',enabled:true,objectRevision:createReceipt.result.object_revision,auditEventId:createReceipt.audit_event_id,actorId:principal});
    requireAudit(item,membershipAudit,{groupId,action:'access_group.membership.set',membershipPrincipal:principal,objectRevision:membershipReceipt.result.object_revision,auditEventId:membershipReceipt.audit_event_id,actorId:principal});
    ensure(item.revision===membershipReceipt.result.object_revision,'public_object_revision_does_not_match_membership_receipt');
    saved={schema_version:1,issuer,subject,principal_id:principal,
      receipts:{create:createReceipt,membership:membershipReceipt},
      object:{access_group_id:item.access_group_id,display_name:item.display_name,description:item.description,enabled:item.enabled,revision:item.revision},
      audit_after_values:{create:createAudit.after_value,membership:membershipAudit.after_value}};
    await writeFile(`${evidence}/smoke-state.json`,JSON.stringify(saved,null,2)+'\n',{mode:0o600});
    await writeFile(`${evidence}/public-admin-command-receipts.json`,JSON.stringify(saved.receipts,null,2)+'\n',{mode:0o600});
  }else{
    saved=JSON.parse(await readFile(`${evidence}/smoke-state.json`,'utf8'));
    ensure(saved.issuer===issuer&&saved.subject===subject&&saved.principal_id===principal,'persisted_smoke_identity_binding_mismatch');
    createReceipt=saved.receipts?.create;
    membershipReceipt=saved.receipts?.membership;
    ensure(createReceipt&&membershipReceipt,'persisted_smoke_receipts_missing');
    requireReceipt(createReceipt,{commandId:createReceipt?.command_id,targetId:zero,groupId:saved.object.access_group_id,action:'access_group.create'});
    requireReceipt(membershipReceipt,{commandId:membershipReceipt?.command_id,targetId:zero,groupId:saved.object.access_group_id,action:'access_group.membership.set'});
    await page.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
    await waitAdminReady();
    const refresh=page.getByRole('button',{name:'Refresh administration',exact:true});
    await refresh.click();
    await cardFor(saved.object.access_group_id,saved.object.revision);
    await page.screenshot({path:`${evidence}/admin-restart.png`,fullPage:true});
  }
  const readback=await api('/api/v1/assessment/access-groups');
  ensure(readback.status===200,'public_access_group_readback_failed');
  const item=readback.body.items?.find(x=>x.access_group_id===saved.object.access_group_id);
  const createAudit=item?.history?.find(x=>x.event_id===createReceipt.audit_event_id);
  const membershipAudit=item?.history?.find(x=>x.event_id===membershipReceipt.audit_event_id);
  if(readbackOnly){
    requireReceipt(createReceipt,{commandId:createReceipt.command_id,targetId:zero,groupId:item.access_group_id,action:'access_group.create',objectRevision:saved.audit_after_values.create.revision});
    requireReceipt(membershipReceipt,{commandId:membershipReceipt.command_id,targetId:zero,groupId:item.access_group_id,action:'access_group.membership.set',objectRevision:saved.object.revision});
    requireAudit(item,createAudit,{groupId:item.access_group_id,action:'access_group.create',displayName:saved.object.display_name,description:saved.object.description,enabled:saved.object.enabled,objectRevision:createReceipt.result.object_revision,auditEventId:createReceipt.audit_event_id,actorId:principal});
    requireAudit(item,membershipAudit,{groupId:item.access_group_id,action:'access_group.membership.set',membershipPrincipal:principal,objectRevision:membershipReceipt.result.object_revision,auditEventId:membershipReceipt.audit_event_id,actorId:principal});
    requirePersistedState(item,createAudit,membershipAudit,saved);
    await writeFile(`${evidence}/public-admin-smoke-restart.json`,JSON.stringify({environment:'local synthetic OIDC container',principal_id:principal,issuer,subject,credential_mode:'oidc_session',group_id:item.access_group_id,create_command_id:createReceipt.command_id,create_receipt_audit_event_id:createReceipt.audit_event_id,membership_command_id:membershipReceipt.command_id,membership_receipt_audit_event_id:membershipReceipt.audit_event_id,public_readback_status:readback.status,object_revision:item.revision,create_audit_event_id:createAudit.event_id,membership_audit_event_id:membershipAudit.event_id,restart_readback:true},null,2)+'\n',{mode:0o600});
  }else{
    requireAudit(item,createAudit,{groupId:saved.object.access_group_id,action:'access_group.create',displayName:saved.object.display_name,description:saved.object.description,enabled:saved.object.enabled,objectRevision:createReceipt.result.object_revision,auditEventId:createReceipt.audit_event_id,actorId:principal});
    requireAudit(item,membershipAudit,{groupId:saved.object.access_group_id,action:'access_group.membership.set',membershipPrincipal:principal,objectRevision:membershipReceipt.result.object_revision,auditEventId:membershipReceipt.audit_event_id,actorId:principal});
    ensure(item.revision===membershipReceipt.result.object_revision,'public_object_revision_does_not_match_membership_receipt');
    await writeFile(`${evidence}/public-admin-smoke.json`,JSON.stringify({environment:'local synthetic OIDC container',principal_id:principal,issuer,subject,credential_mode:'oidc_session',group_id:item.access_group_id,create_command_id:createReceipt.command_id,create_receipt_audit_event_id:createReceipt.audit_event_id,membership_command_id:membershipReceipt.command_id,membership_receipt_audit_event_id:membershipReceipt.audit_event_id,public_readback_status:readback.status,object_revision:item.revision,create_audit_event_id:createAudit.event_id,membership_audit_event_id:membershipAudit.event_id,restart_readback:false},null,2)+'\n',{mode:0o600});
  }
  if(verifyProviderRevocation){
    ensure(readbackOnly,'provider revocation proof must follow the persisted readback phase');
    const before=(await api('/api/v1/auth/session')).body;
    ensure(before.authority?.role_ids?.includes('00000000-0000-4000-8000-000000000002'),'native_role_not_present_before_provider_removal');
    ensure(before.authority?.source_scopes?.some(s=>s[0]==='local'&&s[1]==='volt-local-preview'&&s[2]==='all'),'native_scope_not_present_before_provider_removal');
    const composeDirectory=arg('--compose-directory'), envFile=arg('--env-file'), project=arg('--project');
    const controlScript="import json,pathlib,sys,urllib.request; token=pathlib.Path('/run/uvm-g7-secrets/oidc_operator_secret').read_text().strip(); body=json.loads(sys.argv[1]); req=urllib.request.Request('http://127.0.0.1:9000/__fixture/failure',data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}); response=urllib.request.urlopen(req,timeout=10); print(response.status)";
    const control=execFileSync('docker',['compose','-f',path.join(composeDirectory,'compose.yaml'),'-f',path.join(composeDirectory,'demo.yaml'),'--env-file',envFile,'-p',project,'exec','-T','volt','/opt/uvm/venv/bin/python','-c',controlScript,JSON.stringify({mode:null,identities:[{subject,groups:[]}]})],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
    ensure(control.trim().split(/\r?\n/).at(-1)==='200','synthetic_provider_fixture_update_failed');
    await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session',{cache:'no-store'});return r.status===401;},null,{timeout:30000});
    await page.goto(origin+'/',{waitUntil:'domcontentloaded'});
    await page.getByRole('link',{name:/sign in/i}).click();
    await page.getByLabel('Username').fill(username);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button',{name:'Sign in'}).click();
    await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session',{cache:'no-store'});return r.ok&&(await r.json()).authenticated===true;},null,{timeout:30000});
    const after=(await api('/api/v1/auth/session')).body;
    ensure(after.authority?.role_ids?.length===0,'fresh_signin_recovered_native_role_after_provider_group_removal');
    ensure(after.authority?.source_scopes?.length===0,'fresh_signin_recovered_native_scope_after_provider_group_removal');
    ensure(after.authority?.access_groups?.includes(saved.object.access_group_id),'provider_removal_erased_native_membership_history');
    await writeFile(`${evidence}/provider-group-removal.json`,JSON.stringify({environment:'local synthetic OIDC Compose process',old_cookie_revoked:true,fresh_code_flow_authenticated:true,retained_native_access_group:true,effective_role_ids:after.authority.role_ids,effective_source_scopes:after.authority.source_scopes},null,2)+'\n',{mode:0o600});
  }
  console.log(JSON.stringify({browser_login:'passed',issuer,subject,principal_id:principal,admin_view:'loaded',admin_control:'enabled',...(readbackOnly?{restart_readback:readback.status}:{public_admin_readback:readback.status}),audited:true,create_audit_event_id:createReceipt.audit_event_id,membership_audit_event_id:membershipReceipt.audit_event_id,object_revision:item.revision,group_id:item.access_group_id,create_command_id:createReceipt.command_id,membership_command_id:membershipReceipt.command_id}));
}finally{await context.close();await browser.close();}
