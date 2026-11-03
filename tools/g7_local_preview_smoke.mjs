import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import process from 'node:process';
import crypto from 'node:crypto';
import {requireAdminRendered,requireAudit,requirePersistedState,requireReceipt,requireSession} from './g7_local_preview_smoke_checks.mjs';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`);return process.argv[i+1];}
const origin=arg('--origin'), issuer=arg('--issuer'), subject=arg('--subject'), principal=arg('--principal'), evidence=arg('--evidence');
const readbackOnly=process.argv.includes('--readback');
await mkdir(evidence,{recursive:true,mode:0o700});
const launchOptions={headless:true};
if(process.env.CHROMIUM_EXECUTABLE_PATH)launchOptions.executablePath=process.env.CHROMIUM_EXECUTABLE_PATH;
const browser=await chromium.launch(launchOptions);
const context=await browser.newContext();
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
async function cardFor(groupId){
  const card=page.locator('section[aria-label="Access group records"] article').filter({hasText:'Local preview audit smoke'});
  await card.waitFor({state:'visible',timeout:30000});
  const text=await card.innerText();
  ensure(text.includes(groupId)&&/Revision\s+1/.test(text),'rendered_admin_object_mismatch');
  return card;
}
try{
  await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});
  await page.getByRole('link',{name:/sign in/i}).click({timeout:10000});
  await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session',{cache:'no-store'});if(!r.ok)return false;return (await r.json()).authenticated===true;},null,{timeout:30000});
  const session=(await api('/api/v1/auth/session')).body;
  requireSession(session,{issuer,subject,principal});
  let saved,receipt;
  if(!readbackOnly){
    const bootstrap=await api('/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,body:{policy:{grants:[],denies:[],owner_directory:[{owner_id:principal,owner_type:'person',display_name:'Synthetic Local Preview Administrator',enabled:true}],acceptance_material_changes:{},exception_warning_routes:[]}}});
    ensure([200,409].includes(bootstrap.status),`initial_policy_bootstrap_failed_${bootstrap.status}`);
    let catalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    ensure(catalogue.caller?.principal_id===principal,'bootstrap_administrator_not_authorised');
    if(catalogue.authority_mode==='legacy'){
      const activation=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,membership_ids:[],action:'native.authority.activate',expected_revisions:{target:catalogue.policy_revision,policy:catalogue.policy_revision,authority:catalogue.authority_revision,identity_membership:0,owners:0},payload:{mapping_revision:1,rationale:'Activate native authority for the private synthetic local preview',evidence_ref:'local-preview-bootstrap'}}});
      ensure(activation.status===200,`native_authority_activation_failed_${activation.status}`);
    }
    await page.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
    const createButton=await waitAdminReady();
    await page.screenshot({path:`${evidence}/admin-initial.png`,fullPage:true});
    const latestCatalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    const envelope=latestCatalogue.caller?.grantable;
    ensure(latestCatalogue.authority_mode==='uvm_native_v1'&&latestCatalogue.caller?.principal_id===principal,'native_admin_catalogue_identity_or_mode_mismatch');
    ensure(envelope?.actions?.includes('access_group.read'),'local_bootstrap_action_envelope_missing');
    const groupId=crypto.randomUUID(), commandId=crypto.randomUUID(), permissionId=crypto.randomUUID(), roleId=crypto.randomUUID();
    const created=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:commandId,target_id:zero,membership_ids:[],action:'access_group.create',expected_revisions:{target:latestCatalogue.policy_revision,policy:latestCatalogue.policy_revision,authority:latestCatalogue.authority_revision,ownership:latestCatalogue.ownership_revision,identity_membership:0,owners:0},payload:{access_group_id:groupId,display_name:'Local preview audit smoke',description:'Synthetic local administrator smoke operation',enabled:true,source_scopes:[{source_family:'local',source_account_id:'volt-local-preview',scope_key:'all'}],permissions:[{permission_id:permissionId,role_id:roleId,action:'access_group.read',target_scope:{group_ids:[groupId],source_families:['local'],environments:[],service_ids:[],membership_mode:'explicit'},limits:envelope.limits,separation_of_duties:envelope.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,required_approver_count:1,prohibited_action_pairs:[]}}],rationale:'Verify a public audited administrator operation in the synthetic local preview',evidence_ref:'local-preview-smoke'}}});
    ensure(created.status===200,`public_admin_create_failed_${created.status}_${JSON.stringify(created.body)}`);
    receipt=created.body;
    requireReceipt(receipt,{commandId,targetId:zero,groupId});
    const refresh=page.getByRole('button',{name:'Refresh administration',exact:true});
    await refresh.click();
    await cardFor(groupId);
    await page.screenshot({path:`${evidence}/admin-operation.png`,fullPage:true});
    const readback=await api('/api/v1/assessment/access-groups');
    ensure(readback.status===200,'public_access_group_readback_failed');
    const item=readback.body.items?.find(x=>x.access_group_id===groupId);
    const auditEvent=item?.history?.find(x=>x.event_id===receipt.audit_event_id);
    requireAudit(item,auditEvent,{groupId,displayName:'Local preview audit smoke',objectRevision:receipt.result.object_revision,auditEventId:receipt.audit_event_id,actorId:principal});
    ensure(item.revision===receipt.result.object_revision,'public_object_revision_does_not_match_receipt');
    saved={schema_version:1,issuer,subject,principal_id:principal,receipt,object:{access_group_id:item.access_group_id,display_name:item.display_name,description:item.description,enabled:item.enabled,revision:item.revision},audit_after_value:auditEvent.after_value};
    await writeFile(`${evidence}/smoke-state.json`,JSON.stringify(saved,null,2)+'\n',{mode:0o600});
    await writeFile(`${evidence}/public-admin-command-receipt.json`,JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
  }else{
    saved=JSON.parse(await readFile(`${evidence}/smoke-state.json`,'utf8'));
    ensure(saved.issuer===issuer&&saved.subject===subject&&saved.principal_id===principal,'persisted_smoke_identity_binding_mismatch');
    receipt=saved.receipt;
    requireReceipt(receipt,{commandId:receipt.command_id,targetId:zero,groupId:saved.object.access_group_id});
    await page.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
    await waitAdminReady();
    const refresh=page.getByRole('button',{name:'Refresh administration',exact:true});
    await refresh.click();
    await cardFor(saved.object.access_group_id);
    await page.screenshot({path:`${evidence}/admin-restart.png`,fullPage:true});
  }
  const readback=await api('/api/v1/assessment/access-groups');
  ensure(readback.status===200,'public_access_group_readback_failed');
  const item=readback.body.items?.find(x=>x.access_group_id===saved.object.access_group_id);
  const auditEvent=item?.history?.find(x=>x.event_id===receipt.audit_event_id);
  if(readbackOnly){
    requirePersistedState(item,auditEvent,saved);
    await writeFile(`${evidence}/public-admin-smoke-restart.json`,JSON.stringify({environment:'local synthetic OIDC container',principal_id:principal,issuer,subject,credential_mode:'oidc_session',group_id:item.access_group_id,command_id:receipt.command_id,receipt_audit_event_id:receipt.audit_event_id,public_readback_status:readback.status,object_revision:item.revision,audit_event_id:auditEvent.event_id,audit_event:{event_id:auditEvent.event_id,action:auditEvent.action,actor_id:auditEvent.actor_id,after_value:auditEvent.after_value},restart_readback:true},null,2)+'\n',{mode:0o600});
  }else{
    requireAudit(item,auditEvent,{groupId:saved.object.access_group_id,displayName:saved.object.display_name,objectRevision:receipt.result.object_revision,auditEventId:receipt.audit_event_id,actorId:principal});
    await writeFile(`${evidence}/public-admin-smoke.json`,JSON.stringify({environment:'local synthetic OIDC container',principal_id:principal,issuer,subject,credential_mode:'oidc_session',group_id:item.access_group_id,command_id:receipt.command_id,receipt_audit_event_id:receipt.audit_event_id,public_readback_status:readback.status,object_revision:item.revision,audit_event_id:auditEvent.event_id,audit_event:{event_id:auditEvent.event_id,action:auditEvent.action,actor_id:auditEvent.actor_id,after_value:auditEvent.after_value},restart_readback:false},null,2)+'\n',{mode:0o600});
  }
  console.log(JSON.stringify({browser_login:'passed',issuer,subject,principal_id:principal,admin_view:'loaded',admin_control:'enabled',...(readbackOnly?{restart_readback:readback.status}:{public_admin_readback:readback.status}),audited:true,audit_event_id:auditEvent.event_id,object_revision:item.revision,group_id:item.access_group_id,command_id:receipt.command_id}));
}finally{await context.close();await browser.close();}
