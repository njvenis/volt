import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import process from 'node:process';
import crypto from 'node:crypto';

function arg(name){const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw new Error(`missing ${name}`);return process.argv[i+1];}
const origin=arg('--origin'), evidence=arg('--evidence');
const readbackOnly=process.argv.includes('--readback');
await mkdir(evidence,{recursive:true,mode:0o700});
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH??'/home/nicho/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome'});
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
try{
  await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});
  await page.getByRole('link',{name:/sign in/i}).click({timeout:10000});
  await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session',{cache:'no-store'});if(!r.ok)return false;return (await r.json()).authenticated===true;},null,{timeout:30000});
  const session=(await api('/api/v1/auth/session')).body;
  ensure(session.credential_mode==='oidc_session'&&session.principal_id==='volt-local-preview-admin','synthetic_browser_login_identity_mismatch');
  await page.goto(origin+'/#administration',{waitUntil:'domcontentloaded'});
  await page.screenshot({path:`${evidence}/admin-signed-in.png`,fullPage:true});
  let saved;
  if(readbackOnly){
    saved=JSON.parse(await readFile(`${evidence}/smoke-state.json`,'utf8'));
  }else{
    const bootstrap=await api('/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,body:{policy:{grants:[],denies:[],owner_directory:[{owner_id:'volt-local-preview-admin',owner_type:'person',display_name:'Synthetic Local Preview Administrator',enabled:true}],acceptance_material_changes:{},exception_warning_routes:[]}}});
    ensure([200,409].includes(bootstrap.status),`initial_policy_bootstrap_failed_${bootstrap.status}`);
    let catalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    ensure(catalogue.caller?.principal_id==='volt-local-preview-admin','bootstrap_administrator_not_authorised');
    if(catalogue.authority_mode==='legacy'){
      const activation=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:crypto.randomUUID(),target_id:zero,action:'native.authority.activate',membership_ids:[],expected_revisions:{target:catalogue.policy_revision,policy:catalogue.policy_revision,authority:catalogue.authority_revision,identity_membership:0,owners:0},payload:{mapping_revision:1,rationale:'Activate native authority for the private synthetic local preview',evidence_ref:'local-preview-bootstrap'}}});
      ensure(activation.status===200,`native_authority_activation_failed_${activation.status}`);
      catalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    }
    const envelope=catalogue.caller?.grantable;
    ensure(envelope?.actions?.includes('access_group.read'),'local_bootstrap_action_envelope_missing');
    const groupId=crypto.randomUUID(), commandId=crypto.randomUUID();
    const created=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:{command_id:commandId,target_id:zero,membership_ids:[],action:'access_group.create',expected_revisions:{target:catalogue.policy_revision,policy:catalogue.policy_revision,authority:catalogue.authority_revision,ownership:catalogue.ownership_revision,identity_membership:0,owners:0},payload:{access_group_id:groupId,display_name:'Local preview audit smoke',description:'Synthetic local administrator smoke operation',enabled:true,source_scopes:[{source_family:'local',source_account_id:'volt-local-preview',scope_key:'all'}],permissions:[{permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action:'access_group.read',target_scope:{group_ids:[groupId],source_families:['local'],environments:[],service_ids:[],membership_mode:'explicit'},limits:envelope.limits,separation_of_duties:envelope.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,required_approver_count:1,prohibited_action_pairs:[]}}],rationale:'Verify a public audited administrator operation in the synthetic local preview',evidence_ref:'local-preview-smoke'}}});
    ensure(created.status===200,`public_admin_create_failed_${created.status}`);
    saved={group_id:groupId,command_id:commandId};
    await writeFile(`${evidence}/smoke-state.json`,JSON.stringify(saved,null,2)+'\n',{mode:0o600});
  }
  const readback=await api('/api/v1/assessment/access-groups');
  ensure(readback.status===200,'public_access_group_readback_failed');
  const item=readback.body.items?.find(x=>x.access_group_id===saved.group_id);
  ensure(item,'created_public_access_group_missing');
  const audit=item.history??[];
  ensure(audit.some(x=>x.command_id===saved.command_id&&x.action==='access_group.create'),'audited_admin_create_missing_from_public_history');
  await writeFile(`${evidence}/public-admin-smoke${readbackOnly?'-restart':''}.json`,JSON.stringify({environment:'local synthetic OIDC container',principal_id:session.principal_id,credential_mode:session.credential_mode,group_id:saved.group_id,command_id:saved.command_id,public_readback_status:readback.status,audit_actions:audit.map(x=>x.action),audit_command_ids:audit.map(x=>x.command_id),restart_readback:readbackOnly},null,2)+'\n',{mode:0o600});
  await page.screenshot({path:`${evidence}/admin-operation-readback.png`,fullPage:true});
  console.log(JSON.stringify({browser_login:'passed',principal_id:session.principal_id,...(readbackOnly?{restart_readback:readback.status}:{public_admin_readback:readback.status}),audited:true,group_id:saved.group_id,command_id:saved.command_id}));
}finally{await context.close();await browser.close();}
