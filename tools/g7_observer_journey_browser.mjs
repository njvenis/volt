import {assertOperationalRenderedCards, captureOperationalCards} from './g7_operational_render_assertions.mjs';
import {assertClock, assertRenderedAcceptance, captureAcceptance} from './g7_sla_render_assertions.mjs';
import {runBackupBrowserStep} from '../ui/tests/backup-recovery-browser.mjs';
import { chromium } from '../ui/node_modules/playwright/index.mjs';
import { readFile, mkdir, writeFile, unlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { createHmac } from 'node:crypto';

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}
const origin = arg('--origin');
const evidence = arg('--evidence');
const fixtureRoot = arg('--fixture-root');
const appContainer = process.argv.includes('--app-container') ? arg('--app-container') : 'volt-g7-observer-journey';
const backupSeedOnly = process.argv.includes('--backup-seed-only');
const warningOnly = process.argv.includes('--exception-warning-only');
const exceptionSlaOnly = process.argv.includes('--exception-sla-only');
const operationalAlertsOnly = process.argv.includes('--operational-alerts-only');
const oidcProxyPort = warningOnly || exceptionSlaOnly ? arg('--oidc-proxy-port') : null;
const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const utcMicros=value=>{
  const millis=Date.parse(value);
  const fraction=(String(value).match(/\.(\d+)(?:Z|[+-])/i)?.[1]??'').padEnd(6,'0').slice(3,6);
  return Number.isFinite(millis)?millis*1000+Number(fraction||0):NaN;
};
await mkdir(evidence, {recursive:true, mode:0o700});
const browser = await chromium.launch({headless:true,
  ...(process.env.CHROMIUM_EXECUTABLE_PATH
    ? {executablePath:process.env.CHROMIUM_EXECUTABLE_PATH} : {})});
const context = await browser.newContext({viewport:{width:1440,height:1000},deviceScaleFactor:1});
const page = await context.newPage();
const counts = {bootstrap:0, nativeActivation:0, accessGroup:0, membership:0,
  lostAcknowledgement:0, receiptRecovery:0, revision1:0, revision2:0, rollback3:0,
  crossDeploymentDenied:0, csrfDenied:0, staleRevisionDenied:0, invalidValueDenied:0,
  pending:0, initialUnconfigured:0, failed:0, uncertain:0,
  consumerRestarts:0, controllerRestart:0, containerRestart:0, containerOutage:0,
  schedulerStall:0, healthFaults:[], hostReportAttacks:{},
  reflow:[], axe:[], screenshots:[]};
const authResponseFacts=[];
let capturedLoginSession=null;
await page.exposeFunction('__g7CaptureLoginSession',value=>{capturedLoginSession=value;});
page.on('response',response=>{
  const url=response.url();
  if(!url.includes('/api/v1/auth/session')&&!url.includes('/api/v1/auth/callback'))return;
  void response.headersArray().then(headers=>{
    const cookies=headers.filter(item=>item.name.toLowerCase()==='set-cookie').map(item=>{
      const parts=item.value.split(';').map(part=>part.trim());
      return {name:parts[0]?.split('=',1)[0],attributes:parts.slice(1).map(part=>part.split('=',1)[0].toLowerCase()).sort()};
    });
    void response.json().then(body=>{
    authResponseFacts.push({path:new URL(url).pathname,status:response.status(),
      error_code:body?.detail?.code ?? null,set_cookie_names:cookies.map(c=>c.name),
        set_cookie_attributes:cookies.map(c=>c.attributes),
        disposable_failure_code:headers.find(item=>item.name.toLowerCase()==='x-uvm-g7-auth-failure')?.value ?? null});
    }).catch(()=>authResponseFacts.push({path:new URL(url).pathname,status:response.status(),
      set_cookie_names:cookies.map(c=>c.name),set_cookie_attributes:cookies.map(c=>c.attributes),
      disposable_failure_code:headers.find(item=>item.name.toLowerCase()==='x-uvm-g7-auth-failure')?.value ?? null}));
  });
});
let droppedReceipt = null;
let dropCommandAcknowledgement = false;
page.on('console', message => { if (message.type() === 'error') counts.consoleErrors = (counts.consoleErrors ?? 0) + 1; });
page.on('pageerror', () => { counts.pageErrors = (counts.pageErrors ?? 0) + 1; });

async function api(pathname, options={}) {
  return page.evaluate(async ({pathname,options}) => {
    const session = await (await fetch('/api/v1/auth/session',{credentials:'same-origin'})).json();
    const response = await fetch(pathname,{credentials:'same-origin',...options,
      headers:{Accept:'application/json',...(options.body?{'Content-Type':'application/json'}:{}),
        ...(options.write?{'X-CSRF-Token':session.csrf_token}:{}),...(options.headers??{})}});
    let body; try {body=await response.json();} catch {body=null;}
    return {status:response.status,body};
  },{pathname,options});
}
async function waitForAppliedRevision(revision) {
  const until=Date.now()+90000;
  let latest;
  while(Date.now()<until){
    latest=await api('/api/v1/operations/observer-settings/g7-local');
    if(latest.status===200&&latest.body.desired?.revision===revision
      &&latest.body.application?.status==='applied'&&latest.body.effective?.revision===revision
      &&latest.body.effective?.digest===latest.body.desired?.digest)return latest;
    await page.waitForTimeout(500);
  }
  throw new Error(`host did not apply revision ${revision}: ${JSON.stringify({status:latest?.status,desired:latest?.body?.desired,application:latest?.body?.application,effective:latest?.body?.effective})}`);
}
async function publishApi(values, rationale) {
  const current=await api('/api/v1/operations/observer-settings/g7-local');
  const result=await api('/api/v1/operations/observer-settings/g7-local/commands',{
    method:'POST',write:true,body:JSON.stringify({schema_version:1,command_id:crypto.randomUUID(),
      action:'observer.timing.publish',expected_revisions:current.body.revisions,
      rationale,evidence_ref:'g7-observer-journey-fixture',values})});
  if(![200,201].includes(result.status))throw new Error(`authorized recovery publish returned ${result.status}`);
  return result.body;
}
async function hostTelemetryCount() {
  const output=execFileSync('uv',['run','python','tools/g7_observer_fixture.py',
    'host-telemetry-count','--root',fixtureRoot],
    {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
  return JSON.parse(output.trim());
}
function hostOnce() {
  const output=execFileSync('uv',['run','python','tools/g7_observer_fixture.py',
    'host-once','--root',fixtureRoot],
    {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
  return JSON.parse(output.trim());
}
async function failAtomicWrite(target,values) {
  const before=await api('/api/v1/operations/observer-settings/g7-local');
  const auditBefore=await hostTelemetryCount();
  const commandId=crypto.randomUUID();
  const attempted=await api('/api/v1/operations/observer-settings/g7-local/commands',{method:'POST',write:true,
    headers:{'X-UVM-G7-Fixture-Failpoint':target},
    body:JSON.stringify({schema_version:1,command_id:commandId,action:'observer.timing.publish',
      expected_revisions:before.body.revisions,rationale:`Atomic ${target} failpoint`,
      evidence_ref:'g7-observer-journey-fixture',values})});
  const after=await api('/api/v1/operations/observer-settings/g7-local');
  const receipt=await api(`/api/v1/operations/observer-settings/g7-local/receipts/${commandId}`);
  const auditAfter=await hostTelemetryCount();
  const targetRevision=before.body.revisions.configuration;
  if(attempted.status!==503
      ||after.body.revisions.configuration!==targetRevision||receipt.status!==404
      ||auditBefore.audit_event_count!==auditAfter.audit_event_count)
    throw new Error(`atomic ${target} failure leaked a write: ${JSON.stringify({status:attempted.status,
      revision:after.body.revisions.configuration,
      receipt:receipt.status,auditBefore:auditBefore.audit_event_count,auditAfter:auditAfter.audit_event_count})}`);
  return {status:attempted.status,configurationRevision:after.body.revisions.configuration,
    receipt:receipt.status,auditEventsUnchanged:auditBefore.audit_event_count===auditAfter.audit_event_count};
}
function hostControl(role,action) {
  execFileSync('uv',['run','python','tools/g7_observer_fixture.py','host-control','--root',fixtureRoot,'--role',role,'--action',action],
    {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
}
function docker(args) {
  return execFileSync('docker',args,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
}
function disposableDbSnapshot({commandId,acceptanceId,groupId}) {
  const py=`import json,sqlalchemy as sa,urllib.parse\nfrom pathlib import Path\np=urllib.parse.quote(Path('/run/secrets/uvm_db_password').read_text().strip(),safe='')\ne=sa.create_engine('postgresql+psycopg://uvm_app:'+p+'@127.0.0.1:5432/uvm')\nwith e.connect() as c:\n q=lambda s,p: c.execute(sa.text(s),p).scalar_one()\n group_state=c.execute(sa.text('select revision,document::text from assessment_group_state where group_id=:id'),{'id':'${groupId}'}).first()\n out={'audit':q('select count(*) from assessment_audit_events where command_id=:id',{'id':'${commandId}'}),'receipt':q('select count(*) from assessment_command_receipts where command_id=:id',{'id':'${commandId}'}),'clock':q('select count(*) from sla_clock_events where decision_id=:id',{'id':'${acceptanceId}'}),'warning_intents':q('select count(*) from exception_warning_intents where decision_id=:id',{'id':'${acceptanceId}'}),'projection_intents':q('select count(*) from assessment_projection_intents where target_id=:id',{'id':'${groupId}'}),'group_state':list(group_state) if group_state else None}\n print(json.dumps(out,sort_keys=True))\ne.dispose()`;
  return JSON.parse(docker(['exec',appContainer,'/opt/uvm/venv/bin/python','-c',py]));
}
function disposableAtomClockEvents(episodeId,occurrenceId) {
  const py=`import json,sqlalchemy as sa,urllib.parse
from pathlib import Path
p=urllib.parse.quote(Path('/run/secrets/uvm_db_password').read_text().strip(),safe='')
e=sa.create_engine('postgresql+psycopg://uvm_app:'+p+'@127.0.0.1:5432/uvm')
with e.connect() as c:
 rows=c.execute(sa.text('select event_id,sequence,event_type,effective_at,decision_id,predecessor_event_id,data from sla_clock_events where episode_id=:episode and occurrence_id=:occurrence order by sequence'),{'episode':'${episodeId}','occurrence':'${occurrenceId}'}).mappings().all()
 print(json.dumps([dict(row) for row in rows],default=str,sort_keys=True))
e.dispose()`;
  return JSON.parse(docker(['exec',appContainer,'/opt/uvm/venv/bin/python','-c',py]));
}
function installApprovalAuditFault({commandId,groupId}) {
  const py=`import sqlalchemy as sa,urllib.parse\nfrom pathlib import Path\np=urllib.parse.quote(Path('/run/secrets/uvm_db_password').read_text().strip(),safe='')\ne=sa.create_engine('postgresql+psycopg://uvm_app:'+p+'@127.0.0.1:5432/uvm')\ns=sa.text\nwith e.begin() as c:\n c.execute(s('DROP TRIGGER IF EXISTS g7_fixture_fail_approval_audit ON assessment_audit_events'))\n c.execute(s('DROP FUNCTION IF EXISTS g7_fixture_fail_approval_audit()'))\n c.execute(s(\"CREATE FUNCTION g7_fixture_fail_approval_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'acceptance.approve' AND NEW.target_id = '${groupId}' AND NEW.command_id = '${commandId}' THEN RAISE EXCEPTION 'g7 disposable approval audit fault' USING ERRCODE = 'P0001'; END IF; RETURN NEW; END; $$\"))\n c.execute(s('CREATE TRIGGER g7_fixture_fail_approval_audit BEFORE INSERT ON assessment_audit_events FOR EACH ROW EXECUTE FUNCTION g7_fixture_fail_approval_audit()'))\ne.dispose()`;
  docker(['exec',appContainer,'/opt/uvm/venv/bin/python','-c',py]);
}
function removeApprovalAuditFault() {
  const py=`import sqlalchemy as sa,urllib.parse\nfrom pathlib import Path\np=urllib.parse.quote(Path('/run/secrets/uvm_db_password').read_text().strip(),safe='')\ne=sa.create_engine('postgresql+psycopg://uvm_app:'+p+'@127.0.0.1:5432/uvm')\nwith e.begin() as c:\n c.execute(sa.text('DROP TRIGGER IF EXISTS g7_fixture_fail_approval_audit ON assessment_audit_events'))\n c.execute(sa.text('DROP FUNCTION IF EXISTS g7_fixture_fail_approval_audit()'))\ne.dispose()`;
  docker(['exec',appContainer,'/opt/uvm/venv/bin/python','-c',py]);
}
async function waitForHostStatus(status,timeoutMs=60000) {
  const until=Date.now()+timeoutMs;let latest;
  while(Date.now()<until){
    latest=await api('/api/v1/operations/observer-settings/g7-local');
    if(latest.status===200&&latest.body.application?.status===status)return latest;
    await page.waitForTimeout(500);
  }
  throw new Error(`host status ${status} not observed: ${JSON.stringify(latest?.body?.application)}`);
}
async function waitForContainerHealthy(timeoutMs=90000) {
  const until=Date.now()+timeoutMs;
  while(Date.now()<until){
    try { if(docker(['inspect','--format','{{.State.Health.Status}}',appContainer])==='healthy')return; } catch {}
    await page.waitForTimeout(1000);
  }
  throw new Error('disposable application did not recover to healthy after restart');
}
async function waitForJson(pathname,predicate,timeoutMs=20000) {
  const until=Date.now()+timeoutMs;let latest;
  while(Date.now()<until){
    try { latest=JSON.parse(await readFile(pathname,'utf8')); if(predicate(latest))return latest; } catch {}
    await page.waitForTimeout(250);
  }
  throw new Error(`expected host state was not observed: ${pathname}`);
}
async function waitForHostLog(pathname,needle,timeoutMs=15000) {
  const until=Date.now()+timeoutMs;let latest='';
  while(Date.now()<until){
    try { latest=await readFile(pathname,'utf8'); if(latest.includes(needle))return latest; } catch {}
    await page.waitForTimeout(250);
  }
  throw new Error(`host log did not contain expected status ${needle}`);
}

try {
  await page.goto(origin + '/api/v1/auth/login',{waitUntil:'domcontentloaded',timeout:30000});
  await page.waitForFunction(async()=>{
    const r=await fetch('/api/v1/auth/session'); if(!r.ok)return false;
    const s=await r.json();
    await window.__g7CaptureLoginSession({authenticated:s.authenticated,
      credential_mode:s.credential_mode,principal_id:s.principal_id,url:location.href});
    return s.authenticated===true&&s.credential_mode==='oidc_session';
  },null,{timeout:30000});
  const loginSession=capturedLoginSession;
  const loginCookieNames=(await context.cookies(origin)).map(cookie=>cookie.name).sort();
  await writeFile(path.join(evidence,'recovery-auth-state.json'),
    JSON.stringify(await context.storageState(),null,2),{mode:0o600});

  const bootstrap = await api('/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,
    body:JSON.stringify({policy:{grants:[],denies:[{deny_id:'g7-deny-b-observer',principal_id:'g7-actor',
      actions:['observer.timing.read','observer.timing.configure','backup.settings.read','backup.settings.configure'],target_ids:['g7-other']}],
      acceptance_material_changes:{},exception_warning_routes:[]}})});
  if (![200,409].includes(bootstrap.status)) throw new Error(
    `bootstrap policy failed with ${bootstrap.status}: ${JSON.stringify(bootstrap.body)}; `+
    `session=${JSON.stringify({status:loginSession?.status,
      authenticated:loginSession?.body?.authenticated,credential_mode:loginSession?.body?.credential_mode,
      cookie_names:loginCookieNames,page_url:page.url(),auth_responses:authResponseFacts})}`);
  counts.bootstrap = bootstrap.status;

  // The recovery-control listener evaluates signed host policy against the
  // current global policy revision. Bootstrap that singleton before sending
  // the first host policy report; the host signing key and client credentials
  // remain in the fixture's host-only directory.
  let backupPolicyOutput;
  try {
    backupPolicyOutput=execFileSync('uv',['run','python','tools/g7_observer_fixture.py',
      'backup-policy','--root',fixtureRoot],
      {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
    await writeFile(path.join(evidence,'backup-policy.stdout'),backupPolicyOutput,{mode:0o600});
    const accepted=JSON.parse(backupPolicyOutput.trim());
    if(accepted.accepted!==true||accepted.host_policy_revision!==1)
      throw new Error(`host policy report was not accepted: ${backupPolicyOutput.trim()}`);
    counts.backupPolicy=1;
  } catch(error) {
    const detail=error?.stderr?.toString?.()||error?.message||String(error);
    await writeFile(path.join(evidence,'backup-policy.stderr'),detail,{mode:0o600});
    throw error;
  }

  const zero='00000000-0000-4000-8000-000000000000';
  let activation = await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
    command_id:crypto.randomUUID(),target_id:zero,action:'native.authority.activate',membership_ids:[],
    expected_revisions:{target:1,policy:1,authority:0,identity_membership:0,owners:0},
    payload:{mapping_revision:1,rationale:'Activate disposable observer journey native authority',evidence_ref:'g7-observer-journey-fixture'}})});
  if (activation.status===409) {
    const cat=await api('/api/v1/assessment/administration/catalogue');
    if (cat.status!==200||cat.body.authority_mode!=='uvm_native_v1') throw new Error('native authority is not active');
  } else if (activation.status!==200) throw new Error(`native activation failed with ${activation.status}`);
  counts.nativeActivation=activation.status;

  const catalogue=await api('/api/v1/assessment/administration/catalogue');
  if(catalogue.status!==200)throw new Error(`administration catalogue failed with ${catalogue.status}`);
  const grant=catalogue.body.caller.grantable;
  const groupId=warningOnly?'00000000-0000-4000-8000-000000000024':
    operationalAlertsOnly?'00000000-0000-4000-8000-000000000042':crypto.randomUUID();
  const scope={group_ids:['*'],source_families:['*'],environments:['*'],service_ids:['*'],membership_mode:'all_current'};
  const limits={...grant.limits,allowed_environments:grant.limits.allowed_environments?.length?grant.limits.allowed_environments:['*'],
    allowed_service_ids:grant.limits.allowed_service_ids?.length?grant.limits.allowed_service_ids:['*']};
  const duties=grant.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,
    required_approver_count:1,prohibited_action_pairs:[]};
  const actions=['observer.timing.read','observer.timing.configure',
    'backup.settings.read','backup.settings.configure','assessment.read','audit.read',
    ...(warningOnly?['acceptance.submit','acceptance.approve','warning.route.manage','warning.actor_link.manage',
      'owners.directory.read','ownership.team.manage']:[]),
    ...(exceptionSlaOnly?['acceptance.submit','acceptance.approve','acceptance.reject','acceptance.revoke',
      'owners.directory.read','owners.assign','ownership.team.manage','portion.define','portion.transfer','remediation.confirm_portion','report.create','report.read',
      'policy.sla.publish','policy.read']:[])];
  const permissions=actions.map(action=>({permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action,
    target_scope:scope,limits,separation_of_duties:duties,
    ...(action.startsWith('observer.timing.')||action.startsWith('backup.settings.')?{deployment_scopes:['g7-local','g7-other']}: {})}));
  const policyRevision=catalogue.body.policy_revision, authorityRevision=catalogue.body.authority_revision;
  const create=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
    command_id:crypto.randomUUID(),target_id:zero,action:'access_group.create',membership_ids:[],
    expected_revisions:{target:policyRevision,policy:policyRevision,authority:authorityRevision,identity_membership:0,owners:0},
    payload:{access_group_id:groupId,display_name:'Disposable observer operators',description:'Local G7 journey fixture',
      enabled:true,source_scopes:[{source_family:'local',source_account_id:'g7-local',scope_key:'all'}],permissions,
      rationale:'Configure the local observer journey fixture',evidence_ref:'g7-observer-journey-fixture'}})});
  if(create.status!==200)throw new Error(`access-group create failed with ${create.status}: ${JSON.stringify(create.body)}`);
  counts.accessGroup=create.status;
  const afterCreate=await api('/api/v1/assessment/administration/catalogue');
  const membership=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
    command_id:crypto.randomUUID(),target_id:zero,action:'access_group.membership.set',membership_ids:[],
    expected_revisions:{target:afterCreate.body.policy_revision,policy:afterCreate.body.policy_revision,
      authority:afterCreate.body.authority_revision,identity_membership:0,owners:0,access_group:1},
    payload:{access_group_id:groupId,principal_id:'g7-actor',effective_from:new Date(Date.now()+5000).toISOString(),enabled:true,
      rationale:'Grant the local observer journey actor access',evidence_ref:'g7-observer-journey-fixture'}})});
  if(membership.status!==200)throw new Error(`access-group membership failed with ${membership.status}: ${JSON.stringify(membership.body)}`);
  counts.membership=membership.status;
  if(exceptionSlaOnly) {
    const approverHead=await api('/api/v1/assessment/administration/catalogue');
    const approverMembership=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:zero,action:'access_group.membership.set',membership_ids:[],
      expected_revisions:{target:approverHead.body.policy_revision,policy:approverHead.body.policy_revision,
        authority:approverHead.body.authority_revision,identity_membership:0,owners:0,access_group:2},
      payload:{access_group_id:groupId,principal_id:'g7-exception-approver',effective_from:new Date(Date.now()+5000).toISOString(),enabled:true,
        rationale:'Grant the separately linked synthetic approver the same scoped action set',
        evidence_ref:'g7-exception-sla-approver-fixture'}})});
    if(approverHead.status!==200||approverMembership.status!==200)
      throw new Error(`exception approver access setup failed: ${JSON.stringify({head:approverHead.status,
        membership:approverMembership.status,body:approverMembership.body})}`);
  }
  await page.waitForTimeout(5500);

  if (exceptionSlaOnly) {
    const createSyntheticTeam=async(displayName)=>{
      const teamId=crypto.randomUUID();
      let created;
      for(let attempt=0;attempt<3;attempt++) {
        const head=await api('/api/v1/assessment/administration/catalogue');
        if(head.status!==200)throw new Error('scoped owner directory setup could not read current authority head');
        created=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
          command_id:crypto.randomUUID(),target_id:zero,action:'ownership.team.create',membership_ids:[],
          expected_revisions:{target:head.body.policy_revision,policy:head.body.policy_revision,
            authority:head.body.authority_revision,ownership:head.body.ownership_revision,
            identity_membership:0,owners:0},
          payload:{team_id:teamId,display_name:displayName,enabled:true,
            rationale:'Provide a real eligible owner for the disposable public exception journey',
            evidence_ref:'g7-observer-journey-fixture'}})});
        if(created.status===200)return teamId;
        if(created.status!==409)break;
      }
      throw new Error(`scoped owner directory setup failed ${created?.status}: ${JSON.stringify(created?.body)}`);
    };
    const ownerDirectoryId=await createSyntheticTeam('Synthetic accountable team');
    const transferOwnerBeforeId=await createSyntheticTeam('Synthetic transfer owner before');
    const transferOwnerAfterId=await createSyntheticTeam('Synthetic transfer owner after');
    const suspensionOwnerBeforeId=await createSyntheticTeam('Synthetic suspension owner before');
    const suspensionOwnerAfterId=await createSyntheticTeam('Synthetic suspension owner after');
    const preactivation=JSON.parse(await readFile(path.join(evidence,'sla-preactivation-ids.json'),'utf8'));
    const g7TargetPreactivation=JSON.parse(await readFile(path.join(evidence,'sla-g7-target-preactivation-ids.json'),'utf8'));
    const clockPath=path.join(fixtureRoot,'scheduler','warning-clock.txt');
    const readClock=async()=>new Date((await readFile(clockPath,'utf8')).trim());
    const advanceClock=async(ms)=>{
      const next=new Date((await readClock()).getTime()+ms);
      await writeFile(clockPath,next.toISOString()+'\n',{mode:0o666});
      return next;
    };
    const renderCurrentAcceptance=async(expected,label)=>{
      const responsePromise=page.waitForResponse(r=>r.request().method()==='GET'&&r.status()===200
        &&new URL(r.url()).pathname==='/api/v1/assessment/groups/'+encodeURIComponent(expected.group_id));
      await page.reload({waitUntil:'domcontentloaded'});
      const response=await responsePromise;
      const scoped=await response.json();
      const current=scoped.assessment.acceptances.find(a=>a.acceptance_id===expected.acceptance_id);
      if(scoped.group.group_id!==expected.group_id||current?.state!==expected.state)
        throw new Error('refreshed scoped acceptance response is stale');
      for(const clock of expected.sla_clock)
        assertClock(current.sla_clock.find(c=>c.occurrence_id===clock.occurrence_id),clock);
      await page.locator('.assessment-workspace .load-status').filter({hasText:'Finding assessment loaded.'})
        .waitFor({state:'visible',timeout:20000});
      await page.getByRole('button',{name:'Exceptions',exact:true}).click();
      const rendered=await captureAcceptance(page,expected.acceptance_id);
      assertRenderedAcceptance(rendered,expected);
      await page.screenshot({path:path.join(evidence,`sla-${label}-browser.png`),fullPage:true});
      await writeFile(path.join(evidence,`sla-${label}-browser.json`),JSON.stringify({
        expected,refreshed_group:scoped,rendered,selected_acceptance_and_every_atom_verified:true},null,2),{mode:0o600});
    };
    const publishPolicy=async(policy,readGroupId=preactivation.group_id,verifyPolicyReadback=true)=>{
      const [catalogue,policies]=await Promise.all([
        api('/api/v1/assessment/administration/catalogue'),
        api(`/api/v1/reports/sla-policies?group_id=${encodeURIComponent(readGroupId)}`)]);
      if(catalogue.status!==200||policies.status!==200)
        throw new Error(`scoped SLA publication read failed: ${JSON.stringify({catalogue:catalogue.status,policies:policies.status})}`);
      const command={command_id:crypto.randomUUID(),target_id:'00000000-0000-4000-8000-000000000000',
        action:'policy.sla.publish',membership_ids:[],expected_revisions:{
          target:catalogue.body.policy_revision,policy:catalogue.body.policy_revision,
          authority:catalogue.body.authority_revision,identity_membership:0,owners:0,
          sla_policy:policies.body.sla_policy_head},payload:{policy,rationale:'Publish scoped disposable staged SLA policy',
            evidence_ref:'g7-exception-sla-staged-policy-fixture'}};
      const response=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify(command)});
      if(response.status!==200)throw new Error(`public staged SLA policy publication failed ${response.status}: ${JSON.stringify(response.body)}`);
      if(!verifyPolicyReadback)
        return {request:command,response:response.body,readback:null,head:policies.body.sla_policy_head,
          readback_skipped:'target group has no membership and scoped SLA policy read correctly denies access'};
      const readback=await api(`/api/v1/reports/sla-policies?group_id=${encodeURIComponent(readGroupId)}`);
      if(readback.status!==200)throw new Error(`published SLA policy readback failed ${readback.status}: ${JSON.stringify(readback.body)}`);
      const published=readback.body.policies?.find(item=>item.policy_id===policy.policy_id&&item.version===policy.version);
      if(!published)throw new Error(`public SLA policy readback omitted the just-published policy: ${JSON.stringify(readback.body)}`);
      return {request:command,response:response.body,readback:published,head:readback.body.sla_policy_head};
    };
    const stagedPolicy=(policyId,version,startSource,effectiveFrom)=>({
      policy_id:policyId,version,effective_from:effectiveFrom,effective_until:null,
      scope:{group_ids:[preactivation.group_id],environments:['local'],service_ids:['g7-sla-service-covered']},
      eligibility:{included_severities:['critical','high'],excluded_classifications:[]},
      classification:{source_rating_map:{critical:'critical',low:'high'}},
      duration_seconds_by_severity:{critical:3600,high:86400},clock_basis:'elapsed_utc_seconds',
      deadline_reference_rules:{bindings:[]},backfill:{mode:'prospective'},start_source:startSource});
    const legacyActivationAt=await readClock();
    const legacyPolicy=stagedPolicy(
      'g7-exception-sla-staged-legacy-v1',1,'source_observation_v1',legacyActivationAt.toISOString());
    legacyPolicy.scope.environments=['local'];
    legacyPolicy.scope.service_ids=['g7-sla-service-legacy'];
    const legacyPublication=await publishPolicy(legacyPolicy);
    // Leave ample deterministic logical time after policy publication so the
    // source observation anchor is later than the policy's immutable created_at.
    const postLegacyAt=await advanceClock(10000);
    const postLegacy=JSON.parse(docker(['exec','-e','UVM_G7_SLA_STAGE=postlegacy',appContainer,
      '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_recovery_retained_fixture.py']));
    if(postLegacy.episode_id!==preactivation.episode_id||postLegacy.contract_version!==5)
      throw new Error(`post-legacy policy membership did not remain in the pinned G5 episode: ${JSON.stringify({preactivation,postLegacy})}`);
    const legacyReportCommand=crypto.randomUUID();
    const legacyReport=await api('/api/v1/reports',{method:'POST',write:true,body:JSON.stringify({
      schema_version:1,definition_version:'g5-metrics-v1',command_id:legacyReportCommand,
      mode:'as_known_at',scope:{group_ids:[preactivation.group_id]},
      as_of:postLegacyAt.toISOString(),known_at:postLegacyAt.toISOString()})});
    if(legacyReport.status!==200||!legacyReport.body.report_id)
      throw new Error(`pre-G7 G5 report creation failed ${legacyReport.status}: ${JSON.stringify(legacyReport.body)}`);
    let legacyReportRead;
    for(let attempt=0;attempt<30;attempt++){
      legacyReportRead=await api(`/api/v1/reports/${legacyReport.body.report_id}`);
      if(legacyReportRead.status===200&&legacyReportRead.body.status==='ready')break;
      await page.waitForTimeout(500);
    }
    if(legacyReportRead?.status!==200||legacyReportRead.body.status!=='ready')
      throw new Error(`pre-G7 G5 report did not become ready: ${JSON.stringify(legacyReportRead?.body)}`);
    const legacyAtoms=await api(`/api/v1/reports/${legacyReport.body.report_id}/atoms`);
    const legacyAtom=legacyAtoms.body.items?.find(item=>item.occurrence_id===postLegacy.occurrence_id);
    await writeFile(path.join(evidence,'sla-g5-policy-selection-diagnostic.json'),JSON.stringify({
      preactivation,legacy_publication:legacyPublication,post_legacy_membership:postLegacy,
      report_request:{command_id:legacyReportCommand,mode:'as_known_at',as_of:postLegacyAt.toISOString(),known_at:postLegacyAt.toISOString()},
      report_create:legacyReport.body,report_read:legacyReportRead.body,report_atoms:legacyAtoms.body},null,2),{mode:0o600});
    if(legacyAtoms.status!==200||!legacyAtom?.clock?.deadline
        ||Date.parse(legacyAtom.clock.start)!==Date.parse(postLegacy.observed_at)
        ||Date.parse(legacyAtom.clock.deadline)!==Date.parse(postLegacy.observed_at)+86400*1000
        ||legacyAtom.policy?.policy_id!=='g7-exception-sla-staged-legacy-v1')
      throw new Error(`G5 report writer did not calculate the source-observation deadline: ${JSON.stringify({postLegacy,legacy_publication:legacyPublication,legacyAtom})}`);
    await writeFile(path.join(evidence,'sla-g5-preactivation-public-lifecycle.json'),JSON.stringify({
      preactivation,legacy_publication:legacyPublication,post_legacy_membership:postLegacy,
      report_request:{command_id:legacyReportCommand,mode:'as_known_at',as_of:postLegacyAt.toISOString(),known_at:postLegacyAt.toISOString()},
      report_create:legacyReport.body,report_read:legacyReportRead.body,report_atoms:legacyAtoms.body},null,2),{mode:0o600});
    const g7ActivationAt=await advanceClock(1000);
    const prospectivePolicy=stagedPolicy(
      'g7-exception-sla-ingestion-fixture-v1',1,'uvm_ingest_commit_v1',g7ActivationAt.toISOString());
    prospectivePolicy.scope.group_ids=[g7TargetPreactivation.group_id];
    prospectivePolicy.scope.environments=['local'];
    prospectivePolicy.scope.service_ids=['g7-sla-service-covered','g7-sla-service-breached',
      'g7-sla-service-unknown','g7-sla-service-deadline-boundary','g7-sla-service-replacement','g7-sla-service-legacy'];
    const prospectivePublication=await publishPolicy(prospectivePolicy,preactivation.group_id,false);
    const postG7At=await advanceClock(10000);
    const postG7=JSON.parse(docker(['exec','-e','UVM_G7_SLA_STAGE=postg7',appContainer,
      '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_recovery_retained_fixture.py']));
    if(postG7.episode_id!==preactivation.episode_id||postG7.contract_version!==5)
      throw new Error(`post-G7 membership changed the pinned G5 episode: ${JSON.stringify({preactivation,postG7})}`);
    const legacyReportAfterActivation=await api(`/api/v1/reports/${legacyReport.body.report_id}`);
    const legacyAtomsAfterActivation=await api(`/api/v1/reports/${legacyReport.body.report_id}/atoms`);
    if(JSON.stringify(legacyReportAfterActivation.body)!==JSON.stringify(legacyReportRead.body)
        ||JSON.stringify(legacyAtomsAfterActivation.body)!==JSON.stringify(legacyAtoms.body))
      throw new Error('G7 activation or later G5 membership changed the already-issued preactivation G5 report');
    const mainFixtureOutput=docker(['exec','-e','UVM_G7_SLA_FIXTURE=1',
      '-e',`UVM_G7_SLA_EXPECTED_GROUP_ID=${g7TargetPreactivation.group_id}`,appContainer,
      '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_recovery_retained_fixture.py']);
    await writeFile(path.join(evidence,'sla-fixture-ids.json'),mainFixtureOutput+'\n',{mode:0o600});
    const seeded=JSON.parse(mainFixtureOutput);
    const contextMatrix=JSON.parse(docker(['exec','-e','UVM_G7_SLA_STAGE=context_matrix',appContainer,
      '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_recovery_retained_fixture.py']));
    await writeFile(path.join(evidence,'sla-context-retained-matrix.json'),JSON.stringify(contextMatrix,null,2),{mode:0o600});
    const findingId=seeded.group, members=seeded.members;
    const memberByKey=Object.fromEntries(members.map(member=>[member.key,member]));
    const deadlineBoundaryMember=members.find(member=>member.key==='deadline_boundary');
    const acceptanceMembers=members.filter(member=>!['deadline_boundary','replacement_member'].includes(member.key));
    const occurrenceIds=acceptanceMembers.map(member=>member.occurrence);
    const ingestAt=Date.parse(seeded.ingested_at);
    if (!Number.isFinite(ingestAt) || Date.parse(seeded.observed_at)>=ingestAt
        || Date.parse(seeded.collected_at)>=ingestAt)
      throw new Error('authoritative fixture did not separate the older observation/collection times from UVM retention');
    const pauseAt=new Date(ingestAt+18*60*60*1000);
    const expiry=new Date(pauseAt.getTime()+60*1000);

    // Exercise the actual rendered exception forms against the scoped public
    // API using the dedicated deadline-boundary membership. Revoke this short
    // fixture exception before advancing the deterministic SLA clock.
    const uiOccurrence=deadlineBoundaryMember.occurrence;
    const uiFlowNow=new Date(ingestAt+1000);
    await writeFile(clockPath,uiFlowNow.toISOString()+'\n',{mode:0o666});
    const uiGroupReads=[],uiSlaReads=[],uiCapturePromises=[];
    page.on('response',response=>{
      let url;
      try{url=new URL(response.url());}catch{return;}
      if(response.request().method()!=='GET'||response.status()!==200)return;
      if(url.pathname==='/api/v1/assessment/groups/'+encodeURIComponent(findingId)
          ||url.pathname==='/api/v1/reports/sla-policies') {
        uiCapturePromises.push(response.json().then(body=>{
          if(url.pathname==='/api/v1/assessment/groups/'+encodeURIComponent(findingId))
            uiGroupReads.push(body);
          else if(url.searchParams.get('group_id')===findingId)uiSlaReads.push(body);
        }).catch(()=>{}));
      }
    });
    await page.goto(origin+'/#findings?group='+encodeURIComponent(findingId),{waitUntil:'domcontentloaded'});
    await page.waitForTimeout(1200);
    await page.locator('.assessment-workspace .load-status').filter({hasText:'Finding assessment loaded.'})
      .waitFor({state:'visible',timeout:20000});
    await page.getByRole('button',{name:'Exceptions',exact:true}).waitFor({state:'visible',timeout:20000});
    await page.getByRole('button',{name:'Exceptions',exact:true}).click();
    const requestExceptionButtons=page.getByRole('button',{name:'Request an exception',exact:true});
    await requestExceptionButtons.first().waitFor({state:'visible',timeout:10000});
    let uiFormActionReady=false;
    try {
      await page.waitForFunction(()=>Array.from(document.querySelectorAll('button'))
        .some(button=>button.textContent?.trim()==='Request an exception'&&!button.disabled),
        null,{timeout:10000});
      uiFormActionReady=true;
    } catch {}
    if(!uiFormActionReady) {
      const uiPermissionProbe=await api('/api/v1/assessment/permissions?group_id='+encodeURIComponent(findingId));
      await writeFile(path.join(evidence,'sla-ui-form-permission-diagnostic.json'),JSON.stringify({
        permission_status:uiPermissionProbe.status,permission_body:uiPermissionProbe.body,
        rendered_workspace:(await page.locator('.assessment-workspace').innerText()).slice(0,8000),
        request_buttons:await requestExceptionButtons.evaluateAll(buttons=>buttons.map(button=>({
          disabled:button.disabled,title:button.title,within:button.closest('section')?.getAttribute('aria-label')??null})))},null,2),{mode:0o600});
      throw new Error('rendered exception form remains disabled after the scoped workspace loaded');
    }
    await requestExceptionButtons.first().click();
    const uiSubmitDialog=page.getByRole('dialog',{name:'Request an exception',exact:true});
    await uiSubmitDialog.getByRole('checkbox',{name:uiOccurrence,exact:true}).check();
    await uiSubmitDialog.getByLabel('Accountable owner').selectOption(ownerDirectoryId);
    await uiSubmitDialog.getByLabel('Resource context').fill('Synthetic rendered-form context for the deadline-boundary membership.');
    await uiSubmitDialog.getByLabel('Compensating controls').fill('Disposable local controls while the test exception is active.');
    const uiExpiryValue=expiry.toISOString().slice(0,19);
    await uiSubmitDialog.getByLabel('Proposed expiry (UTC)').fill(uiExpiryValue);
    await uiSubmitDialog.getByLabel('Reason').fill('Exercise actual rendered exception submission and approval.');
    await uiSubmitDialog.getByRole('checkbox',{name:/I have reviewed the instances and current details above/}).check();
    const uiSubmitGroup=uiGroupReads.at(-1),uiSubmitSla=uiSlaReads.at(-1);
    if(!uiSubmitGroup||!uiSubmitSla||uiSubmitGroup.group?.group_id!==findingId
        ||!Number.isSafeInteger(uiSubmitGroup.assessment?.authority_revision)
        ||uiSubmitGroup.assessment.authority_revision<0||uiSubmitSla.group_id!==findingId
        ||uiSubmitSla.policy_revision!==uiSubmitGroup.assessment.policy_revision)
      throw new Error('actual UI submit form lacks its same-response scoped group and SLA readbacks');
    const uiSubmitExposures=uiSubmitSla.current_heads.episodes
      .filter(item=>item.episode_id===deadlineBoundaryMember.episode)
      .map(({exposure_id,episode_id,state_revision})=>({exposure_id,episode_id,state_revision}));
    const uiSubmitEvaluation=uiSubmitSla.current_heads.evaluations
      .filter(item=>item.occurrence_id===uiOccurrence)
      .map(({episode_id,occurrence_id,evaluation_id,revision})=>({episode_id,occurrence_id,evaluation_id,revision}));
    if(uiSubmitExposures.length!==1||uiSubmitEvaluation.length!==1)
      throw new Error('actual UI submit fixture lacks exact current episode/evaluation heads');
    const uiSubmitResponsePromise=page.waitForResponse(response=>
      response.url().endsWith('/api/v1/assessment/commands')&&response.request().method()==='POST');
    await uiSubmitDialog.getByRole('button',{name:'Save decision',exact:true}).click();
    const uiSubmitResponse=await uiSubmitResponsePromise;
    const uiSubmitCommand=uiSubmitResponse.request().postDataJSON();
    const uiSubmitReceipt=await uiSubmitResponse.json();
    if(uiSubmitResponse.status()!==200||uiSubmitCommand.action!=='acceptance.submit'
        ||uiSubmitCommand.target_id!==findingId||JSON.stringify(uiSubmitCommand.membership_ids)!==JSON.stringify([uiOccurrence])
        ||uiSubmitCommand.expected_revisions?.authority!==uiSubmitGroup.assessment.authority_revision
        ||uiSubmitCommand.expected_revisions?.target!==uiSubmitGroup.assessment.revision
        ||uiSubmitCommand.expected_revisions?.policy!==uiSubmitGroup.assessment.policy_revision
        ||uiSubmitCommand.expected_revisions?.identity_membership!==uiSubmitGroup.assessment.membership.revision
        ||uiSubmitCommand.expected_revisions?.owners!==uiSubmitGroup.assessment.owner_revision
        ||JSON.stringify(uiSubmitCommand.expected_exposures)!==JSON.stringify(uiSubmitExposures)
        ||JSON.stringify(uiSubmitCommand.expected_evaluations)!==JSON.stringify(uiSubmitEvaluation)
        ||uiSubmitCommand.payload?.exception_contract_version!==1
        ||uiSubmitCommand.payload?.accountable_owner_id!==ownerDirectoryId
        ||uiSubmitReceipt.command_id!==uiSubmitCommand.command_id
        ||!uiSubmitReceipt.audit_event_id||!uiSubmitReceipt.decision_id)
      throw new Error('actual rendered submit request or receipt differed from current public guards');
    await uiSubmitDialog.getByRole('region',{name:'Saved decision'}).waitFor({state:'visible'});
    await uiSubmitDialog.getByRole('button',{name:'Done',exact:true}).click();
    const uiAcceptanceId=(await api('/api/v1/assessment/groups/'+findingId)).body.assessment.acceptances
      .find(item=>item.state==='pending'&&item.membership_ids?.includes(uiOccurrence))?.acceptance_id;
    if(!uiAcceptanceId)throw new Error('actual rendered submit receipt did not resolve its pending acceptance');
    const approverContext=await browser.newContext({viewport:{width:1440,height:1000},deviceScaleFactor:1});
    await approverContext.route('**/api/v1/auth/login',async route=>{
      const response=await route.fetch({maxRedirects:0});
      const headers=response.headers();
      const loginUrl=new URL(headers.location);
      loginUrl.searchParams.set('fixture_subject','g7-exception-approver-subject');
      await route.fulfill({response,headers:{...headers,location:loginUrl.toString()}});
    });
    const approverPage=await approverContext.newPage();
    await approverPage.goto(origin+'/api/v1/auth/login',{waitUntil:'domcontentloaded'});
    await approverPage.waitForFunction(async()=>{
      const response=await fetch('/api/v1/auth/session',{cache:'no-store'});
      if(!response.ok)return false;
      const session=await response.json();
      return session.authenticated===true&&session.principal_id==='g7-exception-approver';
    },null,{timeout:20000});
    approverPage.on('response',response=>{
      let url;
      try{url=new URL(response.url());}catch{return;}
      if(response.request().method()!=='GET'||response.status()!==200)return;
      if(url.pathname==='/api/v1/assessment/groups/'+encodeURIComponent(findingId)
          ||url.pathname==='/api/v1/reports/sla-policies') {
        uiCapturePromises.push(response.json().then(body=>{
          if(url.pathname==='/api/v1/assessment/groups/'+encodeURIComponent(findingId))
            uiGroupReads.push(body);
          else if(url.searchParams.get('group_id')===findingId)uiSlaReads.push(body);
        }).catch(()=>{}));
      }
    });
    await approverPage.goto(origin+'/#findings?group='+encodeURIComponent(findingId),{waitUntil:'domcontentloaded'});
    await approverPage.locator('.assessment-workspace .load-status').filter({hasText:'Finding assessment loaded.'})
      .waitFor({state:'visible',timeout:20000});
    await approverPage.getByRole('button',{name:'Exceptions',exact:true}).click();
    await approverPage.locator('[data-exception-pending="'+uiAcceptanceId+'"]')
      .getByRole('button',{name:'Approve exception',exact:true}).click();
    const uiApproveDialog=approverPage.getByRole('dialog',{name:'Approve exception',exact:true});
    await uiApproveDialog.getByLabel('Approved expiry (UTC)').fill(uiExpiryValue);
    await uiApproveDialog.getByLabel('Reason').fill('Approve the rendered synthetic exception request.');
    await uiApproveDialog.getByRole('checkbox',{name:/I have reviewed the instances and current details above/}).check();
    await Promise.all(uiCapturePromises);
    const uiApproveGroup=uiGroupReads.at(-1),uiApproveSla=uiSlaReads.at(-1);
    if(!uiApproveGroup||!uiApproveSla
        ||!Number.isSafeInteger(uiApproveGroup.assessment?.authority_revision)
        ||uiApproveGroup.assessment.authority_revision<0
        ||uiApproveSla.policy_revision!==uiApproveGroup.assessment.policy_revision)
      throw new Error('actual UI approve form lacks fresh scoped group and SLA reads');
    const uiApproveResponsePromise=approverPage.waitForResponse(response=>
      response.url().endsWith('/api/v1/assessment/commands')&&response.request().method()==='POST');
    await uiApproveDialog.getByRole('button',{name:'Save decision',exact:true}).click();
    const uiApproveResponse=await uiApproveResponsePromise;
    const uiApproveCommand=uiApproveResponse.request().postDataJSON();
    const uiApproveReceipt=await uiApproveResponse.json();
    if(uiApproveResponse.status()!==200||uiApproveCommand.action!=='acceptance.approve'
        ||uiApproveCommand.target_id!==findingId||JSON.stringify(uiApproveCommand.membership_ids)!==JSON.stringify([uiOccurrence])
        ||uiApproveCommand.expected_revisions?.authority!==uiApproveGroup.assessment.authority_revision
        ||uiApproveCommand.expected_revisions?.target!==uiApproveGroup.assessment.revision
        ||uiApproveCommand.expected_revisions?.policy!==uiApproveGroup.assessment.policy_revision
        ||uiApproveCommand.expected_revisions?.identity_membership!==uiApproveGroup.assessment.membership.revision
        ||uiApproveCommand.expected_revisions?.owners!==uiApproveGroup.assessment.owner_revision
        ||uiApproveCommand.payload?.expected_request_revision!==1
        ||uiApproveCommand.payload?.selected_expires_at!==expiry.toISOString()
        ||uiApproveReceipt.command_id!==uiApproveCommand.command_id
        ||!uiApproveReceipt.audit_event_id||!uiApproveReceipt.decision_id)
      throw new Error('actual rendered approve request or receipt differed from current public guards');
    await uiApproveDialog.getByRole('region',{name:'Saved decision'}).waitFor({state:'visible'});
    await uiApproveDialog.getByRole('button',{name:'Done',exact:true}).click();
    await approverContext.close();
    const uiApprovedRead=await api('/api/v1/assessment/groups/'+findingId);
    const uiApprovedAcceptance=uiApprovedRead.body.assessment.acceptances
      .find(item=>item.acceptance_id===uiAcceptanceId);
    if(uiApprovedRead.status!==200||uiApprovedAcceptance?.state!=='active'
        ||!uiApprovedAcceptance.sla_clock?.some(clock=>clock.occurrence_id===uiOccurrence))
      throw new Error('actual rendered approval has no public active state or per-atom SLA clock');
    const uiRevokeCatalogue=await api('/api/v1/reports/sla-policies?group_id='+encodeURIComponent(findingId));
    const uiRevokeRequest={command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.revoke',
      membership_ids:[uiOccurrence],expected_revisions:{target:uiApprovedRead.body.assessment.revision,
        policy:uiApprovedRead.body.assessment.policy_revision,
        authority:uiApprovedRead.body.assessment.authority_revision,
        identity_membership:uiApprovedRead.body.assessment.membership.revision,
        owners:uiApprovedRead.body.assessment.owner_revision},
      expected_exposures:uiRevokeCatalogue.body.current_heads.episodes
        .filter(item=>item.episode_id===deadlineBoundaryMember.episode)
        .map(({exposure_id,episode_id,state_revision})=>({exposure_id,episode_id,state_revision})),
      expected_evaluations:uiRevokeCatalogue.body.current_heads.evaluations
        .filter(item=>item.occurrence_id===uiOccurrence)
        .map(({episode_id,occurrence_id,evaluation_id,revision})=>({episode_id,occurrence_id,evaluation_id,revision})),
      payload:{acceptance_id:uiAcceptanceId,rationale:'End temporary UI form validation before the SLA deadline journey.'}};
    const uiRevoke=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify(uiRevokeRequest)});
    const uiRevokedRead=await api('/api/v1/assessment/groups/'+findingId);
    const uiRevokedAcceptance=uiRevokedRead.body.assessment.acceptances
      .find(item=>item.acceptance_id===uiAcceptanceId);
    if(uiRevoke.status!==200||uiRevokedAcceptance?.state!=='revoked'
        ||uiRevokedAcceptance.effective_membership_ids?.length!==0)
      throw new Error('early public revoke after actual UI approval did not remove effective membership');
    await writeFile(path.join(evidence,'sla-ui-form-submit-approve.json'),JSON.stringify({
      membership_id:uiOccurrence,authority_read_source:'actual scoped group GET captured from rendered forms',
      submit:{group_view:uiSubmitGroup,sla_catalogue:uiSubmitSla,request:uiSubmitCommand,
        status:uiSubmitResponse.status(),receipt:uiSubmitReceipt},
      approval:{group_view:uiApproveGroup,sla_catalogue:uiApproveSla,request:uiApproveCommand,
        status:uiApproveResponse.status(),receipt:uiApproveReceipt},
      revoke:{request:uiRevokeRequest,response:uiRevoke.body,acceptance:uiRevokedAcceptance},
      assertions:{actual_rendered_submit_and_approve:true,authority_bound_to_exact_group_get:true,
        current_episode_and_evaluation_guards:true,successful_receipts_bound_to_commands:true}},null,2),{mode:0o600});

    await writeFile(clockPath,pauseAt.toISOString()+'\n',{mode:0o666});
    const g7ReportCommand=crypto.randomUUID();
    const g7Report=await api('/api/v1/reports',{method:'POST',write:true,body:JSON.stringify({
      schema_version:1,definition_version:'g7-exception-sla-v1',command_id:g7ReportCommand,
      mode:'as_known_at',scope:{group_ids:[findingId]},as_of:pauseAt.toISOString(),
      known_at:pauseAt.toISOString()})});
    if(g7Report.status!==200||!g7Report.body.report_id)
      throw new Error(`public G7 continuity report creation failed ${g7Report.status}: ${JSON.stringify(g7Report.body)}`);
    let reportRead;
    for(let attempt=0;attempt<30;attempt++) {
      reportRead=await api(`/api/v1/reports/${g7Report.body.report_id}`);
      if(reportRead.status===200&&reportRead.body.status==='ready')break;
      await page.waitForTimeout(500);
    }
    if(reportRead?.status!==200||reportRead.body.status!=='ready')
      throw new Error(`public G7 continuity report did not become ready: ${JSON.stringify(reportRead?.body)}`);
    const g7Atoms=await api(`/api/v1/reports/${g7Report.body.report_id}/atoms`);
    if(g7Atoms.status!==200)throw new Error(`public G7 continuity atoms failed ${g7Atoms.status}: ${JSON.stringify(g7Atoms.body)}`);
    const g7AtomByOccurrence=Object.fromEntries(g7Atoms.body.items.map(item=>[item.occurrence_id,item]));
    const matrixAtoms={};
    for(const name of ['missing_environment','later_environment_not_admitted','missing_service',
        'later_service_not_admitted','optional_unused_absent','omitted_followup']) {
      const retained=contextMatrix[name];
      const atom=g7AtomByOccurrence[retained.occurrence_id];
      matrixAtoms[name]=atom;
      if(!atom)throw new Error(`public context matrix omitted ${name}`);
      const shouldGap=name.includes('missing')||name.includes('not_admitted');
      if(shouldGap?(!atom.gap_reasons?.length||atom.clock.deadline!=null):
          (!atom.clock.deadline||Date.parse(atom.clock.start)!==Date.parse(retained.receipt.ingested_at)
            ||retained.head.policy_id!==prospectivePolicy.policy_id))
        throw new Error(`public context selector/coverage matrix failed: ${JSON.stringify({name,retained,atom})}`);
    }
    if(contextMatrix.optional_unused_absent.head.evaluation_id!==contextMatrix.known_head_after_followups.evaluation_id
        ||contextMatrix.omitted_followup.occurrence_id!==contextMatrix.optional_unused_absent.occurrence_id
        ||contextMatrix.conflicting_followup.occurrence_id!=null)
      throw new Error('omitted/conflicting context changed the established known clock/head');
    await writeFile(path.join(evidence,'sla-context-public-matrix.json'),JSON.stringify({
      retained_inputs_and_receipts:contextMatrix,policy:prospectivePolicy,publication:prospectivePublication,
      report:g7Report.body,public_atoms:matrixAtoms},null,2),{mode:0o600});
    for(const member of members) {
      const atom=g7AtomByOccurrence[member.occurrence];
      const anchorMatches=Date.parse(atom?.clock?.start)===ingestAt
        &&(member.deadline_at
          ? Date.parse(atom?.clock?.original_deadline_at)===Date.parse(member.deadline_at)
          : atom?.clock?.original_deadline_at==null);
      if(!atom||!anchorMatches)
        throw new Error(`public G7 report lost authoritative membership anchor/deadline: ${JSON.stringify({member,atom})}`);
    }
    if(!deadlineBoundaryMember)
      throw new Error('authoritative fixture omitted the dedicated public deadline-boundary membership');
    const deadlineBoundaryAtom=g7AtomByOccurrence[deadlineBoundaryMember.occurrence];
    const uiApprovalAt=uiApprovedAcceptance.pause_snapshots?.[0]?.approved_at;
    const uiEndAt=uiRevokedAcceptance.history?.at(-1)?.at;
    for(const [label,value] of Object.entries({submitted:uiRevokedAcceptance.submitted_at,
        approved:uiApprovalAt,revoked:uiEndAt})) {
      if(Date.parse(value)!==uiFlowNow.getTime())
        throw new Error(`UI ${label} effective time differs from trusted fixture clock: ${value}`);
    }
    const uiPauseDurationMs=Date.parse(uiEndAt)-Date.parse(uiApprovalAt);
    const expectedBoundaryDeadline=Date.parse(deadlineBoundaryMember.deadline_at)+uiPauseDurationMs;
    if(!deadlineBoundaryAtom||!deadlineBoundaryMember.deadline_at
        ||Date.parse(deadlineBoundaryAtom.clock.deadline)!==expectedBoundaryDeadline)
      throw new Error(`deadline-boundary member differs from independent receipt plus pause interval: ${JSON.stringify({deadlineBoundaryMember,deadlineBoundaryAtom,uiApprovalAt,uiEndAt})}`);
    await writeFile(path.join(evidence,'sla-writer-deadline-reconciliation.json'),JSON.stringify({
      original_writer_deadline_at:deadlineBoundaryMember.deadline_at,
      intended_ui_effective_at:uiFlowNow.toISOString(),actual_ui_approval_at:uiApprovalAt,
      actual_ui_end_at:uiEndAt,pause_duration_ms:uiPauseDurationMs,
      independently_expected_deadline_at:new Date(expectedBoundaryDeadline).toISOString(),
      public_report_deadline_at:deadlineBoundaryAtom.clock.deadline},null,2),{mode:0o600});
    await writeFile(path.join(evidence,'sla-continuity-g7-public-report.json'),JSON.stringify({
      create:g7Report.body,read:reportRead.body,atoms:g7Atoms.body,command_id:g7ReportCommand},null,2),{mode:0o600});
    const g5=seeded.g5_compatibility;
    const g5ReportCommand=crypto.randomUUID();
    const g5Report=await api('/api/v1/reports',{method:'POST',write:true,body:JSON.stringify({
      schema_version:1,definition_version:'g5-metrics-v1',command_id:g5ReportCommand,
      mode:'as_known_at',scope:{group_ids:[g5.group]},as_of:pauseAt.toISOString(),
      known_at:pauseAt.toISOString()})});
    if(g5Report.status!==200||!g5Report.body.report_id)
      throw new Error(`public G5 compatibility report creation failed ${g5Report.status}: ${JSON.stringify(g5Report.body)}`);
    let g5ReportRead;
    for(let attempt=0;attempt<30;attempt++) {
      g5ReportRead=await api(`/api/v1/reports/${g5Report.body.report_id}`);
      if(g5ReportRead.status===200&&g5ReportRead.body.status==='ready')break;
      await page.waitForTimeout(500);
    }
    if(g5ReportRead?.status!==200||g5ReportRead.body.status!=='ready')
      throw new Error(`public G5 compatibility report did not become ready: ${JSON.stringify(g5ReportRead?.body)}`);
    const g5Atoms=await api(`/api/v1/reports/${g5Report.body.report_id}/atoms`);
    const g5Atom=g5Atoms.body.items?.find(item=>item.occurrence_id===g5.occurrence);
    if(g5Atoms.status!==200||!g5Atom
        ||Date.parse(g5Atom.clock.start)!==Date.parse(g5.observed_at)
        ||Date.parse(g5Atom.clock.start)===Date.parse(g5.ingested_at))
      throw new Error(`G5 source-observation anchor was changed by prospective G7 setup: ${JSON.stringify({g5,g5Atom})}`);
    await writeFile(path.join(evidence,'g5-prospective-compatibility-public-report.json'),JSON.stringify({
      fixture:g5,create:g5Report.body,read:g5ReportRead.body,atoms:g5Atoms.body,
      scanner_observation_anchor_preserved:true},null,2),{mode:0o600});
    let current=await api(`/api/v1/assessment/groups/${findingId}`);
    if(current.status!==200)throw new Error(`SLA fixture public read failed ${current.status}: ${JSON.stringify(current.body)}`);
    const scopedAuthority=(await api('/api/v1/assessment/administration/catalogue')).body.authority_revision;
    if(!Number.isSafeInteger(current.body.assessment.authority_revision)
        ||current.body.assessment.authority_revision<0
        ||current.body.assessment.authority_revision!==scopedAuthority)
      throw new Error(`scoped assessment read authority revision disagrees with current native authority: ${JSON.stringify({read:current.body.assessment.authority_revision,catalogue:scopedAuthority})}`);
    const episodes=current.body.episodes??[];
    const expectedExposureMap=new Map();
    for(const member of members){
      const episode=episodes.find(item=>item.exposure_id===member.exposure);
      if(!episode)throw new Error(`public finding omitted the writer-created episode ${member.episode}`);
      if(episode.episode_id!==member.episode)throw new Error(`writer-created episode changed for ${member.occurrence}`);
      expectedExposureMap.set(episode.exposure_id,{exposure_id:episode.exposure_id,
        episode_id:episode.episode_id,state_revision:episode.state_revision});
    }
    const expectedExposures=[...expectedExposureMap.values()].filter(item=>
      acceptanceMembers.some(member=>member.exposure===item.exposure_id));
    const transferredMember=memberByKey.covered_six_hours;
    const portionId=crypto.randomUUID();
    const definePortion=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'portion.define',
      membership_ids:[transferredMember.occurrence],expected_revisions:{
        target:current.body.assessment.revision,policy:current.body.assessment.policy_revision,
        authority:current.body.assessment.authority_revision,identity_membership:current.body.assessment.membership.revision,
        owners:current.body.assessment.owner_revision},payload:{portion_id:portionId,
        owner_ids:[transferOwnerBeforeId],membership_ids:[transferredMember.occurrence],
        rationale:'Define exact synthetic membership ownership before transfer'}})});
    if(definePortion.status!==200)throw new Error(`public portion definition failed ${definePortion.status}: ${JSON.stringify(definePortion.body)}`);
    const beforeTransfer=await api(`/api/v1/assessment/groups/${findingId}`);
    const transfer=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'portion.transfer',
      membership_ids:[transferredMember.occurrence],expected_revisions:{
        target:beforeTransfer.body.assessment.revision,policy:beforeTransfer.body.assessment.policy_revision,
        authority:beforeTransfer.body.assessment.authority_revision,
        identity_membership:beforeTransfer.body.assessment.membership.revision,
        owners:beforeTransfer.body.assessment.owner_revision},payload:{portion_id:portionId,
        owner_ids:[transferOwnerAfterId],membership_ids:[transferredMember.occurrence],
        rationale:'Transfer the exact synthetic membership to a new owner'}})});
    if(transfer.status!==200)throw new Error(`public owner transfer failed ${transfer.status}: ${JSON.stringify(transfer.body)}`);
    current=await api(`/api/v1/assessment/groups/${findingId}`);
    const transferredPortion=current.body.assessment.portions.find(item=>item.portion_id===portionId);
    if(current.status!==200||!transferredPortion
        ||JSON.stringify(transferredPortion.owner_ids)!==JSON.stringify([transferOwnerAfterId])
        ||transferredPortion.membership_ids.length!==1
        ||transferredPortion.membership_ids[0]!==transferredMember.occurrence)
      throw new Error(`public owner transfer readback did not preserve exact membership: ${JSON.stringify(transferredPortion)}`);
    const publicAnchorBefore=beforeTransfer.body.assessment.clocks.find(item=>item.occurrence_id===transferredMember.occurrence);
    const publicAnchorAfter=current.body.assessment.clocks.find(item=>item.occurrence_id===transferredMember.occurrence);
    const reportAnchorBefore=g7AtomByOccurrence[transferredMember.occurrence];
    const reportAfterOwnerTransfer=await api(`/api/v1/reports/${g7Report.body.report_id}`);
    const atomsAfterOwnerTransfer=await api(`/api/v1/reports/${g7Report.body.report_id}/atoms`);
    const reportAnchorAfter=atomsAfterOwnerTransfer.body.items.find(item=>item.occurrence_id===transferredMember.occurrence);
    if(!publicAnchorBefore||!publicAnchorAfter||!reportAnchorBefore||!reportAnchorAfter
        ||publicAnchorBefore.first_ingested_at!==publicAnchorAfter.first_ingested_at
        ||reportAnchorBefore.clock.start!==reportAnchorAfter.clock.start
        ||reportAnchorBefore.clock.original_deadline_at!==reportAnchorAfter.clock.original_deadline_at)
      throw new Error('fresh public readbacks do not prove the exact membership anchor survived owner transfer');
    if(reportAfterOwnerTransfer.status!==200
        ||JSON.stringify(reportAfterOwnerTransfer.body)!==JSON.stringify(reportRead.body)
        ||atomsAfterOwnerTransfer.status!==200
        ||JSON.stringify(atomsAfterOwnerTransfer.body)!==JSON.stringify(g7Atoms.body))
      throw new Error('owner transfer mutated the already-issued G7 continuity report');
    const g5ReportAfterTransfer=await api(`/api/v1/reports/${g5Report.body.report_id}`);
    const g5AtomsAfterTransfer=await api(`/api/v1/reports/${g5Report.body.report_id}/atoms`);
    if(g5ReportAfterTransfer.status!==200||g5AtomsAfterTransfer.status!==200
        ||JSON.stringify(g5ReportAfterTransfer.body)!==JSON.stringify(g5ReportRead.body)
        ||JSON.stringify(g5AtomsAfterTransfer.body)!==JSON.stringify(g5Atoms.body))
      throw new Error('owner transfer or G7 activation mutated the already-issued G5 report');
    await writeFile(path.join(evidence,'sla-owner-transfer-public-readback.json'),JSON.stringify({
      define:definePortion.body,transfer:transfer.body,portion:transferredPortion,
      membership_anchor_before:{source:'public group and report readbacks',
        group_clock:publicAnchorBefore,report_atom:reportAnchorBefore},
      membership_anchor_after:{source:'fresh public group and report readbacks',
        group_clock:publicAnchorAfter,report_atom:reportAnchorAfter},
      expected_deadline_at:transferredMember.deadline_at,
      issued_g7_report_id:g7Report.body.report_id,
      report_unchanged_after_transfer:true,
      issued_g5_report_id:g5Report.body.report_id,
      g5_report_unchanged_after_transfer:true},null,2),{mode:0o600});
    await writeFile(path.join(evidence,'sla-before-exception-readback.json'),JSON.stringify(current.body,null,2),{mode:0o600});
    const expectedEvaluations=acceptanceMembers.map(member=>({episode_id:member.episode,occurrence_id:member.occurrence,
      evaluation_id:member.evaluation,revision:member.revision}));
    const unknownMember=memberByKey.unknown_coverage;
    const unknownEvaluation=expectedEvaluations.find(item=>item.occurrence_id===unknownMember.occurrence);
    const unknownExposure=expectedExposures.find(item=>item.exposure_id===unknownMember.exposure);
    const rejectSubmit=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.submit',
      membership_ids:[unknownMember.occurrence],expected_revisions:{target:current.body.assessment.revision,
        policy:current.body.assessment.policy_revision,authority:current.body.assessment.authority_revision,
        identity_membership:current.body.assessment.membership.revision,
        owners:current.body.assessment.owner_revision},expected_exposures:[unknownExposure],
      expected_evaluations:[unknownEvaluation],payload:{accountable_owner_id:ownerDirectoryId,
        rationale:'Exercise public rejection while preserving unknown coverage as a gap',
        expires_at:expiry.toISOString(),continuity_allowed:false,exception_contract_version:1,
        context:{environment:'local',evidence:'synthetic-local'},
        compensating_controls:'Synthetic disposable journey controls.'}})});
    if(rejectSubmit.status!==200)throw new Error(`public rejection fixture submit failed ${rejectSubmit.status}: ${JSON.stringify(rejectSubmit.body)}`);
    let rejectState=await api(`/api/v1/assessment/groups/${findingId}`);
    const rejectAcceptanceId=rejectState.body.assessment.acceptances.find(item=>item.state==='pending'
      &&item.membership_ids?.length===1&&item.membership_ids[0]===unknownMember.occurrence)?.acceptance_id;
    if(!rejectAcceptanceId)throw new Error('unknown-coverage rejection request was not pending');
    const rejectCurrent=rejectState.body.assessment;
    const rejectCommand=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.reject',
      membership_ids:[unknownMember.occurrence],expected_revisions:{target:rejectCurrent.revision,
        policy:rejectCurrent.policy_revision,authority:rejectCurrent.authority_revision,
        identity_membership:rejectCurrent.membership.revision,owners:rejectCurrent.owner_revision},
      expected_exposures:[unknownExposure],expected_evaluations:[unknownEvaluation],
      payload:{acceptance_id:rejectAcceptanceId,rationale:'Reject synthetic exception request'}})});
    if(rejectCommand.status!==200)throw new Error(`public exception rejection failed ${rejectCommand.status}: ${JSON.stringify(rejectCommand.body)}`);
    rejectState=await api(`/api/v1/assessment/groups/${findingId}`);
    const rejectedAcceptance=rejectState.body.assessment.acceptances.find(item=>item.acceptance_id===rejectAcceptanceId);
    if(rejectState.status!==200||rejectedAcceptance?.state!=='rejected')
      throw new Error(`public exception rejection state was not retained: ${JSON.stringify(rejectedAcceptance)}`);
    await writeFile(path.join(evidence,'sla-rejected-public-readback.json'),JSON.stringify({
      submit:rejectSubmit.body,reject:rejectCommand.body,acceptance:rejectedAcceptance,
      unknown_coverage_remains_gap:true},null,2),{mode:0o600});
    current=await api(`/api/v1/assessment/groups/${findingId}`);
    const submit=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.submit',membership_ids:occurrenceIds,
      expected_revisions:{target:current.body.assessment.revision,policy:current.body.assessment.policy_revision,
        authority:current.body.assessment.authority_revision,
        identity_membership:current.body.assessment.membership.revision,owners:current.body.assessment.owner_revision},
      expected_exposures:expectedExposures,expected_evaluations:expectedEvaluations,
      payload:{accountable_owner_id:ownerDirectoryId,rationale:'Exercise ingestion-anchored G7 pause and resume',
        expires_at:expiry.toISOString(),continuity_allowed:false,exception_contract_version:1,
        context:{environment:'local',evidence:'synthetic-local'},
        compensating_controls:'Synthetic disposable journey controls.'}})});
    if(submit.status!==200)throw new Error(`G7 SLA public submit failed ${submit.status}: ${JSON.stringify(submit.body)}`);
    let afterSubmit=await api(`/api/v1/assessment/groups/${findingId}`);
    const acceptanceId=afterSubmit.body.assessment.acceptances.find(item=>item.state==='pending')?.acceptance_id;
    if(!acceptanceId)throw new Error(`public submit did not return the pending request: ${JSON.stringify(afterSubmit.body.assessment.acceptances)}`);
    const approvalBody={command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.approve',
      membership_ids:occurrenceIds,expected_revisions:{target:afterSubmit.body.assessment.revision,
        policy:afterSubmit.body.assessment.policy_revision,authority:afterSubmit.body.assessment.authority_revision,
        identity_membership:afterSubmit.body.assessment.membership.revision,
        owners:afterSubmit.body.assessment.owner_revision},expected_exposures:expectedExposures,
      expected_evaluations:expectedEvaluations,payload:{acceptance_id:acceptanceId,
        rationale:'Approve the synthetic ingestion-anchored exception',selected_expires_at:expiry.toISOString(),
        expected_request_revision:1}};
    const auditBeforeStale=await api(`/api/v1/assessment/audit?group_id=${encodeURIComponent(findingId)}`);
    if(auditBeforeStale.status!==200)throw new Error(`pre-denial public audit read failed ${auditBeforeStale.status}`);
    const staleAuthorityRequest={...approvalBody,command_id:crypto.randomUUID(),expected_revisions:{
      ...approvalBody.expected_revisions,authority:approvalBody.expected_revisions.authority+1}};
    const staleAuthority=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify(staleAuthorityRequest)});
    if(staleAuthority.status!==409)throw new Error(`stale authority approval was not denied without effects: ${staleAuthority.status} ${JSON.stringify(staleAuthority.body)}`);
    const staleMembershipRequest={...approvalBody,command_id:crypto.randomUUID(),expected_revisions:{
      ...approvalBody.expected_revisions,identity_membership:approvalBody.expected_revisions.identity_membership+1}};
    const staleMembership=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify(staleMembershipRequest)});
    if(staleMembership.status!==409)throw new Error(`stale membership approval was not denied without effects: ${staleMembership.status} ${JSON.stringify(staleMembership.body)}`);
    // A receipt replay would return the committed success. Replaying the exact
    // denied command IDs must reach the same guards and remain denied.
    const staleAuthorityReplay=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify(staleAuthorityRequest)});
    const staleMembershipReplay=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify(staleMembershipRequest)});
    const afterStaleGuards=await api(`/api/v1/assessment/groups/${findingId}`);
    const auditAfterStale=await api(`/api/v1/assessment/audit?group_id=${encodeURIComponent(findingId)}`);
    await writeFile(path.join(evidence,'sla-stale-guard-public-readback.json'),JSON.stringify({
      stale_authority_request:staleAuthorityRequest,stale_authority_response:staleAuthority.body,
      stale_membership_request:staleMembershipRequest,stale_membership_response:staleMembership.body,
      stale_authority_replay_response:staleAuthorityReplay.body,
      stale_membership_replay_response:staleMembershipReplay.body,
      latest_receipt_after_denials:afterStaleGuards.body.assessment.latest_receipt,
      audit_before:auditBeforeStale.body,audit_after:auditAfterStale.body,
      pending_request_after_denials:afterStaleGuards.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId)},null,2),{mode:0o600});
    if(afterStaleGuards.status!==200||afterStaleGuards.body.assessment.acceptances.some(item=>
        item.acceptance_id===acceptanceId&&item.state==='active'))
      throw new Error('denied stale authority or membership command changed exception state');
    if(staleAuthorityReplay.status!==409||staleMembershipReplay.status!==409)
      throw new Error(`denied stale command replay found a committed receipt: ${JSON.stringify({
        authority:staleAuthorityReplay.status,membership:staleMembershipReplay.status})}`);
    if(auditAfterStale.status!==200||auditAfterStale.body.items.length!==auditBeforeStale.body.items.length
        ||auditAfterStale.body.items.some(item=>[staleAuthorityRequest.command_id,
          staleMembershipRequest.command_id].includes(item.command_id)))
      throw new Error(`denied stale command changed audit: ${JSON.stringify({before:auditBeforeStale.body.items,
        after:auditAfterStale.body.items,stale:[staleAuthorityRequest.command_id,staleMembershipRequest.command_id]})}`);
    const approveCommand={
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.approve',membership_ids:occurrenceIds,
      expected_revisions:{target:afterSubmit.body.assessment.revision,policy:afterSubmit.body.assessment.policy_revision,
        authority:afterSubmit.body.assessment.authority_revision,identity_membership:afterSubmit.body.assessment.membership.revision,
        owners:afterSubmit.body.assessment.owner_revision},expected_exposures:expectedExposures,
      expected_evaluations:expectedEvaluations,payload:{acceptance_id:acceptanceId,
        rationale:'Approve the synthetic ingestion-anchored exception',selected_expires_at:expiry.toISOString(),
        expected_request_revision:1}};
    const beforeAuditFault=await api(`/api/v1/assessment/groups/${findingId}`);
    const faultDbBefore=disposableDbSnapshot({commandId:approveCommand.command_id,acceptanceId,groupId:findingId});
    installApprovalAuditFault({commandId:approveCommand.command_id,groupId:findingId});
    let failedApproval;
    try {
      failedApproval=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify(approveCommand)});
    } finally {
      removeApprovalAuditFault();
    }
    const afterAuditFault=await api(`/api/v1/assessment/groups/${findingId}`);
    const faultDbAfter=disposableDbSnapshot({commandId:approveCommand.command_id,acceptanceId,groupId:findingId});
    const faultAfterAcceptance=afterAuditFault.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId);
    if(failedApproval.status!==503||failedApproval.body?.error?.code!=='dependency_unavailable'
        ||failedApproval.body?.error?.details?.outcome!=='not_committed'
        ||faultAfterAcceptance?.state!=='pending'
        ||JSON.stringify(faultAfterAcceptance)!==JSON.stringify(beforeAuditFault.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId))
        ||JSON.stringify(faultDbAfter)!==JSON.stringify(faultDbBefore))
      throw new Error(`approval audit failure rollback assertion failed: ${JSON.stringify({status:failedApproval.status,error:failedApproval.body?.error,dbBefore:faultDbBefore,dbAfter:faultDbAfter,acceptanceState:faultAfterAcceptance?.state,acceptanceBefore:beforeAuditFault.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId)?.state})}`);
    await writeFile(path.join(evidence,'sla-approval-audit-failure-rollback.json'),JSON.stringify({
      failed_request:approveCommand,failed_response:failedApproval,before_public:beforeAuditFault.body,
      after_public:afterAuditFault.body,db_before:faultDbBefore,db_after:faultDbAfter,
      rollback_assertions:{request_pending:true,no_pause_events:true,no_warning_intents:true,
        no_audit_or_receipt:true,no_projection_intents:true,group_document_unchanged:true}},null,2),{mode:0o600});
    const approve=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify(approveCommand)});
    if(approve.status!==200)throw new Error(`G7 SLA public approval failed ${approve.status}: ${JSON.stringify(approve.body)}`);
    const pausedRead=await api(`/api/v1/assessment/groups/${findingId}`);
    const pausedAcceptance=pausedRead.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId);
    const pausedClocks=Object.fromEntries((pausedAcceptance?.sla_clock??[]).map(clock=>[clock.occurrence_id,clock]));
    const coveredClock=pausedClocks[memberByKey.covered_six_hours.occurrence];
    const rebuiltClock=pausedClocks[memberByKey.verified_rebuild_membership.occurrence];
    const breachedClock=pausedClocks[memberByKey.already_breached.occurrence];
    const gapClock=pausedClocks[memberByKey.unknown_coverage.occurrence];
    if(pausedAcceptance?.state!=='active'||coveredClock?.state!=='paused'
        ||Date.parse(coveredClock?.target_at)!==expiry.getTime()
        ||Number(coveredClock?.frozen_sla_seconds)!==21600
        ||rebuiltClock?.state!=='paused'||Date.parse(rebuiltClock?.target_at)!==expiry.getTime()
        ||Number(rebuiltClock?.frozen_sla_seconds)!==21600
        ||breachedClock?.state!=='paused'||Number(breachedClock?.frozen_sla_seconds)!==0
        ||breachedClock?.prior_breach!==true||gapClock?.state!=='gap'
        ||gapClock?.target_at!=null||gapClock?.remaining_seconds!=null)
      throw new Error(`public SLA pause failed covered, breached, or unknown atom assertions: ${JSON.stringify({acceptance:pausedAcceptance,expectedExpiry:expiry.toISOString()})}`);
    await writeFile(path.join(evidence,'sla-paused-public-readback.json'),JSON.stringify({
      findingId,memberKeys:members.map(member=>member.key),acceptanceId,submit:submit.body,approve:approve.body,
      public_acceptance:pausedAcceptance,expected_ingest_at:seeded.ingested_at,
      expected_deadline_at:seeded.deadline_at,readback_at:pauseAt.toISOString()},null,2),{mode:0o600});
    await page.goto(origin+'/#findings?group='+encodeURIComponent(findingId),{waitUntil:'domcontentloaded'});
    await page.locator('.assessment-workspace .load-status').filter({hasText:'Finding assessment loaded.'})
      .waitFor({state:'visible',timeout:20000});
    const pausedExpected={group_id:findingId,acceptance_id:acceptanceId,state:'active',expires_at:expiry.toISOString(),
      sla_clock:acceptanceMembers.map(member=>({occurrence_id:member.occurrence,
        state:member.key==='unknown_coverage'?'gap':'paused',
        target_at:member.key==='unknown_coverage'?null:expiry.toISOString(),
        remaining_seconds:member.key==='unknown_coverage'?null:60,
        frozen_sla_seconds:member.key==='unknown_coverage'?null:member.key==='already_breached'?0:21600,
        prior_breach:member.key==='already_breached',currently_breached:false}))};
    await renderCurrentAcceptance(pausedExpected,'paused');
    await writeFile(clockPath,expiry.toISOString()+'\n',{mode:0o666});
    await writeFile(path.join(evidence,'sla-paused-clock.json'),expiry.toISOString()+'\n',{mode:0o666});
    await page.waitForTimeout(1500);
    const exactExpiryRead=await api(`/api/v1/assessment/groups/${findingId}`);
    const exactExpiryAcceptance=exactExpiryRead.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId);
    const exactExpiryClock=exactExpiryAcceptance?.sla_clock?.find(item=>item.occurrence_id===memberByKey.covered_six_hours.occurrence);
    const exactExpiryTarget=expiry.getTime()+21600*1000;
    if(exactExpiryAcceptance?.state!=='expired'||exactExpiryClock?.state!=='running'
        ||Date.parse(exactExpiryClock.target_at)!==exactExpiryTarget
        ||Number(exactExpiryClock.remaining_seconds)!==21600
        ||exactExpiryClock.frozen_sla_seconds!=null)
      throw new Error(`public exact-expiry projection did not end the half-open pause: ${JSON.stringify({acceptance:exactExpiryAcceptance,expectedTarget:new Date(exactExpiryTarget).toISOString()})}`);
    await writeFile(path.join(evidence,'sla-exact-expiry-public-readback.json'),JSON.stringify({
      effective_at:expiry.toISOString(),acceptance:exactExpiryAcceptance,
      expected_resumed_target:new Date(exactExpiryTarget).toISOString(),expected_remainder_seconds:21600},null,2),{mode:0o600});
    const resumedAt=new Date(expiry.getTime()+60*1000);
    await writeFile(clockPath,resumedAt.toISOString()+'\n',{mode:0o666});
    await page.waitForTimeout(1500);
    const resumedRead=await api(`/api/v1/assessment/groups/${findingId}`);
    const resumedAcceptance=resumedRead.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId);
    const resumedClocks=Object.fromEntries((resumedAcceptance?.sla_clock??[]).map(clock=>[clock.occurrence_id,clock]));
    const resumedCovered=resumedClocks[memberByKey.covered_six_hours.occurrence];
    const resumedRebuilt=resumedClocks[memberByKey.verified_rebuild_membership.occurrence];
    const resumedBreached=resumedClocks[memberByKey.already_breached.occurrence];
    const resumedGap=resumedClocks[memberByKey.unknown_coverage.occurrence];
    if(resumedRead.status!==200||resumedCovered?.state!=='running'
        ||Date.parse(resumedCovered.target_at)!==expiry.getTime()+6*60*60*1000
        ||Number(resumedCovered.remaining_seconds)!==21540
        ||resumedRebuilt?.state!=='running'
        ||Date.parse(resumedRebuilt.target_at)!==expiry.getTime()+6*60*60*1000
        ||Number(resumedRebuilt.remaining_seconds)!==21540
        ||resumedBreached?.state!=='running'||Number(resumedBreached.remaining_seconds)!==0
        ||resumedBreached?.prior_breach!==true||resumedBreached?.currently_breached!==true
        ||resumedGap?.state!=='gap'||resumedGap?.target_at!=null||resumedGap?.remaining_seconds!=null)
      throw new Error(`late expiry processing failed resume, prior breach, or gap assertions: ${JSON.stringify({status:resumedRead.status,clocks:resumedAcceptance?.sla_clock,expectedTarget:new Date(expiry.getTime()+6*60*60*1000).toISOString()})}`);
    await writeFile(path.join(evidence,'sla-resumed-public-readback.json'),JSON.stringify({
      readback_at:resumedAt.toISOString(),public_acceptance:resumedAcceptance},null,2),{mode:0o600});
    const resumedExpected={group_id:findingId,acceptance_id:acceptanceId,state:'expired',expires_at:expiry.toISOString(),
      sla_clock:acceptanceMembers.map(member=>({occurrence_id:member.occurrence,
        state:member.key==='unknown_coverage'?'gap':'running',
        target_at:member.key==='unknown_coverage'?null:member.key==='already_breached'?expiry.toISOString():new Date(exactExpiryTarget).toISOString(),
        remaining_seconds:member.key==='unknown_coverage'?null:member.key==='already_breached'?0:21540,
        frozen_sla_seconds:null,prior_breach:member.key==='already_breached',currently_breached:member.key==='already_breached'}))};
    await renderCurrentAcceptance(resumedExpected,'resumed');
    const beforeRevoke=await api(`/api/v1/assessment/groups/${findingId}`);
    const expiredRevokeRequest={
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.revoke',membership_ids:occurrenceIds,
      expected_revisions:{target:beforeRevoke.body.assessment.revision,
        policy:beforeRevoke.body.assessment.policy_revision,authority:beforeRevoke.body.assessment.authority_revision,
        identity_membership:beforeRevoke.body.assessment.membership.revision,
        owners:beforeRevoke.body.assessment.owner_revision},expected_exposures:expectedExposures,
      expected_evaluations:expectedEvaluations,payload:{acceptance_id:acceptanceId,
        rationale:'Attempt to revoke already expired synthetic exception'}};
    const auditBeforeExpiredRevoke=await api(`/api/v1/assessment/audit?group_id=${encodeURIComponent(findingId)}`);
    const expiredRevoke=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify(expiredRevokeRequest)});
    const expiredRevokeReplay=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify(expiredRevokeRequest)});
    const afterExpiredRevoke=await api(`/api/v1/assessment/groups/${findingId}`);
    const auditAfterExpiredRevoke=await api(`/api/v1/assessment/audit?group_id=${encodeURIComponent(findingId)}`);
    const unchangedExpiredAcceptance=afterExpiredRevoke.body.assessment.acceptances.find(item=>item.acceptance_id===acceptanceId);
    const expiredClockBefore=resumedAcceptance.sla_clock;
    const expiredClockAfter=unchangedExpiredAcceptance?.sla_clock;
    if(expiredRevoke.status!==409||expiredRevokeReplay.status!==409
        ||unchangedExpiredAcceptance?.state!=='expired'
        ||JSON.stringify(expiredClockAfter)!==JSON.stringify(expiredClockBefore)
        ||auditAfterExpiredRevoke.status!==200
        ||auditAfterExpiredRevoke.body.items.length!==auditBeforeExpiredRevoke.body.items.length
        ||auditAfterExpiredRevoke.body.items.some(item=>item.command_id===expiredRevokeRequest.command_id))
      throw new Error(`expired exception revoke was not a no-effect denial: ${JSON.stringify({first:expiredRevoke,replay:expiredRevokeReplay,acceptance:unchangedExpiredAcceptance,audit_before:auditBeforeExpiredRevoke.body,audit_after:auditAfterExpiredRevoke.body})}`);
    await writeFile(path.join(evidence,'sla-expired-revoke-denial-public-readback.json'),JSON.stringify({
      request:expiredRevokeRequest,response:expiredRevoke.body,replay:expiredRevokeReplay.body,
      acceptance_before:resumedAcceptance,acceptance_after:unchangedExpiredAcceptance,
      audit_before:auditBeforeExpiredRevoke.body,audit_after:auditAfterExpiredRevoke.body,
      clock_unchanged:true},null,2),{mode:0o600});

    // The expired decision remains terminal. A new request demonstrates an
    // authorised early revocation and resumes its captured remainder exactly.
    const earlyMember=memberByKey.covered_six_hours;
    const earlyExposure=expectedExposures.find(item=>item.exposure_id===earlyMember.exposure);
    const earlyEvaluation=expectedEvaluations.find(item=>item.occurrence_id===earlyMember.occurrence);
    let earlyBase=await api(`/api/v1/assessment/groups/${findingId}`);
    const earlyExpiry=new Date(resumedAt.getTime()+60*60*1000);
    const earlySubmit=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.submit',
      membership_ids:[earlyMember.occurrence],expected_revisions:{target:earlyBase.body.assessment.revision,
        policy:earlyBase.body.assessment.policy_revision,authority:earlyBase.body.assessment.authority_revision,
        identity_membership:earlyBase.body.assessment.membership.revision,
        owners:earlyBase.body.assessment.owner_revision},expected_exposures:[earlyExposure],
      expected_evaluations:[earlyEvaluation],payload:{accountable_owner_id:ownerDirectoryId,
        rationale:'Exercise early revocation and exact remainder resumption',expires_at:earlyExpiry.toISOString(),
        continuity_allowed:false,exception_contract_version:1,
        context:{environment:'local',evidence:'synthetic-local'},
        compensating_controls:'Synthetic disposable journey controls.'}})});
    if(earlySubmit.status!==200)throw new Error(`early-revocation request submit failed ${earlySubmit.status}: ${JSON.stringify(earlySubmit.body)}`);
    earlyBase=await api(`/api/v1/assessment/groups/${findingId}`);
    const earlyAcceptance=earlyBase.body.assessment.acceptances.find(item=>item.state==='pending'
      &&item.membership_ids?.length===1&&item.membership_ids[0]===earlyMember.occurrence);
    if(!earlyAcceptance)throw new Error('new early-revocation request is not pending');
    const earlyApprove=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.approve',
      membership_ids:[earlyMember.occurrence],expected_revisions:{target:earlyBase.body.assessment.revision,
        policy:earlyBase.body.assessment.policy_revision,authority:earlyBase.body.assessment.authority_revision,
        identity_membership:earlyBase.body.assessment.membership.revision,
        owners:earlyBase.body.assessment.owner_revision},expected_exposures:[earlyExposure],
      expected_evaluations:[earlyEvaluation],payload:{acceptance_id:earlyAcceptance.acceptance_id,
        rationale:'Approve short synthetic exception before early revocation',selected_expires_at:earlyExpiry.toISOString(),
        expected_request_revision:1}})});
    if(earlyApprove.status!==200)throw new Error(`early-revocation approval failed ${earlyApprove.status}: ${JSON.stringify(earlyApprove.body)}`);
    const earlyPausedRead=await api(`/api/v1/assessment/groups/${findingId}`);
    const earlyPaused=earlyPausedRead.body.assessment.acceptances.find(item=>item.acceptance_id===earlyAcceptance.acceptance_id);
    const earlyClock=earlyPaused?.sla_clock?.find(item=>item.occurrence_id===earlyMember.occurrence);
    if(earlyPaused?.state!=='active'||earlyClock?.state!=='paused'
        ||Number(earlyClock.frozen_sla_seconds)!==21540)
      throw new Error(`new request did not capture the current running remainder: ${JSON.stringify({state:earlyPaused?.state,clock:earlyClock})}`);
    const earlyRevokedAt=new Date(resumedAt.getTime()+30*60*1000);
    await writeFile(clockPath,earlyRevokedAt.toISOString()+'\n',{mode:0o666});
    const earlyCurrent=await api(`/api/v1/assessment/groups/${findingId}`);
    const earlyRevoke=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.revoke',
      membership_ids:[earlyMember.occurrence],expected_revisions:{target:earlyCurrent.body.assessment.revision,
        policy:earlyCurrent.body.assessment.policy_revision,authority:earlyCurrent.body.assessment.authority_revision,
        identity_membership:earlyCurrent.body.assessment.membership.revision,
        owners:earlyCurrent.body.assessment.owner_revision},expected_exposures:[earlyExposure],
      expected_evaluations:[earlyEvaluation],payload:{acceptance_id:earlyAcceptance.acceptance_id,
        rationale:'End the synthetic exception while its pause remains effective'}})});
    const afterEarlyRevoke=await api(`/api/v1/assessment/groups/${findingId}`);
    const earlyRevoked=afterEarlyRevoke.body.assessment.acceptances.find(item=>item.acceptance_id===earlyAcceptance.acceptance_id);
    const resumedEarlyClock=earlyRevoked?.sla_clock?.find(item=>item.occurrence_id===earlyMember.occurrence);
    const earlyTarget=earlyRevokedAt.getTime()+21540*1000;
    if(earlyRevoke.status!==200||earlyRevoked?.state!=='revoked'
        ||resumedEarlyClock?.state!=='running'||Date.parse(resumedEarlyClock.target_at)!==earlyTarget
        ||Number(resumedEarlyClock.remaining_seconds)!==21540||resumedEarlyClock.frozen_sla_seconds!=null)
      throw new Error(`public early revocation failed to resume the stored remainder: ${JSON.stringify({status:earlyRevoke.status,acceptance:earlyRevoked,expectedTarget:new Date(earlyTarget).toISOString()})}`);
    await writeFile(path.join(evidence,'sla-early-revocation-public-readback.json'),JSON.stringify({
      submit:earlySubmit.body,approve:earlyApprove.body,paused:earlyPaused,
      revoke:earlyRevoke.body,revoked:earlyRevoked,readback_at:earlyRevokedAt.toISOString(),
      expected_remaining_seconds:21540,expected_resumed_target:new Date(earlyTarget).toISOString()},null,2),{mode:0o600});

    const sharedMember=earlyMember;
    const removedMember=memberByKey.already_breached;
    const addedMember=memberByKey.replacement_member;
    const replacementBaseMembers=[sharedMember,removedMember];
    const replacementExpiry=new Date(earlyRevokedAt.getTime()+60*60*1000);
    let replacementBaseView=await api(`/api/v1/assessment/groups/${findingId}`);
    const replacementBaseExposures=[...expectedExposureMap.values()].filter(item=>
      replacementBaseMembers.some(member=>member.exposure===item.exposure_id));
    const replacementBaseEvaluations=replacementBaseMembers.map(member=>({episode_id:member.episode,
      occurrence_id:member.occurrence,evaluation_id:member.evaluation,revision:member.revision}));
    const initialOwners=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:crypto.randomUUID(),target_id:findingId,action:'owners.assign',
        membership_ids:replacementBaseMembers.map(member=>member.occurrence),
        expected_revisions:{target:replacementBaseView.body.assessment.revision,
          policy:replacementBaseView.body.assessment.policy_revision,
          identity_membership:replacementBaseView.body.assessment.membership.revision,
          owners:replacementBaseView.body.assessment.owner_revision},
        payload:{owners:[{owner_id:suspensionOwnerBeforeId,owner_type:'team'}],
          rationale:'Set current accountable owner before material-change suspension'}})});
    if(initialOwners.status!==200)
      throw new Error(`public owner setup for suspension failed ${initialOwners.status}: ${JSON.stringify(initialOwners.body)}`);
    replacementBaseView=await api(`/api/v1/assessment/groups/${findingId}`);
    const replacementBaseSubmit=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:crypto.randomUUID(),target_id:findingId,
        action:'acceptance.submit',membership_ids:replacementBaseMembers.map(member=>member.occurrence),
        expected_revisions:{target:replacementBaseView.body.assessment.revision,
          policy:replacementBaseView.body.assessment.policy_revision,
          authority:replacementBaseView.body.assessment.authority_revision,
          identity_membership:replacementBaseView.body.assessment.membership.revision,
          owners:replacementBaseView.body.assessment.owner_revision},
        expected_exposures:replacementBaseExposures,expected_evaluations:replacementBaseEvaluations,
        payload:{accountable_owner_id:suspensionOwnerBeforeId,
          rationale:'Create active predecessor for scoped material suspension and replacement',
          expires_at:replacementExpiry.toISOString(),continuity_allowed:false,
          exception_contract_version:1,context:{environment:'local',evidence:'synthetic-local'},
          compensating_controls:'Synthetic disposable fixture controls.'}})});
    if(replacementBaseSubmit.status!==200)
      throw new Error(`replacement predecessor submit failed ${replacementBaseSubmit.status}: ${JSON.stringify(replacementBaseSubmit.body)}`);
    replacementBaseView=await api(`/api/v1/assessment/groups/${findingId}`);
    const replacementPredecessor=replacementBaseView.body.assessment.acceptances.find(item=>
      item.state==='pending'&&JSON.stringify([...item.membership_ids].sort())===
        JSON.stringify(replacementBaseMembers.map(member=>member.occurrence).sort()));
    if(!replacementPredecessor)throw new Error('replacement predecessor did not read back as pending for the exact atom set');
    const replacementBaseApprove=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:crypto.randomUUID(),target_id:findingId,
        action:'acceptance.approve',membership_ids:replacementBaseMembers.map(member=>member.occurrence),
        expected_revisions:{target:replacementBaseView.body.assessment.revision,
          policy:replacementBaseView.body.assessment.policy_revision,
          authority:replacementBaseView.body.assessment.authority_revision,
          identity_membership:replacementBaseView.body.assessment.membership.revision,
          owners:replacementBaseView.body.assessment.owner_revision},
        expected_exposures:replacementBaseExposures,expected_evaluations:replacementBaseEvaluations,
        payload:{acceptance_id:replacementPredecessor.acceptance_id,
          rationale:'Approve active predecessor before public material suspension',
          selected_expires_at:replacementExpiry.toISOString(),expected_request_revision:1}})});
    if(replacementBaseApprove.status!==200)
      throw new Error(`replacement predecessor approval failed ${replacementBaseApprove.status}: ${JSON.stringify(replacementBaseApprove.body)}`);
    const basePauseRead=await api(`/api/v1/assessment/groups/${findingId}`);
    const basePaused=basePauseRead.body.assessment.acceptances.find(item=>
      item.acceptance_id===replacementPredecessor.acceptance_id);
    const basePausedClocks=Object.fromEntries((basePaused?.sla_clock??[]).map(clock=>[clock.occurrence_id,clock]));
    const sharedBaseClock=basePausedClocks[sharedMember.occurrence];
    const removedBaseClock=basePausedClocks[removedMember.occurrence];
    if(basePaused?.state!=='active'||sharedBaseClock?.state!=='paused'
        ||Number(sharedBaseClock.frozen_sla_seconds)!==21540
        ||removedBaseClock?.state!=='paused'||Number(removedBaseClock.frozen_sla_seconds)!==0
        ||removedBaseClock.prior_breach!==true)
      throw new Error(`replacement predecessor did not capture both exact atom remainders: ${JSON.stringify({state:basePaused?.state,clocks:basePaused?.sla_clock})}`);
    const suspensionCurrent=await api(`/api/v1/assessment/groups/${findingId}`);
    const materialSuspension=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:crypto.randomUUID(),target_id:findingId,
        action:'owners.assign',membership_ids:replacementBaseMembers.map(member=>member.occurrence),
        expected_revisions:{target:suspensionCurrent.body.assessment.revision,
          policy:suspensionCurrent.body.assessment.policy_revision,
          identity_membership:suspensionCurrent.body.assessment.membership.revision,
          owners:suspensionCurrent.body.assessment.owner_revision},
        expected_exposures:replacementBaseExposures,
        payload:{owners:[{owner_id:suspensionOwnerAfterId,owner_type:'team'}],
          rationale:'Remove the accountable owner through the public guarded owner command'}})});
    if(materialSuspension.status!==200)
      throw new Error(`public material severity suspension command failed ${materialSuspension.status}: ${JSON.stringify(materialSuspension.body)}`);
    const suspendedRead=await api(`/api/v1/assessment/groups/${findingId}`);
    const suspendedPredecessor=suspendedRead.body.assessment.acceptances.find(item=>
      item.acceptance_id===replacementPredecessor.acceptance_id);
    const suspendedClocks=Object.fromEntries((suspendedPredecessor?.sla_clock??[]).map(clock=>[clock.occurrence_id,clock]));
    const suspendedSharedClock=suspendedClocks[sharedMember.occurrence];
    const suspendedRemovedClock=suspendedClocks[removedMember.occurrence];
    if(suspendedPredecessor?.state!=='suspended'
        ||suspendedPredecessor.history?.at(-1)?.reason!=='accountable_owner_changed'
        ||suspendedSharedClock?.state!=='running'
        ||Date.parse(suspendedSharedClock.target_at)!==earlyRevokedAt.getTime()+21540*1000
        ||Number(suspendedSharedClock.remaining_seconds)!==21540
        ||suspendedSharedClock.frozen_sla_seconds!=null
        ||suspendedRemovedClock?.state!=='running'
        ||Number(suspendedRemovedClock.remaining_seconds)!==0
        ||suspendedRemovedClock.prior_breach!==true)
      throw new Error(`public accountable-owner suspension did not resume both exact atom states: ${JSON.stringify({state:suspendedPredecessor?.state,clocks:suspendedPredecessor?.sla_clock})}`);
    const suspendedRunningSeconds=120;
    const replacementAt=await advanceClock(suspendedRunningSeconds*1000);
    const replacementExpiryExtended=new Date(earlyRevokedAt.getTime()+2*60*60*1000);
    const successorMembers=[sharedMember,addedMember];
    const successorExposures=[...expectedExposureMap.values()].filter(item=>
      successorMembers.some(member=>member.exposure===item.exposure_id));
    const successorEvaluations=successorMembers.map(member=>({episode_id:member.episode,
      occurrence_id:member.occurrence,evaluation_id:member.evaluation,revision:member.revision}));
    const successorSubmitView=await api(`/api/v1/assessment/groups/${findingId}`);
    const successorSubmit=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:crypto.randomUUID(),target_id:findingId,
        action:'acceptance.submit',membership_ids:successorMembers.map(member=>member.occurrence),
        expected_revisions:{target:successorSubmitView.body.assessment.revision,
          policy:successorSubmitView.body.assessment.policy_revision,
          authority:successorSubmitView.body.assessment.authority_revision,
          identity_membership:successorSubmitView.body.assessment.membership.revision,
          owners:successorSubmitView.body.assessment.owner_revision},
        expected_exposures:successorExposures,expected_evaluations:successorEvaluations,
        payload:{accountable_owner_id:suspensionOwnerAfterId,
          rationale:'Extend the paused shared membership and add one newly retained atom',
          expires_at:replacementExpiryExtended.toISOString(),continuity_allowed:false,
          predecessor_id:replacementPredecessor.acceptance_id,exception_contract_version:1,
          context:{environment:'local',evidence:'synthetic-local'},
          compensating_controls:'Synthetic disposable replacement controls.'}})});
    if(successorSubmit.status!==200)
      throw new Error(`linked replacement submit failed ${successorSubmit.status}: ${JSON.stringify(successorSubmit.body)}`);
    const successorPendingRead=await api(`/api/v1/assessment/groups/${findingId}`);
    const successorPending=successorPendingRead.body.assessment.acceptances.find(item=>
      item.state==='pending'&&item.predecessor_id===replacementPredecessor.acceptance_id);
    if(!successorPending||JSON.stringify([...successorPending.membership_ids].sort())!==
        JSON.stringify(successorMembers.map(member=>member.occurrence).sort()))
      throw new Error('linked replacement request did not preserve exact added and removed atom sets');
    const successorApprove=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:crypto.randomUUID(),target_id:findingId,
        action:'acceptance.approve',membership_ids:successorMembers.map(member=>member.occurrence),
        expected_revisions:{target:successorPendingRead.body.assessment.revision,
          policy:successorPendingRead.body.assessment.policy_revision,
          authority:successorPendingRead.body.assessment.authority_revision,
          identity_membership:successorPendingRead.body.assessment.membership.revision,
          owners:successorPendingRead.body.assessment.owner_revision},
        expected_exposures:successorExposures,expected_evaluations:successorEvaluations,
        payload:{acceptance_id:successorPending.acceptance_id,
          rationale:'Approve linked exception replacement with exact shared remainder',
          selected_expires_at:replacementExpiryExtended.toISOString(),expected_request_revision:1}})});
    if(successorApprove.status!==200)
      throw new Error(`linked replacement approval failed ${successorApprove.status}: ${JSON.stringify(successorApprove.body)}`);
    const replacementAfter=await api(`/api/v1/assessment/groups/${findingId}`);
    const predecessorAfter=replacementAfter.body.assessment.acceptances.find(item=>
      item.acceptance_id===replacementPredecessor.acceptance_id);
    const successorAfter=replacementAfter.body.assessment.acceptances.find(item=>
      item.acceptance_id===successorPending.acceptance_id);
    const successorClocks=Object.fromEntries((successorAfter?.sla_clock??[]).map(clock=>[clock.occurrence_id,clock]));
    const sharedSuccessorClock=successorClocks[sharedMember.occurrence];
    const addedSuccessorClock=successorClocks[addedMember.occurrence];
    const addedSuccessorSnapshot=successorAfter?.pause_snapshots?.find(item=>
      item.occurrence_id===addedMember.occurrence);
    const removedAfterClock=predecessorAfter?.sla_clock?.find(clock=>clock.occurrence_id===removedMember.occurrence);
    if(predecessorAfter?.state!=='revoked'||successorAfter?.state!=='active'
        ||JSON.stringify([...successorAfter.membership_ids].sort())!==
          JSON.stringify(successorMembers.map(member=>member.occurrence).sort())
        ||sharedSuccessorClock?.state!=='paused'
        ||Number(sharedSuccessorClock.frozen_sla_seconds)!==21540-suspendedRunningSeconds
        ||Date.parse(sharedSuccessorClock.target_at)!==replacementExpiryExtended.getTime()
        ||addedSuccessorClock?.state!=='paused'
        ||Number(addedSuccessorClock.frozen_sla_seconds)!==(Date.parse(addedMember.deadline_at)-replacementAt.getTime())/1000
        ||addedSuccessorSnapshot?.receipt_id!==addedMember.receipt_id
        ||Date.parse(addedSuccessorSnapshot?.started_at)!==Date.parse(seeded.ingested_at)
        ||removedAfterClock?.state!=='running'||Number(removedAfterClock.remaining_seconds)!==0
        ||removedAfterClock.prior_breach!==true
        ||Date.parse(removedAfterClock.target_at)!==Date.parse(suspendedRemovedClock.target_at))
      throw new Error(`linked replacement failed shared/replaced/new-atom clock assertions: ${JSON.stringify({predecessor:predecessorAfter,successor:successorAfter,added:addedMember})}`);
    await writeFile(path.join(evidence,'sla-linked-replacement-public-readback.json'),JSON.stringify({
      predecessor_submit:replacementBaseSubmit.body,predecessor_approve:replacementBaseApprove.body,
      predecessor_paused:basePaused,material_suspension:materialSuspension.body,
      partially_suspended_predecessor:suspendedPredecessor,successor_submit:successorSubmit.body,
      successor_approve:successorApprove.body,predecessor_after:predecessorAfter,
      successor_after:successorAfter,added_membership_receipt:addedMember,
      assertion:{old_frozen_remainder:21540,running_interval_seconds:suspendedRunningSeconds,
        shared_remaining_recaptured:21540-suspendedRunningSeconds,removed_atom_resumed_with_prior_breach:true,
        added_atom_has_its_own_first_ingest_receipt:true,exact_added_and_removed_sets:true}},null,2),{mode:0o600});

    // Replace an effectively active predecessor after time passes while its
    // shared atoms remain paused. Removed and added memberships are distinct.
    const activeAt=await advanceClock(90000);
    const activeShared=sharedMember,activeRemoved=addedMember,activeAdded=memberByKey.verified_rebuild_membership;
    const activeMembers=[activeShared,activeAdded];
    const activeExpiry=new Date(activeAt.getTime()+7200000).toISOString();
    const activeCommand=async(action,payload,ids=activeMembers.map(m=>m.occurrence),override={})=>{
      const [view,heads]=await Promise.all([api(`/api/v1/assessment/groups/${findingId}`),
        api(`/api/v1/reports/sla-policies?group_id=${findingId}`)]);
      const command={command_id:crypto.randomUUID(),target_id:findingId,action,membership_ids:ids,
        expected_revisions:{target:view.body.assessment.revision,policy:view.body.assessment.policy_revision,
          authority:view.body.assessment.authority_revision,identity_membership:view.body.assessment.membership.revision,
          owners:view.body.assessment.owner_revision},
        expected_exposures:heads.body.current_heads.episodes.filter(e=>activeMembers.some(m=>m.exposure===e.exposure_id))
          .map(({exposure_id,episode_id,state_revision})=>({exposure_id,episode_id,state_revision})),
        expected_evaluations:heads.body.current_heads.evaluations.filter(e=>ids.includes(e.occurrence_id))
          .map(({episode_id,occurrence_id,evaluation_id,revision})=>({episode_id,occurrence_id,evaluation_id,revision})),
        payload,...override};
      return {command,response:await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify(command)})};
    };
    const activeBefore=(await api(`/api/v1/assessment/groups/${findingId}`)).body;
    const activePredecessor=activeBefore.assessment.acceptances.find(a=>a.acceptance_id===successorAfter.acceptance_id);
    const activeFrozen=21540-suspendedRunningSeconds;
    if(activePredecessor.state!=='active'||activePredecessor.sla_clock.find(c=>c.occurrence_id===activeShared.occurrence).frozen_sla_seconds!==activeFrozen)
      throw new Error('active predecessor lost frozen time while paused');
    const activeSharedEventsBefore=disposableAtomClockEvents(activeShared.episode,activeShared.occurrence);
    const activeSubmit=await activeCommand('acceptance.submit',{accountable_owner_id:suspensionOwnerAfterId,
      rationale:'Uninterrupted active replacement with shared, added and removed memberships',
      expires_at:activeExpiry,continuity_allowed:false,predecessor_id:activePredecessor.acceptance_id,
      exception_contract_version:1,context:{environment:'local'},compensating_controls:'Synthetic active replacement controls'});
    if(activeSubmit.response.status!==200)throw new Error(`active replacement submit failed: ${JSON.stringify(activeSubmit)}`);
    const activePendingView=(await api(`/api/v1/assessment/groups/${findingId}`)).body;
    const activePending=activePendingView.assessment.acceptances.find(a=>a.state==='pending'&&a.predecessor_id===activePredecessor.acceptance_id);
    const activePayload={acceptance_id:activePending.acceptance_id,rationale:'Approve active linked replacement',
      selected_expires_at:activeExpiry,expected_request_revision:1};
    const badBefore=disposableDbSnapshot({commandId:'00000000-0000-4000-8000-000000000001',acceptanceId:activePending.acceptance_id,groupId:findingId});
    const failedActive=await activeCommand('acceptance.approve',activePayload,undefined,
      {expected_exposures:[{exposure_id:activeShared.exposure,episode_id:activeShared.episode,state_revision:999999}]});
    const failedActiveAfter=(await api(`/api/v1/assessment/groups/${findingId}`)).body;
    const badAfter=disposableDbSnapshot({commandId:failedActive.command.command_id,acceptanceId:activePending.acceptance_id,groupId:findingId});
    if(failedActive.response.status!==409||JSON.stringify(activePendingView)!==JSON.stringify(failedActiveAfter)
        ||JSON.stringify(badBefore)!==JSON.stringify(badAfter))
      throw new Error(`failed active replacement changed predecessor/history/clock: ${JSON.stringify(failedActive)}`);
    const activeSharedEventsAfterFailed=disposableAtomClockEvents(activeShared.episode,activeShared.occurrence);
    if(JSON.stringify(activeSharedEventsBefore)!==JSON.stringify(activeSharedEventsAfterFailed))
      throw new Error('failed guarded replacement appended clock events');
    const activeApproved=await activeCommand('acceptance.approve',activePayload);
    if(activeApproved.response.status!==200)throw new Error(`active replacement approval failed: ${JSON.stringify(activeApproved)}`);
    const activeAfter=(await api(`/api/v1/assessment/groups/${findingId}`)).body;
    const activeSuccessor=activeAfter.assessment.acceptances.find(a=>a.acceptance_id===activePending.acceptance_id);
    const activeOld=activeAfter.assessment.acceptances.find(a=>a.acceptance_id===activePredecessor.acceptance_id);
    const activeSharedClock=activeSuccessor.sla_clock.find(c=>c.occurrence_id===activeShared.occurrence);
    const activeAddedClock=activeSuccessor.sla_clock.find(c=>c.occurrence_id===activeAdded.occurrence);
    const activeRemovedClock=activeOld.sla_clock.find(c=>c.occurrence_id===activeRemoved.occurrence);
    const expectedAddedRemainder=(expiry.getTime()+21600*1000-activeAt.getTime())/1000;
    const expectedRemovedTarget=activeAt.getTime()+addedSuccessorClock.frozen_sla_seconds*1000;
    if(activeOld.state!=='revoked'||activeSuccessor.state!=='active'
        ||activeSharedClock.state!=='paused'||activeSharedClock.frozen_sla_seconds!==activeFrozen
        ||Date.parse(activeSharedClock.target_at)!==Date.parse(activeExpiry)
        ||activeAddedClock.state!=='paused'||activeAddedClock.frozen_sla_seconds!==expectedAddedRemainder
        ||activeRemovedClock.state!=='running'||Date.parse(activeRemovedClock.target_at)!==expectedRemovedTarget)
      throw new Error(`active replacement shared/added/removed assertions failed: ${JSON.stringify({activeOld,activeSuccessor,expectedAddedRemainder,expectedRemovedTarget})}`);
    const activeSharedEventsAfter=disposableAtomClockEvents(activeShared.episode,activeShared.occurrence);
    const retarget=activeSharedEventsAfter.at(-1);
    if(activeSharedEventsAfter.length!==activeSharedEventsBefore.length+1
        ||retarget.event_type!=='paused'||retarget.decision_id!==activePending.acceptance_id
        ||retarget.predecessor_event_id!==activeSharedEventsBefore.at(-1).event_id
        ||retarget.data.remaining_seconds!==activeFrozen)
      throw new Error(`active shared atom did not carry one uninterrupted pause: ${JSON.stringify({activeSharedEventsBefore,activeSharedEventsAfter})}`);
    await writeFile(path.join(evidence,'sla-active-linked-replacement-public-readback.json'),JSON.stringify({
      at:activeAt.toISOString(),predecessor:activePredecessor,submit:activeSubmit,
      shared_clock_events_before:activeSharedEventsBefore,shared_clock_events_after:activeSharedEventsAfter,
      failed_guard:failedActive,unchanged_after_failed_guard:failedActiveAfter,
      approval:activeApproved,successor:activeSuccessor,predecessor_after:activeOld,
      independently_expected:{shared_frozen:activeFrozen,added_frozen:expectedAddedRemainder,
        removed_target:new Date(expectedRemovedTarget).toISOString()},db_before_failed:badBefore,db_after_failed:badAfter},null,2),{mode:0o600});

    // Close every membership in the in-scope preactivation exposure, then
    // recur that exact exposure through the retained writer with a newer fact.
    const g5Ids=[preactivation.occurrence_id,postLegacy.occurrence_id,postG7.occurrence_id];
    const g5Portion=crypto.randomUUID();
    const g5Command=async(action,payload,guarded=false)=>{
      const [view,heads]=await Promise.all([api(`/api/v1/assessment/groups/${findingId}`),
        api(`/api/v1/reports/sla-policies?group_id=${findingId}`)]);
      const response=await api('/api/v1/assessment/commands',{method:'POST',write:true,
        body:JSON.stringify({command_id:crypto.randomUUID(),target_id:findingId,action,
          membership_ids:g5Ids,expected_revisions:{target:view.body.assessment.revision,
            policy:view.body.assessment.policy_revision,authority:view.body.assessment.authority_revision,
            identity_membership:view.body.assessment.membership.revision,owners:view.body.assessment.owner_revision},
          ...(guarded?{expected_exposures:heads.body.current_heads.episodes
            .filter(e=>e.exposure_id===preactivation.exposure_id)
            .map(({exposure_id,episode_id,state_revision})=>({exposure_id,episode_id,state_revision})),
            expected_evaluations:heads.body.current_heads.evaluations.filter(e=>g5Ids.includes(e.occurrence_id))
              .map(({episode_id,occurrence_id,evaluation_id,revision})=>({episode_id,occurrence_id,evaluation_id,revision}))}:{}),payload})});
      if(response.status!==200)throw new Error(`in-scope G5 ${action} failed: ${JSON.stringify(response)}`);
      return response.body;
    };
    await g5Command('portion.define',{portion_id:g5Portion,owner_ids:[ownerDirectoryId],
      membership_ids:g5Ids,rationale:'Define every membership of the preactivation exposure'});
    const g5Closed=await g5Command('remediation.confirm_portion',{portion_id:g5Portion,
      membership_ids:g5Ids,rationale:'Close the same preactivation exposure before recurrence',
      evidence_ref:'synthetic:in-scope-g5-close'},true);
    const g5ClosedAt=await readClock();
    await advanceClock(1000);
    const g5Recur=JSON.parse(docker(['exec','-e','UVM_G7_SLA_STAGE=recur',appContainer,
      '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_recovery_retained_fixture.py']));
    if(g5Recur.exposure_id!==preactivation.exposure_id||g5Recur.episode_id===preactivation.episode_id
        ||g5Recur.contract_version!==7||g5Recur.occurrence_id!==postG7.occurrence_id
        ||Date.parse(g5Recur.observed_at)<=g5ClosedAt.getTime()
        ||g5Recur.receipt_id===postG7.receipt_id)
      throw new Error(`same-exposure recurrence lost causal G7 receipt: ${JSON.stringify(g5Recur)}`);
    const g5IssuedAfterRecurrence=await api(`/api/v1/reports/${legacyReport.body.report_id}/atoms`);
    if(JSON.stringify(g5IssuedAfterRecurrence.body)!==JSON.stringify(legacyAtoms.body))
      throw new Error('same-exposure recurrence altered issued G5 atoms');
    await writeFile(path.join(evidence,'sla-g5-postactivation-continuity.json'),JSON.stringify({
      preactivation,post_legacy_membership:postLegacy,post_g7_membership:postG7,
      later_policy:prospectivePolicy,publication:prospectivePublication,closed:g5Closed,
      closed_at:g5ClosedAt.toISOString(),same_exposure_recurrence:g5Recur,
      unchanged_pre_activation_report:true},null,2),{mode:0o600});

    const boundaryExposure=[...expectedExposureMap.values()].find(item=>item.exposure_id===deadlineBoundaryMember.exposure);
    const boundaryEvaluation={episode_id:deadlineBoundaryMember.episode,
      occurrence_id:deadlineBoundaryMember.occurrence,evaluation_id:deadlineBoundaryMember.evaluation,
      revision:deadlineBoundaryMember.revision};
    let boundaryCurrent=await api(`/api/v1/assessment/groups/${findingId}`);
    const boundaryPortionId=crypto.randomUUID();
    const boundaryPortion=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'portion.define',
      membership_ids:[deadlineBoundaryMember.occurrence],expected_revisions:{
        target:boundaryCurrent.body.assessment.revision,policy:boundaryCurrent.body.assessment.policy_revision,
        authority:boundaryCurrent.body.assessment.authority_revision,
        identity_membership:boundaryCurrent.body.assessment.membership.revision,
        owners:boundaryCurrent.body.assessment.owner_revision},payload:{portion_id:boundaryPortionId,
        owner_ids:[ownerDirectoryId],membership_ids:[deadlineBoundaryMember.occurrence],
        rationale:'Define exact membership for deadline-equality confirmation'}})});
    if(boundaryPortion.status!==200)
      throw new Error(`deadline boundary membership setup failed ${boundaryPortion.status}: ${JSON.stringify(boundaryPortion.body)}`);
    const exactDeadline=deadlineBoundaryMember.deadline_at;
    await writeFile(clockPath,exactDeadline+'\n',{mode:0o666});
    await page.waitForTimeout(1500);
    boundaryCurrent=await api(`/api/v1/assessment/groups/${findingId}`);
    const exactDeadlineCommandId=crypto.randomUUID();
    const exactDeadlineConfirmation=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:exactDeadlineCommandId,target_id:findingId,
        action:'remediation.confirm_portion',membership_ids:[deadlineBoundaryMember.occurrence],
        expected_revisions:{target:boundaryCurrent.body.assessment.revision,
          policy:boundaryCurrent.body.assessment.policy_revision,
          identity_membership:boundaryCurrent.body.assessment.membership.revision,
          owners:boundaryCurrent.body.assessment.owner_revision},
        expected_exposures:[boundaryExposure],expected_evaluations:[boundaryEvaluation],
        payload:{portion_id:boundaryPortionId,membership_ids:[deadlineBoundaryMember.occurrence],
          rationale:'Confirm the synthetic exact-deadline membership on time',
          evidence_ref:'synthetic:exact-deadline-boundary'}})});
    if(exactDeadlineConfirmation.status!==200)
      throw new Error(`public confirmation at exact deadline was not accepted: ${JSON.stringify(exactDeadlineConfirmation.body)}`);
    const boundaryAfterConfirmation=await api(`/api/v1/assessment/groups/${findingId}`);
    const boundaryEpisode=boundaryAfterConfirmation.body.episodes.find(item=>item.episode_id===deadlineBoundaryMember.episode);
    const boundaryEpisodeMember=boundaryEpisode?.members?.find(item=>item.membership_id===deadlineBoundaryMember.occurrence);
    if(boundaryEpisodeMember?.status!=='confirmed'
        ||utcMicros(boundaryEpisodeMember.confirmed_at)!==utcMicros(exactDeadline))
      throw new Error(`exact-deadline confirmation readback differs: ${JSON.stringify(boundaryEpisodeMember)}`);
    const equalityReportCommand=crypto.randomUUID();
    const equalityReport=await api('/api/v1/reports',{method:'POST',write:true,body:JSON.stringify({
      schema_version:1,definition_version:'g7-exception-sla-v1',command_id:equalityReportCommand,
      mode:'as_known_at',scope:{group_ids:[findingId]},as_of:exactDeadline,
      known_at:exactDeadline})});
    if(equalityReport.status!==200||!equalityReport.body.report_id)
      throw new Error(`public deadline-equality report failed ${equalityReport.status}: ${JSON.stringify(equalityReport.body)}`);
    let equalityReportRead;
    for(let attempt=0;attempt<30;attempt++) {
      equalityReportRead=await api(`/api/v1/reports/${equalityReport.body.report_id}`);
      if(equalityReportRead.status===200&&equalityReportRead.body.status==='ready')break;
      await page.waitForTimeout(500);
    }
    const equalityAtoms=await api(`/api/v1/reports/${equalityReport.body.report_id}/atoms`);
    const equalityAtom=equalityAtoms.body.items?.find(item=>item.occurrence_id===deadlineBoundaryMember.occurrence);
    if(equalityReportRead?.status!==200||equalityReportRead.body.status!=='ready'
        ||equalityAtoms.status!==200||!equalityAtom
        ||equalityAtom.completion?.state!=='on_time'
        ||utcMicros(equalityAtom.completion?.confirmed_at)!==utcMicros(exactDeadline)
        ||utcMicros(equalityAtom.completion?.deadline_at_confirmation)!==utcMicros(exactDeadline)
        ||(equalityAtom.clock.overdue_seconds!=null&&Number(equalityAtom.clock.overdue_seconds)!==0))
      throw new Error(`public consumer treated exact-deadline completion as overdue: ${JSON.stringify({report:equalityReportRead?.body,atom:equalityAtom})}`);
    await writeFile(path.join(evidence,'sla-exact-deadline-public-readback.json'),JSON.stringify({
      confirmation:exactDeadlineConfirmation.body,confirmed_member:boundaryEpisodeMember,
      report:equalityReportRead.body,atom:equalityAtom,command_id:equalityReportCommand,
      equality_is_on_time:true},null,2),{mode:0o600});
    process.stdout.write(JSON.stringify({exceptionSlaWorkflow:'paused_then_resumed',findingId,
      memberKeys:members.map(member=>member.key),acceptanceId})+'\n');
    process.exit(0);
  }

  if (warningOnly) {
    const seeded=JSON.parse(await readFile(path.join(evidence,'warning-fixture-ids.json'),'utf8'));
    const findingId=seeded.group, occurrenceId=seeded.occurrence;
    const ownerHead=await api('/api/v1/assessment/administration/catalogue');
    if(ownerHead.status!==200)throw new Error('warning workflow owner setup could not read authority head');
    const ownerDirectoryId=crypto.randomUUID();
    const ownerCreated=await api('/api/v1/assessment/commands',{method:'POST',write:true,
      body:JSON.stringify({command_id:crypto.randomUUID(),target_id:zero,action:'ownership.team.create',
        membership_ids:[],expected_revisions:{target:ownerHead.body.policy_revision,
          policy:ownerHead.body.policy_revision,authority:ownerHead.body.authority_revision,
          ownership:ownerHead.body.ownership_revision,identity_membership:0,owners:0},
        payload:{team_id:ownerDirectoryId,display_name:'Synthetic warning accountable team',enabled:true,
          rationale:'Provide a real eligible owner for the disposable public warning workflow',
          evidence_ref:'g7-observer-warning-fixture'}})});
    if(ownerCreated.status!==200)
      throw new Error(`warning workflow owner setup failed ${ownerCreated.status}: ${JSON.stringify(ownerCreated.body)}`);
    let current=await api('/api/v1/assessment/administration/catalogue');
    for(const destination of [
      {channel_id:'C_FIXTURE_SUCCESS',destination_ref:'fixture-destination'},
      {channel_id:'C_FIXTURE_FAILED',destination_ref:'fixture-failed-destination'},
      {channel_id:'C_FIXTURE_UNCERTAIN',destination_ref:'fixture-uncertain-destination'}]){
      current=await api('/api/v1/assessment/administration/catalogue');
      const route=await api('/api/v1/assessment/exception-warning-routes',{method:'POST',write:true,
        body:JSON.stringify({route_id:crypto.randomUUID(),access_group_ids:[groupId],finding_group_ids:[findingId],
          channel:'slack',installation_id:'fixture-installation',workspace_id:'T_FIXTURE',
          ...destination,recipient_id:'g7-actor',offset_seconds:[60],enabled:true,
          expected_policy_revision:current.body.policy_revision,expected_route_revision:null,
          failure_alert_group_ids:[groupId],link:'https://uvm.example.test/assessment'})});
      if(route.status!==200)throw new Error(`warning route setup failed ${route.status}: ${JSON.stringify(route.body)}`);
    }
    for(const destination of [
      {channel_id:'SMTP_FIXTURE_ACCEPTED',destination_ref:'fixture-smtp-accepted',email_recipient:'accepted@fixture.invalid'},
      {channel_id:'SMTP_FIXTURE_RETRY',destination_ref:'fixture-smtp-retry',email_recipient:'retry@fixture.invalid',retry_base_seconds:1},
      {channel_id:'SMTP_FIXTURE_PREDATA',destination_ref:'fixture-smtp-predatadisconnect',email_recipient:'predatadisconnect@fixture.invalid',retry_base_seconds:1},
      {channel_id:'SMTP_FIXTURE_UNCERTAIN',destination_ref:'fixture-smtp-uncertain',email_recipient:'uncertain@fixture.invalid'}]){
      current=await api('/api/v1/assessment/administration/catalogue');
      const route=await api('/api/v1/assessment/exception-warning-routes',{method:'POST',write:true,
        body:JSON.stringify({route_id:crypto.randomUUID(),access_group_ids:[groupId],finding_group_ids:[findingId],
          channel:'email',installation_id:'fixture-installation',workspace_id:'T_FIXTURE',
          ...destination,recipient_id:'g7-actor',offset_seconds:[60],enabled:true,
          expected_policy_revision:current.body.policy_revision,expected_route_revision:null,
          max_attempts:3,failure_alert_group_ids:[groupId],link:'https://uvm.example.test/assessment'})});
      if(route.status!==200)throw new Error(`SMTP warning route setup failed ${route.status}: ${JSON.stringify(route.body)}`);
    }
    current=await api('/api/v1/assessment/administration/catalogue');
    const actor=await api('/api/v1/assessment/exception-warning-actor-links',{method:'POST',write:true,
      body:JSON.stringify({installation_id:'fixture-installation',workspace_id:'T_FIXTURE',
        slack_user_id:'U_FIXTURE',principal_id:'g7-actor',access_group_ids:[groupId],
        finding_group_ids:[findingId],expected_policy_revision:current.body.policy_revision,
        expected_link_revision:0,enabled:true})});
    if(actor.status!==200)throw new Error(`warning actor link setup failed ${actor.status}: ${JSON.stringify(actor.body)}`);
    current=await api(`/api/v1/assessment/groups/${findingId}`);
    if(current.status!==200)throw new Error(`warning finding read failed ${current.status}: ${JSON.stringify(current.body)}`);
    await writeFile(path.join(evidence,'warning-precommand-readback.json'),JSON.stringify(current.body,null,2),{mode:0o600});
    if(!Array.isArray(current.body.episodes)||current.body.episodes.length===0)
      throw new Error(`warning finding has no public episode records: ${JSON.stringify(current.body)}`);
    const episode=current.body.episodes[0];
    const expectedExposures=[{exposure_id:episode.exposure_id,episode_id:episode.episode_id,state_revision:episode.state_revision}];
    const expectedEvaluations=[{episode_id:seeded.episode,occurrence_id:occurrenceId,
      evaluation_id:seeded.evaluation,revision:1}];
    const expiry=new Date(Date.now()+120000).toISOString();
    const submit=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.submit',membership_ids:[occurrenceId],
      expected_revisions:{target:current.body.assessment.revision,policy:current.body.assessment.policy_revision,
        authority:(await api('/api/v1/assessment/administration/catalogue')).body.authority_revision,
        identity_membership:current.body.assessment.membership.revision,owners:current.body.assessment.owner_revision},
      expected_exposures:expectedExposures,expected_evaluations:expectedEvaluations,
      payload:{accountable_owner_id:ownerDirectoryId,rationale:'Exercise G7 warning expiry workflow',
        expires_at:expiry,continuity_allowed:false,
        exception_contract_version:1,context:{environment:'local'},compensating_controls:'Synthetic local fixture controls.'}})});
    if(submit.status!==200)throw new Error(`G7 exception submit failed ${submit.status}: ${JSON.stringify(submit.body)}`);
    const fresh=await api(`/api/v1/assessment/groups/${findingId}`);
    const acceptanceId=fresh.body.assessment.acceptances.find(item=>item.state==='pending')?.acceptance_id;
    if(!acceptanceId)throw new Error(`public submit response did not create a pending acceptance: ${JSON.stringify(fresh.body.assessment.acceptances)}`);
    const catalogueAfter=await api('/api/v1/assessment/administration/catalogue');
    const approve=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.approve',membership_ids:[occurrenceId],
      expected_revisions:{target:fresh.body.assessment.revision,policy:fresh.body.assessment.policy_revision,
        authority:catalogueAfter.body.authority_revision,identity_membership:fresh.body.assessment.membership.revision,
        owners:fresh.body.assessment.owner_revision},expected_exposures:expectedExposures,
      expected_evaluations:expectedEvaluations,payload:{acceptance_id:acceptanceId,rationale:'Approve synthetic G7 warning exercise',
        selected_expires_at:expiry,expected_request_revision:1}})});
    if(approve.status!==200)throw new Error(`G7 exception approval failed ${approve.status}: ${JSON.stringify(approve.body)}`);
    await writeFile(path.join(evidence,'warning-public-workflow.json'),JSON.stringify({
      findingId,occurrenceId,acceptanceId,submit:submit.body,approve:approve.body},null,2),{mode:0o600});
    const warningClock=new Date(Date.parse(expiry)-60000).toISOString();
    await writeFile(path.join(fixtureRoot,'scheduler','warning-clock.txt'),warningClock+'\n',{mode:0o666});
    const sentUntil=Date.now()+45000;let warnings;
    while(Date.now()<sentUntil){
      warnings=await api(`/api/v1/assessment/groups/${findingId}/exception-warnings`);
      if(warnings.status===200&&warnings.body.items?.length===7
          &&warnings.body.items.every(item=>['sent','failed','uncertain'].includes(item.status)))break;
      await page.waitForTimeout(500);
    }
    if(warnings?.status!==200||warnings.body.items?.length!==7)
      throw new Error(`warning worker did not durably record all seven Slack/SMTP initial outcomes: ${JSON.stringify(warnings)}`);
    if(!['sent','failed','uncertain'].every(status=>warnings.body.items.some(item=>item.status===status)))
      throw new Error(`warning worker did not exercise sent/failed/uncertain outcomes: ${JSON.stringify(warnings.body.items)}`);
    const smtpByDestination=Object.fromEntries(warnings.body.items.filter(item=>item.channel==='email')
      .map(item=>[item.destination_ref,item]));
    if(smtpByDestination['fixture-smtp-accepted']?.status!=='sent'
        ||smtpByDestination['fixture-smtp-retry']?.status!=='failed'
        ||smtpByDestination['fixture-smtp-uncertain']?.status!=='uncertain'
        ||smtpByDestination['fixture-smtp-predatadisconnect']?.status!=='failed')
      throw new Error(`SMTP worker did not record accepted/rejected/uncertain outcomes: ${JSON.stringify(smtpByDestination)}`);
    const failedSmtp=smtpByDestination['fixture-smtp-retry'];
    const preDataSmtp=smtpByDestination['fixture-smtp-predatadisconnect'];
    if(!failedSmtp.next_attempt_at||failedSmtp.attempts?.length!==1
        ||failedSmtp.attempts[0].outcome!=='failed'||failedSmtp.suppression_reason)
      throw new Error(`confirmed SMTP rejection did not retain one scheduled retry: ${JSON.stringify(failedSmtp)}`);
    if(!preDataSmtp.next_attempt_at||preDataSmtp.attempts?.length!==1
        ||preDataSmtp.attempts[0].outcome!=='failed'||preDataSmtp.suppression_reason)
      throw new Error(`pre-DATA SMTP disconnect did not retain one scheduled retry: ${JSON.stringify(preDataSmtp)}`);
    const initialRetryClock=await readFile(path.join(fixtureRoot,'scheduler','warning-clock.txt'),'utf8');
    await writeFile(path.join(evidence,'warning-retry-clock-before.txt'),initialRetryClock,{mode:0o600});
    const initialRetryEpoch=Date.parse(warningClock);
    const mountedRetryEpoch=Date.parse(initialRetryClock.trim());
    if(!Number.isFinite(initialRetryEpoch)||!Number.isFinite(mountedRetryEpoch)
        ||mountedRetryEpoch!==initialRetryEpoch)
      throw new Error(`mounted warning clock differs from the explicit due-time value: ${JSON.stringify({warningClock,initialRetryClock})}`);
    const advancedRetryClock=new Date(initialRetryEpoch+3000).toISOString();
    await writeFile(path.join(fixtureRoot,'scheduler','warning-clock.txt'),advancedRetryClock+'\n',{mode:0o666});
    await writeFile(path.join(evidence,'warning-retry-clock-advancement.json'),JSON.stringify({
      initial_clock:initialRetryClock.trim(),advanced_clock:advancedRetryClock,
      advance_seconds:3,reason:'make the explicitly scheduled one-second SMTP retry due'},null,2),{mode:0o600});
    const retryUntil=Date.now()+15000;let retried;
    while(Date.now()<retryUntil){
      retried=await api(`/api/v1/assessment/groups/${findingId}/exception-warnings`);
      const item=retried.body?.items?.find(row=>row.intent_id===failedSmtp.intent_id);
      const preDataItem=retried.body?.items?.find(row=>row.intent_id===preDataSmtp.intent_id);
      if(item?.status==='sent'&&item.attempts?.length===2
          &&preDataItem?.status==='sent'&&preDataItem.attempts?.length===2)break;
      await page.waitForTimeout(300);
    }
    const retriedSmtp=retried?.body?.items?.find(row=>row.intent_id===failedSmtp.intent_id);
    const preDataRetried=retried?.body?.items?.find(row=>row.intent_id===preDataSmtp.intent_id);
    if(retriedSmtp?.status!=='sent'||retriedSmtp.attempts?.length!==2
        ||retriedSmtp.attempts[0].outcome!=='failed'||retriedSmtp.attempts[1].outcome!=='sent'
        ||retriedSmtp.attempts[0].attempt_number!==1||retriedSmtp.attempts[1].attempt_number!==2
        ||retriedSmtp.provider_receipt_basis!=='smtp_accepted')
      throw new Error(`scheduled SMTP retry did not preserve one intent with a bounded second attempt and SMTP acceptance: ${JSON.stringify(retriedSmtp)}`);
    if(preDataRetried?.status!=='sent'||preDataRetried.attempts?.length!==2
        ||preDataRetried.attempts[0].outcome!=='failed'||preDataRetried.attempts[1].outcome!=='sent'
        ||preDataRetried.attempts[0].attempt_number!==1||preDataRetried.attempts[1].attempt_number!==2
        ||preDataRetried.provider_receipt_basis!=='smtp_accepted')
      throw new Error(`pre-DATA SMTP disconnect did not retry the same intent successfully: ${JSON.stringify(preDataRetried)}`);
    const smtpCaptures=JSON.parse(await readFile(path.join(fixtureRoot,'warning','smtp-captures.json'),'utf8'));
    const retryCaptures=smtpCaptures.filter(row=>row.recipient==='retry@fixture.invalid');
    if(retryCaptures.length!==2||retryCaptures[0].result!=='temporary_rcpt_rejection'
        ||retryCaptures[1].result!=='accepted'||retryCaptures[1].message_id!==retriedSmtp.attempts[1].receipt?.split('|')[2])
      throw new Error(`SMTP fixture did not capture one confirmed rejection and one accepted retry: ${JSON.stringify(retryCaptures)}`);
    const uncertainSmtp=smtpByDestination['fixture-smtp-uncertain'];
    const preDataCaptures=smtpCaptures.filter(row=>row.recipient==='predatadisconnect@fixture.invalid');
    const uncertainCaptures=smtpCaptures.filter(row=>row.recipient==='uncertain@fixture.invalid');
    if(uncertainCaptures.length!==1||uncertainCaptures[0].result!=='connection_lost_after_data'
        ||uncertainSmtp.attempts?.length!==1||uncertainSmtp.status!=='uncertain'
        ||uncertainSmtp.next_attempt_at)
      throw new Error(`ambiguous SMTP outcome was not held without resend: ${JSON.stringify({uncertainSmtp,uncertainCaptures})}`);
    if(preDataCaptures.length!==2||preDataCaptures[0].result!=='connection_lost_before_data'
        ||preDataCaptures[1].result!=='accepted'
        ||preDataRetried.attempts[1].receipt?.split('|')[2]!==preDataCaptures[1].message_id)
      throw new Error(`pre-DATA disconnect proof did not match its durable retry receipt: ${JSON.stringify({preDataRetried,preDataCaptures})}`);
    await writeFile(path.join(evidence,'warning-smtp-retry-proof.json'),JSON.stringify({
      initial_smtp_intents:[smtpByDestination['fixture-smtp-accepted'],failedSmtp,preDataSmtp,uncertainSmtp],
      retried_intent:retriedSmtp,pre_data_retried_intent:preDataRetried,
      retry_exchange:retryCaptures,pre_data_exchange:preDataCaptures,
      uncertain_exchange:uncertainCaptures,acceptance_semantics:'SMTP final 2xx after DATA only; no mailbox delivery claim'},null,2),{mode:0o600});
    warnings=retried;
    const warning=warnings.body.items.find(item=>item.channel==='slack'&&item.status==='sent');
    const successCapture=JSON.parse(await readFile(path.join(fixtureRoot,'warning','provider-captures.json'),'utf8'))
      .find(row=>row.payload.channel==='C_FIXTURE_SUCCESS');
    const token=successCapture.payload.blocks[1].elements[0].value;
    const callbackPayload={api_app_id:'fixture-app',team:{id:'T_FIXTURE'},user:{id:'U_FIXTURE'},
      container:{channel_id:'C_FIXTURE_SUCCESS'},message:{ts:'1720000000.000001'},
      actions:[{action_id:'uvm_warning_ack',value:token}]};
    const raw='payload='+encodeURIComponent(JSON.stringify(callbackPayload));
    const timestamp=String(Math.floor(Date.now()/1000));
    const signature='v0='+createHmac('sha256','g7-warning-fixture-signing-secret')
      .update(`v0:${timestamp}:${raw}`).digest('hex');
    const forged=await api('/api/v1/assessment/exception-warning-callback',{method:'POST',body:raw,
      headers:{'Content-Type':'application/x-www-form-urlencoded','x-slack-request-timestamp':timestamp,
        'x-slack-signature':'v0='+('0'.repeat(64))}});
    if(forged.status!==401)throw new Error(`forged callback returned ${forged.status}`);
    const staleStamp='1';
    const staleSignature='v0='+createHmac('sha256','g7-warning-fixture-signing-secret')
      .update(`v0:${staleStamp}:${raw}`).digest('hex');
    const stale=await api('/api/v1/assessment/exception-warning-callback',{method:'POST',body:raw,
      headers:{'Content-Type':'application/x-www-form-urlencoded','x-slack-request-timestamp':staleStamp,
        'x-slack-signature':staleSignature}});
    if(stale.status!==401)throw new Error(`stale callback returned ${stale.status}`);
    const signPayload=async(payload)=>{
      const body='payload='+encodeURIComponent(JSON.stringify(payload));
      const stamp=String(Math.floor(Date.now()/1000));
      const sig='v0='+createHmac('sha256','g7-warning-fixture-signing-secret')
        .update(`v0:${stamp}:${body}`).digest('hex');
      return api('/api/v1/assessment/exception-warning-callback',{method:'POST',body,
        headers:{'Content-Type':'application/x-www-form-urlencoded','x-slack-request-timestamp':stamp,
          'x-slack-signature':sig}});
    };
    const wrongActor=await signPayload({...callbackPayload,user:{id:'U_WRONG'}});
    const wrongDestination=await signPayload({...callbackPayload,
      container:{channel_id:'C_FIXTURE_FAILED'}});
    if(wrongActor.status!==200||wrongDestination.status!==200)
      throw new Error(`signed out-of-scope callback envelopes were not durably queued: ${JSON.stringify({wrongActor,wrongDestination})}`);
    let callbackOutcomes=[];const deniedUntil=Date.now()+15000;
    while(Date.now()<deniedUntil){
      callbackOutcomes=JSON.parse(execFileSync('docker',['exec',appContainer,
        '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_exception_warning_evidence.py',
        wrongActor.body.inbox_id,wrongDestination.body.inbox_id],{encoding:'utf8'}));
      if(callbackOutcomes.length===2&&callbackOutcomes.every(item=>item.state==='denied'))break;
      await page.waitForTimeout(500);
    }
    if(callbackOutcomes.length!==2||callbackOutcomes.some(item=>item.state!=='denied'))
      throw new Error(`wrong actor/destination callbacks were not rejected by the worker: ${JSON.stringify(callbackOutcomes)}`);
    let linkCatalogue=await api('/api/v1/assessment/administration/catalogue');
    const revokeLink=await api('/api/v1/assessment/exception-warning-actor-links',{method:'POST',write:true,
      body:JSON.stringify({installation_id:'fixture-installation',workspace_id:'T_FIXTURE',
        slack_user_id:'U_FIXTURE',principal_id:'g7-actor',access_group_ids:[groupId],
        finding_group_ids:[findingId],expected_policy_revision:linkCatalogue.body.policy_revision,
        expected_link_revision:1,enabled:false})});
    if(revokeLink.status!==200)throw new Error(`actor link revoke failed ${revokeLink.status}: ${JSON.stringify(revokeLink.body)}`);
    const revokedCallback=await signPayload({...callbackPayload,trigger_id:'after-actor-link-revocation'});
    if(revokedCallback.status!==200)throw new Error(`revoked actor callback was not durably queued: ${JSON.stringify(revokedCallback)}`);
    let revokedOutcome=[];const revokedUntil=Date.now()+12000;
    while(Date.now()<revokedUntil){
      revokedOutcome=JSON.parse(execFileSync('docker',['exec',appContainer,
        '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_exception_warning_evidence.py',
        revokedCallback.body.inbox_id],{encoding:'utf8'}));
      if(revokedOutcome[0]?.state==='denied')break;
      await page.waitForTimeout(500);
    }
    if(revokedOutcome[0]?.state!=='denied')
      throw new Error(`revoked actor link was not rejected: ${JSON.stringify(revokedOutcome)}`);
    linkCatalogue=await api('/api/v1/assessment/administration/catalogue');
    const restoreLink=await api('/api/v1/assessment/exception-warning-actor-links',{method:'POST',write:true,
      body:JSON.stringify({installation_id:'fixture-installation',workspace_id:'T_FIXTURE',
        slack_user_id:'U_FIXTURE',principal_id:'g7-actor',access_group_ids:[groupId],
        finding_group_ids:[findingId],expected_policy_revision:linkCatalogue.body.policy_revision,
        expected_link_revision:2,enabled:true})});
    if(restoreLink.status!==200)throw new Error(`actor link restore failed ${restoreLink.status}: ${JSON.stringify(restoreLink.body)}`);
    const beforeAck=await api(`/api/v1/assessment/groups/${findingId}`);
    const ack=await api('/api/v1/assessment/exception-warning-callback',{method:'POST',body:raw,
      headers:{'Content-Type':'application/x-www-form-urlencoded','x-slack-request-timestamp':timestamp,
        'x-slack-signature':signature}});
    const replay=await api('/api/v1/assessment/exception-warning-callback',{method:'POST',body:raw,
      headers:{'Content-Type':'application/x-www-form-urlencoded','x-slack-request-timestamp':timestamp,
        'x-slack-signature':signature}});
    if(ack.status!==200||replay.status!==200||replay.body.duplicate!==true)
      throw new Error(`signed acknowledgement/replay failed: ${JSON.stringify({ack,replay})}`);
    let acknowledged;
    const ackUntil=Date.now()+15000;
    while(Date.now()<ackUntil){
      acknowledged=await api(`/api/v1/assessment/groups/${findingId}/exception-warnings`);
      if(acknowledged.body.items?.some(item=>item.intent_id===warning.intent_id&&item.acknowledged_at))break;
      await page.waitForTimeout(300);
    }
    if(!acknowledged.body.items?.some(item=>item.intent_id===warning.intent_id&&item.acknowledged_at))
      throw new Error('signed callback was not durably acknowledged by the worker');
    const alerts=await api(`/api/v1/assessment/groups/${findingId}/exception-warning-failure-alerts`);
    const expectedFailureAlerts=acknowledged.body.items.flatMap(intent=>(intent.attempts||[])
      .filter(attempt=>['failed','uncertain'].includes(attempt.outcome))
      .map(attempt=>({intent_id:intent.intent_id,attempt_id:attempt.attempt_id,channel:intent.channel,
        reason:attempt.outcome==='uncertain'?'uncertain_delivery_reconcile_before_retry':'transient_delivery_failure'})));
    const assertFailureAlerts=rows=>expectedFailureAlerts.every(required=>rows.some(item=>
      item.intent_id===required.intent_id&&item.attempt_id===required.attempt_id
        &&item.channel===required.channel&&item.reason===required.reason));
    if(alerts.status!==200||expectedFailureAlerts.length!==5||!assertFailureAlerts(alerts.body.items||[]))
      throw new Error(`eligible warning failure-alert readback missed a failed/uncertain attempt identity: ${JSON.stringify({alerts,expectedFailureAlerts})}`);
    for(const required of expectedFailureAlerts){
      const withoutOne=(alerts.body.items||[]).filter(item=>item.attempt_id!==required.attempt_id);
      if(assertFailureAlerts(withoutOne))
        throw new Error(`failure-alert assertion accepted a response missing ${required.attempt_id}`);
    }
    const afterAck=await api(`/api/v1/assessment/groups/${findingId}`);
    if(JSON.stringify({assessment:beforeAck.body.assessment,episodes:beforeAck.body.episodes})!==
       JSON.stringify({assessment:afterAck.body.assessment,episodes:afterAck.body.episodes}))
      throw new Error('warning acknowledgement mutated assessment or episode state');
    await writeFile(path.join(evidence,'warning-callback-proof.json'),JSON.stringify({
      forged_status:forged.status,stale_status:stale.status,ack:ack.body,replay:replay.body,
      wrong_actor_status:wrongActor.status,wrong_destination_status:wrongDestination.status,
      wrong_actor_and_destination_worker_outcomes:callbackOutcomes,
      revoked_actor_link_worker_outcome:revokedOutcome,
      warning_items:acknowledged.body.items,failure_alerts:alerts.body.items,
      assessment_nonmutation:true},null,2),{mode:0o600});
    const restart=execFileSync('docker',['restart',appContainer],{encoding:'utf8'}).trim();
    const until=Date.now()+90000;let healthy=false;
    while(Date.now()<until){
      try{const ready=await fetch(origin+'/openapi.json');if(ready.ok){healthy=true;break;}}catch{}
      await page.waitForTimeout(1000);
    }
    if(!healthy)throw new Error('app container did not recover after warning persistence restart');
    execFileSync('docker',['exec','-d',appContainer,
      '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_exception_warning_oidc_proxy.py',
      '--host','0.0.0.0','--port',String(oidcProxyPort),'--upstream-port','9000'],
      {encoding:'utf8',stdio:['ignore','pipe','pipe']});
    let oidcReady=false;const oidcUntil=Date.now()+15000;
    while(Date.now()<oidcUntil){
      try{execFileSync('docker',['exec',appContainer,'curl','--fail','--silent','--max-time','2',
        `http://127.0.0.1:${oidcProxyPort}/healthz`],{encoding:'utf8',stdio:['ignore','pipe','pipe']});oidcReady=true;break;}catch{}
      await page.waitForTimeout(250);
    }
    if(!oidcReady)throw new Error('disposable OIDC relay did not recover after container restart');
    await page.goto(origin+'/api/v1/auth/login',{waitUntil:'domcontentloaded'});
    await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session');if(!r.ok)return false;return (await r.json()).authenticated===true;},null,{timeout:30000});
    const afterRestart=await api(`/api/v1/assessment/groups/${findingId}/exception-warnings`);
    if(afterRestart.status!==200||!afterRestart.body.items?.some(item=>item.intent_id===warning.intent_id&&item.acknowledged_at))
      throw new Error('warning delivery and acknowledgement state did not persist across app restart');
    await writeFile(path.join(evidence,'warning-restart-proof.json'),JSON.stringify({
      restarted_container:appContainer,restart_result:restart,oidc_relay_restarted:true,
      persisted_warning_items:afterRestart.body.items},null,2),{mode:0o600});
    await page.goto(origin+'/#findings?group='+encodeURIComponent(findingId),{waitUntil:'domcontentloaded'});
    await page.waitForTimeout(2500);
    await writeFile(path.join(evidence,'warning-ui-debug.json'),JSON.stringify({
      title:await page.title(),url:page.url(),body:(await page.locator('body').innerText()).slice(0,5000),
      buttons:await page.getByRole('button').allTextContents(),errors:counts},null,2),{mode:0o600});
    await page.getByRole('button',{name:'Exceptions',exact:true}).waitFor({state:'visible',timeout:20000});
    await page.getByRole('button',{name:'Exceptions',exact:true}).click();
    await page.locator('.exception-warnings').waitFor({state:'visible',timeout:20000});
    await page.getByRole('heading',{name:'Exception warnings'}).waitFor({state:'visible'});
    await page.getByText('Acknowledged',{exact:true}).first().waitFor({state:'visible',timeout:10000});
    await page.screenshot({path:path.join(evidence,'warning-browser.png'),fullPage:true});
    await writeFile(path.join(evidence,'warning-browser.json'),JSON.stringify({
      page_title:await page.title(),url:page.url(),authenticated:true,
      rendered_warning_panel:true,acknowledgement_visible:true,workflow:'public_api_submit_and_approve'},null,2),{mode:0o600});
    process.stdout.write(JSON.stringify({warningWorkflow:'approved',findingId,acceptanceId})+'\n');
    process.exit(0);
  }

  const cross=await api('/api/v1/operations/observer-settings/g7-other');
  if(cross.status!==404)throw new Error(`registered deployment B read returned ${cross.status}: ${JSON.stringify(cross.body)}`);
  counts.crossDeploymentDenied=cross.status;
  const absent=await api('/api/v1/operations/observer-settings/g7-unregistered');
  if(absent.status!==404)throw new Error(`absent deployment read returned ${absent.status}`);
  counts.absentRegistryDirectRead=absent.status;
  const csrf=await page.evaluate(async()=>{
    const response=await fetch('/api/v1/assessment/commands',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({})});return response.status;
  });
  if(csrf!==403)throw new Error(`missing CSRF returned ${csrf}, expected 403`);
  counts.csrfDenied=csrf;

  const loggedOut=await api('/api/v1/auth/logout',{method:'POST',write:true,body:JSON.stringify({})});
  if(loggedOut.status!==200)throw new Error(`session refresh logout failed with ${loggedOut.status}`);
  await page.goto(origin+'/api/v1/auth/login',{waitUntil:'domcontentloaded'});
  await page.waitForFunction(async()=>{
    const r=await fetch('/api/v1/auth/session'); if(!r.ok)return false;
    const s=await r.json();return s.authenticated===true&&s.credential_mode==='oidc_session';
  },null,{timeout:30000});
  const refreshedSession=await api('/api/v1/auth/session');
  if(!refreshedSession.body.access_groups?.includes(groupId))
    throw new Error('fresh OIDC session did not resolve the newly granted access group');
  counts.sessionRefreshed=1;
  const backupInitial=await api('/api/v1/operations/backup-settings/g7-local');
  if(backupInitial.status!==200||backupInitial.body.revisions?.configuration!==0
      ||backupInitial.body.revisions?.host_policy!==1||backupInitial.body.desired!==null
      ||backupInitial.body.status?.settings_application!==null||backupInitial.body.can_configure!==true)
    throw new Error(`backup initial readback failed: ${JSON.stringify(backupInitial)}`);
  counts.backupInitialRead=1;
  let backupCommandId=crypto.randomUUID();
  let backupReceipt;
  if(backupSeedOnly){
    const step=await runBackupBrowserStep({page,origin, evidenceDirectory:path.join(evidence,"ui-publish"),
      expectations:{schema_version:1,id:"initial-publish",deployment_id:"g7-local",action:"publish",
        rationale:"Exercise the reviewed local backup settings contract",evidence_ref:"g7-backup-journey-fixture",
        values:{interval_seconds:300,timeout_seconds:120,maximum_backup_age_seconds:7200,restore_verification_timeout_seconds:600,archive_target_ref:"archive-target-local-a",recovery_profile_ref:"recovery-profile-local-a"},
        expect:{desired_revision:1,effective_revision:null,application:"pending",archive:"unknown",freshness:"unknown",restore:"unknown"}}});
    backupCommandId=step.commands[0].command_id;
    backupReceipt=await api(`/api/v1/operations/backup-settings/g7-local/receipts/${backupCommandId}`);
  }else backupReceipt=await api('/api/v1/operations/backup-settings/g7-local/commands',{
    method:'POST',write:true,body:JSON.stringify({schema_version:1,command_id:backupCommandId,
      action:'backup.settings.publish',expected_revisions:{configuration:0,
        policy:backupInitial.body.revisions.policy,authority:backupInitial.body.revisions.authority,host_policy:1},
      rationale:'Exercise the reviewed local backup settings contract',evidence_ref:'g7-backup-journey-fixture',
      values:{interval_seconds:300,timeout_seconds:120,maximum_backup_age_seconds:7200,
        restore_verification_timeout_seconds:600,archive_target_ref:'archive-target-local-a',
        recovery_profile_ref:'recovery-profile-local-a'}})});
  if(![200,201].includes(backupReceipt.status)||backupReceipt.body.outcome!=='desired_committed'
      ||backupReceipt.body.desired_revision!==1||backupReceipt.body.settings_digest?.length!==71)
    throw new Error(`backup settings command failed: ${JSON.stringify(backupReceipt)}`);
  counts.backupSettingsCommit=1;
  const retainedBackupReceipt=await api(`/api/v1/operations/backup-settings/g7-local/receipts/${backupCommandId}`);
  if(retainedBackupReceipt.status!==200||retainedBackupReceipt.body.intent_id!==backupReceipt.body.intent_id)
    throw new Error('backup command receipt did not read back atomically');
  counts.backupReceiptReadback=1;
  const backupReadback=await api('/api/v1/operations/backup-settings/g7-local');
  if(backupReadback.status!==200||backupReadback.body.desired?.revision!==1
      ||backupReadback.body.status.settings_application?.state!=='pending')
    throw new Error(`backup desired revision was not retained: ${JSON.stringify(backupReadback)}`);
  counts.backupDesiredReadback=1;
  const backupHostConfig=execFileSync('uv',['run','python','tools/g7_observer_fixture.py',
    'backup-host-config','--root',fixtureRoot],
    {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
  await writeFile(path.join(evidence,'backup-host-config.stdout'),backupHostConfig,{mode:0o600});
  const backupHostApply=execFileSync('uv',['run','python','tools/g7_observer_fixture.py',
    'backup-host-once','--root',fixtureRoot],
    {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
  await writeFile(path.join(evidence,'backup-host-once.stdout'),backupHostApply,{mode:0o600});
  const backupHostResult=JSON.parse(backupHostApply.trim());
  if(backupHostResult.state!=='applied'||backupHostResult.revision!==1||backupHostResult.sequence!==2)
    throw new Error(`independent host controller did not apply backup settings: ${backupHostApply.trim()}`);
  const backupEffective=await api('/api/v1/operations/backup-settings/g7-local');
  if(backupEffective.status!==200||backupEffective.body.status.settings_application?.state!=='applied'
      ||backupEffective.body.effective?.revision!==1
      ||backupEffective.body.effective?.digest!==backupReceipt.body.settings_digest)
    throw new Error(`backup host acknowledgement did not establish matching effective readback: ${JSON.stringify(backupEffective)}`);
  counts.backupHostApplied=1;
  counts.backupEffectiveReadback=1;
  if(backupSeedOnly){
    for(const item of [
      {id:'change',action:'publish',revision:2,interval:360},
      {id:'lost-ack',action:'publish',revision:3,interval:420,lose_acknowledgement:true},
      {id:'rollback',action:'rollback',revision:4,rollback_revision:1}]){
      await runBackupBrowserStep({page,origin,evidenceDirectory:path.join(evidence,'ui-'+item.id),
        expectations:{schema_version:1,id:item.id,deployment_id:'g7-local',action:item.action,
          rationale:'Disposable recovery '+item.id,evidence_ref:'g7-backup-journey-fixture',
          ...(item.action==='publish'?{values:{...backupEffective.body.desired.values,interval_seconds:item.interval}}:{rollback_revision:1}),
          ...(item.lose_acknowledgement?{lose_acknowledgement:true}:{}),
          expect:{desired_revision:item.revision,effective_revision:item.revision-1,application:'pending',archive:'unknown',freshness:'unknown',restore:'unknown'}}});
      execFileSync('uv',['run','python','tools/g7_observer_fixture.py','backup-host-once','--root',fixtureRoot],
        {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
      const applied=await api('/api/v1/operations/backup-settings/g7-local');
      if(applied.status!==200||applied.body.effective?.revision!==item.revision||applied.body.status.settings_application.state!=='applied')
        throw new Error('UI command was not independently consumed: '+JSON.stringify(applied));
    }
    const backupNegatives={};
    const stableBackup=await api('/api/v1/operations/backup-settings/g7-local');
    const {configuration,policy,authority,host_policy}=stableBackup.body.revisions;
    const makeCommand=()=>({schema_version:1,command_id:crypto.randomUUID(),action:'backup.settings.publish',
      expected_revisions:{configuration,policy,authority,host_policy},rationale:'Local backup safety assertion',
      evidence_ref:'g7-backup-journey-fixture',values:stableBackup.body.desired.values});
    const denied=await api('/api/v1/operations/backup-settings/g7-other/commands',{method:'POST',write:true,body:JSON.stringify(makeCommand())});
    if(denied.status!==404)throw new Error('Backup explicit deny disclosed or allowed the deployment');
    backupNegatives.crossDeploymentDenied=denied.status;
    const staleBody=makeCommand();staleBody.expected_revisions.configuration=0;
    const stale=await api('/api/v1/operations/backup-settings/g7-local/commands',{method:'POST',write:true,body:JSON.stringify(staleBody)});
    if(stale.status!==409)throw new Error('Backup stale revision was accepted');
    backupNegatives.staleRevision=stale.status;
    for(const stage of ['audit','intent','receipt']){
      const before=await hostTelemetryCount();const command=makeCommand();
      const failed=await api('/api/v1/operations/backup-settings/g7-local/commands',{method:'POST',write:true,
        headers:{'X-UVM-G7-Fixture-Failpoint':stage},body:JSON.stringify(command)});
      const after=await hostTelemetryCount();
      const receipt=await api('/api/v1/operations/backup-settings/g7-local/receipts/'+command.command_id);
      const unchanged=await api('/api/v1/operations/backup-settings/g7-local');
      if(failed.status!==503||receipt.status!==404||unchanged.body.revisions.configuration!==4||before.audit_event_count!==after.audit_event_count)
        throw new Error('Backup atomic '+stage+' failure leaked durable state');
      backupNegatives[stage]={status:failed.status,receipt_status:receipt.status,audit_unchanged:true,configuration:4};
    }
    await writeFile(path.join(evidence,'backup-command-negatives.json'),JSON.stringify(backupNegatives),{mode:0o600});
    const retainedIds=JSON.parse(await readFile(path.join(evidence,'retained-fixture-ids.json'),'utf8'));
    const retainedGroup=await api('/api/v1/assessment/groups/'+retainedIds.group);
    const retainedAudit=await api('/api/v1/assessment/audit?group_id='+retainedIds.group);
    if(retainedGroup.status!==200||retainedAudit.status!==200||retainedGroup.body.assessment.assessed_severity?.value!=='high'
        ||retainedGroup.body.github.issue_number!==7||retainedGroup.body.github.state!=='uncertain'
        ||!retainedGroup.body.assessment.pending_projection_intents.some(i=>i.intent_id===retainedIds.intent&&i.status==='uncertain'))
      throw new Error('Retained UVM public sentinel is incomplete: '+JSON.stringify({retainedGroup,retainedAudit}));
    await writeFile(path.join(evidence,'source-uvm-retained-group.json'),JSON.stringify(retainedGroup.body),{mode:0o600});
    await writeFile(path.join(evidence,'source-uvm-retained-audit.json'),JSON.stringify(retainedAudit.body),{mode:0o600});
    const finalBackup=await api('/api/v1/operations/backup-settings/g7-local');
    counts.status='backup_seeded';
    await context.storageState({path:path.join(evidence,'recovery-auth-state.json')});
    await writeFile(path.join(evidence,'backup-seed-readback.json'),JSON.stringify({
      public_settings:'applied',desired_revision:finalBackup.body.desired.revision,
      effective_revision:finalBackup.body.effective.revision,
      effective_digest:finalBackup.body.effective.digest,
      receipt_id:retainedBackupReceipt.body.intent_id},null,2)+'\n',{mode:0o600});
    const marker=new Error('G7_BACKUP_SEED_ONLY_COMPLETE');
    marker.backupSeedOnly=true;
    throw marker;
  }
  const explicitlyDeniedB=await api('/api/v1/operations/observer-settings/g7-other');
  if(explicitlyDeniedB.status!==404)
    throw new Error(`registered B with a matching explicit deny returned ${explicitlyDeniedB.status}`);
  counts.registeredMatchingDenyDirectRead=explicitlyDeniedB.status;
  const discovery=await api('/api/v1/operations/observer-settings?limit=100');
  if(discovery.status!==200||discovery.body.deployments?.length!==1
      ||discovery.body.deployments[0]?.deployment_id!=='g7-local'||discovery.body.next_cursor!==null)
    throw new Error('bounded discovery exposed registered deployment B despite a matching explicit deny');
  counts.authorizedDiscovery=discovery.body.deployments.length;
  counts.registeredMatchingDenyDiscovery=discovery.body.deployments.some(item=>item.deployment_id==='g7-other')?0:1;
  const discoveryOverbound=await api('/api/v1/operations/observer-settings?limit=1000');
  if(discoveryOverbound.status!==400)throw new Error(`deployment discovery accepted overbound limit ${discoveryOverbound.status}`);
  counts.discoveryOverboundDenied=discoveryOverbound.status;
  const initial=await api('/api/v1/operations/observer-settings/g7-local');
  if(initial.status!==200||initial.body.desired!==null||initial.body.application!==null||initial.body.effective!==null)
    throw new Error(`initial observer state was not unconfigured: ${JSON.stringify(initial.body)}`);
  counts.initialUnconfigured=1;

  await page.goto(origin+'/#administration?section=observer-timing&deployment_id=g7-local',{waitUntil:'domcontentloaded'});
  await page.getByRole('heading',{name:'Observer timing'}).waitFor({timeout:20000});
  await page.getByLabel('Deployment').selectOption('g7-local');
  await page.getByText('Host application',{exact:true}).waitFor({timeout:15000});
  await page.getByText('Not configured',{exact:true}).waitFor({timeout:10000});
  await page.getByLabel('Observation interval').waitFor({timeout:15000});

  const values1={observation_interval_seconds:1,request_deadline_seconds:8,heartbeat_freshness_seconds:3,
    maximum_future_skew_seconds:1,anchor_export_lag_seconds:30,incident_projection_deadline_seconds:10,
    scheduler_progress_freshness_seconds:15};
  const fillValues=async values=>{
    for(const [label,value] of Object.entries({'Observation interval':values.observation_interval_seconds,
      'Request deadline':values.request_deadline_seconds,'Heartbeat freshness':values.heartbeat_freshness_seconds,
      'Maximum future skew':values.maximum_future_skew_seconds,'Anchor export lag':values.anchor_export_lag_seconds,
      'Incident projection deadline':values.incident_projection_deadline_seconds,
      'Scheduler progress freshness':values.scheduler_progress_freshness_seconds}))
      await page.getByLabel(label).fill(String(value));
    await page.getByLabel('Reason for change').fill('Disposable observer settings journey revision');
  };
  await fillValues(values1);
  dropCommandAcknowledgement=true;
  await page.route(/\/api\/v1\/operations\/observer-settings\/[^/]+\/commands$/,async route=>{
    if(dropCommandAcknowledgement&&route.request().method()==='POST'){
      dropCommandAcknowledgement=false;
      const response=await route.fetch();
      if(!response.ok())throw new Error(`lost-ack fixture command returned ${response.status()}`);
      droppedReceipt=await response.json();
      counts.lostAcknowledgement=1;
      await route.abort('connectionreset');
    } else await route.continue();
  });
  await page.getByRole('button',{name:'Save timing settings'}).click();
  await page.getByText('Command outcome needs recovery',{exact:true}).waitFor({timeout:10000});
  await page.getByRole('button',{name:'Check command receipt'}).click();
  await page.getByText(/Desired revision 1 recorded/).waitFor({timeout:15000});
  counts.receiptRecovery=1;
  if(!droppedReceipt||droppedReceipt.configuration_revision!==1)throw new Error('exact replay receipt not retained');
  await page.locator('.observer-state.applied').waitFor({timeout:90000});
  counts.revision1=1;

  const after1=await api('/api/v1/operations/observer-settings/g7-local');
  if(after1.status!==200||after1.body.desired?.revision!==1||after1.body.application?.status!=='applied'
      ||after1.body.effective?.revision!==1||after1.body.effective?.digest!==after1.body.desired?.digest)
    throw new Error('revision 1 did not reach matching effective readback');

  const atomicValues={...values1,request_deadline_seconds:10};
  counts.atomicWriteFailures={};
  for(const target of ['audit','receipt','intent'])
    counts.atomicWriteFailures[target]=await failAtomicWrite(target,atomicValues);

  const values2={...values1,request_deadline_seconds:9,incident_projection_deadline_seconds:11};
  await fillValues(values2);
  hostControl('controller','stop');
  try {
    await page.getByRole('button',{name:'Save timing settings'}).click();
    await page.getByText(/Desired revision 2 recorded/).waitFor({timeout:15000});
    const pending=await api('/api/v1/operations/observer-settings/g7-local');
    if(pending.body.desired?.revision!==2||pending.body.application?.status!=='pending'
        ||pending.body.effective?.revision!==1)
      throw new Error(`rev2 did not expose pending while the controller was held: ${JSON.stringify({desired:pending.body.desired,application:pending.body.application,effective:pending.body.effective})}`);
    counts.pending=1;
  } finally { hostControl('controller','resume'); }
  const after2=await waitForAppliedRevision(2);
  counts.apiRevision2={status:after2?.status,application:after2?.body?.application,effective:after2?.body?.effective,desired:after2?.body?.desired};
  await page.getByRole('button',{name:'Refresh observer state'}).click();
  await page.waitForTimeout(1500);
  counts.uiApplicationRevision2=await page.locator('.observer-state').innerText().catch(()=>null);
  counts.uiNoticesRevision2=await page.locator('.observer-notice').allInnerTexts().catch(()=>[]);
  if(!counts.uiApplicationRevision2?.includes('Applied'))
    throw new Error(`revision 2 UI did not display applied state: ${JSON.stringify({status:counts.uiApplicationRevision2,notices:counts.uiNoticesRevision2,api:counts.apiRevision2})}`);
  counts.revision2=1;
  if(after2.status!==200||after2.body.desired?.revision!==2||after2.body.application?.status!=='applied'
      ||after2.body.effective?.revision!==2)throw new Error(`revision 2 was not applied: ${JSON.stringify({status:after2.status,desired:after2.body.desired,application:after2.body.application,effective:after2.body.effective})}`);
  const stale=await api('/api/v1/operations/observer-settings/g7-local/commands',{method:'POST',write:true,
    body:JSON.stringify({schema_version:1,command_id:crypto.randomUUID(),action:'observer.timing.publish',
      expected_revisions:{...after2.body.revisions,configuration:1},rationale:'stale revision fixture',values:values1})});
  if(stale.status!==409)throw new Error(`stale revision returned ${stale.status}`);
  counts.staleRevisionDenied=stale.status;
  const invalid=await api('/api/v1/operations/observer-settings/g7-local/commands',{method:'POST',write:true,
    body:JSON.stringify({schema_version:1,command_id:crypto.randomUUID(),action:'observer.timing.publish',
      expected_revisions:after2.body.revisions,rationale:'invalid value fixture',values:{...values2,request_deadline_seconds:true}})});
  if(![400,422].includes(invalid.status))throw new Error(`invalid value returned ${invalid.status}`);
  counts.invalidValueDenied=invalid.status;

  await page.getByLabel('Historical revision').fill('1');
  await page.getByRole('button',{name:'Read historical revision'}).click();
  await page.getByRole('button',{name:'Roll back as new revision'}).waitFor({timeout:10000});
  await page.getByRole('button',{name:'Roll back as new revision'}).click();
  await page.getByText(/Desired revision 3 recorded/).waitFor({timeout:15000});
  const after3=await waitForAppliedRevision(3);
  await page.getByRole('button',{name:'Refresh observer state'}).click();
  await page.waitForFunction(()=>document.querySelector('.observer-state')?.textContent?.includes('Applied'),null,{timeout:15000});
  counts.rollback3=1;
  if(after3.status!==200||after3.body.desired?.revision!==3||after3.body.application?.status!=='applied'
      ||after3.body.effective?.revision!==3||after3.body.desired?.values?.request_deadline_seconds!==values1.request_deadline_seconds)
    throw new Error('rollback did not create and apply revision 3 from revision 1');

  // Run while the authenticated policy and applied host timing are present,
  // before browser fault cases create intentional unknown anchor telemetry.
  // Recovery still uses the strict post-restart serial observer barrier.
  if(operationalAlertsOnly){
    // The fixture deliberately logged out and refreshed the OIDC session
    // earlier; persist that current cookie rather than the pre-refresh state.
    await context.storageState({path:path.join(evidence,'recovery-auth-state.json')});
    const args=['run','python','tools/g7_operational_alert_journey.py','--container',appContainer,
      '--run-id',path.basename(fixtureRoot).split('.').at(-1),
      '--api-port',new URL(origin).port,'--root',fixtureRoot,'--evidence',evidence,
      '--browser-state',path.join(evidence,'recovery-auth-state.json')];
    try{
      const stdout=execFileSync('uv',args,{cwd:repoRoot,encoding:'utf8',maxBuffer:1024*1024,
        env:{...process.env,UV_CACHE_DIR:process.env.UV_CACHE_DIR??'/tmp/volt-g7-uv-cache',
          G7_OPERATIONAL_RECIPIENT_GROUP_ID:groupId}});
      await writeFile(path.join(evidence,'operational-alert-journey.stdout'),stdout,{mode:0o600});
    }catch(error){
      await writeFile(path.join(evidence,'operational-alert-journey.stdout'),error.stdout??'',{mode:0o600});
      await writeFile(path.join(evidence,'operational-alert-journey.stderr'),error.stderr??String(error),{mode:0o600});
      throw error;
    }
    await waitForContainerHealthy();
    await page.goto(origin+'/#administration?section=observer-timing&deployment_id=g7-local',
      {waitUntil:'domcontentloaded',timeout:30000});
    await page.getByRole('heading',{name:'Observer timing'}).waitFor({timeout:20000});
    await page.getByLabel('Observation interval').waitFor({timeout:15000});
    await page.getByRole('button',{name:'Refresh observer state'}).click();

    // This mode owns the operational-alert acceptance journey. Do not fall
    // through into the separate observer fault/restart suite below: that
    // suite deliberately tears down the browser context after its own proof.
    // Exercise the real authenticated incidents endpoint and rendered
    // consumer here before returning to the maintained wrapper.
    const session=await api('/api/v1/auth/session');
    const scope=session.body?.authority?.group_scopes?.[groupId]??[];
    const roles=session.body?.authority?.group_roles?.[groupId]??[];
    if(session.status!==200||session.body?.authenticated!==true
      ||!session.body.access_groups?.includes(groupId)
      ||!roles.includes('g7-operational-alert-reader')
      ||!scope.some(item=>Array.isArray(item)&&item[0]==='local'&&item[1]==='g7-local'&&item[2]==='all'))
      throw new Error('operational incident browser read lacks the current recipient group or exact deployment source scope');

    const incidentRead=await api('/api/v1/integrations/incidents?deployment_id=g7-local&limit=50&offset=0');
    if(incidentRead.status!==200||incidentRead.body?.schema_version!==1
      ||!Array.isArray(incidentRead.body.items))
      throw new Error(`scoped operational incident read returned ${incidentRead.status}`);
    const rows=incidentRead.body.items;
    const availability=rows.filter(item=>item.deployment_id==='g7-local'
      &&item.subject_id===`container:g7-local:${path.basename(fixtureRoot).split('.').at(-1)}`
      &&item.condition==='container_availability');
    const senderHealth=rows.filter(item=>item.deployment_id==='g7-local'
      &&item.subject_id===`host-sender:g7-local:${path.basename(fixtureRoot).split('.').at(-1)}`
      &&item.condition==='host_sender_health');
    for(const [name,stream,total] of [['availability',availability,4],['senderHealth',senderHealth,2]]){
      if(stream.length!==total||stream.some((item,index)=>
        item.transition_kind!==(index%2===0?'opened':'recovered')
        ||item.transition_sequence!==index+1
        ||item.predecessor_id!==(index===0?null:stream[index-1].transition_id)
        ||item.notification?.state!==(name==='availability'&&index===2?'failed':'accepted')
        ||!Array.isArray(item.notification.attempts)||item.notification.attempts.length!==1
        ||item.notification.attempts.some(attempt=>!attempt.attempt_id
          ||attempt.outcome!==(name==='availability'&&index===2?'failed':'accepted'))))
        throw new Error(`scoped ${name} incident stream is incomplete or lacks truthful delivery attempts`);
    }
    await writeFile(path.join(evidence,'operational-browser-consumer.json'),JSON.stringify({
      session_status:session.status,principal_id:session.body.principal_id,
      recipient_group_id:groupId,source_scope:['local','g7-local','all'],
      incident_status:incidentRead.status,item_count:rows.length,
      streams:[...availability,...senderHealth].map(item=>({
        condition:item.condition,subject_id:item.subject_id,transition_id:item.transition_id,
        transition_kind:item.transition_kind,transition_sequence:item.transition_sequence,
        predecessor_id:item.predecessor_id,notification_state:item.notification.state,
        attempt_ids:item.notification.attempts.map(attempt=>attempt.attempt_id),
        attempt_outcomes:item.notification.attempts.map(attempt=>attempt.outcome)}))
    },null,2)+'\n',{mode:0o600});

    await page.goto(origin+'/#incidents?deployment_id=g7-local',{waitUntil:'domcontentloaded',timeout:30000});
    await page.getByRole('heading',{name:'Incident history'}).waitFor({timeout:20000});
    await page.getByText('6 authorised transitions on this page.').waitFor({timeout:20000});
    const cards=page.locator('.incident-card');
    if(await cards.count()!==6)throw new Error('rendered scoped incident history did not contain the six verified transitions');
    for(const card of await cards.all()){
      await card.locator('details > summary').click();
      await card.locator('.incident-identifiers').waitFor({timeout:10000});
    }
    const rendered=await captureOperationalCards(cards);
    assertOperationalRenderedCards([...availability,...senderHealth],rendered);
    const consumerPath=path.join(evidence,'operational-browser-consumer.json');
    const consumer=JSON.parse(await readFile(consumerPath,'utf8'));
    consumer.rendered=rendered;
    await writeFile(consumerPath,JSON.stringify(consumer,null,2)+'\n',{mode:0o600});
    await page.screenshot({path:path.join(evidence,'operational-incidents-current.png'),fullPage:true});
    counts.operationalIncidentConsumer={session:session.status,incidentRead:incidentRead.status,
      recipientGroup:groupId,sourceScope:'local/g7-local/all',transitions:rows.length,
      renderedCards:await cards.count(),availabilityAcceptedAttempts:availability.reduce((n,item)=>n+item.notification.attempts.length,0),
      senderHealthAcceptedAttempts:senderHealth.reduce((n,item)=>n+item.notification.attempts.length,0)};
    counts.status='passed';
    await writeFile(path.join(evidence,'browser-journey.json'),JSON.stringify(counts,null,2)+'\n',{mode:0o600});
    await browser.close();
    process.exit(0);
  }

  // Restart each independent host process and prove its persisted work and
  // consumer progress survive process replacement.
  const hostStateDir=path.join(fixtureRoot,'host','state');
  const observerStatePath=path.join(hostStateDir,'observer-state.json');
  const supervisorStatePath=path.join(hostStateDir,'supervisor-state.json');
  const beforeObserver=JSON.parse(await readFile(observerStatePath,'utf8'));
  const beforeSupervisor=JSON.parse(await readFile(supervisorStatePath,'utf8'));
  hostControl('observer','restart');
  hostControl('supervisor','restart');
  await waitForJson(observerStatePath,state=>state.loop_sequence>beforeObserver.loop_sequence);
  await waitForJson(supervisorStatePath,state=>state.loop_sequence>beforeSupervisor.loop_sequence);
  const observerReadback=JSON.parse(await readFile(path.join(hostStateDir,'observer-readback.json'),'utf8'));
  const supervisorReadback=JSON.parse(await readFile(path.join(hostStateDir,'supervisor-readback.json'),'utf8'));
  if(observerReadback.revision!==3||supervisorReadback.revision!==3)
    throw new Error('consumer restart lost verified revision 3');
  counts.consumerRestarts=2;
  hostControl('controller','restart');
  await page.waitForTimeout(1500);
  const afterControllerRestart=await api('/api/v1/operations/observer-settings/g7-local');
  if(afterControllerRestart.body.application?.status!=='applied'||afterControllerRestart.body.effective?.revision!==3)
    throw new Error('controller restart did not preserve the verified application');
  counts.controllerRestart=1;

  // The scheduler stall marker blocks heartbeat publication after a real
  // completed tick; the host observer must fail closed on missing, stale,
  // future, and nonprogressing samples, then recover after the scheduler resumes.
  const progressPath=path.join(fixtureRoot,'scheduler','progress.json');
  const stallMarker='/run/uvm-g7-scheduler/test-stall';
  const lastProgress=JSON.parse(await readFile(progressPath,'utf8'));
  docker(['exec',appContainer,'touch',stallMarker]);
  try {
    await page.waitForTimeout(18000);
    let observerState=JSON.parse(await readFile(observerStatePath,'utf8'));
    if(observerState.scheduler?.status!=='stale_or_nonprogressing')
      throw new Error('real scheduler stall did not fail host scheduler progress health');
    counts.schedulerStall=1;
    counts.healthFaults.push('real_scheduler_stall');
    docker(['exec','-u','0',appContainer,'rm','-f','/run/uvm-g7-scheduler/progress.json']);
    observerState=await waitForJson(observerStatePath,state=>state.scheduler?.status==='stale_or_nonprogressing'
      &&state.scheduler?.loop_sequence===null);
    counts.healthFaults.push('missing_scheduler_progress');
    // Supply a structurally valid future sample while the actual scheduler is
    // held at the completion boundary; the monotonic skew check must reject it.
    const future={...lastProgress,loop_sequence:Number(lastProgress.loop_sequence)+1,
      monotonic_ns:Number(lastProgress.monotonic_ns)+120_000_000_000};
    const futurePath=path.join('/tmp',`volt-g7-progress-future-${crypto.randomUUID()}.json`);
    await writeFile(futurePath,JSON.stringify(future)+'\n',{mode:0o644});
    docker(['cp',futurePath,`${appContainer}:/tmp/progress.future.json`]);
    docker(['exec','-u','0',appContainer,'cp','/tmp/progress.future.json','/run/uvm-g7-scheduler/progress.json']);
    docker(['exec','-u','0',appContainer,'chmod','0644','/run/uvm-g7-scheduler/progress.json']);
    await unlink(futurePath);
    const futureState=await waitForJson(observerStatePath,state=>state.scheduler?.sample_age_seconds<0);
    if(futureState.scheduler.status!=='stale_or_nonprogressing')throw new Error('future scheduler heartbeat was accepted');
    counts.healthFaults.push('future_scheduler_progress');
  } finally { docker(['exec',appContainer,'rm','-f',stallMarker]); }
  await waitForJson(observerStatePath,state=>state.scheduler?.status==='healthy',25000);
  counts.healthFaults.push('scheduler_recovered');

  // Stop the observer consumer and corrupt its persisted heartbeat in both
  // directions. The independent supervisor must reject stale and future data.
  hostControl('observer','stop');
  try {
    const heartbeatState=JSON.parse(await readFile(observerStatePath,'utf8'));
    heartbeatState.last_completed_loop_at=new Date(Date.now()-60000).toISOString();
    await writeFile(observerStatePath,JSON.stringify(heartbeatState)+'\n',{mode:0o600});
    const staleSupervision=await waitForJson(supervisorStatePath,state=>state.supervision?.status==='stale_or_future');
    if(!(staleSupervision.supervision.heartbeat_age_seconds>3))throw new Error('stale observer heartbeat was not measured');
    counts.healthFaults.push('stale_observer_heartbeat');
    heartbeatState.last_completed_loop_at=new Date(Date.now()+120000).toISOString();
    await writeFile(observerStatePath,JSON.stringify(heartbeatState)+'\n',{mode:0o600});
    const futureSupervision=await waitForJson(supervisorStatePath,state=>state.supervision?.heartbeat_age_seconds<0);
    if(futureSupervision.supervision.status!=='stale_or_future')throw new Error('future observer heartbeat was accepted');
    counts.healthFaults.push('future_observer_heartbeat');
  } finally { hostControl('observer','restart'); }
  await waitForJson(supervisorStatePath,state=>state.supervision?.status==='healthy',10000);
  counts.healthFaults.push('observer_heartbeat_recovered');

  // Exercise signature validation and report id/sequence conflict handling
  // against the live host-report endpoint, with no state-changing request
  // admitted by the API.
  const latestForAttack=await api('/api/v1/operations/observer-settings/g7-local');
  hostControl('controller','stop');
  try {
    const attackOutput=execFileSync('uv',['run','python','tools/g7_observer_fixture.py',
      'host-report-attacks','--root',fixtureRoot,'--report-id',latestForAttack.body.application.latest_report_id],
      {cwd:repoRoot,encoding:'utf8',stdio:['ignore','pipe','pipe']});
    const attacks=JSON.parse(attackOutput.trim());
    counts.hostReportAttacks=attacks;
    if(![401,403].includes(attacks.forged)||attacks.stale!==409||attacks.conflicting!==409)
      throw new Error(`host report attack checks returned unexpected statuses: ${JSON.stringify(attacks)}`);
  } finally { hostControl('controller','resume'); }

  // A newly published candidate outside the current host policy is reported
  // failed without advancing the verified effective snapshot.
  const values4={...values1,request_deadline_seconds:9,incident_projection_deadline_seconds:11};
  hostControl('controller','stop');
  await fillValues(values4);
  await page.getByRole('button',{name:'Save timing settings'}).click();
  try {
    await page.getByText(/Desired revision 4 recorded/).waitFor({timeout:15000});
  } catch(error) {
    const readback=await api('/api/v1/operations/observer-settings/g7-local');
    await writeFile(path.join(evidence,'revision4-save-diagnostics.json'),JSON.stringify({
      api_status:readback.status,desired:readback.body?.desired,revisions:readback.body?.revisions,
      notices:await page.locator('.observer-notice').allInnerTexts().catch(()=>[]),
      state:await page.locator('.observer-state').innerText().catch(()=>null),
      alert_text:await page.locator('[role=alert]').allInnerTexts().catch(()=>[])
    },null,2)+'\n',{mode:0o600});
    throw error;
  }
  hostControl('controller','tighten-policy');
  const failed=await waitForHostStatus('failed',30000);
  if(failed.body.desired?.revision!==4||failed.body.effective?.revision!==3
      ||failed.body.application?.failure_code!=='host_policy_rejected')
    throw new Error(`host policy rejection did not preserve last-good revision 3: ${JSON.stringify(failed.body)}`);
  counts.failed=1;

  // Restore an admissible host policy, then publish revision 5 against the
  // newly observed host-policy revision so the controller can recover.
  hostControl('controller','restore-policy');
  const policyDeadline=Date.now()+30000;
  let policyState;
  while(Date.now()<policyDeadline){
    policyState=await api('/api/v1/operations/observer-settings/g7-local');
    if(policyState.body.host_policy?.revision===3)break;
    await page.waitForTimeout(500);
  }
  if(policyState?.body?.host_policy?.revision!==3)
    throw new Error('restored host policy revision 3 was not reported');
  await page.getByRole('button',{name:'Refresh observer state'}).click();
  await page.waitForTimeout(1200);
  counts.uiAfterFailure={state:await page.locator('.observer-state').innerText().catch(()=>null),
    saveDisabled:await page.getByRole('button',{name:'Save timing settings'}).isDisabled(),
    notices:await page.locator('.observer-notice').allInnerTexts().catch(()=>[])};
  await page.getByLabel('Request deadline').waitFor({timeout:10000});
  await page.waitForFunction(()=>document.querySelector('input[aria-label="Request deadline"]')?.getAttribute('max')==='3600',null,{timeout:15000});
  await page.getByRole('button',{name:'Use latest saved values'}).click();
  const values5={...values1,request_deadline_seconds:8,incident_projection_deadline_seconds:10};
  await page.getByLabel('Request deadline').fill(String(values5.request_deadline_seconds));
  await page.getByLabel('Incident projection deadline').fill(String(values5.incident_projection_deadline_seconds));
  await page.getByLabel('Reason for change').fill('Restore observer settings after host policy correction');
  const recoveryResponse=page.waitForResponse(response=>response.url().endsWith('/api/v1/operations/observer-settings/g7-local/commands')
    &&response.request().method()==='POST');
  await page.getByRole('button',{name:'Save timing settings'}).click();
  await page.getByText(/Desired revision 5 recorded/).waitFor({timeout:15000});
  const recoveryHttp=await recoveryResponse;
  if(recoveryHttp.status()!==201)throw new Error(`rendered recovery Save returned ${recoveryHttp.status()}, expected 201`);
  counts.uiRecoverySaveStatus=recoveryHttp.status();
  const recovered5=await waitForAppliedRevision(5);
  await page.getByRole('button',{name:'Refresh observer state'}).click();
  await page.waitForFunction(()=>document.querySelector('.observer-state')?.textContent?.includes('Applied'),null,{timeout:15000});
  if(recovered5.body.application?.status!=='applied'||recovered5.body.effective?.revision!==5
      ||failed.body.effective?.revision!==3)
    throw new Error('rendered rev5 recovery did not apply after preserving rev3 as last-good on failure');
  counts.failedPreservedEffectiveRevision=failed.body.effective.revision;
  counts.uiRecoveryAppliedRevision=recovered5.body.effective.revision;

  // A real one-consumer outage must expose uncertainty while preserving
  // revision 5 as last-good, then converge after the stopped consumer returns.
  hostControl('supervisor','stop');
  const values6={...values5,request_deadline_seconds:9,incident_projection_deadline_seconds:11};
  const published6=await publishApi(values6,'Exercise partial observer application uncertainty');
  if(published6.configuration_revision!==6)throw new Error('uncertainty fixture did not create revision 6');
  const uncertain=await waitForHostStatus('uncertain',45000);
  if(uncertain.body.desired?.revision!==6||uncertain.body.effective?.revision!==5)
    throw new Error(`partial application did not preserve last-good revision 5: ${JSON.stringify(uncertain.body)}`);
  counts.uncertain=1;
  hostControl('supervisor','restart');
  await waitForAppliedRevision(6);

  // Stop the complete application while the independent host still owns
  // revision 6; check both consumers keep making progress, then reconcile a
  // pending revision after the app returns.
  hostControl('controller','stop');
  const values7={...values1,request_deadline_seconds:10,incident_projection_deadline_seconds:12};
  const published7=await publishApi(values7,'Exercise reconciliation after application outage');
  if(published7.configuration_revision!==7)throw new Error('outage fixture did not create revision 7');
  const outagePending=await api('/api/v1/operations/observer-settings/g7-local');
  if(outagePending.body.application?.status!=='pending'||outagePending.body.effective?.revision!==6)
    throw new Error('revision 7 was not pending before whole-container outage');
  const beforeOutageObserver=JSON.parse(await readFile(observerStatePath,'utf8'));
  const beforeOutageSupervisor=JSON.parse(await readFile(supervisorStatePath,'utf8'));
  docker(['stop',appContainer]);
  await waitForJson(observerStatePath,state=>state.loop_sequence>beforeOutageObserver.loop_sequence,15000);
  await waitForJson(supervisorStatePath,state=>state.loop_sequence>beforeOutageSupervisor.loop_sequence,15000);
  const outageReadbacks=await Promise.all(['observer-readback.json','supervisor-readback.json'].map(async name=>
    JSON.parse(await readFile(path.join(hostStateDir,name),'utf8'))));
  if(outageReadbacks.some(item=>item.revision!==6))
    throw new Error('host consumers did not preserve revision 6 through the app outage');
  docker(['start',appContainer]);
  await waitForContainerHealthy(150000);
  await page.reload({waitUntil:'domcontentloaded'});
  hostControl('controller','resume');
  const after7=await waitForAppliedRevision(7);
  counts.containerOutage=1;
  counts.containerRestart=1;

  // Create an admitted-but-unacknowledged applied report, then leave the
  // consumers stopped beyond the report freshness window. A controller-only
  // restart must not turn their old readbacks into fresh applied evidence.
  await page.goto(origin+'/#administration?section=observer-timing&deployment_id=g7-local',{waitUntil:'domcontentloaded'});
  await page.getByRole('heading',{name:'Observer timing'}).waitFor({timeout:20000});
  await page.getByLabel('Deployment').selectOption('g7-local');
  const values8={...values1,request_deadline_seconds:11,incident_projection_deadline_seconds:13};
  await fillValues(values8);
  // Stop the background controller before Save, so no unobserved loop can
  // report revision 8 before the deliberate one-shot/replay sequence.
  hostControl('controller','terminate');
  const rev8ResponsePromise=page.waitForResponse(response=>response.url().includes('/observer-settings/g7-local/commands')
    &&response.request().method()==='POST');
  await page.getByRole('button',{name:'Save timing settings'}).click();
  const rev8Response=await rev8ResponsePromise;
  if(rev8Response.status()!==201)throw new Error(`rev8 UI Save returned ${rev8Response.status()}`);
  await page.getByText(/Desired revision 8 recorded/).waitFor({timeout:15000});
  const pending8=await api('/api/v1/operations/observer-settings/g7-local');
  if(pending8.body.desired?.revision!==8||pending8.body.application?.status!=='pending'
      ||pending8.body.effective?.revision!==7)
    throw new Error('rev8 did not remain pending before stale-readback expiry check');
  const once=hostOnce();
  if(once.status!=='applied'||once.revision!==8)
    throw new Error(`one-shot controller did not create the pending applied report: ${JSON.stringify(once)}`);
  hostControl('observer','stop');
  hostControl('supervisor','stop');
  await page.waitForTimeout(61000);
  hostControl('controller','start');
  const controllerLog=path.join(fixtureRoot,'host','controller.log');
  await waitForHostLog(controllerLog,'consumer_readback_stale',20000);
  const staleApplied=await api('/api/v1/operations/observer-settings/g7-local');
  if(staleApplied.body.desired?.revision!==8||staleApplied.body.application?.status==='applied'
      ||staleApplied.body.effective?.revision!==7)
    throw new Error(`expired report falsely advanced applied revision: ${JSON.stringify({
      desired:staleApplied.body.desired,application:staleApplied.body.application,effective:staleApplied.body.effective})}`);
  counts.expiredReportNoFalseApplied=1;
  hostControl('observer','resume');
  hostControl('supervisor','resume');
  const after8=await waitForAppliedRevision(8);
  counts.expiredReportFreshRecovery=1;
  if(after8.body.effective?.revision!==8)throw new Error('fresh consumer work did not reconcile expired report revision 8');

  // Exercise keyboard reachability, WCAG 2.1 A/AA and responsive reflow at
  // the three required widths. Reports intentionally retain only counts and
  // violation rule IDs, never page text or credentials.
  await page.keyboard.press('Tab');
  if(await page.evaluate(()=>document.activeElement===document.body))throw new Error('keyboard focus did not enter the UI');
  await page.addScriptTag({path:path.join(repoRoot,'ui/node_modules/axe-core/axe.min.js')});
  for(const width of [1440,390,320]){
    await page.setViewportSize({width,height:1000});
    await page.waitForTimeout(300);
    const overflow=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));
    if(overflow.scroll>overflow.width+1)throw new Error(`horizontal overflow at ${width}px`);
    counts.reflow.push({width,...overflow});
    const axe=await page.evaluate(async()=>{const r=await window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa']}});return {violations:r.violations.map(v=>v.id),passes:r.passes.length};});
    counts.axe.push({width,...axe});
    if(axe.violations.length)throw new Error(`axe violations at ${width}px: ${axe.violations.join(',')}`);
    const screenshot=path.join(evidence,`observer-settings-${width}.png`);
    await page.screenshot({path:screenshot,fullPage:true}); counts.screenshots.push(screenshot);
  }

  // Remove the only deployment-scoped grant through the audited authority
  // API and verify the deployment becomes non-disclosing to that actor.
  const groups=await api('/api/v1/assessment/access-groups');
  const group=groups.body.items?.find(item=>item.display_name==='Disposable observer operators');
  if(!group){
    await writeFile(path.join(evidence,'grant-withdrawal-group-diagnostics.json'),JSON.stringify({
      status:groups.status,body:groups.body
    },null,2)+'\n',{mode:0o600});
    throw new Error('disposable access group missing during grant-withdrawal check');
  }
  const cat=await api('/api/v1/assessment/administration/catalogue');
  const withdrawn=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
    command_id:crypto.randomUUID(),target_id:zero,action:'access_group.membership.set',membership_ids:[],
    expected_revisions:{target:cat.body.policy_revision,policy:cat.body.policy_revision,
      authority:cat.body.authority_revision,identity_membership:0,owners:0,access_group:group.revision},
    payload:{access_group_id:group.access_group_id,principal_id:'g7-actor',effective_from:new Date().toISOString(),
      enabled:false,rationale:'Withdraw disposable observer fixture access',evidence_ref:'g7-observer-journey-fixture'}})});
  if(withdrawn.status!==200)throw new Error(`grant withdrawal failed with ${withdrawn.status}`);
  const denied=await api('/api/v1/operations/observer-settings/g7-local');
  if(denied.status!==404)throw new Error(`withdrawn actor read returned ${denied.status}, expected 404`);
  counts.grantWithdrawalDenied=denied.status;

  const hostState=await Promise.all(['observer-readback.json','supervisor-readback.json'].map(async name=>
    JSON.parse(await readFile(path.join(fixtureRoot,'host','state',name),'utf8'))));
  if(hostState.some(item=>item.revision!==8||item.digest!==after8.body.desired.digest))
    throw new Error('independent host consumer readbacks do not match fresh revision 8');
  counts.hostReadbacks=hostState.map(item=>({revision:item.revision,digest:item.digest}));
  const fixtureRows=await api('/api/v1/operations/observer-settings/g7-local/host/telemetry?limit=1000&sink_id=g7-local-fixture');
  if(fixtureRows.status!==403) counts.hostTelemetryStatus=fixtureRows.status; // User sessions cannot cross the host boundary.
  counts.status='passed';
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'browser-journey.json'),JSON.stringify(counts,null,2)+'\n',{mode:0o600});
} catch (error) {
  if(error?.backupSeedOnly!==true){
    counts.status='failed';
    counts.failure=String(error?.message??error);
    await (await import('node:fs/promises')).writeFile(path.join(evidence,'browser-journey.json'),JSON.stringify(counts,null,2)+'\n',{mode:0o600});
    throw error;
  }
} finally {
  await browser.close();
}
