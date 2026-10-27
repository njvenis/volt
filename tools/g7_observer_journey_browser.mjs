import { chromium } from '../ui/node_modules/playwright/index.mjs';
import { readFile, mkdir, writeFile, unlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}
const origin = arg('--origin');
const evidence = arg('--evidence');
const fixtureRoot = arg('--fixture-root');
const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
await mkdir(evidence, {recursive:true, mode:0o700});
const browser = await chromium.launch({headless:true});
const context = await browser.newContext({viewport:{width:1440,height:1000},deviceScaleFactor:1});
const page = await context.newPage();
const counts = {bootstrap:0, nativeActivation:0, accessGroup:0, membership:0,
  lostAcknowledgement:0, receiptRecovery:0, revision1:0, revision2:0, rollback3:0,
  crossDeploymentDenied:0, csrfDenied:0, staleRevisionDenied:0, invalidValueDenied:0,
  pending:0, initialUnconfigured:0, failed:0, uncertain:0,
  consumerRestarts:0, controllerRestart:0, containerRestart:0, containerOutage:0,
  schedulerStall:0, healthFaults:[], hostReportAttacks:{},
  reflow:[], axe:[], screenshots:[]};
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
    try { if(docker(['inspect','--format','{{.State.Health.Status}}','volt-g7-observer-journey'])==='healthy')return; } catch {}
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
    const s=await r.json();return s.authenticated===true&&s.credential_mode==='oidc_session';
  },null,{timeout:30000});

  const bootstrap = await api('/api/v1/assessment/bootstrap-policy',{method:'POST',write:true,
    body:JSON.stringify({policy:{grants:[],denies:[],acceptance_material_changes:{},exception_warning_routes:[]}})});
  if (![200,409].includes(bootstrap.status)) throw new Error(`bootstrap policy failed with ${bootstrap.status}`);
  counts.bootstrap = bootstrap.status;

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
  const groupId=crypto.randomUUID();
  const scope={group_ids:['*'],source_families:['*'],environments:['*'],service_ids:['*'],membership_mode:'all_current'};
  const limits={...grant.limits,allowed_environments:grant.limits.allowed_environments?.length?grant.limits.allowed_environments:['*'],
    allowed_service_ids:grant.limits.allowed_service_ids?.length?grant.limits.allowed_service_ids:['*']};
  const duties=grant.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,
    required_approver_count:1,prohibited_action_pairs:[]};
  const actions=['observer.timing.read','observer.timing.configure','audit.read'];
  const permissions=actions.map(action=>({permission_id:crypto.randomUUID(),role_id:crypto.randomUUID(),action,
    target_scope:scope,limits,separation_of_duties:duties,
    ...(action.startsWith('observer.timing.')?{deployment_scopes:['g7-local']}: {})}));
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
  await page.waitForTimeout(5500);

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
  const discovery=await api('/api/v1/operations/observer-settings?limit=100');
  if(discovery.status!==200||discovery.body.deployments?.length!==1
      ||discovery.body.deployments[0]?.deployment_id!=='g7-local'||discovery.body.next_cursor!==null)
    throw new Error('bounded discovery exposed registered deployment B without an actor grant');
  counts.authorizedDiscovery=discovery.body.deployments.length;
  counts.registeredMatchingDenyDiscovery=discovery.body.deployments.some(item=>item.deployment_id==='g7-other')?1:0;
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
  docker(['exec','volt-g7-observer-journey','touch',stallMarker]);
  try {
    await page.waitForTimeout(18000);
    let observerState=JSON.parse(await readFile(observerStatePath,'utf8'));
    if(observerState.scheduler?.status!=='stale_or_nonprogressing')
      throw new Error('real scheduler stall did not fail host scheduler progress health');
    counts.schedulerStall=1;
    counts.healthFaults.push('real_scheduler_stall');
    docker(['exec','-u','0','volt-g7-observer-journey','rm','-f','/run/uvm-g7-scheduler/progress.json']);
    observerState=await waitForJson(observerStatePath,state=>state.scheduler?.status==='stale_or_nonprogressing'
      &&state.scheduler?.loop_sequence===null);
    counts.healthFaults.push('missing_scheduler_progress');
    // Supply a structurally valid future sample while the actual scheduler is
    // held at the completion boundary; the monotonic skew check must reject it.
    const future={...lastProgress,loop_sequence:Number(lastProgress.loop_sequence)+1,
      monotonic_ns:Number(lastProgress.monotonic_ns)+120_000_000_000};
    const futurePath=path.join('/tmp',`volt-g7-progress-future-${crypto.randomUUID()}.json`);
    await writeFile(futurePath,JSON.stringify(future)+'\n',{mode:0o644});
    docker(['cp',futurePath,'volt-g7-observer-journey:/tmp/progress.future.json']);
    docker(['exec','-u','0','volt-g7-observer-journey','cp','/tmp/progress.future.json','/run/uvm-g7-scheduler/progress.json']);
    docker(['exec','-u','0','volt-g7-observer-journey','chmod','0644','/run/uvm-g7-scheduler/progress.json']);
    await unlink(futurePath);
    const futureState=await waitForJson(observerStatePath,state=>state.scheduler?.age_seconds<0);
    if(futureState.scheduler.status!=='stale_or_nonprogressing')throw new Error('future scheduler heartbeat was accepted');
    counts.healthFaults.push('future_scheduler_progress');
  } finally { docker(['exec','volt-g7-observer-journey','rm','-f',stallMarker]); }
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
  await page.getByText(/Desired revision 4 recorded/).waitFor({timeout:15000});
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
  docker(['stop','volt-g7-observer-journey']);
  await waitForJson(observerStatePath,state=>state.loop_sequence>beforeOutageObserver.loop_sequence,15000);
  await waitForJson(supervisorStatePath,state=>state.loop_sequence>beforeOutageSupervisor.loop_sequence,15000);
  const outageReadbacks=await Promise.all(['observer-readback.json','supervisor-readback.json'].map(async name=>
    JSON.parse(await readFile(path.join(hostStateDir,name),'utf8'))));
  if(outageReadbacks.some(item=>item.revision!==6))
    throw new Error('host consumers did not preserve revision 6 through the app outage');
  docker(['start','volt-g7-observer-journey']);
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
  if(!group)throw new Error('disposable access group missing during grant-withdrawal check');
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
  counts.status='failed';
  counts.failure=String(error?.message??error);
  await (await import('node:fs/promises')).writeFile(path.join(evidence,'browser-journey.json'),JSON.stringify(counts,null,2)+'\n',{mode:0o600});
  throw error;
} finally {
  await browser.close();
}
