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
const oidcProxyPort = warningOnly || exceptionSlaOnly ? arg('--oidc-proxy-port') : null;
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
  const groupId=warningOnly?'00000000-0000-4000-8000-000000000024':crypto.randomUUID();
  const scope={group_ids:['*'],source_families:['*'],environments:['*'],service_ids:['*'],membership_mode:'all_current'};
  const limits={...grant.limits,allowed_environments:grant.limits.allowed_environments?.length?grant.limits.allowed_environments:['*'],
    allowed_service_ids:grant.limits.allowed_service_ids?.length?grant.limits.allowed_service_ids:['*']};
  const duties=grant.separation_of_duties??{approval_requires_distinct_actor:true,prohibit_requester_approval:true,
    required_approver_count:1,prohibited_action_pairs:[]};
  const actions=['observer.timing.read','observer.timing.configure',
    'backup.settings.read','backup.settings.configure','assessment.read','audit.read',
    ...(warningOnly?['acceptance.submit','acceptance.approve','warning.route.manage','warning.actor_link.manage']:[]),
    ...(exceptionSlaOnly?['acceptance.submit','acceptance.approve','portion.define','portion.transfer','report.create','report.read']:[])];
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
  await page.waitForTimeout(5500);

  if (exceptionSlaOnly) {
    const seeded=JSON.parse(await readFile(path.join(evidence,'sla-fixture-ids.json'),'utf8'));
    const findingId=seeded.group, members=seeded.members;
    const memberByKey=Object.fromEntries(members.map(member=>[member.key,member]));
    const occurrenceIds=members.map(member=>member.occurrence);
    const ingestAt=Date.parse(seeded.ingested_at);
    if (!Number.isFinite(ingestAt) || Date.parse(seeded.observed_at)>=ingestAt
        || Date.parse(seeded.collected_at)>=ingestAt)
      throw new Error('authoritative fixture did not separate the older observation/collection times from UVM retention');
    const pauseAt=new Date(ingestAt+18*60*60*1000);
    const expiry=new Date(pauseAt.getTime()+60*1000);
    const clockPath=path.join(fixtureRoot,'scheduler','warning-clock.txt');
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
    for(const member of members) {
      const atom=g7AtomByOccurrence[member.occurrence];
      const anchorMatches=Date.parse(atom?.clock?.start)===ingestAt
        &&(member.deadline_at
          ? Date.parse(atom?.clock?.original_deadline_at)===Date.parse(member.deadline_at)
          : atom?.clock?.original_deadline_at==null);
      if(!atom||!anchorMatches)
        throw new Error(`public G7 report lost authoritative membership anchor/deadline: ${JSON.stringify({member,atom})}`);
    }
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
    const episodes=current.body.episodes??[];
    const expectedExposureMap=new Map();
    for(const member of members){
      const episode=episodes.find(item=>item.exposure_id===member.exposure);
      if(!episode)throw new Error(`public finding omitted the writer-created episode ${member.episode}`);
      if(episode.episode_id!==member.episode)throw new Error(`writer-created episode changed for ${member.occurrence}`);
      expectedExposureMap.set(episode.exposure_id,{exposure_id:episode.exposure_id,
        episode_id:episode.episode_id,state_revision:episode.state_revision});
    }
    const expectedExposures=[...expectedExposureMap.values()];
    const transferredMember=memberByKey.covered_six_hours;
    const portionId=crypto.randomUUID();
    const authorityBeforeTransfer=(await api('/api/v1/assessment/administration/catalogue')).body.authority_revision;
    const definePortion=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'portion.define',
      membership_ids:[transferredMember.occurrence],expected_revisions:{
        target:current.body.assessment.revision,policy:current.body.assessment.policy_revision,
        authority:authorityBeforeTransfer,identity_membership:current.body.assessment.membership.revision,
        owners:current.body.assessment.owner_revision},payload:{portion_id:portionId,
        owner_ids:['synthetic-owner-before-transfer'],membership_ids:[transferredMember.occurrence],
        rationale:'Define exact synthetic membership ownership before transfer'}})});
    if(definePortion.status!==200)throw new Error(`public portion definition failed ${definePortion.status}: ${JSON.stringify(definePortion.body)}`);
    const beforeTransfer=await api(`/api/v1/assessment/groups/${findingId}`);
    const transferCatalogue=(await api('/api/v1/assessment/administration/catalogue')).body;
    const transfer=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'portion.transfer',
      membership_ids:[transferredMember.occurrence],expected_revisions:{
        target:beforeTransfer.body.assessment.revision,policy:beforeTransfer.body.assessment.policy_revision,
        authority:transferCatalogue.authority_revision,
        identity_membership:beforeTransfer.body.assessment.membership.revision,
        owners:beforeTransfer.body.assessment.owner_revision},payload:{portion_id:portionId,
        owner_ids:['synthetic-owner-after-transfer'],membership_ids:[transferredMember.occurrence],
        rationale:'Transfer the exact synthetic membership to a new owner'}})});
    if(transfer.status!==200)throw new Error(`public owner transfer failed ${transfer.status}: ${JSON.stringify(transfer.body)}`);
    current=await api(`/api/v1/assessment/groups/${findingId}`);
    const transferredPortion=current.body.assessment.portions.find(item=>item.portion_id===portionId);
    if(current.status!==200||!transferredPortion
        ||JSON.stringify(transferredPortion.owner_ids)!==JSON.stringify(['synthetic-owner-after-transfer'])
        ||transferredPortion.membership_ids.length!==1
        ||transferredPortion.membership_ids[0]!==transferredMember.occurrence)
      throw new Error(`public owner transfer readback did not preserve exact membership: ${JSON.stringify(transferredPortion)}`);
    const reportAfterOwnerTransfer=await api(`/api/v1/reports/${g7Report.body.report_id}`);
    if(reportAfterOwnerTransfer.status!==200
        ||JSON.stringify(reportAfterOwnerTransfer.body)!==JSON.stringify(reportRead.body))
      throw new Error('owner transfer mutated the already-issued G7 continuity report');
    const g5ReportAfterTransfer=await api(`/api/v1/reports/${g5Report.body.report_id}`);
    const g5AtomsAfterTransfer=await api(`/api/v1/reports/${g5Report.body.report_id}/atoms`);
    if(g5ReportAfterTransfer.status!==200||g5AtomsAfterTransfer.status!==200
        ||JSON.stringify(g5ReportAfterTransfer.body)!==JSON.stringify(g5ReportRead.body)
        ||JSON.stringify(g5AtomsAfterTransfer.body)!==JSON.stringify(g5Atoms.body))
      throw new Error('owner transfer or G7 activation mutated the already-issued G5 report');
    await writeFile(path.join(evidence,'sla-owner-transfer-public-readback.json'),JSON.stringify({
      define:definePortion.body,transfer:transfer.body,portion:transferredPortion,
      membership_anchor_before:seeded.members.find(item=>item.occurrence===transferredMember.occurrence),
      membership_anchor_after:seeded.continuity.reimport_refresh,
      expected_deadline_at:transferredMember.deadline_at,
      issued_g7_report_id:g7Report.body.report_id,
      report_unchanged_after_transfer:true,
      issued_g5_report_id:g5Report.body.report_id,
      g5_report_unchanged_after_transfer:true},null,2),{mode:0o600});
    await writeFile(path.join(evidence,'sla-before-exception-readback.json'),JSON.stringify(current.body,null,2),{mode:0o600});
    const expectedEvaluations=members.map(member=>({episode_id:member.episode,occurrence_id:member.occurrence,
      evaluation_id:member.evaluation,revision:member.revision}));
    const submit=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.submit',membership_ids:occurrenceIds,
      expected_revisions:{target:current.body.assessment.revision,policy:current.body.assessment.policy_revision,
        authority:(await api('/api/v1/assessment/administration/catalogue')).body.authority_revision,
        identity_membership:current.body.assessment.membership.revision,owners:current.body.assessment.owner_revision},
      expected_exposures:expectedExposures,expected_evaluations:expectedEvaluations,
      payload:{accountable_owner_id:'synthetic-owner',rationale:'Exercise ingestion-anchored G7 pause and resume',
        expires_at:expiry.toISOString(),continuity_allowed:false,exception_contract_version:1,
        context:{environment:'local',evidence:'synthetic-local'},
        compensating_controls:'Synthetic disposable journey controls.'}})});
    if(submit.status!==200)throw new Error(`G7 SLA public submit failed ${submit.status}: ${JSON.stringify(submit.body)}`);
    let afterSubmit=await api(`/api/v1/assessment/groups/${findingId}`);
    const acceptanceId=afterSubmit.body.assessment.acceptances.find(item=>item.state==='pending')?.acceptance_id;
    if(!acceptanceId)throw new Error(`public submit did not return the pending request: ${JSON.stringify(afterSubmit.body.assessment.acceptances)}`);
    const catalogueAfter=await api('/api/v1/assessment/administration/catalogue');
    const approvalBody={command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.approve',
      membership_ids:occurrenceIds,expected_revisions:{target:afterSubmit.body.assessment.revision,
        policy:afterSubmit.body.assessment.policy_revision,authority:catalogueAfter.body.authority_revision,
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
    const approve=await api('/api/v1/assessment/commands',{method:'POST',write:true,body:JSON.stringify({
      command_id:crypto.randomUUID(),target_id:findingId,action:'acceptance.approve',membership_ids:occurrenceIds,
      expected_revisions:{target:afterSubmit.body.assessment.revision,policy:afterSubmit.body.assessment.policy_revision,
        authority:catalogueAfter.body.authority_revision,identity_membership:afterSubmit.body.assessment.membership.revision,
        owners:afterSubmit.body.assessment.owner_revision},expected_exposures:expectedExposures,
      expected_evaluations:expectedEvaluations,payload:{acceptance_id:acceptanceId,
        rationale:'Approve the synthetic ingestion-anchored exception',selected_expires_at:expiry.toISOString(),
        expected_request_revision:1}})});
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
    await page.waitForTimeout(1500);
    await page.getByRole('button',{name:'Exceptions',exact:true}).waitFor({state:'visible',timeout:20000});
    await page.getByRole('button',{name:'Exceptions',exact:true}).click();
    await page.getByText('Recorded SLA state',{exact:true}).waitFor({state:'visible',timeout:10000});
    const pausedRendered=await page.locator('body').innerText();
    await writeFile(path.join(evidence,'sla-paused-ui-debug.json'),JSON.stringify({
      body:pausedRendered,clocks:pausedAcceptance.sla_clock,
      visible_exception_expiry:pausedRendered.includes('Exception expires'),
      visible_frozen_remainder:pausedRendered.includes('Currently frozen SLA duration'),
      visible_gap:pausedRendered.includes('SLA coverage unknown'),
      visible_prior_breach:pausedRendered.includes('Earlier breach retained')},null,2),{mode:0o600});
    if(!pausedRendered.includes('Exception expires')||!pausedRendered.includes('Currently frozen SLA duration')
        ||!pausedRendered.includes('SLA coverage unknown')
        ||!pausedRendered.toLowerCase().includes('earlier breach retained'))
      throw new Error('rendered Exceptions register omitted paused, gap, or prior breach values');
    await page.screenshot({path:path.join(evidence,'sla-paused-browser.png'),fullPage:true});
    await writeFile(path.join(evidence,'sla-paused-browser.json'),JSON.stringify({
      title:await page.title(),findingId,acceptanceId,rendered_paused_sla:true,
      visible_exception_expiry:pausedRendered.includes('Exception expires'),
      visible_frozen_remainder:pausedRendered.includes('Currently frozen SLA duration')},null,2),{mode:0o600});
    await writeFile(path.join(evidence,'sla-paused-clock.json'),expiry.toISOString()+'\n',{mode:0o666});
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
    await page.goto(origin+'/#findings?group='+encodeURIComponent(findingId),{waitUntil:'domcontentloaded'});
    await page.waitForTimeout(2000);
    await page.getByRole('button',{name:'Exceptions',exact:true}).waitFor({state:'visible',timeout:20000});
    await page.getByRole('button',{name:'Exceptions',exact:true}).click();
    await page.getByText('Recorded SLA state',{exact:true}).waitFor({state:'visible',timeout:10000});
    const rendered=await page.locator('body').innerText();
    if(!rendered.includes('Current SLA target')||!rendered.includes('Remaining SLA duration at refresh'))
      throw new Error('rendered Exceptions register omitted server-computed resumed SLA values');
    await page.screenshot({path:path.join(evidence,'sla-resumed-browser.png'),fullPage:true});
    await writeFile(path.join(evidence,'sla-resumed-browser.json'),JSON.stringify({
      title:await page.title(),findingId,acceptanceId,rendered_server_computed_sla:true,
      visible_target:rendered.includes('Current SLA target'),
      visible_remaining:rendered.includes('Remaining SLA duration at refresh')},null,2),{mode:0o600});
    process.stdout.write(JSON.stringify({exceptionSlaWorkflow:'paused_then_resumed',findingId,
      memberKeys:members.map(member=>member.key),acceptanceId})+'\n');
    process.exit(0);
  }

  if (warningOnly) {
    const seeded=JSON.parse(await readFile(path.join(evidence,'warning-fixture-ids.json'),'utf8'));
    const findingId=seeded.group, occurrenceId=seeded.occurrence;
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
      payload:{accountable_owner_id:'synthetic-owner',rationale:'Exercise G7 warning expiry workflow',
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
    const futureState=await waitForJson(observerStatePath,state=>state.scheduler?.sample_age_seconds<0);
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
  if(error?.backupSeedOnly!==true){
    counts.status='failed';
    counts.failure=String(error?.message??error);
    await (await import('node:fs/promises')).writeFile(path.join(evidence,'browser-journey.json'),JSON.stringify(counts,null,2)+'\n',{mode:0o600});
    throw error;
  }
} finally {
  await browser.close();
}
