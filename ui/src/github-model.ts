export type ExposureGuard={exposure_id:string;episode_id:string;state_revision:number};
export type EpisodeMember={membership_id:string;status:'outstanding'|'confirmed'|'continuity_covered'|'review';original_confirmation_decision_id:string|null;original_confirmation_at:string|null;coverage_reason:'direct_confirmation'|'verified_continuity'|'outstanding'|'review'|'new_positive_observation'|'continuity_not_proven'|'legacy_adoption_required';confirmed_by_decision_id:string|null;confirmed_at:string|null};
export type Episode=ExposureGuard&{episode_number?:number;state:'open'|'partially_remediated'|'remediated'|'review';members:EpisodeMember[];recurrence:{count:number;last_event_at:string|null;reason_codes:string[]};review_reasons:string[]};
export const syncStates=['unlinked','pending','applied','failed','uncertain','conflict','audience_blocked','needs_resubmission'] as const;
export type GitHubSync={state:typeof syncStates[number];repository_id:string|null;issue_number:number|null;issue_url:string|null;desired_revision:number;applied_revision:number;last_reconciled_at:string|null;discrepancy_codes:string[]};
export type GitHubIdentity={link_state:'unlinked'|'linked'|'revoked'|'disabled'|'review';repository_id:string|null;account_id:string|null;principal_id:string|null;link_revision:number};
export type G4View={episodes:Episode[];github:GitHubSync;github_identity:GitHubIdentity};
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const integer=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
const text=(v:unknown):v is string=>typeof v==='string';
const uuid=(v:unknown)=>text(v)&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const nullable=(v:unknown,check:(v:unknown)=>boolean)=>v===null||check(v);
const texts=(v:unknown)=>Array.isArray(v)&&v.every(text);
const instant=(v:unknown)=>text(v)&&/(Z|[+-]\d{2}:\d{2})$/.test(v)&&Number.isFinite(Date.parse(v));
// Reasons describe the server's status; they never confer confirmation coverage.
function validCoverageReason(member:Record<string,unknown>):boolean{
  if(['new_positive_observation','continuity_not_proven'].includes(String(member.coverage_reason)))return member.status==='outstanding';
  if(member.coverage_reason==='legacy_adoption_required')return member.status==='review';
  return ['direct_confirmation','verified_continuity','outstanding','review'].includes(String(member.coverage_reason));
}
const numericId=(v:unknown)=>text(v)&&/^\d+$/.test(v);
export function validG4View(v:Record<string,unknown>):boolean{
  const g=v.github,i=v.github_identity;
  if(!Array.isArray(v.episodes)||!v.episodes.every(e=>object(e)&&uuid(e.exposure_id)&&uuid(e.episode_id)&&integer(e.state_revision)&&e.state_revision>0&&(!('episode_number' in e)||integer(e.episode_number)&&e.episode_number>0)&&['open','partially_remediated','remediated','review'].includes(String(e.state))&&Array.isArray(e.members)&&e.members.every(m=>object(m)&&uuid(m.membership_id)&&['outstanding','confirmed','continuity_covered','review'].includes(String(m.status))&&validCoverageReason(m)&&nullable(m.original_confirmation_decision_id,uuid)&&nullable(m.confirmed_by_decision_id,uuid)&&nullable(m.original_confirmation_at,instant)&&nullable(m.confirmed_at,instant))&&object(e.recurrence)&&integer(e.recurrence.count)&&nullable(e.recurrence.last_event_at,instant)&&texts(e.recurrence.reason_codes)&&texts(e.review_reasons)))return false;
  const episodes=v.episodes as Episode[];
  if(new Set(episodes.map(e=>e.exposure_id)).size!==episodes.length)return false;
  const members=episodes.flatMap(e=>e.members.map(m=>m.membership_id));
  if(new Set(members).size!==members.length)return false;
  return object(g)&&syncStates.includes(g.state as GitHubSync['state'])&&nullable(g.repository_id,numericId)&&nullable(g.issue_number,x=>integer(x)&&x>0)&&nullable(g.issue_url,text)&&integer(g.desired_revision)&&integer(g.applied_revision)&&g.applied_revision<=g.desired_revision&&nullable(g.last_reconciled_at,instant)&&texts(g.discrepancy_codes)&&object(i)&&['unlinked','linked','revoked','disabled','review'].includes(String(i.link_state))&&nullable(i.repository_id,numericId)&&nullable(i.account_id,numericId)&&nullable(i.principal_id,text)&&integer(i.link_revision);
}
