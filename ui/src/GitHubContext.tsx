import { describeReason } from './display-copy';
import type { GroupView } from './assessment-api';
import type { GitHubSync } from './github-model';
import { EvidenceLink, Status, UTC, Empty } from './assessment-components';
const syncText:Record<GitHubSync['state'],string>={
  unlinked:'This finding does not have a linked GitHub issue.',
  pending:'An update is waiting to be sent to GitHub. The issue may not yet show the latest changes.',
  applied:'GitHub has received the update shown below. Decisions saved in VOLT are tracked separately.',
  failed:'The GitHub update failed. Your saved VOLT decisions are still recorded. Ask an administrator to review the failure.',
  uncertain:'VOLT cannot yet confirm whether GitHub received the update. It will check before sending more changes. Do not send a duplicate.',
  conflict:'VOLT found conflicting information in GitHub. An administrator needs to review it before updates can continue.',
  audience_blocked:'Updates are blocked because access to this repository has not been verified. Ask an administrator to check who can see it.',
  needs_resubmission:'This command needs to be prepared again. Refresh the finding, review the current instances and approve a new command before copying it to GitHub.'
};
export function GitHubContext({view,onRefresh,loading}:{view:GroupView;onRefresh:()=>void;loading:boolean}){
  const g=view.github,i=view.github_identity;
  return <section className="panel github-context" aria-label="GitHub update status"><div className="panel-head"><h2>GitHub update status</h2><button disabled={loading} onClick={onRefresh}>Refresh GitHub status</button></div><div className="panel-content">
    <div role="status"><Status value={g.state}/><p className="permission-note">{syncText[g.state]}</p></div>
    {g.issue_url?<p><EvidenceLink value={g.issue_url}/></p>:<p>No GitHub issue is linked.</p>}
    <dl className="facts"><div><dt>Latest / sent update version</dt><dd>{g.desired_revision} / {g.applied_revision}</dd></div><div><dt>Last recorded GitHub check</dt><dd><UTC value={g.last_reconciled_at} seconds/></dd></div><div><dt>Repository / issue</dt><dd>{g.repository_id??'Unlinked'} / {g.issue_number??'Unlinked'}</dd></div><div><dt>Your linked GitHub account</dt><dd><Status value={i.link_state}/><small>{i.account_id??'No linked account'} · account link version {i.link_revision}</small></dd></div></dl>
    {!!g.discrepancy_codes.length&&<div><h3>Details needing review</h3><ul>{g.discrepancy_codes.map((code,index)=><li key={index} className="break">{describeReason(code)}</li>)}</ul></div>}
    <p className="permission-note">Saving a decision and updating GitHub are separate steps. Refresh checks the status without sending another update.</p>
  </div></section>;
}
export function EpisodeCoverage({view}:{view:GroupView}){
  return <section className="panel" aria-label="Fix history"><div className="panel-head"><h2>Fixes & repeat detections</h2></div><div className="panel-content"><p className="permission-note">Check which instances still need a fix. Earlier confirmations stay in the history, even when a later scan finds the issue again.</p></div>
    {view.episodes.length?view.episodes.map(e=><article className="portion-card" key={e.exposure_id} data-exposure-id={e.exposure_id}>
      <div className="card-heading"><div><h3>Affected software {e.episode_number?'· fix cycle '+e.episode_number:''}</h3><code>{e.exposure_id}</code></div><Status value={e.state}/></div>
      <dl className="facts"><div><dt>Current fix record</dt><dd><code className="break">{e.episode_id}</code></dd></div><div><dt>Status version</dt><dd>{e.state_revision}</dd></div><div><dt>Times reopened after a fix</dt><dd>{e.recurrence.count}</dd></div><div><dt>Last reopened</dt><dd>{e.recurrence.last_event_at?<UTC value={e.recurrence.last_event_at} seconds/>:'None recorded'}</dd></div></dl>
      {!!e.review_reasons.length&&<div className="notice warning"><span aria-hidden="true">△</span><div><strong>Fix status needs review</strong><ul>{e.review_reasons.map((r,index)=><li key={index}>{describeReason(r)}</li>)}</ul></div></div>}
      {!!e.recurrence.reason_codes.length&&<p>Why it was found again: {e.recurrence.reason_codes.map(r=>describeReason(r)).join(', ')}</p>}
      <details><summary>Instances & fix history ({e.members.length})</summary><ul className="membership-list">{e.members.map(m=><li key={m.membership_id}><code>{m.membership_id}</code><div className="row wrap"><Status value={m.status}/><span>{describeReason(m.coverage_reason)}</span></div>{m.original_confirmation_decision_id&&<dl className="facts"><div><dt>Original confirmation ID</dt><dd><code className="break">{m.original_confirmation_decision_id}</code></dd></div><div><dt>First confirmed fixed</dt><dd><UTC value={m.original_confirmation_at} seconds/></dd></div><div><dt>Current confirmation ID</dt><dd><code className="break">{m.confirmed_by_decision_id??'Not recorded'}</code></dd></div><div><dt>Confirmed fixed at</dt><dd><UTC value={m.confirmed_at} seconds/></dd></div></dl>}</li>)}</ul></details>
    </article>):<Empty title="No fix history available">Without fix records, VOLT cannot show this finding as fixed or detected again.</Empty>}
  </section>;
}
