import type {ConnectorView,Settings} from './connector-types';
import {purposeLabel} from './ConnectorEditor';
import {State,Time,words} from './ConnectorSettings';
// Every value is from saved readback. Unsaved editor and installation selections
// must never become the scope described by the activation action.
export default function ConnectorActivationSummary({view,candidate=view.settings,revision=view.configuration_revision,reviewed,onReview,disabled=false,label='Activation summary'}:{view:ConnectorView;candidate?:Settings;revision?:number;reviewed:boolean;onReview:(checked:boolean)=>void;disabled?:boolean;label?:string}){
 const gh=candidate.github;
 return <section className="connector-activation-summary" aria-label={label}>
  <h4>{label} · saved configuration {revision}</h4>
  <p>Activation applies to this saved snapshot. Unsaved form edits and repository selections are excluded. The server rechecks current access, validation and recovery before committing.</p>
  <dl className="connector-facts">
   <div><dt>Environment and source</dt><dd>{candidate.environment_label}<br/>{view.source.source_family} / {view.source.source_account_id} / {view.source.scope_key}<br/><code>{view.source.source_id}</code></dd></div>
   <div><dt>Credential mode and source</dt><dd>{candidate.authentication_mode==='github_app_v1'?'GitHub App':'Legacy token file'}<br/>{candidate.secret_source?words(candidate.secret_source.kind)+' · '+candidate.secret_source.secret_source_id:'No settings-managed secret source'}<br/>Source revision {view.revisions.source}; secret-source revision {view.revisions.secret_source}</dd></div>
   <div><dt>Saved App and installation</dt><dd>{gh.app?gh.app.slug+' · App '+gh.app.app_id:'No App selected'}<br/>{gh.installation?<>Installation {gh.installation.installation_id} · Account {gh.installation.account_id}<br/>Flow <code>{gh.installation.flow_id}</code></>:'No installation selected'}</dd></div>
   <div><dt>Validation binding</dt><dd><State value={view.validation.status}/><br/>Configuration {view.validation.configuration_revision??'not validated'} · Intent <code>{view.validation.intent_id??'none'}</code><br/><Time value={view.validation.checked_at}/></dd></div>
   <div><dt>Recovery fence</dt><dd><State value={view.recovery.state}/><br/>Epoch {view.recovery.recovery_epoch_id??'none'}<br/>Independent operator clearance: {view.recovery.operator_clearance_present?'recorded':'not recorded'}<br/>Fresh credentials required: {view.recovery.requires_fresh_credentials?'yes':'no'}</dd></div>
   <div><dt>Command preconditions</dt><dd>Connector revision {view.revisions.connector} · Policy {view.revisions.policy} · Authority {view.revisions.authority}<br/>Saved configuration {revision}</dd></div>
  </dl>
  <h5>Exact saved repository subset and disclosure approvals</h5>
  {gh.repository_ids.length?<ul>{gh.repository_ids.map(id=><li key={id}>Repository <code>{id}</code> · Audience revision {gh.audience_revisions[id]??'not approved in this snapshot'}</li>)}</ul>:<p>No repositories selected. No repository audience is inferred.</p>}
  <h5>Selected credential versions</h5>
  <dl className="connector-facts">{Object.entries(candidate.credentials).map(([purpose,ref])=>{const secret=ref?view.secrets.find(s=>s.secret_id===ref.secret_id):undefined;const version=secret?.versions.find(v=>v.version_id===ref?.version_id);return <div key={purpose}><dt>{purposeLabel[purpose as keyof typeof purposeLabel]}</dt><dd>{ref?<><code>{ref.secret_id}</code><br/>Version <code>{ref.version_id}</code><br/>Selected secret revision {ref.secret_revision}; current {secret?.revision??'unavailable'}<br/>{version?<><State value={version.state}/>{version.quarantine!=='clear'&&<State value={version.quarantine}/>}</>:'Version unavailable — server validation required'}</>:'Not selected'}</dd></div>;})}</dl>
  <label className="connector-repo"><input type="checkbox" checked={reviewed} disabled={disabled} onChange={e=>onReview(e.target.checked)}/><span>I reviewed this saved configuration, its repository audience and recovery state.</span></label>
 </section>;
}
