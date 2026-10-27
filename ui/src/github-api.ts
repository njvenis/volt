import {sessionFetch, errorCode} from './session';
import { AssessmentError, type Command, type GroupView } from './assessment-api';
import type { ExposureGuard } from './github-model';
export type GitHubCommand=Omit<Command,'action'>&{action:'confirm_remediation'|'set_owners';scope:'portion'|'whole_group'};
export type SignedPreview={schema_version:1;preview_id:string;principal_id:string;link_id:string;link_revision:number;github_account_id:string;repository_id:string;issue_node_id:string;issue_number:number;group_id:string;command_digest:string;expected_revisions:Command['expected_revisions'];expected_exposures:ExposureGuard[];expires_at:string;signature:string;command:GitHubCommand;permission_hints:Record<string,boolean>;errors:unknown[]};
export type Acknowledgement={schema_version:1;command_ref:string;expires_at:string;canonical_command_digest:string;state:'acknowledged'};
const messages:Record<string,string>={github_actor_unlinked:'Your GitHub account must be linked and verified. Ask an administrator to check your account link.',github_audience_unknown:'Updates are blocked because repository access has not been verified. Ask an administrator to check who can see it.',preview_expired:'This command has expired. Refresh the finding and prepare a new command.',preview_signature_invalid:'VOLT could not verify this command. Refresh and prepare it again.',command_needs_resubmission:'Prepare this command again: refresh the finding, review the affected instances and approve the new command for copying.',github_unavailable:'GitHub is unavailable. Preparing this command has not saved your change.',preview_outcome_unknown:'VOLT could not confirm that this command is ready to copy. Your change has not been saved through this flow. Refresh and prepare a new command.',preview_invalid:'The command details could not be verified, so it cannot be copied. Refresh and prepare it again.'};
export class GitHubError extends AssessmentError{constructor(status:number,code:string){super(status,code);this.message=messages[code]??this.message;}}
async function request(path:string,token:string,body:unknown):Promise<unknown>{
  let response:Response;
  try{response=await sessionFetch('/api/v1/github/commands/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),cache:'no-store',signal:AbortSignal.timeout(15000)});}catch{throw new GitHubError(0,'preview_outcome_unknown');}
  let data:unknown;try{data=await response.json();}catch{throw new GitHubError(response.status,'preview_outcome_unknown');}
  if(!response.ok){const code=errorCode(data);throw new GitHubError(response.status,code);}
  return data;
}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const uuid=(v:unknown)=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const digest=(v:unknown)=>typeof v==='string'&&/^[0-9a-f]{64}$/i.test(v);
function canonical(v:unknown):string{if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';if(object(v))return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';return JSON.stringify(v);}
export function githubCommand(command:Command):GitHubCommand{
  const mapping:Record<string,[GitHubCommand['action'],GitHubCommand['scope']]>={'remediation.confirm_portion':['confirm_remediation','portion'],'remediation.confirm_group':['confirm_remediation','whole_group'],'portion.transfer':['set_owners','portion'],'owners.assign':['set_owners','whole_group']};
  const mapped=mapping[command.action];if(!mapped)throw new GitHubError(422,'invalid_command');
  return {...command,action:mapped[0],scope:mapped[1]};
}
export async function getSignedPreview(command:Command,view:GroupView,token:string):Promise<SignedPreview>{
  const proposal=githubCommand(command),data=await request('preview',token,{command:proposal,issue_number:view.github.issue_number,repository_id:view.github.repository_id});
  if(!object(data)||data.schema_version!==1||!uuid(data.preview_id)||!uuid(data.link_id)||!digest(data.signature)||!digest(data.command_digest)||data.principal_id!==view.github_identity.principal_id||data.github_account_id!==view.github_identity.account_id||data.link_revision!==view.github_identity.link_revision||data.repository_id!==view.github.repository_id||data.issue_number!==view.github.issue_number||typeof data.issue_node_id!=='string'||!data.issue_node_id||data.group_id!==view.group.group_id||canonical(data.command)!==canonical(proposal)||canonical(data.expected_revisions)!==canonical(proposal.expected_revisions)||canonical(data.expected_exposures)!==canonical(proposal.expected_exposures??[])||typeof data.expires_at!=='string'||!/(Z|[+-]\d{2}:\d{2})$/.test(data.expires_at)||!Number.isFinite(Date.parse(data.expires_at))||!object(data.permission_hints)||!['owners.assign','portion.transfer','remediation.confirm_group','remediation.confirm_portion'].every(a=>typeof (data.permission_hints as Record<string,unknown>)[a]==='boolean')||!Array.isArray(data.errors)||data.errors.length)throw new GitHubError(502,'preview_invalid');
  return data as SignedPreview;
}
export async function acknowledgePreview(preview:SignedPreview,token:string):Promise<Acknowledgement>{
  const data=await request('acknowledge',token,{preview_id:preview.preview_id,signature:preview.signature});
  if(!object(data)||data.schema_version!==1||data.command_ref!==preview.preview_id||data.expires_at!==preview.expires_at||data.canonical_command_digest!==preview.command_digest||data.state!=='acknowledged')throw new GitHubError(502,'preview_invalid');
  return data as Acknowledgement;
}
export function commandComment(preview:SignedPreview):string{return '/uvm v1\n```json\n'+JSON.stringify({preview_id:preview.preview_id,signature:preview.signature,command:preview.command},null,2)+'\n```';}
