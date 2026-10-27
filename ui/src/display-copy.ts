import {confirmFindingLabel} from './assessment-copy';
// Presentation only: wire states, permissions and saved commands stay unchanged.
const statusLabels:Record<string,string>={
  actionable:'action available','reconciliation pending':'rebuild check pending',committed:'saved',confirmed:'fix confirmed',continuity_covered:'previous fix still valid',
  remediated:'fixed',partially_remediated:'partly fixed',outstanding:'needs a fix',
  review:'needs review',forbidden:'access denied',denied:'not permitted',
  'pending projection':'update pending',unlinked:'not linked',applied:'update sent',
  uncertain:'delivery not confirmed',conflict:'conflicting changes',
  audience_blocked:'access check needed',needs_resubmission:'prepare again',
  acknowledged:'approved for copying','outcome unknown':'save not confirmed',
  'review pending':'review needed','verified coverage recorded':'verified rebuild covered',
  'coverage blocked':'coverage not allowed'
};
export const displayStatus=(value:string)=>statusLabels[value]??value.replaceAll('_',' ');
const reasonDescriptions:Record<string,string>={
  direct_confirmation:'Confirmed fixed by an authorised person',
  verified_continuity:'Previous fix remains valid for this verified instance',
  outstanding:'No current fix confirmation',review:'More information is needed to confirm the status',
  new_positive_observation:'A later scan found this issue again',
  continuity_not_proven:'The previous fix could not be verified for this instance',
  legacy_adoption_required:'Earlier records need to be checked before fix status can be confirmed',
  newer_positive_after_remediation:'A later scan found the issue after it was marked fixed',
  newer_positive_after_confirmation:'A later scan found the issue after a fix was confirmed',
  observation_time_unknown:'The scan time is missing or cannot be verified',
  observation_time_beyond_future_tolerance:'The scan time is too far in the future to use',
  episode_requires_review:'The current fix status needs review',
  identity_correspondence_changed:'The match between the original and replacement instance has changed',
  revision_conflict:'The finding changed. Refresh and review it before trying again.',
  command_id_reused:'This saved request conflicts with an earlier request. Review the finding before trying again.',
  decision_committed:'The decision was saved in VOLT.',
  authentication_required:'Sign in again to continue.',forbidden:'You do not have permission for this change.',
  invalid_command:'Check the selected instances and required fields.',
  persistence_unavailable:'VOLT could not save this change. Try again.',
  outcome_unknown:'The save could not be confirmed. Check or retry the same request.'
};
export const describeReason=(value:string)=>reasonDescriptions[value]??value.replaceAll('_',' ');
const actionNames:Record<string,string>={
  'policy.sla.publish':'Publish SLA policy','sla.deadline.revise':'Change selected deadlines','reports.read':'View reports','reports.create':'Create reports',
  'assessment.read':'View findings','severity.override':'Change severity',
  'owners.assign':'Assign owners','portion.define':'Create assigned set',
  'portion.transfer':'Change set owners','portion.split':'Split assigned set',
  'routing.override':'Change automatic assignment','routing.expire':'End expired assignment override',
  'acceptance.submit':'Request risk acceptance','acceptance.approve':'Approve risk acceptance',
  'acceptance.reject':'Reject risk acceptance','acceptance.revoke':'End risk acceptance',
  'remediation.confirm_group':confirmFindingLabel,'remediation.confirm_portion':'Confirm fixes for this set',
  'policy.role.create':'Create role','policy.role.assign':'Assign role','policy.role.update':'Update role',
  'principal.update':'Update account access','github.commands.preview':'Prepare commands for GitHub',
  'github.issue.sync':'Update GitHub issues'
};
export const displayAction=(value:string)=>actionNames[value]??value;
