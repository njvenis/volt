// Synthetic data only. Historical fixture bytes remain unchanged.
import {readFileSync} from 'node:fs';
const base=JSON.parse(readFileSync(new URL('./fixtures/g4/partial-group-dto.json',import.meta.url)));
export function fixture(authority=7){
 const view=structuredClone(base);
 view.assessment.authority_revision=authority;
 const ids=view.assessment.membership.outstanding_ids;
 const acceptance={exception_contract_version:1,request_revision:1,requester_id:'synthetic-requester',submitted_at:'2026-10-30T12:00:00Z',proposed_expires_at:'2026-11-01T12:00:00Z',compensating_controls:'Synthetic restricted access',context:{group_id:view.group.group_id,membership_ids:ids,submitted_context:{}},sla_clock:[],acceptance_id:'11111111-1111-4111-8111-111111111111',state:'pending',membership_ids:ids,accountable_owner_id:view.assessment.owners[0].owner_id,rationale:'Synthetic request',expires_at:'2026-11-01T12:00:00Z',continuity_allowed:false,predecessor_id:null,history:[],successor_coverage:[],effective_membership_ids:[],reconciliation_history:[],coverage_invalidations:[]};
 view.assessment.acceptances=[acceptance];
 const catalogue={schema_version:1,group_id:view.group.group_id,policy_revision:view.assessment.policy_revision,sla_policy_head:1,authorisation:{principal_id:'synthetic-approver',effective_actions:['acceptance.submit','acceptance.approve'],grants:[],denies:[],delegation_envelope:{}},policies:[],current_heads:{episodes:view.episodes.map(({exposure_id,episode_id,state_revision,state})=>({exposure_id,episode_id,state_revision,state})),evaluations:ids.map((occurrence_id,i)=>({episode_id:view.episodes.find(e=>e.members.some(m=>m.membership_id===occurrence_id)).episode_id,occurrence_id,evaluation_id:`22222222-2222-4222-8222-${String(i+1).padStart(12,'0')}`,revision:1,policy_id:null,deadline_at:null,head_decision_id:null}))}};
 return {view,ids,acceptance,catalogue};
}
