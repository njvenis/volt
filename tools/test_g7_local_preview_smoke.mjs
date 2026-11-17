import test from 'node:test';
import assert from 'node:assert/strict';
import {requireAdminRendered,requireAudit,requirePersistedState,requireReceipt,requireSession} from './g7_local_preview_smoke_checks.mjs';

const expected={issuer:'http://127.0.0.1:8190',subject:'volt-local-preview-admin-subject',principal:'volt-local-preview-admin'};
const uuid='28c3f3a6-81da-42cd-90bb-862e2402ff9a';
const receipt={schema_version:1,command_id:uuid,decision_id:'24f905ed-5d6f-4c94-bff6-66d57a7ceea6',audit_event_id:'3e6f47b8-fc30-4f18-bf9f-5b2f3e8bd091',action:'access_group.create',target_id:'00000000-0000-4000-8000-000000000000',committed_revision:2,policy_revision:2,result:{authority_mode:'uvm_native_v1',policy_revision:2,object_kind:'access_group',object_id:'d15c52f5-102d-4177-88a1-8def49834148',object_revision:1}};
const membershipReceipt={schema_version:1,command_id:'47d90870-9818-4f8d-a95d-c0c8f1ea7b30',decision_id:'9cdf20b3-e3c0-43b7-897c-696fd60fabc8',audit_event_id:'be8f283d-41ae-4074-9f07-971adb8990d3',action:'access_group.membership.set',target_id:receipt.target_id,committed_revision:3,policy_revision:3,result:{authority_mode:'uvm_native_v1',policy_revision:3,object_kind:'access_group',object_id:receipt.result.object_id,object_revision:2}};

test('session binds exact issuer, subject, principal and OIDC mode',()=>{
  const session={authenticated:true,credential_mode:'oidc_session',principal_id:expected.principal,authority:{issuer:expected.issuer,subject:expected.subject}};
  requireSession(session,expected);
  assert.throws(()=>requireSession({...session,authority:{...session.authority,subject:'wrong'}},expected),/synthetic_browser_login_identity_mismatch/);
  assert.throws(()=>requireSession({...session,authority:{...session.authority,issuer:'wrong'}},expected),/synthetic_browser_login_identity_mismatch/);
});

test('loaded admin view must show enabled current create control',()=>{
  requireAdminRendered({loading:false,error:null,headingVisible:true,createButtonVisible:true,createButtonEnabled:true});
  assert.throws(()=>requireAdminRendered({loading:true,headingVisible:true,createButtonVisible:true,createButtonEnabled:true}),/administration_view_not_ready/);
  assert.throws(()=>requireAdminRendered({loading:false,error:'forbidden',headingVisible:true,createButtonVisible:true,createButtonEnabled:true}),/administration_view_error/);
  assert.throws(()=>requireAdminRendered({loading:false,headingVisible:true,createButtonVisible:true,createButtonEnabled:false}),/administration_view_not_ready/);
});

test('receipt binds request, action, target, object and audit revision',()=>{
  requireReceipt(receipt,{commandId:uuid,targetId:receipt.target_id,groupId:receipt.result.object_id});
  assert.throws(()=>requireReceipt({not_a_command_receipt:true},{commandId:uuid,targetId:receipt.target_id,groupId:receipt.result.object_id}),/public_admin_command_receipt_mismatch/);
  assert.throws(()=>requireReceipt({...receipt,action:'wrong'},{commandId:uuid,targetId:receipt.target_id,groupId:receipt.result.object_id}),/public_admin_command_receipt_mismatch/);
  assert.throws(()=>requireReceipt({...receipt,policy_revision:9},{commandId:uuid,targetId:receipt.target_id,groupId:receipt.result.object_id}),/public_admin_command_receipt_mismatch/);
  assert.throws(()=>requireReceipt({...receipt,result:{...receipt.result,object_id:uuid}},{commandId:uuid,targetId:receipt.target_id,groupId:receipt.result.object_id}),/public_admin_command_receipt_mismatch/);
  requireReceipt(membershipReceipt,{commandId:membershipReceipt.command_id,targetId:receipt.target_id,
    groupId:receipt.result.object_id,action:'access_group.membership.set',objectRevision:2});
  assert.throws(()=>requireReceipt(membershipReceipt,{commandId:membershipReceipt.command_id,targetId:receipt.target_id,
    groupId:receipt.result.object_id,action:'access_group.membership.set',objectRevision:1}),/public_admin_command_receipt_mismatch/);
});

test('history must match the receipt audit ID and committed object revision',()=>{
  const item={access_group_id:receipt.result.object_id,display_name:'Local preview audit smoke',description:'synthetic',enabled:true,revision:1};
  const event={event_id:receipt.audit_event_id,action:'access_group.create',actor_id:expected.principal,after_value:{access_group_id:item.access_group_id,display_name:item.display_name,description:item.description,enabled:item.enabled,revision:1}};
  requireAudit(item,event,{groupId:item.access_group_id,displayName:item.display_name,objectRevision:1,auditEventId:receipt.audit_event_id,actorId:expected.principal});
  assert.throws(()=>requireAudit(item,{...event,event_id:uuid},{groupId:item.access_group_id,displayName:item.display_name,objectRevision:1,auditEventId:receipt.audit_event_id,actorId:expected.principal}),/public_admin_audit_or_object_mismatch/);
  assert.throws(()=>requireAudit(item,{...event,after_value:{access_group_id:item.access_group_id,revision:2}},{groupId:item.access_group_id,displayName:item.display_name,objectRevision:1,auditEventId:receipt.audit_event_id,actorId:expected.principal}),/public_admin_audit_or_object_mismatch/);
  assert.throws(()=>requireAudit(item,{...event,after_value:{...event.after_value,display_name:'wrong'}},{groupId:item.access_group_id,displayName:item.display_name,objectRevision:1,auditEventId:receipt.audit_event_id,actorId:expected.principal}),/public_admin_audit_or_object_mismatch/);
});

test('create and membership receipts preserve both historical revisions and current revision across restart',()=>{
  const createAfter={access_group_id:receipt.result.object_id,display_name:'Local preview audit smoke',
    description:'synthetic',enabled:true,revision:1,memberships:[]};
  const membershipAfter={...createAfter,revision:2,memberships:[{principal_id:expected.principal,
    effective_from:'2026-11-17T12:00:01Z',effective_until:null,enabled:true,revision:3,
    recorded_at:'2026-11-17T12:00:01Z',recorded_by:expected.principal}]};
  const state={principal_id:expected.principal,receipts:{create:receipt,membership:membershipReceipt},
    audit_after_values:{create:createAfter,membership:membershipAfter},
    object:{access_group_id:receipt.result.object_id,display_name:'Local preview audit smoke',
      description:'synthetic',enabled:true,revision:2}};
  const item={...state.object};
  const createEvent={event_id:receipt.audit_event_id,action:'access_group.create',actor_id:expected.principal,after_value:createAfter};
  const membershipEvent={event_id:membershipReceipt.audit_event_id,action:'access_group.membership.set',
    actor_id:expected.principal,after_value:membershipAfter};
  requireAudit(item,createEvent,{groupId:item.access_group_id,action:'access_group.create',
    displayName:item.display_name,description:item.description,enabled:item.enabled,objectRevision:1,
    auditEventId:receipt.audit_event_id,actorId:expected.principal});
  requireAudit(item,membershipEvent,{groupId:item.access_group_id,action:'access_group.membership.set',
    membershipPrincipal:expected.principal,objectRevision:2,auditEventId:membershipReceipt.audit_event_id,
    actorId:expected.principal});
  requirePersistedState(item,createEvent,membershipEvent,state);
  assert.throws(()=>requirePersistedState(item,{...createEvent,event_id:uuid},membershipEvent,state),/restart_persisted_object_or_audit_mismatch/);
  assert.throws(()=>requirePersistedState(item,createEvent,{...membershipEvent,event_id:uuid},state),/restart_persisted_object_or_audit_mismatch/);
  assert.throws(()=>requirePersistedState({...item,revision:1},createEvent,membershipEvent,state),/restart_persisted_object_or_audit_mismatch/);
  assert.throws(()=>requirePersistedState(item,createEvent,null,state),/restart_persisted_object_or_audit_mismatch/);
});
