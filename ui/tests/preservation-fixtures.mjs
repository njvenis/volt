// Synthetic fixture labels only. Never use these expectations as production policy.
export const scope={source_family:'synthetic',source_account_id:'fixture-account',scope_key:'fixture-scope'};
export const snapshot='11111111-1111-5111-8111-111111111111';
export const digest='sha256:'+'a'.repeat(64),canonical='sha256:'+'b'.repeat(64);
export const evidenceId='22222222-2222-4222-8222-222222222222';
export const evidencePath='/api/v1/operations/preservation/evidence/'+evidenceId;
export const classIds=['product.source_evidence','product.audit_history','operational.scanner_collection'];
export const countFields=['expected_records','verified_records','missing_records','changed_records','unreadable_records','unexpected_records'];
export const copyCounts=['expected_events','matching_events','missing_events','changed_events','unexpected_events','expected_receipts','matching_receipts','missing_receipts','changed_receipts','unexpected_receipts','pending_receipts'];
export function fixture(){
 const checked=new Date(Date.now()-10000).toISOString(),expires=new Date(Date.now()+3600000).toISOString();
 const copy={state:'verified',reasons:[],...Object.fromEntries(copyCounts.map(k=>[k,k.startsWith('expected_')||k.startsWith('matching_')?1:0])),checked_at:checked};
 return {schema_version:1,scope:{...scope},snapshot_id:snapshot,checked_at:checked,response_at:new Date().toISOString(),valid_until:expires,authority_fingerprint:digest,audit_authority_fingerprint:digest,mask_reasons:[],environment:'Synthetic local browser fixture',classes:classIds.map(class_id=>({class_id,minimum_period:class_id.startsWith('operational.')?'P3M':'P1Y',state:'verified',reasons:[],expected_records:2,verified_records:2,missing_records:0,changed_records:0,unreadable_records:0,unexpected_records:0,oldest_retained_at:checked,baseline_digest:digest,audit_copy:class_id==='product.audit_history'?copy:null})),uncovered_classes:[],elapsed_preservation:'unverified'};
}
export function record(kind='evidence_registration',key='synthetic-record-1'){
 const bytes=['observation','evidence_registration'].includes(kind);
 return {record_key:key,record_kind:kind,retained_at:new Date().toISOString(),state:'verified',reasons:[],expected_sha256:bytes?digest:null,actual_sha256:bytes?digest:null,record_sha256:canonical,readback_url:kind==='evidence_registration'?evidencePath:null};
}
export function page(class_id=classIds[0]){return {schema_version:1,snapshot_id:snapshot,class_id,items:[record(class_id===classIds[0]?'evidence_registration':class_id===classIds[1]?'audit_event':'run_revision')],next_cursor:null};}
export function masked(){const s=fixture(),a=s.classes[1];s.audit_authority_fingerprint=null;s.mask_reasons=['audit_scope_incomplete'];s.uncovered_classes=[classIds[1]];a.state='unknown';a.reasons=['audit_scope_incomplete'];a.baseline_digest=null;a.oldest_retained_at=null;for(const k of countFields)a[k]=null;a.audit_copy.state='unknown';a.audit_copy.reasons=['audit_scope_incomplete'];a.audit_copy.checked_at=null;for(const k of copyCounts)a.audit_copy[k]=null;return s;}
export function unknown(reason='baseline_missing'){const s=fixture();s.snapshot_id=null;s.checked_at=null;s.valid_until=null;s.uncovered_classes=[...classIds].sort();for(const c of s.classes){c.state='unknown';c.reasons=[reason];c.baseline_digest=null;c.oldest_retained_at=null;for(const k of countFields)c[k]=null;if(c.audit_copy){c.audit_copy.state='unknown';c.audit_copy.reasons=[reason];c.audit_copy.checked_at=null;for(const k of copyCounts)c.audit_copy[k]=null;}}return s;}
