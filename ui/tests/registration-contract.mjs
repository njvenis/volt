// Exact public registration contract, independent of the UI builder.
// The production transport test also validates the current exported schema.
const fields=['schema_version','command_id','action','target_id','membership_ids','expected_policy_revision','expected_authority_revision','expected_connector_registry_revision','payload'].sort();
const payloadFields=['display_name','source_family','account_label','product','platform_id','scope','environment_label','rationale','evidence_ref','grant_initial_read'].sort();
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
export function conformsToRegistrationContract(command){
 if(!object(command)||JSON.stringify(Object.keys(command).sort())!==JSON.stringify(fields)||command.schema_version!==1||command.action!=='connector.binding.register'||command.target_id!=='00000000-0000-0000-0000-000000000000'||!Array.isArray(command.membership_ids)||command.membership_ids.length||!(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(command.command_id)))return false;
 if(!['expected_policy_revision','expected_authority_revision','expected_connector_registry_revision'].every(key=>Number.isSafeInteger(command[key])&&command[key]>=0))return false;
 if(!object(command.payload)||JSON.stringify(Object.keys(command.payload).sort())!==JSON.stringify(payloadFields)||typeof command.payload.grant_initial_read!=='boolean')return false;
 if(command.payload.source_family!=='qualys'||command.payload.product!=='qualys_vm'||!['us1','us2','us3','eu1','eu2','in1'].includes(command.payload.platform_id)||!object(command.payload.scope)||Object.keys(command.payload.scope).join(',')!=='kind'||command.payload.scope.kind!=='account_visible')return false;
 return payloadFields.filter(key=>!['grant_initial_read','scope'].includes(key)).every(key=>typeof command.payload[key]==='string'&&command.payload[key].trim().length>0);
}
