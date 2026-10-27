import {LimitDetails} from './AssessmentPolicy';
import type {Duties} from './assessment-api';
import type {NativeLimits} from './native-admin-api';

export default function NativeLimitDetails({limits,duties}:{limits:NativeLimits;duties:Duties}) {
  const entries:[string,string][]=[
    ['SLA clock bases',limits.allowed_sla_clock_bases.join(', ')||'None'],
    ['SLA severities',limits.allowed_sla_severities.join(', ')||'None'],
    ['SLA start sources',limits.allowed_sla_start_sources.join(', ')||'None'],
    ['Maximum SLA duration (seconds)',String(limits.maximum_sla_duration_seconds??'No value specified')],
    ['Maximum deadline extension (seconds)',String(limits.maximum_deadline_extension_seconds??'No value specified')],
    ['SLA backfill',limits.allow_sla_backfill?'Permitted by this limit':'Not permitted by this limit'],
    ['Identity field corrections',Object.entries(limits.allowed_identity_scalar_fields).map(([action,fields])=>action+': '+(fields.join(', ')||'None')).join('; ')||'None'],
  ];
  return <><LimitDetails limits={limits} duties={duties}/><dl className="policy-facts">{entries.map(([label,value])=><div key={label}><dt>{label}</dt><dd className="break">{value}</dd></div>)}</dl></>;
}
