// Display labels only. API units, membership, clocks and saved values stay exact.
const units:Record<string,string>={atoms:'instance / occurrence period pairs',native_groups:'distinct vulnerabilities',inventory_targets:'scan targets'};
export const reportUnit=(unit:string)=>Object.hasOwn(units,unit)?units[unit]:'items (unit unavailable)';
// Metric dictionary: uvm/assessment/metrics_api.py _metric calls and
// _qualifying_populations; docs/metrics.md. Basis keys are exact server values.
const bases:Record<string,string>={
 'Eligible outstanding mapped membership':'Included total: eligible outstanding instance / occurrence period pairs, including those with missing SLA inputs.',
 'Covered eligible outstanding mapped membership':'Included total: eligible outstanding instance / occurrence period pairs with a computable current SLA deadline.',
 'Distinct native group IDs with at least one current breached outstanding atom':'Included total: distinct vulnerabilities with eligible outstanding membership. Matching: those with at least one current SLA breach.',
 'Outstanding atoms with original deadline':'Included total: eligible outstanding instance / occurrence period pairs with a known original deadline.',
 'Atoms with a retained interval under an original policy deadline':'Included total: instance / occurrence period pairs with retained history under an original policy deadline.',
 'Atoms with a retained outstanding interval under an applicable evaluation deadline':'Included total: instance / occurrence period pairs with a retained outstanding interval under an applicable deadline.',
 'Newly confirmed atoms in the completion period':'Included total: all newly confirmed instance / occurrence period pairs in the selected completion period.',
 'Newly confirmed period atoms with known deadlines':'Included total: newly confirmed instance / occurrence period pairs in the selected completion period with known deadlines.',
 'Exact membership covered by retained earlier confirmation; not a new completion':'Count only: instance / occurrence period pairs covered by an earlier confirmation. No new completion or rate denominator.',
 'Outstanding exact memberships excluded by an explicit versioned SLA policy':'Included total: outstanding instance / occurrence period pairs explicitly excluded by an SLA policy.',
 'Distinct expected targets with fresh complete observations from every required source':'Included total: distinct expected scan targets. Matching: targets with fresh, complete results from every required scanner.'
};
export const reportBasis=(basis:string)=>Object.hasOwn(bases,basis)?bases[basis]:'Inclusion criteria unavailable. See calculation details.';
const terms:Record<string,string>={
 on_time:'Fix confirmed on time',late:'Fix confirmed late',unknown_deadline:'Fix confirmed · deadline unknown',
 review:'Needs review',remediated:'Fixed',partially_remediated:'Partly fixed',open:'Open',
 unknown:'Unknown',failed:'Failed',stale:'Out of date',pending:'Pending',ready:'Ready',complete:'Complete',fresh:'Up to date',partial:'Incomplete',missing:'Missing',
 eligible:'Included in SLA',excluded:'Excluded from SLA',covered:'Covered',uncovered:'Not covered','not covered':'Not covered',
 awaiting_source_time:'Waiting for the scan time',none:'None',active:'Active',suspended:'Suspended',expired:'Expired',revoked:'Revoked',rejected:'Rejected',
 assessed:'Assessed',unassessed:'Not assessed',not_assessed:'Not assessed',

 as_known_at:'Saved information',corrected_history:'Updated historical report',known:'Data available',not_applicable:'Not applicable',
 carried:'Previous fix still applies',direct:'Fix confirmed',outstanding:'Needs a fix',
 elapsed_utc_seconds:'Elapsed time in seconds (UTC)',calendar_days_utc:'Calendar days in UTC',prospective:'New occurrence periods',backfill_existing:'Selected existing findings',
 missing_classification:'Severity classification missing',source_failure:'Scanner collection failed',stale_scanner_observation:'Scan results out of date',unknown_inventory:'Scan inventory unknown',classification_gaps:'Missing severity classifications',
 stale_source_observation:'Scan results out of date',coverage_gaps:'Missing SLA coverage',reference_conflict:'Conflicting deadline references',conflicting_sla_policies:'Conflicting SLA policies',no_applicable_policy:'No applicable SLA policy',missing_observation_time:'Scan time missing'
};
export const reportTerm=(value:string)=>Object.hasOwn(terms,value)?terms[value]:'Details unavailable';
