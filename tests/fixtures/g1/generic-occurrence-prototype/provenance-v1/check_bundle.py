#!/usr/bin/env python3
"""Independent XML/payload oracle plus typed V1 manifest reconstruction."""
from __future__ import annotations
import hashlib
import json
import sys
from dataclasses import fields, replace
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from uvm.engine.manifest import (InventorySealV1, ManifestBindingRegistry, ManifestConflictError,
    OccurrenceManifestV1, PayloadRecordV1, RowDispositionV1, build_occurrence_manifest)
from uvm.engine.operation import EngineImportOperationV1
from uvm.identity.model import IdentityResolutionV1
from uvm.identity.observations import MissingField, SourceObservationV1
from uvm.persistence.observation_store import RetainedObservation, RetainedRun

class ProofError(ValueError): pass

def need(ok, message):
    if not ok: raise ProofError(message)

def digest(data): return hashlib.sha256(data).hexdigest()

def instant(value): return datetime.fromisoformat(value.replace('Z', '+00:00')) if value is not None else None

def exact(cls, data, conversions=None):
    names = {f.name for f in fields(cls)}
    need(type(data) is dict and set(data) == names, f'{cls.__name__}: fields differ')
    value = dict(data)
    for name, convert in (conversions or {}).items(): value[name] = convert(value[name])
    return cls(**value)

def unique(items, key, label):
    values = [item[key] for item in items]
    need(len(values) == len(set(values)), f'duplicate {label}')
    return dict(zip(values, items))

def source_rows(xml):
    root = ElementTree.fromstring(xml)
    result = []
    for host in root.findall('./HOST_LIST/HOST'):
        hostname = (host.findtext('DNS') or host.findtext('IP') or '').strip()
        for vuln in host.findall('./VULN_INFO_LIST/VULN_INFO'):
            item = {name: (vuln.findtext(tag) or '').strip() for name, tag in
                    [('qid','QID'),('component','COMPONENT_NAME'),('version','COMPONENT_VERSION'),
                     ('title','TITLE'),('severity','SEVERITY'),('result','RESULT')]}
            item.update(host=hostname, port=int(vuln.findtext('PORT')),
                        first_found=vuln.findtext('FIRST_FOUND'), last_found=vuln.findtext('LAST_FOUND'),
                        ordinal=len(result)+1)
            need(item['qid'] and hostname and item['component'] and item['title'], 'incomplete XML row')
            result.append(item)
    need(len(result) == 6, 'XML inventory must have six rows')
    unique(result, 'ordinal', 'XML ordinal')
    need(len({key(r) for r in result}) == 6, 'duplicate XML identity')
    return result

def key(row): return (row['qid'], row['host'], row['port'], row['component'], row['version'])

def token(row):
    raw = b''.join(str(len(v.encode())).encode()+b':'+v.encode() for v in
                   (row['qid'], row['host'], str(row['port']), row['component'], row['version']))
    return 'uvm:qualys:occurrence:' + digest(raw)

def approved_rows(phase):
    hosts = (('proto-a.internal',('A','B')),
             ('proto-b.internal',('C','D')),
             ('proto-c.internal',('E','F')))
    if phase == 'reimport':
        hosts = (('proto-c.internal',('F','E')),
                 ('proto-a.internal',('B','A')),
                 ('proto-b.internal',('D','C')))
    out=[]
    for host, letters in hosts:
        for letter in letters:
            port = 443 if letter in 'ACE' else 8443
            out.append({'qid':'1001','host':host,'port':port,'component':'openssl',
                        'version':'3.0.1' if port==443 else '3.0.0',
                        'title':'Qualys prototype QID 1001',
                        'severity':('Critical' if letter=='A' else 'Low' if letter=='B' else 'High')
                                   if phase=='reimport' else 'High',
                        'result':letter,'first_found':'2026-08-01T00:00:00Z',
                        'last_found':'2026-09-29T00:00:00Z' if phase=='reimport' else '2026-09-28T00:00:00Z',
                        'ordinal':len(out)+1})
    return out

def check_identity_graph(p, phase, sources, observations, resolutions):
    graph = p['identity_graph']
    kinds = {'groups': ('group_id', 1), 'workloads': ('workload_id', 3),
             'incarnations': ('incarnation_id', 3), 'exposures': ('exposure_id', 3),
             'occurrences': ('occurrence_id', 6)}
    need(type(graph) is dict and set(graph) == set(kinds) | {'observation_occurrences'},
         f'{phase}: identity graph fields')
    indexes = {}
    for name, (id_field, count) in kinds.items():
        records = graph[name]
        need(type(records) is list and len(records) == count, f'{phase}: identity graph {name} count')
        indexes[name] = unique(records, id_field, f'identity graph {name} ID')
    links = graph['observation_occurrences']
    need(type(links) is dict and set(links) == set(observations), f'{phase}: identity observation links')
    selected = {}; used = {name: set() for name in kinds}; seen_hosts = set()
    created = '2026-09-29T01:00:00Z'
    first_observed = '2026-09-28T00:00:00Z'
    for obs_id in sorted(sources, key=lambda oid: sources[oid]['ordinal']):
        source = sources[obs_id]; obs = observations[obs_id]; rr = resolutions[obs_id]
        ids = tuple(rr[name] for name in ('group_id', 'workload_id', 'incarnation_id',
                                        'exposure_id', 'occurrence_id'))
        group_id, workload_id, incarnation_id, exposure_id, occurrence_id = ids
        for name, (id_field, _) in kinds.items():
            need(rr[id_field] in indexes[name], f'{phase}: identity {id_field} target missing')
            used[name].add(rr[id_field])
        need(links[obs_id] == occurrence_id, f'{phase}: identity observation occurrence mismatch')
        is_new = phase == 'import' and source['host'] not in seen_hosts
        seen_hosts.add(source['host'])
        need(rr['schema_version'] == 1 and rr['outcome'] == ('new' if is_new else 'matched')
             and rr['evaluated_at'] == obs['collected_at'] and rr['supersedes_resolution_id'] is None
             and rr['candidate_workload_ids'] == [workload_id]
             and rr['candidate_explanations'] == ([] if is_new else [{
                 'workload_id': workload_id, 'field': 'provisioning_key',
                 'value': 'pk:' + source['host'], 'reason': 'stable attribute match'}])
             and rr['reason'] == ('new identity created' if is_new else 'matched existing identity'),
             f'{phase}: identity resolution outcome/candidates/evaluation')
        expected = {
            'groups': {'group_id': group_id, 'key': {
                'source_family': obs['source_family'], 'native_id_scheme': obs['native_id_scheme'],
                'native_id_authority': obs['native_id_authority'], 'native_id_value': source['qid']},
                'cve_refs': [], 'revision': 1, 'created_at': created},
            'workloads': {'workload_id': workload_id,
                'stable_attrs': {'provisioning_key': 'pk:' + source['host']},
                'revision': 1, 'created_at': created},
            'incarnations': {'incarnation_id': incarnation_id, 'workload_id': workload_id,
                'host_locator': source['host'], 'image_ref': None,
                'first_observed_at': first_observed, 'revision': 1, 'created_at': created},
            'exposures': {'exposure_id': exposure_id, 'group_id': group_id, 'workload_id': workload_id,
                'first_observed_at': first_observed, 'revision': 1, 'created_at': created},
            'occurrences': {'occurrence_id': occurrence_id, 'exposure_id': exposure_id,
                'incarnation_id': incarnation_id, 'component_locator': obs['component_locator'],
                'first_observed_at': first_observed, 'first_ingested_at': created,
                'revision': 1, 'created_at': created},
        }
        for name, (id_field, _) in kinds.items():
            need(indexes[name][rr[id_field]] == expected[name],
                 f'{phase}: identity {name} source/parent mismatch')
        selected[key(source)] = ids
    need(all(used[name] == set(indexes[name]) for name in kinds), f'{phase}: unreferenced identity graph record')
    return selected, indexes

def check_phase(root, p, phase, account, registry, live=False):
    need(set(p) == {'xml','xml_sha256','run_id','payload','payload_sha256','operation','manifest',
                    'observations','retained_rows','resolutions','occurrences','payload_records',
                    'identity_graph'}, f'{phase}: phase fields')
    need(p['xml'] == phase+'.xml' and p['payload'] == phase+'-payload.json', f'{phase}: phase substitution')
    need(p['run_id']==('qualys-run-20260929' if phase=='import' else 'qualys-run-20260930'),
         f'{phase}: approved run ID')
    xml = (root/p['xml']).read_bytes(); need(digest(xml) == p['xml_sha256'], f'{phase}: XML digest')
    rows = source_rows(xml)
    need(rows==approved_rows(phase),f'{phase}: XML differs from approved synthetic fixture')
    by_ordinal = {r['ordinal']:r for r in rows}
    need(len(p['observations']) == len(p['retained_rows']) == len(p['resolutions']) ==
         len(p['occurrences']) == 6, f'{phase}: retained inventory')
    obs_by_id = unique(p['observations'], 'observation_id', 'observation ID')
    meta_by_id = unique(p['retained_rows'], 'observation_id', 'retained row')
    res_by_id = unique(p['resolutions'], 'observation_id', 'resolution observation ID')
    need(set(obs_by_id) == set(meta_by_id) == set(res_by_id), f'{phase}: inventory/resolution membership')
    need(len({r['resolution_id'] for r in p['resolutions']}) == 6, f'{phase}: resolution ID collision')
    need(len(set(p['occurrences'])) == 6, f'{phase}: occurrence collision')
    typed_rows=[]; typed_res={}; source_by_obs={}
    for obs_id, raw in obs_by_id.items():
        ordinal=raw['source_record_ordinal']
        need(type(ordinal) is int and ordinal in by_ordinal, f'{phase}: XML ordinal')
        source=by_ordinal[ordinal]; source_by_obs[obs_id]=source
        need(raw['source_family']=='qualys' and raw['source_account_id']==account and raw['run_id']==p['run_id'], f'{phase}: observation scope')
        need(raw['raw_evidence_ref']=='bundle://'+phase+'.xml' and raw['raw_evidence_sha256']==digest(xml)
             and raw['report_id']==raw['raw_evidence_ref'], f'{phase}: evidence ref/digest')
        need(raw['source_record_locator']==f'qualys-row-{ordinal}' and raw['native_id_scheme']=='qid'
             and raw['native_id_authority']=='qualys' and raw['native_id_value']==source['qid']
             and raw['asset_locator']==source['host'] and raw['component_locator']==f"{source['component']}:{source['port']}:{source['version']}"
             and raw['source_rating']==source['severity'], f'{phase}: observation source fields')
        need(raw['source_first_seen_at']==source['first_found'] and
             raw['observed_at']==(source['last_found'] or source['first_found']), f'{phase}: scanner timestamps')
        need(raw['collected_at']==('2026-09-29T01:00:00Z' if phase=='import' else '2026-09-30T01:00:00Z')
             and raw['collected_at']==p['operation']['requested_at'] and raw['coverage_scope']=='synthetic-complete'
             and raw['collection_status']=='success' and raw['occurrence_id'] is None
             and raw['revision']==1 and raw['vulnerability_refs'] is None
             and raw['missing_fields']==[{'field':'vulnerability_refs','reason':'not_supplied'}],
             f'{phase}: collection semantics')
        missing=[exact(MissingField,x) for x in raw['missing_fields']]
        obs=exact(SourceObservationV1,raw,{'missing_fields':lambda _:tuple(missing),
             'collected_at':instant,'observed_at':instant,'source_first_seen_at':instant,
             'vulnerability_refs':lambda x: tuple(x) if x is not None else None})
        meta=meta_by_id[obs_id]
        need(set(meta)=={'observation_id','retention_order','ingest_outcome'}
             and type(meta['retention_order']) is int and meta['ingest_outcome']=='created',
             f'{phase}: retained metadata')
        typed_rows.append(RetainedObservation(obs,meta['retention_order'],meta['ingest_outcome']))
        rr=res_by_id[obs_id]
        need(rr['observation_id']==obs_id and rr['revision']==1 and rr['outcome'] in ('new','matched')
             and rr['rule_id']=='qualys-offline-rule'
             and rr['rule_version']==1 and rr['matching_inputs']=={'provisioning_key':'pk:'+source['host']},
             f'{phase}: resolution source/head/outcome')
        typed_res[obs_id]=(exact(IdentityResolutionV1,rr,{'evaluated_at':instant,
              'candidate_workload_ids':tuple,'candidate_explanations':tuple}),)
    identity, graph = check_identity_graph(p, phase, source_by_obs, obs_by_id, res_by_id)
    need({r['source_record_ordinal'] for r in p['observations']}==set(range(1,7)), f'{phase}: XML ordinal coverage')
    orders=sorted(r['retention_order'] for r in p['retained_rows'])
    need(orders==list(range(orders[0],orders[0]+6)), f'{phase}: retention order')
    need(set(p['occurrences'])=={r['occurrence_id'] for r in p['resolutions']}, f'{phase}: occurrence membership')
    payload=(root/p['payload']).read_bytes(); need(digest(payload)==p['payload_sha256'],f'{phase}: payload digest')
    body=json.loads(payload); need(type(body) is dict and set(body)=={'findings'}, f'{phase}: payload shape')
    findings=body['findings']; need(type(findings) is list and len(findings)==6,f'{phase}: payload count')
    unique(findings,'unique_id_from_tool','CE token')
    records=p['payload_records']; need(len(records)==6,f'{phase}: record count')
    unique(records,'payload_record_id','payload record ID')
    need(records==p['manifest']['payload_records'],f'{phase}: payload record binding')
    seen=[]
    for index,(record,finding) in enumerate(zip(records,findings),1):
        need(record['payload_record_id']==str(index) and len(record['source_observation_ids'])==1,
             f'{phase}: payload record index/membership')
        obs_id=record['source_observation_ids'][0]; need(obs_id in obs_by_id,f'{phase}: unknown record observation')
        seen.append(obs_id); source=source_by_obs[obs_id]
        expected={'component_name':source['component'],'component_version':source['version'],
                  'description':source['result'],'endpoints':[{'host':source['host'],'port':source['port']}],
                  'title':source['title'],'severity':source['severity'],
                  'unique_id_from_tool':token(source),'vuln_id_from_tool':source['qid']}
        if source['last_found']: expected['date']=instant(source['last_found']).date().isoformat()
        need(finding==expected,f'{phase}: exact payload source fields/token/date')
    need(len(set(seen))==6 and set(seen)==set(obs_by_id), f'{phase}: payload membership bijection')
    operation=exact(EngineImportOperationV1,p['operation'],{'requested_at':instant,
                   'finding_ids':tuple,'endpoint_ids':tuple})
    need(operation.request_kind==phase and operation.source_run_id==p['run_id']
         and operation.operation_id==('11111111-1111-4111-8111-111111111111' if phase=='import'
                                      else '22222222-2222-4222-8222-222222222222')
         and operation.payload_sha256==digest(payload) and operation.context_key=='offline:qualys/prototype'
         and operation.status=='pending' and not operation.post_issued and operation.close_old_findings is False
         and (operation.test_id is None if phase=='import' else
              (type(operation.test_id) is str and operation.test_id.isdecimal() and int(operation.test_id)>0
               if live else operation.test_id=='offline-test-uvm-g1')),
         f'{phase}: operation scope/state')
    manifest_raw=p['manifest']; seal=exact(InventorySealV1,manifest_raw['inventory_seal'])
    dispositions=tuple(exact(RowDispositionV1,x) for x in manifest_raw['dispositions'])
    typed_records=tuple(exact(PayloadRecordV1,x,{'source_observation_ids':tuple}) for x in records)
    retained=RetainedRun(account,p['run_id'],tuple(sorted(typed_rows,key=lambda x:x.retention_order)),())
    rebuilt=build_occurrence_manifest(operation=operation,retained=retained,seal=seal,
         resolutions=typed_res,dispositions=dispositions,payload_records=typed_records,
         row_kinds={obs_id:'candidate_positive' for obs_id in obs_by_id})
    need(len(manifest_raw['dispositions'])==6 and len({d['observation_id'] for d in manifest_raw['dispositions']})==6,
         f'{phase}: disposition duplicates')
    # Compare every public DTO field, including the digest and fields omitted by the digest.
    supplied=exact(OccurrenceManifestV1,manifest_raw,{'inventory_seal':lambda _:seal,
              'dispositions':lambda _:dispositions,'payload_records':lambda _:typed_records})
    need(supplied==rebuilt,f'{phase}: complete canonical manifest DTO differs from retained run')
    need(registry.bind(rebuilt).outcome=='bound' and registry.bind(rebuilt).outcome=='duplicate',
         f'{phase}: registry replay')
    conflicting=build_occurrence_manifest(operation=replace(operation,context_key='offline:conflict'),
        retained=retained,seal=seal,resolutions=typed_res,dispositions=dispositions,
        payload_records=typed_records,row_kinds={obs_id:'candidate_positive' for obs_id in obs_by_id})
    try:
        registry.bind(conflicting)
    except ManifestConflictError:
        pass
    else:
        raise ProofError(f'{phase}: conflicting operation replay was accepted')
    return identity, rows, findings, graph

def check(root):
    bundle=json.loads((root/'bundle.json').read_text())
    need(set(bundle)=={'schema_version','account','phases','status'} and bundle['schema_version']==1
         and bundle['account']=='qualys-offline-account'
         and bundle['status'] in ('offline-only; CE integration-unverified',
                                  'live-capture; CE integration evidence pending')
         and set(bundle['phases'])=={'import','reimport'}, 'bundle envelope')
    registry=ManifestBindingRegistry()
    live=bundle['status']=='live-capture; CE integration evidence pending'
    first=check_phase(root,bundle['phases']['import'],'import',bundle['account'],registry,live)
    second=check_phase(root,bundle['phases']['reimport'],'reimport',bundle['account'],registry,live)
    need(first[0]==second[0], 'repeat complete identity tuple changed')
    need(first[3]==second[3], 'repeat identity graph records changed')
    for collection, id_field in (('observations', 'observation_id'), ('resolutions', 'resolution_id')):
        need(not ({r[id_field] for r in bundle['phases']['import'][collection]} &
                  {r[id_field] for r in bundle['phases']['reimport'][collection]}),
             f'repeat {id_field} reused')
    need(set(map(key,first[1]))==set(map(key,second[1])) and
         [key(x) for x in first[1]]!=[key(x) for x in second[1]], 'repeat XML order or identity')
    base={key(x):x for x in first[1]}; repeat={key(x):x for x in second[1]}
    changed=[(base[k]['severity'],r['severity']) for k,r in repeat.items() if base[k]['severity']!=r['severity']]
    need(sorted(changed)==[('High','Critical'),('High','Low')], 'exact severity delta')
    need(all(base[k]['first_found']==r['first_found'] and
             instant(r['last_found'])>instant(base[k]['last_found']) for k,r in repeat.items()),
         'first/last scanner dates')
    need(bundle['phases']['import']['operation']['operation_id']!=bundle['phases']['reimport']['operation']['operation_id']
         and bundle['phases']['import']['manifest']['manifest_id']!=bundle['phases']['reimport']['manifest']['manifest_id'],
         'phase operation/manifest identities collide')
    print('PASS provenance-v1: two phases, exact retained inventory, canonical manifests and payloads')
if __name__=='__main__':
    try: check(Path(sys.argv[1]))
    except (OSError,KeyError,TypeError,ValueError,AttributeError) as exc:
        print(f'FAIL provenance-v1: {exc}',file=sys.stderr); raise SystemExit(1)
