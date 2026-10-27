#!/usr/bin/env python3
"""Generate the complete two-phase offline provenance bundle."""
from __future__ import annotations
import argparse, hashlib, json, sys, uuid
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
import sqlalchemy as sa
from uvm.engine.manifest import (DISPOSITION_INCLUDED, ManifestBindingRegistry,
    PayloadRecordV1, RowDispositionV1, InventorySealV1, build_occurrence_manifest)
from uvm.engine.operation import EngineImportOperationV1
from uvm.identity.model import IdentityResolutionV1
from uvm.engine.qualys_generic_adapter import build_generic_import, parse_qualys_rows
from uvm.identity import IdentityState, RuleV1, resolve
from uvm.identity.observations import COLLECTION_SUCCESS, MISSING_NOT_SUPPLIED, MissingField, SourceObservationV1
from uvm.persistence.observation_store import ObservationRepository, RetainedObservation, RetainedRun
from uvm.persistence.schema import uvm_metadata

ROOT = Path(__file__).parent
ACCOUNT = "qualys-offline-account"
RULE = RuleV1("qualys-offline-rule", 1, ("provisioning_key",), verified_asset_locator=True)
OPS = {"import": "11111111-1111-4111-8111-111111111111", "reimport": "22222222-2222-4222-8222-222222222222"}

def iso(value):
    return value.isoformat().replace("+00:00", "Z") if hasattr(value, "isoformat") else value

def jsonable(value):
    if hasattr(value, "to_primitives"): return jsonable(value.to_primitives())
    if hasattr(value, "__dataclass_fields__"):
        return {k: jsonable(getattr(value, k)) for k in value.__dataclass_fields__}
    if isinstance(value, datetime): return iso(value)
    if isinstance(value, set): return [jsonable(v) for v in sorted(value)]
    if isinstance(value, tuple): return [jsonable(v) for v in value]
    if isinstance(value, list): return [jsonable(v) for v in value]
    if isinstance(value, dict): return {k: jsonable(v) for k, v in value.items()}
    return value

def _instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value is not None else None

def bind_reimport_test(bundle: dict, test_id: int) -> dict:
    """Seal the second operation only after the first CE Test is captured."""
    if type(test_id) is not int or test_id < 1 or bundle["status"] != "offline-only; CE integration-unverified":
        raise ValueError("first captured CE Test and offline bundle required")
    p = bundle["phases"]["reimport"]
    raw = p["operation"]
    op = EngineImportOperationV1(**{**raw, "requested_at": _instant(raw["requested_at"]),
                                  "finding_ids": tuple(raw["finding_ids"]),
                                  "endpoint_ids": tuple(raw["endpoint_ids"]),
                                  "test_id": str(test_id)})
    observations = []
    for raw_obs, meta in zip(p["observations"], p["retained_rows"], strict=True):
        obs = SourceObservationV1(**{**raw_obs,
            "missing_fields": tuple(MissingField(**m) for m in raw_obs["missing_fields"]),
            "collected_at": _instant(raw_obs["collected_at"]),
            "observed_at": _instant(raw_obs["observed_at"]),
            "source_first_seen_at": _instant(raw_obs["source_first_seen_at"])})
        observations.append(RetainedObservation(obs, meta["retention_order"], meta["ingest_outcome"]))
    retained = RetainedRun(bundle["account"], p["run_id"], tuple(observations), ())
    resolutions = {}
    for raw_res in p["resolutions"]:
        res = IdentityResolutionV1(**{**raw_res, "evaluated_at": _instant(raw_res["evaluated_at"]),
            "candidate_workload_ids": tuple(raw_res["candidate_workload_ids"]),
            "candidate_explanations": tuple(raw_res["candidate_explanations"])})
        resolutions[res.observation_id] = (res,)
    raw_manifest = p["manifest"]
    manifest = build_occurrence_manifest(operation=op, retained=retained,
        seal=InventorySealV1(**raw_manifest["inventory_seal"]), resolutions=resolutions,
        dispositions=tuple(RowDispositionV1(**d) for d in raw_manifest["dispositions"]),
        payload_records=tuple(PayloadRecordV1(**{**r,"source_observation_ids":tuple(r["source_observation_ids"])})
                              for r in raw_manifest["payload_records"]),
        row_kinds={row.observation.observation_id:"candidate_positive" for row in retained.rows})
    ManifestBindingRegistry().bind(manifest)
    updated = json.loads(json.dumps(bundle))
    updated["phases"]["reimport"]["operation"] = jsonable(op)
    updated["phases"]["reimport"]["manifest"] = jsonable(manifest)
    updated["status"] = "live-capture; CE integration evidence pending"
    return updated

def build_source_observations(xml_bytes, *, source_account_id, run_id, collected_at,
                              raw_evidence_ref, raw_evidence_sha256):
    if raw_evidence_sha256 != hashlib.sha256(xml_bytes).hexdigest():
        raise ValueError("raw evidence digest mismatch")
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError("collected_at must be timezone-aware")
    parsed = parse_qualys_rows(xml_bytes)
    by_key = {(r.qid, r.host, r.port, r.component_name, r.component_version): r for r in parsed}
    root = ElementTree.fromstring(xml_bytes)
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"uvm:qualys:{source_account_id}")
    observations = []
    for host in root.findall("./HOST_LIST/HOST"):
        hostname = (host.findtext("DNS") or host.findtext("IP") or "").strip()
        for vuln in host.findall("./VULN_INFO_LIST/VULN_INFO"):
            key = (vuln.findtext("QID", "").strip(), hostname,
                   int(vuln.findtext("PORT", "0")),
                   vuln.findtext("COMPONENT_NAME", "").strip(),
                   vuln.findtext("COMPONENT_VERSION", "").strip())
            row = by_key[key]
            ordinal = len(observations) + 1
            missing = [MissingField("vulnerability_refs", MISSING_NOT_SUPPLIED)]
            if row.first_found is None:
                missing.append(MissingField("source_first_seen_at", MISSING_NOT_SUPPLIED))
            if row.last_found is None and row.first_found is None:
                missing.append(MissingField("observed_at", MISSING_NOT_SUPPLIED))
            observations.append(SourceObservationV1(
                schema_version=1,
                observation_id=str(uuid.uuid5(namespace, f"{run_id}:{row.source_identity}")),
                revision=1, source_family="qualys", source_account_id=source_account_id,
                run_id=run_id, source_record_ordinal=ordinal,
                collection_status=COLLECTION_SUCCESS, collected_at=collected_at,
                raw_evidence_ref=raw_evidence_ref, raw_evidence_sha256=raw_evidence_sha256,
                missing_fields=tuple(missing), observed_at=row.last_found or row.first_found,
                native_id_scheme="qid", native_id_authority="qualys", native_id_value=row.qid,
                asset_locator=row.host, component_locator=f"{row.component_name}:{row.port}:{row.component_version}",
                source_record_locator=f"qualys-row-{ordinal}", source_rating=row.severity,
                source_first_seen_at=row.first_found, report_id=raw_evidence_ref,
                coverage_scope="synthetic-complete"))
    return tuple(observations)


def main(destination: Path) -> None:
    out = destination.resolve()
    if out.exists():
        raise ValueError(f"destination already exists: {out}")
    out.mkdir(parents=True)
    # Keep the rejected prototype's XML and bundle hashes unchanged.
    fixture = ROOT.parent / "provenance-v1-corrected"
    base = (fixture / "import.xml").read_bytes()
    expectation = json.loads((fixture / "expected-ce-behaviour.json").read_text())
    expectation['persisted_title'] = 'Qualys prototype QID 1001 -> Qualys Prototype QID 1001; Finding.persisted_title/titlecase'
    (out / "expected-ce-behaviour.json").write_text(json.dumps(expectation, sort_keys=True, indent=2) + '\n')
    # The reviewed repeat keeps every occurrence identity and source detail, but
    # changes only host A's two ratings and advances each scanner observation.
    tree = ElementTree.fromstring(base)
    tree.find("./HEADER/GENERATION_DATETIME").text = "2026-09-30T00:00:00Z"
    hosts = tree.find("./HOST_LIST")
    host_nodes = {host.findtext("DNS"): host for host in hosts}
    hosts[:] = [host_nodes[name] for name in
                ("proto-c.internal", "proto-a.internal", "proto-b.internal")]
    for host in hosts:
        findings = host.find("VULN_INFO_LIST")
        findings[:] = list(reversed(findings))
        for finding in findings:
            finding.find("LAST_FOUND").text = "2026-09-29T00:00:00Z"
            if host.findtext("DNS") == "proto-a.internal":
                finding.find("SEVERITY").text = (
                    "Critical" if finding.findtext("PORT") == "443" else "Low")
    repeat = ElementTree.tostring(tree, encoding="unicode").encode() + b"\n"
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        uvm_metadata.create_all(conn)
    repo = ObservationRepository(engine)
    state = IdentityState()
    all_rows = {}
    resolutions = {}
    manifests = {}
    payloads = {}
    graphs = {}
    registry = ManifestBindingRegistry()
    for phase, xml, run, collected in (
        ("import", base, "qualys-run-20260929", datetime(2026, 9, 29, 1, tzinfo=timezone.utc)),
        ("reimport", repeat, "qualys-run-20260930", datetime(2026, 9, 30, 1, tzinfo=timezone.utc)),
    ):
        digest = hashlib.sha256(xml).hexdigest()
        imported = build_generic_import(xml)
        payloads[phase] = imported.payload
        observations = build_source_observations(
            xml, source_account_id=ACCOUNT, run_id=run, collected_at=collected,
            raw_evidence_ref=f"bundle://{phase}.xml", raw_evidence_sha256=digest)
        repo.write_run(ACCOUNT, run, [(obs, "created") for obs in observations])
        retained = repo.read_run(ACCOUNT, run)
        phase_resolutions = {}
        for row in retained.rows:
            obs = row.observation
            host = obs.asset_locator or ""
            result = resolve(state, obs, RULE, {"provisioning_key": f"pk:{host}"}, collected)
            phase_resolutions[obs.observation_id] = (result,)
        # Copy now: the repeat must not retrospectively change the first graph.
        graphs[phase] = {
            name: [jsonable(record) for _, record in sorted(getattr(state, name).items())]
            for name in ('groups', 'workloads', 'incarnations', 'exposures', 'occurrences')
        }
        graphs[phase]['observation_occurrences'] = {
            row.observation.observation_id: state.observation_occurrences[row.observation.observation_id]
            for row in retained.rows
        }
        operation = EngineImportOperationV1(
            schema_version=1, operation_id=OPS[phase], revision=1,
            context_key="offline:qualys/prototype", source_run_id=run,
            scan_type=imported.scan_type, payload_sha256=hashlib.sha256(imported.payload).hexdigest(),
            parser_config_version=imported.parser_config_version, engine_release="CE-offline-unverified",
            request_kind=phase, requested_at=collected, close_old_findings=False,
            status="pending", test_id="offline-test-uvm-g1" if phase == "reimport" else None)
        dispositions = tuple(RowDispositionV1(
            schema_version=1, observation_id=row.observation.observation_id,
            source_record_ordinal=row.observation.source_record_ordinal,
            raw_evidence_sha256=row.observation.raw_evidence_sha256,
            disposition=DISPOSITION_INCLUDED,
            occurrence_id=phase_resolutions[row.observation.observation_id][0].occurrence_id,
            resolution_id=phase_resolutions[row.observation.observation_id][0].resolution_id,
            resolution_revision=phase_resolutions[row.observation.observation_id][0].revision)
            for row in retained.rows)
        by_identity = {(row.qid,row.host,row.port,row.component_name,row.component_version):
                       next(r.observation.observation_id for r in retained.rows
                            if r.observation.native_id_value==row.qid
                            and r.observation.asset_locator==row.host
                            and r.observation.component_locator==f"{row.component_name}:{row.port}:{row.component_version}")
                       for row in imported.rows}
        records = tuple(PayloadRecordV1(1, str(i + 1),
                        (by_identity[(row.qid,row.host,row.port,row.component_name,row.component_version)],))
                        for i, row in enumerate(imported.rows))
        seal = InventorySealV1(1, "qualys", ACCOUNT, run,
                               max(row.retention_order for row in retained.rows),
                               len(retained.rows), 0, f"bundle://{phase}-seal")
        manifest = build_occurrence_manifest(
            operation=operation, retained=retained, seal=seal,
            resolutions=phase_resolutions, dispositions=dispositions,
            payload_records=records,
            row_kinds={row.observation.observation_id: "candidate_positive" for row in retained.rows})
        registry.bind(manifest)
        all_rows[phase] = retained
        resolutions[phase] = phase_resolutions
        manifests[phase] = (operation, manifest)
    bundle = {
        "schema_version": 1, "account": ACCOUNT,
        "phases": {}, "status": "offline-only; CE integration-unverified",
    }
    for phase in ("import", "reimport"):
        operation, manifest = manifests[phase]
        retained = all_rows[phase]
        bundle["phases"][phase] = {
            "xml": f"{phase}.xml", "xml_sha256": hashlib.sha256((base if phase == "import" else repeat)).hexdigest(),
            "run_id": retained.run_id, "payload": f"{phase}-payload.json",
            "payload_sha256": hashlib.sha256(payloads[phase]).hexdigest(),
            "operation": jsonable(operation), "manifest": jsonable(manifest),
            "observations": [jsonable(row.observation) for row in retained.rows],
            "retained_rows": [{"observation_id": row.observation.observation_id,
                               "retention_order": row.retention_order,
                               "ingest_outcome": row.ingest_outcome} for row in retained.rows],
            "resolutions": [jsonable(resolutions[phase][row.observation.observation_id][0]) for row in retained.rows],
            "occurrences": [resolutions[phase][row.observation.observation_id][0].occurrence_id for row in retained.rows],
            "payload_records": jsonable(manifest.payload_records),
            "identity_graph": graphs[phase],
        }
        (out / f"{phase}.xml").write_bytes(base if phase == "import" else repeat)
        (out / f"{phase}-payload.json").write_bytes(payloads[phase])
    (out / "bundle.json").write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n")
    print(f"generated {out / 'bundle.json'}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    main(parser.parse_args().destination)
