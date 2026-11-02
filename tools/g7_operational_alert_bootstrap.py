"""Trusted disposable bootstrap for G7 operational alert public journeys."""
from __future__ import annotations
import os, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from uuid import UUID
import sqlalchemy as sa

from uvm.persistence.assessment_schema import assessment_policy
from uvm.persistence.incident_schema import (
    g7_incident_routes, g7_incident_service_bindings, g7_incident_streams,
    g7_incident_transitions,
)

ZERO = "00000000-0000-4000-8000-000000000000"
GROUP = os.environ.get("G7_OPERATIONAL_RECIPIENT_GROUP_ID", "00000000-0000-4000-8000-000000000042")
PRINCIPAL = "g7-host-operational-alert-sender"
PRODUCER = "g7-host-operational-alert-sender/v1"
SOURCE = {"source_family":"local","source_account_id":"g7-local","scope_key":"all"}

def main():
    run = os.environ["G7_OPERATIONAL_RUN_ID"]
    if str(UUID(GROUP)) != GROUP:
        raise RuntimeError("operational recipient group id must be a canonical UUID")
    deployment = "g7-local"
    subjects = {"container_availability":f"container:g7-local:{run}",
        "host_sender_health":f"host-sender:g7-local:{run}"}
    # The entrypoint exports UVM_DB_URL only to its supervised application
    # children, so this trusted disposable bootstrap reconstructs it from the
    # read-only mounted fixture secret without emitting the credential.
    password = Path("/run/secrets/uvm_db_password").read_text().strip()
    engine = sa.create_engine("postgresql+psycopg://uvm_app:" + quote(password, safe="")
        + "@127.0.0.1:5432/uvm")
    try:
        with engine.begin() as cx:
            row = cx.execute(sa.select(assessment_policy).where(
                assessment_policy.c.policy_id==1).with_for_update()).mappings().one()
            policy = dict(row["document"])
            native = policy.setdefault("native_authority", {"mode":"uvm_native_v1","revision":0,
                "ownership_revision":0,"mapping_revision":0,"bootstrap_admins":["g7-actor"],
                "grantable_envelope":{},"access_groups":{},"ownership_teams":{},"revocations":[]})
            native.setdefault("access_groups",{})
            group = native["access_groups"].get(GROUP)
            if not isinstance(group,dict) or not isinstance(group.get("display_name"),str):
                raise RuntimeError("operational recipient access group must already exist with complete current shape")
            at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
            permissions=list(group.get("permissions",[]))
            if not any(item.get("permission_id")=="g7-operational-alert-read-v1" for item in permissions
                    if isinstance(item,dict)):
                permissions.append({"permission_id":"g7-operational-alert-read-v1",
                    "role_id":"g7-operational-alert-reader","action":"integration.health.read",
                    "target_scope":{"group_ids":[ZERO],"source_families":["local"],
                        "environments":[],"service_ids":[],"membership_mode":"explicit"},"limits":{}})
            group["permissions"]=permissions
            group["revision"]=int(group.get("revision",0))+1
            native["revision"] = int(native.get("revision",0))+1
            cx.execute(assessment_policy.update().where(assessment_policy.c.policy_id==1).values(
                revision=int(row["revision"])+1,document=policy,updated_at=datetime.now(timezone.utc),
                updated_by="g7-disposable-operational-alert-bootstrap"))
            for condition,subject in subjects.items():
                cx.execute(g7_incident_service_bindings.delete().where(
                    g7_incident_service_bindings.c.principal_id==PRINCIPAL,
                    g7_incident_service_bindings.c.deployment_id==deployment,
                    g7_incident_service_bindings.c.subject_id==subject,
                    g7_incident_service_bindings.c.condition==condition))
                cx.execute(g7_incident_service_bindings.insert().values(principal_id=PRINCIPAL,
                    deployment_id=deployment,subject_id=subject,condition=condition,
                    subject_type="host_sender" if condition=="host_sender_health" else "container",
                    producer_id=PRODUCER,producer_revision=1,configuration_revision=1,enabled=True))
                route_id="g7-host-sender-health-v1" if condition=="host_sender_health" else "g7-host-sender-availability-v1"
                cx.execute(g7_incident_routes.delete().where(g7_incident_routes.c.route_id==route_id))
                cx.execute(g7_incident_routes.insert().values(route_id=route_id,revision=1,
                    deployment_id=deployment,subject_id=subject,recipient_access_group_id=GROUP,
                    vulnerability_group_id=None,source_family=SOURCE["source_family"],
                    source_account_id=SOURCE["source_account_id"],scope_key=SOURCE["scope_key"],enabled=True))
            for condition,subject in subjects.items():
                if cx.execute(sa.select(g7_incident_streams.c.last_sequence).where(
                    g7_incident_streams.c.deployment_id==deployment,
                    g7_incident_streams.c.subject_id==subject,
                    g7_incident_streams.c.condition==condition)).first():
                    raise RuntimeError("incident stream already exists; new fixture genesis is forbidden")
                if cx.execute(sa.select(g7_incident_transitions.c.transition_id).where(
                    g7_incident_transitions.c.deployment_id==deployment,
                    g7_incident_transitions.c.subject_id==subject,
                    g7_incident_transitions.c.condition==condition)).first():
                    raise RuntimeError("incident transitions already exist; new fixture genesis is forbidden")
        print("incident_bootstrap=installed; availability_and_sender_health_streams=verified_absent")
    finally: engine.dispose()
if __name__=="__main__": main()
