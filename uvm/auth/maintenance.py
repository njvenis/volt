"""Audited, host-authorised local account capability maintenance."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sqlalchemy as sa

from uvm.auth.local import LocalAuth, _capability_digest, _new_capability, load_local_config
from uvm.persistence.auth_schema import (auth_principals, local_accounts,
    local_auth_installation, local_capabilities, local_sessions)
from uvm.persistence.assessment_schema import assessment_policy
from uvm.assessment.policy_lock import lock_policy

UTC = timezone.utc


def _private_write(path: str, document: dict):
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = target.with_name("." + target.name + "." + secrets.token_hex(8))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, target)
        os.chmod(target, 0o600, follow_symlinks=False)
    finally:
        try: temp.unlink()
        except FileNotFoundError: pass


def run(operation: str, username: str | None = None, display_name: str | None = None,
        config_path: str | None = None, *, input_document=None):
    if config_path:
        os.environ["UVM_LOCAL_AUTH_CONFIG_FILE"] = config_path
    config = load_local_config()
    database_url = os.environ.get("UVM_DB_URL", "").strip()
    if not database_url:
        raise RuntimeError("UVM_DB_URL is required for local account maintenance")
    engine = sa.create_engine(database_url, pool_pre_ping=True)
    if operation in {'scanner-recovery-targets','scanner-recovery-request','scanner-recovery-import'}:
        try:
            if username is not None or display_name is not None or input_document is None:
                raise RuntimeError('closed recovery maintenance input required')
            from uvm.connectors.local_recovery import maintenance_request,maintenance_import
            result=(maintenance_import(engine,input_document,config) if operation=='scanner-recovery-import'
                else maintenance_request(engine,operation,input_document,config))
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        finally:
            engine.dispose()
        return
    if operation in {'validate-local-recovery','apply-local-restore-fence'}:
        try:
            if username is not None or display_name is not None:
                raise RuntimeError('recovery fence maintenance accepts no account input')
            from uvm.connectors.local_recovery import maintenance_fence
            print(json.dumps(maintenance_fence(engine,operation,config),sort_keys=True,separators=(',',':')))
        finally:
            engine.dispose()
        return
    if operation == "initialize-scanner-rule":
        try:
            if username is not None or display_name is not None:
                raise RuntimeError("scanner initialization accepts no account or rule input")
            from uvm.auth.scanner_maintenance import initialize_scanner_rule
            initialize_scanner_rule(engine, config)
            print("Scanner source-only rule initialized.")
        finally:
            engine.dispose()
        return
    service = LocalAuth(engine, {**config, "public_origin": config["public_origin"]})
    now = datetime.now(UTC)
    generated = []
    try:
        with engine.begin() as c:
            lock_policy(c)
            install = c.execute(sa.select(local_auth_installation).where(local_auth_installation.c.singleton_id == 1).with_for_update()).mappings().one()
            policy = c.execute(sa.select(assessment_policy.c.revision).where(assessment_policy.c.policy_id == 1).with_for_update()).scalar_one_or_none()
            if policy is None:
                policy_revision = 0
            else:
                policy_revision = policy
            if operation in {"prepare-setup", "rotate-setup"}:
                if install["claimed_at"] is not None:
                    raise RuntimeError("initial setup is already claimed")
                reuse_setup = False
                if operation == "prepare-setup":
                    current = c.execute(sa.select(local_capabilities).where(
                        local_capabilities.c.purpose == "setup",
                        local_capabilities.c.installation_id == install["installation_id"],
                        local_capabilities.c.consumed_at.is_(None)).with_for_update()).mappings().first()
                    if current:
                        try:
                            delivery = config["bootstrap_delivery"]
                            existing_token = json.loads(Path(delivery["path"]).read_text(encoding="utf-8"))["capability"]
                            presented = _capability_digest(existing_token, current)
                        except (OSError, ValueError, KeyError, TypeError):
                            presented = None
                        if not presented or not __import__("hmac").compare_digest(presented[1], current["capability_hash"]):
                            raise RuntimeError("setup capability already exists; use explicit rotate-setup to replace it")
                        generated.append(("setup", existing_token,
                            max(0, int((current["expires_at"] - now).total_seconds()))))
                        # Re-emit the same delivery token; no capability or audit mutation.
                        reuse_setup = True
                if not reuse_setup:
                    generation = install["setup_generation"] + (1 if operation == "rotate-setup" else 0)
                    if operation == "rotate-setup":
                        c.execute(local_auth_installation.update().where(local_auth_installation.c.singleton_id == 1).values(setup_generation=generation))
                    c.execute(local_capabilities.delete().where(local_capabilities.c.purpose == "setup", local_capabilities.c.installation_id == install["installation_id"]))
                    locator, secret, token, digest = _new_capability("setup", install["installation_id"], None, generation, 0)
                    c.execute(local_capabilities.insert().values(capability_hash=digest, capability_locator=locator, purpose="setup",
                        installation_id=install["installation_id"], principal_id=None, generation=generation,
                        credential_revision=0, expires_at=now + timedelta(minutes=30), consumed_at=None, created_at=now))
                    LocalAuth._audit(c, "host-maintenance", "local.setup.capability_issued", install["installation_id"], now)
                    generated.append(("setup", token, 1800))
            elif operation == "create-account":
                if not username or not display_name or not _valid_username(username):
                    raise RuntimeError("a valid username and display name are required")
                normalized = username.casefold()
                if c.execute(sa.select(local_accounts.c.principal_id).where(local_accounts.c.username_normalized == normalized)).first():
                    raise RuntimeError("local account already exists")
                principal_id = str(uuid.uuid4())
                c.execute(auth_principals.insert().values(principal_id=principal_id,
                    display_label=display_name.strip(), enabled=True, revision=1, created_at=now))
                c.execute(local_accounts.insert().values(principal_id=principal_id,
                    username=username, username_normalized=normalized, verifier=None,
                    credential_revision=1, capability_generation=1, status="pending", created_at=now, updated_at=now))
                locator, secret, token, digest = _new_capability("enrolment", install["installation_id"], principal_id, 1, 1)
                c.execute(local_capabilities.insert().values(capability_hash=digest, capability_locator=locator,
                    purpose="enrolment", installation_id=install["installation_id"],
                    principal_id=principal_id, generation=1, credential_revision=1,
                    expires_at=now + timedelta(minutes=15), consumed_at=None, created_at=now))
                LocalAuth._audit(c, "host-maintenance", "local.account.enrolment_issued", principal_id, now)
                generated.append(("enrolment", token, 900))
            elif operation == "issue-enrolment":
                if not username: raise RuntimeError("username is required")
                account = c.execute(sa.select(local_accounts).where(local_accounts.c.username_normalized == username.casefold()).with_for_update()).mappings().first()
                if not account or account["status"] != "pending":
                    raise RuntimeError("pending local account was not found")
                generation = account["capability_generation"] + 1
                c.execute(local_accounts.update().where(local_accounts.c.principal_id == account["principal_id"]).values(capability_generation=generation, updated_at=now))
                c.execute(local_capabilities.delete().where(local_capabilities.c.principal_id == account["principal_id"], local_capabilities.c.purpose == "enrolment"))
                locator, secret, token, digest = _new_capability("enrolment", install["installation_id"], account["principal_id"], generation, account["credential_revision"])
                c.execute(local_capabilities.insert().values(capability_hash=digest, capability_locator=locator, purpose="enrolment",
                    installation_id=install["installation_id"], principal_id=account["principal_id"],
                    generation=generation, credential_revision=account["credential_revision"],
                    expires_at=now + timedelta(minutes=15), consumed_at=None, created_at=now))
                LocalAuth._audit(c, "host-maintenance", "local.account.enrolment_reissued", account["principal_id"], now)
                generated.append(("enrolment", token, 900))
            elif operation == "issue-recovery":
                if not username: raise RuntimeError("username is required")
                account = c.execute(sa.select(local_accounts).where(local_accounts.c.username_normalized == username.casefold()).with_for_update()).mappings().first()
                if not account or account["status"] != "enabled" or not account["verifier"]:
                    raise RuntimeError("enabled local account was not found")
                c.execute(local_capabilities.delete().where(local_capabilities.c.principal_id == account["principal_id"], local_capabilities.c.purpose == "recovery"))
                locator, secret, token, digest = _new_capability("recovery", install["installation_id"], account["principal_id"], account["capability_generation"], account["credential_revision"])
                c.execute(local_capabilities.insert().values(capability_hash=digest, capability_locator=locator, purpose="recovery",
                    installation_id=install["installation_id"], principal_id=account["principal_id"],
                    generation=account["capability_generation"], credential_revision=account["credential_revision"],
                    expires_at=now + timedelta(minutes=15), consumed_at=None, created_at=now))
                LocalAuth._audit(c, "host-maintenance", "local.account.recovery_issued", account["principal_id"], now)
                generated.append(("recovery", token, 900))
            elif operation == "revoke-capabilities":
                generation = install["setup_generation"] + 1
                c.execute(local_auth_installation.update().where(local_auth_installation.c.singleton_id == 1).values(setup_generation=generation))
                c.execute(local_capabilities.delete().where(local_capabilities.c.installation_id == install["installation_id"]))
                c.execute(local_sessions.update().where(local_sessions.c.revoked_at.is_(None)).values(
                    revoked_at=now, revision=local_sessions.c.revision + 1))
                LocalAuth._audit(c, "host-maintenance", "local.capabilities.revoked_after_restore", install["installation_id"], now)
            elif operation == "disable-account":
                if not username: raise RuntimeError("username is required")
                account = c.execute(sa.select(local_accounts).where(local_accounts.c.username_normalized == username.casefold()).with_for_update()).mappings().first()
                if not account: raise RuntimeError("local account was not found")
                c.execute(local_accounts.update().where(local_accounts.c.principal_id == account["principal_id"]).values(status="disabled", credential_revision=account["credential_revision"] + 1, updated_at=now))
                c.execute(auth_principals.update().where(auth_principals.c.principal_id == account["principal_id"]).values(enabled=False, revision=auth_principals.c.revision + 1))
                c.execute(local_sessions.update().where(local_sessions.c.principal_id == account["principal_id"], local_sessions.c.revoked_at.is_(None)).values(revoked_at=now, revision=local_sessions.c.revision + 1))
                c.execute(local_capabilities.delete().where(local_capabilities.c.principal_id == account["principal_id"]))
                LocalAuth._audit(c, "host-maintenance", "local.account.disabled", account["principal_id"], now)
            else:
                raise RuntimeError("unsupported maintenance operation")
        if generated:
            delivery = config["bootstrap_delivery"]
            _private_write(delivery["path"], {"schema_version": 1, "purpose": generated[0][0],
                "capability": generated[0][1], "expires_in_seconds": generated[0][2]})
            print("Capability written to configured private delivery file.")
        else:
            print("Maintenance operation completed.")
    finally:
        engine.dispose()


def _valid_username(value):
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}", value))


def main():
    parser = argparse.ArgumentParser(prog="uvm-local-auth")
    parser.add_argument("operation", choices=("scanner-recovery-targets", "scanner-recovery-request", "scanner-recovery-import", "validate-local-recovery", "apply-local-restore-fence", "initialize-scanner-rule", "prepare-setup", "rotate-setup", "create-account", "issue-enrolment", "issue-recovery", "revoke-capabilities", "disable-account"))
    parser.add_argument("--config", default=None)
    parser.add_argument("--username")
    parser.add_argument("--display-name")
    inputs=parser.add_mutually_exclusive_group()
    inputs.add_argument('--input',choices=('-',))
    inputs.add_argument('--input-file')
    args = parser.parse_args()
    try:
        document=None
        if args.input or args.input_file:
            if not args.operation.startswith('scanner-recovery-'):
                raise RuntimeError('operation accepts no JSON input')
            from uvm.connectors.local_recovery import private_read,parse_document
            raw=private_read(args.input_file) if args.input_file else sys.stdin.buffer.read(1_000_001)
            if len(raw)>1_000_000:raise RuntimeError('recovery input too large')
            document=parse_document(raw)
        run(args.operation, args.username, args.display_name, args.config,input_document=document)
    except Exception as exc:
        # Never print database URLs, submitted capabilities or verifier material.
        print(f"maintenance failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
