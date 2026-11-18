#!/opt/uvm/venv/bin/python
"""Fixed local maintenance entry point for startup and root-only Docker exec.

Read the entrypoint's ephemeral protected environment; never pass database
credentials through Docker configuration, command arguments or a shell.
"""
from pathlib import Path
import json
import os
import stat
import sys

ENVIRONMENT = Path('/run/uvm-maintenance/environment.json')
KEYS = {'UVM_DB_URL', 'UVM_AUTH_MODE', 'UVM_LOCAL_AUTH_CONFIG_FILE',
        'UVM_LOCAL_RECOVERY_CONFIG_FILE', 'UVM_CONNECTOR_LOCAL_KEY_FILE',
        'UVM_CONNECTOR_LOCAL_KEY_ID', 'UVM_SCANNER_EVIDENCE_DIR'}
RECOVERY = {'validate-local-recovery', 'apply-local-restore-fence',
            'initialize-scanner-rule', 'scanner-recovery-targets',
            'scanner-recovery-request', 'scanner-recovery-import'}
ACCOUNTS = {'prepare-setup', 'rotate-setup', 'create-account', 'issue-enrolment',
            'issue-recovery', 'disable-account', 'revoke-capabilities'}


def main():
    if os.geteuid() != 0 or len(sys.argv) < 2:
        raise RuntimeError('root maintenance operation required')
    operation = sys.argv[1]
    if operation not in RECOVERY | ACCOUNTS | {'prepare-initial-installation'}:
        raise RuntimeError('unsupported maintenance operation')
    descriptor = os.open(ENVIRONMENT, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0:
            raise RuntimeError('unsafe maintenance environment')
        environment = json.load(stream)
    if set(environment) != KEYS or any(not isinstance(v, str) or not v for v in environment.values()):
        raise RuntimeError('invalid maintenance environment')
    os.environ.clear()
    os.environ.update(environment, PATH='/opt/uvm/venv/bin:/usr/local/bin:/usr/bin:/bin',
                      PYTHONPATH='/opt/uvm/app', HOME='/opt/uvm')
    if operation in RECOVERY:
        os.setgroups([])
        os.setgid(1800)
        os.setuid(1800)
    if operation == 'prepare-initial-installation':
        # Supported auth constructor creates only a genuinely empty install.
        # Prepare only when unclaimed; consumed setup never opens on restart.
        import sqlalchemy as sa
        from uvm.auth.local import LocalAuth, load_local_config
        from uvm.auth.maintenance import run
        from uvm.persistence.auth_schema import local_auth_installation
        engine = sa.create_engine(environment['UVM_DB_URL'])
        config = load_local_config()
        LocalAuth(engine, config)
        try:
            with engine.begin() as connection:
                claimed = connection.execute(sa.select(local_auth_installation.c.claimed_at)
                    .where(local_auth_installation.c.singleton_id == 1)).scalar_one()
            if claimed is None:
                run('prepare-setup', config_path='/etc/volt/local-auth.json')
        finally:
            engine.dispose()
        return
    os.execv('/opt/uvm/venv/bin/python', ['python', '-m', 'uvm.auth.maintenance', *sys.argv[1:]])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('protected local maintenance failed', file=sys.stderr)
        raise SystemExit(1) from None
