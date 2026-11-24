"""API-owned routing observation; authority primitives load the protected copy."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time
import types

PROTECTED_RECORDS_PATH = Path('/usr/local/lib/volt-private/volt_route_check_records.py')
_RECORDS = None


def _protected_source():
    # Fixed production path; no source-tree, environment or package fallback.
    path=PROTECTED_RECORDS_PATH
    parent=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(parent)
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o755:raise RuntimeError('protected route records unavailable')
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=child;info=os.fstat(parent)
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o755:raise RuntimeError('protected route records unavailable')
        descriptor=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0
                    or stat.S_IMODE(before.st_mode)!=0o644 or before.st_nlink!=1 or not 0<before.st_size<=131072):
                raise RuntimeError('protected route records unavailable')
            raw=os.read(descriptor,131073)
            def identity(item):return tuple(getattr(item,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
            if (len(raw)!=before.st_size or identity(before)!=identity(os.fstat(descriptor))
                    or identity(before)!=identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))):
                raise RuntimeError('protected route records unavailable')
            return raw
        finally:os.close(descriptor)
    finally:os.close(parent)


def _load_records():
    global _RECORDS
    if _RECORDS is None:
        raw=_protected_source()
        module=types.ModuleType('volt_route_check_records')
        module.__file__=str(PROTECTED_RECORDS_PATH)
        # Execute the SAME protected bytes used by root, no API package import.
        exec(compile(raw,str(PROTECTED_RECORDS_PATH),'exec'),module.__dict__)
        _RECORDS=module
    return _RECORDS


class _Observer:
    @property
    def records(self):return _load_records()
    def __init__(self,service):
        self.service=service;self.boot=None;self.cached=None;self.tokens=10.;self.refill=time.monotonic()
    def _binding(self,connection,installation_row,arm=None):
        if not installation_row or installation_row['installation_id']!=self.service.config['installation_id']:self.records.fail('identity_mismatch')
        from uvm.connectors.local_recovery import load_authority,validate_binding
        authority=load_authority(self.service.config)
        binding=validate_binding(connection,authority,initialize=False,require_applied=True)
        if arm and (arm['installation_id']!=authority.installation_id or arm['journal_id']!=authority.fence['journal_id']
                or arm['restore_generation']!=authority.fence['restore_generation'] or arm['recovery_epoch_id']!=authority.fence['recovery_epoch_id']
                or arm['public_origin']!=self.service.config['public_origin']):self.records.fail('identity_mismatch')
        return binding
    def start(self):
        from uvm.persistence.auth_schema import local_auth_installation
        with self.service.engine.begin() as connection:
            row=connection.execute(__import__('sqlalchemy').select(local_auth_installation).where(local_auth_installation.c.singleton_id==1)).mappings().one()
            self._binding(connection,row)
        deadline=time.monotonic()+10
        while True:
            try:
                with self.records.locked_store(role='api') as store:
                    supervisor=store.read_supervisor();identity=self.records.validate_supervision(supervisor,require_ready=False,own_api=True)
                    state=store.read_state()
                    if state['state']!='disarmed' or store.read_seen() is not None:self.records.fail('state_inconsistent')
                    self.boot=self.records.record(runtime_boot_nonce=self.records.new_nonce(),api=identity,published_boottime_ns=self.records.boottime_ns(),ready=True,loaded_operation_id=None)
                    store.publish_boot(self.boot)
                return
            except self.records.RouteCheckError as exc:
                if exc.code not in {'process_not_ready','state_inconsistent'} or time.monotonic()>=deadline:raise
                time.sleep(0.05)
    def refresh(self):
        try:
            with self.records.locked_store(role='api') as store:
                supervisor=store.read_supervisor();self.records.validate_supervision(supervisor,own_api=True)
                disk=store.read_boot()
                if disk!=self.boot or not self.boot['ready']:self.records.fail('state_inconsistent')
                state=store.read_state();arm=state['arm'] if state['state']=='armed' else None
                if arm:
                    self.records.check_fresh(arm)
                    if arm['api']!=self.boot['api'] or arm['runtime_boot_nonce']!=self.boot['runtime_boot_nonce'] or arm['issued_boottime_ns']<self.boot['published_boottime_ns']:self.records.fail('identity_mismatch')
                updated={**self.boot,'loaded_operation_id':arm['operation_id'] if arm else None}
                if updated!=self.boot:store.publish_boot(updated);self.boot=updated
                self.cached=arm
        except Exception:
            self.cached=None
    async def poll(self):
        while True:
            await asyncio.to_thread(self.refresh)
            await asyncio.sleep(0.1)
    def stop(self):
        self.cached=None
        if self.boot:
            with self.records.locked_store(role='api') as store:
                if store.read_boot()!=self.boot:self.records.fail('state_inconsistent')
                self.boot={**self.boot,'ready':False,'loaded_operation_id':None};store.publish_boot(self.boot)
    def observe(self,request,connection,row):
        arm=self.cached
        raw=[v for k,v in request.scope.get('headers',()) if k.lower()==b'x-volt-route-challenge']
        valid=False
        if len(raw)==1 and len(raw[0])==43:
            try:value=raw[0].decode('ascii');self.records._nonce(value);valid=True
            except (UnicodeError,self.records.RouteCheckError):pass
        if (request.method!='GET' or request.url.path!='/api/v1/auth/config' or request.url.query
                or request.headers.get('cookie') or request.headers.get('authorization')
                or request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding')):return
        if not valid or arm is None or not hmac.compare_digest(value,arm['challenge']):
            now=time.monotonic();self.tokens=min(10.,self.tokens+max(0,now-self.refill)*10);self.refill=now
            if self.tokens>=1:self.tokens-=1
            return
        deadline=time.monotonic()+2
        with self.records.locked_store(role='api') as store:
            self.records.validate_supervision(store.read_supervisor(),own_api=True)
            if store.read_boot()!=self.boot or not self.boot['ready']:self.records.fail('process_not_ready')
            state=store.read_state()
            if state['state']!='armed' or state['arm']!=arm or store.read_seen() is not None:self.records.fail('operation_conflict')
            self.records.check_fresh(arm)
            remaining=max(0,int((deadline-time.monotonic())*1000))
            if remaining<1:self.records.fail('process_not_ready')
            connection.exec_driver_sql("SET LOCAL lock_timeout = '"+str(remaining)+"ms'")
            connection.exec_driver_sql("SET LOCAL statement_timeout = '"+str(remaining)+"ms'")
            self._binding(connection,row,arm)
            self.records.check_fresh(arm)
            seen=self.records.record(operation_id=arm['operation_id'],runtime_boot_nonce=self.boot['runtime_boot_nonce'],api=self.boot['api'],
                challenge_sha256=hashlib.sha256(value.encode()).hexdigest(),observed_utc_ns=time.time_ns(),observed_boottime_ns=self.records.boottime_ns())
            self.records.validate_observation(arm,seen);store.publish_seen(seen)


def observe_config(request,*,local_auth,connection,installation_row)->None:
    observer=getattr(local_auth,'_route_check_observer',None)
    if observer is not None:
        try:observer.observe(request,connection,installation_row)
        except Exception:pass  # This subsystem MUST NOT change the public wire or log a nonce.


def install_main_route_check(app,local_auth)->None:
    from uvm.auth.local import LocalAuth
    if (not isinstance(local_auth,LocalAuth) or local_auth.config['trusted_ingress']['mode']!='https'
            or os.environ.get('UVM_G7_VERIFICATION_ONLY','0')=='1'
            or os.environ.get('UVM_G7_RECOVERY_CONTROL_ONLY','0')=='1'):return
    _load_records()._origin(local_auth.config['public_origin'])
    observer=_Observer(local_auth);local_auth._route_check_observer=observer
    previous=app.router.lifespan_context
    @asynccontextmanager
    async def outermost(application):
        async with previous(application) as state:
            await asyncio.to_thread(observer.start)
            task=asyncio.create_task(observer.poll())
            try:yield state
            finally:
                task.cancel()
                try:await task
                except asyncio.CancelledError:pass
                await asyncio.to_thread(observer.stop)
    app.router.lifespan_context=outermost
