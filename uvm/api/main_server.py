"""Fixed API-owned main runner; only an actual clean owned teardown returns zero.

The protected root launcher owns the recipe/exec, canonical broker owns waitpid
and clean sealing. This module runs as API UID1800, never as root.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager, nullcontext
import hashlib
import inspect
import os
from pathlib import Path
import signal
import sys
import threading
import time
import warnings

FAILURE_EXIT = 70
KERNEL_SI_USER = 0
CONTROL_SIGNALS = frozenset({signal.SIGTERM, signal.SIGINT})
UVICORN_VERSION = '0.54.0'
UVICORN_SOURCE_HASHES = {
    'server': 'c1be9d133467a42ab88d7168e408ef5a90257661a901899426214a3d1fc2d026',
    'config': 'cf91c6ffae283a2b2020da954b4cc4ed47d3246cb062afd09fb77d98e4c5ca87',
    'lifespan': '8844cf163e921613c33dc75e1b17dae372ca226254ecc2398bb41451ea4170f1',
}


def _boottime():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class _Failure:
    def __init__(self):
        self._lock = threading.Lock()
        self.reason = None
        self.deadline = None
        self.parent_term = False
        self.foreign_signal = None
        self.phase = 'starting'
        self.loop = None
        self.server = None

    def fail(self, reason):
        with self._lock:
            first = self.reason is None
            if first:
                self.reason = reason
        if first:
            # Latch FIRST. A kernel default-fatal alarm survives loop/GIL stalls.
            try:
                self.deadline = _boottime() + 5_000_000_000
                if (signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
                        or signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, set())
                        or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)):
                    os._exit(FAILURE_EXIT)
                signal.setitimer(signal.ITIMER_REAL, 4.0)
            except BaseException:
                os._exit(FAILURE_EXIT)
        self.request_shutdown()

    def request_shutdown(self):
        loop, server = self.loop, self.server
        if loop is not None and server is not None and self.phase not in {'shutdown_returned', 'teardown', 'closed'}:
            try:
                loop.call_soon_threadsafe(server.handle_exit, signal.SIGTERM, None)
            except BaseException:
                # Existing failure is already protected by the fatal timer.
                if self.reason is None:
                    self.fail('signal_dispatch')

    def check_deadline(self):
        if self.deadline is not None and _boottime() >= self.deadline:
            os._exit(FAILURE_EXIT)


class _WarningGuard:
    """Keep RuntimeWarning observable throughout owned shutdown/Runner.close."""
    def __init__(self, state):
        self.state = state
        self.old_show = warnings.showwarning
        self.old_filters = warnings.filters
        self.old_class = warnings.__class__
        self.old_warn = warnings.warn
        self.old_add_filter = warnings._add_filter
        self.filter_lock = getattr(warnings,'_lock',None)
        self.filter_getter = getattr(warnings,'_get_filters',None)
        self.held_mutation = getattr(warnings,'_filters_mutated_lock_held',None)
        if (getattr(sys.flags,'context_aware_warnings',0) != 0
                or getattr(warnings,'_use_context',False)
                or self.filter_lock is not None and not callable(self.held_mutation)):
            raise RuntimeError('main server warning context unsupported')
        if self.active_filters() is not warnings.filters:
            raise RuntimeError('main server warning context unsupported')
        self.entry = ('always', None, RuntimeWarning, None, 0)
        self.sealed = False
        self.filters = [self.entry, *self.old_filters]
        def report(message, category, *args, **kwargs):
            if issubclass(category, RuntimeWarning):state.fail('teardown_warning')
        self.report = report
        def add_filter(*item,append):
            # Python3.14 _py_warnings dispatches through _wm._add_filter,
            # _wm._get_filters and _wm._lock. Preserve that exact lock boundary.
            with self.filter_lock if self.filter_lock is not None else nullcontext():
                filters=self.active_filters();candidate=list(filters)
                if not append:
                    try:candidate.remove(item)
                    except ValueError:pass
                    candidate.insert(0,item)
                elif item not in candidate:candidate.append(item)
                if not self.effective(candidate):
                    self.state.fail('warning_filter_replaced')
                    raise RuntimeError('main server warning guard')
                list.__setitem__(filters,slice(None),candidate)
                if self.filter_lock is not None:self.held_mutation()
                else:warnings._filters_mutated()
        self.add_filter=add_filter
        warnings.showwarning = report
        warnings.filters = self.filters
        warnings._filters_mutated()

    def active_filters(self):
        filters=warnings.filters if self.filter_getter is None else self.filter_getter()
        if filters is not warnings.filters:
            raise RuntimeError('main server warning context unsupported')
        return filters

    def effective(self, value):
        if not isinstance(value, list):return False
        for item in value:
            if not isinstance(item, tuple) or len(item)!=5:return False
            action,message,category,module,lineno=item
            if not isinstance(category,type):return False
            if (action=='always' and message is None and category is RuntimeWarning
                    and module is None and type(lineno) is int and lineno==0):return True
            if (issubclass(RuntimeWarning,category) or issubclass(category,RuntimeWarning)) and action!='always':return False
        return False

    def valid(self):
        try:
            return (warnings.showwarning is self.report and warnings.warn is self.old_warn
                    and warnings._add_filter is (self.add_filter if self.sealed else self.old_add_filter)
                    and getattr(warnings,'_lock',None) is self.filter_lock
                    and getattr(warnings,'_get_filters',None) is self.filter_getter
                    and getattr(warnings,'_filters_mutated_lock_held',None) is self.held_mutation
                    and not getattr(warnings,'_use_context',False)
                    and self.effective(self.active_filters())
                    and (not self.sealed or warnings.__class__ is self.module_class))
        except BaseException:return False

    def seal(self):
        if not self.valid():self.state.fail('warning_guard_replaced')
        if self.sealed:return
        import types
        if warnings.__class__ is not types.ModuleType:
            self.state.fail('warning_module_replaced');return
        guard=self
        class Filters(list):
            def change(self,method,*args,**kwargs):
                candidate=list(self);result=getattr(list,method)(candidate,*args,**kwargs)
                if not guard.effective(candidate):
                    guard.state.fail('warning_filter_replaced')
                    raise RuntimeError('main server warning guard')
                list.__setitem__(self,slice(None),candidate)
                # Standard direct list mutations do not update warning caches.
                # The owning stdlib caller performs its (possibly lock-held)
                # mutation notification; never recursively acquire that lock.
                return result
            def insert(self,*a):return self.change('insert',*a)
            def append(self,*a):return self.change('append',*a)
            def extend(self,*a):return self.change('extend',*a)
            def remove(self,*a):return self.change('remove',*a)
            def pop(self,*a):return self.change('pop',*a)
            def clear(self):return self.change('clear')
            def reverse(self):return self.change('reverse')
            def sort(self,*a,**k):return self.change('sort',*a,**k)
            def __setitem__(self,*a):return self.change('__setitem__',*a)
            def __delitem__(self,*a):return self.change('__delitem__',*a)
            def __iadd__(self,value):self.change('__iadd__',value);return self
            def __imul__(self,value):self.change('__imul__',value);return self
        class OwnedWarnings(types.ModuleType):
            def __setattr__(self,name,value):
                if name=='filters':
                    if not guard.effective(value):
                        guard.state.fail('warning_filter_replaced')
                        raise RuntimeError('main server warning guard')
                    value=Filters(value)
                elif ((name=='showwarning' and value is not guard.report)
                      or (name=='warn' and value is not guard.old_warn)
                      or (name=='_add_filter' and value is not guard.add_filter)
                      or (name=='_lock' and value is not guard.filter_lock)
                      or (name=='_get_filters' and value is not guard.filter_getter)
                      or (name=='_filters_mutated_lock_held' and value is not guard.held_mutation)
                      or (name=='_use_context' and value)
                      or (name=='__class__' and value is not OwnedWarnings)):
                    guard.state.fail('warning_guard_replaced')
                    raise RuntimeError('main server warning guard')
                super().__setattr__(name,value)
        # Known invalidity is already sticky; restore observability for cleanup,
        # never restore clean eligibility after an app attempted suppression.
        current=list(warnings.filters) if isinstance(warnings.filters,list) else []
        warnings.filters=Filters([self.entry,*[x for x in current if x is not self.entry]])
        warnings.showwarning=self.report;warnings.warn=self.old_warn
        warnings._add_filter=self.add_filter
        self.module_class=OwnedWarnings
        warnings.__class__=OwnedWarnings
        self.sealed=True
        warnings._filters_mutated()

    def restore(self):
        import types
        if not self.valid():self.state.fail('warning_guard_replaced')
        types.ModuleType.__setattr__(warnings,'__class__',self.old_class)
        warnings.showwarning=self.old_show;warnings.warn=self.old_warn
        warnings._add_filter=self.old_add_filter
        warnings.filters=self.old_filters
        warnings._filters_mutated()


class _LaunchContext:
    def __init__(self, records, launch):
        self.records = records
        self.launch = launch

    def check(self):
        r = self.records
        with r.locked_store(role='api') as store:
            if store.read_launch() != self.launch:
                r.fail('identity_mismatch')
        r.validate_launch_processes(self.launch, own_api=True)
        if self.launch['recipe'] != r.MAIN_API_RECIPE:
            r.fail('identity_mismatch')


def _wait_launch(records):
    deadline = time.monotonic() + 10
    while True:
        try:
            with records.locked_store(role='api') as store:
                launch = store.read_launch()
            context = _LaunchContext(records, launch)
            context.check()
            return context
        except records.RouteCheckError as exc:
            if exc.code not in {'state_inconsistent', 'process_not_ready'} or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def _production_context():
    from uvm.auth.route_check import _load_records
    return _wait_launch(_load_records())


class _Signals:
    def __init__(self, state, context):
        self.state, self.context = state, context
        self.stop = threading.Event()
        self.heartbeat = time.monotonic()
        self.thread = threading.Thread(target=self._receive, name='uvm-main-signals', daemon=True)
        self.monitor = threading.Thread(target=self._monitor, name='uvm-main-signal-watch', daemon=True)

    def dispatch(self, info):
        try:
            self.context.check()
            broker = self.context.launch['supervisor']
            allowed = (info.si_signo == signal.SIGTERM and info.si_code == KERNEL_SI_USER
                       and info.si_pid == broker['pid'] and info.si_uid == 0)
            if not allowed:
                self.state.foreign_signal = info.si_signo
                self.state.fail('foreign_signal')
                return
            self.state.parent_term = True
            self.state.request_shutdown()
        except BaseException:
            self.state.fail('signal_custody')

    def _receive(self):
        try:
            while not self.stop.is_set():
                self.heartbeat = time.monotonic()
                self.context.check()
                info = signal.sigtimedwait(CONTROL_SIGNALS, 0.1)
                if info is not None:
                    self.dispatch(info)
        except BaseException:
            self.state.fail('signal_coordinator')
        finally:
            if not self.stop.is_set():
                self.state.fail('signal_coordinator_lost')

    def _monitor(self):
        try:
            while not self.stop.wait(0.1):
                self.state.check_deadline()
                if not self.thread.is_alive() or time.monotonic() - self.heartbeat > 2.5:
                    self.state.fail('signal_coordinator_lost')
        except BaseException:
            self.state.fail('signal_monitor')

    def start(self):
        self.thread.start()
        self.monitor.start()

    def close(self):
        self.stop.set()
        deadline = time.monotonic() + 1
        for thread in (self.thread, self.monitor):
            if thread.ident is not None:
                thread.join(max(0, deadline - time.monotonic()))
            if thread.is_alive():
                self.state.fail('signal_join')
        # Standard signals coalesce; bounded drain, never an unbounded flood loop.
        for _ in range(4):
            info = signal.sigtimedwait(CONTROL_SIGNALS, 0)
            if info is None:
                return
            self.dispatch(info)
        self.state.fail('signal_pending')


def _vendor_types(state):
    import uvicorn
    import uvicorn.config
    import uvicorn.server
    import uvicorn.lifespan.on
    if uvicorn.__version__ != UVICORN_VERSION:
        raise RuntimeError('main server unsupported')
    for kind, module in (('server', uvicorn.server), ('config', uvicorn.config), ('lifespan', uvicorn.lifespan.on)):
        if hashlib.sha256(Path(inspect.getfile(module)).read_bytes()).hexdigest() != UVICORN_SOURCE_HASHES[kind]:
            raise RuntimeError('main server unsupported')

    class Lifespan(uvicorn.lifespan.on.LifespanOn):
        async def main(self):
            self.main_task = asyncio.current_task()
            await super().main()
        async def send(self, message):
            if message.get('type') in {'lifespan.startup.failed','lifespan.shutdown.failed'}:
                state.fail('lifespan_reported_failure')
            await super().send(message)

    class Config(uvicorn.Config):
        def load(self):
            super().load()
            application=self.loaded_app
            async def checked_application(scope,receive,send):
                try:
                    await application(scope,receive,send)
                except BaseException:
                    if scope['type']=='lifespan':state.fail('application_lifespan')
                    raise
            self.loaded_app=checked_application
            self.lifespan_class = Lifespan

    class Server(uvicorn.Server):
        def __init__(self, config):
            super().__init__(config)
            self.shutdown_entered = False
            self.shutdown_returned = False
            self.drain_complete = False

        @contextmanager
        def capture_signals(self):
            # Actual kernel siginfo coordinator owns TERM/INT. In particular,
            # never perform Uvicorn's post-grace self-replay of parent TERM.
            yield

        async def _wait_tasks_to_complete(self):
            try:
                await super()._wait_tasks_to_complete()
                self.drain_complete = True
            except BaseException:
                state.fail('task_drain')
                raise

        async def shutdown(self, sockets=None):
            self.shutdown_entered = True
            state.phase = 'shutdown_pending'
            try:
                life=getattr(self,'lifespan',None)
                if (not state.parent_term or self.force_exit or life is None
                        or life.startup_failed or life.shutdown_failed or life.error_occurred):
                    state.fail('shutdown_incomplete')
                state.warning_guard.seal()
                await super().shutdown(sockets)
                self.shutdown_returned = True
                state.phase = 'shutdown_returned'
            except BaseException:
                state.fail('server_shutdown')
                raise

    return Config, Server


async def _serve(state, server, sockets):
    try:
        await server.serve(sockets=sockets)
        life = getattr(server, 'lifespan', None)
        task = getattr(life, 'main_task', None)
        # Known failure must arm independent abort BEFORE an unfinished task
        # await. A successful event does not imply the app task has returned.
        if (not state.parent_term or not server.started or not server.shutdown_entered
                or not server.shutdown_returned or not server.drain_complete or server.force_exit
                or life is None or not life.startup_event.is_set() or not life.shutdown_event.is_set()
                or life.startup_failed or life.shutdown_failed or life.error_occurred or task is None):
            state.fail('lifecycle_incomplete')
        if task is not None:
            await task
        if task is None or not task.done() or task.cancelled() or task.exception() is not None:
            state.fail('lifespan_task_incomplete')
            return False
        return state.reason is None
    except BaseException:
        state.fail('server_failure')
        raise


def _run(context_loader, config_factory, *, sockets=None):
    """Internal dependency seam for labelled source-build fixtures, not CLI input."""
    state = _Failure()
    runner = loop = signals = None
    old_mask = old_handlers = old_exception = warning_guard = None
    provisional = closed = False
    try:
        if (threading.current_thread() is not threading.main_thread()
                or signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
                or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)):
            raise RuntimeError('main server signal state')
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CONTROL_SIGNALS)
        if signal.SIGALRM in old_mask or set(old_mask) & CONTROL_SIGNALS:
            raise RuntimeError('main server signal state')
        old_handlers = {sig: signal.getsignal(sig) for sig in CONTROL_SIGNALS}
        context = context_loader()
        context.check()
        Config, Server = _vendor_types(state)
        runner = asyncio.Runner()
        loop = runner.get_loop()
        old_exception = loop.get_exception_handler()
        def loop_failure(_loop, _context):
            state.fail('loop_failure')
        loop.set_exception_handler(loop_failure)
        warning_guard = _WarningGuard(state)
        state.warning_guard = warning_guard
        server = Server(config_factory(Config))
        state.loop, state.server = loop, server
        signals = _Signals(state, context)
        signals.start()
        provisional = runner.run(_serve(state, server, sockets))
        if loop.get_exception_handler() is not loop_failure or not warning_guard.valid():
            state.fail('guard_replaced')
    except BaseException:
        state.fail('runner_failure')
    finally:
        if runner is not None:
            state.phase = 'teardown'
            try:
                if warning_guard is None:
                    state.fail('warning_guard_unavailable')
                else:
                    if loop.get_exception_handler() is not loop_failure or not warning_guard.valid():state.fail('guard_replaced')
                    warning_guard.seal()
                runner.close()
                closed = loop.is_closed()
                if not closed:
                    state.fail('loop_not_closed')
                if warning_guard is not None and (loop.get_exception_handler() is not loop_failure or not warning_guard.valid()):
                    state.fail('guard_replaced')
            except BaseException:
                state.fail('runner_teardown')
        state.phase = 'closed'
        if signals is not None:
            try:signals.close()
            except BaseException:state.fail('signal_restoration')
        try:
            if warning_guard is not None:
                warning_guard.restore()
            if loop is not None and closed:
                loop.set_exception_handler(old_exception)
            if old_handlers is not None:
                if any(signal.getsignal(sig) != handler for sig, handler in old_handlers.items()):
                    state.fail('handler_replaced')
                for sig, handler in old_handlers.items():signal.signal(sig, handler)
            if old_mask is not None:signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            if provisional and closed and state.reason is None:
                if signal.getsignal(signal.SIGALRM)!=signal.SIG_DFL or signal.getitimer(signal.ITIMER_REAL)!=(0.0,0.0):
                    state.fail('abort_guard_replaced')
                context.check()
        except BaseException:
            state.fail('final_restoration')
    state.check_deadline()
    if state.foreign_signal in CONTROL_SIGNALS:
        # Foreign signal is never normalized into zero; default behavior first.
        signal.raise_signal(state.foreign_signal)
    return 0 if provisional and closed and state.reason is None else FAILURE_EXIT


def run_main(host, port):
    def config(Config):
        return Config('uvm.api.app:app', host=host, port=port, workers=1,
                      proxy_headers=False, lifespan='on', loop='asyncio')
    return _run(_production_context, config)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--workers', type=int, choices=(1,), required=True)
    parser.add_argument('--no-proxy-headers', action='store_true', required=True)
    args = parser.parse_args()
    if not args.host or not 1 <= args.port <= 65535:
        raise SystemExit(FAILURE_EXIT)
    code = run_main(args.host, args.port)
    if code:
        os._exit(code)  # Failure cannot hang in unrelated interpreter finalizers.
    raise SystemExit(0)


if __name__ == '__main__':
    main()
