#!/usr/local/bin/python3.14
"""Build/component audit of the ONE protected root Python import closure."""
import ast
import importlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

DIRECTORY=Path('/usr/local/lib/volt-private')
FILES={
 '/opt/uvm/app/uvm/auth/route_check_records.py':DIRECTORY/'volt_route_check_records.py',
 '/opt/uvm/app/uvm/installer/route_check.py':DIRECTORY/'volt_route_check_control.py'}
SCRIPTS=(Path('/usr/local/libexec/volt-main-api-launcher.py'),
 Path('/usr/local/libexec/volt-route-check-control.py'),
 Path('/usr/local/libexec/volt-terminal-write.py'),
 Path('/usr/local/libexec/volt-main-api-completion.py'),
 Path('/usr/local/libexec/volt-start-admission.py'))
SCRIPT_COPIES={
 '/opt/uvm/app/uvm/installer/terminal_write.py':SCRIPTS[2],
 '/opt/uvm/app/uvm/installer/terminal_completion.py':SCRIPTS[3],
 '/opt/uvm/app/uvm/installer/start_admission.py':SCRIPTS[4]}


def protected(path):
    for part in (path,*path.parents):
        value=part.lstat()
        if value.st_uid!=0 or value.st_mode&0o022 or part.is_symlink():raise RuntimeError('unsafe protected Python path')


def audit():
    if not(sys.flags.isolated and sys.flags.no_site):raise RuntimeError('isolated root import required')
    if os.geteuid()!=0:raise RuntimeError('root build audit required')
    protected(Path('/usr/local/bin/python3.14'))
    for source,destination in FILES.items():
        protected(destination)
        if Path(source).read_bytes()!=destination.read_bytes():raise RuntimeError('protected canonical COPY differs')
        if stat.S_IMODE(destination.stat().st_mode)!=0o644:raise RuntimeError('protected module mode differs')
    for script in SCRIPTS:
        protected(script)
        if stat.S_IMODE(script.stat().st_mode)!=0o755:raise RuntimeError('protected entry script mode differs')
    for source,destination in SCRIPT_COPIES.items():
        if Path(source).read_bytes()!=destination.read_bytes():raise RuntimeError('protected adapter COPY differs')
    for path in (*FILES.values(),*SCRIPTS):
        for node in ast.walk(ast.parse(path.read_bytes())):
            if isinstance(node,ast.Import):names=[item.name.split('.')[0]for item in node.names]
            elif isinstance(node,ast.ImportFrom):
                if node.level:raise RuntimeError('relative protected import is forbidden')
                names=[(node.module or'').split('.')[0]]
            else:continue
            if any(name not in sys.stdlib_module_names and name not in
                    {'__future__','volt_route_check_records','volt_route_check_control'}for name in names):
                raise RuntimeError('nonstdlib protected import')
    sys.path.insert(0,str(DIRECTORY))
    for name in ('volt_route_check_records','volt_route_check_control'):importlib.import_module(name)
    spec=importlib.util.spec_from_file_location('volt_broker_audited',SCRIPTS[0])
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for index,path in enumerate(SCRIPTS[2:]):
        spec=importlib.util.spec_from_file_location('volt_terminal_audited_'+str(index),path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for name,module in tuple(sys.modules.items()):
        if name.split('.')[0]in {'uvm','sqlalchemy','site','sitecustomize','usercustomize'}:
            raise RuntimeError('root imported application/site module')
        file=getattr(module,'__file__',None)
        if file:
            path=Path(file)
            if 'site-packages'in path.parts or path.is_relative_to('/opt/uvm'):
                raise RuntimeError('root loaded API-owned code')
            protected(path)
    print('protected_canonical_copy=identical root_import_closure=stdlib_only')


if __name__=='__main__':audit()
