"""Linux/x86_64 owned-process siginfo forgery diagnosis, no production policy."""
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import tempfile
import unittest

TARGET=r'''
import json,os,signal
signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM})
print('ready',flush=True)
for _ in range(2):
 info=signal.sigtimedwait({signal.SIGTERM},5)
 assert info is not None
 print(json.dumps({'si_signo':info.si_signo,'si_code':info.si_code,'si_pid':info.si_pid,'si_uid':info.si_uid,'target_uid':os.getuid()}),flush=True)
'''
FORGER=r'''
import ctypes,json,os,signal,sys
# Linux x86_64 /usr/include/.../asm/unistd_64.h: rt_sigqueueinfo=129.
# asm-generic/siginfo.h: 128-byte siginfo, SI_QUEUE=-1, SI_USER=0.
class SigInfo(ctypes.Structure):
 _fields_=[('signo',ctypes.c_int),('error',ctypes.c_int),('code',ctypes.c_int),('align',ctypes.c_int),
           ('pid',ctypes.c_int),('uid',ctypes.c_uint),('value',ctypes.c_ulonglong),('padding',ctypes.c_ubyte*96)]
assert ctypes.sizeof(SigInfo)==128
info=SigInfo();info.signo=signal.SIGTERM;info.code=-1;info.pid=int(sys.argv[2]);info.uid=0
libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
result=libc.syscall(ctypes.c_long(129),ctypes.c_int(int(sys.argv[1])),ctypes.c_int(signal.SIGTERM),ctypes.byref(info))
assert result==0,ctypes.get_errno()
print(json.dumps({'actual_forger_pid':os.getpid(),'actual_forger_uid':os.getuid(),'forged_pid':info.pid,'forged_uid':info.uid,'syscall_result':result}),flush=True)
'''


@unittest.skipUnless(os.geteuid()==0 and platform.machine()=='x86_64','owned root/UID1800 x86_64 syscall fixture')
class SignalSenderCustodyTests(unittest.TestCase):
    def test_queue_can_forge_root_broker_pid_uid_but_not_kernel_si_user(self):
        with tempfile.TemporaryFile() as stderr:
            target=subprocess.Popen(['setpriv','--reuid=1800','--regid=1800','--clear-groups','/usr/bin/python3','-u','-c',TARGET],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=stderr,text=True)
            pidfd=os.pidfd_open(target.pid)
            def line():
                self.assertTrue(select.select([target.stdout],[],[],5)[0],'owned target timeout')
                return target.stdout.readline().strip()
            try:
                self.assertEqual(line(),'ready')
                signal.pidfd_send_signal(pidfd,signal.SIGTERM) # null siginfo kernel SI_USER.
                genuine=json.loads(line())
                forger=subprocess.run(['setpriv','--reuid=1800','--regid=1800','--clear-groups','/usr/bin/python3','-u','-c',FORGER,str(target.pid),str(os.getpid())],
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5,check=True)
                actual=json.loads(forger.stdout);forged=json.loads(line())
                self.assertEqual(target.wait(timeout=5),0)
                self.assertEqual(genuine['si_code'],0)
                self.assertEqual((genuine['si_pid'],genuine['si_uid']),(os.getpid(),0))
                self.assertEqual((forged['si_pid'],forged['si_uid']),(os.getpid(),0))
                self.assertEqual(forged['si_code'],-1)
                self.assertEqual(actual['actual_forger_uid'],1800)
                self.assertNotEqual(actual['actual_forger_pid'],os.getpid())
                self.assertEqual(forged['target_uid'],1800)
                result={'genuine_pidfd_null_info':genuine,'forged_queued':forged,'actual_forger':actual,
                    'pid_uid_only_would_accept_forgery':True,'si_user_zero_rejects_forgery':True,
                    'scope':'owned root parent/UID1800 target+forger; Linuxx86_64 kernelproof, not image runner'}
                print(json.dumps(result,sort_keys=True),flush=True)
                evidence=os.environ.get('UVM_SIGNAL_CUSTODY_EVIDENCE_DIR')
                if evidence:
                    out=Path(evidence);out.mkdir(parents=True,exist_ok=True)
                    (out/'siginfo-forgery.json').write_text(json.dumps(result,indent=2)+'\n')
                    (out/'forger.stderr').write_text(forger.stderr)
            finally:
                if target.poll() is None:
                    signal.pidfd_send_signal(pidfd,signal.SIGKILL);target.wait(timeout=5)
                os.close(pidfd);target.stdout.close()
