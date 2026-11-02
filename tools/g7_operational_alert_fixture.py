#!/usr/bin/env python3
"""Private HTTPS provider fixture for operational-alert development journeys."""
from __future__ import annotations
import argparse, json, ssl, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,output,token,channel,scenario):
        super().__init__(address,Handler); self.output=Path(output); self.token=token; self.channel=channel; self.scenario=scenario; self.rows=[]; self.hit_count=0; self.lock=threading.Lock()
    def retain(self,row):
        with self.lock:
            self.rows.append(row); tmp=self.output.with_suffix('.tmp'); tmp.write_text(json.dumps(self.rows,sort_keys=True,separators=(',',':'))+'\n'); tmp.replace(self.output)
class Handler(BaseHTTPRequestHandler):
    server: Server
    def log_message(self,*_): return
    def do_GET(self):
        if self.path!='/healthz': self.send_error(404); return
        self.send_response(200); self.end_headers(); self.wfile.write(b'ready\n')
    def do_POST(self):
        if self.path!='/api/chat.postMessage': self.send_error(404); return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=65536: raise ValueError
            raw=self.rfile.read(size); body=json.loads(raw)
            if self.headers.get('Authorization')!='Bearer '+self.server.token or not isinstance(body,dict) or body.get('channel')!=self.server.channel or not isinstance(body.get('text'),str): raise ValueError
        except Exception: self.send_error(400); return
        self.server.retain({'channel':body['channel'],'body':body,'auth_verified':True})
        with self.server.lock:
            self.server.hit_count+=1
            hit=self.server.hit_count
        if self.server.scenario=='accepted_response_lost':
            self.close_connection=True; self.connection.shutdown(2); self.connection.close(); return
        if self.server.scenario=='rate_limited':
            self.send_response(429); self.send_header('Retry-After','1'); self.end_headers(); return
        if self.server.scenario=='rate_limited_once' and hit==1:
            self.send_response(429); self.send_header('Retry-After','0'); self.end_headers(); return
        if self.server.scenario=='permanent_rejection': self.send_response(403); self.end_headers(); return
        answer=json.dumps({'ok':True,'channel':self.server.channel,'ts':'1720000000.000001'},separators=(',',':')).encode()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(answer))); self.end_headers(); self.wfile.write(answer)
def main():
    p=argparse.ArgumentParser(); p.add_argument('--host',default='127.0.0.1'); p.add_argument('--port',type=int,required=True); p.add_argument('--output',required=True); p.add_argument('--token-file',required=True); p.add_argument('--channel',required=True); p.add_argument('--cert',required=True); p.add_argument('--key',required=True); p.add_argument('--scenario',choices=('accepted','rate_limited','rate_limited_once','permanent_rejection','accepted_response_lost'),default='accepted'); a=p.parse_args()
    s=Server((a.host,a.port),a.output,Path(a.token_file).read_text().strip(),a.channel,a.scenario); ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(a.cert,a.key); s.socket=ctx.wrap_socket(s.socket,server_side=True); print(json.dumps({'ready':True,'tls':True,'host':a.host,'port':a.port}),flush=True)
    try:s.serve_forever(poll_interval=.2)
    finally:s.server_close()
if __name__=='__main__': main()
