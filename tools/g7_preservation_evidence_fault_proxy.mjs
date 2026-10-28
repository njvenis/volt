import http from 'node:http';
import process from 'node:process';

const args=process.argv;function arg(name){const i=args.indexOf(name);if(i<0||!args[i+1])throw new Error(`missing ${name}`);return args[i+1];}
const port=Number(arg('--listen')),upstream=Number(arg('--upstream'));
let evidenceRequests=0,snapshotRequests=0;
const server=http.createServer((request,response)=>{
 if(request.url==='/healthz'){response.writeHead(200,{'content-type':'text/plain'});response.end('ready');return;}
 if(request.url==='/__g7_fault_status'){response.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});response.end(JSON.stringify({evidence_requests:evidenceRequests,snapshot_requests:snapshotRequests}));return;}
 if(request.method==='GET'&&request.url.startsWith('/api/v1/operations/preservation/evidence/')){
  evidenceRequests++;
  response.writeHead(503,{'content-type':'application/json','cache-control':'no-store'});
  response.end('{"detail":{"code":"dependency_unavailable"}}');return;
 }
 if(request.method==='POST'&&request.url==='/internal/g7/preservation/source-snapshot')snapshotRequests++;
 const headers={...request.headers,host:`127.0.0.1:${upstream}`};
 const forwarded=http.request({hostname:'127.0.0.1',port:upstream,path:request.url,method:request.method,headers},upstreamResponse=>{
  response.writeHead(upstreamResponse.statusCode??502,upstreamResponse.headers);upstreamResponse.pipe(response);
 });
 forwarded.on('error',()=>{if(!response.headersSent)response.writeHead(502);response.end();});
 request.pipe(forwarded);
});
server.listen(port,'127.0.0.1');
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>server.close(()=>process.exit(0)));
