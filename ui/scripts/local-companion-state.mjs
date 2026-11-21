// Private companion inputs/state only. Never include thrown input/error details in output.
import {constants} from 'node:fs';
import {lstat,open,realpath,unlink} from 'node:fs/promises';
import path from 'node:path';
export const exact=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
export const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export function publicOrigin(value){const url=new URL(value);if(url.origin!==value||!['http:','https:'].includes(url.protocol)||url.username||url.password)throw new Error('invalid_origin');return value;}
export async function protectedInput(){let bytes=0;const chunks=[];for await(const chunk of process.stdin){bytes+=chunk.length;if(bytes>65536)throw new Error('input_too_large');chunks.push(Buffer.from(chunk));}return Buffer.concat(chunks).toString('utf8');}
export const MAX_PRIVATE_BYTES=1048576;
const identity=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
function regular(info){if(!info.isFile()||info.nlink!==1||(info.mode&0o777)!==0o600||info.uid!==process.getuid()||info.size>MAX_PRIVATE_BYTES)throw new Error('private_file_required');}
async function parent(file){
 const absolute=path.resolve(file),name=path.basename(absolute),directory=path.dirname(absolute),canonical=await realpath(directory);
 // Native Linux companion: anchor all child opens to the admitted directory fd.
 // Reject ancestor aliases too, rather than following them on later writes.
 if(canonical!==directory)throw new Error('canonical_private_parent_required');
 const handle=await open(canonical,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const info=await handle.stat();if(!info.isDirectory()||(info.mode&0o777)!==0o700||info.uid!==process.getuid()||!identity(info,await lstat(directory)))throw new Error('private_directory_required');return {handle,info,directory,name,absolute,anchored:'/proc/self/fd/'+handle.fd+'/'+name};}catch(error){await handle.close();throw error;}
}
async function currentParent(p){const info=await lstat(p.directory);if(!identity(info,p.info)||!info.isDirectory()||(info.mode&0o777)!==0o700||info.uid!==process.getuid()||await realpath(p.directory)!==p.directory)throw new Error('private_parent_changed');}
async function entry(p){try{return await lstat(p.anchored);}catch(error){if(error.code==='ENOENT')return null;throw error;}}
export async function privateDestination(file){const p=await parent(file);try{if(await entry(p))throw new Error('private_destination_exists');await currentParent(p);}finally{await p.handle.close();}}
// Admit every destination together and hold its exact fd before any login/upload.
export async function privateOutputs(specs){
 const admitted=[];let closed=false;
 async function close(){if(closed)return;closed=true;for(const p of admitted){if(p.fileHandle){if(p.created&&!p.written){try{if(identity(await p.fileHandle.stat(),await lstat(p.anchored)))await unlink(p.anchored);}catch{}}await p.fileHandle.close();}await p.handle.close();}}
 try{
  for(const spec of specs){const p=await parent(spec.file);admitted.push({...p,replace:spec.replace===true});}
  if(new Set(admitted.map(p=>p.absolute)).size!==admitted.length)throw new Error('private_output_alias');
  for(const p of admitted){p.previous=await entry(p);if(p.previous){regular(p.previous);if(!p.replace)throw new Error('private_destination_exists');}}
  for(let i=0;i<admitted.length;i++)for(let j=0;j<i;j++)if(admitted[i].previous&&admitted[j].previous&&identity(admitted[i].previous,admitted[j].previous))throw new Error('private_output_alias');
  for(const p of admitted){await currentParent(p);p.fileHandle=await open(p.anchored,constants.O_WRONLY|constants.O_NONBLOCK|constants.O_NOFOLLOW|(p.previous?0:constants.O_CREAT|constants.O_EXCL),0o600);p.infoFile=await p.fileHandle.stat();regular(p.infoFile);if(p.previous&&!identity(p.previous,p.infoFile))throw new Error('private_file_changed');p.created=!p.previous;if(!identity(p.infoFile,await lstat(p.anchored)))throw new Error('private_file_changed');}
  return {async write(index,value){
   if(closed||!admitted[index]||typeof value!=='string'||Buffer.byteLength(value)>MAX_PRIVATE_BYTES)throw new Error('invalid_private_write');const p=admitted[index];await currentParent(p);const before=await p.fileHandle.stat();regular(before);if(!identity(before,p.infoFile)||!identity(before,await lstat(p.anchored))||(!p.written&&p.previous&&(before.size!==p.previous.size||before.mtimeMs!==p.previous.mtimeMs||before.ctimeMs!==p.previous.ctimeMs)))throw new Error('private_file_changed');
   await p.fileHandle.truncate(0);await p.fileHandle.writeFile(value);await p.fileHandle.sync();const after=await p.fileHandle.stat();regular(after);if(!identity(after,p.infoFile)||!identity(after,await lstat(p.anchored))||after.size!==Buffer.byteLength(value))throw new Error('private_file_changed');await currentParent(p);p.written=true;
  },close};
 }catch(error){await close();throw error;}
}
export async function privateWrite(file,value,{replace=false}={}){const outputs=await privateOutputs([{file,replace}]);try{await outputs.write(0,value);}finally{await outputs.close();}}
export async function readPrivateDescriptor(handle){
 const before=await handle.stat();regular(before);const buffer=Buffer.alloc(MAX_PRIVATE_BYTES+1);let total=0;
 while(total<buffer.length){const {bytesRead}=await handle.read(buffer,total,buffer.length-total,total);if(!bytesRead)break;total+=bytesRead;}
 const after=await handle.stat();regular(after);if(total>MAX_PRIVATE_BYTES||!identity(before,after)||before.size!==after.size||total!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw new Error('private_file_changed');
 return JSON.parse(buffer.subarray(0,total).toString('utf8'));
}
export async function privateRead(file){const p=await parent(file);let handle;try{
 const previous=await entry(p);if(!previous)throw new Error('private_file_missing');regular(previous);
 handle=await open(p.anchored,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const info=await handle.stat();regular(info);if(!identity(info,previous)||!identity(info,await lstat(p.anchored)))throw new Error('private_file_changed');
 const value=await readPrivateDescriptor(handle);await currentParent(p);if(!identity(await handle.stat(),await lstat(p.anchored)))throw new Error('private_file_changed');return value;
 }finally{await handle?.close();await p.handle.close();}}
export const SAVED_SESSION_MARGIN_SECONDS=120;
export function cookieLifetime(state,margin=0){const expires=state?.storage_state?.cookies?.[0]?.expires;if(!Number.isFinite(expires)||expires-Date.now()/1000<=margin)throw new Error('saved_cookie_expired_or_expiring');}
export async function restoredSessionDenied(page,state,origin){
 cookieLifetime(state,30);
 const response=await page.goto(origin+'/api/v1/auth/session',{waitUntil:'domcontentloaded',timeout:15000});
 if(!response)throw new Error('session_response_missing');const request=response.request();const headers=await request.allHeaders();
 const pairs=(headers.cookie??'').split(';').map(v=>v.trim()).filter(v=>v.startsWith('uvm_session='));
 if(request.url()!==origin+'/api/v1/auth/session'||request.method()!=='GET'||request.redirectedFrom()||pairs.length!==1||pairs[0].slice('uvm_session='.length)!==state.storage_state.cookies[0].value)throw new Error('captured_cookie_not_sent');
 cookieLifetime(state);const result={status:response.status(),body:await response.json()};cookieLifetime(state);
 if(!authenticationDenied(result))throw new Error('saved_session_not_rejected');return result;
}
export function savedSession(value,origin){
 if(!exact(value,['schema_version','kind','origin','captured_at','principal_id','storage_state'])||value.schema_version!==1||value.kind!=='local_browser_session'||value.origin!==origin||!uuid(value.principal_id)||!Number.isFinite(Date.parse(value.captured_at))||Date.parse(value.captured_at)>Date.now()||!exact(value.storage_state,['cookies','origins'])||!Array.isArray(value.storage_state.origins)||value.storage_state.origins.length!==0||!Array.isArray(value.storage_state.cookies)||value.storage_state.cookies.length!==1)throw new Error('invalid_saved_session');
 const cookie=value.storage_state.cookies[0];if(!exact(cookie,['name','value','domain','path','expires','httpOnly','secure','sameSite'])||cookie.name!=='uvm_session'||typeof cookie.value!=='string'||!cookie.value||cookie.value.length>256||cookie.domain!==new URL(origin).hostname||cookie.path!=='/'||typeof cookie.expires!=='number'||cookie.expires<=Date.now()/1000||cookie.httpOnly!==true||cookie.secure!==(new URL(origin).protocol==='https:')||cookie.sameSite!=='Lax')throw new Error('invalid_saved_session');cookieLifetime(value,SAVED_SESSION_MARGIN_SECONDS);return value;
}
export function recoveryState(value,origin){if(!exact(value,['schema_version','kind','origin','principal_id','connector_id','source_id','source_tuple','secret_id','version_id','recovery_epoch_id','configuration_revision'])||value.schema_version!==1||value.kind!=='scanner_recovery'||value.origin!==origin||!['principal_id','connector_id','source_id','secret_id','version_id','recovery_epoch_id'].every(k=>uuid(value[k]))||!exact(value.source_tuple,['source_family','source_account_id','scope_key'])||value.source_tuple.source_family!=='qualys'||!uuid(value.source_tuple.source_account_id)||!uuid(value.source_tuple.scope_key)||!Number.isSafeInteger(value.configuration_revision)||value.configuration_revision<1)throw new Error('invalid_recovery_state');return value;}
export function authenticationDenied(response){return response.status===401&&exact(response.body,['schema_version','error'])&&response.body.schema_version===1&&exact(response.body.error,['code','message','correlation_id','details'])&&response.body.error.code==='authentication_required'&&response.body.error.message==='Authentication required'&&uuid(response.body.error.correlation_id)&&exact(response.body.error.details,[]);}
