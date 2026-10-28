from pathlib import Path
import json,hashlib,os
import sys
import re
root=Path(sys.argv[1]); manifest_path=root/'credential-redaction-manifest.json'
try: manifest=json.loads(manifest_path.read_text())
except (OSError,ValueError): manifest=[]
if not isinstance(manifest,list):raise ValueError('redaction_manifest_invalid')
new_count=0
uri_credentials=re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@:\s]+):([^/@\s]+)@')
for path in root.rglob('*.json'):
 try: raw=path.read_bytes(); doc=json.loads(raw)
 except (ValueError,OSError): continue
 changes=[]
 def uri(value,where):
  updated=uri_credentials.sub(lambda m:m.group(0) if m.group(3)=='[REDACTED]' else m.group(1)+m.group(2)+':[REDACTED]@',value)
  if updated!=value:changes.append({'field':where,'value_sha256':hashlib.sha256(value.encode()).hexdigest()})
  return updated
 def scrub(v,where):
  if isinstance(v,dict):
   for k,x in v.items():
    if any(t in k.lower() for t in ('token','password','secret','credential')) and isinstance(x,str) and x and x!='[REDACTED]':
     changes.append({'field':where+'.'+k,'value_sha256':hashlib.sha256(x.encode()).hexdigest()}); v[k]='[REDACTED]'
    elif isinstance(x,str):v[k]=uri(x,where+'.'+k)
    else: scrub(x,where+'.'+k)
  elif isinstance(v,list):
   for i,x in enumerate(v):
    if isinstance(x,str):v[i]=uri(x,where+f'[{i}]')
    else:scrub(x,where+f'[{i}]')
 def walk(v):
  if isinstance(v,dict):
   for k,x in v.items():
    if k=='Env' and isinstance(x,list):
     for i,item in enumerate(x):
      if not isinstance(item,str) or '=' not in item: continue
      name,value=item.split('=',1)
      try: inner=json.loads(value)
      except ValueError: inner=None
      if isinstance(inner,(dict,list)):
       before=len(changes); scrub(inner,name)
       if len(changes)>before: x[i]=name+'='+json.dumps(inner,separators=(',',':'))
      elif any(t in name.upper() for t in ('TOKEN','PASSWORD','SECRET','CREDENTIAL')) and value and value!='[REDACTED]':
       changes.append({'field':name,'value_sha256':hashlib.sha256(value.encode()).hexdigest()}); x[i]=name+'=[REDACTED]'
      else:x[i]=name+'='+uri(value,name)
    else: walk(x)
  elif isinstance(v,list):
   for x in v: walk(x)
 walk(doc)
 if changes:
  redacted=(json.dumps(doc,indent=2)+'\n').encode(); path.write_bytes(redacted)
  new_count+=1
  manifest.append({'path':str(path.relative_to(root)),'original_sha256':hashlib.sha256(raw).hexdigest(),'redacted_sha256':hashlib.sha256(redacted).hexdigest(),'fields':changes})
p=manifest_path; p.write_text(json.dumps(manifest,indent=2)+'\n'); os.chmod(p,0o600)
print('Redacted artifacts:',new_count)
