// Type-only generation. Handwritten transports and runtime guards remain authoritative.
import {createClient} from '@hey-api/openapi-ts';
import {spawnSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,mkdir,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export const repositoryRoot=resolve(import.meta.dirname,'../..');
export async function generateTypes(input,output){
 await createClient({input,output:{path:output,indexFile:false},plugins:[{name:'@hey-api/typescript',enums:false}],logs:{level:'error',file:false}});
 const files=await readdir(output);
 if(files.length!==1||files[0]!=='types.gen.ts')throw new Error('Expected only generated TypeScript declarations');
 return readFile(join(output,'types.gen.ts'),'utf8');
}
export async function checkArtifacts(root,artifacts){
 const drift=[];
 for(const [name,content] of Object.entries(artifacts)){
  try{if(await readFile(join(root,name),'utf8')!==content)drift.push(name);}
  catch(error){if(error.code==='ENOENT')drift.push(name);else throw error;}
 }
 if(drift.length)throw new Error(`Generated API drift: ${drift.join(', ')}. Run npm --prefix ui run generate:api.`);
}
export async function generateApi({check=false}={}){
 const temporary=await mkdtemp(join(tmpdir(),'volt-openapi-'));
 try{
  const schema=join(temporary,'openapi.json');
  const result=spawnSync('uv',['run','--locked','python','tools/export_openapi.py','--output',schema],{cwd:repositoryRoot,encoding:'utf8'});
  if(result.error)throw result.error;
  if(result.status!==0)throw new Error(`Synthetic schema export failed (${result.status}): ${result.stderr}`);
  const artifacts={
   'ui/openapi.json':await readFile(schema,'utf8'),
   'ui/src/generated/api/types.gen.ts':await generateTypes(schema,join(temporary,'types')),
  };
  if(check)await checkArtifacts(repositoryRoot,artifacts);
  else for(const [name,content] of Object.entries(artifacts)){
   const target=join(repositoryRoot,name);await mkdir(resolve(target,'..'),{recursive:true});await writeFile(target,content);
  }
  console.log(check?'Synthetic API schema and types match.':'Generated synthetic API schema and type-only declarations.');
 }finally{await rm(temporary,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args=process.argv.slice(2);
 if(args.length>1||args.some(arg=>arg!=='--check'))throw new Error('Usage: generate-api.mjs [--check]');
 await generateApi({check:args.includes('--check')});
}
