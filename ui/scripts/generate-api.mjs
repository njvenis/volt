// Type-only generation. Handwritten transports and runtime guards stay authoritative.
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,writeFile,mkdir,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {pathToFileURL} from 'node:url';

const require=createRequire(import.meta.url);
const pins={
 'openapi-types-generator':'1.0.0',
 'json-schema-to-typescript':'13.1.2',
 '@stoplight/json-ref-resolver':'3.1.6',
};
for(const [name,version] of Object.entries(pins)){
 if(require(`${name}/package.json`).version!==version)throw new Error(`API generator requires ${name}@${version}`);
}
const {Resolver}=require('@stoplight/json-ref-resolver');
const {compile}=require('json-schema-to-typescript');
// Version-bound internal API: these three parsers are covered by contract tests.
// The stock CLI concatenates declarations and duplicates shared names. Keep each
// compiler output in its own module, without rewriting declarations or schemas.
const parsers={
 Paths:require('openapi-types-generator/dist/parsers/paths').default,
 Webhooks:require('openapi-types-generator/dist/parsers/webhooks').default,
 Components:require('openapi-types-generator/dist/parsers/components').default,
};
export const repositoryRoot=resolve(import.meta.dirname,'../..');
export const generatedDirectory='ui/src/generated/api';

function assertLocalReferences(value){
 if(value===null||typeof value!=='object')return;
 if('$ref' in value&&(typeof value.$ref!=='string'||!value.$ref.startsWith('#'))){
  throw new Error('API generation accepts only local schema references');
 }
 for(const child of Object.values(value))assertLocalReferences(child);
}

export async function generateTypes(schema){
 assertLocalReferences(schema);
 const resolved=await new Resolver().resolve(schema);
 if(resolved.errors.length)throw new Error(`Schema resolution failed: ${JSON.stringify(resolved.errors)}`);
 const files={};
 for(const [name,parse] of Object.entries(parsers)){
  files[`${name}.ts`]=await compile(parse(resolved.result),name);
 }
 files['index.ts']=Object.keys(parsers).map(name=>`export type {${name}} from './${name}';`).join('\n')+'\n';
 return files;
}

export async function checkArtifacts(root,artifacts){
 const drift=[];
 for(const [name,content] of Object.entries(artifacts)){
  try{if(await readFile(join(root,name),'utf8')!==content)drift.push(name);}
  catch(error){if(error.code==='ENOENT')drift.push(name);else throw error;}
 }
 try{
  for(const name of await readdir(join(root,generatedDirectory),{recursive:true})){
   const relative=`${generatedDirectory}/${name}`;
   if(!(relative in artifacts))drift.push(relative);
  }
 }catch(error){if(error.code!=='ENOENT')throw error;}
 if(drift.length)throw new Error(`Generated API drift: ${drift.join(', ')}. Run npm --prefix ui run generate:api.`);
}

export async function generateApi({check=false}={}){
 const temporary=await mkdtemp(join(tmpdir(),'volt-openapi-'));
 try{
  const schema=join(temporary,'openapi.json');
  const result=spawnSync('uv',['run','--locked','python','tools/export_openapi.py','--output',schema],{cwd:repositoryRoot,encoding:'utf8'});
  if(result.error)throw result.error;
  if(result.status!==0)throw new Error(`Synthetic schema export failed (${result.status}): ${result.stderr}`);
  const schemaText=await readFile(schema,'utf8');
  const declarations=await generateTypes(JSON.parse(schemaText));
  const artifacts={'ui/openapi.json':schemaText,...Object.fromEntries(
   Object.entries(declarations).map(([name,content])=>[`${generatedDirectory}/${name}`,content]))};
  if(check)await checkArtifacts(repositoryRoot,artifacts);
  else{
   // This directory contains generated declarations only; inputs live elsewhere.
   await rm(join(repositoryRoot,generatedDirectory),{recursive:true,force:true});
   for(const [name,content] of Object.entries(artifacts)){
    const target=join(repositoryRoot,name);
    await mkdir(dirname(target),{recursive:true});await writeFile(target,content);
   }
  }
  console.log(check?'Synthetic API schema and types match.':'Generated synthetic API schema and type-only declarations.');
 }finally{await rm(temporary,{recursive:true,force:true});}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args=process.argv.slice(2);
 if(args.length>1||args.some(arg=>arg!=='--check'))throw new Error('Usage: generate-api.mjs [--check]');
 await generateApi({check:args.includes('--check')});
}
