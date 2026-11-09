// Synthetic OpenAPI contracts only. No external service or live data is used.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,mkdir,rm} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {generateTypes,checkArtifacts,generatedDirectory,repositoryRoot} from '../scripts/generate-api.mjs';

const schema=JSON.parse(await readFile(new URL('./fixtures/api-generator-contract.json',import.meta.url),'utf8'));
async function temporary(t){
 const directory=await mkdtemp(join(tmpdir(),'volt-api-types-test-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));return directory;
}
async function writeArtifacts(directory,files){
 for(const [name,content] of Object.entries(files)){
  const path=join(directory,name);await mkdir(dirname(path),{recursive:true});await writeFile(path,content);
 }
}

test('OpenAPI 3.1 contracts compile strictly under only TypeScript 7, including negative assertions',async t=>{
 const directory=await temporary(t);
 const types=await generateTypes(schema);
 assert.deepEqual(Object.keys(types).sort(),['Components.ts','Paths.ts','Webhooks.ts','index.ts']);
 for(const content of Object.values(types)){
  assert.doesNotMatch(content,/\b(?:fetch|class|function|const|let|var|enum)\s/,'Generated output must contain declarations only');
 }
 await writeArtifacts(directory,Object.fromEntries(Object.entries(types).map(([name,content])=>['generated/'+name,content])));
 await writeFile(join(directory,'contracts.ts'),await readFile(new URL('./fixtures/api-generator-contract.ts',import.meta.url)));
 await writeFile(join(directory,'tsconfig.json'),JSON.stringify({compilerOptions:{strict:true,noEmit:true,target:'ES2022',module:'ESNext',moduleResolution:'bundler',types:[]},files:['contracts.ts']}));
 const compiler=resolve(import.meta.dirname,'../node_modules/typescript/bin/tsc');
 const version=spawnSync(process.execPath,[compiler,'--version'],{encoding:'utf8'});
 assert.equal(version.status,0,version.stderr);assert.equal(version.stdout.trim(),'Version 7.0.2');
 const result=spawnSync(process.execPath,[compiler,'-p',join(directory,'tsconfig.json')],{encoding:'utf8'});
 assert.equal(result.status,0,result.stdout+result.stderr);
});

test('separate declarations avoid duplicate names from the actual application schema and are deterministic',async()=>{
 const actual=JSON.parse(await readFile(resolve(import.meta.dirname,'../openapi.json'),'utf8'));
 const before=JSON.stringify(actual);
 const first=await generateTypes(actual),second=await generateTypes(actual);
 assert.deepEqual(first,second);assert.equal(JSON.stringify(actual),before,'Generation must not mutate the schema');
 for(const [name,content] of Object.entries(first)){
  assert.equal(await readFile(join(repositoryRoot,generatedDirectory,name),'utf8'),content);
 }
});

test('drift checking rejects changed schema, changed declarations, missing files and unexpected output without writing',async t=>{
 const directory=await temporary(t),types=await generateTypes(schema);
 const artifacts={'ui/openapi.json':JSON.stringify(schema)+'\n',...Object.fromEntries(Object.entries(types).map(([name,content])=>[generatedDirectory+'/'+name,content]))};
 await writeArtifacts(directory,artifacts);await checkArtifacts(directory,artifacts);
 for(const path of ['ui/openapi.json',generatedDirectory+'/Paths.ts']){
  const changed=artifacts[path]+'\n';await writeFile(join(directory,path),changed);
  await assert.rejects(checkArtifacts(directory,artifacts),/Generated API drift/);
  assert.equal(await readFile(join(directory,path),'utf8'),changed,'Check must not repair drift');
  await writeFile(join(directory,path),artifacts[path]);
 }
 const missing=generatedDirectory+'/Components.ts';await rm(join(directory,missing));
 await assert.rejects(checkArtifacts(directory,artifacts),/Components\.ts/);
 await writeFile(join(directory,missing),artifacts[missing]);
 await writeFile(join(directory,generatedDirectory,'unexpected.ts'),'export type Unexpected = true;\n');
 await assert.rejects(checkArtifacts(directory,artifacts),/unexpected\.ts/);
});

test('schema export ignores ambient deployment credentials and produces the committed synthetic schema',async t=>{
 const directory=await temporary(t),output=join(directory,'openapi.json');
 const result=spawnSync('uv',['run','--locked','python','tools/export_openapi.py','--output',output],{
  cwd:repositoryRoot,encoding:'utf8',env:{...process.env,UVM_DB_URL:'postgresql+psycopg://must-not-contact.invalid/synthetic',UVM_API_CURSOR_SECRET:'synthetic-ambient-value',UVM_AUTH_MODE:'oidc',UVM_OIDC_CONFIG:'invalid-synthetic-config',UVM_G7_RECOVERY_CONTROL_ONLY:'1',UVM_API_READ_SNAPSHOT_DIR:join(directory,'must-not-create')},
 });
 assert.equal(result.status,0,result.stdout+result.stderr);
 assert.equal(await readFile(output,'utf8'),await readFile(join(repositoryRoot,'ui/openapi.json'),'utf8'));
});

test('generation fails closed before resolving external references',async()=>{
 const external=structuredClone(schema);
 external.components.schemas.Widget={$ref:'https://must-not-contact.invalid/schema.json'};
 await assert.rejects(generateTypes(external),/only local schema references/);
});
