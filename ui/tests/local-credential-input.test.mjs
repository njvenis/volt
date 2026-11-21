import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';

const marker='SYNTHETIC_CREDENTIAL_MUST_NOT_APPEAR';
const cases=[
 ['malformed',`{"username":"${marker}","password":"${marker}"`],
 ['trailing input',`{"username":"${marker}","password":"${marker}"} ${marker}`],
 ['null','null'],
 ['string',JSON.stringify(marker)],
 ['array',JSON.stringify([marker])],
 ['missing password',JSON.stringify({username:marker})],
 ['wrong username type',JSON.stringify({username:{secret:marker},password:marker})],
 ['wrong password type',JSON.stringify({username:marker,password:{secret:marker}})],
 ['empty username',JSON.stringify({username:'',password:marker})],
];
const companions=[
 ['compose_release_login.mjs',['http://127.0.0.1:46380','/tmp/unused-volt-cookie','--local-stdin']],
 ['g7_local_preview_smoke.mjs',['--local','--origin','http://127.0.0.1:46380','--evidence','/tmp/unused-volt-evidence','--credentials-stdin']],
];
for(const [companion,args] of companions)for(const [name,input] of cases)test(`${companion}: ${name} returns only a fixed safe error`,()=>{
 const result=spawnSync(process.execPath,[resolve(import.meta.dirname,'../../tools',companion),...args],{input,encoding:'utf8',timeout:10000});
 assert.equal(result.error,undefined,'child process must execute');
 assert.equal(result.status,1);
 assert.equal(result.stdout.includes(marker),false,'credential marker absent from stdout');
 assert.equal(result.stderr.includes(marker),false,'credential marker absent from stderr');
 assert.equal(result.stdout,'');
 assert.equal(result.stderr,'Invalid credential input.\n');
});
