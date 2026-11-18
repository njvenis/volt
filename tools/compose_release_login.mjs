import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {protectedInput,publicOrigin,privateOutputs,savedSession} from '../ui/scripts/local-companion-state.mjs';
const [origin,cookiePath,usernameArgument,...extra]=process.argv.slice(2);
let credentials;
try {
 const input=await protectedInput();
 credentials=usernameArgument==='--local-stdin'?JSON.parse(input):{username:usernameArgument,password:input};
 if(!credentials||typeof credentials!=='object'||Array.isArray(credentials)||typeof credentials.username!=='string'||typeof credentials.password!=='string'||!credentials.username||!credentials.password)throw new Error();
} catch {process.stderr.write('Invalid credential input.\n');process.exit(1);}
let browser,outputs;
try {
 publicOrigin(origin);if(!cookiePath||extra.length&&!(usernameArgument==='--local-stdin'&&extra.length===2&&extra[0]==='--save-browser-state'&&extra[1]))throw new Error();
 outputs=await privateOutputs([{file:cookiePath,replace:true},...(extra.length?[{file:extra[1],replace:false}]:[])]);
 browser=await chromium.launch({headless:true});
 const context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();
 await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});
 const configResponse=await context.request.get(origin+'/api/v1/auth/config');
 const local=configResponse.ok()&&(await configResponse.json()).mode==='local';
 if(!local){await page.getByText('Synthetic local demo',{exact:true}).waitFor({timeout:10000});await page.getByRole('link',{name:/sign in/i}).click();}
 else await page.getByRole('heading',{name:'Sign in to VOLT'}).waitFor();
 await page.getByLabel('Username').fill(credentials.username);await page.getByLabel('Password').fill(credentials.password);await page.getByRole('button',{name:'Sign in'}).click();credentials=null;
 let session;const deadline=Date.now()+30000;
 while(Date.now()<deadline){const response=await context.request.get(origin+'/api/v1/auth/session');if(response.status()===200){const value=await response.json();if(value.authenticated===true&&value.credential_mode===(local?'local_session':'oidc_session')){session=value;break;}}await new Promise(resolve=>setTimeout(resolve,200));}
 if(!session)throw new Error();
 const cookie=(await context.cookies()).find(item=>item.name==='uvm_session');if(!cookie?.value)throw new Error();
 if(extra.length){if(!local)throw new Error();const state=savedSession({schema_version:1,kind:'local_browser_session',origin,captured_at:new Date().toISOString(),principal_id:session.principal_id,storage_state:await context.storageState()},origin);await outputs.write(1,JSON.stringify(state));}
 // Existing private cookie output remains compatible with the delivery runner.
 await outputs.write(0,cookie.value);
 console.log(JSON.stringify({browser_login:'passed',mode:local?'local':'demo',...(extra.length?{saved_browser_session:'confirmed'}:{})}));
} catch {process.stderr.write('Browser login verification failed.\n');process.exitCode=1;}finally{await browser?.close();await outputs?.close();}
