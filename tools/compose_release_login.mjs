import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {writeFile} from 'node:fs/promises';
const [origin, cookiePath, usernameArgument] = process.argv.slice(2);
const passwordChunks = [];
for await (const chunk of process.stdin) passwordChunks.push(Buffer.from(chunk));
const input=Buffer.concat(passwordChunks).toString('utf8');
let credentials;
try {
  credentials=usernameArgument==='--local-stdin'?JSON.parse(input):{username:usernameArgument,password:input};
  if(!credentials||typeof credentials!=='object'||Array.isArray(credentials)||
      typeof credentials.username!=='string'||typeof credentials.password!=='string'||
      !credentials.username||!credentials.password)throw new Error();
} catch {
  // JSON parser diagnostics can quote the input. Never expose their error/cause.
  process.stderr.write('Invalid credential input.\n');
  process.exit(1);
}
const {username,password}=credentials;
const browser = await chromium.launch({headless:true});
try {
  const context = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await context.newPage();
  await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});
  const configResponse=await context.request.get(origin+'/api/v1/auth/config');
  const local=configResponse.ok()&&(await configResponse.json()).mode==='local';
  if(!local){await page.getByText('Synthetic local demo',{exact:true}).waitFor({timeout:10000});await page.getByRole('link',{name:/sign in/i}).click();}
  else await page.getByRole('heading',{name:'Sign in to VOLT'}).waitFor();
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button',{name:'Sign in'}).click();
  let authenticated=false;
  const deadline=Date.now()+30000;
  while(Date.now()<deadline){const response=await context.request.get(origin+'/api/v1/auth/session');if(response.ok()){const session=await response.json();if(session.authenticated===true&&session.credential_mode===(local?'local_session':'oidc_session')){authenticated=true;break;}}await new Promise(resolve=>setTimeout(resolve,200));}
  if(!authenticated)throw new Error('browser session was not confirmed');
  const cookie=(await context.cookies()).find(item=>item.name==='uvm_session');
  if(!cookie?.value) throw new Error('browser session cookie missing');
  await writeFile(cookiePath,cookie.value,{mode:0o600});
  console.log(JSON.stringify({browser_login:'passed',mode:local?'local':'demo'}));
} catch { process.stderr.write('Browser login verification failed.\n'); process.exitCode=1; } finally { await browser.close(); }
