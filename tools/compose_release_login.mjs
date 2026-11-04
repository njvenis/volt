import {chromium} from '../ui/node_modules/playwright/index.mjs';
import {writeFile} from 'node:fs/promises';
const [origin, cookiePath] = process.argv.slice(2);
const browser = await chromium.launch({headless:true});
try {
  const context = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await context.newPage();
  await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:30000});
  await page.getByText('Synthetic local demo',{exact:true}).waitFor({timeout:10000});
  await page.getByRole('link',{name:/sign in/i}).click();
  await page.waitForFunction(async()=>{const r=await fetch('/api/v1/auth/session',{cache:'no-store'});return r.ok&&(await r.json()).authenticated===true;},null,{timeout:30000});
  const cookie=(await context.cookies()).find(item=>item.name==='uvm_session');
  if(!cookie?.value) throw new Error('demo browser session cookie missing');
  await writeFile(cookiePath,cookie.value,{mode:0o600});
  console.log(JSON.stringify({browser_login:'passed',principal:'volt-compose-demo-admin'}));
} finally { await browser.close(); }
