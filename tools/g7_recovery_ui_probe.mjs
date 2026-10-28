import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {chromium} from '../ui/node_modules/playwright/index.mjs';

const args=process.argv.slice(2);
function arg(name){const i=args.indexOf(name);if(i<0||!args[i+1])throw new Error(`missing ${name}`);return args[i+1];}
const origin=arg('--origin'),storageState=arg('--storage-state'),evidence=resolve(arg('--evidence'));
await mkdir(evidence,{recursive:true,mode:0o700});
const report={origin,errors:[],responses:[],failedRequests:[],title:null,heading:null,bodyText:null,
  deploymentLabelCount:0,backupChunkRequests:[]};
let browser;
try{
  browser=await chromium.launch({headless:true});
  const context=await browser.newContext({storageState,viewport:{width:1440,height:1000}});
  const page=await context.newPage();
  page.on('pageerror',error=>report.errors.push(String(error.message).slice(0,500)));
  page.on('console',message=>{if(message.type()==='error')report.errors.push(message.text().slice(0,500));});
  page.on('response',response=>{
    const url=new URL(response.url());
    if(url.pathname.startsWith('/api/v1/auth/')||url.pathname.startsWith('/api/v1/operations/backup-settings')
      ||url.pathname.includes('BackupSettings'))report.responses.push({path:url.pathname,status:response.status()});
    if(url.pathname.includes('BackupSettings'))report.backupChunkRequests.push({path:url.pathname,status:response.status()});
  });
  page.on('requestfailed',request=>{const url=new URL(request.url());if(url.origin===origin)report.failedRequests.push({path:url.pathname,error:(request.failure()?.errorText??'unknown').slice(0,200)});});
  try{
    await page.goto(new URL('/#administration?section=backup-settings',origin).href,{waitUntil:'load',timeout:30000});
    await page.waitForTimeout(2000);
    const deployment=page.getByLabel('Deployment',{exact:true});
    if(await deployment.count()){
      await deployment.selectOption('g7-local');
      await page.waitForTimeout(5000);
    }
    report.title=await page.title();
    report.heading=await page.locator('h1').allInnerTexts();
    report.bodyText=(await page.locator('body').innerText()).slice(0,8000);
    report.deploymentLabelCount=await page.getByLabel('Deployment',{exact:true}).count();
    await page.screenshot({path:resolve(evidence,'restored-backup-settings.png'),fullPage:true});
  }catch(error){report.navigationError=String(error.message).slice(0,1000);}
  await writeFile(resolve(evidence,'restored-backup-settings-probe.json'),JSON.stringify(report,null,2));
  await context.close();
}catch(error){
  report.launchError=String(error.message).slice(0,1000);
  await writeFile(resolve(evidence,'restored-backup-settings-probe.json'),JSON.stringify(report,null,2));
}finally{await browser?.close();}
