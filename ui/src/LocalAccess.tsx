import {useRef, useState, type FormEvent} from 'react';
import {sessionFetch, setBrowserSession} from './session';
import './local-access.css';
export type AuthConfig={schema_version:1;mode:'local'|'oidc'|'demo';setup_state:'required'|'claimed'|'unavailable'|'not_applicable'};
export function isAuthConfig(value:unknown):value is AuthConfig {
 if(!value||typeof value!=='object')return false;
 const v=value as Record<string,unknown>;
 return v.schema_version===1&&['local','oidc','demo'].includes(String(v.mode))&&['required','claimed','unavailable','not_applicable'].includes(String(v.setup_state))&&(v.mode==='local'?v.setup_state!=='not_applicable':v.setup_state==='not_applicable');
}
type Action='setup'|'login'|'recovery'|'enrol'|'password';
const titles:Record<Action,string>={setup:'Set up your VOLT account',login:'Sign in to VOLT',recovery:'Recover your account',enrol:'Activate your account',password:'Change your password'};
export default function LocalAccess({config,onAuthenticated,changePassword=false,onCancel}:{config:AuthConfig;onAuthenticated:()=>void;changePassword?:boolean;onCancel?:()=>void}) {
 const [action,setAction]=useState<Action>(changePassword?'password':config.setup_state==='required'?'setup':'login');
 const [busy,setBusy]=useState(false),[message,setMessage]=useState(''),[failed,setFailed]=useState(false);
 const form=useRef<HTMLFormElement>(null),heading=useRef<HTMLHeadingElement>(null);
 function choose(next:Action){form.current?.reset();setAction(next);setMessage('');setFailed(false);requestAnimationFrame(()=>heading.current?.focus());}
 async function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();if(busy)return;
  let body=JSON.stringify(Object.fromEntries(new FormData(event.currentTarget)));
  // Capture once, then remove every field before the request can remain pending.
  event.currentTarget.reset();
  setBusy(true);setMessage('');setFailed(false);
  try {
   const path=action==='setup'?'setup/claim':`local/${action}`;
   const transport=action==='password'?sessionFetch:fetch;
   const pending=transport('/api/v1/auth/'+path,{credentials:'same-origin',cache:'no-store',method:'POST',headers:{'Content-Type':'application/json'},body,signal:AbortSignal.timeout(20000)});
   body='';
   const response=await pending;
   if(!response.ok){
    const retry=response.headers.get('Retry-After');
    setFailed(true);setMessage(response.status===429?`Too many attempts. ${retry&&/^\d+$/.test(retry)?`Try again in ${retry} seconds.`:'Wait before trying again.'}`:response.status===409?'This capability has already been used or the account state has changed. Sign in, or ask your operator for a new capability.':response.status===401?'The credentials or capability were not accepted. A capability may have expired or been used.':response.status===422?'Check the account details. Use a unique username and a password of 15–128 characters that is not commonly used.':response.status===403?'This request was denied. Refresh access before trying again.':'Account service unavailable. The outcome could not be confirmed; try signing in before repeating setup.');return;
   }
   if(action==='setup'||action==='login'){onAuthenticated();return;}
   if(action==='password'){setBrowserSession();onAuthenticated();return;}
   setAction('login');setMessage('Password saved. Sign in with your username and new password.');
  }catch{form.current?.reset();setFailed(true);setMessage('The outcome could not be confirmed. Check your connection and try signing in. Do not assume setup or password changes failed.');}
  finally{body='';setBusy(false);}
 }
 if(config.setup_state==='unavailable')return <section className="panel local-access"><h2>Account service unavailable</h2><p role="alert">Setup status could not be checked. No account changes are available.</p><button onClick={onAuthenticated}>Retry access check</button></section>;
 return <section className="panel local-access" aria-labelledby="local-title" aria-busy={busy}>
  <div className="eyebrow">VOLT / WORKSPACE ACCESS</div><h2 id="local-title" ref={heading} tabIndex={-1}>{titles[action]}</h2>
  <p>{action==='setup'?'Use the one-use setup capability provided by your installation operator. Create your personal administrator account; connect scanners after signing in.':action==='password'?'Changing your password signs out every session, including this one.':action==='recovery'||action==='enrol'?'Your operator supplies a private, one-use capability. This does not change your access permissions.':'Use your local account to access this workspace.'}</p>
  {message&&<p role={failed?'alert':'status'}>{message}</p>}
  <form ref={form} onSubmit={submit}>
   <fieldset disabled={busy}>
    {(action==='setup'||action==='recovery'||action==='enrol')&&<label>One-use capability<input name="capability" type="password" autoComplete="off" required spellCheck={false}/></label>}
    {(action==='setup'||action==='login')&&<label>Username<input name="username" autoComplete="username" required maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9._@\-]{0,63}" autoCapitalize="none" spellCheck={false}/></label>}
    {action==='setup'&&<label>Display name<input name="display_name" autoComplete="name" required maxLength={200}/></label>}
    {action==='password'&&<label>Current password<input name="current_password" type="password" autoComplete="current-password" required/></label>}
    <label>{action==='login'?'Password':'New password'}<input name={action==='setup'||action==='login'?'password':'new_password'} type="password" autoComplete={action==='login'?'current-password':'new-password'} required aria-describedby={action==='login'?undefined:'password-help'}/></label>
    {action!=='login'&&<small id="password-help">Use 15–128 characters. Spaces and pasted passwords are welcome. Avoid commonly used passwords.</small>}
    <button className="primary" type="submit">{busy?'Please wait…':action==='setup'?'Create administrator account':action==='login'?'Sign in':action==='password'?'Change password and sign out':'Save password'}</button>
   </fieldset>
  </form>
  {!busy&&<div className="row wrap">{action!=='login'&&!changePassword&&<button onClick={()=>choose('login')}>Back to sign in</button>}{action==='login'&&<><button onClick={()=>choose('recovery')}>Recover account</button><button onClick={()=>choose('enrol')}>Activate account</button>{config.setup_state==='required'&&<button onClick={()=>choose('setup')}>Set up administrator</button>}</>}{onCancel&&<button onClick={onCancel}>Cancel</button>}</div>}
 </section>;
}
