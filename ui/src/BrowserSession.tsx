import {sessionCandidates, type Scope} from './preservation-api';
import {useCallback, useEffect, useState} from 'react';
import {errorCode, pauseBrowserSession, SESSION_EVENT, sessionFetch, setBrowserSession} from './session';
import {forbiddenState, sessionCopy, type SessionState as State} from './session-copy';
export function useBrowserSession() {
  const [state, setState] = useState<State>('loading');
  const [session, updateSession] = useState<{name:string;token:string;candidates:Scope[]}>({name:'',token:'',candidates:[]});
  const [signedOut, setSignedOut] = useState(false);
  const bootstrap = useCallback(async () => {
    setState('loading'); setBrowserSession(); updateSession({name:'', token:'',candidates:[]});
    try {
      const response = await fetch('/api/v1/auth/session', {credentials:'same-origin', cache:'no-store', headers:{Accept:'application/json'}, signal:AbortSignal.timeout(15000)});
      const body = await response.json();
      if (!response.ok) { setState(response.status===401?'signed_out':response.status===403?forbiddenState(errorCode(body)):'unavailable'); return; }
      if (body.schema_version!==1 || body.authenticated!==true || body.credential_mode!=='oidc_session' || typeof body.principal_id!=='string' || typeof body.csrf_token!=='string' || !body.csrf_token) throw new Error('Unsupported session');
      setBrowserSession(body.csrf_token); updateSession({name:body.principal_id, token:body.csrf_token,candidates:sessionCandidates(body)}); setState('signed_in'); setSignedOut(false);
    } catch { setState('unavailable'); }
  }, []);
  useEffect(() => {
    const failure = (event: Event) => {
      const {status,code} = (event as CustomEvent<{status:number;code:string}>).detail;
      if(status===401)setBrowserSession(); else pauseBrowserSession(); updateSession(prior=>({name:status===401?'':prior.name, token:'',candidates:[]}));
      setState(status===401?'expired':status===403?forbiddenState(code):'unavailable');
    };
    addEventListener(SESSION_EVENT, failure);
    const status = new URLSearchParams(location.search).get('status');
    if (location.pathname==='/auth/failure') {
      history.replaceState(null, '', '/');
      setState(status==='forbidden'?'forbidden':status==='unavailable'?'unavailable':'invalid');
    } else void bootstrap();
    return ()=>removeEventListener(SESSION_EVENT, failure);
  }, [bootstrap]);
  async function logout() {
    setState('loading'); updateSession(prior=>({...prior, token:''}));
    try {
      const response = await sessionFetch('/api/v1/auth/logout', {method:'POST', signal:AbortSignal.timeout(15000)});
      if (!response.ok) { const code=errorCode(await response.json()); if(response.status!==401)throw new Error(code); }
      const check = await fetch('/api/v1/auth/session', {credentials:'same-origin', cache:'no-store'});
      if (check.status!==401) throw new Error('Logout not confirmed');
      setBrowserSession(); updateSession({name:'', token:'',candidates:[]}); setSignedOut(true); setState('signed_out');
    } catch { setBrowserSession(); updateSession(prior=>({...prior, token:''})); setState('unavailable'); }
  }
  return {session, state, signedOut, bootstrap, logout};
}
export function SessionPanel({state,signedOut,retry}:{state:State;signedOut:boolean;retry:()=>void}) {
  if(state==='signed_in')return null;
  const [title,description]=sessionCopy[state];
  return <section className="panel session-panel" aria-labelledby="session-title" aria-busy={state==='loading'}>
    <div className="session-emblem" aria-hidden="true">↗</div><div className="eyebrow">VOLT / WORKSPACE ACCESS</div>
    <h2 id="session-title">{signedOut&&state==='signed_out'?'You are signed out':title}</h2>
    <p role={state==='loading'?'status':state==='signed_out'?undefined:'alert'}>{description}</p>
    {state!=='loading'&&<div className="row wrap"><a className="button primary" href="/api/v1/auth/login">Sign in</a>{['unavailable','forbidden','denied','unlinked','csrf'].includes(state)&&<button onClick={retry}>Retry access check</button>}</div>}
    <small>Your access is checked by VOLT for each request. Dates are displayed in UTC.</small>
  </section>;
}
