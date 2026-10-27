// Browser authority lives in the HttpOnly cookie. This value is only CSRF
// protection; it is never a bearer credential or persisted in browser storage.
let csrf: string | undefined;
let generation = 0;
export function pauseBrowserSession() { generation++; }
export const SESSION_EVENT = 'uvm-session-failure';
export function setBrowserSession(value?: string) { csrf = value; generation++; }
export function errorCode(body: unknown): string {
  if (!body || typeof body !== 'object') return 'unavailable';
  const value = body as {detail?: {code?: unknown}; error?: {code?: unknown}};
  const code = value.detail?.code ?? value.error?.code;
  return typeof code === 'string' ? code : 'unavailable';
}
export async function sessionFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const epoch = generation;
  const headers = new Headers(init.headers);
  headers.delete('Authorization');
  const write = !['GET', 'HEAD', 'OPTIONS'].includes((init.method ?? 'GET').toUpperCase());
  if (write && csrf) headers.set('X-CSRF-Token', csrf);
  const response = await fetch(path, {...init, headers, credentials: 'same-origin', cache: 'no-store'});
  if (epoch !== generation) throw new DOMException('Session changed', 'AbortError');
  if (!response.ok) {
    const code = await response.clone().json().then(errorCode).catch(() => 'unavailable');
    // Reading the body is asynchronous too. A concurrent denial may already
    // have paused this session and aborted the workspace's remaining reads.
    if (epoch !== generation || init.signal?.aborted) throw new DOMException('Session changed', 'AbortError');
    // Failure alerts have a narrower access-group audience than the finding.
    // This exact read denial is local to that resource, not a session denial.
    // Warning reads, writes and identity/session errors retain the global path.
    const alertScopeDenied = response.status === 403 && code === 'source_scope_forbidden' &&
      (init.method ?? 'GET').toUpperCase() === 'GET' &&
      /^\/api\/v1\/assessment\/groups\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/exception-warning-failure-alerts$/i.test(path);
    if (response.status === 401 || response.status === 403 && !alertScopeDenied ||
        response.status === 503 && (code.startsWith('identity_') || code.startsWith('oidc_'))) {
      dispatchEvent(new CustomEvent(SESSION_EVENT, {detail: {status: response.status, code}}));
    }
  }
  return response;
}
