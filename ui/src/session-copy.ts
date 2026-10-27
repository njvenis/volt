// Presentation states only; authentication and request handling remain server controlled.
export type SessionState = 'loading'|'signed_in'|'signed_out'|'expired'|'forbidden'|'denied'|'unlinked'|'csrf'|'invalid'|'unavailable';
export const sessionCopy: Record<Exclude<SessionState, 'signed_in'>, [string, string]> = {
  loading: ['Checking your session', 'Please wait while VOLT checks your access.'],
  signed_out: ['Sign in to your workspace', 'Use the configured sign-in provider to access the findings and assessments available to you.'],
  expired: ['Your session has ended', 'Your session has expired or your access has changed. Sign in again to continue.'],
  forbidden: ['Access unavailable', 'VOLT could not confirm your account link or permission to access this workspace. Ask your administrator to check both.'],
  denied: ['Permission required', 'Your current permissions do not allow this request. Ask your administrator to check your access to this information or action.'],
  unlinked: ['Account link required', 'Your sign-in account is not linked to a VOLT account. Ask your administrator to link it before signing in again.'],
  csrf: ['Request could not be verified', 'VOLT could not verify that this request came from your session. Retry the access check, then review your change before submitting it again.'],
  invalid: ['Sign-in could not be completed', 'The sign-in request is invalid or has expired. Start a new sign-in to continue.'],
  unavailable: ['Identity service unavailable', 'VOLT cannot verify current access. Your workspace is paused. Retry when the service is available.'],
};
export function forbiddenState(code:string): SessionState {
  if(code==='subject_unlinked')return 'unlinked';
  if(code==='forbidden'||code==='source_scope_forbidden')return 'denied';
  if(code==='csrf_failed')return 'csrf';
  return 'forbidden';
}
