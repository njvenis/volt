import {useEffect, useRef, useState} from 'react';
import {AssessmentError, acknowledgeWarning, getExceptionWarnings, getWarningFailureAlerts, type ExceptionWarning, type GroupView, type WarningFailureAlert, type WarningAcknowledgement} from './assessment-api';
import {Empty, Message, Status, UTC} from './assessment-components';
import './exception-warnings.css';

const hasDeliveryReceipt=(attempt:ExceptionWarning['attempts'][number])=>attempt.outcome==='sent'&&!!attempt.receipt?.trim();
function deliveryLabel(item:ExceptionWarning) {
  if(item.status==='sent')return !item.attempts.some(hasDeliveryReceipt)?'Delivery record incomplete':item.provider_receipt_basis==='slack_api_accepted'?'Accepted by Slack':item.provider_receipt_basis==='smtp_accepted'?'Accepted by SMTP service':'Receipt recorded';
  if(item.status==='failed')return item.next_attempt_at?'Failed · retry scheduled':'Failed';
  return {pending:'Pending',sending:'Sending',uncertain:'Uncertain',missed:'Missed',suppressed:'Suppressed'}[item.status];
}
function deliveryExplanation(item:ExceptionWarning) {
  switch(item.status) {
    case 'sent':return !item.attempts.some(hasDeliveryReceipt)?'No usable receipt was retained. Service acceptance cannot be confirmed.':item.provider_receipt_basis==='slack_api_accepted'?'Slack accepted this message. This does not confirm that a person read it.':item.provider_receipt_basis==='smtp_accepted'?'The SMTP service accepted this submission. This does not confirm inbox delivery or that a person read it.':'A retained receipt is not proof that a person read this warning. This historical record does not identify Slack or SMTP service acceptance.';
    case 'pending':return 'Waiting for dispatch. The due threshold alone does not confirm that VOLT has authorised a send.';
    case 'sending':return 'An attempt is in progress. No service acceptance has been confirmed.';
    case 'failed':return item.next_attempt_at?'The attempt failed. VOLT has recorded another attempt time; it must recheck eligibility before sending.':'The attempt failed. No further automatic attempt is recorded.';
    case 'uncertain':return 'The service may have accepted this warning. Reconciliation is needed before another send; do not assume it is safe to retry.';
    case 'suppressed':return 'VOLT withheld this warning. The recorded reason is retained below.';
    case 'missed':return 'The warning opportunity was missed. This does not change the exception or its expiry.';
  }
}
function Acknowledgement({item,groupId,token,onSaved}:{item:ExceptionWarning;groupId:string;token:string;onSaved:(receipt:WarningAcknowledgement)=>void}) {
  const [saving,setSaving]=useState(false),[saved,setSaved]=useState(false),[error,setError]=useState<AssessmentError>();
  const savedMessage=useRef<HTMLParagraphElement>(null);
  useEffect(()=>{if(saved)savedMessage.current?.focus();},[saved]);
  const save=async()=>{
    setSaving(true);setSaved(false);setError(undefined);
    try {const receipt=await acknowledgeWarning(groupId,item.intent_id,token);onSaved(receipt);setSaved(true);}
    catch(e){setError(e instanceof AssessmentError?e:new AssessmentError(0,'outcome_unknown',true));}
    finally {setSaving(false);}
  };
  return <div className="warning-acknowledgement"><h4>Receipt acknowledgement</h4>
    <p>{item.acknowledged_at?<>Receipt acknowledged by <strong>{item.acknowledged_by}</strong> at <UTC value={item.acknowledged_at} seconds/>.</>:'No acknowledgement recorded.'}</p>
    <p className="permission-note">An acknowledgement records receipt only. Assessment, ownership, remediation and SLA remain separate.</p>
    {saved&&<p role="status" tabIndex={-1} ref={savedMessage}>Receipt acknowledgement saved in VOLT.</p>}
    {error&&<Message title={error.uncertain?'Acknowledgement not confirmed':error.status===409?'Warning changed — refresh required':'Acknowledgement unavailable'} tone="warning" alert>
      {error.uncertain?'VOLT could not confirm the receipt action. Check or retry this acknowledgement; the first recorded actor and time are retained.':error.status===409?'Refresh warnings and review the current receipt before acknowledging.':error.status===403?'Your current access does not permit this receipt action.':error.status===401?'Sign in again to acknowledge this receipt.':'The receipt action failed. Refresh warnings before trying again.'}
    </Message>}
    {!item.acknowledged_at&&item.status==='sent'&&item.attempts.some(hasDeliveryReceipt)&&<button type="button" disabled={saving||!!error&&!error.uncertain} onClick={save}>{saving?'Saving acknowledgement…':error?.uncertain?'Check or retry acknowledgement':'Acknowledge receipt'}</button>}
    {saving&&<span role="status" className="sr-only">Saving receipt acknowledgement</span>}
  </div>;
}
export default function ExceptionWarnings({view,token}:{view:GroupView;token:string}) {
  const [retry,setRetry]=useState(0);
  const [result,setResult]=useState<{view:GroupView;items?:{item:ExceptionWarning;due:string|null}[];alerts?:WarningFailureAlert[];alertError?:AssessmentError;error?:AssessmentError}>();
  useEffect(()=>{
    const controller=new AbortController();setResult(undefined);
    const scopeWarnings=(items:ExceptionWarning[])=>{
      // Validate every decision before exposing any warning from this response.
      return items.map(item=>{
        const decision=view.assessment.acceptances.find(a=>a.acceptance_id===item.decision_id);
        if(!decision)throw new AssessmentError(502,'unsupported_response');
        let due:string|null=item.due_at??null;
        if(!item.due_at&&decision.request_revision===item.expiry_revision){
          // Both operands may be valid individually while their difference is not.
          const threshold=new Date(Date.parse(decision.expires_at)-item.offset_seconds*1000);
          if(!Number.isFinite(threshold.getTime()))throw new AssessmentError(502,'unsupported_response');
          due=threshold.toISOString();
        }
        return {item,due};
      });
    };
    getExceptionWarnings(view.group.group_id,token,controller.signal).then(async items=>{
      const scoped=scopeWarnings(items);
      if(controller.signal.aborted)return;
      // Authorised warnings do not depend on membership of the narrower
      // failure-alert audience. Show them while the alert read is pending.
      setResult({view,items:scoped});
      let alerts:WarningFailureAlert[];
      try {alerts=await getWarningFailureAlerts(view.group.group_id,token,controller.signal);}
      catch(error){
        if(controller.signal.aborted)return;
        if(error instanceof AssessmentError&&error.status===403&&error.code==='source_scope_forbidden'){
          // This code also covers finding-scope revocation between the reads.
          // Hide the first response until the normal warning/session boundary
          // confirms authority again; restore only freshly validated records.
          setResult(undefined);
          const fresh=await getExceptionWarnings(view.group.group_id,token,controller.signal);
          const revalidated=scopeWarnings(fresh);
          if(!controller.signal.aborted)setResult({view,items:revalidated,alertError:error});
          return;
        }
        throw error;
      }
      // Alerts must bind to this already validated warning set. Do not expose
      // even one reason or destination when any binding is foreign/malformed.
      for(const alert of alerts){
        const warning=items.find(item=>item.intent_id===alert.intent_id);
        if(!warning||warning.channel!==alert.channel)throw new AssessmentError(502,'unsupported_response');
        if(warning.status!==alert.status)throw new AssessmentError(409,'stale_revision');
      }
      if(!controller.signal.aborted)setResult(previous=>previous?.view===view?{...previous,alerts}:previous);
    }).catch(error=>{
      if(!controller.signal.aborted)setResult({view,error:error instanceof AssessmentError?error:new AssessmentError(0,'unavailable')});
    });
    return ()=>controller.abort();
  },[view,token,retry]);
  const current=result?.view===view?result:undefined;
  return <section className="panel exception-warnings" aria-label="Exception warnings">
    <div className="panel-head"><div><span className="eyebrow">Expiry notifications</span><h2>Exception warnings</h2></div><button type="button" onClick={()=>{setResult(undefined);setRetry(n=>n+1);}}>Refresh warnings</button></div>
    <div className="panel-content"><p>Configured Slack and email warnings for this finding. Service acceptance and acknowledgement are separate records; neither approves, extends or remediates an exception.</p>
      {!current?<p role="status">Loading warning records…</p>:current.error?<Message title="Warning status unavailable" tone="warning" alert>{current.error.status===403?'You do not have permission to read warning records for this finding.':current.error.status===401?'Sign in again to read warning records.':current.error.status===409?'Warning records have changed. Refresh warnings to load the current records. No previous status is shown.':'VOLT could not load warning records. No delivery status can be confirmed. Refresh warnings to try again.'}</Message>:!current.items?.length?<Empty title="No warning records">No warning intents were returned for this finding. This does not confirm delivery.</Empty>:<p role="status" className="permission-note">Warning records loaded. Refresh to check for updates.</p>}
    </div>
    {current?.items&&<section className="warning-failure-alerts" aria-label="Warning delivery failures">
      <h3>Delivery failure alerts</h3><p className="permission-note">Alerts returned by VOLT for your current access. An earlier failure can remain recorded after a later accepted attempt.</p>
      {current.alertError?<Message title="Delivery failure alerts unavailable" tone="warning" alert>Your current access does not include these delivery failure alerts. Authorised warning records and receipt actions remain available.</Message>:!current.alerts?<p role="status">Loading delivery failure alerts…</p>:!current.alerts.length?<p>No delivery failure alerts were returned for this finding. This does not confirm delivery.</p>:current.alerts.map(alert=><article className="warning-failure" key={alert.alert_id} data-warning-alert-id={alert.alert_id}>
        <div className="card-heading"><h4>{alert.channel==='slack'?'Slack':'Email'} delivery failure recorded</h4><Status value="failed" label="Failure alert"/></div>
        <p>A warning attempt failed or could not be confirmed. Check the current warning and its retained attempts below.</p><p>Recorded <UTC value={alert.created_at} seconds/>.</p>
        <p>Current warning: <strong>{deliveryLabel(current.items!.find(({item})=>item.intent_id===alert.intent_id)!.item)}</strong></p>
        <details><summary>Failure reason and references</summary><dl className="facts"><div><dt>Recorded reason</dt><dd>{alert.reason}</dd></div><div><dt>Alert</dt><dd><code>{alert.alert_id}</code></dd></div><div><dt>Attempt</dt><dd><code>{alert.attempt_id}</code></dd></div></dl></details>
      </article>)}
    </section>}
    {current?.items?.map(({item,due})=>{
      return <article className="acceptance-card" key={item.intent_id} data-warning-id={item.intent_id}>
        <div className="card-heading"><h3>{item.channel==='slack'?'Slack':'Email'} warning</h3><div className="row wrap"><Status value={item.status==='sent'?(item.attempts.some(hasDeliveryReceipt)?'pending':'uncertain'):item.status} label={deliveryLabel(item)}/>{item.acknowledged_at&&<Status value="acknowledged" label="Acknowledged"/>}</div></div>
        <p className="warning-explanation">{deliveryExplanation(item)}</p>
        <dl className="facts"><div><dt>Exception</dt><dd><code>{item.decision_id}</code></dd></div><div><dt>Destination reference</dt><dd>{item.destination_ref}</dd></div><div><dt>Expiry revision</dt><dd>{item.expiry_revision}</dd></div><div><dt>Due threshold</dt><dd>{due?<UTC value={due} seconds/>:'Matching expiry revision unavailable'}</dd></div><div><dt>Warning offset</dt><dd>{item.offset_seconds.toLocaleString('en-GB')} seconds before expiry</dd></div><div><dt>Attempts</dt><dd>{item.retry.attempts} of {item.retry.max_attempts}</dd></div><div><dt>Next attempt</dt><dd>{item.next_attempt_at?<UTC value={item.next_attempt_at} seconds/>:'None recorded'}</dd></div><div><dt>Retry base delay</dt><dd>{item.retry.base_delay_seconds} seconds</dd></div></dl>
        <p className="permission-note">{item.due_at?'The due threshold is recorded by VOLT.':'The due threshold uses the recorded expiry and offset.'} Pending does not confirm current dispatch eligibility or that delivery occurred.</p>
        {view.assessment.acceptances.find(a=>a.acceptance_id===item.decision_id)?.request_revision!==item.expiry_revision&&<Message title="Expiry details have changed" tone="warning">This warning refers to a different expiry revision. Its history is retained. Refresh the finding to check its latest exception.</Message>}
        {item.suppression_reason&&<Message title="Recorded reason" tone="warning">{item.suppression_reason}</Message>}
        {item.status==='uncertain'&&<Message title="Delivery cannot be confirmed" tone="warning">The recorded attempt has an uncertain outcome. No delivery or retry success is assumed.</Message>}
        <Acknowledgement item={item} groupId={view.group.group_id} token={token} onSaved={receipt=>setResult(previous=>previous?.view===view?{...previous,items:previous.items?.map(row=>row.item.intent_id===receipt.intent_id?{...row,item:{...row.item,acknowledged_at:receipt.acknowledged_at,acknowledged_by:receipt.acknowledged_by}}:row)}:previous)}/>
        <details><summary>Delivery attempts and receipts · {item.attempts.length}</summary><p className="permission-note">Intent <code>{item.intent_id}</code> · persisted status <code>{item.status}</code> · route revision {item.route_revision??'not recorded'}</p><p>Receipt source: {!item.attempts.some(hasDeliveryReceipt)?'No accepted receipt confirmed':item.provider_receipt_basis==='slack_api_accepted'?'Slack API acceptance':item.provider_receipt_basis==='smtp_accepted'?'SMTP submission acceptance':'Historical record · provider not recorded'}.</p>{item.attempts.length?item.attempts.map(attempt=><div className="exception-clock" key={attempt.attempt_number}><h4>Attempt {attempt.attempt_number} · {attempt.outcome==='sent'?(hasDeliveryReceipt(attempt)?'Receipt recorded':'Delivery record incomplete'):attempt.outcome}</h4><dl className="facts"><div><dt>Attempted</dt><dd><UTC value={attempt.attempted_at} seconds/></dd></div><div><dt>Finished</dt><dd><UTC value={attempt.finished_at} seconds/></dd></div><div><dt>Receipt</dt><dd>{attempt.receipt?.trim()?attempt.receipt:'None recorded'}</dd></div><div><dt>Error</dt><dd>{attempt.error??'None recorded'}</dd></div></dl></div>):<p>No delivery attempts recorded.</p>}</details>
      </article>;
    })}
  </section>;
}
