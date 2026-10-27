import { useEffect, useState, type FormEvent } from 'react';
import { Message, Modal } from './assessment-components';
import type { ReportContext } from './report-model';

export type ReportDraft={groupIds:string[];mode:'as_known_at'|'corrected_history';asOf:string;knownAt:string;periodStart:string;periodEnd:string;predecessor:string;timezone:string};
export const blankReportDraft=():ReportDraft=>({groupIds:[],mode:'as_known_at',asOf:'',knownAt:'',periodStart:'',periodEnd:'',predecessor:'',timezone:'UTC'});
export function ReportRequest({draft,onChange,onSubmit,onClose,busy,error,uncertain,conflict,predecessor}:{draft:ReportDraft;onChange:(draft:ReportDraft)=>void;onSubmit:()=>void;onClose:()=>void;busy:boolean;error:string|null;uncertain:boolean;conflict:boolean;predecessor?:ReportContext}) {
  const [acknowledged,setAcknowledged]=useState(false);
  const update=(change:Partial<ReportDraft>)=>{onChange({...draft,...change});setAcknowledged(false);};
  const corrected=draft.mode==='corrected_history';
  useEffect(()=>{if(conflict)setAcknowledged(false);},[conflict]);
  function submit(event:FormEvent){event.preventDefault();if(acknowledged||uncertain)onSubmit();}
  return <Modal title="Create a report" eyebrow="REPORTS / SCOPE & TIME" onClose={onClose}><form className="report-filter-form assessment-form" onSubmit={submit}>
    <Message title="Choose the vulnerabilities and dates to report on">Counts, finding details and downloads all use the same saved data. Creating a report does not start a scan.</Message>
    {error&&<Message title={uncertain?'Report save not confirmed':conflict?'Report request conflicts':'Unable to create report'} tone="danger" alert>{error}</Message>}
    <fieldset className="form-fields" disabled={busy||uncertain}>
      <label>Report mode<select value={draft.mode} onChange={e=>{const mode=e.target.value as ReportDraft['mode'];update(mode==='corrected_history'&&predecessor?{mode,asOf:predecessor.asOf,groupIds:predecessor.scope,periodStart:predecessor.periodStart??'',periodEnd:predecessor.periodEnd??'',predecessor:predecessor.id,knownAt:''}:{mode,predecessor:''});}}><option value="as_known_at">Use the information available at the selected time</option><option value="corrected_history" disabled={!predecessor}>Update the loaded report with later information</option></select></label>
      {corrected&&<Message title="Keep the original scope and assessment date">Choose a later information date to include corrections. The original report remains available.</Message>}
      <label>Vulnerability IDs<textarea aria-label="Vulnerability IDs" value={draft.groupIds.join('\n')} onChange={e=>update({groupIds:e.target.value.split(/[\n,]/).map(s=>s.trim())})} placeholder="One vulnerability ID per line" required readOnly={corrected}/><small>Enter the vulnerability IDs to include. Your access is checked for each one.</small></label>
      <div className="form-grid"><label>Assess risk at (UTC)<input aria-label="Assess risk at (UTC)" value={draft.asOf} onChange={e=>update({asOf:e.target.value})} placeholder="YYYY-MM-DDTHH:mm:ssZ" readOnly={corrected}/><small>Leave both dates blank to use the current time.</small></label><label>Use information available by (UTC)<input aria-label="Use information available by (UTC)" value={draft.knownAt} onChange={e=>update({knownAt:e.target.value})} placeholder="YYYY-MM-DDTHH:mm:ssZ" required={corrected||Boolean(draft.asOf)}/><small>Must be at or after the assessment date. Later dates can include corrections.</small></label><label>Completion period start (UTC)<input value={draft.periodStart} onChange={e=>update({periodStart:e.target.value})} placeholder="Optional start (included)" readOnly={corrected}/></label><label>Completion period end (UTC)<input value={draft.periodEnd} onChange={e=>update({periodEnd:e.target.value})} placeholder="Optional end (excluded)" readOnly={corrected} required={Boolean(draft.periodStart)}/></label></div>
      <label>Display timezone<select aria-label="Display timezone" value={draft.timezone} onChange={e=>update({timezone:e.target.value})}><option value="UTC">UTC</option></select><small>Changing the display timezone does not change deadlines or which fixes are counted.</small></label>
      {corrected&&<p className="report-compact">Original report <code>{draft.predecessor}</code></p>}
      <label className="acknowledge"><input type="checkbox" checked={acknowledged} onChange={e=>setAcknowledged(e.target.checked)} required/>I have reviewed the selected vulnerabilities and report dates.</label>
    </fieldset><div className="form-actions"><button type="button" onClick={onClose}>{uncertain?'Close and retain request':'Cancel'}</button><button type="submit" className="primary" disabled={busy||(!uncertain&&!acknowledged)}>{busy?'Saving report…':uncertain?'Check or retry this report':'Create report'}</button></div>
  </form></Modal>;
}
