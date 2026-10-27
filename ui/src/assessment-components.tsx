import { displayStatus } from './display-copy';
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';

export function Status({value,label}:{value:string;label?:string}) {
  const tone=['forbidden','rejected','failed','error','conflict','audience_blocked'].includes(value)?'danger':['suspended','stale','unknown','review pending','outcome unknown','uncertain','needs_resubmission','review','revoked','disabled','partially_remediated'].includes(value)?'warning':['committed','confirmed','continuity_covered','remediated','applied'].includes(value)?'success':['pending','active','pending projection','acknowledged'].includes(value)?'info':'neutral';
  return <span className={'badge '+tone}><span aria-hidden="true">{tone==='danger'?'!':tone==='warning'?'△':tone==='success'?'✓':tone==='info'?'◷':'—'}</span><span>{label??displayStatus(value)}</span></span>;
}

export function UTC({value,seconds=false,timezone='UTC'}:{value:string|null|undefined;seconds?:boolean;timezone?:string}) {
  return value&&Number.isFinite(Date.parse(value))?<time dateTime={value}>{new Date(value).toLocaleString('en-GB',{timeZone:timezone,dateStyle:'medium',timeStyle:seconds?'medium':'short'})} {timezone}</time>:<span className="muted">Unknown</span>;
}

export function EvidenceLink({value}:{value:string|null|undefined}) {
  let safe=false;
  try {const url=new URL(value??'');safe=['https:','http:'].includes(url.protocol)&&!url.username&&!url.password;} catch { /* Non-URL references remain escaped text. */ }
  return value?(safe?<a href={value} target="_blank" rel="noopener noreferrer" className="break">{value}<span className="sr-only"> (opens in a new tab)</span></a>:<span className="break">{value}</span>):<span className="muted">No reference recorded</span>;
}

export function Message({title,children,tone='info',alert=false}:{title:string;children?:ReactNode;tone?:string;alert?:boolean}) {
  return <div className={'notice '+tone} role={alert?'alert':undefined}><span aria-hidden="true" className="notice-icon">{tone==='danger'?'!':tone==='warning'?'△':'ⓘ'}</span><div><strong>{title}</strong><div className="message-body">{children}</div></div></div>;
}

export function Modal({title,eyebrow,children,onClose}:{title:string;eyebrow?:string;children:ReactNode;onClose:()=>void}) {
  const ref=useRef<HTMLDialogElement>(null), titleId=useId(), close=useRef(onClose);
  close.current=onClose;
  useEffect(()=>{
    const previous=document.activeElement instanceof HTMLElement?document.activeElement:null;
    const dialog=ref.current!;
    dialog.showModal();
    const cancel=(event:Event)=>{event.preventDefault();close.current();};
    const cycleFocus=(event:KeyboardEvent)=>{
      if(event.key!=='Tab'||event.ctrlKey||event.metaKey||event.altKey)return;
      const controls=[...dialog.querySelectorAll<HTMLElement>('button,input,select,textarea,summary,a[href],[tabindex]')].filter(el=>!el.matches(':disabled')&&el.tabIndex>=0&&el.getClientRects().length>0);
      const first=controls[0],last=controls.at(-1);
      if(!first)return;
      if(event.shiftKey&&document.activeElement===first){event.preventDefault();last!.focus();}
      else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
    };
    dialog.addEventListener('cancel',cancel);
    dialog.addEventListener('keydown',cycleFocus);
    return ()=>{dialog.removeEventListener('cancel',cancel);dialog.removeEventListener('keydown',cycleFocus);dialog.close();if(previous?.isConnected)previous.focus();};
  },[]);
  return <dialog ref={ref} aria-labelledby={titleId} className="assessment-dialog"><header className="detail-head"><div>{eyebrow&&<div className="eyebrow">{eyebrow}</div>}<h2 id={titleId}>{title}</h2></div><button type="button" onClick={onClose} aria-label={'Close '+title}>✕</button></header><div className="detail-body">{children}</div></dialog>;
}

// These are presentation models, not an invented API contract. The API adapter
// supplies stable IDs and authoritative kind/labels once its shape is released.
export type Choice = {id:string;label:string;kind?:string;detail?:string;disabled?:boolean};
export function MultiSelect({legend,choices,value,onChange,disabled=false,searchable=false}:{legend:string;choices:Choice[];value:string[];onChange:(ids:string[])=>void;disabled?:boolean;searchable?:boolean}) {
  const [search,setSearch]=useState('');
  const shown=choices.filter(c=>[c.id,c.label,c.kind,c.detail].join(' ').toLowerCase().includes(search.toLowerCase()));
  return <fieldset className="choice-field" disabled={disabled}><legend>{legend}</legend>{searchable&&<label className="search-label">Search {legend.toLowerCase()}<input type="search" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Name or ID"/></label>}
    {value.length>0&&<div className="selected-chips" aria-label="Selected values">{value.map(id=>{const choice=choices.find(c=>c.id===id);return <span className="owner-chip" key={id}><span className="owner-kind">{choice?.kind??'ID'}</span><span>{choice?.label??id}</span>{(!choice||choice.disabled)&&<button type="button" aria-label={'Remove unavailable '+id} onClick={()=>onChange(value.filter(selected=>selected!==id))}>Remove unavailable</button>}</span>;})}</div>}
    <div className="choice-list">{shown.length?shown.map(choice=><label className="choice" key={choice.id}><input type="checkbox" aria-label={choice.label+(choice.kind?' ('+choice.kind+')':'')} checked={value.includes(choice.id)} disabled={choice.disabled} onChange={e=>onChange(e.target.checked?[...value,choice.id]:value.filter(id=>id!==choice.id))}/><span><strong>{choice.label}</strong>{choice.kind&&<span className="choice-kind">{choice.kind}</span>}<small className="break">{choice.detail??choice.id}</small></span></label>):<p className="muted">{choices.length?'No matching options.':'No visible options.'}</p>}</div>
    <small>{value.length} selected</small>
  </fieldset>;
}

export function DataTable({label,heads,children}:{label:string;heads:string[];children:ReactNode}) {
  return <div className="table-scroll" role="region" aria-label={label} tabIndex={0}><table><caption className="sr-only">{label}</caption><thead><tr>{heads.map(head=><th key={head} scope="col">{head}</th>)}</tr></thead><tbody>{children}</tbody></table></div>;
}

export function Empty({title,children}:{title:string;children:ReactNode}) {
  return <div className="empty"><span aria-hidden="true">◇</span><h3>{title}</h3><p>{children}</p></div>;
}
