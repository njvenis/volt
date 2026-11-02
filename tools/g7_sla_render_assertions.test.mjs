import {test} from 'node:test';
import assert from 'node:assert/strict';
import {assertRenderedAcceptance} from './g7_sla_render_assertions.mjs';
const expected={acceptance_id:'main',state:'expired',expires_at:'2026-10-30T10:00:00Z',sla_clock:[
  {occurrence_id:'covered',state:'running',target_at:'2026-10-30T16:00:00Z',remaining_seconds:21540,frozen_sla_seconds:null,prior_breach:false,currently_breached:false},
  {occurrence_id:'gap',state:'gap',target_at:null,remaining_seconds:null,frozen_sla_seconds:null,prior_breach:false,currently_breached:false}]};
const valid=()=>({...structuredClone(expected),clocks:structuredClone(expected.sla_clock)});
test('exact selected acceptance and every occurrence',()=>assertRenderedAcceptance(valid(),expected));
for(const [name,mutate] of [
  ['stale paused',r=>{r.state='active';r.clocks[0].state='paused';r.clocks[0].frozen_sla_seconds=21600;}],
  ['wrong numeric remainder',r=>r.clocks[0].remaining_seconds=21600],
  ['gap-only screen',r=>r.clocks.shift()],
  ['another acceptance',r=>r.acceptance_id='ui-fixture'],
  ['wrong target',r=>r.clocks[0].target_at='2026-10-30T17:00:00Z'],
  ['erased breach',r=>r.clocks[0].prior_breach=true]])
  test(`reject ${name}`,()=>{const r=valid();mutate(r);assert.throws(()=>assertRenderedAcceptance(r,expected));});
