import test from 'node:test';
import assert from 'node:assert/strict';
import {assertOperationalRenderedCards} from './g7_operational_render_assertions.mjs';
const rows=Array.from({length:4},(_,i)=>({transition_id:`transition-${i}`,deployment_id:'g7-local',subject_id:`subject-${i}`,
  transition_kind:'opened',episode_id:`episode-${i}`,episode_generation:1,transition_sequence:1,
  opening_transition_id:`transition-${i}`,predecessor_id:null,configuration_revision:1,condition:'host_sender_health',
  first_detected_at:'2026-11-03T00:00:00.000000Z',observed_at:'2026-11-03T00:00:00.000000Z',recovered_at:null,
  notification:{state:'accepted',attempts:[{attempt_id:`attempt-${i}`,outcome:'accepted',attempted_at:'2026-11-03T00:00:01.000000Z'}]}}));
const cards=rows.map(row=>({transition_id:row.transition_id,deployment_id:row.deployment_id,subject_id:row.subject_id,
  kind:'EPISODE OPENED',identifiers:{'Episode ID':row.episode_id,'Episode generation':'1','Transition ID':row.transition_id,
    'Stream sequence':'1','Opening transition':row.transition_id,'Previous transition':'First in stream',
    'Configuration revision':'1','Condition code':'host_sender_health'},
  times:{'First detected':row.first_detected_at,'Observed':row.observed_at,'Recovery recorded':null},
  notification:'Notification: accepted',attempts:structuredClone(row.notification.attempts)}));
test('exact rendered operational identities and times pass',()=>assertOperationalRenderedCards(rows,cards));
test('four unrelated accepted cards fail',()=>{
  const wrong=structuredClone(cards);for(const card of wrong)card.transition_id='unrelated-'+card.transition_id;
  assert.throws(()=>assertOperationalRenderedCards(rows,wrong),/unrecognised rendered transition/);
});
for(const field of ['subject','kind','sequence','episode','predecessor','attempt','outcome','observed','attempted']){
  test(`wrong rendered ${field} fails while four accepted labels remain`,()=>{
    const wrong=structuredClone(cards),card=wrong[0];
    if(field==='subject')card.subject_id='other';
    if(field==='kind')card.kind='RECOVERY RECORDED';
    if(field==='sequence')card.identifiers['Stream sequence']='99';
    if(field==='episode')card.identifiers['Episode ID']='other';
    if(field==='predecessor')card.identifiers['Previous transition']='other';
    if(field==='attempt')card.attempts[0].attempt_id='other';
    if(field==='outcome')card.attempts[0].outcome='failed';
    if(field==='observed')card.times.Observed='1970-01-01T00:00:00Z';
    if(field==='attempted')card.attempts[0].attempted_at='1970-01-01T00:00:00Z';
    assert.throws(()=>assertOperationalRenderedCards(rows,wrong),/rendered values/);
  });
}
