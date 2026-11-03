import assert from 'node:assert/strict';

export function assertOperationalRenderedCards(rows, cards) {
  assert.equal(cards.length, rows.length, 'rendered transition count');
  const seen=new Set();
  for(const card of cards){
    const row=rows.find(item=>item.transition_id===card.transition_id);
    assert.ok(row, `unrecognised rendered transition ${card.transition_id}`);
    assert.ok(!seen.has(card.transition_id),'duplicate rendered transition'); seen.add(card.transition_id);
    const expected={transition_id:row.transition_id,deployment_id:row.deployment_id,subject_id:row.subject_id,
      kind:row.transition_kind==='opened'?'EPISODE OPENED':row.transition_kind==='recovered'?'RECOVERY RECORDED':'FURTHER OBSERVATION',
      identifiers:{'Episode ID':row.episode_id,'Episode generation':String(row.episode_generation),
        'Transition ID':row.transition_id,'Stream sequence':String(row.transition_sequence),
        'Opening transition':row.opening_transition_id,'Previous transition':row.predecessor_id??'First in stream',
        'Configuration revision':String(row.configuration_revision),'Condition code':row.condition},
      times:{'First detected':row.first_detected_at,'Observed':row.observed_at,'Recovery recorded':row.recovered_at},
      notification:`Notification: ${row.notification.state??'unverified'}`,
      attempts:row.notification.attempts.map(a=>({attempt_id:a.attempt_id,outcome:a.outcome,attempted_at:a.attempted_at}))};
    assert.deepEqual(card,expected,`rendered values for ${row.transition_id}`);
  }
}

export async function captureOperationalCards(cards){
  return cards.evaluateAll(nodes=>nodes.map(node=>{
    const definitions=selector=>Object.fromEntries([...node.querySelectorAll(selector+' > div')].map(div=>[
      div.querySelector('dt').textContent.trim(),div.querySelector('dd').textContent.trim()]));
    const times=Object.fromEntries([...node.querySelectorAll('.incident-times > div')].map(div=>[
      div.querySelector('dt').textContent.trim(),div.querySelector('time')?.getAttribute('datetime')??null]));
    return {transition_id:node.querySelector('h3').id.replace(/^incident-/,''),
      deployment_id:node.querySelector('.incident-subject strong').textContent.trim(),
      subject_id:node.querySelector('.incident-subject span').textContent.trim(),
      kind:node.querySelector('.eyebrow').textContent.trim(),identifiers:definitions('.incident-identifiers'),times,
      notification:node.querySelector('.incident-delivery strong').textContent.trim(),
      attempts:[...node.querySelectorAll('.incident-detail > ul:first-of-type > li')].map(li=>({
        attempt_id:li.querySelector('code').textContent.trim(),outcome:li.querySelector('strong').textContent.trim(),
        attempted_at:li.querySelector('time')?.getAttribute('datetime')??null}))};
  }));
}
