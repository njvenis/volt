import assert from 'node:assert/strict';

export function assertClock(actual, expected) {
  assert.ok(actual, 'required occurrence is absent');
  for (const key of ['state','target_at','remaining_seconds','frozen_sla_seconds','prior_breach','currently_breached']) {
    if (key === 'target_at' && expected[key] != null)
      assert.equal(Date.parse(actual[key]), Date.parse(expected[key]), key);
    else assert.equal(actual[key], expected[key], key);
  }
}

export function assertRenderedAcceptance(rendered, expected) {
  assert.equal(rendered.acceptance_id, expected.acceptance_id);
  assert.equal(rendered.state, expected.state);
  assert.equal(Date.parse(rendered.expires_at), Date.parse(expected.expires_at));
  assert.equal(rendered.clocks.length, expected.sla_clock.length);
  for (const clock of expected.sla_clock)
    assertClock(rendered.clocks.find(c=>c.occurrence_id===clock.occurrence_id),clock);
}

export async function captureAcceptance(page, acceptanceId) {
  const card=page.locator(`[data-exception-id="${acceptanceId}"]`);
  await card.waitFor({state:'visible'});
  return card.evaluate((article)=>{
    const facts=element=>Object.fromEntries([...element.querySelectorAll('dl.facts > div')]
      .filter(div=>div.querySelector('dt')&&div.querySelector('dd'))
      .map(div=>[div.querySelector('dt').textContent,div.querySelector('dd')]));
    const number=element=>element?.textContent==='Unknown'?null:Number(element?.textContent.replace(/ seconds$/, '').replaceAll(',',''));
    const badges=element=>[...element.querySelectorAll('.row > .badge > span:last-child')].map(e=>e.textContent);
    const clocks=[...article.querySelectorAll('section[aria-label^="SLA state for "]')].map(section=>{
      const f=facts(section),b=badges(section),paused=b.includes('paused');
      return {occurrence_id:section.getAttribute('aria-label').slice('SLA state for '.length),
        state:b[0],target_at:f[paused?'Exception expires':'Current SLA target']?.querySelector('time')?.dateTime??null,
        remaining_seconds:number(f[paused?'Time to exception expiry at refresh':'Remaining SLA duration at refresh']),
        frozen_sla_seconds:paused?number(f['Currently frozen SLA duration']):null,
        prior_breach:f['Earlier breach']?.textContent==='Recorded — preserved',currently_breached:b.includes('currently breached')};
    });
    return {acceptance_id:article.dataset.exceptionId,
      state:article.querySelector('.card-heading > .badge > span:last-child')?.textContent,
      expires_at:facts(article)['Expiry']?.querySelector('time')?.dateTime??null,clocks};
  });
}
