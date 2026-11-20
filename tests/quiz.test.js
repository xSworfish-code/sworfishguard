const test = require('node:test');
const assert = require('node:assert/strict');
const { CASES, grade } = require('../js/quiz.js');
const phishing = require('../js/phishing-detector.js');
const scam = require('../js/scam-detector.js');

test('every quiz case is complete in both languages', () => {
  assert.ok(CASES.length >= 12);
  assert.equal(new Set(CASES.map((c) => c.id)).size, CASES.length);
  for (const c of CASES) {
    assert.ok(['real', 'scam'].includes(c.answer), c.id);
    assert.ok(['sms', 'whatsapp', 'email', 'link', 'qr', 'dm'].includes(c.kind), c.id);
    for (const lang of ['es', 'en']) {
      assert.ok(c[lang].text.length > 10 && c[lang].why.length > 30, c.id + ' ' + lang);
      assert.equal(typeof c[lang].from, 'string');
    }
  }
  const scams = CASES.filter((c) => c.answer === 'scam').length;
  assert.ok(scams >= 5 && CASES.length - scams >= 4, 'mix of real and scam cases');
});

test('the detectors agree with the quiz answers for links', () => {
  for (const c of CASES.filter((x) => x.kind === 'link')) {
    const r = phishing.analyzeUrl(c.es.text);
    if (c.answer === 'real') assert.ok(r.official, c.id + ' should be official');
    else assert.equal(r.level, 'high', c.id + ' should be high risk');
  }
});

test('the scam detector flags every scam message in the quiz', () => {
  for (const c of CASES.filter((x) => x.answer === 'scam' && x.kind !== 'link')) {
    for (const lang of ['es', 'en']) {
      const r = scam.analyzeMessage(c[lang].from + '\n' + c[lang].text);
      assert.notEqual(r.level, 'low', `${c.id} (${lang}) scored ${r.score}: ${r.findings.map((f) => f.id)}`);
    }
  }
});

test('grading', () => {
  const ids = CASES.slice(0, 4).map((c) => c.id);
  const all = Object.fromEntries(CASES.map((c) => [c.id, c.answer]));
  assert.deepEqual(grade(all, ids), { right: 4, total: 4, pct: 100, wrong: [], level: 'expert' });
  const g = grade({}, ids);
  assert.equal(g.right, 0);
  assert.equal(g.level, 'start');
  assert.deepEqual(g.wrong, ids);
});
