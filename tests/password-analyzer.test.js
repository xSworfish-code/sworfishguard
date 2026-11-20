const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzePassword, formatDuration, crackTimes, MAX_LENGTH, THRESHOLDS } = require('../js/password-analyzer.js');

const types = (r) => r.sequence.map((p) => p.type);

test('empty password scores 0', () => {
  const r = analyzePassword('');
  assert.equal(r.score, 0);
  assert.equal(r.entropy, 0);
  assert.deepEqual(r.sequence, []);
});

test('the most common passwords are recognized with their rank', () => {
  for (const pw of ['123456', 'password', 'qwerty']) {
    const r = analyzePassword(pw);
    assert.equal(r.isCommon, true, pw);
    assert.equal(r.score, 0, pw);
    assert.ok(r.sequence[0].rank <= 10, pw);
    assert.ok(r.warnings.includes('top10'), pw);
  }
});

test('leetspeak and capitals do not fool it', () => {
  const r = analyzePassword('P@ssw0rd');
  assert.equal(r.score, 0);
  assert.equal(r.sequence[0].l33t, true);
  assert.ok(r.warnings.includes('leetNotEnough'));
  assert.ok(r.sequence[0].subs.includes('@→a') && r.sequence[0].subs.includes('0→o'));
});

test('splits "word + year + symbol" the way an attacker would', () => {
  const r = analyzePassword('Olimpia2008!');
  assert.deepEqual(types(r), ['honduras', 'year', 'random']);
  assert.equal(r.sequence[0].caps, 'start');
  assert.ok(r.score <= 1);
  for (const k of ['honduras', 'containsYear', 'capsPredictable', 'predictableEnding']) assert.ok(r.warnings.includes(k), k);
});

test('Honduran words, names and surnames are in the dictionaries', () => {
  assert.equal(analyzePassword('catracho').sequence[0].type, 'honduras');
  assert.equal(analyzePassword('tegucigalpa').sequence[0].type, 'honduras');
  assert.ok(['name', 'passwords'].includes(analyzePassword('Valentina').sequence[0].type));
  assert.ok(analyzePassword('contraseña').score === 0, 'accents are folded (ñ -> n)');
});

test('personal data typed by the user is detected', () => {
  const plain = analyzePassword('Asaf12032008');
  const personal = analyzePassword('Asaf12032008', ['Asaf Rojas', '2008-03-12']);
  assert.ok(types(personal).includes('personal'));
  assert.ok(personal.warnings.includes('personal'));
  assert.ok(personal.guesses < plain.guesses);
  assert.ok(personal.score <= 1);
});

test('dates, years and phone numbers', () => {
  const d = analyzePassword('xq15082005');
  assert.ok(types(d).includes('date'));
  const date = d.sequence.find((p) => p.type === 'date');
  assert.deepEqual([date.day, date.month, date.year], [15, 8, 2005]);
  assert.ok(types(analyzePassword('zq-9988-7766')).includes('phone'));
  assert.ok(types(analyzePassword('perro2019')).includes('year'));
});

test('keyboard walks, sequences, repeats and reversed words', () => {
  assert.ok(types(analyzePassword('qazwsxedc')).includes('keyboard') || analyzePassword('qazwsxedc').isCommon);
  assert.ok(types(analyzePassword('poiuytre')).includes('keyboard'));
  assert.ok(types(analyzePassword('mnbvc')).includes('keyboard'));
  assert.ok(types(analyzePassword('xzkt-abcdefg')).includes('sequence'));
  assert.ok(types(analyzePassword('xzkt-hjhjhjhj')).includes('repeat'));
  const rev = analyzePassword('aipmilo');
  assert.equal(rev.sequence[0].reversed, true);
});

test('random and long passphrases are very strong', () => {
  const r = analyzePassword('x7#Lq9!vR2@mZ8$k');
  assert.equal(r.score, 4);
  assert.deepEqual(types(r), ['random']);
  assert.deepEqual(r.classes, { lower: true, upper: true, digit: true, symbol: true, unicode: false });
  assert.equal(analyzePassword('nube tractor violeta mango faro').score, 4);
  assert.ok(analyzePassword('nube tractor').score < 4, 'two words are not enough');
});

test('more pieces cannot be cheaper than fewer: adding random characters only helps', () => {
  const a = analyzePassword('Olimpia2008');
  const b = analyzePassword('Olimpia2008kq7');
  assert.ok(b.guesses > a.guesses * 100);
});

test('short passwords are capped at score 1', () => {
  assert.ok(analyzePassword('x7#Lq9!').score <= 1);
  assert.ok(analyzePassword('x7#Lq9!').warnings.includes('tooShort'));
});

test('crack times use the four attack scenarios', () => {
  const r = analyzePassword('Olimpia2008!');
  const t = r.crackTimes;
  assert.ok(t.onlineThrottled > t.onlineFast && t.onlineFast > t.offlineSlow && t.offlineSlow > t.offlineFast);
  assert.equal(t.online, t.onlineThrottled);
  assert.equal(t.offline, t.offlineFast);
  assert.ok(crackTimes(40).offlineFast > 0);
  assert.equal(THRESHOLDS.length, 4);
});

test('huge inputs are capped and stay fast', () => {
  const started = Date.now();
  const r = analyzePassword('ab'.repeat(50000));
  assert.equal(r.length, MAX_LENGTH);
  assert.ok(Date.now() - started < 3000);
  assert.ok(analyzePassword('😀🔑🐟x9').length === 5, 'emoji count as one character');
});

test('formatDuration picks sensible units', () => {
  assert.equal(formatDuration(0.5).unit, 'instant');
  assert.deepEqual(formatDuration(30), { unit: 'seconds', value: 30 });
  assert.deepEqual(formatDuration(7200), { unit: 'hours', value: 2 });
  assert.equal(formatDuration(3e7 * 50).unit, 'years');
  assert.equal(formatDuration(1e20).unit, 'eternity');
});
