const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzePassword, formatDuration, MAX_LENGTH } = require('../js/password-analyzer.js');

const types = (r) => r.patterns.map((p) => p.type);

test('empty password scores 0 with no entropy', () => {
  const r = analyzePassword('');
  assert.equal(r.score, 0);
  assert.equal(r.entropy, 0);
});

test('very common passwords are flagged and score 0', () => {
  for (const pw of ['123456', 'password', 'qwerty', 'teamo', 'honduras']) {
    const r = analyzePassword(pw);
    assert.equal(r.isCommon, true, pw);
    assert.equal(r.score, 0, pw);
    assert.ok(r.feedback.includes('commonPassword'), pw);
    assert.ok(r.breakdown, pw);
  }
});

test('leetspeak versions of common passwords are still detected', () => {
  const r = analyzePassword('P4ssw0rd');
  assert.equal(r.isCommon, true);
  assert.equal(r.score, 0);
});

test('detects dictionary words and years', () => {
  const r = analyzePassword('Dragon1990!');
  assert.ok(types(r).includes('word'));
  assert.ok(types(r).includes('year'));
  assert.ok(r.score <= 1);
});

test('detects dates and phone numbers (personal data)', () => {
  const d = analyzePassword('Maria15082005');
  assert.ok(types(d).includes('date'));
  assert.ok(d.feedback.includes('containsDate'));
  const p = analyzePassword('xq99887766!');
  assert.ok(types(p).includes('phone'));
  assert.ok(p.feedback.includes('containsPhone'));
});

test('detects keyboard walks and sequences', () => {
  const r = analyzePassword('zxcvbnm123');
  assert.ok(types(r).includes('keyboard'));
  assert.ok(types(r).includes('sequence'));
});

test('detects repeated characters', () => {
  const r = analyzePassword('aaaaaaaa');
  assert.ok(types(r).includes('repeat'));
  assert.equal(r.score, 0);
});

test('every pattern reports its bits and the breakdown adds up', () => {
  const r = analyzePassword('Maria15082005!');
  const patternBits = r.patterns.reduce((s, p) => s + p.bits, 0);
  assert.ok(Math.abs(patternBits - r.breakdown.patternBits) < 0.2);
  assert.ok(Math.abs(r.breakdown.randomBits + r.breakdown.patternBits - r.entropy) < 0.2);
});

test('random 16-char password with all classes is very strong', () => {
  const r = analyzePassword('x7#Lq9!vR2@mZ8$k');
  assert.equal(r.score, 4);
  assert.deepEqual(r.classes, { lower: true, upper: true, digit: true, symbol: true, unicode: false });
  assert.ok(r.entropy > 100);
});

test('long passphrases are rated strong even without symbols', () => {
  assert.ok(analyzePassword('nube tractor violeta mango').score >= 3);
});

test('short passwords are capped at score 1', () => {
  assert.ok(analyzePassword('x7#Lq9!').score <= 1);
});

test('patterns lower the entropy compared to random characters', () => {
  assert.ok(analyzePassword('qwertyuiop12').entropy < analyzePassword('hf8wkq2mzpe4').entropy);
});

test('huge inputs are capped so analysis stays fast', () => {
  const started = Date.now();
  const r = analyzePassword('ab'.repeat(50000));
  assert.equal(r.length, MAX_LENGTH);
  assert.ok(Date.now() - started < 2000);
});

test('formatDuration picks sensible units', () => {
  assert.equal(formatDuration(0.5).unit, 'instant');
  assert.deepEqual(formatDuration(30), { unit: 'seconds', value: 30 });
  assert.deepEqual(formatDuration(7200), { unit: 'hours', value: 2 });
  assert.equal(formatDuration(3e7 * 50).unit, 'years');
  assert.equal(formatDuration(1e20).unit, 'eternity');
});
