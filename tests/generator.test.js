const test = require('node:test');
const assert = require('node:assert/strict');
const { generatePassword, randomInt, SETS, AMBIGUOUS } = require('../js/generator.js');

test('generates the requested length', () => {
  for (const length of [8, 16, 32, 64]) {
    assert.equal(generatePassword({ length }).password.length, length);
  }
});

test('includes at least one character of every selected type', () => {
  for (let i = 0; i < 200; i++) {
    const { password } = generatePassword({ length: 8 });
    assert.match(password, /[a-z]/);
    assert.match(password, /[A-Z]/);
    assert.match(password, /[0-9]/);
    assert.ok([...password].some((c) => SETS.symbols.includes(c)));
  }
});

test('respects disabled character types', () => {
  const { password } = generatePassword({ length: 40, upper: false, symbols: false });
  assert.match(password, /^[a-z0-9]+$/);
});

test('can exclude ambiguous characters', () => {
  for (let i = 0; i < 50; i++) {
    const { password } = generatePassword({ length: 64, excludeAmbiguous: true });
    assert.ok(![...password].some((c) => AMBIGUOUS.includes(c)));
  }
});

test('throws when no character type is selected', () => {
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
});

test('reports entropy = length * log2(pool)', () => {
  const r = generatePassword({ length: 10, upper: false, digits: false, symbols: false });
  assert.equal(r.poolSize, 26);
  assert.equal(r.entropy, Math.round(10 * Math.log2(26) * 10) / 10);
});

test('randomInt stays in range and is roughly uniform', () => {
  const counts = new Array(6).fill(0);
  const N = 60000;
  for (let i = 0; i < N; i++) counts[randomInt(6)]++;
  for (const c of counts) {
    assert.ok(Math.abs(c - N / 6) < N / 6 * 0.1, `bucket ${c} too far from ${N / 6}`);
  }
});

test('passwords are not repeated', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) seen.add(generatePassword({ length: 12 }).password);
  assert.equal(seen.size, 1000);
});

// ---------------------------------------------------------------- passphrases
const { generatePassphrase } = require('../js/generator.js');
const words = require('../js/wordlists.js');

test('word lists have exactly 256 unique words (8 bits each)', () => {
  for (const lang of ['es', 'en']) {
    assert.equal(words[lang].length, 256);
    assert.equal(new Set(words[lang]).size, 256);
    assert.ok(words[lang].every((w) => /^[a-z]+$/.test(w)), lang + ' has only plain a-z words');
  }
});

test('passphrase has the requested number of words and entropy', () => {
  const r = generatePassphrase({ words: 6, separator: '-', lang: 'es' });
  assert.equal(r.password.split('-').length, 6);
  assert.equal(r.entropy, 48);
  assert.ok(r.words.every((w) => words.es.includes(w)));
});

test('passphrase options: capitalize, number and separator', () => {
  const r = generatePassphrase({ words: 5, separator: '.', capitalize: true, addNumber: true, lang: 'en' });
  const parts = r.password.split('.');
  assert.equal(parts.length, 5);
  assert.ok(parts.every((p) => /^[A-Z]/.test(p)));
  assert.ok(/\d/.test(r.password));
  assert.ok(r.entropy > 40);
});

test('passphrase rejects bad options', () => {
  assert.throws(() => generatePassphrase({ words: 2 }));
  assert.throws(() => generatePassphrase({ separator: '<' }));
});
