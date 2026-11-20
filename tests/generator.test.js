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

test('word lists: 4096 Spanish words (12 bits) and the EFF 7776 English words (12.9 bits)', () => {
  assert.equal(words.es.length, 4096);
  assert.equal(words.en.length, 7776);
  for (const lang of ['es', 'en']) {
    assert.equal(new Set(words[lang]).size, words[lang].length, lang + ' has no repeated words');
    assert.ok(words[lang].every((w) => /^[a-z-]+$/.test(w)), lang + ' has only plain a-z words');
  }
  assert.ok(words.es.every((w) => w.length >= 4 && w.length <= 8));
});

test('passphrase has the requested number of words and honest entropy', () => {
  const r = generatePassphrase({ words: 5, separator: '-', lang: 'es' });
  assert.equal(r.password.split('-').length, 5);
  assert.equal(r.entropy, 60);
  assert.ok(r.words.every((w) => words.es.includes(w)));
  assert.equal(generatePassphrase({ words: 5, lang: 'en' }).entropy, Math.round(5 * Math.log2(7776) * 10) / 10);
  assert.equal(generatePassphrase({ words: 5, capitalize: true, lang: 'es' }).entropy, 60, 'capitals add no real strength');
});

test('passphrase options: capitalize, number, symbol and separator', () => {
  const r = generatePassphrase({ words: 5, separator: '.', capitalize: true, addNumber: true, addSymbol: true, lang: 'en' });
  const parts = r.password.split('.');
  assert.equal(parts.length, 5);
  assert.ok(parts.every((p) => /^[A-Z]/.test(p)));
  assert.ok(/\d/.test(r.password));
  assert.ok(/[!#$%&*?@+=]/.test(r.password));
  assert.ok(r.entropy > 70);
});

test('generated passphrases are rated very strong by the analyzer', () => {
  const { analyzePassword } = require('../js/password-analyzer.js');
  for (let i = 0; i < 20; i++) assert.equal(analyzePassword(generatePassphrase({ words: 5 }).password).score, 4);
});

test('passphrase rejects bad options', () => {
  assert.throws(() => generatePassphrase({ words: 2 }));
  assert.throws(() => generatePassphrase({ separator: '<' }));
});

// ------------------------------------------------------------------- PINs
const { generatePin, weakPinReason } = require('../js/generator.js');

test('weak PINs are recognized', () => {
  const cases = { 1234: 'common', '0000': 'common', 2580: 'common', 1990: 'year', 1508: 'date', 1212: 'common', 4545: 'pattern',
                  9876: 'sequence', 3333: 'common', 4729: '', 123456: 'common', 150805: 'date', 343434: 'pattern', 839271: '' };
  for (const [pin, reason] of Object.entries(cases)) assert.equal(weakPinReason(String(pin).padStart(4, '0')), reason, pin);
});

test('generated PINs are never weak and the pool size is exact', () => {
  for (let i = 0; i < 300; i++) {
    const r = generatePin({ length: 4 });
    assert.match(r.password, /^\d{4}$/);
    assert.equal(weakPinReason(r.password), '');
  }
  for (const length of [4, 6]) {
    const total = 10 ** length;
    let ok = 0;
    for (let x = 0; x < total; x++) if (!weakPinReason(String(x).padStart(length, '0'))) ok++;
    const r = generatePin({ length });
    assert.equal(r.poolSize, ok, 'stored pool for ' + length + ' digits matches the filter');
    assert.equal(r.rejected, total - ok);
  }
});
