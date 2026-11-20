/*
 * Measures detector accuracy on tests/fixtures/corpus.js.
 * Run: node tests/benchmark.js
 */
const corpus = require('./fixtures/corpus.js');
const scam = require('../js/scam-detector.js');
const phishing = require('../js/phishing-detector.js');
const password = require('../js/password-analyzer.js');

function messages() {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const misses = [];
  for (const [label, text] of corpus.messages) {
    const flagged = scam.analyzeMessage(text).level !== 'low';
    if (label === 'scam') { if (flagged) tp++; else { fn++; misses.push('MISSED  ' + text); } }
    else { if (flagged) { fp++; misses.push('FALSE+  ' + text); } else tn++; }
  }
  return { tp, fp, tn, fn, accuracy: (tp + tn) / (tp + tn + fp + fn), recall: tp / (tp + fn), precision: tp / (tp + fp || 1), misses };
}

function passwords() {
  const weakOk = corpus.passwords.weak.filter((p) => password.analyzePassword(p).score <= 1);
  const strongOk = corpus.passwords.strong.filter((p) => password.analyzePassword(p).score === 4);
  const total = corpus.passwords.weak.length + corpus.passwords.strong.length;
  return {
    accuracy: (weakOk.length + strongOk.length) / total,
    weakOk: weakOk.length, weak: corpus.passwords.weak.length, strongOk: strongOk.length, strong: corpus.passwords.strong.length,
    misses: corpus.passwords.weak.filter((p) => !weakOk.includes(p)).map((p) => 'TOO HIGH ' + p + ' → ' + password.analyzePassword(p).score)
      .concat(corpus.passwords.strong.filter((p) => !strongOk.includes(p)).map((p) => 'TOO LOW  ' + p + ' → ' + password.analyzePassword(p).score))
  };
}

function links() {
  let ok = 0;
  const misses = [];
  for (const [expected, url] of corpus.links) {
    const r = phishing.analyzeUrl(url);
    const got = r.official ? 'low' : r.level;
    if (got === expected) ok++; else misses.push(`expected ${expected}, got ${got}: ${url}`);
  }
  return { accuracy: ok / corpus.links.length, ok, total: corpus.links.length, misses };
}

module.exports = { messages, passwords, links };

if (require.main === module) {
  const pct = (x) => (x * 100).toFixed(1) + '%';
  const m = messages(), p = passwords(), l = links();
  console.log(`Messages (${corpus.messages.length}): accuracy ${pct(m.accuracy)}, scams caught ${m.tp}/${m.tp + m.fn} (${pct(m.recall)}), false alarms ${m.fp}/${m.fp + m.tn}`);
  console.log(`Passwords (${p.weak + p.strong}): accuracy ${pct(p.accuracy)}, weak rated weak ${p.weakOk}/${p.weak}, strong rated strong ${p.strongOk}/${p.strong}`);
  console.log(`Links (${l.total}): accuracy ${pct(l.accuracy)}`);
  if (process.argv.includes('-v')) [...m.misses, ...p.misses, ...l.misses].forEach((x) => console.log('  ' + x));
}

// Held-out set (not used for tuning): node tests/benchmark.js --holdout
if (require.main === module && process.argv.includes('--holdout')) {
  const hold = require('./fixtures/holdout.js');
  let ok = 0;
  for (const [label, text] of hold.messages) if ((scam.analyzeMessage(text).level !== 'low') === (label === 'scam')) ok++;
  const pOk = hold.passwords.weak.filter((p) => password.analyzePassword(p).score <= 1).length +
              hold.passwords.strong.filter((p) => password.analyzePassword(p).score === 4).length;
  const pTotal = hold.passwords.weak.length + hold.passwords.strong.length;
  console.log(`HOLDOUT messages: ${ok}/${hold.messages.length} (${(ok / hold.messages.length * 100).toFixed(1)}%), passwords: ${pOk}/${pTotal} (${(pOk / pTotal * 100).toFixed(1)}%)`);
}
