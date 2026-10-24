/*!
 * SworfishGuard — Secure Password & Passphrase Generator
 *
 * Uses crypto.getRandomValues (a cryptographically secure random source),
 * never Math.random(). Random indexes use "rejection sampling" so every
 * character or word has exactly the same probability (no modulo bias).
 *
 * Passphrases pick words from a 256-word list, so each word adds exactly
 * log2(256) = 8 bits of entropy. Six random words = 48 bits, easy to remember.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var SETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~'
  };
  // Characters that look alike in many fonts (O/0, l/1/I, etc.).
  var AMBIGUOUS = 'O0oIl1|`\'"';
  var SEPARATORS = ['-', '.', '_', ' '];

  function getWords(lang) {
    var lists = (root.SworfishGuard && root.SworfishGuard.words) ||
                (typeof require === 'function' ? require('./wordlists.js') : null);
    if (!lists) throw new Error('wordlists.js must be loaded first');
    return lists[lang] || lists.es;
  }

  /** Uniform random integer in [0, max) using rejection sampling. */
  function randomInt(max) {
    if (!Number.isInteger(max) || max <= 0 || max > 0x100000000) throw new RangeError('max out of range');
    var limit = Math.floor(0x100000000 / max) * max; // largest multiple of max below 2^32
    var buf = new Uint32Array(1);
    var x;
    do {
      root.crypto.getRandomValues(buf);
      x = buf[0];
    } while (x >= limit);
    buf[0] = 0;
    return x % max;
  }

  /** Fisher–Yates shuffle with a secure random source. */
  function shuffle(arr) {
    for (var i = arr.length - 1; i > 0; i--) {
      var j = randomInt(i + 1);
      var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
    return arr;
  }

  function buildSets(opts) {
    var chosen = [];
    ['lower', 'upper', 'digits', 'symbols'].forEach(function (k) {
      if (opts[k]) {
        var s = SETS[k];
        if (opts.excludeAmbiguous) s = s.split('').filter(function (c) { return AMBIGUOUS.indexOf(c) === -1; }).join('');
        chosen.push(s);
      }
    });
    return chosen;
  }

  /**
   * Generates a random password.
   * @param {object} options {length, lower, upper, digits, symbols, excludeAmbiguous}
   * @returns {{password:string, entropy:number, poolSize:number}}
   */
  function generatePassword(options) {
    var opts = Object.assign({ length: 16, lower: true, upper: true, digits: true, symbols: true, excludeAmbiguous: false }, options || {});
    var length = Math.floor(opts.length);
    var sets = buildSets(opts);
    if (sets.length === 0) throw new Error('Select at least one character type');
    if (length < sets.length || length < 4 || length > 128) throw new RangeError('Length must be between 4 and 128');

    var all = sets.join('');
    // Guarantee at least one character from each selected set...
    var out = sets.map(function (s) { return s[randomInt(s.length)]; });
    // ...then fill the rest from the full pool and shuffle.
    while (out.length < length) out.push(all[randomInt(all.length)]);
    shuffle(out);

    var entropy = length * Math.log2(all.length);
    return { password: out.join(''), entropy: Math.round(entropy * 10) / 10, poolSize: all.length };
  }

  /**
   * Generates a passphrase such as "nube-tractor-Violeta-mango-42".
   * @param {object} options {words, separator, capitalize, addNumber, lang}
   * @returns {{password:string, entropy:number, poolSize:number, words:string[]}}
   */
  function generatePassphrase(options) {
    var opts = Object.assign({ words: 6, separator: '-', capitalize: false, addNumber: false, lang: 'es' }, options || {});
    var count = Math.floor(opts.words);
    if (count < 3 || count > 12) throw new RangeError('Words must be between 3 and 12');
    if (SEPARATORS.indexOf(opts.separator) === -1) throw new Error('Invalid separator');

    var list = getWords(opts.lang);
    var words = [];
    for (var i = 0; i < count; i++) {
      var w = list[randomInt(list.length)];
      if (opts.capitalize) w = w.charAt(0).toUpperCase() + w.slice(1);
      words.push(w);
    }
    var entropy = count * Math.log2(list.length);
    if (opts.addNumber) {
      var at = randomInt(count);
      words[at] = words[at] + String(randomInt(100));
      entropy += Math.log2(100) + Math.log2(count);
    }
    return { password: words.join(opts.separator), entropy: Math.round(entropy * 10) / 10,
             poolSize: list.length, words: words };
  }

  var api = { generatePassword: generatePassword, generatePassphrase: generatePassphrase, randomInt: randomInt,
              SETS: SETS, AMBIGUOUS: AMBIGUOUS, SEPARATORS: SEPARATORS };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.generator = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
