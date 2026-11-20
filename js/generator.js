/*!
 * SworfishGuard — Secure Password & Passphrase Generator
 *
 * Uses crypto.getRandomValues (a cryptographically secure random source),
 * never Math.random(). Random indexes use "rejection sampling" so every
 * character or word has exactly the same probability (no modulo bias).
 *
 * Passphrases pick words from big lists: 4,096 Spanish words (12 bits each)
 * or the EFF's 7,776 English words (12.9 bits each). Six random words give
 * about 72-77 bits, as strong as a random 12-character password with symbols
 * but much easier to remember.
 *
 * PINs skip the ones people choose most (1234, 0000, years, dates, 1212...),
 * because those are the first an attacker tries.
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
  var PASSPHRASE_SYMBOLS = '!#$%&*?@+=';

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
    var opts = Object.assign({ words: 6, separator: '-', capitalize: false, addNumber: false, addSymbol: false, lang: 'es' }, options || {});
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
    // Capitals on every word don't add strength (an attacker tries that too); they only help with site rules.
    if (opts.addNumber) {
      var at = randomInt(count);
      words[at] = words[at] + String(randomInt(100));
      entropy += Math.log2(100) + Math.log2(count);
    }
    if (opts.addSymbol) {
      var sym = PASSPHRASE_SYMBOLS[randomInt(PASSPHRASE_SYMBOLS.length)];
      var where = randomInt(count);
      words[where] = words[where] + sym;
      entropy += Math.log2(PASSPHRASE_SYMBOLS.length) + Math.log2(count);
    }
    return { password: words.join(opts.separator), entropy: Math.round(entropy * 10) / 10,
             poolSize: list.length, words: words };
  }

  // ------------------------------------------------------------------- PINs
  // Most used PINs in leaked data (DataGenetics analysis of 3.4 million PINs, 2012).
  var COMMON_PINS = ['1234', '1111', '0000', '1212', '7777', '1004', '2000', '4444', '2222', '6969', '9999', '3333',
    '5555', '6666', '1122', '1313', '8888', '4321', '2001', '1010', '123456', '654321', '111111', '000000', '123123',
    '666666', '121212', '112233', '789456', '159753', '147258', '159357', '102030', '696969', '777777',
    // straight lines on the number pad
    '2580', '0852', '1470', '0741', '3690', '0963', '1379', '1397', '7913', '9731', '147258', '258369', '963852', '741852'];

  function validDate(d, m) { return d >= 1 && d <= 31 && m >= 1 && m <= 12; }

  /** Why a PIN is weak, or '' if it looks random. */
  function weakPinReason(pin) {
    if (COMMON_PINS.indexOf(pin) !== -1) return 'common';
    if (/^(\d)\1+$/.test(pin)) return 'repeat';
    var asc = true, desc = true;
    for (var i = 1; i < pin.length; i++) {
      var d = pin.charCodeAt(i) - pin.charCodeAt(i - 1);
      if (d !== 1) asc = false;
      if (d !== -1) desc = false;
    }
    if (asc || desc) return 'sequence';
    if (/^(\d\d)\1+$/.test(pin) || /^(\d{3})\1$/.test(pin) || /^(\d)\1(\d)\2(\d?)\3$/.test(pin)) return 'pattern';
    var n = pin.length;
    if (n === 4) {
      var y = +pin;
      if (y >= 1940 && y <= 2035) return 'year';
      if (validDate(+pin.slice(0, 2), +pin.slice(2)) || validDate(+pin.slice(2), +pin.slice(0, 2))) return 'date';
    }
    if (n === 6) {
      var a = +pin.slice(0, 2), b = +pin.slice(2, 4), c = +pin.slice(4);
      if (validDate(a, b) || validDate(b, a) || validDate(c, b)) return 'date';   // ddmmyy, mmddyy, yymmdd
    }
    return '';
  }

  // How many PINs pass the filter (counted once by tests/generator.test.js, which re-checks it).
  var PIN_POOL = { 4: { total: 10000, allowed: 9118 }, 6: { total: 1000000, allowed: 912388 } };
  function pinPool(length) { return PIN_POOL[length]; }

  /**
   * Generates a PIN that is not one of the predictable ones.
   * @param {object} options {length: 4 or 6}
   */
  function generatePin(options) {
    var length = (options && options.length) === 6 ? 6 : 4;
    var pin;
    do {
      pin = '';
      for (var i = 0; i < length; i++) pin += String(randomInt(10));
    } while (weakPinReason(pin));
    var pool = pinPool(length);
    return { password: pin, entropy: Math.round(Math.log2(pool.allowed) * 10) / 10, poolSize: pool.allowed,
             rejected: pool.total - pool.allowed, total: pool.total };
  }

  var api = { generatePassword: generatePassword, generatePassphrase: generatePassphrase, generatePin: generatePin,
              weakPinReason: weakPinReason, randomInt: randomInt,
              SETS: SETS, AMBIGUOUS: AMBIGUOUS, SEPARATORS: SEPARATORS };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.generator = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
