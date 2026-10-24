/*!
 * SworfishGuard — Password Analyzer
 * Runs 100% in the browser: the password is never stored or sent anywhere.
 *
 * How it works (short version):
 *   1. Count which character classes are used (a-z, A-Z, 0-9, symbols) to get
 *      the "pool size" an attacker would have to try per character.
 *   2. Look for predictable patterns humans use (common passwords, dictionary
 *      words, leetspeak, keyboard walks, sequences, repeats, years).
 *   3. Characters inside a pattern are cheap to guess, so they only add a few
 *      bits; the rest add log2(pool) bits each. The total is the estimated
 *      entropy, which we turn into a score and estimated crack times.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  // Very common passwords (global leaks + common in Spanish-speaking countries).
  var COMMON_PASSWORDS = [
    '123456', 'password', '123456789', '12345678', '12345', 'qwerty', '1234567',
    '111111', '123123', 'abc123', '1234567890', '000000', 'password1', 'iloveyou',
    '1234', 'qwerty123', 'admin', 'welcome', 'monkey', 'dragon', 'letmein',
    'football', 'baseball', 'sunshine', 'princess', 'master', 'shadow', 'superman',
    'michael', 'batman', 'trustno1', 'starwars', 'whatever', 'freedom', 'hello',
    'charlie', 'login', 'passw0rd', 'qazwsx', 'zxcvbnm', 'asdfghjkl', '654321',
    '666666', '121212', '987654321', '7777777', '112233', 'secret', 'computer',
    'internet', 'samsung', 'google', 'pokemon', 'minecraft', 'fortnite', 'soccer',
    'hockey', 'killer', 'jordan', 'hunter', 'ranger', 'buster', 'thomas', 'tigger',
    'contraseña', 'contrasena', 'teamo', 'tequiero', 'amor', 'amorcito', 'mariposa',
    'princesa', 'estrella', 'corazon', 'familia', 'futbol', 'barcelona', 'realmadrid',
    'honduras', 'olimpia', 'motagua', 'dios', 'jesus', 'diosesamor', 'cristo',
    'guadalupe', 'angel', 'chocolate', 'hola', 'hola123', 'qwerty1', 'abcdef',
    'abcd1234', 'clave', 'micontraseña', 'usuario', 'bienvenido'
  ];

  // Dictionary words (length >= 4) that often appear inside passwords.
  var COMMON_WORDS = [
    'password', 'pass', 'admin', 'welcome', 'monkey', 'dragon', 'letmein', 'love',
    'football', 'baseball', 'sunshine', 'princess', 'master', 'shadow', 'superman',
    'batman', 'starwars', 'freedom', 'hello', 'login', 'secret', 'computer',
    'internet', 'samsung', 'google', 'pokemon', 'minecraft', 'fortnite', 'soccer',
    'hockey', 'killer', 'jordan', 'hunter', 'ranger', 'tigger', 'summer', 'winter',
    'spring', 'flower', 'cookie', 'banana', 'orange', 'purple', 'silver', 'golden',
    'qwerty', 'user', 'test', 'root', 'guest', 'iloveyou',
    'contrasena', 'clave', 'teamo', 'tequiero', 'amor', 'amorcito', 'mariposa',
    'princesa', 'estrella', 'corazon', 'familia', 'futbol', 'barcelona', 'madrid',
    'honduras', 'olimpia', 'motagua', 'dios', 'jesus', 'cristo', 'angel', 'chocolate',
    'hola', 'usuario', 'bienvenido', 'perro', 'gato', 'casa', 'mama', 'papa',
    'gracias', 'feliz', 'vida', 'cielo', 'luna', 'tigre', 'leon', 'escuela',
    'colegio', 'maria', 'jose', 'juan', 'carlos', 'luis', 'pedro', 'ana', 'sofia'
  ].filter(function (w) { return w.length >= 4; })
   .sort(function (a, b) { return b.length - a.length; });

  // Keyboard rows/walks. Any 4+ character slice (forwards or backwards) counts.
  var KEYBOARD_ROWS = [
    'qwertyuiop', 'asdfghjklñ', 'zxcvbnm', '1234567890',
    '1qaz2wsx3edc4rfv', 'qazwsxedcrfv', 'poiuytrewq'
  ];

  // Leetspeak substitutions (single character -> single character).
  var LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
               '9': 'g', '@': 'a', '$': 's', '!': 'i', '+': 't', '|': 'l' };

  var POOL = { lower: 26, upper: 26, digit: 10, symbol: 33, unicode: 100 };

  // Guessing speeds used for the two attack scenarios.
  var SPEED = {
    online: 100 / 3600,   // online, rate-limited: ~100 guesses per hour
    offline: 1e10         // offline, fast hash on a GPU rig: 10 billion / s
  };

  var COMMON_SET = new Set(COMMON_PASSWORDS);
  var MAX_LENGTH = 256;

  function log2(n) { return Math.log(n) / Math.LN2; }

  /** Lowercase + optional leetspeak decode, keeping exactly one char per position. */
  function normalize(chars, leet, oneAs) {
    return chars.map(function (c) {
      if (c.length !== 1) return '\u0000';         // emoji / astral chars: placeholder
      var lc = c.toLowerCase();
      if (lc.length !== 1) lc = c;                 // rare multi-char lowercase forms
      if (leet && LEET[lc]) lc = (lc === '1' && oneAs) ? oneAs : LEET[lc];
      return lc;
    }).join('');
  }

  function charClasses(chars) {
    var cls = { lower: false, upper: false, digit: false, symbol: false, unicode: false };
    chars.forEach(function (c) {
      if (/^[a-z]$/.test(c)) cls.lower = true;
      else if (/^[A-Z]$/.test(c)) cls.upper = true;
      else if (/^[0-9]$/.test(c)) cls.digit = true;
      else if (/^[\x20-\x7E]$/.test(c)) cls.symbol = true;
      else cls.unicode = true;   // ñ, á, emoji, etc.
    });
    return cls;
  }

  function poolSize(cls) {
    var p = 0;
    Object.keys(POOL).forEach(function (k) { if (cls[k]) p += POOL[k]; });
    return p;
  }

  /** Marks [start, start+len) as covered if none of it is covered yet. */
  function tryCover(covered, start, len) {
    for (var i = start; i < start + len; i++) if (covered[i]) return false;
    for (var j = start; j < start + len; j++) covered[j] = true;
    return true;
  }

  function findAll(haystack, needle) {
    var out = [], i = haystack.indexOf(needle);
    while (i !== -1) { out.push(i); i = haystack.indexOf(needle, i + 1); }
    return out;
  }

  /**
   * Analyze a password.
   * @param {string} password
   * @returns {object} result with entropy, score (0-4), patterns, feedback keys, crack times
   */
  function analyzePassword(password) {
    // Hard cap keeps every check fast (no slowdowns with giant pasted text).
    var pw = Array.from(String(password || '')).slice(0, MAX_LENGTH).join('');
    var chars = Array.from(pw);
    var length = chars.length;
    var classes = charClasses(chars);
    var pool = poolSize(classes);
    var bitsPerChar = pool > 0 ? log2(pool) : 0;

    var result = {
      length: length,
      classes: classes,
      poolSize: pool,
      entropy: 0,
      score: 0,
      patterns: [],
      feedback: [],
      isCommon: false,
      crackTimes: { online: 0, offline: 0 }
    };
    if (length === 0) return result;

    var lowerPlain = normalize(chars, false);
    var leetI = normalize(chars, true, 'i');
    var leetL = normalize(chars, true, 'l');
    var covered = new Array(length).fill(false);
    var patternBits = 0;
    function addPattern(type, token, bits) {
      patternBits += bits;
      result.patterns.push({ type: type, token: token, bits: Math.round(bits * 10) / 10 });
    }

    // 1) Exact match against the common-password list (with or without leetspeak).
    var commonIdx = -1;
    [lowerPlain, leetI, leetL].some(function (s) {
      var idx = COMMON_PASSWORDS.indexOf(s);
      if (idx !== -1) { commonIdx = idx; return true; }
      return false;
    });
    if (commonIdx !== -1 || COMMON_SET.has(pw.toLowerCase())) {
      result.isCommon = true;
      result.patterns.push({ type: 'common', token: pw, bits: 0 });
      result.entropy = Math.round(log2(Math.max(commonIdx, 0) + 2) * 10) / 10;
      result.score = 0;
      result.feedback = ['commonPassword', 'usePassphrase'];
      result.breakdown = { bitsPerChar: Math.round(bitsPerChar * 100) / 100, randomChars: 0, randomBits: 0,
        patternBits: result.entropy, guessesLog10: Math.round(Math.max(result.entropy - 1, 0) * Math.log10(2) * 10) / 10 };
      result.crackTimes = crackTimes(result.entropy);
      return result;
    }

    // 2) Dictionary words (also detects leetspeak like "Dr4g0n").
    COMMON_WORDS.forEach(function (word) {
      [lowerPlain, leetI, leetL].forEach(function (s, variant) {
        findAll(s, word).forEach(function (pos) {
          if (tryCover(covered, pos, word.length)) {
            var token = chars.slice(pos, pos + word.length).join('');
            var bits = log2(COMMON_WORDS.length);
            if (/[A-Z]/.test(token)) bits += 1;            // capitalization variant
            if (variant > 0 && token.toLowerCase() !== word) bits += 1; // leet variant
            addPattern(variant > 0 && token.toLowerCase() !== word ? 'leet' : 'word', token, bits);
          }
        });
      });
    });

    // 3) Keyboard walks (qwerty, asdf, 1qaz...).
    KEYBOARD_ROWS.forEach(function (row) {
      var rows = [row, row.split('').reverse().join('')];
      rows.forEach(function (r) {
        for (var len = r.length; len >= 4; len--) {
          for (var start = 0; start + len <= r.length; start++) {
            var slice = r.substr(start, len);
            findAll(lowerPlain, slice).forEach(function (pos) {
              if (tryCover(covered, pos, len)) {
                addPattern('keyboard', chars.slice(pos, pos + len).join(''), log2(KEYBOARD_ROWS.length * 2) + log2(len));
              }
            });
          }
        }
      });
    });

    // 4) Personal data: dates (15082005, 15/08/05) and 8-digit phone numbers
    //    (Honduran format). Attackers who know you try these first.
    var m;
    var dateRe = /(0[1-9]|[12]\d|3[01])([\/.\-]?)(0[1-9]|1[0-2])\2((?:19|20)\d\d|\d\d)(?!\d)/g;
    while ((m = dateRe.exec(lowerPlain)) !== null) {
      if (tryCover(covered, m.index, m[0].length)) addPattern('date', m[0], log2(366 * 100));
    }
    var phoneRe = /(^|[^\d])([23789]\d{7})(?!\d)/g;
    while ((m = phoneRe.exec(lowerPlain)) !== null) {
      var start8 = m.index + m[1].length;
      if (tryCover(covered, start8, 8)) addPattern('phone', m[2], 10);
    }

    // 5) Years 1900-2039 (birthdays, graduation years...).
    var yearRe = /(19\d\d|20[0-3]\d)/g;
    while ((m = yearRe.exec(lowerPlain)) !== null) {
      if (tryCover(covered, m.index, 4)) addPattern('year', m[0], log2(140));
    }

    // 6) Sequences like abc, 123, 987, xyz (3+ chars, step +1 or -1).
    var i = 0;
    while (i < length - 2) {
      var a = lowerPlain.charCodeAt(i), b = lowerPlain.charCodeAt(i + 1);
      var step = b - a;
      if ((step === 1 || step === -1) && /[a-z0-9]/.test(lowerPlain[i])) {
        var j = i + 1;
        while (j < length && lowerPlain.charCodeAt(j) - lowerPlain.charCodeAt(j - 1) === step &&
               /[a-z0-9]/.test(lowerPlain[j])) j++;
        var seqLen = j - i;
        if (seqLen >= 3 && tryCover(covered, i, seqLen)) {
          addPattern('sequence', chars.slice(i, j).join(''), log2(36) + log2(seqLen) + (step === -1 ? 1 : 0));
          i = j;
          continue;
        }
      }
      i++;
    }

    // 7) Repeats: "aaa" or repeated chunks like "abcabc", "hahaha".
    var repRe = /(.+?)\1{2,}|(.{2,}?)\2+/g;
    while ((m = repRe.exec(lowerPlain)) !== null) {
      var unit = m[1] || m[2];
      var count = m[0].length / unit.length;
      if (m[0].length >= 3 && tryCover(covered, m.index, m[0].length)) {
        addPattern('repeat', chars.slice(m.index, m.index + m[0].length).join(''), unit.length * bitsPerChar + log2(count));
      }
      if (m[0].length === 0) repRe.lastIndex++;
    }

    var uncovered = covered.filter(function (c) { return !c; }).length;
    var entropy = uncovered * bitsPerChar + patternBits;
    result.entropy = Math.round(entropy * 10) / 10;
    result.breakdown = {
      bitsPerChar: Math.round(bitsPerChar * 100) / 100,
      randomChars: uncovered,
      randomBits: Math.round(uncovered * bitsPerChar * 10) / 10,
      patternBits: Math.round(patternBits * 10) / 10,
      guessesLog10: Math.round(Math.max(entropy - 1, 0) * Math.log10(2) * 10) / 10
    };

    // Score 0-4.
    var score;
    if (entropy < 25) score = 0;
    else if (entropy < 40) score = 1;
    else if (entropy < 60) score = 2;
    else if (entropy < 80) score = 3;
    else score = 4;
    if (length < 8) score = Math.min(score, 1);
    result.score = score;

    // Feedback (keys are translated by the UI).
    var fb = [];
    if (length < 12) fb.push('tooShort');
    if (length < 16) {
      if (!classes.upper) fb.push('addUpper');
      if (!classes.lower) fb.push('addLower');
      if (!classes.digit) fb.push('addDigit');
      if (!classes.symbol && !classes.unicode) fb.push('addSymbol');
    }
    var seen = {};
    result.patterns.forEach(function (p) {
      var key = { word: 'containsWord', leet: 'leetNotEnough', keyboard: 'keyboardPattern',
                  year: 'containsYear', sequence: 'sequencePattern', repeat: 'repeatPattern',
                  date: 'containsDate', phone: 'containsPhone' }[p.type];
      if (key && !seen[key]) { fb.push(key); seen[key] = true; }
    });
    if (score <= 2) fb.push('usePassphrase');
    if (score >= 4 && result.patterns.length === 0 && length >= 12) fb.push('excellent');
    result.feedback = fb;
    result.crackTimes = crackTimes(entropy);
    return result;
  }

  /** Average time (seconds) to guess: half the search space / guesses per second. */
  function crackTimes(entropy) {
    var guesses = Math.pow(2, Math.max(entropy - 1, 0));
    return { online: guesses / SPEED.online, offline: guesses / SPEED.offline };
  }

  /** Turns seconds into { unit, value } so the UI can translate it. */
  function formatDuration(seconds) {
    var MIN = 60, HOUR = 3600, DAY = 86400, MONTH = 2629800, YEAR = 31557600;
    if (!isFinite(seconds) || seconds >= YEAR * 1e6) return { unit: 'eternity', value: null };
    if (seconds < 1) return { unit: 'instant', value: null };
    if (seconds < MIN) return { unit: 'seconds', value: Math.round(seconds) };
    if (seconds < HOUR) return { unit: 'minutes', value: Math.round(seconds / MIN) };
    if (seconds < DAY) return { unit: 'hours', value: Math.round(seconds / HOUR) };
    if (seconds < MONTH) return { unit: 'days', value: Math.round(seconds / DAY) };
    if (seconds < YEAR) return { unit: 'months', value: Math.round(seconds / MONTH) };
    if (seconds < YEAR * 100) return { unit: 'years', value: Math.round(seconds / YEAR) };
    return { unit: 'centuries', value: Math.round(seconds / (YEAR * 100)) };
  }

  var api = { analyzePassword: analyzePassword, formatDuration: formatDuration, crackTimes: crackTimes,
              SPEED: SPEED, MAX_LENGTH: MAX_LENGTH };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.password = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
