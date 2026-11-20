/*!
 * SworfishGuard — Password Analyzer
 * Runs 100% in the browser: the password is never stored or sent anywhere.
 *
 * How it works:
 *   Real attackers don't try "aaaa, aaab, aaac...". They try leaked passwords
 *   first, then words, names, years, keyboard rows, "a→4" swaps... So this
 *   analyzer thinks like them:
 *
 *   1. MATCH: find every piece of the password that matches something an
 *      attacker would try (12,000 leaked passwords, 26,000 Spanish/English
 *      words, 7,000 names and surnames, a Honduras list, your own personal
 *      data, keyboard walks, sequences, repeats, years, dates, phone numbers).
 *   2. ESTIMATE: give each piece the number of guesses it would take
 *      (e.g. a word ranked #300 = 300 guesses, ×2 if it starts with a capital).
 *   3. COMBINE: try every way of splitting the password into pieces and keep
 *      the cheapest one for the attacker (dynamic programming). The leftover
 *      characters count as random.
 *
 *   The idea and formulas follow zxcvbn (Dropbox, Wheeler 2016, "zxcvbn:
 *   Low-Budget Password Strength Estimation"), rewritten here from scratch
 *   with Spanish and Honduran data.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var DICT = (root.SworfishGuard && root.SworfishGuard.dictionaries) ||
             (typeof require === 'function' ? require('./dictionaries.js') : null);

  var MAX_LENGTH = 256;          // anything longer is cut
  var MAX_MATCH = 100;           // patterns are searched in the first 100 characters
  var MAX_WORD = 24;
  var REFERENCE_YEAR = new Date().getFullYear();
  var MIN_YEAR_SPACE = 20;
  // Extra cost for each extra piece, because the attacker doesn't know the structure.
  // zxcvbn uses 10,000; 1,000 is closer to real cracking rules (hashcat/John), which try
  // "word + year + symbol" very early. Measured on tests/fixtures/corpus.js.
  var MIN_GUESSES_BEFORE_GROWING_SEQUENCE = 1000;
  var MIN_SUBMATCH_GUESSES_SINGLE_CHAR = 10;
  var MIN_SUBMATCH_GUESSES_MULTI_CHAR = 50;

  // Guesses per second in four attack scenarios.
  var SPEED = {
    onlineThrottled: 100 / 3600, // a website that limits attempts: ~100 per hour
    onlineFast: 10,              // a website with no limit: 10 per second
    offlineSlow: 1e4,            // leaked database protected with bcrypt/argon2
    offlineFast: 1e10            // leaked database with a fast hash (MD5, SHA-1) on GPUs
  };
  SPEED.online = SPEED.onlineThrottled;   // names kept for older code
  SPEED.offline = SPEED.offlineFast;

  // Score thresholds (guesses). 4 needs ~1e14: centuries for bcrypt, hours+ even for MD5 on GPUs.
  var THRESHOLDS = [1e4, 1e8, 1e10, 1e14];

  var DICT_TYPE = { passwords: 'passwords', es: 'word', en: 'word', names: 'name', surnames: 'surname', honduras: 'honduras', user: 'personal' };

  // ------------------------------------------------------------- dictionaries
  var RANKED = {};
  if (DICT) {
    Object.keys(DICT.LISTS).forEach(function (name) {
      var map = new Map();
      DICT.LISTS[name].split(' ').forEach(function (w, i) { if (w && !map.has(w)) map.set(w, i + 1); });
      RANKED[name] = map;
    });
  }

  var L33T = { '4': ['a'], '@': ['a'], '8': ['b'], '(': ['c'], '{': ['c'], '[': ['c'], '<': ['c'], '3': ['e'],
               '6': ['g'], '9': ['g'], '1': ['i', 'l'], '!': ['i'], '|': ['i', 'l'], '7': ['t', 'l'], '0': ['o'],
               '$': ['s'], '5': ['s'], '+': ['t'], '%': ['x'], '2': ['z'] };

  var GRAPHS = DICT ? DICT.GRAPHS : { qwerty: {}, keypad: {} };
  function graphStats(g) {
    var keys = Object.keys(g), degree = 0;
    keys.forEach(function (k) { degree += g[k].filter(Boolean).length; });
    return { starts: keys.length, degree: keys.length ? degree / keys.length : 0 };
  }
  var GRAPH_STATS = { qwerty: graphStats(GRAPHS.qwerty), keypad: graphStats(GRAPHS.keypad) };
  var SHIFTED = /[~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:"ZXCVBNM<>?]/;

  // ------------------------------------------------------------------ helpers
  function log10(n) { return Math.log(n) / Math.LN10; }
  function nCk(n, k) {
    if (k > n) return 0;
    if (k === 0) return 1;
    var r = 1;
    for (var d = 1; d <= k; d++) { r *= n; r /= d; n--; }
    return r;
  }
  var FACT = [1];
  function factorial(n) { while (FACT.length <= n) FACT.push(FACT[FACT.length - 1] * FACT.length); return FACT[n]; }

  /** lowercase without accents, one output char per input char (ñ -> n, á -> a). */
  function foldChar(c) {
    var lc = c.toLowerCase();
    if (lc.length !== 1) lc = c;
    var f = lc.normalize('NFD').replace(/[̀-ͯ]/g, '');
    return f.length === 1 ? f : lc;
  }

  function charClasses(chars) {
    var cls = { lower: false, upper: false, digit: false, symbol: false, unicode: false };
    chars.forEach(function (c) {
      if (/^[a-z]$/.test(c)) cls.lower = true;
      else if (/^[A-Z]$/.test(c)) cls.upper = true;
      else if (/^[0-9]$/.test(c)) cls.digit = true;
      else if (/^[\x20-\x7E]$/.test(c)) cls.symbol = true;
      else cls.unicode = true;   // ñ, á, emoji...
    });
    return cls;
  }
  var POOL = { lower: 26, upper: 26, digit: 10, symbol: 33, unicode: 100 };
  function poolSize(cls) {
    var p = 0;
    Object.keys(POOL).forEach(function (k) { if (cls[k]) p += POOL[k]; });
    return p;
  }

  // ----------------------------------------------------------------- matching
  function dictionaryMatches(chars, folded, dicts) {
    var out = [], n = folded.length;
    function scan(text, extra) {
      for (var i = 0; i < n; i++) {
        for (var j = i + 2; j < Math.min(n, i + MAX_WORD); j++) {   // 3+ characters
          var w = text.slice(i, j + 1);
          Object.keys(dicts).forEach(function (name) {
            var rank = dicts[name].get(w);
            if (!rank) return;
            var m = { pattern: 'dictionary', i: i, j: j, token: chars.slice(i, j + 1).join(''), word: w, rank: rank, dict: name };
            if (extra) extra(m);
            out.push(m);
          });
        }
      }
    }
    scan(folded);

    // Reversed words ("aipmilo")
    var rev = folded.split('').reverse().join('');
    var revOut = [];
    for (var i = 0; i < n; i++) {
      for (var j = i + 2; j < Math.min(n, i + MAX_WORD); j++) {
        var w = rev.slice(i, j + 1);
        Object.keys(dicts).forEach(function (name) {
          if (name === 'user') return;
          var rank = dicts[name].get(w);
          if (!rank || w.length < 4) return;
          var a = n - 1 - j, b = n - 1 - i;
          revOut.push({ pattern: 'dictionary', i: a, j: b, token: chars.slice(a, b + 1).join(''), word: w, rank: rank, dict: name, reversed: true });
        });
      }
    }

    // Leetspeak ("P4ssw0rd"): try each meaning of the symbols that were used.
    var leetChars = [];
    folded.split('').forEach(function (c) { if (L33T[c] && leetChars.indexOf(c) === -1) leetChars.push(c); });
    var subsList = [{}];
    leetChars.forEach(function (c) {
      var next = [];
      subsList.forEach(function (s) {
        L33T[c].forEach(function (letter) { var copy = Object.assign({}, s); copy[c] = letter; next.push(copy); });
      });
      subsList = next.slice(0, 32);
    });
    if (leetChars.length) {
      subsList.forEach(function (subs) {
        var text = folded.split('').map(function (c) { return subs[c] || c; }).join('');
        var before = out.length;
        scan(text);
        for (var k = before; k < out.length; k++) {
          var m = out[k];
          var used = {};
          for (var p = m.i; p <= m.j; p++) if (subs[folded[p]]) used[folded[p]] = subs[folded[p]];
          if (!Object.keys(used).length) { out.splice(k, 1); k--; continue; }   // nothing substituted: already found
          m.l33t = true;
          m.subs = used;
        }
      });
    }
    return out.concat(revOut);
  }

  function spatialMatches(chars) {
    var out = [];
    ['qwerty', 'keypad'].forEach(function (name) {
      var graph = GRAPHS[name];
      var i = 0, n = chars.length;
      while (i < n - 1) {
        var j = i + 1, lastDir = null, turns = 0;
        var shifted = name === 'qwerty' && SHIFTED.test(chars[i]) ? 1 : 0;
        for (;;) {
          var prev = chars[j - 1], found = false, foundDir = -1, dir = -1;
          var adj = graph[prev] || [];
          if (j < n) {
            var cur = chars[j];
            for (var a = 0; a < adj.length; a++) {
              dir++;
              if (adj[a] && adj[a].indexOf(cur) !== -1) {
                found = true; foundDir = dir;
                if (adj[a].indexOf(cur) === 1) shifted++;
                if (lastDir !== foundDir) { turns++; lastDir = foundDir; }
                break;
              }
            }
          }
          if (found) { j++; continue; }
          if (j - i > 2) out.push({ pattern: 'spatial', i: i, j: j - 1, token: chars.slice(i, j).join(''), graph: name, turns: turns, shifted: shifted });
          i = j;
          break;
        }
      }
    });
    return out;
  }

  function sequenceMatches(chars) {
    var out = [], n = chars.length;
    if (n < 2) return out;
    function update(i, j, delta) {
      if (j - i > 1 || Math.abs(delta) === 1) {
        if (Math.abs(delta) > 0 && Math.abs(delta) <= 5) {
          var token = chars.slice(i, j + 1).join('');
          if (token.length < 3) return;
          out.push({ pattern: 'sequence', i: i, j: j, token: token, ascending: delta > 0 });
        }
      }
    }
    var i = 0, lastDelta = null;
    for (var k = 1; k < n; k++) {
      var delta = chars[k].charCodeAt(0) - chars[k - 1].charCodeAt(0);
      if (lastDelta === null) lastDelta = delta;
      if (delta === lastDelta) continue;
      update(i, k - 1, lastDelta);
      i = k - 1;
      lastDelta = delta;
    }
    update(i, n - 1, lastDelta);
    return out;
  }

  function repeatMatches(chars, cache) {
    var out = [], s = chars.join('');
    var greedy = /(.+)\1+/g, lazy = /(.+?)\1+/g, lazyAnchored = /^(.+?)\1+$/;
    var last = 0;
    while (last < s.length) {
      greedy.lastIndex = lazy.lastIndex = last;
      var g = greedy.exec(s), l = lazy.exec(s);
      if (!g) break;
      var match, base;
      if (g[0].length > l[0].length) { match = g; base = lazyAnchored.exec(g[0])[1]; }
      else { match = l; base = l[1]; }
      var i = match.index, j = match.index + match[0].length - 1;
      var baseChars = Array.from(base);
      var baseAnalysis = guessesOf(baseChars, cache);
      out.push({ pattern: 'repeat', i: i, j: j, token: match[0], base: base, baseGuesses: baseAnalysis,
                 count: match[0].length / base.length });
      last = j + 1;
    }
    // Index fix for astral characters is not needed: chars are single UTF-16 units here or placeholders.
    return out;
  }

  var DATE_SPLITS = { 4: [[1, 2], [2, 3]], 5: [[1, 3], [2, 3]], 6: [[1, 2], [2, 4], [4, 5]],
                      7: [[1, 3], [2, 3], [4, 5], [4, 6]], 8: [[2, 4], [4, 6]] };
  function twoToFour(y) { return y > 99 ? y : y > 50 ? y + 1900 : y + 2000; }
  function intsToDm(a, b) {
    var pairs = [[a, b], [b, a]];
    for (var k = 0; k < 2; k++) {
      var d = pairs[k][0], m = pairs[k][1];
      if (d >= 1 && d <= 31 && m >= 1 && m <= 12) return { day: d, month: m };
    }
    return null;
  }
  function intsToDmy(ints) {
    if (ints[1] > 31 || ints[1] <= 0) return null;
    var over12 = 0, over31 = 0, under1 = 0;
    for (var k = 0; k < 3; k++) {
      var v = ints[k];
      if ((v > 99 && v < 1000) || v > 2050) return null;
      if (v > 31) over31++;
      if (v > 12) over12++;
      if (v <= 0) under1++;
    }
    if (over31 >= 2 || over12 === 3 || under1 >= 2) return null;
    var splits = [[ints[2], ints[0], ints[1]], [ints[0], ints[1], ints[2]]];
    for (var s = 0; s < 2; s++) {
      var y = splits[s][0];
      if (y >= 1000 && y <= 2050) {
        var dm = intsToDm(splits[s][1], splits[s][2]);
        return dm ? { year: y, month: dm.month, day: dm.day } : null;
      }
    }
    for (var t = 0; t < 2; t++) {
      var dm2 = intsToDm(splits[t][1], splits[t][2]);
      if (dm2) return { year: twoToFour(splits[t][0]), month: dm2.month, day: dm2.day };
    }
    return null;
  }

  function dateMatches(chars) {
    var s = chars.join(''), n = s.length, out = [];
    for (var i = 0; i <= n - 4; i++) {
      for (var j = i + 3; j <= i + 7 && j < n; j++) {
        var token = s.slice(i, j + 1);
        if (!/^\d+$/.test(token)) continue;
        var best = null;
        (DATE_SPLITS[token.length] || []).forEach(function (sp) {
          var dmy = intsToDmy([+token.slice(0, sp[0]), +token.slice(sp[0], sp[1]), +token.slice(sp[1])]);
          if (dmy && (!best || Math.abs(dmy.year - REFERENCE_YEAR) < Math.abs(best.year - REFERENCE_YEAR))) best = dmy;
        });
        if (best) out.push({ pattern: 'date', i: i, j: j, token: token, separator: '', year: best.year, month: best.month, day: best.day });
      }
    }
    for (var a = 0; a <= n - 6; a++) {
      for (var b = a + 5; b <= a + 9 && b < n; b++) {
        var tk = s.slice(a, b + 1);
        var m = /^(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})$/.exec(tk);
        if (!m) continue;
        var d = intsToDmy([+m[1], +m[3], +m[4]]);
        if (d) out.push({ pattern: 'date', i: a, j: b, token: tk, separator: m[2], year: d.year, month: d.month, day: d.day });
      }
    }
    // Drop dates that sit inside a bigger date ("1508" inside "15082005").
    return out.filter(function (x) {
      return !out.some(function (o) { return o !== x && o.i <= x.i && o.j >= x.j && (o.j - o.i) > (x.j - x.i); });
    });
  }

  function regexMatches(chars) {
    var s = chars.join(''), out = [], m;
    var year = /(19\d\d|20[0-4]\d)/g;
    while ((m = year.exec(s)) !== null) out.push({ pattern: 'year', i: m.index, j: m.index + 3, token: m[0], year: +m[0] });
    // Honduran phone numbers: 8 digits starting with 2, 3, 7, 8 or 9 (optionally 9999-9999, +504).
    var phone = /(?:\+?504[\s-]?)?[23789]\d{3}[\s-]?\d{4}/g;
    while ((m = phone.exec(s)) !== null) {
      var before = s[m.index - 1], after = s[m.index + m[0].length];
      if ((before && /\d/.test(before)) || (after && /\d/.test(after))) continue;
      out.push({ pattern: 'phone', i: m.index, j: m.index + m[0].length - 1, token: m[0] });
    }
    return out;
  }

  // ---------------------------------------------------------------- guessing
  function uppercaseVariations(token) {
    if (/^[^A-Z]+$/.test(token) || token.toLowerCase() === token) return 1;
    if (/^[A-Z][^A-Z]+$/.test(token) || /^[^A-Z]+[A-Z]$/.test(token) || /^[^a-z]+$/.test(token)) return 2;
    var U = (token.match(/[A-Z]/g) || []).length, L = (token.match(/[a-z]/g) || []).length, v = 0;
    for (var i = 1; i <= Math.min(U, L); i++) v += nCk(U + L, i);
    return Math.max(v, 1);
  }
  function l33tVariations(m) {
    if (!m.l33t) return 1;
    var v = 1, lower = m.token.toLowerCase();
    Object.keys(m.subs).forEach(function (sub) {
      var S = lower.split(sub).length - 1, U = lower.split(m.subs[sub]).length - 1;
      if (S === 0 || U === 0) v *= 2;
      else { var p = 0; for (var i = 1; i <= Math.min(S, U); i++) p += nCk(S + U, i); v *= p; }
    });
    return v;
  }
  function bruteforceGuesses(token) {
    var chars = Array.from(token);
    var card = Math.max(10, poolSize(charClasses(chars)));
    var g = Math.pow(card, chars.length);
    if (!isFinite(g)) g = Number.MAX_VALUE;
    return g;
  }

  function estimate(m, totalLength) {
    if (m.guesses) return m.guesses;
    var g;
    switch (m.pattern) {
      case 'dictionary':
        m.capsVariations = uppercaseVariations(m.token);
        m.l33tVariations = l33tVariations(m);
        g = m.rank * m.capsVariations * m.l33tVariations * (m.reversed ? 2 : 1);
        break;
      case 'spatial':
        var st = GRAPH_STATS[m.graph], L = m.token.length, t = m.turns;
        g = 0;
        for (var i = 2; i <= L; i++) {
          for (var j = 1; j <= Math.min(t, i - 1); j++) g += nCk(i - 1, j - 1) * st.starts * Math.pow(st.degree, j);
        }
        if (m.shifted) {
          var S = m.shifted, U = L - S;
          if (S === 0 || U === 0) g *= 2;
          else { var v = 0; for (var k = 1; k <= Math.min(S, U); k++) v += nCk(S + U, k); g *= v; }
        }
        break;
      case 'sequence':
        var first = m.token.charAt(0);
        var base = 'aAzZ019'.indexOf(first) !== -1 ? 4 : /\d/.test(first) ? 10 : 26;
        g = base * m.token.length * (m.ascending ? 1 : 2);
        break;
      case 'repeat':
        g = m.baseGuesses * m.count;
        break;
      case 'year':
        g = Math.max(Math.abs(m.year - REFERENCE_YEAR), MIN_YEAR_SPACE);
        break;
      case 'date':
        g = Math.max(Math.abs(m.year - REFERENCE_YEAR), MIN_YEAR_SPACE) * 365 * (m.separator ? 4 : 1);
        break;
      case 'phone':
        g = 1e7;   // assigned Honduran numbers, far fewer than 10^8 random digit strings
        break;
      default:
        g = bruteforceGuesses(m.token);
    }
    var len = Array.from(m.token).length;
    var min = len < totalLength ? (len === 1 ? MIN_SUBMATCH_GUESSES_SINGLE_CHAR : MIN_SUBMATCH_GUESSES_MULTI_CHAR) : 1;
    m.guesses = Math.max(g, min);
    m.guessesLog10 = log10(m.guesses);
    return m.guesses;
  }

  /** Cheapest way to split the password into matches + random leftovers (zxcvbn's algorithm). */
  function mostGuessable(chars, matches, excludeAdditive) {
    var n = chars.length;
    if (!n) return { guesses: 1, sequence: [] };
    var byJ = [];
    for (var k = 0; k < n; k++) byJ.push([]);
    matches.forEach(function (m) { byJ[m.j].push(m); });
    byJ.forEach(function (list) { list.sort(function (a, b) { return a.i - b.i; }); });
    var opt = { m: [], pi: [], g: [] };
    for (var x = 0; x < n; x++) { opt.m.push({}); opt.pi.push({}); opt.g.push({}); }

    function update(m, l) {
      var k = m.j;
      var pi = estimate(m, n);
      if (l > 1) pi *= opt.pi[m.i - 1][l - 1];
      var g = factorial(l) * pi;
      if (!excludeAdditive) g += Math.pow(MIN_GUESSES_BEFORE_GROWING_SEQUENCE, l - 1);
      for (var cl in opt.g[k]) {
        if (+cl > l) continue;
        if (opt.g[k][cl] <= g) return;
      }
      opt.g[k][l] = g; opt.m[k][l] = m; opt.pi[k][l] = pi;
    }
    function bf(i, j) { return { pattern: 'bruteforce', i: i, j: j, token: chars.slice(i, j + 1).join('') }; }
    function bruteforceUpdate(k) {
      update(bf(0, k), 1);
      for (var i = 1; i <= k; i++) {
        var lastMs = opt.m[i - 1];
        for (var l in lastMs) {
          if (lastMs[l].pattern === 'bruteforce') continue;
          update(bf(i, k), +l + 1);
        }
      }
    }
    for (var kk = 0; kk < n; kk++) {
      byJ[kk].forEach(function (m) {
        if (m.i > 0) { for (var l in opt.m[m.i - 1]) update(m, +l + 1); }
        else update(m, 1);
      });
      bruteforceUpdate(kk);
    }
    var seq = [], kEnd = n - 1, bestL = null, bestG = Infinity;
    for (var cl in opt.g[kEnd]) if (opt.g[kEnd][cl] < bestG) { bestG = opt.g[kEnd][cl]; bestL = +cl; }
    var kp = kEnd, lp = bestL;
    while (kp >= 0) { var mm = opt.m[kp][lp]; seq.unshift(mm); kp = mm.i - 1; lp--; }
    return { guesses: bestG, sequence: seq };
  }

  /** Guesses for a short token (used for the base of repeats). */
  function guessesOf(chars, cache) {
    var key = chars.join('');
    if (cache[key]) return cache[key];
    var r = mostGuessable(chars, findMatches(chars, {}, cache), true);
    cache[key] = r.guesses;
    return r.guesses;
  }

  function findMatches(chars, userMap, cache) {
    var folded = chars.map(foldChar).join('');
    var dicts = Object.assign({}, RANKED);
    if (userMap && userMap.size) dicts.user = userMap;
    return dictionaryMatches(chars, folded, dicts)
      .concat(spatialMatches(chars), sequenceMatches(chars), repeatMatches(chars, cache), dateMatches(chars), regexMatches(chars));
  }

  /** Personal data the user typed (name, birth date, pet...) -> ranked words. */
  function userInputMap(inputs) {
    var words = [];
    function addWord(w) {
      var f = Array.from(String(w)).map(foldChar).join('').replace(/[^a-z0-9]/g, '');
      if (f.length >= 3 && words.indexOf(f) === -1) words.push(f);
    }
    (inputs || []).forEach(function (raw) {
      var v = String(raw || '').trim().slice(0, 100);
      if (!v) return;
      var date = v.match(/^(\d{4})-(\d{2})-(\d{2})$/);   // from <input type="date">
      if (date) {
        var y = date[1], mo = date[2], d = date[3], yy = y.slice(2);
        [d + mo + y, d + mo + yy, y + mo + d, mo + d + y, d + mo, mo + d, y, d + '' + +mo, +d + '' + +mo + y].forEach(addWord);
        return;
      }
      addWord(v);
      v.split(/[\s,;@._-]+/).forEach(addWord);
    });
    var map = new Map();
    words.slice(0, 60).forEach(function (w, i) { map.set(w, i + 1); });
    return map;
  }

  function scoreOf(guesses) {
    for (var s = 0; s < THRESHOLDS.length; s++) if (guesses < THRESHOLDS[s]) return s;
    return 4;
  }

  function crackTimesFromGuesses(guesses) {
    var t = {};
    Object.keys(SPEED).forEach(function (k) { t[k] = guesses / SPEED[k]; });
    return t;
  }
  /** Same, from entropy bits (used by the generator). */
  function crackTimes(bits) { return crackTimesFromGuesses(Math.pow(2, Math.max(bits, 0))); }

  // ------------------------------------------------------------------- parts
  function describe(m) {
    var type = m.pattern === 'dictionary' ? DICT_TYPE[m.dict] : m.pattern === 'spatial' ? 'keyboard'
             : m.pattern === 'bruteforce' ? 'random' : m.pattern;
    var part = { type: type, token: m.token, i: m.i, j: m.j, guesses: m.guesses,
                 guessesLog10: Math.round(m.guessesLog10 * 10) / 10, bits: Math.round(m.guessesLog10 / log10(2) * 10) / 10 };
    if (m.pattern === 'dictionary') {
      part.rank = m.rank; part.word = m.word; part.dict = m.dict;
      part.l33t = !!m.l33t; part.reversed = !!m.reversed;
      part.caps = m.capsVariations === 1 ? 'none' : /^[A-Z][^A-Z]*$/.test(m.token) ? 'start' : /^[^a-z]+$/.test(m.token) ? 'all' : 'mixed';
      if (m.subs) part.subs = Object.keys(m.subs).map(function (k) { return k + '→' + m.subs[k]; });
    }
    if (m.pattern === 'spatial') { part.graph = m.graph; part.turns = m.turns; }
    if (m.pattern === 'repeat') { part.base = m.base; part.count = m.count; }
    if (m.pattern === 'sequence') part.ascending = m.ascending;
    if (m.pattern === 'date') { part.year = m.year; part.month = m.month; part.day = m.day; }
    if (m.pattern === 'year') part.year = m.year;
    return part;
  }

  // ---------------------------------------------------------------- feedback
  function feedbackFor(r) {
    var warnings = [], tips = [];
    function w(k) { if (warnings.indexOf(k) === -1) warnings.push(k); }
    function s(k) { if (tips.indexOf(k) === -1) tips.push(k); }
    var parts = r.sequence, types = parts.map(function (p) { return p.type; });
    var only = parts.length === 1 ? parts[0] : null;

    if (only && only.type === 'passwords') w(only.rank <= 10 ? 'top10' : only.rank <= 100 ? 'top100' : 'commonPassword');
    if (types.indexOf('personal') !== -1) w('personal');
    parts.forEach(function (p) {
      if (p.type === 'passwords' && !only) w('containsCommon');
      if (p.type === 'honduras') w('honduras');
      if (p.type === 'name' || p.type === 'surname') w('name');
      if (p.type === 'word' && !only) w('containsWord');
      if (p.type === 'word' && only) w('singleWord');
      if (p.type === 'keyboard') w('keyboardPattern');
      if (p.type === 'sequence') w('sequencePattern');
      if (p.type === 'repeat') w('repeatPattern');
      if (p.type === 'date') w('containsDate');
      if (p.type === 'year') w('containsYear');
      if (p.type === 'phone') w('containsPhone');
      if (p.l33t) w('leetNotEnough');
      if (p.caps === 'start' || p.caps === 'all') w('capsPredictable');
      if (p.reversed) w('reversedWord');
    });
    // "Word + 2008!" style endings: the attacker's favourite add-ons
    var last = parts[parts.length - 1];
    if (parts.length > 1 && last && last.type === 'random' && Array.from(last.token).length <= 3 && /^[\d!@#$%&*.?_-]+$/.test(last.token)) w('predictableEnding');

    if (r.length < 8) w('tooShort');
    else if (r.length < 12 && r.score < 4) s('longer');
    if (types.indexOf('personal') !== -1 || types.indexOf('date') !== -1 || types.indexOf('phone') !== -1) s('avoidPersonal');
    if (warnings.indexOf('leetNotEnough') !== -1) s('noLeet');
    if (warnings.indexOf('capsPredictable') !== -1) s('capsMiddle');
    if (r.score <= 2) s('usePassphrase');
    if (r.score === 3) s('addWord');
    if (r.score >= 3) s('uniquePerSite');
    if (r.score === 4 && !warnings.length) s('excellent');
    s('useManager');
    return { warnings: warnings, suggestions: tips };
  }

  // ---------------------------------------------------------------------- api
  /**
   * Analyze a password.
   * @param {string} password
   * @param {string[]} [userInputs] personal data to watch for (name, birth date "YYYY-MM-DD", pet, team...)
   */
  function analyzePassword(password, userInputs) {
    var pw = Array.from(String(password || '')).slice(0, MAX_LENGTH);
    // Characters outside the BMP (emoji) become one placeholder each so indexes stay simple.
    var chars = pw.map(function (c) { return c.length === 1 ? c : '�'; });
    var classes = charClasses(pw);
    var result = {
      length: pw.length, classes: classes, poolSize: poolSize(classes),
      guesses: 1, guessesLog10: 0, entropy: 0, score: 0,
      sequence: [], patterns: [], warnings: [], suggestions: [], feedback: [],
      isCommon: false, crackTimes: crackTimesFromGuesses(1)
    };
    if (!pw.length) return result;

    var head = chars.slice(0, MAX_MATCH), tail = chars.slice(MAX_MATCH);
    var cache = {};
    var matches = findMatches(head, userInputMap(userInputs), cache);
    var best = mostGuessable(head, matches, false);
    var log = log10(best.guesses);
    if (tail.length) log += tail.length * log10(Math.max(10, poolSize(charClasses(tail))));   // the rest counts as random

    result.guessesLog10 = Math.round(log * 100) / 100;
    result.guesses = Math.pow(10, log);
    result.entropy = Math.round(log / log10(2) * 10) / 10;
    result.score = scoreOf(result.guesses);
    if (pw.length < 8) result.score = Math.min(result.score, 1);
    result.sequence = best.sequence.map(describe);
    if (tail.length) result.sequence.push({ type: 'random', token: tail.join(''), i: MAX_MATCH, j: pw.length - 1, guessesLog10: Math.round((log - log10(best.guesses)) * 10) / 10, bits: 0 });
    result.patterns = result.sequence.filter(function (p) { return p.type !== 'random'; });
    result.isCommon = result.sequence.length === 1 && result.sequence[0].type === 'passwords';
    result.crackTimes = crackTimesFromGuesses(result.guesses);
    var fb = feedbackFor(result);
    result.warnings = fb.warnings;
    result.suggestions = fb.suggestions;
    result.feedback = fb.warnings.concat(fb.suggestions);
    result.breakdown = {
      guessesLog10: result.guessesLog10, matchesFound: matches.length, parts: result.sequence.length,
      bitsPerChar: Math.round(Math.log2(Math.max(result.poolSize, 1)) * 100) / 100,
      naiveBits: Math.round(pw.length * Math.log2(Math.max(result.poolSize, 1)) * 10) / 10
    };
    return result;
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
              crackTimesFromGuesses: crackTimesFromGuesses, scoreOf: scoreOf, SPEED: SPEED, THRESHOLDS: THRESHOLDS,
              MAX_LENGTH: MAX_LENGTH };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.password = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
