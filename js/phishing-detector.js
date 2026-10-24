/*!
 * SworfishGuard — Phishing URL Detector (heuristic)
 *
 * Looks at a link WITHOUT opening it and checks for warning signs commonly
 * used in phishing: fake brand domains, look-alike letters (paypa1), letters
 * from other alphabets (homograph attacks), IP addresses instead of names,
 * the "@" trick, risky TLDs, URL shorteners, free hosting, urgent keywords...
 *
 * IMPORTANT: this is a heuristic teaching tool. A legitimate link can raise
 * warnings and a phishing link on a "clean" domain can pass. When in doubt,
 * type the official address yourself instead of clicking.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var DATA = (root.SworfishGuard && root.SworfishGuard.data) ||
             (typeof require === 'function' ? require('./brands.js') : null);
  if (!DATA) throw new Error('brands.js must be loaded before phishing-detector.js');

  var MAX_URL_LENGTH = 2048;

  var KEYWORDS = ['login', 'signin', 'sign-in', 'verify', 'verification', 'account', 'update',
    'secure', 'security', 'banking', 'confirm', 'password', 'wallet', 'suspend', 'unlock',
    'billing', 'reward', 'gift', 'free', 'verificar', 'cuenta', 'confirmar', 'actualizar',
    'seguridad', 'contrasena', 'bloqueo', 'bloqueada', 'premio', 'gratis', 'regalo',
    'iniciar-sesion', 'sesion', 'reembolso', 'refund', 'aduana', 'paquete', 'tracking',
    'acceso', 'ingreso', 'bancaenlinea', 'banca-en-linea', 'pago', 'pagar'];

  // Severity -> points added to the risk score.
  var WEIGHT = { critical: 45, high: 30, medium: 12, low: 5, info: 0 };

  // Letters from other alphabets that look like Latin letters (homograph attacks).
  var CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
    'ԁ': 'd', 'ѕ': 's', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'к': 'k', 'м': 'm', 'т': 't',
    'в': 'b', 'н': 'h', 'п': 'n', 'ь': 'b', 'ɡ': 'g', 'ɑ': 'a', 'ı': 'i', 'ł': 'l',
    'ο': 'o', 'α': 'a', 'ε': 'e', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'ν': 'v',
    'χ': 'x', 'β': 'b', 'η': 'n', 'ω': 'w'
  };

  // ------------------------------------------------------------ helpers
  function levenshtein(a, b) {
    if (a === b) return 0;
    if (Math.abs(a.length - b.length) > 3) return 99;   // cheap early exit
    var prev = [], cur, i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      cur = [i];
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  /** Undo common look-alike tricks: paypa1 -> paypal, rn -> m, vv -> w. */
  function deLookalike(s) {
    return s.replace(/rn/g, 'm').replace(/vv/g, 'w')
      .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
      .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/\$/g, 's');
  }

  /** Replace letters from other alphabets with the Latin letter they imitate. */
  function skeleton(s) {
    return Array.from(s).map(function (c) { return CONFUSABLES[c] || c; }).join('');
  }

  function scriptsOf(s) {
    var found = {};
    Array.from(s).forEach(function (c) {
      var cp = c.codePointAt(0);
      if (/[a-z0-9-]/.test(c)) found.latin = true;
      else if (cp >= 0xC0 && cp <= 0x24F) found.latin = true;           // á, ñ, ü...
      else if (cp >= 0x0400 && cp <= 0x052F) found.cyrillic = true;
      else if (cp >= 0x0370 && cp <= 0x03FF) found.greek = true;
      else if (c !== '.') found.other = true;
    });
    return found;
  }

  /** Punycode decoder (RFC 3492) — turns "xn--pypal-4ve" back into "pаypal". */
  function punycodeDecode(input) {
    var base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    var output = [], i = 0, n = 128, bias = 72;
    if (input.length > 63) throw new Error('label too long');
    var basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (var j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) throw new Error('invalid input');
      output.push(input.charCodeAt(j));
    }
    function digitOf(c) {
      if (c >= 48 && c <= 57) return c - 22;   // 0-9 -> 26-35
      if (c >= 65 && c <= 90) return c - 65;   // A-Z -> 0-25
      if (c >= 97 && c <= 122) return c - 97;  // a-z -> 0-25
      return base;
    }
    function adapt(delta, numPoints, first) {
      var k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
    }
    for (var index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      var oldi = i, w = 1;
      for (var k = base; ; k += base) {
        if (index >= input.length) throw new Error('invalid input');
        var digit = digitOf(input.charCodeAt(index++));
        if (digit >= base) throw new Error('invalid input');
        i += digit * w;
        var t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
        if (digit < t) break;
        w *= base - t;
      }
      var out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      if (n > 0x10FFFF) throw new Error('invalid code point');
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint.apply(null, output);
  }

  function toUnicodeHost(host) {
    return host.split('.').map(function (label) {
      if (label.indexOf('xn--') !== 0) return label;
      try { return punycodeDecode(label.slice(4)); } catch (e) { return label; }
    }).join('.');
  }

  /** "login.paypal.com.evil.xyz" -> { registered: "evil.xyz", label: "evil", tld: "xyz", sub: [...] } */
  function splitHost(host) {
    var labels = host.split('.').filter(Boolean);
    var lastTwo = labels.slice(-2).join('.');
    var n = (labels.length >= 3 && DATA.MULTI_SUFFIXES.indexOf(lastTwo) !== -1) ? 3 : 2;
    var registeredLabels = labels.slice(-n);
    return {
      registered: registeredLabels.join('.'),
      label: registeredLabels[0] || '',
      tld: labels[labels.length - 1] || '',
      sub: labels.slice(0, Math.max(labels.length - n, 0))
    };
  }

  function isIPv4(host) {
    return /^(\d{1,3})(\.\d{1,3}){3}$/.test(host) &&
      host.split('.').every(function (p) { return +p <= 255; });
  }

  function tokensOf(s) { return s.split(/[-_.0-9]+/).filter(Boolean); }

  /** Long keywords match anywhere; short ones (<6) only as a whole word. */
  function hasKeyword(text, tokens, kw) {
    return kw.length >= 6 ? text.indexOf(kw) !== -1 : tokens.indexOf(kw) !== -1;
  }

  /** How many typos we tolerate before calling a domain a copy of a brand. */
  function closeTo(candidate, official) {
    if (candidate === official) return false;
    if (official.length >= 8) return levenshtein(candidate, official) <= 2;
    if (official.length >= 6) return levenshtein(candidate, official) === 1;
    return false;   // too short: only digit/letter swaps count (handled by deLookalike)
  }

  function hostMatches(host, list) {
    return list.some(function (d) { return host === d || host.slice(-(d.length + 1)) === '.' + d; });
  }

  // -------------------------------------------------------------- main
  /**
   * Analyze a URL string.
   * @param {string} input
   * @returns {object} { valid, href, host, unicodeHost, registeredDomain, score, level, findings[], details }
   */
  function analyzeUrl(input) {
    var raw = String(input || '').trim();
    var findings = [];
    function add(id, severity, detail) { findings.push({ id: id, severity: severity, detail: detail || '' }); }

    if (!raw) return { valid: false, error: 'empty', findings: [] };
    if (raw.length > MAX_URL_LENGTH) return { valid: false, error: 'tooLong', findings: [] };

    // Dangerous non-web schemes.
    if (/^\s*(javascript|data|vbscript|file):/i.test(raw)) {
      add('dangerousScheme', 'critical', raw.split(':')[0].toLowerCase());
      return finish({ valid: true, href: raw, host: '', unicodeHost: '', registeredDomain: '', details: {} }, findings);
    }

    var hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
    var url;
    try {
      url = new URL(hadScheme ? raw : 'http://' + raw);
    } catch (e) {
      return { valid: false, error: 'invalid', findings: [] };
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { valid: false, error: 'scheme', findings: [] };
    }

    var host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!host) return { valid: false, error: 'invalid', findings: [] };
    var unicodeHost = toUnicodeHost(host);
    var ipHost = isIPv4(host) || host.indexOf('[') === 0 || host.indexOf(':') !== -1;
    var parts = ipHost ? { registered: host, label: '', tld: '', sub: [] } : splitHost(host);
    var uParts = ipHost ? parts : splitHost(unicodeHost);

    var info = {
      valid: true, href: url.href, host: host, unicodeHost: unicodeHost,
      registeredDomain: parts.registered, scheme: url.protocol.replace(':', ''),
      path: url.pathname + url.search,
      details: {
        port: url.port || (url.protocol === 'https:' ? '443' : '80'),
        subdomains: parts.sub, tld: parts.tld,
        skeleton: skeleton(uParts.label), params: Array.from(url.searchParams.keys()).length
      }
    };

    // --- Connection & structure -------------------------------------------
    if (hadScheme && url.protocol === 'http:') add('noHttps', 'medium');
    if (url.username || url.password) add('atSymbol', 'high', decodeURIComponent(url.username));
    if (ipHost) {
      add('ipAddress', 'high', host);
      // "http://3232235777" or "0xC0A80101" are IP addresses in disguise.
      var rawHost = raw.replace(/^[a-z]+:\/\//i, '').split(/[/?#:]/)[0].replace(/^.*@/, '');
      if (rawHost && rawHost.toLowerCase() !== host) add('obfuscatedIp', 'high', rawHost);
    }
    if (url.port && url.port !== '80' && url.port !== '443') add('unusualPort', 'medium', url.port);

    // --- Internationalized domains & homographs -----------------------------
    var homographBrand = null;
    if (/(^|\.)xn--/.test(host)) {
      var scripts = scriptsOf(unicodeHost);
      var skel = skeleton(uParts.label).replace(/-/g, '');
      DATA.BRANDS.some(function (b) {
        var offLabels = b.domains.map(function (d) { return splitHost(d).label; });
        if (offLabels.indexOf(skel) !== -1 || b.keywords.some(function (k) { return k.length >= 5 && skel.indexOf(k) !== -1; })) {
          homographBrand = b.name; return true;
        }
        return false;
      });
      if (homographBrand) add('homograph', 'critical', homographBrand);
      else if (scripts.latin && (scripts.cyrillic || scripts.greek)) add('mixedScripts', 'high', unicodeHost);
      else if (scripts.cyrillic || scripts.greek || scripts.other) add('punycode', 'medium', unicodeHost);
      else add('idnLatin', 'low', unicodeHost);   // e.g. "españa": normal in Spanish
    }

    if (!ipHost) {
      if (parts.sub.filter(function (s) { return s !== 'www'; }).length >= 3) add('manySubdomains', 'medium', String(parts.sub.length));
      if (DATA.RISKY_TLDS.indexOf(parts.tld) !== -1) add('riskyTld', 'medium', '.' + parts.tld);
      else if (DATA.CAUTION_TLDS.indexOf(parts.tld) !== -1) add('cautionTld', 'low', '.' + parts.tld);
      if ((unicodeHost.match(/-/g) || []).length >= 3) add('manyHyphens', 'low');
    }
    if (DATA.SHORTENERS.indexOf(parts.registered) !== -1 || DATA.SHORTENERS.indexOf(host) !== -1) add('shortener', 'medium', host);
    var userContent = hostMatches(host, DATA.FREE_HOSTS);
    if (userContent) add('freeHosting', 'low', host);
    if (raw.length > 100) add('longUrl', 'low', String(raw.length));
    if (url.pathname.indexOf('//') !== -1) add('doubleSlash', 'low');
    if (/[?&][^=]*=(https?%3a|https?:)/i.test(url.search)) add('redirectParam', 'medium');
    if ((raw.match(/%[0-9a-f]{2}/gi) || []).length > 10) add('heavyEncoding', 'low');

    // --- Brand impersonation ----------------------------------------------
    var labelPlain = parts.label.replace(/-/g, '');
    var labelTokens = tokensOf(parts.label);
    var subText = parts.sub.join('.');
    var subTokens = tokensOf(subText);
    var officialFor = null;

    if (!ipHost) {
      DATA.BRANDS.forEach(function (b) {
        if (b.domains.indexOf(parts.registered) !== -1) { officialFor = b.name; return; }
        if (homographBrand === b.name) return;

        var offLabels = b.domains.map(function (d) { return splitHost(d).label; });
        var candidates = offLabels.concat(b.keywords.filter(function (k) { return k.length >= 6; }));
        var looks = deLookalike(labelPlain);
        var nearOfficial = candidates.some(function (c) {
          return closeTo(labelPlain, c) || (looks !== labelPlain && (looks === c || (c.length >= 5 && looks.indexOf(c) !== -1)));
        });

        if (nearOfficial) {
          add('lookalike', 'critical', b.name);                                   // paypa1.com, steamcommunlty.com
        } else if (b.keywords.some(function (k) { return hasKeyword(subText, subTokens, k); })) {
          add('brandInSubdomain', 'high', b.name);                                // paypal.com.evil.xyz
        } else if (b.keywords.some(function (k) { return hasKeyword(labelPlain, labelTokens, k); })) {
          add('brandInDomain', 'high', b.name);                                   // paypal-seguridad.com
        } else if (b.keywords.some(function (k) { return k.length >= 5 && url.pathname.toLowerCase().indexOf(k) !== -1; })) {
          add('brandInPath', 'medium', b.name);                                   // evil.com/paypal/login
        }
      });
    }
    if (officialFor) add('officialDomain', 'info', officialFor);

    // --- Urgency / credential keywords (skipped on official brand domains) ----
    var lowerAll = (host + url.pathname).toLowerCase();
    var hits = (officialFor && !userContent) ? [] : KEYWORDS.filter(function (k) { return lowerAll.indexOf(k) !== -1; });
    if (hits.length >= 2) add('keywords', 'medium', hits.slice(0, 4).join(', '));
    else if (hits.length === 1) add('keywords', 'low', hits[0]);

    return finish(info, findings);
  }

  function finish(info, findings) {
    var score = findings.reduce(function (s, f) { return s + WEIGHT[f.severity]; }, 0);
    score = Math.min(score, 100);
    info.score = score;
    var hasCritical = findings.some(function (f) { return f.severity === 'critical'; });
    info.level = (score >= 40 || hasCritical) ? 'high' : score >= 20 ? 'medium' : 'low';
    info.official = findings.some(function (f) { return f.id === 'officialDomain'; }) &&
      !findings.some(function (f) { return f.id === 'freeHosting'; }) && score < 20;
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    info.findings = findings.sort(function (a, b) { return order[a.severity] - order[b.severity]; });
    info.breakdown = info.findings.map(function (f) { return { id: f.id, points: WEIGHT[f.severity] }; });
    return info;
  }

  /** Pulls every link-looking string out of a block of text (used by the scam detector). */
  function extractUrls(text) {
    var re = /\b((?:https?:\/\/|www\.)[^\s<>"'()]+|(?:[a-z0-9-]+\.)+(?:com|net|org|hn|info|xyz|top|online|site|link|click|shop|me|ly|gl|co|io|app|live|bond|help|win|cfd|xin|icu|gg)(?:\/[^\s<>"'()]*)?)/gi;
    var out = [], m, s = String(text || '').slice(0, 10000);
    while ((m = re.exec(s)) !== null && out.length < 20) {
      var u = m[1].replace(/[.,;:!?)\]]+$/, '');
      if (out.indexOf(u) === -1) out.push(u);
    }
    return out;
  }

  var api = {
    analyzeUrl: analyzeUrl, splitHost: splitHost, levenshtein: levenshtein, punycodeDecode: punycodeDecode,
    toUnicodeHost: toUnicodeHost, skeleton: skeleton, extractUrls: extractUrls, WEIGHT: WEIGHT
  };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.phishing = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
