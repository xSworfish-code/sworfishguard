/*!
 * SworfishGuard — Email header analyzer
 *
 * The "From" of an email is just text: anyone can write "BAC Credomatic" in
 * it. What can't be faked so easily are the checks the receiving server
 * already did and wrote in the headers (Authentication-Results):
 *   - SPF:   was the email sent from a server the domain allows?
 *   - DKIM:  is the domain's digital signature valid (the mail wasn't changed)?
 *   - DMARC: do those checks match the domain shown in "From"?
 * This module reads those results and also compares From, Reply-To,
 * Return-Path and the display name, which is where most email scams show.
 *
 * Paste the full headers ("Show original" in Gmail, "View message source"
 * in Outlook). Everything runs in the browser.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var SG = root.SworfishGuard || {};
  var phishing = SG.phishing || (typeof require === 'function' ? require('./phishing-detector.js') : null);
  var DATA = SG.data || (typeof require === 'function' ? require('./brands.js') : null);

  var MAX_TEXT = 200000;
  var WEIGHT = { critical: 45, high: 30, medium: 12, low: 5, info: 0 };
  var FREE_MAIL = ['gmail.com', 'googlemail.com', 'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'yahoo.com',
    'yahoo.es', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'aol.com', 'gmx.com', 'mail.com', 'yandex.com', 'zoho.com'];

  // ---------------------------------------------------------------- parsing
  /** Decodes =?UTF-8?B?...?= and =?UTF-8?Q?...?= words (RFC 2047). */
  function decodeWords(s) {
    return String(s).replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=(\s+(?==\?))?/g, function (all, charset, enc, text) {
      try {
        var bytes;
        if (enc.toUpperCase() === 'B') {
          var bin = typeof atob === 'function' ? atob(text) : Buffer.from(text, 'base64').toString('binary');
          bytes = Uint8Array.from(bin, function (c) { return c.charCodeAt(0); });
        } else {
          var q = text.replace(/_/g, ' ');
          var arr = [];
          for (var i = 0; i < q.length; i++) {
            if (q[i] === '=' && /^[0-9a-f]{2}$/i.test(q.substr(i + 1, 2))) { arr.push(parseInt(q.substr(i + 1, 2), 16)); i += 2; }
            else arr.push(q.charCodeAt(i) & 255);
          }
          bytes = Uint8Array.from(arr);
        }
        return new TextDecoder(/^utf-?8$/i.test(charset) ? 'utf-8' : charset.toLowerCase(), { fatal: false }).decode(bytes);
      } catch (e) { return all; }
    });
  }

  /** Unfolds continuation lines and returns [{name, value}] in order (top first). */
  function parseHeaders(text) {
    var lines = String(text || '').slice(0, MAX_TEXT).replace(/\r\n?/g, '\n').split('\n');
    var list = [];
    var started = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line.trim()) { if (started) break; else continue; }
      if (/^[ \t]/.test(line) && list.length) { list[list.length - 1].value += ' ' + line.trim(); continue; }
      var m = line.match(/^([!-9;-~]{1,80}):\s?(.*)$/);   // header name: printable ASCII except ":"
      if (!m) continue;
      started = true;
      list.push({ name: m[1].toLowerCase(), value: m[2].trim() });
    }
    return list;
  }

  /** "Name" <user@domain> -> {name, address, domain} */
  function parseAddress(value) {
    if (!value) return null;
    var v = decodeWords(value).trim();
    var angle = v.match(/<\s*([^<>\s]+@[^<>\s]+)\s*>/);
    var address = angle ? angle[1] : (v.match(/[^\s<>"',;]+@[^\s<>"',;]+/) || [''])[0];
    var name = angle ? v.slice(0, v.indexOf('<')).replace(/^["'\s]+|["'\s]+$/g, '').trim() : '';
    address = address.replace(/^mailto:/i, '').replace(/[>.]+$/, '').toLowerCase();
    var at = address.lastIndexOf('@');
    return { name: name, address: address, domain: at === -1 ? '' : address.slice(at + 1).replace(/[^a-z0-9.-]/g, '') };
  }

  function registered(domain) {
    if (!domain) return '';
    try { return phishing.splitHost(domain.toLowerCase()).registered; } catch (e) { return domain; }
  }
  function aligned(a, b) { return !!a && !!b && registered(a) === registered(b); }

  function authResult(text, method) {
    var re = new RegExp('\\b' + method + '\\s*=\\s*([a-z]+)', 'gi');
    var m, list = [];
    while ((m = re.exec(text)) !== null) list.push(m[1].toLowerCase());
    return list;
  }

  function parseReceived(value) {
    var from = (value.match(/\bfrom\s+([^\s;()]+)/i) || [])[1] || '';
    var by = (value.match(/\bby\s+([^\s;()]+)/i) || [])[1] || '';
    var ip = (value.match(/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]+:[0-9a-f:]+)\]/i) || [])[1] || '';
    var date = value.indexOf(';') !== -1 ? value.slice(value.lastIndexOf(';') + 1).trim() : '';
    return { from: from, by: by, ip: ip, date: date };
  }

  function fold(s) { return String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, ''); }

  // ---------------------------------------------------------------- analyze
  /**
   * @param {string} text raw headers (a full message also works; the body is ignored)
   * @returns {object} { valid, score, level, findings[], from, replyTo, returnPath, subject, date, auth, hops[] }
   */
  function analyzeHeaders(text) {
    var headers = parseHeaders(text);
    if (headers.length < 2) return { valid: false, error: headers.length ? 'tooShort' : 'empty', findings: [] };
    var get = function (n) { for (var i = 0; i < headers.length; i++) if (headers[i].name === n) return headers[i].value; return ''; };
    var all = function (n) { return headers.filter(function (h) { return h.name === n; }).map(function (h) { return h.value; }); };

    var findings = [];
    function add(id, severity, detail) { findings.push({ id: id, severity: severity, detail: detail || '' }); }

    var from = parseAddress(get('from'));
    var replyTo = parseAddress(get('reply-to'));
    var returnPath = parseAddress(get('return-path'));
    var subject = decodeWords(get('subject'));
    var authHeader = all('authentication-results')[0] || all('arc-authentication-results')[0] || '';
    var receivedSpf = (get('received-spf').match(/^\s*([a-z]+)/i) || [])[1];
    var dkimDomains = all('dkim-signature').map(function (v) { return ((v.match(/\bd=([^;\s]+)/i) || [])[1] || '').toLowerCase(); }).filter(Boolean);

    var spfList = authResult(authHeader, 'spf');
    var dkimList = authResult(authHeader, 'dkim');
    var dmarcList = authResult(authHeader, 'dmarc');
    var auth = {
      present: !!authHeader,
      spf: spfList[0] || (receivedSpf ? receivedSpf.toLowerCase() : 'none'),
      dkim: dkimList.indexOf('pass') !== -1 ? 'pass' : dkimList[0] || (dkimDomains.length ? 'unchecked' : 'none'),
      dmarc: dmarcList[0] || 'none',
      dkimDomains: dkimDomains,
      headerDkimDomain: ((authHeader.match(/header\.(?:d|i)=@?([^;\s]+)/i) || [])[1] || '').toLowerCase(),
      mailFrom: ((authHeader.match(/smtp\.mailfrom=([^;\s]+)/i) || [])[1] || '').toLowerCase()
    };

    // --- From --------------------------------------------------------------
    if (!from || !from.address) add('noFrom', 'high');
    var fromDomain = from ? from.domain : '';
    var fromCheck = fromDomain ? phishing.analyzeUrl('https://' + fromDomain) : null;
    var officialBrand = fromCheck && fromCheck.official
      ? (fromCheck.findings.filter(function (f) { return f.id === 'officialDomain'; })[0] || {}).detail : '';

    // --- Authentication (what the receiving server checked) ----------------
    if (!auth.present && !receivedSpf) add('noAuth', 'info');
    if (auth.dmarc === 'fail') add('dmarcFail', 'critical', fromDomain);
    if (auth.spf === 'fail') add('spfFail', 'high');
    else if (auth.spf === 'softfail') add('spfSoftfail', 'medium');
    else if (auth.present && (auth.spf === 'none' || auth.spf === 'neutral')) add('spfNone', 'low');
    if (auth.dkim === 'fail') add('dkimFail', 'high');
    else if (auth.present && auth.dkim === 'none') add('dkimNone', 'low');
    if (auth.dkim === 'pass' && auth.dmarc !== 'pass' && fromDomain) {
      var signed = auth.headerDkimDomain || dkimDomains[0] || '';
      if (signed && !aligned(signed, fromDomain)) add('dkimNotAligned', 'medium', signed);
    }

    // --- Display name tricks -----------------------------------------------
    if (from && from.name) {
      var inName = parseAddress(from.name);
      if (inName && inName.address && inName.domain && !aligned(inName.domain, fromDomain)) add('nameHasEmail', 'high', inName.address);
      // Only the display name: words like "claro" are too common in subjects.
      var nameText = fold(from.name).replace(/[^a-z0-9]+/g, ' ');
      var nameTokens = nameText.split(' ');
      var claimed = DATA.BRANDS.filter(function (b) {
        return b.keywords.some(function (k) { return k.length >= 6 ? nameText.replace(/ /g, '').indexOf(k) !== -1 : nameTokens.indexOf(k) !== -1; }) ||
               nameTokens.indexOf(fold(b.name).replace(/[^a-z0-9]+/g, '')) !== -1;
      })[0];
      if (claimed && fromDomain && !claimed.domains.some(function (d) { return aligned(d, fromDomain); })) {
        if (FREE_MAIL.indexOf(fromDomain) !== -1) add('freeMailBrand', 'critical', claimed.name);
        else add('brandMismatch', 'high', claimed.name);
      }
    }

    // --- Suspicious From domain (lookalikes, risky endings...) -------------
    if (fromCheck && fromCheck.valid && !fromCheck.official) {
      if (fromCheck.level === 'high') add('fromDomainBad', 'high', fromDomain);
      else if (fromCheck.level === 'medium') add('fromDomainOdd', 'medium', fromDomain);
    }

    // --- Where answers and bounces go ---------------------------------------
    if (replyTo && replyTo.domain && fromDomain && !aligned(replyTo.domain, fromDomain)) add('replyToDiffers', 'medium', replyTo.address);
    if (returnPath && returnPath.domain && fromDomain && !aligned(returnPath.domain, fromDomain)) add('returnPathDiffers', 'low', returnPath.domain);
    var msgId = get('message-id');
    var msgDomain = ((msgId.match(/@([^>\s]+)>?/) || [])[1] || '').toLowerCase();
    if (msgDomain && fromDomain && !aligned(msgDomain, fromDomain)) add('messageIdDiffers', 'info', msgDomain);

    var hops = all('received').map(parseReceived).reverse(); // first hop first

    var score = Math.min(100, findings.reduce(function (s, f) { return s + WEIGHT[f.severity]; }, 0));
    var hasCritical = findings.some(function (f) { return f.severity === 'critical'; });
    var level = hasCritical || score >= 45 ? 'high' : score >= 15 ? 'medium' : 'low';
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort(function (a, b) { return order[a.severity] - order[b.severity]; });
    return {
      valid: true, score: score, level: level, findings: findings,
      official: !!officialBrand && auth.dmarc === 'pass' && level === 'low', brand: officialBrand,
      from: from, replyTo: replyTo, returnPath: returnPath, subject: subject, date: get('date'),
      auth: auth, hops: hops, headerCount: headers.length,
      breakdown: findings.map(function (f) { return { id: f.id, points: WEIGHT[f.severity] }; })
    };
  }

  var api = { analyzeHeaders: analyzeHeaders, parseHeaders: parseHeaders, parseAddress: parseAddress, decodeWords: decodeWords, FREE_MAIL: FREE_MAIL };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.email = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
