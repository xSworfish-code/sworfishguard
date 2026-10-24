/*!
 * SworfishGuard — Breach Check (Have I Been Pwned, Pwned Passwords API)
 *
 * Privacy by design — k-anonymity:
 *   1. The password is hashed with SHA-1 locally, in the browser.
 *   2. Only the FIRST 5 characters of the hash are sent to the API.
 *   3. The API answers with every leaked hash that starts with those 5
 *      characters (hundreds of them), and we compare the rest locally.
 *   The service never sees the password or even its full hash.
 *
 * Hardening:
 *   - 10 s timeout (AbortController), no cookies, no referrer, no cache.
 *   - The response is validated line by line; anything that is not
 *     "35 hex chars : number" is rejected, so a tampered response cannot
 *     inject unexpected data into the page.
 *   - Response size is capped.
 *
 * API docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var API_URL = 'https://api.pwnedpasswords.com/range/';
  var TIMEOUT_MS = 10000;
  var MAX_BODY = 2 * 1024 * 1024;           // 2 MB is far above a normal response (~30-40 KB)
  var LINE_RE = /^[0-9A-F]{35}:\d{1,10}$/;

  function getCrypto() {
    var c = (typeof root.crypto !== 'undefined') ? root.crypto : null;
    if (!c || !c.subtle) throw new Error('Web Crypto API not available (use HTTPS or a modern browser).');
    return c;
  }

  function toHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(function (b) { return b.toString(16).padStart(2, '0'); })
      .join('').toUpperCase();
  }

  /** SHA-1 of a UTF-8 string, as uppercase hex. */
  async function sha1Hex(text) {
    var data = new TextEncoder().encode(String(text));
    return toHex(await getCrypto().subtle.digest('SHA-1', data));
  }

  /**
   * Parses the API response ("SUFFIX:COUNT" per line), validating every line.
   * Padding lines (count 0) added by the API are counted but never matched.
   * @returns {{count:number, lines:number, padding:number}}
   */
  function parseRangeResponse(body, suffix) {
    var target = String(suffix).toUpperCase();
    var lines = String(body).split(/\r?\n/).filter(function (l) { return l.trim() !== ''; });
    var result = { count: 0, lines: lines.length, padding: 0 };
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim().toUpperCase();
      if (!LINE_RE.test(line)) throw new Error('Unexpected response format');
      var parts = line.split(':');
      var n = parseInt(parts[1], 10);
      if (n === 0) { result.padding++; continue; }
      if (parts[0] === target) result.count = n;
    }
    return result;
  }

  function withTimeout(promise, ms, controller) {
    var timer;
    var timeout = new Promise(function (_, reject) {
      timer = setTimeout(function () {
        if (controller) controller.abort();
        reject(new Error('timeout'));
      }, ms);
    });
    return Promise.race([promise, timeout]).finally(function () { clearTimeout(timer); });
  }

  /**
   * Checks whether a password appears in known data breaches.
   * @param {string} password
   * @param {function} [fetchFn] injectable fetch (used by the tests)
   */
  async function checkPassword(password, fetchFn) {
    if (!password) throw new Error('Empty password');
    var doFetch = fetchFn || root.fetch.bind(root);
    var started = Date.now();
    var hash = await sha1Hex(password);
    var prefix = hash.slice(0, 5);
    var suffix = hash.slice(5);
    var url = API_URL + prefix;
    var base = { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', mode: 'cors' };

    function attempt(withPadding) {
      var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
      var opts = Object.assign({}, base, controller ? { signal: controller.signal } : {});
      // "Add-Padding" makes every response look the same size (extra privacy).
      if (withPadding) opts.headers = { 'Add-Padding': 'true' };
      return withTimeout(doFetch(url, opts), TIMEOUT_MS, controller);
    }

    var res, padded = true;
    try {
      res = await attempt(true);
    } catch (e) {
      if (e && e.message === 'timeout') throw e;
      // If the padding header is blocked by the browser/CORS, retry without it.
      padded = false;
      res = await attempt(false);
    }
    if (!res.ok) throw new Error('API error: HTTP ' + res.status);
    var body = await res.text();
    if (body.length > MAX_BODY) throw new Error('Response too large');
    var parsed = parseRangeResponse(body, suffix);

    return {
      found: parsed.count > 0, count: parsed.count, prefix: prefix, suffix: suffix, hash: hash,
      stats: { url: url, lines: parsed.lines, padding: parsed.padding, padded: padded,
               bytes: body.length, ms: Date.now() - started }
    };
  }

  var api = { sha1Hex: sha1Hex, toHex: toHex, parseRangeResponse: parseRangeResponse, checkPassword: checkPassword };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.breach = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
