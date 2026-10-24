/*!
 * SworfishGuard — File Fingerprint (hash) Checker
 *
 * Computes the SHA-256 (and optionally SHA-1 / SHA-512) "fingerprint" of a
 * file inside the browser. If you download a program and the developer
 * publishes its SHA-256, matching fingerprints prove the file was not
 * modified or corrupted. The file is read locally; it is never uploaded.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var MAX_BYTES = 512 * 1024 * 1024;   // 512 MB: hashing needs the whole file in memory
  var ALGORITHMS = ['SHA-256', 'SHA-1', 'SHA-512'];
  var LENGTHS = { 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512' };

  function toHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  /** Cleans a pasted hash: removes spaces, "sha256:" prefixes and file names after it. */
  function normalizeHash(input) {
    var s = String(input || '').trim().toLowerCase();
    s = s.replace(/^(sha-?(1|256|512)\s*[:=]\s*)/, '');
    s = s.split(/\s+/)[0] || '';                 // "abc123...  file.zip" -> "abc123..."
    return /^[0-9a-f]+$/.test(s) ? s : '';
  }

  /** Which algorithm a hash of this length belongs to (or null). */
  function detectAlgorithm(hash) {
    return LENGTHS[normalizeHash(hash).length] || null;
  }

  /** Compares two hex strings without stopping at the first different character. */
  function safeEqual(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  /**
   * Hash a File/Blob/ArrayBuffer/Uint8Array.
   * @param {Blob|ArrayBuffer|Uint8Array} input
   * @param {string[]} [algorithms] default all three
   * @returns {Promise<{bytes:number, ms:number, hashes:Object}>}
   */
  async function hashData(input, algorithms) {
    var algs = (algorithms || ALGORITHMS).filter(function (a) { return ALGORITHMS.indexOf(a) !== -1; });
    var size = input && (input.size !== undefined ? input.size : input.byteLength);
    if (!size && size !== 0) throw new Error('Unsupported input');
    if (size > MAX_BYTES) throw new Error('tooLarge');
    var started = Date.now();
    var buffer = typeof input.arrayBuffer === 'function' ? await input.arrayBuffer() : input;
    var hashes = {};
    for (var i = 0; i < algs.length; i++) {
      hashes[algs[i]] = toHex(await root.crypto.subtle.digest(algs[i], buffer));
    }
    return { bytes: size, ms: Date.now() - started, hashes: hashes };
  }

  /** Compare computed hashes with the expected one the user pasted. */
  function compare(hashes, expected) {
    if (!String(expected || '').trim()) return { status: 'empty' };
    var clean = normalizeHash(expected);
    var alg = detectAlgorithm(clean);
    if (!alg) return { status: 'badFormat' };
    if (!hashes[alg]) return { status: 'missing', algorithm: alg };
    return { status: safeEqual(hashes[alg], clean) ? 'match' : 'mismatch', algorithm: alg };
  }

  var api = { hashData: hashData, compare: compare, normalizeHash: normalizeHash, detectAlgorithm: detectAlgorithm,
              safeEqual: safeEqual, MAX_BYTES: MAX_BYTES, ALGORITHMS: ALGORITHMS };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.fileHash = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
