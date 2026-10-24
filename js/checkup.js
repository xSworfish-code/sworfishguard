/*!
 * SworfishGuard — Personal Security Checkup
 *
 * Twelve yes / no / not-sure questions about everyday habits. Each one has a
 * weight based on how much it reduces real-world risk (account takeover,
 * scams, data loss). The result is a 0–100 score and an action plan ordered
 * by impact. Answers can be remembered on this device only (localStorage).
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  // weight 3 = stops the most common attacks; 1 = nice to have.
  var QUESTIONS = [
    { id: 'unique', weight: 3 },
    { id: 'twofa', weight: 3 },
    { id: 'codes', weight: 3 },
    { id: 'manager', weight: 2 },
    { id: 'whatsapp', weight: 2 },
    { id: 'updates', weight: 2 },
    { id: 'lock', weight: 2 },
    { id: 'links', weight: 2 },
    { id: 'apps', weight: 2 },
    { id: 'backup', weight: 2 },
    { id: 'recovery', weight: 1 },
    { id: 'wifi', weight: 1 }
  ];
  var VALUE = { yes: 1, unsure: 0.25, no: 0 };
  var STORAGE_KEY = 'sg-checkup-v1';

  /**
   * @param {Object<string,string>} answers e.g. { unique: 'yes', twofa: 'no' }
   * @returns {{score:number, answered:number, total:number, level:string, plan:string[]}}
   */
  function score(answers) {
    var a = answers || {};
    var max = 0, got = 0, answered = 0;
    // Only answered questions count, so a half-finished checkup is not unfairly low.
    QUESTIONS.forEach(function (q) {
      if (VALUE.hasOwnProperty(a[q.id])) {
        answered++;
        max += q.weight;
        got += q.weight * VALUE[a[q.id]];
      }
    });
    var pct = max ? Math.round(got / max * 100) : 0;
    var plan = QUESTIONS
      .filter(function (q) { return a[q.id] && a[q.id] !== 'yes'; })
      .sort(function (x, y) { return y.weight - x.weight; })
      .map(function (q) { return q.id; });
    return {
      score: pct, answered: answered, total: QUESTIONS.length, plan: plan,
      level: answered === 0 ? 'none' : pct >= 80 ? 'good' : pct >= 50 ? 'fair' : 'poor'
    };
  }

  /** Only accepts known ids and values, so stored data cannot inject anything. */
  function sanitize(obj) {
    var clean = {};
    if (!obj || typeof obj !== 'object') return clean;
    QUESTIONS.forEach(function (q) {
      if (VALUE.hasOwnProperty(obj[q.id])) clean[q.id] = obj[q.id];
    });
    return clean;
  }

  function load() {
    try { return sanitize(JSON.parse(root.localStorage.getItem(STORAGE_KEY) || '{}')); }
    catch (e) { return {}; }
  }

  function save(answers) {
    try { root.localStorage.setItem(STORAGE_KEY, JSON.stringify(sanitize(answers))); return true; }
    catch (e) { return false; }
  }

  function clear() {
    try { root.localStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
  }

  var api = { QUESTIONS: QUESTIONS, score: score, sanitize: sanitize, load: load, save: save, clear: clear };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.checkup = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
