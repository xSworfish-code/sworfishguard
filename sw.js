/*!
 * SworfishGuard — service worker (offline mode)
 *
 * Keeps a copy of the app's own files so it opens without internet.
 * Strategy: network first, cache as backup, so a fixed version reaches
 * users right away. Requests to other sites (the Have I Been Pwned API)
 * are never touched or stored.
 *
 * Bump VERSION whenever a file changes.
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
'use strict';

var VERSION = 'sworfishguard-v1.1.0';
var FILES = [
  './',
  'index.html',
  'manifest.webmanifest',
  'css/styles.css',
  'fonts/inter-var.woff2',
  'fonts/source-serif-4-var.woff2',
  'fonts/source-serif-4-var-italic.woff2',
  'js/i18n.js',
  'js/brands.js',
  'js/wordlists.js',
  'js/dictionaries.js',
  'js/password-analyzer.js',
  'js/breach-check.js',
  'js/generator.js',
  'js/phishing-detector.js',
  'js/scam-detector.js',
  'js/vendor/jsQR.js',
  'js/qr-scanner.js',
  'js/email-headers.js',
  'js/metadata.js',
  'js/quiz.js',
  'js/file-hash.js',
  'js/checkup.js',
  'js/glossary.js',
  'js/app.js',
  'icons/icon.svg',
  'icons/icon-192.png',
  'icons/icon-512.png'
];

self.addEventListener('install', function (event) {
  event.waitUntil(caches.open(VERSION).then(function (cache) { return cache.addAll(FILES); }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener('activate', function (event) {
  event.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== VERSION; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (event) {
  var req = event.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  event.respondWith(fetch(req).then(function (res) {
    if (res.ok && res.type === 'basic') {
      var copy = res.clone();
      caches.open(VERSION).then(function (cache) { cache.put(req, copy); });
    }
    return res;
  }).catch(function () {
    return caches.match(req, { ignoreSearch: true }).then(function (hit) { return hit || caches.match('index.html'); });
  }));
});
