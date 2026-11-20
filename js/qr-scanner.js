/*!
 * SworfishGuard — QR code checker
 *
 * Reads a QR code from a photo, a screenshot or the camera (with the
 * open-source jsQR library, stored inside this repo) and works out what the
 * code really contains BEFORE you open it: a link, a Wi-Fi network, a phone
 * number, a payment request, a 2FA setup key...
 *
 * Fake QR codes stuck on parking meters, posters or menus ("quishing") are a
 * growing scam, because you cannot see where a QR goes by looking at it.
 * Nothing is opened automatically: the content is only shown and analyzed.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var MAX_SIDE = 1400; // big photos are scaled down before decoding (faster, same result)

  var CRYPTO = ['bitcoin', 'ethereum', 'litecoin', 'bitcoincash', 'dogecoin', 'monero', 'solana', 'tron', 'usdt', 'binancecoin'];
  var DANGEROUS = ['javascript', 'data', 'vbscript', 'file', 'blob'];
  var APP_SCHEMES = ['market', 'itms-apps', 'itms-services', 'intent', 'fb', 'whatsapp', 'tg', 'instagram'];

  // In a query string "+" means a space; in the rest of a URI it is a real "+" (phone numbers).
  function safeDecode(s, plusIsSpace) {
    var v = String(s);
    if (plusIsSpace) v = v.replace(/\+/g, ' ');
    try { return decodeURIComponent(v); } catch (e) { return v; }
  }

  /** Splits "a=1&b=2" into an object (no prototype, so "__proto__" is just a key). */
  function query(q) {
    var out = Object.create(null);
    String(q || '').split('&').forEach(function (part) {
      if (!part) return;
      var i = part.indexOf('=');
      var k = (i === -1 ? part : part.slice(0, i)).toLowerCase();
      out[k] = safeDecode(i === -1 ? '' : part.slice(i + 1), true);
    });
    return out;
  }

  /** WIFI:T:WPA;S:Home;P:secret;H:false;; with \ escapes for ; , : \ and " */
  function parseWifi(text) {
    var body = text.slice(5);
    var fields = Object.create(null);
    var key = '', val = '', inKey = true;
    for (var i = 0; i < body.length; i++) {
      var ch = body[i];
      if (ch === '\\' && i + 1 < body.length) { (inKey ? (key += body[++i]) : (val += body[++i])); continue; }
      if (inKey && ch === ':') { inKey = false; continue; }
      if (!inKey && ch === ';') { fields[key.toUpperCase()] = val; key = ''; val = ''; inKey = true; continue; }
      if (inKey) key += ch; else val += ch;
    }
    if (!inKey && key) fields[key.toUpperCase()] = val;
    var sec = (fields.T || 'nopass').toUpperCase();
    if (sec === '') sec = 'NOPASS';
    return {
      type: 'wifi',
      ssid: fields.S || '',
      security: sec === 'WPA' || sec === 'WPA2' || sec === 'WPA3' || sec === 'SAE' ? 'WPA' : sec === 'WEP' ? 'WEP' : sec === 'NOPASS' ? 'open' : sec,
      hidden: /^true$/i.test(fields.H || ''),
      hasPassword: !!fields.P,
      passwordLength: (fields.P || '').length
    };
  }

  function parseVcard(text) {
    var lines = text.replace(/\r\n[ \t]/g, '').split(/\r?\n/);
    var out = { type: 'contact', name: '', phones: [], emails: [], urls: [], org: '' };
    lines.forEach(function (line) {
      var i = line.indexOf(':');
      if (i === -1) return;
      var prop = line.slice(0, i).split(';')[0].toUpperCase();
      var value = line.slice(i + 1).trim();
      if (prop === 'FN') out.name = value;
      else if (prop === 'N' && !out.name) out.name = value.split(';').filter(Boolean).reverse().join(' ');
      else if (prop === 'TEL') out.phones.push(value);
      else if (prop === 'EMAIL') out.emails.push(value);
      else if (prop === 'URL') out.urls.push(value);
      else if (prop === 'ORG') out.org = value.replace(/;/g, ' ').trim();
    });
    return out;
  }

  /**
   * Works out what kind of content a QR code holds.
   * @param {string} raw decoded text
   * @returns {{type:string}} plus fields that depend on the type
   */
  function classifyPayload(raw) {
    var text = String(raw || '').replace(/^﻿/, '').trim();
    if (!text) return { type: 'empty' };
    var lower = text.toLowerCase();
    var schemeMatch = lower.match(/^([a-z][a-z0-9+.-]{0,30}):/);
    var scheme = schemeMatch ? schemeMatch[1] : '';

    if (scheme === 'http' || scheme === 'https') return { type: 'url', url: text };
    if (!scheme && /^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(text) && text.indexOf(' ') === -1) {
      return { type: 'url', url: 'http://' + text, implicit: true };
    }
    if (DANGEROUS.indexOf(scheme) !== -1) return { type: 'dangerous', scheme: scheme };
    if (scheme === 'wifi') return parseWifi(text);
    if (lower.indexOf('begin:vcard') === 0) return parseVcard(text);
    if (scheme === 'mailto') {
      var m = text.slice(7).split('?');
      var q = query(m[1]);
      return { type: 'email', to: safeDecode(m[0]), subject: q.subject || '', body: q.body || '' };
    }
    if (scheme === 'matmsg') {
      var to = (text.match(/TO:([^;]*)/i) || [])[1] || '';
      var sub = (text.match(/SUB:([^;]*)/i) || [])[1] || '';
      var bod = (text.match(/BODY:([^;]*)/i) || [])[1] || '';
      return { type: 'email', to: to, subject: sub, body: bod };
    }
    if (scheme === 'tel') return { type: 'phone', number: safeDecode(text.slice(4)) };
    if (scheme === 'smsto' || scheme === 'sms') {
      var rest = text.slice(scheme.length + 1);
      if (scheme === 'smsto') {
        var c = rest.indexOf(':');
        return { type: 'sms', number: c === -1 ? rest : rest.slice(0, c), body: c === -1 ? '' : rest.slice(c + 1) };
      }
      var parts = rest.split('?');
      return { type: 'sms', number: safeDecode(parts[0]), body: query(parts[1]).body || '' };
    }
    if (scheme === 'otpauth') {
      var path = text.slice(text.indexOf('//') + 2);
      var slash = path.indexOf('/');
      var label = safeDecode((slash === -1 ? path : path.slice(slash + 1)).split('?')[0]);
      var oq = query(path.split('?')[1]);
      return { type: 'otp', issuer: oq.issuer || (label.indexOf(':') !== -1 ? label.split(':')[0] : ''), account: label.indexOf(':') !== -1 ? label.split(':').slice(1).join(':') : label };
    }
    if (CRYPTO.indexOf(scheme) !== -1) {
      var addr = text.slice(scheme.length + 1).split('?');
      var cq = query(addr[1]);
      return { type: 'crypto', coin: scheme, address: addr[0].replace(/^\/\//, ''), amount: cq.amount || cq.value || '' };
    }
    if (APP_SCHEMES.indexOf(scheme) !== -1) return { type: 'app', scheme: scheme };
    if (scheme === 'geo') {
      var g = text.slice(4).split(/[,;?]/);
      return { type: 'geo', lat: g[0], lon: g[1] };
    }
    if (scheme && /^[a-z][a-z0-9+.-]*:\/\//.test(lower)) return { type: 'other', scheme: scheme };
    return { type: 'text', text: text };
  }

  /** Scale so the longest side is at most MAX_SIDE. */
  function fitSize(w, h, max) {
    max = max || MAX_SIDE;
    var k = Math.min(1, max / Math.max(w, h));
    return { width: Math.max(1, Math.round(w * k)), height: Math.max(1, Math.round(h * k)) };
  }

  /** Decodes a QR from RGBA pixels (ImageData). Returns null when there is none. */
  function decodePixels(imageData) {
    if (typeof root.jsQR !== 'function') throw new Error('noDecoder');
    var res = root.jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'attemptBoth' });
    if (!res || typeof res.data !== 'string') return null;
    return { text: res.data, version: res.version, bytes: res.binaryData ? res.binaryData.length : res.data.length };
  }

  /** Browser only: reads an image file (photo or screenshot) and decodes the QR. */
  function decodeImageFile(file) {
    if (!file || !/^image\//.test(file.type || '')) return Promise.reject(new Error('notImage'));
    if (file.size > 25 * 1024 * 1024) return Promise.reject(new Error('tooLarge'));
    return root.createImageBitmap(file).then(function (bitmap) {
      var tries = [MAX_SIDE, 800, 2400];
      for (var i = 0; i < tries.length; i++) {
        var size = fitSize(bitmap.width, bitmap.height, tries[i]);
        var canvas = root.document.createElement('canvas');
        canvas.width = size.width; canvas.height = size.height;
        var ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(bitmap, 0, 0, size.width, size.height);
        var found = decodePixels(ctx.getImageData(0, 0, size.width, size.height));
        if (found) { if (bitmap.close) bitmap.close(); return found; }
      }
      if (bitmap.close) bitmap.close();
      return null;
    });
  }

  var api = { classifyPayload: classifyPayload, decodePixels: decodePixels, decodeImageFile: decodeImageFile, fitSize: fitSize };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.qr = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
