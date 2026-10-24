const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeUrl, splitHost, levenshtein, punycodeDecode, toUnicodeHost, extractUrls } = require('../js/phishing-detector.js');
const { BRANDS } = require('../js/brands.js');

const ids = (r) => r.findings.map((f) => f.id);

test('official domains (Honduran banks and global brands) are low risk and recognized', () => {
  for (const url of ['https://www.bancatlan.hn', 'https://app.bancatlan.hn/login', 'https://www.ficohsa.hn',
                     'https://www.baccredomatic.com/es-hn', 'https://www.banpais.hn', 'https://www.bancocci.hn',
                     'https://www.davivienda.com.hn', 'https://tigo.com.hn', 'https://www.google.com',
                     'https://accounts.google.com/signin', 'https://steamcommunity.com/id/asaf']) {
    const r = analyzeUrl(url);
    assert.equal(r.valid, true, url);
    assert.equal(r.level, 'low', url + ' -> ' + ids(r).join(','));
    assert.equal(r.official, true, url);
  }
});

test('every brand has at least one official domain and keyword', () => {
  for (const b of BRANDS) {
    assert.ok(b.domains.length > 0, b.name);
    assert.ok(b.keywords.length > 0, b.name);
    for (const d of b.domains) assert.match(d, /^[a-z0-9.-]+\.[a-z]{2,}$/, b.name + ' ' + d);
  }
});

test('look-alike and typo domains are high risk', () => {
  for (const url of ['http://paypa1-secure-login.xyz/verify/account', 'https://faceb00k.com',
                     'https://steamcommunlty.com/tradeoffer', 'https://bancatlam.hn', 'https://bancatlan-hn.xyz/verificar']) {
    const r = analyzeUrl(url);
    assert.equal(r.level, 'high', url + ' -> ' + ids(r).join(','));
    assert.ok(ids(r).includes('lookalike'), url);
  }
});

test('brand placed in the subdomain is detected (bancatlan.hn.evil.top)', () => {
  const r = analyzeUrl('https://bancatlan.hn.verificar-cuenta.top/acceso');
  assert.equal(r.registeredDomain, 'verificar-cuenta.top');
  assert.ok(ids(r).includes('brandInSubdomain'));
  assert.ok(ids(r).includes('riskyTld'));
  assert.equal(r.level, 'high');
});

test('short brand keywords only match whole words (no false positives)', () => {
  assert.equal(analyzeUrl('https://contigo.com').level, 'low');      // contains "tigo"
  assert.equal(analyzeUrl('https://steamboat.com').level, 'low');    // contains "steam"
  assert.ok(ids(analyzeUrl('https://tigo-premios.xyz')).includes('brandInDomain'));
});

test('homograph attacks with other alphabets are critical', () => {
  // "аррӏе.com" written with Cyrillic letters
  const r = analyzeUrl('https://xn--80ak6aa92e.com');
  assert.equal(r.unicodeHost, 'аррӏе.com');
  assert.ok(ids(r).includes('homograph'));
  assert.equal(r.level, 'high');
  // "pаypal.com" with a Cyrillic "а", typed directly
  assert.ok(ids(analyzeUrl('https://pаypal.com')).includes('homograph'));
});

test('Latin accented domains (español) only get a small note', () => {
  const r = analyzeUrl('https://españa.com');
  assert.ok(ids(r).includes('idnLatin'));
  assert.equal(r.level, 'low');
});

test('punycode decoder follows RFC 3492', () => {
  assert.equal(punycodeDecode('espaa-rta'), 'españa');
  assert.equal(punycodeDecode('80ak6aa92e'), 'аррӏе');
  assert.equal(toUnicodeHost('www.xn--espaa-rta.com'), 'www.españa.com');
  assert.throws(() => punycodeDecode('a'.repeat(80)));
});

test('IP addresses (including disguised ones), @ trick and plain http are flagged', () => {
  assert.ok(ids(analyzeUrl('http://192.168.1.50/login')).includes('ipAddress'));
  assert.ok(ids(analyzeUrl('http://3232235777/login')).includes('obfuscatedIp'));
  assert.ok(ids(analyzeUrl('https://www.google.com@evil.com')).includes('atSymbol'));
  assert.ok(ids(analyzeUrl('http://example.com')).includes('noHttps'));
});

test('dangerous schemes are critical', () => {
  for (const u of ['javascript:alert(1)', 'data:text/html,<script>x</script>', 'file:///etc/passwd']) {
    const r = analyzeUrl(u);
    assert.equal(r.level, 'high', u);
    assert.equal(r.findings[0].severity, 'critical', u);
  }
});

test('shorteners, free hosting and redirect parameters are flagged', () => {
  assert.ok(ids(analyzeUrl('https://bit.ly/abc123')).includes('shortener'));
  assert.ok(ids(analyzeUrl('https://example.com/out?url=https://evil.com')).includes('redirectParam'));
  const free = analyzeUrl('https://sites.google.com/view/bac-login-verificar');
  assert.ok(ids(free).includes('freeHosting'));
  assert.equal(free.official, false, 'user content on google.com is not "official"');
});

test('invalid and oversized input is reported as invalid', () => {
  assert.equal(analyzeUrl('').valid, false);
  assert.equal(analyzeUrl('http://').valid, false);
  assert.equal(analyzeUrl('ftp://example.com').valid, false);
  assert.equal(analyzeUrl('https://a.com/' + 'x'.repeat(3000)).error, 'tooLong');
});

test('splitHost understands second-level country suffixes', () => {
  assert.equal(splitHost('www.davivienda.com.hn').registered, 'davivienda.com.hn');
  assert.equal(splitHost('login.paypal.com.evil.xyz').registered, 'evil.xyz');
  assert.deepEqual(splitHost('a.b.c.example.co.uk').sub, ['a', 'b', 'c']);
});

test('levenshtein distance', () => {
  assert.equal(levenshtein('paypal', 'paypal'), 0);
  assert.equal(levenshtein('paypal', 'paypall'), 1);
  assert.equal(levenshtein('kitten', 'sitting'), 3);
});

test('extractUrls finds links inside text', () => {
  const urls = extractUrls('Pague en dhl-aduana.top/pago o https://bit.ly/3xYz. Gracias.');
  assert.deepEqual(urls, ['dhl-aduana.top/pago', 'https://bit.ly/3xYz']);
});

test('findings are sorted by severity and score is capped at 100', () => {
  const r = analyzeUrl('http://user@paypa1-login-secure-verify.xyz:8080/account/verify//confirm?next=https://x.com');
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sevs = r.findings.map((f) => order[f.severity]);
  assert.deepEqual(sevs, [...sevs].sort((a, b) => a - b));
  assert.ok(r.score <= 100);
});
