const test = require('node:test');
const assert = require('node:assert/strict');
const { sha1Hex, parseRangeResponse, checkPassword } = require('../js/breach-check.js');

// SHA-1("password") is a well-known test vector.
const PASSWORD_HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
const ok = (body) => async () => ({ ok: true, status: 200, text: async () => body });

test('sha1Hex matches the known test vector', async () => {
  assert.equal(await sha1Hex('password'), PASSWORD_HASH);
});

test('parseRangeResponse finds the suffix and counts padding', () => {
  const body = [
    '0018A45C4D1DEF81644B54AB7F969B88D65:1',
    '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0'
  ].join('\r\n');
  assert.deepEqual(parseRangeResponse(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), { count: 9545824, lines: 3, padding: 1 });
  assert.equal(parseRangeResponse(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF').count, 0);
});

test('parseRangeResponse rejects tampered or unexpected responses', () => {
  assert.throws(() => parseRangeResponse('<script>alert(1)</script>', 'AAAA'), /format/);
  assert.throws(() => parseRangeResponse('1E4C9B93F3F0682250B6CF8331B7EE68FD8:12\nnot-a-hash:3', 'AAAA'), /format/);
});

test('checkPassword only sends the first 5 characters of the hash (k-anonymity)', async () => {
  let requestedUrl = null;
  let options = null;
  const fakeFetch = async (url, opts) => {
    requestedUrl = url;
    options = opts;
    return { ok: true, status: 200, text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n' };
  };
  const res = await checkPassword('password', fakeFetch);
  assert.equal(requestedUrl, 'https://api.pwnedpasswords.com/range/5BAA6');
  assert.equal(requestedUrl.split('/range/')[1].length, 5);
  assert.ok(!requestedUrl.includes(PASSWORD_HASH));
  assert.equal(res.found, true);
  assert.equal(res.count, 42);
  // Privacy-hardened request
  assert.equal(options.credentials, 'omit');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.headers['Add-Padding'], 'true');
});

test('checkPassword reports not found and request stats', async () => {
  const res = await checkPassword('a-very-unique-passphrase', ok('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3\n'));
  assert.equal(res.found, false);
  assert.equal(res.count, 0);
  assert.equal(res.stats.lines, 1);
  assert.ok(res.stats.ms >= 0);
});

test('checkPassword retries without the padding header if the first request fails', async () => {
  let calls = 0;
  const fakeFetch = async (url, opts) => {
    calls++;
    if (opts.headers) throw new TypeError('blocked by CORS');
    return { ok: true, status: 200, text: async () => '' };
  };
  const res = await checkPassword('x', fakeFetch);
  assert.equal(calls, 2);
  assert.equal(res.stats.padded, false);
});

test('checkPassword throws on HTTP errors and oversized responses', async () => {
  await assert.rejects(() => checkPassword('x', async () => ({ ok: false, status: 503, text: async () => '' })), /503/);
  await assert.rejects(() => checkPassword('x', ok('A'.repeat(3 * 1024 * 1024))), /too large/);
});

test('checkPassword rejects an empty password', async () => {
  await assert.rejects(() => checkPassword('', ok('')), /Empty/);
});
