const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fh = require('../js/file-hash.js');
const checkup = require('../js/checkup.js');

// ---------------------------------------------------------------- file hash
test('hashData matches Node\'s own SHA implementations', async () => {
  const data = new TextEncoder().encode('SworfishGuard');
  const r = await fh.hashData(data);
  assert.equal(r.bytes, data.byteLength);
  assert.equal(r.hashes['SHA-256'], crypto.createHash('sha256').update('SworfishGuard').digest('hex'));
  assert.equal(r.hashes['SHA-1'], crypto.createHash('sha1').update('SworfishGuard').digest('hex'));
  assert.equal(r.hashes['SHA-512'], crypto.createHash('sha512').update('SworfishGuard').digest('hex'));
});

test('compare detects match, mismatch and bad formats', async () => {
  const r = await fh.hashData(new TextEncoder().encode('abc'));
  const sha256 = r.hashes['SHA-256'];
  assert.deepEqual(fh.compare(r.hashes, sha256.toUpperCase()), { status: 'match', algorithm: 'SHA-256' });
  assert.equal(fh.compare(r.hashes, 'sha256: ' + sha256 + '  archivo.zip').status, 'match');
  assert.equal(fh.compare(r.hashes, 'f'.repeat(64)).status, 'mismatch');
  assert.equal(fh.compare(r.hashes, '1234').status, 'badFormat');
  assert.equal(fh.compare(r.hashes, '<script>').status, 'badFormat');
  assert.equal(fh.compare(r.hashes, '').status, 'empty');
});

test('detectAlgorithm and safeEqual', () => {
  assert.equal(fh.detectAlgorithm('a'.repeat(40)), 'SHA-1');
  assert.equal(fh.detectAlgorithm('a'.repeat(64)), 'SHA-256');
  assert.equal(fh.detectAlgorithm('a'.repeat(128)), 'SHA-512');
  assert.equal(fh.detectAlgorithm('a'.repeat(10)), null);
  assert.equal(fh.safeEqual('abc', 'abc'), true);
  assert.equal(fh.safeEqual('abc', 'abd'), false);
  assert.equal(fh.safeEqual('abc', 'abcd'), false);
});

test('hashData refuses files larger than the limit', async () => {
  await assert.rejects(() => fh.hashData({ size: fh.MAX_BYTES + 1, arrayBuffer: async () => new ArrayBuffer(0) }), /tooLarge/);
});

// ------------------------------------------------------------------ checkup
test('checkup scores only answered questions', () => {
  assert.equal(checkup.score({}).level, 'none');
  const all = Object.fromEntries(checkup.QUESTIONS.map((q) => [q.id, 'yes']));
  assert.equal(checkup.score(all).score, 100);
  assert.equal(checkup.score(all).level, 'good');
  const half = checkup.score({ unique: 'yes', twofa: 'no' });
  assert.equal(half.answered, 2);
  assert.equal(half.score, 50);
});

test('the action plan lists missing habits by impact', () => {
  const s = checkup.score({ wifi: 'no', unique: 'no', backup: 'unsure', lock: 'yes' });
  assert.deepEqual(s.plan, ['unique', 'backup', 'wifi']);
});

test('sanitize drops unknown keys and values (stored data cannot inject anything)', () => {
  const clean = checkup.sanitize({ unique: 'yes', twofa: '<img onerror=x>', __proto__: { x: 1 }, evil: 'yes' });
  assert.deepEqual(clean, { unique: 'yes' });
  assert.deepEqual(checkup.sanitize(null), {});
});
