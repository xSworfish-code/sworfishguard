/*
 * Accuracy gates: if a change makes the detectors worse on the benchmark
 * set (tests/fixtures/corpus.js), these tests fail.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const bench = require('./benchmark.js');

test('scam detector: catches at least 95% of scams with at most 1 false alarm', () => {
  const m = bench.messages();
  assert.ok(m.recall >= 0.95, `recall ${m.recall}: ${m.misses.join(' / ')}`);
  assert.ok(m.fp <= 1, `false alarms: ${m.misses.join(' / ')}`);
});

test('password analyzer: rates at least 95% of the set correctly', () => {
  const p = bench.passwords();
  assert.ok(p.accuracy >= 0.95, p.misses.join(' / '));
});

test('link checker: at least 95% of links get the expected level', () => {
  const l = bench.links();
  assert.ok(l.accuracy >= 0.95, l.misses.join(' / '));
});
