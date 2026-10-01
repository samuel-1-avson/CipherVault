'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { argumentsFor, summarize, totpCode } = require('../scripts/capacity-validation.cjs');

test('capacity evidence distinguishes admission, semantic failure and latency tails', () => {
  const evidence = summarize([
    { ms: 1, status: 200, ok: true },
    { ms: 5, status: 503, ok: false, rejected: true },
    { ms: 40, status: 200, ok: false, error: 'integrity mismatch' },
    { ms: 100, status: 0, ok: false, error: 'timeout' },
  ], 200);
  assert.equal(evidence.successes, 1);
  assert.equal(evidence.rejected, 1);
  assert.equal(evidence.failures, 2);
  assert.equal(evidence.p50_ms, 5);
  assert.equal(evidence.p95_ms, 100);
  assert.equal(evidence.p99_ms, 100);
  assert.equal(evidence.successes_per_second, 5);
  assert.deepEqual(evidence.statuses, { 0: 1, 200: 2, 503: 1 });
});

test('capacity harness bounds workload, rejects remote targets and preserves existing evidence', () => {
  const base = ['--account-bin', __filename, '--operator-bin', __filename,
    '--output', path.join(__dirname, 'capacity-not-created.json')];
  assert.throws(() => argumentsFor([...base, '--concurrency', '16,16']), /distinct/);
  assert.throws(() => argumentsFor([...base, '--requests', '1000000']), /Bounded/);
  assert.throws(() => argumentsFor([...base, '--overload', '10000']), /Bounded/);
  assert.throws(() => argumentsFor([...base, '--endpoint', 'https://vault.cipherv.online']), /Unknown argument/);
  assert.throws(() => argumentsFor(['--account-bin', __filename, '--operator-bin', __filename,
    '--output', __filename]), /never overwritten/);
  assert.equal(argumentsFor(base).requests, 240);
});

test('capacity fixture computes independent RFC6238 SHA1 codes correctly', () => {
  // RFC6238 appendix B SHA1 seed, reduced to the service's six digits.
  const seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  for (const [seconds, expected] of [[59, '287082'], [1111111109, '081804'],
    [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037']]) {
    assert.equal(totpCode(seed, Math.floor(seconds / 30)), expected);
  }
});
