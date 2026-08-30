import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  nextPolicyRunAt,
  normalizePolicyInput,
  POLICY_CADENCES,
  policyDispatchIdempotencyKey,
  PolicyValidationError,
} from '../../src/contracts/testPolicyManagement.mjs';

describe('test policy management contract', () => {
  it('rejects invalid cadence, verdict, timezone, windows, and concurrency instead of coercing', () => {
    assert.throws(() => normalizePolicyInput({ cadence: 'sometimes' }), PolicyValidationError);
    assert.throws(() => normalizePolicyInput({ expected_verdict: 'probably' }), PolicyValidationError);
    assert.throws(() => normalizePolicyInput({ timezone: 'Mars/Olympus' }), PolicyValidationError);
    assert.throws(() => normalizePolicyInput({ safe_windows: [{ day: 'Mon', start: '9:00', end: '11:00' }] }), PolicyValidationError);
    assert.throws(() => normalizePolicyInput({ safe_windows: [{ day: 'Mon', start: '11:00', end: '09:00' }] }), PolicyValidationError);
    assert.throws(() => normalizePolicyInput({ max_concurrent_runs: 2 }), PolicyValidationError);
  });

  it('normalizes safe windows and persists the rule controls', () => {
    assert.deepEqual(normalizePolicyInput({
      cadence: 'weekly',
      expected_verdict: 'WARN',
      enabled: true,
      timezone: 'America/Los_Angeles',
      max_concurrent_runs: 1,
      safe_windows: [{ day: 'monday', start: '09:00', end: '11:00' }],
    }), {
      cadence: 'weekly',
      expected_verdict: 'warn',
      enabled: true,
      timezone: 'America/Los_Angeles',
      max_concurrent_runs: 1,
      state: 'active',
      event_trigger: null,
      safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'America/Los_Angeles' }],
    });
  });

  it('excludes unsupported event cadence and fails closed for event policy inputs', () => {
    assert.deepEqual(POLICY_CADENCES, ['manual', 'daily', 'weekly', 'monthly']);
    assert.equal(POLICY_CADENCES.includes('event_driven'), false);

    assert.throws(
      () => normalizePolicyInput({ cadence: 'event_driven' }),
      (error) => error instanceof PolicyValidationError && error.field === 'cadence',
    );
    assert.throws(
      () => normalizePolicyInput({
        cadence: 'daily',
        event_trigger: { type: 'finding.created' },
      }),
      (error) => error instanceof PolicyValidationError && error.field === 'event_trigger',
    );
    assert.throws(
      () => normalizePolicyInput({
        cadence: 'event_driven',
        event_trigger: { type: 'finding.created' },
      }),
      (error) => error instanceof PolicyValidationError && error.field === 'cadence',
    );
  });

  it('computes timezone-aware next runs inside a safe window', () => {
    const policy = normalizePolicyInput({
      cadence: 'daily',
      timezone: 'America/New_York',
      safe_windows: [{ day: 'Mon', start: '09:00', end: '10:00' }],
    });
    assert.equal(
      nextPolicyRunAt(policy, { from: new Date('2026-03-08T12:00:00.000Z'), initial: true }),
      '2026-03-09T13:00:00.000Z',
    );
    assert.equal(nextPolicyRunAt({ ...policy, enabled: false }, { from: new Date() }), null);
  });

  it('derives stable tenant/policy/scheduled-time idempotency keys', () => {
    const first = policyDispatchIdempotencyKey('ten_1', 'pol_1', '2026-01-02T03:04:05Z');
    assert.equal(first, policyDispatchIdempotencyKey('ten_1', 'pol_1', '2026-01-02T03:04:05.000Z'));
    assert.notEqual(first, policyDispatchIdempotencyKey('ten_2', 'pol_1', '2026-01-02T03:04:05Z'));
    assert.match(first, /^[a-f0-9]{64}$/);
  });
});
