import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildDefaultSubscription,
  checkSubscriptionLimit,
} from '../../src/contracts/subscriptions.mjs';

describe('subscription limits', () => {
  it('allows usage below a configured metric limit', () => {
    const subscription = buildDefaultSubscription('starter', 'ten_demo');
    const result = checkSubscriptionLimit(subscription, [], 'safe_runs_per_hour', 19);

    assert.equal(result.ok, true);
  });

  it('rejects usage at the configured metric limit', () => {
    const subscription = buildDefaultSubscription('starter', 'ten_demo');
    const result = checkSubscriptionLimit(subscription, [], 'safe_runs_per_hour', 20);

    assert.equal(result.ok, false);
    assert.equal(result.error, 'entitlement_limit_exceeded');
    assert.equal(result.metric, 'safe_runs_per_hour');
    assert.equal(result.limit, 20);
    assert.equal(result.current, 20);
  });

  it('treats missing or unlimited metrics as allowed', () => {
    const subscription = buildDefaultSubscription('starter', 'ten_demo');

    assert.deepEqual(checkSubscriptionLimit(subscription, [], 'custom_unlimited_metric', 999), {
      ok: true,
    });
  });
});
