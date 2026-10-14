import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  FINDING_CLOSURE_STATUSES,
  FINDING_STATUSES,
  FINDING_STATUS_DESCRIPTIONS,
  findingStatusTransitions,
} from '../../apps/web/react/src/lib/findings-query.mjs';

const statusesOf = (current) => findingStatusTransitions(current).map((transition) => transition.status);

describe('finding status transitions', () => {
  it('offers start work and every outcome from open', () => {
    assert.deepEqual(findingStatusTransitions('open'), [
      { status: 'in_progress', label: 'Start work' },
      { status: 'resolved', label: 'Mark resolved' },
      { status: 'false_positive', label: 'Mark false positive' },
      { status: 'accepted_risk', label: 'Accept risk' },
      { status: 'closed', label: 'Close' },
    ]);
  });

  it('offers reopen plus every outcome from in progress', () => {
    assert.deepEqual(statusesOf('in_progress'), ['open', 'resolved', 'false_positive', 'accepted_risk', 'closed']);
  });

  it('offers only reopen and start work from every closure state', () => {
    for (const status of ['accepted_risk', 'accepted', 'fix_verified', 'resolved', 'closed', 'false_positive']) {
      assert.deepEqual(statusesOf(status), ['open', 'in_progress'], status);
    }
    assert.deepEqual([...FINDING_CLOSURE_STATUSES].sort(), ['accepted', 'accepted_risk', 'closed', 'false_positive', 'fix_verified', 'resolved']);
  });

  it('never offers the current status or the older accepted status', () => {
    for (const status of FINDING_STATUSES) {
      const offered = statusesOf(status);
      assert.equal(offered.includes(status), false, status);
      assert.equal(offered.includes('accepted'), false, status);
    }
  });

  it('normalizes case and treats a missing status as open', () => {
    assert.deepEqual(statusesOf(' In_Progress '.trim()), statusesOf('in_progress'));
    assert.deepEqual(statusesOf(''), statusesOf('open'));
    assert.deepEqual(statusesOf(null), statusesOf('open'));
  });
});

describe('finding status descriptions', () => {
  it('defines every status in plain language', () => {
    for (const status of FINDING_STATUSES) assert.ok(FINDING_STATUS_DESCRIPTIONS[status], status);
    assert.equal(FINDING_STATUS_DESCRIPTIONS.accepted, 'Accepted (older status set through the API)');
    assert.equal(FINDING_STATUS_DESCRIPTIONS.closed, 'Closed without a fix');
    assert.equal(FINDING_STATUS_DESCRIPTIONS.false_positive, 'Evidence did not hold');
  });
});
