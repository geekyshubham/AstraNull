import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  countAxfrProbeRequests,
  resolveBoundedSequenceBudget,
  resolveProbeRequestBudget,
} from '../../src/lib/probeRequestBudget.mjs';

describe('probeRequestBudget', () => {
  it('resolveProbeRequestBudget prefers constraints over profile', () => {
    const job = {
      constraints: { max_requests: 3 },
      probe_profile: { max_requests: 9 },
    };
    assert.equal(resolveProbeRequestBudget(job), 3);
  });

  it('resolveBoundedSequenceBudget caps by ceiling', () => {
    const job = { constraints: { max_requests: 10 } };
    assert.equal(resolveBoundedSequenceBudget(job, { ceiling: 5 }), 5);
  });

  it('countAxfrProbeRequests counts resolve-only and resolve+tcp', () => {
    assert.equal(countAxfrProbeRequests({ nameserverResolved: true, tcpAttempted: false }), 1);
    assert.equal(countAxfrProbeRequests({ nameserverResolved: true, tcpAttempted: true }), 2);
    assert.equal(countAxfrProbeRequests({ nameserverResolved: false, tcpAttempted: false }), 0);
  });
});