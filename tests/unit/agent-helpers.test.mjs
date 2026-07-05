import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  formatPlacementOverview,
  formatPlacementStatus,
} from '../../apps/web/react/src/lib/placement-labels.ts';

describe('placement-labels (customer-facing labels)', () => {
  it('formatPlacementStatus maps technical codes to plain language', () => {
    assert.equal(formatPlacementStatus('missing_agent'), 'No agent');
    assert.equal(formatPlacementStatus('needs_baseline'), 'Needs a test run');
    assert.equal(formatPlacementStatus('proven'), 'Ready');
    assert.equal(formatPlacementStatus('misplaced_risk'), 'Agent offline');
  });

  it('formatPlacementOverview summarizes counts in plain language', () => {
    const summary = formatPlacementOverview({
      total_groups: 4,
      proven: 0,
      needs_baseline: 1,
      missing_agent: 3,
      misplaced_risk: 0,
    });
    assert.match(summary, /0 of 4 groups ready/);
    assert.match(summary, /3 need an agent/);
    assert.match(summary, /1 need a test run/);
    assert.doesNotMatch(summary, /missing_agent/);
  });
});