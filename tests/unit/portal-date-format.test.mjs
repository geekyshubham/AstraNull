import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { findingSlaDueAt } from '../../apps/web/react/src/lib/findings-helpers.ts';
import { formatDate } from '../../apps/web/react/src/lib/utils.ts';

const DATE_OPTIONS = {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
};

describe('portal date formatting', () => {
  it('formats computed numeric SLA timestamps instead of rendering epoch milliseconds', () => {
    const dueAt = findingSlaDueAt({
      status: 'open',
      severity: 'medium',
      created_at: '2026-09-02T20:02:59.917Z',
    });
    assert.equal(typeof dueAt, 'number');
    assert.equal(formatDate(dueAt), new Date(dueAt).toLocaleString(undefined, DATE_OPTIONS));
    assert.doesNotMatch(formatDate(dueAt), /^\d{13}$/);
  });

  it('preserves ISO timestamp and invalid-value behavior', () => {
    const iso = '2026-09-02T20:02:59.917Z';
    assert.equal(formatDate(iso), new Date(iso).toLocaleString(undefined, DATE_OPTIONS));
    assert.equal(formatDate('not-a-date'), 'not-a-date');
    assert.equal(formatDate(null), 'Not recorded');
  });
});
