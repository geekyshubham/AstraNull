import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { formatAuditAction, formatResourceTypeLabel } from '../../apps/web/react/src/lib/utils.ts';

describe('portal audit labels', () => {
  it('renders known audit actions and resource types in plain English', () => {
    assert.equal(formatAuditAction('rbac.denied'), 'Access denied (missing permission)');
    assert.equal(formatResourceTypeLabel('api'), 'Access control');
    assert.equal(formatResourceTypeLabel('test_run'), 'Validation run');
  });

  it('falls back to sentence case without raw separators', () => {
    assert.equal(formatAuditAction('waf.offensive_request.approved'), 'WAF offensive request approved');
    assert.equal(formatResourceTypeLabel('evidence_snapshot'), 'Evidence snapshot');
    assert.equal(formatAuditAction('  ', 'fallback'), 'fallback');
    assert.doesNotMatch(formatAuditAction('a.b_c'), /[._·]/);
  });
});
