import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { formatAuditAction, formatResourceTypeLabel, sensitiveResourceLabel } from '../../apps/web/react/src/lib/utils.ts';

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

  it('labels credential resources so raw invite/reset/session ids are not shown verbatim', () => {
    // The audit UI renders these as a friendly label (raw id only in a tooltip) so a live
    // password-invite id like pwi_… never surfaces as machine-token text.
    assert.equal(sensitiveResourceLabel('user_password_invite'), 'Password invite');
    assert.equal(sensitiveResourceLabel('user_password_reset'), 'Password reset');
    assert.equal(sensitiveResourceLabel('user_session'), 'Session');
    // Case/whitespace tolerant.
    assert.equal(sensitiveResourceLabel('  User_Password_Invite  '), 'Password invite');
    // Operator-pivotable resources stay visible (null = render id verbatim).
    assert.equal(sensitiveResourceLabel('target'), null);
    assert.equal(sensitiveResourceLabel('test_run'), null);
    assert.equal(sensitiveResourceLabel('finding'), null);
  });
});
