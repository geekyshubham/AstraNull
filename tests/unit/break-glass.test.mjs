import assert from 'node:assert/strict';
import { describe, it, beforeEach } from 'node:test';
import { validateBreakGlassActivation } from '../../src/contracts/breakGlass.mjs';
import {
  activateBreakGlass,
  breakGlassStatus,
  resetBreakGlassStore,
} from '../../src/services/breakGlass.mjs';

describe('break glass', () => {
  beforeEach(() => resetBreakGlassStore());

  it('validates activation payload', () => {
    const ok = validateBreakGlassActivation({
      reason: 'SOC incident response',
      ticket_reference: 'INC-1001',
      duration_minutes: 30,
    });
    assert.equal(ok.ok, true);

    const bad = validateBreakGlassActivation({ reason: 'x' });
    assert.equal(bad.ok, false);
    assert.ok(bad.missing_fields.includes('ticket_reference'));
  });

  it('activates and reports status', () => {
    const ctx = { staffId: 'staff_admin', staffRole: 'internal_admin' };
    const result = activateBreakGlass(ctx, {
      reason: 'Emergency tenant access review',
      ticket_reference: 'INC-2002',
      duration_minutes: 15,
    });
    assert.ok(result.activation?.id);
    const status = breakGlassStatus();
    assert.equal(status.active, true);
    assert.equal(status.activation.ticket_reference, 'INC-2002');
  });
});