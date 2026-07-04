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

  it('rejects forbidden secret fields and duration bounds', () => {
    const forbidden = validateBreakGlassActivation({
      reason: 'x',
      ticket_reference: 'INC-1',
      duration_minutes: 30,
      token: 'no',
    });
    assert.equal(forbidden.ok, false);
    assert.ok(forbidden.forbidden_fields.includes('token'));

    const shortDuration = validateBreakGlassActivation({
      reason: 'x',
      ticket_reference: 'INC-1',
      duration_minutes: 2,
    });
    assert.ok(shortDuration.missing_fields.includes('duration_minutes'));
  });

  it('supersedes prior activation and expires after window', () => {
    const ctx = { staffId: 'staff_admin', staffRole: 'internal_admin' };
    const t0 = new Date('2026-07-04T12:00:00.000Z');
    activateBreakGlass(ctx, {
      reason: 'First activation',
      ticket_reference: 'INC-A',
      duration_minutes: 10,
    }, { now: () => t0 });

    activateBreakGlass(ctx, {
      reason: 'Second activation',
      ticket_reference: 'INC-B',
      duration_minutes: 10,
    }, { now: () => new Date(t0.getTime() + 60_000) });

    const active = breakGlassStatus(new Date(t0.getTime() + 120_000));
    assert.equal(active.activation.ticket_reference, 'INC-B');

    const expired = breakGlassStatus(new Date(t0.getTime() + 11 * 60_000));
    assert.equal(expired.active, false);
    assert.equal(expired.activation, null);
  });

  it('records audit callback metadata without secrets', () => {
    const audits = [];
    activateBreakGlass(
      { staffId: 'staff_audit', staffRole: 'internal_admin' },
      { reason: 'Audit path', ticket_reference: 'INC-AUD', duration_minutes: 20 },
      { audit: (event) => audits.push(event) },
    );
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, 'break_glass.activated');
    assert.equal(audits[0].metadata.ticket_reference, 'INC-AUD');
    assert.equal(audits[0].metadata.password, undefined);
  });
});