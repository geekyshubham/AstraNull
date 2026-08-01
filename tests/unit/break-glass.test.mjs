import assert from 'node:assert/strict';
import { describe, it, before, beforeEach, after } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { validateBreakGlassActivation } from '../../src/contracts/breakGlass.mjs';
import {
  activateBreakGlass,
  breakGlassStatus,
  resetBreakGlassStore,
} from '../../src/services/breakGlass.mjs';
import * as internalManagement from '../../src/services/internalManagement.mjs';
import { request, staffHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

/** Every activation needs an audit writer; collect events for assertions. */
function auditCollector() {
  const events = [];
  return { events, audit: (event) => events.push(event) };
}

describe('break glass', () => {
  beforeEach(() => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    freshStore();
    resetBreakGlassStore();
  });

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

  it('activates and reports status', async () => {
    const ctx = { staffId: 'staff_admin', staffRole: 'internal_admin' };
    const result = await activateBreakGlass(ctx, {
      reason: 'Emergency tenant access review',
      ticket_reference: 'INC-2002',
      duration_minutes: 15,
    }, auditCollector());
    assert.ok(result.activation?.id);
    const status = await breakGlassStatus();
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

  it('supersedes prior activation and expires after window', async () => {
    const ctx = { staffId: 'staff_admin', staffRole: 'internal_admin' };
    const t0 = new Date('2026-07-04T12:00:00.000Z');
    await activateBreakGlass(ctx, {
      reason: 'First activation',
      ticket_reference: 'INC-A',
      duration_minutes: 10,
    }, { ...auditCollector(), now: () => t0 });

    await activateBreakGlass(ctx, {
      reason: 'Second activation',
      ticket_reference: 'INC-B',
      duration_minutes: 10,
    }, { ...auditCollector(), now: () => new Date(t0.getTime() + 60_000) });

    const active = await breakGlassStatus(new Date(t0.getTime() + 120_000));
    assert.equal(active.activation.ticket_reference, 'INC-B');

    const expired = await breakGlassStatus(new Date(t0.getTime() + 11 * 60_000));
    assert.equal(expired.active, false);
    assert.equal(expired.activation, null);
  });

  it('records audit callback metadata without secrets', async () => {
    const { events, audit } = auditCollector();
    await activateBreakGlass(
      { staffId: 'staff_audit', staffRole: 'internal_admin' },
      { reason: 'Audit path', ticket_reference: 'INC-AUD', duration_minutes: 20 },
      { audit },
    );
    assert.equal(events.length, 1);
    assert.equal(events[0].action, 'break_glass.activated');
    assert.equal(events[0].metadata.ticket_reference, 'INC-AUD');
    assert.equal(events[0].metadata.password, undefined);
  });

  it('refuses to activate when no audit writer is supplied', async () => {
    // Regression guard for the silent-no-op defect: the route used to call
    // `appendInternalAudit?.()` against services that never implemented it, so every
    // activation succeeded with no audit trail. Activating unaudited must now fail loudly.
    await assert.rejects(
      () => activateBreakGlass(
        { staffId: 'staff_admin', staffRole: 'internal_admin' },
        { reason: 'No audit writer', ticket_reference: 'INC-NOAUDIT', duration_minutes: 30 },
      ),
      /refusing to activate unaudited/,
    );
    const status = await breakGlassStatus();
    assert.equal(status.active, false, 'must not record an activation it cannot audit');
  });

  it('propagates audit write failures instead of returning success', async () => {
    await assert.rejects(
      () => activateBreakGlass(
        { staffId: 'staff_admin', staffRole: 'internal_admin' },
        { reason: 'Audit down', ticket_reference: 'INC-FAIL', duration_minutes: 30 },
        { audit: () => Promise.reject(new Error('audit store unavailable')) },
      ),
      /audit store unavailable/,
    );
  });

  it('reports reporting-only enforcement so callers cannot mistake it for elevated access', async () => {
    const { audit } = auditCollector();
    await activateBreakGlass(
      { staffId: 'staff_admin', staffRole: 'internal_admin' },
      { reason: 'Enforcement contract', ticket_reference: 'INC-ENF', duration_minutes: 30 },
      { audit },
    );
    const status = await breakGlassStatus();
    assert.equal(status.enforcement, 'reporting_only');
  });
});

describe('break glass in-memory service audit wiring', () => {
  beforeEach(() => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    freshStore();
    resetBreakGlassStore();
  });

  it('appendInternalAudit maps route event shape onto the internal audit log', () => {
    internalManagement.appendInternalAudit(
      { staffId: 'staff_admin', staffRole: 'internal_admin' },
      {
        action: 'break_glass.activated',
        actor_user_id: 'staff_actor',
        actor_role: 'internal_admin',
        resource_type: 'break_glass_activation',
        resource_id: 'bg_x',
        metadata: { ticket_reference: 'INC-MAP' },
      },
    );
    const [entry] = internalManagement.listInternalAudit({ action: 'break_glass.activated' });
    assert.equal(entry.staff_id, 'staff_actor');
    assert.equal(entry.staff_role, 'internal_admin');
    assert.equal(entry.resource_id, 'bg_x');
    assert.equal(entry.metadata.ticket_reference, 'INC-MAP');
  });
});

describe('break glass route audit trail (real wiring)', () => {
  let server;
  let baseUrl;

  before(() => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    freshStore();
    resetBreakGlassStore();
    server = createServer();
    server.listen(0);
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => server?.close());

  it('records break_glass.activated in the audit log through the real route and service', async () => {
    // Drives the actual HTTP route with NO injected audit callback, which is exactly the path
    // the previous test suite never exercised: the route's own `appendInternalAudit` call is
    // what must land the entry.
    const activated = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: {
        reason: 'Real-wiring audit trail check for INC-WIRED',
        ticket_reference: 'INC-WIRED',
        duration_minutes: 30,
      },
    });
    assert.equal(activated.status, 200);
    const activationId = activated.json.activation.id;

    const auditLog = await request(baseUrl, 'GET', '/internal/admin/audit-log?action=break_glass.activated', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(auditLog.status, 200);
    const entry = auditLog.json.items.find((item) => item.resource_id === activationId);
    assert.ok(entry, 'break_glass.activated must be recorded in the internal audit log');
    assert.equal(entry.action, 'break_glass.activated');
    assert.equal(entry.resource_type, 'break_glass_activation');
    assert.equal(entry.staff_id, 'staff_admin');
    assert.equal(entry.metadata.ticket_reference, 'INC-WIRED');
    assert.equal(entry.metadata.enforcement, 'reporting_only');
  });

  it('exposes reporting-only enforcement on the status route', async () => {
    const status = await request(baseUrl, 'GET', '/internal/admin/break-glass/status', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(status.status, 200);
    assert.equal(status.json.enforcement, 'reporting_only');
  });
});
