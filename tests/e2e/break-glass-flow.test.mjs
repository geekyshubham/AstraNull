import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { resetBreakGlassStore } from '../../src/services/breakGlass.mjs';
import { demoHeaders, request, staffHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let baseUrl;
let server;

const activationBody = {
  reason: 'Emergency SOC tenant review during incident INC-9001',
  ticket_reference: 'INC-9001',
  duration_minutes: 30,
};

before(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  resetBreakGlassStore();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('break-glass e2e flow', () => {
  it('denies unauthenticated and customer principals on break-glass routes', async () => {
    const unauthStatus = await request(baseUrl, 'GET', '/internal/admin/break-glass/status');
    assert.ok([401, 403].includes(unauthStatus.status), `expected 401/403 got ${unauthStatus.status}`);

    const customerStatus = await request(baseUrl, 'GET', '/internal/admin/break-glass/status', {
      headers: demoHeaders('admin'),
    });
    assert.equal(customerStatus.status, 403);

    const customerActivate = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: demoHeaders('admin'),
      body: activationBody,
    });
    assert.equal(customerActivate.status, 403);
  });

  it('allows security_admin to read status but not activate break-glass', async () => {
    const status = await request(baseUrl, 'GET', '/internal/admin/break-glass/status', {
      headers: staffHeaders('security_admin', 'staff_security'),
    });
    assert.equal(status.status, 200);
    assert.equal(status.json.active, false);
    assert.equal(status.json.procedure_reference, 'runbook://security/break-glass');

    const denied = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('security_admin', 'staff_security'),
      body: activationBody,
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.error, 'forbidden');
  });

  it('denies support_engineer on break-glass read and activate', async () => {
    const status = await request(baseUrl, 'GET', '/internal/admin/break-glass/status', {
      headers: staffHeaders('support_engineer', 'staff_support'),
    });
    assert.equal(status.status, 403);

    const activate = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('support_engineer', 'staff_support'),
      body: activationBody,
    });
    assert.equal(activate.status, 403);
  });

  it('activates break-glass, reports active status, and supersedes prior activation', async () => {
    const first = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: activationBody,
    });
    assert.equal(first.status, 200);
    assert.ok(first.json.activation?.id);
    assert.equal(first.json.activation.ticket_reference, 'INC-9001');

    const status = await request(baseUrl, 'GET', '/internal/admin/break-glass/status', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(status.status, 200);
    assert.equal(status.json.active, true);
    assert.equal(status.json.activation.id, first.json.activation.id);

    const second = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: {
        reason: 'Follow-up emergency access for INC-9002',
        ticket_reference: 'INC-9002',
        duration_minutes: 15,
      },
    });
    assert.equal(second.status, 200);
    assert.notEqual(second.json.activation.id, first.json.activation.id);

    const latest = await request(baseUrl, 'GET', '/internal/admin/break-glass/status', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(latest.json.activation.ticket_reference, 'INC-9002');
  });

  it('rejects activation missing ticket_reference and forbidden credential fields', async () => {
    const missingTicket = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'No ticket', duration_minutes: 30 },
    });
    assert.equal(missingTicket.status, 400);
    assert.equal(missingTicket.json.error, 'validation_failed');
    assert.ok(missingTicket.json.missing_fields.includes('ticket_reference'));

    const forbidden = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: {
        ...activationBody,
        password: 'must-not-accept',
      },
    });
    assert.equal(forbidden.status, 400);
    assert.ok(forbidden.json.forbidden_fields.includes('password'));
  });

  it('status response omits activation reason from API surface', async () => {
    await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: {
        reason: 'Sensitive incident narrative that must not appear in status API',
        ticket_reference: 'INC-PRIVACY',
        duration_minutes: 30,
      },
    });
    const status = await request(baseUrl, 'GET', '/internal/admin/break-glass/status', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(status.json.active, true);
    assert.equal(status.json.activation.reason, undefined);
    assert.equal(status.json.activation.ticket_reference, 'INC-PRIVACY');
  });

  it('rejects out-of-range duration_minutes', async () => {
    const tooShort = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'x', ticket_reference: 'INC-1', duration_minutes: 1 },
    });
    assert.equal(tooShort.status, 400);
    assert.ok(tooShort.json.missing_fields.includes('duration_minutes'));

    const tooLong = await request(baseUrl, 'POST', '/internal/admin/break-glass/activate', {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'x', ticket_reference: 'INC-1', duration_minutes: 500 },
    });
    assert.equal(tooLong.status, 400);
    assert.ok(tooLong.json.missing_fields.includes('duration_minutes'));
  });
});