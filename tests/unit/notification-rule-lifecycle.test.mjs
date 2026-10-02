import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import {
  createNotificationRule,
  deleteNotificationRule,
  emitNotification,
  hasActiveNotificationRule,
  listNotifications,
  NOTIFICATION_EVENTS_WINDOW,
  updateNotificationRule,
} from '../../src/services/notifications.mjs';
import {
  latestDeliveryByRuleFromEvents,
  normalizeNotificationRuleUpdate,
} from '../../src/lib/notificationRuleUpdate.mjs';
import { NOTIFICATION_RULE_ID_ROUTE } from '../../src/lib/postgresRouteGuard.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const demoCtx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const otherCtx = { tenantId: 'ten_other', userId: 'usr_other', role: 'admin' };
const SECRET_URL = 'https://hooks.example.invalid/services/T000/B000/secretpathvalue';

function ruleAudits(action) {
  return getStore().auditLog.filter((entry) => entry.action === action);
}

describe('normalizeNotificationRuleUpdate (G01 validation reuse)', () => {
  const existing = {
    channel: 'webhook',
    destination: 'https://hooks.example.invalid/a',
    triggers: ['finding.high_severity'],
    enabled: true,
  };

  it('rejects credentials in a replacement URL exactly like the create path', () => {
    const result = normalizeNotificationRuleUpdate(existing, {
      destination: 'https://user:pass@hooks.example.invalid/a',
    });
    assert.equal(result.ok, undefined);
    assert.equal(result.status, 400);
  });

  it('rejects a malformed email destination for an email rule', () => {
    const result = normalizeNotificationRuleUpdate(
      { channel: 'email', destination: 'ops@example.com', triggers: ['report.ready'], enabled: true },
      { destination: 'not an email' },
    );
    assert.equal(result.status, 400);
  });

  it('rejects channel changes, non-boolean enabled, unknown triggers, and empty bodies', () => {
    assert.equal(normalizeNotificationRuleUpdate(existing, { channel: 'email' }).error, 'channel_immutable');
    assert.equal(normalizeNotificationRuleUpdate(existing, { enabled: 'no' }).error, 'invalid_enabled');
    assert.equal(normalizeNotificationRuleUpdate(existing, { triggers: ['nope'] }).error, 'invalid_trigger');
    assert.equal(normalizeNotificationRuleUpdate(existing, {}).error, 'no_changes');
    assert.equal(normalizeNotificationRuleUpdate(existing, null).error, 'invalid_body');
  });

  it('reports only fields that actually change', () => {
    const result = normalizeNotificationRuleUpdate(existing, { enabled: true, triggers: ['finding.high_severity'] });
    assert.equal(result.ok, true);
    assert.deepEqual(result.changedFields, []);
    const toggled = normalizeNotificationRuleUpdate(existing, { enabled: false });
    assert.deepEqual(toggled.changedFields, ['enabled']);
  });
});

describe('dev store notification rule lifecycle (G01)', () => {
  beforeEach(() => freshStore());

  it('disables a rule, audits the change without the destination, and stops it emitting', async () => {
    const rule = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: SECRET_URL,
      triggers: ['finding.high_severity'],
    });
    assert.equal(hasActiveNotificationRule(demoCtx, 'finding.high_severity'), true);

    const updated = updateNotificationRule(demoCtx, rule.id, { enabled: false });
    assert.equal(updated.enabled, false);
    assert.equal(hasActiveNotificationRule(demoCtx, 'finding.high_severity'), false);

    const event = await emitNotification(demoCtx, { trigger: 'finding.high_severity', subject: 'x' });
    assert.equal(event.delivery_attempts.length, 0);

    const audits = ruleAudits('notification.rule_updated');
    assert.equal(audits.length, 1);
    assert.equal(audits[0].tenant_id, demoCtx.tenantId);
    assert.equal(audits[0].resource_id, rule.id);
    assert.deepEqual(audits[0].metadata.changed_fields, ['enabled']);
    assert.equal(audits[0].metadata.destination_changed, false);
    assert.doesNotMatch(JSON.stringify(audits[0]), /secretpathvalue/);
  });

  it('replaces destination and triggers after create-path validation', () => {
    const rule = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/old',
      triggers: ['finding.high_severity'],
    });
    const bad = updateNotificationRule(demoCtx, rule.id, { destination: 'https://u:p@hooks.example.invalid/x' });
    assert.equal(bad.status, 400);
    assert.equal(getStore().notificationRules[0].destination, 'https://hooks.example.invalid/old');

    const updated = updateNotificationRule(demoCtx, rule.id, {
      destination: SECRET_URL,
      triggers: ['report.ready', 'report.ready'],
    });
    assert.equal(updated.destination, SECRET_URL);
    assert.deepEqual(updated.triggers, ['report.ready']);
    const [audit] = ruleAudits('notification.rule_updated');
    assert.deepEqual(audit.metadata.changed_fields, ['triggers', 'destination']);
    assert.equal(audit.metadata.destination_changed, true);
    assert.doesNotMatch(JSON.stringify(audit), /secretpathvalue/);
  });

  it('cannot update or delete another tenant rule', () => {
    const rule = createNotificationRule(demoCtx, { channel: 'in_app', triggers: ['report.ready'] });
    assert.equal(updateNotificationRule(otherCtx, rule.id, { enabled: false }), null);
    assert.equal(deleteNotificationRule(otherCtx, rule.id), null);
    assert.equal(getStore().notificationRules[0].enabled, true);
    assert.equal(ruleAudits('notification.rule_updated').length, 0);
    assert.equal(ruleAudits('notification.rule_deleted').length, 0);
  });

  it('soft-deletes a rule: hidden from reads, destination cleared, history kept, audited once', async () => {
    const rule = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: SECRET_URL,
      triggers: ['finding.high_severity'],
    });
    await emitNotification(demoCtx, { trigger: 'finding.high_severity', subject: 'before' });

    const removed = deleteNotificationRule(demoCtx, rule.id);
    assert.equal(removed.deleted, true);
    assert.equal(deleteNotificationRule(demoCtx, rule.id), null, 'second delete is a 404');

    const listed = listNotifications(demoCtx);
    assert.equal(listed.rules.length, 0);
    assert.equal(listed.events.length, 1, 'delivery history is kept');
    const stored = getStore().notificationRules[0];
    assert.equal(stored.destination, '');
    assert.equal(stored.enabled, false);
    assert.ok(stored.deleted_at);
    assert.equal(hasActiveNotificationRule(demoCtx, 'finding.high_severity'), false);
    assert.equal(updateNotificationRule(demoCtx, rule.id, { enabled: true }), null);

    const audits = ruleAudits('notification.rule_deleted');
    assert.equal(audits.length, 1);
    assert.deepEqual(audits[0].metadata, { channel: 'webhook' });
  });
});

describe('authoritative latest delivery per rule (F11)', () => {
  beforeEach(() => freshStore());

  it('reports a quiet rule latest delivery even after 100+ newer events from other rules', async () => {
    const quiet = createNotificationRule(demoCtx, { channel: 'in_app', triggers: ['report.ready'] });
    const busy = createNotificationRule(demoCtx, { channel: 'in_app', triggers: ['finding.high_severity'] });
    await emitNotification(demoCtx, { trigger: 'report.ready', subject: 'quiet one' });
    for (let i = 0; i < NOTIFICATION_EVENTS_WINDOW + 5; i += 1) {
      await emitNotification(demoCtx, { trigger: 'finding.high_severity', subject: `busy ${i}` });
    }

    const listed = listNotifications(demoCtx);
    assert.equal(listed.events.length, NOTIFICATION_EVENTS_WINDOW);
    const inWindow = listed.events.some((event) =>
      (event.delivery_attempts ?? []).some((attempt) => attempt.rule_id === quiet.id));
    assert.equal(inWindow, false, 'the quiet rule attempt has fallen out of the bounded feed');

    assert.equal(listed.latest_deliveries[quiet.id]?.status, 'delivered_in_app');
    assert.equal(listed.latest_deliveries[busy.id]?.status, 'delivered_in_app');
    assert.deepEqual(listed.events_window, {
      limit: NOTIFICATION_EVENTS_WINDOW,
      returned: NOTIFICATION_EVENTS_WINDOW,
      truncated: true,
    });
  });

  it('returns null (not missing) for a live rule with no attempt, and nothing for another tenant', () => {
    const rule = createNotificationRule(demoCtx, { channel: 'in_app', triggers: ['report.ready'] });
    const listed = listNotifications(demoCtx);
    assert.ok(Object.prototype.hasOwnProperty.call(listed.latest_deliveries, rule.id));
    assert.equal(listed.latest_deliveries[rule.id], null);
    assert.deepEqual(listNotifications(otherCtx).latest_deliveries, {});
  });

  it('latestDeliveryByRuleFromEvents picks the newest attempt and redacts the payload', () => {
    const latest = latestDeliveryByRuleFromEvents([
      {
        id: 'e1',
        created_at: '2026-01-01T00:00:00.000Z',
        delivery_attempts: [{ id: 'a1', rule_id: 'r1', status: 'provider_retry_scheduled', created_at: '2026-01-01T00:00:00.000Z', destination_preview: 'webhook://x', provider_error: 'boom' }],
      },
      {
        id: 'e2',
        created_at: '2026-01-02T00:00:00.000Z',
        delivery_attempts: [{ id: 'a2', rule_id: 'r1', status: 'delivered_provider', created_at: '2026-01-02T00:00:00.000Z' }],
      },
    ]);
    assert.equal(latest.get('r1').status, 'delivered_provider');
    assert.equal(latest.get('r1').event_id, 'e2');
    assert.equal(latest.get('r1').destination_preview, undefined);
    assert.equal(latest.get('r1').provider_error, undefined);
  });
});

describe('PATCH/DELETE /v1/notifications/:id (G01 HTTP)', () => {
  let server;
  let baseUrl;

  before(async () => {
    freshStore();
    server = createServer();
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await closeServer(server);
  });

  beforeEach(() => freshStore());

  async function createViaApi() {
    const res = await request(baseUrl, 'POST', '/v1/notifications', {
      headers: demoHeaders('admin'),
      body: { channel: 'webhook', destination: SECRET_URL, triggers: ['finding.high_severity'] },
    });
    assert.equal(res.status, 201);
    return res.json;
  }

  it('route pattern accepts real rule ids but never the deeper management subpaths', () => {
    assert.equal(NOTIFICATION_RULE_ID_ROUTE.test('/v1/notifications/id_0123abcd'), true);
    assert.equal(NOTIFICATION_RULE_ID_ROUTE.test('/v1/notifications/retries/process'), false);
    assert.equal(NOTIFICATION_RULE_ID_ROUTE.test('/v1/notifications/dlq/redrive'), false);
    assert.equal(NOTIFICATION_RULE_ID_ROUTE.test('/v1/notifications'), false);
  });

  it('admin can toggle and edit; the response carries only the redacted preview', async () => {
    const rule = await createViaApi();
    const res = await request(baseUrl, 'PATCH', `/v1/notifications/${rule.id}`, {
      headers: demoHeaders('admin'),
      body: { enabled: false, destination: 'https://hooks.example.invalid/new/othersecret' },
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.enabled, false);
    assert.equal(res.json.destination, undefined);
    assert.match(res.json.destination_preview, /^webhook:\/\/hooks\.example\.invalid/);
    assert.doesNotMatch(res.text, /othersecret|secretpathvalue/);
    assert.equal(ruleAudits('notification.rule_updated').length, 1);
  });

  it('rejects invalid updates with 400 and does not audit', async () => {
    const rule = await createViaApi();
    const res = await request(baseUrl, 'PATCH', `/v1/notifications/${rule.id}`, {
      headers: demoHeaders('admin'),
      body: { destination: 'https://user:pw@hooks.example.invalid/x' },
    });
    assert.equal(res.status, 400);
    assert.ok(res.json.error);
    assert.equal(ruleAudits('notification.rule_updated').length, 0);
  });

  it('denies engineer, auditor and viewer with 403 for both PATCH and DELETE', async () => {
    const rule = await createViaApi();
    for (const role of ['engineer', 'auditor', 'viewer']) {
      const patch = await request(baseUrl, 'PATCH', `/v1/notifications/${rule.id}`, {
        headers: demoHeaders(role),
        body: { enabled: false },
      });
      assert.equal(patch.status, 403, `${role} PATCH`);
      const del = await request(baseUrl, 'DELETE', `/v1/notifications/${rule.id}`, { headers: demoHeaders(role) });
      assert.equal(del.status, 403, `${role} DELETE`);
    }
    assert.equal(getStore().notificationRules[0].enabled, true);
    assert.equal(getStore().notificationRules[0].deleted_at, undefined);
  });

  it('returns 404 for another tenant rule on PATCH and DELETE', async () => {
    const rule = await createViaApi();
    const otherHeaders = demoHeaders('admin', 'ten_other', 'usr_other');
    const patch = await request(baseUrl, 'PATCH', `/v1/notifications/${rule.id}`, {
      headers: otherHeaders,
      body: { enabled: false },
    });
    assert.equal(patch.status, 404);
    const del = await request(baseUrl, 'DELETE', `/v1/notifications/${rule.id}`, { headers: otherHeaders });
    assert.equal(del.status, 404);
    assert.equal(getStore().notificationRules[0].enabled, true);
  });

  it('DELETE removes the rule from GET and audits notification.rule_deleted', async () => {
    const rule = await createViaApi();
    const del = await request(baseUrl, 'DELETE', `/v1/notifications/${rule.id}`, { headers: demoHeaders('admin') });
    assert.equal(del.status, 200);
    assert.deepEqual(Object.keys(del.json).sort(), ['deleted', 'deleted_at', 'id']);
    const list = await request(baseUrl, 'GET', '/v1/notifications', { headers: demoHeaders('admin') });
    assert.equal(list.json.rules.length, 0);
    assert.ok(list.json.events_window);
    assert.equal(ruleAudits('notification.rule_deleted').length, 1);
    const again = await request(baseUrl, 'DELETE', `/v1/notifications/${rule.id}`, { headers: demoHeaders('admin') });
    assert.equal(again.status, 404);
  });
});
