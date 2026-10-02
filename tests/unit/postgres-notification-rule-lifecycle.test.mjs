import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import {
  NOTIFICATION_REPOSITORY_METHODS,
  NOTIFICATION_RULE_LIFECYCLE_REPOSITORY_METHODS,
  POSTGRES_NOTIFICATION_EVENTS_WINDOW,
  createPostgresNotificationServices,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import { createServer } from '../../src/server.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const NOW = '2026-06-01T12:00:00.000Z';
const SECRET_URL = 'https://hooks.example.invalid/services/T0/B0/secretpathvalue';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params) ?? { rows: [] };
    },
    release() {
      this.released = true;
    },
  };
  return { client, async connect() { return client; } };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

const ruleRow = (overrides = {}) => ({
  id: 'id_rule1',
  tenant_id: CTX.tenantId,
  channel: 'webhook',
  destination: SECRET_URL,
  trigger: 'finding.high_severity',
  triggers_json: ['finding.high_severity'],
  enabled: true,
  created_at: NOW,
  updated_at: null,
  ...overrides,
});

describe('postgres notification repository rule lifecycle', () => {
  it('listNotificationRules hides soft-deleted rules', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    await createNotificationRepository(pool).listNotificationRules(CTX);
    const [query] = dataQueries(pool.client);
    assert.match(query.text, /tenant_id = \$1 AND deleted_at IS NULL/);
  });

  it('updateNotificationRule writes only changed fields with parameters, tenant-scoped', async () => {
    const pool = createRecordingPool((sql) => (/UPDATE notification_rules/.test(sql)
      ? { rows: [ruleRow({ enabled: false, updated_at: NOW })] }
      : { rows: [] }));
    const updated = await createNotificationRepository(pool).updateNotificationRule(
      CTX,
      'id_rule1',
      { enabled: false },
      { updated_at: NOW },
    );
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [query] = dataQueries(pool.client);
    assert.match(query.text, /WHERE tenant_id = \$1 AND id = \$2 AND deleted_at IS NULL/);
    assert.match(query.text, /enabled = \$5/);
    assert.doesNotMatch(query.text, /destination =|triggers_json =/);
    assert.deepEqual(query.params, [CTX.tenantId, 'id_rule1', NOW, CTX.userId, false]);
    assert.equal(updated.enabled, false);
    assert.equal(updated.updated_at, NOW);
  });

  it('updateNotificationRule keeps the legacy trigger column in sync and never interpolates values', async () => {
    const pool = createRecordingPool(() => ({ rows: [ruleRow()] }));
    await createNotificationRepository(pool).updateNotificationRule(
      CTX,
      'id_rule1',
      { triggers: ['report.ready'], destination: SECRET_URL },
      { updated_at: NOW },
    );
    const [query] = dataQueries(pool.client);
    assert.match(query.text, /triggers_json = \$5::jsonb/);
    assert.match(query.text, /trigger = \$6/);
    assert.match(query.text, /destination = \$7/);
    assert.doesNotMatch(query.text, /secretpathvalue|report\.ready/);
    assert.deepEqual(query.params.slice(4), [JSON.stringify(['report.ready']), 'report.ready', SECRET_URL]);
  });

  it('deleteNotificationRule soft-deletes, disables, and clears the stored destination', async () => {
    const pool = createRecordingPool(() => ({ rows: [ruleRow({ enabled: false, destination: '' })] }));
    const removed = await createNotificationRepository(pool).deleteNotificationRule(CTX, 'id_rule1', { deleted_at: NOW });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [query] = dataQueries(pool.client);
    assert.match(query.text, /^UPDATE notification_rules/);
    assert.doesNotMatch(query.text, /DELETE FROM/);
    assert.match(query.text, /deleted_at = \$3::timestamptz/);
    assert.match(query.text, /enabled = FALSE/);
    assert.match(query.text, /destination = ''/);
    assert.match(query.text, /AND deleted_at IS NULL/);
    assert.equal(removed.id, 'id_rule1');
  });

  it('listLatestDeliveryAttemptsByRule reads full history per live rule (not the event feed)', async () => {
    const pool = createRecordingPool(() => ({
      rows: [{
        id: 'att_1',
        tenant_id: CTX.tenantId,
        notification_event_id: 'nevt_old',
        rule_id: 'id_rule1',
        channel: 'webhook',
        destination_preview: 'webhook://hooks.example.invalid…',
        status: 'delivered_provider',
        created_at: new Date(NOW),
        attempted_at: new Date(NOW),
      }],
    }));
    const rows = await createNotificationRepository(pool).listLatestDeliveryAttemptsByRule(CTX);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [query] = dataQueries(pool.client);
    assert.match(query.text, /SELECT DISTINCT ON \(a\.rule_id\)/);
    assert.match(query.text, /ORDER BY a\.rule_id, a\.created_at DESC, a\.id DESC/);
    assert.match(query.text, /r\.deleted_at IS NULL/);
    assert.doesNotMatch(query.text, /LIMIT/);
    assert.deepEqual(query.params, [CTX.tenantId]);
    assert.equal(rows[0].notification_event_id, 'nevt_old');
    assert.equal(rows[0].created_at, NOW);
  });
});

function recordingRepositories(overrides = {}) {
  const auditEvents = [];
  const calls = [];
  const notifications = {};
  for (const method of [...NOTIFICATION_REPOSITORY_METHODS, ...NOTIFICATION_RULE_LIFECYCLE_REPOSITORY_METHODS]) {
    notifications[method] = async (...args) => {
      calls.push({ method, args });
      return overrides[method] ? overrides[method](...args) : null;
    };
  }
  return {
    repositories: { notifications, audit: { appendAuditEvent: async (entry) => { auditEvents.push(entry); return entry; } } },
    auditEvents,
    calls,
  };
}

describe('postgres notification adapter rule lifecycle', () => {
  const now = () => new Date(NOW);

  it('updateNotificationRule validates with the create path and audits without the destination', async () => {
    const { repositories, auditEvents, calls } = recordingRepositories({
      getNotificationRule: async () => ({ ...ruleRow(), triggers: ['finding.high_severity'] }),
      updateNotificationRule: async (_ctx, _id, changes) => ({ ...ruleRow(), triggers: ['finding.high_severity'], ...changes }),
    });
    const services = createPostgresNotificationServices(repositories, { now });

    const bad = await services.updateNotificationRule(CTX, 'id_rule1', { destination: 'https://u:p@hooks.example.invalid/x' });
    assert.equal(bad.status, 400);
    assert.equal(calls.some((c) => c.method === 'updateNotificationRule'), false);
    assert.equal(auditEvents.length, 0);

    const updated = await services.updateNotificationRule(CTX, 'id_rule1', {
      enabled: false,
      destination: 'https://hooks.example.invalid/new/othersecret',
    });
    assert.equal(updated.enabled, false);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'notification.rule_updated');
    assert.equal(auditEvents[0].tenant_id, CTX.tenantId);
    assert.deepEqual(auditEvents[0].metadata.changed_fields, ['enabled', 'destination']);
    assert.doesNotMatch(JSON.stringify(auditEvents), /othersecret|secretpathvalue/);
  });

  it('returns null (404) for a rule outside the tenant and writes nothing', async () => {
    const { repositories, auditEvents, calls } = recordingRepositories({ getNotificationRule: async () => null });
    const services = createPostgresNotificationServices(repositories, { now });
    assert.equal(await services.updateNotificationRule(CTX, 'id_other', { enabled: false }), null);
    assert.equal(await services.deleteNotificationRule(CTX, 'id_other'), null);
    assert.equal(calls.filter((c) => c.method === 'updateNotificationRule').length, 0);
    assert.equal(auditEvents.length, 0);
  });

  it('deleteNotificationRule audits notification.rule_deleted', async () => {
    const { repositories, auditEvents } = recordingRepositories({
      deleteNotificationRule: async () => ({ ...ruleRow(), destination: '' }),
    });
    const services = createPostgresNotificationServices(repositories, { now });
    const result = await services.deleteNotificationRule(CTX, 'id_rule1');
    assert.deepEqual(result, { id: 'id_rule1', deleted: true, deleted_at: NOW });
    assert.equal(auditEvents[0].action, 'notification.rule_deleted');
    assert.deepEqual(auditEvents[0].metadata, { channel: 'webhook' });
  });

  it('listNotifications returns authoritative latest_deliveries and the events window', async () => {
    const { repositories } = recordingRepositories({
      listNotificationRules: async () => [{ ...ruleRow(), triggers: ['finding.high_severity'] }, { ...ruleRow({ id: 'id_quiet' }), triggers: ['report.ready'] }],
      listNotificationEvents: async () => Array.from({ length: POSTGRES_NOTIFICATION_EVENTS_WINDOW }, (_, i) => ({
        id: `nevt_${i}`,
        delivery_attempts: [{ rule_id: 'id_rule1', status: 'delivered_provider' }],
      })),
      listLatestDeliveryAttemptsByRule: async () => [
        { id: 'att_q', rule_id: 'id_quiet', notification_event_id: 'nevt_old', status: 'delivered_provider', created_at: NOW, provider_error: 'x', destination_preview: 'p' },
      ],
    });
    const payload = await createPostgresNotificationServices(repositories).listNotifications(CTX);
    assert.equal(payload.latest_deliveries.id_quiet.status, 'delivered_provider');
    assert.equal(payload.latest_deliveries.id_quiet.event_id, 'nevt_old');
    assert.equal(payload.latest_deliveries.id_quiet.provider_error, undefined);
    assert.equal(payload.latest_deliveries.id_rule1, null);
    assert.deepEqual(payload.events_window, { limit: 100, returned: 100, truncated: true });
    assert.doesNotMatch(JSON.stringify(payload.rules), /secretpathvalue/);
  });

  it('stays constructible with an older repository and answers 503 for lifecycle calls', async () => {
    const notifications = Object.fromEntries(NOTIFICATION_REPOSITORY_METHODS.map((m) => [m, async () => []]));
    const services = createPostgresNotificationServices({
      notifications,
      audit: { appendAuditEvent: async () => null },
    });
    const listed = await services.listNotifications(CTX);
    assert.equal('latest_deliveries' in listed, false, 'no authoritative claim without the full-history read');
    assert.deepEqual(await services.updateNotificationRule(CTX, 'id_x', { enabled: false }), { error: 'postgres_route_not_wired', status: 503 });
    assert.deepEqual(await services.deleteNotificationRule(CTX, 'id_x'), { error: 'postgres_route_not_wired', status: 503 });
  });
});

describe('postgres-mode server PATCH/DELETE /v1/notifications/:id', () => {
  let server;
  afterEach(async () => {
    if (server) await closeServer(server);
    server = null;
  });

  async function listen(services) {
    server = createServer({
      env: { ...process.env, ASTRANULL_NO_PERSIST: '1' },
      runtimeConfig: {
        authMode: 'dev-headers',
        sessionSecret: null,
        oidc: null,
        nodeEnv: 'test',
        maxJsonBodyBytes: 65536,
        shutdownGraceMs: 30_000,
        persistenceMode: 'postgres',
        databaseUrlConfigured: true,
        probeMode: 'simulation',
        probeWorkerSecret: null,
        probeWorkerSecretConfigured: false,
        rateLimit: { windowMs: 60_000, maxRequests: 600, disabled: false, trustProxyHeaders: false },
        secretEncryptionKey: null,
        secretEncryptionConfigured: false,
      },
      services,
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${server.address().port}`;
  }

  it('returns 503 postgres_route_not_wired when lifecycle methods are not wired', async () => {
    const baseUrl = await listen({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      notifications: { listNotifications: async () => ({ rules: [], events: [] }), createNotificationRule: async () => ({}) },
    });
    const patch = await request(baseUrl, 'PATCH', '/v1/notifications/id_rule1', { headers: demoHeaders('admin'), body: { enabled: false } });
    assert.equal(patch.status, 503);
    assert.equal(patch.json.error, 'postgres_route_not_wired');
    const del = await request(baseUrl, 'DELETE', '/v1/notifications/id_rule1', { headers: demoHeaders('admin') });
    assert.equal(del.status, 503);
  });

  it('checks permission before wiring and routes to the injected service with tenant ctx', async () => {
    const calls = [];
    const baseUrl = await listen({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      notifications: {
        listNotifications: async () => ({ rules: [], events: [] }),
        createNotificationRule: async () => ({}),
        updateNotificationRule: async (ctx, id, body) => {
          calls.push(['update', ctx.tenantId, id, body]);
          return id === 'id_missing' ? null : { ...ruleRow({ id }), triggers: ['finding.high_severity'], enabled: false };
        },
        deleteNotificationRule: async (ctx, id) => {
          calls.push(['delete', ctx.tenantId, id]);
          return { id, deleted: true, deleted_at: NOW };
        },
      },
    });
    const forbidden = await request(baseUrl, 'PATCH', '/v1/notifications/id_rule1', { headers: demoHeaders('engineer'), body: { enabled: false } });
    assert.equal(forbidden.status, 403);
    assert.equal(calls.length, 0);

    const patch = await request(baseUrl, 'PATCH', '/v1/notifications/id_rule1', { headers: demoHeaders('admin'), body: { enabled: false } });
    assert.equal(patch.status, 200);
    assert.equal(patch.json.destination, undefined);
    assert.doesNotMatch(patch.text, /secretpathvalue/);
    assert.deepEqual(calls[0], ['update', 'ten_demo', 'id_rule1', { enabled: false }]);

    const missing = await request(baseUrl, 'PATCH', '/v1/notifications/id_missing', { headers: demoHeaders('admin'), body: { enabled: false } });
    assert.equal(missing.status, 404);

    const del = await request(baseUrl, 'DELETE', '/v1/notifications/id_rule1', { headers: demoHeaders('owner') });
    assert.equal(del.status, 200);
    assert.deepEqual(del.json, { id: 'id_rule1', deleted: true, deleted_at: NOW });
  });
});
