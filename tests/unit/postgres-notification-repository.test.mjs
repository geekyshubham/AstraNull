import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createNotificationRepository,
  mapDeliveryAttemptRow,
  mapNotificationRuleRow,
} from '../../src/persistence/postgres/notificationRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

describe('postgres notification repository', () => {
  it('maps notification rule rows with triggers_json array', () => {
    const mapped = mapNotificationRuleRow({
      id: 'nrule_1',
      tenant_id: CTX.tenantId,
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/x',
      trigger: 'finding.high_severity',
      triggers_json: ['finding.high_severity', 'agent.offline'],
      enabled: true,
      created_at: new Date(FIXED_NOW),
    });
    assert.deepEqual(mapped.triggers, ['finding.high_severity', 'agent.offline']);
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('falls back to legacy trigger column when triggers_json is empty', () => {
    const mapped = mapNotificationRuleRow({
      id: 'nrule_2',
      tenant_id: CTX.tenantId,
      channel: 'in_app',
      destination: '',
      trigger: 'report.ready',
      triggers_json: [],
      enabled: true,
      created_at: FIXED_NOW,
    });
    assert.deepEqual(mapped.triggers, ['report.ready']);
  });

  it('maps delivery attempt rows with ISO timestamps', () => {
    const mapped = mapDeliveryAttemptRow({
      id: 'natt_1',
      rule_id: 'nrule_1',
      channel: 'email',
      destination_preview: 'email:a…@example.com',
      status: 'queued_provider_not_configured',
      reason: 'outbound_provider_not_configured_opt_in',
      created_at: new Date(FIXED_NOW),
      attempted_at: null,
    });
    assert.equal(mapped.attempted_at, null);
    assert.equal(mapped.created_at, FIXED_NOW);
    assert.equal(mapped.attempt_number, null);
    assert.equal(mapped.next_retry_at, null);
  });

  it('maps delivery attempt retry and DLQ fields', () => {
    const nextRetry = '2026-06-01T13:00:00.000Z';
    const mapped = mapDeliveryAttemptRow({
      id: 'natt_retry',
      rule_id: 'nrule_1',
      channel: 'webhook',
      destination_preview: 'webhook:hooks.example.invalid',
      status: 'provider_retry_scheduled',
      reason: 'webhook_send_failed',
      attempt_number: 1,
      max_attempts: 3,
      next_retry_at: new Date(nextRetry),
      provider_error: 'webhook_send_failed',
      exhausted: false,
      provider_status: 503,
      created_at: FIXED_NOW,
      attempted_at: FIXED_NOW,
    });
    assert.equal(mapped.attempt_number, 1);
    assert.equal(mapped.max_attempts, 3);
    assert.equal(mapped.next_retry_at, nextRetry);
    assert.equal(mapped.provider_error, 'webhook_send_failed');
    assert.equal(mapped.exhausted, false);
    assert.equal(mapped.provider_status, 503);
  });

  it('createNotificationRule uses parameterized SQL and triggers_json', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO notification_rules/i.test(sql)) {
        assert.match(sql, /triggers_json/i);
        assert.ok(params.includes(CTX.tenantId));
        const triggersParam = params.find(
          (p) => typeof p === 'string' && p.includes('finding.high_severity'),
        );
        assert.ok(triggersParam);
        return {
          rows: [
            {
              id: 'nrule_new',
              tenant_id: CTX.tenantId,
              channel: 'in_app',
              destination: '',
              trigger: 'finding.high_severity',
              triggers_json: ['finding.high_severity', 'agent.offline'],
              enabled: true,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const repo = createNotificationRepository(pool);
    const created = await repo.createNotificationRule(CTX, {
      id: 'nrule_new',
      channel: 'in_app',
      destination: '',
      triggers: ['finding.high_severity', 'agent.offline'],
      enabled: true,
      created_at: FIXED_NOW,
    });

    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 1);
    assert.deepEqual(created.triggers, ['finding.high_severity', 'agent.offline']);
  });

  it('listNotificationEvents loads delivery attempts for tenant-scoped events', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM notification_events/i.test(sql)) {
        assert.ok(params.includes(CTX.tenantId));
        return {
          rows: [
            {
              id: 'nevt_1',
              tenant_id: CTX.tenantId,
              rule_id: null,
              trigger: 'finding.high_severity',
              subject: 'Finding opened',
              metadata_json: { severity: 'high' },
              delivery_status: 'metadata_only',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (/FROM notification_delivery_attempts/i.test(sql)) {
        assert.ok(params.includes(CTX.tenantId));
        assert.ok(params.some((p) => Array.isArray(p) && p.includes('nevt_1')));
        return {
          rows: [
            {
              id: 'natt_nevt_1_nrule_1',
              tenant_id: CTX.tenantId,
              notification_event_id: 'nevt_1',
              rule_id: 'nrule_1',
              channel: 'in_app',
              destination_preview: 'in_app:feed',
              status: 'delivered_in_app',
              reason: 'recorded_in_tenant_in_app_feed',
              created_at: FIXED_NOW,
              attempted_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const repo = createNotificationRepository(pool);
    const events = await repo.listNotificationEvents(CTX, { limit: 50 });
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 2);
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].metadata, { severity: 'high' });
    assert.equal(events[0].delivery_attempts.length, 1);
    assert.equal(events[0].delivery_attempts[0].status, 'delivered_in_app');
  });

  it('appendNotificationEvent stores redacted metadata_json with parameterized SQL', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO notification_events/i.test(sql)) {
        assert.match(sql, /metadata_json/i);
        assert.ok(params.includes(JSON.stringify({ token: '[REDACTED]' })));
        return {
          rows: [
            {
              id: 'nevt_meta',
              tenant_id: CTX.tenantId,
              rule_id: null,
              trigger: 'agent.offline',
              subject: 'Agent [REDACTED]',
              metadata_json: { token: '[REDACTED]' },
              delivery_status: 'metadata_only',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const repo = createNotificationRepository(pool);
    const event = await repo.appendNotificationEvent(CTX, {
      id: 'nevt_meta',
      trigger: 'agent.offline',
      subject: 'Agent [REDACTED]',
      metadata: { token: '[REDACTED]' },
      delivery_status: 'metadata_only',
      created_at: FIXED_NOW,
    });

    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.deepEqual(event.metadata, { token: '[REDACTED]' });
  });

  it('appendDeliveryAttempts persists retry metadata and round-trips via mapper', async () => {
    const nextRetry = '2026-06-01T13:00:00.000Z';
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO notification_delivery_attempts/i.test(sql)) {
        assert.match(sql, /attempt_number/i);
        assert.match(sql, /next_retry_at/i);
        assert.match(sql, /provider_error/i);
        assert.match(sql, /exhausted/i);
        assert.match(sql, /provider_status/i);
        assert.ok(params.includes(2));
        assert.ok(params.includes(3));
        assert.ok(params.includes(nextRetry));
        assert.ok(params.includes('timeout'));
        assert.equal(params.includes(false), true);
        assert.equal(params.includes(502), true);
        return {
          rows: [
            {
              id: 'natt_retry',
              tenant_id: CTX.tenantId,
              notification_event_id: 'nevt_retry',
              rule_id: 'nrule_1',
              channel: 'webhook',
              destination_preview: 'webhook:hooks.example.invalid',
              status: 'provider_retry_scheduled',
              reason: 'timeout',
              attempt_number: 2,
              max_attempts: 3,
              next_retry_at: new Date(nextRetry),
              provider_error: 'timeout',
              exhausted: false,
              provider_status: 502,
              created_at: FIXED_NOW,
              attempted_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const repo = createNotificationRepository(pool);
    const inserted = await repo.appendDeliveryAttempts(CTX, 'nevt_retry', [
      {
        id: 'natt_retry',
        rule_id: 'nrule_1',
        channel: 'webhook',
        destination_preview: 'webhook:hooks.example.invalid',
        status: 'provider_retry_scheduled',
        reason: 'timeout',
        attempt_number: 2,
        max_attempts: 3,
        next_retry_at: nextRetry,
        provider_error: 'timeout',
        exhausted: false,
        provider_status: 502,
        created_at: FIXED_NOW,
        attempted_at: FIXED_NOW,
      },
    ]);

    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(inserted.length, 1);
    assert.equal(inserted[0].next_retry_at, nextRetry);
    assert.equal(inserted[0].attempt_number, 2);
    assert.equal(inserted[0].provider_status, 502);
  });
});

describe('postgres notification repository delivery claims (R02/R04)', () => {
  it('claimDeliveryAttempt is a tenant-scoped conditional UPDATE ... RETURNING with a DB-clock lease', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE notification_delivery_attempts a/i.test(sql)) {
        return {
          rows: [{
            id: 'natt_1', tenant_id: CTX.tenantId, notification_event_id: 'nevt_1', rule_id: 'nrule_1',
            channel: 'webhook', status: 'provider_retry_scheduled', attempt_number: 0, max_attempts: 3,
            next_retry_at: FIXED_NOW, created_at: FIXED_NOW, lease_expires_at: FIXED_NOW,
          }],
        };
      }
      return { rows: [] };
    });
    const repo = createNotificationRepository(pool);
    const claimed = await repo.claimDeliveryAttempt(CTX, { attemptId: 'natt_1', claimToken: 'tok', leaseMs: 1000, dueBy: FIXED_NOW });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [update] = dataQueries(pool.client);
    assert.match(update.text, /WHERE a\.tenant_id = \$1 AND a\.id = \$2/);
    assert.match(update.text, /superseded_at IS NULL/);
    assert.match(update.text, /lease_expires_at IS NULL OR a\.lease_expires_at <= clock_timestamp\(\)/);
    assert.match(update.text, /RETURNING/);
    assert.deepEqual(update.params, [CTX.tenantId, 'natt_1', 'tok', 1000, FIXED_NOW]);
    assert.equal(claimed.notification_event_id, 'nevt_1');
    assert.equal(claimed.lease_expires_at, FIXED_NOW);
  });

  it('claimDeliveryAttempt returns null when the claim is lost', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createNotificationRepository(pool);
    assert.equal(await repo.claimDeliveryAttempt(CTX, { attemptId: 'natt_1', claimToken: 'tok', leaseMs: 1000 }), null);
  });

  it('listDueDeliveryAttempts reads due work from the attempt ledger with a keyset cursor', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createNotificationRepository(pool);
    await repo.listDueDeliveryAttempts(CTX, {
      asOf: FIXED_NOW, limit: 25, after: { next_retry_at: '2026-06-01T11:00:00.000Z', id: 'natt_0' },
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [select] = dataQueries(pool.client);
    assert.doesNotMatch(select.text, /ORDER BY e\.created_at DESC/);
    assert.match(select.text, /a\.next_retry_at <= \$2::timestamptz/);
    assert.match(select.text, /\(a\.next_retry_at, a\.id\) > \(\$3::timestamptz, \$4::text\)/);
    assert.match(select.text, /ORDER BY a\.next_retry_at ASC, a\.id ASC/);
    // The cursor column must carry full database precision: a ms-truncated Date string would
    // re-serve the page-boundary row on the next page and burn the tick's work budget on it.
    assert.match(select.text, /a\.next_retry_at::text AS next_retry_at_cursor/);
    assert.deepEqual(select.params, [CTX.tenantId, FIXED_NOW, '2026-06-01T11:00:00.000Z', 'natt_0', 25]);
  });

  it('listDlqDeliveryAttempts selects a full-precision created_at cursor column', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createNotificationRepository(pool);
    await repo.listDlqDeliveryAttempts(CTX, {
      limit: 25, after: { created_at: '2026-06-01T11:00:00.000123Z', id: 'natt_0' },
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [select] = dataQueries(pool.client);
    assert.match(select.text, /ORDER BY a\.created_at ASC, a\.id ASC/);
    assert.match(select.text, /\(a\.created_at, a\.id\) > \(/);
    assert.match(select.text, /a\.created_at::text AS created_at_cursor/);
  });

  it('mapDeliveryAttemptRow keeps the cursor columns as exact strings', async () => {
    // A microsecond-precision boundary row must survive the mapping unchanged: an ISO round-trip
    // would truncate to milliseconds and break the keyset page advance.
    const MICROSECOND_TS = '2026-06-01T11:00:00.000123+00:00';
    const pool = createRecordingPool((sql) => {
      if (/FROM notification_delivery_attempts a/i.test(sql)) {
        return {
          rows: [{
            id: 'natt_1', tenant_id: CTX.tenantId, notification_event_id: 'nevt_1', rule_id: 'nrule_1',
            channel: 'webhook', status: 'provider_retry_scheduled', attempt_number: 1, max_attempts: 3,
            next_retry_at: MICROSECOND_TS, created_at: MICROSECOND_TS, lease_expires_at: null,
            next_retry_at_cursor: '2026-06-01T11:00:00.000123',
          }],
        };
      }
      return { rows: [] };
    });
    const repo = createNotificationRepository(pool);
    const [row] = await repo.listDueDeliveryAttempts(CTX, { asOf: FIXED_NOW, limit: 10 });
    assert.equal(row.attempt.next_retry_at_cursor, '2026-06-01T11:00:00.000123');
    assert.notEqual(new Date(row.attempt.next_retry_at).toISOString(), row.attempt.next_retry_at_cursor, 'the cursor is not a ms-truncated Date string');
  });

  it('completeDeliveryAttemptClaim writes nothing when this claim no longer owns the attempt', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createNotificationRepository(pool);
    const result = await repo.completeDeliveryAttemptClaim(CTX, {
      attemptId: 'natt_1', claimToken: 'tok', eventId: 'nevt_1', record: { id: 'natt_2' },
    });
    assert.deepEqual(result, { completed: false, attempt: null });
    assert.equal(dataQueries(pool.client).some((q) => /INSERT INTO/i.test(q.text)), false);
  });
});
