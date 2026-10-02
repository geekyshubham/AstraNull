import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  NOTIFICATION_REPOSITORY_METHODS,
  createPostgresNotificationServices,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  NOTIFICATION_RULE_GATE,
  NOTIFICATION_RULE_HELD_STATUS,
  NOTIFICATION_RULE_REMOVED_STATUS,
  NOTIFICATION_RULE_UNSUBSCRIBED_STATUS,
  buildMetadataOnlyRetryDeliveryAttempt,
  buildWebhookRetryDeliveryAttempt,
  collectDueNotificationRetries,
  finalizeGatedNotificationDeliveryAttempts,
  notificationRuleDeliveryGate,
  processDueNotificationRetryBatch,
} from '../../src/lib/notificationRetry.mjs';
import { WEBHOOK_DELIVERY_MODE } from '../../src/lib/notificationDelivery.mjs';
import {
  createNotificationRule,
  emitNotification,
} from '../../src/services/notifications.mjs';
import { processDueNotificationRetries } from '../../src/services/notificationRetry.mjs';
import { redriveNotificationDlq } from '../../src/services/notificationDlqRedrive.mjs';
import {
  buildMetadataOnlyDlqRedriveAttempt,
  collectDlqNotificationAttempts,
  processNotificationDlqRedriveBatch,
  resolveDlqRedriveDeliveryMode,
} from '../../src/lib/notificationDlqRedrive.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const demoCtx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
const AS_OF = '2026-06-01T12:00:00.000Z';

afterEach(() => {
  freshStore();
});

function sampleDueEvent(overrides = {}) {
  return {
    id: 'nevt_1',
    tenant_id: 'ten_demo',
    trigger: 'report.ready',
    subject: '[REDACTED]',
    metadata: { token: '[REDACTED]' },
    created_at: '2026-06-01T10:00:00.000Z',
    delivery_attempts: [
      {
        id: 'natt_1',
        rule_id: 'nrule_1',
        channel: 'webhook',
        destination_preview: 'webhook://hooks.example.invalid/…',
        status: 'provider_retry_scheduled',
        attempt_number: 1,
        max_attempts: 3,
        next_retry_at: '2026-06-01T11:00:00.000Z',
        provider_error: 'webhook_http_error',
      },
    ],
    ...overrides,
  };
}

describe('notification retry runtime library', () => {
  it('collects only due latest attempts per rule', () => {
    const events = [
      sampleDueEvent(),
      {
        id: 'nevt_future',
        delivery_attempts: [
          {
            id: 'natt_future',
            rule_id: 'nrule_1',
            channel: 'webhook',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2099-01-01T00:00:00.000Z',
          },
        ],
      },
      {
        id: 'nevt_superseded',
        delivery_attempts: [
          {
            id: 'natt_old',
            rule_id: 'nrule_1',
            channel: 'webhook',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2020-01-01T00:00:00.000Z',
          },
          {
            id: 'natt_new',
            rule_id: 'nrule_1',
            channel: 'webhook',
            status: 'delivered_provider',
            attempt_number: 2,
            max_attempts: 3,
          },
        ],
      },
    ];

    const collected = collectDueNotificationRetries(events, AS_OF);
    assert.equal(collected.due_count, 1);
    assert.equal(collected.scheduled_not_due, 1);
    assert.equal(collected.due_items[0].event.id, 'nevt_1');
  });

  it('metadata-only retry schedules next attempt or DLQ at max attempts', () => {
    const scheduled = buildMetadataOnlyRetryDeliveryAttempt({
      attempt: { rule_id: 'nrule_1', channel: 'webhook', attempt_number: 1, max_attempts: 3 },
      now: AS_OF,
      newAttemptId: 'natt_2',
    });
    assert.equal(scheduled.status, 'provider_retry_scheduled');
    assert.equal(scheduled.attempt_number, 2);
    assert.ok(scheduled.next_retry_at);

    const dlq = buildMetadataOnlyRetryDeliveryAttempt({
      attempt: { rule_id: 'nrule_1', channel: 'webhook', attempt_number: 2, max_attempts: 3 },
      now: AS_OF,
      newAttemptId: 'natt_3',
    });
    assert.equal(dlq.status, 'provider_failed_dlq');
    assert.equal(dlq.exhausted, true);
  });

  it('webhook retry uses redacted body and injected sender', async () => {
    const sent = [];
    const record = await buildWebhookRetryDeliveryAttempt({
      attempt: {
        rule_id: 'nrule_1',
        channel: 'webhook',
        attempt_number: 1,
        max_attempts: 3,
      },
      event: {
        id: 'nevt_1',
        trigger: 'report.ready',
        subject: '[REDACTED]',
        metadata: { token: '[REDACTED]' },
        created_at: '2026-06-01T10:00:00.000Z',
      },
      rule: {
        id: 'nrule_1',
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/retry',
      },
      now: AS_OF,
      newAttemptId: 'natt_retry',
      webhookSender: async (destination, body) => {
        sent.push({ destination, body });
        return { ok: true, status: 202 };
      },
    });

    assert.equal(sent.length, 1);
    assert.equal(sent[0].body.metadata.token, '[REDACTED]');
    assert.equal(record.status, 'delivered_provider');
    assert.equal(record.attempt_number, 2);
  });

  it('combined email,webhook delivery mode performs webhook retry I/O only for webhook attempts', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: 'email,webhook',
      events: [sampleDueEvent()],
      rules: [
        { id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x' },
      ],
      asOf: AS_OF,
      webhookSender: async (destination, body) => {
        sent.push({ destination, body });
        return { ok: true, status: 202 };
      },
      fetchFn: async () => {
        throw new Error('fetch must not be called when webhookSender is injected');
      },
    });

    assert.equal(batch.network_sends_performed, 1);
    assert.equal(sent.length, 1);
    assert.equal(batch.processed[0].status, 'delivered_provider');
  });

  it('slack delivery mode performs slack retry I/O for slack attempts', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: 'slack',
      events: [
        sampleDueEvent({
          delivery_attempts: [
            {
              id: 'natt_slack',
              rule_id: 'nrule_slack',
              channel: 'slack',
              destination_preview: 'webhook:hooks.slack.invalid',
              status: 'provider_retry_scheduled',
              attempt_number: 1,
              max_attempts: 3,
              next_retry_at: '2026-06-01T11:00:00.000Z',
            },
          ],
        }),
      ],
      rules: [
        { id: 'nrule_slack', channel: 'slack', destination: 'https://hooks.slack.invalid/retry' },
      ],
      asOf: AS_OF,
      slackDeliverer: async (payload, destination) => {
        sent.push({ destination, payload });
        return { status: 'delivered_provider', reason: 'slack_delivered' };
      },
    });

    assert.equal(batch.network_sends_performed, 1);
    assert.equal(sent.length, 1);
    assert.equal(batch.processed[0].status, 'delivered_provider');
    assert.equal(batch.processed[0].attempt_number, 2);
  });

  it('email delivery mode performs email retry I/O for email attempts', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: 'email',
      events: [
        sampleDueEvent({
          delivery_attempts: [
            {
              id: 'natt_email',
              rule_id: 'nrule_email',
              channel: 'email',
              destination_preview: 'email:a…@customer.example',
              status: 'provider_retry_scheduled',
              attempt_number: 1,
              max_attempts: 3,
              next_retry_at: '2026-06-01T11:00:00.000Z',
            },
          ],
        }),
      ],
      rules: [
        { id: 'nrule_email', channel: 'email', destination: 'alerts@customer.example' },
      ],
      asOf: AS_OF,
      emailDeliverer: async (envelope) => {
        sent.push(envelope);
        return { status: 'delivered_provider', reason: 'email_delivered' };
      },
    });

    assert.equal(batch.network_sends_performed, 1);
    assert.equal(sent.length, 1);
    assert.match(sent[0].html_body, /Trigger/);
    assert.equal(batch.processed[0].status, 'delivered_provider');
  });

  it('email-only combined mode keeps webhook attempts metadata-only', async () => {
    const fetchCalls = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: 'email',
      events: [sampleDueEvent()],
      rules: [
        { id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x' },
      ],
      asOf: AS_OF,
      fetchFn: async () => {
        fetchCalls.push(1);
        return { ok: true, status: 200 };
      },
    });

    assert.equal(batch.network_sends_performed, 0);
    assert.equal(fetchCalls.length, 0);
    assert.equal(batch.processed[0].status, 'provider_retry_scheduled');
  });

  it('webhook mode does not count network sends when rule has no destination', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [sampleDueEvent()],
      rules: [{ id: 'nrule_1', channel: 'webhook', destination: '' }],
      asOf: AS_OF,
      webhookSender: async (destination, body) => {
        sent.push({ destination, body });
        return { ok: true, status: 202 };
      },
    });

    assert.equal(batch.network_sends_performed, 0);
    assert.equal(sent.length, 0);
    assert.equal(batch.processed[0].status, 'provider_failed_dlq');
    assert.equal(batch.processed[0].delivery_record.reason, 'retry_channel_not_supported');
  });

  it('webhook mode does not count network sends when matching rule is absent', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [sampleDueEvent()],
      rules: [],
      asOf: AS_OF,
      webhookSender: async (destination, body) => {
        sent.push({ destination, body });
        return { ok: true, status: 202 };
      },
    });

    assert.equal(batch.network_sends_performed, 0);
    assert.equal(sent.length, 0);
    assert.equal(batch.processed[0].status, 'provider_failed_dlq');
    assert.equal(batch.processed[0].delivery_record.reason, 'retry_channel_not_supported');
  });

  it('default delivery mode batch performs no network sends', async () => {
    const fetchCalls = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: 'metadata_only',
      events: [sampleDueEvent()],
      rules: [
        { id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x' },
      ],
      asOf: AS_OF,
      fetchFn: async () => {
        fetchCalls.push(1);
        return { ok: true, status: 200 };
      },
    });

    assert.equal(batch.network_sends_performed, 0);
    assert.equal(batch.processed.length, 1);
    assert.equal(batch.processed[0].status, 'provider_retry_scheduled');
    assert.equal(fetchCalls.length, 0);
  });
});

describe('dev notification retry service', () => {
  it('persists metadata-only retry attempts and audits without destinations', async () => {
    freshStore();
    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/fail',
      triggers: ['report.ready'],
    });

    await emitNotification(
      demoCtx,
      { trigger: 'report.ready', subject: 'secret ast_abcdefghijklmnop', metadata: { token: 'ast_abcdefghijklmnop' } },
      {
        deliveryMode: WEBHOOK_DELIVERY_MODE,
        webhookSender: async () => ({ ok: false, error: 'webhook_http_error', status: 503 }),
      },
    );

    const eventBefore = getStore().notificationEvents[0];
    eventBefore.delivery_attempts[0].next_retry_at = '2026-06-01T11:00:00.000Z';

    const result = await processDueNotificationRetries(demoCtx, {
      asOf: AS_OF,
      deliveryMode: 'metadata_only',
      now: AS_OF,
      newId: () => 'natt_retry_2',
    });

    assert.equal(result.network_sends_performed, 0);
    assert.equal(result.processed.length, 1);
    const eventAfter = getStore().notificationEvents[0];
    assert.equal(eventAfter.delivery_attempts.length, 2);
    assert.equal(eventAfter.delivery_attempts[1].status, 'provider_retry_scheduled');
    assert.equal(eventAfter.delivery_attempts[1].attempt_number, 2);

    const audits = getStore().auditLog.filter((a) => a.action === 'notification.delivery_attempt_recorded');
    const blob = JSON.stringify(audits);
    assert.ok(!blob.includes('hooks.example.invalid'));
    assert.ok(!blob.includes('ast_abcdefghijklmnop'));
  });

  it('dry-run does not append attempts', async () => {
    freshStore();
    getStore().notificationEvents.push(sampleDueEvent());

    const result = await processDueNotificationRetries(demoCtx, {
      asOf: AS_OF,
      dryRun: true,
      deliveryMode: 'metadata_only',
    });

    assert.equal(result.processed[0].status, 'retry_due');
    assert.equal(getStore().notificationEvents[0].delivery_attempts.length, 1);
  });
});

describe('postgres notification retry service adapter', () => {
  it('exposes processDueNotificationRetries on the service surface', () => {
    assert.ok(
      createPostgresNotificationServices({
        notifications: Object.fromEntries(
          NOTIFICATION_REPOSITORY_METHODS.map((method) => [method, async () => []]),
        ),
        audit: { appendAuditEvent: async () => {} },
      }).processDueNotificationRetries,
    );
  });

  it('appends retry attempts and audits in apply mode', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const rule = {
      id: 'nrule_1',
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/x',
      triggers: ['report.ready'],
      enabled: true,
    };
    const appendCalls = [];
    const auditEvents = [];

    const notifications = createPostgresNotificationServices(
      {
        notifications: {
          listNotificationRules: async () => [rule],
          listNotificationEvents: async () => [
            {
              id: 'nevt_1',
              tenant_id: ctx.tenantId,
              trigger: 'report.ready',
              subject: '[REDACTED]',
              metadata: {},
              created_at: '2026-06-01T10:00:00.000Z',
              delivery_attempts: [
                {
                  id: 'natt_1',
                  rule_id: 'nrule_1',
                  channel: 'webhook',
                  status: 'provider_retry_scheduled',
                  attempt_number: 2,
                  max_attempts: 3,
                  next_retry_at: '2026-06-01T11:00:00.000Z',
                },
              ],
            },
          ],
          createNotificationRule: async () => rule,
          appendNotificationEvent: async () => ({}),
          appendDeliveryAttempts: async (_c, eventId, attempts) => {
            appendCalls.push({ eventId, attempts });
            return attempts;
          },
        },
        audit: {
          appendAuditEvent: async (entry) => {
            auditEvents.push(entry);
            return entry;
          },
        },
      },
      { newId: () => 'natt_pg_retry', deliveryMode: 'metadata_only' },
    );

    const result = await notifications.processDueNotificationRetries(ctx, {
      asOf: AS_OF,
      now: AS_OF,
    });

    assert.equal(result.due_count, 1);
    assert.equal(result.processed[0].status, 'provider_failed_dlq');
    assert.equal(appendCalls.length, 1);
    assert.equal(appendCalls[0].attempts[0].id, 'natt_pg_retry');
    assert.ok(auditEvents.some((a) => a.metadata?.retry === true));
  });

  it('exposes redriveNotificationDlq on the service surface', () => {
    assert.ok(
      createPostgresNotificationServices({
        notifications: Object.fromEntries(
          NOTIFICATION_REPOSITORY_METHODS.map((method) => [method, async () => []]),
        ),
        audit: { appendAuditEvent: async () => {} },
      }).redriveNotificationDlq,
    );
  });
});

function sampleDlqEvent(overrides = {}) {
  return {
    id: 'nevt_dlq',
    tenant_id: 'ten_demo',
    trigger: 'report.ready',
    subject: '[REDACTED]',
    metadata: {},
    created_at: '2026-06-01T10:00:00.000Z',
    delivery_attempts: [
      {
        id: 'natt_dlq_1',
        rule_id: 'nrule_1',
        channel: 'webhook',
        destination_preview: 'webhook://hooks.example.invalid/…',
        status: 'provider_failed_dlq',
        reason: 'webhook_http_error',
        provider_error: 'webhook_http_error',
        attempt_number: 3,
        max_attempts: 3,
        exhausted: true,
      },
    ],
    ...overrides,
  };
}

describe('notification DLQ redrive runtime library', () => {
  it('collects latest DLQ attempts and filters by attempt id', () => {
    const events = [sampleDlqEvent()];
    const collected = collectDlqNotificationAttempts(events, { attemptIds: ['natt_dlq_1'] });
    assert.equal(collected.candidate_count, 1);
    assert.equal(collected.skipped_count, 0);

    const missing = collectDlqNotificationAttempts(events, { attemptIds: ['natt_missing'] });
    assert.equal(missing.candidate_count, 0);
    assert.equal(missing.skipped_count, 1);
  });

  it('metadata-only DLQ redrive requeues with attempt reset', () => {
    const record = buildMetadataOnlyDlqRedriveAttempt({
      attempt: {
        rule_id: 'nrule_1',
        channel: 'webhook',
        attempt_number: 3,
        max_attempts: 3,
        destination_preview: 'webhook://hooks.example.invalid/…',
      },
      now: AS_OF,
      newAttemptId: 'natt_redrive_1',
    });
    assert.equal(record.status, 'provider_retry_scheduled');
    assert.equal(record.attempt_number, 1);
    assert.equal(record.reason, 'dlq_redrive_metadata_only');
    assert.equal(record.next_retry_at, AS_OF);
  });

  it('resolveDlqRedriveDeliveryMode stays metadata-only by default and in test', () => {
    assert.equal(resolveDlqRedriveDeliveryMode({}), 'metadata_only');
    assert.equal(resolveDlqRedriveDeliveryMode({ forceMetadataOnly: true }), 'metadata_only');
    const prevMode = process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
    const prevEnv = process.env.NODE_ENV;
    process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = 'webhook';
    process.env.NODE_ENV = 'test';
    assert.equal(resolveDlqRedriveDeliveryMode({ forceMetadataOnly: false }), 'metadata_only');
    process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = prevMode;
    process.env.NODE_ENV = prevEnv;
  });

  it('processes metadata-only DLQ redrive batch without network sends', async () => {
    const events = [sampleDlqEvent()];
    const rules = [{
      id: 'nrule_1',
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/x',
    }];

    const batch = await processNotificationDlqRedriveBatch({
      deliveryMode: 'metadata_only',
      events,
      rules,
      attemptIds: ['natt_dlq_1'],
      now: AS_OF,
      newAttemptId: () => 'natt_redrive_1',
    });

    assert.equal(batch.requeued_count, 1);
    assert.equal(batch.skipped_count, 0);
    assert.equal(batch.still_dlq_count, 0);
    assert.equal(batch.network_sends_performed, 0);
    assert.equal(batch.processed[0].status, 'provider_retry_scheduled');
    assert.equal(batch.processed[0].delivery_record.attempt_number, 1);
  });

  it('adapter redrive performs bounded webhook send when mode is active outside test', async () => {
    const prevEnv = process.env.NODE_ENV;
    const prevMode = process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
    process.env.NODE_ENV = 'staging';
    process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = 'webhook';

    const sent = [];
    const batch = await processNotificationDlqRedriveBatch({
      deliveryMode: resolveDlqRedriveDeliveryMode({ forceMetadataOnly: false }),
      events: [sampleDlqEvent()],
      rules: [{
        id: 'nrule_1',
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/x',
      }],
      attemptIds: ['natt_dlq_1'],
      now: AS_OF,
      newAttemptId: () => 'natt_redrive_adapter',
      webhookSender: async (destination, body) => {
        sent.push({ destination, body });
        return { ok: true, status: 202 };
      },
    });

    process.env.NODE_ENV = prevEnv;
    process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = prevMode;

    assert.equal(sent.length, 1);
    assert.equal(batch.processed[0].status, 'delivered_provider');
    assert.equal(batch.requeued_count, 1);
    assert.equal(batch.still_dlq_count, 0);
    assert.equal(batch.network_sends_performed, 1);
    assert.equal(JSON.stringify(sent[0].body).includes('ast_'), false);
  });

  it('dry-run plans redrive without changing still_dlq_count projection', async () => {
    const events = [sampleDlqEvent()];
    const batch = await processNotificationDlqRedriveBatch({
      deliveryMode: 'metadata_only',
      events,
      rules: [{ id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x' }],
      attemptIds: ['natt_dlq_1'],
      dryRun: true,
      now: AS_OF,
    });

    assert.equal(batch.dry_run, true);
    assert.equal(batch.requeued_count, 1);
    assert.equal(batch.still_dlq_count, 1);
    assert.equal(batch.processed[0].status, 'redrive_planned');
  });
});

describe('dev-json notification DLQ redrive service', () => {
  it('redrives DLQ attempts, audits safely, and omits delivery_record', async () => {
    freshStore();
    getStore().notificationRules.push({
      id: 'nrule_1',
      tenant_id: 'ten_demo',
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/ast_v1.secret',
      triggers: ['report.ready'],
      enabled: true,
    });
    getStore().notificationEvents.push(sampleDlqEvent());

    const result = await redriveNotificationDlq(demoCtx, {
      attemptIds: ['natt_dlq_1'],
      now: AS_OF,
      newId: () => 'natt_redrive_svc',
    });

    assert.equal(result.requeued_count, 1);
    assert.equal(result.still_dlq_count, 0);
    assert.equal(result.processed[0].status, 'provider_retry_scheduled');
    assert.equal(JSON.stringify(result).includes('delivery_record'), false);
    assert.equal(JSON.stringify(result).includes('ast_v1.secret'), false);

    const event = getStore().notificationEvents[0];
    assert.equal(event.delivery_attempts.length, 2);
    assert.equal(event.delivery_attempts[1].id, 'natt_redrive_svc');

    const audits = getStore().auditLog.filter((a) => a.action === 'notification.dlq_redrive');
    assert.equal(audits.length, 1);
    assert.equal(audits[0].metadata.requeued_count, 1);
    assert.equal(JSON.stringify(audits[0]).includes('hooks.example.invalid'), false);
  });
});
describe('notification rule lifecycle gate (R01)', () => {
  const liveRule = { id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x', enabled: true };

  it('classifies live, turned-off, removed, and unknown rules', () => {
    assert.equal(notificationRuleDeliveryGate(liveRule), NOTIFICATION_RULE_GATE.DELIVER);
    assert.equal(notificationRuleDeliveryGate({ ...liveRule, enabled: false }), NOTIFICATION_RULE_GATE.HOLD);
    assert.equal(
      notificationRuleDeliveryGate({ ...liveRule, enabled: false, deleted_at: AS_OF }),
      NOTIFICATION_RULE_GATE.CANCEL,
    );
    assert.equal(notificationRuleDeliveryGate(null), NOTIFICATION_RULE_GATE.UNKNOWN);
  });

  it('retry batch holds a due attempt for a turned-off rule without sending or recording', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [sampleDueEvent()],
      rules: [{ ...liveRule, enabled: false }],
      asOf: AS_OF,
      webhookSender: async (destination) => { sent.push(destination); return { ok: true, status: 202 }; },
    });
    assert.equal(sent.length, 0);
    assert.equal(batch.network_sends_performed, 0);
    assert.equal(batch.held_count, 1);
    assert.equal(batch.processed[0].status, NOTIFICATION_RULE_HELD_STATUS);
    assert.equal(batch.processed[0].delivery_record, undefined);
  });

  it('retry batch re-reads the rule per attempt so a stale enabled snapshot cannot send', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [sampleDueEvent()],
      rules: [liveRule],
      resolveRule: async () => ({ ...liveRule, enabled: false }),
      asOf: AS_OF,
      webhookSender: async (destination) => { sent.push(destination); return { ok: true, status: 202 }; },
    });
    assert.equal(sent.length, 0);
    assert.equal(batch.held_count, 1);
  });

  it('retry batch cancels pending work for a removed rule with a non-sent terminal attempt', async () => {
    const sent = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [sampleDueEvent()],
      rules: [],
      resolveRule: async () => ({ ...liveRule, enabled: false, destination: '', deleted_at: AS_OF }),
      asOf: AS_OF,
      webhookSender: async (destination) => { sent.push(destination); return { ok: true, status: 202 }; },
    });
    assert.equal(sent.length, 0);
    assert.equal(batch.network_sends_performed, 0);
    assert.equal(batch.cancelled_count, 1);
    const record = batch.processed[0].delivery_record;
    assert.equal(record.status, NOTIFICATION_RULE_REMOVED_STATUS);
    assert.equal(record.attempted_at, null);
    assert.equal(record.exhausted, true);
    // Terminal: the cancellation is the latest attempt, so nothing is due afterwards.
    const after = collectDueNotificationRetries(
      [{ ...sampleDueEvent(), delivery_attempts: [...sampleDueEvent().delivery_attempts, record] }],
      AS_OF,
    );
    assert.equal(after.due_count, 0);
  });

  it('DLQ redrive holds a turned-off rule and cancels a removed rule, sending nothing', async () => {
    const sent = [];
    const webhookSender = async (destination) => { sent.push(destination); return { ok: true, status: 202 }; };
    const held = await processNotificationDlqRedriveBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [sampleDlqEvent()],
      rules: [{ ...liveRule, enabled: false }],
      attemptIds: ['natt_dlq_1'],
      now: AS_OF,
      webhookSender,
    });
    assert.equal(held.held_count, 1);
    assert.equal(held.requeued_count, 0);
    assert.equal(held.still_dlq_count, 1);
    assert.equal(held.processed[0].delivery_record, undefined);

    const cancelled = await processNotificationDlqRedriveBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [sampleDlqEvent()],
      rules: [],
      resolveRule: () => ({ ...liveRule, enabled: false, destination: '', deleted_at: AS_OF }),
      attemptIds: ['natt_dlq_1'],
      now: AS_OF,
      webhookSender,
    });
    assert.equal(cancelled.cancelled_count, 1);
    assert.equal(cancelled.requeued_count, 0);
    assert.equal(cancelled.still_dlq_count, 0);
    assert.equal(cancelled.processed[0].delivery_record.status, NOTIFICATION_RULE_REMOVED_STATUS);
    assert.equal(sent.length, 0);
  });

  it('dev JSON retry holds a turned-off rule using the live store', async () => {
    const rule = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/dev',
      triggers: ['report.ready'],
    });
    getStore().notificationEvents.push(sampleDueEvent({
      delivery_attempts: [{ ...sampleDueEvent().delivery_attempts[0], rule_id: rule.id }],
    }));
    getStore().notificationRules.find((r) => r.id === rule.id).enabled = false;
    const sent = [];
    const result = await processDueNotificationRetries(demoCtx, {
      asOf: AS_OF,
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      webhookSender: async (destination) => { sent.push(destination); return { ok: true, status: 202 }; },
    });
    assert.equal(sent.length, 0);
    assert.equal(result.held_count, 1);
    assert.equal(getStore().notificationEvents.at(-1).delivery_attempts.length, 1);
  });
});

describe('immediate emit delivery gate (R01 follow-up)', () => {
  const liveRule = { id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x', enabled: true };
  const gateEvent = { id: 'nevt_1', trigger: 'report.ready', subject: 's', metadata: {}, created_at: AS_OF };
  const initialAttempt = {
    id: 'natt_1', rule_id: 'nrule_1', channel: 'webhook',
    destination_preview: 'webhook://hooks.example.invalid/…',
    status: 'queued_provider_not_configured',
    reason: 'outbound_provider_not_configured_opt_in',
    created_at: AS_OF, attempted_at: null,
  };
  const sender = (sent) => async (destination) => { sent.push(destination); return { ok: true, status: 202 }; };

  it('without resolveRule it delegates to the snapshot finalize', async () => {
    const sent = [];
    const out = await finalizeGatedNotificationDeliveryAttempts({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      attempts: [initialAttempt],
      rules: [liveRule],
      event: gateEvent,
      now: AS_OF,
      webhookSender: sender(sent),
    });
    assert.deepEqual(sent, ['https://hooks.example.invalid/x']);
    assert.equal(out[0].status, 'delivered_provider');
  });

  it('sends a live rule with the resolver-supplied rule state', async () => {
    const sent = [];
    const out = await finalizeGatedNotificationDeliveryAttempts({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      attempts: [initialAttempt],
      rules: [{ ...liveRule, destination: 'https://hooks.example.invalid/stale' }],
      event: gateEvent,
      now: AS_OF,
      webhookSender: sender(sent),
      resolveRule: async () => ({ ...liveRule, destination: 'https://hooks.example.invalid/live' }),
    });
    assert.deepEqual(sent, ['https://hooks.example.invalid/live'], 'the live destination is used, not the snapshot copy');
    assert.equal(out[0].status, 'delivered_provider');
  });

  it('holds a rule disabled after the snapshot without sending, recording resumable pending work', async () => {
    const sent = [];
    const out = await finalizeGatedNotificationDeliveryAttempts({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      attempts: [initialAttempt],
      rules: [liveRule],
      event: gateEvent,
      now: AS_OF,
      webhookSender: sender(sent),
      resolveRule: async () => ({ ...liveRule, enabled: false }),
    });
    assert.deepEqual(sent, [], 'a disabled rule is never delivered to');
    assert.equal(out.length, 1);
    assert.equal(out[0].status, 'provider_retry_scheduled');
    assert.equal(out[0].reason, 'outbox_pending_delivery', 'the pending attempt resumes through the retry worker');
    assert.equal(out[0].attempted_at, null);
    assert.equal(out[0].attempt_number, 0);
    assert.equal(out[0].exhausted, false);
    // Resumable: once the rule is re-enabled the attempt is due again.
    const due = collectDueNotificationRetries(
      [{ ...gateEvent, delivery_attempts: [out[0]] }],
      AS_OF,
    );
    assert.equal(due.due_count, 1);
  });

  it('cancels a rule removed or unsubscribed after the snapshot with a non-sent terminal attempt', async () => {
    const sent = [];
    const removed = await finalizeGatedNotificationDeliveryAttempts({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      attempts: [initialAttempt],
      rules: [liveRule],
      event: gateEvent,
      now: AS_OF,
      webhookSender: sender(sent),
      resolveRule: async () => ({ ...liveRule, deleted_at: AS_OF }),
    });
    assert.deepEqual(sent, []);
    assert.equal(removed[0].status, NOTIFICATION_RULE_REMOVED_STATUS);
    assert.equal(removed[0].attempted_at, null);
    assert.equal(removed[0].exhausted, true);

    const unsubscribed = await finalizeGatedNotificationDeliveryAttempts({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      attempts: [initialAttempt],
      rules: [liveRule],
      event: gateEvent,
      now: AS_OF,
      webhookSender: sender(sent),
      resolveRule: async () => ({ ...liveRule, triggers: ['safe_test.completed'] }),
    });
    assert.deepEqual(sent, []);
    assert.equal(unsubscribed[0].status, NOTIFICATION_RULE_UNSUBSCRIBED_STATUS);
    assert.equal(unsubscribed[0].attempted_at, null);
    // Terminal: nothing is due afterwards.
    const after = collectDueNotificationRetries(
      [{ ...gateEvent, delivery_attempts: [removed[0]] }],
      AS_OF,
    );
    assert.equal(after.due_count, 0);
  });

  it('fails closed when the live rule cannot be resolved', async () => {
    const sent = [];
    const out = await finalizeGatedNotificationDeliveryAttempts({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      attempts: [initialAttempt],
      rules: [liveRule],
      event: gateEvent,
      now: AS_OF,
      webhookSender: sender(sent),
      resolveRule: async () => null,
    });
    assert.deepEqual(sent, []);
    assert.deepEqual(out, [initialAttempt]);
  });

  it('does not gate in-app recording', async () => {
    const out = await finalizeGatedNotificationDeliveryAttempts({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      attempts: [{ ...initialAttempt, channel: 'in_app', status: 'delivered_in_app', reason: 'recorded_in_tenant_in_app_feed' }],
      rules: [{ ...liveRule, channel: 'in_app' }],
      event: gateEvent,
      now: AS_OF,
      resolveRule: async () => ({ ...liveRule, channel: 'in_app', enabled: false }),
    });
    assert.equal(out[0].status, 'delivered_in_app');
  });
});

describe('postgres emitNotification wires the live rule gate (R01 follow-up)', () => {
  const ctx = { tenantId: 'ten_emit_gate', userId: 'system', role: 'system' };
  const liveRule = { id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x', triggers: ['report.ready'], enabled: true };

  function emitService(liveState, webhookSender) {
    return createPostgresNotificationServices({
      notifications: {
        listNotificationRules: async () => [{ ...liveRule }],
        getNotificationRuleDeliveryState: async () => ({ ...liveState }),
        listNotificationEvents: async () => [],
        createNotificationRule: async () => null,
        appendNotificationEvent: async () => ({ id: 'nevt_1' }),
        appendDeliveryAttempts: async (_c, _eventId, attempts) => attempts,
      },
      audit: { appendAuditEvent: async () => ({}) },
    }, {
      deliveryMode: 'webhook',
      webhookSender,
    });
  }

  it('a rule disabled after the emit snapshot is held, not sent', async () => {
    const sent = [];
    const notifications = emitService({ ...liveRule, enabled: false }, async (destination) => {
      sent.push(destination);
      return { ok: true, status: 202 };
    });
    const result = await notifications.emitNotification(ctx, { trigger: 'report.ready', subject: 's', metadata: {} });
    assert.deepEqual(sent, [], 'the emit path must re-gate on the live rule, not the snapshot');
    assert.equal(result.delivery_attempts.length, 1);
    assert.equal(result.delivery_attempts[0].status, 'provider_retry_scheduled');
    assert.equal(result.delivery_attempts[0].reason, 'outbox_pending_delivery');
    assert.equal(result.delivery_attempts[0].attempted_at, null);
  });

  it('a rule removed after the emit snapshot is cancelled with a non-sent terminal attempt', async () => {
    const sent = [];
    const notifications = emitService({ ...liveRule, deleted_at: '2026-06-01T12:00:00.000Z' }, async (destination) => {
      sent.push(destination);
      return { ok: true, status: 202 };
    });
    const result = await notifications.emitNotification(ctx, { trigger: 'report.ready', subject: 's', metadata: {} });
    assert.deepEqual(sent, []);
    assert.equal(result.delivery_attempts[0].status, 'cancelled_rule_removed');
    assert.equal(result.delivery_attempts[0].attempted_at, null);
  });
});

describe('postgres retry recovery with delivery claims (R04)', () => {
  it('sends nothing for a due attempt whose claim is lost to another sender', async () => {
    const { createPostgresNotificationServices } = await import('../../src/persistence/postgres/notificationServiceAdapters.mjs');
    const ctx = { tenantId: 'ten_demo', userId: 'system', role: 'system' };
    const due = {
      event: { id: 'nevt_1', trigger: 'report.ready', subject: 's', metadata: {}, created_at: '2026-06-01T10:00:00.000Z' },
      attempt: {
        id: 'natt_1', rule_id: 'nrule_1', channel: 'webhook', status: 'provider_retry_scheduled',
        attempt_number: 0, max_attempts: 3, next_retry_at: '2026-06-01T10:05:00.000Z',
      },
    };
    let sends = 0;
    const claims = [];
    const notifications = createPostgresNotificationServices({
      notifications: {
        listNotificationRules: async () => [],
        listNotificationEvents: async () => { throw new Error('recovery must not read the events feed'); },
        createNotificationRule: async () => null,
        appendNotificationEvent: async () => ({}),
        appendDeliveryAttempts: async () => { throw new Error('unexpected append'); },
        listDueDeliveryAttempts: async (_c, { after }) => (after ? [] : [due]),
        summarizePendingDeliveryAttempts: async () => ({ scheduled_not_due: 0, held_due: 0, in_flight: 1 }),
        claimDeliveryAttempt: async (_c, claim) => { claims.push(claim); return null; },
        completeDeliveryAttemptClaim: async () => { throw new Error('unexpected complete'); },
        releaseDeliveryAttemptClaim: async () => ({ released: false }),
      },
      audit: { appendAuditEvent: async () => ({}) },
    });
    const result = await notifications.processDueNotificationRetries(ctx, {
      asOf: '2026-06-01T11:00:00.000Z',
      deliveryMode: 'webhook',
      webhookSender: async () => { sends += 1; return { ok: true }; },
    });
    assert.equal(sends, 0);
    assert.equal(claims.length, 1);
    assert.equal(claims[0].dueBy, '2026-06-01T11:00:00.000Z');
    assert.equal(result.claim_lost_count, 1);
    assert.equal(result.in_flight_count, 1);
    assert.equal(result.network_sends_performed, 0);
  });
});
