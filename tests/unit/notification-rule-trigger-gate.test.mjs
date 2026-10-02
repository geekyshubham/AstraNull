import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  NOTIFICATION_RULE_CANCELLED_STATUSES,
  NOTIFICATION_RULE_GATE,
  NOTIFICATION_RULE_HELD_STATUS,
  NOTIFICATION_RULE_REMOVED_STATUS,
  NOTIFICATION_RULE_UNSUBSCRIBED_STATUS,
  buildRuleRemovedCancellationAttempt,
  collectDueNotificationRetries,
  evaluateNotificationRuleDeliveryGate,
  notificationRuleDeliveryGate,
  processDueNotificationRetryBatch,
  resolveNotificationRuleForDelivery,
} from '../../src/lib/notificationRetry.mjs';
import { processNotificationDlqRedriveBatch } from '../../src/lib/notificationDlqRedrive.mjs';
import { WEBHOOK_DELIVERY_MODE } from '../../src/lib/notificationDelivery.mjs';

const AS_OF = '2026-06-01T12:00:00.000Z';
const liveRule = {
  id: 'nrule_1',
  channel: 'webhook',
  destination: 'https://hooks.example.invalid/x',
  enabled: true,
  triggers: ['report.ready', 'safe_test.completed'],
};
const unsubscribedRule = { ...liveRule, triggers: ['safe_test.completed'] };

function dueEvent() {
  return {
    id: 'nevt_1',
    tenant_id: 'ten_demo',
    trigger: 'report.ready',
    subject: '[REDACTED]',
    metadata: {},
    created_at: '2026-06-01T10:00:00.000Z',
    delivery_attempts: [{
      id: 'natt_1',
      rule_id: 'nrule_1',
      channel: 'webhook',
      destination_preview: 'webhook://hooks.example.invalid/…',
      status: 'provider_retry_scheduled',
      attempt_number: 1,
      max_attempts: 3,
      next_retry_at: '2026-06-01T11:00:00.000Z',
      provider_error: 'webhook_http_error',
    }],
  };
}

function dlqEvent() {
  return {
    ...dueEvent(),
    id: 'nevt_dlq',
    delivery_attempts: [{
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
      created_at: '2026-06-01T11:00:00.000Z',
    }],
  };
}

function countingSender() {
  const sent = [];
  return { sent, webhookSender: async (destination) => { sent.push(destination); return { ok: true, status: 202 }; } };
}

describe('notification rule trigger-subscription gate (R01 trigger unsubscribe)', () => {
  it('cancels a live rule that dropped the event trigger and keeps legacy calls unchanged', () => {
    assert.equal(
      notificationRuleDeliveryGate(unsubscribedRule, { trigger: 'report.ready' }),
      NOTIFICATION_RULE_GATE.CANCEL,
    );
    assert.deepEqual(
      evaluateNotificationRuleDeliveryGate(unsubscribedRule, { trigger: 'report.ready' }).cancellation,
      { status: NOTIFICATION_RULE_UNSUBSCRIBED_STATUS, reason: 'rule_unsubscribed' },
    );
    assert.equal(notificationRuleDeliveryGate(liveRule, { trigger: 'report.ready' }), NOTIFICATION_RULE_GATE.DELIVER);
    // No trigger, or a rule record without triggers: enabled/deleted-only behavior.
    assert.equal(notificationRuleDeliveryGate(unsubscribedRule), NOTIFICATION_RULE_GATE.DELIVER);
    const { triggers: _omit, ...noTriggers } = liveRule;
    assert.equal(notificationRuleDeliveryGate(noTriggers, { trigger: 'report.ready' }), NOTIFICATION_RULE_GATE.DELIVER);
    // Removed wins over unsubscribed; turned off holds (agrees with the SQL held predicate).
    assert.equal(
      evaluateNotificationRuleDeliveryGate({ ...unsubscribedRule, deleted_at: AS_OF }, { trigger: 'report.ready' })
        .cancellation.status,
      NOTIFICATION_RULE_REMOVED_STATUS,
    );
    assert.equal(
      notificationRuleDeliveryGate({ ...unsubscribedRule, enabled: false }, { trigger: 'report.ready' }),
      NOTIFICATION_RULE_GATE.HOLD,
    );
    assert.deepEqual([...NOTIFICATION_RULE_CANCELLED_STATUSES].sort(), [
      NOTIFICATION_RULE_REMOVED_STATUS,
      NOTIFICATION_RULE_UNSUBSCRIBED_STATUS,
    ].sort());
  });

  it('resolveNotificationRuleForDelivery passes the trigger through and returns the cancellation', async () => {
    const result = await resolveNotificationRuleForDelivery({
      ruleId: 'nrule_1',
      trigger: 'report.ready',
      resolveRule: async () => unsubscribedRule,
    });
    assert.equal(result.gate, NOTIFICATION_RULE_GATE.CANCEL);
    assert.equal(result.cancellation.status, NOTIFICATION_RULE_UNSUBSCRIBED_STATUS);
    const record = buildRuleRemovedCancellationAttempt({
      attempt: dueEvent().delivery_attempts[0],
      now: AS_OF,
      newAttemptId: 'natt_c',
      cancellation: result.cancellation,
    });
    assert.equal(record.status, NOTIFICATION_RULE_UNSUBSCRIBED_STATUS);
    assert.equal(record.reason, 'rule_unsubscribed');
    assert.equal(record.attempted_at, null);
    assert.equal(record.exhausted, true);
    // Default shape is unchanged for existing callers.
    assert.equal(
      buildRuleRemovedCancellationAttempt({ attempt: dueEvent().delivery_attempts[0], now: AS_OF, newAttemptId: 'x' }).status,
      NOTIFICATION_RULE_REMOVED_STATUS,
    );
  });

  it('retry batch cancels due work for an unsubscribed trigger without sending', async () => {
    const { sent, webhookSender } = countingSender();
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [dueEvent()],
      rules: [liveRule],
      resolveRule: async () => unsubscribedRule,
      asOf: AS_OF,
      webhookSender,
    });
    assert.equal(sent.length, 0);
    assert.equal(batch.network_sends_performed, 0);
    assert.equal(batch.cancelled_count, 1);
    assert.equal(batch.held_count, 0);
    const record = batch.processed[0].delivery_record;
    assert.equal(record.status, NOTIFICATION_RULE_UNSUBSCRIBED_STATUS);
    const after = collectDueNotificationRetries(
      [{ ...dueEvent(), delivery_attempts: [...dueEvent().delivery_attempts, record] }],
      AS_OF,
    );
    assert.equal(after.due_count, 0, 'terminal: nothing is due afterwards');

    const dry = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [dueEvent()],
      rules: [unsubscribedRule],
      asOf: AS_OF,
      dryRun: true,
      webhookSender,
    });
    assert.equal(dry.processed[0].status, NOTIFICATION_RULE_UNSUBSCRIBED_STATUS);
    assert.equal(sent.length, 0);
  });

  it('retry batch holds an off-and-unsubscribed rule, then cancels once it is back on', async () => {
    const { sent, webhookSender } = countingSender();
    const held = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [dueEvent()],
      rules: [{ ...unsubscribedRule, enabled: false }],
      asOf: AS_OF,
      webhookSender,
    });
    assert.equal(held.held_count, 1);
    assert.equal(held.processed[0].status, NOTIFICATION_RULE_HELD_STATUS);
    const resumed = await processDueNotificationRetryBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [dueEvent()],
      rules: [unsubscribedRule],
      asOf: AS_OF,
      webhookSender,
    });
    assert.equal(resumed.cancelled_count, 1);
    assert.equal(sent.length, 0);
  });

  it('DLQ redrive cancels a row whose trigger the rule dropped, sending nothing', async () => {
    const { sent, webhookSender } = countingSender();
    const batch = await processNotificationDlqRedriveBatch({
      deliveryMode: WEBHOOK_DELIVERY_MODE,
      events: [dlqEvent()],
      rules: [unsubscribedRule],
      attemptIds: ['natt_dlq_1'],
      now: AS_OF,
      webhookSender,
    });
    assert.equal(sent.length, 0);
    assert.equal(batch.cancelled_count, 1);
    assert.equal(batch.requeued_count, 0, 'an unsubscribed cancellation is not a requeue');
    assert.equal(batch.processed[0].delivery_record.status, NOTIFICATION_RULE_UNSUBSCRIBED_STATUS);
  });
});
