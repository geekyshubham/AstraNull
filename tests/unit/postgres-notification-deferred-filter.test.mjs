import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import { createPostgresNotificationServices } from '../../src/persistence/postgres/notificationServiceAdapters.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';

function createRecordingPool(rows = []) {
  const queries = [];
  const client = {
    async query(text, params) {
      queries.push({ text: String(text), params });
      return { rows: /^\s*SELECT/i.test(String(text)) && !/set_config/i.test(String(text)) ? rows : [] };
    },
    release() {},
  };
  return { queries, async connect() { return client; } };
}

describe('deferred outbox rows are filtered in SQL (R02 budget follow-up)', () => {
  it('listDueDeliveryAttempts excludes outbox_pending_delivery rows outside activeChannels', async () => {
    const pool = createRecordingPool();
    const repo = createNotificationRepository(pool);
    await repo.listDueDeliveryAttempts(CTX, { asOf: FIXED_NOW, limit: 10, activeChannels: ['webhook'] });
    const select = pool.queries.find((q) => /FROM notification_delivery_attempts a/.test(q.text));
    // Only a still-deliverable pending send is excluded; a removed or unsubscribed rule's
    // cancellation needs no channel, so it stays in the due list for any tick to close.
    assert.match(select.text, /AND NOT \(a\.reason = 'outbox_pending_delivery'/);
    assert.match(select.text, /AND NOT \(COALESCE\(a\.channel, ''\) = ANY\(\$6::text\[\]\)\)/);
    assert.match(select.text, /AND r\.id IS NOT NULL AND r\.deleted_at IS NULL AND r\.enabled IS NOT FALSE/);
    assert.match(select.text, /AND r\.triggers_json IS NOT NULL AND r\.triggers_json @> to_jsonb\(e\.trigger\)\)/);
    assert.deepEqual(select.params, [CTX.tenantId, FIXED_NOW, null, null, 10, ['webhook']]);
  });

  it('listDueDeliveryAttempts keeps the unfiltered query when activeChannels is absent', async () => {
    const pool = createRecordingPool();
    const repo = createNotificationRepository(pool);
    await repo.listDueDeliveryAttempts(CTX, { asOf: FIXED_NOW, limit: 10 });
    const select = pool.queries.find((q) => /FROM notification_delivery_attempts a/.test(q.text));
    assert.doesNotMatch(select.text, /outbox_pending_delivery/);
    assert.equal(select.params.length, 5);
  });

  it('summarizePendingDeliveryAttempts counts deferred rows for the same channels', async () => {
    const pool = createRecordingPool();
    const repo = createNotificationRepository(pool);
    const summary = await repo.summarizePendingDeliveryAttempts(CTX, { asOf: FIXED_NOW, activeChannels: [] });
    const select = pool.queries.find((q) => /AS deferred_inactive_channel/.test(q.text));
    assert.match(select.text, /ANY\(\$3::text\[\]\)/);
    assert.deepEqual(select.params, [CTX.tenantId, FIXED_NOW, []]);
    assert.equal(summary.deferred_inactive_channel, 0);
  });

  it('the service never charges unfiltered deferred rows to the work budget', async () => {
    const deferred = (i) => ({
      event: { id: `nevt_d${i}`, trigger: 'report.ready', subject: 's', metadata: {}, created_at: FIXED_NOW },
      attempt: {
        id: `natt_d${i}`, rule_id: 'nrule_email', channel: 'email', status: 'provider_retry_scheduled',
        reason: 'outbox_pending_delivery', attempt_number: 0, max_attempts: 3,
        next_retry_at: `2026-06-01T10:0${i}:00.000Z`,
      },
    });
    const retry = {
      event: { id: 'nevt_r', trigger: 'report.ready', subject: 's', metadata: {}, created_at: FIXED_NOW },
      attempt: {
        id: 'natt_r', rule_id: 'nrule_hook', channel: 'webhook', status: 'provider_retry_scheduled',
        reason: 'provider_http_503', attempt_number: 1, max_attempts: 3, next_retry_at: '2026-06-01T11:00:00.000Z',
      },
    };
    // A repository that ignores activeChannels: deferred rows lead every page. The live rule is
    // enabled and still subscribed, so the service defers it (gate `deliver`) after resolving it.
    const liveRule = { id: 'nrule_email', enabled: true, deleted_at: null, triggers: ['report.ready'] };
    const ruleStates = [];
    const all = [deferred(0), deferred(1), deferred(2), retry];
    const listCalls = [];
    const claims = [];
    const notifications = createPostgresNotificationServices({
      notifications: {
        listNotificationRules: async () => [],
        getNotificationRuleDeliveryState: async (_c, ruleId) => {
          ruleStates.push(ruleId);
          return ruleId === 'nrule_email' ? { ...liveRule } : null;
        },
        listNotificationEvents: async () => [],
        createNotificationRule: async () => null,
        appendNotificationEvent: async () => ({}),
        appendDeliveryAttempts: async () => [],
        listDueDeliveryAttempts: async (_c, { limit, after, activeChannels }) => {
          listCalls.push(activeChannels);
          const start = after ? all.findIndex((r) => r.attempt.id === after.id) + 1 : 0;
          return all.slice(start, start + limit);
        },
        summarizePendingDeliveryAttempts: async () => ({ scheduled_not_due: 0, held_due: 0, in_flight: 0 }),
        claimDeliveryAttempt: async (_c, claim) => { claims.push(claim.attemptId); return null; },
        completeDeliveryAttemptClaim: async () => ({ completed: false }),
        releaseDeliveryAttemptClaim: async () => ({ released: false }),
      },
      audit: { appendAuditEvent: async () => ({}) },
    });
    const result = await notifications.processDueNotificationRetries(CTX, {
      asOf: FIXED_NOW, deliveryMode: 'webhook', maxItems: 2, pageSize: 2,
    });
    assert.deepEqual(listCalls[0], ['webhook']);
    assert.deepEqual(ruleStates, ['nrule_email', 'nrule_email', 'nrule_email'], 'each deferred row re-gates on the live rule');
    assert.deepEqual(claims, ['natt_r'], 'the retry behind the deferred rows is reached');
    assert.equal(result.deferred_inactive_channel_count, 3);
    assert.equal(result.due_count, 1);
    assert.equal(result.budget_exhausted, false);
  });

  it('a metadata-only tick closes deferred rows of removed or unsubscribed rules instead of deferring them', async () => {
    const deferredRow = (i, ruleId, rule) => ({
      event: { id: `nevt_d${i}`, trigger: 'report.ready', subject: 's', metadata: {}, created_at: FIXED_NOW },
      attempt: {
        id: `natt_d${i}`, rule_id: ruleId, channel: 'email', status: 'provider_retry_scheduled',
        reason: 'outbox_pending_delivery', attempt_number: 0, max_attempts: 3,
        next_retry_at: `2026-06-01T10:0${i}:00.000Z`,
      },
      rule,
    });
    const retry = {
      event: { id: 'nevt_r', trigger: 'report.ready', subject: 's', metadata: {}, created_at: FIXED_NOW },
      attempt: {
        id: 'natt_r', rule_id: 'nrule_hook', channel: 'webhook', status: 'provider_retry_scheduled',
        reason: 'provider_http_503', attempt_number: 1, max_attempts: 3, next_retry_at: '2026-06-01T11:00:00.000Z',
      },
    };
    const removed = { id: 'nrule_email', enabled: true, deleted_at: FIXED_NOW, triggers: ['report.ready'] };
    const unsubscribed = { id: 'nrule_sms', enabled: true, deleted_at: null, triggers: ['safe_test.completed'] };
    // A repository that ignores activeChannels, and whose deferred head rows belong to a removed
    // rule and to a rule that unsubscribed from the trigger: cancellation needs no email channel,
    // so this webhook-only tick must claim and close them rather than leave them pending forever.
    const all = [deferredRow(0, 'nrule_email', removed), deferredRow(1, 'nrule_sms', unsubscribed), retry];
    const claims = [];
    const notifications = createPostgresNotificationServices({
      notifications: {
        listNotificationRules: async () => [],
        getNotificationRuleDeliveryState: async (_c, ruleId) => {
          if (ruleId === 'nrule_email') return { ...removed };
          if (ruleId === 'nrule_sms') return { ...unsubscribed };
          return null;
        },
        listNotificationEvents: async () => [],
        createNotificationRule: async () => null,
        appendNotificationEvent: async () => ({}),
        appendDeliveryAttempts: async () => [],
        listDueDeliveryAttempts: async (_c, { limit, after }) => {
          const start = after ? all.findIndex((r) => r.attempt.id === after.id) + 1 : 0;
          return all.slice(start, start + limit);
        },
        summarizePendingDeliveryAttempts: async () => ({ scheduled_not_due: 0, held_due: 0, in_flight: 0 }),
        claimDeliveryAttempt: async (_c, claim) => { claims.push(claim.attemptId); return null; },
        completeDeliveryAttemptClaim: async () => ({ completed: false }),
        releaseDeliveryAttemptClaim: async () => ({ released: false }),
      },
      audit: { appendAuditEvent: async () => ({}) },
    });
    const result = await notifications.processDueNotificationRetries(CTX, {
      asOf: FIXED_NOW, deliveryMode: 'webhook', maxItems: 3, pageSize: 3,
    });
    assert.deepEqual(claims, ['natt_d0', 'natt_d1', 'natt_r'], 'cancellation candidates pass through to the claim path');
    assert.equal(result.deferred_inactive_channel_count, 0);
    // All three rows went through the claim path, so the budget of 3 was spent.
    assert.equal(result.budget_exhausted, true);
  });

  it('counts rows deferred by the defensive branch even when the summary already reported deferred rows', async () => {
    const deferred = (i) => ({
      event: { id: `nevt_d${i}`, trigger: 'report.ready', subject: 's', metadata: {}, created_at: FIXED_NOW },
      attempt: {
        id: `natt_d${i}`, rule_id: 'nrule_email', channel: 'email', status: 'provider_retry_scheduled',
        reason: 'outbox_pending_delivery', attempt_number: 0, max_attempts: 3,
        next_retry_at: `2026-06-01T10:0${i}:00.000Z`,
      },
    });
    const liveRule = { id: 'nrule_email', enabled: true, deleted_at: null, triggers: ['report.ready'] };
    const notifications = createPostgresNotificationServices({
      notifications: {
        listNotificationRules: async () => [],
        getNotificationRuleDeliveryState: async () => ({ ...liveRule }),
        listNotificationEvents: async () => [],
        createNotificationRule: async () => null,
        appendNotificationEvent: async () => ({}),
        appendDeliveryAttempts: async () => [],
        // The stub reports a deferred count (SQL filtered some rows) but its list ignores
        // activeChannels: the two deferred rows it returns were missed by the summary (a rule
        // flipped between the two queries) and must still be counted, not vanish.
        listDueDeliveryAttempts: async (_c, { after }) => (after ? [] : [deferred(0), deferred(1)]),
        summarizePendingDeliveryAttempts: async () => ({
          scheduled_not_due: 0, held_due: 0, in_flight: 0, deferred_inactive_channel: 1,
        }),
        claimDeliveryAttempt: async () => null,
        completeDeliveryAttemptClaim: async () => ({ completed: false }),
        releaseDeliveryAttemptClaim: async () => ({ released: false }),
      },
      audit: { appendAuditEvent: async () => ({}) },
    });
    const result = await notifications.processDueNotificationRetries(CTX, {
      asOf: FIXED_NOW, deliveryMode: 'webhook', maxItems: 10, pageSize: 10,
    });
    assert.equal(result.deferred_inactive_channel_count, 3, 'summary count 1 + two rows deferred by the defensive branch');
    assert.equal(result.budget_exhausted, false);
  });

  it('a full deferred-scan bound stops the reads without claiming the work budget was spent', async () => {
    const deferred = (i) => ({
      event: { id: `nevt_d${i}`, trigger: 'report.ready', subject: 's', metadata: {}, created_at: FIXED_NOW },
      attempt: {
        id: `natt_d${i}`, rule_id: 'nrule_email', channel: 'email', status: 'provider_retry_scheduled',
        reason: 'outbox_pending_delivery', attempt_number: 0, max_attempts: 3,
        next_retry_at: `2026-06-01T10:0${i}:00.000Z`,
      },
    });
    const liveRule = { id: 'nrule_email', enabled: true, deleted_at: null, triggers: ['report.ready'] };
    const notifications = createPostgresNotificationServices({
      notifications: {
        listNotificationRules: async () => [],
        getNotificationRuleDeliveryState: async () => ({ ...liveRule }),
        listNotificationEvents: async () => [],
        createNotificationRule: async () => null,
        appendNotificationEvent: async () => ({}),
        appendDeliveryAttempts: async () => [],
        listDueDeliveryAttempts: async (_c, { after }) => (after ? [] : [deferred(0), deferred(1), deferred(2)]),
        summarizePendingDeliveryAttempts: async () => ({ scheduled_not_due: 0, held_due: 0, in_flight: 0 }),
        claimDeliveryAttempt: async () => null,
        completeDeliveryAttemptClaim: async () => ({ completed: false }),
        releaseDeliveryAttemptClaim: async () => ({ released: false }),
      },
      audit: { appendAuditEvent: async () => ({}) },
    });
    const result = await notifications.processDueNotificationRetries(CTX, {
      asOf: FIXED_NOW, deliveryMode: 'webhook', maxItems: 10, pageSize: 10, maxDeferredScan: 1,
    });
    assert.equal(result.deferred_inactive_channel_count, 1, 'the scan stopped at the bound');
    assert.equal(result.budget_exhausted, false, 'the work budget was not spent');
  });

  it('a dry run reports a held row the way the real run would', async () => {
    const retry = {
      event: { id: 'nevt_r', trigger: 'report.ready', subject: 's', metadata: {}, created_at: FIXED_NOW },
      attempt: {
        id: 'natt_r', rule_id: 'nrule_off', channel: 'webhook', status: 'provider_retry_scheduled',
        reason: 'provider_http_503', attempt_number: 1, max_attempts: 3, next_retry_at: '2026-06-01T11:00:00.000Z',
      },
    };
    // A stub whose list SQL does not filter held rows: the row appears in the page and the live
    // gate says hold. The dry run must report the same held outcome the real run records.
    const notifications = createPostgresNotificationServices({
      notifications: {
        listNotificationRules: async () => [],
        getNotificationRuleDeliveryState: async () => ({ id: 'nrule_off', enabled: false, deleted_at: null, triggers: ['report.ready'] }),
        listNotificationEvents: async () => [],
        createNotificationRule: async () => null,
        appendNotificationEvent: async () => ({}),
        appendDeliveryAttempts: async () => [],
        listDueDeliveryAttempts: async (_c, { after }) => (after ? [] : [retry]),
        summarizePendingDeliveryAttempts: async () => ({ scheduled_not_due: 0, held_due: 0, in_flight: 0 }),
        claimDeliveryAttempt: async () => ({ ...retry.attempt }),
        completeDeliveryAttemptClaim: async () => ({ completed: true }),
        releaseDeliveryAttemptClaim: async () => ({ released: true }),
      },
      audit: { appendAuditEvent: async () => ({}) },
    });
    const dry = await notifications.processDueNotificationRetries(CTX, {
      asOf: FIXED_NOW, deliveryMode: 'webhook', dryRun: true, pageSize: 10,
    });
    assert.equal(dry.held_count, 1);
    assert.equal(dry.processed[0].status, 'held_rule_disabled');

    const real = await notifications.processDueNotificationRetries(CTX, {
      asOf: FIXED_NOW, deliveryMode: 'webhook', pageSize: 10,
    });
    assert.equal(real.held_count, 1);
  });
});
