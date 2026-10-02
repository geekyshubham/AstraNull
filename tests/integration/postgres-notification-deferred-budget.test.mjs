import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import { createReportRepository } from '../../src/persistence/postgres/reportRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';
import {
  OUTBOX_PENDING_REASON,
  createPostgresNotificationServices,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import { registerPostgresNotificationReconciliation } from '../../src/persistence/postgres/notificationReconciliation.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

/**
 * Review follow-ups:
 * - R02 deferred-budget starvation: outbox rows awaiting a first send on a channel the tick cannot
 *   deliver must not consume page slots / the work budget and starve due work behind them.
 * - R03 mode finalization: a metadata-only scheduler's reconciliation must not finalize an owed
 *   provider send as metadata-only; a provider-capable tick must still deliver it exactly once.
 * Mocked senders only; no live provider traffic.
 */

const TENANT = 'ten_notify_deferred_budget';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const SYSTEM = { tenantId: TENANT, userId: 'notification-retry-scheduler', role: 'system' };
const minutesFromNow = (minutes) => new Date(Date.now() + minutes * 60_000).toISOString();
const pause = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms));

async function withHarness(t, fn) {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) {
    t.skip(availability.reason);
    return;
  }
  await withEphemeralPostgres(async (pool) => {
    await withTenantContext(pool, TENANT, async (client) => {
      await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'deferred budget tenant')`, [TENANT]);
    });
    await fn(pool);
  });
}

/** A durable pending attempt whose in-process job was lost (e.g. process restart). */
async function insertStrandedAttempt(pool, {
  eventId, ruleId, channel, minutesAgo, reason = OUTBOX_PENDING_REASON, attemptNumber = 0,
}) {
  const createdAt = minutesFromNow(-minutesAgo - 5);
  const dueAt = minutesFromNow(-minutesAgo);
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO notification_events (id, tenant_id, trigger, subject, metadata_json, created_at)
       VALUES ($2, $1, 'report.ready', 'stranded', '{}'::jsonb, $3::timestamptz)`,
      [TENANT, eventId, createdAt],
    );
    await client.query(
      `INSERT INTO notification_delivery_attempts (
         id, tenant_id, notification_event_id, rule_id, channel, destination_preview, status, reason,
         attempt_number, max_attempts, next_retry_at, exhausted, created_at, attempted_at
       ) VALUES ($2 || '_att', $1, $2, $3, $4, $4 || ':example.invalid', 'provider_retry_scheduled', $5,
                 $6, 3, $7::timestamptz, FALSE, $8::timestamptz, NULL)`,
      [TENANT, eventId, ruleId, channel, reason, attemptNumber, dueAt, createdAt],
    );
  });
  return `${eventId}_att`;
}

async function attemptsFor(pool, eventId) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT id, status, reason, attempt_number, superseded_at, claimed_by
       FROM notification_delivery_attempts
       WHERE tenant_id = $1 AND notification_event_id = $2
       ORDER BY created_at, COALESCE(attempt_number, 0), id`,
      [TENANT, eventId],
    );
    return rows;
  });
}

describe('deferred outbox rows never consume the recovery work budget (R02 follow-up)', () => {
  it('a webhook tick reaches a due webhook attempt queued behind more stranded email rows than its budget', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const sends = [];
      const webhookSender = async (_destination, body) => {
        sends.push(body.event_id);
        return { ok: true, status: 202 };
      };
      const notifications = createPostgresNotificationServices(
        { notifications: createNotificationRepository(pool), audit: createAuditRepository(pool) },
        { deliveryMode: 'webhook,email', webhookSender },
      );
      const emailRule = await notifications.createNotificationRule(CTX, {
        channel: 'email', destination: 'ops@example.invalid', triggers: ['report.ready'],
      });
      const webhookRule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook', destination: 'https://hooks.example.invalid/deferred', triggers: ['report.ready'],
      });
      // Delivery mode later narrowed to webhook: these email rows are stranded ahead in due order.
      for (let i = 0; i < 6; i += 1) {
        await insertStrandedAttempt(pool, {
          eventId: `nevt_email_${i}`, ruleId: emailRule.id, channel: 'email', minutesAgo: 60 - i,
        });
      }
      await insertStrandedAttempt(pool, {
        eventId: 'nevt_webhook_due', ruleId: webhookRule.id, channel: 'webhook', minutesAgo: 25,
      });

      const tick = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, maxItems: 5, pageSize: 2,
      });
      assert.equal(tick.deferred_inactive_channel_count, 6, 'stranded email rows are still reported');
      assert.equal(tick.due_count, 1, 'only deliverable work counts as due');
      assert.equal(tick.budget_exhausted, false);
      assert.equal(tick.network_sends_performed, 1);
      assert.deepEqual(sends, ['nevt_webhook_due']);
      assert.deepEqual(
        (await attemptsFor(pool, 'nevt_webhook_due')).map((r) => r.status),
        ['provider_retry_scheduled', 'delivered_provider'],
      );

      // Email rows are untouched: never claimed, never finalized, still pending for a capable tick.
      for (let i = 0; i < 6; i += 1) {
        const rows = await attemptsFor(pool, `nevt_email_${i}`);
        assert.equal(rows.length, 1);
        assert.equal(rows[0].reason, OUTBOX_PENDING_REASON);
        assert.equal(rows[0].superseded_at, null);
        assert.equal(rows[0].claimed_by, null);
      }

      const again = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, maxItems: 5,
      });
      assert.equal(again.due_count, 0);
      assert.equal(again.deferred_inactive_channel_count, 6);
      assert.equal(sends.length, 1, 'exactly one send');
    });
  });

  it('a metadata-only tick progresses a real retry queued behind more deferred outbox rows than its budget', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const sends = [];
      const webhookSender = async (_destination, body) => {
        sends.push(body.event_id);
        return { ok: true, status: 202 };
      };
      const notifications = createPostgresNotificationServices(
        { notifications: createNotificationRepository(pool), audit: createAuditRepository(pool) },
        { deliveryMode: 'webhook', webhookSender },
      );
      const ruleA = await notifications.createNotificationRule(CTX, {
        channel: 'webhook', destination: 'https://hooks.example.invalid/a', triggers: ['report.ready'],
      });
      const ruleB = await notifications.createNotificationRule(CTX, {
        channel: 'webhook', destination: 'https://hooks.example.invalid/b', triggers: ['report.ready'],
      });
      for (let i = 0; i < 4; i += 1) {
        await insertStrandedAttempt(pool, {
          eventId: `nevt_pending_${i}`, ruleId: ruleA.id, channel: 'webhook', minutesAgo: 50 - i,
        });
      }
      await insertStrandedAttempt(pool, {
        eventId: 'nevt_retry', ruleId: ruleB.id, channel: 'webhook', minutesAgo: 10,
        reason: 'provider_http_503', attemptNumber: 1,
      });

      const tick = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'metadata_only', maxItems: 3,
      });
      assert.equal(tick.deferred_inactive_channel_count, 4);
      assert.equal(tick.budget_exhausted, false);
      assert.equal(tick.network_sends_performed, 0);
      assert.deepEqual(tick.processed.map((p) => p.event_id), ['nevt_retry'], 'retry behind the deferred rows is reached');
      const retryRows = await attemptsFor(pool, 'nevt_retry');
      assert.equal(retryRows.length, 2);
      assert.notEqual(retryRows[0].superseded_at, null, 'the due retry was progressed');
      for (let i = 0; i < 4; i += 1) {
        assert.equal((await attemptsFor(pool, `nevt_pending_${i}`)).length, 1, 'deferred rows untouched');
      }

      const dryRun = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'metadata_only', maxItems: 3, dryRun: true,
      });
      assert.equal(dryRun.deferred_inactive_channel_count, 4);
      assert.equal(sends.length, 0);
    });
  });
});

describe('reconciliation on a metadata-only scheduler never finalizes an owed provider send (R03 follow-up)', () => {
  it('keeps the reconciled webhook attempt pending; the webhook-mode API tick sends it exactly once', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const sends = [];
      const webhookSender = async (_destination, body) => {
        sends.push(body.event_id);
        return { ok: true, status: 202 };
      };
      const audit = createAuditRepository(pool);
      // Service A: the API process (webhook mode).
      const api = createPostgresNotificationServices(
        { notifications: createNotificationRepository(pool), audit },
        { deliveryMode: 'webhook', webhookSender },
      );
      await api.createNotificationRule(CTX, {
        channel: 'webhook', destination: 'https://hooks.example.invalid/reconcile-mode', triggers: ['report.ready'],
      });
      await api.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      await pause();
      // Crash case: the report commits, the emitter never runs.
      const { reports: crashedReports } = createPostgresReportServices({
        reports: createReportRepository(pool),
        validationEvidence: createValidationEvidenceRepository(pool),
        audit,
      });
      await crashedReports.createReport(CTX, { title: 'Owed webhook, mixed modes' });

      // Service B: the scheduler process at its default metadata-only mode, hosting reconciliation.
      const scheduler = createPostgresNotificationServices(
        { notifications: createNotificationRepository(pool), audit },
        { deliveryMode: 'metadata_only' },
      );
      registerPostgresNotificationReconciliation({ pool, notifications: scheduler, audit });

      const schedulerTick = await scheduler.processDueNotificationRetries(SYSTEM, { asOf: minutesFromNow(5) });
      assert.equal(schedulerTick.reconciliation.reconciled_count, 1);
      assert.equal(schedulerTick.network_sends_performed, 0);
      assert.equal(schedulerTick.deferred_inactive_channel_count, 1, 'the webhook send is deferred, not finalized');

      const eventId = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(`SELECT id FROM notification_events WHERE tenant_id = $1`, [TENANT]);
        assert.equal(rows.length, 1);
        return rows[0].id;
      });
      const pending = await attemptsFor(pool, eventId);
      assert.equal(pending.some((a) => a.status === 'queued_provider_not_configured'), false);
      const webhookPending = pending.filter((a) => a.status === 'provider_retry_scheduled');
      assert.equal(webhookPending.length, 1);
      assert.equal(webhookPending[0].reason, OUTBOX_PENDING_REASON);
      assert.equal(webhookPending[0].claimed_by, null);
      assert.ok(pending.some((a) => a.status === 'delivered_in_app'), 'in-app is still final at enqueue');

      // Repeated metadata-only ticks keep it pending and re-reconcile nothing.
      const schedulerTick2 = await scheduler.processDueNotificationRetries(SYSTEM, { asOf: minutesFromNow(10) });
      assert.equal(schedulerTick2.reconciliation.reconciled_count, 0);
      assert.equal(schedulerTick2.deferred_inactive_channel_count, 1);

      const apiTick = await api.processDueNotificationRetries(SYSTEM, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(30),
      });
      assert.equal(apiTick.network_sends_performed, 1);
      assert.deepEqual(sends, [eventId]);
      const after = await attemptsFor(pool, eventId);
      assert.ok(after.some((a) => a.status === 'delivered_provider'));

      const quiet = await api.processDueNotificationRetries(SYSTEM, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(60),
      });
      assert.equal(quiet.due_count, 0);
      assert.equal(sends.length, 1, 'exactly one send');
    });
  });
});
