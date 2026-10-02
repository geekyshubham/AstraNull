import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createPostgresNotificationServices } from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

// R01 follow-up: a rule edit that drops a trigger must stop queued work for that trigger on every
// claimed send path (deferred recovery, in-process outbox worker, DLQ redrive).
const TENANT = 'ten_notify_unsub';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const START = '2026-01-01T00:00:00.000Z';

async function attemptsFor(pool, eventId) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT id, status, reason, attempt_number, attempted_at FROM notification_delivery_attempts
       WHERE tenant_id = $1 AND notification_event_id = $2
       ORDER BY created_at, COALESCE(attempt_number, 0), id`,
      [TENANT, eventId],
    );
    return rows;
  });
}

async function auditsFor(pool, resourceId) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT action FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2`,
      [TENANT, resourceId],
    );
    return rows.map((r) => r.action);
  });
}

describe('postgres notification delivery after a rule drops a trigger (R01)', () => {
  it('cancels unsubscribed outbox, recovery, and DLQ work with zero sends; other triggers still deliver', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, TENANT, (client) =>
        client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'trigger unsubscribe tenant')`, [TENANT]));

      const notificationRepo = createNotificationRepository(pool);
      const audit = createAuditRepository(pool);
      const clock = new Date(START);
      const sends = [];
      let failSends = false;
      const webhookSender = async (_destination, body) => {
        sends.push(body.trigger);
        return failSends ? { ok: false, error: 'webhook_http_error' } : { ok: true, status: 202 };
      };
      const notifications = createPostgresNotificationServices(
        { notifications: notificationRepo, audit },
        { deliveryMode: 'webhook', webhookSender, now: () => clock },
      );
      const later = (minutes) => new Date(clock.getTime() + minutes * 60_000).toISOString();
      const retry = (asOf) => notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook',
        webhookSender,
        asOf,
      });
      const subscribeBoth = () => notifications.updateNotificationRule(CTX, rule.id, {
        triggers: ['report.ready', 'safe_test.completed'],
      });
      const unsubscribeReport = () => notifications.updateNotificationRule(CTX, rule.id, {
        triggers: ['safe_test.completed'],
      });

      const rule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/unsub',
        triggers: ['report.ready', 'safe_test.completed'],
      });

      // 1. Deferred recovery path (the review repro): enqueue -> drop trigger -> recovery tick.
      const deferred = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'deferred',
        metadata: { report_id: 'rpt_unsub_1' },
        dedupeKey: 'report.ready:report:rpt_unsub_1',
        deferToRecovery: true,
        recoveryAsOf: later(1),
      });
      assert.equal(deferred.inserted, true);
      await unsubscribeReport();
      const tick = await retry(later(1));
      assert.deepEqual(sends, [], 'recovery must not send for a dropped trigger');
      assert.equal(tick.network_sends_performed, 0);
      assert.equal(tick.cancelled_count, 1);
      assert.equal(tick.held_count, 0);
      let attempts = await attemptsFor(pool, deferred.event.id);
      let latest = attempts.at(-1);
      assert.equal(latest.status, 'cancelled_rule_unsubscribed');
      assert.equal(latest.reason, 'rule_unsubscribed');
      assert.equal(latest.attempted_at, null);
      assert.deepEqual(await auditsFor(pool, latest.id), ['notification.delivery_attempt_recorded']);
      // Terminal: re-subscribing does not resurrect it, later ticks find nothing due.
      await subscribeBoth();
      const quiet = await retry(later(30));
      assert.equal(quiet.due_count ?? 0, 0);
      assert.deepEqual(sends, []);

      // 2. In-process outbox worker path: enqueue -> drop trigger -> drain. The worker's pre-send
      // rule read waits until the edit has committed, so the race is deterministic.
      const releaseBarrier = (() => {
        const real = notificationRepo.getNotificationRuleDeliveryState;
        let release;
        const barrier = new Promise((resolve) => { release = resolve; });
        notificationRepo.getNotificationRuleDeliveryState = async (...args) => {
          await barrier;
          return real(...args);
        };
        return () => { release(); notificationRepo.getNotificationRuleDeliveryState = real; };
      })();
      const outboxed = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'outbox',
        metadata: { report_id: 'rpt_unsub_2' },
        dedupeKey: 'report.ready:report:rpt_unsub_2',
      });
      assert.equal(outboxed.inserted, true);
      await unsubscribeReport();
      releaseBarrier();
      await notifications.drainNotificationOutbox();
      assert.deepEqual(sends, [], 'outbox worker must not send for a dropped trigger');
      latest = (await attemptsFor(pool, outboxed.event.id)).at(-1);
      assert.equal(latest.status, 'cancelled_rule_unsubscribed');

      // A trigger the rule still subscribes to keeps delivering.
      const kept = await notifications.enqueueNotification(CTX, {
        trigger: 'safe_test.completed',
        subject: 'kept',
        metadata: { test_run_id: 'run_unsub' },
        dedupeKey: 'safe_test.completed:run:run_unsub',
      });
      await notifications.drainNotificationOutbox();
      assert.deepEqual(sends, ['safe_test.completed']);
      assert.equal((await attemptsFor(pool, kept.event.id)).at(-1).status, 'delivered_provider');
      sends.length = 0;

      // 3. DLQ redrive path: enqueue/fail into the DLQ -> drop trigger -> redrive.
      await subscribeBoth();
      failSends = true;
      const failing = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'dlq',
        metadata: { report_id: 'rpt_unsub_3' },
        dedupeKey: 'report.ready:report:rpt_unsub_3',
      });
      await notifications.drainNotificationOutbox();
      await retry(later(40));
      await retry(later(50));
      latest = (await attemptsFor(pool, failing.event.id)).at(-1);
      assert.equal(latest.status, 'provider_failed_dlq');
      const dlqAttemptId = latest.id;
      sends.length = 0;
      failSends = false;
      await unsubscribeReport();

      const prevEnv = process.env.NODE_ENV;
      const prevMode = process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
      process.env.NODE_ENV = 'staging';
      process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = 'webhook';
      try {
        const redrive = await notifications.redriveNotificationDlq(CTX, {
          attemptIds: [dlqAttemptId],
          forceMetadataOnly: false,
          webhookSender,
          now: later(60),
        });
        assert.equal(redrive.delivery_mode, 'webhook', 'redrive ran in provider mode');
        assert.equal(redrive.network_sends_performed, 0);
        assert.equal(redrive.requeued_count, 0);
        assert.equal(redrive.cancelled_count, 1);
        assert.deepEqual(sends, [], 'redrive must not send for a dropped trigger');
        latest = (await attemptsFor(pool, failing.event.id)).at(-1);
        assert.equal(latest.status, 'cancelled_rule_unsubscribed');

        // Terminal for redrive too, even after re-subscribing.
        await subscribeBoth();
        const again = await notifications.redriveNotificationDlq(CTX, {
          attemptIds: [dlqAttemptId],
          forceMetadataOnly: false,
          webhookSender,
          now: later(61),
        });
        assert.equal(again.network_sends_performed, 0);
        assert.deepEqual(sends, []);
      } finally {
        process.env.NODE_ENV = prevEnv;
        if (prevMode === undefined) delete process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
        else process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = prevMode;
      }
    });
  });
});

describe('postgres notification lifecycle cancellation in a metadata-only tick (R01 follow-up)', () => {
  it('cancels removed-rule and unsubscribed pending work with zero sends even without provider channels', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, TENANT, (client) =>
        client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'trigger unsubscribe tenant')`, [TENANT]));

      const notificationRepo = createNotificationRepository(pool);
      const audit = createAuditRepository(pool);
      const clock = new Date(START);
      const sends = [];
      const notifications = createPostgresNotificationServices(
        { notifications: notificationRepo, audit },
        { deliveryMode: 'webhook', webhookSender: async (_destination, body) => {
          sends.push(body.trigger);
          return { ok: true, status: 202 };
        }, now: () => clock },
      );
      const later = (minutes) => new Date(clock.getTime() + minutes * 60_000).toISOString();
      // A metadata-only tick has no provider channel at all: the only lifecycle work it can
      // still close is a cancellation, which needs no network I/O.
      const metadataTick = (asOf) => notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'metadata_only',
        asOf,
      });

      // Removed rule: the deferred-inactive-channel filter must not hide the pending attempt
      // from the gate, or a default scheduler leaves it due forever.
      const removedRule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/meta-removed',
        triggers: ['report.ready'],
      });
      const removedEvent = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'meta removed',
        metadata: { report_id: 'rpt_meta_removed' },
        dedupeKey: 'report.ready:report:rpt_meta_removed',
        deferToRecovery: true,
        recoveryAsOf: later(1),
      });
      await notifications.deleteNotificationRule(CTX, removedRule.id);
      const removedTick = await metadataTick(later(1));
      assert.deepEqual(sends, [], 'a metadata-only tick must not send');
      assert.equal(removedTick.network_sends_performed, 0);
      assert.equal(removedTick.cancelled_count, 1, 'the removed-rule attempt is cancelled, not deferred');
      assert.equal(removedTick.deferred_inactive_channel_count, 0);
      const removedLatest = (await attemptsFor(pool, removedEvent.event.id)).at(-1);
      assert.equal(removedLatest.status, 'cancelled_rule_removed');
      assert.equal(removedLatest.attempted_at, null);
      assert.deepEqual(await auditsFor(pool, removedLatest.id), ['notification.delivery_attempt_recorded']);
      const againTick = await metadataTick(later(2));
      assert.equal(againTick.cancelled_count, 0, 'terminal cancellation is not repeated');
      assert.deepEqual(sends, []);

      // Unsubscribed rule: a dropped trigger is the same terminal case without a channel.
      const unsubRule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/meta-unsub',
        triggers: ['report.ready'],
      });
      const unsubEvent = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'meta unsub',
        metadata: { report_id: 'rpt_meta_unsub' },
        dedupeKey: 'report.ready:report:rpt_meta_unsub',
        deferToRecovery: true,
        recoveryAsOf: later(3),
      });
      await notifications.updateNotificationRule(CTX, unsubRule.id, { triggers: ['safe_test.completed'] });
      const unsubTick = await metadataTick(later(3));
      assert.deepEqual(sends, []);
      assert.equal(unsubTick.cancelled_count, 1);
      assert.equal(unsubTick.deferred_inactive_channel_count, 0);
      const unsubLatest = (await attemptsFor(pool, unsubEvent.event.id)).at(-1);
      assert.equal(unsubLatest.status, 'cancelled_rule_unsubscribed');
      assert.deepEqual(await auditsFor(pool, unsubLatest.id), ['notification.delivery_attempt_recorded']);
      assert.deepEqual(sends, []);
    });
  });
});
