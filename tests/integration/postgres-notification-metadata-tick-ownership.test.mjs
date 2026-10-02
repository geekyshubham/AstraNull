import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import {
  OUTBOX_PENDING_REASON,
  createPostgresNotificationServices,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_notify_meta_tick';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const minutesFromNow = (minutes) => new Date(Date.now() + minutes * 60_000).toISOString();

async function seed(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'metadata tick tenant')`, [TENANT]);
  });
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

describe('metadata-only retry ticks never take ownership of pending outbox sends (R04)', () => {
  it('a future as_of metadata-only tick leaves a queued outbox attempt for the worker, which sends it once', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      let release;
      const stalled = new Promise((resolve) => { release = resolve; });
      const sends = [];
      const webhookSender = async (_destination, body) => {
        sends.push(body.event_id);
        if (sends.length === 1) await stalled;
        return { ok: true, status: 202 };
      };
      const notifications = createPostgresNotificationServices(
        { notifications: createNotificationRepository(pool), audit: createAuditRepository(pool) },
        { deliveryMode: 'webhook', webhookSender, outboxConcurrency: 1 },
      );
      await notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/meta-tick',
        triggers: ['report.ready'],
      });

      const a = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready', subject: 'A', metadata: { report_id: 'rpt_meta_a' },
        dedupeKey: 'report.ready:report:rpt_meta_a',
      });
      const b = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready', subject: 'B', metadata: { report_id: 'rpt_meta_b' },
        dedupeKey: 'report.ready:report:rpt_meta_b',
      });
      for (let i = 0; i < 200 && sends.length === 0; i += 1) await new Promise((r) => setTimeout(r, 10));
      assert.deepEqual(sends, [a.event.id], 'worker is mid-send on A; B is still queued');

      // Metadata-only ticks (the HTTP route forces this mode) with caller-supplied future as_of.
      for (const minutes of [30, 60, 90]) {
        const tick = await notifications.processDueNotificationRetries(CTX, {
          deliveryMode: 'metadata_only',
          asOf: minutesFromNow(minutes),
        });
        assert.equal(tick.network_sends_performed, 0);
        assert.equal(tick.processed.length, 0, 'no pending outbox attempt is progressed');
        assert.equal(tick.claim_lost_count, 0);
        assert.equal(tick.deferred_inactive_channel_count, 1, 'B is deferred (A is leased by the worker)');
        assert.equal(tick.in_flight_count, 1);
      }
      const bBefore = await attemptsFor(pool, b.event.id);
      assert.equal(bBefore.length, 1);
      assert.equal(bBefore[0].reason, OUTBOX_PENDING_REASON);
      assert.equal(bBefore[0].superseded_at, null);
      assert.equal(bBefore[0].claimed_by, null, 'metadata-only tick never claimed B');

      release();
      await notifications.drainNotificationOutbox();
      assert.deepEqual(sends, [a.event.id, b.event.id], 'worker still sends B');

      const bAfter = await attemptsFor(pool, b.event.id);
      assert.deepEqual(bAfter.map((r) => r.status), ['provider_retry_scheduled', 'delivered_provider']);
      assert.equal(bAfter.some((r) => r.reason === 'retry_planned_metadata_only'), false);

      const quiet = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(120),
      });
      assert.equal(quiet.due_count, 0);
      assert.equal(sends.length, 2, 'exactly one send per event');
    });
  });

  it('a stranded pending outbox attempt survives metadata-only ticks and is recovered by a webhook tick', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const sends = [];
      const webhookSender = async (_destination, body) => {
        sends.push(body.event_id);
        return { ok: true, status: 202 };
      };
      const notifications = createPostgresNotificationServices(
        { notifications: createNotificationRepository(pool), audit: createAuditRepository(pool) },
        { deliveryMode: 'webhook', webhookSender },
      );
      const rule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/meta-tick-stranded',
        triggers: ['report.ready'],
      });
      // A pending outbox attempt whose in-process job was lost (process restart): durable row only.
      const enqueued = { event: { id: 'nevt_meta_stranded' } };
      const createdAt = minutesFromNow(-1);
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `INSERT INTO notification_events (id, tenant_id, trigger, subject, metadata_json, created_at)
           VALUES ($2, $1, 'report.ready', 'stranded', '{"report_id":"rpt_meta_s"}'::jsonb, $3::timestamptz)`,
          [TENANT, enqueued.event.id, createdAt],
        );
        await client.query(
          `INSERT INTO notification_delivery_attempts (
             id, tenant_id, notification_event_id, rule_id, channel, destination_preview, status, reason,
             attempt_number, max_attempts, next_retry_at, exhausted, created_at, attempted_at
           ) VALUES ($2 || '_att', $1, $2, $3, 'webhook', 'webhook:hooks.example.invalid',
                     'provider_retry_scheduled', $4, 0, 3, $5::timestamptz + interval '5 minutes', FALSE,
                     $5::timestamptz, NULL)`,
          [TENANT, enqueued.event.id, rule.id, OUTBOX_PENDING_REASON, createdAt],
        );
      });

      for (const minutes of [10, 20, 30, 40]) {
        const tick = await notifications.processDueNotificationRetries(CTX, {
          deliveryMode: 'metadata_only', asOf: minutesFromNow(minutes),
        });
        assert.equal(tick.deferred_inactive_channel_count, 1);
        assert.equal(tick.processed.length, 0);
      }
      const dryRun = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'metadata_only', asOf: minutesFromNow(50), dryRun: true,
      });
      assert.equal(dryRun.processed.length, 0, 'dry run reports nothing it would progress');
      assert.equal(dryRun.deferred_inactive_channel_count, 1);
      assert.equal((await attemptsFor(pool, enqueued.event.id)).length, 1, 'ledger untouched');

      const recovered = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(10),
      });
      assert.equal(recovered.network_sends_performed, 1);
      assert.deepEqual(sends, [enqueued.event.id]);
      const rows = await attemptsFor(pool, enqueued.event.id);
      assert.deepEqual(rows.map((r) => r.status), ['provider_retry_scheduled', 'delivered_provider']);
    });
  });
});
