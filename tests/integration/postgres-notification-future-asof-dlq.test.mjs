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

// Regression (R02/R04 review "future as_of hides DLQ"): a retry tick run with a future `as_of`
// must not future-date ledger rows, and a superseded row must never outrank the live DLQ row in
// the "latest attempt" checks used by DLQ list / count / held summary / claim.
// Mock senders only; no live provider traffic.

const TENANT = 'ten_notify_future_asof';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const DAY_MS = 24 * 60 * 60_000;

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'future as_of tenant')`, [TENANT]);
  });
}

async function ledgerFor(pool, notificationEventId) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT id, status, attempt_number, created_at, attempted_at, superseded_at
       FROM notification_delivery_attempts
       WHERE tenant_id = $1 AND notification_event_id = $2
       ORDER BY created_at, COALESCE(attempt_number, 0), id`,
      [TENANT, notificationEventId],
    );
    return rows;
  });
}

async function dbNow(pool) {
  const { rows } = await pool.query('SELECT clock_timestamp() AS now');
  return new Date(rows[0].now).getTime();
}

function runtime(pool, webhookSender) {
  const notificationRepo = createNotificationRepository(pool);
  const audit = createAuditRepository(pool);
  const notifications = createPostgresNotificationServices(
    { notifications: notificationRepo, audit },
    { deliveryMode: 'webhook', webhookSender },
  );
  return { notificationRepo, notifications };
}

async function harnessOrSkip(t) {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) {
    t.skip(availability.reason);
    return false;
  }
  return true;
}

const fromNow = (ms) => new Date(Date.now() + ms).toISOString();

describe('postgres notification DLQ vs future as_of ticks', () => {
  it('clamps appended attempt timestamps to the database clock and keeps null attempted_at null', { timeout: 60_000 }, async (t) => {
    if (!(await harnessOrSkip(t))) return;
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const { notificationRepo, notifications } = runtime(pool, async () => ({ ok: true, status: 202 }));
      const rule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook', destination: 'https://hooks.example.invalid/clamp', triggers: ['report.ready'],
      });
      await notificationRepo.appendNotificationEvent(CTX, {
        id: 'nevt_clamp', trigger: 'report.ready', subject: 'clamp', metadata: {}, created_at: fromNow(0),
      });
      const future = fromNow(2 * DAY_MS);
      const past = '2026-01-01T00:00:00.000Z';
      const [futureRow, pastRow] = await notificationRepo.appendDeliveryAttempts(CTX, 'nevt_clamp', [
        {
          id: 'natt_clamp_future', rule_id: rule.id, channel: 'webhook', destination_preview: 'webhook:x',
          status: 'provider_retry_scheduled', reason: 'webhook_http_error', attempt_number: 1, max_attempts: 3,
          next_retry_at: future, created_at: future, attempted_at: future,
        },
        {
          id: 'natt_clamp_past', rule_id: rule.id, channel: 'webhook', destination_preview: 'webhook:x',
          status: 'provider_retry_scheduled', reason: 'outbox_pending_delivery', attempt_number: 0, max_attempts: 3,
          next_retry_at: past, created_at: past, attempted_at: null,
        },
      ]);
      const ceiling = await dbNow(pool);
      assert.ok(new Date(futureRow.created_at).getTime() <= ceiling, 'future created_at is clamped');
      assert.ok(new Date(futureRow.attempted_at).getTime() <= ceiling, 'future attempted_at is clamped');
      assert.equal(futureRow.next_retry_at, new Date(future).toISOString(), 'next_retry_at is not clamped');
      assert.equal(pastRow.created_at, past, 'past created_at is kept');
      assert.equal(pastRow.attempted_at, null, 'null attempted_at stays null');
    });
  });

  it('a superseded later row does not hide the live DLQ row from list, count, held summary, or claim', { timeout: 60_000 }, async (t) => {
    if (!(await harnessOrSkip(t))) return;
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const { notificationRepo, notifications } = runtime(pool, async () => ({ ok: true, status: 202 }));
      const rule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook', destination: 'https://hooks.example.invalid/sup', triggers: ['report.ready'],
      });
      // Legacy/future-dated ledger written directly: a superseded DLQ row dated two days ahead,
      // and the live (unsuperseded) DLQ row created after it in real time.
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `INSERT INTO notification_events (id, tenant_id, trigger, subject, metadata_json, created_at)
           VALUES ('nevt_sup', $1, 'report.ready', 'sup', '{}'::jsonb, clock_timestamp())`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO notification_delivery_attempts (
             id, tenant_id, notification_event_id, rule_id, channel, destination_preview, status, reason,
             attempt_number, max_attempts, exhausted, created_at, attempted_at, superseded_at
           ) VALUES
             ('natt_sup_old', $1, 'nevt_sup', $2, 'webhook', 'webhook:x', 'provider_failed_dlq', 'webhook_http_error',
              3, 3, TRUE, clock_timestamp() + interval '2 days', clock_timestamp() + interval '2 days', clock_timestamp()),
             ('natt_sup_live', $1, 'nevt_sup', $2, 'webhook', 'webhook:x', 'provider_failed_dlq', 'webhook_http_error',
              3, 3, TRUE, clock_timestamp(), clock_timestamp(), NULL)`,
          [TENANT, rule.id],
        );
      });

      const listed = await notificationRepo.listDlqDeliveryAttempts(CTX, {});
      assert.deepEqual(listed.map((r) => r.attempt.id), ['natt_sup_live']);
      assert.equal(await notificationRepo.countDlqDeliveryAttempts(CTX), 1);

      await notifications.updateNotificationRule(CTX, rule.id, { enabled: false });
      const held = await notificationRepo.summarizeHeldDlqDeliveryAttempts(CTX, { attemptIds: ['natt_sup_live'] });
      assert.equal(held.held_count, 1);
      assert.deepEqual(held.held_attempt_ids, ['natt_sup_live']);
      await notifications.updateNotificationRule(CTX, rule.id, { enabled: true });

      const claimed = await notificationRepo.claimDlqDeliveryAttempt(CTX, {
        attemptId: 'natt_sup_live', claimToken: 'tok_test', leaseMs: 30_000,
      });
      assert.equal(claimed?.id, 'natt_sup_live', 'live DLQ row is claimable');

      // A LIVE later attempt still outranks an older DLQ row (redrive must not reclaim it).
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `INSERT INTO notification_delivery_attempts (
             id, tenant_id, notification_event_id, rule_id, channel, destination_preview, status, reason,
             attempt_number, max_attempts, exhausted, created_at
           ) VALUES ('natt_sup_newer', $1, 'nevt_sup', $2, 'webhook', 'webhook:x', 'delivered_provider',
                     'webhook_delivered', 1, 3, FALSE, clock_timestamp() + interval '1 second')`,
          [TENANT, rule.id],
        );
      });
      assert.equal(await notificationRepo.countDlqDeliveryAttempts(CTX), 0);
      assert.deepEqual(await notificationRepo.listDlqDeliveryAttempts(CTX, {}), []);
    });
  });

  it('end to end: future as_of ticks then real-time failure leave a redrivable, counted DLQ row', { timeout: 120_000 }, async (t) => {
    if (!(await harnessOrSkip(t))) return;
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const sends = [];
      const failingSender = async (_destination, body) => {
        sends.push(body.event_id);
        return { ok: false, error: 'webhook_http_error' };
      };
      const { notificationRepo, notifications } = runtime(pool, failingSender);
      await notifications.createNotificationRule(CTX, {
        channel: 'webhook', destination: 'https://hooks.example.invalid/future', triggers: ['report.ready'],
      });

      // 1. Enqueue; the worker's first send fails and attempt 1 is retry-scheduled.
      const enqueued = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'future as_of',
        metadata: { report_id: 'rpt_future' },
        dedupeKey: 'report.ready:report:rpt_future',
      });
      await notifications.drainNotificationOutbox();
      const eventId = enqueued.event.id;

      // 2. Operator ticks with as_of days ahead walk the retry into the DLQ.
      await notifications.processDueNotificationRetries(CTX, { deliveryMode: 'metadata_only', asOf: fromNow(DAY_MS) });
      await notifications.processDueNotificationRetries(CTX, { deliveryMode: 'metadata_only', asOf: fromNow(2 * DAY_MS) });
      let ledger = await ledgerFor(pool, eventId);
      assert.equal(ledger.at(-1).status, 'provider_failed_dlq', 'future ticks reached the DLQ');
      const ceiling = await dbNow(pool);
      for (const row of ledger) {
        assert.ok(new Date(row.created_at).getTime() <= ceiling, `row ${row.id} is not future-dated`);
      }

      // 3. Redrive the DLQ row (metadata-only requeue).
      const firstRedrive = await notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: true });
      assert.equal(firstRedrive.requeued_count, 1);
      assert.equal(await notificationRepo.countDlqDeliveryAttempts(CTX), 0);

      // 4. Real-time webhook ticks fail the requeued attempt back into the DLQ.
      for (const ms of [1_000, 2 * 60_000, 4 * 60_000, 6 * 60_000]) {
        await notifications.processDueNotificationRetries(CTX, {
          deliveryMode: 'webhook', webhookSender: failingSender, asOf: fromNow(ms),
        });
      }
      ledger = await ledgerFor(pool, eventId);
      const liveDlq = ledger.filter((r) => r.status === 'provider_failed_dlq' && r.superseded_at === null);
      assert.equal(liveDlq.length, 1, 'one live DLQ row after the real-time failures');
      assert.ok(sends.length >= 1, 'the requeued attempt was retried through the mock sender');

      // The live DLQ row is visible to the backlog count and to a second redrive.
      assert.equal(await notificationRepo.countDlqDeliveryAttempts(CTX), 1, 'still_dlq backlog is not understated');
      const listed = await notificationRepo.listDlqDeliveryAttempts(CTX, {});
      assert.deepEqual(listed.map((r) => r.attempt.id), [liveDlq[0].id]);
      const secondRedrive = await notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: true });
      assert.equal(secondRedrive.requeued_count, 1, 'live DLQ row is redrivable again');
    });
  });
});
