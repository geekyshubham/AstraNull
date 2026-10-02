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

// Claim-aware DLQ redrive (Postgres): redrive reads DLQ candidates from the attempt ledger, claims
// each row with a lease before any send, and applies the rule lifecycle gate after the claim.
// Mock senders only; no live provider traffic.

const TENANT = 'ten_notify_dlq';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'notification dlq tenant')`, [TENANT]);
  });
}

function eventId(prefix, g) {
  return `${prefix}${String(g).padStart(5, '0')}`;
}

/**
 * Insert `count` events for one webhook rule, each with one attempt. `dlq` rows are exhausted
 * `provider_failed_dlq` attempts; the rest are delivered (completed, never redrivable).
 */
async function insertLedger(pool, { prefix, count, ruleId, createdStart, dlq }) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO notification_events (id, tenant_id, trigger, subject, metadata_json, created_at)
       SELECT $2 || lpad(g::text, 5, '0'), $1, 'report.ready', 'dlq ' || g::text,
              jsonb_build_object('report_id', $2 || g::text),
              $3::timestamptz + g * interval '1 second'
       FROM generate_series(1, $4::int) g`,
      [TENANT, prefix, createdStart, count],
    );
    await client.query(
      `INSERT INTO notification_delivery_attempts (
         id, tenant_id, notification_event_id, rule_id, channel, destination_preview, status, reason,
         provider_error, attempt_number, max_attempts, next_retry_at, exhausted, created_at, attempted_at
       )
       SELECT $2 || lpad(g::text, 5, '0') || '_att', $1, $2 || lpad(g::text, 5, '0'), $5, 'webhook',
              'webhook:hooks.example.invalid',
              CASE WHEN $6::boolean THEN 'provider_failed_dlq' ELSE 'delivered_provider' END,
              CASE WHEN $6::boolean THEN 'webhook_http_error' ELSE 'webhook_delivered' END,
              CASE WHEN $6::boolean THEN 'webhook_http_error' ELSE NULL END,
              CASE WHEN $6::boolean THEN 3 ELSE 1 END, 3, NULL,
              $6::boolean,
              $3::timestamptz + g * interval '1 second',
              $3::timestamptz + g * interval '1 second'
       FROM generate_series(1, $4::int) g`,
      [TENANT, prefix, createdStart, count, ruleId, dlq === true],
    );
  });
}

async function attemptsFor(pool, notificationEventId) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT id, status, reason, attempt_number, claimed_by, lease_expires_at, superseded_at
       FROM notification_delivery_attempts
       WHERE tenant_id = $1 AND notification_event_id = $2
       ORDER BY created_at, COALESCE(attempt_number, 0), id`,
      [TENANT, notificationEventId],
    );
    return rows;
  });
}

async function deliveredCount(pool) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT COUNT(*)::int AS n FROM notification_delivery_attempts
       WHERE tenant_id = $1 AND status = 'delivered_provider' AND reason = 'webhook_delivered'
         AND id NOT LIKE '%\\_att' ESCAPE '\\'`,
      [TENANT],
    );
    return rows[0].n;
  });
}

async function auditsFor(pool, action) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT resource_id, metadata_json FROM audit_logs
       WHERE tenant_id = $1 AND action = $2 ORDER BY sequence`,
      [TENANT, action],
    );
    return rows;
  });
}

function runtime(pool, serviceOptions = {}) {
  const notificationRepo = createNotificationRepository(pool);
  const audit = createAuditRepository(pool);
  const sends = [];
  const webhookSender = serviceOptions.webhookSender ?? (async (_destination, body) => {
    sends.push(body.event_id);
    return { ok: true, status: 202 };
  });
  const notifications = createPostgresNotificationServices(
    { notifications: notificationRepo, audit },
    { deliveryMode: 'webhook', webhookSender, ...serviceOptions },
  );
  return { notificationRepo, notifications, sends, webhookSender };
}

async function createWebhookRule(notifications) {
  const rule = await notifications.createNotificationRule(CTX, {
    channel: 'webhook',
    destination: 'https://hooks.example.invalid/dlq',
    triggers: ['report.ready'],
  });
  assert.ok(rule.id);
  return rule;
}

/** Provider-mode redrive is only reachable outside NODE_ENV=test with an explicit delivery mode. */
async function withProviderRedriveEnv(fn) {
  const prevEnv = process.env.NODE_ENV;
  const prevMode = process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
  process.env.NODE_ENV = 'staging';
  process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = 'webhook';
  try {
    return await fn();
  } finally {
    process.env.NODE_ENV = prevEnv;
    if (prevMode === undefined) delete process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
    else process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = prevMode;
  }
}

async function waitFor(predicate, timeoutMs = 10_000) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > timeoutMs) throw new Error('waitFor timed out');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const minutesFromNow = (minutes) => new Date(Date.now() + minutes * 60_000).toISOString();

async function harnessOrSkip(t) {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) {
    t.skip(availability.reason);
    return false;
  }
  return true;
}

describe('postgres notification DLQ redrive (claim-aware)', () => {
  it('sends a DLQ row exactly once when redrive races another redrive and recovery', { timeout: 120_000 }, async (t) => {
    if (!(await harnessOrSkip(t))) return;
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);

      let release;
      const stalled = new Promise((resolve) => { release = resolve; });
      const allSends = [];
      const blockingSender = async (_destination, body) => {
        allSends.push(body.event_id);
        await stalled;
        return { ok: true, status: 202 };
      };
      const countingSender = async (_destination, body) => {
        allSends.push(body.event_id);
        return { ok: true, status: 202 };
      };
      const a = runtime(pool, { webhookSender: blockingSender });
      const b = runtime(pool, { webhookSender: countingSender });
      const rule = await createWebhookRule(a.notifications);
      await insertLedger(pool, { prefix: 'nevt_race_', count: 1, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z', dlq: true });
      const dlqEvent = eventId('nevt_race_', 1);
      const dlqAttemptId = `${dlqEvent}_att`;

      await withProviderRedriveEnv(async () => {
        // 1. Instance A claims the DLQ row and blocks mid-send.
        const redriveA = a.notifications.redriveNotificationDlq(CTX, {
          attemptIds: [dlqAttemptId], forceMetadataOnly: false, webhookSender: blockingSender,
        });
        await waitFor(() => allSends.length === 1);

        // 2. While A is sending: another redrive and two recovery ticks run concurrently.
        const [redriveB, recoveryA, recoveryB] = await Promise.all([
          b.notifications.redriveNotificationDlq(CTX, {
            attemptIds: [dlqAttemptId], forceMetadataOnly: false, webhookSender: countingSender,
          }),
          a.notifications.processDueNotificationRetries(CTX, { deliveryMode: 'webhook', webhookSender: countingSender, asOf: minutesFromNow(30) }),
          b.notifications.processDueNotificationRetries(CTX, { deliveryMode: 'webhook', webhookSender: countingSender, asOf: minutesFromNow(30) }),
        ]);
        assert.equal(redriveB.network_sends_performed, 0, 'second redrive must not send a claimed row');
        assert.equal(redriveB.in_flight_count + redriveB.claim_lost_count, 1);
        assert.equal(redriveB.requeued_count, 0);
        assert.equal(recoveryA.network_sends_performed + recoveryB.network_sends_performed, 0);
        assert.equal(allSends.length, 1, 'only the claim owner sent');

        release();
        const doneA = await redriveA;
        assert.equal(doneA.requeued_count, 1);
        assert.equal(doneA.network_sends_performed, 1);
        assert.equal(doneA.still_dlq_count, 0);

        // 3. Nothing is left: a later redrive and recovery send nothing.
        const again = await b.notifications.redriveNotificationDlq(CTX, {
          attemptIds: [dlqAttemptId], forceMetadataOnly: false, webhookSender: countingSender,
        });
        assert.equal(again.network_sends_performed, 0);
        assert.equal(again.skipped_count, 1, 'superseded DLQ row is no longer redrivable');
      });

      const rows = await attemptsFor(pool, dlqEvent);
      assert.equal(rows.length, 2);
      assert.equal(rows[0].id, dlqAttemptId);
      assert.ok(rows[0].superseded_at, 'claimed DLQ row is superseded by the outcome');
      assert.equal(rows[1].status, 'delivered_provider');
      assert.deepEqual(allSends, [dlqEvent]);

      // 4. Metadata-only redrive requeues; recovery on two instances racing a redrive sends once.
      await insertLedger(pool, { prefix: 'nevt_meta_', count: 1, ruleId: rule.id, createdStart: '2026-01-01T01:00:00.000Z', dlq: true });
      const metaEvent = eventId('nevt_meta_', 1);
      allSends.length = 0;
      const requeued = await b.notifications.redriveNotificationDlq(CTX, { attemptIds: [`${metaEvent}_att`] });
      assert.equal(requeued.delivery_mode, 'metadata_only');
      assert.equal(requeued.requeued_count, 1);
      assert.equal(requeued.network_sends_performed, 0);
      assert.equal(allSends.length, 0);

      await withProviderRedriveEnv(async () => {
        const results = await Promise.all([
          a.notifications.processDueNotificationRetries(CTX, { deliveryMode: 'webhook', webhookSender: countingSender, asOf: minutesFromNow(30) }),
          b.notifications.processDueNotificationRetries(CTX, { deliveryMode: 'webhook', webhookSender: countingSender, asOf: minutesFromNow(30) }),
          b.notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: false, webhookSender: countingSender }),
        ]);
        assert.equal(results[2].network_sends_performed, 0, 'requeued row is not a DLQ row');
      });
      assert.deepEqual(allSends, [metaEvent], 'requeued attempt delivered exactly once');
      const metaRows = await attemptsFor(pool, metaEvent);
      assert.equal(metaRows.filter((r) => r.status === 'delivered_provider').length, 1);
      assert.equal(await deliveredCount(pool), 2);
    });
  });

  it('holds a turned-off rule (0 sends, row untouched), resumes on re-enable, cancels on delete', { timeout: 120_000 }, async (t) => {
    if (!(await harnessOrSkip(t))) return;
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const { notifications, sends, webhookSender } = runtime(pool);
      const rule = await createWebhookRule(notifications);
      await insertLedger(pool, { prefix: 'nevt_hold_', count: 2, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z', dlq: true });
      const first = eventId('nevt_hold_', 1);
      const second = eventId('nevt_hold_', 2);

      await notifications.updateNotificationRule(CTX, rule.id, { enabled: false });
      await withProviderRedriveEnv(async () => {
        const redrive = (attemptIds) => notifications.redriveNotificationDlq(CTX, {
          attemptIds, forceMetadataOnly: false, webhookSender,
        });

        // Turned off: concurrent redrive + recovery make zero sends and leave the DLQ rows as is.
        const [held, recovery] = await Promise.all([
          redrive(undefined),
          notifications.processDueNotificationRetries(CTX, { deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(30) }),
        ]);
        assert.equal(held.delivery_mode, 'webhook');
        assert.equal(held.held_count, 2);
        assert.equal(held.requeued_count, 0);
        assert.equal(held.network_sends_performed, 0);
        assert.equal(held.still_dlq_count, 2);
        assert.equal(recovery.network_sends_performed, 0);
        assert.equal(sends.length, 0, 'redrive must not send for a turned-off rule');
        for (const id of [first, second]) {
          const rows = await attemptsFor(pool, id);
          assert.equal(rows.length, 1, 'held DLQ row is untouched');
          assert.equal(rows[0].status, 'provider_failed_dlq');
          assert.equal(rows[0].superseded_at, null);
          assert.equal(rows[0].claimed_by, null, 'held claim is released');
          assert.equal(rows[0].lease_expires_at, null);
        }

        // Dry run never claims or writes.
        const dry = await notifications.redriveNotificationDlq(CTX, { dryRun: true, forceMetadataOnly: false, webhookSender });
        assert.equal(dry.held_count, 2);
        assert.equal(dry.network_sends_performed, 0);

        // Re-enable: the first row redrives exactly once.
        await notifications.updateNotificationRule(CTX, rule.id, { enabled: true });
        const resumed = await redrive([`${first}_att`]);
        assert.equal(resumed.network_sends_performed, 1);
        assert.deepEqual(sends, [first]);

        // Delete: the second row is cancelled with no send, audited, and never redriven again.
        await notifications.deleteNotificationRule(CTX, rule.id);
        const cancelled = await redrive(undefined);
        assert.equal(cancelled.cancelled_count, 1);
        assert.equal(cancelled.network_sends_performed, 0);
        assert.equal(cancelled.still_dlq_count, 0);
        assert.deepEqual(sends, [first], 'deleted rule is never sent to');
        const quiet = await redrive(undefined);
        assert.equal(quiet.processed.length, 0);
      });

      const secondRows = await attemptsFor(pool, second);
      const closing = secondRows.at(-1);
      assert.equal(closing.status, 'cancelled_rule_removed');
      assert.equal(closing.reason, 'rule_removed');
      const recorded = await auditsFor(pool, 'notification.delivery_attempt_recorded');
      assert.equal(recorded.filter((a) => a.resource_id === closing.id).length, 1, 'cancellation is audited');
      const redriveAudits = await auditsFor(pool, 'notification.dlq_redrive');
      assert.ok(redriveAudits.some((a) => a.metadata_json.held_count === 2));
      assert.ok(redriveAudits.some((a) => a.metadata_json.cancelled_count === 1));
    });
  });

  it('redrives DLQ rows that sit behind 500+ newer events, paging oldest-first', { timeout: 120_000 }, async (t) => {
    if (!(await harnessOrSkip(t))) return;
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const { notificationRepo, notifications, sends, webhookSender } = runtime(pool);
      const rule = await createWebhookRule(notifications);
      await insertLedger(pool, { prefix: 'nevt_olddlq_', count: 5, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z', dlq: true });
      await insertLedger(pool, { prefix: 'nevt_newer_', count: 520, ruleId: rule.id, createdStart: '2026-01-02T00:00:00.000Z', dlq: false });

      // The bounded recent-events feed cannot see them.
      const feed = await notificationRepo.listNotificationEvents(CTX, { limit: 500 });
      assert.ok(feed.every((e) => !e.id.startsWith('nevt_olddlq_')));

      await withProviderRedriveEnv(async () => {
        // A targeted redrive of the oldest row finds it.
        const targeted = await notifications.redriveNotificationDlq(CTX, {
          attemptIds: [`${eventId('nevt_olddlq_', 1)}_att`], forceMetadataOnly: false, webhookSender,
        });
        assert.equal(targeted.skipped_count, 0);
        assert.equal(targeted.network_sends_performed, 1);
        assert.equal(targeted.still_dlq_count, 4);

        // A bulk redrive drains the rest across pages, oldest first, each once.
        const bulk = await notifications.redriveNotificationDlq(CTX, {
          forceMetadataOnly: false, webhookSender, pageSize: 2,
        });
        assert.equal(bulk.requeued_count, 4);
        assert.equal(bulk.network_sends_performed, 4);
        assert.equal(bulk.pages_read, 3);
        assert.equal(bulk.still_dlq_count, 0);

        // A work budget bounds a single call; a fresh DLQ row is then left for the next call.
        await insertLedger(pool, { prefix: 'nevt_late_', count: 3, ruleId: rule.id, createdStart: '2026-01-03T00:00:00.000Z', dlq: true });
        const budgeted = await notifications.redriveNotificationDlq(CTX, {
          forceMetadataOnly: false, webhookSender, pageSize: 10, maxItems: 2,
        });
        assert.equal(budgeted.network_sends_performed, 2);
        assert.equal(budgeted.budget_exhausted, true);
        assert.equal(budgeted.still_dlq_count, 1);
        const rest = await notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: false, webhookSender });
        assert.equal(rest.network_sends_performed, 1);
        assert.equal(rest.still_dlq_count, 0);
      });

      assert.deepEqual(sends, [
        ...[1, 2, 3, 4, 5].map((g) => eventId('nevt_olddlq_', g)),
        ...[1, 2, 3].map((g) => eventId('nevt_late_', g)),
      ]);
    });
  });

  it('does not redrive a row leased by a dead owner until the lease expires, then sends once', { timeout: 120_000 }, async (t) => {
    if (!(await harnessOrSkip(t))) return;
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const { notificationRepo, notifications, sends, webhookSender } = runtime(pool);
      const rule = await createWebhookRule(notifications);
      await insertLedger(pool, { prefix: 'nevt_dead_', count: 1, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z', dlq: true });
      const dlqEvent = eventId('nevt_dead_', 1);
      const attemptId = `${dlqEvent}_att`;

      const dead = await notificationRepo.claimDlqDeliveryAttempt(CTX, { attemptId, claimToken: 'dead-owner', leaseMs: 400 });
      assert.ok(dead, 'dead owner held the claim');
      assert.equal(
        await notificationRepo.claimDlqDeliveryAttempt(CTX, { attemptId, claimToken: 'rival', leaseMs: 400 }),
        null,
        'a live lease refuses a second claim',
      );

      await withProviderRedriveEnv(async () => {
        const blocked = await notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: false, webhookSender });
        assert.equal(blocked.in_flight_count, 1);
        assert.equal(blocked.network_sends_performed, 0);

        await new Promise((resolve) => setTimeout(resolve, 600));
        const reclaimed = await notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: false, webhookSender });
        assert.equal(reclaimed.network_sends_performed, 1);
      });
      assert.deepEqual(sends, [dlqEvent]);

      const late = await notificationRepo.completeDeliveryAttemptClaim(CTX, {
        attemptId,
        claimToken: 'dead-owner',
        eventId: dlqEvent,
        record: { id: 'natt_dead_late', rule_id: rule.id, channel: 'webhook', status: 'delivered_provider', created_at: new Date().toISOString() },
      });
      assert.equal(late.completed, false, 'the dead owner cannot record a late outcome');
      const rows = await attemptsFor(pool, dlqEvent);
      assert.equal(rows.filter((r) => r.status === 'delivered_provider').length, 1);
    });
  });
});
