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

// R01 regression: DLQ rows held by a turned-off rule must not use up the bulk redrive work budget
// or block enabled rules' DLQ rows queued behind them. Mock senders only; no live provider traffic.

const TENANT = 'ten_notify_dlq_held';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'notification dlq held tenant')`, [TENANT]);
  });
}

/** Insert `count` events for one webhook rule, each with one exhausted `provider_failed_dlq` attempt. */
async function insertDlqLedger(pool, { prefix, count, ruleId, createdStart }) {
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
              'webhook:hooks.example.invalid', 'provider_failed_dlq', 'webhook_http_error',
              'webhook_http_error', 3, 3, NULL, true,
              $3::timestamptz + g * interval '1 second',
              $3::timestamptz + g * interval '1 second'
       FROM generate_series(1, $4::int) g`,
      [TENANT, prefix, createdStart, count, ruleId],
    );
  });
}

async function heldRowState(pool, ruleId) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE status = 'provider_failed_dlq' AND superseded_at IS NULL
                               AND claimed_by IS NULL AND lease_expires_at IS NULL)::int AS untouched
       FROM notification_delivery_attempts
       WHERE tenant_id = $1 AND rule_id = $2`,
      [TENANT, ruleId],
    );
    return rows[0];
  });
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

describe('postgres notification DLQ redrive: held rules and the work budget (R01)', () => {
  it('does not let 1000+ held DLQ rows starve an enabled rule queued behind them', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool);
      const notificationRepo = createNotificationRepository(pool);
      const audit = createAuditRepository(pool);
      const sends = [];
      const claimCalls = [];
      const repo = {
        ...notificationRepo,
        claimDlqDeliveryAttempt: (ctx, input) => {
          claimCalls.push(input.attemptId);
          return notificationRepo.claimDlqDeliveryAttempt(ctx, input);
        },
      };
      const webhookSender = async (_destination, body) => {
        sends.push(body.event_id);
        return { ok: true, status: 202 };
      };
      const notifications = createPostgresNotificationServices(
        { notifications: repo, audit },
        { deliveryMode: 'webhook', webhookSender },
      );
      const createRule = (suffix) => notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: `https://hooks.example.invalid/${suffix}`,
        triggers: ['report.ready'],
      });
      const ruleA = await createRule('held');
      const ruleB = await createRule('enabled');

      const heldCount = 1005;
      await insertDlqLedger(pool, { prefix: 'nevt_held_', count: heldCount, ruleId: ruleA.id, createdStart: '2026-01-01T00:00:00.000Z' });
      await insertDlqLedger(pool, { prefix: 'nevt_live_', count: 1, ruleId: ruleB.id, createdStart: '2026-01-02T00:00:00.000Z' });
      await notifications.updateNotificationRule(CTX, ruleA.id, { enabled: false });
      const liveEvent = 'nevt_live_00001';

      await withProviderRedriveEnv(async () => {
        // Dry run reports the held backlog without claiming anything.
        const dry = await notifications.redriveNotificationDlq(CTX, { dryRun: true, forceMetadataOnly: false, webhookSender });
        assert.equal(dry.held_count, heldCount);
        assert.equal(dry.requeued_count, 1);
        assert.equal(dry.budget_exhausted, false);
        assert.equal(claimCalls.length, 0);

        // Unfiltered bulk redrive (default work budget) reaches B's row behind the held backlog.
        const first = await notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: false, webhookSender });
        assert.equal(first.held_count, heldCount, 'held rows are still reported');
        assert.equal(first.budget_exhausted, false, 'held rows do not use up the work budget');
        assert.equal(first.requeued_count, 1);
        assert.equal(first.network_sends_performed, 1);
        assert.equal(first.still_dlq_count, heldCount);
        assert.deepEqual(sends, [liveEvent]);
        assert.deepEqual(claimCalls, [`${liveEvent}_att`], 'held rows are never claimed');

        // A second call: nothing to send, held rows still untouched, still no claims on them.
        const second = await notifications.redriveNotificationDlq(CTX, { forceMetadataOnly: false, webhookSender });
        assert.equal(second.held_count, heldCount);
        assert.equal(second.network_sends_performed, 0);
        assert.equal(second.budget_exhausted, false);
        assert.equal(claimCalls.length, 1);

        // A targeted redrive of a held row reports it held, not skipped as missing.
        const targeted = await notifications.redriveNotificationDlq(CTX, {
          attemptIds: ['nevt_held_00001_att'], forceMetadataOnly: false, webhookSender,
        });
        assert.equal(targeted.held_count, 1);
        assert.equal(targeted.skipped_count, 0);
        assert.equal(targeted.network_sends_performed, 0);

        // Re-enable A: its rows become redrivable again, bounded by the work budget.
        await notifications.updateNotificationRule(CTX, ruleA.id, { enabled: true });
        const resumed = await notifications.redriveNotificationDlq(CTX, {
          forceMetadataOnly: false, webhookSender, pageSize: 50, maxItems: 10,
        });
        assert.equal(resumed.held_count, 0);
        assert.equal(resumed.network_sends_performed, 10);
        assert.equal(resumed.budget_exhausted, true);
      });

      const state = await heldRowState(pool, ruleA.id);
      assert.equal(state.untouched, heldCount - 10, 'only re-enabled rows were redriven');
      assert.equal(sends.length, 11);

      const redriveAudits = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(
          `SELECT metadata_json FROM audit_logs WHERE tenant_id = $1 AND action = 'notification.dlq_redrive'`,
          [TENANT],
        );
        return rows;
      });
      assert.ok(redriveAudits.some((a) => a.metadata_json.held_count === heldCount));
    });
  });
});
