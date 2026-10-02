import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import { createReportRepository } from '../../src/persistence/postgres/reportRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';
import { createPostgresNotificationServices } from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  NOTIFICATION_RECONCILE_FLOOR_MIGRATION,
  createNotificationOutboxReconciler,
  registerPostgresNotificationReconciliation,
} from '../../src/persistence/postgres/notificationReconciliation.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

/**
 * Reconciliation floor (upgrade safety): records committed before the build that introduced the
 * Postgres lifecycle emitters (migration 0062) were never owed a notification, so the first
 * recovery tick after deploy must not back-fill them even for long-standing subscribed rules.
 */

const TENANT = 'ten_notify_reconcile_floor';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const SYSTEM = { tenantId: TENANT, userId: 'notification-retry-scheduler', role: 'system' };

const futureAsOf = (minutes = 5) => new Date(Date.now() + minutes * 60_000).toISOString();

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'reconcile floor tenant')`, [TENANT]);
  });
}

/** A ready report committed at `at` with no outbox event (what the pre-upgrade build wrote). */
async function seedLegacyReport(pool, { id, at }) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO reports (id, tenant_id, kind, title, status, summary_json, run_ids, created_by, created_at)
       VALUES ($1, $2, 'readiness_summary', $3, 'ready', '{}'::jsonb, ARRAY[]::text[], 'usr_admin', $4::timestamptz)`,
      [id, TENANT, `Legacy ${id}`, at],
    );
  });
}

/** Makes a rule long-standing: created well before the legacy records, never edited since. */
async function backdateRule(pool, ruleId, days = 30) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `UPDATE notification_rules
       SET created_at = NOW() - make_interval(days => $3::int), updated_at = NULL
       WHERE tenant_id = $1 AND id = $2`,
      [TENANT, ruleId, days],
    );
  });
}

async function setFloorAppliedAt(pool, at) {
  await pool.query(`UPDATE schema_migrations SET applied_at = $2::timestamptz WHERE version = $1`, [
    NOTIFICATION_RECONCILE_FLOOR_MIGRATION,
    at,
  ]);
}

async function readEvents(pool) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT trigger, dedupe_key FROM notification_events WHERE tenant_id = $1 ORDER BY created_at, id`,
      [TENANT],
    );
    return rows;
  });
}

/** Production-shaped wiring (mirrors runtime.mjs) with no provider senders. */
function buildRuntime(pool, reconcileOptions = {}) {
  const notificationRepo = createNotificationRepository(pool);
  const audit = createAuditRepository(pool);
  const notifications = createPostgresNotificationServices({ notifications: notificationRepo, audit });
  registerPostgresNotificationReconciliation({ pool, notifications, audit, ...reconcileOptions });
  // "Crash": commits the report only, never reaching the notification emitter.
  const { reports: crashedReports } = createPostgresReportServices({
    reports: createReportRepository(pool),
    validationEvidence: createValidationEvidenceRepository(pool),
    audit,
  });
  return { notifications, crashedReports };
}

async function withHarness(t, fn) {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) {
    t.skip(availability.reason);
    return;
  }
  await withEphemeralPostgres(async (pool) => {
    await seedTenant(pool);
    await fn(pool);
  });
}

describe('postgres notification reconciliation floor', () => {
  it('does not back-fill records committed before the live-emitter migration was applied', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      // Deploy happened 1h ago; the old build committed rep_old 6h ago with no event.
      await setFloorAppliedAt(pool, new Date(Date.now() - 60 * 60_000).toISOString());
      const rt = buildRuntime(pool);
      const rule = await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      await backdateRule(pool, rule.id);
      await seedLegacyReport(pool, { id: 'rep_old', at: new Date(Date.now() - 6 * 60 * 60_000).toISOString() });

      const first = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(first.reconciliation.floor_unavailable, false);
      assert.equal(first.reconciliation.missing_count, 0);
      assert.equal(first.reconciliation.reconciled_count, 0);
      assert.ok(Date.parse(first.reconciliation.window_from) >= Date.parse(first.reconciliation.floor));
      assert.deepEqual(await readEvents(pool), [], 'pre-upgrade activity is never notified');

      // Control: a post-deploy report whose enqueue was lost is still reconciled.
      const lost = await rt.crashedReports.createReport(CTX, { title: 'After deploy' });
      const second = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(second.reconciliation.reconciled_count, 1);
      assert.deepEqual(
        (await readEvents(pool)).map((e) => e.dedupe_key),
        [`report.ready:report:${lost.id}`],
      );
    });
  });

  it('a configured reconcileSince raises the floor above the migration time', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      await setFloorAppliedAt(pool, new Date(Date.now() - 12 * 60 * 60_000).toISOString());
      const rt = buildRuntime(pool, { reconcileSince: new Date(Date.now() - 60 * 60_000).toISOString() });
      const rule = await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      await backdateRule(pool, rule.id);
      // After the migration floor, before the configured one.
      await seedLegacyReport(pool, { id: 'rep_mid', at: new Date(Date.now() - 6 * 60 * 60_000).toISOString() });

      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(tick.reconciliation.missing_count, 0);
      assert.equal(tick.reconciliation.reconciled_count, 0);
      assert.deepEqual(await readEvents(pool), []);
    });
  });

  it('fails closed when the live-emitter migration is not recorded', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      const rule = await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      await backdateRule(pool, rule.id);
      await rt.crashedReports.createReport(CTX, { title: 'Unknown floor' });
      await pool.query(`DELETE FROM schema_migrations WHERE version = $1`, [NOTIFICATION_RECONCILE_FLOOR_MIGRATION]);
      try {
        const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
        assert.equal(tick.reconciliation.floor_unavailable, true);
        assert.equal(tick.reconciliation.missing_count, 0);
        assert.equal(tick.reconciliation.reconciled_count, 0);
        assert.deepEqual(await readEvents(pool), []);
      } finally {
        await pool.query(
          `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`,
          [NOTIFICATION_RECONCILE_FLOOR_MIGRATION],
        );
      }
    });
  });
});

describe('notification reconciler floor (no database)', () => {
  function fakeRepository(floor, calls) {
    return {
      async getReconciliationFloor() {
        if (floor instanceof Error) throw floor;
        return floor;
      },
      async listUnnotifiedReports(_ctx, window) {
        calls.push(window);
        return [];
      },
    };
  }
  const notifications = { async enqueueNotification() { throw new Error('must not enqueue'); } };
  const asOf = '2026-10-02T12:00:00.000Z';

  it('clamps the window start to the floor', async () => {
    const calls = [];
    const reconcile = createNotificationOutboxReconciler({
      repository: fakeRepository('2026-10-02T09:00:00.000Z', calls),
      notifications,
    });
    const result = await reconcile(SYSTEM, { asOf });
    assert.equal(result.window_from, '2026-10-02T09:00:00.000Z');
    assert.equal(result.floor, '2026-10-02T09:00:00.000Z');
    assert.equal(calls[0].from, '2026-10-02T09:00:00.000Z');
  });

  it('uses the later of reconcileSince and the migration floor', async () => {
    const calls = [];
    const reconcile = createNotificationOutboxReconciler({
      repository: fakeRepository('2026-10-02T09:00:00.000Z', calls),
      notifications,
      reconcileSince: '2026-10-02T10:30:00.000Z',
    });
    const result = await reconcile(SYSTEM, { asOf });
    assert.equal(calls[0].from, '2026-10-02T10:30:00.000Z');
    assert.equal(result.floor, '2026-10-02T10:30:00.000Z');
  });

  it('reads nothing when the floor is after the grace boundary', async () => {
    const calls = [];
    const reconcile = createNotificationOutboxReconciler({
      repository: fakeRepository('2026-10-02T11:59:30.000Z', calls),
      notifications,
    });
    const result = await reconcile(SYSTEM, { asOf });
    assert.equal(calls.length, 0);
    assert.equal(result.missing_count, 0);
  });

  it('fails closed when the floor is missing or unreadable', async () => {
    for (const floor of [null, new Error('db down')]) {
      const calls = [];
      const reconcile = createNotificationOutboxReconciler({ repository: fakeRepository(floor, calls), notifications });
      const result = await reconcile(SYSTEM, { asOf });
      assert.equal(calls.length, 0);
      assert.equal(result.floor_unavailable, true);
      assert.equal(result.failed_count, floor instanceof Error ? 1 : 0);
    }
  });

  it('rejects an invalid reconcileSince', () => {
    assert.throws(
      () => createNotificationOutboxReconciler({ repository: fakeRepository(null, []), notifications, reconcileSince: 'nope' }),
      /invalid reconcileSince/,
    );
  });
});
