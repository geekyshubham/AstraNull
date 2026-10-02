import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createPostgresNotificationServices } from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  NOTIFICATION_RECONCILE_GRACE_MS,
  NOTIFICATION_RECONCILE_LOOKBACK_MS,
  NOTIFICATION_RECONCILE_FLOOR_MIGRATION,
  createNotificationOutboxReconciler,
  registerPostgresNotificationReconciliation,
} from '../../src/persistence/postgres/notificationReconciliation.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

/**
 * R03 follow-up (R03-asof-window): a caller-supplied retry `asOf` (API `as_of`, runner/scheduler
 * `--as-of`) must not move the reconciliation window. The lookback is bounded by the service
 * clock, so a past as-of can never reach records older than NOTIFICATION_RECONCILE_LOOKBACK_MS.
 */

const TENANT = 'ten_notify_reconcile_asof';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const SYSTEM = { tenantId: TENANT, userId: 'notification-retry-scheduler', role: 'system' };
const DAY_MS = 24 * 60 * 60_000;

async function withHarness(t, fn) {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) {
    t.skip(availability.reason);
    return;
  }
  await withEphemeralPostgres(async (pool) => {
    await withTenantContext(pool, TENANT, async (client) => {
      await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'reconcile as-of tenant')`, [TENANT]);
    });
    await fn(pool);
  });
}

/**
 * The upgrade floor is the applied_at of migration 0062 in this ephemeral database, which is
 * "now" on a fresh harness. Backdate it before the first floor read so the positive control
 * (created 1h ago) is post-upgrade, while the floor still predates both seeded reports — the
 * 20-day-old exclusion must stay the lookback's job, not the floor's.
 */
async function backdateReconcileFloor(pool, at) {
  await pool.query(
    `UPDATE schema_migrations SET applied_at = $1::timestamptz WHERE version = $2`,
    [at, NOTIFICATION_RECONCILE_FLOOR_MIGRATION],
  );
}

async function backdateRule(pool, ruleId, at) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `UPDATE notification_rules SET created_at = $3::timestamptz, updated_at = $3::timestamptz
       WHERE tenant_id = $1 AND id = $2`,
      [TENANT, ruleId, at],
    );
  });
}

/** A committed ready report whose notification enqueue never happened. */
async function seedReport(pool, id, at) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO reports (id, tenant_id, kind, title, status, created_at)
       VALUES ($1, $2, 'readiness_summary', $3, 'ready', $4::timestamptz)`,
      [id, TENANT, `Report ${id}`, at],
    );
  });
}

async function readReportEvents(pool) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT dedupe_key FROM notification_events
       WHERE tenant_id = $1 AND trigger = 'report.ready' ORDER BY dedupe_key`,
      [TENANT],
    );
    return rows.map((r) => r.dedupe_key);
  });
}

function buildRuntime(pool, serviceOptions = {}) {
  const notificationRepo = createNotificationRepository(pool);
  const audit = createAuditRepository(pool);
  const notifications = createPostgresNotificationServices(
    { notifications: notificationRepo, audit },
    serviceOptions,
  );
  registerPostgresNotificationReconciliation({ pool, notifications, audit });
  return { notifications };
}

describe('postgres notification reconciliation window vs caller as-of (R03)', () => {
  it('a past as-of never reconciles records older than the lookback', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      const nowMs = Date.now();
      await backdateReconcileFloor(pool, new Date(nowMs - 30 * DAY_MS).toISOString());
      const rule = await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      await backdateRule(pool, rule.id, new Date(nowMs - 30 * DAY_MS).toISOString());
      await seedReport(pool, 'rpt_old_20d', new Date(nowMs - 20 * DAY_MS).toISOString());
      await seedReport(pool, 'rpt_recent_1h', new Date(nowMs - 60 * 60_000).toISOString());

      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, {
        asOf: new Date(nowMs - 19.5 * DAY_MS).toISOString(),
        deliveryMode: 'metadata_only',
      });
      const fromMs = new Date(tick.reconciliation.window_from).getTime();
      assert.ok(
        fromMs >= nowMs - NOTIFICATION_RECONCILE_LOOKBACK_MS,
        `window_from ${tick.reconciliation.window_from} must stay within the lookback of the service clock`,
      );
      // Only the in-window record is reconciled; the 20-day-old report stays out of reach.
      assert.equal(tick.reconciliation.reconciled_count, 1);
      assert.deepEqual(await readReportEvents(pool), ['report.ready:report:rpt_recent_1h']);

      // Repeating with an even older as-of still cannot reach it.
      const again = await rt.notifications.processDueNotificationRetries(SYSTEM, {
        asOf: new Date(nowMs - 25 * DAY_MS).toISOString(),
        deliveryMode: 'metadata_only',
      });
      assert.equal(again.reconciliation.reconciled_count, 0);
      assert.deepEqual(await readReportEvents(pool), ['report.ready:report:rpt_recent_1h']);
    });
  });
});

describe('reconciliation anchor (service clock vs retry as-of)', () => {
  const FIXED_NOW = new Date('2026-10-01T12:00:00.000Z');

  function stubService() {
    const windows = [];
    const notificationRepo = {
      async listNotificationRules() { return []; },
      async listNotificationEvents() { return []; },
      async createNotificationRule() { throw new Error('not used'); },
      async appendNotificationEvent() { throw new Error('not used'); },
      async appendDeliveryAttempts() {},
    };
    const notifications = createPostgresNotificationServices(
      { notifications: notificationRepo, audit: { async appendAuditEvent() {} } },
      { now: () => FIXED_NOW },
    );
    notifications.registerNotificationReconciler(createNotificationOutboxReconciler({
      notifications,
      repository: {
        async listUnnotifiedReports(_ctx, window) {
          windows.push(window);
          return [];
        },
      },
    }));
    return { notifications, windows };
  }

  it('ignores a past as-of, honours a later one, and defaults to the service clock', async () => {
    const { notifications, windows } = stubService();
    const past = new Date(FIXED_NOW.getTime() - 19.5 * DAY_MS).toISOString();
    const future = new Date(FIXED_NOW.getTime() + 5 * 60_000).toISOString();

    const pastTick = await notifications.processDueNotificationRetries(SYSTEM, { asOf: past });
    assert.equal(pastTick.reconciliation.window_from, new Date(FIXED_NOW.getTime() - NOTIFICATION_RECONCILE_LOOKBACK_MS).toISOString());
    assert.equal(pastTick.reconciliation.window_to, new Date(FIXED_NOW.getTime() - NOTIFICATION_RECONCILE_GRACE_MS).toISOString());

    const defaultTick = await notifications.processDueNotificationRetries(SYSTEM, {});
    assert.equal(defaultTick.reconciliation.window_from, pastTick.reconciliation.window_from);

    const futureTick = await notifications.processDueNotificationRetries(SYSTEM, { asOf: future });
    // A later as-of only narrows the lookback side; it never reaches further back than the clock.
    assert.ok(new Date(futureTick.reconciliation.window_from).getTime() >= FIXED_NOW.getTime() - NOTIFICATION_RECONCILE_LOOKBACK_MS);
    assert.equal(windows.length, 3);
  });

  it('rejects an unparseable as-of before any reconciliation runs', async () => {
    const { notifications, windows } = stubService();
    await assert.rejects(
      notifications.processDueNotificationRetries(SYSTEM, { asOf: 'not-a-date' }),
      /invalid as-of/,
    );
    assert.equal(windows.length, 0);
  });
});
