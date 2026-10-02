import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createNotificationRepository } from '../../src/persistence/postgres/notificationRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createReportRepository } from '../../src/persistence/postgres/reportRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';
import {
  createPostgresNotificationServices,
  registerPostgresRunNotificationHook,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  createNotificationOutboxReconciler,
  createNotificationReconciliationRepository,
  registerPostgresNotificationReconciliation,
} from '../../src/persistence/postgres/notificationReconciliation.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_notify_reconcile';
const GROUP = 'tg_notify_reconcile';
const TARGET = 'tgt_notify_reconcile';
const CHECK = 'origin.direct_bypass.safe';
const RUN = 'run_notify_reconcile';
const VERDICT = 'verdict_notify_reconcile';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const SYSTEM = { tenantId: TENANT, userId: 'notification-retry-scheduler', role: 'system' };

/** A recovery tick far enough ahead that the reconcile grace has passed for every record. */
const futureAsOf = () => new Date(Date.now() + 5 * 60_000).toISOString();

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'notification reconcile tenant')`, [TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'reconcile group')`,
      [GROUP, TENANT],
    );
    await client.query(
      `INSERT INTO targets (
         id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior
       ) VALUES ($1, $2, $3, 'ip', '203.0.113.41', '203.0.113.41', 'must_block_before_origin')`,
      [TARGET, TENANT, GROUP],
    );
  });
}

/** A run whose external evidence and verdict are durably committed (the domain write). */
async function seedVerdictedRun(pool) {
  const at = new Date().toISOString();
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO test_runs (
         id, tenant_id, target_group_id, target_id, check_id, status,
         probe_external_result, awaiting_external_probe, remediation_template,
         safety_constraints, correlation_json, collection_deadline_at,
         started_at, completed_at, created_at
       ) VALUES (
         $1, $2, $3, $4, $5, 'verdicted', 'connected', FALSE, 'block_origin',
         '{"max_events":50}'::jsonb,
         jsonb_build_object('nonce_hash', 'nonce_reconcile', 'window_ms', 120000),
         $6::timestamptz, $6::timestamptz, $6::timestamptz, $6::timestamptz
       )`,
      [RUN, TENANT, GROUP, TARGET, CHECK, at],
    );
    await client.query(
      `INSERT INTO events (
         id, tenant_id, test_run_id, target_id, check_id, agent_id, source,
         signal_type, producer_kind, nonce_hash, timestamp, metadata_json
       ) VALUES ('evt_probe_reconcile', $1, $2, $3, $4, NULL, 'probe_worker', 'probe_result',
                 'signed_probe', 'nonce_reconcile', $5::timestamptz, '{"external_result":"connected"}'::jsonb)`,
      [TENANT, RUN, TARGET, CHECK, at],
    );
    await client.query(
      `INSERT INTO verdicts (
         id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
         placement_confidence_json, explanation, evidence_ids, created_at
       ) VALUES ($1, $2, $3, $4, $5, 'bypassable', 'high', '{}'::jsonb,
                 'origin reachable directly', ARRAY['evt_probe_reconcile']::text[], $6::timestamptz)`,
      [VERDICT, TENANT, RUN, TARGET, CHECK, at],
    );
  });
}

async function readLedger(pool) {
  return withTenantContext(pool, TENANT, async (client) => {
    const events = await client.query(
      `SELECT id, trigger, dedupe_key, metadata_json FROM notification_events
       WHERE tenant_id = $1 ORDER BY created_at, id`,
      [TENANT],
    );
    const attempts = await client.query(
      `SELECT notification_event_id, status FROM notification_delivery_attempts WHERE tenant_id = $1`,
      [TENANT],
    );
    const audits = await client.query(
      `SELECT action, metadata_json FROM audit_logs
       WHERE tenant_id = $1 AND action LIKE 'notification.%' ORDER BY sequence`,
      [TENANT],
    );
    const reports = await client.query(`SELECT id FROM reports WHERE tenant_id = $1`, [TENANT]);
    return { events: events.rows, attempts: attempts.rows, audits: audits.rows, reports: reports.rows };
  });
}

/**
 * Production-shaped wiring (mirrors runtime.mjs). `failEnqueue` makes the first N outbox enqueues
 * throw, i.e. the domain commit succeeded and the separate notification transaction failed.
 */
function buildRuntime(pool, { failEnqueue = 0 } = {}) {
  const notificationRepo = createNotificationRepository(pool);
  const realEnqueue = notificationRepo.enqueueNotificationEvent;
  const faults = { remaining: failEnqueue };
  notificationRepo.enqueueNotificationEvent = async (...args) => {
    if (faults.remaining > 0) {
      faults.remaining -= 1;
      throw new Error('transient persistence failure');
    }
    return realEnqueue(...args);
  };
  const audit = createAuditRepository(pool);
  const validationEvidence = createValidationEvidenceRepository(pool);
  const validation = createPostgresValidationServices({
    validationEvidence,
    audit,
    coreCatalog: createCoreCatalogRepository(pool),
    probeJobs: createProbeJobRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
  });
  const notifications = createPostgresNotificationServices({ notifications: notificationRepo, audit });
  registerPostgresRunNotificationHook({
    testRuns: validation.testRuns,
    notifications,
    notificationRules: notificationRepo,
    validationEvidence,
  });
  const unregister = registerPostgresNotificationReconciliation({ pool, notifications, audit });
  assert.equal(typeof unregister, 'function', 'reconciliation must be wired into the recovery worker');
  const { reports } = createPostgresReportServices(
    { reports: createReportRepository(pool), validationEvidence, audit, notifications: notificationRepo },
    { notifications },
  );
  return { validation, notifications, reports, faults, audit };
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

describe('postgres notification outbox reconciliation (R03)', () => {
  it('recovers report.ready exactly once after the enqueue fails post-commit, without reissuing the report', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool, { failEnqueue: 1 });
      await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });

      const report = await rt.reports.createReport(CTX, { title: 'Weekly readiness' });
      assert.ok(report.id, 'report creation must still succeed');
      let ledger = await readLedger(pool);
      assert.equal(ledger.reports.length, 1);
      assert.equal(ledger.events.length, 0, 'the initial enqueue failed after the report committed');

      // Recovery tick: the user operation is NOT reissued.
      const first = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(first.reconciliation.reconciled_count, 1);
      assert.equal(first.reconciliation.by_trigger['report.ready'].reconciled, 1);

      ledger = await readLedger(pool);
      assert.equal(ledger.reports.length, 1, 'reconciliation never creates another report');
      assert.equal(ledger.events.length, 1);
      assert.equal(ledger.events[0].trigger, 'report.ready');
      assert.equal(ledger.events[0].dedupe_key, `report.ready:report:${report.id}`);
      assert.equal(ledger.events[0].metadata_json.report_id, report.id);
      assert.equal(ledger.attempts.length, 1);
      assert.equal(ledger.attempts[0].status, 'delivered_in_app');
      const reconciledAudit = ledger.audits.filter((a) => a.action === 'notification.outbox_reconciled');
      assert.equal(reconciledAudit.length, 1);
      assert.deepEqual(reconciledAudit[0].metadata_json.event_ids, [ledger.events[0].id]);

      // A second pass finds nothing owed and records nothing.
      const second = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(second.reconciliation.missing_count, 0);
      assert.equal(second.reconciliation.reconciled_count, 0);
      ledger = await readLedger(pool);
      assert.equal(ledger.events.length, 1);
      assert.equal(ledger.audits.filter((a) => a.action === 'notification.outbox_reconciled').length, 1);
    });
  });

  it('recovers a report whose process died between the domain commit and the enqueue', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      // "Crash": a report service without a notification emitter commits the report only.
      const { reports: crashed } = createPostgresReportServices({
        reports: createReportRepository(pool),
        validationEvidence: createValidationEvidenceRepository(pool),
        audit: rt.audit,
      });
      const report = await crashed.createReport(CTX, { title: 'Crashed before enqueue' });
      assert.equal((await readLedger(pool)).events.length, 0);

      await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      const ledger = await readLedger(pool);
      assert.deepEqual(ledger.events.map((e) => e.dedupe_key), [`report.ready:report:${report.id}`]);
    });
  });

  it('recovers run completion and its high-severity alert exactly once after both enqueues fail', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      await rt.notifications.createNotificationRule(CTX, {
        channel: 'in_app',
        triggers: ['safe_test.completed', 'finding.high_severity'],
      });
      await seedVerdictedRun(pool);

      // Real publication repairs the verdict into a high finding and fires the terminal hook; both
      // separate outbox transactions fail after the verdict/finding commit.
      rt.faults.remaining = 2;
      await rt.validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN);
      let ledger = await readLedger(pool);
      assert.equal(ledger.events.length, 0, 'both lifecycle enqueues were lost');

      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(tick.reconciliation.by_trigger['safe_test.completed'].reconciled, 1);
      assert.equal(tick.reconciliation.by_trigger['finding.high_severity'].reconciled, 1);

      ledger = await readLedger(pool);
      const keys = ledger.events.map((e) => e.dedupe_key).sort();
      assert.equal(keys.length, 2);
      assert.equal(keys[1], `safe_test.completed:run:${RUN}`);
      assert.match(keys[0], new RegExp(`^finding\\.high_severity:finding:.+:verdict:${VERDICT}$`));
      const alert = ledger.events.find((e) => e.trigger === 'finding.high_severity');
      assert.equal(alert.metadata_json.verdict_id, VERDICT);
      assert.equal(alert.metadata_json.test_run_id, RUN);
      const completion = ledger.events.find((e) => e.trigger === 'safe_test.completed');
      assert.equal(completion.metadata_json.run_id, RUN);

      // Repeat reconciliation and a late replay of the live hook: still one event per identity.
      await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      await rt.validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN);
      ledger = await readLedger(pool);
      assert.equal(ledger.events.length, 2);
      assert.ok(ledger.attempts.every((a) => a.status === 'delivered_in_app'));
    });
  });

  it('collapses concurrent reconciliation passes from two instances to one event per identity', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const a = buildRuntime(pool, { failEnqueue: 1 });
      const b = buildRuntime(pool);
      await a.notifications.createNotificationRule(CTX, {
        channel: 'in_app',
        triggers: ['report.ready', 'safe_test.completed', 'finding.high_severity'],
      });
      await a.reports.createReport(CTX, { title: 'Concurrent' });
      await seedVerdictedRun(pool);
      a.faults.remaining = 2;
      await a.validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN);
      assert.equal((await readLedger(pool)).events.length, 0);

      const asOf = futureAsOf();
      const [ra, rb] = await Promise.all([
        a.notifications.processDueNotificationRetries(SYSTEM, { asOf }),
        b.notifications.processDueNotificationRetries(SYSTEM, { asOf }),
      ]);
      assert.equal(ra.reconciliation.failed_count + rb.reconciliation.failed_count, 0);
      assert.equal(ra.reconciliation.reconciled_count + rb.reconciliation.reconciled_count, 3);

      const ledger = await readLedger(pool);
      assert.equal(ledger.events.length, 3);
      assert.equal(new Set(ledger.events.map((e) => e.dedupe_key)).size, 3);
      assert.equal(ledger.attempts.length, 3);
    });
  });

  it('never back-fills records that predate the subscribing rule, and dry run writes nothing', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      // Report created with no subscriber at all.
      await rt.reports.createReport(CTX, { title: 'Before subscription' });
      await new Promise((resolve) => setTimeout(resolve, 20));
      await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(tick.reconciliation.missing_count, 0);
      assert.equal((await readLedger(pool)).events.length, 0);

      // A report owed under the rule: a dry-run pass reports it but writes nothing.
      const reconcile = createNotificationOutboxReconciler({
        repository: createNotificationReconciliationRepository(pool),
        notifications: rt.notifications,
        graceMs: 0,
      });
      const { reports: crashed } = createPostgresReportServices({
        reports: createReportRepository(pool),
        validationEvidence: createValidationEvidenceRepository(pool),
        audit: rt.audit,
      });
      await crashed.createReport(CTX, { title: 'Owed' });
      const dry = await reconcile(SYSTEM, { asOf: futureAsOf(), dryRun: true });
      assert.equal(dry.missing_count, 1);
      assert.equal(dry.reconciled_count, 0);
      assert.equal((await readLedger(pool)).events.length, 0);
      const real = await reconcile(SYSTEM, { asOf: futureAsOf() });
      assert.equal(real.reconciled_count, 1);
      assert.equal((await readLedger(pool)).events.length, 1);
    });
  });
});
