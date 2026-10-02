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
  createNotificationReconciliationRepository,
  registerPostgresNotificationReconciliation,
} from '../../src/persistence/postgres/notificationReconciliation.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

/**
 * Reconciliation eligibility (R01/R03 review follow-ups): reconciliation must only send what the
 * live emitter would have sent when the domain record committed.
 */

const TENANT = 'ten_notify_reconcile_elig';
const GROUP = 'tg_notify_reconcile_elig';
const TARGET = 'tgt_notify_reconcile_elig';
const CHECK = 'origin.direct_bypass.safe';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const SYSTEM = { tenantId: TENANT, userId: 'notification-retry-scheduler', role: 'system' };
const WEBHOOK_DESTINATION = 'https://hooks.example.invalid/reconcile';

const futureAsOf = (minutes = 5) => new Date(Date.now() + minutes * 60_000).toISOString();
const pause = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms));

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'reconcile eligibility tenant')`, [TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'eligibility group')`,
      [GROUP, TENANT],
    );
    await client.query(
      `INSERT INTO targets (
         id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior
       ) VALUES ($1, $2, $3, 'ip', '203.0.113.42', '203.0.113.42', 'must_block_before_origin')`,
      [TARGET, TENANT, GROUP],
    );
  });
}

/** A verdicted run plus its committed verdict at `at`. */
async function seedVerdictedRun(pool, { runId, verdictId, verdict, at }) {
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
         jsonb_build_object('nonce_hash', $7::text, 'window_ms', 120000),
         $6::timestamptz, $6::timestamptz, $6::timestamptz, $6::timestamptz
       )`,
      [runId, TENANT, GROUP, TARGET, CHECK, at, `nonce_${runId}`],
    );
    await client.query(
      `INSERT INTO events (
         id, tenant_id, test_run_id, target_id, check_id, agent_id, source,
         signal_type, producer_kind, nonce_hash, timestamp, metadata_json
       ) VALUES ($1, $2, $3, $4, $5, NULL, 'probe_worker', 'probe_result',
                 'signed_probe', $6, $7::timestamptz, '{"external_result":"connected"}'::jsonb)`,
      [`evt_${runId}`, TENANT, runId, TARGET, CHECK, `nonce_${runId}`, at],
    );
    await client.query(
      `INSERT INTO verdicts (
         id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
         placement_confidence_json, explanation, evidence_ids, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, 'high', '{}'::jsonb,
                 'seeded verdict', ARRAY[$7]::text[], $8::timestamptz)`,
      [verdictId, TENANT, runId, TARGET, CHECK, verdict, `evt_${runId}`, at],
    );
  });
}

async function seedFinding(pool, { id, severity, verdictId, lastVerdictId, runId, at, checkId = CHECK }) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO findings (
         id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
         status, verdict_id, last_verdict_id, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open', $9, $10, $11::timestamptz)`,
      [id, TENANT, GROUP, TARGET, runId, checkId, `Finding ${id}`, severity, verdictId, lastVerdictId, at],
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
      `SELECT notification_event_id, rule_id, status, reason, superseded_at, lease_expires_at
       FROM notification_delivery_attempts WHERE tenant_id = $1 ORDER BY created_at, id`,
      [TENANT],
    );
    return { events: events.rows, attempts: attempts.rows };
  });
}

/** Production-shaped wiring (mirrors runtime.mjs) with mocked senders only. */
function buildRuntime(pool, serviceOptions = {}) {
  const notificationRepo = createNotificationRepository(pool);
  const audit = createAuditRepository(pool);
  const validationEvidence = createValidationEvidenceRepository(pool);
  const notifications = createPostgresNotificationServices(
    { notifications: notificationRepo, audit },
    serviceOptions,
  );
  registerPostgresNotificationReconciliation({ pool, notifications, audit });
  const { reports } = createPostgresReportServices(
    { reports: createReportRepository(pool), validationEvidence, audit, notifications: notificationRepo },
    { notifications },
  );
  // "Crash": commits the report only, never reaching the notification emitter.
  const { reports: crashedReports } = createPostgresReportServices({
    reports: createReportRepository(pool),
    validationEvidence,
    audit,
  });
  return { notifications, reports, crashedReports };
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

describe('postgres notification reconciliation eligibility', () => {
  it('does not back-fill reports created while the rule was paused once it is re-enabled', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      const rule = await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      await pause();
      await rt.notifications.updateNotificationRule(CTX, rule.id, { enabled: false });
      await pause();
      for (let i = 0; i < 3; i += 1) await rt.reports.createReport(CTX, { title: `Paused ${i}` });
      assert.equal((await readLedger(pool)).events.length, 0, 'live emitter sends nothing while off');

      const whileOff = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(whileOff.reconciliation.missing_count, 0);

      await pause();
      await rt.notifications.updateNotificationRule(CTX, rule.id, { enabled: true });
      const afterOn = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(afterOn.reconciliation.missing_count, 0);
      assert.equal(afterOn.reconciliation.reconciled_count, 0);
      const ledger = await readLedger(pool);
      assert.equal(ledger.events.length, 0, 'nothing owed for the paused period');
      assert.equal(ledger.attempts.length, 0);

      // A report committed after re-enable (and lost by a crash) is still recovered.
      await pause();
      const owed = await rt.crashedReports.createReport(CTX, { title: 'After re-enable' });
      const recovered = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(recovered.reconciliation.reconciled_count, 1);
      assert.deepEqual((await readLedger(pool)).events.map((e) => e.dedupe_key), [`report.ready:report:${owed.id}`]);
    });
  });

  it('does not back-fill reports created before the rule subscribed to the trigger', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      const rule = await rt.notifications.createNotificationRule(CTX, {
        channel: 'in_app',
        triggers: ['finding.high_severity'],
      });
      await pause();
      for (let i = 0; i < 3; i += 1) await rt.reports.createReport(CTX, { title: `Unsubscribed ${i}` });
      await pause();
      await rt.notifications.updateNotificationRule(CTX, rule.id, {
        triggers: ['finding.high_severity', 'report.ready'],
      });

      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(tick.reconciliation.missing_count, 0);
      assert.equal(tick.reconciliation.reconciled_count, 0);
      assert.equal((await readLedger(pool)).events.length, 0);
    });
  });

  it('does not alert for a finding created medium and later escalated to high by another run', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['finding.high_severity'] });
      await pause();
      const t1 = new Date(Date.now()).toISOString();
      await seedVerdictedRun(pool, { runId: 'run_elig_1', verdictId: 'v_elig_1', verdict: 'edge_exposed', at: t1 });
      await seedVerdictedRun(pool, { runId: 'run_elig_2', verdictId: 'v_elig_2', verdict: 'bypassable', at: t1 });
      // Shape upsertOpenFindingFromVerdict produces when v2 advances a medium finding from v1.
      await seedFinding(pool, {
        id: 'f_escalated', severity: 'high', verdictId: 'v_elig_1', lastVerdictId: 'v_elig_2', runId: 'run_elig_2', at: t1,
      });
      // Control: a finding created high by its own verdict is still owed.
      await seedFinding(pool, {
        id: 'f_created_high', severity: 'high', verdictId: 'v_elig_2', lastVerdictId: 'v_elig_2', runId: 'run_elig_2', at: t1,
        checkId: 'origin.control.safe', // one open finding per target/check
      });

      const repo = createNotificationReconciliationRepository(pool);
      const rows = await repo.listUnnotifiedHighSeverityFindings(SYSTEM, {
        from: new Date(Date.now() - 60 * 60_000).toISOString(),
        to: futureAsOf(),
        limit: 50,
      });
      assert.deepEqual(rows.map((r) => r.id), ['f_created_high']);
      assert.equal(rows[0].test_run_id, 'run_elig_2');

      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(tick.reconciliation.by_trigger['finding.high_severity'].reconciled, 1);
      const alerts = (await readLedger(pool)).events.filter((e) => e.trigger === 'finding.high_severity');
      assert.deepEqual(alerts.map((e) => e.metadata_json.finding_id), ['f_created_high']);
    });
  });

  it('addresses a reconciled event only to rules subscribed when the record committed', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const rt = buildRuntime(pool);
      const ruleA = await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      await pause();
      const report = await rt.crashedReports.createReport(CTX, { title: 'Before rule B' });
      await pause();
      const ruleB = await rt.notifications.createNotificationRule(CTX, { channel: 'in_app', triggers: ['report.ready'] });
      assert.notEqual(ruleA.id, ruleB.id);

      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, { asOf: futureAsOf() });
      assert.equal(tick.reconciliation.reconciled_count, 1);
      const ledger = await readLedger(pool);
      assert.deepEqual(ledger.events.map((e) => e.dedupe_key), [`report.ready:report:${report.id}`]);
      assert.deepEqual(ledger.attempts.map((a) => a.rule_id), [ruleA.id]);
    });
  });

  it('delivers reconciled provider sends inside the tick, not on the in-process worker (one-shot runners)', { timeout: 120_000 }, async (t) => {
    await withHarness(t, async (pool) => {
      const sends = [];
      let inFlight = 0;
      const webhookSender = async (_destination, body) => {
        inFlight += 1;
        await pause(200);
        sends.push(body.event_id);
        inFlight -= 1;
        return { ok: true, status: 202 };
      };
      const rt = buildRuntime(pool, { deliveryMode: 'webhook', webhookSender });
      await rt.notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: WEBHOOK_DESTINATION,
        triggers: ['report.ready'],
      });
      await pause();
      await rt.crashedReports.createReport(CTX, { title: 'Owed webhook' });

      const tick = await rt.notifications.processDueNotificationRetries(SYSTEM, {
        deliveryMode: 'webhook', webhookSender, asOf: futureAsOf(),
      });
      assert.equal(tick.reconciliation.reconciled_count, 1);
      // The send already finished when the tick returned: a runner may close its pool now.
      assert.equal(inFlight, 0, 'no background send is left running after the tick');
      assert.equal(sends.length, 1);
      assert.equal(tick.network_sends_performed, 1);

      const ledger = await readLedger(pool);
      assert.equal(ledger.events.length, 1);
      const latest = ledger.attempts.at(-1);
      assert.equal(latest.status, 'delivered_provider');
      assert.ok(
        ledger.attempts.every((a) => a.status !== 'provider_retry_scheduled' || a.superseded_at),
        'no pending claimed attempt is left behind',
      );

      // Later ticks (past any lease) never resend it.
      await rt.notifications.drainNotificationOutbox();
      const later = await rt.notifications.processDueNotificationRetries(SYSTEM, {
        deliveryMode: 'webhook', webhookSender, asOf: futureAsOf(60),
      });
      assert.equal(later.network_sends_performed ?? 0, 0);
      assert.equal(sends.length, 1);
    });
  });
});
