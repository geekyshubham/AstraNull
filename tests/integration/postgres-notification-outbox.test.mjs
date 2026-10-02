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
  OUTBOX_PENDING_REASON,
  createPostgresNotificationServices,
  registerPostgresRunNotificationHook,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_notify_outbox';
const GROUP = 'tg_notify_outbox';
const TARGET = 'tgt_notify_outbox';
const CHECK = 'origin.direct_bypass.safe';
const RUN = 'run_notify_outbox';
const VERDICT = 'verdict_notify_outbox';
const CTX = { tenantId: TENANT, userId: 'usr_admin', role: 'admin' };
const CREATED_AT = '2026-01-01T00:00:00.000Z';

async function seed(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'notification outbox tenant')`, [TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'outbox group')`,
      [GROUP, TENANT],
    );
    await client.query(
      `INSERT INTO targets (
         id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior
       ) VALUES ($1, $2, $3, 'ip', '203.0.113.40', '203.0.113.40', 'must_block_before_origin')`,
      [TARGET, TENANT, GROUP],
    );
    await client.query(
      `INSERT INTO test_runs (
         id, tenant_id, target_group_id, target_id, check_id, status,
         probe_external_result, awaiting_external_probe, remediation_template,
         safety_constraints, correlation_json, collection_deadline_at,
         started_at, completed_at, created_at
       ) VALUES (
         $1, $2, $3, $4, $5, 'verdicted', 'connected', FALSE, 'block_origin',
         '{"max_events":50}'::jsonb,
         jsonb_build_object('nonce_hash', 'nonce_outbox', 'window_ms', 120000),
         $6::timestamptz, $6::timestamptz, $6::timestamptz, $6::timestamptz
       )`,
      [RUN, TENANT, GROUP, TARGET, CHECK, CREATED_AT],
    );
    await client.query(
      `INSERT INTO events (
         id, tenant_id, test_run_id, target_id, check_id, agent_id, source,
         signal_type, producer_kind, nonce_hash, timestamp, metadata_json
       ) VALUES ('evt_probe_outbox', $1, $2, $3, $4, NULL, 'probe_worker', 'probe_result',
                 'signed_probe', 'nonce_outbox', $5::timestamptz, '{"external_result":"connected"}'::jsonb)`,
      [TENANT, RUN, TARGET, CHECK, CREATED_AT],
    );
    await client.query(
      `INSERT INTO verdicts (
         id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
         placement_confidence_json, explanation, evidence_ids, created_at
       ) VALUES ($1, $2, $3, $4, $5, 'bypassable', 'high', '{}'::jsonb,
                 'origin reachable directly', ARRAY['evt_probe_outbox']::text[], $6::timestamptz)`,
      [VERDICT, TENANT, RUN, TARGET, CHECK, CREATED_AT],
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
      `SELECT id, notification_event_id, rule_id, status, reason, attempt_number
       FROM notification_delivery_attempts
       WHERE tenant_id = $1 ORDER BY created_at, COALESCE(attempt_number, 0), id`,
      [TENANT],
    );
    const audits = await client.query(
      `SELECT action, resource_id FROM audit_logs
       WHERE tenant_id = $1 AND action LIKE 'notification.%' ORDER BY sequence`,
      [TENANT],
    );
    return { events: events.rows, attempts: attempts.rows, audits: audits.rows };
  });
}

function buildRuntime(pool, notificationOptions = {}) {
  const validationEvidence = createValidationEvidenceRepository(pool);
  const audit = createAuditRepository(pool);
  const notificationRepo = createNotificationRepository(pool);
  const validation = createPostgresValidationServices({
    validationEvidence,
    audit,
    coreCatalog: createCoreCatalogRepository(pool),
    probeJobs: createProbeJobRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
  });
  const notifications = createPostgresNotificationServices(
    { notifications: notificationRepo, audit },
    notificationOptions,
  );
  registerPostgresRunNotificationHook({
    testRuns: validation.testRuns,
    notifications,
    notificationRules: notificationRepo,
    validationEvidence,
  });
  const { reports } = createPostgresReportServices(
    { reports: createReportRepository(pool), validationEvidence, audit, notifications: notificationRepo },
    { notifications },
  );
  return { validation, notifications, reports };
}

describe('postgres notification outbox (real publication -> persisted events/attempts)', () => {
  it('enqueues completion and the high-severity alert once, durably, before delivery', { timeout: 120_000 }, async (t) => {
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
      const instanceA = buildRuntime(pool, {
        deliveryMode: 'webhook',
        webhookSender: async (destination, body) => {
          sends.push(body.trigger);
          await stalled;
          return { ok: true, status: 202 };
        },
      });
      // Second API instance sharing the database (no shared process memory).
      const instanceB = buildRuntime(pool, { deliveryMode: 'webhook', webhookSender: async () => ({ ok: true, status: 202 }) });

      const rule = await instanceA.notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/outbox',
        triggers: ['safe_test.completed', 'finding.high_severity', 'report.ready'],
      });
      assert.ok(rule.id);

      // Real publication: repairs the verdict into a high finding, then fires the terminal hook.
      const started = Date.now();
      await Promise.all([
        instanceA.validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN),
        instanceB.validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN),
      ]);
      await instanceA.validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN);
      assert.ok(Date.now() - started < 20_000, 'finalization must not wait on a stalled provider');

      let ledger = await readLedger(pool);
      const triggers = ledger.events.map((e) => e.trigger).sort();
      assert.deepEqual(triggers, ['finding.high_severity', 'safe_test.completed']);
      const alert = ledger.events.find((e) => e.trigger === 'finding.high_severity');
      assert.equal(alert.metadata_json.verdict_id, VERDICT);
      assert.equal(alert.metadata_json.test_run_id, RUN);
      assert.match(alert.dedupe_key, new RegExp(`:verdict:${VERDICT}$`));
      const completion = ledger.events.find((e) => e.trigger === 'safe_test.completed');
      assert.equal(completion.dedupe_key, `safe_test.completed:run:${RUN}`);
      // One pending attempt per event recorded before any send completed.
      for (const event of ledger.events) {
        const first = ledger.attempts.find((a) => a.notification_event_id === event.id);
        assert.equal(first.reason, OUTBOX_PENDING_REASON);
        assert.equal(first.attempt_number, 0);
      }
      assert.equal(
        ledger.audits.filter((a) => a.action === 'notification.event_emitted').length,
        2,
      );

      release();
      await instanceA.notifications.drainNotificationOutbox();
      await instanceB.notifications.drainNotificationOutbox();

      ledger = await readLedger(pool);
      for (const event of ledger.events) {
        const eventAttempts = ledger.attempts.filter((a) => a.notification_event_id === event.id);
        assert.equal(eventAttempts.at(-1).status, 'delivered_provider', event.trigger);
        assert.equal(eventAttempts.at(-1).attempt_number, 1);
        // Exactly one delivery per identity even with two instances racing.
        assert.equal(eventAttempts.filter((a) => a.status === 'delivered_provider').length, 1);
      }

      // report.ready via real report creation, durably recorded once per report id.
      const report = await instanceB.reports.createReport(CTX, { title: 'Weekly outbox' });
      await instanceB.notifications.drainNotificationOutbox();
      ledger = await readLedger(pool);
      const ready = ledger.events.filter((e) => e.trigger === 'report.ready');
      assert.equal(ready.length, 1);
      assert.equal(ready[0].metadata_json.report_id, report.id);
      assert.equal(ready[0].dedupe_key, `report.ready:report:${report.id}`);
      const readyAttempts = ledger.attempts.filter((a) => a.notification_event_id === ready[0].id);
      assert.equal(readyAttempts.at(-1).status, 'delivered_provider');
    });
  });

  it('records the event on replay after the first enqueue fails', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const notificationRepo = createNotificationRepository(pool);
      const realEnqueue = notificationRepo.enqueueNotificationEvent;
      let failures = 1;
      notificationRepo.enqueueNotificationEvent = async (...args) => {
        if (failures > 0) {
          failures -= 1;
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
      await notifications.createNotificationRule(CTX, {
        channel: 'in_app',
        triggers: ['safe_test.completed', 'finding.high_severity'],
      });

      await validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN);
      let ledger = await readLedger(pool);
      // Completion failed; the isolated high-severity alert still landed.
      assert.deepEqual(ledger.events.map((e) => e.trigger), ['finding.high_severity']);

      await validation.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, RUN);
      ledger = await readLedger(pool);
      assert.deepEqual(
        ledger.events.map((e) => e.trigger).sort(),
        ['finding.high_severity', 'safe_test.completed'],
      );
      assert.ok(ledger.attempts.every((a) => a.status === 'delivered_in_app'));
    });
  });

  it('holds retries and DLQ redrive for a turned-off rule, resumes on re-enable, cancels on delete (R01)', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const notificationRepo = createNotificationRepository(pool);
      // Hold the outbox worker's pre-send rule read until the operator change has committed, so
      // the test exercises "rule changed before the send" deterministically.
      const realRuleState = notificationRepo.getNotificationRuleDeliveryState;
      let ruleReadBarrier = null;
      const holdRuleReads = () => {
        let release;
        ruleReadBarrier = new Promise((resolve) => { release = resolve; });
        return () => { ruleReadBarrier = null; release(); };
      };
      notificationRepo.getNotificationRuleDeliveryState = async (...args) => {
        if (ruleReadBarrier) await ruleReadBarrier;
        return realRuleState(...args);
      };
      const audit = createAuditRepository(pool);
      let clock = new Date(CREATED_AT);
      const sends = [];
      let failSends = false;
      const webhookSender = async (_destination, body) => {
        sends.push(body.event_id);
        return failSends ? { ok: false, error: 'webhook_http_error' } : { ok: true, status: 202 };
      };
      const notifications = createPostgresNotificationServices(
        { notifications: notificationRepo, audit },
        { deliveryMode: 'webhook', webhookSender, now: () => clock, outboxMaxQueue: 1 },
      );
      const retry = (asOf) => notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook',
        webhookSender,
        asOf,
      });
      const latestFor = async (eventId) => {
        const ledger = await readLedger(pool);
        return ledger.attempts.filter((a) => a.notification_event_id === eventId).at(-1);
      };
      const later = (minutes) => new Date(clock.getTime() + minutes * 60_000).toISOString();

      // 1. Enqueue -> turn off before the in-process worker runs -> worker and retry send nothing.
      const rule = await notifications.createNotificationRule(CTX, {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/r01',
        triggers: ['report.ready'],
      });
      let releaseRuleReads = holdRuleReads();
      const enqueued = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'R01 held',
        metadata: { report_id: 'rpt_r01' },
        dedupeKey: 'report.ready:report:rpt_r01',
      });
      assert.equal(enqueued.inserted, true);
      await notifications.updateNotificationRule(CTX, rule.id, { enabled: false });
      releaseRuleReads();
      await notifications.drainNotificationOutbox();
      assert.equal(sends.length, 0, 'outbox worker must not send for a turned-off rule');

      const held = await retry(later(10));
      assert.equal(held.due_count, 1);
      assert.equal(held.held_count, 1);
      assert.equal(held.network_sends_performed, 0);
      assert.equal(sends.length, 0, 'retry must not send for a turned-off rule');
      let latest = await latestFor(enqueued.event.id);
      assert.equal(latest.status, 'provider_retry_scheduled', 'held attempt stays pending');
      assert.equal(latest.attempt_number, 0, 'held attempt budget is not burned');

      // 2. Re-enable -> next retry delivers exactly once.
      await notifications.updateNotificationRule(CTX, rule.id, { enabled: true });
      const resumed = await retry(later(11));
      assert.equal(resumed.network_sends_performed, 1);
      assert.deepEqual(sends, [enqueued.event.id]);
      latest = await latestFor(enqueued.event.id);
      assert.equal(latest.status, 'delivered_provider');
      await retry(later(20));
      assert.equal(sends.length, 1, 'delivered exactly once');

      // 3. Enqueue/fail into the DLQ -> turn off -> redrive sends nothing and leaves the DLQ row.
      sends.length = 0;
      failSends = true;
      const failing = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'R01 dlq',
        metadata: { report_id: 'rpt_r01_dlq' },
        dedupeKey: 'report.ready:report:rpt_r01_dlq',
      });
      await notifications.drainNotificationOutbox();
      await retry(later(30));
      await retry(later(40));
      latest = await latestFor(failing.event.id);
      assert.equal(latest.status, 'provider_failed_dlq');
      const dlqAttemptId = latest.id;
      sends.length = 0;
      failSends = false;

      await notifications.updateNotificationRule(CTX, rule.id, { enabled: false });
      const prevEnv = process.env.NODE_ENV;
      const prevMode = process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
      process.env.NODE_ENV = 'staging';
      process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = 'webhook';
      try {
        const redrive = (now) => notifications.redriveNotificationDlq(CTX, {
          attemptIds: [dlqAttemptId],
          forceMetadataOnly: false,
          webhookSender,
          now,
        });
        const heldRedrive = await redrive(later(50));
        assert.equal(heldRedrive.delivery_mode, 'webhook', 'redrive ran in provider mode');
        assert.equal(heldRedrive.held_count, 1);
        assert.equal(heldRedrive.requeued_count, 0);
        assert.equal(heldRedrive.network_sends_performed, 0);
        assert.equal(sends.length, 0, 'redrive must not send for a turned-off rule');
        latest = await latestFor(failing.event.id);
        assert.equal(latest.id, dlqAttemptId, 'held DLQ row is untouched');

        // Re-enable -> redrive delivers exactly once.
        await notifications.updateNotificationRule(CTX, rule.id, { enabled: true });
        const resumedRedrive = await redrive(later(51));
        assert.equal(resumedRedrive.network_sends_performed, 1);
        assert.deepEqual(sends, [failing.event.id]);
        assert.equal((await latestFor(failing.event.id)).status, 'delivered_provider');
      } finally {
        process.env.NODE_ENV = prevEnv;
        if (prevMode === undefined) delete process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE;
        else process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE = prevMode;
      }

      // 4. Enqueue -> delete -> pending work is cancelled with a non-sent terminal attempt.
      sends.length = 0;
      releaseRuleReads = holdRuleReads();
      const doomed = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready',
        subject: 'R01 deleted',
        metadata: { report_id: 'rpt_r01_del' },
        dedupeKey: 'report.ready:report:rpt_r01_del',
      });
      await notifications.deleteNotificationRule(CTX, rule.id);
      releaseRuleReads();
      await notifications.drainNotificationOutbox();
      const afterDelete = await retry(later(60));
      assert.equal(afterDelete.network_sends_performed, 0);
      assert.equal(sends.length, 0, 'deleted rule is never sent to');
      latest = await latestFor(doomed.event.id);
      assert.equal(latest.status, 'cancelled_rule_removed');
      assert.equal(latest.reason, 'rule_removed');
      // Terminal: later ticks find nothing due.
      const quiet = await retry(later(120));
      assert.equal(quiet.due_count, 0);
      assert.equal(sends.length, 0);

      const ledger = await readLedger(pool);
      const cancelAudits = ledger.audits.filter((a) => a.action === 'notification.delivery_attempt_recorded'
        && a.resource_id === latest.id);
      assert.equal(cancelAudits.length, 1, 'cancellation is audited');
    });
  });
});

/**
 * Insert `count` events for one rule, each with a single attempt. `pending` rows are due outbox
 * attempts (next_retry_at = dueStart + g seconds, so due order follows g); others are delivered.
 */
async function insertBulkLedger(pool, { prefix, count, ruleId, createdStart, pending, dueStart }) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO notification_events (id, tenant_id, trigger, subject, metadata_json, created_at)
       SELECT $2 || lpad(g::text, 5, '0'), $1, 'report.ready', 'bulk ' || g::text,
              jsonb_build_object('report_id', $2 || g::text),
              $3::timestamptz + g * interval '1 second'
       FROM generate_series(1, $4::int) g`,
      [TENANT, prefix, createdStart, count],
    );
    await client.query(
      `INSERT INTO notification_delivery_attempts (
         id, tenant_id, notification_event_id, rule_id, channel, destination_preview, status, reason,
         attempt_number, max_attempts, next_retry_at, exhausted, created_at, attempted_at
       )
       SELECT $2 || lpad(g::text, 5, '0') || '_att', $1, $2 || lpad(g::text, 5, '0'), $5, 'webhook',
              'webhook:hooks.example.invalid',
              CASE WHEN $6::boolean THEN 'provider_retry_scheduled' ELSE 'delivered_provider' END,
              CASE WHEN $6::boolean THEN $8 ELSE 'webhook_delivered' END,
              CASE WHEN $6::boolean THEN 0 ELSE 1 END, 3,
              CASE WHEN $6::boolean THEN $7::timestamptz + g * interval '1 second' ELSE NULL END,
              FALSE,
              $3::timestamptz + g * interval '1 second',
              CASE WHEN $6::boolean THEN NULL ELSE $3::timestamptz + g * interval '1 second' END
       FROM generate_series(1, $4::int) g`,
      [TENANT, prefix, createdStart, count, ruleId, pending === true, dueStart ?? createdStart, OUTBOX_PENDING_REASON],
    );
  });
}

function eventId(prefix, g) {
  return `${prefix}${String(g).padStart(5, '0')}`;
}

async function deliveredCountsByEvent(pool) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT notification_event_id AS id, COUNT(*)::int AS delivered
       FROM notification_delivery_attempts
       WHERE tenant_id = $1 AND status = 'delivered_provider'
       GROUP BY notification_event_id`,
      [TENANT],
    );
    return new Map(rows.map((r) => [r.id, r.delivered]));
  });
}

async function webhookRuntime(pool, serviceOptions = {}) {
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
    destination: 'https://hooks.example.invalid/recovery',
    triggers: ['report.ready'],
  });
  assert.ok(rule.id);
  return rule;
}

const minutesFromNow = (minutes) => new Date(Date.now() + minutes * 60_000).toISOString();

describe('postgres notification recovery and delivery claims (R02/R04)', () => {
  it('recovers a due pending attempt behind 500+ newer events (R02)', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const { notifications, sends, webhookSender } = await webhookRuntime(pool);
      const rule = await createWebhookRule(notifications);
      await insertBulkLedger(pool, {
        prefix: 'nevt_old_', count: 1, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z', pending: true,
      });
      await insertBulkLedger(pool, {
        prefix: 'nevt_new_', count: 520, ruleId: rule.id, createdStart: '2026-01-02T00:00:00.000Z', pending: false,
      });

      const tick = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(0),
      });
      assert.equal(tick.due_count, 1);
      assert.equal(tick.network_sends_performed, 1);
      assert.deepEqual(sends, [eventId('nevt_old_', 1)]);
      const ledger = await readLedger(pool);
      const latest = ledger.attempts.filter((a) => a.notification_event_id === eventId('nevt_old_', 1)).at(-1);
      assert.equal(latest.status, 'delivered_provider');

      const quiet = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(10),
      });
      assert.equal(quiet.due_count, 0);
      assert.equal(sends.length, 1);
    });
  });

  it('drains a multi-page backlog oldest-first within a per-tick budget, and recovers queue overflow (R02)', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const { notifications, sends, webhookSender } = await webhookRuntime(pool);
      const rule = await createWebhookRule(notifications);
      const total = 250;
      await insertBulkLedger(pool, {
        prefix: 'nevt_bk_', count: total, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z',
        pending: true, dueStart: '2026-01-01T00:05:00.000Z',
      });
      // Newer delivered events must not crowd out the backlog.
      await insertBulkLedger(pool, {
        prefix: 'nevt_dn_', count: 600, ruleId: rule.id, createdStart: '2026-02-01T00:00:00.000Z', pending: false,
      });

      const tickOptions = { deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(0), pageSize: 40, maxItems: 100 };
      const first = await notifications.processDueNotificationRetries(CTX, tickOptions);
      assert.equal(first.network_sends_performed, 100);
      assert.equal(first.budget_exhausted, true);
      assert.equal(first.pages_read, 3, '40 + 40 + 20 within the budget');
      assert.deepEqual(sends, Array.from({ length: 100 }, (_, i) => eventId('nevt_bk_', i + 1)), 'oldest due first');

      const second = await notifications.processDueNotificationRetries(CTX, tickOptions);
      assert.equal(second.network_sends_performed, 100);
      assert.equal(sends[100], eventId('nevt_bk_', 101), 'next tick advances past drained work');
      const third = await notifications.processDueNotificationRetries(CTX, tickOptions);
      assert.equal(third.network_sends_performed, 50);
      assert.equal(third.budget_exhausted, false);
      const drained = await notifications.processDueNotificationRetries(CTX, tickOptions);
      assert.equal(drained.due_count, 0);

      assert.equal(sends.length, total);
      assert.equal(new Set(sends).size, total, 'each backlog attempt sent exactly once');
      const delivered = await deliveredCountsByEvent(pool);
      for (let g = 1; g <= total; g += 1) assert.equal(delivered.get(eventId('nevt_bk_', g)), 1);

      // Queue overflow: jobs the in-process worker dropped stay durable and are recovered once.
      let release;
      const stalled = new Promise((resolve) => { release = resolve; });
      const overflowSends = [];
      const overflowSender = async (_destination, body) => {
        overflowSends.push(body.event_id);
        await stalled;
        return { ok: true, status: 202 };
      };
      const overflow = await webhookRuntime(pool, {
        webhookSender: overflowSender, outboxConcurrency: 1, outboxMaxQueue: 1,
      });
      const enqueued = [];
      for (let i = 0; i < 5; i += 1) {
        enqueued.push(await overflow.notifications.enqueueNotification(CTX, {
          trigger: 'report.ready',
          subject: `overflow ${i}`,
          metadata: { report_id: `rpt_overflow_${i}` },
          dedupeKey: `report.ready:report:rpt_overflow_${i}`,
        }));
      }
      assert.deepEqual(enqueued.map((e) => e.scheduled), [1, 1, 0, 0, 0], 'queue of 1 drops the rest');
      release();
      await overflow.notifications.drainNotificationOutbox();
      assert.equal(overflowSends.length, 2);
      const recovered = await overflow.notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender: overflowSender, asOf: minutesFromNow(10),
      });
      assert.equal(recovered.network_sends_performed, 3);
      assert.equal(new Set(overflowSends).size, 5);
      assert.equal(overflowSends.length, 5, 'every overflow event sent exactly once');
    });
  });

  it('never double-sends while the background worker is mid-send or still queued past the grace (R04)', { timeout: 120_000 }, async (t) => {
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
        await stalled;
        return { ok: true, status: 202 };
      };
      const { notifications } = await webhookRuntime(pool, { webhookSender, outboxConcurrency: 1 });
      await createWebhookRule(notifications);

      const blocked = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready', subject: 'blocked mid-send', metadata: { report_id: 'rpt_r04_a' },
        dedupeKey: 'report.ready:report:rpt_r04_a',
      });
      const queued = await notifications.enqueueNotification(CTX, {
        trigger: 'report.ready', subject: 'queued behind', metadata: { report_id: 'rpt_r04_b' },
        dedupeKey: 'report.ready:report:rpt_r04_b',
      });
      for (let i = 0; i < 200 && sends.length === 0; i += 1) await new Promise((r) => setTimeout(r, 10));
      assert.deepEqual(sends, [blocked.event.id], 'background worker is mid-send on the first event');

      // Recovery after the grace: the claimed (leased) attempt is skipped; the still-queued one is
      // claimed and sent by recovery instead.
      const recoverySends = [];
      const tick = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook',
        webhookSender: async (_destination, body) => {
          recoverySends.push(body.event_id);
          return { ok: true, status: 202 };
        },
        asOf: minutesFromNow(10),
      });
      assert.equal(tick.in_flight_count, 1);
      assert.deepEqual(recoverySends, [queued.event.id]);

      release();
      await notifications.drainNotificationOutbox();
      // The worker reached the queued job after recovery delivered it: its claim is lost, no send.
      assert.deepEqual(sends, [blocked.event.id]);
      const delivered = await deliveredCountsByEvent(pool);
      assert.equal(delivered.get(blocked.event.id), 1);
      assert.equal(delivered.get(queued.event.id), 1);

      const quiet = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(20),
      });
      assert.equal(quiet.due_count, 0);
      assert.equal(sends.length + recoverySends.length, 2, 'exactly one send per attempt');
    });
  });

  it('two concurrent recovery instances send each due attempt once (R04)', { timeout: 120_000 }, async (t) => {
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
        await new Promise((r) => setTimeout(r, 2));
        return { ok: true, status: 202 };
      };
      const a = await webhookRuntime(pool, { webhookSender });
      const b = await webhookRuntime(pool, { webhookSender });
      const rule = await createWebhookRule(a.notifications);
      const total = 40;
      await insertBulkLedger(pool, {
        prefix: 'nevt_cc_', count: total, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z', pending: true,
      });

      const tickOptions = { deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(0), pageSize: 10 };
      const [ra, rb] = await Promise.all([
        a.notifications.processDueNotificationRetries(CTX, tickOptions),
        b.notifications.processDueNotificationRetries(CTX, tickOptions),
      ]);
      assert.equal(ra.network_sends_performed + rb.network_sends_performed, total);
      assert.equal(sends.length, total);
      assert.equal(new Set(sends).size, total, 'no attempt sent by both instances');
      const delivered = await deliveredCountsByEvent(pool);
      for (let g = 1; g <= total; g += 1) assert.equal(delivered.get(eventId('nevt_cc_', g)), 1);
    });
  });

  it('reclaims an expired lease after owner death and sends it once (R04)', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const { notificationRepo, notifications, sends, webhookSender } = await webhookRuntime(pool);
      const rule = await createWebhookRule(notifications);
      await insertBulkLedger(pool, {
        prefix: 'nevt_ls_', count: 1, ruleId: rule.id, createdStart: '2026-01-01T00:00:00.000Z', pending: true,
      });
      const attemptId = `${eventId('nevt_ls_', 1)}_att`;

      // A sender claims the attempt and then its process dies (no heartbeat, no completion).
      const dead = await notificationRepo.claimDeliveryAttempt(CTX, {
        attemptId, claimToken: 'dead-instance:claim', leaseMs: 300,
      });
      assert.equal(dead.id, attemptId);

      const whileLeased = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(0),
      });
      assert.equal(whileLeased.network_sends_performed, 0);
      assert.equal(whileLeased.in_flight_count, 1);
      assert.equal(sends.length, 0, 'an active lease is never stolen');

      await new Promise((r) => setTimeout(r, 450));
      const reclaimed = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(0),
      });
      assert.equal(reclaimed.network_sends_performed, 1);
      assert.deepEqual(sends, [eventId('nevt_ls_', 1)]);

      // The dead owner's late completion cannot record a second outcome.
      const late = await notificationRepo.completeDeliveryAttemptClaim(CTX, {
        attemptId,
        claimToken: 'dead-instance:claim',
        eventId: eventId('nevt_ls_', 1),
        record: {
          id: 'natt_late', rule_id: rule.id, channel: 'webhook', destination_preview: 'webhook:x',
          status: 'delivered_provider', created_at: minutesFromNow(0), attempted_at: minutesFromNow(0),
          attempt_number: 1, max_attempts: 3,
        },
      });
      assert.equal(late.completed, false);

      const quiet = await notifications.processDueNotificationRetries(CTX, {
        deliveryMode: 'webhook', webhookSender, asOf: minutesFromNow(10),
      });
      assert.equal(quiet.due_count, 0);
      assert.equal(sends.length, 1);
      const delivered = await deliveredCountsByEvent(pool);
      assert.equal(delivered.get(eventId('nevt_ls_', 1)), 1);
    });
  });
});
