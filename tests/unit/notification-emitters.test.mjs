import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createNotificationRule } from '../../src/services/notifications.mjs';
import { createReport } from '../../src/services/reports.mjs';
import { upsertFindingFromVerdict } from '../../src/services/findings.mjs';
import { notifyRunTerminal } from '../../src/services/runTerminalHooks.mjs';
import {
  OUTBOX_PENDING_REASON,
  OUTBOX_RECOVERY_GRACE_MS,
  createPostgresNotificationServices,
  highSeverityFindingDedupeKey,
  registerPostgresRunNotificationHook,
  safeTestCompletedDedupeKey,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';
import {
  createNotificationOutboxReconciler,
  reportReadyDedupeKey,
} from '../../src/persistence/postgres/notificationReconciliation.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const flush = () => new Promise((resolve) => setImmediate(resolve));
const FIXED_NOW = new Date('2026-06-01T12:00:00.000Z');

describe('notification emitters (dev store)', () => {
  it('emits report.ready when a report is generated and a rule subscribes', async () => {
    freshStore();
    createNotificationRule(ctx, { channel: 'in_app', triggers: ['report.ready'] });
    const report = createReport(ctx, { title: 'Weekly summary' });
    await flush();
    const events = getStore().notificationEvents.filter((e) => e.trigger === 'report.ready');
    assert.equal(events.length, 1);
    assert.equal(events[0].metadata.report_id, report.id);
    assert.equal(events[0].delivery_attempts[0].status, 'delivered_in_app');
  });

  it('emits safe_test.completed only for verdicted runs', async () => {
    freshStore();
    createNotificationRule(ctx, { channel: 'in_app', triggers: ['safe_test.completed'] });
    notifyRunTerminal({ id: 'run_1', tenant_id: 'ten_demo', check_id: 'chk' }, { reason: 'verdicted' });
    notifyRunTerminal({ id: 'run_2', tenant_id: 'ten_demo' }, { reason: 'cancelled' });
    await flush();
    const events = getStore().notificationEvents.filter((e) => e.trigger === 'safe_test.completed');
    assert.equal(events.length, 1);
    assert.equal(events[0].metadata.run_id, 'run_1');
  });

  it('records nothing when no rule subscribes', async () => {
    freshStore();
    createReport(ctx, {});
    notifyRunTerminal({ id: 'run_3', tenant_id: 'ten_demo' }, { reason: 'verdicted' });
    await flush();
    assert.equal((getStore().notificationEvents ?? []).length, 0);
  });

  // G04: the dev finding-creation emitter must respect subscriptions like Postgres does.
  function publishHighFinding(suffix) {
    return upsertFindingFromVerdict(
      ctx,
      { id: `v_${suffix}`, verdict: 'bypassable', severity: 'high', explanation: 'x', evidence_ids: [] },
      { id: `run_${suffix}`, target_group_id: `tg_${suffix}`, check_id: 'chk' },
      { id: `tgt_${suffix}`, value: '203.0.113.9' },
    );
  }

  it('does not record a high-severity finding event for an unsubscribed tenant', async () => {
    freshStore();
    publishHighFinding('unsub');
    await flush();
    const events = (getStore().notificationEvents ?? []).filter((e) => e.trigger === 'finding.high_severity');
    assert.equal(events.length, 0);
  });

  it('records a high-severity finding event bound to its verdict when subscribed', async () => {
    freshStore();
    createNotificationRule(ctx, { channel: 'in_app', triggers: ['finding.high_severity'] });
    const finding = publishHighFinding('sub');
    await flush();
    const events = getStore().notificationEvents.filter((e) => e.trigger === 'finding.high_severity');
    assert.equal(events.length, 1);
    assert.equal(events[0].metadata.finding_id, finding.id);
    assert.equal(events[0].metadata.verdict_id, 'v_sub');
  });
});

/**
 * In-memory stand-in for the Postgres notification repository. `enqueueNotificationEvent`
 * models the (tenant_id, dedupe_key) unique index: check-and-insert happens atomically after an
 * await, so concurrent callers and separate service instances collapse to one row.
 */
function createFakeNotificationStore(rules, faults = {}) {
  const state = {
    events: [],
    attempts: [],
    failEnqueue: faults.failEnqueue ?? 0,
    failAppendAttempts: faults.failAppendAttempts ?? 0,
  };
  const withAttempts = (event) => ({
    ...event,
    delivery_attempts: state.attempts.filter((a) => a.notification_event_id === event.id),
  });
  const repo = {
    async listNotificationRules() {
      return rules;
    },
    async listNotificationEvents() {
      return state.events.map(withAttempts);
    },
    async createNotificationRule() {
      return null;
    },
    async appendNotificationEvent(c, event) {
      const row = { ...event, tenant_id: c.tenantId };
      state.events.push(row);
      return row;
    },
    async appendDeliveryAttempts(_c, eventId, attempts) {
      await Promise.resolve();
      if (state.failAppendAttempts > 0) {
        state.failAppendAttempts -= 1;
        throw new Error('attempt persistence unavailable');
      }
      for (const attempt of attempts) state.attempts.push({ ...attempt, notification_event_id: eventId });
      return attempts;
    },
    async enqueueNotificationEvent(c, event, attempts) {
      await Promise.resolve();
      if (state.failEnqueue > 0) {
        state.failEnqueue -= 1;
        throw new Error('db down');
      }
      const existing = event.dedupe_key
        ? state.events.find((e) => e.tenant_id === c.tenantId && e.dedupe_key === event.dedupe_key)
        : null;
      if (existing) return { inserted: false, event: withAttempts(existing) };
      const row = { ...event, tenant_id: c.tenantId };
      state.events.push(row);
      for (const attempt of attempts) state.attempts.push({ ...attempt, notification_event_id: event.id });
      return { inserted: true, event: withAttempts(row) };
    },
  };
  return { repo, state };
}

function createAuditStub() {
  const entries = [];
  return {
    entries,
    async appendAuditEvent(entry) {
      entries.push(entry);
      return entry;
    },
    async getLastAuditEntry() {
      return null;
    },
  };
}

function gate() {
  let release;
  const promise = new Promise((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

function withinMs(promise, ms, label) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} did not return within ${ms}ms`)), ms);
    }),
  ]);
}

const RUN = { id: 'run_pg', tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'chk' };
const RUN_VERDICT = 'v_run_pg';

const BOTH_RULES = [
  {
    id: 'nrule_app',
    tenant_id: 'ten_demo',
    channel: 'in_app',
    destination: '',
    triggers: ['safe_test.completed', 'finding.high_severity', 'report.ready'],
    enabled: true,
  },
];

const FINDINGS = [
  // Created by this run's publication.
  { id: 'f_new', severity: 'high', status: 'open', verdict_id: RUN_VERDICT, last_verdict_id: RUN_VERDICT, title: 'New' },
  // Advanced by this run, created earlier: must not re-alert.
  { id: 'f_adv', severity: 'high', status: 'open', verdict_id: 'v_old', last_verdict_id: RUN_VERDICT, title: 'Advanced' },
  // Not high severity.
  { id: 'f_med', severity: 'medium', status: 'open', verdict_id: RUN_VERDICT, last_verdict_id: RUN_VERDICT },
];

function buildHookHarness({ rules = BOTH_RULES, findings = FINDINGS, store, serviceOptions = {} } = {}) {
  const shared = store ?? createFakeNotificationStore(rules);
  const audit = createAuditStub();
  const hooks = [];
  const testRuns = { registerRunTerminalHook: (fn) => { hooks.push(fn); } };
  const validationEvidence = {
    listFindings: async () => findings,
    getVerdictForRun: async (_c, runId) => (runId === RUN.id ? { id: RUN_VERDICT } : null),
  };
  const services = [];
  function addInstance() {
    const notifications = createPostgresNotificationServices(
      { notifications: shared.repo, audit },
      { now: () => FIXED_NOW, ...serviceOptions },
    );
    registerPostgresRunNotificationHook({
      testRuns,
      notifications,
      notificationRules: shared.repo,
      validationEvidence,
    });
    services.push(notifications);
    return notifications;
  }
  addInstance();
  return {
    store: shared,
    audit,
    services,
    addInstance,
    hookAt: (index) => (run, context) => hooks[index](run, context),
    hook: (run, context) => hooks[0](run, context),
    triggers: () => shared.state.events.map((e) => e.trigger).sort(),
  };
}

describe('registerPostgresRunNotificationHook (durable outbox)', () => {
  it('enqueues completion once and high-severity alerts only for findings this run created', async () => {
    const h = buildHookHarness();
    await h.hook(RUN, { reason: 'verdicted' });
    await h.hook(RUN, { reason: 'verdicted' });
    await h.hook({ ...RUN, id: 'run_x' }, { reason: 'cancelled' });

    assert.deepEqual(h.triggers(), ['finding.high_severity', 'safe_test.completed']);
    const alert = h.store.state.events.find((e) => e.trigger === 'finding.high_severity');
    assert.equal(alert.metadata.finding_id, 'f_new');
    assert.equal(alert.metadata.verdict_id, RUN_VERDICT);
    assert.equal(alert.metadata.test_run_id, RUN.id);
    assert.equal(alert.dedupe_key, highSeverityFindingDedupeKey('f_new', RUN_VERDICT));
    const completion = h.store.state.events.find((e) => e.trigger === 'safe_test.completed');
    assert.equal(completion.dedupe_key, safeTestCompletedDedupeKey(RUN.id));
  });

  it('records the event on replay after persistence fails once (no success claimed before commit)', async () => {
    const store = createFakeNotificationStore(BOTH_RULES, { failEnqueue: 1 });
    const h = buildHookHarness({ store });

    // First enqueue (completion) fails; the high-severity alert is still recorded.
    await h.hook(RUN, { reason: 'verdicted' });
    assert.deepEqual(h.triggers(), ['finding.high_severity']);

    // Replay records the missing completion event; the alert is not duplicated.
    await h.hook(RUN, { reason: 'verdicted' });
    assert.deepEqual(h.triggers(), ['finding.high_severity', 'safe_test.completed']);
  });

  it('keeps the high-severity alert when the completion enqueue throws', async () => {
    const store = createFakeNotificationStore(BOTH_RULES);
    const original = store.repo.enqueueNotificationEvent;
    store.repo.enqueueNotificationEvent = async (c, event, attempts) => {
      if (event.trigger === 'safe_test.completed') throw new Error('completion insert failed');
      return original(c, event, attempts);
    };
    const h = buildHookHarness({ store });
    await assert.doesNotReject(() => h.hook(RUN, { reason: 'verdicted' }));
    assert.deepEqual(h.triggers(), ['finding.high_severity']);
  });

  it('records exactly one event per identity across concurrent calls and separate hook instances', async () => {
    const h = buildHookHarness();
    h.addInstance();
    await Promise.all([
      h.hookAt(0)(RUN, { reason: 'verdicted' }),
      h.hookAt(1)(RUN, { reason: 'verdicted' }),
      h.hookAt(0)(RUN, { reason: 'verdicted' }),
      h.hookAt(1)(RUN, { reason: 'verdicted' }),
    ]);
    assert.deepEqual(h.triggers(), ['finding.high_severity', 'safe_test.completed']);
    const keys = h.store.state.events.map((e) => e.dedupe_key);
    assert.equal(new Set(keys).size, keys.length);
  });

  it('alerts on the finding this run created even if another run advanced it before the hook read it', async () => {
    const advancedElsewhere = [
      {
        id: 'f_new',
        severity: 'high',
        status: 'open',
        test_run_id: 'run_other',
        verdict_id: RUN_VERDICT,
        last_verdict_id: 'v_other',
        title: 'Created by run_pg, advanced by run_other',
      },
    ];
    const h = buildHookHarness({ findings: advancedElsewhere });
    await h.hook(RUN, { reason: 'verdicted' });
    const alerts = h.store.state.events.filter((e) => e.trigger === 'finding.high_severity');
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].metadata.finding_id, 'f_new');
  });

  it('records nothing without an enabled subscription and never throws into the run lifecycle', async () => {
    const h = buildHookHarness({
      rules: [{ id: 'r', channel: 'in_app', destination: '', enabled: false, triggers: ['safe_test.completed'] }],
    });
    await h.hook(RUN, { reason: 'verdicted' });
    assert.equal(h.store.state.events.length, 0);

    const failing = createFakeNotificationStore(BOTH_RULES);
    failing.repo.listNotificationRules = async () => {
      throw new Error('db down');
    };
    const broken = buildHookHarness({ store: failing });
    await assert.doesNotReject(() => broken.hook(RUN, { reason: 'verdicted' }));
  });

  it('does not wait on a stalled provider; the worker records the outcome later', async () => {
    const webhookRule = {
      id: 'nrule_wh',
      tenant_id: 'ten_demo',
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/deliver',
      triggers: ['safe_test.completed'],
      enabled: true,
    };
    const stall = gate();
    let sends = 0;
    const h = buildHookHarness({
      rules: [webhookRule],
      findings: [],
      serviceOptions: {
        deliveryMode: 'webhook',
        webhookSender: async () => {
          sends += 1;
          await stall.promise;
          return { ok: true, status: 202 };
        },
      },
    });

    await withinMs(h.hook(RUN, { reason: 'verdicted' }), 500, 'run terminal hook');

    // Durable before any send: the event and its pending attempt exist while the sender is stalled.
    assert.equal(h.store.state.events.length, 1);
    assert.equal(h.store.state.attempts.length, 1);
    assert.equal(h.store.state.attempts[0].status, 'provider_retry_scheduled');
    assert.equal(h.store.state.attempts[0].reason, OUTBOX_PENDING_REASON);
    assert.equal(h.store.state.attempts[0].attempt_number, 0);

    await flush();
    assert.equal(sends, 1);
    stall.release();
    await h.services[0].drainNotificationOutbox();

    const outcome = h.store.state.attempts.at(-1);
    assert.equal(h.store.state.attempts.length, 2);
    assert.equal(outcome.status, 'delivered_provider');
    assert.equal(outcome.attempt_number, 1);
    assert.ok(h.audit.entries.some((a) => a.action === 'notification.delivery_attempt_recorded' && a.metadata.outbox));
  });

  it('leaves a pending attempt the retry worker recovers when in-process delivery fails', async () => {
    const webhookRule = {
      id: 'nrule_wh',
      tenant_id: 'ten_demo',
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/deliver',
      triggers: ['safe_test.completed'],
      enabled: true,
    };
    const store = createFakeNotificationStore([webhookRule], { failAppendAttempts: 1 });
    let sends = 0;
    const serviceOptions = {
      deliveryMode: 'webhook',
      webhookSender: async () => {
        sends += 1;
        return { ok: true, status: 200 };
      },
    };
    const h = buildHookHarness({ store, findings: [], serviceOptions });
    await h.hook(RUN, { reason: 'verdicted' });
    await h.services[0].drainNotificationOutbox();

    // The worker sent but could not record the outcome; the durable pending attempt remains.
    assert.equal(store.state.attempts.length, 1);
    assert.equal(store.state.attempts[0].reason, OUTBOX_PENDING_REASON);

    // Not due before the recovery grace, so the retry worker does not race a healthy worker.
    const early = await h.services[0].processDueNotificationRetries(
      { tenantId: 'ten_demo', userId: 'system', role: 'system' },
      { asOf: FIXED_NOW.toISOString(), deliveryMode: 'webhook', webhookSender: serviceOptions.webhookSender },
    );
    assert.equal(early.due_count, 0);

    const later = new Date(FIXED_NOW.getTime() + OUTBOX_RECOVERY_GRACE_MS + 1000).toISOString();
    const recovered = await h.services[0].processDueNotificationRetries(
      { tenantId: 'ten_demo', userId: 'system', role: 'system' },
      { asOf: later, deliveryMode: 'webhook', webhookSender: serviceOptions.webhookSender },
    );
    assert.equal(recovered.due_count, 1);
    assert.equal(store.state.attempts.at(-1).status, 'delivered_provider');
    assert.equal(store.state.attempts.at(-1).attempt_number, 1);
    assert.equal(sends, 2);
  });
});

describe('postgres report.ready emitter (durable outbox)', () => {
  function buildReportHarness({ rules, serviceOptions = {} } = {}) {
    const store = createFakeNotificationStore(rules);
    const audit = createAuditStub();
    const notifications = createPostgresNotificationServices(
      { notifications: store.repo, audit },
      { now: () => FIXED_NOW, ...serviceOptions },
    );
    const reportsRepo = {
      createReport: async (_c, record) => record,
      getReport: async () => null,
      listReports: async () => [],
      listRunsForReport: async () => [],
      listVerdictsForRunIds: async () => [],
    };
    const validationEvidence = {
      listTestRuns: async () => [],
      listFindings: async () => [],
      getFinding: async () => null,
    };
    const { reports } = createPostgresReportServices(
      { reports: reportsRepo, validationEvidence, audit, notifications: store.repo },
      { now: () => FIXED_NOW, notifications },
    );
    return { store, reports, notifications };
  }

  it('returns from report creation before a stalled provider send and records the outcome later', async () => {
    const stall = gate();
    const h = buildReportHarness({
      rules: [{
        id: 'nrule_wh',
        tenant_id: 'ten_demo',
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/reports',
        triggers: ['report.ready'],
        enabled: true,
      }],
      serviceOptions: {
        deliveryMode: 'webhook',
        webhookSender: async () => {
          await stall.promise;
          return { ok: true, status: 200 };
        },
      },
    });

    const report = await withinMs(h.reports.createReport(ctx, { title: 'Weekly' }), 500, 'createReport');
    assert.equal(h.store.state.events.length, 1);
    assert.equal(h.store.state.events[0].trigger, 'report.ready');
    assert.equal(h.store.state.events[0].metadata.report_id, report.id);
    assert.equal(h.store.state.events[0].dedupe_key, `report.ready:report:${report.id}`);
    assert.equal(h.store.state.attempts.at(-1).reason, OUTBOX_PENDING_REASON);

    stall.release();
    await h.notifications.drainNotificationOutbox();
    assert.equal(h.store.state.attempts.at(-1).status, 'delivered_provider');
  });

  it('records nothing for an unsubscribed tenant and never fails report creation', async () => {
    const h = buildReportHarness({ rules: [] });
    const report = await h.reports.createReport(ctx, {});
    assert.ok(report.id);
    assert.equal(h.store.state.events.length, 0);

    const failing = buildReportHarness({ rules: BOTH_RULES });
    failing.store.state.failEnqueue = 1;
    const ok = await failing.reports.createReport(ctx, {});
    assert.ok(ok.id);
    // The enqueue failed after the report committed; nothing is recorded yet...
    assert.equal(failing.store.state.events.length, 0);

    // ...but the recovery tick's reconciliation pass (R03) discovers the report whose identity has
    // no event and enqueues it, without reissuing report creation. Repeating adds nothing.
    const committedReports = [ok];
    failing.notifications.registerNotificationReconciler(createNotificationOutboxReconciler({
      notifications: failing.notifications,
      graceMs: 0,
      repository: {
        async listUnnotifiedReports() {
          const keys = new Set(failing.store.state.events.map((e) => e.dedupe_key));
          return committedReports.filter((r) => !keys.has(reportReadyDedupeKey(r.id)));
        },
      },
    }));
    for (let pass = 0; pass < 2; pass += 1) {
      const tick = await failing.notifications.processDueNotificationRetries(ctx, {
        asOf: FIXED_NOW.toISOString(),
      });
      assert.equal(tick.reconciliation.reconciled_count, pass === 0 ? 1 : 0);
    }
    assert.equal(failing.store.state.events.length, 1);
    assert.equal(failing.store.state.events[0].trigger, 'report.ready');
    assert.equal(failing.store.state.events[0].dedupe_key, `report.ready:report:${ok.id}`);
    assert.equal(failing.store.state.events[0].metadata.report_id, ok.id);
  });
});
