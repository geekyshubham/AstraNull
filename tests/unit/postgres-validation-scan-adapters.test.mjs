import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { customerSelectableChecks, CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { SCAN_AUDIT_ACTIONS } from '../../src/contracts/validationScanManagement.mjs';
import {
  POSTGRES_VALIDATION_SCAN_SERVICE_METHODS,
  createPostgresValidationScanServices,
} from '../../src/persistence/postgres/validationScanServiceAdapters.mjs';
import { VALIDATION_SCAN_REPOSITORY_METHODS } from '../../src/persistence/postgres/validationScanRepository.mjs';

const TENANT = 'ten_scan_unit';
const OTHER_TENANT = 'ten_scan_other';
const CTX = { tenantId: TENANT, userId: 'usr_scan', role: 'admin' };
const GROUP_ID = 'tg_scan_unit';
const TARGET_A = 'tgt_scan_a';
const TARGET_B = 'tgt_scan_b';
const CHECK_ID = 'waf.fingerprint.safe';
const SECOND_CHECK_ID = 'origin.leak_scan.safe';
const NOW = new Date('2026-06-01T12:00:00.000Z');
const RUNTIME_CONFIG = { probeMode: 'simulation' };

function group(overrides = {}) {
  return {
    id: GROUP_ID,
    tenant_id: TENANT,
    name: 'unit group',
    environment_id: 'env_scan_unit',
    safe_test_windows: [],
    safety_policy: { min_seconds_between_runs: 30 },
    validation_mode: 'external_only',
    targets: [
      { id: TARGET_A, kind: 'fqdn', value: 'a.scan.test' },
      { id: TARGET_B, kind: 'fqdn', value: 'b.scan.test' },
    ],
    ...overrides,
  };
}

function createFakeScanRepository() {
  const scans = new Map();
  const steps = new Map();
  const audits = [];
  const locks = new Set();
  const calls = [];

  const tenantScan = (ctx, id) => {
    const scan = scans.get(id);
    return scan && scan.tenant_id === ctx.tenantId ? { ...scan } : null;
  };
  const stepsFor = (ctx, scanId) => [...steps.values()]
    .filter((step) => step.scan_id === scanId && step.tenant_id === ctx.tenantId)
    .sort((a, b) => a.position - b.position)
    .map((step) => ({ ...step }));
  const activeConflict = (tenantId, targetGroupId, excludeId) => [...scans.values()].some((scan) =>
    scan.tenant_id === tenantId && scan.target_group_id === targetGroupId && scan.id !== excludeId
      && ['pending', 'running'].includes(scan.status));

  const repo = {
    async createScan(ctx, record, stepRecords) {
      calls.push(['createScan', record.id]);
      if (['pending', 'running'].includes(record.status) && activeConflict(ctx.tenantId, record.target_group_id, null)) {
        return { error: 'concurrent_scan_blocked', status: 409 };
      }
      const scan = { ...record, tenant_id: ctx.tenantId };
      scans.set(scan.id, scan);
      for (const step of stepRecords) steps.set(step.id, { ...step, scan_id: scan.id, tenant_id: ctx.tenantId });
      return { scan: { ...scan }, steps: stepsFor(ctx, scan.id) };
    },
    async getScan(ctx, id) { return tenantScan(ctx, id); },
    async getStep(ctx, stepId) {
      const step = steps.get(stepId);
      return step && step.tenant_id === ctx.tenantId ? { ...step } : null;
    },
    async listScans(ctx, options = {}) {
      return [...scans.values()]
        .filter((scan) => scan.tenant_id === ctx.tenantId)
        .filter((scan) => !options.targetGroupId || scan.target_group_id === options.targetGroupId)
        .filter((scan) => !options.targetId || scan.target_id === options.targetId)
        .filter((scan) => !options.status?.length || options.status.includes(scan.status))
        .filter((scan) => !options.excludeId || scan.id !== options.excludeId)
        .filter((scan) => !options.seriesId || scan.recurrence_series_id === options.seriesId)
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
        .slice(0, options.limit ?? 50)
        .map((scan) => ({ ...scan }));
    },
    async listSteps(ctx, scanId) { return stepsFor(ctx, scanId); },
    async listStepsForScans(ctx, scanIds) { return scanIds.flatMap((scanId) => stepsFor(ctx, scanId)); },
    async updateScan(ctx, id, patch, options = {}) {
      const scan = scans.get(id);
      if (!scan || scan.tenant_id !== ctx.tenantId) return null;
      if (options.expectedStatuses && !options.expectedStatuses.includes(scan.status)) return null;
      if (options.leaseToken && scan.lease_token !== options.leaseToken) return null;
      if (options.requireUnleasedAt && scan.lease_token
        && new Date(scan.lease_expires_at) > new Date(options.requireUnleasedAt)) return null;
      const next = { ...scan, ...patch };
      if (['pending', 'running'].includes(next.status) && !['pending', 'running'].includes(scan.status)
        && activeConflict(ctx.tenantId, next.target_group_id, id)) {
        return { error: 'concurrent_scan_blocked', status: 409 };
      }
      scans.set(id, next);
      calls.push(['updateScan', id, Object.keys(patch)]);
      return { ...next };
    },
    async updateScanWithSteps(ctx, id, patch, stepRecords, options = {}) {
      const updated = await repo.updateScan(ctx, id, patch, options);
      if (!updated || updated.error) return updated;
      return { ...updated, steps: await repo.replaceSteps(ctx, id, stepRecords) };
    },
    async updateStep(ctx, stepId, patch, options = {}) {
      const step = steps.get(stepId);
      if (!step || step.tenant_id !== ctx.tenantId) return null;
      if (options.expectedStatuses && !options.expectedStatuses.includes(step.status)) return null;
      const next = { ...step, ...patch };
      steps.set(stepId, next);
      return { ...next };
    },
    async replaceSteps(ctx, scanId, stepRecords) {
      for (const [id, step] of steps) if (step.scan_id === scanId) steps.delete(id);
      for (const step of stepRecords) steps.set(step.id, { ...step, scan_id: scanId, tenant_id: ctx.tenantId });
      return stepsFor(ctx, scanId);
    },
    async findStepByRunId(ctx, runId) {
      return [...steps.values()].find((step) => step.tenant_id === ctx.tenantId && step.test_run_id === runId) ?? null;
    },
    async findScanByOccurrenceKey(ctx, key) {
      return [...scans.values()].find((scan) => scan.tenant_id === ctx.tenantId && scan.occurrence_key === key) ?? null;
    },
    async listDueScans(ctx, options = {}) {
      const now = new Date(options.now ?? Date.now());
      return [...scans.values()].filter((scan) => scan.tenant_id === ctx.tenantId && scan.status === 'scheduled'
        && scan.scheduled_for && new Date(scan.scheduled_for) <= now
        && !(scan.lease_expires_at && new Date(scan.lease_expires_at) > now));
    },
    async leaseDueScans(ctx, options = {}) {
      calls.push(['leaseDueScans', options.workerId]);
      const now = new Date(options.now ?? Date.now());
      const due = await repo.listDueScans(ctx, { now });
      const leased = [];
      for (const scan of due.filter((row) => !options.scanId || row.id === options.scanId).slice(0, options.limit ?? 25)) {
        const next = {
          ...scan,
          lease_token: `lease_${scan.id}`,
          lease_owner: options.workerId,
          lease_expires_at: new Date(now.getTime() + (options.leaseMs ?? 60_000)).toISOString(),
        };
        scans.set(scan.id, next);
        leased.push({ ...next });
      }
      return leased;
    },
    async listRunnableScans(ctx, options = {}) {
      const now = new Date(options.now ?? Date.now());
      return [...scans.values()].filter((scan) => scan.tenant_id === ctx.tenantId
        && ['pending', 'running'].includes(scan.status)
        && !(scan.lease_expires_at && new Date(scan.lease_expires_at) > now)
        && (!scan.next_eligible_at || new Date(scan.next_eligible_at) <= now));
    },
    async withScanLock(ctx, scanId, callback) {
      if (locks.has(scanId)) return { acquired: false, result: null };
      locks.add(scanId);
      try {
        return { acquired: true, result: await callback() };
      } finally {
        locks.delete(scanId);
      }
    },
    async createNextOccurrence(ctx, record, stepRecords) {
      const existing = await repo.findScanByOccurrenceKey(ctx, record.occurrence_key);
      if (existing) return { scan: { ...existing }, created: false, steps: [] };
      const created = await repo.createScan(ctx, record, stepRecords);
      return { ...created, created: true };
    },
    async appendScanAudit(ctx, event, options = {}) {
      const entry = {
        id: `aud_${String(audits.length + 1).padStart(3, '0')}`,
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        timestamp: new Date(options.now ?? Date.now()).toISOString(),
        sequence: audits.length + 1,
        ...event,
        metadata: event.metadata ?? {},
      };
      audits.push(entry);
      return entry;
    },
    async listAuditEntriesForScan(ctx, { scanId, runIds = [] }) {
      return audits.filter((entry) => entry.tenant_id === ctx.tenantId && (
        (entry.resource_type === 'validation_scan' && entry.resource_id === scanId)
        || (entry.resource_type === 'test_run' && runIds.includes(entry.resource_id))
        || entry.metadata?.scan_id === scanId));
    },
    async listProbeJobsForRuns() { return []; },
  };
  for (const method of VALIDATION_SCAN_REPOSITORY_METHODS) assert.equal(typeof repo[method], 'function', method);
  return { repo, scans, steps, audits, calls, locks };
}

function createHarness(overrides = {}) {
  const fake = createFakeScanRepository();
  const runs = new Map();
  const startCalls = [];
  const cancelCalls = [];
  const hooks = [];
  let killSwitchActive = overrides.killSwitchActive ?? false;
  let groupRecord = overrides.group ?? group();

  const testRuns = {
    async startTestRun(ctx, body, runtimeConfig, dispatchOptions = {}) {
      startCalls.push({ ctx, body, runtimeConfig, dispatchOptions });
      if (overrides.startTestRun) return overrides.startTestRun({ ctx, body, runtimeConfig, dispatchOptions, runs, fake });
      const dispatch = dispatchOptions.scanDispatch;
      const scan = fake.scans.get(dispatch?.scan_id);
      const step = fake.steps.get(dispatch?.step_id);
      if (!scan || !step || scan.lease_token !== dispatch.lease_token
        || new Date(scan.lease_expires_at) <= NOW || step.status !== 'starting') {
        return { error: 'scan_dispatch_invalid', status: 409 };
      }
      const run = {
        id: `run_${startCalls.length}`,
        tenant_id: ctx.tenantId,
        target_group_id: body.target_group_id,
        target_id: body.target_id,
        check_id: body.check_id,
        status: 'collecting',
        scan_id: dispatch.scan_id,
        scan_step_id: dispatch.step_id,
        created_at: new Date().toISOString(),
        completed_at: null,
      };
      runs.set(run.id, run);
      return { run, jobs_dispatched: 0 };
    },
    async cancelTestRun(ctx, id, cancelOptions) {
      cancelCalls.push({ ctx, id, cancelOptions });
      const run = runs.get(id);
      if (!run) return null;
      run.status = 'cancelled';
      run.completed_at = new Date().toISOString();
      for (const hook of hooks) await hook(run, { reason: 'cancelled', source: cancelOptions?.source });
      return { run };
    },
    async getTestRun(ctx, id) { return runs.get(id) ?? null; },
    registerRunTerminalHook(hook) { hooks.push(hook); return () => hooks.splice(hooks.indexOf(hook), 1); },
  };

  const validationEvidence = {
    async listTestRuns(ctx, options = {}) {
      return [...runs.values()].filter((run) => run.tenant_id === ctx.tenantId
        && (!options.targetGroupId || run.target_group_id === options.targetGroupId)
        && (!options.statuses || options.statuses.includes(run.status)));
    },
    async getTestRun(ctx, id) { return runs.get(id) ?? null; },
    async getTestRunByScanStepId(ctx, stepId) {
      return [...runs.values()].find((run) => run.scan_step_id === stepId) ?? null;
    },
    async getVerdictForRun(ctx, runId) {
      const run = runs.get(runId);
      return run?.status === 'verdicted' ? { test_run_id: runId, verdict: 'protected', confidence: 'high', explanation: 'ok' } : null;
    },
    async listRunEvents() { return []; },
  };

  const services = createPostgresValidationScanServices({
    validationScans: fake.repo,
    validationEvidence,
    coreCatalog: { async getTargetGroup(ctx, id) { return groupRecord && id === groupRecord.id && ctx.tenantId === TENANT ? groupRecord : null; } },
    killSwitch: { async isKillSwitchActiveForTenant() { return killSwitchActive; } },
  }, { testRuns, now: () => NOW, runtimeConfig: overrides.runtimeConfig ?? RUNTIME_CONFIG });

  return {
    services,
    fake,
    runs,
    startCalls,
    cancelCalls,
    hooks,
    async finishRun(runId, status = 'verdicted') {
      const run = runs.get(runId);
      run.status = status;
      run.completed_at = new Date().toISOString();
      for (const hook of hooks) await hook(run, { reason: status });
    },
    setKillSwitch(value) { killSwitchActive = value; },
    setGroup(value) { groupRecord = value; },
  };
}

describe('postgres validation scan service adapter', () => {
  it('exposes the same method surface as the dev-json service', () => {
    for (const method of ['createValidationScan', 'listValidationScans', 'getValidationScan', 'patchValidationScan',
      'cancelValidationScan', 'getValidationScanActivity', 'advanceScan', 'advanceScanForRun',
      'listDueValidationScans', 'dispatchDueValidationScans']) {
      assert.ok(POSTGRES_VALIDATION_SCAN_SERVICE_METHODS.includes(method), method);
    }
    const { services } = createHarness();
    for (const method of POSTGRES_VALIDATION_SCAN_SERVICE_METHODS) {
      assert.equal(typeof services[method], 'function', method);
    }
    assert.ok(customerSelectableChecks(CHECK_CATALOG).some((check) => check.check_id === CHECK_ID));
  });

  it('fails closed when the scan repository or test-run service is incomplete', () => {
    const { repo } = createFakeScanRepository();
    assert.throws(
      () => createPostgresValidationScanServices({ validationScans: {} }, { testRuns: {} }),
      /requires repositories\.validationScans\.createScan\(\)/,
    );
    assert.throws(
      () => createPostgresValidationScanServices({
        validationScans: repo,
        validationEvidence: { listTestRuns() {}, getTestRun() {}, getVerdictForRun() {}, listRunEvents() {} },
        coreCatalog: { getTargetGroup() {} },
        killSwitch: { isKillSwitchActiveForTenant() {} },
      }, { testRuns: { startTestRun() {} } }),
      /requires options\.testRuns\.cancelTestRun\(\)/,
    );
  });

  it('create starts exactly the first step through startTestRun with a scan dispatch binding', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
    }, RUNTIME_CONFIG, { now: NOW });

    assert.equal(scan.status, 'running');
    assert.equal(scan.steps.length, 2);
    assert.equal(harness.startCalls.length, 1);
    const call = harness.startCalls[0];
    assert.deepEqual(call.body, { check_id: CHECK_ID, target_group_id: GROUP_ID, target_id: TARGET_A });
    assert.equal(call.ctx.tenantId, TENANT);
    assert.equal(call.ctx.via, 'validation_scan');
    assert.equal(call.dispatchOptions.scanDispatch.scan_id, scan.id);
    assert.equal(call.dispatchOptions.scanDispatch.step_id, scan.steps[0].step_id);
    assert.ok(call.dispatchOptions.scanDispatch.lease_token);
    assert.equal(scan.steps[0].status, 'collecting');
    assert.equal(scan.steps[0].test_run_id, 'run_1');
    assert.equal(scan.steps[1].status, 'pending');
    assert.equal(scan.summary.running, 1);
    assert.equal(scan.summary.pending, 1);
    const stored = harness.fake.scans.get(scan.id);
    assert.equal(stored.lease_token, null, 'lease released after startTestRun returns');
    const actions = harness.fake.audits.map((entry) => entry.action);
    assert.deepEqual(actions, [SCAN_AUDIT_ACTIONS.created, SCAN_AUDIT_ACTIONS.stepStarted]);
    assert.equal(JSON.stringify(harness.fake.audits).includes('a.scan.test'), false);
  });

  it('advances to the next step when the child run turns terminal and completes the scan', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
    }, RUNTIME_CONFIG, { now: NOW });

    await harness.finishRun('run_1', 'verdicted');
    assert.equal(harness.startCalls.length, 2, 'terminal hook advanced the parent and started step two');
    let current = await harness.services.getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
    assert.equal(current.steps[0].status, 'verdicted');
    assert.equal(current.steps[0].verdict.verdict, 'protected');
    assert.equal(current.steps[1].status, 'collecting');

    await harness.finishRun('run_2', 'verdicted');
    current = await harness.services.getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
    assert.equal(current.status, 'completed');
    assert.equal(current.summary.verdicted, 2);
    assert.ok(current.completed_at);
    const actions = harness.fake.audits.map((entry) => entry.action);
    assert.ok(actions.includes(SCAN_AUDIT_ACTIONS.stepCompleted));
    assert.equal(actions.at(-1), SCAN_AUDIT_ACTIONS.completed);
    const again = await harness.services.advanceScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
    assert.equal(again.acquired, false);
    assert.equal(again.reason, 'inactive');
  });

  it('rejects a forged or expired lease binding and denies the step without retry storms', async () => {
    const harness = createHarness({
      startTestRun: async ({ dispatchOptions, fake }) => {
        const scan = fake.scans.get(dispatchOptions.scanDispatch.scan_id);
        const forged = { ...dispatchOptions.scanDispatch, lease_token: 'forged' };
        const valid = scan.lease_token === forged.lease_token && new Date(scan.lease_expires_at) > new Date();
        return valid ? { run: { id: 'run_forged' } } : { error: 'scan_dispatch_invalid', status: 409 };
      },
    });
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
      target_id: TARGET_A,
    }, RUNTIME_CONFIG, { now: NOW });
    assert.equal(scan.status, 'denied');
    assert.equal(scan.abort_reason, 'scan_dispatch_invalid');
    assert.equal(scan.steps[0].status, 'denied');
    assert.equal(scan.steps[0].error_code, 'scan_dispatch_invalid');
    assert.equal(harness.startCalls.length, 1);
  });

  it('classifies start denials: defers on min interval, denies per step, aborts on group gates', async () => {
    const responses = [
      { error: 'safe_min_interval_active', status: 429 },
    ];
    const harness = createHarness({
      startTestRun: async () => responses.shift() ?? { error: 'target_kind_not_supported', status: 400 },
    });
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
      target_id: TARGET_A,
    }, RUNTIME_CONFIG, { now: NOW });
    assert.equal(scan.status, 'running');
    assert.equal(scan.steps.length, 1);
    assert.equal(scan.steps[0].status, 'deferred');
    assert.equal(scan.steps[0].eligible_at, new Date(NOW.getTime() + 30_000).toISOString());
    assert.equal(scan.next_eligible_at, scan.steps[0].eligible_at);
    const notYet = await harness.services.advanceScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG, now: NOW });
    assert.equal(notYet.waiting, true);
    assert.equal(harness.startCalls.length, 1);

    const later = new Date(NOW.getTime() + 31_000);
    const advanced = await harness.services.advanceScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG, now: later });
    assert.equal(advanced.waiting, false);
    assert.equal(advanced.status, 'denied');
    const final = await harness.services.getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
    assert.deepEqual(final.steps.map((step) => step.status), ['denied']);
    assert.deepEqual(final.steps.map((step) => step.error_code), ['target_kind_not_supported']);
    assert.equal(harness.startCalls.length, 2);
    const actions = harness.fake.audits.map((entry) => entry.action);
    assert.ok(actions.includes(SCAN_AUDIT_ACTIONS.stepDeferred));
    assert.equal(actions.filter((action) => action === SCAN_AUDIT_ACTIONS.stepDenied).length, 1);
  });

  it('blocks a second immediate scan for the same group and hides other tenants', async () => {
    const harness = createHarness();
    await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    const blocked = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    assert.deepEqual(blocked, { error: 'concurrent_scan_blocked', status: 409 });
    const listed = await harness.services.listValidationScans(CTX, {});
    assert.equal(listed.count, 1);
    const foreign = await harness.services.listValidationScans({ tenantId: OTHER_TENANT, userId: 'x', role: 'admin' }, {});
    assert.equal(foreign.count, 0);
    assert.equal(await harness.services.getValidationScan({ tenantId: OTHER_TENANT, userId: 'x', role: 'admin' }, listed.items[0].id), null);
  });

  it('cancel calls cancelTestRun with source scan, skips remaining steps, and audits actor metadata', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    const cancelled = await harness.services.cancelValidationScan(CTX, scan.id, { reason: '  operator stop  ' });
    assert.equal(cancelled.status, 'cancelled');
    assert.equal(cancelled.cancel_reason, 'operator stop');
    assert.equal(cancelled.cancelled_by, CTX.userId);
    assert.deepEqual(cancelled.steps.map((step) => step.status), ['cancelled', 'skipped']);
    assert.equal(cancelled.steps[1].skip_reason, 'scan_cancelled');
    assert.equal(harness.cancelCalls.length, 1);
    assert.deepEqual(harness.cancelCalls[0].cancelOptions, { reason: 'operator stop', source: 'scan', scan_id: scan.id });
    assert.equal(harness.startCalls.length, 1, 'the terminal hook must not restart steps on a cancelled scan');
    const audit = harness.fake.audits.find((entry) => entry.action === SCAN_AUDIT_ACTIONS.cancelled);
    assert.equal(audit.metadata.cancelled_by, CTX.userId);
    assert.equal(audit.metadata.cancelled_by_role, CTX.role);
    assert.equal(audit.metadata.cancelled_steps, 1);
    assert.equal(audit.metadata.skipped_steps, 1);
    assert.equal(audit.metadata.active_test_run_id, 'run_1');
    const denied = await harness.services.cancelValidationScan(CTX, scan.id, {});
    assert.deepEqual(denied, { error: 'not_cancellable', status: 409 });
    assert.ok(harness.fake.audits.some((entry) => entry.action === SCAN_AUDIT_ACTIONS.cancelDenied));
  });

  it('denies a scheduled dispatch when the kill switch is active and audits schedule_denied', async () => {
    const harness = createHarness({ killSwitchActive: true });
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
      scheduled_for: scheduledFor,
    }, RUNTIME_CONFIG, { now: NOW });
    assert.equal(scan.status, 'scheduled');
    assert.equal(harness.startCalls.length, 0);

    const early = await harness.services.dispatchDueValidationScans(CTX, { now: NOW, workerId: 'w1', runtimeConfig: RUNTIME_CONFIG });
    assert.deepEqual(early, []);
    const due = new Date(NOW.getTime() + 11 * 60_000);
    const results = await harness.services.dispatchDueValidationScans(CTX, { now: due, workerId: 'w1', runtimeConfig: RUNTIME_CONFIG });
    assert.deepEqual(results, [{ scan_id: scan.id, dispatched: false, denied: 'kill_switch_active' }]);
    assert.equal(harness.startCalls.length, 0);
    const stored = await harness.services.getValidationScan(CTX, scan.id, { now: due, runtimeConfig: RUNTIME_CONFIG });
    assert.equal(stored.status, 'denied');
    assert.equal(stored.abort_reason, 'kill_switch_active');
    assert.deepEqual(stored.steps.map((step) => step.skip_reason), ['schedule_denied:kill_switch_active', 'schedule_denied:kill_switch_active']);
    const audit = harness.fake.audits.find((entry) => entry.action === SCAN_AUDIT_ACTIONS.scheduleDenied);
    assert.equal(audit.metadata.code, 'kill_switch_active');
    assert.equal(audit.metadata.scheduled_for, scheduledFor);
  });

  it('dispatches a recurring scan once and creates exactly one next occurrence', async () => {
    const harness = createHarness();
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
      scheduled_for: scheduledFor,
      recurrence: { cadence: 'daily' },
    }, RUNTIME_CONFIG, { now: NOW });
    assert.equal(scan.status, 'scheduled');
    assert.ok(scan.next_occurrence_at);

    const due = new Date(NOW.getTime() + 11 * 60_000);
    const first = await harness.services.dispatchDueValidationScans(CTX, { now: due, workerId: 'w1', runtimeConfig: RUNTIME_CONFIG });
    const second = await harness.services.dispatchDueValidationScans(CTX, { now: due, workerId: 'w2', runtimeConfig: RUNTIME_CONFIG });
    assert.equal(first.length, 1);
    assert.equal(first[0].dispatched, true);
    assert.equal(first[0].advanced.acquired, true);
    assert.deepEqual(second, []);
    assert.equal(harness.startCalls.length, 1);

    const all = await harness.services.listValidationScans(CTX, {});
    assert.equal(all.count, 2);
    const next = all.items.find((row) => row.id !== scan.id);
    assert.equal(next.status, 'scheduled');
    assert.equal(next.previous_scan_id, scan.id);
    assert.equal(next.occurrence_index, 1);
    assert.equal(next.recurrence_series_id, scan.id);
    const parent = all.items.find((row) => row.id === scan.id);
    assert.equal(parent.status, 'running');
    assert.equal(parent.next_scan_id, next.id);
    assert.equal(harness.fake.audits.filter((entry) => entry.action === SCAN_AUDIT_ACTIONS.scheduled).length, 2);
    assert.equal(harness.fake.audits.filter((entry) => entry.action === SCAN_AUDIT_ACTIONS.dispatched).length, 1);

    const stopped = await harness.services.cancelValidationScan(CTX, scan.id, { reason: 'stop series', cancel_series: true });
    assert.equal(stopped.status, 'cancelled');
    assert.equal(stopped.recurrence, null);
    const nextAfter = await harness.services.getValidationScan(CTX, next.id, { now: due, runtimeConfig: RUNTIME_CONFIG });
    assert.equal(nextAfter.status, 'cancelled');
    assert.ok(harness.fake.audits.some((entry) => entry.action === SCAN_AUDIT_ACTIONS.seriesStopped));
  });

  it('patch only edits scheduled scans, re-plans steps, and bumps the revision', async () => {
    const harness = createHarness();
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
      scheduled_for: scheduledFor,
    }, RUNTIME_CONFIG, { now: NOW });
    const patched = await harness.services.patchValidationScan(CTX, scan.id, {
      check_ids: [CHECK_ID, SECOND_CHECK_ID],
      name: 'Nightly',
    }, { now: NOW, runtimeConfig: RUNTIME_CONFIG });
    assert.equal(patched.revision, 2);
    assert.equal(patched.name, 'Nightly');
    assert.equal(patched.steps.length, 4);
    const audit = harness.fake.audits.find((entry) => entry.action === SCAN_AUDIT_ACTIONS.updated);
    assert.deepEqual(audit.metadata.changed_fields, ['check_ids', 'name']);

    const running = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    const rejected = await harness.services.patchValidationScan(CTX, running.id, { name: 'nope' }, { now: NOW });
    assert.deepEqual(rejected, { error: 'scan_not_editable', status: 409 });
  });

  it('activity feed merges scan audits and child run audits in order', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    await harness.fake.repo.appendScanAudit(CTX, {
      action: 'test_run.started',
      resource_type: 'test_run',
      resource_id: 'run_1',
      metadata: { check_id: CHECK_ID, scan_id: scan.id, scan_step_id: scan.steps[0].step_id },
    });
    const activity = await harness.services.getValidationScanActivity(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
    assert.equal(activity.scan_id, scan.id);
    assert.equal(activity.count, 3);
    assert.deepEqual(activity.items.map((item) => item.action), [
      SCAN_AUDIT_ACTIONS.created,
      SCAN_AUDIT_ACTIONS.stepStarted,
      'test_run.started',
    ]);
    assert.equal(activity.items[2].kind, 'run');
    assert.equal(activity.items[2].step_id, scan.steps[0].step_id);
    assert.equal(activity.items[2].test_run_id, 'run_1');
    const paged = await harness.services.getValidationScanActivity(CTX, scan.id, { after: activity.items[0].id, limit: 1 });
    assert.equal(paged.count, 1);
    assert.equal(paged.items[0].action, 'test_run.started');
  });

  it('reports a lock contention as not acquired instead of running two executors', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    harness.fake.locks.add(scan.id);
    const contended = await harness.services.advanceScan(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
    assert.deepEqual(contended, { scan_id: scan.id, acquired: false, reason: 'locked' });
    harness.fake.locks.delete(scan.id);
    assert.equal(await harness.services.advanceScan(CTX, 'scan_missing', {}), null);
    assert.equal(await harness.services.advanceScanForRun({ tenant_id: TENANT, scan_id: null }), null);
  });

  it('hook-driven advancement fails closed and audits when signed-worker signing material is missing', async () => {
    const harness = createHarness({ runtimeConfig: { probeMode: 'signed-worker', probeWorkerSecret: null, probeConfigError: 'probe_worker_secret_too_short' } });
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
    }, undefined, { now: NOW });
    assert.equal(harness.startCalls.length, 0, 'no child run is created without a valid signing secret');
    assert.deepEqual(scan.steps.map((step) => step.status), ['pending', 'pending']);
    const blocked = harness.fake.audits.find((entry) => entry.action === SCAN_AUDIT_ACTIONS.advanceBlocked);
    assert.equal(blocked.metadata.reason, 'probe_signing_unavailable');
    assert.equal(blocked.metadata.error_code, 'probe_worker_secret_too_short');

    const resumed = await harness.services.advanceScan(CTX, scan.id, {
      now: NOW,
      runtimeConfig: { probeMode: 'signed-worker', probeWorkerSecret: 'probe-worker-secret-at-least-32-chars' },
    });
    assert.equal(resumed.acquired, true);
    assert.equal(harness.startCalls.length, 1, 'a correctly configured runner resumes the blocked step');
  });

  it('cancels a child run that starts after Stop and never leaves the step running', async () => {
    let harness;
    harness = createHarness({
      startTestRun: async ({ ctx, body, dispatchOptions, runs }) => {
        await harness.services.cancelValidationScan(CTX, dispatchOptions.scanDispatch.scan_id, { reason: 'stop now', now: NOW });
        const run = {
          id: 'run_late',
          tenant_id: ctx.tenantId,
          target_group_id: body.target_group_id,
          target_id: body.target_id,
          check_id: body.check_id,
          status: 'running',
          scan_id: dispatchOptions.scanDispatch.scan_id,
          scan_step_id: dispatchOptions.scanDispatch.step_id,
          created_at: NOW.toISOString(),
        };
        runs.set(run.id, run);
        return { run };
      },
    });
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
    }, RUNTIME_CONFIG, { now: NOW });
    assert.equal(scan.status, 'cancelled');
    assert.equal(harness.runs.get('run_late').status, 'cancelled');
    assert.ok(harness.cancelCalls.some((call) => call.id === 'run_late'));
    assert.equal(scan.steps[0].status, 'cancelled');
    assert.equal(scan.steps[0].test_run_id, 'run_late');
    assert.equal(scan.steps[1].status, 'skipped');
    assert.equal(harness.startCalls.length, 1);
    assert.ok(harness.fake.audits.some((entry) => entry.action === SCAN_AUDIT_ACTIONS.orphanRunCancelled));
  });

  it('cancel also stops an active child run that is not yet linked to its step', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    const firstStepId = scan.steps[0].step_id;
    harness.fake.steps.set(firstStepId, { ...harness.fake.steps.get(firstStepId), status: 'pending', test_run_id: null });
    const cancelled = await harness.services.cancelValidationScan(CTX, scan.id, { reason: 'stop', now: NOW });
    assert.equal(harness.runs.get('run_1').status, 'cancelled');
    assert.equal(cancelled.steps[0].status, 'cancelled');
    assert.equal(cancelled.steps[0].test_run_id, 'run_1');
  });

  it('guards executor writes so a concurrent cancel is never overwritten', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID] }, RUNTIME_CONFIG, { now: NOW });
    harness.fake.scans.set(scan.id, { ...harness.fake.scans.get(scan.id), status: 'cancelled', cancelled_at: NOW.toISOString() });
    await harness.finishRun('run_1', 'verdicted');
    assert.equal(harness.fake.scans.get(scan.id).status, 'cancelled');
    assert.equal(harness.startCalls.length, 1);
  });

  it('defers hourly cap denials until the oldest run in the rolling hour ages out', async () => {
    const oldest = new Date(NOW.getTime() - 50 * 60_000).toISOString();
    const harness = createHarness({
      startTestRun: async ({ runs }) => {
        runs.set('run_prior', { id: 'run_prior', tenant_id: TENANT, target_group_id: 'tg_other', status: 'verdicted', created_at: oldest });
        return { error: 'entitlement_limit_exceeded', status: 403 };
      },
    });
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
      target_id: TARGET_A,
    }, RUNTIME_CONFIG, { now: NOW });
    assert.equal(scan.status, 'running');
    assert.equal(scan.steps[0].status, 'deferred');
    assert.equal(scan.steps[0].eligible_at, new Date(new Date(oldest).getTime() + 3_600_000 + 1000).toISOString());
    const audit = harness.fake.audits.find((entry) => entry.action === SCAN_AUDIT_ACTIONS.stepDeferred);
    assert.equal(audit.metadata.error_code, 'entitlement_limit_exceeded');
  });

  it('runs scheduled steps under the scheduler system identity', async () => {
    const harness = createHarness();
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID], scheduled_for: scheduledFor }, RUNTIME_CONFIG, { now: NOW });
    const due = new Date(NOW.getTime() + 11 * 60_000);
    await harness.services.dispatchDueValidationScans(CTX, { now: due, workerId: 'w1', runtimeConfig: RUNTIME_CONFIG });
    assert.equal(harness.startCalls.length, 1);
    assert.equal(harness.startCalls[0].ctx.role, 'system');
    assert.equal(harness.startCalls[0].ctx.userId, 'validation-scan-scheduler');
    assert.equal(harness.startCalls[0].ctx.on_behalf_of, CTX.userId);
  });

  it('read-only callers never trigger dispatch or advancement on read endpoints', async () => {
    const harness = createHarness();
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID], scheduled_for: scheduledFor }, RUNTIME_CONFIG, { now: NOW });
    const due = new Date(NOW.getTime() + 11 * 60_000);
    for (const role of ['viewer', 'auditor']) {
      const reader = { tenantId: TENANT, userId: `usr_${role}`, role };
      const read = await harness.services.getValidationScan(reader, scan.id, { now: due, runtimeConfig: RUNTIME_CONFIG });
      assert.equal(read.status, 'scheduled');
      await harness.services.getValidationScanActivity(reader, scan.id, { now: due, runtimeConfig: RUNTIME_CONFIG });
    }
    assert.equal(harness.startCalls.length, 0);
    assert.equal(harness.fake.calls.filter(([name]) => name === 'leaseDueScans').length, 0);
    const operatorRead = await harness.services.getValidationScan(CTX, scan.id, { now: due, runtimeConfig: RUNTIME_CONFIG });
    assert.equal(operatorRead.status, 'running');
  });

  it('rejects PATCH while a dispatcher holds the lease and dispatch ignores a scan cancelled mid-flight', async () => {
    let cancelDuringDispatch = false;
    const harness = createHarness();
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID], scheduled_for: scheduledFor }, RUNTIME_CONFIG, { now: NOW });
    harness.fake.scans.set(scan.id, {
      ...harness.fake.scans.get(scan.id),
      lease_token: 'lease_other',
      lease_owner: 'w_other',
      lease_expires_at: new Date(NOW.getTime() + 30_000).toISOString(),
    });
    const rejected = await harness.services.patchValidationScan(CTX, scan.id, { name: 'late edit' }, { now: NOW });
    assert.deepEqual(rejected, { error: 'scan_not_editable', status: 409 });
    harness.fake.scans.set(scan.id, { ...harness.fake.scans.get(scan.id), lease_token: null, lease_owner: null, lease_expires_at: null });

    const originalLease = harness.fake.repo.leaseDueScans;
    harness.fake.repo.leaseDueScans = async (ctx, options) => {
      const leased = await originalLease(ctx, options);
      cancelDuringDispatch = true;
      await harness.services.cancelValidationScan(CTX, scan.id, { reason: 'operator stop', now: NOW });
      return leased;
    };
    const due = new Date(NOW.getTime() + 11 * 60_000);
    const results = await harness.services.dispatchDueValidationScans(CTX, { now: due, workerId: 'w1', runtimeConfig: RUNTIME_CONFIG });
    assert.ok(cancelDuringDispatch);
    assert.deepEqual(results, [{ scan_id: scan.id, dispatched: false, reason: 'lease_lost' }]);
    assert.equal(harness.fake.scans.get(scan.id).status, 'cancelled');
    assert.equal(harness.startCalls.length, 0);
  });

  it('isolates a failing scheduled dispatch so the rest of the tenant tick continues', async () => {
    const harness = createHarness();
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID], scheduled_for: scheduledFor }, RUNTIME_CONFIG, { now: NOW });
    harness.fake.repo.listSteps = async () => { throw new Error('transient'); };
    const due = new Date(NOW.getTime() + 11 * 60_000);
    const results = await harness.services.dispatchDueValidationScans(CTX, { now: due, workerId: 'w1', runtimeConfig: RUNTIME_CONFIG });
    assert.deepEqual(results, [{ scan_id: scan.id, dispatched: false, reason: 'dispatch_failed' }]);
    assert.ok(harness.fake.audits.some((entry) => entry.action === SCAN_AUDIT_ACTIONS.dispatchFailed));
  });

  it('cancel_series cancels upcoming occurrences even when next_scan_id was not linked yet', async () => {
    const harness = createHarness();
    const scheduledFor = new Date(NOW.getTime() + 10 * 60_000).toISOString();
    const scan = await harness.services.createValidationScan(CTX, {
      target_group_id: GROUP_ID,
      check_ids: [CHECK_ID],
      scheduled_for: scheduledFor,
      recurrence: { cadence: 'daily' },
    }, RUNTIME_CONFIG, { now: NOW });
    const due = new Date(NOW.getTime() + 11 * 60_000);
    await harness.services.dispatchDueValidationScans(CTX, { now: due, workerId: 'w1', runtimeConfig: RUNTIME_CONFIG });
    const next = [...harness.fake.scans.values()].find((row) => row.id !== scan.id);
    harness.fake.scans.set(scan.id, { ...harness.fake.scans.get(scan.id), next_scan_id: null });
    await harness.services.cancelValidationScan(CTX, scan.id, { reason: 'stop series', cancel_series: true, now: due });
    assert.equal(harness.fake.scans.get(next.id).status, 'cancelled');
    assert.equal(harness.fake.scans.get(scan.id).recurrence, null);
  });

  it('activity cursor returns late observations whose event time precedes the cursor', async () => {
    const harness = createHarness();
    const scan = await harness.services.createValidationScan(CTX, { target_group_id: GROUP_ID, check_ids: [CHECK_ID], target_id: TARGET_A }, RUNTIME_CONFIG, { now: NOW });
    const first = await harness.services.getValidationScanActivity(CTX, scan.id, { runtimeConfig: RUNTIME_CONFIG });
    assert.match(first.cursor, /^c1\./);
    await harness.fake.repo.appendScanAudit(CTX, {
      action: 'observation.ingested',
      resource_type: 'test_run',
      resource_id: 'run_1',
      metadata: { test_run_id: 'run_1' },
    }, { now: new Date(NOW.getTime() - 60_000) });
    const next = await harness.services.getValidationScanActivity(CTX, scan.id, { after: first.cursor, runtimeConfig: RUNTIME_CONFIG });
    assert.deepEqual(next.items.map((item) => item.action), ['observation.ingested']);
    const empty = await harness.services.getValidationScanActivity(CTX, scan.id, { after: next.cursor, runtimeConfig: RUNTIME_CONFIG });
    assert.equal(empty.count, 0);
  });

  it('lists scans whose combined child runs exceed one evidence batch, and filters by exact target', async () => {
    const harness = createHarness();
    const batchSizes = [];
    const capped = (label) => (ids) => {
      batchSizes.push([label, ids.length]);
      if (ids.length > 500) throw new RangeError(`${label} accepts at most 500 run ids.`);
    };
    const checkRuns = capped('listTestRunsByIds');
    const checkEvidence = capped('loadRunEvidenceBatch');
    const checkJobs = capped('listProbeJobsForRuns');
    const listRunsByIds = async (ctx, ids) => { checkRuns(ids); return ids.map((id) => harness.runs.get(id)).filter(Boolean); };
    const services = createPostgresValidationScanServices({
      validationScans: { ...harness.fake.repo, async listProbeJobsForRuns(ctx, ids) { checkJobs(ids); return []; } },
      validationEvidence: {
        async listTestRuns() { return []; },
        async getTestRun(ctx, id) { return harness.runs.get(id) ?? null; },
        async getTestRunByScanStepId() { return null; },
        async getVerdictForRun() { return null; },
        async listRunEvents() { return []; },
        listTestRunsByIds: listRunsByIds,
        async loadRunEvidenceBatch(ctx, selection) { checkEvidence(selection.runIds); return { verdicts: [], events: [] }; },
      },
      coreCatalog: { async getTargetGroup(ctx, id) { return id === GROUP_ID && ctx.tenantId === TENANT ? group() : null; } },
      killSwitch: { async isKillSwitchActiveForTenant() { return false; } },
    }, { testRuns: { async startTestRun() { return { error: 'unused', status: 500 }; }, async cancelTestRun() { return null; }, async getTestRun(ctx, id) { return harness.runs.get(id) ?? null; }, registerRunTerminalHook() { return () => {}; } }, now: () => NOW, runtimeConfig: RUNTIME_CONFIG });

    let runCounter = 0;
    for (const [scanId, targetId] of [['scan_big_a', TARGET_A], ['scan_big_b', TARGET_B]]) {
      harness.fake.scans.set(scanId, {
        id: scanId, tenant_id: TENANT, target_group_id: GROUP_ID, target_id: targetId, status: 'completed',
        check_ids: [CHECK_ID], created_at: new Date(NOW.getTime() + runCounter).toISOString(),
      });
      for (let position = 0; position < 300; position += 1) {
        runCounter += 1;
        const runId = `run_big_${runCounter}`;
        harness.runs.set(runId, { id: runId, tenant_id: TENANT, target_group_id: GROUP_ID, target_id: targetId, check_id: CHECK_ID, status: 'verdicted' });
        harness.fake.steps.set(`step_big_${runCounter}`, {
          id: `step_big_${runCounter}`, tenant_id: TENANT, scan_id: scanId, position, check_id: CHECK_ID,
          target_id: targetId, status: 'verdicted', test_run_id: runId, request_snapshot: {},
        });
      }
    }

    const all = await services.listValidationScans(CTX, { target_group_id: GROUP_ID, limit: 10 });
    assert.equal(all.count, 2);
    assert.deepEqual(all.items.map((scan) => scan.steps.length), [300, 300]);
    assert.ok(batchSizes.length >= 3 && batchSizes.every(([, size]) => size <= 500), JSON.stringify(batchSizes));

    const exact = await services.listValidationScans(CTX, { target_group_id: GROUP_ID, target_id: TARGET_A, limit: 1 });
    assert.deepEqual(exact.items.map((scan) => scan.id), ['scan_big_a']);
  });
});
