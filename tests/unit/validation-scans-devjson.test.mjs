import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  advanceScan,
  cancelValidationScan,
  createValidationScan,
  getValidationScan,
  getValidationScanActivity,
  listValidationScans,
} from '../../src/services/validationScans.mjs';
import { autoCancelActiveSafeRunsForKillSwitch, startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_engineer', role: 'engineer' };
const VIEWER = { tenantId: 'ten_demo', userId: 'usr_viewer', role: 'viewer' };
const RUNTIME = { probeMode: 'simulation' };
const CHECKS = ['dns.authoritative_response.safe', 'origin.leak_scan.safe', 'l3.firewall_exposure_scan.safe'];

function expireCollectionWindows() {
  for (const run of getStore().testRuns) {
    run.collection_deadline_at = new Date(Date.now() - 1000).toISOString();
  }
}

function auditActions(filter = () => true) {
  return getStore().auditLog.filter(filter).map((entry) => entry.action);
}

function bypassedGates() {
  return getStore().auditLog
    .filter((entry) => entry.action === 'test_run.demo_gates_bypassed')
    .flatMap((entry) => entry.metadata?.bypassed ?? []);
}

describe('validation scans (dev-json): selection and sequential execution', () => {
  beforeEach(() => freshStore());

  it('runs only the selected checks, one child run at a time, in selection order', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', target_id: 'tgt_1', check_ids: CHECKS }, RUNTIME);
    assert.equal(scan.status, 'running');
    assert.equal(scan.summary.total, 3);
    assert.deepEqual(scan.steps.map((step) => step.status), ['collecting', 'pending', 'pending']);
    assert.equal(getStore().testRuns.length, 1);
    assert.equal(getStore().testRuns[0].check_id, CHECKS[0]);
    assert.equal(getStore().testRuns[0].scan_id, scan.id);
    assert.equal(getStore().testRuns[0].scan_step_id, scan.steps[0].step_id);

    expireCollectionWindows();
    const viewerRead = getValidationScan(VIEWER, scan.id, { runtimeConfig: RUNTIME });
    assert.deepEqual(viewerRead.steps.map((step) => step.status), ['collecting', 'pending', 'pending']);
    assert.equal(getStore().testRuns.length, 1, 'read-only callers never advance or start child runs');
    const second = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.deepEqual(second.steps.map((step) => step.status), ['verdicted', 'collecting', 'pending']);
    assert.equal(second.steps[0].verdict.verdict, 'inconclusive');
    assert.equal(second.steps[0].requests_sent, 0);
    assert.equal(second.steps[0].requests_simulated, true);
    assert.equal(second.steps[0].response.external_result, 'blocked');
    assert.equal(second.steps[0].request.protocol, 'dns');
    assert.equal(getStore().testRuns.length, 2);

    expireCollectionWindows();
    getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    expireCollectionWindows();
    const done = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.equal(done.status, 'completed');
    assert.deepEqual(done.steps.map((step) => step.status), ['verdicted', 'verdicted', 'verdicted']);
    assert.deepEqual(getStore().testRuns.map((run) => run.check_id), CHECKS);
    assert.equal(done.completed_at != null, true);
    const actions = auditActions((entry) => entry.resource_type === 'validation_scan' && entry.resource_id === scan.id);
    assert.equal(actions.filter((action) => action === 'validation_scan.step_started').length, 3);
    assert.equal(actions.filter((action) => action === 'validation_scan.step_completed').length, 3);
    assert.equal(actions.at(-1), 'validation_scan.completed');
  });

  it('accepts a SOC-gated check and rejects an unknown check', () => {
    const soc = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe', 'waf.offensive_sqli.soc'] }, RUNTIME);
    assert.equal(soc.error, undefined);
    assert.equal(soc.status, 'running');
    const unknown = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['does.not.exist'] }, RUNTIME);
    assert.equal(unknown.error, 'unknown_check');
    assert.equal(getStore().validationScans.length, 1);
    assert.deepEqual(auditActions((entry) => entry.action === 'validation_scan.create_denied').length, 1);
  });

  it('expands whole-group scans across compatible targets and records incompatible pairs', () => {
    getStore().targets.push({
      id: 'tgt_url',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      kind: 'url',
      value: 'https://app.test/health',
      expected_behavior: 'must_block_before_origin',
    });
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['dns.authoritative_response.safe', 'origin.leak_scan.safe'] }, RUNTIME);
    assert.equal(scan.target, null);
    assert.equal(scan.summary.total, 3);
    assert.deepEqual(scan.excluded.map((row) => [row.check_id, row.target_id]), [['dns.authoritative_response.safe', 'tgt_url']]);
    const exact = createValidationScan(CTX, { target_group_id: 'tg_1', target_id: 'tgt_url', check_ids: ['dns.authoritative_response.safe'] }, RUNTIME);
    assert.equal(exact.error, 'target_kind_not_supported');
  });

  it('blocks a second active scan or an active foreign run on the same group', () => {
    const first = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe'] }, RUNTIME);
    assert.equal(first.status, 'running');
    const second = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe'] }, RUNTIME);
    assert.equal(second.error, 'concurrent_scan_blocked');
    assert.equal(second.status, 409);
  });

  it('starts the next step past the hourly cap and only records the bypass', () => {
    // Group safety policies are advisory now; the cap is still counted but never defers a step.
    getStore().targetGroups[0].safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 0 };
    process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR = '1';
    try {
      const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['dns.authoritative_response.safe', 'origin.leak_scan.safe'] }, RUNTIME);
      expireCollectionWindows();
      const advanced = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
      assert.deepEqual(advanced.steps.map((step) => step.status), ['verdicted', 'collecting']);
      assert.equal(advanced.next_eligible_at, null);
      assert.equal(getStore().testRuns.length, 2);
      assert.ok(!auditActions().includes('validation_scan.step_deferred'));
      assert.ok(bypassedGates().includes('hourly_cap'), 'the bypass stays recorded');

      expireCollectionWindows();
      const finished = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
      assert.equal(finished.status, 'completed');
      assert.equal(getStore().testRuns.length, 2);
    } finally {
      delete process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR;
    }
  });

  it('aborts the remaining steps when the kill switch cancels the active child', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: CHECKS }, RUNTIME);
    getStore().socKillSwitch = { active: true, reason: 'incident', tenant_id: null };
    const cancelled = autoCancelActiveSafeRunsForKillSwitch({ tenantId: 'ten_demo', userId: 'usr_soc', role: 'soc' }, 'incident');
    assert.equal(cancelled.length, 1);
    const after = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.equal(after.status, 'denied');
    assert.equal(after.abort_reason, 'kill_switch_active');
    assert.deepEqual(after.steps.map((step) => step.status), ['cancelled', 'denied', 'skipped']);
    assert.equal(after.steps[2].skip_reason, 'scan_aborted:kill_switch_active');
    assert.equal(getStore().testRuns.length, 1);
    assert.ok(auditActions().includes('test_run.kill_switch_denied'));
  });

  it('rejects forged or conflicting scan dispatch contexts inside startTestRun', () => {
    getStore().targetGroups[0].safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 0 };
    process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR = '1';
    try {
      const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe', 'dns.authoritative_response.safe'] }, RUNTIME);
      expireCollectionWindows();
      const advanced = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
      assert.deepEqual(advanced.steps.map((step) => step.status), ['verdicted', 'collecting']);
      const stored = getStore().validationScans[0];
      // Cancel the active child so the dispatcher checks, not the concurrency guard, answer these.
      getStore().testRuns[1].status = 'verdicted';
      const forged = startTestRun(
        CTX,
        { check_id: 'dns.authoritative_response.safe', target_group_id: 'tg_1', target_id: 'tgt_1' },
        RUNTIME,
        { scanDispatch: { scan_id: scan.id, step_id: stored.steps[1].id, lease_token: 'forged' } },
      );
      assert.equal(forged.error, 'scan_dispatch_invalid');
      const conflicting = startTestRun(
        CTX,
        { check_id: 'dns.authoritative_response.safe', target_group_id: 'tg_1', target_id: 'tgt_1', policy_id: 'pol_x' },
        RUNTIME,
        { scanDispatch: { scan_id: scan.id, step_id: stored.steps[1].id, lease_token: 'forged' } },
      );
      assert.equal(conflicting.error, 'conflicting_dispatch_context');
      assert.equal(getStore().testRuns.length, 2);
      const bodyOnly = startTestRun(
        CTX,
        { check_id: 'dns.authoritative_response.safe', target_group_id: 'tg_1', target_id: 'tgt_1', scan_id: scan.id, scan_step_id: stored.steps[1].id },
        RUNTIME,
      );
      assert.equal(bodyOnly.error, 'concurrent_run_blocked');
      assert.equal(getStore().testRuns.filter((run) => run.scan_step_id === stored.steps[1].id).length, 1);
    } finally {
      delete process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR;
    }
  });
});

describe('validation scans (dev-json): stop and activity', () => {
  beforeEach(() => freshStore());

  it('stops a scan mid-flight, cancels the active child and its jobs, and skips pending steps', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: CHECKS }, RUNTIME);
    const activeRun = getStore().testRuns[0];
    getStore().probeJobs.push({ id: 'pjob_1', tenant_id: 'ten_demo', test_run_id: activeRun.id, status: 'pending' });

    const stopped = cancelValidationScan(CTX, scan.id, { reason: 'operator stop' });
    assert.equal(stopped.status, 'cancelled');
    assert.equal(stopped.cancel_reason, 'operator stop');
    assert.equal(stopped.cancelled_by, 'usr_engineer');
    assert.deepEqual(stopped.steps.map((step) => step.status), ['cancelled', 'skipped', 'skipped']);
    assert.equal(activeRun.status, 'cancelled');
    assert.equal(getStore().probeJobs[0].status, 'cancelled');
    assert.equal(activeRun.summary.cancellation.source, 'scan');
    assert.equal(getStore().testRuns.length, 1);

    const runCancelAudit = getStore().auditLog.find((entry) => entry.action === 'test_run.cancelled');
    assert.equal(runCancelAudit.metadata.reason, 'operator stop');
    assert.equal(runCancelAudit.metadata.cancelled_by, 'usr_engineer');
    assert.deepEqual(runCancelAudit.metadata.cancelled_probe_job_ids, ['pjob_1']);
    const scanCancelAudit = getStore().auditLog.find((entry) => entry.action === 'validation_scan.cancelled');
    assert.equal(scanCancelAudit.metadata.skipped_steps, 2);
    assert.equal(scanCancelAudit.metadata.cancelled_steps, 1);

    const again = cancelValidationScan(CTX, scan.id, { reason: 'twice' });
    assert.equal(again.error, 'not_cancellable');
    const after = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.equal(after.status, 'cancelled');
    assert.equal(getStore().testRuns.length, 1);
  });

  it('exposes a chronological metadata-only activity feed and a filtered list envelope', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['dns.authoritative_response.safe'] }, RUNTIME);
    expireCollectionWindows();
    getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    const activity = getValidationScanActivity(VIEWER, scan.id, { runtimeConfig: RUNTIME });
    const actions = activity.items.map((item) => item.action);
    assert.equal(actions[0], 'validation_scan.created');
    assert.ok(actions.includes('validation_scan.step_started'));
    assert.ok(actions.includes('probe_result'));
    assert.ok(actions.includes('validation_scan.step_completed'));
    assert.equal(actions.at(-1), 'validation_scan.completed');
    for (const item of activity.items) {
      assert.equal(Object.prototype.hasOwnProperty.call(item, 'payload'), false);
      assert.equal(JSON.stringify(item).includes('nonce_for'), false);
    }
    const page = getValidationScanActivity(VIEWER, scan.id, { after: activity.items[1].id, runtimeConfig: RUNTIME });
    assert.equal(page.items[0].id, activity.items[2].id);

    const listed = listValidationScans(VIEWER, { target_group_id: 'tg_1', runtimeConfig: RUNTIME });
    assert.equal(listed.count, 1);
    assert.equal(listed.items[0].status, 'completed');
    const filtered = listValidationScans(VIEWER, { status: 'scheduled', runtimeConfig: RUNTIME });
    assert.equal(filtered.count, 0);
    assert.ok(filtered.meta.empty_reason);
  });
});

describe('validation scans (dev-json): parity guards', () => {
  beforeEach(() => freshStore());

  it('does not start a run or advance scans when listing (finding 9)', () => {
    // A scheduled scan that is already due.
    const scan = createValidationScan(
      CTX,
      { target_group_id: 'tg_1', target_id: 'tgt_1', check_ids: ['dns.authoritative_response.safe'], scheduled_for: '2026-06-01T13:00:00.000Z' },
      RUNTIME,
      { now: new Date('2026-06-01T12:00:00.000Z') },
    );
    assert.equal(scan.status, 'scheduled');
    const before = getStore().testRuns.length;
    // Listing at a time when the scan is due must NOT dispatch it or start a run (parity with
    // Postgres, whose list is a pure read).
    const listed = listValidationScans(CTX, { runtimeConfig: RUNTIME, now: new Date('2026-06-01T13:00:01.000Z') });
    assert.equal(listed.items[0].status, 'scheduled');
    assert.equal(getStore().testRuns.length, before);
    // The single-scan read path still advances (unchanged behavior).
    const got = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME, now: new Date('2026-06-01T13:00:01.000Z') });
    assert.equal(got.status, 'running');
  });

  it('cancel also stops an active child run that is not linked to its step yet', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: CHECKS }, RUNTIME);
    const stored = getStore().validationScans.find((row) => row.id === scan.id);
    const run = getStore().testRuns[0];
    stored.steps[0].test_run_id = null;
    stored.steps[0].status = 'pending';
    const stopped = cancelValidationScan(CTX, scan.id, { reason: 'stop' });
    assert.equal(run.status, 'cancelled');
    assert.equal(stopped.steps[0].status, 'cancelled');
    assert.equal(stopped.steps[0].test_run_id, run.id);
  });

  it('does not start steps without signing material and audits the blocked advance', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: CHECKS }, { probeMode: 'signed-worker', probeWorkerSecret: '' });
    assert.equal(getStore().testRuns.length, 0);
    assert.deepEqual(scan.steps.map((step) => step.status), ['pending', 'pending', 'pending']);
    assert.ok(auditActions().includes('validation_scan.advance_blocked'));
  });

  it('runs through the hourly safe-run cap instead of deferring the step', () => {
    getStore().targetGroups[0].safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 0 };
    process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR = '1';
    try {
      const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: CHECKS.slice(0, 2), target_id: 'tgt_1' }, RUNTIME);
      expireCollectionWindows();
      const current = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
      assert.equal(current.status, 'running');
      assert.deepEqual(current.steps.map((step) => step.status), ['verdicted', 'collecting']);
      assert.equal(current.steps[1].eligible_at, null);
    } finally {
      delete process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR;
    }
  });
});


describe('explicit domain sets preserve each target execution policy', () => {
  beforeEach(() => {
    freshStore();
    const store = getStore();
    store.targetGroups[0].safety_policy = { max_runs_per_hour: 60, min_seconds_between_runs: 0 };
    store.targetGroups.push({ ...store.targetGroups[0], id: 'tg_second', name: 'legacy policy', safety_policy: { max_runs_per_hour: 60, min_seconds_between_runs: 0 } });
    store.targets.push({ ...store.targets[0], id: 'tgt_second', target_group_id: 'tg_second', value: 'second.test' });
  });

  it('executes an explicit domain set sequentially across existing policy bindings', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', target_ids: ['tgt_1', 'tgt_second'], check_ids: [CHECKS[0]] }, RUNTIME);
    assert.deepEqual(scan.target_ids, ['tgt_1', 'tgt_second']);
    assert.equal(scan.summary.total, 2);
    assert.equal(getStore().testRuns[0].target_group_id, 'tg_1');
    getStore().targets.push({ ...getStore().targets[0], id: 'tgt_unselected', value: 'unselected.test' });
    expireCollectionWindows();
    const next = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.equal(next.steps[1].status, 'collecting');
    assert.equal(getStore().testRuns[1].target_group_id, 'tg_second');
    assert.ok(listValidationScans(CTX, { target_id: 'tgt_second' }).items.some((item) => item.id === scan.id));
    expireCollectionWindows();
    assert.equal(getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME }).status, 'completed');
    assert.equal(getStore().testRuns.length, 2);
    assert.ok(getStore().testRuns.every((run) => run.target_id !== 'tgt_unselected'));
  });

  it('runs a later domain past the hourly cap and records the bypass on its own run', () => {
    getStore().targetGroups[0].safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 0 };
    getStore().targetGroups[1].safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 0 };
    process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR = '2';
    try {
      const priorAt = new Date(Date.now() - 60_000).toISOString();
      getStore().testRuns.push({ id: 'prior', tenant_id: CTX.tenantId, target_group_id: 'tg_second', target_id: 'tgt_second', check_id: CHECKS[0], created_at: priorAt, status: 'verdicted' });
      const scan = createValidationScan(CTX, { target_group_id: 'tg_1', target_ids: ['tgt_1', 'tgt_second'], check_ids: [CHECKS[0]] }, RUNTIME);
      expireCollectionWindows();
      const next = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
      assert.equal(next.steps[1].status, 'collecting');
      assert.equal(getStore().testRuns.length, 3);
      const secondRun = getStore().testRuns.find((run) => run.target_id === 'tgt_second' && run.id !== 'prior');
      assert.equal(secondRun.target_group_id, 'tg_second');
      assert.ok(bypassedGates().includes('hourly_cap'));
    } finally {
      delete process.env.ASTRANULL_DEMO_MAX_RUNS_PER_HOUR;
    }
  });

  it('rejects an absent or foreign domain before creating a scan or starting a run', () => {
    const denied = createValidationScan(CTX, { target_group_id: 'tg_1', target_ids: ['tgt_1', 'foreign'], check_ids: [CHECKS[0]] }, RUNTIME);
    assert.equal(denied.error, 'target_not_found');
    assert.equal(getStore().testRuns.length, 0);
    assert.equal(getStore().validationScans.length, 0);
  });

  it('projects demo required_input_missing step with verdict explanation_reason and required_input', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', target_id: 'tgt_1', check_ids: [CHECKS[0]] }, RUNTIME);
    const step = scan.steps[0];
    const run = getStore().testRuns.find((r) => r.id === step.test_run_id);
    run.status = 'verdicted';
    run.summary = { requests_sent: 0, required_input_missing: 'declared_tcp_deny_required' };
    getStore().verdicts.push({
      id: 'vrd_demo_dev',
      tenant_id: CTX.tenantId,
      test_run_id: run.id,
      target_id: 'tgt_1',
      check_id: CHECKS[0],
      verdict: 'inconclusive',
      confidence: 'external_only',
      explanation: 'No denied port is declared, so there was nothing to probe.',
      explanation_reason: 'required_input_missing',
      required_input: 'declared_tcp_deny_required',
      severity: 'info',
    });
    const projected = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.equal(projected.steps[0].verdict.verdict, 'inconclusive');
    assert.equal(projected.steps[0].verdict.explanation_reason, 'required_input_missing');
    assert.equal(projected.steps[0].verdict.required_input, 'declared_tcp_deny_required');
  });
});
