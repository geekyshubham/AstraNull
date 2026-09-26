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

  it('rejects the whole request when a SOC-gated or unknown check is selected and audits the denial', () => {
    const soc = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe', 'waf.offensive_sqli.soc'] }, RUNTIME);
    assert.equal(soc.error, 'soc_gated_check');
    assert.equal(soc.status, 403);
    assert.equal(soc.check_id, 'waf.offensive_sqli.soc');
    const unknown = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['does.not.exist'] }, RUNTIME);
    assert.equal(unknown.error, 'unknown_check');
    assert.equal(getStore().validationScans.length, 0);
    assert.equal(getStore().testRuns.length, 0);
    assert.deepEqual(auditActions((entry) => entry.action === 'validation_scan.create_denied').length, 2);
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

  it('defers the next step while the target-group cooldown is active and resumes when eligible', () => {
    getStore().targetGroups[0].safety_policy = { min_seconds_between_runs: 300 };
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['dns.authoritative_response.safe', 'origin.leak_scan.safe'] }, RUNTIME);
    expireCollectionWindows();
    const deferred = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.deepEqual(deferred.steps.map((step) => step.status), ['verdicted', 'deferred']);
    assert.ok(deferred.steps[1].eligible_at);
    assert.equal(deferred.next_eligible_at, deferred.steps[1].eligible_at);
    assert.equal(getStore().testRuns.length, 1);
    assert.ok(auditActions().includes('validation_scan.step_deferred'));

    getStore().testRuns[0].created_at = new Date(Date.now() - 301_000).toISOString();
    const resumed = advanceScan(CTX, scan.id, {
      runtimeConfig: RUNTIME,
      now: new Date(new Date(deferred.steps[1].eligible_at).getTime() + 1000),
    });
    assert.equal(resumed.acquired, true);
    const after = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.equal(after.steps[1].status, 'collecting');
    assert.equal(getStore().testRuns.length, 2);
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
    getStore().targetGroups[0].safety_policy = { min_seconds_between_runs: 300 };
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe', 'dns.authoritative_response.safe'] }, RUNTIME);
    expireCollectionWindows();
    const deferred = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.deepEqual(deferred.steps.map((step) => step.status), ['verdicted', 'deferred']);
    const stored = getStore().validationScans[0];
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
    assert.equal(getStore().testRuns.length, 1);
    const bodyOnly = startTestRun(
      CTX,
      { check_id: 'dns.authoritative_response.safe', target_group_id: 'tg_1', target_id: 'tgt_1', scan_id: scan.id, scan_step_id: stored.steps[1].id },
      RUNTIME,
    );
    assert.equal(bodyOnly.error, 'safe_min_interval_active');
    assert.equal(getStore().testRuns.some((run) => run.scan_step_id === stored.steps[1].id), false);
  });
});

describe('validation scans (dev-json): stop and activity', () => {
  beforeEach(() => freshStore());

  it('stops a scan mid-flight, cancels the active child and its jobs, and skips pending steps', () => {
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: CHECKS }, RUNTIME);
    const activeRun = getStore().testRuns[0];
    getStore().agentJobs.push({ id: 'job_1', tenant_id: 'ten_demo', agent_id: 'agt_1', test_run_id: activeRun.id, status: 'pending' });
    getStore().probeJobs.push({ id: 'pjob_1', tenant_id: 'ten_demo', test_run_id: activeRun.id, status: 'pending' });

    const stopped = cancelValidationScan(CTX, scan.id, { reason: 'operator stop' });
    assert.equal(stopped.status, 'cancelled');
    assert.equal(stopped.cancel_reason, 'operator stop');
    assert.equal(stopped.cancelled_by, 'usr_engineer');
    assert.deepEqual(stopped.steps.map((step) => step.status), ['cancelled', 'skipped', 'skipped']);
    assert.equal(activeRun.status, 'cancelled');
    assert.equal(getStore().agentJobs[0].status, 'cancelled');
    assert.equal(getStore().probeJobs[0].status, 'cancelled');
    assert.equal(activeRun.summary.cancellation.source, 'scan');
    assert.equal(getStore().testRuns.length, 1);

    const runCancelAudit = getStore().auditLog.find((entry) => entry.action === 'test_run.cancelled');
    assert.equal(runCancelAudit.metadata.reason, 'operator stop');
    assert.equal(runCancelAudit.metadata.cancelled_by, 'usr_engineer');
    assert.deepEqual(runCancelAudit.metadata.cancelled_agent_job_ids, ['job_1']);
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

  it('defers a step on the hourly safe-run cap instead of aborting the scan', () => {
    getStore().targetGroups[0].safety_policy = { max_runs_per_hour: 1 };
    const scan = createValidationScan(CTX, { target_group_id: 'tg_1', check_ids: CHECKS.slice(0, 2), target_id: 'tgt_1' }, RUNTIME);
    expireCollectionWindows();
    const current = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME });
    assert.equal(current.status, 'running');
    assert.deepEqual(current.steps.map((step) => step.status), ['verdicted', 'deferred']);
    const firstRunAt = new Date(getStore().testRuns[0].created_at).getTime();
    assert.equal(current.steps[1].eligible_at, new Date(firstRunAt + 3_600_000 + 1000).toISOString());
  });
});

