import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test, beforeEach } from 'node:test';
import { freshStore } from '../helpers/reset.mjs';
import { readFileSync, statSync } from 'node:fs';
import { getStore, persistStore, resolveDataFile } from '../../src/store.mjs';
import { createTargetDirect, importTargets } from '../../src/services/targetGroups.mjs';
import { devInitialEdgeDetections } from '../../src/services/initialEdgeDetections.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { createValidationScan } from '../../src/services/validationScans.mjs';
import { recordDnsVerification } from '../helpers/subdomain-fixtures.mjs';
import { processLeasedProbeBatch } from '../../workers/probe-worker.mjs';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';
import { loadInitialEdgeDetectionRunnerConfig } from '../../src/config.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const runtimeConfig = { probeMode: 'simulation', featureFlags: { wafPostureEnabled: true } };
beforeEach(() => { freshStore(); });

test('the initial-observation runner requires only dispatch credentials and strict WAF feature flags', () => {
  const config = loadInitialEdgeDetectionRunnerConfig({ NODE_ENV: 'test', ASTRANULL_PROBE_MODE: 'simulation', ASTRANULL_WAF_POSTURE_ENABLED: '1' });
  assert.equal(config.featureFlags.wafPostureEnabled, true);
  assert.equal(config.probeMode, 'simulation');
  assert.throws(() => loadInitialEdgeDetectionRunnerConfig({ NODE_ENV: 'test', ASTRANULL_WAF_POSTURE_ENABLED: 'yes' }), /must be/);
});

test('domain, child and CSV creation queue one initial detection without client navigation', async () => {
  const parent = createTargetDirect(ctx, { kind: 'fqdn', value: 'example.test' });
  const child = createTargetDirect(ctx, { kind: 'fqdn', value: 'api.example.test', target_group_id: parent.target_group_id,
    tags: [`subdomain-of:${parent.id}`] });
  const imported = importTargets(ctx, parent.target_group_id, [{ kind: 'fqdn', value: 'csv.example.test' }]);
  assert.equal(imported.error, undefined);
  assert.equal(getStore().initialEdgeDetections.length, 3);
  assert.equal(getStore().testRuns.length, 0);
  const requests = await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig });
  assert.ok(requests.every((row) => row.blocked_reason === 'ownership_not_verified'));
  recordDnsVerification(ctx, parent);
  const detail = getTargetDetail(ctx, child.id);
  assert.equal(detail.verification.state, 'dns_verified');
  assert.equal(detail.verification.source_kind, 'inherited_parent');
  const later = new Date(Date.now() + 31_000);
  const dispatched = await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig, now: later });
  assert.equal(dispatched.filter((row) => row.status === 'dispatched').length, 2);
  assert.equal(getStore().testRuns.filter((run) => [parent.id, child.id].includes(run.target_id)).length, 2);
  await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig, now: new Date(Date.now() + 62_000) });
  assert.equal(getStore().testRuns.length, 2, 'accepted initial requests never duplicate');
});

test('idle dispatch ticks leave the dev store file untouched while real claims persist', async () => {
  const oldNoPersist = process.env.ASTRANULL_NO_PERSIST;
  const oldMode = process.env.ASTRANULL_PERSISTENCE_MODE;
  delete process.env.ASTRANULL_NO_PERSIST;
  delete process.env.ASTRANULL_PERSISTENCE_MODE;
  try {
    const target = createTargetDirect(ctx, { kind: 'fqdn', value: 'idle.test' });
    persistStore();
    const stored = () => JSON.parse(readFileSync(resolveDataFile(), 'utf8')).initialEdgeDetections.find((row) => row.target_id === target.id);
    const identity = () => {
      const { ino, ctimeNs, mtimeNs } = statSync(resolveDataFile(), { bigint: true });
      return `${ino}:${ctimeNs}:${mtimeNs}`;
    };
    const attemptsBefore = stored().attempts;
    const later = new Date(Date.now() + 31_000);
    const claimed = await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig, now: later });
    assert.deepEqual(claimed.map((row) => row.target_id), [target.id]);
    assert.equal(stored().attempts, attemptsBefore + 1, 'a claimed lease is durably persisted');
    const afterClaim = identity();
    assert.deepEqual(await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig, now: later }), []);
    assert.equal(identity(), afterClaim, 'an idle tick performs no store write');
  } finally {
    if (oldNoPersist === undefined) delete process.env.ASTRANULL_NO_PERSIST; else process.env.ASTRANULL_NO_PERSIST = oldNoPersist;
    if (oldMode === undefined) delete process.env.ASTRANULL_PERSISTENCE_MODE; else process.env.ASTRANULL_PERSISTENCE_MODE = oldMode;
  }
});

test('independent targets sharing policy can run together while same-target overlap remains denied', () => {
  const first = createTargetDirect(ctx, { kind: 'fqdn', value: 'one.test' });
  const second = createTargetDirect(ctx, { kind: 'fqdn', value: 'two.test' });
  const group = getStore().targetGroups.find((row) => row.id === first.target_group_id);
  group.safety_policy = { min_seconds_between_runs: 0, max_runs_per_hour: 100 };
  const run = (target) => startTestRun(ctx, { target_group_id: group.id, target_id: target.id, check_id: 'waf.fingerprint.safe' }, runtimeConfig);
  assert.ok(run(first).run);
  assert.ok(run(second).run);
  assert.equal(run(first).error, 'concurrent_run_blocked');
});

test('independent scans reserve only their own targets and reject overlapping target sets', () => {
  const first = createTargetDirect(ctx, { kind: 'fqdn', value: 'one.test' });
  const second = createTargetDirect(ctx, { kind: 'fqdn', value: 'two.test' });
  getStore().targetGroups.find((row) => row.id === first.target_group_id).safety_policy = { min_seconds_between_runs: 0, max_runs_per_hour: 100 };
  const scan = (id) => createValidationScan(ctx, { target_id: id, check_ids: ['waf.fingerprint.safe'] }, runtimeConfig);
  assert.equal(scan(first.id).status, 'running');
  assert.equal(scan(second.id).status, 'running');
  assert.equal(scan(first.id).error, 'concurrent_scan_blocked');
});

test('automatic detection dispatches without feature gates and follows an accepted result', async () => {
  const target = createTargetDirect(ctx, { kind: 'fqdn', value: 'one.test' });
  recordDnsVerification(ctx, target);
  const first = await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig: { probeMode: 'simulation' } });
  assert.equal(first[0].blocked_reason, null);
  assert.ok(first[0].test_run_id);
  const manual = startTestRun(ctx, { target_group_id: target.target_group_id, target_id: target.id, check_id: 'waf.fingerprint.safe' }, runtimeConfig);
  assert.equal(manual.error, 'concurrent_run_blocked');
  const again = await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig, now: new Date(Date.now() + 31_000) });
  assert.equal(again.length, 0);
  assert.equal(getStore().testRuns.length, 1);
});

test('probe worker processes independent leased jobs concurrently within its fixed four-job cap', async () => {
  let active = 0; let peak = 0;
  const output = await processLeasedProbeBatch(Array.from({ length: 9 }, (_, index) => index), async (job) => {
    active += 1; peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, 5)); active -= 1; return job;
  });
  assert.equal(peak, 4);
  assert.deepEqual(output, Array.from({ length: 9 }, (_, index) => index));
  const activeTargets = new Set();
  await processLeasedProbeBatch([{ target_id: 'a' }, { target_id: 'a' }, { target_id: 'b' }], async (job) => {
    assert.equal(activeTargets.has(job.target_id), false);
    activeTargets.add(job.target_id); await new Promise((resolve) => setTimeout(resolve, 5)); activeTargets.delete(job.target_id);
  });
});

test('a lost queue lease reconciles an accepted manual observation without a duplicate dispatch', async () => {
  const target = createTargetDirect(ctx, { kind: 'fqdn', value: 'one.test' });
  recordDnsVerification(ctx, target);
  const queued = getStore().initialEdgeDetections[0];
  Object.assign(queued, { status: 'leased', lease_expires_at: new Date(Date.now() - 1000).toISOString(), lease_token: 'expired' });
  const existing = startTestRun(ctx, { target_group_id: target.target_group_id, target_id: target.id, check_id: 'waf.fingerprint.safe' }, runtimeConfig);
  const result = await devInitialEdgeDetections.dispatchPending(ctx, { runtimeConfig });
  assert.equal(result[0].test_run_id, existing.run.id);
  assert.equal(getStore().testRuns.length, 1);
});
