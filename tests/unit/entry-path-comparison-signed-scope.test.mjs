// PV-04: comparisons start only via the reviewed run start and signed jobs; no sockets or DNS.
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { normalizeEntryPathDeclaration } from '../../src/contracts/protectionValidation.mjs';
import { classifyDirectOriginObservation } from '../../src/lib/externalObservationOutcomes.mjs';
import { verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { computeScopeHashFromTargets } from '../../src/lib/scopeHash.mjs';
import {
  advanceDueEntryPathComparisons,
  cancelEntryPathComparison,
  configureEntryPathComparisonRuntime,
  createEntryPathComparison,
  entryPathComparisonEvaluationRecord,
  finalizeExpiredComparisonRuns,
  getEntryPathComparison,
  listEntryPathComparisons,
  planOrStartEntryPathComparison,
} from '../../src/services/entryPathComparisons.mjs';
import { setKillSwitch } from '../../src/services/highScale.mjs';
import { createOriginBinding } from '../../src/services/originBindings.mjs';
import { finalizeTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const SECRET = 'b'.repeat(32);
const SIGNED = { probeMode: 'signed-worker', probeWorkerSecret: SECRET, featureFlags: { protectionValidationEnabled: true } };
const SIGNED_GATE_OFF = { ...SIGNED, featureFlags: { protectionValidationEnabled: false } };
const TENANT = 'ten_demo';
const CTX = { tenantId: TENANT, userId: 'u1', role: 'admin' };
const VIEWER = { tenantId: TENANT, userId: 'u2', role: 'viewer' };
const SOC = { tenantId: TENANT, userId: 'soc1', role: 'soc' };
const SCENARIO = 'waf.ssrf_marker.safe';
const DECLARED = '2026-09-01T00:00:00.000Z';

configureEntryPathComparisonRuntime(SIGNED);

function addGroup(id) {
  getStore().targetGroups.push({ id, tenant_id: TENANT, environment_id: 'env_demo', name: id, ownership_status: 'dns_verified' });
}

function addTarget(partial) {
  const store = getStore();
  store.targets.push({ tenant_id: TENANT, created_at: DECLARED, ...partial });
  if (!Array.isArray(store.targetVerifications)) store.targetVerifications = [];
  store.targetVerifications.push({
    id: `tv_${partial.id}`,
    tenant_id: TENANT,
    target_id: partial.id,
    state: 'dns_verified',
    source_kind: 'dns_txt',
    source_ref: { dns_challenge_id: `dns_${partial.id}` },
    transitioned_at: new Date().toISOString(),
    transitioned_by: 'system',
  });
}

function relation(id, body) {
  return {
    id,
    ...normalizeEntryPathDeclaration({
      owner: 'App Team',
      purpose: 'Declared route',
      expected_behavior: 'must_be_protected_by_layers',
      required_layers: ['waf'],
      ...body,
    }, { tenantId: TENANT, anchorTargetId: 'tgt_app' }),
    created_at: DECLARED,
  };
}

function seed() {
  freshStore();
  addGroup('tg_2');
  addGroup('tg_3');
  addTarget({ id: 'tgt_app', target_group_id: 'tg_1', kind: 'fqdn', value: 'app.example' });
  addTarget({ id: 'tgt_alt', target_group_id: 'tg_2', kind: 'fqdn', value: 'alt.example', metadata: { redirect_location: 'https://elsewhere.example/' } });
  addTarget({ id: 'tgt_login', target_group_id: 'tg_3', kind: 'url', value: 'https://[2001:db8::5]:8443/login' });
  addTarget({ id: 'tgt_origin', target_group_id: 'tg_1', kind: 'ip', value: '203.0.113.10' });
  const binding = createOriginBinding(CTX, { protected_target_id: 'tgt_app', origin_target_id: 'tgt_origin' });
  assert.equal(binding.error, undefined, JSON.stringify(binding));
  getStore().applicationEntryPaths = [
    relation('ep_primary', { entry_target_id: 'tgt_app', relation_kind: 'primary_route' }),
    relation('ep_alt', { entry_target_id: 'tgt_alt', relation_kind: 'alternate_hostname' }),
    relation('ep_login', { entry_target_id: 'tgt_login', relation_kind: 'declared_login_url' }),
    relation('ep_origin', { entry_target_id: 'tgt_origin', relation_kind: 'origin', origin_binding_id: binding.id }),
  ];
  return binding;
}

function body(mode, extra = {}) {
  return {
    mode,
    anchor_target_id: 'tgt_app',
    primary_entry_path_id: 'ep_primary',
    entry_path_ids: ['ep_primary', 'ep_alt', 'ep_login', 'ep_origin'],
    expectation: { scenario: SCENARIO, layer_outcomes: { waf: 'enforce' } },
    ...extra,
  };
}

function planDigest() {
  const planned = createEntryPathComparison(CTX, body('plan'), SIGNED);
  assert.equal(planned.status, 200, JSON.stringify(planned));
  return planned.plan;
}

function start() {
  const plan = planDigest();
  const started = createEntryPathComparison(CTX, body('start', { reviewed_plan_digest: plan.plan_digest }), SIGNED);
  assert.equal(started.status, 202, JSON.stringify(started));
  return { plan, started, comparison: getStore().entryPathComparisons.find((row) => row.id === started.comparison.id) };
}

function jobForRun(runId) {
  return getStore().probeJobs.find((job) => job.test_run_id === runId);
}

function itemState(comparison, id) {
  return comparison.items.find((row) => row.entry_path_id === id);
}

function markerMetadata({ allowed = 0, blocked = 3 } = {}) {
  return {
    phases: [{ phase: 'baseline', status_code: 200 }],
    marker_results: [
      ...Array.from({ length: blocked }, (_, i) => ({ phase: `b${i}`, blocked: true, allowed: false, inconclusive: false, status_code: 403 })),
      ...Array.from({ length: allowed }, (_, i) => ({ phase: `a${i}`, blocked: false, allowed: true, inconclusive: false, status_code: 200 })),
    ],
  };
}

function completeRun(runId, externalResult, metadata) {
  const store = getStore();
  const run = store.testRuns.find((row) => row.id === runId);
  const job = jobForRun(runId);
  store.events.push({
    id: `event_${runId}`,
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: job.target_id,
    check_id: job.check_id,
    source: 'probe_worker',
    signal_type: 'probe_result',
    producer_kind: 'signed_probe',
    timestamp: new Date().toISOString(),
    nonce_hash: job.nonce_hash,
    metadata: { ...metadata, external_result: externalResult, profile_kind: job.probe_profile.kind, probe_worker_id: 'worker-eu-1' },
  });
  run.correlation.nonce_hash = job.nonce_hash;
  run.probe_external_result = externalResult;
  run.status = 'collecting';
  job.status = 'completed';
  const finalized = finalizeTestRun(CTX, runId, { force: true });
  assert.equal(finalized.error, undefined, JSON.stringify(finalized));
}

function auditCount(action) {
  return getStore().auditLog.filter((row) => row.action === action).length;
}

describe('entry-path comparison planning is passive', () => {
  beforeEach(seed);

  it('plans from exact declarations without starting runs or jobs', () => {
    const plan = planDigest();
    assert.equal(plan.eligible_count, 4);
    assert.equal(getStore().testRuns.length, 0);
    assert.equal(getStore().probeJobs.length, 0);
    assert.equal(auditCount('entry_path_comparison.started'), 0);
    assert.equal(plan.items.find((row) => row.entry_path_id === 'ep_login').target.address_family, 'ipv6');
    assert.equal(plan.items.find((row) => row.entry_path_id === 'ep_login').target.port, 8443);
  });

  it('requires test_run:start and rejects destination overrides', () => {
    assert.equal(createEntryPathComparison(VIEWER, body('plan'), SIGNED).status, 403);
    const override = createEntryPathComparison(CTX, body('plan', { expectation: { scenario: SCENARIO, layer_outcomes: { waf: 'enforce' }, destination: '198.51.100.1' } }), SIGNED);
    assert.equal(override.status, 400);
    assert.equal(override.error, 'scope_not_declared');
  });

  it('rejects a tampered or stale reviewed plan digest and starts nothing', () => {
    const plan = planDigest();
    const flipped = `${plan.plan_digest.slice(0, -1)}${plan.plan_digest.endsWith('0') ? '1' : '0'}`;
    const tampered = createEntryPathComparison(CTX, body('start', { reviewed_plan_digest: flipped }), SIGNED);
    assert.equal(tampered.status, 409);
    assert.equal(tampered.error, 'reviewed_plan_mismatch');
    const store = getStore();
    const alt = store.applicationEntryPaths.find((row) => row.id === 'ep_alt');
    alt.status = 'archived';
    const stale = createEntryPathComparison(CTX, body('start', { reviewed_plan_digest: plan.plan_digest }), SIGNED);
    assert.equal(stale.error, 'reviewed_plan_mismatch');
    assert.equal(store.testRuns.length, 0);
    assert.equal(store.probeJobs.length, 0);
    assert.equal(auditCount('entry_path_comparison.start_denied'), 2);
  });

  it('refuses to start while the kill switch is active', () => {
    const plan = planDigest();
    setKillSwitch(SOC, true, 'hold');
    const denied = createEntryPathComparison(CTX, body('start', { reviewed_plan_digest: plan.plan_digest }), SIGNED);
    assert.equal(denied.status, 423);
    assert.equal(denied.error, 'kill_switch_active');
    assert.equal(getStore().testRuns.length, 0);
    assert.equal((getStore().entryPathComparisons ?? []).length, 0);
  });
});

describe('entry-path comparison start uses the signed run path', () => {
  beforeEach(seed);

  it('signs jobs for exactly the approved targets and waits on group concurrency', () => {
    const { started, comparison } = start();
    assert.equal(auditCount('entry_path_comparison.started'), 1);
    assert.equal(comparison.approved_scope.plan_digest, started.comparison.plan_digest);
    assert.equal(itemState(comparison, 'ep_origin').state, 'pending');
    for (const id of ['ep_primary', 'ep_alt', 'ep_login']) {
      const item = itemState(comparison, id);
      assert.equal(item.state, 'started');
      const scopeItem = comparison.approved_scope.items.find((row) => row.entry_path_id === id);
      const job = jobForRun(item.test_run_id);
      assert.ok(verifyProbeJobSignature(job, SECRET));
      assert.equal(job.target.id, scopeItem.target_id);
      assert.equal(job.check_id, scopeItem.check_id);
      assert.equal(computeScopeHashFromTargets(scopeItem.target_group_id, [job.target]), scopeItem.target_scope_hash);
    }
    const altJob = jobForRun(itemState(comparison, 'ep_alt').test_run_id);
    assert.equal(altJob.target.value, 'alt.example');
    assert.equal(JSON.stringify(altJob.probe_profile).includes('elsewhere.example'), false);
    assert.equal(getStore().testRuns.length, 3);
  });

  it('completes the comparison, carrying the origin gate scope and per-path outcomes', () => {
    const { comparison } = start();
    completeRun(itemState(comparison, 'ep_primary').test_run_id, 'blocked', markerMetadata());
    const origin = itemState(comparison, 'ep_origin');
    assert.equal(origin.state, 'started');
    const originJob = jobForRun(origin.test_run_id);
    assert.ok(verifyProbeJobSignature(originJob, SECRET));
    assert.equal(originJob.target.value, '203.0.113.10');
    assert.equal(originJob.constraints.origin_scope.host, 'app.example');
    assert.equal(getStore().testRuns.find((row) => row.id === origin.test_run_id).origin_binding_id, comparison.approved_scope.items.find((row) => row.entry_path_id === 'ep_origin').origin_binding_id);

    completeRun(itemState(comparison, 'ep_alt').test_run_id, 'blocked', markerMetadata());
    completeRun(itemState(comparison, 'ep_login').test_run_id, 'connected', markerMetadata({ blocked: 2, allowed: 1 }));
    completeRun(origin.test_run_id, 'connected', {
      origin_observation: classifyDirectOriginObservation({ response: { status: 200, headers: new Map() }, baseline: { status_code: 200 } }),
    });

    assert.equal(comparison.status, 'completed');
    const view = getEntryPathComparison(CTX, comparison.id);
    const outcome = Object.fromEntries(view.items.map((row) => [row.entry_path_id, row.outcome]));
    assert.deepEqual(outcome, {
      ep_primary: 'consistent_enforcement',
      ep_alt: 'consistent_enforcement',
      ep_login: 'weaker_observed_enforcement',
      ep_origin: 'reachability_exposure',
    });
    assert.equal(view.summary.accepted, false);
    assert.ok(view.evaluation_digest);
    assert.ok(view.baseline);
    assert.equal(auditCount('entry_path_comparison.completed'), 1);
    const record = entryPathComparisonEvaluationRecord(comparison);
    assert.equal(record.kind, 'path_validation');
    assert.equal(record.reviewed_plan_digest, comparison.plan_digest);
    assert.equal('attempts' in record, false);
  });

  it('keeps reads passive: get and list never start pending items', () => {
    const { comparison } = start();
    const runs = getStore().testRuns.length;
    assert.ok(getEntryPathComparison(CTX, comparison.id));
    const listed = listEntryPathComparisons(VIEWER, { anchor_target_id: 'tgt_app', limit: 1 });
    assert.equal(listed.count, 1);
    assert.equal(getStore().testRuns.length, runs);
    assert.equal(itemState(comparison, 'ep_origin').state, 'pending');
    assert.equal(getEntryPathComparison({ tenantId: 'ten_other', userId: 'x', role: 'admin' }, comparison.id), null);
  });

  it('exposes the delegated route shape used by the protection-validation routes', () => {
    const plan = planOrStartEntryPathComparison(CTX, body('plan'), { runtimeConfig: SIGNED });
    assert.equal(plan.mode, 'plan');
    const started = planOrStartEntryPathComparison(CTX, body('start', { reviewed_plan_digest: plan.plan_digest }), { runtimeConfig: SIGNED });
    assert.equal(started.mode, 'start');
    assert.equal(started.status, 'running');
    assert.equal(getEntryPathComparison(CTX, { comparisonId: started.id }).id, started.id);
    assert.equal(planOrStartEntryPathComparison(CTX, body('start', { reviewed_plan_digest: '0'.repeat(64) }), { runtimeConfig: SIGNED }).status, 409);
  });

  it('replays an identical start instead of dispatching twice', () => {
    const { plan } = start();
    const again = createEntryPathComparison(CTX, body('start', { reviewed_plan_digest: plan.plan_digest }), SIGNED);
    assert.equal(again.status, 200);
    assert.equal(again.replayed, true);
    assert.equal(getStore().testRuns.length, 3);
    assert.equal(auditCount('entry_path_comparison.started'), 1);
  });
});

describe('entry-path comparison safety controls', () => {
  beforeEach(seed);

  it('respects the kill switch mid-flight: runs cancelled, jobs revoked, nothing new starts', () => {
    const { comparison } = start();
    const jobsBefore = getStore().probeJobs.length;
    setKillSwitch(SOC, true, 'incident');
    assert.equal(comparison.status, 'cancelled');
    assert.equal(comparison.cancel_reason, 'kill_switch_active');
    for (const item of comparison.items) assert.equal(item.state, 'skipped');
    assert.equal(itemState(comparison, 'ep_origin').skip_reason, 'kill_switch_active');
    assert.equal(getStore().probeJobs.length, jobsBefore);
    assert.ok(getStore().probeJobs.every((job) => job.status === 'cancelled'));
    assert.ok(comparison.evaluation.items.every((row) => row.outcome === 'skipped'));
    assert.equal(comparison.evaluation.summary.accepted, false);
  });

  it('stops on request through the existing run cancel path', () => {
    const { comparison } = start();
    const result = cancelEntryPathComparison(CTX, comparison.id, { reason: 'operator stop' });
    assert.equal(result.comparison.status, 'cancelled');
    assert.ok(getStore().testRuns.every((run) => run.status === 'cancelled'));
    assert.ok(getStore().probeJobs.every((job) => job.status === 'cancelled'));
    assert.equal(auditCount('test_run.cancelled'), 3);
    assert.equal(itemState(comparison, 'ep_origin').skip_reason, 'comparison_cancelled');
    assert.equal(cancelEntryPathComparison(CTX, comparison.id).status, 409);
    assert.equal(cancelEntryPathComparison(VIEWER, comparison.id).status, 403);
  });

  it('defers items blocked by rate budgets and minimum intervals instead of bypassing them', () => {
    const store = getStore();
    store.targetGroups.find((row) => row.id === 'tg_2').safety_policy = { max_runs_per_hour: 1 };
    store.targetGroups.find((row) => row.id === 'tg_3').safety_policy = { min_seconds_between_runs: 3600 };
    store.testRuns.push({ id: 'run_prior', tenant_id: TENANT, target_group_id: 'tg_3', target_id: 'tgt_login', check_id: SCENARIO, status: 'verdicted', created_at: new Date(Date.now() - 60_000).toISOString(), correlation: {} });
    const { comparison } = start();
    const alt = itemState(comparison, 'ep_alt');
    const login = itemState(comparison, 'ep_login');
    assert.equal(alt.state, 'deferred');
    assert.equal(alt.last_start_error, 'safe_rate_cap_exceeded');
    assert.ok(Date.parse(alt.deferred_until) > Date.now());
    assert.equal(login.state, 'deferred');
    assert.equal(login.last_start_error, 'safe_min_interval_active');
    assert.equal(alt.test_run_id, null);
    assert.equal(store.testRuns.filter((run) => run.target_id === 'tgt_alt').length, 0);
    advanceDueEntryPathComparisons({ runtimeConfig: SIGNED });
    assert.equal(alt.state, 'deferred');
    store.targetGroups.find((row) => row.id === 'tg_2').safety_policy = {};
    advanceDueEntryPathComparisons({ runtimeConfig: SIGNED, now: alt.deferred_until });
    assert.equal(alt.state, 'started');
    assert.ok(verifyProbeJobSignature(jobForRun(alt.test_run_id), SECRET));
  });

  it('skips queued paths without starting runs once the tenant gate is turned off', () => {
    const store = getStore();
    store.targetGroups.find((row) => row.id === 'tg_2').safety_policy = { max_runs_per_hour: 1 };
    const { comparison } = start();
    const alt = itemState(comparison, 'ep_alt');
    assert.equal(alt.state, 'deferred');
    store.targetGroups.find((row) => row.id === 'tg_2').safety_policy = {};
    const runsBefore = store.testRuns.length;
    advanceDueEntryPathComparisons({ runtimeConfig: SIGNED_GATE_OFF, now: alt.deferred_until });
    assert.equal(alt.state, 'skipped');
    assert.equal(alt.skip_reason, 'protection_validation_disabled');
    assert.equal(alt.test_run_id, null);
    assert.equal(store.testRuns.length, runsBefore);
    assert.equal(comparison.cancel_reason, 'protection_validation_disabled');
    assert.equal(auditCount('entry_path_comparison.item_skipped') >= 1, true);
  });

  it('rejects a tampered approved scope and cancels outstanding work', () => {
    const { comparison } = start();
    comparison.approved_scope.items.find((row) => row.entry_path_id === 'ep_origin').target_id = 'tgt_alt';
    completeRun(itemState(comparison, 'ep_primary').test_run_id, 'blocked', markerMetadata());
    assert.equal(comparison.status, 'cancelled');
    assert.equal(comparison.cancel_reason, 'approved_scope_invalid');
    assert.equal(itemState(comparison, 'ep_origin').test_run_id, null);
    assert.equal(auditCount('entry_path_comparison.scope_rejected'), 1);
    assert.ok(comparison.evaluation.items.every((row) => row.outcome === 'inconclusive'));
    assert.equal(getStore().testRuns.filter((run) => run.target_id === 'tgt_origin').length, 0);
  });

  it('skips a relation archived after approval instead of executing it', () => {
    const { comparison } = start();
    getStore().applicationEntryPaths.find((row) => row.id === 'ep_origin').status = 'archived';
    completeRun(itemState(comparison, 'ep_primary').test_run_id, 'blocked', markerMetadata());
    assert.equal(itemState(comparison, 'ep_origin').state, 'skipped');
    assert.equal(itemState(comparison, 'ep_origin').skip_reason, 'entry_path_archived');
    assert.equal(getStore().testRuns.filter((run) => run.target_id === 'tgt_origin').length, 0);
  });

  it('treats a signed job whose target drifted after signing as inconclusive evidence', () => {
    const { comparison } = start();
    const altRun = itemState(comparison, 'ep_alt').test_run_id;
    const job = jobForRun(altRun);
    job.target = { ...job.target, value: 'elsewhere.example' };
    assert.equal(verifyProbeJobSignature(job, SECRET), false);
    completeRun(itemState(comparison, 'ep_primary').test_run_id, 'blocked', markerMetadata());
    completeRun(altRun, 'blocked', markerMetadata());
    completeRun(itemState(comparison, 'ep_login').test_run_id, 'blocked', markerMetadata());
    completeRun(itemState(comparison, 'ep_origin').test_run_id, 'connected', {
      origin_observation: classifyDirectOriginObservation({ error: Object.assign(new Error('t'), { name: 'AbortError' }), baseline: { status_code: 200 } }),
    });
    const items = Object.fromEntries(comparison.evaluation.items.map((row) => [row.entry_path_id, row]));
    assert.equal(items.ep_alt.outcome, 'inconclusive');
    assert.ok(items.ep_alt.reasons.includes('attempt_scope_hash_mismatch'));
    assert.equal(items.ep_origin.outcome, 'inconclusive');
  });

  it('finalizes collecting runs whose window expired from the dev ticker sweep, without a client read (D10)', () => {
    const { comparison } = start();
    const startedItems = comparison.items.filter((row) => row.state === 'started');
    assert.ok(startedItems.length >= 1);
    const store = getStore();
    for (const item of startedItems) {
      const run = store.testRuns.find((row) => row.id === item.test_run_id);
      const job = jobForRun(run.id);
      store.events.push({
        id: `event_${run.id}`, tenant_id: run.tenant_id, test_run_id: run.id, target_id: job.target_id, check_id: job.check_id,
        source: 'probe_worker', signal_type: 'probe_result', producer_kind: 'signed_probe', timestamp: new Date().toISOString(),
        nonce_hash: job.nonce_hash, metadata: { external_result: 'not_run', profile_kind: job.probe_profile.kind },
      });
      run.correlation.nonce_hash = job.nonce_hash;
      run.probe_external_result = 'not_run';
      run.status = 'collecting';
      run.collection_deadline_at = new Date(Date.now() - 60_000).toISOString();
    }
    assert.equal(finalizeExpiredComparisonRuns(), startedItems.length);
    for (const item of startedItems) {
      assert.equal(store.testRuns.find((row) => row.id === item.test_run_id).status === 'collecting', false);
      assert.equal(itemState(comparison, item.entry_path_id).state, 'finalized');
    }
    assert.equal(finalizeExpiredComparisonRuns(), 0);
  });
});
