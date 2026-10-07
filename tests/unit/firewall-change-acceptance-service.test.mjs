import '../helpers/dev-data-dir.mjs';

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  PROTECTION_VALIDATION_AUDIT_ACTIONS,
  normalizeFirewallExpectation,
} from '../../src/contracts/protectionValidation.mjs';
import {
  approvedSourcesFromEnv,
  createApprovedSourceResolver,
  createDevStoreFirewallEvidenceReader,
  createFirewallChangeAcceptanceService,
} from '../../src/services/firewallChangeAcceptance.mjs';

const TENANT = 'ten_1';
const OTHER = 'ten_2';
const SOURCE = 'public-worker-eu';
const OWNER = { tenantId: TENANT, userId: 'usr_1', role: 'owner' };
const VIEWER = { tenantId: TENANT, userId: 'usr_2', role: 'viewer' };

function makeExpectation(id, overrides = {}) {
  return {
    ...normalizeFirewallExpectation({
      destination_target_id: 'tgt_fw',
      protocol: 'tcp',
      port: 443,
      expected: 'allow',
      source_perspective: SOURCE,
      change_id: 'CHG-1001',
      ...overrides,
    }, { tenantId: TENANT }),
    id,
    status: 'active',
  };
}

function makeStore() {
  return {
    targets: [
      { id: 'tgt_fw', tenant_id: TENANT, value: 'fw.example.test:443' },
      { id: 'tgt_gone', tenant_id: TENANT, value: 'gone.example.test:443', deleted_at: '2026-10-01T00:00:00.000Z' },
      { id: 'tgt_other', tenant_id: OTHER, value: 'other.example.test:443' },
    ],
    testRuns: [],
    events: [],
    verdicts: [],
  };
}

let eventSeq = 0;
function addRun(store, { id, tenant = TENANT, target = 'tgt_fw', status = 'verdicted', day = '2026-10-01', worker = 'worker_eu_1', tls = true, samples = 1, producer = 'signed_probe' }) {
  store.testRuns.push({ id, tenant_id: tenant, target_id: target, check_id: 'tls.full_audit.safe', status, check_version: '1.0.0', scenario_version: null });
  store.verdicts.push({ id: `verdict_${id}`, tenant_id: tenant, test_run_id: id });
  for (let index = 0; index < samples; index += 1) {
    eventSeq += 1;
    store.events.push({
      id: `evt_${eventSeq}`,
      tenant_id: tenant,
      test_run_id: id,
      target_id: target,
      check_id: 'tls.full_audit.safe',
      signal_type: 'probe_result',
      producer_kind: producer,
      timestamp: `${day}T00:0${index}:00.000Z`,
      metadata: {
        profile_kind: 'tls_audit',
        external_result: tls ? 'blocked' : 'timeout',
        probe_worker_id: worker,
        safety_attestation: { requests_sent: 1, duration_ms: 4 },
        ...(tls ? { tls_protocol: 'TLSv1.3' } : { error_class: 'ETIMEDOUT' }),
      },
    });
  }
}

function makeRepository(expectations) {
  const state = { baselines: [], evaluations: [], audits: [], expectations: new Map(expectations.map((row) => [row.id, row])) };
  let id = 0;
  const repo = {
    state,
    getFirewallExpectation: async (tenantId, expectationId) => {
      const row = state.expectations.get(expectationId);
      return row && row.tenant_id === tenantId ? structuredClone(row) : null;
    },
    listFirewallExpectations: async (tenantId, query) => ({
      items: [...state.expectations.values()].filter((row) => row.tenant_id === tenantId && row.change_id === query.change_id && row.status === query.status),
    }),
    findFirewallBaselineByIdempotencyKey: async (tenantId, key) => state.baselines.find((row) => row.tenant_id === tenantId && row.idempotency_key === key) ?? null,
    insertFirewallBaseline: async (tenantId, record, { auditEntry }) => {
      id += 1;
      const stored = structuredClone({ ...record, id: `fwb_${id}`, created_at: '2026-10-02T00:00:00.000Z' });
      state.baselines.push(stored);
      state.audits.push({ ...auditEntry, resource_id: stored.id });
      return structuredClone(stored);
    },
    getFirewallBaseline: async (tenantId, baselineId) => structuredClone(state.baselines.find((row) => row.tenant_id === tenantId && row.id === baselineId) ?? null),
    listFirewallBaselines: async (tenantId, query) => ({ items: state.baselines.filter((row) => row.tenant_id === tenantId).slice(0, query.limit), limit: query.limit }),
    findFirewallEvaluationByIdempotencyKey: async (tenantId, key) => state.evaluations.find((row) => row.tenant_id === tenantId && row.idempotency_key === key) ?? null,
    insertFirewallEvaluation: async (tenantId, record, { auditEntry }) => {
      id += 1;
      const stored = structuredClone({ ...record, id: `fwc_${id}` });
      state.evaluations.push(stored);
      state.audits.push({ ...auditEntry, resource_id: stored.id });
      return structuredClone(stored);
    },
    getFirewallEvaluation: async (tenantId, evaluationId) => structuredClone(state.evaluations.find((row) => row.tenant_id === tenantId && row.id === evaluationId) ?? null),
    listFirewallEvaluations: async (tenantId, query) => ({ items: state.evaluations.filter((row) => row.tenant_id === tenantId).slice(0, query.limit), limit: query.limit }),
  };
  return repo;
}

function setup({ expectations = [makeExpectation('fwx_1')], clock = '2026-10-02T00:00:00.000Z' } = {}) {
  const store = makeStore();
  const repository = makeRepository(expectations);
  let now = clock;
  const service = createFirewallChangeAcceptanceService({
    repository,
    evidence: createDevStoreFirewallEvidenceReader(() => store),
    resolveSourcePerspective: createApprovedSourceResolver({ [SOURCE]: ['worker_eu_1', 'worker_eu_2'], 'public-worker-us': ['worker_us_1'] }),
    now: () => now,
  });
  return { store, repository, service, setNow: (value) => { now = value; } };
}

const baselineBody = (runs = ['run_pre']) => ({ change_id: 'CHG-1001', expectation_ids: ['fwx_1'], test_run_ids: runs });

describe('firewall change acceptance service', () => {
  let originalFetch;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = () => { throw new Error('network access is not allowed in firewall acceptance'); };
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('captures an immutable baseline once, audits it, and replays identical requests without a second audit', async () => {
    const { store, repository, service } = setup();
    addRun(store, { id: 'run_pre', samples: 2 });
    const created = await service.captureFirewallBaseline(OWNER, baselineBody());
    assert.equal(created.error, undefined, JSON.stringify(created));
    assert.equal(created.replayed, false);
    assert.equal(created.immutable, true);
    assert.equal(created.entries[0].references[0].source_perspective, SOURCE);
    assert.equal(created.entries[0].references[0].verdict_id, 'verdict_run_pre');
    assert.equal(repository.state.audits.length, 1);
    assert.equal(repository.state.audits[0].action, PROTECTION_VALIDATION_AUDIT_ACTIONS.firewall_baseline_captured);
    assert.equal(repository.state.audits[0].metadata.dispatched_traffic, false);
    const replay = await service.captureFirewallBaseline(OWNER, baselineBody());
    assert.equal(replay.replayed, true);
    assert.equal(replay.id, created.id);
    assert.equal(repository.state.audits.length, 1);
  });

  it('rejects unfinished, unknown, cross-tenant, unrelated and unsourced baseline evidence', async () => {
    const { store, service } = setup();
    addRun(store, { id: 'run_live', status: 'collecting' });
    addRun(store, { id: 'run_foreign', tenant: OTHER, target: 'tgt_other' });
    addRun(store, { id: 'run_unsourced', worker: 'worker_unregistered' });
    addRun(store, { id: 'run_ok' });
    addRun(store, { id: 'run_sim', producer: 'internal_simulation' });
    assert.equal((await service.captureFirewallBaseline(OWNER, baselineBody(['run_live']))).error, 'evidence_not_finalized');
    const unknown = await service.captureFirewallBaseline(OWNER, baselineBody(['run_missing']));
    assert.deepEqual([unknown.error, unknown.status], ['unknown_test_run', 404]);
    const foreign = await service.captureFirewallBaseline(OWNER, baselineBody(['run_foreign']));
    assert.deepEqual([foreign.error, foreign.status], ['unknown_test_run', 404]);
    assert.equal((await service.captureFirewallBaseline(OWNER, baselineBody(['run_unsourced']))).error, 'invalid_comparison_baseline');
    const unrelated = await service.captureFirewallBaseline(OWNER, baselineBody(['run_ok', 'run_sim']));
    assert.equal(unrelated.error, 'invalid_comparison_baseline');
    assert.deepEqual(unrelated.test_run_ids, ['run_sim']);
  });

  it('enforces permissions and target lifecycle', async () => {
    const { store, service } = setup({ expectations: [makeExpectation('fwx_1'), makeExpectation('fwx_gone', { destination_target_id: 'tgt_gone' })] });
    addRun(store, { id: 'run_pre' });
    const denied = await service.captureFirewallBaseline(VIEWER, baselineBody());
    assert.deepEqual([denied.error, denied.status], ['forbidden', 403]);
    const gone = await service.captureFirewallBaseline(OWNER, { change_id: 'CHG-1001', expectation_ids: ['fwx_gone'], test_run_ids: ['run_pre'] });
    assert.deepEqual([gone.error, gone.status], ['target_not_active', 409]);
    const malformed = await service.captureFirewallBaseline(OWNER, { change_id: 'CHG-1001', expectation_ids: [], test_run_ids: ['run_pre'], source_ip: '192.0.2.1' });
    assert.equal(malformed.status, 400);
    assert.equal((await service.listFirewallBaselines(VIEWER, { limit: 500 })).limit, 100);
  });

  it('evaluates post-change evidence, records an audited immutable evaluation, and replays', async () => {
    const { store, repository, service, setNow } = setup();
    addRun(store, { id: 'run_pre' });
    const baseline = await service.captureFirewallBaseline(OWNER, baselineBody());
    addRun(store, { id: 'run_post', day: '2026-10-03' });
    setNow('2026-10-04T00:00:00.000Z');
    const result = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_post'] });
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.equal(result.items[0].status, 'matched');
    assert.equal(result.summary.accepted, true);
    assert.equal(result.readiness_effect, 'none');
    assert.match(result.statement.not_established, /routing, NAT, egress and east-west equivalence are not established/);
    assert.equal(repository.state.audits.at(-1).action, PROTECTION_VALIDATION_AUDIT_ACTIONS.firewall_comparison_evaluated);
    const replay = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_post'] });
    assert.equal(replay.replayed, true);
    assert.equal(repository.state.evaluations.length, 1);
    const read = await service.getFirewallComparison(VIEWER, result.id);
    assert.equal(read.evaluation_digest, result.evaluation_digest);
    assert.equal((await service.getFirewallComparison({ ...VIEWER, tenantId: OTHER }, result.id)).status, 404);
  });

  it('reports a regression gap and keeps unfinished or wrong-source post evidence not comparable', async () => {
    const { store, service, setNow } = setup();
    addRun(store, { id: 'run_pre' });
    const baseline = await service.captureFirewallBaseline(OWNER, baselineBody());
    addRun(store, { id: 'run_down', day: '2026-10-03', tls: false, samples: 2 });
    addRun(store, { id: 'run_us', day: '2026-10-03', worker: 'worker_us_1' });
    addRun(store, { id: 'run_live', day: '2026-10-03', status: 'collecting' });
    setNow('2026-10-04T00:00:00.000Z');
    const down = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_down'] });
    assert.equal(down.items[0].status, 'regression');
    assert.equal(down.items[0].gap_kind, 'required_service_newly_unavailable');
    assert.equal(down.summary.accepted, false);
    const us = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_us'] });
    assert.equal(us.items[0].status, 'not_comparable');
    assert.ok(us.items[0].compatibility_reasons.includes('source_mismatch'));
    const live = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_live'] });
    assert.equal(live.items[0].status, 'not_comparable');
    assert.ok(live.items[0].compatibility_reasons.includes('evidence_not_finalized'));
  });

  it('fails closed on tampered, archived, unknown or foreign baselines', async () => {
    const { store, repository, service, setNow } = setup();
    addRun(store, { id: 'run_pre' });
    const baseline = await service.captureFirewallBaseline(OWNER, baselineBody());
    addRun(store, { id: 'run_post', day: '2026-10-03' });
    setNow('2026-10-04T00:00:00.000Z');
    repository.state.baselines[0].entries[0].observations[0].observation_class = 'explicit_denial_observed';
    const tampered = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_post'] });
    assert.equal(tampered.items[0].status, 'not_comparable');
    assert.ok(tampered.items[0].compatibility_reasons.includes('invalid_baseline'));
    repository.state.baselines[0].status = 'archived';
    const archived = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_post'] });
    assert.deepEqual([archived.error, archived.status], ['baseline_not_comparable', 409]);
    assert.equal((await service.evaluateFirewallComparison(OWNER, { baseline_id: 'fwb_missing', post_test_run_ids: ['run_post'] })).status, 404);
    assert.equal((await service.evaluateFirewallComparison({ ...OWNER, tenantId: OTHER }, { baseline_id: baseline.id, post_test_run_ids: ['run_post'] })).status, 404);
    assert.equal((await service.evaluateFirewallComparison(VIEWER, { baseline_id: baseline.id, post_test_run_ids: ['run_post'] })).status, 403);
  });

  it('surfaces active expectations of the change that were never baselined', async () => {
    const { store, service, setNow } = setup({ expectations: [makeExpectation('fwx_1'), makeExpectation('fwx_2', { port: 8443 })] });
    addRun(store, { id: 'run_pre' });
    const baseline = await service.captureFirewallBaseline(OWNER, baselineBody());
    addRun(store, { id: 'run_post', day: '2026-10-03' });
    setNow('2026-10-04T00:00:00.000Z');
    const result = await service.evaluateFirewallComparison(OWNER, { baseline_id: baseline.id, post_test_run_ids: ['run_post'] });
    assert.equal(result.summary.total, 2);
    assert.equal(result.summary.accepted, false);
    assert.equal(result.items.find((item) => item.expectation_id === 'fwx_2').status, 'not_tested');
  });

  it('resolves sources only from the approved registry', () => {
    const resolve = createApprovedSourceResolver({ [SOURCE]: ['worker_eu_1'] });
    assert.equal(resolve('worker_eu_1'), SOURCE);
    assert.equal(resolve('worker_x'), null);
    assert.equal(resolve(undefined), null);
    assert.deepEqual(approvedSourcesFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: '{"a":["w1"]}' }), { a: ['w1'] });
    assert.deepEqual(approvedSourcesFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: 'not json' }), {});
    assert.equal(createApprovedSourceResolver({ eu: ['worker_x'], us: ['worker_x'] })('worker_x'), null);
    assert.throws(() => createFirewallChangeAcceptanceService({}), /repository/);
  });
});
