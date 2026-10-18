import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import { getCheckById, buildProbeProfile } from '../../src/contracts/checks.mjs';
import { normalizeEntryPathDeclaration } from '../../src/contracts/protectionValidation.mjs';
import { buildApprovedScope, planEntryPathComparison, reviewedOriginIdentityPair } from '../../src/lib/entryPathComparison.mjs';
import { buildOriginIdentityPairSnapshot, originIdentityContentSupport, originIdentityProofBinding, signedOriginIdentityPair } from '../../src/lib/originIdentityPair.mjs';
import { buildSignedProbeJobRecord, verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { executeProbeForJob, processJob, buildResultBody, sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';
import { originBaselineComparable } from '../../src/lib/externalObservationOutcomes.mjs';
import { probeOriginLeakScan } from '../../src/lib/capabilityProbes.mjs';
import { createEntryPathComparison, configureEntryPathComparisonRuntime } from '../../src/services/entryPathComparisons.mjs';
import { bindingRecordsFromStore, createOriginBinding, validateOriginBindingForExecution } from '../../src/services/originBindings.mjs';
import { startTestRun, finalizeTestRun } from '../../src/services/testRuns.mjs';
import { listPendingProbeJobsForWorker, reserveProbeExecution, ingestProbeResult } from '../../src/services/probeCoordinator.mjs';
import { computeReadiness } from '../../src/services/readiness.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TENANT = 'ten_pair';
const SECRET = '0123456789abcdef'.repeat(4);
const CONTENT = `<html><head><title>Declared production application</title></head><body><main>${'A specific application response. '.repeat(9)}</main></body></html>`;

function fixture(method = 'HEAD') {
  const check = getCheckById(`origin.identity_pair.${method.toLowerCase()}.v1`);
  const origin = { id: 'origin', tenant_id: TENANT, target_group_id: 'group', kind: 'ip', value: '203.0.113.10' };
  const protectedTarget = { id: 'app', tenant_id: TENANT, target_group_id: 'group', kind: 'fqdn', value: 'app.example' };
  const binding = { id: 'binding', tenant_id: TENANT, status: 'active', origin_target_id: origin.id,
    protected_target_id: protectedTarget.id, host: 'app.example', sni: 'app.example', port: 443, path: '/health' };
  const records = { targets: [origin, protectedTarget], targetVerifications: [origin, protectedTarget].map((target) => ({
    id: `proof_${target.id}`, tenant_id: TENANT, target_id: target.id, state: 'dns_verified', source_kind: 'dns_txt',
    source_ref: { challenge_id: target.id }, transitioned_at: new Date(Date.now() - 1000).toISOString(),
  })) };
  const relation = { id: 'entry_origin', ...normalizeEntryPathDeclaration({ entry_target_id: origin.id,
    relation_kind: 'origin', origin_binding_id: binding.id, owner: 'Application team', purpose: 'Reviewed identity',
    expected_behavior: 'must_not_be_reachable', required_layers: [] }, { tenantId: TENANT, anchorTargetId: protectedTarget.id }) };
  const request = { mode: 'plan', anchor_target_id: protectedTarget.id, primary_entry_path_id: relation.id,
    entry_path_ids: [relation.id], expectation: { scenario: check.check_id, layer_outcomes: { waf: 'no_expectation' } } };
  const plan = planEntryPathComparison({ tenantId: TENANT, request, anchorTarget: protectedTarget,
    relations: [relation], targets: records.targets, originBindings: [binding], catalog: [check], verificationRecords: records });
  assert.equal(plan.items[0].eligible, true, JSON.stringify(plan));
  const comparison = { id: 'comparison', status: 'running', approved_scope: buildApprovedScope(plan, {
    comparisonId: 'comparison', approvedAt: new Date().toISOString(), approvedBy: 'reviewer',
  }) };
  const paired = buildOriginIdentityPairSnapshot({ check, binding, originTarget: origin, protectedTarget,
    scope: binding, records, tenantId: TENANT, reviewedPair: reviewedOriginIdentityPair(comparison, check, origin, binding.id) });
  assert.equal(paired.ok, true, JSON.stringify(paired));
  const scope = { host: binding.host, sni: binding.sni, port: binding.port, path: binding.path };
  const run = { id: 'run', tenant_id: TENANT, origin_binding_id: binding.id, created_at: new Date().toISOString(),
    safety_constraints: { max_requests: 2, timeout_ms: 5000 },
    provenance_json: { origin_scope: scope, origin_identity_pair: paired.snapshot } };
  const job = buildSignedProbeJobRecord({ run, check, target: origin, probeWorkerSecret: SECRET, now: new Date(), newId: () => 'job' });
  return { job, plan, comparison, check, run, binding, origin, protectedTarget, records };
}

function transport(job, options = {}) {
  const calls = [];
  let dnsCalls = 0;
  const controller = new AbortController();
  const deps = { workerId: 'worker-one', sourcePerspective: 'public-one', signedJobVerified: true,
    cancellationSignal: controller.signal,
    resolve4Fn: async (host) => { dnsCalls += 1; assert.equal(host, 'app.example'); return options.privateBaseline ? ['127.0.0.1'] : ['93.184.216.34']; },
    resolve6Fn: async (host) => { dnsCalls += 1; assert.equal(host, 'app.example'); return []; },
    httpsRequestFn: (opts, callback) => {
      calls.push(opts);
      const req = new EventEmitter();
      req.getHeaders = () => opts.headers;
      req.end = () => queueMicrotask(() => {
        const index = calls.length - 1;
        const row = options.responses?.[index] ?? {};
        if (row.error) { req.emit('error', Object.assign(new Error(row.error), { code: row.error })); return; }
        const res = Readable.from([Buffer.from(row.body ?? CONTENT)]);
        res.statusCode = row.status ?? 200;
        res.headers = { 'content-type': 'text/html', ...(options.canary === false ? {} : { 'x-astranull-canary-echo': job.nonce }), ...row.headers };
        res.rawHeaders = Object.entries(res.headers).flat();
        res.httpVersion = '1.1';
        res.socket = { authorized: true, getPeerCertificate: () => row.certificate ?? ({}) };
        callback(res);
        if (options.cancelAfterBaseline && calls.length === 1) controller.abort();
      });
      req.destroy = (error) => { req.destroyed = true; if (error) req.emit('error', error); };
      return req;
    },
  };
  return { deps, calls, dnsCalls: () => dnsCalls };
}

describe('reviewed paired origin identity', () => {
  it('leaves ordinary Host/SNI cap at one and gives distinct HEAD/GET scenario versions', () => {
    assert.equal(buildProbeProfile({ kind: 'host_sni_bypass', max_requests: 2 }).max_requests, 1);
    for (const method of ['HEAD', 'GET']) {
      const { job, plan } = fixture(method);
      assert.equal(job.probe_profile.max_requests, 2);
      assert.equal(job.probe_profile.scenario_version, `origin-identity-${method.toLowerCase()}-v1`);
      assert.equal(job.probe_profile.observation_only, true);
      assert.equal(job.probe_profile.readiness_conclusion, false);
      assert.equal(plan.items[0].paired_plan.method, method);
      assert.equal(job.constraints.max_probe_requests, 2);
      assert.equal(job.constraints.max_destination_resolver_attempts, 2);
      assert.equal(job.constraints.max_total_operations, 4);
    }
  });

  for (const method of ['HEAD', 'GET']) it(`executes exactly two ${method} requests with one nonce, pinned Host/SNI and fresh same-worker proof`, async () => {
    const { job } = fixture(method);
    const io = transport(job);
    const result = await executeProbeForJob(job, io.deps);
    assert.equal(result.probe_requests_sent, 2, JSON.stringify(result));
    assert.equal(result.destination_resolver_attempts, 2);
    assert.equal(io.dnsCalls(), 2);
    assert.equal(io.calls.length, 2);
    assert.deepEqual(io.calls.map((call) => call.hostname), ['93.184.216.34', '203.0.113.10']);
    for (const call of io.calls) {
      assert.equal(call.method, method);
      assert.equal(call.path, '/health');
      assert.equal(call.servername, 'app.example');
      assert.equal(call.headers.Host, 'app.example');
      assert.equal(call.headers['x-astranull-nonce'], job.nonce);
      assert.equal(call.rejectUnauthorized, true);
    }
    assert.equal(result.metadata.origin_observation.application_bypass_confirmed, true, JSON.stringify(result));
    assert.equal(result.metadata.comparison_complete, true);
    assert.equal(result.metadata.readiness_conclusion, false);
    assert.equal(result.metadata.origin_observation.readiness_conclusion, false);
    assert.equal(result.metadata.origin_observation.origin_lockdown_confirmed, false);
    assert.equal(result.metadata.permitted_baseline.tls.verification_enabled, true);
    assert.equal(JSON.stringify(result.metadata).includes(job.nonce), false);
    const cleaned = sanitizeProbeMetadata(result.metadata);
    assert.equal(cleaned.permitted_baseline.application_identity.method, 'nonce_canary');
    assert.equal(cleaned.direct_tls.verification_enabled, true);
  });

  it('production processor supplies actual configured worker/source identity rather than a synthetic scope', async () => {
    const { job } = fixture(); const io = transport(job);
    delete io.deps.workerId; delete io.deps.sourcePerspective;
    const body = await processJob({ secret: SECRET, workerId: 'configured-worker', perspectiveId: 'configured-source' }, job, io.deps);
    assert.equal(io.calls.length, 2);
    assert.equal(body.metadata.origin_observation.application_bypass_confirmed, true, JSON.stringify(body));
    assert.equal(body.metadata.origin_observation.scope.worker_id, 'configured-worker');
    assert.equal(body.metadata.origin_observation.scope.source_perspective, 'configured-source');
  });

  it('binds both proof references and both descriptors into the signature and reviewed plan', () => {
    const { job, check, run, origin } = fixture();
    assert.equal(verifyProbeJobSignature(job, SECRET), true);
    for (const mutate of [
      (pair) => { pair.protected_target.value = 'other.example'; },
      (pair) => { pair.origin_target.value = '8.8.8.8'; },
      (pair) => { pair.protected_ownership_binding.transitioned_at = new Date().toISOString(); },
      (pair) => { pair.origin_ownership_binding.source_ref_digest = 'a'.repeat(64); },
      (pair) => { pair.path = '/other'; },
      (pair) => { pair.method = 'GET'; },
      (pair) => { pair.limits.http_requests = 3; },
    ]) {
      const tampered = structuredClone(job); mutate(tampered.constraints.origin_identity_pair);
      assert.equal(verifyProbeJobSignature(tampered, SECRET), false);
    }
    const missing = structuredClone(run); delete missing.provenance_json.origin_identity_pair;
    assert.throws(() => buildSignedProbeJobRecord({ run: missing, check, target: origin, probeWorkerSecret: SECRET, now: new Date(), newId: () => 'no-job' }), /origin_identity_review_required/);
  });

  it('rejects review scope/proof changes and public-address tampering before DNS/HTTP', async () => {
    const { job, records, check, binding, origin, protectedTarget, comparison } = fixture();
    records.targetVerifications[0].transitioned_at = new Date(Date.now() + 1000).toISOString();
    const changed = buildOriginIdentityPairSnapshot({ check, binding, originTarget: origin, protectedTarget,
      scope: binding, records, tenantId: TENANT, reviewedPair: reviewedOriginIdentityPair(comparison, check, origin, binding.id) });
    assert.equal(changed.error, 'origin_identity_review_required');
    const tampered = structuredClone(job); tampered.constraints.origin_identity_pair.address = '127.0.0.1';
    assert.equal(signedOriginIdentityPair(tampered), null);
    const io = transport(tampered);
    const result = await executeProbeForJob(tampered, io.deps);
    assert.equal(result.probe_requests_sent, 0);
    assert.equal(io.dnsCalls(), 0);
    assert.equal(io.calls.length, 0);
  });

  it('refuses enlarged aggregate budgets or an authority older than the signed 60-second scope before I/O', async () => {
    const { job } = fixture();
    for (const patch of [
      { max_destination_resolver_attempts: 3 }, { max_total_operations: 5 },
      { not_after: new Date(Date.parse(job.constraints.issued_at) + 60001).toISOString() },
    ]) {
      const changed = { ...job, constraints: { ...job.constraints, ...patch } };
      assert.equal(signedOriginIdentityPair(changed), null);
      const io = transport(changed);
      const result = await executeProbeForJob(changed, io.deps);
      assert.equal(result.probe_requests_sent, 0);
      assert.equal(io.dnsCalls(), 0);
      assert.equal(io.calls.length, 0);
    }
  });

  it('vets baseline private/rebound answers before opening either socket', async () => {
    const { job } = fixture(); const io = transport(job, { privateBaseline: true });
    const result = await executeProbeForJob(job, io.deps);
    assert.equal(result.probe_requests_sent, 0);
    assert.equal(io.calls.length, 0);
  });

  it('missing worker identity never becomes a fresh comparable confirmation', async () => {
    const { job } = fixture(); const io = transport(job); delete io.deps.workerId;
    const result = await executeProbeForJob(job, io.deps);
    assert.equal(io.calls.length, 2);
    assert.equal(result.metadata.origin_observation.application_bypass_confirmed, false);
    assert.equal(result.metadata.origin_observation.baseline_comparable, false);
  });

  it('Stop between legs cancels without direct request or confirmation', async () => {
    const { job } = fixture(); const io = transport(job, { cancelAfterBaseline: true });
    const result = await executeProbeForJob(job, io.deps);
    assert.equal(result.probe_requests_sent, 1);
    assert.equal(io.calls.length, 1);
    assert.notEqual(result.metadata.comparison_complete, true);
    assert.notEqual(result.metadata.application_bypass_confirmed, true);
  });

  for (const row of [
    { name: 'static marker only', canary: false, responses: [{ headers: { 'x-astranull-marker-echo': 'static' } }, { headers: { 'x-astranull-marker-echo': 'static' } }] },
    { name: 'redirect to CDN', responses: [{}, { status: 302, headers: { location: 'https://cdn.example/' } }] },
    { name: 'unhealthy baseline', responses: [{ status: 503 }, {}] },
    { name: 'redirected baseline', responses: [{ status: 302, headers: { location: 'https://other.example/' } }, {}] },
    { name: 'baseline denial with a canary', responses: [{ headers: { 'cf-mitigated': 'challenge' } }, {}] },
    { name: 'certificate only', canary: false, responses: [0, 1].map(() => ({ body: '', certificate: { subjectaltname: 'DNS:app.example', fingerprint256: 'aa:bb' } })) },
    { name: 'certificate trust failure', responses: [{}, { error: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }] },
    { name: 'certificate hostname failure', responses: [{}, { error: 'ERR_TLS_CERT_ALTNAME_INVALID' }] },
    { name: 'generic error with a canary', responses: [{ body: 'Error 404 Forbidden '.repeat(30) }, { body: 'Error 404 Forbidden '.repeat(30) }] },
    { name: 'generic directory with a canary', responses: [{ body: 'Index of / '.repeat(30) }, { body: 'Index of / '.repeat(30) }] },
    { name: 'generic page', responses: [{ body: 'Welcome to nginx '.repeat(30) }, { body: 'Welcome to nginx '.repeat(30) }] },
    { name: 'challenge page', responses: [{ body: 'checking your browser '.repeat(30) }, { body: 'checking your browser '.repeat(30) }] },
    { name: 'oversized body', responses: [{ body: 'x'.repeat(10000) }, { body: 'x'.repeat(10000) }] },
    { name: 'CDN direct answer', responses: [{}, { headers: { server: 'cloudflare', 'cf-ray': 'edge' } }] },
  ]) it(`${row.name} never becomes nonce-confirmed`, async () => {
    const { job } = fixture('GET'); const io = transport(job, row);
    const result = await executeProbeForJob(job, io.deps);
    assert.equal(io.calls.length, 2);
    assert.equal(result.metadata.origin_observation.application_bypass_confirmed, false, JSON.stringify(result));
    assert.equal(result.metadata.readiness_conclusion, false);
  });

  it('complete matching content without a canary is supporting suspicion only', async () => {
    const { job } = fixture('GET'); const io = transport(job, { canary: false });
    const result = await executeProbeForJob(job, io.deps);
    assert.equal(result.metadata.content_support.suspected_application_association, true, JSON.stringify(result));
    assert.equal(result.metadata.content_support.nonce_confirmed, false);
    assert.equal(result.metadata.origin_observation.application_bypass_confirmed, false);
  });

  it('content/certificate/static-marker support cannot authorize or confirm identity', () => {
    assert.equal(originIdentityProofBinding({ targets: [], targetVerifications: [] }, TENANT, 'unknown'), null);
    const support = originIdentityContentSupport({ response: { status: 200 }, body_text: CONTENT, body_complete: true },
      { response: { status: 200 }, body_text: CONTENT, body_complete: false });
    assert.equal(support.suspected_application_association, false);
    assert.equal(support.nonce_confirmed, false);
  });

  it('preserves exact port/worker/source/method/path/scenario/nonce and 60s comparability criteria', () => {
    const scope = { host: 'app.example', path: '/health', port: 443, method: 'HEAD', scenario_version: 'origin-identity-head-v1', source_perspective: 'source', worker_id: 'worker' };
    const baseline = { status_code: 200, application_identity: { confirmed: true, method: 'nonce_canary' },
      canary_echo: 'nonce', scope, observed_at: '2026-10-16T00:00:00.000Z' };
    const args = { baseline, scope, expectedNonce: 'nonce', observedAt: '2026-10-16T00:00:01.000Z' };
    assert.equal(originBaselineComparable(args), true);
    for (const key of Object.keys(scope)) assert.equal(originBaselineComparable({ ...args, scope: { ...scope, [key]: key === 'port' ? 8443 : 'mismatch' } }), false);
    assert.equal(originBaselineComparable({ ...args, expectedNonce: 'different' }), false);
    assert.equal(originBaselineComparable({ ...args, observedAt: '2026-10-16T00:01:00.001Z' }), false);
  });
});

describe('paired identity through real reviewed dev start and execution authority', () => {
  const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
  const runtime = { probeMode: 'signed-worker', probeWorkerSecret: SECRET, featureFlags: { protectionValidationEnabled: true } };
  function seed(method = 'HEAD') {
    freshStore();
    configureEntryPathComparisonRuntime(runtime);
    const store = getStore();
    store.targetGroups[0].safety_policy = { min_seconds_between_runs: 0, max_runs_per_hour: 100 };
    const targets = [
      { id: 'pair_origin', kind: 'ip', value: '203.0.113.10' },
      { id: 'pair_app', kind: 'fqdn', value: 'app.example', declaration_json: { allowed_scope: { ports: [443], paths: ['/health'] } } },
    ].map((target) => ({ ...target, tenant_id: ctx.tenantId, target_group_id: 'tg_1', created_at: new Date().toISOString() }));
    store.targets.push(...targets);
    store.targetVerifications ??= [];
    for (const target of targets) store.targetVerifications.push({ id: `proof_${target.id}`, tenant_id: ctx.tenantId,
      target_id: target.id, state: 'dns_verified', source_kind: 'dns_txt', source_ref: { challenge: target.id },
      transitioned_at: new Date(Date.now() - 1000).toISOString(), transitioned_by: 'system' });
    const binding = createOriginBinding(ctx, { protected_target_id: 'pair_app', origin_target_id: 'pair_origin' });
    assert.equal(binding.error, undefined, JSON.stringify(binding));
    store.applicationEntryPaths = [{ id: 'pair_entry', ...normalizeEntryPathDeclaration({ entry_target_id: 'pair_origin',
      relation_kind: 'origin', origin_binding_id: binding.id, owner: 'App team', purpose: 'Reviewed identity',
      expected_behavior: 'must_not_be_reachable', required_layers: [] }, { tenantId: ctx.tenantId, anchorTargetId: 'pair_app' }) }];
    const request = { mode: 'plan', anchor_target_id: 'pair_app', primary_entry_path_id: 'pair_entry', entry_path_ids: ['pair_entry'],
      expectation: { scenario: `origin.identity_pair.${method.toLowerCase()}.v1`, layer_outcomes: { waf: 'no_expectation' } } };
    return { store, binding, request };
  }
  function reviewedStart(method = 'HEAD') {
    const setup = seed(method);
    const before = setup.store.probeJobs.length;
    const planned = createEntryPathComparison(ctx, setup.request, runtime);
    assert.equal(planned.status, 200, JSON.stringify(planned));
    assert.equal(planned.plan.items[0].paired_plan.method, method);
    assert.equal(setup.store.probeJobs.length, before, 'planning sends no job');
    const started = createEntryPathComparison(ctx, { ...setup.request, mode: 'start', reviewed_plan_digest: planned.plan.plan_digest }, runtime);
    assert.equal(started.status, 202, JSON.stringify(started));
    const comparison = setup.store.entryPathComparisons.find((row) => row.id === started.comparison.id);
    const run = setup.store.testRuns.find((row) => row.id === comparison.items[0].test_run_id);
    assert.ok(run, JSON.stringify(comparison));
    const job = setup.store.probeJobs.find((row) => row.test_run_id === run.id);
    assert.ok(job, JSON.stringify(run));
    return { ...setup, planned, comparison, run, job };
  }
  for (const method of ['HEAD', 'GET']) it(`real ${method} reviewed start emits exactly one signed paired job with both current proofs`, () => {
    const { store, comparison, run, job, binding } = reviewedStart(method);
    assert.equal(verifyProbeJobSignature(job, SECRET), true);
    assert.equal(job.constraints.origin_identity_pair.comparison_id, comparison.id);
    assert.deepEqual(job.constraints.origin_identity_pair, run.provenance_json.origin_identity_pair);
    assert.equal(job.constraints.origin_identity_pair.protected_ownership_binding.target_id, 'pair_app');
    assert.equal(job.constraints.origin_identity_pair.origin_ownership_binding.target_id, 'pair_origin');
    assert.equal(job.constraints.max_probe_requests, 2);
    assert.equal(Date.parse(job.constraints.not_after) - Date.parse(job.constraints.issued_at) <= 60000, true);
    assert.equal(validateOriginBindingForExecution({ job, run, binding,
      records: bindingRecordsFromStore(store, ctx.tenantId) }).ok, true);
  });
  for (const method of ['HEAD', 'GET']) it(`${method} signed lease/grant/ingestion retains identity evidence with zero protected/readiness credit`, async () => {
    const { store, run, job } = reviewedStart(method);
    const worker = { tenantId: ctx.tenantId, workerId: 'pair-worker', role: 'probe_worker' };
    const leased = listPendingProbeJobsForWorker(worker, runtime).find((row) => row.id === job.id);
    assert.ok(leased);
    const grant = reserveProbeExecution(worker, job.id, { leased_at: leased.leased_at });
    assert.equal(grant.authorized, true, JSON.stringify(grant));
    const io = transport(leased); io.deps.workerId = worker.workerId;
    const outcome = await executeProbeForJob(leased, io.deps);
    assert.equal(outcome.metadata.direct_application_path_confirmed, true);
    const body = buildResultBody(leased, outcome.external_result, outcome.metadata, outcome);
    const ingested = ingestProbeResult(worker, leased.id, body, runtime);
    assert.equal(ingested.error, undefined, JSON.stringify(ingested));
    assert.equal(finalizeTestRun(ctx, run.id, { force: true }).error, undefined);
    const event = store.events.find((row) => row.test_run_id === run.id && row.signal_type === 'probe_result');
    assert.equal(event.metadata.direct_application_path_confirmed, true);
    const verdict = store.verdicts.find((row) => row.test_run_id === run.id);
    assert.equal(verdict.verdict, 'inconclusive');
    assert.equal(verdict.confidence, 'external_only');
    const readiness = computeReadiness(ctx.tenantId, { catalog: [getCheckById(job.check_id)] });
    assert.equal(readiness.coverage.passed_count, 0);
    assert.equal(io.calls.length, 2);
  });
  it('direct unreviewed start is refused and audited with no job', () => {
    const { store, binding } = seed(); const before = store.probeJobs.length;
    const denied = startTestRun(ctx, { check_id: 'origin.identity_pair.head.v1', target_id: 'pair_origin', target_group_id: 'tg_1', origin_binding_id: binding.id }, runtime);
    assert.equal(denied.error, 'origin_identity_review_required');
    assert.equal(store.probeJobs.length, before);
    assert.ok(store.auditLog.some((row) => row.action === 'test_run.origin_identity_review_denied'));
  });
  it('review/start proof drift cannot reuse the old reviewed digest', () => {
    const { store, request } = seed();
    const plan = createEntryPathComparison(ctx, request, runtime);
    assert.equal(plan.status, 200);
    store.targetVerifications.find((row) => row.target_id === 'pair_app').source_ref.challenge = 'changed';
    const denied = createEntryPathComparison(ctx, { ...request, mode: 'start', reviewed_plan_digest: plan.plan.plan_digest }, runtime);
    assert.equal(denied.error, 'reviewed_plan_mismatch');
    assert.equal(store.probeJobs.some((row) => row.check_id === request.expectation.scenario), false);
  });
  it('execution grant rejects drift of either current proof, either descriptor, scope or archived binding', () => {
    const { store, run, job, binding } = reviewedStart();
    const records = bindingRecordsFromStore(store, ctx.tenantId);
    for (const targetId of ['pair_origin', 'pair_app']) {
      const changed = structuredClone(records);
      changed.targetVerifications.find((row) => row.target_id === targetId).source_ref.challenge = 'drift';
      assert.equal(validateOriginBindingForExecution({ job, run, binding, records: changed }).error, 'origin_identity_authority_changed');
      const targetChanged = structuredClone(records);
      targetChanged.targets.find((row) => row.id === targetId).value = targetId === 'pair_app' ? 'other.example' : '8.8.8.8';
      assert.ok(validateOriginBindingForExecution({ job, run, binding, records: targetChanged }).error);
    }
    assert.ok(validateOriginBindingForExecution({ job, run, binding: { ...binding, path: '/other' }, records }).error);
    assert.ok(validateOriginBindingForExecution({ job, run, binding: { ...binding, status: 'archived' }, records }).error);
  });
});

describe('origin leak metadata correction', () => {
  it('does not persist arbitrary response-header text as an IP clue', async () => {
    const result = await probeOriginLeakScan({ target: { kind: 'fqdn', value: 'app.example' },
      constraints: { max_requests: 3, timeout_ms: 500 }, probe_profile: { kind: 'origin_leak_scan', max_requests: 3 } }, {
      resolve4Fn: async () => ['93.184.216.34'], resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 200, headers: new Headers({ 'x-backend-ip': 'private-session-value' }) }),
    });
    assert.deepEqual(result.metadata.untrusted_header_clues, []);
    assert.doesNotMatch(JSON.stringify(sanitizeProbeMetadata(result.metadata)), /private-session-value/);
    assert.equal(result.metadata.readiness_conclusion, false);
  });

  it('treats spoofed x-backend-ip as untrusted, never actual peer or confirmed origin', async () => {
    const job = { target: { kind: 'fqdn', value: 'app.example' }, constraints: { max_requests: 4, timeout_ms: 500 },
      probe_profile: { kind: 'origin_leak_scan', max_requests: 4 } };
    const result = await probeOriginLeakScan(job, {
      resolve4Fn: async (host) => host === 'app.example' ? ['93.184.216.34'] : ['203.0.113.10'], resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 200, headers: new Headers({ 'x-backend-ip': '8.8.8.8' }) }),
    });
    assert.equal(result.metadata.edge_peer_address, null);
    assert.equal(result.metadata.addresses_are_confirmed_origins, false);
    assert.equal(result.metadata.leak_count, 0);
    assert.equal(result.metadata.corroborated_leak_signals.length, 0);
    assert.equal(result.metadata.untrusted_header_clues[0].trusted, false);
    assert.equal(result.metadata.exposure_conclusion, 'not_established');
    assert.equal(result.external_result, 'connected');
    const cleaned = sanitizeProbeMetadata(result.metadata);
    assert.deepEqual(cleaned.observed_addresses, ['93.184.216.34', '203.0.113.10']);
  });
});
