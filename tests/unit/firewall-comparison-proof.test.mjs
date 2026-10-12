import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { normalizeFirewallExpectation, comparisonEvaluationDigest } from '../../src/contracts/protectionValidation.mjs';
import { buildFirewallBaselineCapture, evaluateFirewallChange, firewallSampleFromProbeEvent } from '../../src/lib/firewallChangeAcceptance.mjs';
import { buildProtectionValidationReport } from '../../src/lib/protectionValidationReport.mjs';
import { buildSignedProbeJobRecord } from '../../src/lib/probeJobs.mjs';
import { executionReservation, probeExecutionEvidenceReceipt } from '../../src/lib/probeExecution.mjs';
import { deriveAssuranceScope } from '../../src/lib/assuranceScope.mjs';
import { deriveRunEvidenceStamp } from '../../src/lib/checkDefinitionVersion.mjs';
import { probeSourceResolverFromEnv } from '../../src/lib/probeSourcePerspective.mjs';

const tenantId = 'ten_firewall_proof';
const workerId = 'worker_firewall_proof';
const now = '2026-10-04T00:00:00.000Z';
const source = probeSourceResolverFromEnv()(workerId);
function world({ sourcePerspective = source, resolveSourcePerspective, freshnessWindowSeconds = 2592000,
  timeline = {}, generatedAt = now, probeKind = 'tls_audit' } = {}) {
  const target = { id: 'tgt_firewall', tenant_id: tenantId, kind: 'fqdn', value: 'firewall.example.test', port: 443,
    created_at: '2026-09-30T00:00:00.000Z' };
  const check = { check_id: 'tls.proof', version: '1.1.0', scenario_version: 's1', evidence_tier: 'E2',
    probe_profile: { kind: probeKind, max_requests: 1, target_port: 443, ...(probeKind === 'port_scan_bounded' ? { ports: [443] } : {}) } };
  const expectation = { ...normalizeFirewallExpectation({ destination_target_id: target.id, protocol: probeKind === 'udp_probe' ? 'udp' : 'tcp',
    port: 443, expected: 'allow', source_perspective: sourcePerspective, change_id: 'CHG-proof' }, { tenantId }),
    id: 'fwx_proof', status: 'active', created_at: target.created_at };
  const runs = [], events = [], jobs = [];
  for (const [side, day] of [['pre', '01'], ['post', '03']]) {
    const at = timeline[side] ?? `2026-10-${day}T00:00:00.000Z`;
    const time = (ms) => new Date(Date.parse(at) + ms).toISOString();
    const run = { id: `run_${side}`, tenant_id: tenantId, target_id: target.id, check_id: check.check_id,
      ...deriveRunEvidenceStamp(check, undefined, { probeMode: 'signed-worker', scenarioVersion: 's1' }), status: 'completed', producer_kind: 'signed_probe',
      created_at: at, completed_at: time(1200), probe_external_result: 'connected',
      safety_constraints: { assurance_scope: deriveAssuranceScope({ target, check }) } };
    const job = buildSignedProbeJobRecord({ run, check, target, probeWorkerSecret: 'local-firewall-proof-signing-key',
      now: new Date(at), newId: () => `job_${side}` });
    Object.assign(job, { status: 'leased', leased_by: workerId, leased_at: time(100) });
    const reservation = executionReservation(job, workerId, job.leased_at, `reservation_${side}`, new Date(time(200)));
    assert.equal(reservation.error, undefined);
    job.worker_metadata.execution_reservation = reservation.reservation;
    const resolverAttempts = job.constraints.min_destination_resolver_attempts;
    const attestation = { requests_sent: 1 + resolverAttempts, probe_requests_sent: 1, destination_resolver_attempts: resolverAttempts,
      total_operations: 1 + resolverAttempts, duration_ms: 20 };
    const metadata = { profile_kind: probeKind, external_result: 'connected', probe_job_id: job.id,
      probe_worker_id: workerId, source_perspective: sourcePerspective, safety_attestation: attestation,
      execution_receipt: probeExecutionEvidenceReceipt(job, workerId, attestation, 'connected'),
      ...(probeKind === 'tls_audit' ? { complete: true, tls_protocol: 'TLSv1.3' } : { observation_complete: true }),
      ...(probeKind === 'udp_probe' ? { response_received: true, response_bytes: 16 } : {}),
      ...(probeKind === 'port_scan_bounded' ? { open_ports: [443], closed_ports: [], filtered_ports: [] } : {}),
      target_port: 443, pinned_address: '192.0.2.10' };
    const event = { id: `event_${side}`, tenant_id: tenantId, test_run_id: run.id, target_id: target.id,
      check_id: check.check_id, nonce_hash: job.nonce_hash, timestamp: time(1000), ingested_at: time(1000),
      producer_kind: 'signed_probe', signal_type: 'probe_result', metadata };
    run.correlation = { nonce_hash: job.nonce_hash };
    Object.assign(job, { status: 'completed', completed_at: time(1100) });
    runs.push(run); events.push(event); jobs.push(job);
  }
  const samples = events.map((event, index) => firewallSampleFromProbeEvent({ event, run: runs[index], target, sourcePerspective }));
  const baseline = buildFirewallBaselineCapture({ tenantId, changeId: expectation.change_id,
    expectations: [{ id: expectation.id, record: expectation }], samples: [samples[0]],
    freshnessWindowSeconds, capturedAt: timeline.capture ?? '2026-10-02T00:00:00.000Z' }).capture;
  Object.assign(baseline, { id: 'fwb_proof', created_at: baseline.captured_at, entry_count: baseline.entries.length });
  const evaluation = { ...evaluateFirewallChange({ tenantId, baseline, expectations: { [expectation.id]: expectation },
    candidateSamples: [samples[1]], evaluatedAt: timeline.evaluated ?? '2026-10-03T00:01:00.000Z', now: generatedAt }).evaluation, id: 'fwc_proof' };
  const evidenceInputs = { runs, events, jobs, baselines: [baseline], evidenceItems: [], input_complete: true };
  const report = () => buildProtectionValidationReport({ tenantId, generatedAt, targets: [target],
    firewallExpectations: [expectation], firewallEvaluations: [evaluation], checkCatalog: [check], evidenceInputs, resolveSourcePerspective });
  return { target, expectation, baseline, evaluation, evidenceInputs, report };
}
function conclusion(w) { return w.report().conclusions.find((row) => row.subject.expectation_id); }

describe('passive independently reconstructed firewall acceptance', () => {
  it('qualifies actual before/after TLS samples with signed jobs and durable reservations, without readiness credit', () => {
    const w = world();
    const row = conclusion(w);
    assert.equal(row.current_assurance.status, 'sampled_ingress_only', JSON.stringify(row.current_assurance));
    assert.equal(w.report().units.firewall_expectations.by_status.accepted, 1);
    assert.equal(row.readiness_eligible, false);
    assert.equal(row.freshness.observed_at, w.baseline.entries[0].references[0].observed_at);
  });
  for (const [name, mutate] of [
    ['missing pre-run', (w) => { w.evidenceInputs.runs.shift(); }],
    ['missing baseline', (w) => { w.evidenceInputs.baselines = []; }],
    ['missing pre-event', (w) => { w.evidenceInputs.events.shift(); }],
    ['missing job', (w) => { w.evidenceInputs.jobs.shift(); }],
    ['wrong tenant job', (w) => { w.evidenceInputs.jobs[0].tenant_id = 'ten_other'; }],
    ['wrong worker', (w) => { w.evidenceInputs.jobs[0].leased_by = 'worker_other'; }],
    ['missing reservation', (w) => { delete w.evidenceInputs.jobs[0].worker_metadata.execution_reservation; }],
    ['changed allowance', (w) => { w.evidenceInputs.jobs[0].constraints.max_probe_requests++; }],
    ['missing accepted receipt', (w) => { delete w.evidenceInputs.events[0].metadata.execution_receipt; }],
    ['forged accepted receipt', (w) => { w.evidenceInputs.events[0].metadata.execution_receipt.digest = '0'.repeat(64); }],
    ['changed attestation', (w) => { w.evidenceInputs.events[0].metadata.safety_attestation.duration_ms++; }],
    ['late ingested pre-event', (w) => { w.evidenceInputs.events[0].ingested_at = '2026-10-05T00:00:00.000Z'; }],
    ['wrong nonce', (w) => { w.evidenceInputs.events[0].nonce_hash = 'other'; }],
    ['changed target', (w) => { w.target.value = 'different.example.test'; }],
    ['retained observation forged', (w) => { w.baseline.entries[0].observations_digest = '0'.repeat(64); }],
    ['omitted contradictory event', (w) => { w.evidenceInputs.events.push({ ...w.evidenceInputs.events[0], id: 'unreferenced' }); }],
    ['same pre/post run', (w) => { w.evaluation.items[0].evidence_refs = structuredClone(w.baseline.entries[0].references);
      w.evaluation.evaluation_digest = comparisonEvaluationDigest(w.evaluation); }],
    ['forged retained outcome', (w) => { w.evaluation.items[0].status = 'improvement';
      w.evaluation.items[0].pre_state = 'violated'; w.evaluation.evaluation_digest = comparisonEvaluationDigest(w.evaluation); }],
  ]) it(`withholds current qualification for ${name} while retaining the comparison`, () => {
    const w = world(); mutate(w);
    const row = conclusion(w);
    assert.equal(row.current_assurance.status, 'not_established', name);
    assert.equal(w.report().units.firewall_expectations.by_status.accepted, 0);
    assert.equal(row.result_role, 'retained_immutable_comparison');
  });
  for (const probeKind of ['tcp_connect', 'udp_probe', 'port_scan_bounded']) {
    it(`qualifies finite ${probeKind} observations without a multi-leg protection assertion`, () => {
      const w = world({ probeKind });
      assert.equal(conclusion(w).current_assurance.status, 'sampled_ingress_only', JSON.stringify(conclusion(w).current_assurance));
      assert.equal(conclusion(w).readiness_eligible, false);
      w.evidenceInputs.events[0].metadata.observation_complete = false;
      assert.equal(conclusion(w).current_assurance.status, 'not_established');
    });
  }

  it('uses equivalent PostgreSQL timestamp instants without changing signed authority JSON', () => {
    const w = world();
    for (const job of w.evidenceInputs.jobs) job.leased_at = job.leased_at.replace('Z', '+00:00');
    assert.equal(conclusion(w).current_assurance.status, 'sampled_ingress_only');
    w.evidenceInputs.jobs[0].leased_at = '2026-10-01T00:00:01.000+00:00';
    assert.equal(conclusion(w).current_assurance.status, 'not_established');
  });

  it('uses the injected registry instead of process environment for current source qualification', () => {
    const resolver = probeSourceResolverFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: JSON.stringify({ 'approved-region-one': [workerId] }) });
    const w = world({ sourcePerspective: 'approved-region-one', resolveSourcePerspective: resolver });
    assert.equal(conclusion(w).current_assurance.status, 'sampled_ingress_only');
    const denied = world({ resolveSourcePerspective: probeSourceResolverFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: '{}' }) });
    assert.equal(conclusion(denied).current_assurance.status, 'not_established');
    assert.ok(conclusion(denied).current_assurance.reasons.includes('actual_firewall_source_unverified'));
  });

  it('reports expiry using the shorter baseline window and a distinct expiry reason', () => {
    const w = world({ freshnessWindowSeconds: 3600, generatedAt: '2026-10-01T01:10:00.000Z',
      timeline: { pre: '2026-10-01T00:00:00.000Z', capture: '2026-10-01T00:10:00.000Z',
        post: '2026-10-01T00:30:00.000Z', evaluated: '2026-10-01T00:31:00.000Z' } });
    const row = conclusion(w);
    assert.equal(row.freshness.state, 'stale');
    assert.equal(row.freshness.window_seconds, 3600);
    assert.equal(row.freshness.expires_at, '2026-10-01T01:00:01.000Z');
    assert.ok(row.current_assurance.reasons.includes('actual_firewall_sample_expired'));
    assert.equal(w.report().units.firewall_expectations.by_status.stale, 1);
  });

  it('never extends the report policy with a longer baseline freshness window', () => {
    const w = world({ freshnessWindowSeconds: 5184000 });
    assert.equal(conclusion(w).freshness.window_seconds, 2592000);
    assert.equal(conclusion(w).freshness.baseline_window_seconds, 5184000);
  });

  it('qualifies equivalent PostgreSQL JSON-column shapes', () => {
    const w = world();
    for (const job of w.evidenceInputs.jobs) {
      job.constraints_json = job.constraints; delete job.constraints;
      job.target_descriptor_json = job.target; delete job.target;
      job.worker_metadata_json = job.worker_metadata; delete job.worker_metadata;
    }
    for (const event of w.evidenceInputs.events) { event.metadata_json = event.metadata; delete event.metadata; }
    assert.equal(conclusion(w).current_assurance.status, 'sampled_ingress_only');
  });
});
