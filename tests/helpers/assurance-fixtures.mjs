import { getCheckById } from '../../src/contracts/checks.mjs';
import { deriveRunEvidenceStamp, approvedScenarioVersion } from '../../src/lib/checkDefinitionVersion.mjs';
import { deriveAssuranceScope } from '../../src/lib/assuranceScope.mjs';
import { WAF_GRADING_VERSION, SIGNATURE_CORPUS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';

export const ASSURANCE_NOW = '2026-10-08T12:00:00.000Z';
export const ASSURANCE_OBSERVED = '2026-10-07T12:00:00.000Z';
export function assuranceWorld({ targetCount = 1, checkCount = 1, tenantId = 'ten_demo' } = {}) {
  const group = { id: 'tg_1', tenant_id: tenantId, expected_behavior_default: 'block_at_edge', safety_policy: {}, created_at: '2026-01-01T00:00:00.000Z' };
  const check = getCheckById('waf.sqli_managed_marker.safe');
  const catalog = Array.from({ length: checkCount }, (_, index) => index ? { ...structuredClone(check), check_id: `waf.test_marker_${index}.safe` } : structuredClone(check));
  return { tenantId, asOf: ASSURANCE_NOW, input_complete: true, groups: [group], targets: Array.from({ length: targetCount }, (_, index) => ({ id: `tgt_${index + 1}`, tenant_id: tenantId, target_group_id: group.id, kind: 'url', value: `https://app${index + 1}.example.test/path`, created_at: group.created_at })), catalog, runs: [], verdicts: [], events: [], evidenceItems: [], findings: [], policies: [], highScaleRequests: [] };
}
export function addAssuredObservation(world, { target = world.targets[0], check = world.catalog[0], observedAt = ASSURANCE_OBSERVED, startedAt = observedAt, outcome = 'protected', id = `run_${world.runs.length + 1}`, policy = null } = {}) {
  const stamp = deriveRunEvidenceStamp(check, undefined, { probeMode: 'signed-worker', scenarioVersion: approvedScenarioVersion(check) });
  // Only marker probes carry a comparison classifier: evasion probes are graded by v4, every
  // other marker probe by v5. Declaration-only checks record no classifier at all.
  const markerKind = ['waf_class_marker_probe', 'waf_evasion_marker_probe', 'outside_in_waf_scan'].includes(check?.probe_profile?.kind);
  const classifier = !markerKind && check?.requires_complete_comparison !== true ? null
    : check?.probe_profile?.kind === 'waf_evasion_marker_probe' ? 'marker-comparison-v4' : 'marker-comparison-v5';
  const nonce = `fixture_nonce_${id}`;
  const run = { id, correlation: { nonce_hash: nonce }, tenant_id: world.tenantId, target_id: target.id, target_group_id: target.target_group_id, check_id: check.check_id, policy_id: policy?.id ?? null, status: 'verdicted', created_at: startedAt, started_at: startedAt, completed_at: observedAt, probe_metadata: { grading_version: WAF_GRADING_VERSION, signature_corpus_version: SIGNATURE_CORPUS_VERSION }, ...stamp, safety_constraints: { assurance_scope: deriveAssuranceScope({ target, policy, targetGroup: world.groups.find((row) => row.id === target.target_group_id) }) } };
  const event = { id: `evt_${id}`, nonce_hash: nonce, tenant_id: world.tenantId, test_run_id: id, producer_kind: 'signed_probe', signal_type: 'probe_result', timestamp: observedAt, ingested_at: observedAt, metadata: { grading_version: WAF_GRADING_VERSION, signature_corpus_version: SIGNATURE_CORPUS_VERSION, ...(classifier ? { classifier_version: classifier } : {}), comparison_complete: true, planned_marker_legs: 2, attempted_marker_legs: 2, completed_marker_legs: 2, graded_marker_legs: 2, ungraded_marker_legs: 0, missing_marker_legs: 0, permitted_baseline_health: 'healthy', trailing_control: { outcome: 'allowed' }, enforcement: ['protected', 'edge_protected'].includes(outcome) ? 'enforced' : 'not_enforced', evidence_complete: true, observation_only: false, readiness_conclusion: true } };
  const verdict = { id: `vrd_${id}`, tenant_id: world.tenantId, test_run_id: id, verdict: outcome, created_at: observedAt, evidence_ids: [event.id] };
  world.runs.push(run); world.events.push(event); world.verdicts.push(verdict);
  return { run, event, verdict };
}

export function assuredPosture(asset, status = 'protected', observedAt = ASSURANCE_OBSERVED) {
  const world = assuranceWorld({ tenantId: asset.tenant_id ?? 'ten_demo' });
  const { run, event } = addAssuredObservation(world, { observedAt });
  const proof = { ...event.metadata, complete: true, producer_kind: 'signed_probe', check_id: run.check_id, check_version: run.check_version, scenario_version: run.scenario_version, canonical_url: asset.canonical_url, source_perspective: 'external_fixture', observed_at: observedAt, test_run_id: run.id, evidence_ids: [event.id], corpus_version: 'fixture-corpus-v1', scan_success: true, observation_outcome: 'observed' };
  Object.assign(event.metadata, proof, { waf_asset_id: asset.id, posture_status: status });
  return { id: `snapshot_${asset.id}`, waf_asset_id: asset.id, tenant_id: world.tenantId, status, observed_at: observedAt, created_at: observedAt, evidence_json: { ...proof, result_events: [event] } };
}
export function exactOriginProof(snapshot) {
  const proof = { confirmed: true, complete: true, origin_binding_id: 'origin_binding', application_identity_confirmed: true, same_scenario: true, primary_healthy: true, canonical_url: 'https://app.example.test/path', check_version: '1.0.0', scenario_version: 'origin-fixture-v1', source_perspective: 'external_fixture', observed_at: snapshot.observed_at ?? snapshot.created_at, test_run_id: 'origin_run', evidence_ids: ['origin_event'] };
  proof.result_events = [{ id: 'origin_event', tenant_id: snapshot.tenant_id, test_run_id: proof.test_run_id, producer_kind: 'signed_probe', signal_type: 'probe_result', timestamp: proof.observed_at, ingested_at: proof.observed_at, metadata: { ...proof, origin_bypass_confirmed: true } }];
  return proof;
}
export function comparablePosture(snapshot) {
  const evidence = { complete: true, scan_success: true, observation_outcome: 'observed', canonical_url: 'https://app.example.test/path', check_version: '1.0.0', scenario_version: 'posture-fixture-v1', corpus_version: 'fixture-corpus-v1', source_perspective: 'external_fixture', ...(snapshot.evidence_json ?? {}) };
  if (snapshot.reason_codes?.includes('origin_bypass_confirmed')) evidence.origin_bypass_evidence = exactOriginProof(snapshot);
  return { ...snapshot, evidence_json: evidence };
}
