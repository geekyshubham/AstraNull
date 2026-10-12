/** Read-time posture assurance. Stored snapshots and custody hashes are never rewritten. */
import { CHECK_CATALOG } from '../contracts/checks.mjs';
import { versionGapFor, observationAssuranceGap } from './protectionCoverage.mjs';
export const WAF_POSTURE_ASSURANCE_VERSION = 'waf-posture-assurance.v2';
export const WAF_POSTURE_MAX_AGE_MS = 7 * 86400000;
const time = (value) => { const ms = value == null ? NaN : new Date(value).getTime(); return Number.isFinite(ms) ? ms : null; };
const evidenceOf = (snapshot) => snapshot?.evidence_json ?? snapshot?.evidence ?? {};
const available = (row, cutoff, fallback) => {
  const times = [row?.created_at, row?.ingested_at].filter((value) => value != null).map(time);
  return (times.length ? times : [time(fallback)]).every((at) => at != null && at <= cutoff);
};

export function snapshotObservedAt(snapshot) {
  return snapshot?.observed_at ?? evidenceOf(snapshot).observed_at ?? snapshot?.created_at ?? null;
}
export function snapshotAvailableAsOf(snapshot, cutoff) {
  const cutoffMs = new Date(cutoff).getTime(); const observed = time(snapshotObservedAt(snapshot));
  return observed != null && observed <= cutoffMs && available(snapshot, cutoffMs, snapshotObservedAt(snapshot));
}
export function assetInCohortAsOf(asset, cutoff, firstKnownAt = null) {
  const cutoffMs = new Date(cutoff).getTime(); const created = time(asset?.created_at ?? firstKnownAt);
  if (created == null || created > cutoffMs) return false;
  return ![asset.deleted_at, asset.archived_at, asset.retired_at].some((value) => time(value) != null && time(value) <= cutoffMs);
}

function proofGap(snapshot, asOf, catalog) {
  const proof = evidenceOf(snapshot); const cutoff = new Date(asOf).getTime();
  const check = catalog.find((row) => row.check_id === proof.check_id);
  if (!check || check.evidence_tier !== 'E3' || check.observation_only || check.readiness_conclusion === false) return 'scenario_proof_missing';
  if (proof.complete !== true || proof.comparison_complete !== true || proof.producer_kind !== 'signed_probe' || !proof.canonical_url || !proof.source_perspective || !proof.test_run_id) return 'complete_scoped_proof_missing';
  const versionGap = versionGapFor(check, proof, null) ?? observationAssuranceGap({ probe_metadata: proof }, null, check);
  if (versionGap) return versionGap;
  const ids = proof.evidence_ids; const events = proof.result_events ?? [];
  if (!Array.isArray(ids) || !ids.length || ids.some((id) => {
    const event = events.find((row) => row.id === id); const metadata = event?.metadata ?? event?.metadata_json ?? {};
    return !event || event.producer_kind !== 'signed_probe' || event.signal_type !== 'probe_result'
      || !snapshot.tenant_id || event.tenant_id !== snapshot.tenant_id || event.test_run_id !== proof.test_run_id
      || metadata.waf_asset_id !== snapshot.waf_asset_id || metadata.posture_status !== snapshot.status
      || metadata.complete !== true || metadata.observation_only === true || metadata.readiness_conclusion === false
      || ['canonical_url', 'check_id', 'check_version', 'scenario_version', 'source_perspective'].some((field) => metadata[field] !== proof[field])
      || time(event.ingested_at) == null || time(event.timestamp) == null || time(event.timestamp) > cutoff || !available(event, cutoff, event.timestamp)
      || cutoff - time(event.timestamp) > WAF_POSTURE_MAX_AGE_MS
      || observationAssuranceGap({ probe_metadata: metadata }, null, check);
  })) return 'referenced_posture_evidence_unverified';
  // Captured posture labels and completeness flags cannot override a contradictory
  // performed result. Every required actual signed leg must support positive credit.
  if (['protected', 'edge_protected'].includes(snapshot.status) && ids.some((id) => {
    const event = events.find((row) => row.id === id);
    return (event.metadata ?? event.metadata_json ?? {}).enforcement !== 'enforced';
  })) return 'actual_positive_outcome_mismatch';
  if (Math.min(...ids.map((id) => time(events.find((row) => row.id === id).timestamp))) !== time(snapshotObservedAt(snapshot))) return 'observation_time_mismatch';
  return null;
}
export function assessPostureAssurance({ asset = null, snapshot = null, asOf = new Date(), catalog = CHECK_CATALOG } = {}) {
  const historical = snapshot?.status ?? 'unknown'; const observedAt = snapshotObservedAt(snapshot); const nowMs = new Date(asOf).getTime();
  let reason = !snapshot ? 'no_snapshot' : !snapshotAvailableAsOf(snapshot, asOf) ? 'observation_time_unknown_or_future' : nowMs - time(observedAt) > WAF_POSTURE_MAX_AGE_MS ? 'stale' : null;
  if (!reason && historical !== 'excluded') reason = proofGap(snapshot, asOf, catalog);
  if (!reason && asset) {
    const changed = time(asset.assurance_invalidated_at ?? asset.material_updated_at ?? asset.definition_updated_at);
    if (changed != null && changed > time(observedAt) && changed <= nowMs) reason = 'asset_definition_changed';
    if (evidenceOf(snapshot).canonical_url !== asset.canonical_url) reason = 'asset_path_changed';
  }
  return { version: WAF_POSTURE_ASSURANCE_VERSION, status: reason ? 'unknown' : historical, historical_status: historical, observed_at: observedAt, current_assurance: reason ? 'not_established' : historical === 'excluded' ? 'excluded_declaration' : historical === 'edge_protected' ? 'edge_only_tested_scenario' : 'tested_scenario_only', retest_required: Boolean(snapshot && reason), reason, edge_only: historical === 'edge_protected', origin_lockdown: 'not_established', expires_at: time(observedAt) == null ? null : new Date(time(observedAt) + WAF_POSTURE_MAX_AGE_MS).toISOString() };
}

/** A failed/unknown observation is never provider loss. Both legs must be complete and comparable. */
export function comparablePostureObservation(previous, current, { asOf = new Date() } = {}) {
  if (!previous || !current || ['unknown', 'excluded'].includes(current.status)) return false;
  const before = evidenceOf(previous); const after = evidenceOf(current);
  for (const [snapshot, proof] of [[previous, before], [current, after]]) {
    if (proof.complete !== true || proof.scan_success !== true || !['observed', 'success', 'response_observed', 'not_detected'].includes(proof.observation_outcome ?? proof.scan_outcome) || !snapshotAvailableAsOf(snapshot, asOf)) return false;
  }
  for (const field of ['canonical_url', 'check_version', 'scenario_version', 'corpus_version', 'source_perspective']) if (!before[field] || !after[field] || before[field] !== after[field]) return false;
  return previous.tenant_id === current.tenant_id && previous.waf_asset_id === current.waf_asset_id && time(snapshotObservedAt(current)) >= time(snapshotObservedAt(previous));
}
export function detectPostureDrifts(previous, current, options = {}) {
  if (!comparablePostureObservation(previous, current, options)) return [];
  const before = { status: previous.status, detected_vendor: previous.detected_vendor ?? null, reason_codes: previous.reason_codes ?? [] };
  const after = { status: current.status, detected_vendor: current.detected_vendor ?? null, reason_codes: current.reason_codes ?? [], evidence_role: 'comparable_external_observation', retest_required: true, establishes_control_cause: false };
  const result = []; const add = (type, severity) => result.push({ drift_type: type, severity, before_summary_json: before, after_summary_json: after, reason_codes: current.reason_codes ?? [] });
  if (previous.detected_vendor && !current.detected_vendor) add('fingerprint_loss', ['protected', 'edge_protected'].includes(previous.status) && current.status === 'unprotected' ? 'critical' : 'high');
  if (['protected', 'edge_protected'].includes(previous.status) && ['unprotected', 'underprotected'].includes(current.status)) {
    if (verifiedOriginBypass(current, {}, options)) add('origin_bypass_new', 'critical');
    if ((current.reason_codes ?? []).some((code) => ['monitor_only_behavior', 'rule_mode_changed', 'marker_rule_not_blocking'].includes(code))) add('mode_downgrade', 'critical');
  }
  return result;
}

/** Boolean flags and unresolved IDs alone are not origin-bypass evidence. */
export function verifiedOriginBypass(snapshot, summary = {}, { asOf = new Date() } = {}) {
  const proof = summary.origin_bypass_evidence ?? evidenceOf(snapshot).origin_bypass_evidence; const cutoff = new Date(asOf).getTime();
  if (!(proof?.confirmed === true && proof.complete === true && proof.origin_binding_id && proof.application_identity_confirmed === true && proof.same_scenario === true && proof.primary_healthy === true && proof.canonical_url && proof.scenario_version && proof.check_version && proof.source_perspective && Array.isArray(proof.evidence_ids) && proof.evidence_ids.length)) return false;
  const events = proof.result_events ?? []; const observed = time(proof.observed_at);
  return observed != null && observed <= cutoff && cutoff - observed <= WAF_POSTURE_MAX_AGE_MS && proof.evidence_ids.every((id) => {
    const event = events.find((row) => row.id === id); const metadata = event?.metadata ?? event?.metadata_json ?? {};
    return event?.producer_kind === 'signed_probe' && event.signal_type === 'probe_result' && snapshot?.tenant_id && event.tenant_id === snapshot.tenant_id
      && event.test_run_id === proof.test_run_id && metadata.origin_bypass_confirmed === true && metadata.complete === true
      && ['canonical_url', 'scenario_version', 'check_version', 'source_perspective', 'origin_binding_id'].every((field) => metadata[field] === proof[field])
      && time(event.ingested_at) != null && time(event.timestamp) === observed && available(event, cutoff, event.timestamp);
  });
}
