/** Evidence-specific advice, not an authorization, execution plan, or proof of closure. */
export const REMEDIATION_PLAN_VERSION = 'finding-remediation.v2';
export const REMEDIATION_STATES = Object.freeze(['open', 'in_progress', 'delivered', 'accepted_risk', 'resolved']);
const text = (value) => typeof value === 'string' && value.trim() ? value.trim() : null;
const list = (value) => Array.isArray(value) ? value : [];

export function remediationDisposition(record = {}) {
  return { kind: record.state === 'resolved' ? 'administrative_disposition' : record.state === 'accepted_risk' ? 'accepted_risk' : 'open', mitigation_verified: false, requires_compatible_retest: true };
}

export function buildFindingRemediationPlan(finding, payload = {}) {
  const pv = finding.protection_validation ?? {};
  const observed = pv.observed ?? {};
  const scope = pv.observed_route ?? { target_id: finding.target_id ?? null };
  const codes = list(finding.reason_codes);
  const outcome = observed.gap_kind ?? observed.outcome ?? finding.finding_class ?? finding.verdict ?? codes[0] ?? 'unqualified_observation';
  const evidenceIds = [...new Set([...list(finding.evidence_ids), ...list(pv.evidence_refs).flatMap((ref) => list(ref.evidence_ids))])].sort();
  const suspect = !evidenceIds.length || /suspected|unknown|unqualified/.test(outcome);
  let action = 'review_evidence_and_retest';
  let review = 'Confirm the observed cause and current declared path; do not infer a missing WAF or origin control from an unknown observation.';
  if (outcome === 'scoped_application_bypass' || outcome === 'confirmed_exposure' && pv.comparison_kind === 'path_validation') {
    action = 'review_declared_path_controls';
    review = 'Compare the declared route with the primary route for the same scenario; review attachment, exclusions and allowed origin access only where this evidence identifies the affected scope.';
  } else if (outcome === 'weaker_observed_enforcement' || outcome === 'observed_enforcement_gap') {
    action = 'review_scenario_enforcement';
    review = 'Compare enforcement and exclusions for this scenario on the affected route. No provider-specific rule or responsible layer has been established.';
  } else if (outcome === 'forbidden_service_newly_reachable') {
    action = 'review_declared_ingress_change';
    review = 'Review the authorized change for the declared destination, endpoint and source perspective; identify the permitting rule or route before restricting it.';
  } else if (outcome === 'required_service_newly_unavailable' || outcome === 'observed_availability_gap') {
    action = 'review_service_availability_change';
    review = 'Check the declared service health and authorized routing/firewall change. Silence alone does not identify a blocking control.';
  }
  const owner = text(payload.owner_group ?? payload.owner) ?? text(pv.owner ?? finding.owner ?? finding.owner_hint) ?? 'unassigned';
  const scenario = pv.scenario ?? pv.comparison_context?.scenario ?? finding.scenario_version ?? null;
  const retest = { target_id: finding.target_id ?? null, check_id: finding.check_id ?? null, scenario, comparison_kind: pv.comparison_kind ?? null, source_perspective: pv.failed_expectation?.source_perspective ?? null, authorization: 'existing_run_admission_and_SOC_gates', closes_without_verified_result: false };
  const custom = Array.isArray(payload.steps) ? payload.steps.map(String) : typeof payload.steps === 'string' ? payload.steps.split('|').map((step) => step.trim()).filter(Boolean) : null;
  return {
    semantics_version: REMEDIATION_PLAN_VERSION,
    action_slug: text(payload.action_slug ?? payload.action) ?? action,
    owner_group: owner,
    description: text(payload.description) ?? `Finding ${finding.id}: ${finding.title ?? outcome}. Observed cause: ${outcome}; confidence ${suspect ? 'review_required' : 'external_only_tested_scope'}. Evidence: ${evidenceIds.join(', ') || 'not_linked'}. Scope: ${JSON.stringify(scope)}. Responsible control/vendor not established.`,
    steps: custom ?? [
      `Review linked evidence for finding ${finding.id}: ${evidenceIds.join(', ') || 'obtain missing references'}; confirm observation time, source and scenario ${scenario ?? 'not_recorded'}.`,
      review,
      `Assign a change owner (${owner}); record expected impact on legitimate traffic, approval, canary rollout and rollback criteria before any control change.`,
      `Retest the exact compatible scope with check ${retest.check_id ?? 'approved compatible check'}, scenario ${scenario ?? 'approved scenario'}, after deployment; retain the prior evidence and do not mark technical mitigation verified from delivery or administrative resolution.`,
    ],
    evidence_ids: evidenceIds,
    observed_cause: outcome,
    confidence: suspect ? 'review_required' : 'external_only',
    affected_scope: scope,
    impact_and_rollback: 'Customer-approved change, legitimate-traffic monitoring, canary rollout and recorded rollback criteria required.',
    retest,
    sla_hours: Number.isFinite(Number(payload.sla_hours)) && Number(payload.sla_hours) > 0 ? Number(payload.sla_hours) : null,
    resolution: remediationDisposition(),
  };
}
