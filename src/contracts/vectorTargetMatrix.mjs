import {
  checkRequiresAdditionalInput,
  evaluateCheckPrerequisites,
  getCheckById,
  isCustomerRunnable,
} from './checks.mjs';
import { targetKindCompatibilityError } from './checkTargetCompatibility.mjs';
import { VECTOR_LIBRARY, VECTOR_LIBRARY_TOTAL } from './vectorLibrary.mjs';

export const DEFAULT_VECTOR_TARGET_PROFILE = Object.freeze({
  target_kind: 'fqdn',
  validation_mode: 'external_only',
  agent: 'none',
});

export const TARGET_VECTOR_DISPOSITIONS = Object.freeze([
  'safe_runnable',
  'agent_required',
  'additional_input_required',
  'target_incompatible',
  'soc_gated',
  'monitor_only',
  'not_runnable',
]);

function sortStrings(values) {
  return [...new Set(values)].sort((left, right) => (
    left < right ? -1 : left > right ? 1 : 0
  ));
}

function syntheticTarget(targetKind) {
  if (targetKind === 'url') return { kind: 'url', value: 'https://example.invalid/' };
  if (targetKind === 'ip') return { kind: 'ip', value: '203.0.113.1' };
  return { kind: targetKind, value: 'example.invalid' };
}

function assessSafeCheck(checkId, profile) {
  const check = getCheckById(checkId);
  if (!check || !isCustomerRunnable(check)) {
    return { check_id: checkId, runnable: false, reasons: ['not_customer_runnable'] };
  }

  const reasons = [];
  if (targetKindCompatibilityError(check, syntheticTarget(profile.target_kind))) {
    reasons.push('target_kind_not_supported');
  }
  const onlineAgents = profile.agent === 'none' ? [] : [{ capabilities: check.required_agent_modes ?? [] }];
  if (evaluateCheckPrerequisites(check, { onlineAgents }).length > 0) reasons.push('agent_required');
  if (checkRequiresAdditionalInput(check) && !reasons.includes('agent_required')) {
    reasons.push('additional_customer_input_required');
  }
  return { check_id: checkId, runnable: reasons.length === 0, reasons };
}

function rowDisposition(vector, assessments) {
  if (vector.execution_disposition === 'monitor_only') return 'monitor_only';
  if (vector.execution_disposition === 'soc_gated_only') return 'soc_gated';
  if (vector.execution_disposition !== 'safe_validation_available') return 'not_runnable';
  if (assessments.some((assessment) => assessment.runnable)) return 'safe_runnable';
  if (assessments.some((assessment) => assessment.reasons.includes('agent_required'))) {
    return 'agent_required';
  }
  if (assessments.some((assessment) => (
    assessment.reasons.includes('additional_customer_input_required')
  ))) {
    return 'additional_input_required';
  }
  return vector.safe_check_ids.length > 0 ? 'target_incompatible' : 'not_runnable';
}

export function buildVectorTargetMatrix(profile = DEFAULT_VECTOR_TARGET_PROFILE) {
  const normalizedProfile = {
    target_kind: String(profile.target_kind ?? 'fqdn').trim().toLowerCase(),
    validation_mode: String(profile.validation_mode ?? 'external_only').trim().toLowerCase(),
    agent: String(profile.agent ?? 'none').trim().toLowerCase(),
  };
  const rows = VECTOR_LIBRARY.map((vector) => {
    const assessments = vector.execution_disposition === 'safe_validation_available'
      ? vector.safe_check_ids.map((checkId) => assessSafeCheck(checkId, normalizedProfile))
      : [];
    const runnableSafeCheckIds = sortStrings(
      assessments.filter((assessment) => assessment.runnable).map((assessment) => assessment.check_id),
    );
    return {
      vector_id: vector.vector_id,
      canonical_name: vector.canonical_name,
      evidence_tier: vector.evidence_tier,
      evidence_capability: vector.evidence_capability,
      execution_disposition: vector.execution_disposition,
      target_disposition: rowDisposition(vector, assessments),
      safe_check_ids: [...vector.safe_check_ids],
      soc_check_ids: [...vector.soc_check_ids],
      metadata_available: vector.metadata_available,
      metadata_check_ids: [...vector.metadata_check_ids],
      transport_check_ids: [...vector.transport_check_ids],
      semantic_safe_check_ids: [...vector.semantic_safe_check_ids],
      supplemental_safe_check_ids: vector.execution_disposition === 'safe_validation_available'
        ? []
        : [...vector.safe_check_ids],
      runnable_safe_check_ids: runnableSafeCheckIds,
      blocked_safe_checks: assessments
        .filter((assessment) => !assessment.runnable)
        .map((assessment) => ({
          check_id: assessment.check_id,
          reasons: [...assessment.reasons],
        })),
    };
  });

  const runnableSafeCheckIds = sortStrings(rows.flatMap((row) => row.runnable_safe_check_ids));
  const dispositions = Object.fromEntries(TARGET_VECTOR_DISPOSITIONS.map((value) => [value, 0]));
  const evidenceCapabilities = {};
  const executionDispositions = {};
  const evidenceExecutionMatrix = {};
  for (const row of rows) {
    dispositions[row.target_disposition] += 1;
    evidenceCapabilities[row.evidence_capability] = (
      evidenceCapabilities[row.evidence_capability] ?? 0
    ) + 1;
    executionDispositions[row.execution_disposition] = (
      executionDispositions[row.execution_disposition] ?? 0
    ) + 1;
    evidenceExecutionMatrix[row.evidence_capability] ??= {};
    evidenceExecutionMatrix[row.evidence_capability][row.execution_disposition] = (
      evidenceExecutionMatrix[row.evidence_capability][row.execution_disposition] ?? 0
    ) + 1;
  }

  return {
    profile: normalizedProfile,
    summary: {
      total: VECTOR_LIBRARY_TOTAL,
      dispositions,
      evidence_capabilities: evidenceCapabilities,
      execution_dispositions: executionDispositions,
      evidence_execution_matrix: evidenceExecutionMatrix,
      runnable_safe_check_count: runnableSafeCheckIds.length,
    },
    runnable_safe_check_ids: runnableSafeCheckIds,
    rows,
  };
}
