import type { DataItem } from './types';

/** Mirrors `PRODUCTION_RELEASE_EVIDENCE_KINDS` in `src/contracts/productionReleaseEvidence.mjs`. */
export const PRODUCTION_RELEASE_EVIDENCE_KINDS = [
  'third_party_security_review',
  'migration_apply',
  'operator_runbook_exercise',
  'oidc_prod_auth_preflight',
  'edge_protection',
  'agent_sbom_provenance',
  'agent_install_matrix',
  'agent_mtls_gateway',
  'agent_trust_key_ceremony',
  'governed_adapter',
  'provider_approval',
  'kill_switch_drill',
  'postgres_concurrency',
  'dr_restore',
  'ui_accessibility_matrix',
  'notification_provider_config',
  'probe_fleet_matrix',
  'vector_safety_policy',
  'secret_rotation_drill',
  'observability_slo',
  'support_readiness',
  'evidence_snapshot_manifest',
  'postgres_tenant_query_audit',
  'rollback_fixforward',
  'kms_vault_posture',
  'control_plane_container_release',
  'staging_e2e_matrix',
  'compliance_legal_signoff',
  'authorization_custody',
  'placement_confidence_staging',
  'gateway_load_abuse'
] as const;

function isAcceptedReleaseEvidenceStatus(status: unknown) {
  const normalized = typeof status === 'string' ? status.trim().toLowerCase() : 'accepted';
  return normalized === 'accepted' || normalized === 'approved';
}

function isSubmittableReleaseEvidenceItem(item: DataItem = {}) {
  if (item.dry_run === true || item.submittable === false || item.collector_dry_run === true) {
    return false;
  }
  return isAcceptedReleaseEvidenceStatus(item.status);
}

export function computeReleaseEvidenceCoverage(items: DataItem[] = []) {
  const recorded = new Set<string>();
  for (const item of items) {
    const kind = typeof item.kind === 'string' ? item.kind : '';
    if (!kind || !isSubmittableReleaseEvidenceItem(item)) continue;
    recorded.add(kind);
  }
  const missing = PRODUCTION_RELEASE_EVIDENCE_KINDS.filter((kind) => !recorded.has(kind));
  return {
    expected: PRODUCTION_RELEASE_EVIDENCE_KINDS.length,
    recorded: recorded.size,
    missing: [...missing],
    kindsComplete: missing.length === 0 && recorded.size > 0
  };
}

export function pickReleaseEvidenceCustodyUri(evidence: DataItem | null | undefined) {
  if (!evidence || typeof evidence !== 'object') return null;
  const priority = ['evidence_uri', 'review_report_uri', 'remediation_tracker_uri', 'runner_evidence_uri', 'post_apply_check_uri', 'signoff_reference'];
  for (const field of priority) {
    const value = evidence[field];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  for (const [key, value] of Object.entries(evidence)) {
    if (typeof value !== 'string' || !value.trim()) continue;
    const normalized = key.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
    if (normalized.endsWith('_uri') || normalized.endsWith('_reference')) return value.trim();
  }
  return null;
}

export function summarizeReleaseEvidenceValidation(validation: DataItem | null | undefined) {
  if (!validation) return 'No validation summary';
  if (validation.ok === true) return 'Contract valid (metadata-only)';
  const parts: string[] = [];
  const missing = Array.isArray(validation.missing_fields) ? validation.missing_fields : [];
  const forbidden = Array.isArray(validation.forbidden_fields) ? validation.forbidden_fields : [];
  if (missing.length) parts.push(`missing ${missing.length} field(s)`);
  if (forbidden.length) parts.push(`forbidden ${forbidden.length} field(s)`);
  return parts.length ? `Invalid — ${parts.join('; ')}` : 'Invalid';
}