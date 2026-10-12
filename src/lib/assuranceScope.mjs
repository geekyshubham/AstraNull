import { sha256CanonicalJson } from './custody.mjs';

export const ASSURANCE_SCOPE_VERSION = 'assurance-scope.v3';

function pick(record, fields) {
  return Object.fromEntries(fields.map((field) => [field, record?.[field] ?? null]));
}

/** Server-derived material scope; presentation timestamps, names and tags are not inputs. */
export function deriveAssuranceScope({ target, policy = null, targetGroup = null } = {}) {
  return {
    version: ASSURANCE_SCOPE_VERSION,
    target: {
      id: target?.id ?? null,
      kind: target?.kind ?? null,
      value: target?.value ?? null,
      definition_digest: sha256CanonicalJson(pick(target, ['id', 'kind', 'value', 'protocol', 'port', 'target_group_id', 'expected_behavior', 'declaration_json'])),
    },
    policy: policy ? {
      id: policy.id,
      definition_digest: sha256CanonicalJson(pick(policy, ['id', 'target_id', 'target_group_id', 'check_id', 'expected_behavior', 'probe_profile', 'safety_constraints', 'safety_policy_snapshot', 'schedule_revision', 'expected_verdict', 'enabled', 'state'])),
    } : null,
    target_group: targetGroup ? {
      id: targetGroup.id,
      definition_digest: sha256CanonicalJson(pick(targetGroup, ['id', 'expected_behavior_default', 'declaration_json', 'safety_policy'])),
    } : null,
  };
}

function materialTimestamp(record) {
  return Date.parse(record?.assurance_invalidated_at ?? record?.material_updated_at ?? record?.definition_updated_at ?? record?.updated_at ?? '') || null;
}

/** Current read model only. Never mutates a run, verdict, digest or historical snapshot. */
export function currentAssuranceGap({ run, target, policy = null, targetGroup = null } = {}) {
  if (!run || !target) return 'scope_unknown';
  if (run.target_id && run.target_id !== target.id) return 'target_scope_mismatch';
  if (run.tenant_id && target.tenant_id && run.tenant_id !== target.tenant_id) return 'tenant_scope_mismatch';
  if (run.target_group_id && target.target_group_id && run.target_group_id !== target.target_group_id) return 'target_policy_membership_changed';
  const recorded = run.safety_constraints?.assurance_scope ?? run.provenance_json?.assurance_scope ?? null;
  if (recorded) {
    if (recorded.version !== ASSURANCE_SCOPE_VERSION) return 'assurance_scope_version_mismatch';
    const current = deriveAssuranceScope({ target, policy, targetGroup });
    if (recorded.target?.definition_digest !== current.target.definition_digest) return 'target_definition_changed';
    if (recorded.policy?.id && !policy) return 'policy_unavailable';
    if ((recorded.policy?.definition_digest ?? null) !== (current.policy?.definition_digest ?? null)) return 'policy_definition_changed';
    if (recorded.target_group?.id && !targetGroup) return 'target_group_unavailable';
    if ((recorded.target_group?.definition_digest ?? null) !== (current.target_group?.definition_digest ?? null)) return 'target_group_definition_changed';
    return null;
  }
  // Legacy runs have no material snapshot. A later definition update cannot be assumed compatible.
  const started = Date.parse(run.started_at ?? run.created_at ?? run.completed_at ?? '');
  if (!Number.isFinite(started)) return 'scope_time_unknown';
  for (const [record, reason] of [[target, 'target_definition_changed'], [policy, 'policy_definition_changed'], [targetGroup, 'target_group_definition_changed']]) {
    const changed = materialTimestamp(record);
    if (changed != null && changed > started) return reason;
  }
  return null;
}
