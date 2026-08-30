import { audit } from '../audit.mjs';
import {
  normalizeTargetInput,
  targetDedupeKey,
  targetValidationResponse,
} from '../contracts/targetManagement.mjs';
import { newId } from '../lib/ids.mjs';
import { ownershipProofFromStates, VERIFICATION_RANK } from '../lib/ownershipPolicy.mjs';
import { getStore, persistStore } from '../store.mjs';
import { normalizeSafetyPolicy } from './safeTestPolicy.mjs';

const ACTIVE_RUN_STATUSES = new Set(['planned', 'running', 'collecting']);

/** Detail-page cap on runs / findings, mirrored by the Postgres adapter. */
const TARGET_GROUP_RUNS_RECENT_LIMIT = 6;
export const TARGET_GROUP_FINDINGS_LIMIT = 50;

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function toIso(value) {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function optionalString(...values) {
  for (const value of values) {
    if (value == null) continue;
    const normalized = String(value).trim();
    if (normalized) return normalized;
  }
  return null;
}

function latestTargetVerifications(tenantId) {
  const latestByTarget = new Map();
  for (const row of getStore().targetVerifications ?? []) {
    if (row.tenant_id !== tenantId) continue;
    const previous = latestByTarget.get(row.target_id);
    const rowAt = String(row.transitioned_at ?? '');
    const previousAt = String(previous?.transitioned_at ?? '');
    if (
      !previous
      || rowAt > previousAt
      || (rowAt === previousAt
        && (VERIFICATION_RANK[row.state] ?? 0) > (VERIFICATION_RANK[previous.state] ?? 0))
    ) {
      latestByTarget.set(row.target_id, row);
    }
  }
  return latestByTarget;
}

function targetInventoryItem(target, group, environment, verification) {
  const metadata = asObject(target.metadata ?? target.metadata_json);
  const verificationState = optionalString(verification?.state) ?? 'unverified';
  const sourceKind = optionalString(verification?.source_kind);
  const sourceRef = verification?.source_ref ?? null;
  const transitionedAt = toIso(verification?.transitioned_at);
  const managedProvenance = asObject(metadata.managed_provenance);
  const declaredImport = asObject(metadata.declared_import);
  const importIntegration = optionalString(managedProvenance.connector_id, declaredImport.label);
  const source = managedProvenance.connector_id
    ? 'connector_inventory'
    : declaredImport.label
      ? 'customer_declared_import'
      : 'manual';
  const proof = ownershipProofFromStates({
    groupState: group.ownership_status,
    targetState: verificationState,
  });
  const eligibility = proof.verified ? 'eligible' : 'not_eligible';
  const eligibilityReason = proof.verified ? null : 'verification_required';

  return {
    id: target.id,
    tenant_id: target.tenant_id,
    target_group_id: target.target_group_id,
    target_group_name: group.name,
    environment_id: group.environment_id ?? null,
    environment_name: environment?.name ?? null,
    kind: target.kind,
    value: target.value,
    expected_behavior: target.expected_behavior ?? group.expected_behavior_default ?? null,
    ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
    verification_state: verificationState,
    verification: {
      state: verificationState,
      source_kind: sourceKind,
      source_ref: sourceRef,
      transitioned_at: transitionedAt,
    },
    eligibility,
    eligibility_reason: eligibilityReason,
    source,
    import_source: importIntegration,
    import_integration: importIntegration,
    created_at: toIso(target.created_at),
  };
}

/** Tenant-scoped target inventory used by the Targets page. */
export function listTargets(ctx) {
  const store = getStore();
  const groups = new Map(
    store.targetGroups
      .filter((group) => group.tenant_id === ctx.tenantId && !isArchivedTargetGroup(group))
      .map((group) => [group.id, group]),
  );
  const environments = new Map(
    store.environments
      .filter((environment) => environment.tenant_id === ctx.tenantId)
      .map((environment) => [environment.id, environment]),
  );
  const verifications = latestTargetVerifications(ctx.tenantId);

  return store.targets
    .filter((target) => target.tenant_id === ctx.tenantId && !isArchivedTarget(target) && groups.has(target.target_group_id))
    .map((target) => {
      const group = groups.get(target.target_group_id);
      return targetInventoryItem(
        target,
        group,
        environments.get(group.environment_id),
        verifications.get(target.id),
      );
    })
    .sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? ''))
      || String(a.id).localeCompare(String(b.id)));
}

export function listTargetsEnvelope(ctx) {
  const items = listTargets(ctx);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : 'No targets have been declared for this tenant yet.',
    },
  };
}

export function isArchivedTargetGroup(group) {
  return Boolean(group?.deleted_at ?? group?.archived_at);
}

export function isArchivedTarget(target) {
  return Boolean(target?.deleted_at);
}

export function activeTargetGroupsForTenant(tenantId) {
  return getStore().targetGroups.filter(
    (g) => g.tenant_id === tenantId && !isArchivedTargetGroup(g),
  );
}

function activeRunForGroup(tenantId, targetGroupId) {
  return getStore().testRuns.find(
    (run) =>
      run.tenant_id === tenantId
      && run.target_group_id === targetGroupId
      && ACTIVE_RUN_STATUSES.has(run.status),
  ) ?? null;
}

function activeRunForTarget(tenantId, targetGroupId, targetId) {
  return getStore().testRuns.find(
    (run) =>
      run.tenant_id === tenantId
      && run.target_group_id === targetGroupId
      && run.target_id === targetId
      && ACTIVE_RUN_STATUSES.has(run.status),
  ) ?? null;
}

/** Single-pass tenant joins so the list summary stays O(targets + signatures), not O(groups × rows). */
function targetGroupSummaryJoins(tenantId) {
  const targetCounts = new Map();
  for (const target of getStore().targets) {
    if (target.tenant_id !== tenantId || isArchivedTarget(target)) continue;
    targetCounts.set(target.target_group_id, (targetCounts.get(target.target_group_id) ?? 0) + 1);
  }
  const loaStates = new Map();
  for (const row of getStore().loaSignatures ?? []) {
    if (row.tenant_id !== tenantId || row.state !== 'signed') continue;
    loaStates.set(row.target_group_id, row.state);
  }
  return { targetCounts, loaStates };
}

export function listTargetGroups(ctx, options = {}) {
  const includeArchived = options.archived === true;
  const groups = getStore().targetGroups.filter(
    (g) => g.tenant_id === ctx.tenantId
      && (includeArchived ? isArchivedTargetGroup(g) : !isArchivedTargetGroup(g)),
  );
  const { targetCounts, loaStates } = targetGroupSummaryJoins(ctx.tenantId);
  return groups.map((g) => ({
    ...g,
    target_count: targetCounts.get(g.id) ?? 0,
    loa_state: loaStates.get(g.id) ?? g.loa_state ?? 'required',
  }));
}

export function listTargetGroupsEnvelope(ctx, options = {}) {
  const items = listTargetGroups(ctx, options);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : options.archived
          ? 'No archived target groups match this tenant.'
          : 'No target groups have been declared for this tenant yet.',
    },
  };
}

export function getTargetGroup(ctx, id) {
  const g = getStore().targetGroups.find(
    (x) => x.id === id && x.tenant_id === ctx.tenantId && !isArchivedTargetGroup(x),
  );
  if (!g) return null;
  const verifications = latestTargetVerifications(ctx.tenantId);
  const targets = getStore().targets
    .filter((t) => t.target_group_id === id && t.tenant_id === ctx.tenantId && !isArchivedTarget(t))
    .map((target) => ({
      ...target,
      verification_state: verifications.get(target.id)?.state ?? 'unverified',
    }));
  const runsRecent = (getStore().testRuns ?? [])
    .filter((run) => run.tenant_id === ctx.tenantId && run.target_group_id === id)
    .sort((a, b) => String(b.started_at ?? b.created_at).localeCompare(String(a.started_at ?? a.created_at)))
    .slice(0, TARGET_GROUP_RUNS_RECENT_LIMIT)
    .map((run) => ({
      id: run.id,
      policy_id: run.policy_id ?? run.test_policy_id ?? null,
      check_count: run.check_count ?? run.check_id ?? null,
      verdict: run.verdict ?? run.status ?? 'pending',
      started_at: run.started_at ?? run.created_at,
      agent_id: run.agent_id ?? null,
    }));
  const groupFindings = (getStore().findings ?? []).filter(
    (finding) => finding.tenant_id === ctx.tenantId && finding.target_group_id === id,
  );
  const findingsOnGroupTotal = groupFindings.length;
  const findingsOnGroup = groupFindings
    .slice()
    .sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? ''))
      || String(b.id ?? '').localeCompare(String(a.id ?? '')))
    .slice(0, TARGET_GROUP_FINDINGS_LIMIT)
    .map((finding) => ({
      id: finding.id,
      target_id: finding.target_id ?? null,
      title: finding.title,
      severity: finding.severity,
      status: finding.status ?? finding.state ?? 'open',
    }));
  const loa = (getStore().loaSignatures ?? []).find(
    (row) => row.tenant_id === ctx.tenantId && row.target_group_id === id && row.state === 'signed',
  );
  return {
    ...g,
    targets,
    target_count: targets.length,
    runs_recent: runsRecent,
    findings_on_group: findingsOnGroup,
    findings_on_group_total: findingsOnGroupTotal,
    loa: loa
      ? {
          state: loa.state,
          signer_name: loa.signer_name,
          signed_at: loa.signed_at,
          custody_digest_sha256: loa.custody_digest_sha256,
        }
      : g.loa ?? null,
    loa_state: loa?.state ?? g.loa_state ?? 'required',
    meta: {
      targets_empty_reason: targets.length
        ? null
        : 'No targets have been declared for this group yet.',
      runs_empty_reason: runsRecent.length
        ? null
        : 'No test runs have been recorded for this target group yet.',
      findings_empty_reason: findingsOnGroup.length
        ? null
        : 'No findings are published for this target group yet.',
    },
  };
}

export function createTargetGroup(ctx, body = {}) {
  const environmentId = String(body.environment_id ?? 'env_demo').trim();
  const name = String(body.name ?? 'New target group').trim() || 'New target group';
  const duplicate = getStore().targetGroups.find(
    (group) => group.tenant_id === ctx.tenantId
      && !isArchivedTargetGroup(group)
      && String(group.environment_id ?? '') === environmentId
      && String(group.name).trim().toLowerCase() === name.toLowerCase(),
  );
  if (duplicate) return { error: 'target_group_exists', status: 409, existing_id: duplicate.id };

  const id = newId('tg');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    environment_id: environmentId,
    name,
    description: String(body.description ?? ''),
    expected_behavior_default: body.expected_behavior_default ?? null,
    timezone: String(body.timezone ?? 'UTC').trim() || 'UTC',
    safe_test_windows: Array.isArray(body.safe_test_windows) ? body.safe_test_windows : [],
    safety_policy: normalizeSafetyPolicy(body.safety_policy),
    ownership_status: 'unverified',
    dns_ownership: null,
    validation_mode: body.validation_mode === 'external_only' ? 'external_only' : 'agent_assisted',
    created_at: new Date().toISOString(),
  };
  getStore().targetGroups.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.created',
    resource_type: 'target_group',
    resource_id: id,
    metadata: { changed_fields: ['environment_id', 'name', 'description', 'expected_behavior_default', 'timezone', 'safe_test_windows', 'safety_policy', 'validation_mode'] },
  });
  persistStore();
  return record;
}

export function addTarget(ctx, groupId, body = {}) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === groupId && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;

  let normalized;
  try {
    normalized = normalizeTargetInput(body);
  } catch (error) {
    return targetValidationResponse(error);
  }
  const duplicateKey = `${normalized.kind}\u0000${normalized.normalized_value}`;
  const duplicate = getStore().targets.find(
    (target) => target.tenant_id === ctx.tenantId
      && target.target_group_id === groupId
      && !isArchivedTarget(target)
      && targetDedupeKey(target) === duplicateKey,
  );
  if (duplicate) return { error: 'target_exists', status: 409, existing_id: duplicate.id };

  const id = newId('target');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    target_group_id: groupId,
    kind: normalized.kind,
    value: normalized.value,
    normalized_value: normalized.normalized_value,
    expected_behavior: body.expected_behavior ?? null,
    created_at: new Date().toISOString(),
  };
  if (Object.keys(normalized.metadata).length > 0) record.metadata = normalized.metadata;
  getStore().targets.push(record);
  // A new target has no proof. Reset only the presentation rollup; existing per-target
  // verification rows remain intact and continue to authorize their exact targets.
  group.ownership_status = 'unverified';
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.added',
    resource_type: 'target',
    resource_id: id,
    metadata: {
      target_group_id: groupId,
      changed_fields: ['kind', 'value', 'expected_behavior', ...(Object.keys(normalized.metadata).length ? ['metadata'] : [])],
      dropped_untrusted_fields: normalized.dropped_fields,
    },
  });
  persistStore();
  return record;
}

export function patchTargetGroup(ctx, id, body = {}) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === id && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  const changedFields = [];

  if (body.name !== undefined) {
    const name = String(body.name).trim() || group.name;
    const duplicate = getStore().targetGroups.find(
      (candidate) => candidate.id !== id
        && candidate.tenant_id === ctx.tenantId
        && !isArchivedTargetGroup(candidate)
        && String(candidate.environment_id ?? '') === String(body.environment_id ?? group.environment_id ?? '')
        && String(candidate.name).trim().toLowerCase() === name.toLowerCase(),
    );
    if (duplicate) return { error: 'target_group_exists', status: 409, existing_id: duplicate.id };
    group.name = name;
    changedFields.push('name');
  }
  if (body.description !== undefined) { group.description = String(body.description ?? ''); changedFields.push('description'); }
  if (body.environment_id !== undefined) { group.environment_id = String(body.environment_id).trim(); changedFields.push('environment_id'); }
  if (body.timezone !== undefined) { group.timezone = String(body.timezone).trim() || 'UTC'; changedFields.push('timezone'); }
  if (body.safe_test_windows !== undefined) {
    if (!Array.isArray(body.safe_test_windows)) return { error: 'invalid_target_group', status: 400, field: 'safe_test_windows' };
    group.safe_test_windows = body.safe_test_windows;
    changedFields.push('safe_test_windows');
  }
  if (body.safety_policy !== undefined) { group.safety_policy = normalizeSafetyPolicy(body.safety_policy); changedFields.push('safety_policy'); }
  if (body.validation_mode !== undefined) {
    group.validation_mode = body.validation_mode === 'external_only' ? 'external_only' : 'agent_assisted';
    changedFields.push('validation_mode');
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.updated',
    resource_type: 'target_group',
    resource_id: id,
    metadata: { changed_fields: changedFields },
  });
  persistStore();
  return group;
}

export function archiveTargetGroup(ctx, id) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === id && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  if (activeRunForGroup(ctx.tenantId, id)) return { error: 'target_group_active_run', status: 409 };

  const now = new Date().toISOString();
  group.deleted_at = now;
  group.deleted_by = ctx.userId;
  group.archived_at = now;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.archived',
    resource_type: 'target_group',
    resource_id: id,
    metadata: { changed_fields: ['deleted_at', 'deleted_by', 'archived_at'] },
  });
  persistStore();
  return { archived: true, id, deleted_at: now, deleted_by: ctx.userId };
}

export function patchTarget(ctx, groupId, targetId, body = {}) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === groupId && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  const target = getStore().targets.find(
    (candidate) => candidate.id === targetId
      && candidate.target_group_id === groupId
      && candidate.tenant_id === ctx.tenantId
      && !isArchivedTarget(candidate),
  );
  if (!target) return null;

  let normalized;
  try {
    normalized = normalizeTargetInput(body, { current: target });
  } catch (error) {
    return targetValidationResponse(error);
  }
  const duplicateKey = `${normalized.kind}\u0000${normalized.normalized_value}`;
  if (
    (body.kind !== undefined || body.value !== undefined)
    && duplicateKey !== targetDedupeKey(target)
  ) {
    return {
      error: 'target_identity_immutable',
      status: 409,
      message: 'Target kind and value are immutable; create a new target so ownership must be proven again.',
    };
  }
  const duplicate = getStore().targets.find(
    (candidate) => candidate.id !== targetId
      && candidate.tenant_id === ctx.tenantId
      && candidate.target_group_id === groupId
      && !isArchivedTarget(candidate)
      && targetDedupeKey(candidate) === duplicateKey,
  );
  if (duplicate) return { error: 'target_exists', status: 409, existing_id: duplicate.id };

  const changedFields = [];
  if (body.kind !== undefined || body.value !== undefined) {
    target.kind = normalized.kind;
    target.value = normalized.value;
    target.normalized_value = normalized.normalized_value;
    changedFields.push('kind', 'value');
  }
  if (body.metadata !== undefined || body.metadata_json !== undefined) {
    target.metadata = normalized.metadata;
    changedFields.push('metadata');
  }
  if (body.expected_behavior !== undefined) {
    target.expected_behavior = body.expected_behavior ?? null;
    changedFields.push('expected_behavior');
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.updated',
    resource_type: 'target',
    resource_id: targetId,
    metadata: { target_group_id: groupId, changed_fields: changedFields, dropped_untrusted_fields: normalized.dropped_fields },
  });
  persistStore();
  return target;
}

export function deleteTarget(ctx, groupId, targetId) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === groupId && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  const target = getStore().targets.find(
    (candidate) => candidate.id === targetId
      && candidate.target_group_id === groupId
      && candidate.tenant_id === ctx.tenantId
      && !isArchivedTarget(candidate),
  );
  if (!target) return null;
  if (activeRunForTarget(ctx.tenantId, groupId, targetId)) return { error: 'target_active_run', status: 409 };

  const now = new Date().toISOString();
  target.deleted_at = now;
  target.deleted_by = ctx.userId;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.archived',
    resource_type: 'target',
    resource_id: targetId,
    metadata: { target_group_id: groupId, changed_fields: ['deleted_at', 'deleted_by'] },
  });
  persistStore();
  return { deleted: true, archived: true, id: targetId, deleted_at: now, deleted_by: ctx.userId };
}

/**
 * Restores an archived target group (portal revamp §3.8).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 */
export function restoreArchived(ctx, groupId) {
  const group = getStore().targetGroups.find(
    (g) => g.id === groupId && g.tenant_id === ctx.tenantId,
  );
  if (!group) {
    return { error: 'not_found', status: 404 };
  }
  if (!isArchivedTargetGroup(group)) {
    return { error: 'not_archived', status: 404 };
  }
  const duplicate = getStore().targetGroups.find(
    (candidate) => candidate.id !== groupId
      && candidate.tenant_id === ctx.tenantId
      && !isArchivedTargetGroup(candidate)
      && String(candidate.environment_id ?? '') === String(group.environment_id ?? '')
      && String(candidate.name).trim().toLowerCase() === String(group.name).trim().toLowerCase(),
  );
  if (duplicate) return { error: 'target_group_exists', status: 409, existing_id: duplicate.id };

  delete group.deleted_at;
  delete group.deleted_by;
  delete group.archived_at;

  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.restored',
    resource_type: 'target_group',
    resource_id: groupId,
    metadata: { changed_fields: ['deleted_at', 'deleted_by', 'archived_at'] },
  });
  persistStore();
  return { target_group: group, audit_entry_id: auditEntry.id };
}

/**
 * Bulk import targets from connector inventory (portal revamp §3.5).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 * @param {{ source?: string, items?: unknown[] }} _body
 */
export function bulkImportTargets(ctx, groupId, body = {}) {
  const store = getStore();
  const group = store.targetGroups.find(
    (candidate) => candidate.id === groupId && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const source = String(body.source ?? 'customer').trim() || 'customer';
  const connectorId = String(body.connector_id ?? '').trim() || null;
  const connector = connectorId
    ? (store.wafConnectors ?? []).find((item) => item.id === connectorId && item.tenant_id === ctx.tenantId && !['disabled', 'revoked'].includes(item.status))
    : null;
  if (connectorId && !connector) return { error: 'connector_not_found', status: 404 };

  const rawInventory = connector
    ? (Array.isArray(connector.inventory_items)
      ? connector.inventory_items
      : Array.isArray(connector.inventory_cache?.items) ? connector.inventory_cache.items : [])
    : [];
  const connectorKeys = new Set();
  for (const item of rawInventory) {
    try { connectorKeys.add(targetDedupeKey(item)); } catch { /* ignore malformed connector snapshots */ }
  }

  const items = Array.isArray(body.items) ? body.items : [];
  const imported = [];
  const skipped = [];
  for (const item of items) {
    let normalized;
    try {
      normalized = normalizeTargetInput(item);
    } catch (error) {
      const response = targetValidationResponse(error);
      skipped.push({ value: String(item?.value ?? ''), reason: response.error, field: response.field, message: response.message });
      continue;
    }
    const key = `${normalized.kind}\u0000${normalized.normalized_value}`;
    if (connector && !connectorKeys.has(key)) {
      skipped.push({ value: normalized.value, reason: 'connector_item_not_found' });
      continue;
    }
    const existing = store.targets.find(
      (target) => target.tenant_id === ctx.tenantId
        && target.target_group_id === groupId
        && !isArchivedTarget(target)
        && targetDedupeKey(target) === key,
    );
    if (existing) {
      skipped.push({ value: normalized.value, reason: 'already_imported' });
      continue;
    }

    const verifyState = normalized.kind === 'fqdn' || normalized.kind === 'dns_zone' ? 'pending' : 'awaiting_heartbeat';
    const metadata = {
      ...normalized.metadata,
      ...(connector
        ? { managed_provenance: { kind: 'connector_inventory', connector_id: connector.id, provider: connector.provider ?? null } }
        : { declared_import: { label: source, trusted: false } }),
    };
    const target = {
      id: newId('target'),
      tenant_id: ctx.tenantId,
      target_group_id: groupId,
      kind: normalized.kind,
      value: normalized.value,
      normalized_value: normalized.normalized_value,
      expected_behavior: item.expected_behavior ?? null,
      verify_state: verifyState,
      metadata,
      created_at: new Date().toISOString(),
    };
    store.targets.push(target);
    if (!store.targetVerifications) store.targetVerifications = [];
    const auditEntry = audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'target.bulk_imported',
      resource_type: 'target',
      resource_id: target.id,
      metadata: {
        target_group_id: groupId,
        changed_fields: ['kind', 'value', 'expected_behavior', 'metadata'],
        provenance_trust: connector ? 'connector_inventory' : 'customer_declared',
        connector_id: connector?.id ?? null,
        dropped_untrusted_fields: normalized.dropped_fields,
      },
    });
    store.targetVerifications.push({
      id: newId('tv'),
      tenant_id: ctx.tenantId,
      target_id: target.id,
      state: verifyState === 'pending' ? 'pending' : 'unverified',
      source_kind: connector ? 'connector_inventory' : 'customer_declaration',
      source_ref: connector ? { connector_id: connector.id } : { declared_source: source },
      transitioned_at: target.created_at,
      transitioned_by: ctx.userId ?? 'system',
      audit_entry_id: auditEntry.id,
    });
    imported.push(target);
  }

  if (imported.length) {
    group.ownership_status = 'unverified';
    persistStore();
  }
  return { imported, skipped, count: imported.length };
}
