import { audit } from '../audit.mjs';
import {
  normalizeTargetInput,
  targetDedupeKey,
  targetTagsFromRecord,
  targetValidationResponse,
} from '../contracts/targetManagement.mjs';
import {
  DeclarationValidationError,
  mergeStoredDeclaration,
  normalizeDeclarationInput,
  presentGroupDeclaration,
  presentTargetDeclaration,
} from '../lib/targetDeclarations.mjs';
import { newId } from '../lib/ids.mjs';
import {
  DEMO_AUTO_VERIFY_SOURCE_KIND,
  DEMO_AUTO_VERIFY_STATE,
  demoAutoVerifyAuditEntry,
  demoAutoVerifySourceRef,
  isDemoAutoVerifyTenant,
} from '../lib/demoAutoVerify.mjs';
import { csvImportRejected, validateTargetImportRows } from '../lib/targetCsvImport.mjs';
import {
  isCurrentSuccessfulProviderSnapshot,
  isProviderVerifiedDnsEvidence,
} from '../lib/connectorProviders/domainInventory.mjs';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';
import {
  ownershipProofFromStates,
  ownershipSummaryFromTargetStates,
} from '../lib/ownershipPolicy.mjs';
import { getStore, persistStore } from '../store.mjs';
import { normalizeSafetyPolicy } from './safeTestPolicy.mjs';
import { listTargetEdgeDetectionsForGroup } from './targetEdgeDetectionStore.mjs';
import { presentTargetEdgeDetection } from '../lib/edgeDetectionPresenter.mjs';
import { presentDeclaredTargetObservation } from './declaredHostAnalytics.mjs';
import { findingRowStatus } from '../lib/findingList.mjs';

const ACTIVE_RUN_STATUSES = new Set(['planned', 'running', 'collecting']);

/**
 * The group list counter counts the exact canonical open state only: the
 * effective lifecycle status (`status`, then legacy `state`, then the open
 * fallback) must be exactly `open` after trimming and lowercasing, matching the
 * portal `isFindingOpen` contract. `in_progress` belongs to the UI "Active"
 * bucket, not to the `Open findings` count, and closure statuses never count.
 * The group link and its `status=open` findings filter must agree with it.
 */
export function isGroupOpenFinding(finding) {
  return findingRowStatus(finding) === 'open';
}

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

function declarationPatchFromBody(body) {
  if (body?.declaration === undefined) return { patch: null, error: null };
  try {
    return { patch: normalizeDeclarationInput(body.declaration), error: null };
  } catch (error) {
    if (error instanceof DeclarationValidationError) return { patch: null, error: error.toResponse() };
    throw error;
  }
}

function applyStoredDeclaration(record, patch, changedFields) {
  if (!patch || Object.keys(patch).length === 0) return false;
  record.declaration_json = mergeStoredDeclaration(record.declaration_json, patch);
  changedFields.push('declaration');
  return true;
}

/** Copy for clients. Stored `declaration_json` stays on the record so a later patch can inherit. */
function presentTarget(target, group = null) {
  if (!target || target.error) return target;
  const { declaration_json, ...rest } = target;
  return {
    ...rest,
    tags: targetTagsFromRecord(target),
    declaration: presentTargetDeclaration(declaration_json, group?.declaration_json),
  };
}

function presentGroup(group) {
  if (!group || group.error) return group;
  const { declaration_json, ...rest } = group;
  return { ...rest, declaration: presentGroupDeclaration(declaration_json) };
}

function latestTargetVerifications(tenantId) {
  return effectiveTargetVerifications(getStore(), tenantId);
}

function targetInventoryItem(target, group, verification) {
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
  const eligibility = 'eligible';
  const eligibilityReason = null;

  return {
    id: target.id,
    tenant_id: target.tenant_id,
    target_group_id: target.target_group_id,
    target_group_name: group.name,
    kind: target.kind,
    value: target.value,
    expected_behavior: target.expected_behavior ?? group.expected_behavior_default ?? null,
    tags: targetTagsFromRecord(target),
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
    declaration: presentTargetDeclaration(target.declaration_json, group?.declaration_json),
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
  const verifications = latestTargetVerifications(ctx.tenantId);

  return store.targets
    .filter((target) => target.tenant_id === ctx.tenantId && !isArchivedTarget(target) && groups.has(target.target_group_id))
    .map((target) => {
      const group = groups.get(target.target_group_id);
      return targetInventoryItem(
        target,
        group,
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

/** One active target for read-only projections. Missing verification stays null. */
export function getTarget(ctx, id) {
  if (!id) return null;
  const store = getStore();
  const target = store.targets.find(
    (row) => row.id === id && row.tenant_id === ctx.tenantId && !isArchivedTarget(row),
  );
  if (!target) return null;
  const group = store.targetGroups.find(
    (row) => row.id === target.target_group_id && row.tenant_id === ctx.tenantId && !isArchivedTargetGroup(row),
  );
  if (!group) return null;
  return {
    id: target.id,
    tenant_id: target.tenant_id,
    target_group_id: target.target_group_id,
    kind: target.kind,
    value: target.value,
    declaration: presentTargetDeclaration(target.declaration_json, group.declaration_json),
  };
}

/**
 * Active declared rows for the shared analytics predicate.
 * Does not copy metadata or call getTargetDetail. Open findings of zero are a known zero.
 *
 * @param {{ tenantId: string }} ctx
 * @param {{ asOf?: unknown }} [options]
 */
function edgeCloudFamily(edge) {
  if (!edge) return null;
  const legacy = edge.evidence_json?.cloud;
  const status = typeof edge.cloud_status === 'string' ? edge.cloud_status : legacy?.status;
  if (typeof status !== 'string') return null;
  const provider = typeof edge.cloud_provider === 'string' ? edge.cloud_provider : legacy?.provider;
  return { status, provider: status === 'detected' && provider ? provider : null };
}

export function listDeclaredAnalyticsRows(ctx, options = {}) {
  const store = getStore();
  const groups = new Map(
    store.targetGroups
      .filter((group) => group.tenant_id === ctx.tenantId && !isArchivedTargetGroup(group))
      .map((group) => [group.id, group]),
  );
  const verifications = latestTargetVerifications(ctx.tenantId);
  const edges = new Map();
  for (const row of store.targetEdgeDetections ?? []) {
    if (row.tenant_id === ctx.tenantId && row.target_id) edges.set(row.target_id, row);
  }
  const openFindings = new Map();
  for (const finding of store.findings ?? []) {
    if (finding.tenant_id !== ctx.tenantId || !finding.target_id) continue;
    if (finding.status !== 'open' && finding.state !== 'open') continue;
    openFindings.set(finding.target_id, (openFindings.get(finding.target_id) ?? 0) + 1);
  }
  const lastValidation = new Map();
  for (const run of store.testRuns ?? []) {
    if (run.tenant_id !== ctx.tenantId || !run.target_id || !run.completed_at) continue;
    const iso = toIso(run.completed_at);
    const previous = lastValidation.get(run.target_id);
    if (iso && (!previous || iso > previous)) lastValidation.set(run.target_id, iso);
  }
  return store.targets
    .filter((target) => target.tenant_id === ctx.tenantId && !isArchivedTarget(target) && groups.has(target.target_group_id))
    .map((target) => {
      const group = groups.get(target.target_group_id);
      const edge = edges.get(target.id) ?? null;
      const raw = {
        id: target.id,
        tenant_id: target.tenant_id,
        target_group_id: target.target_group_id,
        kind: target.kind,
        value: target.value,
        edge_id: edge?.id ?? null,
        waf_status: edge?.waf_status ?? null,
        cdn_status: edge?.cdn_status ?? null,
        waf_vendor: edge?.waf_vendor ?? null,
        cdn_provider: edge?.cdn_provider ?? null,
        conflicting_vendor_signals: edge?.conflicting_vendor_signals === true,
        edge_observed_at: edge?.observed_at ?? null,
      };
      return {
        id: target.id,
        tenant_id: target.tenant_id,
        target_group_id: target.target_group_id,
        target_group_name: group.name,
        kind: target.kind,
        value: target.value,
        normalized_value: target.normalized_value ?? null,
        tags: targetTagsFromRecord(target),
        verification_state: verifications.get(target.id)?.state ?? null,
        declaration: presentTargetDeclaration(target.declaration_json, group.declaration_json),
        protection_profile: presentDeclaredTargetObservation(raw, { now: options.asOf ?? null }),
        edge_cloud: edgeCloudFamily(edge),
        findings_count: openFindings.get(target.id) ?? 0,
        last_validation_at: lastValidation.get(target.id) ?? null,
        created_at: toIso(target.created_at),
      };
    });
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
  // One pass over the tenant's findings with the shared findings-list predicate
  // (stored group OR active same-tenant target membership). Each finding contributes
  // once per distinct matching group, never a pass per group.
  const targetGroupByTargetId = new Map(
    getStore().targets
      .filter((target) => target.tenant_id === tenantId && !isArchivedTarget(target) && target.target_group_id)
      .map((target) => [target.id, target.target_group_id]),
  );
  const openCounts = new Map();
  for (const finding of getStore().findings ?? []) {
    if (finding.tenant_id !== tenantId || !isGroupOpenFinding(finding)) continue;
    const matchGroups = new Set();
    if (finding.target_group_id) matchGroups.add(finding.target_group_id);
    const memberGroup = finding.target_id ? targetGroupByTargetId.get(finding.target_id) : null;
    if (memberGroup) matchGroups.add(memberGroup);
    for (const groupId of matchGroups) {
      openCounts.set(groupId, (openCounts.get(groupId) ?? 0) + 1);
    }
  }
  return { targetCounts, loaStates, openCounts };
}

export function listTargetGroups(ctx, options = {}) {
  const includeArchived = options.archived === true;
  const groups = getStore().targetGroups.filter(
    (g) => g.tenant_id === ctx.tenantId
      && (includeArchived ? isArchivedTargetGroup(g) : !isArchivedTargetGroup(g)),
  );
  const { targetCounts, loaStates, openCounts } = targetGroupSummaryJoins(ctx.tenantId);
  return groups.map((g) => ({
    ...presentGroup(g),
    target_count: targetCounts.get(g.id) ?? 0,
    loa_state: loaStates.get(g.id) ?? g.loa_state ?? 'required',
    // Authoritative whole-tenant count for the portal list. Always a number: a zero here
    // was actually counted over every tenant finding, never derived from a capped page.
    open_findings_count: openCounts.get(g.id) ?? 0,
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
  const edgeDetections = listTargetEdgeDetectionsForGroup(ctx.tenantId, id);
  const targets = getStore().targets
    .filter((t) => t.target_group_id === id && t.tenant_id === ctx.tenantId && !isArchivedTarget(t))
    .map((target) => ({
      ...presentTarget(target, g),
      verification_state: verifications.get(target.id)?.state ?? 'unverified',
      edge_detection: presentTargetEdgeDetection(edgeDetections[target.id] ?? null),
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
    ...presentGroup(g),
    ownership_status: ownershipSummaryFromTargetStates(targets.map((target) => target.verification_state)),
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
  const declared = declarationPatchFromBody(body);
  if (declared.error) return declared.error;
  const name = String(body.name ?? 'New target group').trim() || 'New target group';
  // ADR-0008: groups are tenant-scoped now that environments are gone; the uniqueness check
  // is tenant-wide instead of per-environment.
  const duplicate = getStore().targetGroups.find(
    (group) => group.tenant_id === ctx.tenantId
      && !isArchivedTargetGroup(group)
      && String(group.name).trim().toLowerCase() === name.toLowerCase(),
  );
  if (duplicate) return { error: 'target_group_exists', status: 409, existing_id: duplicate.id };

  const id = newId('tg');
  const settings = body.settings_json && typeof body.settings_json === 'object' ? { ...body.settings_json } : {};
  const record = {
    id,
    tenant_id: ctx.tenantId,
    environment_id: null,
    name,
    description: String(body.description ?? ''),
    expected_behavior_default: body.expected_behavior_default ?? null,
    timezone: String(body.timezone ?? 'UTC').trim() || 'UTC',
    safe_test_windows: Array.isArray(body.safe_test_windows) ? body.safe_test_windows : [],
    safety_policy: normalizeSafetyPolicy(body.safety_policy),
    ownership_status: 'unverified',
    dns_ownership: null,
    validation_mode: 'external_only',
    ...(Object.keys(settings).length > 0 ? { settings_json: settings } : {}),
    created_at: new Date().toISOString(),
  };
  const declarationFields = [];
  applyStoredDeclaration(record, declared.patch, declarationFields);
  getStore().targetGroups.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.created',
    resource_type: 'target_group',
    resource_id: id,
    metadata: { changed_fields: ['name', 'description', 'expected_behavior_default', 'timezone', 'safe_test_windows', 'safety_policy', 'validation_mode'] },
  });
  if (declarationFields.includes('declaration')) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'target_group.declaration_updated',
      resource_type: 'target_group',
      resource_id: id,
      metadata: { changed_fields: declarationFields },
    });
  }
  persistStore();
  return presentGroup(record);
}

function recordDemoAutoVerification(ctx, target) {
  if (!isDemoAutoVerifyTenant(ctx.tenantId)) return;
  const store = getStore();
  if (!store.targetVerifications) store.targetVerifications = [];
  const auditEntry = audit(demoAutoVerifyAuditEntry(ctx, { targetId: target.id, targetGroupId: target.target_group_id }));
  store.targetVerifications.push({
    id: newId('tv'),
    tenant_id: ctx.tenantId,
    target_id: target.id,
    state: DEMO_AUTO_VERIFY_STATE,
    source_kind: DEMO_AUTO_VERIFY_SOURCE_KIND,
    source_ref: demoAutoVerifySourceRef(),
    transitioned_at: new Date().toISOString(),
    transitioned_by: ctx.userId ?? 'system',
    audit_entry_id: auditEntry.id,
  });
}

/** Record demo verification for active targets of an allowlisted tenant that lack proof. */
export function backfillDemoAutoVerifications(ctx) {
  if (!isDemoAutoVerifyTenant(ctx.tenantId)) return { error: 'demo_auto_verify_not_enabled', status: 409 };
  const latest = latestTargetVerifications(ctx.tenantId);
  const pending = getStore().targets.filter((target) => target.tenant_id === ctx.tenantId
    && !isArchivedTarget(target)
    && !ownershipProofFromStates({ targetState: latest.get(target.id)?.state }).verified);
  for (const target of pending) recordDemoAutoVerification(ctx, target);
  if (pending.length) persistStore();
  return { verified_count: pending.length, target_ids: pending.map((target) => target.id) };
}

export function addTarget(ctx, groupId, body = {}) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === groupId && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  const declared = declarationPatchFromBody(body);
  if (declared.error) return declared.error;

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
  const declarationFields = [];
  applyStoredDeclaration(record, declared.patch, declarationFields);
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
      changed_fields: ['kind', 'value', 'expected_behavior', ...(normalized.tags.length ? ['tags'] : []), ...(Object.keys(normalized.metadata).length ? ['metadata'] : [])],
      dropped_untrusted_fields: normalized.dropped_fields,
    },
  });
  if (declarationFields.includes('declaration')) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'target.declaration_updated',
      resource_type: 'target',
      resource_id: id,
      metadata: { target_group_id: groupId, changed_fields: declarationFields },
    });
  }
  recordDemoAutoVerification(ctx, record);
  persistStore();
  return presentTarget(record, group);
}

export function importTargets(ctx, groupId, rows = []) {
  const store = getStore();
  const group = store.targetGroups.find(
    (candidate) => candidate.id === groupId && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  const existingKeys = new Set(
    store.targets
      .filter((target) => target.tenant_id === ctx.tenantId && target.target_group_id === groupId && !isArchivedTarget(target))
      .map((target) => targetDedupeKey(target)),
  );
  const { accepted, errors } = validateTargetImportRows(rows, existingKeys);
  if (errors.length) return csvImportRejected(errors);

  const now = new Date().toISOString();
  const created = accepted.map(({ row, normalized, expected_behavior: expectedBehavior }) => {
    const record = {
      id: newId('target'),
      tenant_id: ctx.tenantId,
      target_group_id: groupId,
      kind: normalized.kind,
      value: normalized.value,
      normalized_value: normalized.normalized_value,
      expected_behavior: expectedBehavior ?? null,
      created_at: now,
    };
    store.targets.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'target.added',
      resource_type: 'target',
      resource_id: record.id,
      metadata: { target_group_id: groupId, changed_fields: ['kind', 'value', 'expected_behavior'], import_source: 'csv', csv_row: row },
    });
    recordDemoAutoVerification(ctx, record);
    return record;
  });
  group.ownership_status = 'unverified';
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.csv_imported',
    resource_type: 'target_group',
    resource_id: groupId,
    metadata: { created_count: created.length, target_ids: created.map((target) => target.id) },
  });
  persistStore();
  return { created, errors: [] };
}

export function patchTargetGroup(ctx, id, body = {}) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === id && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  const declared = declarationPatchFromBody(body);
  if (declared.error) return declared.error;
  const changedFields = [];

  if (body.name !== undefined) {
    const name = String(body.name).trim() || group.name;
    const duplicate = getStore().targetGroups.find(
      (candidate) => candidate.id !== id
        && candidate.tenant_id === ctx.tenantId
        && !isArchivedTargetGroup(candidate)
        && String(candidate.name).trim().toLowerCase() === name.toLowerCase(),
    );
    if (duplicate) return { error: 'target_group_exists', status: 409, existing_id: duplicate.id };
    group.name = name;
    changedFields.push('name');
  }
  if (body.description !== undefined) { group.description = String(body.description ?? ''); changedFields.push('description'); }
  if (body.timezone !== undefined) { group.timezone = String(body.timezone).trim() || 'UTC'; changedFields.push('timezone'); }
  if (body.safe_test_windows !== undefined) {
    if (!Array.isArray(body.safe_test_windows)) return { error: 'invalid_target_group', status: 400, field: 'safe_test_windows' };
    group.safe_test_windows = body.safe_test_windows;
    changedFields.push('safe_test_windows');
  }
  if (body.safety_policy !== undefined) { group.safety_policy = normalizeSafetyPolicy(body.safety_policy); changedFields.push('safety_policy'); }
  if (body.validation_mode !== undefined) {
    // ADR-0008: every group is external_only; the field stays for compatibility but is fixed.
    group.validation_mode = 'external_only';
    changedFields.push('validation_mode');
  }
  applyStoredDeclaration(group, declared.patch, changedFields);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.updated',
    resource_type: 'target_group',
    resource_id: id,
    metadata: { changed_fields: changedFields },
  });
  if (changedFields.includes('declaration')) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'target_group.declaration_updated',
      resource_type: 'target_group',
      resource_id: id,
      metadata: { changed_fields: ['declaration'] },
    });
  }
  persistStore();
  return presentGroup(group);
}

export function archiveTargetGroup(ctx, id) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === id && candidate.tenant_id === ctx.tenantId && !isArchivedTargetGroup(candidate),
  );
  if (!group) return null;
  if (activeRunForGroup(ctx.tenantId, id)) return { error: 'target_group_active_run', status: 409 };

  const now = new Date().toISOString();
  const pausedPolicyIds = [];
  for (const policy of getStore().testPolicies ?? []) {
    if (policy.tenant_id !== ctx.tenantId
      || policy.target_group_id !== id
      || policy.archived_at) continue;
    policy.state = 'paused';
    policy.enabled = false;
    policy.next_run_at = null;
    policy.lease_token = null;
    policy.lease_owner = null;
    policy.lease_expires_at = null;
    policy.schedule_revision = Number(policy.schedule_revision ?? 0) + 1;
    policy.updated_at = now;
    pausedPolicyIds.push(policy.id);
  }
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
    metadata: {
      changed_fields: ['deleted_at', 'deleted_by', 'archived_at'],
      paused_policy_ids: pausedPolicyIds,
    },
  });
  persistStore();
  return {
    archived: true,
    id,
    deleted_at: now,
    deleted_by: ctx.userId,
    paused_policy_count: pausedPolicyIds.length,
  };
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
  const declared = declarationPatchFromBody(body);
  if (declared.error) return declared.error;

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
  // Tags live inside metadata; normalizeTargetInput has already merged the resolved tag list
  // into normalized.metadata, so persist it whenever metadata OR tags were touched.
  if (body.tags !== undefined) changedFields.push('tags');
  if (body.metadata !== undefined || body.metadata_json !== undefined) changedFields.push('metadata');
  if (body.metadata !== undefined || body.metadata_json !== undefined || body.tags !== undefined) {
    if (Object.keys(normalized.metadata).length > 0) target.metadata = normalized.metadata;
    else delete target.metadata;
  }
  if (body.expected_behavior !== undefined) {
    target.expected_behavior = body.expected_behavior ?? null;
    changedFields.push('expected_behavior');
  }
  applyStoredDeclaration(target, declared.patch, changedFields);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.updated',
    resource_type: 'target',
    resource_id: targetId,
    metadata: { target_group_id: groupId, changed_fields: changedFields, dropped_untrusted_fields: normalized.dropped_fields },
  });
  if (changedFields.includes('declaration')) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'target.declaration_updated',
      resource_type: 'target',
      resource_id: targetId,
      metadata: { target_group_id: groupId, changed_fields: ['declaration'] },
    });
  }
  persistStore();
  return presentTarget(target, group);
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
  const pausedPolicyIds = [];
  for (const policy of getStore().testPolicies ?? []) {
    if (policy.tenant_id !== ctx.tenantId
      || policy.target_group_id !== groupId
      || policy.target_id !== targetId
      || policy.archived_at) continue;
    policy.state = 'paused';
    policy.enabled = false;
    policy.next_run_at = null;
    policy.lease_token = null;
    policy.lease_owner = null;
    policy.lease_expires_at = null;
    policy.schedule_revision = Number(policy.schedule_revision ?? 0) + 1;
    policy.updated_at = now;
    pausedPolicyIds.push(policy.id);
  }
  target.deleted_at = now;
  target.deleted_by = ctx.userId;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.archived',
    resource_type: 'target',
    resource_id: targetId,
    metadata: {
      target_group_id: groupId,
      changed_fields: ['deleted_at', 'deleted_by'],
      paused_policy_ids: pausedPolicyIds,
    },
  });
  persistStore();
  return {
    deleted: true,
    archived: true,
    id: targetId,
    deleted_at: now,
    deleted_by: ctx.userId,
    paused_policy_count: pausedPolicyIds.length,
  };
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

  const connectorEvidence = new Map();
  if (connector) {
    const evidenceRanks = new Map();
    const rememberEvidence = (normalized, evidence, rank) => {
      const key = targetDedupeKey(normalized);
      if ((evidenceRanks.get(key) ?? -1) >= rank) return;
      evidenceRanks.set(key, rank);
      connectorEvidence.set(key, {
        kind: normalized.kind,
        value: normalized.value,
        ...evidence,
      });
    };

    const rawInventory = Array.isArray(connector.inventory_items)
      ? connector.inventory_items
      : Array.isArray(connector.inventory_cache?.items) ? connector.inventory_cache.items : [];
    for (const item of rawInventory) {
      if (item?.importable === false) continue;
      try {
        const normalized = normalizeTargetInput(item);
        rememberEvidence(normalized, {
          provider: connector.provider ?? null,
          snapshot_kind: null,
          snapshot_id: null,
          resource_ref: null,
          observed_at: null,
          poll_generation: null,
          evidence_source: 'manual_metadata',
          candidate_source: 'legacy_inventory',
          inventory_complete: false,
          inventory_truncated: false,
        }, 0);
      } catch { /* ignore malformed connector inventory */ }
    }

    const snapshots = (store.wafConnectorSnapshots ?? [])
      .filter((snapshot) => snapshot.tenant_id === ctx.tenantId && snapshot.connector_id === connector.id)
      .sort((left, right) => String(right.observed_at).localeCompare(String(left.observed_at)));
    for (const snapshot of snapshots) {
      const currentSuccessfulPoll = isCurrentSuccessfulProviderSnapshot(connector, snapshot);
      if (snapshot.evidence_source === 'provider_api' && !currentSuccessfulPoll) continue;

      const summary = asObject(snapshot.summary_json ?? snapshot.summary);
      const hostnames = Array.isArray(summary.hostnames) ? summary.hostnames : [];
      const direct = Array.isArray(summary.items)
        ? summary.items
        : Array.isArray(summary.inventory_items) ? summary.inventory_items : [];
      const candidateSource = hostnames.length || direct.length ? 'snapshot_inventory' : 'display_ref';
      const candidates = hostnames.length
        ? hostnames.map((value) => ({ kind: 'fqdn', value }))
        : direct.length
          ? direct
          : snapshot.display_ref
            ? [{ kind: 'fqdn', value: snapshot.display_ref }]
            : [];
      for (const candidate of candidates) {
        if (candidate?.importable === false) continue;
        try {
          const normalized = normalizeTargetInput(candidate);
          rememberEvidence(normalized, {
            provider: snapshot.provider ?? connector.provider ?? null,
            snapshot_kind: snapshot.snapshot_kind ?? null,
            snapshot_id: snapshot.id ?? null,
            resource_ref: snapshot.resource_ref_hash ?? null,
            observed_at: snapshot.observed_at ?? null,
            poll_generation: currentSuccessfulPoll ? connector.last_success_at : null,
            poll_revision: snapshot.poll_revision ?? 0,
            evidence_source: snapshot.evidence_source ?? 'manual_metadata',
            candidate_source: candidateSource,
            current_successful_poll: currentSuccessfulPoll,
            inventory_complete: snapshot.inventory_complete === true,
            inventory_truncated: snapshot.inventory_truncated === true,
          }, currentSuccessfulPoll ? 2 : 1);
        } catch { /* ignore malformed provider snapshots */ }
      }
    }
  }
  const connectorKeys = new Set(connectorEvidence.keys());

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
    const itemEvidence = connector ? connectorEvidence.get(key) : null;
    const providerVerified = isProviderVerifiedDnsEvidence(connector, itemEvidence);
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

    const verifyState = providerVerified
      ? 'provider_verified'
      : normalized.kind === 'fqdn' || normalized.kind === 'dns_zone' ? 'pending' : 'awaiting_heartbeat';
    const metadata = {
      ...normalized.metadata,
      ...(connector
        ? {
            managed_provenance: {
              kind: providerVerified ? 'provider_account' : 'connector_inventory',
              connector_id: connector.id,
              provider: itemEvidence?.provider ?? connector.provider ?? null,
              snapshot_kind: itemEvidence?.snapshot_kind ?? null,
              snapshot_id: itemEvidence?.snapshot_id ?? null,
              resource_ref_hash: itemEvidence?.resource_ref ?? null,
              observed_at: itemEvidence?.observed_at ?? null,
              poll_generation: itemEvidence?.poll_generation ?? null,
              evidence_source: itemEvidence?.evidence_source ?? 'manual_metadata',
              candidate_source: itemEvidence?.candidate_source ?? null,
              inventory_complete: itemEvidence?.inventory_complete === true,
              inventory_truncated: itemEvidence?.inventory_truncated === true,
            },
          }
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
        provenance_trust: providerVerified ? 'provider_account' : connector ? 'connector_inventory' : 'customer_declared',
        connector_id: connector?.id ?? null,
        snapshot_id: providerVerified ? itemEvidence.snapshot_id : null,
        provider: providerVerified ? itemEvidence.provider : null,
        snapshot_kind: providerVerified ? itemEvidence.snapshot_kind : null,
        poll_generation: providerVerified ? itemEvidence.poll_generation : null,
        resource_ref_hash: providerVerified ? itemEvidence.resource_ref : null,
        dropped_untrusted_fields: normalized.dropped_fields,
      },
    });
    store.targetVerifications.push({
      id: newId('tv'),
      tenant_id: ctx.tenantId,
      target_id: target.id,
      state: verifyState === 'provider_verified' ? 'provider_verified' : verifyState === 'pending' ? 'pending' : 'unverified',
      source_kind: providerVerified ? 'provider_account' : connector ? 'connector_inventory' : 'customer_declaration',
      source_ref: providerVerified
        ? {
            connector_id: connector.id,
            provider: itemEvidence.provider,
            snapshot_kind: itemEvidence.snapshot_kind,
            evidence_source: itemEvidence.evidence_source,
            resource_ref_hash: itemEvidence.resource_ref,
            snapshot_id: itemEvidence.snapshot_id,
            observed_at: itemEvidence.observed_at,
            poll_generation: itemEvidence.poll_generation,
          }
        : connector ? { connector_id: connector.id } : { declared_source: source },
      transitioned_at: target.created_at,
      transitioned_by: ctx.userId ?? 'system',
      audit_entry_id: auditEntry.id,
    });
    recordDemoAutoVerification(ctx, target);
    imported.push(target);
  }

  if (imported.length) {
    const activeTargets = store.targets.filter(
      (target) => target.tenant_id === ctx.tenantId && target.target_group_id === groupId && !target.deleted_at,
    );
    const latest = latestTargetVerifications(ctx.tenantId);
    group.ownership_status = ownershipSummaryFromTargetStates(
      activeTargets.map((target) => latest.get(target.id)?.state ?? 'unverified'),
    );
    persistStore();
  }
  return { imported, skipped, count: imported.length };
}

/**
 * Resolve (or lazily create) the tenant's default target group for direct target creation
 * (ADR-0008 §3). The default group is the active group whose `settings_json.default_scope`
 * is `true`; if none exists it is created on demand as an external-only "Default" group.
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {{ expected_behavior_default?: string|null }} [options]
 */
function resolveDefaultTargetGroup(ctx, options = {}) {
  const existing = getStore().targetGroups.find(
    (group) => group.tenant_id === ctx.tenantId
      && !isArchivedTargetGroup(group)
      && group.settings_json?.default_scope === true,
  );
  if (existing) return existing;

  const id = newId('tg');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    environment_id: null,
    name: 'Default',
    description: 'Default target group for directly declared targets.',
    expected_behavior_default: options.expected_behavior_default ?? 'block_at_edge',
    timezone: 'UTC',
    safe_test_windows: [],
    safety_policy: normalizeSafetyPolicy(undefined),
    ownership_status: 'unverified',
    dns_ownership: null,
    validation_mode: 'external_only',
    settings_json: { default_scope: true },
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
    metadata: { changed_fields: ['name', 'validation_mode', 'settings_json'], default_scope: true },
  });
  return record;
}

/**
 * Direct target creation (ADR-0008 `POST /v1/targets`). Omitted `target_group_id` lands the
 * target in the tenant default group, created on demand.
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {{ kind?: string, value?: string, expected_behavior?: string, tags?: string[], target_group_id?: string }} body
 */
export function createTargetDirect(ctx, body = {}) {
  const explicitGroupId = optionalString(body.target_group_id);
  let group;
  if (explicitGroupId) {
    group = getStore().targetGroups.find(
      (candidate) => candidate.id === explicitGroupId
        && candidate.tenant_id === ctx.tenantId
        && !isArchivedTargetGroup(candidate),
    );
    if (!group) return { error: 'target_group_not_found', status: 404 };
  } else {
    group = resolveDefaultTargetGroup(ctx, { expected_behavior_default: body.expected_behavior });
  }
  return addTarget(ctx, group.id, body);
}

/**
 * Direct target patch by id (ADR-0008 `PATCH /v1/targets/:id`).
 * Body `{ tags?, expected_behavior?, declaration? }`. Kind and value stay immutable.
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} targetId
 * @param {{ tags?: string[], expected_behavior?: string, declaration?: object }} body
 */
export function patchTargetById(ctx, targetId, body = {}) {
  const target = getStore().targets.find(
    (candidate) => candidate.id === targetId
      && candidate.tenant_id === ctx.tenantId
      && !isArchivedTarget(candidate),
  );
  if (!target) return { error: 'not_found', status: 404 };
  // Route through the group-scoped patch so audit, dedupe, and immutability rules stay shared.
  // Kind and value are forwarded so a change is rejected instead of dropped.
  return patchTarget(ctx, target.target_group_id, targetId, {
    ...(body.tags !== undefined ? { tags: body.tags } : {}),
    ...(body.expected_behavior !== undefined ? { expected_behavior: body.expected_behavior } : {}),
    ...(body.declaration !== undefined ? { declaration: body.declaration } : {}),
    ...(body.metadata !== undefined ? { metadata: body.metadata } : {}),
    ...(body.metadata_json !== undefined ? { metadata_json: body.metadata_json } : {}),
    ...(body.kind !== undefined ? { kind: body.kind } : {}),
    ...(body.value !== undefined ? { value: body.value } : {}),
  });
}
