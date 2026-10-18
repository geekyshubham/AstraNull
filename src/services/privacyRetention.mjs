import { buildAuditRecord } from '../audit.mjs';
import { normalizePrivacySettings } from '../lib/privacySettings.mjs';
import { requirePermission } from '../rbac.mjs';
import { advanceTenantLifecycleGeneration, commitDevStoreChanges, getStore } from '../store.mjs';

export const PROTECTED_GOVERNANCE_COLLECTIONS = [
  'auditLog', 'highScaleRequests', 'highScaleAuthorizationArtifacts', 'socNotes', 'socReports', 'findings', 'testRuns',
];
export const ORIGIN_CLUE_EXPIRED_RESPONSE = Object.freeze({ error: 'origin_clue_response_expired', expired: true });
export const emptyOriginClueCounts = () => ({ originClues: 0, originClueBatches: 0, originClueResponses: 0 });
export const totalRetentionCounts = (counts) => Object.values(counts).reduce((sum, count) => sum + Number(count ?? 0), 0);

export function getEffectiveReportRetentionDays(privacy) {
  return Math.max(privacy.metadata_retention_days, privacy.evidence_retention.report_days);
}
export function buildMetadataRetentionCutoffs(privacy, now = new Date()) {
  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  const reportRetentionDays = getEffectiveReportRetentionDays(privacy);
  return { metadataCutoffMs: nowMs - privacy.metadata_retention_days * 86400000,
    reportRetentionDays, reportCutoffMs: nowMs - reportRetentionDays * 86400000 };
}
function expired(value, cutoff) {
  if (value == null || value === '') return false;
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) && timestamp < cutoff;
}
function purge(items = [], tenantId, field, cutoff) {
  const kept = items.filter((item) => item.tenant_id !== tenantId || !expired(item[field], cutoff));
  return { kept, removed: items.length - kept.length };
}

/** Source time is not retention time. Newer replay responses must not extend an old clue's life. */
export function planOriginClueLifecycle(store, tenantId, { cutoffMs, erase = false }) {
  const clues = store.originClues ?? [];
  const batches = store.originClueBatches ?? [];
  const removedClues = clues.filter((item) => item.tenant_id === tenantId && (erase || expired(item.retrieved_at, cutoffMs)));
  const removedIds = new Set(removedClues.map((item) => item.id));
  const keptClues = clues.filter((item) => item.tenant_id !== tenantId || !removedIds.has(item.id));
  const counts = { ...emptyOriginClueCounts(), originClues: removedClues.length };
  const keptBatches = [];
  for (const batch of batches) {
    if (batch.tenant_id !== tenantId) { keptBatches.push(batch); continue; }
    const old = expired(batch.created_at, cutoffMs);
    const hasChildren = keptClues.some((clue) => clue.tenant_id === tenantId && clue.target_id === batch.target_id && clue.batch_id === batch.id);
    if (erase || (old && !hasChildren)) { counts.originClueBatches += 1; continue; }
    const hasExpiredCopy = (batch.response?.items ?? []).some((item) => removedIds.has(item.id) || expired(item.retrieved_at, cutoffMs));
    if ((old || hasExpiredCopy) && !batch.response?.expired) {
      counts.originClueResponses += 1;
      keptBatches.push({ ...batch, response: { ...ORIGIN_CLUE_EXPIRED_RESPONSE } });
    } else keptBatches.push(batch);
  }
  return { counts, originClues: keptClues, originClueBatches: keptBatches };
}

export function buildRetentionPolicySnapshot(tenant) {
  const privacy = normalizePrivacySettings(tenant.privacy_settings ?? {});
  return { tenant_id: tenant.id, metadata_retention_days: privacy.metadata_retention_days,
    evidence_retention: { ...privacy.evidence_retention }, protected_collections: [...PROTECTED_GOVERNANCE_COLLECTIONS],
    deletion_collections: ['events', 'evidenceVault', 'reports', 'notificationEvents', 'connectorPollJobs', 'connectorSnapshots', 'originClues', 'originClueBatches']
      .map((collection) => ({ collection, effective_retention_days: collection === 'reports' ? getEffectiveReportRetentionDays(privacy) : privacy.metadata_retention_days })),
  };
}
export function validateOriginClueErasure(ctx, body) {
  const gate = requirePermission(ctx, 'tenant:write');
  if (!gate.ok) return { ...gate.body, status: gate.status };
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some((key) => !['confirmation_tenant_id', 'reason', 'dry_run'].includes(key))
    || body.confirmation_tenant_id !== ctx.tenantId
    || typeof body.reason !== 'string' || !body.reason.trim() || body.reason.trim().length > 500
    || /[\u0000-\u001f\u007f]/.test(body.reason)
    || (body.dry_run !== undefined && typeof body.dry_run !== 'boolean')) {
    return { error: 'invalid_origin_clue_erasure_confirmation', status: 400 };
  }
  return { confirmation_tenant_id: ctx.tenantId, reason: body.reason.trim(), dry_run: body.dry_run === true };
}
function chainedAudit(store, events, now) {
  const result = [...store.auditLog];
  for (const event of events) {
    const prior = [...result].reverse().find((row) => row.entry_hash) ?? null;
    result.push(buildAuditRecord(event, prior, now));
  }
  return result;
}
function eventFor(tenantId, ctx, action, metadata) {
  return { tenant_id: tenantId, actor_user_id: ctx.userId ?? null, actor_role: ctx.role ?? 'system', action,
    resource_type: 'tenant', resource_id: tenantId, metadata };
}

/** Atomic current-tenant metadata lifecycle. options.tenantUpdate is internal to tenant PATCH. */
export function enforceMetadataRetentionForTenant(tenantId, auditContext = {}, options = {}) {
  const store = getStore();
  const current = store.tenants.find((tenant) => tenant.id === tenantId);
  if (!current) return null;
  const now = new Date(options.now ?? Date.now());
  const tenant = { ...current, ...options.tenantUpdate };
  const privacy = normalizePrivacySettings(tenant.privacy_settings);
  tenant.privacy_settings = privacy;
  const policy = buildRetentionPolicySnapshot(tenant);
  const { metadataCutoffMs, reportCutoffMs } = buildMetadataRetentionCutoffs(privacy, now);
  const results = {
    events: purge(store.events, tenantId, 'timestamp', metadataCutoffMs),
    evidenceVault: purge(store.evidenceVault, tenantId, 'created_at', metadataCutoffMs),
    reports: purge(store.reports, tenantId, 'created_at', reportCutoffMs),
    notificationEvents: purge(store.notificationEvents, tenantId, 'created_at', metadataCutoffMs),
  };
  const origin = planOriginClueLifecycle(store, tenantId, { cutoffMs: metadataCutoffMs });
  const candidates = { ...Object.fromEntries(Object.entries(results).map(([key, value]) => [key, value.removed])), ...origin.counts };
  const zeros = Object.fromEntries(Object.keys(candidates).map((key) => [key, 0]));
  const held = privacy.evidence_retention.legal_hold;
  const deleted = held ? zeros : candidates;
  const events = [...(options.auditEvents ?? [])];
  if (totalRetentionCounts(candidates)) events.push(eventFor(tenantId, auditContext,
    held ? 'privacy.retention_legal_hold' : 'privacy.retention_purged',
    { deleted, ...(held ? { blocked_deletions: candidates } : {}), metadata_retention_days: privacy.metadata_retention_days, policy_snapshot: policy }));
  const changes = { tenants: store.tenants.map((item) => item.id === tenantId ? tenant : item) };
  if (!held && totalRetentionCounts(candidates)) {
    Object.assign(changes, Object.fromEntries(Object.entries(results).map(([key, value]) => [key, value.kept])),
      { originClues: origin.originClues, originClueBatches: origin.originClueBatches });
  }
  if (events.length) changes.auditLog = chainedAudit(store, events, now);
  if (events.length || JSON.stringify(current) !== JSON.stringify(tenant) || totalRetentionCounts(deleted)) {
    commitDevStoreChanges(changes);
    advanceTenantLifecycleGeneration(tenantId);
  }
  return { tenant_id: tenantId, deleted, metadata_retention_days: privacy.metadata_retention_days,
    evidence_retention: privacy.evidence_retention, policy_snapshot: policy, legal_hold: held };
}

/** Explicit erasure is independent of optional collection enablement and target archival. */
export function eraseOriginCluesForCurrentTenant(ctx, body, options = {}) {
  const request = validateOriginClueErasure(ctx, body);
  if (request.error) return request;
  const store = getStore();
  const tenant = store.tenants.find((item) => item.id === ctx.tenantId);
  if (!tenant) return { error: 'not_found', status: 404 };
  const privacy = normalizePrivacySettings(tenant.privacy_settings);
  const plan = planOriginClueLifecycle(store, ctx.tenantId, { erase: true });
  const held = privacy.evidence_retention.legal_hold;
  const policy = buildRetentionPolicySnapshot(tenant);
  const deleted = request.dry_run || held ? emptyOriginClueCounts() : plan.counts;
  const summary = { tenant_id: ctx.tenantId, dry_run: request.dry_run, deleted, would_delete: plan.counts,
    blocked_deletions: held ? plan.counts : emptyOriginClueCounts(), legal_hold: held,
    metadata_retention_days: privacy.metadata_retention_days, policy_snapshot: policy, audit_entry_id: null };
  if (request.dry_run) return summary;
  const now = new Date(options.now ?? Date.now());
  const log = chainedAudit(store, [eventFor(ctx.tenantId, ctx, held ? 'privacy.origin_clues_erasure_blocked' : 'privacy.origin_clues_erased',
    { confirmation_tenant_id: ctx.tenantId, reason: request.reason, deleted, blocked_deletions: summary.blocked_deletions, policy_snapshot: policy })], now);
  commitDevStoreChanges({ auditLog: log, ...(!held ? { originClues: plan.originClues, originClueBatches: plan.originClueBatches } : {}) });
  if (!held) advanceTenantLifecycleGeneration(ctx.tenantId);
  summary.audit_entry_id = log.at(-1).id;
  return held ? { ...summary, error: 'origin_clue_erasure_legal_hold', status: 409 } : summary;
}
