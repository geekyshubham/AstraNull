import { buildAuditRecord } from '../audit.mjs';
import { DEFAULT_PRIVACY, normalizePrivacySettings } from '../lib/privacySettings.mjs';
import { enforceMetadataRetentionForTenant } from './privacyRetention.mjs';
import { commitDevStoreChanges, getStore } from '../store.mjs';

export function getCurrentTenant(ctx) {
  return getStore().tenants.find((t) => t.id === ctx.tenantId) ?? null;
}

export function patchCurrentTenant(ctx, body) {
  const tenant = getCurrentTenant(ctx);
  if (!tenant) return null;
  const updated = { ...tenant, ...(body.name ? { name: body.name } : {}), updated_at: new Date().toISOString() };
  if (body.privacy_settings) updated.privacy_settings = normalizePrivacySettings({ ...tenant.privacy_settings, ...body.privacy_settings });
  const event = { tenant_id: ctx.tenantId, actor_user_id: ctx.userId, actor_role: ctx.role,
    action: 'tenant.updated', resource_type: 'tenant', resource_id: tenant.id,
    metadata: { fields: Object.keys(body) } };
  if (body.privacy_settings) {
    enforceMetadataRetentionForTenant(ctx.tenantId, ctx, { tenantUpdate: updated, auditEvents: [event] });
  } else {
    const store = getStore();
    const prior = [...store.auditLog].reverse().find((row) => row.entry_hash) ?? null;
    commitDevStoreChanges({ tenants: store.tenants.map((row) => row.id === tenant.id ? updated : row),
      auditLog: [...store.auditLog, buildAuditRecord(event, prior)] });
  }
  return getCurrentTenant(ctx);
}

export { DEFAULT_PRIVACY };
