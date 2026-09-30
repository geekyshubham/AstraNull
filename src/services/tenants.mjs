import { audit } from '../audit.mjs';
import { DEFAULT_PRIVACY, normalizePrivacySettings } from '../lib/privacySettings.mjs';
import { enforceMetadataRetentionForTenant } from './privacyRetention.mjs';
import { getStore, persistStore } from '../store.mjs';

export function getCurrentTenant(ctx) {
  return getStore().tenants.find((t) => t.id === ctx.tenantId) ?? null;
}

export function patchCurrentTenant(ctx, body) {
  const tenant = getCurrentTenant(ctx);
  if (!tenant) return null;
  if (body.name) tenant.name = body.name;
  const privacyPatched = Boolean(body.privacy_settings);
  if (privacyPatched) {
    tenant.privacy_settings = normalizePrivacySettings({
      ...tenant.privacy_settings,
      ...body.privacy_settings,
    });
  }
  tenant.updated_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'tenant.updated',
    resource_type: 'tenant',
    resource_id: tenant.id,
    metadata: { fields: Object.keys(body) },
  });
  if (privacyPatched) {
    enforceMetadataRetentionForTenant(ctx.tenantId, { userId: ctx.userId, role: ctx.role });
  }
  persistStore();
  return tenant;
}

export { DEFAULT_PRIVACY };