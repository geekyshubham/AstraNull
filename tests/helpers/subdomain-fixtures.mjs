import { newId } from '../../src/lib/ids.mjs';
import { getStore } from '../../src/store.mjs';

export function recordDnsVerification(ctx, target) {
  const store = getStore();
  if (!store.targetVerifications) store.targetVerifications = [];
  store.targetVerifications.push({
    id: newId('tv'),
    tenant_id: ctx.tenantId,
    target_id: target.id,
    state: 'dns_verified',
    source_kind: 'dns_txt',
    source_ref: { challenge_id: 'test' },
    transitioned_at: new Date(Date.now() + 1000).toISOString(),
    transitioned_by: ctx.userId,
    audit_entry_id: 'aud_test',
  });
}
