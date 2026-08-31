import { isCurrentProviderDnsOwnershipProof } from './connectorProviders/domainInventory.mjs';
import { VERIFICATION_RANK } from './ownershipPolicy.mjs';

function latestRows(store, tenantId, targetIds = null) {
  const wanted = targetIds ? new Set(targetIds) : null;
  const latest = new Map();
  for (const row of store.targetVerifications ?? []) {
    if (row.tenant_id !== tenantId || (wanted && !wanted.has(row.target_id))) continue;
    const previous = latest.get(row.target_id);
    const rowAt = String(row.transitioned_at ?? '');
    const previousAt = String(previous?.transitioned_at ?? '');
    if (!previous
      || rowAt > previousAt
      || (rowAt === previousAt
        && (VERIFICATION_RANK[row.state] ?? 0) > (VERIFICATION_RANK[previous.state] ?? 0))) {
      latest.set(row.target_id, row);
    }
  }
  return latest;
}

export function effectiveTargetVerification(store, verification, target) {
  if (!verification || verification.state !== 'provider_verified') return verification ?? null;
  const sourceRef = verification.source_ref && typeof verification.source_ref === 'object'
    && !Array.isArray(verification.source_ref)
    ? verification.source_ref
    : {};
  const connector = (store.wafConnectors ?? []).find(
    (candidate) => candidate.tenant_id === verification.tenant_id
      && candidate.id === sourceRef.connector_id,
  );
  const current = Boolean(connector && target) && (store.wafConnectorSnapshots ?? []).some(
    (snapshot) => snapshot.tenant_id === verification.tenant_id
      && snapshot.connector_id === connector.id
      && snapshot.resource_ref_hash === sourceRef.resource_ref_hash
      && isCurrentProviderDnsOwnershipProof({ connector, snapshot, sourceRef, target }),
  );
  return current ? verification : { ...verification, state: 'pending', effective_state: 'pending' };
}

export function effectiveTargetVerifications(store, tenantId, targetIds = null) {
  const targets = new Map(
    (store.targets ?? [])
      .filter((target) => target.tenant_id === tenantId && (!targetIds || targetIds.includes(target.id)))
      .map((target) => [target.id, target]),
  );
  const rows = latestRows(store, tenantId, targetIds);
  for (const [targetId, verification] of rows) {
    rows.set(targetId, effectiveTargetVerification(store, verification, targets.get(targetId)));
  }
  return rows;
}
