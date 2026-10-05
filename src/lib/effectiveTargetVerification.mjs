import { isCurrentProviderDnsOwnershipProof } from './connectorProviders/domainInventory.mjs';
import { isDemoAutoVerifyTenant } from './demoAutoVerify.mjs';
import { ownershipProofFromStates, VERIFICATION_RANK } from './ownershipPolicy.mjs';
import { ownershipParentFor } from './subdomainEnumeration.mjs';

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
  const tenantTargets = (store.targets ?? []).filter((target) => target.tenant_id === tenantId);
  const targets = new Map(
    tenantTargets
      .filter((target) => !targetIds || targetIds.includes(target.id))
      .map((target) => [target.id, target]),
  );
  const rows = latestRows(store, tenantId, targetIds);
  for (const [targetId, verification] of rows) {
    rows.set(targetId, effectiveTargetVerification(store, verification, targets.get(targetId)));
  }
  for (const [targetId, target] of targets) {
    if (ownershipProofFromStates({ targetState: rows.get(targetId)?.state }).verified) continue;
    const parent = ownershipParentFor(target, tenantTargets);
    if (!parent) continue;
    const parentRow = effectiveTargetVerification(store, latestRows(store, tenantId, [parent.id]).get(parent.id), parent);
    if (!ownershipProofFromStates({ targetState: parentRow?.state }).verified) continue;
    rows.set(targetId, {
      ...parentRow,
      target_id: targetId,
      target_group_id: target.target_group_id,
      source_kind: 'inherited_parent',
      inherited_from_target_id: parent.id,
    });
  }
  if (isDemoAutoVerifyTenant(tenantId)) {
    for (const [targetId, target] of targets) {
      if (!ownershipProofFromStates({ targetState: rows.get(targetId)?.state }).verified) {
        rows.set(targetId, {
          id: `tv_demo_${targetId}`,
          tenant_id: tenantId,
          target_id: targetId,
          target_group_id: target.target_group_id,
          state: 'user_confirmed',
          source_kind: 'manual_override',
          source_ref: { method: 'demo_auto_verify', demo: true },
          transitioned_at: target.created_at || new Date().toISOString(),
        });
      }
    }
  }
  return rows;
}
