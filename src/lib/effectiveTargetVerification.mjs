import { isCurrentProviderDnsOwnershipProof } from './connectorProviders/domainInventory.mjs';
import { isDemoAutoVerifyTenant } from './demoAutoVerify.mjs';
import { ownershipProofFromStates } from './ownershipPolicy.mjs';
import { compareOwnershipInstants, ownershipTransitionInstant } from './ownershipTransitions.mjs';
import { isDeepStrictEqual } from 'node:util';
import { ownershipParentFor } from './subdomainEnumeration.mjs';

function latestRows(store, tenantId, targetIds = null) {
  const wanted = targetIds ? new Set(targetIds) : null;
  const latest = new Map();
  for (const row of store.targetVerifications ?? []) {
    if (row.tenant_id !== tenantId || (wanted && !wanted.has(row.target_id))) continue;
    const instant = ownershipTransitionInstant(row.transitioned_at);
    const previous = latest.get(row.target_id);
    if (!instant) {
      latest.set(row.target_id, { row, malformed: true, ambiguous: true });
      continue;
    }
    if (previous?.malformed) continue;
    const order = previous ? compareOwnershipInstants(instant, previous.instant) : 1;
    if (order > 0) {
      latest.set(row.target_id, { row, instant, ambiguous: false });
    } else if (order === 0
      && (row.state !== previous.row.state || row.source_kind !== previous.row.source_kind
        || !isDeepStrictEqual(row.source_ref ?? {}, previous.row.source_ref ?? {}))) {
      previous.ambiguous = true;
    }
  }
  return new Map([...latest].map(([targetId, value]) => [targetId, value.ambiguous
    ? { ...value.row, state: 'pending', effective_state: 'pending', source_kind: 'ownership_ambiguous', source_ref: {} }
    : value.row]));
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
    if (rows.get(targetId)?.source_kind === 'ownership_ambiguous'
      || ownershipProofFromStates({ targetState: rows.get(targetId)?.state }).verified) continue;
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
      if (rows.get(targetId)?.source_kind !== 'ownership_ambiguous'
        && !ownershipProofFromStates({ targetState: rows.get(targetId)?.state }).verified) {
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
