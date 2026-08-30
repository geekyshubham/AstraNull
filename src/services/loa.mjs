import { audit } from '../audit.mjs';
import { buildLoaCustodyDigest, recordSignature } from '../lib/authorizationArtifactLedger.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isArchivedTargetGroup } from './targetGroups.mjs';

const VERIFICATION_RANK = Object.freeze({
  unverified: 0,
  pending: 1,
  dns_verified: 2,
  agent_verified: 3,
  user_confirmed: 4,
});

function nowIso() {
  return new Date().toISOString();
}

function isActiveSignedLoa(row, atMs = Date.now()) {
  if (row?.state !== 'signed') return false;
  if (!row.expires_at) return true;
  const expiresAt = Date.parse(row.expires_at);
  return !Number.isFinite(expiresAt) || expiresAt > atMs;
}

function findGroup(ctx, groupId) {
  return (
    getStore().targetGroups.find(
      (g) => g.id === groupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
    ) ?? null
  );
}

function getLatestVerificationState(ctx, targetId) {
  const rows = (getStore().targetVerifications ?? []).filter(
    (row) => row.tenant_id === ctx.tenantId && row.target_id === targetId,
  );
  if (!rows.length) return 'unverified';
  const latest = rows.reduce((best, row) => {
    const bestAt = String(best.transitioned_at);
    const rowAt = String(row.transitioned_at);
    if (rowAt > bestAt) return row;
    if (rowAt < bestAt) return best;
    return (VERIFICATION_RANK[row.state] ?? 0) > (VERIFICATION_RANK[best.state] ?? 0) ? row : best;
  });
  return latest.state;
}

function isEligibleForLoaScope(state) {
  return (VERIFICATION_RANK[state] ?? 0) >= VERIFICATION_RANK.agent_verified;
}

function buildScopeSnapshot(ctx, groupId, scopeAck) {
  if (!Array.isArray(scopeAck) || scopeAck.length === 0) {
    return { error: 'invalid_scope_ack', status: 400 };
  }
  const acknowledged = scopeAck.map((targetId) => String(targetId ?? '').trim());
  if (acknowledged.some((targetId) => !targetId)) {
    return { error: 'invalid_scope_ack', status: 400 };
  }
  const ackSet = new Set(acknowledged);
  const targets = getStore().targets.filter(
    (t) => t.tenant_id === ctx.tenantId && t.target_group_id === groupId && !t.deleted_at,
  );
  const targetIds = new Set(targets.map((target) => target.id));
  if ([...ackSet].some((targetId) => !targetIds.has(targetId))) {
    return { error: 'scope_target_not_found', status: 400 };
  }
  const targetsInScope = [];
  const excluded = [];
  for (const target of targets) {
    const state = getLatestVerificationState(ctx, target.id);
    const eligible = isEligibleForLoaScope(state);
    if (eligible && ackSet.has(target.id)) {
      targetsInScope.push(target.id);
    } else {
      excluded.push({ target_id: target.id, reason: eligible ? 'not_acknowledged' : 'unverified' });
    }
  }
  if (targetsInScope.length === 0) {
    return { error: 'invalid_scope_ack', status: 400 };
  }
  return { targets: targetsInScope, excluded };
}

function formatLoa(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    state: row.state,
    signer_name: row.signer_name,
    signer_title: row.signer_title,
    signer_email: row.signer_email,
    signed_at: row.signed_at,
    expires_at: row.expires_at ?? null,
    emergency_contact: row.emergency_contact,
    attested: row.attested,
    scope_snapshot: row.scope_snapshot,
    custody_artifact_id: row.custody_artifact_id,
    custody_digest_sha256: row.custody_digest_sha256,
    audit_entry_id: row.audit_entry_id,
  };
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 * @param {Record<string, unknown>} payload
 */
export function sign(ctx, groupId, payload) {
  if (payload?.attested !== true) {
    return { error: 'attestation_required', status: 403 };
  }

  const group = findGroup(ctx, groupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const scope_snapshot = buildScopeSnapshot(ctx, groupId, payload.scope_ack);
  if (scope_snapshot.error) return scope_snapshot;

  const signed_at = nowIso();
  const signedAtMs = Date.parse(signed_at);
  const active = (getStore().loaSignatures ?? []).find(
    (row) =>
      row.tenant_id === ctx.tenantId
      && row.target_group_id === groupId
      && isActiveSignedLoa(row, signedAtMs),
  );
  if (active) return { error: 'loa_active', status: 409 };

  const expiredLoas = (getStore().loaSignatures ?? []).filter((row) => {
    if (row.tenant_id !== ctx.tenantId || row.target_group_id !== groupId || row.state !== 'signed' || !row.expires_at) {
      return false;
    }
    const expiresAt = Date.parse(row.expires_at);
    return Number.isFinite(expiresAt) && expiresAt <= signedAtMs;
  });
  for (const expiredLoa of expiredLoas) {
    const expirationAudit = audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'loa.expired',
      resource_type: 'loa_signature',
      resource_id: expiredLoa.id,
      metadata: { target_group_id: groupId },
    });
    expiredLoa.state = 'expired';
    expiredLoa.audit_entry_id = expirationAudit.id;
  }
  const loaId = newId('loa');
  const custody_artifact_id = newId('art');
  const loaDraft = {
    id: loaId,
    tenant_id: ctx.tenantId,
    target_group_id: groupId,
    state: 'signed',
    signer_name: String(payload.signer_name ?? '').trim(),
    signer_title: String(payload.signer_title ?? '').trim(),
    signer_email: String(payload.signer_email ?? '').trim(),
    signed_at,
    expires_at: payload.expires_at ?? null,
    emergency_contact: payload.emergency_contact ?? {},
    attested: true,
    scope_snapshot,
    custody_artifact_id,
    custody_digest_sha256: null,
    audit_entry_id: null,
  };

  const custody = recordSignature(ctx, groupId, payload, loaDraft);
  loaDraft.custody_artifact_id = custody.custody_artifact_id;
  loaDraft.custody_digest_sha256 = custody.custody_digest_sha256;

  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'loa.signed',
    resource_type: 'loa_signature',
    resource_id: loaId,
    metadata: { target_group_id: groupId, custody_digest_sha256: custody.custody_digest_sha256 },
  });
  loaDraft.audit_entry_id = auditEntry.id;

  if (!getStore().loaSignatures) getStore().loaSignatures = [];
  getStore().loaSignatures.push(loaDraft);
  persistStore();

  return {
    loa: formatLoa(loaDraft),
    custody_artifact_id: custody.custody_artifact_id,
    custody_digest_sha256: custody.custody_digest_sha256,
    audit_entry_id: auditEntry.id,
  };
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} loaId
 * @param {string} reason
 */
export function revoke(ctx, loaId, reason) {
  const record = (getStore().loaSignatures ?? []).find(
    (row) => row.id === loaId && row.tenant_id === ctx.tenantId,
  );
  if (!record) return { error: 'not_found', status: 404 };
  if (record.state !== 'signed') return { error: 'loa_not_active', status: 409 };

  record.state = 'revoked';
  record.revoked_at = nowIso();
  record.revoke_reason = reason ?? null;

  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'loa.revoked',
    resource_type: 'loa_signature',
    resource_id: loaId,
    metadata: { reason: reason ?? null, target_group_id: record.target_group_id },
  });

  persistStore();
  return { loa: formatLoa(record), audit_entry_id: auditEntry.id };
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 */
export function getActive(ctx, groupId) {
  const loa = (getStore().loaSignatures ?? []).find(
    (row) =>
      row.tenant_id === ctx.tenantId
      && row.target_group_id === groupId
      && isActiveSignedLoa(row),
  ) ?? null;
  return {
    loa: formatLoa(loa),
    meta: loa ? undefined : { empty_reason: 'no_active_loa' },
  };
}

/** Re-hash helper for tests (FT-LOA-01). */
export function rehashLoaDigest(targetGroupId, payload, loaRecord) {
  return buildLoaCustodyDigest({
    tenant_id: loaRecord.tenant_id,
    target_group_id: targetGroupId,
    signer_name: payload.signer_name,
    signer_email: payload.signer_email,
    signed_at: loaRecord.signed_at,
    scope_snapshot: loaRecord.scope_snapshot,
  });
}