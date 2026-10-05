import { audit } from '../audit.mjs';
import { isCurrentProviderDnsOwnershipProof } from '../lib/connectorProviders/domainInventory.mjs';
import { effectiveTargetVerifications } from '../lib/effectiveTargetVerification.mjs';
import { newId } from '../lib/ids.mjs';
import { ownershipParentFor } from '../lib/subdomainEnumeration.mjs';
import {
  VERIFICATION_RANK,
  ownershipProofFromStates,
  ownershipSummaryFromTargetStates,
} from '../lib/ownershipPolicy.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isArchivedTargetGroup } from './targetGroups.mjs';

// Outside-in only (ADR-0008): there is no agent. The old agent-observation ownership
// challenge (probe nonce + agent observation -> `agent_verified`) is removed. Ownership
// proof now comes from the DNS TXT challenge in dnsOwnership.mjs (`dns_verified`) or a
// provider connector (`provider_verified`), then optional `user_confirmed` attestation.

function findTargetGroup(ctx, targetGroupId) {
  return getStore().targetGroups.find(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  ) ?? null;
}

function findVerification(ctx, id) {
  return getStore().ownershipVerifications.find(
    (v) => v.id === id && v.tenant_id === ctx.tenantId,
  ) ?? null;
}

function auditVerification(ctx, id, action, metadata) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? 'system',
    action,
    resource_type: 'ownership_verification',
    resource_id: id,
    ...(metadata ? { metadata } : {}),
  });
}

function refreshGroupOwnershipSummary(ctx, group) {
  const targets = getStore().targets.filter(
    (target) =>
      target.tenant_id === ctx.tenantId
      && target.target_group_id === group.id
      && !target.deleted_at,
  );
  const latest = latestVerificationByTarget(ctx, targets.map((target) => target.id));
  group.ownership_status = ownershipSummaryFromTargetStates(
    targets.map((target) => latest.get(target.id)?.state ?? 'unverified'),
  );
}

function activeTargetBoundToVerification(ctx, record) {
  if (!record.target_id) return null;
  const target = getStore().targets.find(
    (candidate) =>
      candidate.id === record.target_id
      && candidate.tenant_id === ctx.tenantId
      && candidate.target_group_id === record.target_group_id
      && candidate.kind === 'fqdn'
      && !candidate.deleted_at,
  );
  if (!target) return null;
  const value = String(target.normalized_value ?? target.value).trim().toLowerCase();
  if (value !== String(record.declared_fqdn ?? '').trim().toLowerCase()) return null;

  // Retain the creation-time guard used by PostgreSQL as defense in depth against a
  // hand-edited dev store reusing that identity.
  const targetCreatedAt = Date.parse(String(target.created_at ?? ''));
  const challengeCreatedAt = Date.parse(String(record.created_at ?? ''));
  if (
    Number.isFinite(targetCreatedAt)
    && Number.isFinite(challengeCreatedAt)
    && targetCreatedAt > challengeCreatedAt
  ) {
    return null;
  }
  return target;
}

// ADR-0008: the agent-observation ownership challenge is gone. These endpoints stay
// wired for API stability but fail closed — callers must use the DNS ownership challenge
// (`/v1/target-groups/:id/dns-ownership*`) to reach `dns_verified`.
const AGENT_FLOW_REMOVED = Object.freeze({
  error: 'ownership_agent_flow_removed',
  status: 410,
  message:
    'Agent-observed ownership verification was removed (outside-in only). '
    + 'Prove ownership with the DNS TXT challenge instead.',
});

export function verifyOwnershipSetup() {
  return { dry_run: true, ready: false, ...AGENT_FLOW_REMOVED };
}

export function createOwnershipChallenge() {
  return { ...AGENT_FLOW_REMOVED };
}

export function recordOwnershipSignal() {
  return { ...AGENT_FLOW_REMOVED };
}

export function recordOwnershipSignalByNonce() {
  return { ...AGENT_FLOW_REMOVED };
}

export function confirmOwnership(ctx, id) {
  const record = findVerification(ctx, id);
  if (!record) return { error: 'ownership_verification_not_found', status: 404 };

  if (record.status !== 'verified') {
    return { error: 'ownership_not_verified', status: 409 };
  }

  const group = findTargetGroup(ctx, record.target_group_id);
  const target = activeTargetBoundToVerification(ctx, record);
  if (!group || !target) {
    return { error: 'ownership_target_not_active', status: 409 };
  }

  const now = new Date().toISOString();
  const actorUserId = ctx.userId ?? 'system';
  const current = latestVerificationByTarget(ctx, [target.id]).get(target.id);
  let targetVerification = current ?? null;

  if ((VERIFICATION_RANK[current?.state] ?? 0) < VERIFICATION_RANK.user_confirmed) {
    const auditEntry = audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? 'system',
      action: 'target_verification.user_confirmed',
      resource_type: 'target',
      resource_id: target.id,
      metadata: {
        target_group_id: record.target_group_id,
        ownership_verification_id: record.id,
      },
    });
    targetVerification = {
      id: newId('tv'),
      tenant_id: ctx.tenantId,
      target_id: target.id,
      state: 'user_confirmed',
      source_kind: 'user_attestation',
      source_ref: {
        ownership_verification_id: record.id,
        declared_fqdn: record.declared_fqdn,
        confirmed_by_user_id: actorUserId,
      },
      transitioned_at: now,
      transitioned_by: actorUserId,
      audit_entry_id: auditEntry.id,
    };
    if (!getStore().targetVerifications) getStore().targetVerifications = [];
    getStore().targetVerifications.push(targetVerification);
    target.verify_state = 'user_confirmed';
  }

  if (!record.confirmed_at) {
    record.confirmed_by_user_id = actorUserId;
    record.confirmed_at = now;
    auditVerification(ctx, id, 'ownership_verification.user_confirmed', {
      target_group_id: record.target_group_id,
      target_id: target.id,
    });
  }

  refreshGroupOwnershipSummary(ctx, group);
  persistStore();
  return {
    verification: record,
    target_id: target.id,
    target_verification: targetVerification,
    ownership_status: group.ownership_status,
  };
}

export function listOwnershipVerifications(ctx) {
  return getStore().ownershipVerifications.filter((v) => v.tenant_id === ctx.tenantId);
}

export function getOwnershipVerification(ctx, id) {
  return findVerification(ctx, id);
}

// Ladder without the agent rung (ADR-0008): declared -> dns_verified -> user_confirmed.
const LADDER_STEP_IDS = Object.freeze([
  'declared',
  'dns_verified',
  'user_confirmed',
]);

const LADDER_LABELS = Object.freeze({
  declared: 'Declared',
  dns_verified: 'DNS verified',
  user_confirmed: 'User confirmed',
});

// user_confirmed now requires DNS/provider proof (dns_verified) — the agent rung is gone.
const VERIFY_PREREQ_STATES = new Set(['dns_verified', 'provider_verified', 'user_confirmed']);

function latestVerificationByTarget(ctx, targetIds) {
  return effectiveTargetVerifications(getStore(), ctx.tenantId, targetIds);
}

function getActiveLoa(ctx, groupId) {
  return (getStore().loaSignatures ?? []).find(
    (row) =>
      row.tenant_id === ctx.tenantId
      && row.target_group_id === groupId
      && row.state === 'signed'
      && (!row.expires_at || new Date(row.expires_at).getTime() > Date.now()),
  ) ?? null;
}

function loaScopeTargetIds(loa) {
  const targets = loa?.scope_snapshot?.targets;
  if (!Array.isArray(targets)) return new Set();
  return new Set(
    targets
      .map((target) => (target && typeof target === 'object' ? target.target_id : target))
      .map((targetId) => String(targetId ?? '').trim())
      .filter(Boolean),
  );
}

/**
 * Whether ownership of `targetId` has been proven well enough to aim live traffic at it.
 *
 * Reads only the latest target-bound verification. The group's status is a presentation
 * summary and is deliberately excluded from authorization.
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {{ id: string }} group
 * @param {string} targetId
 * @returns {{ verified: boolean, state: string, source: 'target'|null }}
 */
export function targetOwnershipProof(ctx, group, targetId) {
  const store = getStore();
  const groupTargets = store.targets.filter(
    (candidate) =>
      candidate.tenant_id === ctx.tenantId
      && candidate.target_group_id === group?.id
      && !candidate.deleted_at,
  );
  const target = groupTargets.find((candidate) => candidate.id === targetId);
  if (!target) return ownershipProofFromStates({ targetState: null });

  const own = ownTargetOwnershipProof(ctx, store, target);
  if (own.verified) return own;
  const parent = ownershipParentFor(target, groupTargets);
  if (!parent) return own;
  const inherited = ownTargetOwnershipProof(ctx, store, parent);
  return inherited.verified
    ? { ...inherited, source: 'parent', inherited_from_target_id: parent.id }
    : own;
}

function ownTargetOwnershipProof(ctx, store, target) {
  const verification = latestVerificationByTarget(ctx, [target.id]).get(target.id);
  if (verification?.inherited_from_target_id) return { verified: false, state: 'unverified', source: null };
  if (verification?.state !== 'provider_verified') {
    return ownershipProofFromStates({ targetState: verification?.state ?? null });
  }

  const sourceRef = verification.source_ref && typeof verification.source_ref === 'object'
    && !Array.isArray(verification.source_ref)
    ? verification.source_ref
    : {};
  const connector = (store.wafConnectors ?? []).find(
    (candidate) =>
      candidate.id === sourceRef.connector_id
      && candidate.tenant_id === ctx.tenantId,
  );
  const currentProof = Boolean(connector) && (store.wafConnectorSnapshots ?? []).some(
    (snapshot) =>
      snapshot.tenant_id === ctx.tenantId
      && snapshot.connector_id === connector.id
      && snapshot.resource_ref_hash === sourceRef.resource_ref_hash
      && isCurrentProviderDnsOwnershipProof({ connector, snapshot, sourceRef, target }),
  );
  return ownershipProofFromStates({
    targetState: currentProof ? 'provider_verified' : 'pending',
  });
}

/**
 * Server-computed verification ladder (portal revamp §3.4).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 */
export function getLadder(ctx, groupId) {
  const group = findTargetGroup(ctx, groupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const targets = getStore().targets.filter(
    (t) => t.tenant_id === ctx.tenantId && t.target_group_id === groupId && !t.deleted_at,
  );
  const latestByTarget = latestVerificationByTarget(
    ctx,
    targets.map((t) => t.id),
  );

  const total = targets.length;
  const steps = LADDER_STEP_IDS.map((id) => {
    let count = 0;
    if (id === 'declared') {
      count = total;
    } else {
      for (const state of latestByTarget.values()) {
        const ladderState = state.state === 'provider_verified' ? 'dns_verified' : state.state;
        if (ladderState === id) count += 1;
      }
    }
    return {
      id,
      label: LADDER_LABELS[id] ?? id,
      done: total > 0 && count >= total,
      count,
      total,
    };
  });

  return {
    steps,
    meta: total === 0
      ? { empty_reason: 'No targets declared for this group; the verification ladder cannot be computed yet.' }
      : undefined,
  };
}

/**
 * Elevates a target to user_confirmed (portal revamp §3.4).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 * @param {string} targetId
 * @param {{ signer?: string, note?: string }} _signer
 */
export function confirmTarget(ctx, groupId, targetId, signer = {}) {
  const group = findTargetGroup(ctx, groupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const target = getStore().targets.find(
    (t) =>
      t.id === targetId
      && t.tenant_id === ctx.tenantId
      && t.target_group_id === groupId
      && !t.deleted_at,
  );
  if (!target) return { error: 'target_not_found', status: 404 };

  const activeLoa = getActiveLoa(ctx, groupId);
  if (!activeLoa) return { error: 'loa_missing', status: 409 };

  const latestByTarget = latestVerificationByTarget(ctx, [targetId]);
  const current = latestByTarget.get(targetId);
  const currentState = current?.state ?? 'pending';
  if (!VERIFY_PREREQ_STATES.has(currentState)) {
    return { error: 'verify_prereq_not_met', status: 409 };
  }
  if (!loaScopeTargetIds(activeLoa).has(targetId)) {
    return { error: 'target_not_in_loa_scope', status: 409 };
  }

  const now = new Date().toISOString();
  const verification = {
    id: newId('tv'),
    tenant_id: ctx.tenantId,
    target_id: targetId,
    state: 'user_confirmed',
    source_kind: 'user_attestation',
    source_ref: {
      signer: ctx.userId ?? 'system',
      note: signer.note ?? null,
      loa_id: activeLoa.id,
      loa_custody_digest_sha256: activeLoa.custody_digest_sha256,
    },
    transitioned_at: now,
    transitioned_by: ctx.userId ?? 'system',
    audit_entry_id: null,
  };
  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_verification.user_confirmed',
    resource_type: 'target',
    resource_id: targetId,
    metadata: { target_group_id: groupId, loa_id: activeLoa.id },
  });
  verification.audit_entry_id = auditEntry.id;
  if (!getStore().targetVerifications) getStore().targetVerifications = [];
  getStore().targetVerifications.push(verification);
  target.verify_state = 'user_confirmed';
  persistStore();

  return {
    target,
    verification: {
      state: verification.state,
      source_kind: verification.source_kind,
      source_ref: verification.source_ref,
      transitioned_at: verification.transitioned_at,
    },
    audit_entry_id: auditEntry.id,
  };
}
