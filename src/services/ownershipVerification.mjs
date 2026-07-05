import { audit } from '../audit.mjs';
import { generateNonce, hashNonce } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isArchivedTargetGroup } from './targetGroups.mjs';

const OPEN_STATUSES = new Set(['challenge_sent', 'verified']);

function findTargetGroup(ctx, targetGroupId) {
  return getStore().targetGroups.find(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  ) ?? null;
}

function groupFqdnTargets(tenantId, targetGroupId) {
  return getStore().targets
    .filter(
      (t) => t.tenant_id === tenantId && t.target_group_id === targetGroupId && t.kind === 'fqdn',
    )
    .map((t) => String(t.value).trim().toLowerCase());
}

function findVerification(ctx, id) {
  return getStore().ownershipVerifications.find(
    (v) => v.id === id && v.tenant_id === ctx.tenantId,
  ) ?? null;
}

function auditVerification(ctx, id, action) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action,
    resource_type: 'ownership_verification',
    resource_id: id,
  });
}

export function createOwnershipChallenge(ctx, body) {
  const targetGroupId = body.target_group_id;
  const agentId = body.agent_id;

  const group = findTargetGroup(ctx, targetGroupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const agent = getStore().agents.find(
    (a) => a.id === agentId && a.tenant_id === ctx.tenantId,
  );
  if (!agent) return { error: 'agent_not_found', status: 404 };

  if (agent.target_group_id !== group.id) {
    return { error: 'agent_not_bound_to_target_group', status: 400 };
  }
  if (agent.status !== 'online') {
    return { error: 'agent_not_online', status: 409 };
  }
  if (agent.last_token_validation_status === 'invalid') {
    return { error: 'agent_token_invalid', status: 409 };
  }

  const declaredFqdnRaw = agent.probe_endpoint?.declared_fqdn ?? null;
  if (!declaredFqdnRaw) {
    return { error: 'agent_probe_endpoint_missing', status: 409 };
  }
  const declaredFqdn = String(declaredFqdnRaw).trim().toLowerCase();
  const fqdnSet = new Set(groupFqdnTargets(ctx.tenantId, group.id));
  if (!fqdnSet.has(declaredFqdn)) {
    return { error: 'declared_fqdn_not_in_target_group', status: 400 };
  }

  const nonce = generateNonce();
  const challenge_nonce_hash = hashNonce(nonce);
  const id = newId('own');
  const now = new Date().toISOString();
  const record = {
    id,
    tenant_id: ctx.tenantId,
    target_group_id: targetGroupId,
    agent_id: agentId,
    declared_fqdn: declaredFqdn,
    status: 'challenge_sent',
    challenge_nonce_hash,
    probe_observed: false,
    agent_observed: false,
    verified_at: null,
    confirmed_by_user_id: null,
    confirmed_at: null,
    created_at: now,
    created_by: ctx.userId,
  };
  getStore().ownershipVerifications.push(record);
  auditVerification(ctx, id, 'ownership_verification.challenge_created');
  persistStore();
  return { verification: record, nonce };
}

export function recordOwnershipSignal(ctx, id, { source, nonce_hash }) {
  const record = findVerification(ctx, id);
  if (!record) return { error: 'ownership_verification_not_found', status: 404 };

  if (!OPEN_STATUSES.has(record.status)) {
    return { error: 'ownership_verification_not_open', status: 409 };
  }
  if (nonce_hash !== record.challenge_nonce_hash) {
    return { error: 'nonce_mismatch', status: 400 };
  }

  if (source === 'probe') {
    record.probe_observed = true;
  } else if (source === 'agent') {
    record.agent_observed = true;
  } else {
    return { error: 'invalid_source', status: 400 };
  }

  if (record.probe_observed && record.agent_observed && record.status === 'challenge_sent') {
    const now = new Date().toISOString();
    record.status = 'verified';
    record.verified_at = now;
    const group = findTargetGroup(ctx, record.target_group_id);
    if (group) {
      group.ownership_status = 'agent_verified';
    }
    auditVerification(ctx, id, 'ownership_verification.agent_verified');
  }

  persistStore();
  return { verification: record };
}

export function confirmOwnership(ctx, id) {
  const record = findVerification(ctx, id);
  if (!record) return { error: 'ownership_verification_not_found', status: 404 };

  if (record.status !== 'verified') {
    return { error: 'ownership_not_verified', status: 409 };
  }

  const now = new Date().toISOString();
  record.confirmed_by_user_id = ctx.userId;
  record.confirmed_at = now;
  const group = findTargetGroup(ctx, record.target_group_id);
  if (group) {
    group.ownership_status = 'user_confirmed';
  }
  auditVerification(ctx, id, 'ownership_verification.user_confirmed');
  persistStore();
  return { verification: record };
}

export function listOwnershipVerifications(ctx) {
  return getStore().ownershipVerifications.filter((v) => v.tenant_id === ctx.tenantId);
}

export function getOwnershipVerification(ctx, id) {
  return findVerification(ctx, id);
}