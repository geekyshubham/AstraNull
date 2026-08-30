import { generateNonce, hashNonce } from '../../lib/crypto.mjs';
import { newId } from '../../lib/ids.mjs';
import { buildSignedProbeJobRecord, signProbeJob } from '../../lib/probeJobs.mjs';

/** @type {readonly string[]} */
export const OWNERSHIP_VERIFICATION_REPOSITORY_METHODS = Object.freeze([
  'insertVerification',
  'setVerificationProbeJobId',
  'findById',
  'findOpenByNonceHash',
  'listByTenant',
  'recordOwnershipSignalAtomic',
  'confirmOwnershipAtomic',
  'updateVerificationSignals',
  'updateVerificationConfirmed',
  'updateTargetGroupOwnershipStatus',
  'updateTargetGroupDnsOwnership',
  'getCurrentTargetVerification',
  'listFqdnTargetValues',
  'getActiveTargetGroup',
]);

/** @type {readonly string[]} */
export const POSTGRES_OWNERSHIP_VERIFICATION_SERVICE_METHODS = Object.freeze([
  'createOwnershipChallenge',
  'verifyOwnershipSetup',
  'recordOwnershipSignal',
  'recordOwnershipSignalByNonce',
  'confirmOwnership',
  'listOwnershipVerifications',
  'getOwnershipVerification',
]);

/** @type {readonly string[]} */
export const POSTGRES_DNS_OWNERSHIP_SERVICE_METHODS = Object.freeze([
  'issueDnsOwnershipChallenge',
  'verifyDnsOwnership',
]);

function flattenTxtRecords(records) {
  if (!Array.isArray(records)) return [];
  const out = [];
  for (const entry of records) {
    if (Array.isArray(entry)) {
      for (const chunk of entry) out.push(String(chunk));
    } else {
      out.push(String(entry));
    }
  }
  return out;
}

function assertRepository(repositories) {
  const repo = repositories?.ownershipVerifications;
  if (!repo || typeof repo !== 'object') {
    throw new Error('Postgres ownership adapter requires repositories.ownershipVerifications.');
  }
  for (const method of OWNERSHIP_VERIFICATION_REPOSITORY_METHODS) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres ownership adapter requires ownershipVerifications.${method}().`);
    }
  }
}

async function auditVerification(auditRepo, ctx, id, action) {
  if (!auditRepo?.appendAuditEvent) return;
  await auditRepo.appendAuditEvent({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? 'system',
    action,
    resource_type: 'ownership_verification',
    resource_id: id,
  });
}

async function auditTargetGroup(auditRepo, ctx, targetGroupId, action) {
  if (!auditRepo?.appendAuditEvent) return;
  await auditRepo.appendAuditEvent({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? 'system',
    action,
    resource_type: 'target_group',
    resource_id: targetGroupId,
  });
}


function buildOwnershipChallengeProbeJob(ctx, verification, runtimeConfig) {
  const run = {
    id: verification.id,
    tenant_id: ctx.tenantId,
    safety_constraints: { max_events: 1, max_duration_seconds: 30 },
  };
  const check = {
    check_id: 'ownership.challenge',
    vector_family: 'ownership',
    title: 'Ownership challenge',
    probe_profile: {
      kind: 'ownership_challenge',
      max_requests: 1,
      timeout_ms: 5000,
      marker: 'astranull-ownership-challenge',
    },
  };
  const target = {
    id: verification.agent_id,
    kind: 'fqdn',
    value: verification.declared_fqdn,
  };
  const job = buildSignedProbeJobRecord({
    run,
    check,
    target,
    probeProfile: undefined,
    probeWorkerSecret: runtimeConfig.probeWorkerSecret,
    now: new Date(),
    newId: () => newId('pjob'),
  });
  job.ownership_verification_id = verification.id;
  job.nonce_hash = verification.challenge_nonce_hash;
  job.job_signature = signProbeJob(job, runtimeConfig.probeWorkerSecret);
  return job;
}

async function validateOwnershipChallengeInputs(deps, ctx, body) {
  const { ownershipVerifications, agentControl } = deps;
  const targetGroupId = body.target_group_id;
  const agentId = body.agent_id;

  const group = await ownershipVerifications.getActiveTargetGroup(ctx, targetGroupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  if (!agentControl?.getAgentById) {
    return { error: 'agent_not_found', status: 404 };
  }
  const agent = await agentControl.getAgentById(ctx, agentId);
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
  const fqdnValues = await ownershipVerifications.listFqdnTargetValues(ctx, group.id);
  const fqdnSet = new Set(fqdnValues);
  if (!fqdnSet.has(declaredFqdn)) {
    return { error: 'declared_fqdn_not_in_target_group', status: 400 };
  }

  return { group, agent, targetGroupId, agentId, declaredFqdn };
}

/**
 * @param {{
 *   repositories: Record<string, unknown>,
 *   agentControl?: { getAgentById?: (...args: unknown[]) => unknown },
 *   probeJobs?: { createProbeJob?: (...args: unknown[]) => unknown },
 * }} deps
 */
export function createPostgresOwnershipVerificationServices(deps) {
  const repositories = deps?.repositories ?? deps;
  assertRepository(repositories);
  const ownershipVerifications = repositories.ownershipVerifications;
  const agentControl = deps?.agentControl ?? repositories.agentControl;
  const probeJobs = deps?.probeJobs ?? repositories.probeJobs;
  const audit = deps?.audit ?? repositories.audit;

  const challengeDeps = { ownershipVerifications, agentControl };

  return {
    async verifyOwnershipSetup(ctx, body, _runtimeConfig) {
      const validated = await validateOwnershipChallengeInputs(challengeDeps, ctx, body);
      if (validated.error) {
        return {
          dry_run: true,
          ready: false,
          error: validated.error,
          status: validated.status,
        };
      }

      const { targetGroupId, agentId, declaredFqdn } = validated;
      if (audit?.appendAuditEvent) {
        await audit.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId ?? null,
          actor_role: ctx.role ?? 'system',
          action: 'ownership_verification.setup_verified',
          resource_type: 'ownership_verification',
          resource_id: targetGroupId,
        });
      }

      return {
        dry_run: true,
        ready: true,
        target_group_id: targetGroupId,
        agent_id: agentId,
        declared_fqdn: declaredFqdn,
        checks: {
          agent_online: true,
          agent_bound: true,
          token_valid: true,
          fqdn_declared: true,
        },
      };
    },

    async createOwnershipChallenge(ctx, body, runtimeConfig) {
      const validated = await validateOwnershipChallengeInputs(challengeDeps, ctx, body);
      if (validated.error) {
        return { error: validated.error, status: validated.status };
      }

      const { targetGroupId, agentId, declaredFqdn } = validated;

      const nonce = generateNonce();
      const challenge_nonce_hash = hashNonce(nonce);
      const id = newId('own');
      const now = new Date().toISOString();
      let verification = await ownershipVerifications.insertVerification(ctx, {
        id,
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
      });
      await auditVerification(audit, ctx, id, 'ownership_verification.challenge_created');

      if (runtimeConfig?.probeMode === 'signed-worker' && runtimeConfig.probeWorkerSecret) {
        if (probeJobs?.createProbeJob) {
          const job = buildOwnershipChallengeProbeJob(ctx, verification, runtimeConfig);
          const created = await probeJobs.createProbeJob(ctx, job);
          if (created?.id) {
            verification = await ownershipVerifications.setVerificationProbeJobId(
              ctx,
              verification.id,
              created.id,
            );
          }
        }
      }

      return { verification, nonce };
    },

    async recordOwnershipSignal(ctx, id, payload) {
      return ownershipVerifications.recordOwnershipSignalAtomic(ctx, {
        verification_id: id,
        source: payload.source,
        nonce_hash: payload.nonce_hash,
        target_verification_id: newId('tv'),
        observed_at: new Date().toISOString(),
        transitioned_by: ctx.userId ?? 'system',
      }, audit);
    },

    async recordOwnershipSignalByNonce({ tenantId }, payload) {
      const ctx = { tenantId, userId: 'system', role: 'system' };
      return ownershipVerifications.recordOwnershipSignalAtomic(ctx, {
        source: payload.source,
        nonce_hash: payload.nonce_hash,
        target_verification_id: newId('tv'),
        observed_at: new Date().toISOString(),
        transitioned_by: 'system',
      }, audit);
    },

    async confirmOwnership(ctx, id) {
      const actorUserId = ctx.userId ?? 'system';
      return ownershipVerifications.confirmOwnershipAtomic(ctx, {
        verification_id: id,
        target_verification_id: newId('tv'),
        confirmed_by_user_id: actorUserId,
        confirmed_at: new Date().toISOString(),
        transitioned_by: actorUserId,
      }, audit);
    },

    async listOwnershipVerifications(ctx) {
      return ownershipVerifications.listByTenant(ctx);
    },

    async getOwnershipVerification(ctx, id) {
      return ownershipVerifications.findById(ctx, id);
    },
  };
}

/**
 * @param {{ repositories: Record<string, unknown>, audit?: { appendAuditEvent?: (...args: unknown[]) => unknown } }} deps
 */
export function createPostgresDnsOwnershipServices(deps) {
  const repositories = deps?.repositories ?? deps;
  assertRepository(repositories);
  const ownershipVerifications = repositories.ownershipVerifications;
  const audit = deps?.audit ?? repositories.audit;

  return {
    async issueDnsOwnershipChallenge(ctx, { target_group_id }) {
      const group = await ownershipVerifications.getActiveTargetGroup(ctx, target_group_id);
      if (!group) return { error: 'target_group_not_found', status: 404 };

      const fqdnValues = await ownershipVerifications.listFqdnTargetValues(ctx, target_group_id);
      const domain = fqdnValues[0] ?? null;
      if (!domain) return { error: 'no_fqdn_target', status: 409 };

      const token = `${newId('dnstxt')}_${generateNonce()}`;
      const issued_at = new Date().toISOString();
      const dns_ownership = {
        token,
        record_name: `_astranull-challenge.${domain}`,
        record_value: token,
        status: 'pending',
        issued_at,
      };
      await ownershipVerifications.updateTargetGroupDnsOwnership(ctx, target_group_id, {
        dns_ownership,
      });
      await auditTargetGroup(audit, ctx, target_group_id, 'dns_ownership.challenge_issued');

      return {
        target_group_id,
        record_name: dns_ownership.record_name,
        record_value: dns_ownership.record_value,
        status: 'pending',
      };
    },

    async verifyDnsOwnership(ctx, { target_group_id }, { resolveTxt } = {}) {
      const group = await ownershipVerifications.getActiveTargetGroup(ctx, target_group_id);
      if (!group) return { error: 'target_group_not_found', status: 404 };
      if (!group.dns_ownership) return { error: 'no_dns_challenge', status: 409 };

      let lookup;
      try {
        let resolveFn = resolveTxt;
        if (!resolveFn) {
          const dns = await import('node:dns/promises');
          resolveFn = dns.resolveTxt.bind(dns);
        }
        lookup = await resolveFn(group.dns_ownership.record_name);
      } catch {
        return { error: 'dns_lookup_failed', status: 502 };
      }

      const values = flattenTxtRecords(lookup);
      const matched = values.some((v) => v === group.dns_ownership.record_value);
      const dns_ownership = { ...group.dns_ownership };
      let ownership_status = group.ownership_status;

      if (matched) {
        dns_ownership.status = 'verified';
        dns_ownership.verified_at = new Date().toISOString();
        ownership_status = 'dns_verified';
        await auditTargetGroup(audit, ctx, target_group_id, 'dns_ownership.verified');
      } else {
        dns_ownership.status = 'failed';
        await auditTargetGroup(audit, ctx, target_group_id, 'dns_ownership.failed');
      }

      await ownershipVerifications.updateTargetGroupDnsOwnership(ctx, target_group_id, {
        dns_ownership,
        ownership_status,
      });

      return {
        target_group_id,
        status: dns_ownership.status,
        ownership_status,
      };
    },
  };
}