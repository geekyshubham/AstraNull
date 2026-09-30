import { generateNonce } from '../../lib/crypto.mjs';
import { newId } from '../../lib/ids.mjs';

/** @type {readonly string[]} */
export const OWNERSHIP_VERIFICATION_REPOSITORY_METHODS = Object.freeze([
  'insertVerification',
  'findById',
  'listByTenant',
  'confirmOwnershipAtomic',
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

// Outside-in only (ADR-0008): the agent-observed ownership challenge is removed. These
// endpoints stay wired for API stability but fail closed — ownership proof comes from the
// DNS TXT challenge below.
const AGENT_FLOW_REMOVED = Object.freeze({
  error: 'ownership_agent_flow_removed',
  status: 410,
  message:
    'Agent-observed ownership verification was removed (outside-in only). '
    + 'Prove ownership with the DNS TXT challenge instead.',
});

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

async function withOwnershipAuditLock(auditRepo, ctx, options, callback) {
  if (options?.client) return callback(options.client);
  if (typeof auditRepo?.withTenantAuditLock !== 'function') {
    throw new Error('Postgres ownership mutation requires audit.withTenantAuditLock().');
  }
  return auditRepo.withTenantAuditLock(ctx.tenantId, ({ client }) => callback(client));
}

/**
 * @param {{
 *   repositories: Record<string, unknown>,
 *   probeJobs?: { createProbeJob?: (...args: unknown[]) => unknown },
 * }} deps
 */
export function createPostgresOwnershipVerificationServices(deps) {
  const repositories = deps?.repositories ?? deps;
  assertRepository(repositories);
  const ownershipVerifications = repositories.ownershipVerifications;
  const audit = deps?.audit ?? repositories.audit;

  return {
    // Agent-observed ownership is gone (ADR-0008); use DNS ownership instead.
    async verifyOwnershipSetup() {
      return { dry_run: true, ready: false, ...AGENT_FLOW_REMOVED };
    },

    async createOwnershipChallenge() {
      return { ...AGENT_FLOW_REMOVED };
    },

    async recordOwnershipSignal() {
      return { ...AGENT_FLOW_REMOVED };
    },

    async recordOwnershipSignalByNonce() {
      return { ...AGENT_FLOW_REMOVED };
    },

    async confirmOwnership(ctx, id) {
      const actorUserId = ctx.userId ?? 'system';
      return withOwnershipAuditLock(audit, ctx, {}, (client) =>
        ownershipVerifications.confirmOwnershipAtomic(ctx, {
          verification_id: id,
          target_verification_id: newId('tv'),
          confirmed_by_user_id: actorUserId,
          confirmed_at: new Date().toISOString(),
          transitioned_by: actorUserId,
        }, audit, { client }));
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
