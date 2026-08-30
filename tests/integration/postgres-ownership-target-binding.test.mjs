import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';
import { createPostgresOwnershipVerificationServices } from '../../src/persistence/postgres/ownershipVerificationServiceAdapters.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
  createPostgresValidationServices,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const IDS = Object.freeze({
  tenant: 'ten_ownership_binding',
  environment: 'env_ownership_binding',
  group: 'tg_ownership_binding',
  targetA: 'tgt_ownership_a',
  literalTarget: 'tgt_ownership_literal',
});
const CTX = { tenantId: IDS.tenant, userId: 'usr_ownership', role: 'engineer' };
const SIGNED_WORKER = {
  probeMode: 'signed-worker',
  probeWorkerSecret: 'ownership-target-binding-secret-for-tests',
};

async function seed(client) {
  await client.query(
    `INSERT INTO tenants (id, name) VALUES ($1, 'ownership target binding')`,
    [IDS.tenant],
  );
  await client.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'prod')`,
    [IDS.environment, IDS.tenant],
  );
  await client.query(
    `INSERT INTO target_groups (
       id, tenant_id, environment_id, name, ownership_status, validation_mode
     ) VALUES ($1, $2, $3, 'protected origins', 'unverified', 'agent_assisted')`,
    [IDS.group, IDS.tenant, IDS.environment],
  );
  await client.query(
    `INSERT INTO targets (
       id, tenant_id, target_group_id, kind, value, normalized_value, created_at
     ) VALUES ($1, $2, $3, 'fqdn', 'owned.example', 'owned.example', now())`,
    [IDS.targetA, IDS.tenant, IDS.group],
  );
}

function agentControl() {
  const methods = Object.fromEntries(
    VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS.map((method) => [method, async () => null]),
  );
  const agent = {
    id: 'agt_ownership',
    tenant_id: IDS.tenant,
    target_group_id: IDS.group,
    status: 'online',
    capabilities: ['heartbeat', 'canary', 'packet'],
    last_token_validation_status: 'valid',
    probe_endpoint: { declared_fqdn: 'owned.example' },
  };
  methods.getAgentById = async (_ctx, id) => (id === agent.id ? agent : null);
  methods.listAgents = async () => [agent];
  methods.createAgentJob = async (_ctx, record) => ({ ...record });
  return { methods, agent };
}

describe('postgres target-bound live-egress ownership', () => {
  it('binds ownership and every signed destination to the exact target', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, IDS.tenant, seed);

      const audit = createAuditRepository(pool);
      const ownershipVerifications = createOwnershipVerificationRepository(pool);
      const { methods: agents, agent } = agentControl();
      const ownership = createPostgresOwnershipVerificationServices({
        repositories: { ownershipVerifications },
        agentControl: agents,
        audit,
      });

      const challenge = await ownership.createOwnershipChallenge(CTX, {
        target_group_id: IDS.group,
        agent_id: agent.id,
      });
      assert.equal(challenge.error, undefined);
      const nonceHash = challenge.verification.challenge_nonce_hash;
      await ownership.recordOwnershipSignal(CTX, challenge.verification.id, {
        source: 'probe',
        nonce_hash: nonceHash,
      });
      const completed = await ownership.recordOwnershipSignal(CTX, challenge.verification.id, {
        source: 'agent',
        nonce_hash: nonceHash,
      });
      assert.equal(completed.verification.status, 'verified');
      assert.equal(completed.target_id, IDS.targetA);
      assert.equal(completed.target_verification.target_id, IDS.targetA);
      assert.equal(completed.target_verification.state, 'agent_verified');

      const coreCatalog = createCoreCatalogRepository(pool, { auditRepository: audit });
      const victim = await coreCatalog.addTarget(
        CTX,
        IDS.group,
        { kind: 'fqdn', value: 'victim.example' },
        { id: 'tgt_ownership_b' },
      );
      assert.equal(victim.error, undefined);

      const confirmed = await ownership.confirmOwnership(CTX, challenge.verification.id);
      assert.equal(confirmed.error, undefined);
      assert.equal(confirmed.target_id, IDS.targetA);
      assert.equal(confirmed.target_verification.target_id, IDS.targetA);
      assert.equal(confirmed.target_verification.state, 'user_confirmed');
      assert.equal(confirmed.ownership_status, 'unverified');
      const repeated = await ownership.confirmOwnership(CTX, challenge.verification.id);
      assert.equal(repeated.error, undefined);
      assert.equal(repeated.target_verification.id, confirmed.target_verification.id);
      assert.equal(repeated.verification.confirmed_at, confirmed.verification.confirmed_at);

      const confirmationCounts = await withTenantContext(pool, IDS.tenant, async (client) => {
        const targetRows = await client.query(
          `SELECT COUNT(*)::int AS count
           FROM target_verifications
           WHERE tenant_id = $1 AND target_id = $2 AND state = 'user_confirmed'`,
          [IDS.tenant, IDS.targetA],
        );
        const auditRows = await client.query(
          `SELECT action, COUNT(*)::int AS count
           FROM audit_logs
           WHERE tenant_id = $1
             AND action = ANY($2::text[])
           GROUP BY action
           ORDER BY action`,
          [IDS.tenant, [
            'ownership_verification.user_confirmed',
            'target_verification.user_confirmed',
          ]],
        );
        return {
          target: targetRows.rows[0].count,
          audits: Object.fromEntries(auditRows.rows.map((row) => [row.action, row.count])),
        };
      });
      assert.equal(confirmationCounts.target, 1);
      assert.deepEqual(confirmationCounts.audits, {
        'ownership_verification.user_confirmed': 1,
        'target_verification.user_confirmed': 1,
      });

      const summary = await withTenantContext(pool, IDS.tenant, async (client) => {
        const { rows } = await client.query(
          `SELECT ownership_status FROM target_groups WHERE tenant_id = $1 AND id = $2`,
          [IDS.tenant, IDS.group],
        );
        return rows[0]?.ownership_status;
      });
      assert.equal(summary, 'unverified');
      assert.equal(
        (await ownershipVerifications.getCurrentTargetVerification(
          CTX,
          IDS.group,
          IDS.targetA,
        )).state,
        'user_confirmed',
      );
      assert.equal(
        await ownershipVerifications.getCurrentTargetVerification(CTX, IDS.group, victim.id),
        null,
      );

      const validationEvidence = createValidationEvidenceRepository(pool);
      const probeJobs = createProbeJobRepository(pool);
      const { testRuns } = createPostgresValidationServices({
        validationEvidence,
        audit,
        coreCatalog,
        agentControl: agents,
        probeJobs,
        killSwitch: { isKillSwitchActiveForTenant: async () => false },
        ownershipVerifications,
      });

      const bodyRetarget = await testRuns.startTestRun(
        CTX,
        {
          check_id: 'origin.direct_bypass.safe',
          target_group_id: IDS.group,
          target_id: IDS.targetA,
          probe_profile: { direct_ip: '198.51.100.200' },
        },
        SIGNED_WORKER,
      );
      assert.equal(bodyRetarget.error, 'missing_target_bound_direct_address');

      const metadataTarget = await coreCatalog.patchTarget(CTX, IDS.group, IDS.targetA, {
        metadata: {
          direct_origin_ip: '198.51.100.201',
          resolver_host: '8.8.8.8',
          alert_webhook_url: 'https://webhook-victim.example.test/hook',
        },
      });
      assert.equal(metadataTarget.metadata.direct_origin_ip, '198.51.100.201');
      const metadataRetarget = await testRuns.startTestRun(
        CTX,
        {
          check_id: 'origin.direct_bypass.safe',
          target_group_id: IDS.group,
          target_id: IDS.targetA,
        },
        SIGNED_WORKER,
      );
      assert.equal(metadataRetarget.error, 'missing_target_bound_direct_address');

      const afterRetargetDenials = await withTenantContext(pool, IDS.tenant, async (client) => {
        const runs = await client.query(
          `SELECT COUNT(*)::int AS count FROM test_runs WHERE tenant_id = $1`,
          [IDS.tenant],
        );
        const jobs = await client.query(
          `SELECT COUNT(*)::int AS count FROM probe_jobs WHERE tenant_id = $1`,
          [IDS.tenant],
        );
        const audits = await client.query(
          `SELECT metadata_json
           FROM audit_logs
           WHERE tenant_id = $1 AND action = 'test_run.destination_binding_denied'
           ORDER BY sequence, id`,
          [IDS.tenant],
        );
        return {
          runs: runs.rows[0].count,
          jobs: jobs.rows[0].count,
          audits: audits.rows,
        };
      });
      assert.equal(afterRetargetDenials.runs, 0);
      assert.equal(afterRetargetDenials.jobs, 0);
      assert.equal(afterRetargetDenials.audits.length, 2);
      assert.equal(JSON.stringify(afterRetargetDenials.audits).includes('198.51.100.200'), false);
      assert.equal(JSON.stringify(afterRetargetDenials.audits).includes('198.51.100.201'), false);

      const axfrRetargetMetadata = await coreCatalog.patchTarget(CTX, IDS.group, IDS.targetA, {
        metadata: {
          zone: 'victim-b.example',
          declared_apex_domain: 'victim-b.example.',
        },
      });
      assert.equal(axfrRetargetMetadata.metadata.zone, 'victim-b.example');
      const axfrRetarget = await testRuns.startTestRun(
        CTX,
        {
          check_id: 'dns.zone_transfer_exposure.safe',
          target_group_id: IDS.group,
          target_id: IDS.targetA,
          probe_profile: { zone: 'victim-b.example' },
        },
        SIGNED_WORKER,
      );
      assert.equal(axfrRetarget.error, undefined);
      const axfrRetargetJob = await probeJobs.getProbeJobByTestRun(CTX, axfrRetarget.run.id);
      assert.equal(axfrRetargetJob.probe_profile.zone, undefined);
      assert.equal(axfrRetargetJob.target.metadata?.zone, undefined);
      assert.equal(axfrRetargetJob.target.metadata?.declared_apex_domain, undefined);
      assert.equal(JSON.stringify(axfrRetargetJob).includes('victim-b.example'), false);
      assert.equal((await testRuns.cancelTestRun(CTX, axfrRetarget.run.id)).run.status, 'cancelled');

      const axfrExactMetadata = await coreCatalog.patchTarget(CTX, IDS.group, IDS.targetA, {
        metadata: {
          zone: 'OWNED.EXAMPLE.',
          declared_apex_domain: 'owned.example',
        },
      });
      assert.equal(axfrExactMetadata.metadata.zone, 'OWNED.EXAMPLE.');
      const axfrExact = await testRuns.startTestRun(
        CTX,
        {
          check_id: 'dns.zone_transfer_exposure.safe',
          target_group_id: IDS.group,
          target_id: IDS.targetA,
          probe_profile: { zone: 'owned.example.' },
        },
        SIGNED_WORKER,
      );
      assert.equal(axfrExact.error, undefined);
      const axfrExactJob = await probeJobs.getProbeJobByTestRun(CTX, axfrExact.run.id);
      assert.equal(axfrExactJob.probe_profile.zone, 'owned.example');
      assert.equal(axfrExactJob.target.metadata.zone, 'owned.example');
      assert.equal(axfrExactJob.target.metadata.declared_apex_domain, 'owned.example');
      assert.equal((await testRuns.cancelTestRun(CTX, axfrExact.run.id)).run.status, 'cancelled');

      const literalTarget = await coreCatalog.addTarget(
        CTX,
        IDS.group,
        {
          kind: 'url',
          value: 'https://203.0.113.55/origin?bounded=1',
          metadata: {
            direct_origin_ip: '198.51.100.202',
            resolver_host: '9.9.9.9',
            webhook_url: 'https://another-victim.example.test/hook',
          },
        },
        { id: IDS.literalTarget },
      );
      assert.equal(literalTarget.error, undefined);
      await withTenantContext(pool, IDS.tenant, async (client) => {
        await client.query(
          `INSERT INTO target_verifications (
             id, tenant_id, target_id, state, source_kind, source_ref,
             transitioned_at, transitioned_by, audit_entry_id
           ) VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', $4::jsonb, now(), 'test', $5)`,
          [
            'tv_ownership_literal', IDS.tenant, IDS.literalTarget,
            JSON.stringify({ test_fixture: true }), 'audit_ownership_literal',
          ],
        );
      });

      const literalAllowed = await testRuns.startTestRun(
        CTX,
        {
          check_id: 'origin.direct_bypass.safe',
          target_group_id: IDS.group,
          target_id: IDS.literalTarget,
          probe_profile: {
            protected_host: 'edge.example.test',
            direct_ip: '198.51.100.203',
            resolver_host: '1.1.1.1',
            secondary_nameservers: ['ns.victim.example.test'],
          },
        },
        SIGNED_WORKER,
      );
      assert.equal(literalAllowed.error, undefined);
      const literalJob = await probeJobs.getProbeJobByTestRun(CTX, literalAllowed.run.id);
      assert.equal(literalJob.target.value, 'https://203.0.113.55/origin?bounded=1');
      assert.equal(literalJob.probe_profile.protected_host, 'edge.example.test');
      assert.equal(literalJob.probe_profile.direct_ip, undefined);
      assert.equal(literalJob.probe_profile.resolver_host, undefined);
      assert.equal(literalJob.probe_profile.secondary_nameservers, undefined);
      assert.equal(literalJob.target.metadata?.direct_origin_ip, undefined);
      assert.equal(literalJob.target.metadata?.webhook_url, undefined);
      for (const victimDestination of [
        '198.51.100.202', '198.51.100.203', '9.9.9.9', '1.1.1.1',
        'another-victim.example.test', 'ns.victim.example.test',
      ]) {
        assert.equal(JSON.stringify(literalJob).includes(victimDestination), false);
      }
      const literalCancelled = await testRuns.cancelTestRun(CTX, literalAllowed.run.id);
      assert.equal(literalCancelled.run.status, 'cancelled');

      const body = {
        check_id: 'origin.leak_scan.safe',
        target_group_id: IDS.group,
      };

      const denied = await testRuns.startTestRun(
        CTX,
        { ...body, target_id: victim.id },
        SIGNED_WORKER,
      );
      assert.deepEqual(denied, { error: 'ownership_not_verified', status: 409 });
      const afterDenied = await withTenantContext(pool, IDS.tenant, async (client) => {
        const { rows } = await client.query(
          `SELECT COUNT(*)::int AS count
           FROM test_runs
           WHERE tenant_id = $1 AND target_id = $2`,
          [IDS.tenant, victim.id],
        );
        return rows[0].count;
      });
      assert.equal(afterDenied, 0);

      const allowed = await testRuns.startTestRun(
        CTX,
        { ...body, target_id: IDS.targetA },
        SIGNED_WORKER,
      );
      assert.equal(allowed.error, undefined);
      assert.equal(allowed.run.target_id, IDS.targetA);
      assert.equal(allowed.probe_job.status, 'pending');

      const cancelled = await testRuns.cancelTestRun(CTX, allowed.run.id);
      assert.equal(cancelled.run.status, 'cancelled');
      const challengeCreatedMs = Date.parse(challenge.verification.created_at);
      const deleted = await coreCatalog.deleteTarget(CTX, IDS.group, IDS.targetA, {
        now: new Date(challengeCreatedMs + 30_000).toISOString(),
      });
      assert.equal(deleted.deleted, true);
      const replacement = await coreCatalog.addTarget(
        CTX,
        IDS.group,
        { kind: 'fqdn', value: 'owned.example' },
        {
          id: 'tgt_ownership_a_replacement',
          now: new Date(challengeCreatedMs + 60_000).toISOString(),
        },
      );
      assert.equal(replacement.error, undefined);

      const staleConfirmation = await ownership.confirmOwnership(
        CTX,
        challenge.verification.id,
      );
      assert.deepEqual(staleConfirmation, {
        error: 'ownership_target_not_active',
        status: 409,
      });
      assert.equal(
        await ownershipVerifications.getCurrentTargetVerification(
          CTX,
          IDS.group,
          replacement.id,
        ),
        null,
      );
      const replacementSummary = await withTenantContext(pool, IDS.tenant, async (client) => {
        const { rows } = await client.query(
          `SELECT ownership_status FROM target_groups WHERE tenant_id = $1 AND id = $2`,
          [IDS.tenant, IDS.group],
        );
        return rows[0]?.ownership_status;
      });
      assert.equal(replacementSummary, 'unverified');
    }, availability.env ?? process.env);
  });
});
