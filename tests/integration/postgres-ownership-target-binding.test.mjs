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

// ADR-0008 (outside-in only): the agent-observed ownership challenge is gone. Ownership proof
// reaches `dns_verified` through the DNS challenge, and a legacy `verified` ownership record can
// still be confirmed to `user_confirmed`. This seed models the post-DNS state directly.
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
     ) VALUES ($1, $2, $3, 'protected origins', 'unverified', 'external_only')`,
    [IDS.group, IDS.tenant, IDS.environment],
  );
  await client.query(
    `INSERT INTO targets (
       id, tenant_id, target_group_id, kind, value, normalized_value, created_at
     ) VALUES ($1, $2, $3, 'fqdn', 'owned.example', 'owned.example', now() - interval '1 hour')`,
    [IDS.targetA, IDS.tenant, IDS.group],
  );
  // DNS-proven ownership for targetA (the live path after the agent challenge was removed).
  await client.query(
    `INSERT INTO target_verifications (
       id, tenant_id, target_id, state, source_kind, source_ref,
       transitioned_at, transitioned_by, audit_entry_id
     ) VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', $4::jsonb, now() - interval '1 minute', 'system', $5)`,
    [
      'tv_ownership_a_dns', IDS.tenant, IDS.targetA,
      JSON.stringify({ dns_challenge_id: 'dns_ownership_a' }), 'audit_ownership_a_dns',
    ],
  );
  await client.query(
    `UPDATE target_groups SET ownership_status = 'dns_verified'
     WHERE tenant_id = $1 AND id = $2`,
    [IDS.tenant, IDS.group],
  );
  // A legacy verified ownership_verifications row bound to targetA, created before the target's
  // replacement window, so confirmOwnership can elevate it to user_confirmed.
  await client.query(
    `INSERT INTO ownership_verifications (
       id, tenant_id, target_group_id, declared_fqdn, status,
       challenge_nonce_hash, probe_observed, verified_at, created_at, created_by
     ) VALUES (
       'own_ownership_a', $1, $2, 'owned.example', 'verified',
       'sha256:legacy', TRUE, now() - interval '30 minutes', now() - interval '45 minutes', $3
     )`,
    [IDS.tenant, IDS.group, CTX.userId],
  );
}

describe('postgres target-bound live-egress ownership (outside-in)', () => {
  it('binds every signed destination to the exact target and confirms only proven targets', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, IDS.tenant, seed);

      const audit = createAuditRepository(pool);
      const ownershipVerifications = createOwnershipVerificationRepository(pool);
      const probeJobs = createProbeJobRepository(pool);
      const ownership = createPostgresOwnershipVerificationServices({
        repositories: { ownershipVerifications },
        probeJobs,
        audit,
      });

      // ADR-0008: the agent-observed challenge/verify-setup/signal endpoints fail closed.
      const removedChallenge = await ownership.createOwnershipChallenge(CTX, {
        target_group_id: IDS.group,
      }, SIGNED_WORKER);
      assert.equal(removedChallenge.error, 'ownership_agent_flow_removed');
      assert.equal(removedChallenge.status, 410);
      const removedSignal = await ownership.recordOwnershipSignal(CTX, 'own_ownership_a', {
        source: 'probe', nonce_hash: 'sha256:legacy',
      });
      assert.equal(removedSignal.error, 'ownership_agent_flow_removed');

      const coreCatalog = createCoreCatalogRepository(pool, { auditRepository: audit });
      const victim = await coreCatalog.addTarget(
        CTX,
        IDS.group,
        { kind: 'fqdn', value: 'victim.example' },
        { id: 'tgt_ownership_b' },
      );
      assert.equal(victim.error, undefined);

      // confirmOwnership elevates the legacy verified record's target to user_confirmed.
      const confirmed = await ownership.confirmOwnership(CTX, 'own_ownership_a');
      assert.equal(confirmed.error, undefined, JSON.stringify(confirmed));
      assert.equal(confirmed.target_id, IDS.targetA);
      assert.equal(confirmed.target_verification.target_id, IDS.targetA);
      assert.equal(confirmed.target_verification.state, 'user_confirmed');
      assert.equal('agent_id' in confirmed.target_verification.source_ref, false);
      assert.equal(confirmed.ownership_status, 'unverified');
      const repeated = await ownership.confirmOwnership(CTX, 'own_ownership_a');
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
      const { testRuns } = createPostgresValidationServices({
        validationEvidence,
        audit,
        coreCatalog,
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
        const audits = await client.query(
          `SELECT metadata_json
           FROM audit_logs
           WHERE tenant_id = $1 AND action = 'test_run.destination_binding_denied'
           ORDER BY sequence, id`,
          [IDS.tenant],
        );
        return {
          runs: runs.rows[0].count,
          audits: audits.rows,
        };
      });
      assert.equal(afterRetargetDenials.runs, 0);
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
    }, availability.env ?? process.env);
  });
});
