import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { deriveAssuranceScope } from '../../src/lib/assuranceScope.mjs';
import { deriveRunEvidenceStamp, approvedScenarioVersion } from '../../src/lib/checkDefinitionVersion.mjs';
import { buildSignedProbeJobRecord } from '../../src/lib/probeJobs.mjs';
import { probeSourceResolverFromEnv } from '../../src/lib/probeSourcePerspective.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createProtectionValidationRepository } from '../../src/persistence/postgres/protectionValidationRepository.mjs';
import { createPostgresProtectionValidationBackend } from '../../src/persistence/postgres/protectionValidationServiceAdapters.mjs';
import { createPostgresFirewallEvidenceReader } from '../../src/persistence/postgres/firewallEvidenceReader.mjs';
import { createProtectionValidationService } from '../../src/services/protectionValidation.mjs';
import { createProtectionValidationFacade } from '../../src/services/protectionValidationFacade.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { databaseUrlWithDatabase, ensureHarnessAppRole, resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

// Exercises persistence and server acceptance of fixture observations, not network enforcement.
test('PostgreSQL accepted firewall results qualify through passive readers with injected source trust and original leases', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) { t.skip(availability.reason); return; }
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    const tenantId = 'ten_fw_accepted';
    const workerId = 'worker_fw_accepted';
    const ctx = { tenantId, userId: 'usr_fw_accepted', role: 'owner' };
    const worker = { ...ctx, workerId };
    const source = 'reviewed-fixture-region';
    const resolveSourcePerspective = probeSourceResolverFromEnv({
      ASTRANULL_APPROVED_PROBE_SOURCES: JSON.stringify({ [source]: [workerId] }),
    });
    const declaredAt = new Date(Date.now() - 60_000);
    await owner.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Firewall accepted proof'), ('ten_fw_other', 'Other')`, [tenantId]);
    await owner.query(`INSERT INTO target_groups (id, tenant_id, name, created_at)
      VALUES ('tg_fw_accepted', $1, 'Historical association only', $2)`, [tenantId, declaredAt]);
    await owner.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, protocol, port, expected_behavior, created_at)
      VALUES ('tgt_fw_accepted', $1, 'tg_fw_accepted', 'fqdn', 'firewall.example.test', 'firewall.example.test', 'tcp', 443, 'intentionally_public', $2)`, [tenantId, declaredAt]);
    await withTenantContext(owner, tenantId, (client) => client.query(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
      VALUES ('proof_fw_accepted', $1, 'tgt_fw_accepted', 'dns_verified', 'dns_txt', '{}', $2, 'usr_fw_accepted', 'audit_fixture')`, [tenantId, declaredAt]));
    await ensureHarnessAppRole(owner);
    const baseUrl = availability.env.ASTRANULL_ADMIN_DATABASE_URL ?? availability.env.ASTRANULL_DATABASE_URL;
    const appUrl = new URL(databaseUrlWithDatabase(baseUrl, databaseName));
    appUrl.username = 'astranull_app'; appUrl.password = 'astranull_app_local_dev';
    appUrl.searchParams.set('options', '-c timezone=UTC');
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl.toString() });
    try {
      const role = (await pool.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user')).rows[0];
      assert.deepEqual(role, { rolsuper: false, rolbypassrls: false });
      const audit = createAuditRepository(pool);
      const repositories = { audit, probeJobs: createProbeJobRepository(pool),
        validationEvidence: createValidationEvidenceRepository(pool), killSwitch: createKillSwitchRepository(pool) };
      const repository = createProtectionValidationRepository(pool);
      const backend = createPostgresProtectionValidationBackend(repository, audit);
      const base = createProtectionValidationService({ backend, resolveSourcePerspective });
      let clock = new Date();
      const facade = (resolver = resolveSourcePerspective) => createProtectionValidationFacade({
        base, backend, evidence: createPostgresFirewallEvidenceReader(pool), resolveSourcePerspective: resolver, now: () => clock,
      });
      const services = facade();
      const expectation = await services.createFirewallExpectation(ctx, {
        destination_target_id: 'tgt_fw_accepted', protocol: 'tcp', port: 443, expected: 'allow',
        source_perspective: source, change_id: 'CHG-accepted-fixture',
      }, { now: clock });
      assert.equal(expectation.error, undefined, JSON.stringify(expectation));
      const check = getCheckById('tls.profile_exposure.safe');
      const target = (await backend.loadTargetContext(ctx, ['tgt_fw_accepted'])).targets[0];
      const stamp = deriveRunEvidenceStamp(check, undefined, { probeMode: 'signed-worker', scenarioVersion: approvedScenarioVersion(check) });
      const observedIds = [];
      async function accept(side) {
        clock = new Date();
        const runId = `run_fw_accepted_${side}`;
        await owner.query(`INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, producer_kind,
          check_version, scenario_version, safety_constraints, provenance_json, created_at)
          VALUES ($1, $2, 'tg_fw_accepted', $3, $4, 'running', 'signed_probe', $5, $6, $7::jsonb, $8::jsonb, $9)`,
        [runId, tenantId, target.id, check.check_id, stamp.check_version, stamp.scenario_version,
          JSON.stringify({ assurance_scope: deriveAssuranceScope({ target, check }) }), JSON.stringify(stamp.provenance_json), clock]);
        const run = await repositories.validationEvidence.getTestRun(ctx, runId);
        const record = buildSignedProbeJobRecord({ run, check, target, now: clock,
          ownershipBinding: { state: 'dns_verified', kind: 'dns_txt', transitioned_at: declaredAt.toISOString() },
          probeWorkerSecret: 'local-firewall-regression-secret', newId: () => `job_fw_accepted_${side}` });
        await repositories.probeJobs.createProbeJob(ctx, record);
        await owner.query('UPDATE test_runs SET correlation_json = jsonb_build_object(\'nonce_hash\', $2::text) WHERE id = $1', [runId, record.nonce_hash]);
        const job = await repositories.probeJobs.claimPendingJobForWorker(worker, record.id, workerId, clock.toISOString());
        assert.ok(job, 'fixture is authorized for its original lease');
        const jobs = createPostgresProbeJobServices(repositories, { now: () => clock, resolveSourcePerspective });
        const grant = await jobs.reserveProbeExecution(worker, job.id, { leased_at: job.leased_at });
        assert.equal(grant.authorized, true, JSON.stringify(grant));
        clock = new Date();
        const resolvers = job.constraints.min_destination_resolver_attempts;
        const accepted = await jobs.ingestProbeResult(worker, job.id, { external_result: 'connected',
          metadata: { complete: true, tls_protocol: 'TLSv1.3', target_port: 443, pinned_address: '192.0.2.10' },
          safety_attestation: { requests_sent: 1 + resolvers, probe_requests_sent: 1, destination_resolver_attempts: resolvers,
            total_operations: 1 + resolvers, duration_ms: 1 } });
        assert.equal(accepted.error, undefined, JSON.stringify(accepted));
        assert.equal(accepted.probe_event.metadata.source_perspective, source);
        assert.equal(accepted.probe_event.metadata.execution_receipt.version, 'accepted-probe-execution.v1');
        observedIds.push(accepted.probe_event.id);
        await owner.query(`UPDATE test_runs SET status = 'completed', completed_at = $2 WHERE id = $1`, [runId, clock]);
        return runId;
      }
      const pre = await accept('pre');
      clock = new Date();
      const baseline = await services.captureFirewallBaseline(ctx, { change_id: expectation.change_id,
        expectation_ids: [expectation.id], test_run_ids: [pre] });
      assert.equal(baseline.error, undefined, JSON.stringify(baseline));
      const post = await accept('post');
      clock = new Date();
      const evaluation = await services.evaluateFirewallComparison(ctx, { baseline_id: baseline.id, post_test_run_ids: [post] });
      assert.equal(evaluation.error, undefined, JSON.stringify(evaluation));
      // Read after all server inserts, rather than before their immutable created_at values.
      clock = new Date(Date.now() + 100);
      const input = await repository.loadComparisonEvidence(ctx, { runIds: [pre, post], asOf: clock });
      assert.equal(input.input_complete, true);
      assert.ok(input.jobs.every((job) => /\+00:00$/.test(job.leased_at)), 'raw PostgreSQL JSON timestamps preserve +00:00 formatting');
      assert.equal(input.events.length, 2);
      const report = await services.getProtectionValidationReport(ctx);
      assert.equal(report.error, undefined, JSON.stringify(report));
      const row = report.conclusions.find((item) => item.subject.expectation_id === expectation.id);
      assert.equal(row.current_assurance.status, 'sampled_ingress_only', JSON.stringify(row.current_assurance));
      assert.equal(row.readiness_eligible, false);
      assert.equal(report.units.firewall_expectations.by_status.accepted, 1);
      await owner.query(`UPDATE targets SET port = 8443 WHERE id = 'tgt_fw_accepted'`);
      const changed = await services.getProtectionValidationReport(ctx);
      const changedRow = changed.conclusions.find((item) => item.subject.expectation_id === expectation.id);
      assert.equal(changedRow.current_assurance.status, 'not_established');
      assert.ok(changedRow.current_assurance.reasons.includes('target_definition_changed'));
      await owner.query(`UPDATE targets SET port = 443 WHERE id = 'tgt_fw_accepted'`);
      const before = JSON.stringify([input.runs, input.events, input.jobs, baseline, evaluation]);
      const revoked = await facade(probeSourceResolverFromEnv({ ASTRANULL_APPROVED_PROBE_SOURCES: '{}' })).getProtectionValidationReport(ctx);
      const denied = revoked.conclusions.find((item) => item.subject.expectation_id === expectation.id);
      assert.equal(denied.current_assurance.status, 'not_established');
      assert.ok(denied.current_assurance.reasons.includes('actual_firewall_source_unverified'));
      assert.equal(revoked.units.firewall_expectations.by_status.accepted, 0);
      const after = await repository.loadComparisonEvidence(ctx, { runIds: [pre, post], asOf: clock });
      assert.equal(JSON.stringify([after.runs, after.events, after.jobs, baseline, evaluation]), before, 'passive report reads do not mutate custody');
      const hidden = await repository.loadComparisonEvidence({ ...ctx, tenantId: 'ten_fw_other' }, { runIds: [pre, post], asOf: clock });
      assert.deepEqual(hidden.runs, []);
      assert.deepEqual(hidden.events, []);
      assert.deepEqual(hidden.jobs, []);
      const audits = await owner.query(`SELECT action FROM audit_logs WHERE tenant_id = $1 AND action IN
        ('probe_job.result_ingested', 'probe_job.execution_reserved') ORDER BY action`, [tenantId]);
      assert.equal(audits.rows.filter((item) => item.action === 'probe_job.result_ingested').length, 2);
      assert.equal(audits.rows.filter((item) => item.action === 'probe_job.execution_reserved').length, 2);
      assert.equal(observedIds.length, 2);
    } finally { await closePgPool(pool); }
  }, availability.env ?? process.env);
});
