import '../helpers/check-delivery-fixtures.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import { probeExecutionEvidenceReceipt } from '../../src/lib/probeExecution.mjs';
import { executeProbeForJob, buildResultBody } from '../../workers/probe-worker.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';
import { createHighScaleRepository } from '../../src/persistence/postgres/highScaleRepository.mjs';
import { createPostgresStateServices } from '../../src/persistence/postgres/stateServiceAdapters.mjs';
import { createPostgresValidationScanRepository } from '../../src/persistence/postgres/validationScanRepository.mjs';
import { createPostgresValidationScanServices } from '../../src/persistence/postgres/validationScanServiceAdapters.mjs';
import { createPgPool, closePgPool } from '../../src/persistence/postgres/pool.mjs';
import { listMigrationFiles, runMigrations } from '../../src/persistence/postgres/migrations.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { withEphemeralPostgres, ensureHarnessAppRole, withTenantContextAsAppRole, databaseUrlWithDatabase, resolvePostgresHarnessAvailability, MIGRATIONS_DIR } from '../helpers/pg-harness.mjs';
import { createCheckDeliveryFixtures, actualDeliveryReceipt, DELIVERY_RUNTIME, DELIVERY_CTX, DELIVERY_WORKER_CTX, DELIVERY_WORKER_SECRET } from '../helpers/check-delivery-fixtures.mjs';

// Only current safe catalog checks; no simulation, synthetic verdicts or historical
// imported evidence. Socket errors come from an actual owned peer reset.
const CASES = [
  { id: 'l7.expensive_endpoint.safe', scenario: 'success', expected: 'connected' },
  { id: 'waf.fingerprint.safe', scenario: 'error', expected: 'error' },
  { id: 'waf.evasion_body_gzip.safe', scenario: 'success', expected: 'not_run' },
  { id: 'l3.icmp_flood.readiness', scenario: 'success', expected: 'not_run' },
  { id: 'l7.hpack_bomb.readiness', scenario: 'success', expected: 'connected' },
  { id: 'l7.request_parser_size.posture', scenario: 'success', expected: 'connected' },
  { id: 'l7.password_reset.safe', scenario: 'success', expected: 'connected' },
];

test('real PostgreSQL signed scan survives observation -> peer error -> unsupported -> declaration -> later observation', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
  if (!availability.available) { t.skip(availability.reason); return; }
  const fixtures = await createCheckDeliveryFixtures();
  try {
    await withEphemeralPostgres(async (owner, context) => {
      // Apply current migrations. Never apply held 0079 (it is outside db/migrations).
      const files = listMigrationFiles(MIGRATIONS_DIR);
      assert.equal(files.some((file) => Number(file.name.slice(0, 4)) === 79), false);
      assert.ok(files.some((file) => file.name.startsWith('0080')));
      assert.ok(files.some((file) => file.name.startsWith('0081')));
      await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files });
      await ensureHarnessAppRole(owner);
      const initial = fixtures.forCheck(getCheckById(CASES[0].id), { targetKind: 'fqdn' });
      await owner.query(`INSERT INTO tenants (id, name) VALUES ($1, 'owned delivery test'), ('ten_delivery_other', 'other')`, [DELIVERY_CTX.tenantId]);
      await withTenantContext(owner, DELIVERY_CTX.tenantId, async (client) => {
        await client.query(`INSERT INTO target_groups (id, tenant_id, name, validation_mode, safety_policy) VALUES ('tg_1', $1, 'legacy persistence slot', 'external_only', '{"min_seconds_between_runs":0,"max_runs_per_hour":100}'::jsonb)`, [DELIVERY_CTX.tenantId]);
        await client.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, metadata_json) VALUES ('tgt_1', $1, 'tg_1', 'fqdn', 'grpc.test', 'grpc.test', $2::jsonb)`, [DELIVERY_CTX.tenantId, JSON.stringify({ port: initial.target.port })]);
        await client.query(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id) VALUES ('tv_delivery', $1, 'tgt_1', 'dns_verified', 'dns_txt', '{"owned_local_fixture":true}', now(), 'system', 'fixture_declaration')`, [DELIVERY_CTX.tenantId]);
      });
      const appUrl = new URL(databaseUrlWithDatabase(availability.env.ASTRANULL_DATABASE_URL, context.databaseName));
      appUrl.username = 'astranull_app'; appUrl.password = 'astranull_app_local_dev';
      const pool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl.toString() });
      try {
        const audit = createAuditRepository(pool);
        const repositories = { audit, ownershipVerifications: createOwnershipVerificationRepository(pool), highScale: createHighScaleRepository(pool), coreCatalog: createCoreCatalogRepository(pool), probeJobs: createProbeJobRepository(pool), validationEvidence: createValidationEvidenceRepository(pool), killSwitch: createKillSwitchRepository(pool), validationScans: createPostgresValidationScanRepository(pool, { auditRepository: audit }) };
        const validation = createPostgresValidationServices(repositories);
        const jobs = createPostgresProbeJobServices(repositories);
        const scans = createPostgresValidationScanServices(repositories, { testRuns: validation.testRuns, runtimeConfig: DELIVERY_RUNTIME });
        const created = await scans.createValidationScan(DELIVERY_CTX, { target_ids: ['tgt_1'], check_ids: CASES.map((entry) => entry.id) }, DELIVERY_RUNTIME);
        assert.equal(created.error, undefined, JSON.stringify(created));
        assert.equal(created.steps.length, CASES.length);
        const receipts = [];
        for (const entry of CASES) {
          const check = getCheckById(entry.id);
          const fixture = fixtures.forCheck(check, { targetKind: 'fqdn', scenario: entry.scenario });
          const scan = await scans.getValidationScan(DELIVERY_CTX, created.id);
          const step = scan.steps.find((row) => row.check_id === entry.id);
          assert.ok(step.test_run_id, JSON.stringify(scan));
          const [job] = await jobs.listPendingProbeJobsForWorker(DELIVERY_WORKER_CTX);
          assert.ok(job, JSON.stringify(step));
          assert.equal(job.test_run_id, step.test_run_id);
          assert.equal(job.check_id, entry.id);
          assert.equal(verifyProbeJobSignature(job, DELIVERY_WORKER_SECRET), true);
          assert.equal((await jobs.reserveProbeExecution({ ...DELIVERY_WORKER_CTX, tenantId: 'ten_delivery_other' }, job.id, { leased_at: job.leased_at })).status, 404);
          const reservation = await jobs.reserveProbeExecution(DELIVERY_WORKER_CTX, job.id, { leased_at: job.leased_at });
          assert.equal(reservation.authorized, true, JSON.stringify(reservation));
          const outcome = await executeProbeForJob(job, fixture.deps);
          assert.equal(outcome.external_result, entry.expected, JSON.stringify(outcome));
          const body = buildResultBody(job, outcome.external_result, outcome.metadata, outcome);
          assert.equal((await jobs.ingestProbeResult({ ...DELIVERY_WORKER_CTX, tenantId: 'ten_delivery_other' }, job.id, body)).status, 404);
          const accepted = await jobs.ingestProbeResult(DELIVERY_WORKER_CTX, job.id, body);
          assert.equal(accepted.error, undefined, JSON.stringify(accepted));
          await validation.testRuns.maybeFinalizeRunAfterProbeIngest(DELIVERY_CTX, job.test_run_id);
          let verdict = await repositories.validationEvidence.getVerdictForRun(DELIVERY_CTX, job.test_run_id);
          if (!verdict) {
            const finalized = await validation.testRuns.finalizeTestRun(DELIVERY_CTX, job.test_run_id, { force: true });
            assert.equal(finalized.error, undefined, JSON.stringify(finalized));
            verdict = finalized.verdict;
          }
          const run = await repositories.validationEvidence.getTestRun(DELIVERY_CTX, job.test_run_id);
          const events = await repositories.validationEvidence.listRunEvents(DELIVERY_CTX, run.id, { limit: 100 });
          assert.equal(events.length, 1);
          const event = events[0];
          const stored = await repositories.probeJobs.getJobById(DELIVERY_WORKER_CTX, job.id);
          assert.equal(event.metadata.execution_receipt.digest, probeExecutionEvidenceReceipt(stored, DELIVERY_WORKER_CTX.workerId, body.safety_attestation, outcome.external_result).digest);
          assert.equal(event.nonce_hash, job.nonce_hash);
          assert.equal(run.scan_id, created.id);
          assert.equal(run.scan_step_id, step.step_id);
          assert.equal(run.check_id, check.check_id);
          assert.equal(run.status, 'verdicted');
          assert.equal(verdict.verdict, 'inconclusive');
          assert.equal(verdict.confidence, 'external_only');
          assert.ok(verdict.evidence_ids.includes(event.id));
          const readiness = (await createPostgresStateServices(repositories, { catalog: CASES.map((row) => getCheckById(row.id)) }).getState(DELIVERY_CTX)).readiness;
          assert.equal(readiness.coverage.passed_count, 0);
          const visible = await withTenantContextAsAppRole(owner, 'ten_delivery_other', (client) => client.query('SELECT id FROM test_runs WHERE id=$1', [run.id]));
          assert.equal(visible.rows.length, 0);
          await fixture.waitForWire(outcome);
          const receipt = actualDeliveryReceipt(check, { run, job: stored, event, verdict, outcome, body, readiness, reservation, wire: fixture.wire() });
          receipt.transport_routes = fixture.routes();
          receipt.declared_target = structuredClone(job.target);
          receipts.push(receipt);
          await scans.advanceScan(DELIVERY_CTX, created.id, { runtimeConfig: DELIVERY_RUNTIME });
        }
        const final = await scans.getValidationScan(DELIVERY_CTX, created.id);
        assert.equal(final.status, 'completed');
        assert.equal(final.steps.length, CASES.length);
        assert.ok(final.steps.every((step) => ['completed', 'verdicted'].includes(step.status)), JSON.stringify(final.steps));
        assert.equal(new Set(receipts.map((row) => row.job_id)).size, CASES.length);
        assert.equal(new Set(receipts.map((row) => row.run_id)).size, CASES.length);
        const counts = await withTenantContextAsAppRole(owner, DELIVERY_CTX.tenantId, (client) => client.query(`SELECT (SELECT count(*) FROM events)::int events, (SELECT count(*) FROM verdicts)::int verdicts, (SELECT count(*) FROM findings)::int findings, (SELECT count(*) FROM audit_logs WHERE action='probe_job.execution_reserved')::int reservations`));
        assert.deepEqual(counts.rows[0], { events: CASES.length, verdicts: CASES.length, findings: 0, reservations: CASES.length });
        t.diagnostic(JSON.stringify({ lifecycle: 'check-delivery-postgres.v1', scan_id: created.id, receipts }));
      } finally { await closePgPool(pool); }
    }, availability.env, { applyMigrations: false });
  } finally { await fixtures.close(); }
});
