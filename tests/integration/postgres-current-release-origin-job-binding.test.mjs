/**
 * Postgres parity for the current-release origin job binding slice (handoff:
 * backend-bound-job-fidelity / root-history-confirmed-review findings 1 and 6).
 *
 * Covered against the real ephemeral database (RLS app role, real repositories):
 *  1. A bound signed-worker start captures ONLY the server-validated approved scope
 *     (exact existing binding, both current proofs) in provenance_json.origin_scope, and
 *     the signed probe job serializes exactly that Host/SNI/port/path while the socket
 *     destination stays the independently verified origin IP literal.
 *  2. Dispatch recovery (repairSignedDispatch) rebuilds a lost probe job by signing the
 *     approved scope from the persisted run provenance snapshot — not from caller input.
 *  3. Stamped runs finalize against the immutable expected_behavior_json snapshot taken at
 *     start even when the live catalog drifts; legacy unstamped runs keep the truthful
 *     today-catalog fallback and stamped null snapshots stay inconclusive (never a phantom
 *     PASS).
 *  4. List/detail verdict authority: published same-tenant verdict records only.
 *
 * No sockets, no DNS: this suite only exercises control-plane serialization, signing, and
 * finalization; the signed job is never executed against a network destination.
 */
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { recordProbeResultEdgeDetection } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { createTargetHistoryRepository } from '../../src/persistence/postgres/targetHistoryRepository.mjs';
import { createPostgresTargetHistoryServices } from '../../src/persistence/postgres/targetHistoryServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPostgresValidationScanRepository } from '../../src/persistence/postgres/validationScanRepository.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
import {
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const SECRET = 'a'.repeat(32);
const SIGNED_WORKER = { probeMode: 'signed-worker', probeWorkerSecret: SECRET };
const TENANT = 'ten_origin_binding';
const GROUP = 'tg_origin_binding';
const ENVIRONMENT = 'env_origin_binding';
const ORIGIN = 'tgt_origin_literal';
const PROTECTED = 'tgt_protected_host';
const CHECK_ID = 'origin.direct_reachability.safe';
const DECLARED = new Date('2026-09-01T00:00:00.000Z');
const CTX = { tenantId: TENANT, userId: 'usr_origin_binding', role: 'admin' };
const SCAN_ID = 'vscan_origin_binding';
const STEP_ID = 'vstep_origin_binding';
const LEASE_TOKEN = 'lease_origin_binding';
const APPROVED_SCOPE = Object.freeze({
  host: 'app.example',
  sni: 'app.example',
  port: 8443,
  path: '/health',
});

async function seedTenant(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'origin binding tenant')`, [TENANT]);
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'prod')`, [ENVIRONMENT, TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, validation_mode, safety_policy)
       VALUES ($1, $2, $3, 'origin binding group', 'external_only',
               '{"min_seconds_between_runs": 0, "max_runs_per_hour": 100}'::jsonb)`,
      [GROUP, TENANT, ENVIRONMENT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at, declaration_json, metadata_json)
       VALUES ($1, $2, $3, 'ip', '203.0.113.10', '203.0.113.10', $5::timestamptz, '{}'::jsonb, $7::jsonb),
              ($4, $2, $3, 'fqdn', 'app.example', 'app.example', $5::timestamptz,
               $6::jsonb, '{}'::jsonb)`,
      [ORIGIN, TENANT, GROUP, PROTECTED, DECLARED, JSON.stringify({
        allowed_scope: { ports: [8443], paths: ['/health'] },
      }), JSON.stringify({ direct_origin_ip: '198.51.100.99' })],
    );
    await client.query(
      `INSERT INTO target_verifications (
         id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id
       ) VALUES
         ('ver_origin_binding', $1, $2, 'dns_verified', 'dns_txt', '{}'::jsonb, $3::timestamptz, 'usr_origin_binding', 'aud_seed'),
         ('ver_protected_binding', $1, $4, 'dns_verified', 'dns_txt', '{}'::jsonb, $3::timestamptz, 'usr_origin_binding', 'aud_seed')`,
      [TENANT, ORIGIN, DECLARED, PROTECTED],
    );
    await client.query(
      `INSERT INTO validation_scans (id, tenant_id, target_group_id, status, check_ids, lease_token, lease_owner, lease_expires_at)
       VALUES ($1, $2, $3, 'running', $4::jsonb, $5, 'origin-binding-test', now() + interval '1 hour')`,
      [SCAN_ID, TENANT, GROUP, JSON.stringify([CHECK_ID]), LEASE_TOKEN],
    );
    await client.query(
      `INSERT INTO validation_scan_steps (id, tenant_id, scan_id, position, check_id, target_id, status)
       VALUES ($1, $2, $3, 1, $4, $5, 'starting')`,
      [STEP_ID, TENANT, SCAN_ID, CHECK_ID, ORIGIN],
    );
  });
}

function buildServices(pool) {
  const audit = createAuditRepository(pool);
  const repositories = {
    validationEvidence: createValidationEvidenceRepository(pool),
    audit,
    coreCatalog: createCoreCatalogRepository(pool),
    probeJobs: createProbeJobRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
    ownershipVerifications: createOwnershipVerificationRepository(pool),
    validationScans: createPostgresValidationScanRepository(pool, { auditRepository: audit }),
  };
  const validation = createPostgresValidationServices(repositories);
  const history = createPostgresTargetHistoryServices({
    repository: createTargetHistoryRepository(pool),
    audit,
  });
  return { validation, testRuns: validation.testRuns, history, repositories };
}

async function createBinding(history) {
  const binding = await history.createOriginBinding(CTX, {
    protected_target_id: PROTECTED,
    origin_target_id: ORIGIN,
  }, { now: DECLARED });
  assert.equal(binding.error, undefined, JSON.stringify(binding));
  assert.equal(binding.status, 'active');
  assert.equal(binding.host, APPROVED_SCOPE.host);
  assert.equal(binding.sni, APPROVED_SCOPE.sni);
  assert.equal(binding.port, APPROVED_SCOPE.port);
  assert.equal(binding.path, APPROVED_SCOPE.path);
  assert.equal(binding.currently_authorized, true, 'both current proofs must authorize the binding');
  return binding;
}

function boundStartBody(bindingId) {
  return {
    check_id: CHECK_ID,
    target_group_id: GROUP,
    target_id: ORIGIN,
    origin_binding_id: bindingId,
    // Untrusted caller input that must not reach signed Host/SNI/port/path selection.
    probe_profile: { protected_host: 'other.example' },
  };
}

async function readJob(repositories, runId) {
  return repositories.probeJobs.getProbeJobByTestRun(CTX, runId);
}

async function readAudits(pool, action) {
  return withTenantContext(pool, TENANT, async (client) => {
    const { rows } = await client.query(
      `SELECT metadata_json FROM audit_logs WHERE tenant_id = $1 AND action = $2 ORDER BY sequence`,
      [TENANT, action],
    );
    return rows;
  });
}

async function seedExternalProbeEvidence(pool, runId, nonceHash, externalResult) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO events (
         id, tenant_id, test_run_id, target_id, check_id, source, signal_type,
         producer_kind, nonce_hash, timestamp, metadata_json
       ) VALUES ($1, $2, $3, $4, $5, 'probe_worker', 'probe_result',
                 'signed_probe', $6, now(), $7::jsonb)`,
      [`evt_probe_${runId}`, TENANT, runId, ORIGIN, CHECK_ID, nonceHash,
        JSON.stringify({ external_result: externalResult })],
    );
    await client.query(
      `UPDATE test_runs SET status = 'collecting', probe_external_result = $3
       WHERE tenant_id = $1 AND id = $2`,
      [TENANT, runId, externalResult],
    );
  });
}

async function seedRunRow(pool, runId, overrides = {}) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(
      `INSERT INTO test_runs (
         id, tenant_id, target_group_id, target_id, check_id, status,
         probe_external_result, remediation_template, safety_constraints,
         correlation_json, started_at, completed_at, created_at,
         producer_kind, expected_behavior_json, provenance_json
       ) VALUES (
         $1, $2, $3, $4, $5, 'collecting', $6, 'block_origin', '{}'::jsonb,
         jsonb_build_object('nonce_hash', $7::text, 'window_ms', 120000),
         now(), now(), now(), $8, $9::jsonb, $10::jsonb
       )`,
      [
        runId, TENANT, GROUP, ORIGIN, overrides.check_id ?? CHECK_ID,
        overrides.probe_external_result ?? 'connected',
        overrides.nonce_hash ?? `nonce_${runId}`,
        overrides.producer_kind ?? null,
        JSON.stringify(overrides.expected_behavior_json ?? null),
        JSON.stringify(overrides.provenance_json ?? null),
      ],
    );
  });
}

for (const side of ['origin', 'protected']) {
  it(`postgres ${side}-side grant locks both current descriptors/proofs and exact immutable scope`, { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) return t.skip(availability.reason);
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedTenant(pool);
      await withTenantContext(pool, TENANT, (client) => client.query(`UPDATE targets SET metadata_json =
        jsonb_build_object('control_declarations', jsonb_build_object('version', 1, 'origin', jsonb_build_object('lockdown_expected', true)))
        WHERE tenant_id = $1 AND id = $2`, [TENANT, PROTECTED]));
      const { testRuns, history, repositories } = buildServices(pool);
      const binding = await createBinding(history);
      const body = side === 'origin' ? boundStartBody(binding.id) : {
        check_id: 'nfw.origin_lockdown.safe', target_group_id: GROUP, target_id: PROTECTED,
      };
      const started = await testRuns.startTestRun(CTX, body, SIGNED_WORKER);
      assert.equal(started.error, undefined, JSON.stringify(started));
      const worker = { tenantId: TENANT, workerId: 'grant_worker' };
      const [job] = await repositories.probeJobs.leasePendingJobsForWorker(worker, worker.workerId);
      assert.ok(job, 'signed job is leased without making a socket');
      const reserve = (client) => repositories.probeJobs.reserveExecution(worker, job, { id: 'fixture_reservation' }, { client });
      await withTenantContext(pool, TENANT, async (client) => {
        for (const [label, statement, params] of [
          ['binding archive', `UPDATE origin_bindings SET status = 'archived', archived_at = now() WHERE tenant_id = $1 AND id = $2`, [TENANT, binding.id]],
          ['origin soft delete', `UPDATE targets SET deleted_at = now() WHERE tenant_id = $1 AND id = $2`, [TENANT, ORIGIN]],
          ['protected soft delete', `UPDATE targets SET deleted_at = now() WHERE tenant_id = $1 AND id = $2`, [TENANT, PROTECTED]],
          ['policy archive', `UPDATE target_groups SET archived_at = now() WHERE tenant_id = $1 AND id = $2`, [TENANT, GROUP]],
          ['origin destination drift', `UPDATE targets SET value = '93.184.216.35' WHERE tenant_id = $1 AND id = $2`, [TENANT, ORIGIN]],
          ['protected Host drift', `UPDATE targets SET value = 'other.example' WHERE tenant_id = $1 AND id = $2`, [TENANT, PROTECTED]],
          ['protected port drift', `UPDATE targets SET port = 9443 WHERE tenant_id = $1 AND id = $2`, [TENANT, PROTECTED]],
          ['declared port drift', `UPDATE targets SET declaration_json = '{"allowed_scope":{"ports":[443],"paths":["/health"]}}' WHERE tenant_id = $1 AND id = $2`, [TENANT, PROTECTED]],
          ['declared path drift', `UPDATE targets SET declaration_json = '{"allowed_scope":{"ports":[8443],"paths":["/other"]}}' WHERE tenant_id = $1 AND id = $2`, [TENANT, PROTECTED]],
          ...[ORIGIN, PROTECTED].map((id) => [`${id} proof revoked`, `INSERT INTO target_verifications
            (id,tenant_id,target_id,state,source_kind,source_ref,transitioned_at,transitioned_by,audit_entry_id)
            VALUES ($1,$2,$3,'unverified','manual_override','{}',now(),'system','audit_fixture')`, [`revoked_${id}`, TENANT, id]]),
        ]) {
          await client.query('SAVEPOINT before_authority_change');
          await client.query(statement, params);
          assert.equal(await reserve(client), null, label);
          await client.query('ROLLBACK TO SAVEPOINT before_authority_change');
        }
        assert.ok(await reserve(client), 'unchanged exact current authority grants once');
      });
      const stored = await repositories.probeJobs.getJobById(CTX, job.id);
      assert.equal(stored.worker_metadata.execution_reservation.id, 'fixture_reservation');
      // The real accepted-result history producer must bind either execution side
      // to the same immutable evidence, without a sibling-target history lookup.
      const observedAt = new Date().toISOString();
      await recordProbeResultEdgeDetection(repositories.validationEvidence, CTX, {
        run: started.run, job, observedAt,
        probeMetadata: { external_result: 'connected', source_completed_at: observedAt },
      });
      const portal = createPortalRevampRepository(pool);
      const assertBothViews = async (authorized) => {
        const assessed = await history.assessOriginReachability(CTX, binding.id);
        assert.equal(assessed.historical_evidence_valid, true, JSON.stringify(assessed));
        assert.equal(assessed.currently_authorized, authorized);
        assert.equal(assessed.test_run_id, started.run.id);
        for (const targetId of [ORIGIN, PROTECTED]) {
          const detail = await portal.getTargetDetailBundle(CTX, targetId);
          const projected = detail.protection_profile.origin_bindings.find((row) => row.id === binding.id);
          assert.deepEqual(projected.reachability, assessed, `${side} evidence is identical on ${targetId}`);
          assert.equal(projected.reachability.target_id, job.target_id);
          assert.equal(projected.reachability.actual_destination, '203.0.113.10');
          assert.equal(projected.reachability.assurance, 'none');
        }
      };
      await assertBothViews(true);
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query('SAVEPOINT before_counterpart_revocation');
        await client.query(`INSERT INTO target_verifications
          (id,tenant_id,target_id,state,source_kind,source_ref,transitioned_at,transitioned_by,audit_entry_id)
          VALUES ('revoked_history_counterpart',$1,$2,'unverified','manual_override','{}',now(),'system','audit_fixture')`,
        [TENANT, side === 'origin' ? PROTECTED : ORIGIN]);
        await assertBothViews(false);
        await client.query('ROLLBACK TO SAVEPOINT before_counterpart_revocation');
      });
      const archived = await history.archiveOriginBinding(CTX, binding.id);
      await assertBothViews(false);
      assert.equal(archived.status, 'archived');
      const cancelledRun = await repositories.validationEvidence.getTestRun(CTX, started.run.id);
      assert.equal(cancelledRun.status, 'cancelled');
      assert.equal((await repositories.probeJobs.getJobById(CTX, job.id)).status, 'cancelled');
      assert.equal(await repositories.probeJobs.reserveExecution(worker, job, { id: 'never_after_archive' }), null);
      assert.deepEqual(cancelledRun.provenance_json, started.run.provenance_json, 'archival never rewrites immutable historical scope');
    });
  });
}

for (const method of ['HEAD', 'GET']) {
  it(`postgres reviewed paired ${method} start captures both proofs and grant rejects either proof-reference drift`, { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) return t.skip(availability.reason);
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedTenant(pool);
      const runtimeConfig = { ...SIGNED_WORKER, featureFlags: { protectionValidationEnabled: true } };
      const runtime = await createPostgresRuntime({ ...process.env, NODE_ENV: 'test',
        ASTRANULL_PERSISTENCE_MODE: 'postgres', ASTRANULL_DATABASE_URL: pool.options.connectionString,
        ASTRANULL_PROTECTION_VALIDATION_ENABLED: '1', ASTRANULL_APPROVED_PROBE_SOURCES: '' }, {
        createPool: () => pool, closePool: async () => {}, entryPathComparisonRuntimeConfig: runtimeConfig,
      });
      try {
        const { history, repositories } = buildServices(pool);
        const binding = await createBinding(history);
        const pv = runtime.services.protectionValidation;
        const entry = await pv.createEntryPath(CTX, PROTECTED, { entry_target_id: ORIGIN,
          relation_kind: 'origin', origin_binding_id: binding.id, owner: 'App team', purpose: 'Reviewed identity',
          expected_behavior: 'must_not_be_reachable', required_layers: [] });
        assert.equal(entry.error, undefined, JSON.stringify(entry));
        const paths = await pv.listEntryPaths(CTX, PROTECTED, { limit: 10 });
        const entryId = paths.items.find((row) => row.entry_target_id === ORIGIN).id;
        const request = { mode: 'plan', anchor_target_id: PROTECTED, primary_entry_path_id: entryId, entry_path_ids: [entryId],
          expectation: { scenario: `origin.identity_pair.${method.toLowerCase()}.v1`, layer_outcomes: { waf: 'no_expectation' } } };
        const plan = await pv.planOrStartEntryPathComparison(CTX, request, { runtimeConfig });
        assert.equal(plan.error, undefined, JSON.stringify(plan));
        assert.equal(plan.items[0].paired_plan.method, method);
        const started = await pv.planOrStartEntryPathComparison(CTX, { ...request, mode: 'start', reviewed_plan_digest: plan.plan_digest }, { runtimeConfig });
        assert.equal(started.error, undefined, JSON.stringify(started));
        const worker = { tenantId: TENANT, workerId: 'pg_pair_worker' };
        const [job] = await repositories.probeJobs.leasePendingJobsForWorker(worker, worker.workerId);
        assert.ok(job, JSON.stringify(started));
        assert.equal(verifyProbeJobSignature(job, SECRET), true);
        const run = await repositories.validationEvidence.getTestRun(CTX, job.test_run_id);
        assert.deepEqual(job.constraints.origin_identity_pair, run.provenance_json.origin_identity_pair);
        assert.equal(job.constraints.origin_identity_pair.origin_ownership_binding.target_id, ORIGIN);
        assert.equal(job.constraints.origin_identity_pair.protected_ownership_binding.target_id, PROTECTED);
        await withTenantContext(pool, TENANT, async (client) => {
          for (const targetId of [ORIGIN, PROTECTED]) {
            await client.query('SAVEPOINT before_pair_proof_drift');
            await client.query(`UPDATE target_verifications SET source_ref = '{"challenge":"different"}'
              WHERE tenant_id=$1 AND target_id=$2`, [TENANT, targetId]);
            assert.equal(await repositories.probeJobs.reserveExecution(worker, job, { id: 'pair_proof_drift' }, { client }), null,
              `${targetId} proof-source drift cannot reuse the reviewed signed authority`);
            await client.query('ROLLBACK TO SAVEPOINT before_pair_proof_drift');
          }
          assert.ok(await repositories.probeJobs.reserveExecution(worker, job, { id: 'pair_authority_unchanged' }, { client }));
        });
      } finally { await runtime.close(); }
    }, availability.env ?? process.env);
  });
}

async function waitForDatabaseWaiter(pool, blockingPid) {
  const deadline = Date.now() + 5000;
  do {
    const { rows } = await pool.query(`SELECT EXISTS (
      SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))
    ) AS waiting`, [blockingPid]);
    if (rows[0].waiting) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  } while (Date.now() < deadline);
  assert.fail('the concurrent authority mutation must contend on the held database locks');
}

for (const side of ['origin', 'protected']) {
  it(`postgres ${side}-side concurrent counterpart revocation and archive serialize with durable grants`, { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) return t.skip(availability.reason);
    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedTenant(pool);
      await withTenantContext(pool, TENANT, (client) => client.query(`UPDATE targets SET metadata_json =
        '{"control_declarations":{"version":1,"origin":{"lockdown_expected":true}}}' WHERE tenant_id=$1 AND id=$2`, [TENANT, PROTECTED]));
      const { testRuns, history, repositories } = buildServices(pool);
      const binding = await createBinding(history);
      const started = await testRuns.startTestRun(CTX, side === 'origin' ? boundStartBody(binding.id) : {
        check_id: 'nfw.origin_lockdown.safe', target_group_id: GROUP, target_id: PROTECTED,
      }, SIGNED_WORKER);
      assert.equal(started.error, undefined, JSON.stringify(started));
      const worker = { tenantId: TENANT, workerId: 'concurrent_grant_worker' };
      const [job] = await repositories.probeJobs.leasePendingJobsForWorker(worker, worker.workerId);
      const held = await pool.connect();
      let pending;
      try {
        await held.query('BEGIN');
        await held.query(`SELECT set_config('app.tenant_id', $1, true)`, [TENANT]);
        const { rows: [{ pid }] } = await held.query('SELECT pg_backend_pid() AS pid');
        const counterpart = side === 'origin' ? PROTECTED : ORIGIN;
        await held.query(`INSERT INTO target_verifications
          (id,tenant_id,target_id,state,source_kind,source_ref,transitioned_at,transitioned_by,audit_entry_id)
          VALUES ('concurrent_revoke',$1,$2,'unverified','manual_override','{}',now(),'system','audit_fixture')`, [TENANT, counterpart]);
        pending = repositories.probeJobs.reserveExecution(worker, job, { id: 'revocation_must_win' });
        await waitForDatabaseWaiter(pool, pid);
        await held.query('COMMIT');
        assert.equal(await pending, null, 'revocation commits before the blocked grant revalidates both proofs');
        pending = null;
        await withTenantContext(pool, TENANT, (client) => client.query(`INSERT INTO target_verifications
          (id,tenant_id,target_id,state,source_kind,source_ref,transitioned_at,transitioned_by,audit_entry_id)
          VALUES ('concurrent_restore',$1,$2,'dns_verified','dns_txt','{}',now(),'system','audit_fixture')`, [TENANT, counterpart]));
        await held.query('BEGIN');
        await held.query(`SELECT set_config('app.tenant_id', $1, true)`, [TENANT]);
        assert.ok(await repositories.probeJobs.reserveExecution(worker, job, { id: 'grant_before_archive' }, { client: held }));
        pending = history.archiveOriginBinding(CTX, binding.id);
        await waitForDatabaseWaiter(pool, pid);
        await held.query('COMMIT');
        assert.equal((await pending).status, 'archived');
        pending = null;
        assert.equal((await repositories.probeJobs.getJobById(CTX, job.id)).status, 'cancelled');
        assert.equal((await repositories.validationEvidence.getTestRun(CTX, started.run.id)).status, 'cancelled');
        assert.equal(await repositories.probeJobs.reserveExecution(worker, job, { id: 'after_archive' }), null);
      } finally {
        await held.query('ROLLBACK');
        held.release();
        if (pending) await pending.catch(() => {});
      }
    }, availability.env ?? process.env);
  });
}

describe('postgres origin job binding (signed scope serialization + snapshot finalization)', () => {
  it('signs the validated origin scope at start, recovers it on repair, and finalizes on the start snapshot', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedTenant(pool);
      const { testRuns, history, repositories } = buildServices(pool);
      const binding = await createBinding(history);

      // --- 1. Real bound signed-worker start ---
      const started = await testRuns.startTestRun(CTX, boundStartBody(binding.id), SIGNED_WORKER, {
        scanDispatch: { scan_id: SCAN_ID, step_id: STEP_ID, lease_token: LEASE_TOKEN },
      });
      assert.equal(started.error, undefined, JSON.stringify(started));
      const runId = started.run.id;

      // Scope snapshot captured at start in the provenance stamp.
      assert.deepEqual(started.run.provenance_json.origin_scope, APPROVED_SCOPE);
      assert.equal(started.run.producer_kind, 'signed_probe');
      assert.equal(started.run.expected_behavior_json.value, 'must_block_before_origin');
      assert.equal(started.run.origin_binding_id, binding.id);

      let job = await readJob(repositories, runId);
      assert.ok(job, 'signed probe job persisted');
      // Socket destination remains the independently verified target-bound origin IP.
      assert.equal(job.target.value, '203.0.113.10');
      assert.equal(job.target.kind, 'ip');
      // Untrusted body profile values cannot retarget the logical Host/SNI/port/path.
      assert.equal(job.probe_profile.protected_host, APPROVED_SCOPE.host);
      assert.equal(job.probe_profile.direct_ip, undefined);
      assert.equal(JSON.stringify(job).includes('198.51.100.99'), false);
      assert.deepEqual(job.constraints.origin_scope, APPROVED_SCOPE);
      assert.equal(verifyProbeJobSignature(job, SECRET), true);

      // Tampering with any signed scope carrier kills the signature.
      const tamperedScope = structuredClone(job);
      tamperedScope.constraints.origin_scope.host = 'evil.example';
      assert.equal(verifyProbeJobSignature(tamperedScope, SECRET), false);
      const tamperedProfile = structuredClone(job);
      tamperedProfile.probe_profile.protected_host = 'evil.example';
      assert.equal(verifyProbeJobSignature(tamperedProfile, SECRET), false);
      const tamperedTarget = structuredClone(job);
      tamperedTarget.target.value = '198.51.100.99';
      assert.equal(verifyProbeJobSignature(tamperedTarget, SECRET), false);

      // --- 2. Dispatch recovery rebuilds the job from the persisted provenance snapshot ---
      // Realistic lost-dispatch crash: the job row never committed AND the run correlation
      // update never landed, so the repair must rebuild and re-bind the run nonce.
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `UPDATE test_runs
           SET correlation_json = jsonb_build_object('window_ms', 120000), awaiting_external_probe = FALSE
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, runId],
        );
        await client.query(`DELETE FROM probe_jobs WHERE tenant_id = $1 AND test_run_id = $2`, [TENANT, runId]);
      });
      const repaired = await testRuns.startTestRun(CTX, boundStartBody(binding.id), SIGNED_WORKER, {
        scanDispatch: { scan_id: SCAN_ID, step_id: STEP_ID, lease_token: LEASE_TOKEN },
      });
      assert.equal(repaired.error, undefined, JSON.stringify(repaired));
      assert.equal(repaired.idempotent_replay, true);
      assert.equal(repaired.dispatch_repaired, true);
      job = await readJob(repositories, runId);
      assert.ok(job, 'recovery rebuilt the lost probe job');
      assert.deepEqual(job.constraints.origin_scope, APPROVED_SCOPE);
      assert.equal(job.probe_profile.protected_host, APPROVED_SCOPE.host);
      assert.equal(job.target.value, '203.0.113.10');
      assert.equal(verifyProbeJobSignature(job, SECRET), true);
      const recoveryAudits = await readAudits(pool, 'probe_job.dispatch_recovered');
      assert.equal(recoveryAudits.length, 1);
      assert.equal(recoveryAudits[0].metadata_json.test_run_id, runId);
      assert.equal(recoveryAudits[0].metadata_json.probe_job_recreated, true);

      // --- 3a. Stamped bound run finalizes on its own start snapshot ---
      const nonce = job.nonce_hash;
      await seedExternalProbeEvidence(pool, runId, nonce, 'connected');
      const check = getCheckById(CHECK_ID);
      assert.equal(check.default_expected_behavior, 'must_block_before_origin');
      const finalized = await testRuns.finalizeTestRun(CTX, runId, { force: true });
      assert.equal(finalized?.error, undefined, JSON.stringify(finalized));
      assert.equal(finalized.verdict.verdict, 'inconclusive');
      assert.match(finalized.verdict.explanation, /transport or liveness metadata only|observation only/);

      // --- 3b. Catalog drifts after start; a new stamped run keeps the start snapshot ---
      const drifted = await testRuns.startTestRun(
        CTX,
        { check_id: CHECK_ID, target_group_id: GROUP, target_id: ORIGIN },
        { probeMode: 'simulation' },
      );
      assert.equal(drifted.error, undefined, JSON.stringify(drifted));
      try {
        check.default_expected_behavior = 'must_reach_canary';
        assert.equal(drifted.run.expected_behavior_json.value, 'must_block_before_origin', 'start snapshot ignores later catalog drift');
        const driftedFinalize = await testRuns.finalizeTestRun(CTX, drifted.run.id, { force: true });
        assert.equal(driftedFinalize.verdict.verdict, 'inconclusive', 'the immutable snapshot survives drift, but simulation and liveness never establish assurance');

        // --- 3c. Legacy unstamped run keeps the truthful today-catalog fallback ---
        await seedRunRow(pool, 'run_pg_legacy', {
          probe_external_result: 'connected',
          producer_kind: null,
          expected_behavior_json: null,
        });
        const legacy = await testRuns.finalizeTestRun(CTX, 'run_pg_legacy', { force: true });
        assert.equal(legacy.verdict.verdict, 'inconclusive', 'legacy liveness cannot become technical assurance from the current catalog');

        // --- 3d. Stamped run with no recorded snapshot stays inconclusive, never a phantom PASS ---
        await seedRunRow(pool, 'run_pg_null_snapshot', {
          probe_external_result: 'connected',
          producer_kind: 'signed_probe',
          expected_behavior_json: null,
        });
        const unrecorded = await testRuns.finalizeTestRun(CTX, 'run_pg_null_snapshot', { force: true });
        assert.equal(unrecorded.verdict.verdict, 'inconclusive');
        assert.match(unrecorded.verdict.explanation, /transport or liveness metadata only|observation only/);
      } finally {
        check.default_expected_behavior = 'must_block_before_origin';
      }

      // --- 4. List/detail verdict authority: published same-tenant verdict records only ---
      const listed = await testRuns.listTestRuns(CTX, { target_id: ORIGIN });
      const verdicted = listed.filter((row) => row.verdict != null);
      assert.equal(verdicted.length >= 3, true, 'finalized runs carry their published verdict');
      for (const row of verdicted) {
        assert.equal(typeof row.verdict.verdict, 'string');
        assert.equal(row.verdict.test_run_id, row.id);
      }
      // A completed run with no published verdict record projects null, never an invented PASS.
      await seedRunRow(pool, 'run_pg_completed_no_verdict', {
        probe_external_result: 'connected',
        producer_kind: 'signed_probe',
        expected_behavior_json: { value: 'must_block_before_origin', source: 'catalog_default', check_id: CHECK_ID, check_version: '1.0.0' },
      });
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `UPDATE test_runs SET status = 'completed', completed_at = now()
           WHERE tenant_id = $1 AND id = 'run_pg_completed_no_verdict'`,
          [TENANT],
        );
      });
      const completedNoVerdict = (await testRuns.listTestRuns(CTX, {}))
        .find((row) => row.id === 'run_pg_completed_no_verdict');
      assert.ok(completedNoVerdict);
      assert.equal(completedNoVerdict.verdict, null, 'completed status never invents a verdict');
    }, availability.env ?? process.env);
  });

  it('fails closed: a bound legacy recovery run without its stored approved scope is reported blocked, never re-signed', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await seedTenant(pool);
      const { testRuns, history, repositories } = buildServices(pool);
      const binding = await createBinding(history);

      // A bound legacy/recovery run whose provenance stamp lost its approved scope.
      // It is bound to a live scan dispatch so startTestRun reaches repairSignedDispatch.
      const runId = 'run_pg_bound_missing_scope';
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `INSERT INTO test_runs (
             id, tenant_id, target_group_id, target_id, check_id, status,
             remediation_template, safety_constraints, correlation_json,
             started_at, created_at, producer_kind, origin_binding_id,
             scan_id, scan_step_id, provenance_json, expected_behavior_json
           ) VALUES (
             $1, $2, $3, $4, $5, 'running', 'block_origin', '{}'::jsonb,
             jsonb_build_object('window_ms', 120000),
             now(), now(), 'signed_probe', $6,
             $7, $8, '{}'::jsonb, $9::jsonb
           )`,
          [runId, TENANT, GROUP, ORIGIN, CHECK_ID, binding.id, SCAN_ID, STEP_ID,
            JSON.stringify({ value: 'must_block_before_origin', source: 'catalog_default', check_id: CHECK_ID, check_version: '1.0.0' })],
        );
      });

      const runsBefore = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(`SELECT count(*)::int AS n FROM test_runs WHERE tenant_id = $1`, [TENANT]);
        return rows[0].n;
      });

      // Replay with caller input that would happily re-target the scope if it were trusted.
      const replay = await testRuns.startTestRun(
        CTX,
        {
          check_id: CHECK_ID,
          target_group_id: GROUP,
          target_id: ORIGIN,
          origin_binding_id: binding.id,
          probe_profile: { protected_host: 'different.example' },
        },
        SIGNED_WORKER,
        { scanDispatch: { scan_id: SCAN_ID, step_id: STEP_ID, lease_token: LEASE_TOKEN } },
      );
      assert.deepEqual(
        { error: replay.error, status: replay.status, retryable: replay.retryable },
        { error: 'probe_dispatch_recovery_scope_blocked', status: 503, retryable: false },
      );

      // No unsafe job was created, signed, or dispatched.
      assert.equal(await readJob(repositories, runId), null, 'no probe job exists for the blocked recovery');
      const jobCount = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(
          `SELECT count(*)::int AS n FROM probe_jobs WHERE tenant_id = $1 AND test_run_id = $2`,
          [TENANT, runId],
        );
        return rows[0].n;
      });
      assert.equal(jobCount, 0);

      // The blocked recovery is audited with the truthful reason.
      const blockedAudits = await readAudits(pool, 'probe_job.dispatch_recovery_blocked');
      assert.equal(blockedAudits.length, 1);
      assert.equal(blockedAudits[0].metadata_json.reason, 'bound_run_missing_approved_origin_scope');
      assert.equal(blockedAudits[0].metadata_json.origin_binding_id, binding.id);

      // The run intent is not orphaned: no second run was created, and the scan-recovery
      // contract marks the bound run truthfully terminal (dispatch_failed) instead of
      // re-dispatching it on an untrusted scope. Nothing was silently re-signed.
      const runsAfter = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(`SELECT count(*)::int AS n FROM test_runs WHERE tenant_id = $1`, [TENANT]);
        return rows[0].n;
      });
      assert.equal(runsAfter, runsBefore, 'recovery never creates a duplicate run intent');
      const seededRun = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(
          `SELECT status, summary_json FROM test_runs WHERE tenant_id = $1 AND id = $2`,
          [TENANT, runId],
        );
        return rows[0] ?? null;
      });
      assert.equal(seededRun.status, 'cancelled');
      assert.equal(seededRun.summary_json.dispatch_failed, true);
      assert.equal(seededRun.summary_json.reason, 'probe_dispatch_recovery_scope_blocked');
    }, availability.env ?? process.env);
  });
});
