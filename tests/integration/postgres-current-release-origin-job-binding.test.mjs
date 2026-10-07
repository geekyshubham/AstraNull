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
      assert.equal(finalized.verdict.verdict, 'edge_exposed');
      assert.match(finalized.verdict.explanation, /Origin response observed/);
      assert.match(finalized.verdict.explanation, /application identity was not confirmed/);

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
        assert.equal(driftedFinalize.verdict.verdict, 'edge_exposed', 'snapshot, not drifted catalog, governs the verdict');

        // --- 3c. Legacy unstamped run keeps the truthful today-catalog fallback ---
        await seedRunRow(pool, 'run_pg_legacy', {
          probe_external_result: 'connected',
          producer_kind: null,
          expected_behavior_json: null,
        });
        const legacy = await testRuns.finalizeTestRun(CTX, 'run_pg_legacy', { force: true });
        assert.equal(legacy.verdict.verdict, 'allowed_as_expected', 'legacy unstamped runs fall back to today\'s catalog truthfully');

        // --- 3d. Stamped run with no recorded snapshot stays inconclusive, never a phantom PASS ---
        await seedRunRow(pool, 'run_pg_null_snapshot', {
          probe_external_result: 'connected',
          producer_kind: 'signed_probe',
          expected_behavior_json: null,
        });
        const unrecorded = await testRuns.finalizeTestRun(CTX, 'run_pg_null_snapshot', { force: true });
        assert.equal(unrecorded.verdict.verdict, 'inconclusive');
        assert.equal(unrecorded.verdict.explanation, 'Insufficient external probe evidence for a definitive verdict.');
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
