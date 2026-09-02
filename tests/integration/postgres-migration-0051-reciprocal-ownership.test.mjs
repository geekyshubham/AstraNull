import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import {
  listMigrationFiles,
  runMigrations,
} from '../../src/persistence/postgres/migrations.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  MIGRATIONS_DIR,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const MIGRATION_0051 = '0051_reciprocal_ownership_probe_jobs';
const TENANT = 'ten_0051';
const ENVIRONMENT = 'env_0051';
const GROUP = 'tg_0051';
const TARGET = 'tgt_0051';
const AGENT = 'agt_0051';
const RUN = 'run_0051';
const ORDINARY_JOB = 'pjob_0051_ordinary';
const CTX = { tenantId: TENANT, userId: 'usr_0051', role: 'system' };

async function seedPreconditions(pool) {
  await pool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'migration 0051')`, [TENANT]);
  await pool.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'prod')`,
    [ENVIRONMENT, TENANT],
  );
  await pool.query(
    `INSERT INTO target_groups (
       id, tenant_id, environment_id, name, validation_mode, ownership_status
     ) VALUES ($1, $2, $3, 'owned target', 'agent_assisted', 'unverified')`,
    [GROUP, TENANT, ENVIRONMENT],
  );
  await pool.query(
    `INSERT INTO targets (
       id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior
     ) VALUES ($1, $2, $3, 'fqdn', 'owned.example', 'owned.example', 'must_block_before_origin')`,
    [TARGET, TENANT, GROUP],
  );
  await pool.query(
    `INSERT INTO agents (
       id, tenant_id, target_group_id, status, last_token_validation_status
     ) VALUES ($1, $2, $3, 'online', 'valid')`,
    [AGENT, TENANT, GROUP],
  );
  await pool.query(
    `INSERT INTO test_runs (
       id, tenant_id, target_group_id, target_id, check_id, status,
       safety_constraints, correlation_json
     ) VALUES (
       $1, $2, $3, $4, 'origin.direct_bypass.safe', 'running',
       '{"max_events":20}'::jsonb, '{"nonce_hash":"nonce_ordinary"}'::jsonb
     )`,
    [RUN, TENANT, GROUP, TARGET],
  );
  await pool.query(
    `INSERT INTO probe_jobs (
       id, tenant_id, test_run_id, target_id, check_id, status, nonce_hash,
       target_descriptor_json, job_signature
     ) VALUES (
       $1, $2, $3, $4, 'origin.direct_bypass.safe', 'pending', 'nonce_ordinary',
       '{"kind":"fqdn","value":"owned.example"}'::jsonb, 'ordinary-signed-job'
     )`,
    [ORDINARY_JOB, TENANT, RUN, TARGET],
  );
}

function verificationInsert(id, jobId, nonce) {
  return {
    text: `INSERT INTO ownership_verifications (
             id, tenant_id, target_group_id, agent_id, declared_fqdn, status,
             challenge_nonce_hash, probe_job_id, created_by
           ) VALUES ($1, $2, $3, $4, 'owned.example', 'challenge_sent', $5, $6, $7)`,
    values: [id, TENANT, GROUP, AGENT, nonce, jobId, CTX.userId],
  };
}

function ownershipJobInsert(id, verificationId, nonce, status = 'completed') {
  return {
    text: `INSERT INTO probe_jobs (
             id, tenant_id, test_run_id, target_id, check_id, status, nonce_hash,
             target_descriptor_json, ownership_verification_id, completed_at, job_signature
           ) VALUES (
             $1, $2, $3, $4, 'ownership.challenge', $5, $6,
             '{"kind":"fqdn","value":"owned.example"}'::jsonb, $3,
             CASE WHEN $5 = 'completed' THEN now() ELSE NULL END,
             'ownership-signed-job'
           )`,
    values: [id, TENANT, verificationId, AGENT, status, nonce],
  };
}

async function insertReciprocalPair(pool, suffix, order) {
  const verificationId = `own_0051_${suffix}`;
  const jobId = `pjob_0051_${suffix}`;
  const nonce = `nonce_0051_${suffix}`;
  const verification = verificationInsert(verificationId, jobId, nonce);
  const job = ownershipJobInsert(jobId, verificationId, nonce);

  await withTenantContext(pool, TENANT, async (client) => {
    const statements = order === 'verification_first'
      ? [verification, job]
      : [job, verification];
    for (const statement of statements) {
      await client.query(statement.text, statement.values);
    }
  });
  return { verificationId, jobId, nonce };
}

function assertReciprocalConstraint(error) {
  assert.equal(error?.code, '23514');
  assert.ok([
    'ownership_verifications_probe_job_binding',
    'probe_jobs_ownership_challenge_binding',
  ].includes(error?.constraint), JSON.stringify({
    code: error?.code,
    constraint: error?.constraint,
    message: error?.message,
  }));
  return true;
}

describe('postgres migration 0051 reciprocal ownership jobs', () => {
  it('defers the complete tuple to commit, supports both insertion orders, and quarantines injected ordinary jobs', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seedPreconditions(pool);

      const malformed = verificationInsert(
        'own_0051_points_to_ordinary',
        ORDINARY_JOB,
        'nonce_ordinary',
      );
      await assert.rejects(
        () => withTenantContext(pool, TENANT, (client) =>
          client.query(malformed.text, malformed.values)),
        assertReciprocalConstraint,
      );

      const verificationFirst = await insertReciprocalPair(
        pool,
        'verification_first',
        'verification_first',
      );
      const jobFirst = await insertReciprocalPair(pool, 'job_first', 'job_first');
      const persisted = await pool.query(
        `SELECT ov.id AS verification_id, j.id AS job_id
         FROM ownership_verifications ov
         JOIN probe_jobs j
           ON j.tenant_id = ov.tenant_id
          AND j.id = ov.probe_job_id
          AND j.ownership_verification_id = ov.id
         WHERE ov.tenant_id = $1
           AND ov.id = ANY($2::text[])
         ORDER BY ov.id`,
        [TENANT, [verificationFirst.verificationId, jobFirst.verificationId]],
      );
      assert.equal(persisted.rows.length, 2);

      const triggerContract = await pool.query(
        `SELECT tgname, tgdeferrable, tginitdeferred
         FROM pg_trigger
         WHERE tgname = ANY($1::text[])
         ORDER BY tgname`,
        [[
          'ownership_verifications_reciprocal_probe_job',
          'probe_jobs_reciprocal_ownership_verification',
        ]],
      );
      assert.deepEqual(triggerContract.rows, [
        {
          tgname: 'ownership_verifications_reciprocal_probe_job',
          tgdeferrable: true,
          tginitdeferred: true,
        },
        {
          tgname: 'probe_jobs_reciprocal_ownership_verification',
          tgdeferrable: true,
          tginitdeferred: true,
        },
      ]);

      // Model state that could only arrive through a superuser/restore bypass. Runtime reads,
      // leasing, completion and result reconciliation must still refuse the ordinary job.
      const adminClient = await pool.connect();
      try {
        await adminClient.query(`SET session_replication_role = 'replica'`);
        const injected = verificationInsert(
          'own_0051_injected_ordinary',
          ORDINARY_JOB,
          'nonce_ordinary',
        );
        await adminClient.query(injected.text, injected.values);
      } finally {
        try {
          await adminClient.query(`SET session_replication_role = 'origin'`);
        } finally {
          adminClient.release();
        }
      }

      const probeJobs = createProbeJobRepository(pool);
      const workerCtx = { tenantId: TENANT, workerId: 'worker_0051', role: 'probe_worker' };
      const injectedLeaseAt = '2026-09-01T20:00:00.000Z';
      assert.equal(await probeJobs.getJobById(CTX, ORDINARY_JOB), null);
      assert.equal(await probeJobs.getProbeJobByTestRun(CTX, RUN), null);
      assert.deepEqual(
        await probeJobs.leasePendingJobsForWorker(workerCtx, workerCtx.workerId),
        [],
      );
      assert.equal(
        await probeJobs.claimPendingJobForWorker(
          workerCtx,
          ORDINARY_JOB,
          workerCtx.workerId,
          injectedLeaseAt,
        ),
        null,
      );
      assert.equal(
        await probeJobs.claimJobForResult(
          workerCtx,
          ORDINARY_JOB,
          workerCtx.workerId,
          injectedLeaseAt,
        ),
        null,
      );

      // Even a restore-bypassed leased row cannot be completed through the runtime repository.
      const leaseInjector = await pool.connect();
      try {
        await leaseInjector.query(`SET session_replication_role = 'replica'`);
        await leaseInjector.query(
          `UPDATE probe_jobs
           SET status = 'leased', leased_by = $2, leased_at = $3::timestamptz
           WHERE tenant_id = $1 AND id = $4`,
          [TENANT, workerCtx.workerId, injectedLeaseAt, ORDINARY_JOB],
        );
      } finally {
        try {
          await leaseInjector.query(`SET session_replication_role = 'origin'`);
        } finally {
          leaseInjector.release();
        }
      }
      assert.equal(
        await probeJobs.markJobCompleted(
          workerCtx,
          ORDINARY_JOB,
          '2026-09-01T20:00:01.000Z',
          { workerId: workerCtx.workerId, leasedAt: injectedLeaseAt },
        ),
        null,
      );

      const probeServices = createPostgresProbeJobServices({
        probeJobs,
        validationEvidence: createValidationEvidenceRepository(pool),
        audit: createAuditRepository(pool),
        killSwitch: createKillSwitchRepository(pool),
      });
      const reconcile = await probeServices.ingestProbeResult(
        workerCtx,
        ORDINARY_JOB,
        {
          external_result: 'connected',
          safety_attestation: { requests_sent: 1, duration_ms: 5 },
        },
      );
      assert.deepEqual(reconcile, { error: 'job_not_found', status: 404 });

      const rawOrdinary = await pool.query(
        `SELECT status, completed_at FROM probe_jobs WHERE id = $1`,
        [ORDINARY_JOB],
      );
      assert.equal(rawOrdinary.rows[0].status, 'leased');
      assert.equal(rawOrdinary.rows[0].completed_at, null);
    }, availability.env ?? process.env);
  });

  it('allows only reciprocal unlink and relink final states and rejects one-sided attacker updates', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seedPreconditions(pool);

      const unboundId = 'own_0051_initially_unbound';
      const unbound = verificationInsert(unboundId, null, 'nonce_0051_initially_unbound');
      await withTenantContext(pool, TENANT, (client) =>
        client.query(unbound.text, unbound.values));
      const persistedUnbound = await pool.query(
        `SELECT probe_job_id FROM ownership_verifications WHERE tenant_id = $1 AND id = $2`,
        [TENANT, unboundId],
      );
      assert.equal(persistedUnbound.rows[0]?.probe_job_id, null);

      // An initially-null edge is allowed only while no job claims the verification. Queue the
      // verification event first so its deferred trigger is the check that rejects this commit.
      const claimedUnboundId = 'own_0051_claimed_unbound';
      const claimedUnboundJobId = 'pjob_0051_claimed_unbound';
      await assert.rejects(
        () => withTenantContext(pool, TENANT, async (client) => {
          const verification = verificationInsert(
            claimedUnboundId,
            null,
            'nonce_0051_claimed_unbound',
          );
          const job = ownershipJobInsert(
            claimedUnboundJobId,
            claimedUnboundId,
            'nonce_0051_claimed_unbound',
          );
          await client.query(verification.text, verification.values);
          await client.query(job.text, job.values);
        }),
        (error) => {
          assert.equal(error?.code, '23514');
          assert.equal(error?.constraint, 'ownership_verifications_probe_job_binding');
          return true;
        },
      );

      await assert.rejects(
        () => withTenantContext(pool, TENANT, (client) => client.query(
          `UPDATE ownership_verifications
           SET probe_job_id = $3
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, unboundId, ORDINARY_JOB],
        )),
        assertReciprocalConstraint,
      );

      const pair = await insertReciprocalPair(
        pool,
        'transition_a',
        'verification_first',
      );

      // Reviewer reproduction: clearing only the verification edge must fail even though the
      // unchanged job does not queue its own deferred trigger in this transaction.
      await assert.rejects(
        () => withTenantContext(pool, TENANT, (client) => client.query(
          `UPDATE ownership_verifications
           SET probe_job_id = NULL
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.verificationId],
        )),
        (error) => {
          assert.equal(error?.code, '23514');
          assert.equal(error?.constraint, 'ownership_verifications_probe_job_binding');
          return true;
        },
      );

      await assert.rejects(
        () => withTenantContext(pool, TENANT, (client) => client.query(
          `UPDATE probe_jobs
           SET ownership_verification_id = NULL
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.jobId],
        )),
        (error) => {
          assert.equal(error?.code, '23514');
          assert.equal(error?.constraint, 'probe_jobs_ownership_challenge_binding');
          return true;
        },
      );

      // A -> B cannot commit while unchanged A still points back at the verification.
      const relinkJobId = 'pjob_0051_transition_b';
      await assert.rejects(
        () => withTenantContext(pool, TENANT, async (client) => {
          await client.query(
            `UPDATE ownership_verifications
             SET probe_job_id = $3
             WHERE tenant_id = $1 AND id = $2`,
            [TENANT, pair.verificationId, relinkJobId],
          );
          const replacement = ownershipJobInsert(
            relinkJobId,
            pair.verificationId,
            pair.nonce,
          );
          await client.query(replacement.text, replacement.values);
        }),
        (error) => {
          assert.equal(error?.code, '23514');
          assert.equal(error?.constraint, 'ownership_verifications_probe_job_binding');
          return true;
        },
      );

      // The reciprocal invariant is symmetric: reassigning the job cannot strand an unchanged
      // former verification even when the newly selected verification is otherwise valid.
      const reassignedVerificationId = 'own_0051_reassigned_job';
      const reassignedVerification = verificationInsert(
        reassignedVerificationId,
        null,
        pair.nonce,
      );
      await withTenantContext(pool, TENANT, (client) =>
        client.query(reassignedVerification.text, reassignedVerification.values));
      await assert.rejects(
        () => withTenantContext(pool, TENANT, async (client) => {
          await client.query(
            `UPDATE probe_jobs
             SET test_run_id = $3, ownership_verification_id = $3
             WHERE tenant_id = $1 AND id = $2`,
            [TENANT, pair.jobId, reassignedVerificationId],
          );
          await client.query(
            `UPDATE ownership_verifications
             SET probe_job_id = $3
             WHERE tenant_id = $1 AND id = $2`,
            [TENANT, reassignedVerificationId, pair.jobId],
          );
        }),
        (error) => {
          assert.equal(error?.code, '23514');
          assert.equal(error?.constraint, 'probe_jobs_ownership_challenge_binding');
          return true;
        },
      );

      const afterAttacks = await pool.query(
        `SELECT ov.probe_job_id, j.ownership_verification_id
         FROM ownership_verifications ov
         JOIN probe_jobs j ON j.tenant_id = ov.tenant_id AND j.id = ov.probe_job_id
         WHERE ov.tenant_id = $1 AND ov.id = $2`,
        [TENANT, pair.verificationId],
      );
      assert.deepEqual(afterAttacks.rows[0], {
        probe_job_id: pair.jobId,
        ownership_verification_id: pair.verificationId,
      });

      await assert.rejects(
        () => withTenantContext(pool, TENANT, (client) => client.query(
          `DELETE FROM probe_jobs WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.jobId],
        )),
        (error) => {
          assert.equal(error?.code, '23503');
          assert.equal(error?.constraint, 'fk_ownership_verifications_probe_job_tenant');
          return true;
        },
      );
      await assert.rejects(
        () => withTenantContext(pool, TENANT, (client) => client.query(
          `DELETE FROM ownership_verifications WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.verificationId],
        )),
        (error) => {
          assert.equal(error?.code, '23503');
          assert.equal(error?.constraint, 'fk_probe_jobs_ownership_verification_tenant');
          return true;
        },
      );

      // Deferred final-state validation permits a legitimate unlink in either statement order.
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `UPDATE ownership_verifications
           SET probe_job_id = NULL
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.verificationId],
        );
        await client.query(
          `DELETE FROM probe_jobs WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.jobId],
        );
      });
      const unlinked = await pool.query(
        `SELECT ov.probe_job_id,
                EXISTS (SELECT 1 FROM probe_jobs j WHERE j.id = $2) AS job_exists
         FROM ownership_verifications ov
         WHERE ov.tenant_id = $1 AND ov.id = $3`,
        [TENANT, pair.jobId, pair.verificationId],
      );
      assert.deepEqual(unlinked.rows[0], { probe_job_id: null, job_exists: false });

      // Link the existing unbound verification first, then create the reciprocal job.
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `UPDATE ownership_verifications
           SET probe_job_id = $3
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.verificationId, relinkJobId],
        );
        const replacement = ownershipJobInsert(
          relinkJobId,
          pair.verificationId,
          pair.nonce,
        );
        await client.query(replacement.text, replacement.values);
      });

      // Relink again with the opposite construction order; removing the old edge in the same
      // transaction keeps the final graph reciprocal.
      const finalJobId = 'pjob_0051_transition_c';
      await withTenantContext(pool, TENANT, async (client) => {
        const replacement = ownershipJobInsert(
          finalJobId,
          pair.verificationId,
          pair.nonce,
        );
        await client.query(replacement.text, replacement.values);
        await client.query(
          `UPDATE ownership_verifications
           SET probe_job_id = $3
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.verificationId, finalJobId],
        );
        await client.query(
          `DELETE FROM probe_jobs WHERE tenant_id = $1 AND id = $2`,
          [TENANT, relinkJobId],
        );
      });

      const relinked = await pool.query(
        `SELECT ov.probe_job_id, j.ownership_verification_id,
                EXISTS (SELECT 1 FROM probe_jobs old WHERE old.id = $3) AS old_job_exists
         FROM ownership_verifications ov
         JOIN probe_jobs j ON j.tenant_id = ov.tenant_id AND j.id = ov.probe_job_id
         WHERE ov.tenant_id = $1 AND ov.id = $2`,
        [TENANT, pair.verificationId, relinkJobId],
      );
      assert.deepEqual(relinked.rows[0], {
        probe_job_id: finalJobId,
        ownership_verification_id: pair.verificationId,
        old_job_exists: false,
      });

      // Deleting both sides remains valid under the deferred foreign keys.
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query(
          `DELETE FROM ownership_verifications WHERE tenant_id = $1 AND id = $2`,
          [TENANT, pair.verificationId],
        );
        await client.query(
          `DELETE FROM probe_jobs WHERE tenant_id = $1 AND id = $2`,
          [TENANT, finalJobId],
        );
      });
      const deletedPair = await pool.query(
        `SELECT
           EXISTS (SELECT 1 FROM ownership_verifications WHERE id = $1) AS verification_exists,
           EXISTS (SELECT 1 FROM probe_jobs WHERE id = $2) AS job_exists`,
        [pair.verificationId, finalJobId],
      );
      assert.deepEqual(deletedPair.rows[0], {
        verification_exists: false,
        job_exists: false,
      });
    }, availability.env ?? process.env);
  });

  it('fails the upgrade before installing trust when preexisting reciprocal data is malformed', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (pool) => {
        const files = listMigrationFiles(MIGRATIONS_DIR);
        const before0051 = files.filter((file) => file.version < MIGRATION_0051);
        const migration0051 = files.filter((file) => file.version === MIGRATION_0051);
        assert.equal(migration0051.length, 1);
        await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files: before0051 });
        await seedPreconditions(pool);

        const malformed = verificationInsert(
          'own_0051_bad_upgrade',
          ORDINARY_JOB,
          'nonce_ordinary',
        );
        await pool.query(malformed.text, malformed.values);

        await assert.rejects(
          () => runMigrations(pool, {
            migrationsDir: MIGRATIONS_DIR,
            files: migration0051,
          }),
          (error) => {
            assert.equal(error?.code, '23514');
            assert.equal(error?.constraint, 'ownership_verifications_probe_job_binding');
            assert.match(error?.message ?? '', /preexisting ownership verification\/probe job binding is malformed/);
            return true;
          },
        );

        const applied = await pool.query(
          `SELECT 1 FROM schema_migrations WHERE version = $1`,
          [MIGRATION_0051],
        );
        assert.equal(applied.rows.length, 0);
        const installed = await pool.query(
          `SELECT 1
           FROM pg_constraint
           WHERE conname = 'fk_ownership_verifications_probe_job_tenant'`,
        );
        assert.equal(installed.rows.length, 0, 'failed migration must roll back trust constraints');
      },
      availability.env ?? process.env,
      { applyMigrations: false },
    );
  });
});
