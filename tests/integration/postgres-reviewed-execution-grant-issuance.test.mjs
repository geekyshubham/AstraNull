import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createReviewedExecutionGrantRepository } from '../../src/persistence/postgres/reviewedExecutionGrantRepository.mjs';
import { createReviewedExecutionGrantIssuance } from '../../src/services/reviewedExecutionGrantIssuance.mjs';
import { createReviewedOperationRepository } from '../../src/persistence/postgres/reviewedOperationRepository.mjs';
import { createReviewedOperationAuthority } from '../../src/services/reviewedOperationAuthority.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { withTenantContext, assertNoManagedTenantTransaction } from '../../src/persistence/postgres/tenantContext.mjs';
import { buildReviewedExecutionGrantEnvelope } from '../../src/contracts/reviewedExecutionGrant.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { signPreparedReviewedExecutionGrant } from '../../src/lib/preparedReviewedExecutionGrant.mjs';
import { signProbeJob } from '../../src/lib/probeJobs.mjs';
import { createPgPool, closePgPool } from '../../src/persistence/postgres/pool.mjs';
import { databaseUrlWithDatabase, resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';
import { SECRET, KEY, CHECK, grantFixture, keyFixture, deferred, iso } from '../helpers/reviewed-grant-fixture.mjs';

const TENANT = 'ten_grant_test', OTHER = 'ten_grant_foreign';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const denied = (result, error) => { assert.equal(result.ok, false, JSON.stringify(result)); if (error) assert.equal(result.error, error); assert.equal(result.execution_available, false); };
function localEnv() {
  const env = { ...process.env };
  for (const key of ['ASTRANULL_DATABASE_URL', 'ASTRANULL_ADMIN_DATABASE_URL']) if (env[key]) {
    const url = new URL(env[key]); assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname));
    assert.ok(!url.searchParams.has('host') && !url.searchParams.has('hostaddr'));
  }
  return env;
}

test('actual PostgreSQL app-role durable at-most-once issuance prerequisite; no runtime dispatch', { timeout: 120_000 }, async (t) => {
  const available = await resolvePostgresHarnessAvailability(localEnv(), { tryDocker: false });
  if (!available.available) return t.skip(available.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    await owner.query("INSERT INTO tenants (id, name) VALUES ($1, 'Grant prerequisite'), ($2, 'Foreign tenant')", [TENANT, OTHER]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev'; url.searchParams.set('options', '-c timezone=UTC');
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const audit = createAuditRepository(pool);
    const authority = createReviewedOperationAuthority({ backend: createReviewedOperationRepository(pool, audit) });
    const repository = createReviewedExecutionGrantRepository(pool, { audit, authority });
    const sql = (statement, values = [], tenant = TENANT) => withTenantContext(pool, tenant, (client) => client.query(statement, values));
    const ledger = async (f) => (await sql('SELECT * FROM reviewed_execution_grant_issuances WHERE probe_job_id = $1', [f.job.id], f.ctx.tenantId)).rows[0];
    async function seed(suffix, tenantId = TENANT) {
      await sql('INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, $3)', [`tg_${suffix}`, tenantId, suffix], tenantId);
      await sql(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, protocol, port,
        expected_behavior, declaration_json) VALUES ($1, $2, $3, 'url', $4, $4, 'https', 443, 'must_block_before_origin', '{"operation":"inert"}')`,
      [`tgt_${suffix}`, tenantId, `tg_${suffix}`, `https://${suffix.replaceAll('_', '-')}.example.test/diagnostic`], tenantId);
      const target = (await sql('SELECT * FROM targets WHERE id = $1', [`tgt_${suffix}`], tenantId)).rows[0];
      const group = (await sql('SELECT * FROM target_groups WHERE id = $1', [`tg_${suffix}`], tenantId)).rows[0];
      const f = grantFixture({ suffix, tenantId, target, group });
      await sql(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref,
        transitioned_at, transitioned_by, audit_entry_id) VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', $4::jsonb, $5, 'fixture', 'fixture_audit')`,
      [f.ownership.id, tenantId, target.id, JSON.stringify(f.ownership.source_ref), f.ownership.transitioned_at], tenantId);
      await sql(`INSERT INTO reviewed_operations (id, tenant_id, target_id, plan_json, plan_digest, approved_by, approved_role, approved_at)
        VALUES ($1, $2, $3, $4::jsonb, $5, $6, 'owner', $7)`,
      [f.review.id, tenantId, target.id, JSON.stringify(f.review.plan), f.review.plan_digest, f.review.approved_by, f.review.approved_at], tenantId);
      await sql(`INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, safety_class,
        safety_constraints, correlation_json, collection_deadline_at) VALUES ($1, $2, $3, $4, $5, 'running', 'safe', $6::jsonb, $7::jsonb, $8)`,
      [f.run.id, tenantId, group.id, target.id, CHECK, JSON.stringify(f.run.safety_constraints), JSON.stringify(f.run.correlation_json), f.run.collection_deadline_at], tenantId);
      await insertJob(f);
      await sql('INSERT INTO soc_kill_switch (tenant_id, active) VALUES ($1, false) ON CONFLICT (tenant_id) DO UPDATE SET active = false', [tenantId], tenantId);
      return f;
    }
    // Actual stored reservation slot only. Current runtime explicitly CANNOT create reviewed reservations.
    async function insertJob(f, job = f.job, reservation = f.reservation) {
      await sql(`INSERT INTO probe_jobs (id, tenant_id, test_run_id, target_id, check_id, status, nonce_hash,
        probe_profile, constraints_json, target_descriptor_json, worker_metadata_json, job_signature, leased_at, leased_by)
        VALUES ($1, $2, $3, $4, $5, 'leased', $6, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11, $12, $13)`,
      [job.id, job.tenant_id, job.test_run_id, job.target_id, job.check_id, job.nonce_hash, JSON.stringify(job.probe_profile),
        JSON.stringify(job.constraints), JSON.stringify(job.target), JSON.stringify({ execution_reservation: reservation }),
        job.job_signature, job.leased_at, job.leased_by], f.ctx.tenantId);
    }
    function service(f, options = {}) {
      const keys = keyFixture(f.ctx.tenantId); let calls = 0;
      const selectedAudit = options.auditFailure ? { appendAuditEvent: async (entry, settings) => {
        await audit.appendAuditEvent(entry, settings);
        if (entry.action === options.auditFailure) await settings.client.query('SELECT 1 / 0 AS test_audit_failure');
      } } : audit;
      const backend = options.auditFailure ? createReviewedExecutionGrantRepository(pool, { audit: selectedAudit, authority }) : repository;
      const repo = { ...backend, withTransaction: async (...args) => {
        try {
          const result = await backend.withTransaction(...args);
          await options.afterCommit?.(result);
          if (result.claim) {
            // PostgreSQL may run in a VM a few milliseconds ahead of this host.
            // Wait only in the fixture, after COMMIT, so signer-specific scenarios
            // reach their intended guard without accepting future-issued authority.
            const claimedAt = Date.parse(result.claim.claimed_at), deadline = performance.now() + 1000;
            while (Date.now() < claimedAt) {
              assert.ok(performance.now() < deadline, 'fixture host clock must catch the committed database claim within 1 second');
              await options.onClockWait?.();
              await delay(1);
            }
          }
          return result;
        }
        catch (error) { t.diagnostic(`fixture transaction rejected: ${error.code ?? 'exception'} ${error.message} ${error.constraint ?? ''}`); throw error; }
      } };
      const adapter = { async signEnvelope(input) {
        assertNoManagedTenantTransaction(); calls++;
        const row = await ledger(f); assert.equal(row.state, 'signing_unknown', 'claim is visible through ANOTHER connection');
        assert.equal(row.envelope_canonical, canonicalJsonStringify(input.envelope));
        const claimedAudit = (await sql("SELECT id FROM audit_logs WHERE resource_id = $1 AND action = 'reviewed_execution_grant.signing_claimed'", [row.id])).rows;
        assert.equal(claimedAudit.length, 1);
        return options.sign ? options.sign({ ...input, keys, f }) : keys.receipt(input.envelope);
      } };
      const api = createReviewedExecutionGrantIssuance({ repository: repo, probeWorkerSecret: SECRET, trust: keys.trust,
        keyReference: KEY, signingAdapter: adapter, timeoutMs: options.timeoutMs ?? 1000 });
      return { api, keys, calls: () => calls };
    }
    async function lostCommit(number, fn) {
      const connect = pool.connect.bind(pool); let commits = 0;
      pool.connect = async () => {
        const client = await connect();
        return { release: () => client.release(), query: async (...args) => {
          const result = await client.query(...args);
          if (args[0] === 'COMMIT' && ++commits === number) throw new Error('test lost COMMIT acknowledgement');
          return result;
        } };
      };
      try { return await fn(); } finally { pool.connect = connect; }
    }
    async function rawClaim(f) {
      const keys = keyFixture(f.ctx.tenantId);
      return repository.withTransaction(f.ctx, f.request, (tx) => tx.withAuthority(async (snapshot) => {
        const at = await tx.now(), c = { originalJob: tx.job, reservation: tx.reservation, check: snapshot.check,
          tenantId: f.ctx.tenantId, workerId: f.ctx.workerId, leasedAt: tx.job.leased_at, now: at };
        const e = buildReviewedExecutionGrantEnvelope(c, keys.signer).envelope;
        assert.ok(e);
        const history = snapshot.ownershipHistory.slice().sort((a, b) => canonicalJsonStringify(a).localeCompare(canonicalJsonStringify(b)));
        return { id: `raw_${randomUUID()}`, tenant_id: f.ctx.tenantId, probe_job_id: f.job.id, test_run_id: f.run.id,
          target_id: f.target.id, check_id: CHECK, reservation_id: f.reservation.id, review_id: f.review.id, plan_digest: f.review.plan_digest,
          worker_id: f.ctx.workerId, leased_at: f.job.leased_at, original_job_payload: e.original_job_payload,
          original_job_payload_sha256: hash(e.original_job_payload), original_job_signature: f.job.job_signature,
          original_job_signature_sha256: hash(f.job.job_signature), reservation_json: f.reservation,
          provenance_json: { assurance_scope: f.run.safety_constraints.assurance_scope, dns_proof: history[0], ownership_history_sha256: hash(canonicalJsonStringify(history)) },
          envelope_json: structuredClone(e), envelope_canonical: canonicalJsonStringify(e), envelope_sha256: hash(canonicalJsonStringify(e)),
          completion_token_hash: hash(randomBytes(32)), claimed_at: e.authority.grant_issued_at, state: 'signing_unknown' };
      }));
    }
    function refresh(row) {
      row.envelope_json.reservation = row.reservation_json;
      row.envelope_json.original_job_payload = row.original_job_payload;
      row.original_job_payload_sha256 = hash(row.original_job_payload);
      row.envelope_canonical = canonicalJsonStringify(row.envelope_json); row.envelope_sha256 = hash(row.envelope_canonical);
    }
    async function insertClaim(row, tenant = TENANT) {
      const columns = Object.keys(row), json = new Set(['reservation_json', 'provenance_json', 'envelope_json']);
      return sql(`INSERT INTO reviewed_execution_grant_issuances (${columns.join(', ')}) VALUES (${columns.map((key, i) => `$${i + 1}${json.has(key) ? '::jsonb' : ''}`).join(', ')})`,
        columns.map((key) => json.has(key) ? JSON.stringify(row[key]) : row[key]), tenant);
    }
    try {
      await t.test('real non-owner role, FORCE RLS, one committed signer call, unchanged job and exact replay', async () => {
        const role = (await pool.query('SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user')).rows[0];
        assert.deepEqual(role, { role: 'astranull_app', rolsuper: false, rolbypassrls: false });
        const f = await seed('success'), s = service(f);
        const before = (await sql('SELECT constraints_json, job_signature FROM probe_jobs WHERE id = $1', [f.job.id])).rows[0];
        const first = await s.api.issueOnce(f.ctx, f.request); assert.equal(first.ok, true, JSON.stringify(first));
        assert.equal((await ledger(f)).state, 'issued'); assert.equal(first.execution_available, false);
        const after = (await sql('SELECT constraints_json, job_signature FROM probe_jobs WHERE id = $1', [f.job.id])).rows[0]; assert.deepEqual(after, before);
        const replay = await s.api.issueOnce(f.ctx, f.request); assert.equal(replay.replayed, true); assert.deepEqual(replay.grant, first.grant); assert.equal(s.calls(), 1);
        assert.deepEqual((await pool.query('SELECT id FROM reviewed_execution_grant_issuances')).rows, []);
        assert.deepEqual((await sql('SELECT id FROM reviewed_execution_grant_issuances', [], OTHER)).rows, []);
        const rls = (await owner.query("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'reviewed_execution_grant_issuances'")).rows[0];
        assert.deepEqual(rls, { relrowsecurity: true, relforcerowsecurity: true });
        await sql('UPDATE soc_kill_switch SET active = true WHERE tenant_id = $1', [TENANT]);
        denied(await s.api.issueOnce(f.ctx, f.request)); assert.equal(s.calls(), 1);
        await sql('UPDATE soc_kill_switch SET active = false WHERE tenant_id = $1', [TENANT]);
        const replacement = { ...f.job, id: 'job_success_replacement' }; replacement.job_signature = signProbeJob(replacement, SECRET);
        await insertJob(f, replacement, { ...f.reservation, id: 'res_success_replacement' });
        denied(await s.api.issueOnce(f.ctx, f.request), 'reviewed_grant_run_jobs_ambiguous'); assert.equal(s.calls(), 1);
        const issuedRow = await ledger(f);
        for (const statement of ["UPDATE reviewed_execution_grant_issuances SET grant_signature = $2 WHERE id = $1",
          "UPDATE reviewed_execution_grant_issuances SET state = 'closed_unknown', grant_signature = NULL, failure_code = 'reclose' WHERE id = $1",
          'DELETE FROM reviewed_execution_grant_issuances WHERE id = $1']) {
          await assert.rejects(sql(statement, statement.includes('$2') ? [issuedRow.id, 'A'.repeat(86) + '=='] : [issuedRow.id]), /immutable|cannot be deleted/);
        }
      });
      await t.test('fixture host clock catches committed database issuance before exercising wrong-key rejection', async (clockTest) => {
        const realNow = Date.now.bind(Date);
        let hostNow;
        clockTest.mock.method(Date, 'now', () => hostNow ?? realNow());
        const foreign = keyFixture(), f = await seed('host_clock_boundary');
        let clockWaits = 0;
        const s = service(f, {
          afterCommit: async (result) => {
            if (!result.claim) return;
            const claimedAt = Date.parse(result.claim.claimed_at);
            hostNow = claimedAt - 1;
            assert.equal(Date.now(), claimedAt - 1, 'deterministic future-grant boundary, independent of scheduler or VM skew');
            let prematureCalls = 0;
            const premature = await signPreparedReviewedExecutionGrant({ envelope: result.claim.envelope_json,
              context: result.context, trust: s.keys.trust, now: () => hostNow,
              signingAdapter: { signEnvelope: async () => { prematureCalls++; throw new Error('future authority must not sign'); } } });
            assert.equal(premature.error, 'reviewed_grant_clock_invalid');
            assert.equal(prematureCalls, 0, 'even one millisecond in the future remains forbidden');
          },
          onClockWait: async () => {
            // Only observing the future claim in the catch-up loop advances this
            // clock. Without that loop it stays future-issued, regardless of load.
            assert.equal(clockWaits++, 0);
            hostNow += 1;
          },
          sign: async ({ envelope, keys }) => ({ ...keys.receipt(envelope), signature: foreign.receipt(envelope).signature }),
        });
        denied(await s.api.issueOnce(f.ctx, f.request), 'reviewed_grant_signature_invalid');
        assert.equal(clockWaits, 1);
        assert.equal(s.calls(), 1);
        assert.equal((await ledger(f)).state, 'closed_unknown');
      });
      await t.test('concurrent requests obtain one durable slot and one independent signer invocation', async () => {
        const f = await seed('concurrent'), gate = deferred(), ready = deferred();
        const s = service(f, { sign: async ({ envelope, keys }) => { ready.resolve(); await gate.promise; return keys.receipt(envelope); } });
        const first = s.api.issueOnce(f.ctx, f.request);
        await Promise.race([ready.promise, first.then((result) => assert.fail(`signer not entered: ${JSON.stringify(result)}`))]);
        denied(await s.api.issueOnce(f.ctx, f.request), 'reviewed_grant_consumed_unknown');
        gate.resolve(); assert.equal((await first).ok, true); assert.equal(s.calls(), 1);
        assert.equal((await sql('SELECT id FROM reviewed_execution_grant_issuances WHERE test_run_id = $1', [f.run.id])).rowCount, 1);
      });
      await t.test('actual unauthentic HMAC, missing reservation and historical scope/proof fail before claim/sign', async () => {
        for (const [suffix, change] of [
          ['bad_hmac', async (f) => sql("UPDATE probe_jobs SET job_signature = $2 WHERE id = $1", [f.job.id, 'b'.repeat(64)])],
          ['no_reservation', async (f) => sql("UPDATE probe_jobs SET worker_metadata_json = '{\"hmac_verified\":true}' WHERE id = $1", [f.job.id])],
          ['old_scope', async (f) => sql("UPDATE test_runs SET safety_constraints = jsonb_set(safety_constraints, '{assurance_scope,version}', '\"assurance-scope.v2\"') WHERE id = $1", [f.run.id])],
          ['old_dns', async (f) => sql("UPDATE target_verifications SET source_ref = jsonb_set(source_ref, '{dns_target_binding,version}', '\"dns-ownership-target.v1\"') WHERE id = $1", [f.ownership.id])],
          ['micro_lease', async (f) => sql("UPDATE probe_jobs SET leased_at = leased_at + interval '1 microsecond' WHERE id = $1", [f.job.id])],
        ]) {
          const f = await seed(suffix), s = service(f); await change(f);
          denied(await s.api.issueOnce(f.ctx, f.request)); assert.equal(s.calls(), 0); assert.equal(await ledger(f), undefined);
        }
      });
      await t.test('multiple actual original jobs for run deny preparation and replay; no duplicate authority', async () => {
        const f = await seed('duplicate_initial'), other = { ...f.job, id: 'job_duplicate_second' };
        other.job_signature = signProbeJob(other, SECRET); await insertJob(f, other, { ...f.reservation, id: 'res_second' });
        const s = service(f); denied(await s.api.issueOnce(f.ctx, f.request), 'reviewed_grant_run_jobs_ambiguous'); assert.equal(s.calls(), 0); assert.equal(await ledger(f), undefined);
      });
      await t.test('preparation audit SQL-transaction rollback invokes zero signing', async () => {
        const f = await seed('claim_audit'), s = service(f, { auditFailure: 'reviewed_execution_grant.signing_claimed' });
        denied(await s.api.issueOnce(f.ctx, f.request)); assert.equal(s.calls(), 0); assert.equal(await ledger(f), undefined);
        assert.equal((await sql("SELECT id FROM audit_logs WHERE metadata_json->>'probe_job_id' = $1", [f.job.id])).rowCount, 0);
      });
      await t.test('lost preparation COMMIT acknowledgement leaves consumed durable unknown and ZERO signing', async () => {
        const f = await seed('claim_commit'), s = service(f);
        denied(await lostCommit(1, () => s.api.issueOnce(f.ctx, f.request))); assert.equal(s.calls(), 0); assert.equal((await ledger(f)).state, 'signing_unknown');
        denied(await s.api.issueOnce(f.ctx, f.request), 'reviewed_grant_consumed_unknown'); assert.equal(s.calls(), 0);
      });
      await t.test('finalization audit rollback never releases signature; closure is terminal', async () => {
        const f = await seed('final_audit'), s = service(f, { auditFailure: 'reviewed_execution_grant.issued' });
        denied(await s.api.issueOnce(f.ctx, f.request)); assert.equal(s.calls(), 1); assert.equal((await ledger(f)).state, 'closed_unknown');
        assert.equal((await sql("SELECT id FROM audit_logs WHERE metadata_json->>'probe_job_id' = $1 AND action = 'reviewed_execution_grant.issued'", [f.job.id])).rowCount, 0);
        denied(await s.api.issueOnce(f.ctx, f.request)); assert.equal(s.calls(), 1);
      });
      await t.test('lost final COMMIT response withholds this response but exact committed grant replay never signs', async () => {
        const f = await seed('final_commit'), s = service(f);
        // Signer's two read-only transactions also commit, so issued commit is fourth.
        denied(await lostCommit(4, () => s.api.issueOnce(f.ctx, f.request))); assert.equal((await ledger(f)).state, 'issued');
        const replay = await s.api.issueOnce(f.ctx, f.request); assert.equal(replay.ok, true, JSON.stringify(replay)); assert.equal(s.calls(), 1);
      });
      for (const [suffix, change] of [
        ['sign_revoke', async (f) => sql('UPDATE reviewed_operations SET revoked_at = clock_timestamp(), revoked_by = $2 WHERE id = $1', [f.review.id, f.review.approved_by])],
        ['sign_material', async (f) => sql("UPDATE targets SET declaration_json = '{\"operation\":\"changed\"}' WHERE id = $1", [f.target.id])],
        ['sign_lease', async (f) => sql("UPDATE probe_jobs SET leased_by = 'worker_other' WHERE id = $1", [f.job.id])],
        ['sign_reservation', async (f) => sql("UPDATE probe_jobs SET worker_metadata_json = jsonb_set(worker_metadata_json, '{execution_reservation,max_total_operations}', '7') WHERE id = $1", [f.job.id])],
        ['sign_hmac', async (f) => sql('UPDATE probe_jobs SET job_signature = $2 WHERE id = $1', [f.job.id, 'b'.repeat(64)])],
        ['sign_stop', async (f) => sql("UPDATE test_runs SET status = 'cancelled' WHERE id = $1", [f.run.id])],
        ['sign_kill', async () => sql('UPDATE soc_kill_switch SET active = true WHERE tenant_id = $1', [TENANT])],
        ['sign_deadline', async (f) => sql("UPDATE test_runs SET collection_deadline_at = date_trunc('milliseconds', clock_timestamp()) - interval '1 second' WHERE id = $1", [f.run.id])],
        ['sign_duplicate_job', async (f) => { const other = { ...f.job, id: 'job_sign_duplicate_second' }; other.job_signature = signProbeJob(other, SECRET); await insertJob(f, other, { ...f.reservation, id: 'res_sign_duplicate_second' }); }],
      ]) await t.test(`actual ${suffix} mutation during signer wait permanently withholds execution grant`, async () => {
        const f = await seed(suffix), s = service(f, { sign: async ({ envelope, keys }) => { await change(f); return keys.receipt(envelope); } });
        denied(await s.api.issueOnce(f.ctx, f.request)); assert.equal((await ledger(f)).state, 'closed_unknown'); assert.equal(s.calls(), 1);
        await s.api.issueOnce(f.ctx, f.request); assert.equal(s.calls(), 1);
      });
      await t.test('real Ed25519 wrong-key signature and timeout/late response never issue or re-sign', async () => {
        const foreign = keyFixture();
        const f = await seed('wrong_key'), s = service(f, { sign: async ({ envelope, keys }) => ({ ...keys.receipt(envelope), signature: foreign.receipt(envelope).signature }) });
        denied(await s.api.issueOnce(f.ctx, f.request), 'reviewed_grant_signature_invalid'); assert.equal((await ledger(f)).state, 'closed_unknown');
        const late = deferred(), g = await seed('late_signature'); let stopped;
        const z = service(g, { timeoutMs: 10, sign: async ({ envelope, keys, signal }) => { stopped = signal; await late.promise; return keys.receipt(envelope); } });
        denied(await z.api.issueOnce(g.ctx, g.request), 'reviewed_grant_signing_timeout'); assert.equal(stopped.aborted, true);
        late.resolve(); await delay(10); denied(await z.api.issueOnce(g.ctx, g.request)); assert.equal(z.calls(), 1); assert.equal((await ledger(g)).state, 'closed_unknown');
      });
      await t.test('wrong owner completion token cannot close or finish a durable unknown claim', async () => {
        const f = await seed('wrong_owner'), row = await rawClaim(f); await insertClaim(row);
        assert.equal(await repository.closeUnknown(f.ctx, row.id, Buffer.alloc(32), 'test_failure'), false);
        const result = await repository.withTransaction(f.ctx, f.request, async (tx) => tx.finish(await tx.getSlot(), Buffer.alloc(32), 'A'.repeat(86) + '==', await tx.now()));
        assert.equal(result, null); assert.equal((await ledger(f)).state, 'signing_unknown');
      });
      await t.test('FORCE RLS write checks, tenant/run/review FKs, and unique job/run/reservation slots are actual SQL guards', async () => {
        const f = await seed('sql_identity'), row = await rawClaim(f);
        await assert.rejects(insertClaim(row, OTHER), (error) => error.code === '42501');
        const foreign = await seed('sql_foreign', OTHER);
        const wrongRun = structuredClone(row); wrongRun.test_run_id = foreign.run.id; wrongRun.envelope_json.job.test_run_id = foreign.run.id;
        const payload = JSON.parse(wrongRun.original_job_payload); payload.test_run_id = foreign.run.id; wrongRun.original_job_payload = canonicalJsonStringify(payload); refresh(wrongRun);
        await assert.rejects(insertClaim(wrongRun), (error) => error.code === '23503');
        const wrongReview = structuredClone(row); wrongReview.review_id = foreign.review.id;
        const original = JSON.parse(wrongReview.original_job_payload); original.constraints.reviewed_operation_binding.review_id = foreign.review.id;
        wrongReview.original_job_payload = canonicalJsonStringify(original); wrongReview.reservation_json.reviewed_operation.review_id = foreign.review.id; refresh(wrongReview);
        await assert.rejects(insertClaim(wrongReview), (error) => error.code === '23503');
        await insertClaim(row);
        await assert.rejects(insertClaim({ ...row, id: `duplicate_${randomUUID()}` }), (error) => error.code === '23505');
        const definitions = (await owner.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid = 'reviewed_execution_grant_issuances'::regclass AND contype = 'u'")).rows.map((item) => item.definition);
        for (const name of ['probe_job_id', 'test_run_id', 'reservation_id']) assert.ok(definitions.includes(`UNIQUE (tenant_id, ${name})`));
        const g = await seed('reservation_reuse'), reused = await rawClaim(g);
        reused.reservation_id = row.reservation_id; reused.reservation_json.id = row.reservation_id; refresh(reused);
        await assert.rejects(insertClaim(reused), (error) => error.code === '23505' && error.constraint.includes('reservation'));
        const replacement = { ...f.job, id: 'job_run_replacement' }; replacement.job_signature = signProbeJob(replacement, SECRET); await insertJob(f, replacement);
        const runReuse = structuredClone(row); runReuse.id = `run_reuse_${randomUUID()}`; runReuse.probe_job_id = replacement.id;
        runReuse.reservation_id = 'res_run_replacement'; runReuse.reservation_json.id = runReuse.reservation_id;
        runReuse.envelope_json.job.id = replacement.id;
        const replacementPayload = JSON.parse(runReuse.original_job_payload); replacementPayload.id = replacement.id;
        runReuse.original_job_payload = canonicalJsonStringify(replacementPayload); refresh(runReuse);
        await assert.rejects(insertClaim(runReuse), (error) => error.code === '23505' && error.constraint.includes('test_run'));
      });
      await t.test('typed bounded SQL authority/budgets/digests and immutable terminal history cannot be weakened by records', async () => {
        const f = await seed('sql_integrity'), valid = await rawClaim(f);
        for (const change of [
          (r) => { r.envelope_json.authority.not_after = r.envelope_json.authority.not_after.replace('Z', '001Z'); },
          (r) => { r.envelope_json.authority.not_after = 'infinity'; },
          (r) => { r.envelope_json.authority.extra = 'caller'; },
          (r) => { r.envelope_json.worker.id = 123; },
          (r) => { r.envelope_json.budgets.max_probe_requests = '4'; r.reservation_json.max_probe_requests = '4'; },
          (r) => { r.envelope_json.budgets.max_total_operations = -1; r.reservation_json.max_total_operations = -1; },
          (r) => { r.envelope_json.budgets.timeout_ms = 5001; },
          (r) => { r.provenance_json.dns_proof.source_ref.dns_target_binding.version = 'dns-ownership-target.v1'; },
          (r) => { r.provenance_json.assurance_scope.version = 'assurance-scope.v2'; },
          (r) => { r.original_job_signature_sha256 = 'b'.repeat(64); },
          (r) => { const p = JSON.parse(r.original_job_payload); p.constraints.reviewed_operation_binding.review_id = 123; r.original_job_payload = canonicalJsonStringify(p); },
          (r) => { const p = JSON.parse(r.original_job_payload); p.constraints.reviewed_operation_binding.plan_digest = 123; r.original_job_payload = canonicalJsonStringify(p); },
          (r) => { r.reservation_json.reviewed_operation.binding_version = 'reviewed-operation-binding.v0'; },
          (r) => { r.reservation_json.reviewed_operation.plan_version = 'reviewed-inert-operation.v0'; },
        ]) {
          const row = structuredClone(valid); change(row); refresh(row);
          await assert.rejects(insertClaim(row), (error) => error.code === '23514');
        }
        await assert.rejects(insertClaim({ ...valid, state: 'issued', finished_at: valid.claimed_at, grant_signature: 'A'.repeat(86) + '==' }), /start consumed unknown/);
        // Coherent bytes/identities/deadlines still cannot widen original 120-second authority.
        const extended = structuredClone(valid), payload = JSON.parse(extended.original_job_payload);
        const extendedEnd = iso(Date.parse(payload.constraints.issued_at) + 120001);
        payload.constraints.not_after = extendedEnd;
        Object.assign(payload.constraints.reviewed_operation_binding.authority, { original_not_after: extendedEnd, not_after: extendedEnd });
        extended.original_job_payload = canonicalJsonStringify(payload);
        Object.assign(extended.envelope_json.authority, { original_not_after: extendedEnd, not_after: extendedEnd });
        extended.reservation_json.not_after = extendedEnd; refresh(extended);
        await assert.rejects(insertClaim(extended), (error) => error.code === '23514');
        // Original and reservation numeric review identities have equal coercible text, but must remain strings.
        const numeric = structuredClone(valid), numericPayload = JSON.parse(numeric.original_job_payload);
        numericPayload.constraints.reviewed_operation_binding.review_id = 123;
        numeric.reservation_json.reviewed_operation.review_id = 123;
        numeric.original_job_payload = canonicalJsonStringify(numericPayload); refresh(numeric);
        assert.equal((await sql('SELECT valid_reviewed_grant_json($1::jsonb, $2::jsonb, $3::jsonb) AS valid',
          [JSON.stringify(numeric.envelope_json), JSON.stringify(numeric.reservation_json), JSON.stringify(numeric.provenance_json)])).rows[0].valid, false);
        await insertClaim(valid);
        for (const offset of [0, 1]) await assert.rejects(sql(`UPDATE reviewed_execution_grant_issuances SET state = 'issued',
          grant_signature = $2, finished_at = ($3::timestamptz + ($4::int * interval '1 millisecond')) WHERE id = $1`,
        [valid.id, 'A'.repeat(86) + '==', valid.envelope_json.authority.not_after, offset]), (error) => error.code === '23514');
        await assert.rejects(sql(`UPDATE reviewed_execution_grant_issuances SET state = 'issued', grant_signature = $2,
          finished_at = $3::timestamptz + interval '1 microsecond' WHERE id = $1`, [valid.id, 'A'.repeat(86) + '==', valid.claimed_at]), (error) => error.code === '23514');
        await assert.rejects(sql("UPDATE reviewed_execution_grant_issuances SET worker_id = 'other' WHERE id = $1", [valid.id]), /immutable/);
        await assert.rejects(sql('DELETE FROM reviewed_execution_grant_issuances WHERE id = $1', [valid.id]), /cannot be deleted/);
        await sql("UPDATE reviewed_execution_grant_issuances SET state = 'closed_unknown', finished_at = $2::timestamptz + interval '1 millisecond', failure_code = 'test_unknown' WHERE id = $1", [valid.id, valid.envelope_json.authority.not_after]);
        for (const statement of ["UPDATE reviewed_execution_grant_issuances SET state = 'signing_unknown', finished_at = NULL, failure_code = NULL WHERE id = $1",
          "UPDATE reviewed_execution_grant_issuances SET failure_code = 'overwrite' WHERE id = $1", 'DELETE FROM reviewed_execution_grant_issuances WHERE id = $1']) {
          await assert.rejects(sql(statement, [valid.id]), /immutable|cannot be deleted/);
        }
      });
      await t.test('fresh database clock after actual finalization audit-lock wait denies expired authority', async () => {
        const f = await seed('final_lock_clock'), entered = deferred();
        const at = Date.parse(f.job.constraints.issued_at), untilAt = Date.now() + 1500;
        f.job.constraints.not_after = iso(untilAt);
        f.job.constraints.reviewed_operation_binding = structuredClone(f.job.constraints.reviewed_operation_binding);
        Object.assign(f.job.constraints.reviewed_operation_binding.authority, { issued_at: iso(at), original_not_after: iso(untilAt), not_after: iso(untilAt) });
        f.job.job_signature = signProbeJob(f.job, SECRET);
        f.reservation.not_after = f.job.constraints.not_after;
        f.run.collection_deadline_at = f.job.constraints.not_after;
        await sql('UPDATE probe_jobs SET constraints_json = $2::jsonb, job_signature = $3, worker_metadata_json = $4::jsonb WHERE id = $1',
          [f.job.id, JSON.stringify(f.job.constraints), f.job.job_signature, JSON.stringify({ execution_reservation: f.reservation })]);
        await sql('UPDATE test_runs SET collection_deadline_at = $2 WHERE id = $1', [f.run.id, f.run.collection_deadline_at]);
        const holder = await pool.connect();
        const s = service(f, { sign: async ({ envelope, keys }) => {
          await holder.query('BEGIN'); await holder.query("SELECT set_config('app.tenant_id', $1, true)", [TENANT]);
          await holder.query('SELECT pg_advisory_xact_lock(hashtext($1))', [TENANT]);
          entered.resolve(); return keys.receipt(envelope);
        } });
        try {
          const pending = s.api.issueOnce(f.ctx, f.request);
          await Promise.race([entered.promise, pending.then((result) => assert.fail(JSON.stringify(result)))]);
          const holderPid = (await holder.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          const until = Date.now() + 2000; let blocked = false;
          while (Date.now() < until) {
            const waiters = (await owner.query('SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))', [holderPid])).rows;
            if (waiters.length) { blocked = true; break; } await delay(5);
          }
          assert.equal(blocked, true, 'actual finalization waits on PostgreSQL advisory lock');
          await delay(Math.max(1, Date.parse(f.job.constraints.not_after) - Date.now() + 20));
          await holder.query('COMMIT');
          denied(await pending); assert.equal(s.calls(), 1); assert.equal((await ledger(f)).state, 'closed_unknown');
        } finally { await holder.query('ROLLBACK').catch(() => {}); holder.release(); }
      });
      await t.test('managed outer tenant transaction never signs or claims', async () => {
        const f = await seed('nested'), s = service(f);
        await withTenantContext(pool, TENANT, async () => denied(await s.api.issueOnce(f.ctx, f.request), 'reviewed_grant_enclosing_transaction'));
        assert.equal(s.calls(), 0); assert.equal(await ledger(f), undefined);
      });
      t.diagnostic('All target URLs were .test declarations; only local ephemeral PostgreSQL and injected Ed25519 fixtures were used. No live reservation lifecycle, signer, DNS, probe, migration outside test DB or deployment.');
    } finally { await closePgPool(pool); }
  }, available.env);
});
