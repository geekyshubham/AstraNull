import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { buildReviewedOperationPlan } from '../../src/contracts/reviewedOperations.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { createReviewedOperationAuthority } from '../../src/services/reviewedOperationAuthority.mjs';
import { createReviewedOperationRepository } from '../../src/persistence/postgres/reviewedOperationRepository.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { databaseUrlWithDatabase, resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_current_authority';
const OTHER = 'ten_current_authority_other';
const ctx = { tenantId: TENANT, userId: 'usr_authority_owner', role: 'owner' };
const CHECK = 'waf.evasion_base64_wrap.safe';
const iso = (time) => new Date(time).toISOString();
function localEnv() {
  const env = { ...process.env };
  for (const key of ['ASTRANULL_DATABASE_URL', 'ASTRANULL_ADMIN_DATABASE_URL']) {
    if (!env[key]) continue;
    const url = new URL(env[key]);
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), `${key} must be loopback`);
    assert.ok(!url.searchParams.has('host') && !url.searchParams.has('hostaddr'));
  }
  return env;
}
function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}

// Real application-role connections; .test target URLs are NEVER contacted.
test('PostgreSQL internal reviewed current-authority prerequisite remains non-executable', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(localEnv(), { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    await owner.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Current authority'), ($2, 'Foreign authority')`, [TENANT, OTHER]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    url.searchParams.set('options', '-c timezone=UTC -c statement_timeout=10000');
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const repository = createReviewedOperationRepository(pool, createAuditRepository(pool));
    const authority = createReviewedOperationAuthority({ backend: repository });
    const sql = (statement, params = [], tenant = TENANT) => withTenantContext(pool, tenant, (client) => client.query(statement, params));
    async function connect(tenant = TENANT) {
      const client = await pool.connect();
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
      return client;
    }
    async function cleanup(client) { await client.query('ROLLBACK').catch(() => {}); client.release(); }
    async function blockedBy(waiter, holder) {
      const until = Date.now() + 3000;
      while (Date.now() < until) {
        const pids = (await owner.query('SELECT pg_blocking_pids($1) AS pids', [waiter])).rows[0].pids;
        if (pids.includes(holder)) return;
        await delay(10);
      }
      assert.fail('expected a real PostgreSQL lock wait');
    }
    async function seed(suffix, tenant = TENANT, { approvalMicroseconds = false, lifetimeMs = 3_600_000 } = {}) {
      const at = Date.now() - 20_000;
      const approvedAt = approvalMicroseconds ? iso(at).replace('Z', '001Z') : iso(at);
      const targetId = `tgt_authority_${suffix}`, groupId = `tg_authority_${suffix}`, reviewId = `rop_authority_${suffix}`;
      await sql('INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, $3)', [groupId, tenant, suffix], tenant);
      await sql(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value,
        protocol, port, expected_behavior, declaration_json) VALUES ($1, $2, $3, 'url', $4, $4, 'https', 443,
        'must_block_before_origin', '{"operation":"inert"}')`,
      [targetId, tenant, groupId, `https://${suffix.replaceAll('_', '-')}.example.test/diagnostic`], tenant);
      const target = (await sql('SELECT * FROM targets WHERE id = $1', [targetId], tenant)).rows[0];
      const source = JSON.stringify({ dns_target_binding: dnsOwnershipTargetBinding(target) });
      await sql(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref,
        transitioned_at, transitioned_by, audit_entry_id) VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', $4::jsonb,
        $5::timestamptz, 'fixture', 'audit_fixture')`, [`proof_${suffix}`, tenant, targetId, source, iso(at - 1000)], tenant);
      const proposal = buildReviewedOperationPlan({ target_id: targetId, check_id: CHECK, template: 'marker-query-v1',
        semantics: 'inert_diagnostic', side_effects: 'none', expires_at: iso(at + lifetimeMs) },
      { tenantId: tenant, target, check: getCheckById(CHECK), now: iso(at) });
      await sql(`INSERT INTO reviewed_operations (id, tenant_id, target_id, plan_json, plan_digest, approved_by,
        approved_role, approved_at) VALUES ($1, $2, $3, $4::jsonb, $5, $6, 'owner', $7::timestamptz)`,
      [reviewId, tenant, targetId, JSON.stringify(proposal.plan), proposal.plan_digest, ctx.userId, approvedAt], tenant);
      return { target, groupId, reviewId, source, proposal, request: { mode: 'build', reviewId, targetId, checkId: CHECK,
        originalAuthority: { issued_at: iso(at + 1000), not_after: iso(at + 120_000) } } };
    }
    const load = (f, request = f.request, callback = (snapshot) => snapshot, options) => authority.withCurrentAuthority(ctx, request, callback, options);
    async function denied(f, error, request = f.request, actor = ctx) {
      let invoked = false;
      const result = await authority.withCurrentAuthority(actor, request, () => { invoked = true; });
      assert.equal(invoked, false); assert.equal(result.ok, false, JSON.stringify(result));
      assert.equal(result.grants_execution, false); assert.equal(result.execution_available, false);
      if (error) assert.equal(result.error, error);
      return result;
    }
    try {
      await t.test('real non-owner NOSUPERUSER NOBYPASSRLS role reads full actual rows and exact direct history', async () => {
        const role = (await pool.query(`SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`)).rows[0];
        assert.deepEqual(role, { role: 'astranull_app', rolsuper: false, rolbypassrls: false });
        const f = await seed('snapshot');
        const snapshot = await load(f);
        assert.equal(snapshot.ok, true, JSON.stringify(snapshot));
        assert.equal(snapshot.grants_execution, false); assert.equal(snapshot.execution_available, false);
        assert.equal(snapshot.target.normalized_value, f.target.normalized_value);
        assert.equal(snapshot.target.declaration_json.operation, 'inert');
        assert.equal(snapshot.targetGroup.id, f.groupId);
        assert.equal(typeof snapshot.target.created_at, 'string');
        assert.equal(typeof snapshot.targetGroup.created_at, 'string');
        assert.equal(snapshot.target.created_at, f.target.created_at.toISOString());
        assert.equal(snapshot.target.created_at.setTime, undefined, 'frozen snapshots contain no mutable driver Dates');
        assert.match(snapshot.ownershipHistory[0].transitioned_at, /\.\d{3}000Z$/);
        assert.match(snapshot.ownership.transitioned_at, /\.\d{3}Z$/);
        assert.match(snapshot.review.approved_at, /\.\d{3}Z$/);
        assert.ok(Object.isFrozen(snapshot)); assert.ok(Object.isFrozen(snapshot.review.plan));
        const compared = await load(f, { mode: 'compare', targetId: f.target.id, checkId: CHECK, binding: snapshot.binding });
        assert.equal(compared.ok, true); assert.deepEqual(compared.binding.authority, snapshot.binding.authority);
        assert.deepEqual((await pool.query('SELECT id FROM reviewed_operations')).rows, [], 'unscoped RLS never reads authority');
      });

      await t.test('strict request and options reject caller records, selectors and replacement compare clocks', async () => {
        const f = await seed('strict'), binding = (await load(f)).binding;
        for (const request of [{ ...f.request, review: {} }, { ...f.request, ownership: true },
          { ...f.request, targetGroupId: f.groupId }, { ...f.request, originalAuthority: { ...f.request.originalAuthority, retry: true } },
          { ...f.request, originalAuthority: { ...f.request.originalAuthority, issued_at: f.request.originalAuthority.issued_at.replace(/\.\d{3}Z$/, 'Z') } },
          { ...f.request, originalAuthority: { ...f.request.originalAuthority, not_after: f.request.originalAuthority.not_after.replace(/\.\d{3}Z$/, 'Z') } },
          ...['issued_at', 'original_not_after', 'not_after'].map((field) => ({ mode: 'compare', targetId: f.target.id, checkId: CHECK,
            binding: { ...binding, authority: { ...binding.authority, [field]: binding.authority[field].replace(/\.\d{3}Z$/, 'Z') } } })),
          { mode: 'compare', targetId: f.target.id, checkId: CHECK, binding, reviewId: f.reviewId },
          { mode: 'compare', targetId: f.target.id, checkId: CHECK, binding, originalAuthority: f.request.originalAuthority },
          { mode: 'compare', targetId: f.target.id, checkId: CHECK, binding: undefined }]) {
          await denied(f, 'invalid_reviewed_operation_authority_request', request);
        }
        const invalid = await load(f, f.request, () => assert.fail(), { now: new Date() });
        assert.equal(invalid.error, 'invalid_reviewed_operation_authority_options');
      });

      await t.test('tenant, full material, active group, current ownership, revocation and expiry fail closed', async () => {
        const f = await seed('material'), foreign = await seed('foreign', OTHER);
        await denied(f, 'operation_target_changed', f.request, { ...ctx, tenantId: OTHER });
        await denied(f, 'operation_not_found', { ...f.request, reviewId: foreign.reviewId });
        await sql(`UPDATE targets SET declaration_json = jsonb_set(declaration_json, '{deep}', $2::jsonb) WHERE id = $1`,
          [f.target.id, JSON.stringify({ nested: { value: 'x'.repeat(1200) } })]);
        await denied(f, 'operation_target_changed');
        await sql(`UPDATE targets SET declaration_json = '{"operation":"inert"}' WHERE id = $1`, [f.target.id]);
        await sql('UPDATE target_groups SET archived_at = clock_timestamp() WHERE id = $1', [f.groupId]);
        await denied(f, 'operation_target_changed');
        await sql('UPDATE target_groups SET archived_at = NULL WHERE id = $1', [f.groupId]);
        await sql(`UPDATE target_verifications SET source_ref = jsonb_set(source_ref, '{dns_target_binding,version}', '"dns-ownership-target.v1"') WHERE target_id = $1`, [f.target.id]);
        await denied(f, 'ownership_not_verified');
        await sql('UPDATE target_verifications SET source_ref = $2::jsonb WHERE target_id = $1', [f.target.id, f.source]);
        await sql(`UPDATE target_verifications SET state = 'unverified' WHERE target_id = $1`, [f.target.id]);
        await denied(f, 'ownership_not_verified');
        await sql(`UPDATE target_verifications SET state = 'dns_verified' WHERE target_id = $1`, [f.target.id]);
        const expired = { ...f.request, originalAuthority: { issued_at: iso(Date.now() - 2000), not_after: iso(Date.now() - 1000) } };
        await denied(f, 'probe_authority_expired', expired);
        await sql(`UPDATE reviewed_operations SET revoked_at = clock_timestamp(), revoked_by = $2 WHERE id = $1`, [f.reviewId, ctx.userId]);
        await denied(f, 'operation_revoked');
      });

      await t.test('retained approval microseconds and expired review cannot be rounded or renewed into authority', async () => {
        const micros = await seed('approval_microseconds', TENANT, { approvalMicroseconds: true });
        assert.match((await repository.get(ctx, micros.reviewId)).approved_at, /\.\d{3}001Z$/);
        await denied(micros, 'operation_review_invalid');
        const expired = await seed('review_expired', TENANT, { lifetimeMs: 5000 });
        await denied(expired, 'operation_expired');
      });

      await t.test('current actual catalog is read and full definition drift denies without caller override', async () => {
        const f = await seed('catalog'), check = getCheckById(CHECK), before = check.description;
        try { check.description += ' changed'; await denied(f, 'operation_check_changed'); }
        finally { check.description = before; }
      });

      await t.test('all direct history is selected by raw microseconds; newer noncanonical proof cannot fall back', async () => {
        const f = await seed('chronology');
        await sql(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref,
          transitioned_at, transitioned_by, audit_entry_id) VALUES ('proof_micro_latest', $1, $2, 'dns_verified', 'dns_txt',
          $3::jsonb, $4::timestamptz, 'fixture', 'audit_fixture')`,
        [TENANT, f.target.id, f.source, iso(Date.parse(f.request.originalAuthority.issued_at) - 500)]);
        // Existing history is intentionally mutable in this fixture to model retained
        // rows predating the new INSERT clock trigger. No schema or trigger is relaxed.
        await sql(`UPDATE target_verifications SET transitioned_at =
          (SELECT transitioned_at FROM target_verifications WHERE id = 'proof_chronology') + interval '1 microsecond'
          WHERE id = 'proof_micro_latest'`);
        await denied(f, 'ownership_not_verified');
        await sql(`UPDATE target_verifications SET state = 'unverified' WHERE id = 'proof_micro_latest'`);
        await denied(f, 'ownership_not_verified');
        await sql(`UPDATE target_verifications SET transitioned_at =
          (SELECT transitioned_at FROM target_verifications WHERE id = 'proof_chronology') WHERE id = 'proof_micro_latest'`);
        await denied(f, 'ownership_not_verified', f.request);
        await sql(`UPDATE target_verifications SET transitioned_at = 'infinity' WHERE id = 'proof_micro_latest'`);
        await denied(f, 'ownership_not_verified');
      });

      await t.test('same-pool outer transaction is reused and async callback completes before release', async () => {
        const f = await seed('outer'), reader = await connect();
        try {
          await withTenantContext(pool, TENANT, async (outer) => {
            const pid = (await outer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
            const result = await load(f, f.request, async (snapshot) => {
              const nestedPid = (await sql('SELECT pg_backend_pid() AS pid')).rows[0].pid;
              assert.equal(nestedPid, pid);
              await sql(`UPDATE targets SET metadata_json = '{"callback":"held"}' WHERE id = $1`, [f.target.id]);
              const outside = (await reader.query('SELECT metadata_json FROM targets WHERE id = $1', [f.target.id])).rows[0];
              assert.notEqual(outside.metadata_json.callback, 'held');
              assert.equal((await reader.query('SELECT pg_try_advisory_xact_lock(hashtext($1)) AS acquired', [TENANT])).rows[0].acquired, false);
              await delay(5);
              assert.equal((await sql('SELECT metadata_json FROM targets WHERE id = $1', [f.target.id])).rows[0].metadata_json.callback, 'held');
              return snapshot;
            });
            assert.equal(result.ok, true);
            assert.equal((await reader.query('SELECT pg_try_advisory_xact_lock(hashtext($1)) AS acquired', [TENANT])).rows[0].acquired, false,
              'outer transaction still owns authority locks after callback');
          });
          assert.equal((await reader.query('SELECT metadata_json FROM targets WHERE id = $1', [f.target.id])).rows[0].metadata_json.callback, 'held');
        } finally { await cleanup(reader); }
      });

      await t.test('group, full target, review and ALL direct history rows remain FOR SHARE locked during callback', async () => {
        const f = await seed('all_row_locks');
        await sql(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref,
          transitioned_at, transitioned_by, audit_entry_id) VALUES ('proof_older_lock', $1, $2, 'unverified', 'dns_txt',
          '{}', clock_timestamp(), 'fixture', 'audit_fixture')`, [TENANT, f.target.id]);
        await sql(`UPDATE target_verifications SET transitioned_at =
          (SELECT transitioned_at FROM target_verifications WHERE id = 'proof_all_row_locks') - interval '1 second'
          WHERE id = 'proof_older_lock'`);
        const result = await load(f, f.request, async (snapshot) => {
          assert.equal(snapshot.ownershipHistory.length, 2);
          assert.equal(snapshot.ownership.id, 'proof_all_row_locks');
          for (const [table, id] of [['target_groups', f.groupId], ['targets', f.target.id],
            ['target_verifications', 'proof_older_lock'], ['target_verifications', 'proof_all_row_locks'], ['reviewed_operations', f.reviewId]]) {
            const writer = await connect();
            try {
              await assert.rejects(writer.query(`SELECT id FROM ${table} WHERE id = $1 FOR UPDATE NOWAIT`, [id]),
                (error) => error.code === '55P03', `${table}/${id} must be locked throughout callback`);
            } finally { await cleanup(writer); }
          }
          return snapshot;
        });
        assert.equal(result.ok, true);
      });

      await t.test('callback exception rolls back nested writes, even when outer caller swallows it', async () => {
        const f = await seed('rollback'), error = new Error('consumer failure');
        await assert.rejects(withTenantContext(pool, TENANT, async () => {
          try {
            await load(f, f.request, async () => {
              await sql(`UPDATE targets SET metadata_json = '{"callback":"must_rollback"}' WHERE id = $1`, [f.target.id]);
              throw error;
            });
          } catch (caught) { assert.equal(caught, error); }
        }), (caught) => caught === error);
        assert.notEqual((await sql('SELECT metadata_json FROM targets WHERE id = $1', [f.target.id])).rows[0].metadata_json.callback, 'must_rollback');
      });

      await t.test('standalone callback SQL failure rolls back its owned tenant transaction', async () => {
        const f = await seed('sql_rollback');
        await assert.rejects(load(f, f.request, async () => {
          await sql(`UPDATE targets SET metadata_json = '{"callback":"sql_rollback"}' WHERE id = $1`, [f.target.id]);
          await sql('SELECT 1 / 0');
        }), (error) => error.code === '22012');
        assert.notEqual((await sql('SELECT metadata_json FROM targets WHERE id = $1', [f.target.id])).rows[0].metadata_json.callback, 'sql_rollback');
      });

      await t.test('exact explicit MANAGED client is reused and callback failure poisons a swallowed outer transaction', async () => {
        const f = await seed('explicit'), error = new Error('explicit consumer failure');
        await assert.rejects(withTenantContext(pool, TENANT, async (client) => {
          const pid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          const result = await load(f, f.request, async (snapshot) => {
            assert.equal((await sql('SELECT pg_backend_pid() AS pid')).rows[0].pid, pid);
            await client.query(`UPDATE targets SET metadata_json = '{"callback":"explicit"}' WHERE id = $1`, [f.target.id]);
            return snapshot;
          }, { client });
          assert.equal(result.ok, true);
          assert.equal((await client.query('SELECT metadata_json FROM targets WHERE id = $1', [f.target.id])).rows[0].metadata_json.callback, 'explicit');
          try { await load(f, f.request, () => { throw error; }, { client }); }
          catch (caught) { assert.equal(caught, error); }
        }), (caught) => caught === error);
        assert.notEqual((await sql('SELECT metadata_json FROM targets WHERE id = $1', [f.target.id])).rows[0].metadata_json.callback, 'explicit');
      });

      await t.test('raw pool, autocommit, manual BEGIN, foreign tenant and foreign-pool clients never establish authority', async () => {
        const f = await seed('untracked'), auto = await pool.connect(), manual = await connect();
        const invalid = async (client, actor = ctx) => {
          let invoked = false;
          await assert.rejects(authority.withCurrentAuthority(actor, f.request, () => { invoked = true; }, { client }),
            (error) => error.code === 'reviewed_operation_authority_client_invalid');
          assert.equal(invoked, false);
        };
        try {
          await invalid(pool); await invalid(auto); await invalid(manual);
          await withTenantContext(pool, TENANT, async (held) => {
            await invalid(auto);
            await invalid(held, { ...ctx, tenantId: OTHER });
            const foreignPool = { connect() { assert.fail('must not connect on provided-client mismatch'); } };
            const otherAuthority = createReviewedOperationAuthority({ backend: createReviewedOperationRepository(foreignPool, createAuditRepository(pool)) });
            await assert.rejects(otherAuthority.withCurrentAuthority(ctx, f.request, () => assert.fail(), { client: held }),
              (error) => error.code === 'reviewed_operation_authority_client_invalid');
          });
        } finally { auto.release(); await cleanup(manual); }
      });

      for (const lock of ['audit', 'review']) await t.test(`fresh clock after real ${lock} lock wait rejects expired original deadline`, async () => {
        const f = await seed(`clock_${lock}`), holder = await connect(), waiterReady = deferred();
        let pending;
        try {
          if (lock === 'audit') await holder.query('SELECT pg_advisory_xact_lock(hashtext($1))', [TENANT]);
          else await holder.query('SELECT id FROM reviewed_operations WHERE id = $1 FOR UPDATE', [f.reviewId]);
          const holderPid = (await holder.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          f.request.originalAuthority.not_after = iso(Date.now() + 150);
          let invoked = false;
          pending = withTenantContext(pool, TENANT, async (waiter) => {
            waiterReady.resolve((await waiter.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
            return load(f, f.request, () => { invoked = true; }, { client: waiter });
          });
          void pending.catch(() => {});
          await blockedBy(await waiterReady.promise, holderPid);
          if (lock === 'audit') {
            // Audit is first: its holder must still update group/target while the
            // loader waits, rather than forming an audit-to-row deadlock cycle.
            await holder.query("SET LOCAL lock_timeout = '500ms'");
            await holder.query('UPDATE target_groups SET name = name WHERE id = $1', [f.groupId]);
            await holder.query('UPDATE targets SET value = value WHERE id = $1', [f.target.id]);
          }
          await delay(200);
          await holder.query('ROLLBACK');
          const result = await pending;
          assert.equal(result.error, 'probe_authority_expired'); assert.equal(invoked, false);
          assert.equal(result.grants_execution, false); assert.equal(result.execution_available, false);
        } finally {
          await holder.query('ROLLBACK').catch(() => {});
          if (pending) await pending.catch(() => {});
          await cleanup(holder);
        }
      });

      await t.test('canonical audit lock serializes actual new verification INSERTs until callback transaction ends', async () => {
        const f = await seed('insert_lock'), entered = deferred(), release = deferred(), writer = await connect();
        let reading, inserting;
        try {
          reading = load(f, f.request, async (snapshot) => {
            const pid = (await sql('SELECT pg_backend_pid() AS pid')).rows[0].pid;
            entered.resolve({ snapshot, pid });
            await release.promise;
            return snapshot;
          });
          const current = await entered.promise;
          const writerPid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          inserting = writer.query(`INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind,
            source_ref, transitioned_at, transitioned_by, audit_entry_id) VALUES ('proof_concurrent_loss', $1, $2,
            'unverified', 'dns_txt', '{}', clock_timestamp(), 'fixture', 'audit_fixture')`, [TENANT, f.target.id]);
          void inserting.catch(() => {});
          await blockedBy(writerPid, current.pid);
          assert.equal(current.snapshot.ownershipHistory.length, 1);
          release.resolve();
          assert.equal((await reading).ok, true);
          await inserting; await writer.query('COMMIT');
          await denied(f, 'ownership_not_verified');
          await denied(f, 'ownership_not_verified', { mode: 'compare', targetId: f.target.id, checkId: CHECK, binding: current.snapshot.binding });
        } finally {
          release.resolve();
          if (reading) await reading.catch(() => {});
          if (inserting) await inserting.catch(() => {});
          await cleanup(writer);
        }
      });

      await t.test('loader creates no audits, runs, jobs, reservations or authority writes', async () => {
        const row = (await sql(`SELECT (SELECT count(*)::int FROM audit_logs) AS audits,
          (SELECT count(*)::int FROM test_runs) AS runs, (SELECT count(*)::int FROM probe_jobs) AS jobs`)).rows[0];
        assert.deepEqual(row, { audits: 0, runs: 0, jobs: 0 });
        t.diagnostic('all authority reads used a real application login; no target DNS/socket/HTTP or deployment occurred');
      });
    } finally { await closePgPool(pool); }
  }, availability.env);
});
