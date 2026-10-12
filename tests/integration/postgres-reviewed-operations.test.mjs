import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { buildReviewedOperationPlan, reviewedOperationGap } from '../../src/contracts/reviewedOperations.mjs';
import { createReviewedOperationService } from '../../src/services/reviewedOperations.mjs';
import { createReviewedOperationRepository } from '../../src/persistence/postgres/reviewedOperationRepository.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { databaseUrlWithDatabase, resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_reviewed_pg';
const OTHER = 'ten_reviewed_other';
const ctx = { tenantId: TENANT, userId: 'usr_reviewed_owner', role: 'owner' };
const foreign = { ...ctx, tenantId: OTHER };
const AT = '2026-10-10T00:00:00.000Z';
const EXPIRES = '2026-10-10T01:00:00.000Z';
const check = getCheckById('waf.evasion_alt_charset.safe');
const body = (targetId, extra = {}) => ({ target_id: targetId, check_id: check.check_id,
  template: 'inert-json-v1', semantics: 'inert_diagnostic', side_effects: 'none', expires_at: EXPIRES, ...extra });
const inert = (result) => {
  assert.equal(result.error, undefined, JSON.stringify(result));
  assert.equal(result.grants_execution, false);
  assert.equal(result.execution_available, false);
};
const INSERT = `INSERT INTO reviewed_operations
  (id, tenant_id, target_id, plan_json, plan_digest, approved_by, approved_role, approved_at)
  VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)`;
const insertParams = (id, proposal, actor = ctx) => [id, proposal.plan.tenant_id, proposal.plan.target_id,
  JSON.stringify(proposal.plan), proposal.plan_digest, actor.userId, actor.role, AT];

// Refuse remote URLs before the harness can ping them. This suite only creates and
// destroys ephemeral local databases; the declared .test URLs are never contacted.
function localHarnessEnv() {
  const env = { ...process.env };
  for (const key of ['ASTRANULL_DATABASE_URL', 'ASTRANULL_ADMIN_DATABASE_URL']) {
    if (!env[key]) continue;
    const url = new URL(env[key]);
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), `${key} must be loopback for this suite`);
    assert.ok(!url.searchParams.has('host') && !url.searchParams.has('hostaddr'), 'database URL must not override its loopback host');
  }
  return env;
}

test('PostgreSQL reviewed inert preflight foundation (no execution authority)', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(localHarnessEnv(), { tryDocker: false });
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    await owner.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Reviewed operations'), ($2, 'Foreign tenant')`, [TENANT, OTHER]);
    await owner.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES
      ('tg_reviewed_pg', $1, 'Historical association'), ('tg_reviewed_other', $2, 'Other historical association')`, [TENANT, OTHER]);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app';
    url.password = 'astranull_app_local_dev';
    url.searchParams.set('options', '-c timezone=UTC -c statement_timeout=15000');
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const audit = createAuditRepository(pool);
    const repository = createReviewedOperationRepository(pool, audit);
    let clock = AT;
    const serviceWith = (auditRepository = audit) => createReviewedOperationService({
      backend: createReviewedOperationRepository(pool, auditRepository), now: () => new Date(clock),
    });
    const service = serviceWith();
    const sql = (tenant, statement, params = []) => withTenantContext(pool, tenant, (client) => client.query(statement, params));
    const counts = async () => (await sql(TENANT, `SELECT
      (SELECT count(*)::int FROM reviewed_operations) AS operations,
      (SELECT count(*)::int FROM audit_logs) AS audits,
      (SELECT count(*)::int FROM test_runs) AS runs,
      (SELECT count(*)::int FROM probe_jobs) AS jobs`)).rows[0];
    const auditsFor = async (id) => (await audit.listAuditEntries(ctx)).filter((entry) => entry.resource_id === id);
    async function seedTarget(id, tenant = TENANT, verified = true) {
      const endpoint = `https://${id.replaceAll('_', '-')}.example.test/diagnostics`;
      await sql(tenant, `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value,
        protocol, port, expected_behavior, declaration_json, created_at)
        VALUES ($1, $2, $3, 'url', $4, $4, 'https', 443, 'intentionally_public', '{}', '2026-10-09T00:00:00Z')`,
      [id, tenant, tenant === TENANT ? 'tg_reviewed_pg' : 'tg_reviewed_other', endpoint]);
      const target = (await sql(tenant, 'SELECT * FROM targets WHERE id = $1', [id])).rows[0];
      if (verified) await sql(tenant, `INSERT INTO target_verifications
        (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
        VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', $4::jsonb, '2026-10-09T00:00:00Z', 'fixture', 'audit_fixture')`,
      [`proof_${id}`, tenant, id, JSON.stringify({ dns_target_binding: dnsOwnershipTargetBinding(target) })]);
      return target;
    }
    async function approve(targetId, actor = ctx, extra = {}) {
      const input = body(targetId, extra);
      const preview = await service.preview(actor, input);
      inert(preview);
      const result = await service.approve(actor, { ...input, reviewed_plan_digest: preview.plan_digest });
      inert(result);
      return result;
    }
    const rejectSql = (statement, params, code, message) => assert.rejects(sql(TENANT, statement, params),
      (error) => error.code === code && (!message || message.test(error.message)));
    try {
      await t.test('uses a real non-owner non-BYPASSRLS application login and FORCE RLS', async () => {
        const role = (await pool.query(`SELECT current_user AS role, rolsuper, rolbypassrls
          FROM pg_roles WHERE rolname = current_user`)).rows[0];
        assert.deepEqual(role, { role: 'astranull_app', rolsuper: false, rolbypassrls: false });
        const table = (await pool.query(`SELECT relrowsecurity, relforcerowsecurity,
          pg_get_userbyid(relowner) = current_user AS is_owner FROM pg_class WHERE oid = 'reviewed_operations'::regclass`)).rows[0];
        assert.deepEqual(table, { relrowsecurity: true, relforcerowsecurity: true, is_owner: false });
        assert.equal((await pool.query(`SELECT count(*)::int AS n FROM pg_policies
          WHERE tablename = 'reviewed_operations' AND policyname = 'reviewed_operations_tenant_isolation'`)).rows[0].n, 1);
      });

      await t.test('orders PostgreSQL verification instants rather than locale weekday strings', async () => {
        const target = await seedTarget('tgt_reviewed_ownership_order');
        await sql(TENANT, "UPDATE target_verifications SET transitioned_at = '2026-10-08T00:00:00Z' WHERE target_id = $1", [target.id]);
        await sql(TENANT, `INSERT INTO target_verifications
          (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
          VALUES ('proof_reviewed_newer_pending', $1, $2, 'pending', 'dns_txt', '{}', '2026-10-09T00:00:00Z', 'fixture', 'audit_fixture')`, [TENANT, target.id]);
        assert.deepEqual(await service.preview(ctx, body(target.id)), { error: 'ownership_not_verified', status: 409 });
        await sql(TENANT, `INSERT INTO target_verifications
          (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
          VALUES ('proof_reviewed_newest_verified', $1, $2, 'dns_verified', 'dns_txt', $3::jsonb, '2026-10-10T00:00:00Z', 'fixture', 'audit_fixture')`,
        [TENANT, target.id, JSON.stringify({ dns_target_binding: dnsOwnershipTargetBinding(target) })]);
        inert(await service.preview(ctx, body(target.id)));
      });

      await t.test('preview is side-effect free and approval pins the fixed plan without dispatch', async () => {
        const target = await seedTarget('tgt_reviewed_preview');
        const before = await counts();
        const preview = await service.preview(ctx, body(target.id));
        inert(preview);
        assert.deepEqual(preview, buildReviewedOperationPlan(body(target.id), { tenantId: TENANT, target, check, now: AT }));
        assert.equal(preview.plan.endpoint, target.value);
        assert.equal(preview.plan.method, 'POST');
        assert.equal(preview.plan.request_schema, 'fixed-asn-marker-json.v1');
        assert.equal(preview.plan.maximum_body_bytes, 1024);
        assert.equal(preview.plan.maximum_probe_operations, 4);
        assert.deepEqual(await counts(), before);
        const row = await approve(target.id);
        assert.equal(row.replayed, false);
        assert.equal(row.current_review_gap, null);
        assert.equal(row.approved_by, ctx.userId);
        assert.equal(row.approved_role, ctx.role);
        assert.equal(row.approved_at, AT);
        const persisted = await repository.get(ctx, row.id);
        assert.deepEqual(persisted.plan, preview.plan);
        assert.equal(persisted.plan_digest, preview.plan_digest);
        const events = await auditsFor(row.id);
        assert.equal(events.length, 1);
        assert.equal(events[0].action, 'reviewed_operation.approved');
        assert.equal(events[0].actor_user_id, ctx.userId);
        assert.equal(events[0].actor_role, ctx.role);
        assert.deepEqual(events[0].metadata, { target_id: target.id, plan_digest: row.plan_digest });
        assert.deepEqual(await counts(), { ...before, operations: before.operations + 1, audits: before.audits + 1 });
      });

      await t.test('replay preserves original reviewer and timestamp and writes no extra audit', async () => {
        const target = await seedTarget('tgt_reviewed_replay');
        const row = await approve(target.id);
        const before = await counts();
        clock = '2026-10-10T00:01:00.000Z';
        try {
          const replay = await service.approve({ ...ctx, userId: 'usr_other_admin', role: 'admin' },
            body(target.id, { reviewed_plan_digest: row.plan_digest }));
          inert(replay);
          assert.deepEqual(replay, { ...row, replayed: true });
          assert.deepEqual(await counts(), before);
          assert.equal((await auditsFor(row.id)).length, 1);
        } finally { clock = AT; }
      });

      await t.test('eight overlapping approvals produce one record, seven replays and one audit', async () => {
        const target = await seedTarget('tgt_reviewed_race');
        const preview = await service.preview(ctx, body(target.id));
        inert(preview);
        const before = await counts();
        const results = await Promise.all(Array.from({ length: 8 }, (_, i) => service.approve(
          { ...ctx, userId: `usr_concurrent_${i}` }, body(target.id, { reviewed_plan_digest: preview.plan_digest }))));
        results.forEach(inert);
        assert.equal(new Set(results.map((row) => row.id)).size, 1);
        assert.equal(results.filter((row) => row.replayed === false).length, 1);
        assert.equal(results.filter((row) => row.replayed === true).length, 7);
        const winner = results.find((row) => row.replayed === false);
        assert.ok(results.every((row) => row.approved_by === winner.approved_by));
        assert.deepEqual(await counts(), { ...before, operations: before.operations + 1, audits: before.audits + 1 });
        assert.equal((await auditsFor(winner.id)).length, 1);
        await rejectSql(INSERT, insertParams('rop_reviewed_duplicate', preview), '23505');
      });

      await t.test('takes tenant audit before target locks so catalog mutations cannot deadlock with approval', async () => {
        const target = await seedTarget('tgt_reviewed_audit_order');
        const preview = await service.preview(ctx, body(target.id));
        inert(preview);
        const before = await counts();
        const catalogClient = await pool.connect(), reviewClient = await pool.connect();
        let pending;
        try {
          await catalogClient.query('BEGIN');
          await catalogClient.query("SELECT set_config('app.tenant_id', $1, true)", [TENANT]);
          await catalogClient.query("SET LOCAL statement_timeout = '2000ms'");
          await catalogClient.query('SELECT pg_advisory_xact_lock(hashtext($1))', [TENANT]);
          const catalogPid = (await catalogClient.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          const reviewPid = (await reviewClient.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          const reviewPool = { connect: async () => ({ query: (...args) => reviewClient.query(...args), release() {} }) };
          const competing = createReviewedOperationService({ now: () => new Date(AT),
            backend: createReviewedOperationRepository(reviewPool, audit) });
          pending = competing.approve(ctx, body(target.id, { reviewed_plan_digest: preview.plan_digest }));
          void pending.catch(() => {});
          let blocked = false;
          const until = Date.now() + 2000;
          while (Date.now() < until) {
            const blockers = (await owner.query('SELECT pg_blocking_pids($1) AS pids', [reviewPid])).rows[0].pids;
            if (blockers.includes(catalogPid)) { blocked = true; break; }
            await delay(10);
          }
          assert.equal(blocked, true, 'approval must actually wait for the catalog tenant-audit lock');
          // The catalog lock holder must still acquire the target row. The old
          // target-first review held FOR SHARE here and formed an audit↔target cycle.
          const updated = await catalogClient.query('UPDATE targets SET value = value WHERE tenant_id = $1 AND id = $2 RETURNING id', [TENANT, target.id]);
          assert.equal(updated.rowCount, 1);
          await catalogClient.query('ROLLBACK');
          const row = await pending;
          inert(row);
          assert.equal(row.current_review_gap, null);
          assert.equal((await auditsFor(row.id)).length, 1);
          assert.deepEqual(await counts(), { ...before, operations: before.operations + 1, audits: before.audits + 1 });
        } finally {
          await catalogClient.query('ROLLBACK').catch(() => {});
          if (pending) await pending.catch(() => {});
          catalogClient.release(); reviewClient.release();
        }
      });

      await t.test('RLS isolates bare SQL reads, writes and inserts, not just repository predicates', async () => {
        const target = await seedTarget('tgt_reviewed_rls');
        const otherTarget = await seedTarget('tgt_reviewed_other', OTHER);
        const row = await approve(target.id);
        const otherRow = await approve(otherTarget.id, foreign);
        const before = await counts();
        assert.deepEqual((await sql(OTHER, 'SELECT id FROM reviewed_operations WHERE id = $1', [row.id])).rows, []);
        assert.deepEqual((await sql(TENANT, 'SELECT id FROM reviewed_operations WHERE id = $1', [otherRow.id])).rows, []);
        assert.equal((await sql(OTHER, `UPDATE reviewed_operations SET revoked_at = $2, revoked_by = 'foreign'
          WHERE id = $1 RETURNING id`, [row.id, AT])).rowCount, 0);
        assert.equal((await sql(OTHER, 'DELETE FROM reviewed_operations WHERE id = $1 RETURNING id', [row.id])).rowCount, 0);
        assert.deepEqual((await pool.query('SELECT id FROM reviewed_operations')).rows, []);
        assert.equal((await pool.query(`UPDATE reviewed_operations SET revoked_at = $2, revoked_by = 'unscoped'
          WHERE id = $1`, [row.id, AT])).rowCount, 0);
        const foreignProposal = { plan: otherRow.plan, plan_digest: otherRow.plan_digest };
        await rejectSql(INSERT, insertParams('rop_reviewed_foreign_insert', foreignProposal, foreign), '42501');
        await assert.rejects(pool.query(INSERT, insertParams('rop_reviewed_unscoped_insert',
          { plan: row.plan, plan_digest: row.plan_digest })), (error) => error.code === '42501');
        assert.equal(await repository.get(foreign, row.id), null);
        assert.deepEqual(await service.get(foreign, row.id), { error: 'operation_not_found', status: 404 });
        assert.deepEqual(await service.revoke(foreign, row.id), { error: 'operation_not_found', status: 404 });
        assert.deepEqual(await service.preview(foreign, body(target.id)), { error: 'target_not_found', status: 404 });
        assert.deepEqual(await service.approve(foreign, body(target.id, { reviewed_plan_digest: row.plan_digest })),
          { error: 'target_not_found', status: 404 });
        assert.equal((await audit.listAuditEntries(foreign)).some((event) => event.resource_id === row.id), false);
        assert.deepEqual(await counts(), before);
        assert.equal((await repository.get(ctx, row.id)).revoked_at, null);
      });

      await t.test('composite tenant FK rejects a foreign target even when row and plan use the current tenant', async () => {
        const target = (await sql(OTHER, 'SELECT * FROM targets WHERE id = $1', ['tgt_reviewed_other'])).rows[0];
        // This internally consistent own-tenant plan passes the plan CHECK and RLS;
        // only the (tenant_id, target_id) FK can reject the actual foreign target.
        const proposal = buildReviewedOperationPlan(body(target.id), {
          tenantId: TENANT, target: { ...target, tenant_id: TENANT }, check, now: AT,
        });
        const before = await counts();
        await assert.rejects(sql(TENANT, INSERT, insertParams('rop_reviewed_bad_fk', proposal)),
          (error) => error.code === '23503' && error.constraint === 'fk_reviewed_operations_target_tenant');
        assert.deepEqual(await counts(), before);
      });

      await t.test('database rejects malformed fixed plans even through a direct application SQL writer', async () => {
        const target = await seedTarget('tgt_reviewed_plan_checks');
        const preview = await service.preview(ctx, body(target.id));
        inert(preview);
        const before = await counts();
        const mutations = [
          { method: 'DELETE' }, { maximum_body_bytes: 1025 }, { maximum_body_bytes: '1024' },
          { endpoint: null }, { endpoint: 42 }, { endpoint: 'ftp://owned.example.test/' },
          { request_schema: 'arbitrary-json' }, { maximum_probe_operations: 5 }, { maximum_probe_operations: '4' },
          { target_definition_digest: null }, { check_definition_digest: 'invalid' }, { check_id: null },
          { check_version: '' }, { scenario_version: 123 }, { semantics: 'business_transaction' },
          { side_effects: 'send_email' }, { expires_at: null }, { expires_at: '2026-10-10 01:00:00+00' },
          { expires_at: AT }, { expires_at: '2026-10-11T00:00:00.001Z' },
          { template: 'marker-query-v1' },
        ];
        for (let i = 0; i < mutations.length; i++) {
          const malformed = { ...preview, plan: { ...preview.plan, ...mutations[i] } };
          await assert.rejects(sql(TENANT, INSERT, insertParams(`rop_bad_plan_${i}`, malformed)),
            (error) => error.code === '23514' && error.constraint === 'reviewed_operations_plan_check',
            JSON.stringify(mutations[i]));
        }
        const missing = structuredClone(preview);
        delete missing.plan.endpoint;
        await rejectSql(INSERT, insertParams('rop_missing_endpoint', missing), '23514');
        assert.deepEqual(await counts(), before);
      });

      await t.test('approval requires an authorized human and exact digest and rejects arbitrary payload fields', async () => {
        const target = await seedTarget('tgt_reviewed_denials');
        const preview = await service.preview(ctx, body(target.id));
        inert(preview);
        const before = await counts();
        for (const actor of [{ ...ctx, role: 'viewer' }, { ...ctx, role: 'engineer' }, { ...ctx, role: 'soc' },
          { ...ctx, serviceAccountId: 'svc_reviewed' }, { ...ctx, scopes: ['test_run:read'] }, { ...ctx, userId: undefined }]) {
          assert.deepEqual(await service.approve(actor, body(target.id, { reviewed_plan_digest: preview.plan_digest })),
            { error: 'forbidden', status: 403 });
        }
        for (const digest of [undefined, '0'.repeat(64)]) {
          assert.deepEqual(await service.approve(ctx, body(target.id, { reviewed_plan_digest: digest })),
            { error: 'reviewed_plan_digest_mismatch', status: 409 });
        }
        for (const extra of [{ raw_body: 'not accepted' }, { approved_by: 'forged' }, { grants_execution: true },
          { endpoint: 'https://foreign.example.test/' }, { headers: {} }]) {
          assert.deepEqual(await service.approve(ctx, body(target.id, { ...extra, reviewed_plan_digest: preview.plan_digest })),
            { error: 'operation_field_not_allowed', status: 400 });
        }
        for (const expires_at of [null, 1791594000000, '2026-10-10', '2026-10-10T01:00:00+00:00',
          '2026-10-10T01:00:00.0000Z', '2026-02-30T01:00:00.000Z']) {
          assert.deepEqual(await service.preview(ctx, body(target.id, { expires_at })),
            { error: 'operation_expiry_invalid', status: 400 });
        }
        const normalized = await service.preview(ctx, body(target.id, { expires_at: '2026-10-10T01:00:00Z' }));
        inert(normalized);
        assert.equal(normalized.plan.expires_at, EXPIRES);
        assert.equal(normalized.plan_digest, preview.plan_digest);
        assert.deepEqual(await counts(), before);
      });

      await t.test('database history guard rejects plan, digest, reviewer, identity, timestamp changes and deletion', async () => {
        const target = await seedTarget('tgt_reviewed_immutable');
        const row = await approve(target.id);
        const persisted = await repository.get(ctx, row.id);
        const before = await counts();
        for (const assignment of [
          `plan_json = jsonb_set(plan_json, '{endpoint}', '"https://changed.example.test/"'::jsonb)`,
          `plan_digest = repeat('0', 64)`, `approved_by = 'forged'`, `approved_role = 'admin'`,
          `approved_at = approved_at + interval '1 second'`, `id = 'rop_rewritten'`,
          `target_id = 'tgt_reviewed_preview'`, `tenant_id = '${OTHER}'`,
        ]) {
          // Include an otherwise valid first revocation so these assertions test
          // immutable scope comparison, not merely the no-op update guard.
          await rejectSql(`UPDATE reviewed_operations SET revoked_at = $2, revoked_by = $3, ${assignment} WHERE id = $1`,
            [row.id, '2026-10-10T00:02:00.000Z', ctx.userId], 'P0001', /scope is immutable/);
        }
        for (const assignment of [`plan_digest = plan_digest`, `revoked_at = NULL, revoked_by = NULL`]) {
          await rejectSql(`UPDATE reviewed_operations SET ${assignment} WHERE id = $1`, [row.id], 'P0001', /scope is immutable/);
        }
        await rejectSql('DELETE FROM reviewed_operations WHERE id = $1', [row.id], 'P0001', /history cannot be deleted/);
        assert.deepEqual(await repository.get(ctx, row.id), persisted);
        assert.deepEqual(await counts(), before);
      });

      await t.test('revocation is constrained, concurrent, audited once and terminal with immutable readable history', async () => {
        const target = await seedTarget('tgt_reviewed_revoke');
        const row = await approve(target.id);
        const before = await counts();
        for (const [at, by, code] of [[AT, null, '23514'], [null, ctx.userId, 'P0001'],
          ['2026-10-09T23:59:59Z', ctx.userId, '23514'], [AT, '', '23514']]) {
          await rejectSql('UPDATE reviewed_operations SET revoked_at = $2, revoked_by = $3 WHERE id = $1',
            [row.id, at, by], code);
        }
        clock = '2026-10-10T00:02:00.000Z';
        try {
          assert.deepEqual(await service.revoke({ ...ctx, role: 'engineer' }, row.id), { error: 'forbidden', status: 403 });
          const results = await Promise.all(Array.from({ length: 6 }, () => service.revoke(ctx, row.id)));
          const winners = results.filter((result) => !result.error);
          assert.equal(winners.length, 1);
          inert(winners[0]);
          assert.equal(winners[0].current_review_gap, 'operation_revoked');
          assert.equal(winners[0].revoked_at, clock);
          assert.equal(winners[0].revoked_by, ctx.userId);
          assert.equal(results.filter((result) => result.error === 'operation_revoked' && result.status === 409).length, 5);
          assert.deepEqual(await service.approve(ctx, body(target.id, { reviewed_plan_digest: row.plan_digest })),
            { error: 'operation_revoked', status: 409 });
          const history = await service.get(ctx, row.id);
          inert(history);
          assert.equal(history.current_review_gap, 'operation_revoked');
          assert.deepEqual(history.plan, row.plan);
          assert.equal(history.plan_digest, row.plan_digest);
          assert.equal(history.approved_at, row.approved_at);
          const events = await auditsFor(row.id);
          assert.deepEqual(events.map((event) => event.action), ['reviewed_operation.approved', 'reviewed_operation.revoked']);
          assert.deepEqual(events[1].metadata, { target_id: target.id, plan_digest: row.plan_digest });
          assert.equal(events[1].actor_user_id, ctx.userId);
          for (const assignment of [`revoked_at = NULL, revoked_by = NULL`, `revoked_by = 'replacement'`,
            `revoked_at = revoked_at + interval '1 second'`, `revoked_at = revoked_at`]) {
            await rejectSql(`UPDATE reviewed_operations SET ${assignment} WHERE id = $1`, [row.id], 'P0001', /scope is immutable/);
          }
          await rejectSql('DELETE FROM reviewed_operations WHERE id = $1', [row.id], 'P0001', /history cannot be deleted/);
          assert.deepEqual(await counts(), { ...before, audits: before.audits + 1 });
        } finally { clock = AT; }
      });

      await t.test('get re-reads persisted revocation after its initial unlocked lookup becomes stale', async () => {
        const target = await seedTarget('tgt_reviewed_read_race');
        const row = await approve(target.id);
        let interleaved = false;
        const readService = createReviewedOperationService({ now: () => new Date(clock), backend: {
          ...repository,
          async get(actor, id) {
            const stale = await repository.get(actor, id);
            assert.equal(stale.revoked_at, null);
            const revoked = await service.revoke(ctx, id);
            inert(revoked);
            interleaved = true;
            return stale;
          },
        } });
        const current = await readService.get(ctx, row.id);
        inert(current);
        assert.equal(interleaved, true);
        assert.equal(current.current_review_gap, 'operation_revoked');
        assert.equal(current.revoked_at, AT);
        assert.equal(current.revoked_by, ctx.userId);
        assert.deepEqual(current.plan, row.plan);
        assert.equal((await auditsFor(row.id)).length, 2);
      });

      // Inject failure only at the audit adapter boundary, after the real audit
      // INSERT. SQL division by zero aborts the actual shared PostgreSQL transaction.
      function failingAudit(onInserted) {
        return { async appendAuditEvent(entry, options) {
          assert.ok(options?.client, 'audit must receive the operation transaction client');
          const event = await audit.appendAuditEvent(entry, options);
          const visible = (await options.client.query(`SELECT revoked_at FROM reviewed_operations WHERE id = $1`, [entry.resource_id])).rows[0];
          assert.ok(visible, 'operation write is visible in the audit transaction before failure');
          assert.equal((await options.client.query('SELECT count(*)::int AS n FROM audit_logs WHERE id = $1', [event.id])).rows[0].n, 1);
          onInserted(visible);
          await options.client.query('SELECT 1 / 0');
        } };
      }

      await t.test('approval and real inserted audit both roll back on a database audit failure', async () => {
        const target = await seedTarget('tgt_reviewed_rollback_insert');
        const preview = await service.preview(ctx, body(target.id));
        inert(preview);
        const before = await counts();
        let sawWrite = false;
        const broken = serviceWith(failingAudit((visible) => { sawWrite = true; assert.equal(visible.revoked_at, null); }));
        await assert.rejects(broken.approve(ctx, body(target.id, { reviewed_plan_digest: preview.plan_digest })),
          (error) => error.code === '22012');
        assert.equal(sawWrite, true);
        assert.deepEqual(await counts(), before);
        assert.deepEqual((await sql(TENANT, 'SELECT id FROM reviewed_operations WHERE plan_digest = $1', [preview.plan_digest])).rows, []);
        const retry = await approve(target.id);
        assert.equal(retry.replayed, false);
        assert.equal((await auditsFor(retry.id)).length, 1);
      });

      await t.test('revocation and real inserted audit both roll back on a database audit failure', async () => {
        const target = await seedTarget('tgt_reviewed_rollback_revoke');
        const row = await approve(target.id);
        const persisted = await repository.get(ctx, row.id);
        const before = await counts();
        let sawWrite = false;
        const broken = serviceWith(failingAudit((visible) => { sawWrite = true; assert.ok(visible.revoked_at); }));
        await assert.rejects(broken.revoke(ctx, row.id), (error) => error.code === '22012');
        assert.equal(sawWrite, true);
        assert.deepEqual(await repository.get(ctx, row.id), persisted);
        assert.deepEqual(await counts(), before);
        const retry = await service.revoke(ctx, row.id);
        inert(retry);
        assert.equal(retry.current_review_gap, 'operation_revoked');
        assert.equal((await auditsFor(row.id)).filter((event) => event.action === 'reviewed_operation.revoked').length, 1);
      });

      await t.test('target URL and declaration changes invalidate stale digests without rewriting history', async () => {
        const target = await seedTarget('tgt_reviewed_scope');
        const row = await approve(target.id);
        const persisted = await repository.get(ctx, row.id);
        await sql(TENANT, 'UPDATE targets SET value = $2, normalized_value = $2 WHERE id = $1',
          [target.id, `https://${target.id.replaceAll('_', '-')}.example.test/changed-path`]);
        const before = await counts();
        const changed = await service.get(ctx, row.id);
        inert(changed);
        assert.equal(changed.current_review_gap, 'operation_target_changed');
        assert.deepEqual(await service.approve(ctx, body(target.id, { reviewed_plan_digest: row.plan_digest })),
          { error: 'ownership_not_verified', status: 409 });
        assert.deepEqual(await repository.get(ctx, row.id), persisted);
        assert.deepEqual(await counts(), before);
        assert.deepEqual(await service.preview(ctx, body(target.id)), { error: 'ownership_not_verified', status: 409 });
        const changedTarget = (await sql(TENANT, 'SELECT * FROM targets WHERE id = $1', [target.id])).rows[0];
        await sql(TENANT, `INSERT INTO target_verifications
          (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
          VALUES ('proof_reviewed_changed_material', $1, $2, 'dns_verified', 'dns_txt', $3::jsonb,
            '2026-10-10T00:00:00Z', 'fixture', 'audit_fixture')`,
        [TENANT, target.id, JSON.stringify({ dns_target_binding: dnsOwnershipTargetBinding(changedTarget) })]);
        const fresh = await approve(target.id);
        assert.notEqual(fresh.id, row.id);
        assert.notEqual(fresh.plan_digest, row.plan_digest);
        assert.equal(fresh.current_review_gap, null);
        await sql(TENANT, `UPDATE targets SET declaration_json = '{"allowed_scope":{"paths":["/changed-path"]}}'::jsonb WHERE id = $1`, [target.id]);
        assert.equal((await service.get(ctx, fresh.id)).current_review_gap, 'operation_target_changed');
        assert.deepEqual(await service.approve(ctx, body(target.id, { reviewed_plan_digest: fresh.plan_digest })),
          { error: 'ownership_not_verified', status: 409 });
        // Check scope validation uses a real stored row, not a fabricated approval.
        assert.equal(reviewedOperationGap(persisted, { tenantId: TENANT, target, now: AT,
          check: { ...check, probe_profile: { ...check.probe_profile, timeout_ms: 123 } } }), 'operation_check_changed');
        assert.deepEqual(await repository.get(ctx, row.id), persisted);
      });

      await t.test('ownership loss, target deletion and expiry fail closed while preserving retained reviews', async () => {
        const unverified = await seedTarget('tgt_reviewed_unverified', TENANT, false);
        assert.deepEqual(await service.preview(ctx, body(unverified.id)), { error: 'ownership_not_verified', status: 409 });
        assert.deepEqual(await service.approve(ctx, body(unverified.id)), { error: 'ownership_not_verified', status: 409 });
        const target = await seedTarget('tgt_reviewed_lifecycle');
        const row = await approve(target.id);
        const persisted = await repository.get(ctx, row.id);
        const before = await counts();
        await sql(TENANT, `UPDATE target_verifications SET state = 'unverified' WHERE target_id = $1`, [target.id]);
        const lost = await service.get(ctx, row.id);
        inert(lost);
        assert.equal(lost.current_review_gap, 'ownership_not_verified');
        assert.deepEqual(await service.approve(ctx, body(target.id, { reviewed_plan_digest: row.plan_digest })),
          { error: 'ownership_not_verified', status: 409 });
        await sql(TENANT, `UPDATE target_verifications SET state = 'dns_verified' WHERE target_id = $1`, [target.id]);
        await sql(TENANT, 'UPDATE targets SET deleted_at = $2 WHERE id = $1', [target.id, AT]);
        assert.equal((await service.get(ctx, row.id)).current_review_gap, 'operation_target_changed');
        assert.deepEqual(await service.preview(ctx, body(target.id)), { error: 'ownership_not_verified', status: 409 });
        assert.deepEqual(await service.approve(ctx, body(target.id, { reviewed_plan_digest: row.plan_digest })),
          { error: 'ownership_not_verified', status: 409 });
        await sql(TENANT, 'UPDATE targets SET deleted_at = NULL WHERE id = $1', [target.id]);
        clock = EXPIRES;
        try {
          const expired = await service.get(ctx, row.id);
          inert(expired);
          assert.equal(expired.current_review_gap, 'operation_expired');
          assert.deepEqual(await service.approve(ctx, body(target.id, { reviewed_plan_digest: row.plan_digest })),
            { error: 'operation_expiry_invalid', status: 400 });
        } finally { clock = AT; }
        assert.deepEqual(await repository.get(ctx, row.id), persisted);
        assert.deepEqual(await counts(), before);
      });

      await t.test('fixed GET template stays inert, audit chain has no rollback holes and no traffic work exists', async () => {
        const target = await seedTarget('tgt_reviewed_get');
        const row = await approve(target.id, ctx, { template: 'marker-query-v1' });
        assert.equal(row.plan.method, 'GET');
        assert.equal(row.plan.maximum_body_bytes, 0);
        assert.equal(row.plan.request_schema, 'fixed-asn-probe-query.v1');
        const events = await audit.listAuditEntries(ctx);
        for (let i = 0; i < events.length; i++) {
          assert.equal(events[i].sequence, i + 1);
          assert.equal(events[i].prev_hash ?? null, i ? events[i - 1].entry_hash : null);
        }
        const final = await counts();
        assert.equal(final.runs, 0);
        assert.equal(final.jobs, 0);
        const all = (await sql(TENANT, 'SELECT id FROM reviewed_operations')).rows;
        for (const stored of all) inert(await service.get(ctx, stored.id));
        assert.deepEqual(await counts(), final, 'retained review reads must not mutate persistence or dispatch');
        t.diagnostic(`tenant records=${final.operations}, audit events=${final.audits}, test runs=${final.runs}, probe jobs=${final.jobs}`);
      });
    } finally { await closePgPool(pool); }
  }, availability.env);
});
