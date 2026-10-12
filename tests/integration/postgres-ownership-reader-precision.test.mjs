import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { buildReviewedOperationPlan } from '../../src/contracts/reviewedOperations.mjs';
import { buildReviewedOperationBinding } from '../../src/contracts/reviewedOperationBinding.mjs';
import { effectiveTargetVerifications } from '../../src/lib/effectiveTargetVerification.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createReviewedOperationRepository } from '../../src/persistence/postgres/reviewedOperationRepository.mjs';
import { createProtectionValidationRepository } from '../../src/persistence/postgres/protectionValidationRepository.mjs';
import { createTargetHistoryRepository } from '../../src/persistence/postgres/targetHistoryRepository.mjs';
import { createReviewedOperationService } from '../../src/services/reviewedOperations.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { listMigrationFiles, runMigrations } from '../../src/persistence/postgres/migrations.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { MIGRATIONS_DIR, databaseUrlWithDatabase, ensureHarnessAppRole,
  resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_reader_precision';
const ctx = { tenantId: TENANT, userId: 'usr_precision', role: 'owner' };
const AT = '2026-10-10T00:00:00.000Z';
const EXPIRES = '2026-10-10T01:00:00.000Z';
const MIGRATION = '0077_ownership_transition_order.sql';
const check = getCheckById('waf.evasion_base64_wrap.safe');
const input = (id) => ({ target_id: id, check_id: check.check_id, template: 'marker-query-v1',
  semantics: 'inert_diagnostic', side_effects: 'none', expires_at: EXPIRES });
const instant = (fraction) => `2026-10-09T00:00:00.${fraction}Z`;
const cases = [
  { name: 'latest_verified', rows: [['pending', '000100'], ['dns_verified', '000900']], state: 'dns_verified' },
  { name: 'latest_pending', rows: [['dns_verified', '000100'], ['pending', '000900']], state: 'pending' },
  { name: 'changed_source', rows: [['dns_verified', '000100', { token: 'old' }], ['dns_verified', '000900', { token: 'new' }]], state: 'dns_verified' },
  { name: 'conflicting_tie', rows: [['dns_verified', '000900'], ['pending', '000900']], state: 'pending' },
  { name: 'equivalent_tie', rows: [['dns_verified', '000900', { a: 1, b: 2 }], ['dns_verified', '000900', { b: 2, a: 1 }]], state: 'dns_verified' },
  { name: 'later_than_tie', rows: [['dns_verified', '000100'], ['pending', '000100'], ['dns_verified', '000900']], state: 'dns_verified' },
  { name: 'nonfinite_history', rows: [['pending', '-infinity'], ['dns_verified', '000900']], state: 'pending' },
  { name: 'nonfinite_latest', rows: [['dns_verified', '000900'], ['dns_verified', 'infinity']], state: 'pending' },
  { name: 'unrepresentable_history', rows: [['dns_verified', '275760-09-13T00:00:00.001Z']], state: 'pending' },
];
const rowTime = (value) => value.includes('T') || value.includes('infinity') ? value : instant(value);
const approvals = [
  { name: 'approval_millis', at: AT, projected: AT, valid: true },
  { name: 'approval_micros', at: '2026-10-10T00:00:00.000999Z', projected: '2026-10-10T00:00:00.000999Z', valid: false },
];

function localEnv() {
  const env = { ...process.env, ASTRANULL_RUN_PUBLIC_DNS: '0' };
  for (const key of ['ASTRANULL_DATABASE_URL', 'ASTRANULL_ADMIN_DATABASE_URL']) {
    if (!env[key]) continue;
    const url = new URL(env[key]);
    assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'precision tests require loopback PostgreSQL');
    assert.ok(!url.searchParams.has('host') && !url.searchParams.has('hostaddr'), 'no remote host override');
  }
  return env;
}

test('PostgreSQL ownership readers preserve legacy exact chronology without execution', { timeout: 120_000 }, async (t) => {
  const env = localEnv();
  const available = await resolvePostgresHarnessAvailability(env, { tryDocker: false });
  if (!available.available) return t.skip(available.reason);
  await withEphemeralPostgres(async (owner, { databaseName }) => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files: files.filter((file) => file.name < MIGRATION) });
    await ensureHarnessAppRole(owner);
    const seed = (fn) => withTenantContext(owner, TENANT, fn);
    const targets = new Map();
    await seed(async (client) => {
      await client.query("INSERT INTO tenants (id, name) VALUES ($1, 'Reader precision')", [TENANT]);
      await client.query("INSERT INTO target_groups (id, tenant_id, name) VALUES ('tg_precision', $1, 'Historical association')", [TENANT]);
      for (const name of [...cases.map((item) => item.name), ...approvals.map((item) => item.name)]) {
        const id = `tgt_precision_${name}`;
        const target = (await client.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, protocol, port, expected_behavior)
          VALUES ($1, $2, 'tg_precision', 'url', $3, 'https', 443, 'intentionally_public') RETURNING *`,
        [id, TENANT, `https://${name.replaceAll('_', '-')}.example.test/diagnostics`])).rows[0];
        targets.set(name, target);
        const history = cases.find((item) => item.name === name)?.rows ?? [['dns_verified', '000000']];
        for (let index = 0; index < history.length; index++) {
          const [state, fraction, source = {}] = history[index];
          await client.query(`INSERT INTO target_verifications
            (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
            VALUES ($1, $2, $3, $4, 'dns_txt', $5::jsonb, $6::timestamptz, 'fixture', 'aud_fixture')`,
          [`tv_precision_${name}_${index}`, TENANT, id, state, JSON.stringify({ ...source, dns_target_binding: dnsOwnershipTargetBinding(target) }), rowTime(fraction)]);
        }
      }
      for (const { name, at: approvedAt } of approvals) {
        const target = targets.get(name);
        const proposal = buildReviewedOperationPlan(input(target.id), { tenantId: TENANT, target, check, now: AT });
        await client.query(`INSERT INTO reviewed_operations (id, tenant_id, target_id, plan_json, plan_digest, approved_by, approved_role, approved_at)
          VALUES ($1, $2, $3, $4::jsonb, $5, $6, 'owner', $7::timestamptz)`,
        [`rop_precision_${name}`, TENANT, target.id, JSON.stringify(proposal.plan), proposal.plan_digest, ctx.userId, approvedAt]);
      }
    });
    // Seed legacy microsecond/tied/nonfinite history before 0077. Only this new
    // ephemeral local database is migrated; no existing rows are repaired/backfilled.
    await runMigrations(owner, { migrationsDir: MIGRATIONS_DIR, files: files.filter((file) => file.name >= MIGRATION) });
    await ensureHarnessAppRole(owner);
    const url = new URL(databaseUrlWithDatabase(owner.options.connectionString, databaseName));
    url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
    url.searchParams.set('options', '-c timezone=Asia/Kolkata -c statement_timeout=15000');
    const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
    const sql = (statement, params = []) => withTenantContext(pool, TENANT, (client) => client.query(statement, params));
    const reviewed = createReviewedOperationRepository(pool, createAuditRepository(pool));
    const service = createReviewedOperationService({ backend: reviewed, now: () => new Date(AT) });
    const pv = createProtectionValidationRepository(pool);
    const history = createTargetHistoryRepository(pool);
    const snapshot = async () => (await sql(`SELECT
      (SELECT jsonb_agg(to_jsonb(tv) ORDER BY id) FROM target_verifications tv) AS ownership,
      (SELECT jsonb_agg(to_jsonb(ro) ORDER BY id) FROM reviewed_operations ro) AS reviews,
      (SELECT count(*)::int FROM audit_logs) AS audits,
      (SELECT count(*)::int FROM test_runs) AS runs,
      (SELECT count(*)::int FROM probe_jobs) AS jobs`)).rows[0];
    try {
      const before = await snapshot();
      await t.test('runs through a real non-owner non-BYPASSRLS application login', async () => {
        const role = (await pool.query('SELECT current_user AS name, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user')).rows[0];
        assert.deepEqual(role, { name: 'astranull_app', rolsuper: false, rolbypassrls: false });
      });
      for (const reader of ['reviewed', 'protection', 'history']) {
        for (const item of cases) await t.test(`${reader}: ${item.name} agrees with exact database current state`, async () => {
          const target = targets.get(item.name);
          const expected = (await sql('SELECT * FROM target_verification_current WHERE tenant_id = $1 AND target_id = $2', [TENANT, target.id])).rows[0];
          assert.equal(expected.state, item.state);
          if (reader === 'reviewed') {
            const actual = await reviewed.withTarget(ctx, target.id, (tx) => tx.context());
            assert.equal(actual.ownershipVerified, item.state === 'dns_verified');
            if (item.state === 'dns_verified') {
              const preview = await service.preview(ctx, input(target.id));
              assert.equal(preview.error, undefined);
              assert.equal(preview.grants_execution, false);
              assert.equal(preview.execution_available, false);
            } else assert.deepEqual(await service.preview(ctx, input(target.id)), { error: 'ownership_not_verified', status: 409 });
          } else {
            const records = reader === 'protection' ? (await pv.loadTargetContext(ctx, [target.id])).records
              : await history.loadBindingContext(ctx, [target.id]);
            const actual = effectiveTargetVerifications(records, TENANT, [target.id]).get(target.id);
            assert.equal(actual.state, item.state);
            assert.equal(actual.source_kind, expected.source_kind);
            assert.deepEqual(actual.source_ref, expected.source_ref);
            for (let index = 0; index < item.rows.length; index++) {
              const fraction = item.rows[index][1];
              const row = records.targetVerifications.find((record) => record.id === `tv_precision_${item.name}_${index}`);
              if (!fraction.includes('infinity')) assert.equal(row.transitioned_at,
                fraction.includes('T') ? fraction.replace('.001Z', '.001000Z') : instant(fraction), 'precision must survive node-postgres parsing');
            }
          }
        });
      }
      for (const { name, projected: expected, valid } of approvals) await t.test(`review material: ${name} is not normalized into different authority`, async () => {
        const target = targets.get(name);
        const row = await reviewed.get(ctx, `rop_precision_${name}`);
        const result = buildReviewedOperationBinding({ reviewId: row.id, review: row, tenantId: TENANT, target, check,
          ownership: { tenant_id: TENANT, target_id: target.id, state: 'dns_verified', source_kind: 'dns_txt',
            source_ref: { dns_target_binding: dnsOwnershipTargetBinding(target) }, transitioned_at: '2026-10-09T00:00:00.000Z' },
          originalAuthority: { issued_at: AT, not_after: '2026-10-10T00:02:00.000Z' }, now: AT });
        assert.equal(result.grants_execution, false); assert.equal(result.execution_available, false);
        assert.equal(result.ok, valid, JSON.stringify(result));
        if (!valid) assert.equal(result.error, 'operation_review_invalid');
        assert.equal(row.approved_at, expected);
        await reviewed.withTarget(ctx, target.id, async (tx) => {
          assert.equal((await tx.get(row.id)).approved_at, expected);
          assert.equal((await tx.findByDigest(row.plan_digest)).approved_at, expected);
        });
      });
      await t.test('passive projection preserves historical rows/audits and creates no runs or jobs', async () => {
        assert.deepEqual(await snapshot(), before);
        assert.equal(before.runs, 0); assert.equal(before.jobs, 0);
      });
    } finally { await closePgPool(pool); }
  }, env, { applyMigrations: false });
});
