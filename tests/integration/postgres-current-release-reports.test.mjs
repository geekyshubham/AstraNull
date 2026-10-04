import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createReportRepository } from '../../src/persistence/postgres/reportRepository.mjs';
import { createPostgresReportServices } from '../../src/persistence/postgres/reportServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT = 'ten_report_scope';
const OTHER = 'ten_report_other';
const GROUP = 'tg_report_scope';
const OTHER_GROUP = 'tg_report_other';
const TARGET = 'tgt_report_scope';
const FOREIGN_TARGET = 'tgt_report_foreign';
const CHECK = 'origin.direct_bypass.safe';
const HEADER_MARKER = 'synthetic-vault-header-marker';
const NOTE_MARKER = 'synthetic-finding-note-marker';
const CTX = { tenantId: TENANT, userId: 'usr_report', role: 'admin' };

async function createAppRolePool(adminPool, ownerDatabaseUrl) {
  await adminPool.query(
    `ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`,
  );
  const url = new URL(ownerDatabaseUrl.replace(/^postgresql:/i, 'postgres:'));
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
  const pool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl });
  const check = await pool.query(
    'SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user',
  );
  assert.equal(check.rows[0].role, APP_ROLE_NAME);
  assert.equal(check.rows[0].rolsuper, false);
  assert.equal(check.rows[0].rolbypassrls, false);
  return pool;
}

async function reportCount(ownerPool) {
  const { rows } = await ownerPool.query('SELECT count(*)::int AS n FROM reports');
  return rows[0].n;
}

describe('postgres current-release reports', () => {
  it('validates scope, freezes the snapshot, and keeps it after later closure', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await assertRlsPoliciesExist(ownerPool, ['tenant_isolation_reports', 'tenant_isolation_targets', 'tenant_isolation_evidence_vault']);
      const now = Date.now();
      await withTenantContext(ownerPool, TENANT, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Report scope')`, [TENANT]);
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'Scope group'), ($3, $2, 'Empty group')`,
          [GROUP, TENANT, 'tg_report_empty'],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, declaration_json)
           VALUES ($1, $2, $3, 'fqdn', 'origin.example', 'origin.example', $4::jsonb)`,
          [TARGET, TENANT, GROUP, JSON.stringify({
            purpose: 'checkout',
            service_roles: ['api'],
            owner_label: 'ops',
            criticality: 'high',
          })],
        );
        for (let i = 0; i <= 10; i += 1) {
          const started = new Date(i === 0 ? now - 40 * 24 * 60 * 60 * 1000 : now - (10 - i) * 60_000).toISOString();
          await client.query(
            `INSERT INTO test_runs (
               id, tenant_id, target_group_id, target_id, check_id, status, vector_family, safety_class, started_at, created_at
             ) VALUES ($1, $2, $3, $4, $5, 'verdicted', 'volumetric', 'safe', $6::timestamptz, $6::timestamptz)`,
            [`run_${String(i).padStart(2, '0')}`, TENANT, GROUP, TARGET, CHECK, started],
          );
        }
        await client.query(
          `INSERT INTO verdicts (id, tenant_id, test_run_id, target_id, check_id, verdict, confidence, explanation, evidence_ids, created_at)
           VALUES ('vd_05', $1, 'run_05', $2, $3, 'fail', 'high', 'blocked at the edge', ARRAY['ev_1']::text[], $4::timestamptz)`,
          [TENANT, TARGET, CHECK, new Date(now).toISOString()],
        );
        await client.query(
          `INSERT INTO evidence_vault (id, tenant_id, test_run_id, label, metadata_json, created_at)
           VALUES ('ev_1', $1, 'run_05', 'probe', $2::jsonb, $3::timestamptz)`,
          [TENANT, JSON.stringify({ authorization: HEADER_MARKER }), new Date(now).toISOString()],
        );
        await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status, notes, evidence_ids, created_at
           ) VALUES ('fnd_1', $1, $2, $3, 'run_05', $4, 'Open gap', 'high', 'open', $5, ARRAY['ev_1']::text[], $6::timestamptz)`,
          [TENANT, GROUP, TARGET, CHECK, NOTE_MARKER, new Date(now).toISOString()],
        );
      });
      await withTenantContext(ownerPool, OTHER, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Other')`, [OTHER]);
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'Other group')`,
          [OTHER_GROUP, OTHER],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
           VALUES ($1, $2, $3, 'fqdn', 'foreign.example', 'foreign.example')`,
          [FOREIGN_TARGET, OTHER, OTHER_GROUP],
        );
      });

      await ensureHarnessAppRole(ownerPool);
      const appPool = await createAppRolePool(ownerPool, databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName));
      try {
        const reports = createPostgresReportServices({
          reports: createReportRepository(appPool),
          validationEvidence: createValidationEvidenceRepository(appPool),
          audit: createAuditRepository(appPool),
        }).reports;

        assert.equal((await reports.createReport(CTX, { targets: [TARGET] })).error, 'unrecognized_scope');
        assert.equal((await reports.createReport(CTX, { target_ids: [TARGET], target_group_ids: ['tg_report_empty'] })).error, 'scope_mismatch');
        const foreign = await reports.createReport(CTX, { target_ids: [FOREIGN_TARGET] });
        assert.equal(foreign.error, 'unknown_target');
        assert.equal(JSON.stringify(foreign).includes('foreign.example'), false);
        assert.equal(await reportCount(ownerPool), 0);

        const omitted = await reports.createReport(CTX, { kind: 'technical', title: 'Estate', period: 'all-time' });
        assert.equal(omitted.summary.readiness_score, null);
        assert.equal(omitted.summary.readiness_factors.status, 'postgres_report_readiness_summary_not_wired');
        assert.equal(omitted.summary.run_capture.total, 11);
        assert.equal(omitted.summary.run_capture.included, 10);
        assert.equal(omitted.summary.run_capture.excluded, 1);
        assert.equal(omitted.summary.run_capture.total_status, 'complete');
        assert.equal(omitted.summary.primary_run_id, null);
        assert.equal(omitted.run_ids[0], 'run_10');
        assert.equal(omitted.run_ids.includes('run_00'), false);
        assert.equal(omitted.summary.scope.selection, 'omitted_defaults_to_tenant');
        assert.equal(JSON.stringify(omitted.summary).includes(HEADER_MARKER), false);

        assert.equal((await reports.createReport(CTX, { run_ids: ['run_00'], period: 'last-7-days' })).error, 'run_outside_period');
        assert.equal(await reportCount(ownerPool), 1);

        const scoped = await reports.createReport(CTX, {
          kind: 'technical',
          title: 'Scoped',
          target_ids: [TARGET],
          run_ids: ['run_02', 'run_05'],
        });
        assert.deepEqual(scoped.run_ids, ['run_02', 'run_05']);
        assert.equal(scoped.summary.primary_run_id, null);
        assert.equal(scoped.summary.snapshot_frozen, true);
        assert.equal(scoped.summary.readiness_score, null);
        assert.deepEqual(scoped.summary.readiness_factors, []);
        assert.equal(scoped.summary.readiness_score_status, 'unknown');
        assert.equal(scoped.summary.readiness_score_reason, 'published_readiness_formula_is_tenant_wide');
        assert.equal(scoped.summary.sections.protection_profile.status, 'not_included');
        assert.equal(scoped.summary.sections.protection_profile.reason, 'no_frozen_protection_profile_on_declared_target');
        assert.equal(scoped.summary.declaration_snapshot.items[0].purpose, 'checkout');
        assert.equal(scoped.summary.findings_snapshot.items[0].status, 'open');
        assert.equal(JSON.stringify(scoped.summary).includes(HEADER_MARKER), false);
        assert.equal(JSON.stringify(scoped.summary).includes(NOTE_MARKER), false);
        const frozen = JSON.parse(JSON.stringify(scoped.summary));

        const beforeInspection = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query(
            `SELECT count(*)::int AS n FROM audit_logs WHERE action = 'report.exported'`,
          );
          return rows[0].n;
        });
        assert.equal(await reports.getReport({ ...CTX, role: 'viewer' }, scoped.id) != null, true);
        assert.equal((await reports.listReports({ ...CTX, role: 'viewer' })).some((row) => row.id === scoped.id), true);
        const afterInspection = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query(
            `SELECT count(*)::int AS n FROM audit_logs WHERE action = 'report.exported'`,
          );
          return rows[0].n;
        });
        assert.equal(afterInspection, beforeInspection);

        await withTenantContext(appPool, TENANT, async (client) => {
          await client.query(`UPDATE findings SET status = 'closed', updated_at = now() WHERE id = 'fnd_1'`);
          await client.query(`UPDATE test_runs SET status = 'cancelled' WHERE id = 'run_05'`);
          await client.query(
            `INSERT INTO test_runs (
               id, tenant_id, target_group_id, target_id, check_id, status, started_at, created_at
             ) VALUES ('run_pass', $1, $2, $3, $4, 'verdicted', now(), now())`,
            [TENANT, GROUP, TARGET, CHECK],
          );
          await client.query(
            `INSERT INTO verdicts (id, tenant_id, test_run_id, target_id, check_id, verdict, confidence, explanation, created_at)
             VALUES ('vd_pass', $1, 'run_pass', $2, $3, 'pass', 'high', 'later pass', now())`,
            [TENANT, TARGET, CHECK],
          );
        });

        const reread = await reports.getReport(CTX, scoped.id);
        assert.deepEqual(reread.summary, frozen);
        const exported = await reports.exportReport(CTX, scoped.id, 'json');
        assert.deepEqual(exported.payload.runs.map((run) => run.id), ['run_02', 'run_05']);
        assert.equal(exported.payload.runs.find((run) => run.id === 'run_05').status, 'verdicted');
        assert.equal(exported.payload.summary.findings_snapshot.items[0].status, 'open');
        assert.equal(JSON.stringify(exported).includes(HEADER_MARKER), false);
        assert.equal(JSON.stringify(exported).includes('run_pass'), false);
        assert.deepEqual((await reports.getReport(CTX, scoped.id)).summary, frozen);

        assert.equal(await reports.getReport({ tenantId: OTHER, userId: 'usr_other', role: 'admin' }, scoped.id), null);
        assert.equal(await reports.exportReport({ tenantId: OTHER, userId: 'usr_other', role: 'admin' }, scoped.id, 'json'), null);
        const otherAudits = await withTenantContext(appPool, OTHER, async (client) => {
          const { rows } = await client.query(`SELECT count(*)::int AS n FROM audit_logs WHERE action = 'report.exported'`);
          return rows[0].n;
        });
        assert.equal(otherAudits, 0);
        const hidden = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query(`SELECT id FROM targets WHERE id = $1`, [FOREIGN_TARGET]);
          return rows.length;
        });
        assert.equal(hidden, 0);
      } finally {
        await closePgPool(appPool);
      }
    });
  });
});
