// Integration: protection validation through the Postgres runtime (app role, RLS), including PV-05 and PV-06 seams.
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { normalizeComparisonEvaluation } from '../../src/contracts/protectionValidation.mjs';
import { createPostgresProtectionFindingsRepository } from '../../src/persistence/postgres/protectionFindingsRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createServer } from '../../src/server.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import {
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT = 'ten_pv_pg_api';
const GROUP = 'tg_pv_pg_api';
const DECLARED = '2026-09-01T00:00:00.000Z';
const SOURCE = 'astranull-signed-public-worker';
const CHECK = 'tls.full_audit.safe';

const admin = () => demoHeaders('admin', TENANT, 'usr_pv_admin');
const viewer = () => demoHeaders('viewer', TENANT, 'usr_pv_viewer');

async function seedTlsRun(client, { id, targetId, day, tls }) {
  const at = `${day}T00:00:00.000Z`;
  await client.query(
    `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, producer_kind, check_version, completed_at, created_at)
     VALUES ($1, $2, $3, $4, $5, 'running', 'signed_probe', '1.0.0', $6::timestamptz, $6::timestamptz)`,
    [id, TENANT, GROUP, targetId, CHECK, at],
  );
  for (const index of [0, 1]) {
    await client.query(
      `INSERT INTO events (id, tenant_id, test_run_id, target_id, check_id, source, signal_type, producer_kind, timestamp, metadata_json)
       VALUES ($1, $2, $3, $4, $5, 'probe_worker', 'probe_result', 'signed_probe', $6::timestamptz, $7::jsonb)`,
      [`evt_${id}_${index}`, TENANT, id, targetId, CHECK, `${day}T00:0${index}:00.000Z`, JSON.stringify({
        profile_kind: 'tls_audit',
        external_result: tls ? 'blocked' : 'timeout',
        probe_worker_id: 'worker_pool_1',
        safety_attestation: { requests_sent: 1, duration_ms: 4 },
        ...(tls ? { tls_protocol: 'TLSv1.3' } : { error_class: 'ETIMEDOUT' }),
      })],
    );
  }
  await client.query(
    `INSERT INTO verdicts (id, tenant_id, test_run_id, target_id, check_id, verdict, evidence_ids, created_at)
     VALUES ($1, $2, $3, $4, $5, 'pass', ARRAY[]::text[], $6::timestamptz)`,
    [`vrd_${id}`, TENANT, id, targetId, CHECK, at],
  );
  await client.query(`UPDATE test_runs SET status = 'verdicted' WHERE tenant_id = $1 AND id = $2`, [TENANT, id]);
}

describe('protection validation over the Postgres runtime', () => {
  it('captures and evaluates a firewall change, persists findings, and gates retests with real RLS', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await withTenantContext(ownerPool, TENANT, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'PV API')`, [TENANT]);
        await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ('env_pv_pg_api', $1, 'prod')`, [TENANT]);
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode)
           VALUES ($1, $2, 'env_pv_pg_api', 'PV', 'dns_verified', 'external_only')`,
          [GROUP, TENANT],
        );
        for (const [id, value] of [['tgt_pg_api_fw', 'fw.example.test'], ['tgt_pg_api_app', 'app.example.test']]) {
          await client.query(
            `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
             VALUES ($1, $2, $3, 'fqdn', $4, $4, $5::timestamptz)`,
            [id, TENANT, GROUP, value, DECLARED],
          );
          await client.query(
            `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
             VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', '{}'::jsonb, $4::timestamptz, 'usr_pv_admin', 'aud_seed')`,
            [`tv_${id}`, TENANT, id, DECLARED],
          );
        }
        await seedTlsRun(client, { id: 'run_pg_api_pre', targetId: 'tgt_pg_api_fw', day: '2026-10-01', tls: true });
        await seedTlsRun(client, { id: 'run_pg_api_post', targetId: 'tgt_pg_api_fw', day: '2026-10-03', tls: false });
      });

      await ensureHarnessAppRole(ownerPool);
      await ownerPool.query(`ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
      const url = new URL(databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName).replace(/^postgresql:/i, 'postgres:'));
      url.username = APP_ROLE_NAME;
      url.password = APP_ROLE_PASSWORD;
      const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
      const appPool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl });
      const env = {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_PERSISTENCE_MODE: 'postgres',
        ASTRANULL_DATABASE_URL: appUrl,
        ASTRANULL_RATE_LIMIT_DISABLED: '1',
        ASTRANULL_PROTECTION_VALIDATION_ENABLED: '1',
        ASTRANULL_APPROVED_PROBE_SOURCES: '',
      };
      delete env.ASTRANULL_NO_PERSIST;
      const runtime = await createPostgresRuntime(env, { createPool: () => appPool, closePool: async () => {} });
      const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env, services: runtime.services, runtimeHealth: runtime.health });
      server.listen(0);
      const baseUrl = `http://127.0.0.1:${server.address().port}`;
      try {
        const expectation = await request(baseUrl, 'POST', '/v1/firewall-expectations', {
          headers: admin(),
          body: { destination_target_id: 'tgt_pg_api_fw', protocol: 'tcp', port: 443, expected: 'allow', source_perspective: SOURCE, change_id: 'CHG-PG-1' },
        });
        assert.equal(expectation.status, 201, expectation.text);
        const baseline = await request(baseUrl, 'POST', '/v1/firewall-baselines', {
          headers: admin(), body: { change_id: 'CHG-PG-1', expectation_ids: [expectation.json.id], test_run_ids: ['run_pg_api_pre'] },
        });
        assert.equal(baseline.status, 201, baseline.text);
        assert.equal(baseline.json.digest_verified, true);
        assert.equal(baseline.json.entries[0].observations.length, 2);
        const listed = await request(baseUrl, 'GET', '/v1/firewall-baselines?change_id=CHG-PG-1', { headers: viewer() });
        assert.equal(listed.status, 200, listed.text);
        assert.equal(listed.json.items[0].entries[0].observations_digest, baseline.json.entries[0].observations_digest);

        const comparison = await request(baseUrl, 'POST', '/v1/firewall-comparisons', {
          headers: admin(), body: { baseline_id: baseline.json.id, post_test_run_ids: ['run_pg_api_post'] },
        });
        assert.equal(comparison.status, 201, comparison.text);
        assert.equal(comparison.json.items[0].status, 'regression');
        assert.equal(comparison.json.items[0].gap_kind, 'required_service_newly_unavailable');
        const replay = await request(baseUrl, 'POST', '/v1/firewall-comparisons', {
          headers: admin(), body: { baseline_id: baseline.json.id, post_test_run_ids: ['run_pg_api_post'] },
        });
        assert.equal(replay.status, 200, replay.text);
        assert.equal(replay.json.id, comparison.json.id);

        const findings = await ownerPool.query(
          `SELECT id, source, finding_class, priority, target_group_id, protection_validation_json->'comparison_context'->>'evaluation_id' AS evaluation_id
           FROM findings WHERE tenant_id = $1 AND source = 'protection_validation'`,
          [TENANT],
        );
        assert.equal(findings.rows.length, 1);
        assert.equal(findings.rows[0].finding_class, 'observed_availability_gap');
        assert.equal(findings.rows[0].target_group_id, null);
        assert.equal(findings.rows[0].evaluation_id, comparison.json.id);
        const audits = await ownerPool.query(
          `SELECT action, count(*)::int AS n FROM audit_logs WHERE tenant_id = $1
             AND action IN ('firewall_baseline.captured', 'firewall_comparison.evaluated', 'finding.created') GROUP BY action`,
          [TENANT],
        );
        assert.deepEqual(Object.fromEntries(audits.rows.map((row) => [row.action, row.n])), {
          'finding.created': 1, 'firewall_baseline.captured': 1, 'firewall_comparison.evaluated': 1,
        });

        // No row exists to FOR UPDATE: a racing weak observation must not swallow the stronger finding.
        await ownerPool.query('DELETE FROM findings WHERE tenant_id = $1 AND source = $2', [TENANT, 'protection_validation']);
        const low = { ...normalizeComparisonEvaluation({ ...comparison.json, items: comparison.json.items.map((item) => ({
          ...item, status: 'matched', gap_kind: null, expectation_met: false, pre_state: 'not_observed', post_state: 'not_observed',
        })) }), id: 'fwc_concurrent_low' };
        const findingRepository = createPostgresProtectionFindingsRepository(appPool);
        const context = { tenantId: TENANT, userId: 'usr_pv_admin', role: 'admin' };
        const records = { expectations: [{ ...expectation.json, tenant_id: TENANT }], baseline: baseline.json };
        const concurrent = await Promise.all([
          findingRepository.upsertProtectionFindingsFromEvaluation(context, low, records),
          findingRepository.upsertProtectionFindingsFromEvaluation(context, comparison.json, records),
        ]);
        assert.ok(concurrent.every((result) => result.ok));
        const winner = await ownerPool.query('SELECT id, severity, priority FROM findings WHERE tenant_id = $1 AND source = $2', [TENANT, 'protection_validation']);
        assert.equal(winner.rows.length, 1);
        assert.equal(winner.rows[0].severity, 'high');
        findings.rows[0].id = winner.rows[0].id;

        const findingRead = await request(baseUrl, 'GET', `/v1/findings/${findings.rows[0].id}`, { headers: viewer() });
        assert.equal(findingRead.status, 200, findingRead.text);

        const matrix = await request(baseUrl, 'GET', '/v1/targets/tgt_pg_api_app/protection-validation', { headers: viewer() });
        assert.equal(matrix.status, 200, matrix.text);
        assert.deepEqual(matrix.json.paths, []);
        const comparisons = await request(baseUrl, 'GET', '/v1/entry-path-comparisons', { headers: viewer() });
        assert.equal(comparisons.status, 200, comparisons.text);
        assert.deepEqual(comparisons.json, { items: [], count: 0, next_cursor: null });
        const missingComparison = await request(baseUrl, 'GET', '/v1/entry-path-comparisons/epc_missing', { headers: viewer() });
        assert.equal(missingComparison.status, 404, missingComparison.text);
        const viewerStart = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', { headers: viewer(), body: { mode: 'plan' } });
        assert.equal(viewerStart.status, 403, viewerStart.text);
        const report = await request(baseUrl, 'GET', '/v1/reports/protection-validation', { headers: viewer() });
        assert.equal(report.status, 200, report.text);
        assert.equal(report.json.units.firewall_expectations.denominator, 1);

        const archive = await request(baseUrl, 'POST', `/v1/firewall-expectations/${expectation.json.id}/archive`, { headers: admin() });
        assert.equal(archive.status, 200, archive.text);
        const retest = await request(baseUrl, 'POST', '/v1/test-runs', {
          headers: admin(),
          body: { check_id: CHECK, target_group_id: GROUP, target_id: 'tgt_pg_api_fw', retest_of_finding_id: findings.rows[0].id },
        });
        assert.equal(retest.status, 409, retest.text);
        assert.equal(retest.json.error, 'retest_not_authorized');
        const lineage = await ownerPool.query('SELECT count(*)::int AS n FROM finding_retest_lineage WHERE tenant_id = $1', [TENANT]);
        assert.equal(lineage.rows[0].n, 0);
      } finally {
        await closeServer(server);
        await runtime.close();
        await closePgPool(appPool);
      }
    }, availability.env);
  });
});
