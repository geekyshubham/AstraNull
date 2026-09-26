import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createServer } from '../../src/server.mjs';
import { validHighScaleRequestPayload } from '../helpers/highScalePayload.mjs';
import { closeServer, demoHeaders, request, staffHeaders } from '../helpers/http.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT_A = 'ten_remed_a';
const TENANT_B = 'ten_remed_b';
const ENV_A = 'env_remed_a';
const ENV_B = 'env_remed_b';
const GROUP_A = 'tg_remed_a';
const GROUP_B = 'tg_remed_b';

async function createAppRolePool(ownerPool, databaseName) {
  await ensureHarnessAppRole(ownerPool);
  await ownerPool.query(`ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
  const url = new URL(databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName).replace(/^postgresql:/i, 'postgres:'));
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
  return { appUrl, appPool: createPgPool({ ASTRANULL_DATABASE_URL: appUrl }) };
}

async function seedTenants(ownerPool) {
  for (const [tenant, env, group, host] of [
    [TENANT_A, ENV_A, GROUP_A, 'a.remed.example.com'],
    [TENANT_B, ENV_B, GROUP_B, 'b.remed.example.com'],
  ]) {
    await withTenantContext(ownerPool, tenant, async (client) => {
      await client.query(`INSERT INTO tenants (id, name) VALUES ($1, $2)`, [tenant, `Tenant ${tenant}`]);
      await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'prod')`, [env, tenant]);
      await client.query(
        `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES ($1, $2, $3, 'edge')`,
        [group, tenant, env],
      );
      await client.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
         VALUES ($1, $2, $3, 'fqdn', $4, $4)`,
        [`tgt_${group}`, tenant, group, host],
      );
    });
  }
}

async function withPostgresServer(run) {
  await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
    await seedTenants(ownerPool);
    const { appUrl, appPool } = await createAppRolePool(ownerPool, databaseName);
    const env = {
      ...process.env,
      NODE_ENV: 'test',
      ASTRANULL_PERSISTENCE_MODE: 'postgres',
      ASTRANULL_DATABASE_URL: appUrl,
      ASTRANULL_WAF_POSTURE_ENABLED: '1',
      ASTRANULL_CONNECTORS_ENABLED: '1',
      ASTRANULL_RATE_LIMIT_DISABLED: '1',
    };
    delete env.ASTRANULL_NO_PERSIST;
    const runtime = await createPostgresRuntime(env, { createPool: () => appPool, closePool: async () => {} });
    const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env, services: runtime.services, runtimeHealth: runtime.health });
    server.listen(0);
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      await run({ baseUrl, ownerPool });
    } finally {
      await closeServer(server);
      await runtime.close();
      await closePgPool(appPool);
    }
  });
}

function tenantHeaders(role, tenant = TENANT_A) {
  return demoHeaders(role, tenant, `usr_${role}_${tenant}`);
}

describe('postgres audit remediation (live database, app role)', () => {
  it('keeps connector gate, bootstrap tokens, SOC queue, agent updates, and CSV import consistent', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withPostgresServer(async ({ baseUrl, ownerPool }) => {
      await assertRlsPoliciesExist(ownerPool, ['platform_scope_read_high_scale_requests']);

      const features = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: tenantHeaders('admin') });
      assert.equal(features.status, 200);
      assert.equal(features.json.connectors, true);
      const projection = await withTenantContext(ownerPool, TENANT_A, (client) => client.query(
        'SELECT enabled FROM tenant_connector_features WHERE tenant_id = $1',
        [TENANT_A],
      ));
      assert.equal(projection.rows[0]?.enabled, true);

      const preflight = await request(baseUrl, 'POST', '/v1/connectors', {
        headers: tenantHeaders('admin', TENANT_B),
        body: { provider: 'cloudflare', name: 'edge', status: 'active', config: { read_only: true }, validate_only: true },
      });
      assert.equal(preflight.status, 200, preflight.text);
      const connector = await request(baseUrl, 'POST', '/v1/connectors', {
        headers: tenantHeaders('admin', TENANT_B),
        body: { provider: 'cloudflare', name: 'edge', status: 'active', config: { read_only: true } },
      });
      assert.equal(connector.status, 201, connector.text);

      const releases = await request(baseUrl, 'GET', '/v1/agent-updates', { headers: tenantHeaders('admin') });
      assert.equal(releases.status, 200, releases.text);
      const trustKeys = await request(baseUrl, 'GET', '/v1/agent-update-trust-keys', { headers: tenantHeaders('admin') });
      assert.equal(trustKeys.status, 200);
      assert.equal((trustKeys.json.items ?? []).length, 0);
      for (const body of [
        { name: 'agent-install', max_registrations: 1, target_group_id: GROUP_A, environment_id: ENV_A },
        { name: 'agent-install', max_registrations: 1, target_group_id: GROUP_A },
      ]) {
        const token = await request(baseUrl, 'POST', '/v1/bootstrap-tokens', { headers: tenantHeaders('admin'), body });
        assert.equal(token.status, 201, token.text);
        assert.match(token.json.secret, /^ast_/);
      }

      const intake = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
        headers: tenantHeaders('engineer'),
        body: validHighScaleRequestPayload({ target_group_id: GROUP_A, objective: 'pg staff soc visibility' }),
      });
      assert.equal(intake.status, 201, intake.text);
      const queue = await request(baseUrl, 'GET', '/internal/admin/soc/high-scale-requests', {
        headers: staffHeaders('soc_lead', 'staff_soc_pg'),
      });
      assert.equal(queue.status, 200, queue.text);
      const row = queue.json.items.find((item) => item.id === intake.json.id);
      assert.ok(row, 'tenant intake must be visible to staff SOC across tenants');
      assert.equal(row.tenant_id, TENANT_A);
      assert.deepEqual(
        [TENANT_A, TENANT_B].every((id) => queue.json.tenants.some((tenant) => tenant.tenant_id === id)),
        true,
      );
      const denied = await request(baseUrl, 'GET', '/internal/admin/soc/high-scale-requests', { headers: staffHeaders('billing_ops') });
      assert.equal(denied.status, 403);
      const staffAudit = await ownerPool.query(
        `SELECT staff_id FROM internal_audit_log WHERE action = 'staff.soc.high_scale_queue_viewed'`,
      );
      assert.equal(staffAudit.rows[0]?.staff_id, 'staff_soc_pg');

      const tenantBList = await request(baseUrl, 'GET', '/v1/high-scale-requests', { headers: tenantHeaders('admin', TENANT_B) });
      assert.equal(tenantBList.status, 200);
      assert.equal(tenantBList.json.items.some((item) => item.id === intake.json.id), false);

      const boundary = '----pgCsvBoundary';
      const csv = 'kind,value\nfqdn,csv1.remed.example.com\nip,192.0.2.44\n';
      const multipart = [
        `--${boundary}`,
        'Content-Disposition: form-data; name="file"; filename="targets.csv"',
        'Content-Type: text/csv',
        '',
        csv,
        `--${boundary}--`,
        '',
      ].join('\r\n');
      const imported = await request(baseUrl, 'POST', `/v1/target-groups/${GROUP_A}/targets:csv`, {
        rawBody: multipart,
        headers: { ...tenantHeaders('admin'), 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      });
      assert.equal(imported.status, 201, imported.text);
      assert.equal(imported.json.created.length, 2);

      const rejected = await request(baseUrl, 'POST', `/v1/target-groups/${GROUP_A}/targets:csv`, {
        body: { csv: 'value\ncsv2.remed.example.com\ncsv1.remed.example.com\n' },
        headers: tenantHeaders('admin'),
      });
      assert.equal(rejected.status, 422, rejected.text);
      assert.deepEqual(rejected.json.errors.map((entry) => [entry.row, entry.error]), [[3, 'target_exists']]);
      const targets = await withTenantContext(ownerPool, TENANT_A, (client) => client.query(
        `SELECT normalized_value FROM targets WHERE tenant_id = $1 AND target_group_id = $2 AND deleted_at IS NULL ORDER BY normalized_value`,
        [TENANT_A, GROUP_A],
      ));
      assert.deepEqual(targets.rows.map((r) => r.normalized_value), ['192.0.2.44', 'a.remed.example.com', 'csv1.remed.example.com']);
      const csvAudit = await withTenantContext(ownerPool, TENANT_A, (client) => client.query(
        `SELECT metadata_json FROM audit_logs WHERE tenant_id = $1 AND action = 'target.csv_imported'`,
        [TENANT_A],
      ));
      assert.equal(csvAudit.rows.length, 1);
      assert.equal(csvAudit.rows[0].metadata_json.created_count, 2);

      const crossTenant = await request(baseUrl, 'POST', `/v1/target-groups/${GROUP_A}/targets:csv`, {
        body: { csv: 'value\ncsv3.remed.example.com\n' },
        headers: tenantHeaders('admin', TENANT_B),
      });
      assert.equal(crossTenant.status, 404);
    });
  });
});
