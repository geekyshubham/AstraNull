import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { probeWorkerAuthHeaders } from '../../src/services/probeCoordinator.mjs';
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
const TENANT = 'ten_r2_pg';
const GROUP = 'tg_r2_pg';
const TARGET = 'tgt_r2_app';
const SECRET = randomBytes(32).toString('hex');
const EU_SECRET = randomBytes(32).toString('hex');
const PERSPECTIVES = JSON.stringify([
  { id: 'eu-1', label: 'EU 1', region: 'eu', egress_ips: ['198.51.100.10'], worker_secret: EU_SECRET },
  { id: 'us-1', label: 'US 1', region: 'us', egress_ips: ['198.51.100.20'] },
]);
const PATH = `/v1/targets/${TARGET}/control-declarations`;
const admin = () => demoHeaders('admin', TENANT, 'usr_r2_admin');

async function seed(ownerPool) {
  await ownerPool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'R2')`, [TENANT]);
  await withTenantContext(ownerPool, TENANT, async (client) => {
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ('env_r2_pg', $1, 'prod')`, [TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode, safety_policy)
       VALUES ($1, $2, 'env_r2_pg', 'R2', 'dns_verified', 'external_only', '{"min_seconds_between_runs":0,"max_runs_per_hour":100}'::jsonb)`,
      [GROUP, TENANT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES ($1, $2, $3, 'fqdn', 'app.r2.example.com', 'app.r2.example.com')`,
      [TARGET, TENANT, GROUP],
    );
  });
}

async function withR2Server(t, callback) {
  const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
  if (!availability.available) {
    t.skip(availability.reason);
    return;
  }
  await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
    await seed(ownerPool);
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
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: SECRET,
      ASTRANULL_PROBE_PERSPECTIVES: PERSPECTIVES,
      ASTRANULL_APPROVED_PROBE_SOURCES: '',
    };
    delete env.ASTRANULL_NO_PERSIST;
    const runtime = await createPostgresRuntime(env, { createPool: () => appPool, closePool: async () => {} });
    const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env, services: runtime.services, runtimeHealth: runtime.health });
    server.listen(0);
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      await callback({ baseUrl, ownerPool });
    } finally {
      await closeServer(server);
      await runtime.close?.();
      await closePgPool(appPool);
    }
  });
}

describe('R2 Postgres control-declarations concurrency and perspective authenticity', () => {
  it('requires If-Match, gives the second concurrent writer 412, and keeps the first write', { timeout: 240_000 }, async (t) => {
    await withR2Server(t, async ({ baseUrl, ownerPool }) => {
      const initial = await request(baseUrl, 'GET', PATH, { headers: admin() });
      assert.equal(initial.status, 200, initial.text);
      assert.equal(initial.json.revision, 0);
      assert.equal(initial.headers.etag, '"decl-r0"');
      const missing = await request(baseUrl, 'PUT', PATH, { headers: admin(), body: { version: 1 } });
      assert.equal(missing.status, 428);
      assert.equal(missing.json.error, 'precondition_required');

      const bodyA = { network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };
      const bodyB = { waf: { expected_action: 'block' } };
      const [a, b] = await Promise.all([
        request(baseUrl, 'PUT', PATH, { headers: { ...admin(), 'if-match': initial.headers.etag }, body: bodyA }),
        request(baseUrl, 'PUT', PATH, { headers: { ...admin(), 'if-match': initial.headers.etag }, body: bodyB }),
      ]);
      const statuses = [a.status, b.status].sort();
      assert.deepEqual(statuses, [200, 412]);
      const winner = a.status === 200 ? a : b;
      const loser = a.status === 412 ? a : b;
      assert.equal(winner.json.revision, 1);
      assert.equal(winner.headers.etag, '"decl-r1"');
      assert.equal(loser.json.error, 'declarations_conflict');
      assert.equal(loser.json.revision, 1);

      const stored = await request(baseUrl, 'GET', PATH, { headers: admin() });
      assert.equal(stored.json.revision, 1);
      assert.equal(Boolean(stored.json.network_policy), winner === a);
      const audits = await withTenantContext(ownerPool, TENANT, (client) => client.query(
        `SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = 'target.control_declarations_updated'`,
        [TENANT],
      ));
      assert.equal(audits.rows[0].n, 1);

      const next = await request(baseUrl, 'PUT', PATH, { headers: { ...admin(), 'if-match': stored.headers.etag }, body: bodyA });
      assert.equal(next.status, 200);
      assert.equal(next.json.revision, 2);
    });
  });

  it('refuses a shared-secret claim of a secured perspective with 403 and an audit entry', { timeout: 240_000 }, async (t) => {
    await withR2Server(t, async ({ baseUrl, ownerPool }) => {
      const path = '/internal/probe/jobs';
      const forged = probeWorkerAuthHeaders('w_forged', { method: 'GET', path, tenantId: TENANT, perspectiveId: 'eu-1' }, SECRET);
      const denied = await request(baseUrl, 'GET', path, { headers: forged });
      assert.equal(denied.status, 403);
      assert.equal(denied.json.error, 'probe_perspective_unauthenticated');
      const audits = await withTenantContext(ownerPool, TENANT, (client) => client.query(
        `SELECT resource_id, metadata_json::text AS metadata FROM audit_logs WHERE tenant_id = $1 AND action = 'probe_worker.perspective_auth_denied'`,
        [TENANT],
      ));
      assert.equal(audits.rows.length, 1);
      assert.equal(audits.rows[0].resource_id, 'eu-1');
      assert.equal(audits.rows[0].metadata.includes(EU_SECRET) || audits.rows[0].metadata.includes(SECRET), false);

      const signed = probeWorkerAuthHeaders('w_eu', { method: 'GET', path, tenantId: TENANT, perspectiveId: 'eu-1' }, EU_SECRET);
      assert.equal((await request(baseUrl, 'GET', path, { headers: signed })).status, 200);
      const open = probeWorkerAuthHeaders('w_us', { method: 'GET', path, tenantId: TENANT, perspectiveId: 'us-1' }, SECRET);
      assert.equal((await request(baseUrl, 'GET', path, { headers: open })).status, 200);
    });
  });
});
