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
import { buildResultBody } from '../../workers/probe-worker.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import {
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT = 'ten_r3c_pg';
const GROUP = 'tg_r3c_pg';
const TARGET = 'tgt_r3c_app';
const SECRET = randomBytes(32).toString('hex');
const PERSPECTIVES = JSON.stringify([
  { id: 'us-1', label: 'US 1', region: 'us', egress_ips: ['198.51.100.20'] },
]);

const admin = () => demoHeaders('admin', TENANT, 'usr_r3c_admin');

function workerHeaders(method, path, body, perspectiveId) {
  return probeWorkerAuthHeaders('worker_r3c', {
    method, path, bodyText: body == null ? '' : JSON.stringify(body), tenantId: TENANT, perspectiveId,
  }, SECRET);
}

async function workerRequest(baseUrl, method, path, body, perspectiveId) {
  return request(baseUrl, method, path, { headers: workerHeaders(method, path, body, perspectiveId), body });
}

async function startRun(baseUrl, targetId, checkId) {
  return request(baseUrl, 'POST', '/v1/test-runs', {
    headers: admin(), body: { target_group_id: GROUP, target_id: targetId, check_id: checkId },
  });
}

async function seed(ownerPool) {
  await ownerPool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'R3c')`, [TENANT]);
  await withTenantContext(ownerPool, TENANT, async (client) => {
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ('env_r3c_pg', $1, 'prod')`, [TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode, safety_policy)
       VALUES ($1, $2, 'env_r3c_pg', 'R3c', 'dns_verified', 'external_only', '{"min_seconds_between_runs":0,"max_runs_per_hour":100}'::jsonb)`,
      [GROUP, TENANT],
    );
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES ($1, $2, $3, 'fqdn', 'app.r3c.example.com', 'app.r3c.example.com')`,
      [TARGET, TENANT, GROUP],
    );
    await client.query(
      `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
       VALUES ('tv_r3c_app', $1, $2, 'dns_verified', 'dns_txt', '{}'::jsonb, now(), 'usr_r3c_admin', 'aud_r3c_seed')`,
      [TENANT, TARGET],
    );
  });
}

async function withR3cServer(t, callback) {
  const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
  if (!availability.available) {
    t.skip(availability.reason);
    return;
  }
  await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
    await seed(ownerPool);
    try {
      await ownerPool.query(`ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
    } catch (err) {
      if (!err?.message?.includes('concurrently updated')) throw err;
    }
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

describe('R3c Postgres N12 violation-only closure and 6a port_results read path', () => {
  it('moves violation-only finding to fix_verified with basis, and returns port_results top-level on verdict', { timeout: 240_000 }, async (t) => {
    await withR3cServer(t, async ({ baseUrl, ownerPool }) => {
      const declared = await request(baseUrl, 'PUT', `/v1/targets/${TARGET}/control-declarations`, {
        headers: { ...admin(), 'if-match': '"decl-r0"' },
        body: {
          network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }],
        },
      });
      assert.equal(declared.status, 200, declared.text);

      // Run 1: violate declared deny port 22 -> creates finding
      const started1 = await startRun(baseUrl, TARGET, 'nfw.declared_deny_tcp.safe');
      assert.equal(started1.status, 201, started1.text);
      const runId1 = started1.json.run?.id ?? started1.json.id;

      const jobs1 = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'us-1');
      assert.equal(jobs1.status, 200, jobs1.text);
      const job1 = jobs1.json.jobs.find((j) => j.test_run_id === runId1);
      assert.ok(job1);

      await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job1.id}/execute`, { leased_at: job1.leased_at }, 'us-1');
      const body1 = buildResultBody(job1, 'connected', {
        probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, address: '93.184.216.34', address_family: 4,
        tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree', service_validated: true,
        source_perspective: 'us-1',
        port_results: [{
          protocol: 'tcp', port: 22, address: '93.184.216.34', address_family: 4,
          tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree',
          samples: [{ tcp_outcome: 'handshake' }, { tcp_outcome: 'handshake' }],
        }],
        samples: [{ tcp_outcome: 'handshake' }, { tcp_outcome: 'handshake' }],
        families: { ipv4: { tcp_outcome: 'handshake', port: 22, peer_is_cdn: false } },
      }, {
        requests_sent: 4, probe_requests_sent: 2, destination_resolver_attempts: 2, total_operations: 4, duration_ms: 6,
      });
      const ingested1 = await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job1.id}/result`, body1, 'us-1');
      assert.equal(ingested1.status, 201, ingested1.text);

      const runRead1 = await request(baseUrl, 'GET', `/v1/test-runs/${runId1}`, { headers: admin() });
      assert.equal(runRead1.status, 200, runRead1.text);
      assert.equal(runRead1.json.verdict?.verdict, 'exposed');
      // 6(a): port_results must be returned top-level on verdict
      assert.ok(Array.isArray(runRead1.json.verdict?.port_results), 'port_results must be top-level on verdict');
      assert.equal(runRead1.json.verdict.port_results[0].port, 22);

      const findingRows1 = await ownerPool.query(`SELECT id, status, verdict_id FROM findings WHERE tenant_id = $1 AND target_id = $2`, [TENANT, TARGET]);
      assert.equal(findingRows1.rows.length, 1);
      assert.equal(findingRows1.rows[0].status, 'open');
      const findingId = findingRows1.rows[0].id;

      // Run 2: Retest with no violation from same perspective with 2 agreeing samples
      const started2 = await startRun(baseUrl, TARGET, 'nfw.declared_deny_tcp.safe');
      assert.equal(started2.status, 201, started2.text);
      const runId2 = started2.json.run?.id ?? started2.json.id;

      const jobs2 = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'us-1');
      const job2 = jobs2.json.jobs.find((j) => j.test_run_id === runId2);
      assert.ok(job2);

      await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job2.id}/execute`, { leased_at: job2.leased_at }, 'us-1');
      const body2 = buildResultBody(job2, 'timeout', {
        probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, address: '93.184.216.34', address_family: 4,
        tcp_outcome: 'timeout', peer_is_cdn: false, sample_agreement: 'agree', service_validated: false,
        source_perspective: 'us-1',
        port_results: [{
          protocol: 'tcp', port: 22, address: '93.184.216.34', address_family: 4,
          tcp_outcome: 'timeout', peer_is_cdn: false, sample_agreement: 'agree',
          samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
        }],
        unprobed_deny_ports: [],
        samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
        families: { ipv4: { tcp_outcome: 'timeout', port: 22, peer_is_cdn: false } },
      }, {
        requests_sent: 4, probe_requests_sent: 2, destination_resolver_attempts: 2, total_operations: 4, duration_ms: 10,
      });
      const ingested2 = await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job2.id}/result`, body2, 'us-1');
      assert.equal(ingested2.status, 201, ingested2.text);

      const runRead2 = await request(baseUrl, 'GET', `/v1/test-runs/${runId2}`, { headers: admin() });
      assert.equal(runRead2.status, 200, runRead2.text);
      assert.equal(runRead2.json.verdict?.verdict, 'inconclusive');
      // 6(a): port_results must be returned top-level on verdict for retest as well
      assert.ok(Array.isArray(runRead2.json.verdict?.port_results), 'port_results must be top-level on verdict');

      // N12: Finding must be fix_verified in Postgres with verification_basis
      const findingRows2 = await ownerPool.query(`SELECT status, verifying_run_id, verification_basis FROM findings WHERE id = $1`, [findingId]);
      assert.equal(findingRows2.rows[0].status, 'fix_verified');
      assert.equal(findingRows2.rows[0].verifying_run_id, runId2);
      assert.equal(findingRows2.rows[0].verification_basis, 'violation_not_reproduced');

      // GET /v1/findings/:id returns verification_basis in Postgres
      const findingApi = await request(baseUrl, 'GET', `/v1/findings/${findingId}`, { headers: admin() });
      assert.equal(findingApi.status, 200, findingApi.text);
      assert.equal(findingApi.json.verification_basis, 'violation_not_reproduced');

      // GET /v1/findings list returns verification_basis in Postgres
      const findingList = await request(baseUrl, 'GET', `/v1/findings`, { headers: admin() });
      assert.equal(findingList.status, 200, findingList.text);
      const found = findingList.json.items.find((f) => f.id === findingId);
      assert.ok(found);
      assert.equal(found.verification_basis, 'violation_not_reproduced');

      // PATCH /v1/findings/:id ignores client verification_basis in Postgres (docs/api.md:599)
      const patchRes = await request(baseUrl, 'PATCH', `/v1/findings/${findingId}`, {
        headers: admin(),
        body: { verification_basis: 'manual_soc_verified' },
      });
      assert.equal(patchRes.status, 200, patchRes.text);
      assert.equal(patchRes.json.verification_basis, 'violation_not_reproduced');

      const findingApiAfterPatch = await request(baseUrl, 'GET', `/v1/findings/${findingId}`, { headers: admin() });
      assert.equal(findingApiAfterPatch.json.verification_basis, 'violation_not_reproduced');

      // N12: audit finding.fix_verified with verification_basis: violation_not_reproduced
      const audits = await ownerPool.query(
        `SELECT action, metadata_json FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2 AND action = 'finding.fix_verified'`,
        [TENANT, findingId],
      );
      assert.equal(audits.rows.length, 1);
      assert.equal(audits.rows[0].metadata_json.verification_basis, 'violation_not_reproduced');
    });
  });

  it('keeps violation-only finding open when declaration changed before retest', { timeout: 240_000 }, async (t) => {
    await withR3cServer(t, async ({ baseUrl, ownerPool }) => {
      const declared1 = await request(baseUrl, 'PUT', `/v1/targets/${TARGET}/control-declarations`, {
        headers: { ...admin(), 'if-match': '"decl-r0"' },
        body: {
          network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }],
        },
      });
      assert.equal(declared1.status, 200, declared1.text);

      const started1 = await startRun(baseUrl, TARGET, 'nfw.declared_deny_tcp.safe');
      assert.equal(started1.status, 201, started1.text);
      const runId1 = started1.json.run?.id ?? started1.json.id;

      const jobs1 = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'us-1');
      const job1 = jobs1.json.jobs.find((j) => j.test_run_id === runId1);
      assert.ok(job1);

      await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job1.id}/execute`, { leased_at: job1.leased_at }, 'us-1');
      const body1 = buildResultBody(job1, 'connected', {
        probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, address: '93.184.216.34', address_family: 4,
        tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree', service_validated: true,
        source_perspective: 'us-1',
        port_results: [{
          protocol: 'tcp', port: 22, address: '93.184.216.34', address_family: 4,
          tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree',
          samples: [{ tcp_outcome: 'handshake' }, { tcp_outcome: 'handshake' }],
        }],
        samples: [{ tcp_outcome: 'handshake' }, { tcp_outcome: 'handshake' }],
      }, {
        requests_sent: 4, probe_requests_sent: 2, destination_resolver_attempts: 2, total_operations: 4, duration_ms: 6,
      });
      const ingested1 = await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job1.id}/result`, body1, 'us-1');
      assert.equal(ingested1.status, 201, ingested1.text);

      const findingRows1 = await ownerPool.query(`SELECT id, status FROM findings WHERE tenant_id = $1 AND target_id = $2`, [TENANT, TARGET]);
      assert.equal(findingRows1.rows.length, 1);
      assert.equal(findingRows1.rows[0].status, 'open');
      const findingId = findingRows1.rows[0].id;

      const declRead = await request(baseUrl, 'GET', `/v1/targets/${TARGET}/control-declarations`, { headers: admin() });
      const etag = declRead.headers.etag;
      const declared2 = await request(baseUrl, 'PUT', `/v1/targets/${TARGET}/control-declarations`, {
        headers: { ...admin(), 'if-match': etag },
        body: {
          network_policy: [{ protocol: 'tcp', port: 80, action: 'deny', address_family: 'any' }],
        },
      });
      assert.equal(declared2.status, 200, declared2.text);

      const started2 = await startRun(baseUrl, TARGET, 'nfw.declared_deny_tcp.safe');
      assert.equal(started2.status, 201, started2.text);
      const runId2 = started2.json.run?.id ?? started2.json.id;

      const jobs2 = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'us-1');
      const job2 = jobs2.json.jobs.find((j) => j.test_run_id === runId2);
      assert.ok(job2);

      await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job2.id}/execute`, { leased_at: job2.leased_at }, 'us-1');
      const body2 = buildResultBody(job2, 'timeout', {
        probe_kind: 'tcp_connect', protocol: 'tcp', port: 80, address: '93.184.216.34', address_family: 4,
        tcp_outcome: 'timeout', peer_is_cdn: false, sample_agreement: 'agree', service_validated: false,
        source_perspective: 'us-1',
        port_results: [{
          protocol: 'tcp', port: 80, address: '93.184.216.34', address_family: 4,
          tcp_outcome: 'timeout', peer_is_cdn: false, sample_agreement: 'agree',
          samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
        }],
        unprobed_deny_ports: [],
        samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
      }, {
        requests_sent: 4, probe_requests_sent: 2, destination_resolver_attempts: 2, total_operations: 4, duration_ms: 10,
      });
      const ingested2 = await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job2.id}/result`, body2, 'us-1');
      assert.equal(ingested2.status, 201, ingested2.text);

      const findingRows2 = await ownerPool.query(`SELECT status, verifying_run_id FROM findings WHERE id = $1`, [findingId]);
      assert.equal(findingRows2.rows[0].status, 'open');
      assert.equal(findingRows2.rows[0].verifying_run_id, null);
    });
  });
});
