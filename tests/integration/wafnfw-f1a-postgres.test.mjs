import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES } from '../../src/contracts/wafOffensive.mjs';
import { sha256Hex } from '../../src/lib/authorizationArtifactLedger.mjs';
import { verifyProbeJobSignature } from '../../src/lib/probeJobs.mjs';
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
const TENANT = 'ten_f1a_pg';
const OTHER = 'ten_f1a_other';
const GROUP = 'tg_f1a_pg';
const SECRET = randomBytes(32).toString('hex');
const PERSPECTIVES = JSON.stringify([
  { id: 'eu-1', label: 'EU 1', region: 'eu', egress_ips: ['198.51.100.10'] },
  { id: 'us-1', label: 'US 1', region: 'us', egress_ips: ['198.51.100.20'] },
]);
const TARGETS = [
  ['tgt_f1a_app', 'fqdn', 'app.f1a.example.com'],
  ['tgt_f1a_priv', 'fqdn', 'priv.f1a.example.com'],
  ['tgt_f1a_bare', 'fqdn', 'bare.f1a.example.com'],
  ['tgt_f1a_origin', 'ip', '8.8.8.8'],
  ['tgt_f1a_origin_priv', 'ip', '10.0.0.5'],
];

const admin = () => demoHeaders('admin', TENANT, 'usr_f1a_admin');
const outsider = () => demoHeaders('admin', OTHER, 'usr_f1a_outsider');
const socA = () => demoHeaders('soc', TENANT, 'usr_f1a_soc_a');
const socB = () => demoHeaders('soc', TENANT, 'usr_f1a_soc_b');

function workerHeaders(method, path, body, perspectiveId) {
  return probeWorkerAuthHeaders('worker_f1a', {
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
  await ownerPool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'F1a'), ($2, 'F1a other')`, [TENANT, OTHER]);
  await withTenantContext(ownerPool, TENANT, async (client) => {
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ('env_f1a_pg', $1, 'prod')`, [TENANT]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode, safety_policy)
       VALUES ($1, $2, 'env_f1a_pg', 'F1a', 'dns_verified', 'external_only', '{"min_seconds_between_runs":0,"max_runs_per_hour":100}'::jsonb)`,
      [GROUP, TENANT],
    );
    for (const [id, kind, value] of TARGETS) {
      await client.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES ($1, $2, $3, $4, $5, $5)`,
        [id, TENANT, GROUP, kind, value],
      );
      await client.query(
        `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
         VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', '{}'::jsonb, now(), 'usr_f1a_admin', 'aud_f1a_seed')`,
        [`tv_${id}`, TENANT, id],
      );
    }
    for (const [id, protectedId, originId, host] of [
      ['ob_f1a_app', 'tgt_f1a_app', 'tgt_f1a_origin', 'app.f1a.example.com'],
      ['ob_f1a_priv', 'tgt_f1a_priv', 'tgt_f1a_origin_priv', 'priv.f1a.example.com'],
    ]) {
      await client.query(
        `INSERT INTO origin_bindings (id, tenant_id, protected_target_id, protected_target_group_id, origin_target_id, origin_target_group_id, host, sni)
         VALUES ($1, $2, $3, $4, $5, $4, $6, $6)`,
        [id, TENANT, protectedId, GROUP, originId, host],
      );
    }
  });
}

async function withF1aServer(t, callback) {
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
      ASTRANULL_WAF_POSTURE_ENABLED: '1',
      ASTRANULL_APPROVED_PROBE_SOURCES: '',
    };
    delete env.ASTRANULL_NO_PERSIST;
    const savedPerspectives = process.env.ASTRANULL_PROBE_PERSPECTIVES;
    process.env.ASTRANULL_PROBE_PERSPECTIVES = PERSPECTIVES;
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
      if (savedPerspectives === undefined) delete process.env.ASTRANULL_PROBE_PERSPECTIVES;
      else process.env.ASTRANULL_PROBE_PERSPECTIVES = savedPerspectives;
    }
  });
}

describe('F1a Postgres declaration plumbing', () => {
  it('signs stored declarations into jobs, finalizes and replays with them, routes by perspective, and binds origin lockdown', { timeout: 240_000 }, async (t) => {
    await withF1aServer(t, async ({ baseUrl, ownerPool }) => {
      const declared = await request(baseUrl, 'PUT', '/v1/targets/tgt_f1a_app/control-declarations', {
        headers: { ...admin(), 'if-match': '"decl-r0"' },
        body: {
          network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }],
          perspectives: { allowlisted_perspective_ids: ['us-1'], denied_perspective_ids: ['eu-1'] },
          origin: { lockdown_expected: true },
        },
      });
      assert.equal(declared.status, 200, declared.text);

      const checksApp = await request(baseUrl, 'GET', '/v1/checks?target_id=tgt_f1a_app&scope=all', { headers: admin() });
      assert.equal(checksApp.status, 200, checksApp.text);
      const appChecks = checksApp.json.items ?? checksApp.json.checks ?? [];
      const lockdownApp = appChecks.find((c) => c.check_id === 'nfw.origin_lockdown.safe');
      assert.ok(lockdownApp, 'lockdown check listed');
      assert.equal(lockdownApp.requires_additional_input, false, 'real postgres binding makes lockdown check runnable');
      assert.equal(lockdownApp.additional_input_reason, null);

      const started = await startRun(baseUrl, 'tgt_f1a_app', 'nfw.declared_deny_tcp.safe');
      assert.equal(started.status, 201, started.text);
      const runId = started.json.run?.id ?? started.json.id;
      assert.ok(runId, started.text);

      const listed = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'us-1');
      assert.equal(listed.status, 200, listed.text);
      const job = listed.json.jobs.find((row) => row.test_run_id === runId);
      assert.ok(job, 'a job without required_perspective_id is claimable by any perspective');
      assert.equal(job.constraints.required_perspective_id, undefined);
      assert.deepEqual(job.probe_profile.declarations.network_policy, [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }]);
      assert.equal(verifyProbeJobSignature(job, SECRET), true);

      const execute = await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job.id}/execute`, { leased_at: job.leased_at }, 'us-1');
      assert.equal(execute.status, 201, execute.text);
      const body = buildResultBody(job, 'connected', {
        probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, address: '93.184.216.34', address_family: 4,
        tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree', service_validated: true,
        families: { ipv4: { tcp_outcome: 'handshake', port: 22, peer_is_cdn: false } },
      }, {
        requests_sent: job.constraints.min_destination_resolver_attempts + 2,
        probe_requests_sent: 2,
        destination_resolver_attempts: job.constraints.min_destination_resolver_attempts,
        total_operations: job.constraints.min_destination_resolver_attempts + 2,
        duration_ms: 5,
      });
      assert.equal(body.metadata.families.ipv4.tcp_outcome, 'handshake');
      const ingested = await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${job.id}/result`, body, 'us-1');
      assert.equal(ingested.status, 201, ingested.text);

      const runRead = await request(baseUrl, 'GET', `/v1/test-runs/${runId}`, { headers: admin() });
      assert.equal(runRead.status, 200, runRead.text);
      assert.equal(runRead.json.verdict?.verdict, 'exposed', runRead.text);
      const storedVerdict = await ownerPool.query(`SELECT placement_confidence_json AS placement FROM verdicts WHERE test_run_id = $1`, [runId]);
      assert.equal(storedVerdict.rows[0].placement.creates_finding, true);
      const finding = await ownerPool.query(`SELECT severity FROM findings WHERE tenant_id = $1 AND test_run_id = $2`, [TENANT, runId]);
      assert.equal(finding.rows.length, 1, 'an exposed NFW violation creates a finding in Postgres');
      assert.equal(finding.rows[0].severity, storedVerdict.rows[0].placement.finding_severity);
      const published = await ownerPool.query(`SELECT action FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2 AND action LIKE 'verdict.%'`, [TENANT, runId]);
      assert.deepEqual(published.rows.map((row) => row.action), ['verdict.published']);

      const replay = await request(baseUrl, 'GET', `/v1/test-runs/${runId}/verdict-replay`, { headers: admin() });
      assert.equal(replay.status, 200, replay.text);
      assert.equal(replay.json.stored.verdict, 'exposed');
      assert.equal(replay.json.rederived.verdict, 'exposed');
      assert.equal(replay.json.rederived.declarations_applied, true);
      assert.equal(replay.json.changed, false);
      assert.equal(replay.json.grading_version_gap, null);
      assert.equal((await request(baseUrl, 'GET', `/v1/test-runs/${runId}/verdict-replay`, { headers: outsider() })).status, 404);

      const coverage = await request(baseUrl, 'GET', '/v1/targets/tgt_f1a_app/rule-coverage', { headers: admin() });
      assert.equal(coverage.status, 200, coverage.text);
      assert.equal(coverage.json.version, 'rule-coverage.v1');
      assert.ok(coverage.json.categories.length > 0);
      const denyCategory = coverage.json.categories.find((row) => row.checks.some((check) => check.check_id === 'nfw.declared_deny_tcp.safe'));
      assert.ok(denyCategory, JSON.stringify(coverage.json.categories.map((row) => row.id)));
      assert.equal(denyCategory.checks.find((check) => check.check_id === 'nfw.declared_deny_tcp.safe').status, 'covered_fail');
      assert.equal((await request(baseUrl, 'GET', '/v1/targets/tgt_f1a_app/rule-coverage', { headers: outsider() })).status, 404);

      const current = await request(baseUrl, 'GET', '/v1/targets/tgt_f1a_app/control-declarations', { headers: admin() });
      const cleared = await request(baseUrl, 'PUT', '/v1/targets/tgt_f1a_app/control-declarations', {
        headers: { ...admin(), 'if-match': current.headers.etag },
        body: {
          perspectives: { allowlisted_perspective_ids: ['us-1'], denied_perspective_ids: ['eu-1'] },
          origin: { lockdown_expected: true },
        },
      });
      assert.equal(cleared.status, 200, cleared.text);
      const changed = await request(baseUrl, 'GET', `/v1/test-runs/${runId}/verdict-replay`, { headers: admin() });
      assert.equal(changed.json.rederived.verdict, 'inconclusive');
      assert.equal(changed.json.changed, true);

      const perspectiveRun = await startRun(baseUrl, 'tgt_f1a_app', 'nfw.perspective_allowlist.safe');
      assert.equal(perspectiveRun.status, 201, perspectiveRun.text);
      const perspectiveRunId = perspectiveRun.json.run?.id ?? perspectiveRun.json.id;
      const wrong = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'us-1');
      assert.equal(wrong.json.jobs.some((row) => row.test_run_id === perspectiveRunId), false);
      const anonymous = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, undefined);
      assert.equal(anonymous.json.jobs.some((row) => row.test_run_id === perspectiveRunId), false);
      const right = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'eu-1');
      const pinned = right.json.jobs.find((row) => row.test_run_id === perspectiveRunId);
      assert.ok(pinned, right.text);
      assert.equal(pinned.constraints.required_perspective_id, 'eu-1');
      assert.equal(verifyProbeJobSignature(pinned, SECRET), true);
      const mismatch = await workerRequest(baseUrl, 'POST', `/internal/probe/jobs/${pinned.id}/execute`, { leased_at: pinned.leased_at }, 'us-1');
      assert.equal(mismatch.status, 403, mismatch.text);
      assert.equal(mismatch.json.error, 'probe_perspective_mismatch');
      const cancelled = await request(baseUrl, 'POST', `/v1/test-runs/${perspectiveRunId}/cancel`, { headers: admin(), body: {} });
      assert.equal(cancelled.status, 200, cancelled.text);

      const lockdownRun = await startRun(baseUrl, 'tgt_f1a_app', 'nfw.origin_lockdown.safe');
      assert.equal(lockdownRun.status, 201, lockdownRun.text);
      const lockdownRunId = lockdownRun.json.run?.id ?? lockdownRun.json.id;
      const lockdownJobs = await workerRequest(baseUrl, 'GET', '/internal/probe/jobs', undefined, 'us-1');
      const lockdownJob = lockdownJobs.json.jobs.find((row) => row.test_run_id === lockdownRunId);
      assert.ok(lockdownJob, lockdownJobs.text);
      assert.equal(lockdownJob.target.value, 'app.f1a.example.com');
      assert.equal(lockdownJob.probe_profile.direct_ip, '8.8.8.8');
      assert.equal(lockdownJob.probe_profile.protected_host, 'app.f1a.example.com');
      assert.deepEqual(lockdownJob.constraints.origin_scope, { host: 'app.f1a.example.com', sni: 'app.f1a.example.com', port: null, path: null });
      assert.equal(lockdownJob.probe_profile.declarations.origin.lockdown_expected, true);
      assert.equal(verifyProbeJobSignature(lockdownJob, SECRET), true);
      const stored = await ownerPool.query(`SELECT provenance_json->'origin_lockdown' AS lockdown FROM test_runs WHERE id = $1`, [lockdownRunId]);
      assert.equal(stored.rows[0].lockdown.binding_id, 'ob_f1a_app');

      const undeclared = await startRun(baseUrl, 'tgt_f1a_bare', 'nfw.origin_lockdown.safe');
      assert.equal(undeclared.status, 409, undeclared.text);
      assert.equal(undeclared.json.error, 'declared_origin_lockdown_required');

      const declaredPriv = await request(baseUrl, 'PUT', '/v1/targets/tgt_f1a_priv/control-declarations', {
        headers: { ...admin(), 'if-match': '"decl-r0"' },
        body: { origin: { lockdown_expected: true } },
      });
      assert.equal(declaredPriv.status, 200, declaredPriv.text);

      const declaredBare = await request(baseUrl, 'PUT', '/v1/targets/tgt_f1a_bare/control-declarations', {
        headers: { ...admin(), 'if-match': '"decl-r0"' },
        body: { origin: { lockdown_expected: true } },
      });
      assert.equal(declaredBare.status, 200, declaredBare.text);

      const checksBare = await request(baseUrl, 'GET', '/v1/checks?target_id=tgt_f1a_bare&scope=all', { headers: admin() });
      assert.equal(checksBare.status, 200, checksBare.text);
      const bareChecks = checksBare.json.items ?? checksBare.json.checks ?? [];
      const lockdownBare = bareChecks.find((c) => c.check_id === 'nfw.origin_lockdown.safe');
      assert.ok(lockdownBare, 'lockdown check listed for bare target');
      assert.equal(lockdownBare.requires_additional_input, true, 'missing origin binding refuses lockdown check');
      assert.equal(lockdownBare.additional_input_reason, 'origin_binding_required');

      const privateOrigin = await startRun(baseUrl, 'tgt_f1a_priv', 'nfw.origin_lockdown.safe');
      assert.equal(privateOrigin.status, 400, privateOrigin.text);
      assert.equal(privateOrigin.json.error, 'origin_destination_not_allowed');
      const unbound = await startRun(baseUrl, 'tgt_f1a_bare', 'nfw.origin_lockdown.safe');
      assert.equal(unbound.status, 400, unbound.text);
      assert.equal(unbound.json.error, 'missing_declared_origin_binding');
    });
  });

  it('binds SOC canary-sink plans to the stored declaration and an approved in-scope request', { timeout: 240_000 }, async (t) => {
    await withF1aServer(t, async ({ baseUrl, ownerPool }) => {
      const declared = await request(baseUrl, 'PUT', '/v1/targets/tgt_f1a_app/control-declarations', {
        headers: { ...admin(), 'if-match': '"decl-r0"' }, body: { canary_sink: { url: 'https://app.f1a.example.com/canary' } },
      });
      assert.equal(declared.status, 200, declared.text);
      const asset = await request(baseUrl, 'POST', '/v1/waf/assets', {
        headers: admin(),
        body: { target_group_id: GROUP, target_id: 'tgt_f1a_app', canonical_url: 'https://app.f1a.example.com', owner_hint: 'edge' },
      });
      assert.equal(asset.status, 201, asset.text);
      const created = await request(baseUrl, 'POST', '/v1/waf/offensive-requests', {
        headers: admin(),
        body: {
          waf_asset_id: asset.json.asset.id,
          objective: 'Canary-sink body suite',
          requested_suites: ['sqli_offensive'],
          emergency_contacts: ['ops@example.invalid'],
          stop_criteria: 'Stop on origin impact',
          scope_confirmation: true,
          staging_only: true,
        },
      });
      assert.equal(created.status, 201, created.text);
      const requestId = created.json.offensive_request.id;
      const planPath = `/internal/soc/waf-offensive/${requestId}/canary-sink-body/plan`;

      const early = await request(baseUrl, 'POST', planPath, { headers: socA(), body: { variants: ['json'] } });
      assert.equal(early.status, 409, early.text);
      assert.equal(early.json.error, 'canary_sink_request_not_approved');

      for (const type of WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES) {
        const uploaded = await request(baseUrl, 'POST', `/v1/waf/offensive-requests/${requestId}/artifacts`, {
          headers: admin(),
          body: {
            type,
            content_sha256: sha256Hex(`f1a-artifact:${type}`),
            reference_uri: 'metadata://f1a/artifact',
            approval_reference: 'REF-F1A-001',
            approver: 'Customer Approver',
            valid_window: { valid_from: new Date().toISOString(), valid_to: new Date(Date.now() + 86_400_000).toISOString() },
            approved_targets: [GROUP],
            approved_scenario_families: ['sqli_offensive'],
            emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
            abort_criteria: { threshold: 'waf_bypass_detected', auto_stop: true },
          },
        });
        assert.equal(uploaded.status, 201, uploaded.text);
        const reviewed = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/artifacts/${uploaded.json.artifact.id}/review`, {
          headers: socA(), body: { status: 'accepted' },
        });
        assert.equal(reviewed.status, 200, reviewed.text);
      }
      for (const headers of [socA(), socB()]) {
        const approved = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/approve`, { headers });
        assert.equal(approved.status, 200, approved.text);
      }

      const outOfScope = await request(baseUrl, 'POST', planPath, { headers: socA(), body: { target_id: 'tgt_f1a_bare' } });
      assert.equal(outOfScope.status, 403, outOfScope.text);
      assert.equal(outOfScope.json.error, 'canary_sink_target_out_of_scope');
      const mismatch = await request(baseUrl, 'POST', planPath, {
        headers: socA(), body: { canary_sink_url: 'https://evil.example.invalid/sink', variants: ['json'] },
      });
      assert.equal(mismatch.status, 400, mismatch.text);
      assert.equal(mismatch.json.error, 'sink_url_mismatch');
      const planned = await request(baseUrl, 'POST', planPath, {
        headers: socA(), body: { declared_canary_sink_url: 'https://evil.example.invalid/sink', variants: ['json'] },
      });
      assert.equal(planned.status, 200, planned.text);
      assert.equal(planned.json.plan.canary_sink_url, 'https://app.f1a.example.com/canary');
      assert.ok(planned.json.plan.requests.every((row) => row.url.startsWith('https://app.f1a.example.com/')));

      const observed = await request(baseUrl, 'POST', `/internal/soc/waf-offensive/${requestId}/canary-sink-body/observations`, {
        headers: socA(), body: { observations: [{ id: 'json_marker', blocked: true, status_code: 403 }] },
      });
      assert.equal(observed.status, 200, observed.text);
      assert.equal(observed.json.results.variant_results[0].outcome, 'blocked');

      const outsiderPlan = await request(baseUrl, 'POST', planPath, { headers: demoHeaders('soc', OTHER, 'usr_f1a_soc_x'), body: {} });
      assert.equal(outsiderPlan.status, 404, outsiderPlan.text);

      const audits = await ownerPool.query(
        `SELECT action, metadata_json->>'reason' AS reason FROM audit_logs
         WHERE tenant_id = $1 AND resource_id = $2 AND action LIKE 'waf.offensive_canary_sink_body.%' ORDER BY sequence`,
        [TENANT, requestId],
      );
      const rows = audits.rows.map((row) => `${row.action}:${row.reason ?? ''}`);
      assert.deepEqual(rows.filter((row) => row.includes('.refused')).sort(), [
        'waf.offensive_canary_sink_body.refused:canary_sink_request_not_approved',
        'waf.offensive_canary_sink_body.refused:canary_sink_target_out_of_scope',
        'waf.offensive_canary_sink_body.refused:sink_url_mismatch',
      ]);
      assert.ok(rows.includes('waf.offensive_canary_sink_body.planned:'));
      assert.ok(rows.includes('waf.offensive_canary_sink_body.observed:'));
      const jobs = await ownerPool.query('SELECT count(*)::int AS n FROM probe_jobs WHERE tenant_id = $1', [TENANT]);
      assert.equal(jobs.rows[0].n, 0);
    });
  });
});
