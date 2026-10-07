import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assessComparisonCompatibility,
  classifyFirewallComparisonItem,
  REQUIRED_LIMITATIONS,
  verifyBaselineDigest,
} from '../../src/contracts/protectionValidation.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createProtectionValidationRepository } from '../../src/persistence/postgres/protectionValidationRepository.mjs';
import { createPostgresProtectionValidationServices } from '../../src/persistence/postgres/protectionValidationServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { currentOriginProof } from '../../src/services/originBindings.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT = 'ten_pv_pg';
const OTHER = 'ten_pv_pg_other';
const GROUP = 'tg_pv_pg';
const OTHER_GROUP = 'tg_pv_pg_other';
const DECLARED = '2026-09-01T00:00:00.000Z';
const NOW = new Date('2026-10-06T00:00:00.000Z');
const CTX = { tenantId: TENANT, userId: 'usr_pv', role: 'owner' };
const VIEWER = { tenantId: TENANT, userId: 'usr_view', role: 'viewer' };
const OTHER_CTX = { tenantId: OTHER, userId: 'usr_other', role: 'owner' };
const TCP_CHECK = 'l3.basic_deny_rule.safe';

const POLICIES = [
  'tenant_isolation_application_entry_paths',
  'tenant_isolation_protection_expectations',
  'tenant_isolation_protection_comparison_baselines',
  'tenant_isolation_protection_comparison_evaluations',
  'tenant_isolation_protection_comparison_evidence_refs',
];

async function createAppRolePool(adminPool, ownerDatabaseUrl) {
  await adminPool.query(`ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
  const url = new URL(ownerDatabaseUrl.replace(/^postgresql:/i, 'postgres:'));
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString().replace(/^postgres:/i, 'postgresql:') });
  const check = await pool.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user');
  assert.equal(check.rows[0].rolsuper, false);
  assert.equal(check.rows[0].rolbypassrls, false);
  return pool;
}

async function seedRun(client, tenant, group, { id, targetId, status = 'verdicted', producer = 'signed_probe', source = 'public-worker-eu', port = 443, observedAt = '2026-10-05T00:00:00.000Z' }) {
  await client.query(
    `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, producer_kind, check_version, completed_at, created_at)
     VALUES ($1, $2, $3, $4, $5, 'running', $6, 'v1', $7::timestamptz, $7::timestamptz)`,
    [id, tenant, group, targetId, TCP_CHECK, producer, observedAt],
  );
  await client.query(
    `INSERT INTO probe_jobs (id, tenant_id, test_run_id, target_id, check_id, status, nonce_hash, target_descriptor_json,
       worker_metadata_json, job_signature, leased_by, leased_at, completed_at)
     VALUES ($1, $2, $3, $4, $5, 'completed', 'nonce_hash', $6::jsonb, $7::jsonb, 'sig', 'worker_eu_1', $8::timestamptz, $8::timestamptz)`,
    [`job_${id}`, tenant, id, targetId, TCP_CHECK, JSON.stringify({ id: targetId, port }), JSON.stringify({ source_perspective: source }), observedAt],
  );
  await client.query(
    `INSERT INTO events (id, tenant_id, test_run_id, target_id, check_id, source, signal_type, producer_kind, timestamp, metadata_json)
     VALUES ($1, $2, $3, $4, $5, 'probe_worker', 'probe_result', 'signed_probe', $6::timestamptz, '{}'::jsonb)`,
    [`evt_${id}`, tenant, id, targetId, TCP_CHECK, observedAt],
  );
  await client.query(
    `INSERT INTO verdicts (id, tenant_id, test_run_id, target_id, check_id, verdict, evidence_ids, created_at)
     VALUES ($1, $2, $3, $4, $5, 'pass', ARRAY[$6]::text[], $7::timestamptz)`,
    [`vrd_${id}`, tenant, id, targetId, TCP_CHECK, `ev_${id}`, observedAt],
  );
  await client.query('UPDATE test_runs SET status = $3 WHERE tenant_id = $1 AND id = $2', [tenant, id, status]);
}

async function seed(ownerPool) {
  await withTenantContext(ownerPool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'PV')`, [TENANT]);
    await client.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'PV')`, [GROUP, TENANT]);
    for (const [id, kind, value, deleted] of [
      ['tgt_pg_app', 'fqdn', 'app.example.test', false],
      ['tgt_pg_alt', 'fqdn', 'alt.example.test', false],
      ['tgt_pg_login', 'fqdn', 'login.example.test', false],
      ['tgt_pg_origin', 'ip', '203.0.113.10', false],
      ['tgt_pg_fw', 'ip', '198.51.100.5', false],
      ['tgt_pg_deleted', 'fqdn', 'gone.example.test', true],
    ]) {
      await client.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at, deleted_at)
         VALUES ($1, $2, $3, $4, $5, $5, $6::timestamptz, $7::timestamptz)`,
        [id, TENANT, GROUP, kind, value, DECLARED, deleted ? DECLARED : null],
      );
      await client.query(
        `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
         VALUES ($1, $2, $3, 'dns_verified', 'dns_txt', '{}'::jsonb, $4::timestamptz, 'usr_pv', 'aud_seed')`,
        [`tv_${id}`, TENANT, id, DECLARED],
      );
    }
    await client.query(
      `INSERT INTO origin_bindings (id, tenant_id, protected_target_id, protected_target_group_id, origin_target_id, origin_target_group_id, host, sni, created_at)
       VALUES ('obind_pg', $1, 'tgt_pg_app', $2, 'tgt_pg_origin', $2, 'app.example.test', 'app.example.test', $3::timestamptz)`,
      [TENANT, GROUP, DECLARED],
    );
    await seedRun(client, TENANT, GROUP, { id: 'run_pg_pre', targetId: 'tgt_pg_fw' });
    await seedRun(client, TENANT, GROUP, { id: 'run_pg_post', targetId: 'tgt_pg_fw', observedAt: '2026-10-05T12:00:00.000Z' });
    await seedRun(client, TENANT, GROUP, { id: 'run_pg_alt', targetId: 'tgt_pg_alt', port: null });
    await seedRun(client, TENANT, GROUP, { id: 'run_pg_running', targetId: 'tgt_pg_fw', status: 'running' });
  });
  await withTenantContext(ownerPool, OTHER, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Other')`, [OTHER]);
    await client.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'Other')`, [OTHER_GROUP, OTHER]);
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
       VALUES ('tgt_pg_foreign', $1, $2, 'ip', '198.51.100.9', '198.51.100.9', $3::timestamptz)`,
      [OTHER, OTHER_GROUP, DECLARED],
    );
    await seedRun(client, OTHER, OTHER_GROUP, { id: 'run_pg_foreign', targetId: 'tgt_pg_foreign' });
  });
}

const ALT = {
  entry_target_id: 'tgt_pg_alt',
  relation_kind: 'alternate_hostname',
  owner: 'App Team',
  purpose: 'Partner hostname',
  expected_behavior: 'must_be_protected_by_layers',
  required_layers: ['waf', 'cdn_edge'],
};

const FW = {
  destination_target_id: 'tgt_pg_fw',
  protocol: 'tcp',
  port: 443,
  expected: 'allow',
  source_perspective: 'public-worker-eu',
  change_id: 'CHG-PG-1',
};

describe('postgres protection validation persistence', () => {
  it('persists declarations, baselines, and evaluations with RLS, replay, audit, and immutability', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await assertRlsPoliciesExist(ownerPool, POLICIES);
      await seed(ownerPool);
      await ensureHarnessAppRole(ownerPool);
      const appPool = await createAppRolePool(ownerPool, databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName));
      const audits = async (action) => {
        const { rows } = await ownerPool.query('SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = $2', [TENANT, action]);
        return rows[0].n;
      };
      const traffic = async () => {
        const { rows } = await ownerPool.query('SELECT (SELECT count(*) FROM test_runs)::int AS runs, (SELECT count(*) FROM probe_jobs)::int AS jobs');
        return rows[0];
      };
      try {
        const services = createPostgresProtectionValidationServices({
          repository: createProtectionValidationRepository(appPool),
          audit: createAuditRepository(appPool),
        });
        const trafficBefore = await traffic();

        const created = await services.createEntryPath(CTX, 'tgt_pg_app', ALT, { now: NOW });
        assert.equal(created.error, undefined, JSON.stringify(created));
        assert.equal(created.replayed, false);
        assert.deepEqual(created.required_layers, ['waf', 'cdn_edge']);
        assert.equal(created.currently_authorized, true);
        assert.equal(created.digest_verified, true);
        assert.equal(created.created_at, '2026-10-06T00:00:00.000000Z');
        const replay = await services.createEntryPath(CTX, 'tgt_pg_app', ALT, { now: NOW });
        assert.equal(replay.replayed, true);
        assert.equal(replay.id, created.id);
        assert.equal(await audits('entry_path.created'), 1);
        assert.equal((await services.createEntryPath(CTX, 'tgt_pg_app', { ...ALT, purpose: 'Other' })).error, 'entry_path_conflict');
        const foreign = await services.createEntryPath(CTX, 'tgt_pg_app', { ...ALT, entry_target_id: 'tgt_pg_foreign' });
        const missing = await services.createEntryPath(CTX, 'tgt_pg_app', { ...ALT, entry_target_id: 'tgt_pg_missing' });
        assert.deepEqual(foreign, missing);
        assert.equal(foreign.status, 404);
        assert.equal((await services.createEntryPath(CTX, 'tgt_pg_app', { ...ALT, entry_target_id: 'tgt_pg_deleted' })).error, 'target_not_active');
        const origin = await services.createEntryPath(CTX, 'tgt_pg_app', {
          entry_target_id: 'tgt_pg_origin', relation_kind: 'origin', owner: 'Ops', purpose: 'Origin', expected_behavior: 'must_not_be_reachable', origin_binding_id: 'obind_pg',
        }, { now: new Date('2026-10-06T00:00:01Z') });
        assert.equal(origin.origin_binding_id, 'obind_pg');
        await services.createEntryPath(CTX, 'tgt_pg_app', { ...ALT, entry_target_id: 'tgt_pg_login', relation_kind: 'declared_login_url' }, { now: new Date('2026-10-06T00:00:02Z') });

        const concurrent = await Promise.all(Array.from({ length: 4 }, () => services.createEntryPath(CTX, 'tgt_pg_app', {
          ...ALT, entry_target_id: 'tgt_pg_app', relation_kind: 'primary_route',
        }, { now: new Date('2026-10-06T00:00:03Z') })));
        assert.equal(concurrent.filter((row) => row.error).length, 0, JSON.stringify(concurrent));
        assert.equal(new Set(concurrent.map((row) => row.id)).size, 1);
        assert.equal(concurrent.filter((row) => row.replayed === false).length, 1);

        const page1 = await services.listEntryPaths(VIEWER, 'tgt_pg_app', { limit: 2 });
        assert.equal(page1.count, 2);
        const page2 = await services.listEntryPaths(VIEWER, 'tgt_pg_app', { limit: 2, cursor: page1.next_cursor });
        assert.equal(page2.count, 2);
        assert.equal(page2.next_cursor, null);
        assert.equal(new Set([...page1.items, ...page2.items].map((row) => row.id)).size, 4);

        assert.equal((await services.getEntryPath(OTHER_CTX, created.id)).status, 404);
        const hidden = await withTenantContext(appPool, OTHER, async (client) => (await client.query('SELECT count(*)::int AS n FROM application_entry_paths')).rows[0].n);
        assert.equal(hidden, 0);

        const archived = await services.archiveEntryPath(CTX, created.id);
        assert.equal(archived.status, 'archived');
        assert.equal((await services.archiveEntryPath(CTX, created.id)).error, 'already_archived');
        assert.equal((await services.authorizeEntryPathForExecution(CTX, created.id)).error, 'entry_path_archived');
        const redeclared = await services.createEntryPath(CTX, 'tgt_pg_app', { ...ALT, purpose: 'Changed' });
        assert.equal(redeclared.declaration_version, 2);
        await assert.rejects(
          withTenantContext(appPool, TENANT, (client) => client.query(`UPDATE application_entry_paths SET purpose = 'x' WHERE id = $1`, [redeclared.id])),
          /immutable/,
        );

        const expectation = await services.createFirewallExpectation(CTX, FW, { now: NOW, idempotencyKey: 'fw-pg-1' });
        assert.equal(expectation.replayed, false);
        assert.equal(expectation.digest_verified, true);
        assert.equal((await services.createFirewallExpectation(CTX, FW, { idempotencyKey: 'fw-pg-1' })).replayed, true);
        assert.equal((await services.createFirewallExpectation(CTX, FW)).replayed, true);
        assert.equal((await services.createFirewallExpectation(CTX, { ...FW, expected: 'deny' })).error, 'firewall_expectation_conflict');
        assert.equal(await audits('firewall_expectation.created'), 1);
        assert.equal((await services.listExpectations(VIEWER, { change_id: 'CHG-PG-1' })).count, 1);

        const request = { change_id: 'CHG-PG-1', expectation_ids: [expectation.id], test_run_ids: ['run_pg_pre'] };
        assert.equal((await services.captureFirewallBaseline(CTX, { ...request, test_run_ids: ['run_pg_running'] })).error, 'evidence_not_finalized');
        assert.equal((await services.captureFirewallBaseline(CTX, { ...request, test_run_ids: ['run_pg_foreign'] })).status, 404);
        const capture = await services.captureFirewallBaseline(CTX, request, { now: NOW });
        assert.equal(capture.error, undefined, JSON.stringify(capture));
        assert.equal(capture.digest_verified, true);
        assert.equal(capture.entries[0].references[0].worker_id, 'worker_eu_1');
        assert.equal(verifyBaselineDigest(capture.entries[0]), true);
        const captureReplay = await services.captureFirewallBaseline(CTX, request);
        assert.equal(captureReplay.replayed, true);
        assert.equal(captureReplay.id, capture.id);
        assert.equal(await audits('firewall_baseline.captured'), 1);
        await assert.rejects(
          withTenantContext(appPool, TENANT, (client) => client.query(`UPDATE protection_comparison_baselines SET freshness_window_seconds = 7200 WHERE id = $1`, [capture.id])),
          /immutable/,
        );
        const baselineList = await services.listBaselineCaptures(VIEWER, { change_id: 'CHG-PG-1' });
        assert.equal(baselineList.count, 1);
        assert.equal(baselineList.items[0].digest_verified, true);
        assert.deepEqual(baselineList.items[0].entries, capture.entries);

        const postRef = { ...capture.entries[0].references[0], test_run_id: 'run_pg_post', verdict_id: 'vrd_run_pg_post', evidence_ids: ['ev_run_pg_post'], observed_at: '2026-10-05T12:00:00.000Z' };
        const candidate = { ...capture.entries[0], references: [postRef], captured_at: postRef.observed_at };
        delete candidate.baseline_digest;
        const compatibility = assessComparisonCompatibility(capture.entries[0], candidate);
        assert.equal(compatibility.comparable, true, JSON.stringify(compatibility));
        const item = classifyFirewallComparisonItem({ expectation, baseline: ['service_response_observed'], candidate: ['service_response_observed'], compatibility });
        assert.equal(item.status, 'matched');
        const evaluationInput = {
          kind: 'firewall_change',
          baseline_id: capture.id,
          baseline_digest: capture.baseline_digest,
          items: [{ expectation_id: expectation.id, ...item, evidence_refs: [postRef] }],
          evaluated_at: '2026-10-06T00:00:00.000Z',
        };
        const evaluation = await services.recordComparisonEvaluation(CTX, evaluationInput, { now: NOW });
        assert.equal(evaluation.error, undefined, JSON.stringify(evaluation));
        assert.equal(evaluation.summary.accepted, true);
        assert.equal(evaluation.digest_verified, true);
        assert.equal(evaluation.change_id, 'CHG-PG-1');
        assert.deepEqual(evaluation.limitations, [...REQUIRED_LIMITATIONS.firewall_change]);
        const evaluationReplay = await services.recordComparisonEvaluation(CTX, evaluationInput);
        assert.equal(evaluationReplay.replayed, true);
        assert.equal(await audits('firewall_comparison.evaluated'), 1);
        const read = await services.getEvaluation(VIEWER, evaluation.id, { kind: 'firewall_change' });
        assert.equal(read.digest_verified, true);
        assert.deepEqual(read.items, evaluation.items);
        const listed = await services.listEvaluations(VIEWER, { change_id: 'CHG-PG-1' });
        assert.equal(listed.count, 1);
        assert.equal(listed.items[0].digest_verified, true);
        const foreignRef = await services.recordComparisonEvaluation(CTX, {
          ...evaluationInput,
          items: [{ expectation_id: expectation.id, ...item, evidence_refs: [{ ...postRef, test_run_id: 'run_pg_foreign', verdict_id: null }] }],
          evaluated_at: '2026-10-06T01:00:00.000Z',
        });
        assert.equal(foreignRef.status, 404);
        const refCount = await withTenantContext(appPool, TENANT, async (client) => (await client.query(
          'SELECT count(*)::int AS n FROM protection_comparison_evidence_refs WHERE tenant_id = $1 AND evaluation_id = $2',
          [TENANT, evaluation.id],
        )).rows[0].n);
        assert.equal(refCount, 1);
        await assert.rejects(
          withTenantContext(appPool, TENANT, (client) => client.query('DELETE FROM protection_comparison_evaluations WHERE id = $1', [evaluation.id])),
          /immutable/,
        );

        const pvx = await services.recordPathValidationExpectation(CTX, { anchor_target_id: 'tgt_pg_app', scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce' } });
        assert.equal(pvx.expectation_version, 1);
        const pathBaseline = await services.capturePathValidationBaseline(CTX, { entry_path_id: redeclared.id, expectation_id: pvx.id, test_run_ids: ['run_pg_alt'] });
        assert.equal(pathBaseline.error, undefined, JSON.stringify(pathBaseline));
        assert.equal(pathBaseline.declaration_digest, redeclared.declaration_digest);
        assert.equal(pathBaseline.declaration_version, 2);
        assert.equal(pathBaseline.digest_verified, true);
        const pvx2 = await services.recordPathValidationExpectation(CTX, { anchor_target_id: 'tgt_pg_app', scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce', cdn_edge: 'enforce' } });
        assert.equal(pvx2.expectation_version, 2);
        assert.equal((await services.getExpectation(CTX, pvx.id)).status, 'archived');
        const pinned = await services.getBaselineCapture(VIEWER, pathBaseline.id);
        assert.equal(pinned.expectation_digest, pvx.digest);
        assert.equal(pinned.digest_verified, true);

        const pathEvaluation = await services.recordComparisonEvaluation(CTX, {
          kind: 'path_validation',
          anchor_target_id: 'tgt_pg_app',
          primary_entry_path_id: redeclared.id,
          items: [{ entry_path_id: redeclared.id, scenario: 'waf.sqli.marker', outcome: 'skipped', limitations: REQUIRED_LIMITATIONS.path_validation }],
          evaluated_at: '2026-10-06T00:00:00.000Z',
        }, { internal: true, actor: 'system' });
        assert.equal(pathEvaluation.error, undefined, JSON.stringify(pathEvaluation));
        assert.equal(pathEvaluation.summary.accepted, false);

        assert.equal((await services.listEntryPaths(OTHER_CTX, 'tgt_pg_app', {})).error, 'unknown_target');
        assert.equal((await services.getBaselineCapture(OTHER_CTX, capture.id)).status, 404);
        assert.equal((await services.getEvaluation(OTHER_CTX, evaluation.id)).status, 404);
        assert.deepEqual(await traffic(), trafficBefore);
      } finally {
        await closePgPool(appPool);
      }
    });
  });

  it('applies inherited subdomain ownership like the dev store', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await withTenantContext(ownerPool, TENANT, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'PV')`, [TENANT]);
        await client.query(`INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'PV')`, [GROUP, TENANT]);
        for (const [id, value, tags] of [
          ['tgt_pg_apex', 'example.test', []],
          ['tgt_pg_sub', 'app.example.test', ['subdomain-of:tgt_pg_apex']],
        ]) {
          await client.query(
            `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, metadata_json, created_at)
             VALUES ($1, $2, $3, 'fqdn', $4, $4, $5::jsonb, $6::timestamptz)`,
            [id, TENANT, GROUP, value, JSON.stringify({ tags }), DECLARED],
          );
        }
        await client.query(
          `INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
           VALUES ('tv_pg_apex', $1, 'tgt_pg_apex', 'dns_verified', 'dns_txt', '{}'::jsonb, $2::timestamptz, 'usr_pv', 'aud_seed')`,
          [TENANT, DECLARED],
        );
      });
      await ensureHarnessAppRole(ownerPool);
      const appPool = await createAppRolePool(ownerPool, databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName));
      try {
        const repository = createProtectionValidationRepository(appPool);
        const loaded = await repository.loadTargetContext(CTX, ['tgt_pg_sub']);
        assert.deepEqual(loaded.targets.map((row) => row.id), ['tgt_pg_sub']);
        assert.deepEqual(currentOriginProof(loaded.records, TENANT, 'tgt_pg_sub'), currentOriginProof(
          { targets: loaded.records.targets, targetVerifications: loaded.records.targetVerifications },
          TENANT,
          'tgt_pg_sub',
        ));
        assert.equal(currentOriginProof(loaded.records, TENANT, 'tgt_pg_sub').verified, true);
        const services = createPostgresProtectionValidationServices({ repository, audit: createAuditRepository(appPool) });
        const created = await services.createEntryPath(CTX, 'tgt_pg_apex', {
          entry_target_id: 'tgt_pg_sub', relation_kind: 'alternate_hostname', owner: 'App Team', purpose: 'Discovered subdomain',
          expected_behavior: 'must_be_protected_by_layers', required_layers: ['waf'],
        }, { now: NOW });
        assert.equal(created.error, undefined, JSON.stringify(created));
        assert.equal(created.currently_authorized, true);

        const client = await ownerPool.connect();
        try {
          await client.query('SET enable_seqscan = off');
          const plan = await client.query(
            `EXPLAIN SELECT id FROM protection_comparison_baselines
             WHERE tenant_id = $1 AND provenance_json->>'capture_id' = $2 AND (id = $2 OR starts_with(id, $2 || '.'))`,
            [TENANT, 'pcb_capture'],
          );
          assert.match(plan.rows.map((row) => row['QUERY PLAN']).join('\n'), /idx_protection_comparison_baselines_capture\b/);
        } finally {
          client.release();
        }
      } finally {
        await closePgPool(appPool);
      }
    });
  });
});
