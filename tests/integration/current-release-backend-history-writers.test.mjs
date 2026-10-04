import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { recordProbeResultEdgeDetection } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createTargetHistoryRepository } from '../../src/persistence/postgres/targetHistoryRepository.mjs';
import { createPostgresTargetHistoryServices } from '../../src/persistence/postgres/targetHistoryServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { historyReadModel } from '../../src/services/protectionProfile.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT = 'ten_hist_writers';
const OTHER = 'ten_hist_writers_other';
const GROUP = 'tg_hist_writers';
const OTHER_GROUP = 'tg_hist_writers_other';
const APP = 'tgt_hist_writers_app';
const ORIGIN = 'tgt_hist_writers_origin';
const SIBLING = 'tgt_hist_writers_sib';
const FOREIGN = 'tgt_hist_writers_foreign';
const CHECK = 'waf.fingerprint.safe';
const OPS = 'ops.runbook_contact_validation.safe';
const ORIGIN_CHECK = 'origin.direct_reachability.safe';
const DECLARED = '2026-09-01T00:00:00.000Z';
const CTX = { tenantId: TENANT, userId: 'usr_hist_writers', role: 'admin' };
const OTHER_CTX = { tenantId: OTHER, userId: 'usr_hist_writers_other', role: 'admin' };

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

function edgeMetadata(observedAt, overrides = {}) {
  return {
    external_result: 'connected',
    edge_signature_corpus_version: 'v2',
    source_completed_at: observedAt,
    edge_signature: {
      waf_present: true,
      cdn_detected: true,
      best_vendor: { vendor: 'cloudflare', confidence: 0.9 },
      address_matches: [{ family: 'cdn', provider: 'cloudfront' }],
    },
    ...overrides,
  };
}

describe('postgres current-release history writers', () => {
  it('stamps runs, appends signed history, and keeps closure per finding', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    const clock = Date.now();
    const iso = (ageMs) => new Date(clock - ageMs).toISOString();
    const newer = iso(2 * 86_400_000);
    const older = iso(10 * 86_400_000);
    const newest = iso(86_400_000);
    const failedAt = iso(3_600_000);

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await assertRlsPoliciesExist(ownerPool, [
        'tenant_isolation_target_observations',
        'tenant_isolation_origin_bindings',
        'tenant_isolation_finding_retest_lineage',
      ]);
      await withTenantContext(ownerPool, TENANT, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Writers')`, [TENANT]);
        await client.query(
          `INSERT INTO environments (id, tenant_id, name) VALUES ('env_hist_writers', $1, 'prod')`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode, safety_policy)
           VALUES ($1, $2, 'env_hist_writers', 'Writers', 'dns_verified', 'external_only',
                   '{"min_seconds_between_runs": 0, "max_runs_per_hour": 100}'::jsonb)`,
          [GROUP, TENANT],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at, declaration_json)
           VALUES
             ($1, $2, $3, 'fqdn', 'app.example.test', 'app.example.test', $4::timestamptz, $5::jsonb),
             ($6, $2, $3, 'ip', '203.0.113.10', '203.0.113.10', $4::timestamptz, '{}'::jsonb),
             ($7, $2, $3, 'fqdn', 'sib.example.test', 'sib.example.test', $4::timestamptz, '{}'::jsonb)`,
          [APP, TENANT, GROUP, DECLARED, JSON.stringify({ allowed_scope: { ports: [443], paths: ['/checkout'] } }), ORIGIN, SIBLING],
        );
        await client.query(
          `INSERT INTO waf_connectors (id, tenant_id, provider, name, status)
           VALUES ('conn_hist_writers_revoked', $1, 'cloudflare', 'Revoked DNS', 'revoked')`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO target_verifications (
             id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id
           ) VALUES
             ('ver_hist_writers_origin', $1, $2, 'dns_verified', 'dns_txt', '{}'::jsonb, $4::timestamptz, 'usr_hist_writers', 'aud_seed'),
             ('ver_hist_writers_app', $1, $3, 'provider_verified', 'provider_account', $5::jsonb, $4::timestamptz, 'usr_hist_writers', 'aud_seed')`,
          [TENANT, ORIGIN, APP, DECLARED, JSON.stringify({ connector_id: 'conn_hist_writers_revoked' })],
        );
        for (const run of [
          ['run_origin', APP, CHECK],
          ['run_sib', SIBLING, CHECK],
          ['run_edge_new', APP, CHECK, '1.0.0'],
          ['run_edge_old', APP, CHECK, '1.0.0'],
          ['run_edge_v2', APP, CHECK, '1.0.1'],
          ['run_edge_fail', APP, CHECK, '1.0.1'],
        ]) {
          await client.query(
            `INSERT INTO test_runs (
               id, tenant_id, target_group_id, target_id, check_id, status, created_at, check_version, scenario_version, producer_kind
             ) VALUES ($1, $2, $3, $4, $5, 'verdicted', $6::timestamptz, $7, 'fingerprint', 'signed_probe')`,
            [run[0], TENANT, GROUP, run[1], run[2], DECLARED, run[3] ?? null],
          );
        }
        await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status, created_at
           ) VALUES
             ('fnd_a', $1, $2, $3, 'run_origin', $4, 'Edge gap', 'high', 'open', $5::timestamptz),
             ('fnd_sib', $1, $2, $6, 'run_sib', $4, 'Sibling', 'low', 'open', $5::timestamptz)`,
          [TENANT, GROUP, APP, CHECK, DECLARED, SIBLING],
        );
      });
      await withTenantContext(ownerPool, OTHER, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Other')`, [OTHER]);
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, name) VALUES ($1, $2, 'Other')`,
          [OTHER_GROUP, OTHER],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
           VALUES ($1, $2, $3, 'fqdn', 'foreign.example.test', 'foreign.example.test', $4::timestamptz)`,
          [FOREIGN, OTHER, OTHER_GROUP, DECLARED],
        );
      });

      await ensureHarnessAppRole(ownerPool);
      const appPool = await createAppRolePool(ownerPool, databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName));
      try {
        const evidence = createValidationEvidenceRepository(appPool);
        const validation = createPostgresValidationServices({
          validationEvidence: evidence,
          audit: createAuditRepository(appPool),
          coreCatalog: createCoreCatalogRepository(appPool),
          probeJobs: createProbeJobRepository(appPool),
          killSwitch: createKillSwitchRepository(appPool),
        });
        const history = createPostgresTargetHistoryServices({
          repository: createTargetHistoryRepository(appPool),
          audit: createAuditRepository(appPool),
        });
        const countObs = async (tenantId = TENANT) => {
          const { rows } = await ownerPool.query(
            'SELECT count(*)::int AS n FROM target_observations WHERE tenant_id = $1',
            [tenantId],
          );
          return rows[0].n;
        };
        const countRuns = async () => {
          const { rows } = await ownerPool.query(
            'SELECT count(*)::int AS n FROM test_runs WHERE tenant_id = $1',
            [TENANT],
          );
          return rows[0].n;
        };
        const auditCount = async (action) => {
          const { rows } = await ownerPool.query(
            'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = $2',
            [TENANT, action],
          );
          return rows[0].n;
        };
        const settle = async (runId) => {
          await evidence.updateTestRun(CTX, runId, {
            status: 'cancelled',
            completed_at: new Date().toISOString(),
            expected_statuses: ['running', 'collecting'],
          });
        };
        const ingest = async (run, observedAt, metadata) => withTenantContext(appPool, TENANT, async (client) => (
          recordProbeResultEdgeDetection(evidence, CTX, {
            run,
            job: { id: `job_${run.id}`, check_id: CHECK, target_id: APP, target_group_id: GROUP },
            probeMetadata: metadata,
            observedAt,
            newIdFn: (prefix) => `${prefix}_${run.id}`,
            client,
          })
        ));

        const forgedStart = await validation.testRuns.startTestRun(CTX, {
          check_id: CHECK,
          target_group_id: GROUP,
          target_id: APP,
          check_version: 'forged',
          scenario_version: 'forged-scenario',
          producer_kind: 'signed_probe',
          live: true,
          expected_behavior: 'must_allow',
          internal: true,
        }, { probeMode: 'simulation' });
        assert.equal(forgedStart.error, undefined, JSON.stringify(forgedStart));
        assert.equal(forgedStart.run.check_version, '1.0.0');
        assert.equal(forgedStart.run.scenario_version, 'fingerprint');
        assert.equal(forgedStart.run.producer_kind, 'internal_simulation');
        assert.equal(forgedStart.run.expected_behavior, 'must_block_before_origin');
        assert.equal(forgedStart.run.expected_behavior_json.source, 'catalog_default');
        assert.equal(forgedStart.run.expected_behavior_json.value, 'must_block_before_origin');
        assert.equal(JSON.stringify(forgedStart.run).includes('must_allow'), false);
        assert.equal(forgedStart.probe_event.producer_kind, 'internal_simulation');
        assert.equal(forgedStart.probe_job, undefined);
        await settle(forgedStart.run.id);

        const ops = await validation.testRuns.startTestRun(CTX, {
          check_id: OPS,
          target_group_id: GROUP,
          target_id: APP,
          producer_kind: 'signed_probe',
          check_version: 'live',
          expected_behavior: 'must_allow',
        }, { probeMode: 'signed-worker' });
        assert.equal(ops.error, undefined, JSON.stringify(ops));
        assert.equal(ops.run.producer_kind, 'customer_declaration');
        assert.equal(ops.run.check_version, '1.0.0');
        assert.equal(ops.run.scenario_version, 'runbook_contacts');
        assert.equal(ops.run.expected_behavior, 'must_block_before_origin');
        assert.equal(ops.probe_job, undefined);
        assert.equal(ops.probe_event.producer_kind, 'internal_simulation');
        if (ops.run.status === 'running' || ops.run.status === 'collecting') await settle(ops.run.id);

        const edgeRun = (id, checkVersion) => ({
          id,
          target_group_id: GROUP,
          check_version: checkVersion,
          scenario_version: 'fingerprint',
          origin_binding_id: null,
        });
        await ingest(edgeRun('run_edge_new', '1.0.0'), newer, edgeMetadata(newer));
        let current = await evidence.getTargetEdgeDetection(CTX, APP);
        assert.equal(current.test_run_id, 'run_edge_new');
        const afterFirst = await countObs();
        await ingest(edgeRun('run_edge_old', '1.0.0'), older, edgeMetadata(older));
        current = await evidence.getTargetEdgeDetection(CTX, APP);
        assert.equal(current.test_run_id, 'run_edge_new');
        await ingest(edgeRun('run_edge_new', '1.0.0'), newer, edgeMetadata(newer));
        assert.equal(await countObs(), afterFirst + 2);
        await ingest(edgeRun('run_edge_v2', '1.0.1'), newest, edgeMetadata(newest));
        await ingest(edgeRun('run_edge_fail', '1.0.1'), failedAt, edgeMetadata(failedAt, {
          external_result: 'timeout',
          error_class: 'timeout',
        }));
        current = await evidence.getTargetEdgeDetection(CTX, APP);
        assert.equal(current.test_run_id, 'run_edge_v2');
        assert.notEqual(current.status, 'not_detected');

        const listed = await history.listTargetObservations(CTX, { target_id: APP, limit: 50 });
        const model = historyReadModel({ observations: listed.items, bindings: [], targetId: APP });
        const waf = model.retained_family_states.find((row) => row.family === 'waf');
        assert.equal(waf.last_successful.test_run_id, 'run_edge_v2');
        assert.equal(waf.last_successful.outcome, 'detected');
        assert.equal(waf.latest_failed_attempt.outcome, 'timeout');
        assert.equal(waf.latest_failed_attempt.test_run_id, 'run_edge_fail');
        assert.equal(waf.fresh_negative, false);
        assert.equal(waf.provider_loss, false);
        assert.equal(model.comparable_changes.some((row) => row.direction === 'improvement'), false);
        assert.equal(model.comparison_gaps.some((row) => row.family === 'waf' && row.reason === 'check_version_changed'), true);
        assert.equal(listed.items.every((row) => row.producer_kind === 'signed_probe'), true);

        const beforeBypass = await countObs();
        const bypass = await history.appendTargetObservation(CTX, {
          target_id: APP,
          family: 'waf',
          check_id: CHECK,
          source_kind: 'explicit_record',
          outcome: 'not_detected',
          observed_at: newer,
          nonce: 'forged-producer',
          producer_kind: 'signed_probe',
          check_version: 'forged',
          internal: true,
          server_derived: true,
        }, { now: new Date(clock) });
        assert.equal(bypass.error, 'body_supplied_version');
        assert.equal(await countObs(), beforeBypass);

        const hidden = await history.appendTargetObservation(OTHER_CTX, {
          target_id: FOREIGN,
          family: 'waf',
          check_id: CHECK,
          source_kind: 'explicit_record',
          outcome: 'detected',
          observed_at: newer,
          nonce: 'foreign-writers',
        }, { now: new Date(clock) });
        assert.equal(hidden.error, undefined, JSON.stringify(hidden));
        const visible = await history.listTargetObservations(CTX, { limit: 50 });
        assert.equal(visible.items.some((row) => row.id === hidden.id), false);
        const isolated = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query(
            'SELECT count(*)::int AS n FROM target_observations WHERE id = $1',
            [hidden.id],
          );
          return rows[0].n;
        });
        assert.equal(isolated, 0);

        const runsBeforeRetest = await countRuns();
        const viewer = await validation.testRuns.startTestRun({ ...CTX, role: 'viewer' }, {
          check_id: CHECK,
          target_group_id: GROUP,
          target_id: APP,
          retest_of_finding_id: 'fnd_a',
        }, { probeMode: 'simulation' });
        assert.equal(viewer.error, 'forbidden');
        assert.equal(viewer.status, 403);
        const mismatched = await validation.testRuns.startTestRun(CTX, {
          check_id: CHECK,
          target_group_id: GROUP,
          target_id: APP,
          retest_of_finding_id: 'fnd_sib',
        }, { probeMode: 'simulation' });
        assert.equal(mismatched.error, 'pair_mismatch');
        assert.equal(mismatched.status, 409);
        assert.equal(await countRuns(), runsBeforeRetest);

        const retest = await validation.testRuns.startTestRun(CTX, {
          check_id: CHECK,
          target_group_id: GROUP,
          target_id: APP,
          retest_of_finding_id: 'fnd_a',
          producer_kind: 'signed_probe',
          check_version: 'forged',
        }, { probeMode: 'simulation' });
        assert.equal(retest.error, undefined, JSON.stringify(retest));
        assert.equal(retest.run.retest_of_finding_id, 'fnd_a');
        assert.equal(retest.run.producer_kind, 'internal_simulation');
        assert.equal(retest.run.check_version, '1.0.0');
        const lineageRow = await ownerPool.query(
          `SELECT intent, relation FROM finding_retest_lineage
           WHERE tenant_id = $1 AND finding_id = 'fnd_a' AND test_run_id = $2`,
          [TENANT, retest.run.id],
        );
        assert.equal(lineageRow.rows[0].intent, 'retest');
        assert.equal(lineageRow.rows[0].relation, 'retest');
        const openBeforeClose = await validation.findings.getFinding(CTX, 'fnd_a');
        assert.equal(openBeforeClose.status, 'open');
        assert.equal(openBeforeClose.closed_at, null);
        assert.equal(openBeforeClose.retests.some((row) => row.test_run_id === retest.run.id), true);
        assert.equal(openBeforeClose.lineage.later_same_pair.some((row) => row.test_run_id === retest.run.id), false);
        assert.equal(openBeforeClose.lineage.later_same_pair.some((row) => row.test_run_id === 'run_edge_new'), true);
        assert.equal(openBeforeClose.lineage.later_same_pair.every((row) => row.can_advance_remediation === false), true);
        assert.equal(openBeforeClose.lineage.sibling_closure, false);
        assert.equal(openBeforeClose.originating.test_run_id, 'run_origin');
        assert.equal(openBeforeClose.latest.relation, 'retest');
        assert.equal(openBeforeClose.latest.test_run_id, retest.run.id);
        assert.equal(openBeforeClose.fix_proved, undefined);
        await settle(retest.run.id);

        const assigned = await validation.findings.patchFinding(CTX, 'fnd_a', {
          notes: 'operator note', closed_at: '2000-01-01T00:00:00.000Z',
          last_verdict_id: 'customer_forged_verdict', evidence_ids: ['customer_forged_evidence'],
        });
        assert.equal(assigned.status, 'open');
        assert.equal(assigned.closed_at, null);
        assert.equal(assigned.last_verdict_id, openBeforeClose.last_verdict_id);
        assert.deepEqual(assigned.evidence_ids, openBeforeClose.evidence_ids);

        const auditsBefore = await auditCount('finding.updated');
        const invalid = await validation.findings.patchFinding(CTX, 'fnd_a', { status: 'fixed' });
        assert.equal(invalid.error, 'invalid_lifecycle');
        assert.equal(invalid.status, 400);
        assert.equal(await auditCount('finding.updated'), auditsBefore);
        const stillOpen = await ownerPool.query(`SELECT status, closed_at FROM findings WHERE id = 'fnd_a'`);
        assert.equal(stillOpen.rows[0].status, 'open');
        assert.equal(stillOpen.rows[0].closed_at, null);

        const closed = await validation.findings.patchFinding(CTX, 'fnd_a', { status: 'closed', notes: 'operator closed' });
        assert.equal(closed.status, 'closed');
        assert.ok(closed.closed_at);
        assert.equal(closed.fix_proved, undefined);
        const sibling = await ownerPool.query(`SELECT status, closed_at FROM findings WHERE id = 'fnd_sib'`);
        assert.equal(sibling.rows[0].status, 'open');
        assert.equal(sibling.rows[0].closed_at, null);
        const closedView = await validation.findings.getFinding(CTX, 'fnd_a');
        assert.equal(closedView.lineage.siblings.find((row) => row.id === 'fnd_sib').status, 'open');
        assert.equal(await auditCount('finding.updated'), auditsBefore + 1);

        const retainedClosure = await validation.findings.patchFinding(CTX, 'fnd_a', {
          notes: 'another operator note', closed_at: null,
        });
        assert.equal(retainedClosure.status, 'closed');
        assert.equal(retainedClosure.closed_at, closed.closed_at);

        const binding = await history.createOriginBinding(CTX, {
          protected_target_id: APP,
          origin_target_id: ORIGIN,
        }, { now: new Date(DECLARED) });
        assert.equal(binding.error, undefined, JSON.stringify(binding));
        assert.equal(binding.assurance, 'none');
        const bannedDestination = await validation.testRuns.startTestRun(CTX, {
          check_id: ORIGIN_CHECK,
          target_group_id: GROUP,
          target_id: ORIGIN,
          origin_binding_id: binding.id,
          direct_ip: '198.51.100.10',
        }, { probeMode: 'simulation' });
        assert.equal(bannedDestination.error, 'scope_not_declared');
        assert.equal(bannedDestination.field, 'direct_ip');
        const deniedOrigin = await validation.testRuns.startTestRun(CTX, {
          check_id: ORIGIN_CHECK,
          target_group_id: GROUP,
          target_id: ORIGIN,
          origin_binding_id: binding.id,
        }, { probeMode: 'simulation' });
        assert.equal(deniedOrigin.error, 'ownership_not_verified', JSON.stringify(deniedOrigin));
        assert.equal(deniedOrigin.proof, 'protected');
        const boundRuns = await ownerPool.query(
          'SELECT count(*)::int AS n FROM test_runs WHERE origin_binding_id = $1',
          [binding.id],
        );
        assert.equal(boundRuns.rows[0].n, 0);
      } finally {
        await closePgPool(appPool);
      }
    });
  });
});
