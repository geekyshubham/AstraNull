import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { sha256Hex } from '../../src/lib/authorizationArtifactLedger.mjs';
import { computeScopeHashFromTargets } from '../../src/lib/scopeHash.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createWafOffensiveRepository } from '../../src/persistence/postgres/wafOffensiveRepository.mjs';
import { createPostgresWafOffensiveServices } from '../../src/persistence/postgres/wafOffensiveServiceAdapters.mjs';
import { createWafPostureRepository } from '../../src/persistence/postgres/wafPostureRepository.mjs';
import { createPostgresWafPostureServices } from '../../src/persistence/postgres/wafPostureServiceAdapters.mjs';
import { WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES } from '../../src/contracts/wafOffensive.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT_A = 'ten_wof_pg_a';
const TENANT_B = 'ten_wof_pg_b';
const GROUP_A = 'tg_wof_pg_a';
const GROUP_B = 'tg_wof_pg_b';
const TARGET_A = 'tgt_wof_pg_a';
const TARGET_B = 'tgt_wof_pg_b';
const WAF_ASSET_A = 'waf_wof_pg_a';
const WAF_ASSET_B = 'waf_wof_pg_b';

const ENGINEER = { tenantId: TENANT_A, userId: 'usr_wof_eng', role: 'engineer' };
const SOC_A = { tenantId: TENANT_A, userId: 'usr_wof_soc_a', role: 'soc' };
const SOC_B = { tenantId: TENANT_A, userId: 'usr_wof_soc_b', role: 'soc' };
const OTHER_TENANT = { tenantId: TENANT_B, userId: 'usr_wof_b', role: 'soc' };

async function createAppRolePool(ownerPool, databaseName) {
  await ensureHarnessAppRole(ownerPool);
  await ownerPool.query(
    `ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`,
  );
  const url = new URL(
    databaseUrlWithDatabase(ownerPool.options.connectionString, databaseName)
      .replace(/^postgresql:/i, 'postgres:'),
  );
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  return createPgPool({
    ASTRANULL_DATABASE_URL: url.toString().replace(/^postgres:/i, 'postgresql:'),
  });
}

async function seedTenant(ownerPool, suffix, tenantId, groupId, targetId, wafAssetId) {
  await withTenantContext(ownerPool, tenantId, async (client) => {
    const environmentId = `env_wof_pg_${suffix}`;
    await client.query(
      `INSERT INTO tenants (id, name) VALUES ($1, $2)`,
      [tenantId, `WAF offensive tenant ${suffix}`],
    );
    await client.query(
      `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'staging')`,
      [environmentId, tenantId],
    );
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name)
       VALUES ($1, $2, $3, 'staging edge')`,
      [groupId, tenantId, environmentId],
    );
    await client.query(
      `INSERT INTO targets (
         id, tenant_id, target_group_id, kind, value, normalized_value
       ) VALUES ($1, $2, $3, 'fqdn', $4, $4)`,
      [targetId, tenantId, groupId, `${suffix}.waf-offensive.example.test`],
    );
    await client.query(
      `INSERT INTO waf_assets (
         id, tenant_id, target_group_id, target_id, environment_id, canonical_url,
         asset_kind, expected_waf_required, business_criticality, traffic_tier
       ) VALUES ($1, $2, $3, $4, $5, $6, 'hostname', TRUE, 'high', 'staging')`,
      [
        wafAssetId,
        tenantId,
        groupId,
        targetId,
        environmentId,
        `https://${suffix}.waf-offensive.example.test`,
      ],
    );
  });
}

function requestBody(objective) {
  return {
    waf_asset_id: WAF_ASSET_A,
    objective,
    requested_suites: ['sqli_offensive', 'xss_offensive'],
    emergency_contacts: ['soc-on-call@example.invalid'],
    stop_criteria: 'Stop on origin impact or customer signal',
    abort_criteria: 'Abort on any safety threshold',
    scope_confirmation: true,
    staging_only: true,
  };
}

function artifactBody(type) {
  return {
    type,
    content_sha256: sha256Hex(`postgres-waf-offensive:${type}`),
    reference_uri: `metadata://waf-offensive/${type}`,
    approval_reference: 'WOF-PG-001',
    approver: 'Customer security approver',
    valid_window: {
      valid_from: new Date(Date.now() - 60_000).toISOString(),
      valid_to: new Date(Date.now() + 86_400_000).toISOString(),
    },
    approved_targets: [GROUP_A],
    approved_scenario_families: ['sqli_offensive', 'xss_offensive'],
    emergency_contacts: [{ name: 'SOC on-call', contact: 'soc-on-call@example.invalid' }],
    abort_criteria: { threshold: 'origin_impact', auto_stop: true },
  };
}

async function addAndAcceptAuthorizationPack(service, requestId) {
  for (const type of WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES) {
    const uploaded = await service.addArtifact(ENGINEER, requestId, artifactBody(type));
    assert.ok(uploaded?.artifact?.id, `artifact upload failed for ${type}`);
    const reviewed = await service.reviewArtifact(
      SOC_A,
      requestId,
      uploaded.artifact.id,
      { status: 'accepted', notes: 'Scope and custody reviewed.' },
    );
    assert.equal(reviewed.artifact.status, 'accepted');
  }
}

async function approveAndSchedule(service, objective) {
  const created = await service.createOffensiveRequest(ENGINEER, requestBody(objective));
  const requestId = created.offensive_request.id;
  await addAndAcceptAuthorizationPack(service, requestId);

  const concurrentSameSoc = await Promise.all([
    service.transitionOffensiveRequest(SOC_A, requestId, 'approve'),
    service.transitionOffensiveRequest(SOC_A, requestId, 'approve'),
  ]);
  assert.equal(
    concurrentSameSoc.filter((result) => result?.offensive_request?.state === 'under_review').length,
    1,
  );
  assert.equal(
    concurrentSameSoc.filter((result) => result?.error === 'duplicate_soc_approval').length,
    1,
  );

  const second = await service.transitionOffensiveRequest(SOC_B, requestId, 'approve');
  assert.equal(second.offensive_request.state, 'approved');
  assert.equal(
    second.offensive_request.scope_hash,
    computeScopeHashFromTargets(GROUP_A, [{
      id: TARGET_A,
      kind: 'fqdn',
      value: 'a.waf-offensive.example.test',
    }]),
  );

  const scheduled = await service.transitionOffensiveRequest(SOC_A, requestId, 'schedule', {
    window_start: new Date(Date.now() - 60_000).toISOString(),
    window_end: new Date(Date.now() + 3_600_000).toISOString(),
  });
  assert.equal(scheduled.offensive_request.state, 'scheduled');
  return requestId;
}

describe('Postgres WAF offensive workflow', () => {
  it('persists the complete SOC-gated lifecycle with forced RLS and the Postgres kill switch', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await assertRlsPoliciesExist(ownerPool, [
        'waf_offensive_requests_tenant_isolation',
        'waf_offensive_reports_tenant_isolation',
      ]);
      await seedTenant(ownerPool, 'a', TENANT_A, GROUP_A, TARGET_A, WAF_ASSET_A);
      await seedTenant(ownerPool, 'b', TENANT_B, GROUP_B, TARGET_B, WAF_ASSET_B);

      const appPool = await createAppRolePool(ownerPool, databaseName);
      try {
        const audit = createAuditRepository(appPool);
        const coreCatalog = createCoreCatalogRepository(appPool, { auditRepository: audit });
        const validationEvidence = createValidationEvidenceRepository(appPool);
        const killSwitch = createKillSwitchRepository(appPool);
        const wafPosture = createWafPostureRepository(appPool, { auditRepository: audit });
        const wafOffensive = createWafOffensiveRepository(appPool);
        const repositories = {
          audit,
          coreCatalog,
          validationEvidence,
          killSwitch,
          wafPosture,
          wafOffensive,
        };
        const wafPostureServices = createPostgresWafPostureServices(repositories, {
          connectorEncryptionKey: null,
        });
        const service = createPostgresWafOffensiveServices(repositories, {
          wafPostureServices,
        });

        const requestId = await approveAndSchedule(service, 'Postgres lifecycle validation');
        const started = await service.transitionOffensiveRequest(SOC_A, requestId, 'start');
        assert.equal(started.offensive_request.state, 'running');
        const runId = started.offensive_request.waf_validation_run_id;
        assert.ok(runId);

        const run = await withTenantContext(appPool, TENANT_A, async (client) => {
          const result = await client.query(
            `SELECT id, tenant_id, waf_asset_id, offensive_request_id, execution_class,
                    status, safety_profile_json
             FROM waf_validation_runs
             WHERE tenant_id = $1 AND id = $2`,
            [TENANT_A, runId],
          );
          return result.rows[0];
        });
        assert.equal(run.offensive_request_id, requestId);
        assert.equal(run.execution_class, 'offensive_suite');
        assert.equal(run.status, 'planned');
        assert.equal(run.safety_profile_json.risk_class, 'soc_gated');

        const stopped = await service.transitionOffensiveRequest(
          SOC_A,
          requestId,
          'stop',
          { reason: 'approved_suite_complete' },
        );
        assert.equal(stopped.offensive_request.state, 'stopped');

        const results = await service.recordOffensiveSuiteResults(SOC_A, requestId, {
          suite_results: [
            {
              suite_id: 'sqli_offensive',
              observed_action: 'block',
              passed: true,
              confidence: 0.97,
              evidence_summary: { block_page_signature_id: 'vendor-403' },
              probes_attempted: 10,
              blocked_count: 10,
            },
            {
              suite_id: 'xss_offensive',
              observed_action: 'block',
              passed: true,
              confidence: 0.93,
              evidence_summary: { challenge_detected: true },
              probes_attempted: 8,
              blocked_count: 8,
            },
          ],
        });
        assert.equal(results.suite_results.length, 2);

        const createdReport = await service.upsertOffensivePostTestReport(SOC_A, requestId, {
          executive_summary: 'All approved bounded suites were blocked before origin.',
          blocking_verdict: 'effective',
          bypass_findings: [],
          remediation_notes: 'Retain current staging policy.',
        });
        assert.equal(createdReport.created, true);
        assert.deepEqual(createdReport.report.suite_results, results.suite_results);
        const fetchedReport = await service.getOffensivePostTestReport(SOC_A, requestId);
        assert.equal(fetchedReport.report.id, createdReport.report.id);

        const closed = await service.transitionOffensiveRequest(SOC_A, requestId, 'close');
        assert.equal(closed.offensive_request.state, 'closed');

        const reportCount = await withTenantContext(appPool, TENANT_A, async (client) => {
          const result = await client.query(
            `SELECT count(*)::int AS count
             FROM waf_offensive_reports
             WHERE tenant_id = $1 AND waf_offensive_request_id = $2`,
            [TENANT_A, requestId],
          );
          return result.rows[0].count;
        });
        assert.equal(reportCount, 1);

        assert.equal(await service.getOffensiveRequest(OTHER_TENANT, requestId), null);
        await withTenantContext(appPool, TENANT_B, async (client) => {
          const leakedRequests = await client.query(
            `SELECT id FROM waf_offensive_requests
             WHERE id = $1 OR tenant_id = $2`,
            [requestId, TENANT_A],
          );
          assert.deepEqual(leakedRequests.rows, []);
          const leakedReports = await client.query(
            `SELECT id FROM waf_offensive_reports
             WHERE waf_offensive_request_id = $1 OR tenant_id = $2`,
            [requestId, TENANT_A],
          );
          assert.deepEqual(leakedReports.rows, []);
        });

        const auditActions = (await audit.listAuditEntries(SOC_A, { limit: 200 }))
          .map((entry) => entry.action);
        for (const action of [
          'waf.offensive_request.submitted',
          'waf.offensive_request.soc_approval_recorded',
          'waf.offensive_request.approved',
          'waf.offensive_request.scheduled',
          'waf.offensive_validation.started',
          'waf.offensive_request.execution_started',
          'waf.offensive_request.execution_stopped',
          'waf.offensive_request.results_recorded',
          'waf.offensive_report.created',
          'waf.offensive_request.closed',
        ]) {
          assert.ok(auditActions.includes(action), `missing audit action ${action}`);
        }

        const killSwitchRequestId = await approveAndSchedule(
          service,
          'Postgres kill-switch validation',
        );
        await killSwitch.upsertKillSwitch(SOC_A, {
          active: true,
          reason: 'integration safety drill',
          updated_by: SOC_A.userId,
          updated_at: new Date().toISOString(),
        });
        const denied = await service.transitionOffensiveRequest(
          SOC_A,
          killSwitchRequestId,
          'start',
        );
        assert.equal(denied.error, 'kill_switch_active');
        assert.equal(denied.status, 409);
        const stillScheduled = await service.getOffensiveRequest(SOC_A, killSwitchRequestId);
        assert.equal(stillScheduled.offensive_request.state, 'scheduled');
        const deniedRunCount = await withTenantContext(appPool, TENANT_A, async (client) => {
          const result = await client.query(
            `SELECT count(*)::int AS count
             FROM waf_validation_runs
             WHERE tenant_id = $1 AND offensive_request_id = $2`,
            [TENANT_A, killSwitchRequestId],
          );
          return result.rows[0].count;
        });
        assert.equal(deniedRunCount, 0);
      } finally {
        await closePgPool(appPool);
      }
    }, availability.env ?? process.env);
  });
});
