import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createWafPostureRepository,
  mapConnectorPollJobRow,
  mapWafAssetRow,
  mapWafConnectorRow,
  mapWafConnectorSnapshotRow,
  mapWafCoverageDailyRollupRow,
  mapWafDriftEventRow,
  mapWafExceptionRow,
  mapWafPostureSnapshotRow,
  mapWafValidationRunRow,
} from '../../src/persistence/postgres/wafPostureRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-07-02T12:00:00.000Z';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const text = q.text.trim();
    return text !== 'BEGIN' &&
      text !== 'COMMIT' &&
      text !== 'ROLLBACK' &&
      !text.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [CTX.tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function assertTenantScoped(sql, params) {
  const hasTenantPredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertTenantColumn = /INSERT\s+INTO\s+(?:waf_|connector_poll_jobs)/i.test(sql) && /tenant_id/i.test(sql);
  assert.ok(hasTenantPredicate || hasInsertTenantColumn, `expected tenant scope in: ${sql}`);
  assert.ok(params.includes(CTX.tenantId), `expected tenant id param in: ${sql}`);
}

function connectorRowFixture(overrides = {}) {
  return {
    id: 'conn_1',
    tenant_id: CTX.tenantId,
    provider: 'cloudflare',
    name: 'Edge read-only',
    secret_id: null,
    config_json: { read_only: true, zone_ref_hash: 'zh_abc' },
    status: 'disabled',
    last_success_at: null,
    last_error_at: null,
    created_at: new Date(FIXED_NOW),
    updated_at: new Date(FIXED_NOW),
    ...overrides,
  };
}


function connectorPollJobRowFixture(overrides = {}) {
  return {
    id: 'connector_poll_conn_1_7',
    tenant_id: CTX.tenantId,
    connector_id: 'conn_1',
    provider: 'cloudflare',
    poll_revision: '7',
    status: 'pending',
    envelope_json: { version: 1, job_id: 'connector_poll_conn_1_7' },
    job_signature: 'signature-redacted-by-mapper',
    leased_by: null,
    leased_at: null,
    lease_token: null,
    expires_at: new Date('2026-07-02T12:10:00.000Z'),
    completed_at: null,
    error_code: null,
    created_at: new Date(FIXED_NOW),
    updated_at: new Date(FIXED_NOW),
    ...overrides,
  };
}
describe('postgres WAF posture repository', () => {
  it('maps waf asset rows to route-facing shape', () => {
    const mapped = mapWafAssetRow({
      id: 'waf_1',
      tenant_id: CTX.tenantId,
      target_group_id: 'tg_1',
      target_id: null,
      environment_id: null,
      canonical_url: 'https://app.example.com',
      asset_kind: 'web',
      expected_waf_required: true,
      expected_vendor_hint: null,
      business_criticality: 'high',
      traffic_tier: 'edge',
      compliance_tags: ['pci'],
      owner_hint: 'edge-team',
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
    });
    assert.equal(mapped.id, 'waf_1');
    assert.equal(mapped.canonical_url, 'https://app.example.com');
    assert.deepEqual(mapped.compliance_tags, ['pci']);
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists waf assets inside tenant context with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_assets/i.test(sql)) {
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              id: 'waf_1',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              environment_id: null,
              canonical_url: 'https://app.example.com',
              asset_kind: 'unknown',
              expected_waf_required: true,
              expected_vendor_hint: null,
              business_criticality: 'medium',
              traffic_tier: 'unknown',
              compliance_tags: [],
              owner_hint: null,
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listWafAssets(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].id, 'waf_1');
  });

  it('creates waf asset with metadata-only columns', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_assets/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.doesNotMatch(sql, /payload|credential|secret/i);
        return {
          rows: [
            {
              id: 'waf_new',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              environment_id: null,
              canonical_url: 'https://new.example.com',
              asset_kind: 'unknown',
              expected_waf_required: true,
              expected_vendor_hint: null,
              business_criticality: 'medium',
              traffic_tier: 'unknown',
              compliance_tags: [],
              owner_hint: null,
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const created = await repo.createWafAsset(CTX, {
      id: 'waf_new',
      target_group_id: 'tg_1',
      canonical_url: 'https://new.example.com',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.id, 'waf_new');
    assert.equal(dataQueries(pool.client).length, 1);
  });

  it('finalize bundle uses tenant-scoped updates and metadata json only', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_posture_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
      }
      if (/INSERT INTO waf_posture_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /source_mix_json/);
        assert.doesNotMatch(sql, /raw_payload|request_body/i);
      }
      if (/INSERT INTO waf_scenario_results/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /evidence_summary_json/);
      }
      if (/UPDATE waf_validation_runs/i.test(sql)) {
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              id: 'wvr_1',
              tenant_id: CTX.tenantId,
              test_run_id: null,
              waf_asset_id: 'waf_1',
              mode: 'marker',
              status: 'finalized',
              started_at: null,
              finalized_at: new Date(FIXED_NOW),
              safety_profile_json: {},
              summary_json: { posture_status: 'protected' },
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      if (/UPDATE waf_assets/i.test(sql)) {
        assertTenantScoped(sql, params);
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.finalizeWafValidationBundle(CTX, {
      run_id: 'wvr_1',
      waf_asset_id: 'waf_1',
      asset_updated_at: FIXED_NOW,
      snapshot: {
        id: 'snap_1',
        status: 'protected',
        reason_codes: [],
        coverage_required: true,
        risk_score: 0,
        confidence: 0.9,
        source_mix_json: { validation: true },
        created_at: FIXED_NOW,
      },
      scenarios: [
        {
          id: 'scn_1',
          scenario_family: 'marker',
          expected_action: 'block',
          observed_action: 'block',
          passed: true,
          confidence: 1,
          evidence_summary_json: { marker_seen: true },
          created_at: FIXED_NOW,
        },
      ],
      run_updates: {
        status: 'finalized',
        finalized_at: FIXED_NOW,
        summary_json: { posture_status: 'protected' },
      },
    });
    assertTenantWrapped(pool.client);
    assert.equal(result.validation_run.status, 'finalized');
    assert.equal(mapWafPostureSnapshotRow(result.snapshot).status, 'protected');
    assert.equal(mapWafValidationRunRow(result.validation_run).waf_asset_id, 'waf_1');
  });

  it('finalize bundle locks and rejects a bound run that is no longer successfully terminal', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/SELECT status\s+FROM test_runs/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /FOR UPDATE/);
        return { rows: [{ status: 'cancelled' }] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    await assert.rejects(
      () => repo.finalizeWafValidationBundle(CTX, {
        run_id: 'wvr_1',
        test_run_id: 'run_bound_1',
        waf_asset_id: 'waf_1',
      }),
      (error) => error.code === 'waf_validation_test_run_not_terminal' && error.status === 409,
    );
    assert.equal(
      dataQueries(pool.client).some((query) => /waf_posture_snapshots|waf_scenario_results/i.test(query.text)),
      false,
    );
    assert.equal(pool.client.queries.some((query) => query.text.trim() === 'ROLLBACK'), true);
    assert.equal(pool.client.released, true);
  });

  it('upsertWafPostureFinding inserts metadata-only finding with tenant scope', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM findings/i.test(sql) && /IS NOT DISTINCT FROM/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /status = 'open'/i);
        return { rows: [] };
      }
      if (/INSERT INTO findings/i.test(sql)) {
        assert.ok(params.includes(CTX.tenantId));
        assert.doesNotMatch(sql, /payload|credential|secret|raw_/i);
        return {
          rows: [
            {
              id: 'fnd_waf_1',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              test_run_id: 'run_1',
              check_id: 'waf.posture.waf_1',
              title: 'WAF posture unprotected: https://app.example.com',
              severity: 'high',
              status: 'open',
              evidence_ids: ['snap_1', 'scn_1'],
              notes: 'WAF posture finding.',
              remediation_template: 'waf_posture_remediation',
              verdict_id: null,
              last_verdict_id: null,
              assignee: null,
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.upsertWafPostureFinding(CTX, {
      id: 'fnd_waf_1',
      target_group_id: 'tg_1',
      target_id: null,
      test_run_id: 'run_1',
      check_id: 'waf.posture.waf_1',
      title: 'WAF posture unprotected: https://app.example.com',
      severity: 'high',
      notes: 'WAF posture finding.',
      remediation_template: 'waf_posture_remediation',
      evidence_ids: ['snap_1', 'scn_1'],
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(result.inserted, true);
    assert.equal(result.finding.check_id, 'waf.posture.waf_1');
    const data = dataQueries(pool.client);
    assert.equal(data.some((q) => /IS NOT DISTINCT FROM/i.test(q.text)), true);
    assert.equal(data.some((q) => /INSERT INTO findings/i.test(q.text)), true);
  });

  it('upsertWafPostureFinding updates open finding when target_id is null', async () => {
    let sawDistinctLookup = false;
    const pool = createRecordingPool((sql, params) => {
      if (/FROM findings/i.test(sql) && /IS NOT DISTINCT FROM/i.test(sql)) {
        sawDistinctLookup = true;
        assert.deepEqual(params[2], null);
        return {
          rows: [
            {
              id: 'fnd_existing',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              test_run_id: 'run_old',
              check_id: 'waf.posture.waf_1',
              title: 'old title',
              severity: 'medium',
              status: 'open',
              evidence_ids: [],
              notes: null,
              remediation_template: null,
              verdict_id: null,
              last_verdict_id: null,
              assignee: null,
              created_at: new Date('2026-07-01T12:00:00.000Z'),
              updated_at: null,
            },
          ],
        };
      }
      if (/UPDATE findings/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /last_verdict_id = NULL/i);
        return {
          rows: [
            {
              id: 'fnd_existing',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              test_run_id: 'run_new',
              check_id: 'waf.posture.waf_1',
              title: 'WAF posture underprotected: https://app.example.com',
              severity: 'high',
              status: 'open',
              evidence_ids: ['snap_2'],
              notes: 'updated notes',
              remediation_template: 'waf_posture_remediation',
              verdict_id: null,
              last_verdict_id: null,
              assignee: null,
              created_at: new Date('2026-07-01T12:00:00.000Z'),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.upsertWafPostureFinding(CTX, {
      id: 'fnd_new_should_not_insert',
      target_group_id: 'tg_1',
      target_id: null,
      test_run_id: 'run_new',
      check_id: 'waf.posture.waf_1',
      title: 'WAF posture underprotected: https://app.example.com',
      severity: 'high',
      notes: 'updated notes',
      remediation_template: 'waf_posture_remediation',
      evidence_ids: ['snap_2'],
      updated_at: FIXED_NOW,
      created_at: FIXED_NOW,
    });
    assert.equal(sawDistinctLookup, true);
    assert.equal(result.inserted, false);
    assert.equal(result.finding.id, 'fnd_existing');
    assert.equal(result.finding.test_run_id, 'run_new');
    assert.equal(dataQueries(pool.client).some((q) => /INSERT INTO findings/i.test(q.text)), false);
  });

  it('maps waf drift event rows with before_summary and after_summary', () => {
    const mapped = mapWafDriftEventRow({
      id: 'drf_1',
      tenant_id: CTX.tenantId,
      waf_asset_id: 'waf_1',
      baseline_id: null,
      drift_type: 'marker_failed',
      severity: 'high',
      before_summary_json: { posture_status: 'protected' },
      after_summary_json: { posture_status: 'underprotected' },
      status: 'open',
      finding_id: 'fnd_1',
      created_at: new Date(FIXED_NOW),
      resolved_at: null,
    });
    assert.equal(mapped.drift_type, 'marker_failed');
    assert.deepEqual(mapped.before_summary, { posture_status: 'protected' });
    assert.deepEqual(mapped.after_summary, { posture_status: 'underprotected' });
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists waf drift events inside tenant context with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.doesNotMatch(sql, /payload|credential|secret/i);
        return {
          rows: [
            {
              id: 'drf_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: null,
              drift_type: 'marker_failed',
              severity: 'high',
              before_summary_json: { posture_status: 'protected' },
              after_summary_json: { posture_status: 'underprotected' },
              status: 'open',
              finding_id: null,
              created_at: new Date(FIXED_NOW),
              resolved_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listWafDriftEvents(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].before_summary.posture_status, 'protected');
  });

  it('upsertWafDriftEvent atomically preserves maximum severity and original creation', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /ON CONFLICT \(tenant_id, waf_asset_id, drift_type\) WHERE status = 'open'/i);
        assert.match(sql, /THEN waf_drift_events\.severity/i);
        assert.match(sql, /after_summary_json = EXCLUDED\.after_summary_json/i);
        assert.doesNotMatch(sql, /created_at = EXCLUDED\.created_at/i);
        assert.doesNotMatch(sql, /raw_payload|request_body/i);
        return {
          rows: [
            {
              id: 'drf_existing',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: null,
              drift_type: 'marker_failed',
              severity: 'critical',
              before_summary_json: { posture_status: 'protected' },
              after_summary_json: { posture_status: 'underprotected', waf_detected: true },
              status: 'open',
              finding_id: 'fnd_1',
              created_at: new Date('2026-07-01T12:00:00.000Z'),
              resolved_at: null,
              was_inserted: false,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.upsertWafDriftEvent(CTX, {
      id: 'drf_new_should_not_insert',
      waf_asset_id: 'waf_1',
      drift_type: 'marker_failed',
      severity: 'high',
      before_summary: { posture_status: 'protected' },
      after_summary: { posture_status: 'underprotected', waf_detected: true },
      finding_id: 'fnd_1',
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(result.inserted, false);
    assert.equal(result.drift_event.id, 'drf_existing');
    assert.equal(result.drift_event.severity, 'critical');
    assert.equal(result.drift_event.created_at, '2026-07-01T12:00:00.000Z');
    assert.equal(
      dataQueries(pool.client).filter((q) => /INSERT INTO waf_drift_events/i.test(q.text)).length,
      1,
    );
    assert.equal(
      dataQueries(pool.client).some((q) => /^\s*SELECT[\s\S]*FROM waf_drift_events/i.test(q.text)),
      false,
    );
  });

  it('maps waf connector rows with config field', () => {
    const mapped = mapWafConnectorRow(connectorRowFixture());
    assert.equal(mapped.provider, 'cloudflare');
    assert.deepEqual(mapped.config, { read_only: true, zone_ref_hash: 'zh_abc' });
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists connectors inside tenant context with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connectors/i.test(sql)) {
        assertTenantScoped(sql, params);
        return { rows: [connectorRowFixture()] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listConnectors(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].config.zone_ref_hash, 'zh_abc');
  });

  it('atomically revokes connector authority and provider-bound probes only on feature disable transition', async () => {
    let upsertCount = 0;
    let connectorRevocations = 0;
    let connectorJobCancellations = 0;
    let probeJobCancellations = 0;
    let auditCount = 0;
    const stateRow = {
      tenant_id: CTX.tenantId,
      enabled: false,
      updated_at: new Date(FIXED_NOW),
      updated_by: CTX.userId,
      revision: '3',
    };
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO tenant_connector_features/i.test(sql)) {
        upsertCount += 1;
        assert.deepEqual(params, [CTX.tenantId, false, FIXED_NOW, CTX.userId]);
        assert.match(sql, /enabled IS DISTINCT FROM EXCLUDED\.enabled/);
        assert.match(sql, /revision = tenant_connector_features\.revision \+ 1/);
        return { rows: upsertCount === 1 ? [stateRow] : [] };
      }
      if (/SELECT tenant_id, enabled, updated_at/i.test(sql)) return { rows: [stateRow] };
      if (/UPDATE waf_connectors/i.test(sql)) {
        connectorRevocations += 1;
        assert.match(sql, /last_success_at = NULL/);
        assert.match(sql, /last_success_revision = 0/);
        assert.match(sql, /poll_revision = poll_revision \+ 1/);
        return { rows: [] };
      }
      if (/UPDATE connector_poll_jobs/i.test(sql)) {
        connectorJobCancellations += 1;
        assert.match(sql, /status IN \('pending', 'leased'\)/);
        assert.match(sql, /lease_token = NULL/);
        return { rows: [] };
      }
      if (/UPDATE probe_jobs/i.test(sql)) {
        probeJobCancellations += 1;
        assert.match(sql, /ownership_binding/);
        assert.match(sql, /provider_verified/);
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool, {
      auditRepository: {
        appendAuditEvent: async (_event, options) => {
          auditCount += 1;
          assert.equal(options.client, pool.client);
        },
      },
    });
    const auditEvent = { tenant_id: CTX.tenantId, action: 'connector.feature.disabled' };

    const changed = await repo.setConnectorFeatureState(CTX, false, {
      updated_at: FIXED_NOW,
      updated_by: CTX.userId,
      audit_event: auditEvent,
    });
    const unchanged = await repo.setConnectorFeatureState(CTX, false, {
      updated_at: FIXED_NOW,
      updated_by: CTX.userId,
      audit_event: auditEvent,
    });

    assert.equal(changed.changed, true);
    assert.equal(unchanged.changed, false);
    assert.equal(changed.revision, 3);
    assert.equal(connectorRevocations, 1);
    assert.equal(connectorJobCancellations, 1);
    assert.equal(probeJobCancellations, 1);
    assert.equal(auditCount, 1);
    assert.equal(pool.client.queries.filter((query) => query.text.trim() === 'COMMIT').length, 2);
  });

  it('creates connector with metadata-only config json', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_connectors/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /config_json/);
        assert.doesNotMatch(sql, /payload|credential|raw_/i);
        return { rows: [connectorRowFixture({ id: 'conn_new' })] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const created = await repo.createConnector(CTX, {
      id: 'conn_new',
      provider: 'cloudflare',
      name: 'Edge read-only',
      config_json: { read_only: true },
      status: 'disabled',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.id, 'conn_new');
    assert.equal(created.config.read_only, true);
  });

  it('gets connector by id with tenant scope', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connectors/i.test(sql) && /WHERE tenant_id/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.deepEqual(params.slice(0, 2), [CTX.tenantId, 'conn_1']);
        return { rows: [connectorRowFixture()] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const item = await repo.getConnector(CTX, 'conn_1');
    assert.equal(item.id, 'conn_1');
  });

  it('reserves a due connector revision through sustained provider admission', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/SELECT provider/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /next_poll_at <=/);
        assert.match(sql, /last_poll_requested_at <=/);
        return { rows: [{ provider: 'cloudflare' }] };
      }
      if (/INSERT INTO connector_provider_rate_limits/i.test(sql)) {
        assert.match(sql, /request_count < 20/);
        assert.match(sql, /INTERVAL '30 seconds'/);
        assert.match(sql, /INTERVAL '1 hour'/);
        return { rows: [{ request_count: 1 }] };
      }
      if (/SET poll_revision = CASE/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /last_poll_requested_at =/);
        assert.match(sql, /next_poll_at = .*INTERVAL '15 minutes'/s);
        return { rows: [{ poll_revision: '7' }] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    assert.equal(await repo.beginConnectorPoll(CTX, 'conn_1'), 7);
    assertTenantWrapped(pool.client);
  });


  it('lists bounded scheduler candidates without a usable open generation', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connectors c/i.test(sql) && /NOT EXISTS/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /c\.secret_id IS NOT NULL/i);
        assert.match(sql, /c\.next_poll_at <= CURRENT_TIMESTAMP/i);
        assert.match(sql, /config_json->>'read_only'/i);
        assert.match(sql, /j\.poll_revision = c\.poll_revision/i);
        assert.match(sql, /j\.expires_at > CURRENT_TIMESTAMP \+ INTERVAL '150 seconds'/i);
        assert.match(sql, /ORDER BY c\.updated_at, c\.id/i);
        assert.match(sql, /LIMIT \$2/i);
        assert.deepEqual(params, [CTX.tenantId, 2]);
        return { rows: [
          { connector_id: 'conn_schedule_1', provider: 'cloudflare' },
          { connector_id: 'conn_schedule_2', provider: 'aws_waf' },
        ] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const candidates = await repo.listConnectorPollScheduleCandidates(CTX, { limit: 2 });
    assert.deepEqual(candidates, [
      { connector_id: 'conn_schedule_1', provider: 'cloudflare' },
      { connector_id: 'conn_schedule_2', provider: 'aws_waf' },
    ]);
    assertTenantWrapped(pool.client);
  });

  it('lists only bounded current unexpired pending connector metadata', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM connector_poll_jobs j/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /j\.poll_revision = c\.poll_revision/i);
        assert.match(sql, /j\.provider = c\.provider/i);
        assert.match(sql, /j\.expires_at > CURRENT_TIMESTAMP \+ INTERVAL '150 seconds'/i);
        assert.match(sql, /c\.status NOT IN \('disabled', 'revoked'\)/i);
        assert.match(sql, /j\.leased_at <= CURRENT_TIMESTAMP - INTERVAL '5 minutes'/i);
        assert.match(sql, /LIMIT \$2/i);
        assert.deepEqual(params, [CTX.tenantId, 2]);
        return { rows: [
          { connector_id: 'conn_1', provider: 'cloudflare' },
          { connector_id: 'conn_2', provider: 'aws_waf' },
        ] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const pending = await repo.listPendingConnectorPollConnectors(CTX, { limit: 2 });
    assert.deepEqual(pending, [
      { connector_id: 'conn_1', provider: 'cloudflare' },
      { connector_id: 'conn_2', provider: 'aws_waf' },
    ]);
    assertTenantWrapped(pool.client);
  });

  it('creates tenant-scoped durable jobs and only refreshes expired open generations', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO connector_poll_jobs/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /ON CONFLICT \(tenant_id, connector_id, poll_revision\) DO UPDATE/i);
        assert.match(sql, /connector_poll_jobs\.status = 'pending'/i);
        assert.match(sql, /expires_at <= EXCLUDED\.created_at \+ INTERVAL '150 seconds'/i);
        assert.match(sql, /connector_poll_jobs\.status = 'leased'/i);
        assert.match(sql, /leased_at <= EXCLUDED\.created_at - INTERVAL '5 minutes'/i);
        assert.match(sql, /lease_token = NULL/i);
        return { rows: [connectorPollJobRowFixture()] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const job = await repo.createConnectorPollJob(CTX, {
      id: 'connector_poll_conn_1_7',
      connector_id: 'conn_1',
      provider: 'cloudflare',
      poll_revision: 7,
      envelope_json: { version: 1, job_id: 'connector_poll_conn_1_7' },
      job_signature: 'signed-value',
      expires_at: '2026-07-02T12:10:00.000Z',
      created_at: FIXED_NOW,
    });
    assert.equal(job.poll_revision, 7);
    assert.equal(job.job_signature, 'signature-redacted-by-mapper');
    assertTenantWrapped(pool.client);
  });

  it('rolls back signed job creation when transactional audit provenance fails', async () => {
    const pool = createRecordingPool((sql) => {
      if (/INSERT INTO connector_poll_jobs/i.test(sql)) {
        return { rows: [connectorPollJobRowFixture()] };
      }
      return { rows: [] };
    });
    const auditError = new Error('audit unavailable');
    const repo = createWafPostureRepository(pool, {
      auditRepository: {
        appendAuditEvent: async (_event, options) => {
          assert.equal(options.client, pool.client);
          throw auditError;
        },
      },
    });
    await assert.rejects(repo.createConnectorPollJob(CTX, {
      id: 'connector_poll_conn_1_7',
      connector_id: 'conn_1',
      provider: 'cloudflare',
      poll_revision: 7,
      envelope_json: { version: 2, job_id: 'connector_poll_conn_1_7' },
      job_signature: 'signed-value',
      expires_at: '2026-07-02T12:10:00.000Z',
      created_at: FIXED_NOW,
      audit_event: { tenant_id: CTX.tenantId, action: 'connector.poll.requested' },
    }), auditError);
    const statements = pool.client.queries.map((query) => query.text.trim());
    assert.equal(statements.includes('ROLLBACK'), true);
    assert.equal(statements.includes('COMMIT'), false);
  });

  it('claims only the current unexpired generation and reclaims a stale lease after its TTL', async () => {
    const leasedAt = '2026-07-02T12:06:00.000Z';
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connectors/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        assertTenantScoped(sql, params);
        return { rows: [connectorRowFixture({ status: 'validating', poll_revision: 7 })] };
      }
      if (/UPDATE connector_poll_jobs/i.test(sql) && /SET status = 'leased'/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /poll_revision = \$3::bigint/i);
        assert.match(sql, /provider = \$5/i);
        assert.match(sql, /expires_at > CURRENT_TIMESTAMP \+ INTERVAL '150 seconds'/i);
        assert.match(sql, /leased_at <= CURRENT_TIMESTAMP - INTERVAL '5 minutes'/i);
        assert.match(sql, /leased_at = CURRENT_TIMESTAMP/i);
        assert.match(sql, /lease_token = gen_random_uuid\(\)::text/i);
        assert.deepEqual(params, [CTX.tenantId, 'conn_1', 7, 'worker-a', 'cloudflare']);
        return { rows: [connectorPollJobRowFixture({
          status: 'leased',
          leased_by: 'worker-a',
          leased_at: new Date(leasedAt),
          lease_token: 'lease-token-a',
          updated_at: new Date(leasedAt),
        })] };
      }
      if (/UPDATE waf_connectors/i.test(sql)) {
        assert.match(sql, /status = 'polling'/i);
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const job = await repo.claimConnectorPollJob(CTX, 'conn_1', {
      worker_id: 'worker-a',
      leased_at: leasedAt,
    });
    assert.equal(job.leased_by, 'worker-a');
    assert.equal(job.lease_token, 'lease-token-a');
    assert.equal(job.poll_revision, 7);
    assertTenantWrapped(pool.client);
  });

  it('rejects claim admission unless the full signed execution window remains', async () => {
    let connectorMutated = false;
    const pool = createRecordingPool((sql) => {
      if (/FROM waf_connectors/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        return { rows: [connectorRowFixture({ status: 'validating', poll_revision: 7 })] };
      }
      if (/UPDATE connector_poll_jobs/i.test(sql) && /SET status = 'leased'/i.test(sql)) {
        assert.match(sql, /expires_at > CURRENT_TIMESTAMP \+ INTERVAL '150 seconds'/i);
        return { rows: [] };
      }
      if (/UPDATE waf_connectors/i.test(sql)) connectorMutated = true;
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const job = await repo.claimConnectorPollJob(CTX, 'conn_1', { worker_id: 'worker-a' });
    assert.equal(job, null);
    assert.equal(connectorMutated, false);
    assertTenantWrapped(pool.client);
  });

  it('revalidates exact lease and secret generation before provider request boundaries', async () => {
    const binding = {
      job_id: 'connector_poll_conn_1_7',
      worker_id: 'worker-a',
      lease_token: 'lease-token-a',
      poll_revision: 7,
      provider: 'cloudflare',
      secret_id: 'sec_cf',
      secret_rotation: 3,
    };
    const pool = createRecordingPool((sql, params) => {
      if (/SELECT EXISTS/i.test(sql) && /FROM connector_poll_jobs j/i.test(sql)) {
        assert.match(sql, /j\.lease_token = \$5/i);
        assert.match(sql, /c\.status = 'polling'/i);
        assert.match(sql, /c\.poll_revision = j\.poll_revision/i);
        assert.match(sql, /c\.secret_id = \$8/i);
        assert.match(sql, /s\.rotation = \$9::integer/i);
        assert.deepEqual(params, [
          CTX.tenantId, binding.job_id, 'conn_1', binding.worker_id, binding.lease_token,
          binding.poll_revision, binding.provider, binding.secret_id, binding.secret_rotation,
        ]);
        return { rows: [{ current: true }] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    assert.equal(await repo.isConnectorPollLeaseCurrent(CTX, 'conn_1', binding), true);
    assertTenantWrapped(pool.client);
  });

  it('does not mutate connector state or insert snapshots after a lost signed job lease', async () => {
    const pool = createRecordingPool((sql) => {
      if (/FROM waf_connectors/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        return { rows: [connectorRowFixture({ status: 'polling', poll_revision: 7 })] };
      }
      if (/FROM connector_poll_jobs/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        return { rows: [connectorPollJobRowFixture({
          status: 'leased',
          leased_by: 'worker-new',
          leased_at: new Date('2026-07-02T12:05:00.000Z'),
          lease_token: 'lease-token-new',
        })] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.completeConnectorPoll(CTX, 'conn_1', {
      job_id: 'connector_poll_conn_1_7',
      worker_id: 'worker-stale',
      lease_token: 'lease-token-stale',
      poll_revision: 7,
      completed_at: FIXED_NOW,
      updates: { status: 'active', last_success_at: FIXED_NOW },
      records: [{ id: 'must_not_insert' }],
    });
    assert.equal(result, null);
    assert.equal(dataQueries(pool.client).some((query) => /^\s*INSERT INTO waf_connector_snapshots/i.test(query.text)), false);
    assert.equal(dataQueries(pool.client).some((query) => /^\s*UPDATE waf_connectors/i.test(query.text)), false);
    assertTenantWrapped(pool.client);
  });

  it('rejects an otherwise exact connector completion at job expiry without side effects', async () => {
    const leasedAt = FIXED_NOW;
    const expiresAt = '2026-07-02T12:10:00.000Z';
    const pool = createRecordingPool((sql) => {
      if (/FROM waf_connectors/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        return { rows: [connectorRowFixture({ status: 'polling', poll_revision: 7 })] };
      }
      if (/FROM connector_poll_jobs/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        assert.match(sql, /expires_at > CURRENT_TIMESTAMP/i);
        assert.match(sql, /leased_at > CURRENT_TIMESTAMP - INTERVAL '5 minutes'/i);
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.completeConnectorPoll(CTX, 'conn_1', {
      job_id: 'connector_poll_conn_1_7', worker_id: 'worker-a', lease_token: 'lease-token-a',
      poll_revision: 7, completed_at: expiresAt,
      updates: { status: 'active', last_success_at: expiresAt },
      records: [{ id: 'must_not_insert' }],
    });
    assert.equal(result, null);
    assert.equal(dataQueries(pool.client).some((query) => /^\s*UPDATE waf_connectors/i.test(query.text)), false);
    assert.equal(dataQueries(pool.client).some((query) => /INSERT INTO waf_connector_snapshots/i.test(query.text)), false);
    assertTenantWrapped(pool.client);
  });

  it('atomically completes the exact lease after connector lock, persists snapshots, and advances generation', async () => {
    const leasedAt = '2026-07-02T11:59:00.000Z';
    const pool = createRecordingPool((sql) => {
      if (/FROM waf_connectors/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        return { rows: [connectorRowFixture({ status: 'polling', poll_revision: 7 })] };
      }
      if (/FROM connector_poll_jobs/i.test(sql) && /FOR UPDATE/i.test(sql)) {
        return { rows: [connectorPollJobRowFixture({
          status: 'leased', leased_by: 'worker-a', leased_at: new Date(leasedAt),
          lease_token: 'lease-token-a',
        })] };
      }
      if (/UPDATE waf_connectors/i.test(sql)) {

        assert.match(sql, /last_success_revision =/i);
        assert.match(sql, /status = 'polling'/i);
        return { rows: [connectorRowFixture({
          status: 'active', poll_revision: 7, last_success_revision: 7,
          last_success_at: new Date(FIXED_NOW),
        })] };
      }
      if (/INSERT INTO waf_connector_snapshots/i.test(sql)) {
        return { rows: [{
          id: 'csnap_1', tenant_id: CTX.tenantId, connector_id: 'conn_1', provider: 'cloudflare',
          snapshot_kind: 'dns_zone', resource_ref_hash: 'rh_1', display_ref: 'example.com',
          summary_json: { hostname: 'example.com', ownership_eligible: true }, config_hash: null,
          evidence_source: 'provider_api', inventory_complete: true, inventory_truncated: false,
          poll_revision: '7', observed_at: new Date(FIXED_NOW), created_at: new Date(FIXED_NOW),
        }] };
      }
      if (/UPDATE connector_poll_jobs/i.test(sql)) {
        assert.match(sql, /status = 'leased' AND leased_by = \$6 AND lease_token = \$7/i);
        assert.match(sql, /leased_by = NULL, leased_at = NULL, lease_token = NULL/i);
        assert.match(sql, /completed_at = CURRENT_TIMESTAMP/i);
        assert.match(sql, /expires_at > CURRENT_TIMESTAMP/i);
        assert.match(sql, /leased_at > CURRENT_TIMESTAMP - INTERVAL '5 minutes'/i);
        return { rows: [connectorPollJobRowFixture({
          status: 'completed', leased_by: null, leased_at: null, lease_token: null,
          completed_at: new Date(FIXED_NOW),
        })] };
      }
      return { rows: [] };
    });
    let atomicAudit = null;
    const repo = createWafPostureRepository(pool, {
      auditRepository: {
        appendAuditEvent: async (event, options) => {
          atomicAudit = event;
          assert.equal(options.client, pool.client);
          return event;
        },
      },
    });
    const result = await repo.completeConnectorPoll(CTX, 'conn_1', {
      job_id: 'connector_poll_conn_1_7', worker_id: 'worker-a', lease_token: 'lease-token-a',
      poll_revision: 7, completed_at: FIXED_NOW,
      updates: { status: 'active', last_success_at: FIXED_NOW, last_error_at: null },
      records: [{
        id: 'csnap_1', connector_id: 'conn_1', provider: 'cloudflare', snapshot_kind: 'dns_zone',
        resource_ref_hash: 'rh_1', display_ref: 'example.com',
        summary_json: { hostname: 'example.com', ownership_eligible: true },
        evidence_source: 'provider_api', inventory_complete: true, inventory_truncated: false,
        poll_revision: 7, observed_at: FIXED_NOW, created_at: FIXED_NOW,
      }],
      audit_event: {
        tenant_id: CTX.tenantId,
        action: 'connector.snapshot.created',
        resource_id: 'conn_1',
      },
    });
    assert.equal(atomicAudit?.action, 'connector.snapshot.created');
    assert.equal(result.connector.last_success_revision, 7);
    assert.equal(result.snapshots.length, 1);
    assert.equal(result.job.status, 'completed');
    const data = dataQueries(pool.client);
    assert.ok(data.findIndex((q) => /FROM waf_connectors/i.test(q.text))
      < data.findIndex((q) => /FROM connector_poll_jobs/i.test(q.text)));
    assert.equal(data.filter((q) => /INSERT INTO waf_connector_snapshots/i.test(q.text)).length, 1);
    assertTenantWrapped(pool.client);
  });
  it('updates connector status inside tenant context with optional poll compare-and-set', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_connectors/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /status =/);
        assert.match(sql, /last_success_revision =/);
        assert.match(sql, /poll_revision = \$\d+::bigint/);
        assert.equal(params.filter((value) => value === 7).length, 2);
        return {
          rows: [connectorRowFixture({
            status: 'active',
            last_success_at: new Date(FIXED_NOW),
            poll_revision: 7,
            last_success_revision: 7,
          })],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const updated = await repo.updateConnectorStatus(CTX, 'conn_1', {
      status: 'active',
      last_success_at: FIXED_NOW,
      updated_at: FIXED_NOW,
      expected_poll_revision: 7,
    });
    assert.equal(updated.status, 'active');
    assert.equal(updated.last_success_revision, 7);
    assertTenantWrapped(pool.client);
  });


  it('invalidates successful generation on disable and guards poll completions from revival', async () => {
    const statements = [];
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_connectors/i.test(sql)) {
        statements.push(sql);
        return { rows: [connectorRowFixture({ status: 'disabled' })] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    await repo.updateConnectorStatus(CTX, 'conn_1', {
      status: 'disabled',
      advance_poll_revision: true,
      invalidate_success_generation: true,
      updated_at: FIXED_NOW,
    });
    await repo.updateConnectorStatus(CTX, 'conn_1', {
      status: 'active',
      expected_poll_revision: 7,
      poll_completion: true,
      updated_at: FIXED_NOW,
    });

    assert.match(statements[0], /poll_revision = poll_revision \+ 1/);
    assert.match(statements[0], /last_success_at = NULL/);
    assert.match(statements[0], /last_success_revision = 0/);
    assert.equal((statements[0].match(/last_success_at\s*=/g) ?? []).length, 1);
    assert.match(statements[1], /status = 'polling'/);
  });
  it('creates connector snapshots with summary json only', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_connector_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /summary_json/);
        assert.match(sql, /poll_revision/);
        assert.doesNotMatch(sql, /raw_payload|request_body/i);
        return {
          rows: [
            {
              id: 'csnap_1',
              tenant_id: CTX.tenantId,
              connector_id: 'conn_1',
              provider: 'cloudflare',
              snapshot_kind: 'waf_policy',
              resource_ref_hash: 'rh_1',
              display_ref: 'zone-a',
              summary_json: { policy_mode: 'block', rule_count: 12 },
              config_hash: 'cfg_hash_1',
              poll_revision: 7,
              observed_at: new Date(FIXED_NOW),
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.createConnectorSnapshots(CTX, [
      {
        id: 'csnap_1',
        connector_id: 'conn_1',
        provider: 'cloudflare',
        snapshot_kind: 'waf_policy',
        resource_ref_hash: 'rh_1',
        display_ref: 'zone-a',
        summary_json: { policy_mode: 'block', rule_count: 12 },
        config_hash: 'cfg_hash_1',
        poll_revision: 7,
        observed_at: FIXED_NOW,
        created_at: FIXED_NOW,
      },
    ]);
    assert.equal(items.length, 1);
    assert.equal(items[0].summary.policy_mode, 'block');
    assert.equal(items[0].poll_revision, 7);
  });

  it('lists connector snapshots for connector id with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connector_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.deepEqual(params, [CTX.tenantId, 'conn_1']);
        return {
          rows: [
            {
              id: 'csnap_1',
              tenant_id: CTX.tenantId,
              connector_id: 'conn_1',
              provider: 'cloudflare',
              snapshot_kind: 'waf_policy',
              resource_ref_hash: 'rh_1',
              display_ref: null,
              summary_json: { rule_count: 3 },
              config_hash: null,
              observed_at: new Date(FIXED_NOW),
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listConnectorSnapshots(CTX, 'conn_1');
    assertTenantWrapped(pool.client);
    assert.equal(items[0].summary.rule_count, 3);
  });

  it('maps coverage daily rollup rows with UTC date buckets', () => {
    const mapped = mapWafCoverageDailyRollupRow({
      id: 'rollup_1',
      tenant_id: CTX.tenantId,
      rollup_date: new Date('2026-07-02T00:00:00.000Z'),
      total_assets: 10,
      protected: 6,
      underprotected: 2,
      unprotected: 1,
      unknown: 1,
      excluded: 0,
      coverage_ratio: 0.6,
      created_at: new Date(FIXED_NOW),
    });
    assert.equal(mapped.rollup_date, '2026-07-02');
    assert.equal(mapped.coverage_ratio, 0.6);
    assert.equal(mapped.protected, 6);
  });

  it('upserts coverage daily rollups with tenant-scoped conflict target', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_coverage_daily_rollups/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /ON CONFLICT \(tenant_id, rollup_date\)/i);
        return {
          rows: [
            {
              id: 'rollup_1',
              tenant_id: CTX.tenantId,
              rollup_date: '2026-07-02',
              total_assets: 4,
              protected: 2,
              underprotected: 1,
              unprotected: 1,
              unknown: 0,
              excluded: 0,
              coverage_ratio: 0.5,
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const saved = await repo.upsertWafCoverageDailyRollup(CTX, {
      id: 'rollup_1',
      rollup_date: '2026-07-02',
      total_assets: 4,
      protected: 2,
      underprotected: 1,
      unprotected: 1,
      unknown: 0,
      excluded: 0,
      coverage_ratio: 0.5,
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(saved.rollup_date, '2026-07-02');
    assert.equal(saved.total_assets, 4);
  });

  it('lists coverage daily rollups for a tenant window', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_coverage_daily_rollups/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.deepEqual(params, [CTX.tenantId, 90]);
        return {
          rows: [
            {
              id: 'rollup_1',
              tenant_id: CTX.tenantId,
              rollup_date: '2026-07-02',
              total_assets: 4,
              protected: 2,
              underprotected: 1,
              unprotected: 1,
              unknown: 0,
              excluded: 0,
              coverage_ratio: 0.5,
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listWafCoverageDailyRollups(CTX, { windowDays: 90 });
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].protected, 2);
  });

  it('maps waf exception rows to route-facing shape', () => {
    const mapped = mapWafExceptionRow({
      id: 'wafexc_1',
      tenant_id: CTX.tenantId,
      waf_asset_id: 'waf_1',
      owner: 'edge-team',
      reason: 'Legacy sunset',
      expires_at: new Date('2099-01-01T00:00:00.000Z'),
      scope_hash: 'scope_abc',
      approved_at: new Date(FIXED_NOW),
      approved_by: 'usr_admin',
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
    });
    assert.equal(mapped.id, 'wafexc_1');
    assert.equal(mapped.waf_asset_id, 'waf_1');
    assert.equal(mapped.expires_at, '2099-01-01T00:00:00.000Z');
    assert.equal(mapped.scope_hash, 'scope_abc');
    assert.equal(mapped.approved_at, FIXED_NOW);
    assert.equal(mapped.approved_by, 'usr_admin');
  });

  it('lists active waf exceptions with tenant scope and expiry filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_exceptions/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /expires_at > NOW\(\)/i);
        assert.deepEqual(params, [CTX.tenantId]);
        return {
          rows: [
            {
              id: 'wafexc_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              owner: 'edge-team',
              reason: 'Legacy sunset',
              expires_at: new Date('2099-01-01T00:00:00.000Z'),
              scope_hash: null,
              approved_at: new Date(FIXED_NOW),
              approved_by: 'usr_admin',
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listWafExceptions(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].owner, 'edge-team');
  });

  it('creates waf exceptions with tenant-scoped insert', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_exceptions/i.test(sql)) {
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              id: 'wafexc_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              owner: 'edge-team',
              reason: 'Legacy sunset',
              expires_at: new Date('2099-01-01T00:00:00.000Z'),
              scope_hash: 'scope_abc',
              approved_at: new Date(FIXED_NOW),
              approved_by: 'usr_admin',
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const created = await repo.createWafException(CTX, {
      id: 'wafexc_1',
      waf_asset_id: 'waf_1',
      owner: 'edge-team',
      reason: 'Legacy sunset',
      expires_at: '2099-01-01T00:00:00.000Z',
      scope_hash: 'scope_abc',
      approved_at: FIXED_NOW,
      approved_by: 'usr_admin',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(created.scope_hash, 'scope_abc');
  });

  it('patchWafDriftEvent is tenant-scoped and metadata-only', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.doesNotMatch(sql, /payload|credential|secret/i);
        assert.match(sql, /resolved_at = \$4::timestamptz/i);
        return {
          rows: [
            {
              id: 'drf_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: null,
              drift_type: 'marker_failed',
              severity: 'high',
              before_summary_json: {},
              after_summary_json: {},
              status: 'acknowledged',
              finding_id: null,
              created_at: new Date(FIXED_NOW),
              resolved_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const patched = await repo.patchWafDriftEvent(CTX, 'drf_1', {
      status: 'acknowledged',
      resolved_at: null,
    });
    assertTenantWrapped(pool.client);
    assert.equal(patched.status, 'acknowledged');
  });
});
