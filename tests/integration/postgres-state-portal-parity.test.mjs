import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createHighScaleRepository } from '../../src/persistence/postgres/highScaleRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createPostgresStateServices } from '../../src/persistence/postgres/stateServiceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { getState as getDevState } from '../../src/services/state.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

function appRoleProjectionPool(pool, { legacyJsonb = false, statements = [] } = {}) {
  return {
    async connect() {
      const client = await pool.connect();
      return {
        async query(sql, params) {
          if (sql === 'BEGIN') {
            await client.query(sql);
            return client.query('SET LOCAL ROLE astranull_app');
          }
          if (sql.includes('AS policies')) {
            statements.push(sql);
            if (legacyJsonb) sql = sql.replaceAll('json_agg(', 'jsonb_agg(').replace(/'\[\]'::json\b/g, "'[]'::jsonb");
          }
          return client.query(sql, params);
        },
        release() { client.release(); },
      };
    },
  };
}

function stateServices(pool) {
  return createPostgresStateServices({
    coreCatalog: createCoreCatalogRepository(pool),
    validationEvidence: createValidationEvidenceRepository(pool),
    highScale: createHighScaleRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
  }, { now: () => FIXED_NOW });
}

const TENANT = 'ten_state_portal_parity';
const CTX = { tenantId: TENANT, userId: 'state-parity-test', role: 'viewer' };
const FIXED_NOW = new Date('2026-09-27T00:00:00.000Z');
const GROUP_ID = 'tg_state_portal';
const TARGET_ID = 'tgt_state_portal';

const RUN_SPECS = [
  ['run_state_1', 'origin.direct_reachability.safe', 'protected'],
  ['run_state_2', 'origin.direct_bypass.safe', 'edge_protected'],
  ['run_state_3', 'origin.host_sni_bypass.safe', 'bypassable'],
  ['run_state_4', 'origin.direct_reachability.safe', 'bypassable'],
  ['run_state_5', 'origin.direct_bypass.safe', 'protected'],
  ['run_state_6', 'origin.host_sni_bypass.safe', 'edge_protected'],
  ['run_state_7', 'origin.direct_reachability.safe', null],
].map(([id, check_id, verdict], index) => ({
  id, correlation: { nonce_hash: `nonce_${id}` },
  tenant_id: TENANT,
  target_group_id: GROUP_ID,
  target_id: TARGET_ID,
  check_id,
  status: 'verdicted',
  created_at: new Date(Date.UTC(2026, 8, 20 + index)).toISOString(),
  completed_at: new Date(Date.UTC(2026, 8, 20 + index)).toISOString(),
  verdict,
}));

async function seed(pool) {
  await pool.query('INSERT INTO tenants (id, name) VALUES ($1, $1)', [TENANT]);
  await pool.query("INSERT INTO environments (id, tenant_id, name) VALUES ('env_state_portal', $1, 'prod')", [TENANT]);
  await pool.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name, validation_mode, created_at)
     VALUES ($1, $2, 'env_state_portal', 'Portal state', 'external_only', '2026-01-01')`,
    [GROUP_ID, TENANT],
  );
  await pool.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
     VALUES ($1, $2, $3, 'fqdn', 'state.example.test', 'state.example.test', '2026-01-01')`,
    [TARGET_ID, TENANT, GROUP_ID],
  );

  for (const run of RUN_SPECS) {
    await pool.query(
      `INSERT INTO test_runs (
         id, tenant_id, target_group_id, target_id, check_id, status, created_at, completed_at, correlation_json
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
      [run.id, TENANT, GROUP_ID, TARGET_ID, run.check_id, run.status, run.created_at, run.completed_at, JSON.stringify(run.correlation)],
    );
    if (!run.verdict) continue;
    const eventId = `evt_${run.id}`;
    await pool.query(
      `INSERT INTO events (
         id, tenant_id, test_run_id, target_id, check_id, source,
         signal_type, producer_kind, timestamp, ingested_at, metadata_json, nonce_hash
       ) VALUES ($1, $2, $3, $4, $5, 'probe_worker', 'probe_result', 'signed_probe', $6, $6, '{}'::jsonb, $7)`,
      [eventId, TENANT, run.id, TARGET_ID, run.check_id, run.completed_at, run.correlation.nonce_hash],
    );
    await pool.query(
      `INSERT INTO verdicts (
         id, tenant_id, test_run_id, target_id, check_id, verdict, evidence_ids, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, ARRAY[$7]::text[], $8)`,
      [`verdict_${run.id}`, TENANT, run.id, TARGET_ID, run.check_id, run.verdict, eventId, run.completed_at],
    );
  }
}

function devStore() {
  const verdicts = RUN_SPECS.filter((run) => run.verdict).map((run) => ({
    id: `verdict_${run.id}`,
    tenant_id: TENANT,
    test_run_id: run.id,
    target_id: TARGET_ID,
    check_id: run.check_id,
    verdict: run.verdict,
    evidence_ids: [`evt_${run.id}`],
    created_at: run.completed_at,
  }));
  const events = RUN_SPECS.filter((run) => run.verdict).map((run) => ({
    id: `evt_${run.id}`,
    tenant_id: TENANT,
    test_run_id: run.id,
    target_id: TARGET_ID,
    check_id: run.check_id,
    source: 'probe_worker',
    signal_type: 'probe_result',
    producer_kind: 'signed_probe',
    timestamp: run.completed_at, ingested_at: run.completed_at, nonce_hash: run.correlation.nonce_hash,
    metadata: {},
  }));
  return {
    tenants: [{ id: TENANT, name: TENANT }],
    environments: [{ id: 'env_state_portal', tenant_id: TENANT, name: 'prod' }],
    targetGroups: [{ id: GROUP_ID, tenant_id: TENANT, environment_id: 'env_state_portal', name: 'Portal state' }],
    targets: [{ id: TARGET_ID, tenant_id: TENANT, target_group_id: GROUP_ID, kind: 'fqdn', value: 'state.example.test' }],
    agents: [],
    testRuns: RUN_SPECS.map(({ verdict: _verdict, ...run }) => ({ ...run })),
    verdicts,
    events,
    evidenceVault: [],
    findings: [],
    highScaleRequests: [],
    auditLog: [],
    readiness: {},
    stateRollups: {},
    socKillSwitch: {},
  };
}

function assertPortalStateShape(payload) {
  const { applicable_count: applicable, not_run_count: notRun } = payload.readiness.coverage;
  assert.deepEqual(payload.readiness.posture, { pass: 0, review: applicable - notRun, gap: 0, not_run: notRun, total: applicable }, 'legacy E2 verdicts never earn current protection or exposure credit');
  assert.deepEqual(
    payload.recent_runs.map((run) => run.id),
    ['run_state_3', 'run_state_4', 'run_state_5', 'run_state_6', 'run_state_7'],
    'state keeps the newest five in chronological order for the portal reverse() projection',
  );
  for (const run of payload.recent_runs.slice(0, -1)) {
    assert.equal(typeof run.verdict, 'object', `${run.id} carries its trusted published verdict`);
    assert.ok(run.verdict.evidence_ids.length > 0);
  }
  assert.equal(payload.recent_runs.at(-1).verdict, null, 'a terminal run without cited evidence is not labelled tested');
}

describe('postgres state portal parity', () => {
  it('decodes complete JSON readiness snapshots with app-role parity to JSONB, without changing scope or payload', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const declaration = { note: 'Quoted "value" — origin', nested: { enabled: true, absent: null, ports: [443, 8443] } };
      await pool.query('UPDATE targets SET declaration_json = $2::jsonb, protocol = $3, port = $4 WHERE id = $1',
        [TARGET_ID, JSON.stringify(declaration), 'https', 8443]);
      await pool.query(`INSERT INTO evidence_vault (id, tenant_id, test_run_id, related_event_id, label, metadata_json, created_at)
        VALUES ('ev_state_codec', $1, $2, $3, 'Nested metadata', $4::jsonb, $5)`,
      [TENANT, RUN_SPECS[0].id, `evt_${RUN_SPECS[0].id}`, JSON.stringify(declaration), RUN_SPECS[0].created_at]);
      await pool.query(`INSERT INTO findings (id, tenant_id, target_id, title, severity, status, created_at)
        VALUES ('fnd_state_codec', $1, $2, 'Codec finding', 's3', 'open', $3)`,
      [TENANT, TARGET_ID, RUN_SPECS[0].created_at]);
      await pool.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
        VALUES ('tgt_state_future', $1, $2, 'fqdn', 'future.state.test', 'future.state.test', '2099-01-01')`, [TENANT, GROUP_ID]);
      await pool.query(`INSERT INTO test_policies (id, tenant_id, target_group_id, target_id, check_id, safety_policy_snapshot, created_at)
        VALUES ('pol_state_codec', $1, $2, $3, 'origin.direct_reachability.safe', $4::jsonb, '2026-01-01')`,
      [TENANT, GROUP_ID, TARGET_ID, JSON.stringify(declaration)]);
      await pool.query("INSERT INTO tenants (id, name) VALUES ('ten_other_codec', 'Other codec tenant')");
      await pool.query("INSERT INTO environments (id, tenant_id, name) VALUES ('env_other_codec', 'ten_other_codec', 'Other codec')");
      await pool.query(`INSERT INTO target_groups (id, tenant_id, environment_id, name, created_at)
        VALUES ('tg_other_codec', 'ten_other_codec', 'env_other_codec', 'Other codec', '2026-01-01')`);
      await pool.query(`INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
        VALUES ('tgt_other_codec', 'ten_other_codec', 'tg_other_codec', 'fqdn', 'other.codec.test', 'other.codec.test', '2026-01-01')`);
      const statements = [];
      const jsonPool = appRoleProjectionPool(pool, { statements });
      const legacyPool = appRoleProjectionPool(pool, { legacyJsonb: true });
      const repository = createValidationEvidenceRepository(jsonPool);
      const legacy = createValidationEvidenceRepository(legacyPool);
      const empty = await repository.readReadinessInputs(CTX, { asOf: '2025-01-01' });
      for (const key of ['groups', 'targets', 'runs', 'verdicts', 'events', 'evidenceItems', 'findingCounts', 'policies']) assert.deepEqual(empty[key], [], key);
      assert.equal((statements[0].match(/json_agg\(/g) ?? []).length, 8);
      assert.doesNotMatch(statements[0], /jsonb_agg\(/);
      assert.deepEqual(empty, await legacy.readReadinessInputs(CTX, { asOf: '2025-01-01' }));
      const result = await repository.readReadinessInputs(CTX, { asOf: FIXED_NOW });
      assert.deepEqual(result, await legacy.readReadinessInputs(CTX, { asOf: FIXED_NOW }));
      assert.deepEqual(result.targets.map((target) => target.id), [TARGET_ID]);
      assert.deepEqual(result.targets[0].declaration_json, declaration);
      assert.equal(result.targets[0].port, 8443);
      assert.equal(Date.parse(result.runs[0].created_at), Date.parse(RUN_SPECS[0].created_at));
      assert.equal(result.events.length, RUN_SPECS.filter((run) => run.verdict).length);
      assert.equal(result.verdicts.find((verdict) => verdict.test_run_id === RUN_SPECS[0].id).evidence_ids[0], `evt_${RUN_SPECS[0].id}`);
      assert.equal(result.evidenceItems[0].related_event_id, `evt_${RUN_SPECS[0].id}`);
      assert.deepEqual(result.evidenceItems[0].metadata, declaration);
      assert.equal(result.findingCounts[0].count, 1);
      assert.deepEqual(result.policies[0].safety_policy_snapshot, declaration);
      const foreign = await repository.readReadinessInputs({ ...CTX, tenantId: 'ten_other_codec' }, { asOf: FIXED_NOW });
      assert.deepEqual(foreign.targets.map((target) => target.id), ['tgt_other_codec']);
      assert.deepEqual(foreign.runs, []);
      assert.equal(result.input_complete && result.scope_complete && result.finding_counts_complete, true);
      assert.deepEqual(await stateServices(jsonPool).getState(CTX), await stateServices(legacyPool).getState(CTX));
      const otherTenant = await repository.readReadinessInputs({ ...CTX, tenantId: 'ten_missing_codec' }, { asOf: FIXED_NOW });
      for (const key of ['groups', 'targets', 'runs', 'verdicts', 'events', 'evidenceItems', 'findingCounts', 'policies']) assert.deepEqual(otherTenant[key], [], key);
    }, availability.env ?? process.env);
  });

  it('returns evidence-backed posture and safe recent-run fields with dev-json parity', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const state = createPostgresStateServices({
        coreCatalog: createCoreCatalogRepository(pool),
        validationEvidence: createValidationEvidenceRepository(pool),
        highScale: createHighScaleRepository(pool),
        killSwitch: createKillSwitchRepository(pool),
      }, { now: () => FIXED_NOW });

      const postgresPayload = await state.getState(CTX);
      assertPortalStateShape(postgresPayload);

      resetStoreForTests(devStore());
      const devPayload = await getDevState(CTX);
      assertPortalStateShape(devPayload);
      assert.deepEqual(devPayload.readiness.posture, postgresPayload.readiness.posture);
    }, availability.env ?? process.env);
  });
});
