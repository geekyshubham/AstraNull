import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAgentControlRepository } from '../../src/persistence/postgres/agentControlRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createHighScaleRepository } from '../../src/persistence/postgres/highScaleRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createPostgresStateServices } from '../../src/persistence/postgres/stateServiceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { getState as getDevState } from '../../src/services/state.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

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
  id,
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
    `INSERT INTO target_groups (id, tenant_id, environment_id, name, validation_mode)
     VALUES ($1, $2, 'env_state_portal', 'Portal state', 'external_only')`,
    [GROUP_ID, TENANT],
  );
  await pool.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
     VALUES ($1, $2, $3, 'fqdn', 'state.example.test', 'state.example.test')`,
    [TARGET_ID, TENANT, GROUP_ID],
  );

  for (const run of RUN_SPECS) {
    await pool.query(
      `INSERT INTO test_runs (
         id, tenant_id, target_group_id, target_id, check_id, status, created_at, completed_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [run.id, TENANT, GROUP_ID, TARGET_ID, run.check_id, run.status, run.created_at, run.completed_at],
    );
    if (!run.verdict) continue;
    const eventId = `evt_${run.id}`;
    await pool.query(
      `INSERT INTO events (
         id, tenant_id, test_run_id, target_id, check_id, source,
         signal_type, producer_kind, timestamp, metadata_json
       ) VALUES ($1, $2, $3, $4, $5, 'probe_worker', 'probe_result', 'signed_probe', $6, '{}'::jsonb)`,
      [eventId, TENANT, run.id, TARGET_ID, run.check_id, run.completed_at],
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
    timestamp: run.completed_at,
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
  assert.deepEqual(payload.readiness.posture, { pass: 1, review: 1, gap: 1, total: 3 });
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
        agentControl: createAgentControlRepository(pool),
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
