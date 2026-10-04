import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createTargetHistoryRepository } from '../../src/persistence/postgres/targetHistoryRepository.mjs';
import { createPostgresTargetHistoryServices } from '../../src/persistence/postgres/targetHistoryServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { compareObservationOrder } from '../../src/services/targetHistory.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT = 'ten_hist_pg';
const OTHER = 'ten_hist_other';
const GROUP = 'tg_hist_pg';
const OTHER_GROUP = 'tg_hist_other';
const APP = 'tgt_hist_app';
const ORIGIN = 'tgt_hist_origin';
const UNPROVEN = 'tgt_hist_unproven';
const AGENT = 'tgt_hist_agent';
const PROVIDER = 'tgt_hist_provider';
const FOREIGN = 'tgt_hist_foreign';
const CHECK = 'waf.fingerprint.safe';
const DECLARED = '2026-09-01T00:00:00.000Z';
const NOW = new Date('2026-10-04T12:00:00.000Z');
const CTX = { tenantId: TENANT, userId: 'usr_hist', role: 'admin' };
const OTHER_CTX = { tenantId: OTHER, userId: 'usr_other', role: 'admin' };

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

function observation(overrides = {}) {
  return {
    target_id: APP,
    family: 'waf',
    check_id: CHECK,
    source_kind: 'explicit_record',
    corpus_version: 'corpus-1',
    scenario_version: 'scenario-1',
    observed_at: '2026-09-02T00:00:00.100Z',
    source_completed_at: '2026-09-02T00:00:01.000Z',
    outcome: 'detected',
    nonce: `n-${Math.random().toString(16).slice(2)}`,
    provenance: { provider: 'cloudflare', status: 'detected' },
    ...overrides,
  };
}

describe('postgres current-release history', () => {
  it('enforces RLS, order, replay, comparison, origin proof, and per-target retest', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await assertRlsPoliciesExist(ownerPool, [
        'tenant_isolation_target_observations',
        'tenant_isolation_target_observation_current',
        'tenant_isolation_origin_bindings',
        'tenant_isolation_finding_retest_lineage',
      ]);
      await withTenantContext(ownerPool, TENANT, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'History')`, [TENANT]);
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, name, ownership_status) VALUES ($1, $2, 'History', 'dns_verified')`,
          [GROUP, TENANT],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at, declaration_json)
           VALUES
             ($1, $2, $3, 'fqdn', 'app.example.test', 'app.example.test', $4::timestamptz, $5::jsonb),
             ('tgt_hist_origin', $2, $3, 'ip', '203.0.113.10', '203.0.113.10', $4::timestamptz, '{}'::jsonb),
             ('tgt_hist_unproven', $2, $3, 'ip', '203.0.113.11', '203.0.113.11', $4::timestamptz, '{}'::jsonb),
             ('tgt_hist_agent', $2, $3, 'ip', '203.0.113.12', '203.0.113.12', $4::timestamptz, '{}'::jsonb),
             ('tgt_hist_provider', $2, $3, 'ip', '203.0.113.13', '203.0.113.13', $4::timestamptz, '{}'::jsonb),
             ('tgt_hist_b', $2, $3, 'fqdn', 'b.example.test', 'b.example.test', $4::timestamptz, '{}'::jsonb)`,
          [APP, TENANT, GROUP, DECLARED, JSON.stringify({ allowed_scope: { ports: [443], paths: ['/checkout'] } })],
        );
        await client.query(
          `INSERT INTO target_verifications (
             id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id
           ) VALUES
             ('ver_origin', $1, $2, 'dns_verified', 'dns_txt', '{}'::jsonb, $5::timestamptz, 'usr_hist', 'aud_seed'),
             ('ver_agent', $1, $3, 'agent_verified', 'agent_observation', '{}'::jsonb, $5::timestamptz, 'usr_hist', 'aud_seed'),
             ('ver_provider', $1, $4, 'provider_verified', 'provider_account', '{}'::jsonb, $5::timestamptz, 'usr_hist', 'aud_seed')`,
          [TENANT, ORIGIN, AGENT, PROVIDER, DECLARED],
        );
        for (const run of [
          ['run_origin', APP, CHECK, 'verdicted'],
          ['run_later', APP, CHECK, 'completed'],
          ['run_retest', APP, CHECK, 'verdicted'],
          ['run_other_target', 'tgt_hist_b', CHECK, 'verdicted'],
          ['run_other_check', APP, 'dns.resolution.safe', 'verdicted'],
        ]) {
          await client.query(
            `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz)`,
            [run[0], TENANT, GROUP, run[1], run[2], run[3], DECLARED],
          );
        }
        await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status, created_at
           ) VALUES
             ('fnd_a', $1, $2, $3, 'run_origin', $4, 'Edge gap', 'high', 'open', $5::timestamptz),
             ('fnd_sib', $1, $2, 'tgt_hist_b', 'run_other_target', $4, 'Sibling', 'low', 'open', $5::timestamptz)`,
          [TENANT, GROUP, APP, CHECK, DECLARED],
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
        const services = createPostgresTargetHistoryServices({
          repository: createTargetHistoryRepository(appPool),
          audit: createAuditRepository(appPool),
        });
        const countObservations = async () => {
          const { rows } = await ownerPool.query('SELECT count(*)::int AS n FROM target_observations');
          return rows[0].n;
        };

        const hidden = await services.appendTargetObservation(OTHER_CTX, observation({
          target_id: FOREIGN,
          nonce: 'foreign-obs',
        }), { now: NOW });
        assert.equal(hidden.error, undefined);
        const visible = await services.listTargetObservations(CTX, { limit: 50 });
        assert.equal(visible.items.some((row) => row.id === hidden.id), false);
        const isolated = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query('SELECT count(*)::int AS n FROM target_observations WHERE id = $1', [hidden.id]);
          return rows[0].n;
        });
        assert.equal(isolated, 0);
        assert.equal(await countObservations(), 1);

        const newer = await services.appendTargetObservation(CTX, observation({
          nonce: 'newer',
          observed_at: '2026-09-04T00:00:00.000Z',
          source_completed_at: '2026-09-04T00:00:01.000Z',
          check_version: 'check-1',
          producer_kind: 'manual',
        }), { internal: true, now: NOW });
        const older = await services.appendTargetObservation(CTX, observation({
          nonce: 'older',
          observed_at: '2026-09-03T00:00:00.000Z',
          source_completed_at: '2026-09-03T00:00:01.000Z',
          check_version: 'check-1',
          producer_kind: 'manual',
        }), { internal: true, now: NOW });
        const replay = await services.appendTargetObservation(CTX, observation({
          nonce: 'newer',
          observed_at: '2026-09-04T00:00:00.000Z',
          source_completed_at: '2026-09-04T00:00:01.000Z',
          check_version: 'check-1',
          producer_kind: 'manual',
        }), { internal: true, now: NOW });
        assert.equal(replay.replayed, true);
        assert.equal(replay.id, newer.id);
        assert.equal(await countObservations(), 3);
        let current = await services.getCurrentFamilyState(CTX, { target_id: APP, family: 'waf' });
        assert.equal(current.items[0].last_successful.id, newer.id);
        assert.equal(current.items[0].fresh_negative, false);
        assert.equal(current.items[0].provider_loss, false);
        const conflict = await services.appendTargetObservation(CTX, observation({
          nonce: 'newer',
          outcome: 'not_detected',
          check_version: 'check-1',
          producer_kind: 'manual',
        }), { internal: true, now: NOW });
        assert.equal(conflict.status, 409);
        assert.equal(await countObservations(), 3);

        const changed = await services.appendTargetObservation(CTX, observation({
          nonce: 'version-2',
          observed_at: '2026-09-05T00:00:00.000Z',
          source_completed_at: '2026-09-05T00:00:01.000Z',
          check_version: 'check-2',
          producer_kind: 'manual',
        }), { internal: true, now: NOW });
        const comparison = services.assessComparability(newer, changed);
        assert.equal(comparison.comparable, false);
        assert.equal(comparison.reason, 'check_version_changed');
        assert.equal(comparison.direction, null);
        const missingVersion = await services.appendTargetObservation(CTX, observation({
          nonce: 'no-version',
          observed_at: '2026-09-05T00:00:02.000Z',
          source_completed_at: '2026-09-05T00:00:03.000Z',
        }), { now: NOW });
        assert.equal(services.assessComparability(newer, missingVersion).reason, 'missing_version');
        const timeout = await services.appendTargetObservation(CTX, observation({
          nonce: 'timeout',
          outcome: 'timeout',
          observed_at: '2026-09-06T00:00:00.000Z',
          source_completed_at: '2026-09-06T00:00:01.000Z',
          provenance: { status: 'timeout' },
        }), { now: NOW });
        current = await services.getCurrentFamilyState(CTX, { target_id: APP, family: 'waf' });
        assert.equal(current.items[0].last_successful.id, missingVersion.id);
        assert.equal(current.items[0].last_successful.outcome, 'detected');
        assert.equal(current.items[0].latest_failed_attempt.id, timeout.id);
        assert.equal(current.items[0].fresh_negative, false);
        assert.equal(current.items[0].provider_loss, false);
        assert.equal(services.assessComparability(changed, timeout).reason, 'transport_failure');

        const beforeCount = await countObservations();
        assert.equal((await services.appendTargetObservation(CTX, observation({
          nonce: 'too-early',
          observed_at: '2026-08-01T00:00:00.000Z',
        }), { now: NOW })).error, 'before_declaration');
        assert.equal((await services.appendTargetObservation(CTX, observation({
          nonce: 'too-late',
          observed_at: '2026-10-04T12:03:00.000Z',
          source_completed_at: '2026-10-04T12:03:00.000Z',
        }), { now: NOW })).error, 'future_timestamp');
        assert.equal(await countObservations(), beforeCount);

        const redacted = await services.appendTargetObservation(CTX, observation({
          nonce: 'redact',
          family: 'cdn',
          provenance: { provider: 'cloudfront', cookie: 'sid=1', authorization: 'Bearer secret', ok: true },
        }), { now: NOW });
        assert.deepEqual(redacted.provenance, { provider: 'cloudfront', ok: true });
        const storedProvenance = await ownerPool.query(
          'SELECT provenance_json FROM target_observations WHERE id = $1',
          [redacted.id],
        );
        assert.equal(JSON.stringify(storedProvenance.rows[0].provenance_json).includes('cookie'), false);
        assert.equal(JSON.stringify(storedProvenance.rows[0].provenance_json).includes('authorization'), false);

        const ties = [];
        for (const sourceId of ['src-a', 'src-b', 'src-c']) {
          ties.push(await services.appendTargetObservation(CTX, observation({
            nonce: sourceId,
            family: 'dns',
            source_id: sourceId,
            observed_at: '2026-09-07T00:00:00.250Z',
            source_completed_at: sourceId === 'src-a' ? null : '2026-09-07T00:00:01.000Z',
            provenance: { status: 'detected', slot: sourceId },
          }), { now: NOW }));
        }
        const firstPage = await services.listTargetObservations(CTX, { target_id: APP, family: 'dns', limit: 2 });
        assert.equal(firstPage.items.length, 2);
        assert.match(firstPage.items[0].observed_at, /\.\d{6}Z$/);
        assert.equal(firstPage.next_cursor != null, true);
        const secondPage = await services.listTargetObservations(CTX, {
          target_id: APP,
          family: 'dns',
          limit: 2,
          cursor: firstPage.next_cursor,
        });
        const seen = [...firstPage.items, ...secondPage.items];
        assert.equal(new Set(seen.map((row) => row.id)).size, 3);
        const sorted = [...seen].sort((left, right) => compareObservationOrder(right, left));
        assert.deepEqual(seen.map((row) => row.id), sorted.map((row) => row.id));
        assert.equal((await services.listTargetObservations(CTX, { cursor: '@@@' })).status, 400);
        assert.equal(older.id !== newer.id, true);

        const microRows = [];
        for (const [nonce, micro] of [['micro-early', '123001'], ['micro-late', '123999']]) {
          microRows.push(await services.appendTargetObservation(CTX, observation({
            nonce,
            family: 'cloud',
            observed_at: `2026-09-08T00:00:00.${micro}Z`,
            source_completed_at: `2026-09-08T00:00:01.${micro}Z`,
          }), { now: NOW }));
        }
        assert.equal(microRows[0].observed_at, '2026-09-08T00:00:00.123001Z');
        assert.equal(microRows[1].observed_at, '2026-09-08T00:00:00.123999Z');
        const microFirst = await services.listTargetObservations(CTX, { target_id: APP, family: 'cloud', limit: 1 });
        assert.equal(microFirst.items[0].id, microRows[1].id);
        assert.match(microFirst.items[0].observed_at, /\.123999Z$/);
        const microSecond = await services.listTargetObservations(CTX, {
          target_id: APP,
          family: 'cloud',
          cursor: microFirst.next_cursor,
        });
        const microSeen = [...microFirst.items, ...microSecond.items];
        assert.deepEqual(microSeen.map((row) => row.id), microRows.map((row) => row.id).reverse());
        const microSorted = [...microSeen].sort((left, right) => compareObservationOrder(right, left));
        assert.deepEqual(microSeen.map((row) => row.id), microSorted.map((row) => row.id));

        const foreign = await services.createOriginBinding(CTX, {
          protected_target_id: FOREIGN,
          origin_target_id: ORIGIN,
        }, { now: NOW });
        assert.equal(foreign.error, 'unknown_target');
        assert.equal(JSON.stringify(foreign).includes('foreign.example'), false);
        assert.equal((await services.createOriginBinding(CTX, {
          protected_target_id: APP,
          origin_target_id: UNPROVEN,
        }, { now: NOW })).error, 'ownership_not_verified');
        assert.equal((await services.createOriginBinding(CTX, {
          protected_target_id: APP,
          origin_target_id: AGENT,
        }, { now: NOW })).ownership_state, 'agent_verified');
        const downgraded = await services.createOriginBinding(CTX, {
          protected_target_id: APP,
          origin_target_id: PROVIDER,
        }, { now: NOW });
        assert.equal(downgraded.error, 'ownership_not_verified');
        assert.equal(downgraded.ownership_state, 'pending');
        const auditsBefore = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query(`SELECT count(*)::int AS n FROM audit_logs WHERE action = 'origin_binding.created'`);
          return rows[0].n;
        });
        const binding = await services.createOriginBinding(CTX, {
          protected_target_id: APP,
          origin_target_id: ORIGIN,
        }, { now: new Date('2026-09-10T00:00:00.000Z') });
        assert.equal(binding.currently_authorized, true);
        assert.equal(binding.host, 'app.example.test');
        assert.equal(binding.sni, 'app.example.test');
        assert.equal(binding.port, 443);
        assert.equal(binding.path, '/checkout');
        assert.equal(binding.assurance, 'none');
        assert.equal(binding.lockdown, 'not_tested');
        assert.equal(binding.relation, 'declared_binding');
        assert.equal(binding.capacity_assurance, false);
        const auditsAfter = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query(`SELECT count(*)::int AS n FROM audit_logs WHERE action = 'origin_binding.created'`);
          return rows[0].n;
        });
        assert.equal(auditsAfter, auditsBefore + 1);
        assert.equal((await services.getOriginBinding({ ...CTX, role: 'viewer' }, binding.id)).id, binding.id);
        const auditsRead = await withTenantContext(appPool, TENANT, async (client) => {
          const { rows } = await client.query(`SELECT count(*)::int AS n FROM audit_logs WHERE action LIKE 'origin_binding.%'`);
          return rows[0].n;
        });
        assert.equal(auditsRead, auditsAfter);
        const replayedCreate = await services.createOriginBinding(CTX, {
          protected_target_id: APP,
          origin_target_id: ORIGIN,
        }, { now: NOW });
        assert.equal(replayedCreate.replayed, true);
        assert.equal(replayedCreate.id, binding.id);
        assert.equal(replayedCreate.currently_authorized, true);
        // Same active pair: the identical stored scope replays, a different
        // requested scope is a 409 scope_conflict, and no second row appears.
        const repo = createTargetHistoryRepository(appPool);
        const bindingRecord = {
          tenant_id: TENANT,
          protected_target_id: binding.protected_target_id,
          protected_target_group_id: binding.protected_target_group_id,
          origin_target_id: binding.origin_target_id,
          origin_target_group_id: binding.origin_target_group_id,
          host: binding.host,
          sni: binding.sni,
          port: binding.port,
          path: binding.path,
          created_by: CTX.userId,
          created_at: '2026-09-15T00:00:00.000Z',
        };
        const identicalBinding = await repo.insertBinding(CTX, { ...bindingRecord });
        assert.equal(identicalBinding.replayed, true);
        assert.equal(identicalBinding.id, binding.id);
        const conflictingPort = await repo.insertBinding(CTX, { ...bindingRecord, port: binding.port === 443 ? 8443 : 443 });
        assert.equal(conflictingPort.error, 'scope_conflict');
        assert.equal(conflictingPort.status, 409);
        const conflictingPath = await repo.insertBinding(CTX, { ...bindingRecord, path: null });
        assert.equal(conflictingPath.error, 'scope_conflict');
        assert.equal(conflictingPath.status, 409);
        const bindingRows = await ownerPool.query(
          `SELECT count(*)::int AS n FROM origin_bindings
           WHERE tenant_id = $1 AND protected_target_id = $2 AND origin_target_id = $3 AND status = 'active'`,
          [TENANT, binding.protected_target_id, binding.origin_target_id],
        );
        assert.equal(bindingRows.rows[0].n, 1);
        const unbound = await services.appendTargetObservation(CTX, observation({
          target_id: ORIGIN,
          family: 'origin_hosting',
          nonce: 'unbound-origin',
          outcome: 'reachable',
          observed_at: '2026-09-02T00:00:00.000Z',
          source_completed_at: '2026-09-02T00:00:01.000Z',
        }), { now: NOW });
        assert.equal(unbound.origin_binding_id, null);
        assert.equal((await services.assessOriginReachability(CTX, binding.id)).reason, 'no_bound_finalized_evidence');
        const predates = await services.appendTargetObservation(CTX, observation({
          target_id: ORIGIN,
          family: 'origin_hosting',
          nonce: 'predates',
          outcome: 'reachable',
          origin_binding_id: binding.id,
          observed_at: '2026-09-02T00:00:00.000Z',
          source_completed_at: '2026-09-02T00:00:01.000Z',
        }), { now: NOW });
        assert.equal(predates.error, 'observation_predates_binding');
        const bound = await services.appendTargetObservation(CTX, observation({
          target_id: ORIGIN,
          family: 'origin_hosting',
          check_id: 'origin.host_sni_bypass.safe',
          nonce: 'bound-origin',
          outcome: 'reachable',
          origin_binding_id: binding.id,
          producer_kind: 'signed_probe',
          observed_at: '2026-09-11T00:00:00.000Z',
          source_completed_at: '2026-09-11T00:00:01.000Z',
        }), { internal: true, now: NOW });
        const reach = await services.assessOriginReachability(CTX, binding.id);
        assert.equal(reach.status, 'reachable');
        assert.equal(reach.lockdown, 'not_established');
        assert.equal(reach.capacity_assurance, false);
        assert.equal(reach.observation_id, bound.id);
        const stillUnbound = await ownerPool.query(
          'SELECT origin_binding_id FROM target_observations WHERE id = $1',
          [unbound.id],
        );
        assert.equal(stillUnbound.rows[0].origin_binding_id, null);

        assert.equal((await services.registerRetestLineage(CTX, {
          finding_id: 'fnd_a',
          test_run_id: 'run_other_target',
          intent: 'retest',
        })).error, 'pair_mismatch');
        assert.equal((await services.registerRetestLineage(CTX, {
          finding_id: 'fnd_a',
          test_run_id: 'run_other_check',
          intent: 'retest',
        })).error, 'pair_mismatch');
        const registered = await services.registerRetestLineage(CTX, {
          finding_id: 'fnd_a',
          test_run_id: 'run_retest',
          intent: 'retest',
        }, { now: NOW });
        assert.equal(registered.sibling_closure, false);
        assert.equal((await services.registerRetestLineage(CTX, {
          finding_id: 'fnd_a',
          test_run_id: 'run_retest',
          intent: 'retest',
        })).replayed, true);
        const lineage = await services.listFindingLineage(CTX, 'fnd_a');
        assert.equal(lineage.closed_at, null);
        assert.equal(lineage.sibling_closure, false);
        assert.equal(lineage.siblings[0].closed_at, null);
        assert.deepEqual(lineage.retests.map((row) => row.test_run_id), ['run_retest']);
        assert.deepEqual(lineage.later_same_pair.map((row) => row.test_run_id), ['run_later']);
        assert.equal(lineage.later_same_pair[0].relation, 'later_same_pair');
        assert.equal(lineage.later_same_pair[0].can_advance_remediation, false);
        const closed = await ownerPool.query(
          `SELECT closed_at FROM findings WHERE id = 'fnd_a' OR id = 'fnd_sib'`,
        );
        assert.equal(closed.rows.every((row) => row.closed_at == null), true);
        const stamped = await ownerPool.query(
          `SELECT retest_of_finding_id FROM test_runs WHERE id = 'run_retest'`,
        );
        assert.equal(stamped.rows[0].retest_of_finding_id, null);
      } finally {
        await closePgPool(appPool);
      }
    });
  });
});
