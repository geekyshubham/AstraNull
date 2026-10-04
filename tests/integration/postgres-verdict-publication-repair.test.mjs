import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_verdict_repair';
const ENVIRONMENT = 'env_verdict_repair';
const GROUP = 'tg_verdict_repair';
const AGENT = 'agt_verdict_repair';
const CHECK = 'origin.direct_bypass.safe';
const CTX = { tenantId: TENANT, userId: 'verdict-repair-test', role: 'system' };

const TARGETS = Object.freeze({
  archive: 'tgt_repair_archive',
  closed: 'tgt_repair_closed',
  oldFirst: 'tgt_repair_old_first',
  newFirst: 'tgt_repair_new_first',
  mismatch: 'tgt_repair_mismatch',
  mismatchOther: 'tgt_repair_mismatch_other',
});

function runId(name) {
  return `run_repair_${name}`;
}

function verdictId(name) {
  return `verdict_repair_${name}`;
}

const RUNS = Object.freeze([
  { name: 'archive', target: TARGETS.archive, createdAt: '2026-01-01T00:00:00.000Z' },
  { name: 'closed_old', target: TARGETS.closed, createdAt: '2026-01-01T00:00:00.000Z' },
  { name: 'closed_new', target: TARGETS.closed, createdAt: '2026-01-02T00:00:00.000Z' },
  { name: 'old_first_old', target: TARGETS.oldFirst, createdAt: '2026-01-01T00:00:00.000Z' },
  { name: 'old_first_new', target: TARGETS.oldFirst, createdAt: '2026-01-02T00:00:00.000Z' },
  { name: 'new_first_old', target: TARGETS.newFirst, createdAt: '2026-01-01T00:00:00.000Z' },
  { name: 'new_first_new', target: TARGETS.newFirst, createdAt: '2026-01-02T00:00:00.000Z' },
  { name: 'mismatch', target: TARGETS.mismatch, createdAt: '2026-01-01T00:00:00.000Z' },
]);

async function seed(pool) {
  await withTenantContext(pool, TENANT, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'verdict repair tenant')`, [TENANT]);
    await client.query(
      `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'prod')`,
      [ENVIRONMENT, TENANT],
    );
    await client.query(
      `INSERT INTO target_groups (
         id, tenant_id, environment_id, name, validation_mode
       ) VALUES ($1, $2, $3, 'archived verdict repair', 'agent_assisted')`,
      [GROUP, TENANT, ENVIRONMENT],
    );

    let octet = 10;
    for (const target of Object.values(TARGETS)) {
      const value = `203.0.113.${octet}`;
      octet += 1;
      await client.query(
        `INSERT INTO targets (
           id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior
         ) VALUES ($1, $2, $3, 'ip', $4, $4, 'must_block_before_origin')`,
        [target, TENANT, GROUP, value],
      );
    }
    await client.query(
      `INSERT INTO agents (
         id, tenant_id, target_group_id, status, last_token_validation_status
       ) VALUES ($1, $2, $3, 'online', 'valid')`,
      [AGENT, TENANT, GROUP],
    );

    for (const definition of RUNS) {
      const run = runId(definition.name);
      const nonce = `nonce_${definition.name}`;
      await client.query(
        `INSERT INTO test_runs (
           id, tenant_id, target_group_id, target_id, check_id, status,
           probe_external_result, awaiting_external_probe, remediation_template,
           safety_constraints, correlation_json, collection_deadline_at,
           started_at, completed_at, created_at
         ) VALUES (
           $1, $2, $3, $4, $5, 'verdicted',
           'connected', FALSE, 'block_origin',
           '{"max_events":50}'::jsonb,
           jsonb_build_object('nonce_hash', $6::text, 'window_ms', 120000),
           $7::timestamptz, $7::timestamptz, $7::timestamptz, $7::timestamptz
         )`,
        [run, TENANT, GROUP, definition.target, CHECK, nonce, definition.createdAt],
      );
      await client.query(
        `INSERT INTO events (
           id, tenant_id, test_run_id, target_id, check_id, agent_id, source,
           signal_type, producer_kind, nonce_hash, timestamp, metadata_json
         ) VALUES
           ($1, $2, $3, $4, $5, NULL, 'probe_worker', 'probe_result',
            'signed_probe', $6, $7::timestamptz, '{"external_result":"connected"}'::jsonb),
           ($8, $2, $3, $4, $5, $9, 'agent', 'agent_observation',
            'authenticated_agent', $6, $7::timestamptz, '{}'::jsonb)`,
        [
          `evt_probe_${definition.name}`, TENANT, run, definition.target, CHECK, nonce,
          definition.createdAt, `evt_obs_${definition.name}`, AGENT,
        ],
      );
      await client.query(
        `INSERT INTO verdicts (
           id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
           placement_confidence_json, explanation, evidence_ids, created_at
         ) VALUES (
           $1, $2, $3, $4, $5, 'bypassable', 'high',
           '{"level":"high","status":"supported"}'::jsonb,
           $6, $7::text[], $8::timestamptz
         )`,
        [
          verdictId(definition.name), TENANT, run, definition.target, CHECK,
          `Durable ${definition.name} verdict`,
          [`evt_probe_${definition.name}`, `evt_obs_${definition.name}`],
          definition.createdAt,
        ],
      );
    }

    // The mismatch is durable and references a real target, but not the target bound to its run.
    await client.query(
      `UPDATE verdicts SET target_id = $1 WHERE tenant_id = $2 AND id = $3`,
      [TARGETS.mismatchOther, TENANT, verdictId('mismatch')],
    );

    await client.query(
      `INSERT INTO findings (
         id, tenant_id, target_group_id, target_id, test_run_id, check_id,
         title, severity, status, evidence_ids, notes, remediation_template,
         verdict_id, last_verdict_id, created_at, updated_at
       ) VALUES (
         'finding_repair_closed_new', $1, $2, $3, $4, $5,
         'newer closed finding', 'high', 'resolved', $6::text[], 'newer durable state',
         'block_origin', $7, $7, '2026-01-02T00:00:00.000Z', '2026-01-03T00:00:00.000Z'
       )`,
      [
        TENANT, GROUP, TARGETS.closed, runId('closed_new'), CHECK,
        ['evt_probe_closed_new', 'evt_obs_closed_new'], verdictId('closed_new'),
      ],
    );

    await client.query(
      `UPDATE targets SET deleted_at = '2026-01-10T00:00:00.000Z'
       WHERE tenant_id = $1 AND target_group_id = $2`,
      [TENANT, GROUP],
    );
    await client.query(
      `UPDATE target_groups SET archived_at = '2026-01-10T00:00:00.000Z'
       WHERE tenant_id = $1 AND id = $2`,
      [TENANT, GROUP],
    );
  });
}

function buildServices(pool) {
  let catalogReads = 0;
  const coreCatalog = createCoreCatalogRepository(pool);
  coreCatalog.getTargetGroup = async () => {
    catalogReads += 1;
    throw new Error('terminal repair consulted the active catalog');
  };
  return {
    services: createPostgresValidationServices({
      validationEvidence: createValidationEvidenceRepository(pool),
      audit: createAuditRepository(pool),
      coreCatalog,
      probeJobs: createProbeJobRepository(pool),
      killSwitch: createKillSwitchRepository(pool),
    }),
    getCatalogReads: () => catalogReads,
  };
}

async function readTuple(pool, target, checkId = CHECK) {
  return withTenantContext(pool, TENANT, async (client) => {
    const findings = await client.query(
      `SELECT id, status, test_run_id, verdict_id, last_verdict_id, evidence_ids
       FROM findings
       WHERE tenant_id = $1 AND target_group_id = $2 AND target_id = $3 AND check_id = $4
       ORDER BY created_at, id`,
      [TENANT, GROUP, target, checkId],
    );
    const audits = await client.query(
      `SELECT action, resource_type, resource_id, metadata_json
       FROM audit_logs
       WHERE tenant_id = $1
         AND (
           (resource_type = 'test_run' AND resource_id LIKE 'run_repair_%')
           OR (resource_type = 'finding' AND metadata_json->>'test_run_id' LIKE 'run_repair_%')
         )
       ORDER BY sequence, id`,
      [TENANT],
    );
    return { findings: findings.rows, audits: audits.rows };
  });
}

describe('postgres terminal verdict publication repair', () => {
  it('publishes the version 2 DNSKEY absence finding once with its original evidence and audit', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) { t.skip(availability.reason); return; }
    await withEphemeralPostgres(async pool => {
      await seed(pool);
      await withTenantContext(pool, TENANT, async client => {
        await client.query(`UPDATE test_runs SET check_id = 'dns.dnssec_expensive_query.safe', check_version = '2.0.0' WHERE id = $1`, [runId('archive')]);
        await client.query(`UPDATE events SET check_id = 'dns.dnssec_expensive_query.safe' WHERE test_run_id = $1`, [runId('archive')]);
        await client.query(`UPDATE verdicts SET check_id = 'dns.dnssec_expensive_query.safe', verdict = 'exposed', confidence = 'external_only', explanation = 'An authoritative response contained no DNSKEY records.' WHERE id = $1`, [verdictId('archive')]);
      });
      const { services } = buildServices(pool);
      await services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId('archive'));
      await services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId('archive'));
      const state = await readTuple(pool, TARGETS.archive, 'dns.dnssec_expensive_query.safe');
      assert.equal(state.findings.length, 1);
      assert.equal(state.findings[0].last_verdict_id, verdictId('archive'));
      assert.ok(state.audits.some(row => row.action === 'finding.created'));
      await withTenantContext(pool, TENANT, async client => {
        await client.query(`UPDATE test_runs SET check_id = 'dns.dnssec_expensive_query.safe', check_version = '1.0.0' WHERE id = $1`, [runId('old_first_old')]);
        await client.query(`UPDATE verdicts SET check_id = 'dns.dnssec_expensive_query.safe', verdict = 'exposed' WHERE id = $1`, [verdictId('old_first_old')]);
      });
      await services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId('old_first_old'));
      assert.equal((await readTuple(pool, TARGETS.oldFirst, 'dns.dnssec_expensive_query.safe')).findings.length, 0);
    });
  });

  it('is chronology-safe, concurrent, and archival-safe on durable state', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seed(pool);

      const archived = buildServices(pool);
      const first = await archived.services.testRuns.maybeFinalizeRunAfterProbeIngest(
        CTX,
        runId('archive'),
      );
      const second = await archived.services.testRuns.maybeFinalizeRunAfterProbeIngest(
        CTX,
        runId('archive'),
      );
      assert.equal(first.id, verdictId('archive'));
      assert.equal(second.id, verdictId('archive'));
      assert.equal(archived.getCatalogReads(), 0);

      let archiveState = await readTuple(pool, TARGETS.archive);
      assert.equal(archiveState.findings.length, 1);
      assert.equal(archiveState.findings[0].test_run_id, runId('archive'));
      assert.equal(archiveState.findings[0].last_verdict_id, verdictId('archive'));
      assert.deepEqual(
        archiveState.findings[0].evidence_ids,
        ['evt_probe_archive', 'evt_obs_archive'],
      );
      assert.equal(
        archiveState.audits.filter((audit) =>
          audit.resource_type === 'test_run' && audit.resource_id === runId('archive')).length,
        1,
      );
      assert.equal(
        archiveState.audits.filter((audit) =>
          audit.resource_type === 'finding'
            && audit.metadata_json.verdict_id === verdictId('archive')).length,
        1,
      );

      await withTenantContext(pool, TENANT, (client) => client.query(
        `UPDATE findings SET status = 'resolved', updated_at = now()
         WHERE tenant_id = $1 AND id = $2`,
        [TENANT, archiveState.findings[0].id],
      ));
      await archived.services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId('archive'));
      archiveState = await readTuple(pool, TARGETS.archive);
      assert.equal(archiveState.findings.length, 1);
      assert.equal(archiveState.findings[0].status, 'resolved');
      assert.equal(archived.getCatalogReads(), 0);

      const closed = buildServices(pool);
      await closed.services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId('closed_old'));
      const closedState = await readTuple(pool, TARGETS.closed);
      assert.equal(closedState.findings.length, 1);
      assert.equal(closedState.findings[0].status, 'resolved');
      assert.equal(closedState.findings[0].verdict_id, verdictId('closed_new'));
      assert.equal(closedState.findings[0].last_verdict_id, verdictId('closed_new'));
      assert.equal(
        closedState.audits.some((audit) =>
          audit.resource_type === 'finding'
            && audit.metadata_json.verdict_id === verdictId('closed_old')),
        false,
      );
      assert.equal(closed.getCatalogReads(), 0);

      for (const order of ['old_first', 'new_first']) {
        const old = buildServices(pool);
        const newer = buildServices(pool);
        const calls = order === 'old_first'
          ? [
              old.services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId(`${order}_old`)),
              newer.services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId(`${order}_new`)),
            ]
          : [
              newer.services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId(`${order}_new`)),
              old.services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId(`${order}_old`)),
            ];
        await Promise.all(calls);

        const target = order === 'old_first' ? TARGETS.oldFirst : TARGETS.newFirst;
        const state = await readTuple(pool, target);
        assert.equal(state.findings.length, 1, `${order} must not duplicate the finding`);
        assert.equal(state.findings[0].status, 'open');
        assert.equal(state.findings[0].test_run_id, runId(`${order}_new`));
        assert.equal(state.findings[0].last_verdict_id, verdictId(`${order}_new`));
        assert.equal(old.getCatalogReads() + newer.getCatalogReads(), 0);

        await old.services.testRuns.maybeFinalizeRunAfterProbeIngest(CTX, runId(`${order}_old`));
        const replayed = await readTuple(pool, target);
        assert.equal(replayed.findings.length, 1);
        assert.equal(replayed.findings[0].last_verdict_id, verdictId(`${order}_new`));
      }

      const mismatch = buildServices(pool);
      await assert.rejects(
        () => mismatch.services.testRuns.maybeFinalizeRunAfterProbeIngest(
          CTX,
          runId('mismatch'),
        ),
        /verdict_run_binding_mismatch:run_repair_mismatch/,
      );
      const mismatchState = await readTuple(pool, TARGETS.mismatch);
      assert.equal(mismatchState.findings.length, 0);
      assert.equal(
        mismatchState.audits.some((audit) => audit.resource_id === runId('mismatch')),
        false,
      );
      assert.equal(mismatch.getCatalogReads(), 0);
    }, availability.env ?? process.env);
  });
});


describe('postgres terminal verdict repair with a single pool client', () => {
  it('orders concurrent sweepers and completes run/finding/audit repair without a second checkout', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    const maxOneEnv = {
      ...(availability.env ?? process.env),
      ASTRANULL_PG_POOL_MAX: '1',
      ASTRANULL_PG_CONNECTION_TIMEOUT_MS: '1000',
    };
    await withEphemeralPostgres(async (pool) => {
      assert.equal(pool.options.max, 1, 'regression must execute against a true max=1 pool');
      await seed(pool);

      // Simulate the historical partial terminal state: the immutable verdict committed, but
      // the run transition, finding and audit publication did not. The expired-run sweeper is
      // responsible for completing this repair transactionally.
      await withTenantContext(pool, TENANT, (client) => client.query(
        `UPDATE test_runs
         SET status = 'collecting', completed_at = NULL
         WHERE tenant_id = $1 AND id = $2`,
        [TENANT, runId('archive')],
      ));

      const sweeperA = buildServices(pool);
      const sweeperB = buildServices(pool);
      const [resultA, resultB] = await Promise.all([
        sweeperA.services.testRuns.sweepExpiredCollectingRuns(CTX),
        sweeperB.services.testRuns.sweepExpiredCollectingRuns(CTX),
      ]);

      assert.deepEqual(resultA.errors, []);
      assert.deepEqual(resultB.errors, []);
      assert.equal(resultA.finalized + resultB.finalized, 1);
      assert.equal(resultA.skipped_not_finalizable + resultB.skipped_not_finalizable, 1);
      assert.equal(sweeperA.getCatalogReads() + sweeperB.getCatalogReads(), 0);

      const repaired = await readTuple(pool, TARGETS.archive);
      assert.equal(repaired.findings.length, 1);
      assert.equal(repaired.findings[0].test_run_id, runId('archive'));
      assert.equal(repaired.findings[0].last_verdict_id, verdictId('archive'));
      assert.equal(
        repaired.audits.filter((audit) =>
          audit.resource_type === 'test_run'
            && audit.resource_id === runId('archive')
            && audit.action === 'verdict.published').length,
        1,
      );
      assert.equal(
        repaired.audits.filter((audit) =>
          audit.resource_type === 'finding'
            && audit.metadata_json.verdict_id === verdictId('archive')).length,
        1,
      );
      const run = await withTenantContext(pool, TENANT, async (client) => {
        const { rows } = await client.query(
          `SELECT status, completed_at
           FROM test_runs
           WHERE tenant_id = $1 AND id = $2`,
          [TENANT, runId('archive')],
        );
        return rows[0];
      });
      assert.equal(run.status, 'verdicted');
      assert.ok(run.completed_at);
    }, maxOneEnv);
  });
});
