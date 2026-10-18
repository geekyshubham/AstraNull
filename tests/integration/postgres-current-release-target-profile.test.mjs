import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { deriveAssuranceScope } from '../../src/lib/assuranceScope.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { approvedScenarioVersion, deriveRunEvidenceStamp } from '../../src/lib/checkDefinitionVersion.mjs';
import { WAF_GRADING_VERSION, SIGNATURE_CORPUS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import { buildSignedProbeJobRecord } from '../../src/lib/probeJobs.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresProbeJobServices } from '../../src/persistence/postgres/probeJobServiceAdapters.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createPgPool, closePgPool } from '../../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { projectReadiness } from '../../src/lib/readinessProjection.mjs';
import { databaseUrlWithDatabase } from '../helpers/pg-harness.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const TENANT = 'ten_target_profile';
const OTHER = 'ten_target_profile_other';
const ENV = 'env_target_profile';
const GROUP = 'tg_target_profile';
const TARGET = 'tgt_target_profile';
const INHERITED = 'tgt_target_profile_inherited';
const CTX = { tenantId: TENANT, userId: 'usr_target_profile', role: 'engineer' };

async function seed(pool) {
  await pool.query('INSERT INTO tenants (id, name) VALUES ($1, $1), ($2, $2)', [TENANT, OTHER]);
  await pool.query(
    'INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, $3)',
    [ENV, TENANT, 'prod'],
  );
  await pool.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name)
     VALUES ($1, $2, $3, 'Profile group')`,
    [GROUP, TENANT, ENV],
  );
  await pool.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
     VALUES ($1, $2, $3, 'fqdn', 'profile.example.test', 'profile.example.test'),
            ($4, $2, $3, 'fqdn', 'inherited.example.test', 'inherited.example.test')`,
    [TARGET, TENANT, GROUP, INHERITED],
  );
  await pool.query(
    `INSERT INTO test_runs (
       id, tenant_id, target_group_id, target_id, check_id, status, started_at, completed_at
     ) VALUES (
       'run_target_profile', $1, $2, $3, 'waf.fingerprint.safe', 'completed',
       '2026-10-03T00:00:00.000Z', '2026-10-03T00:01:00.000Z'
     )`,
    [TENANT, GROUP, TARGET],
  );
  await pool.query(
    `INSERT INTO target_edge_detections (
       id, tenant_id, target_group_id, target_id, test_run_id,
       status, waf_status, waf_vendor, cdn_status, confidence, evidence_json, observed_at
     ) VALUES (
       'edge_target_profile', $1, $2, $3, 'run_target_profile',
       'detected', 'detected', 'cloudflare', 'detected', 0.8,
       $4::jsonb, '2026-10-03T00:01:00.000Z'
     )`,
    [TENANT, GROUP, TARGET, JSON.stringify({
      cloud: { provider: 'aws', status: 'detected', confidence: 0, observed_at: '2026-10-03T00:01:00.000Z' },
      cname_chain: ['edge.example.net'],
    })],
  );
  await pool.query(
    `INSERT INTO findings (
       id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status
     ) VALUES
       ('fnd_profile_owned', $1, $2, $3, 'run_target_profile', 'waf.fingerprint.safe', 'Owned', 'low', 'open'),
       ('fnd_profile_open', $1, $2, $3, 'run_target_profile', 'origin.direct_bypass.safe', 'Unassigned', 'low', 'open')`,
    [TENANT, GROUP, TARGET],
  );
  await pool.query(
    `INSERT INTO finding_remediations (
       id, tenant_id, finding_id, action_slug, owner_group, description, steps, audit_entry_id
     ) VALUES (
       'rem_profile_owned', $1, 'fnd_profile_owned', 'review', 'app-owners',
       'Recorded owner', ARRAY['review']::text[], 'audit_profile_seed'
     )`,
    [TENANT],
  );
}

async function stampScope(pool, runId) {
  const target = (await pool.query('SELECT * FROM targets WHERE tenant_id = $1 AND id = $2', [TENANT, TARGET])).rows[0];
  const group = (await pool.query('SELECT * FROM target_groups WHERE tenant_id = $1 AND id = $2', [TENANT, GROUP])).rows[0];
  await pool.query('UPDATE test_runs SET safety_constraints = $1::jsonb WHERE tenant_id = $2 AND id = $3',
    [JSON.stringify({ assurance_scope: deriveAssuranceScope({ target, targetGroup: group }) }), TENANT, runId]);
}

describe('postgres current-release target profile', () => {
  it('publishes only the accepted reserved signed result beside activity and resolves live coverage under app-role RLS', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) { t.skip(availability.reason); return; }
    const databaseUrl = new URL(availability.env.ASTRANULL_ADMIN_DATABASE_URL ?? availability.env.ASTRANULL_DATABASE_URL);
    assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(databaseUrl.hostname), 'proof fixture must use isolated loopback PostgreSQL');
    await withEphemeralPostgres(async (owner, env) => {
      await seed(owner);
      const now = new Date();
      const ctx = { ...CTX, workerId: 'worker_proof' };
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const stamp = deriveRunEvidenceStamp(check, undefined, { probeMode: 'signed-worker', scenarioVersion: approvedScenarioVersion(check) });
      await owner.query(`UPDATE targets SET expected_behavior = 'block_at_edge' WHERE id = $1`, [TARGET]);
      await owner.query(`UPDATE test_runs SET check_id = $1, check_version = $2, scenario_version = $3,
        provenance_json = $4::jsonb, producer_kind = 'signed_probe', status = 'running', completed_at = NULL,
        started_at = $5, created_at = $5 WHERE id = 'run_target_profile'`,
      [check.check_id, stamp.check_version, stamp.scenario_version, JSON.stringify(stamp.provenance_json), now]);
      await stampScope(owner, 'run_target_profile');
      await withTenantContext(owner, TENANT, (client) => client.query(`INSERT INTO target_verifications
        (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
        VALUES ('proof_publication', $1, $2, 'dns_verified', 'dns_txt', '{}', $3, 'usr_target_profile', 'audit_fixture')`, [TENANT, TARGET, now]));
      const url = new URL(databaseUrlWithDatabase(databaseUrl.toString(), env.databaseName));
      url.username = 'astranull_app'; url.password = 'astranull_app_local_dev';
      const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString() });
      try {
        const repositories = { audit: createAuditRepository(pool), coreCatalog: createCoreCatalogRepository(pool),
          validationEvidence: createValidationEvidenceRepository(pool), probeJobs: createProbeJobRepository(pool), killSwitch: createKillSwitchRepository(pool) };
        const jobs = createPostgresProbeJobServices(repositories);
        const validation = createPostgresValidationServices(repositories);
        const run = await repositories.validationEvidence.getTestRun(ctx, 'run_target_profile');
        const target = (await owner.query('SELECT * FROM targets WHERE id = $1', [TARGET])).rows[0];
        const record = buildSignedProbeJobRecord({ run, check, target,
          ownershipBinding: { state: 'dns_verified', kind: 'dns_txt', transitioned_at: now.toISOString() },
          probeWorkerSecret: 'a'.repeat(64), now, newId: () => 'job_publication' });
        await repositories.probeJobs.createProbeJob(ctx, record);
        await owner.query(`UPDATE test_runs SET correlation_json = jsonb_build_object('nonce_hash', $1::text) WHERE id = 'run_target_profile'`, [record.nonce_hash]);
        const job = await repositories.probeJobs.claimPendingJobForWorker(ctx, record.id, ctx.workerId, now.toISOString());
        assert.equal((await jobs.reserveProbeExecution(ctx, job.id, { leased_at: job.leased_at })).authorized, true);
        const capture = { version: 'probe-capture.v1', recorded_count: 1, last_sequence: 1,
          dropped_count: 0, delivery_failures: 0, finalized_at: now.toISOString() };
        const activity = await jobs.ingestProbeActivity(ctx, job.id, { leased_at: job.leased_at, capture,
          items: [{ sequence: 1, at: now.toISOString(), stage: 'request_started', method: 'GET', url: 'https://profile.example.test/' }] });
        assert.equal(activity.accepted, 1, JSON.stringify(activity));
        const metadata = { classifier_version: 'marker-comparison-v5', comparison_complete: true,
          planned_marker_legs: 2, attempted_marker_legs: 2, completed_marker_legs: 2, graded_marker_legs: 2,
          ungraded_marker_legs: 0, missing_marker_legs: 0, permitted_baseline_health: 'healthy', trailing_control: { outcome: 'allowed' },
          enforcement: 'enforced', evidence_complete: true, observation_only: false, readiness_conclusion: true,
          grading_version: WAF_GRADING_VERSION, signature_corpus_version: SIGNATURE_CORPUS_VERSION };
        const accepted = await jobs.ingestProbeResult(ctx, job.id, { external_result: 'blocked', metadata,
          safety_attestation: { requests_sent: 6, probe_requests_sent: 4, destination_resolver_attempts: 2, total_operations: 6, duration_ms: 10 } });
        assert.equal(accepted.error, undefined, JSON.stringify(accepted));
        await validation.testRuns.maybeFinalizeRunAfterProbeIngest(ctx, run.id);
        const events = await repositories.validationEvidence.listRunEvents(ctx, run.id);
        const result = events.find((event) => event.signal_type === 'probe_result');
        const activityEvent = events.find((event) => event.signal_type === 'probe_activity');
        assert.ok(result); assert.ok(activityEvent);
        const verdict = await repositories.validationEvidence.getVerdictForRun(ctx, run.id);
        assert.deepEqual(verdict.evidence_ids, [result.id]);
        assert.ok(['protected', 'edge_protected'].includes(verdict.verdict), JSON.stringify(verdict));
        const portal = createPortalRevampRepository(pool);
        const pairFor = async () => (await portal.getTargetDetailBundle(ctx, TARGET, {})).coverage.pairs.find((pair) => pair.check_id === check.check_id);
        assert.equal((await pairFor()).live_external, true);
        const inputs = await repositories.validationEvidence.readReadinessInputs(ctx, { asOf: new Date() });
        assert.equal(projectReadiness({ ...inputs, tenantId: TENANT, catalog: [check] }).coverage.passed_count, 1);
        const custody = await repositories.validationEvidence.getVerdictForRun(ctx, run.id);
        await validation.testRuns.maybeFinalizeRunAfterProbeIngest(ctx, run.id);
        assert.deepEqual(await repositories.validationEvidence.getVerdictForRun(ctx, run.id), custody);
        assert.deepEqual(await repositories.validationEvidence.listRunEvents(ctx, run.id), events);
        // Negative controls deliberately corrupt only this disposable fixture's citations.
        for (const [ids, reason] of [[[], 'no_evidence'], [[result.id, activityEvent.id], 'invalid_or_unresolved_evidence'], [['missing'], 'invalid_or_unresolved_evidence']]) {
          await owner.query('UPDATE verdicts SET evidence_ids = $1::text[] WHERE id = $2', [ids, verdict.id]);
          const pair = await pairFor();
          assert.equal(pair.pair_reason, reason); assert.equal(pair.live_external, false);
          assert.equal(pair.retained.verdict, custody.verdict);
          const invalidInputs = await repositories.validationEvidence.readReadinessInputs(ctx, { asOf: new Date() });
          assert.equal(projectReadiness({ ...invalidInputs, tenantId: TENANT, catalog: [check] }).coverage.passed_count, 0);
        }
        assert.equal(await portal.getTargetDetailBundle({ ...ctx, tenantId: OTHER }, TARGET, {}), null);
      } finally { await closePgPool(pool); }
    }, availability.env);
  });
  it('keeps an unsupported nonce-bound marker attempt partial without inventing a complete comparison', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) { t.skip(availability.reason); return; }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const stamp = deriveRunEvidenceStamp(check, undefined, { probeMode: 'signed-worker', scenarioVersion: approvedScenarioVersion(check) });
      // Keep synthetic publications before the JS assessment cutoff: PostgreSQL's
      // microsecond now() can otherwise be later than a same-millisecond JS Date.
      await pool.query(
        `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, started_at, created_at, completed_at, check_version, scenario_version, producer_kind, probe_external_result, correlation_json)
         VALUES ('run_reason', $1, $2, $3, $4, 'verdicted', now() - interval '2 seconds', now() - interval '2 seconds', date_trunc('milliseconds', now() - interval '1 second'), $5, $6, 'signed_probe', 'error', '{"nonce_hash":"reason_nonce"}')`,
        [TENANT, GROUP, TARGET, check.check_id, stamp.check_version, stamp.scenario_version],
      );
      await stampScope(pool, 'run_reason');
      for (const [id, nonce, error] of [['evt_reason', 'reason_nonce', 'unsupported_target'], ['evt_wrong_nonce', 'wrong_nonce', 'ESERVFAIL']]) {
        await pool.query(
          `INSERT INTO events (id, tenant_id, test_run_id, signal_type, producer_kind, nonce_hash, timestamp, ingested_at, metadata_json)
           VALUES ($1, $2, 'run_reason', 'probe_result', 'signed_probe', $3,
             date_trunc('milliseconds', now() - interval '1 second'), date_trunc('milliseconds', now() - interval '1 second'), $4::jsonb)`,
          [id, TENANT, nonce, JSON.stringify({ error_class: error, grading_version: WAF_GRADING_VERSION, signature_corpus_version: SIGNATURE_CORPUS_VERSION })],
        );
      }
      await pool.query(`INSERT INTO verdicts (id, tenant_id, test_run_id, verdict, evidence_ids, created_at)
        VALUES ('verdict_reason', $1, 'run_reason', 'inconclusive', ARRAY['evt_reason'], date_trunc('milliseconds', now() - interval '1 second'))`, [TENANT]);
      const detail = await createPortalRevampRepository(pool).getTargetDetailBundle(CTX, TARGET, {});
      assert.equal(detail.coverage.inconclusive_count, 0);
      const pair = detail.coverage.pairs.find((row) => row.check_id === check.check_id);
      assert.equal(pair.state, 'partial', JSON.stringify(pair));
      assert.equal(pair.pair_reason, 'complete_marker_comparison_missing');
      assert.equal(pair.current_assurance, 'retest_required');
      assert.ok(detail.coverage.observation_only_count > 0);
    });
  });

  it('counts stored signed-run versions as live coverage without rewriting historical runs', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) { t.skip(availability.reason); return; }
    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const checkId = 'waf.sqli_managed_marker.safe';
      const check = getCheckById(checkId);
      const scenarioVersion = approvedScenarioVersion(check);
      await pool.query(`UPDATE test_runs SET check_id = $1, correlation_json = '{"nonce_hash":"profile_nonce"}',
        producer_kind = 'signed_probe', completed_at = date_trunc('milliseconds', now() - interval '1 second') WHERE id = 'run_target_profile'`, [checkId]);
      await pool.query(`INSERT INTO events (id, tenant_id, test_run_id, signal_type, producer_kind, nonce_hash, timestamp, ingested_at, metadata_json)
        VALUES ('evidence_profile_live', $1, 'run_target_profile', 'probe_result', 'signed_probe', 'profile_nonce',
          date_trunc('milliseconds', now() - interval '1 second'), date_trunc('milliseconds', now() - interval '1 second'), $2::jsonb)`,
        [TENANT, JSON.stringify({ classifier_version: 'marker-comparison-v5', comparison_complete: true,
          planned_marker_legs: 2, attempted_marker_legs: 2, completed_marker_legs: 2, graded_marker_legs: 2,
          ungraded_marker_legs: 0, missing_marker_legs: 0, trailing_control: { outcome: 'allowed' },
          permitted_baseline_health: 'healthy', enforcement: 'enforced', evidence_complete: true,
          grading_version: WAF_GRADING_VERSION, signature_corpus_version: SIGNATURE_CORPUS_VERSION })]);
      await stampScope(pool, 'run_target_profile');
      const portal = createPortalRevampRepository(pool);
      await pool.query(
        `INSERT INTO verdicts (id, tenant_id, test_run_id, verdict, confidence, evidence_ids, created_at)
         VALUES ('verdict_profile_live', $1, 'run_target_profile', 'edge_protected', 'external_only', ARRAY['evidence_profile_live'],
           date_trunc('milliseconds', now() - interval '1 second'))`,
        [TENANT],
      );
      const pairFor = async () => (await portal.getTargetDetailBundle(CTX, TARGET, {})).coverage.pairs
        .find((pair) => pair.check_id === checkId);
      assert.equal((await pairFor()).pair_reason, 'missing_check_version');
      await pool.query(
        `UPDATE test_runs SET check_version = '0.0.0', scenario_version = $1, producer_kind = 'signed_probe',
           completed_at = date_trunc('milliseconds', now() - interval '1 second') WHERE id = 'run_target_profile'`, [scenarioVersion],
      );
      assert.equal((await pairFor()).pair_reason, 'check_version_mismatch');
      const currentVersion = check.version;
      await pool.query(`UPDATE test_runs SET check_version = $1 WHERE id = 'run_target_profile'`, [currentVersion]);
      const live = await pairFor();
      assert.equal(live.state, 'conclusive');
      assert.equal(live.provenance, 'external');
      assert.equal(live.live_external, true);
      assert.equal(live.retained.check_version, currentVersion);
      assert.equal(live.retained.scenario_version, scenarioVersion);
      assert.equal(live.outcome, 'pass');
      const observedCustody = (await pool.query(`SELECT r.safety_constraints, v.verdict, v.evidence_ids
        FROM test_runs r JOIN verdicts v ON v.test_run_id = r.id WHERE r.id = 'run_target_profile'`)).rows;
      await pool.query(`UPDATE events SET metadata_json = jsonb_set(metadata_json, '{enforcement}', '"not_enforced"') WHERE id = 'evidence_profile_live'`);
      assert.equal((await pairFor()).pair_reason, 'actual_positive_outcome_mismatch');
      assert.deepEqual((await pool.query(`SELECT r.safety_constraints, v.verdict, v.evidence_ids
        FROM test_runs r JOIN verdicts v ON v.test_run_id = r.id WHERE r.id = 'run_target_profile'`)).rows, observedCustody);
      await pool.query(`UPDATE events SET metadata_json = jsonb_set(metadata_json, '{enforcement}', '"enforced"') WHERE id = 'evidence_profile_live'`);

      await pool.query(`UPDATE verdicts SET verdict = 'edge_exposed' WHERE id = 'verdict_profile_live'`);
      assert.equal((await pairFor()).outcome, 'gap');
      await assert.rejects(pool.query(`INSERT INTO verdicts (id, tenant_id, test_run_id, verdict, evidence_ids, created_at)
        VALUES ('verdict_profile_newer_unresolved', $1, 'run_target_profile', 'edge_protected', ARRAY['unresolved'], now())`, [TENANT]),
        (error) => error.constraint === 'uniq_verdict_per_test_run');
      await pool.query(`UPDATE verdicts SET verdict = 'edge_protected', evidence_ids = ARRAY['unresolved'] WHERE id = 'verdict_profile_live'`);
      assert.equal((await pairFor()).pair_reason, 'invalid_or_unresolved_evidence', 'an unresolved positive cannot borrow any nonce-bound event not cited by its exact verdict');
      await pool.query(`UPDATE verdicts SET verdict = 'edge_protected', evidence_ids = ARRAY['evidence_profile_live'] WHERE id = 'verdict_profile_live'`);
      await pool.query(`UPDATE events SET nonce_hash = 'wrong_nonce' WHERE id = 'evidence_profile_live'`);
      assert.equal((await pairFor()).pair_reason, 'invalid_or_unresolved_evidence');
      await pool.query(`UPDATE events SET nonce_hash = 'profile_nonce' WHERE id = 'evidence_profile_live'`);
      await pool.query(`UPDATE test_runs SET producer_kind = 'internal_simulation' WHERE id = 'run_target_profile'`);
      assert.equal((await pairFor()).live_external, false);
      assert.equal((await pairFor()).pair_reason, 'internal_simulation');
      await pool.query(`UPDATE test_runs SET producer_kind = 'signed_probe', scenario_version = 'old-scenario' WHERE id = 'run_target_profile'`);
      assert.equal((await pairFor()).pair_reason, 'scenario_version_mismatch');
      await pool.query(`UPDATE test_runs SET scenario_version = $1 WHERE id = 'run_target_profile'`, [scenarioVersion]);
      const custody = (await pool.query(`SELECT r.safety_constraints, r.provenance_json, v.evidence_ids
        FROM test_runs r JOIN verdicts v ON v.test_run_id = r.id WHERE r.id = 'run_target_profile'`)).rows;
      await pool.query(`UPDATE targets SET port = 8443 WHERE id = $1`, [TARGET]);
      assert.equal((await pairFor()).pair_reason, 'target_definition_changed');
      await pool.query(`UPDATE targets SET port = NULL, protocol = 'http' WHERE id = $1`, [TARGET]);
      assert.equal((await pairFor()).pair_reason, 'target_definition_changed');
      assert.deepEqual((await pool.query(`SELECT r.safety_constraints, r.provenance_json, v.evidence_ids
        FROM test_runs r JOIN verdicts v ON v.test_run_id = r.id WHERE r.id = 'run_target_profile'`)).rows, custody);
    });
  });

  it('round-trips declarations under RLS and derives the profile from recorded rows', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const catalog = createCoreCatalogRepository(pool, { auditRepository: createAuditRepository(pool) });
      const portal = createPortalRevampRepository(pool);

      const column = await pool.query(
        `SELECT is_nullable, column_default
         FROM information_schema.columns
         WHERE table_name = 'targets' AND column_name = 'declaration_json'`,
      );
      assert.equal(column.rows[0].is_nullable, 'NO');
      assert.match(column.rows[0].column_default, /\{\}/);
      await assert.rejects(
        pool.query(`UPDATE targets SET declaration_json = '[]'::jsonb WHERE id = $1`, [TARGET]),
      );

      const invalid = await catalog.patchTargetGroup(CTX, GROUP, {
        declaration: { service_roles: ['mail'] },
      });
      assert.equal(invalid.status, 400);
      assert.equal(invalid.error, 'invalid_declaration');
      assert.equal(invalid.field, 'service_roles');

      const group = await catalog.patchTargetGroup(CTX, GROUP, {
        declaration: { criticality: 'high', purpose: 'group purpose', service_roles: ['api', 'website'] },
      });
      assert.equal(group.declaration.criticality.value, 'high');
      assert.equal(group.declaration.criticality.source, 'target_group');
      assert.equal(group.declaration.criticality.status, 'declared');
      assert.deepEqual(group.declaration.service_roles, ['website', 'api']);

      const immutable = await catalog.patchTargetById(CTX, TARGET, {
        value: 'changed.example.test',
        declaration: { purpose: 'should not apply' },
      });
      assert.equal(immutable.status, 409);
      assert.equal(immutable.error, 'target_identity_immutable');

      const patched = await catalog.patchTargetById(CTX, TARGET, {
        declaration: { purpose: 'login', owner: { label: 'Ops' }, service_roles: ['login'] },
        metadata: { declaration: { purpose: 'smuggle' }, notes: 'kept' },
      });
      assert.equal(patched.declaration.purpose, 'login');
      assert.equal(patched.declaration.purpose_status, 'declared');
      assert.equal(patched.declaration.purpose_source, 'target');
      assert.equal(patched.declaration.owner.label, 'Ops');
      assert.equal(patched.declaration.criticality.status, 'inherited');
      assert.equal(patched.declaration.criticality.source, 'target_group');
      assert.equal(patched.metadata.notes, 'kept');
      assert.equal(patched.metadata.declaration, undefined);

      const items = await catalog.listTargets(CTX);
      const declared = items.find((item) => item.id === TARGET);
      const inherited = items.find((item) => item.id === INHERITED);
      assert.equal(declared.declaration.purpose, 'login');
      assert.equal(declared.declaration.criticality.status, 'inherited');
      assert.equal(inherited.declaration.purpose_status, 'inherited');
      assert.equal(inherited.declaration.purpose, 'group purpose');
      assert.equal(inherited.declaration.purpose_source, 'target_group');
      assert.equal(inherited.declaration.owner.status, 'unassigned');

      const detail = await portal.getTargetDetailBundle(CTX, TARGET, {});
      assert.equal(detail.target.declaration.purpose, 'login');
      assert.equal(detail.protection_profile.families.waf.provider, 'cloudflare');
      assert.equal(detail.protection_profile.families.waf.confidence, null);
      assert.equal(detail.protection_profile.families.cdn.provider, null);
      assert.equal(detail.protection_profile.families.cdn.confidence, null);
      assert.equal(detail.edge_detection.cdn.provider, undefined);
      assert.equal(detail.edge_detection.waf.provider, 'cloudflare');
      assert.equal(detail.protection_profile.families.cloud.provider, 'aws');
      assert.equal(detail.protection_profile.families.cloud.confidence, 0);
      assert.equal(detail.protection_profile.families.dns.status, 'not_recorded');
      assert.equal(detail.protection_profile.families.origin_hosting.status, 'unknown');
      assert.equal(detail.protection_profile.origin.status, 'not_tested');
      assert.equal(detail.protection_profile.origin.binding_id, null);
      assert.equal(detail.coverage.runtime_launch_gates, 'not_evaluated');
      assert.equal(detail.coverage.pairs.every((pair) => pair.launchable === null), true);
      const owners = new Map(detail.findings.map((finding) => [finding.id, finding.owner_group]));
      assert.equal(owners.get('fnd_profile_owned'), 'app-owners');
      assert.equal(owners.get('fnd_profile_open'), 'unassigned');

      const audits = await pool.query(
        `SELECT action FROM audit_logs
         WHERE tenant_id = $1 AND action = 'target.declaration_updated'`,
        [TENANT],
      );
      assert.equal(audits.rowCount, 1);
      const groupAudits = await pool.query(
        `SELECT action FROM audit_logs
         WHERE tenant_id = $1 AND action = 'target_group.declaration_updated'`,
        [TENANT],
      );
      assert.equal(groupAudits.rowCount, 1);

      const hidden = await withTenantContextAsAppRole(pool, OTHER, (client) => client.query(
        'SELECT id, declaration_json FROM targets WHERE id = $1',
        [TARGET],
      ));
      assert.equal(hidden.rows.length, 0);
      const visible = await withTenantContextAsAppRole(pool, TENANT, (client) => client.query(
        'SELECT declaration_json FROM targets WHERE id = $1',
        [TARGET],
      ));
      assert.equal(visible.rows.length, 1);
      assert.equal(visible.rows[0].declaration_json.purpose, 'login');
    }, availability.env ?? process.env);
  });
});
