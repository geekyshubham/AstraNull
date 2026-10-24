import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildVectorTargetMatrix } from '../../src/contracts/vectorTargetMatrix.mjs';
import { sha256CanonicalJson } from '../../src/lib/custody.mjs';
import {
  buildFullCatalogLiveEvidence,
  payloadForContentDigest,
  validateFullCatalogLiveEvidence,
} from '../../scripts/generate-full-catalog-live-evidence.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const GENERATED_AT = '2026-09-02T20:03:00.543Z';
const EVENT_AT = '2026-09-02T20:02:59.877Z';
const TARGET_ID = 'tgt_unitcatalog0001';
const TARGET_GROUP_ID = 'tg_unitcatalog0001';
const MATRIX = buildVectorTargetMatrix();
const CATALOG_RAW = readFileSync(
  path.join(REPO_ROOT, 'src/lib/data/vectorCatalog.generated.mjs'),
);

const BASE_OPTIONS = Object.freeze({
  domain: 'catalog.example.test',
  targetId: TARGET_ID,
  targetGroupId: TARGET_GROUP_ID,
  ownershipState: 'dns_verified',
  eligibility: 'eligible',
  deploymentCommit: 'a'.repeat(40),
  deploymentImage: `sha256:${'b'.repeat(64)}`,
  generatedAt: GENERATED_AT,
  targetRateLimitRps: 5,
  targetRateLimitBurst: 10,
  restoredMaxRunsPerHour: 60,
  restoredMinSecondsBetweenRuns: 0,
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function makeLiveResults() {
  const results = MATRIX.runnable_safe_check_ids.map((checkId, index) => {
    const suffix = (index + 1).toString(16).padStart(16, '0');
    const runId = `run_${suffix}`;
    const eventId = `evt_${suffix}`;
    return {
      check_id: checkId,
      run_id: runId,
      target_id: TARGET_ID,
      status: 'verdicted',
      verdict: index % 3 === 0 ? 'edge_exposed' : index % 3 === 1 ? 'edge_protected' : 'inconclusive',
      confidence: 'external_only',
      evidence_ids: [eventId],
      event_count: 1,
      evidence: [{
        id: eventId,
        tenant_id: 'ten_unit_catalog',
        test_run_id: runId,
        target_id: TARGET_ID,
        check_id: checkId,
        signal_type: 'probe_result',
        producer_kind: 'signed_probe',
        source: 'probe_worker',
        timestamp: EVENT_AT,
        requests_sent: 1,
        total_operations: 1,
        duration_ms: 1,
      }],
      source: 'unit_test',
      recorded_at: GENERATED_AT,
      target_group_id: TARGET_GROUP_ID,
    };
  });
  return {
    target_id: TARGET_ID,
    group_id: TARGET_GROUP_ID,
    matrix_summary: structuredClone(MATRIX.summary),
    results: results.reverse(),
    refusals: [],
  };
}

function buildArtifact({ matrix = MATRIX, liveResults = makeLiveResults() } = {}) {
  const matrixRaw = Buffer.from(`${JSON.stringify(matrix, null, 2)}\n`);
  const liveResultsRaw = Buffer.from(`${JSON.stringify(liveResults, null, 2)}\n`);
  return buildFullCatalogLiveEvidence({
    matrix,
    liveResults,
    sourceFiles: {
      generated_catalog: {
        path: 'src/lib/data/vectorCatalog.generated.mjs',
        sha256: sha256(CATALOG_RAW),
      },
      raw_matrix_input: {
        path: '/tmp/unit-vector-matrix.json',
        sha256: sha256(matrixRaw),
      },
      raw_live_results_input: {
        path: '/tmp/unit-vector-live-results.json',
        sha256: sha256(liveResultsRaw),
      },
    },
    ...BASE_OPTIONS,
  });
}

describe('full-catalog live evidence generator', () => {
  it('rejects old assessment semantics instead of rewriting historical artifacts', () => {
    for (const [schemaVersion, generatorVersion] of [[2, 'v1'], [3, 'v2']]) {
      const legacy = buildArtifact();
      legacy.schema_version = schemaVersion;
      legacy.generator.schema = `astranull.full-catalog-live-evidence.${generatorVersion}`;
      const original = structuredClone(legacy);
      assert.throws(() => validateFullCatalogLiveEvidence(legacy), /schema_version/);
      assert.deepEqual(legacy, original);
    }
  });

  it('rejects stale matrix totals rather than relabeling old captured inputs', () => {
    const matrix = structuredClone(MATRIX);
    matrix.summary.dispositions.safe_runnable = 373;
    matrix.summary.dispositions.soc_gated = 245;
    matrix.summary.runnable_safe_check_count = 167;
    const original = structuredClone(matrix);
    assert.throws(() => buildArtifact({ matrix }), /matrix disposition totals/);
    assert.deepEqual(matrix, original);
  });

  it('produces deterministic non-self-referential custody', () => {
    const first = buildArtifact();
    const second = buildArtifact();

    assert.deepEqual(second, first);
    assert.equal(
      first.generator.sha256,
      sha256(readFileSync(path.join(REPO_ROOT, first.generator.path))),
    );
    assert.equal(
      first.custody.content_sha256,
      sha256CanonicalJson(payloadForContentDigest(first)),
    );
    assert.equal(Object.hasOwn(payloadForContentDigest(first), 'custody'), false);
    assert.equal(validateFullCatalogLiveEvidence(first), true);
  });

  it('rejects mismatched result targets and mismatched event bindings', () => {
    const wrongResultTarget = makeLiveResults();
    wrongResultTarget.results[0].target_id = 'tgt_wrongtarget0001';
    assert.throws(
      () => buildArtifact({ liveResults: wrongResultTarget }),
      /target_id does not match requested target/,
    );

    const wrongEventTarget = makeLiveResults();
    wrongEventTarget.results[0].evidence[0].target_id = 'tgt_wrongtarget0001';
    assert.throws(
      () => buildArtifact({ liveResults: wrongEventTarget }),
      /event target_id does not match requested target/,
    );
  });

  it('gives every non-executed catalog row zero evidence references', () => {
    const artifact = buildArtifact();
    const nonExecutedRows = artifact.rows.filter((row) => row.target_disposition !== 'safe_runnable');

    assert.equal(nonExecutedRows.length, 347);
    assert.ok(nonExecutedRows.every((row) => row.check_result_refs.length === 0));
    assert.ok(artifact.rows
      .filter((row) => row.target_disposition === 'safe_runnable')
      .every((row) => row.check_result_refs.length > 0));
  });

  it('pins the current 721/374/0/254/49/44/176 totals without upgrading history', () => {
    const artifact = buildArtifact();

    assert.equal(artifact.schema_version, 4);
    assert.equal(artifact.generator.schema, 'astranull.full-catalog-live-evidence.v3');
    assert.equal(artifact.rows.length, 721);
    assert.equal(artifact.check_results.length, 176);
    assert.equal(new Set(artifact.check_results.map((result) => result.check_id)).size, 176);
    assert.deepEqual(MATRIX.summary.dispositions, {
      safe_runnable: 374,
      additional_input_required: 0,
      target_incompatible: 0,
      soc_gated: 254,
      monitor_only: 49,
      not_runnable: 44,
    });
    assert.deepEqual(artifact.summary.evaluation_status, {
      evaluated_bounded: 374,
      monitor_only_not_executed: 49,
      soc_gated_not_executed: 254,
      not_runnable: 44,
    });
    assert.equal(artifact.summary.planned_unique_safe_checks, 176);
    assert.equal(artifact.summary.completed_unique_safe_checks, 176);
    assert.equal(artifact.summary.check_status.verdicted, 176);
    assert.equal(artifact.summary.check_confidence.external_only, 176);
  });
});
