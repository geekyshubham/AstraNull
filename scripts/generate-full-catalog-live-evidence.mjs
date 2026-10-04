#!/usr/bin/env node
/**
 * Build deterministic, metadata-only evidence for one full-catalog live evaluation.
 *
 * This generator never calls an API or executes a probe. It reads previously captured matrix
 * and live-result JSON, validates every binding, and writes only after the complete artifact and
 * its non-self-referential custody digest pass validation.
 */
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { VECTOR_CATALOG } from '../src/lib/data/vectorCatalog.generated.mjs';
import {
  CONTENT_CANONICALIZATION,
  canonicalJsonStringify,
  sha256CanonicalJson,
} from '../src/lib/custody.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CATALOG_PATH = 'src/lib/data/vectorCatalog.generated.mjs';
const CATALOG_ABSOLUTE_PATH = path.join(REPO_ROOT, CATALOG_PATH);

export const GENERATOR_PATH = 'scripts/generate-full-catalog-live-evidence.mjs';
export const GENERATOR_SCHEMA = 'astranull.full-catalog-live-evidence.v1';
export const ARTIFACT_TYPE = 'astranull_full_catalog_target_evaluation';
export const ARTIFACT_SCHEMA_VERSION = 2;
export const EXPECTED_CATALOG_ROWS = 721;
// Website/FQDN evidence excludes open-recursion testing, which requires a declared resolver IP.
export const EXPECTED_SAFE_CHECK_RESULTS = 193;
export const EXPECTED_DISPOSITIONS = Object.freeze({
  safe_runnable: 404,
  additional_input_required: 10,
  target_incompatible: 0,
  soc_gated: 258,
  monitor_only: 49,
  not_runnable: 0,
});

const EXPECTED_PROFILE = Object.freeze({
  target_kind: 'fqdn',
  validation_mode: 'external_only',
});

const EVALUATION_STATUS_BY_DISPOSITION = Object.freeze({
  safe_runnable: 'evaluated_bounded',
  additional_input_required: 'additional_input_required',
  target_incompatible: 'target_incompatible_not_executed',
  soc_gated: 'soc_gated_not_executed',
  monitor_only: 'monitor_only_not_executed',
  not_runnable: 'not_runnable',
});

const EXPECTED_EVALUATION_STATUS = Object.freeze({
  additional_input_required: 10,
  evaluated_bounded: 404,
  monitor_only_not_executed: 49,
  soc_gated_not_executed: 258,
});

const CLI_ALIASES = new Map([
  ['--matrix-input', 'matrixInput'],
  ['--matrix', 'matrixInput'],
  ['--live-results-input', 'liveResultsInput'],
  ['--live-results', 'liveResultsInput'],
  ['--output', 'output'],
  ['--out', 'output'],
  ['--domain', 'domain'],
  ['--target-id', 'targetId'],
  ['--target', 'targetId'],
  ['--target-group-id', 'targetGroupId'],
  ['--group-id', 'targetGroupId'],
  ['--group', 'targetGroupId'],
  ['--ownership-state', 'ownershipState'],
  ['--ownership', 'ownershipState'],
  ['--eligibility', 'eligibility'],
  ['--deployment-commit', 'deploymentCommit'],
  ['--commit', 'deploymentCommit'],
  ['--deployment-image', 'deploymentImage'],
  ['--image', 'deploymentImage'],
  ['--generated-at', 'generatedAt'],
  ['--target-rate-limit-rps', 'targetRateLimitRps'],
  ['--rate-limit-rps', 'targetRateLimitRps'],
  ['--target-rate-limit', 'targetRateLimitRps'],
  ['--target-rate-limit-burst', 'targetRateLimitBurst'],
  ['--rate-limit-burst', 'targetRateLimitBurst'],
  ['--target-rate-burst', 'targetRateLimitBurst'],
  ['--restored-max-runs-per-hour', 'restoredMaxRunsPerHour'],
  ['--restored-min-seconds-between-runs', 'restoredMinSecondsBetweenRuns'],
]);

const REQUIRED_CLI_VALUES = Object.freeze([
  'matrixInput',
  'liveResultsInput',
  'output',
  'domain',
  'targetId',
  'targetGroupId',
  'ownershipState',
  'eligibility',
  'deploymentCommit',
  'deploymentImage',
  'generatedAt',
  'targetRateLimitRps',
  'targetRateLimitBurst',
  'restoredMaxRunsPerHour',
  'restoredMinSecondsBetweenRuns',
]);

const USAGE = `Usage:
  node ${GENERATOR_PATH} \\
    --matrix-input <matrix.json> \\
    --live-results-input <live-results.json> \\
    --output <artifact.json> \\
    --domain <fqdn> --target-id <tgt_id> --target-group-id <tg_id> \\
    --ownership-state <state> --eligibility <state> \\
    --deployment-commit <40-hex> --deployment-image <sha256:digest> \\
    --generated-at <ISO-8601> \\
    --target-rate-limit-rps <integer> --target-rate-limit-burst <integer> \\
    --restored-max-runs-per-hour <integer> \\
    --restored-min-seconds-between-runs <integer>
`;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, label) {
  invariant(isObject(value), `${label} must be an object`);
}

function requireNonEmptyString(value, label) {
  invariant(typeof value === 'string' && value.trim() !== '', `${label} must be a non-empty string`);
}

function requireCanonicalTimestamp(value, label) {
  requireNonEmptyString(value, label);
  const milliseconds = Date.parse(value);
  invariant(Number.isFinite(milliseconds), `${label} must be an ISO-8601 timestamp`);
  invariant(new Date(milliseconds).toISOString() === value, `${label} must use canonical UTC ISO-8601 form`);
  return milliseconds;
}

function requireNonNegativeInteger(value, label) {
  invariant(Number.isInteger(value) && value >= 0, `${label} must be a non-negative integer`);
}

function requirePositiveInteger(value, label) {
  invariant(Number.isInteger(value) && value > 0, `${label} must be a positive integer`);
}

function requireSha256(value, label) {
  invariant(/^[a-f0-9]{64}$/.test(value), `${label} must be a lowercase SHA-256 hex digest`);
}

function assertSameJson(actual, expected, label) {
  invariant(
    canonicalJsonStringify(actual) === canonicalJsonStringify(expected),
    `${label} does not match`,
  );
}

function uniqueStrings(values, label) {
  invariant(Array.isArray(values), `${label} must be an array`);
  for (const value of values) requireNonEmptyString(value, `${label} entry`);
  invariant(new Set(values).size === values.length, `${label} must contain unique IDs`);
  return new Set(values);
}

function increment(counter, value) {
  counter[value] = (counter[value] ?? 0) + 1;
}

function sortedCounter(values) {
  const counter = {};
  for (const value of values) increment(counter, value);
  return Object.fromEntries(Object.entries(counter).sort(([left], [right]) => (
    left < right ? -1 : left > right ? 1 : 0
  )));
}

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parseJsonBuffer(buffer, label) {
  try {
    const value = JSON.parse(buffer.toString('utf8'));
    requireObject(value, label);
    return value;
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON: ${error.message}`);
    throw error;
  }
}

function validateOptions(options) {
  requireNonEmptyString(options.domain, 'domain');
  invariant(
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(options.domain),
    'domain must be an FQDN without a URL scheme or path',
  );
  invariant(/^tgt_[A-Za-z0-9]+$/.test(options.targetId), 'target ID must start with tgt_');
  invariant(/^tg_[A-Za-z0-9]+$/.test(options.targetGroupId), 'target group ID must start with tg_');
  invariant(/^[a-z][a-z0-9_]*$/.test(options.ownershipState), 'ownership state is invalid');
  invariant(/^[a-z][a-z0-9_]*$/.test(options.eligibility), 'eligibility is invalid');
  invariant(/^[a-f0-9]{40}$/.test(options.deploymentCommit), 'deployment commit must be 40 lowercase hex characters');
  invariant(/^sha256:[a-f0-9]{64}$/.test(options.deploymentImage), 'deployment image must be a sha256: digest');
  requireCanonicalTimestamp(options.generatedAt, 'generated-at');
  requirePositiveInteger(options.targetRateLimitRps, 'target rate limit RPS');
  requirePositiveInteger(options.targetRateLimitBurst, 'target rate limit burst');
  requirePositiveInteger(options.restoredMaxRunsPerHour, 'restored max runs per hour');
  requireNonNegativeInteger(
    options.restoredMinSecondsBetweenRuns,
    'restored min seconds between runs',
  );
}

function validateMatrix(matrix, catalogRows = VECTOR_CATALOG) {
  requireObject(matrix, 'matrix');
  assertSameJson(matrix.profile, EXPECTED_PROFILE, 'matrix profile');
  invariant(Array.isArray(matrix.rows), 'matrix.rows must be an array');
  invariant(matrix.rows.length === EXPECTED_CATALOG_ROWS, `matrix must contain exactly ${EXPECTED_CATALOG_ROWS} rows`);
  invariant(Array.isArray(catalogRows) && catalogRows.length === EXPECTED_CATALOG_ROWS, 'committed generated catalog must contain 721 rows');

  const catalogById = new Map(catalogRows.map((row) => [row.vector_id, row]));
  invariant(catalogById.size === EXPECTED_CATALOG_ROWS, 'committed generated catalog vector IDs must be unique');

  const vectorIds = new Set();
  const recomputedDispositions = Object.fromEntries(
    Object.keys(EXPECTED_DISPOSITIONS).map((disposition) => [disposition, 0]),
  );
  const rowRunnableIds = new Set();

  for (const row of matrix.rows) {
    requireObject(row, 'matrix row');
    requireNonEmptyString(row.vector_id, 'matrix row vector_id');
    invariant(!vectorIds.has(row.vector_id), `duplicate matrix vector_id: ${row.vector_id}`);
    vectorIds.add(row.vector_id);

    const catalogRow = catalogById.get(row.vector_id);
    invariant(catalogRow, `matrix vector_id is absent from committed catalog: ${row.vector_id}`);
    invariant(
      row.canonical_name === catalogRow.canonical_name,
      `matrix canonical_name does not match committed catalog for ${row.vector_id}`,
    );
    invariant(
      Object.hasOwn(recomputedDispositions, row.target_disposition),
      `unsupported target disposition for ${row.vector_id}: ${row.target_disposition}`,
    );
    recomputedDispositions[row.target_disposition] += 1;

    const safeIds = uniqueStrings(row.safe_check_ids, `${row.vector_id}.safe_check_ids`);
    const runnableIds = uniqueStrings(
      row.runnable_safe_check_ids,
      `${row.vector_id}.runnable_safe_check_ids`,
    );
    uniqueStrings(row.soc_check_ids, `${row.vector_id}.soc_check_ids`);
    invariant(Array.isArray(row.blocked_safe_checks), `${row.vector_id}.blocked_safe_checks must be an array`);
    for (const checkId of runnableIds) {
      invariant(safeIds.has(checkId), `${row.vector_id} runnable check is absent from safe_check_ids: ${checkId}`);
      rowRunnableIds.add(checkId);
    }
    if (row.target_disposition === 'safe_runnable') {
      invariant(runnableIds.size > 0, `${row.vector_id} is safe_runnable without a runnable check`);
    } else {
      invariant(runnableIds.size === 0, `${row.vector_id} is non-executed but has runnable check IDs`);
    }
  }

  requireObject(matrix.summary, 'matrix.summary');
  invariant(matrix.summary.total === EXPECTED_CATALOG_ROWS, 'matrix summary total must be 721');
  assertSameJson(matrix.summary.dispositions, recomputedDispositions, 'matrix disposition totals');
  assertSameJson(matrix.summary.dispositions, EXPECTED_DISPOSITIONS, 'expected matrix disposition totals');

  const plannedIds = uniqueStrings(
    matrix.runnable_safe_check_ids,
    'matrix.runnable_safe_check_ids',
  );
  invariant(plannedIds.size === EXPECTED_SAFE_CHECK_RESULTS, 'matrix must plan exactly 193 unique safe checks');
  invariant(
    matrix.summary.runnable_safe_check_count === EXPECTED_SAFE_CHECK_RESULTS,
    'matrix runnable_safe_check_count must be 193',
  );
  assertSameJson([...rowRunnableIds].sort(), [...plannedIds].sort(), 'row/planned runnable check IDs');

  return { plannedIds, recomputedDispositions };
}

function validateResult(result, options, seen, label) {
  requireObject(result, label);
  requireNonEmptyString(result.check_id, `${label}.check_id`);
  requireNonEmptyString(result.run_id, `${label}.run_id`);
  invariant(/^run_[A-Za-z0-9]+$/.test(result.run_id), `${label}.run_id is invalid`);
  invariant(!seen.checkIds.has(result.check_id), `duplicate live check_id: ${result.check_id}`);
  invariant(!seen.runIds.has(result.run_id), `duplicate live run_id: ${result.run_id}`);
  seen.checkIds.add(result.check_id);
  seen.runIds.add(result.run_id);

  invariant(result.target_id === options.targetId, `${label}.target_id does not match requested target`);
  invariant(
    result.target_group_id === options.targetGroupId,
    `${label}.target_group_id does not match requested target group`,
  );
  invariant(result.status === 'verdicted', `${label}.status must be verdicted`);
  invariant(result.confidence === 'external_only', `${label}.confidence must be external_only`);
  invariant(
    ['edge_exposed', 'edge_protected', 'inconclusive'].includes(result.verdict),
    `${label}.verdict is unsupported`,
  );
  requireNonEmptyString(result.source, `${label}.source`);
  requireCanonicalTimestamp(result.recorded_at, `${label}.recorded_at`);

  invariant(result.event_count === 1, `${label}.event_count must be 1`);
  invariant(Array.isArray(result.evidence) && result.evidence.length === 1, `${label} must contain exactly one evidence event`);
  invariant(Array.isArray(result.evidence_ids) && result.evidence_ids.length === 1, `${label} must contain exactly one evidence ID`);

  const event = result.evidence[0];
  requireObject(event, `${label}.evidence[0]`);
  requireNonEmptyString(event.id, `${label}.evidence[0].id`);
  invariant(/^evt_[A-Za-z0-9]+$/.test(event.id), `${label} evidence ID is invalid`);
  invariant(!seen.evidenceIds.has(event.id), `duplicate live evidence ID: ${event.id}`);
  seen.evidenceIds.add(event.id);
  invariant(result.evidence_ids[0] === event.id, `${label} evidence_ids do not bind to the event`);

  requireNonEmptyString(event.tenant_id, `${label} event tenant_id`);
  invariant(event.test_run_id === result.run_id, `${label} event test_run_id does not bind to the run`);
  invariant(event.target_id === options.targetId, `${label} event target_id does not match requested target`);
  invariant(event.check_id === result.check_id, `${label} event check_id does not bind to the result`);
  invariant(event.signal_type === 'probe_result', `${label} event signal_type must be probe_result`);
  invariant(event.producer_kind === 'signed_probe', `${label} event producer_kind must be signed_probe`);
  invariant(event.source === 'probe_worker', `${label} event source must be probe_worker`);
  requireCanonicalTimestamp(event.timestamp, `${label} event timestamp`);
  requireNonNegativeInteger(event.requests_sent, `${label} event requests_sent`);
  requireNonNegativeInteger(event.total_operations, `${label} event total_operations`);
  requireNonNegativeInteger(event.duration_ms, `${label} event duration_ms`);

  seen.tenantIds.add(event.tenant_id);
  return Math.max(Date.parse(result.recorded_at), Date.parse(event.timestamp));
}

function validateLiveResults(liveResults, matrix, plannedIds, options) {
  requireObject(liveResults, 'live results');
  invariant(liveResults.target_id === options.targetId, 'live results target_id does not match requested target');
  invariant(liveResults.group_id === options.targetGroupId, 'live results group_id does not match requested target group');
  assertSameJson(liveResults.matrix_summary, matrix.summary, 'live-results/matrix summary');
  invariant(Array.isArray(liveResults.refusals), 'live results refusals must be an array');
  invariant(liveResults.refusals.length === 0, 'live results contain a refusal');
  invariant(Array.isArray(liveResults.results), 'live results results must be an array');

  const seen = {
    checkIds: new Set(),
    runIds: new Set(),
    evidenceIds: new Set(),
    tenantIds: new Set(),
  };
  const byCheckId = new Map();
  let latestTimestampMs = Number.NEGATIVE_INFINITY;

  liveResults.results.forEach((result, index) => {
    const label = `live results.results[${index}]`;
    latestTimestampMs = Math.max(
      latestTimestampMs,
      validateResult(result, options, seen, label),
    );
    byCheckId.set(result.check_id, result);
  });

  invariant(seen.tenantIds.size === 1, 'live result events must bind to exactly one tenant_id');
  for (const checkId of plannedIds) {
    invariant(byCheckId.has(checkId), `missing live result for planned check: ${checkId}`);
  }
  const selected = matrix.runnable_safe_check_ids.map((checkId) => byCheckId.get(checkId));
  invariant(selected.length === EXPECTED_SAFE_CHECK_RESULTS, 'selected live result count must be 193');
  invariant(
    new Set(selected.map((result) => result.check_id)).size === EXPECTED_SAFE_CHECK_RESULTS,
    'selected live check results must be unique',
  );

  const latestTimestamp = new Date(latestTimestampMs).toISOString();
  invariant(
    options.generatedAt === latestTimestamp,
    `generated-at must equal the latest result/readback timestamp: ${latestTimestamp}`,
  );

  return {
    selected,
    latestTimestamp,
    tenantId: [...seen.tenantIds][0],
    unplannedCheckIds: liveResults.results
      .filter((result) => !plannedIds.has(result.check_id))
      .map((result) => result.check_id)
      .sort(),
  };
}

function validateSourceFiles(sourceFiles) {
  requireObject(sourceFiles, 'source files');
  for (const key of ['generated_catalog', 'raw_matrix_input', 'raw_live_results_input']) {
    requireObject(sourceFiles[key], `source files.${key}`);
    requireNonEmptyString(sourceFiles[key].path, `source files.${key}.path`);
    requireSha256(sourceFiles[key].sha256, `source files.${key}.sha256`);
  }
  invariant(sourceFiles.generated_catalog.path === CATALOG_PATH, 'generated catalog source path is invalid');
}

function resultReference(result) {
  return {
    check_id: result.check_id,
    run_id: result.run_id,
    evidence_ids: [...result.evidence_ids],
  };
}

function buildRows(matrix, resultByCheckId) {
  return matrix.rows.map((row) => {
    const evaluationStatus = EVALUATION_STATUS_BY_DISPOSITION[row.target_disposition];
    invariant(evaluationStatus, `unsupported target disposition: ${row.target_disposition}`);
    return {
      ...structuredClone(row),
      evaluation_status: evaluationStatus,
      check_result_refs: row.target_disposition === 'safe_runnable'
        ? row.runnable_safe_check_ids.map((checkId) => resultReference(resultByCheckId.get(checkId)))
        : [],
    };
  });
}

function buildSummary(rows, selectedResults, liveResults) {
  const evaluationStatus = sortedCounter(rows.map((row) => row.evaluation_status));
  const boundedRequests = selectedResults.reduce((total, result) => (
    total + result.evidence.reduce((subtotal, event) => subtotal + event.requests_sent, 0)
  ), 0);
  return {
    catalog_rows: rows.length,
    unique_vector_ids: new Set(rows.map((row) => row.vector_id)).size,
    evaluation_status: evaluationStatus,
    planned_unique_safe_checks: EXPECTED_SAFE_CHECK_RESULTS,
    completed_unique_safe_checks: selectedResults.length,
    source_check_results: liveResults.results.length,
    unplanned_source_check_results: liveResults.results.length - selectedResults.length,
    refusals: liveResults.refusals.length,
    check_status: sortedCounter(selectedResults.map((result) => result.status)),
    check_verdict: sortedCounter(selectedResults.map((result) => result.verdict)),
    check_confidence: sortedCounter(selectedResults.map((result) => result.confidence)),
    probe_result_events: selectedResults.reduce((total, result) => total + result.evidence.length, 0),
    bounded_requests: boundedRequests,
  };
}

export function payloadForContentDigest(artifact) {
  requireObject(artifact, 'artifact');
  const { custody: _custody, ...payload } = artifact;
  return payload;
}

export function validateFullCatalogLiveEvidence(artifact) {
  requireObject(artifact, 'artifact');
  invariant(artifact.artifact_type === ARTIFACT_TYPE, 'artifact_type is invalid');
  invariant(artifact.schema_version === ARTIFACT_SCHEMA_VERSION, 'schema_version is invalid');
  invariant(artifact.generator?.path === GENERATOR_PATH, 'generator path is invalid');
  invariant(artifact.generator?.schema === GENERATOR_SCHEMA, 'generator schema is invalid');
  invariant(
    artifact.generator?.sha256 === sha256Bytes(readFileSync(fileURLToPath(import.meta.url))),
    'generator sha256 is invalid',
  );
  validateSourceFiles(artifact.inputs);
  requireCanonicalTimestamp(artifact.generated_at, 'artifact.generated_at');
  invariant(artifact.target?.validation_mode === 'external_only', 'artifact target must be external_only');
  invariant(Array.isArray(artifact.rows) && artifact.rows.length === EXPECTED_CATALOG_ROWS, 'artifact must contain exactly 721 rows');
  invariant(Array.isArray(artifact.check_results) && artifact.check_results.length === EXPECTED_SAFE_CHECK_RESULTS, 'artifact must contain exactly 193 check results');

  const resultByCheckId = new Map();
  const runIds = new Set();
  const evidenceIds = new Set();
  for (const result of artifact.check_results) {
    invariant(!resultByCheckId.has(result.check_id), `duplicate artifact check result: ${result.check_id}`);
    invariant(!runIds.has(result.run_id), `duplicate artifact run ID: ${result.run_id}`);
    invariant(result.target_id === artifact.target.target_id, `${result.check_id} target_id is not bound to artifact target`);
    invariant(result.target_group_id === artifact.target.target_group_id, `${result.check_id} target_group_id is not bound to artifact group`);
    invariant(result.status === 'verdicted', `${result.check_id} status must be verdicted`);
    invariant(result.confidence === 'external_only', `${result.check_id} confidence must be external_only`);
    invariant(result.event_count === 1 && result.evidence?.length === 1, `${result.check_id} must have one event`);
    const event = result.evidence[0];
    invariant(event.tenant_id === artifact.target.tenant_id, `${result.check_id} event tenant_id is not bound`);
    invariant(event.test_run_id === result.run_id, `${result.check_id} event run binding is invalid`);
    invariant(event.target_id === result.target_id, `${result.check_id} event target binding is invalid`);
    invariant(event.check_id === result.check_id, `${result.check_id} event check binding is invalid`);
    invariant(event.signal_type === 'probe_result', `${result.check_id} event must be probe_result`);
    invariant(event.producer_kind === 'signed_probe', `${result.check_id} event must be signed_probe`);
    invariant(event.source === 'probe_worker', `${result.check_id} event must be from probe_worker`);
    invariant(result.evidence_ids?.length === 1 && result.evidence_ids[0] === event.id, `${result.check_id} evidence binding is invalid`);
    invariant(!evidenceIds.has(event.id), `duplicate artifact evidence ID: ${event.id}`);
    resultByCheckId.set(result.check_id, result);
    runIds.add(result.run_id);
    evidenceIds.add(event.id);
  }

  const vectorIds = new Set();
  const evaluationStatuses = [];
  const referencedChecks = new Set();
  for (const row of artifact.rows) {
    invariant(!vectorIds.has(row.vector_id), `duplicate artifact vector ID: ${row.vector_id}`);
    vectorIds.add(row.vector_id);
    invariant(!Object.hasOwn(row, 'verdict'), `${row.vector_id} must not synthesize a vector verdict`);
    invariant(Array.isArray(row.check_result_refs), `${row.vector_id} check_result_refs must be an array`);
    evaluationStatuses.push(row.evaluation_status);

    if (row.target_disposition !== 'safe_runnable') {
      invariant(row.check_result_refs.length === 0, `${row.vector_id} is non-executed and must not reference evidence`);
      continue;
    }

    invariant(
      row.check_result_refs.length === row.runnable_safe_check_ids.length,
      `${row.vector_id} result reference count does not match runnable checks`,
    );
    row.check_result_refs.forEach((reference, index) => {
      const checkId = row.runnable_safe_check_ids[index];
      const result = resultByCheckId.get(checkId);
      invariant(result, `${row.vector_id} references unknown check result: ${checkId}`);
      assertSameJson(reference, resultReference(result), `${row.vector_id}/${checkId} exact result reference`);
      referencedChecks.add(checkId);
    });
  }

  invariant(vectorIds.size === EXPECTED_CATALOG_ROWS, 'artifact vector IDs must be unique');
  invariant(referencedChecks.size === EXPECTED_SAFE_CHECK_RESULTS, 'artifact rows must reference all 193 check results');
  assertSameJson(sortedCounter(evaluationStatuses), EXPECTED_EVALUATION_STATUS, 'artifact evaluation totals');
  invariant(artifact.summary?.catalog_rows === EXPECTED_CATALOG_ROWS, 'artifact summary catalog_rows must be 721');
  invariant(artifact.summary?.unique_vector_ids === EXPECTED_CATALOG_ROWS, 'artifact summary vector IDs must be 721');
  invariant(artifact.summary?.planned_unique_safe_checks === EXPECTED_SAFE_CHECK_RESULTS, 'artifact summary planned checks must be 193');
  invariant(artifact.summary?.completed_unique_safe_checks === EXPECTED_SAFE_CHECK_RESULTS, 'artifact summary completed checks must be 193');
  invariant(artifact.summary?.refusals === 0, 'artifact summary refusals must be zero');
  invariant(artifact.summary?.check_status?.verdicted === EXPECTED_SAFE_CHECK_RESULTS, 'artifact must have 193 verdicted checks');
  invariant(artifact.summary?.check_confidence?.external_only === EXPECTED_SAFE_CHECK_RESULTS, 'artifact must have 193 external_only checks');
  invariant(artifact.summary?.probe_result_events === EXPECTED_SAFE_CHECK_RESULTS, 'artifact must have 193 probe_result events');
  assertSameJson(artifact.summary.evaluation_status, EXPECTED_EVALUATION_STATUS, 'artifact summary evaluation totals');

  requireObject(artifact.custody, 'artifact.custody');
  invariant(
    artifact.custody.content_canonicalization === CONTENT_CANONICALIZATION,
    'artifact custody canonicalization is invalid',
  );
  invariant(
    artifact.custody.payload_scope === 'top_level_excluding_custody',
    'artifact custody payload scope is invalid',
  );
  requireSha256(artifact.custody.content_sha256, 'artifact.custody.content_sha256');
  invariant(
    artifact.custody.content_sha256 === sha256CanonicalJson(payloadForContentDigest(artifact)),
    'artifact custody content digest does not match the non-self-referential payload',
  );
  return true;
}

export function buildFullCatalogLiveEvidence({
  matrix,
  liveResults,
  sourceFiles,
  catalogRows = VECTOR_CATALOG,
  ...options
}) {
  validateOptions(options);
  validateSourceFiles(sourceFiles);
  const { plannedIds } = validateMatrix(matrix, catalogRows);
  const {
    selected,
    latestTimestamp,
    tenantId,
    unplannedCheckIds,
  } = validateLiveResults(liveResults, matrix, plannedIds, options);

  const selectedResults = selected.map((result) => structuredClone(result));
  const resultByCheckId = new Map(selectedResults.map((result) => [result.check_id, result]));
  const rows = buildRows(matrix, resultByCheckId);
  const payload = {
    artifact_type: ARTIFACT_TYPE,
    schema_version: ARTIFACT_SCHEMA_VERSION,
    generated_at: options.generatedAt,
    generator: {
      path: GENERATOR_PATH,
      schema: GENERATOR_SCHEMA,
      sha256: sha256Bytes(readFileSync(fileURLToPath(import.meta.url))),
      runtime_dependencies: ['node:crypto', 'node:fs', 'node:path', 'node:url'],
    },
    inputs: structuredClone(sourceFiles),
    target: {
      domain: options.domain,
      tenant_id: tenantId,
      target_id: options.targetId,
      target_group_id: options.targetGroupId,
      target_kind: 'fqdn',
      validation_mode: 'external_only',
      ownership_state: options.ownershipState,
      eligibility: options.eligibility,
    },
    safety: {
      execution: 'sequential',
      concurrent_runs: 1,
      high_scale_executed: false,
      soc_adapter_executed: false,
      target_rate_limit: {
        requests_per_second: options.targetRateLimitRps,
        burst: options.targetRateLimitBurst,
      },
      group_policy_restored: {
        max_runs_per_hour: options.restoredMaxRunsPerHour,
        min_seconds_between_runs: options.restoredMinSecondsBetweenRuns,
      },
    },
    deployment: {
      commit: options.deploymentCommit,
      image: options.deploymentImage,
    },
    input_accounting: {
      latest_result_or_readback_at: latestTimestamp,
      source_check_results: liveResults.results.length,
      selected_matrix_check_results: selectedResults.length,
      unplanned_check_ids: unplannedCheckIds,
    },
    summary: buildSummary(rows, selectedResults, liveResults),
    check_results: selectedResults,
    rows,
  };
  const artifact = {
    ...payload,
    custody: {
      schema: `${GENERATOR_SCHEMA}.custody`,
      payload_scope: 'top_level_excluding_custody',
      content_canonicalization: CONTENT_CANONICALIZATION,
      content_sha256: sha256CanonicalJson(payload),
    },
  };
  validateFullCatalogLiveEvidence(artifact);
  return artifact;
}

function resolvedExistingPath(filePath) {
  return existsSync(filePath) ? realpathSync(filePath) : path.resolve(filePath);
}

export function generateFullCatalogLiveEvidence({
  matrixInput,
  liveResultsInput,
  output,
  ...options
}) {
  for (const [value, label] of [
    [matrixInput, 'matrix input'],
    [liveResultsInput, 'live-results input'],
    [output, 'output'],
  ]) requireNonEmptyString(value, label);

  const matrixResolved = realpathSync(matrixInput);
  const liveResultsResolved = realpathSync(liveResultsInput);
  const catalogResolved = realpathSync(CATALOG_ABSOLUTE_PATH);
  const outputResolved = resolvedExistingPath(output);
  invariant(outputResolved !== matrixResolved, 'output must not overwrite the matrix input');
  invariant(outputResolved !== liveResultsResolved, 'output must not overwrite the live-results input');
  invariant(outputResolved !== catalogResolved, 'output must not overwrite the generated catalog');

  const matrixRaw = readFileSync(matrixResolved);
  const liveResultsRaw = readFileSync(liveResultsResolved);
  const catalogRaw = readFileSync(catalogResolved);
  const artifact = buildFullCatalogLiveEvidence({
    matrix: parseJsonBuffer(matrixRaw, 'matrix input'),
    liveResults: parseJsonBuffer(liveResultsRaw, 'live-results input'),
    sourceFiles: {
      generated_catalog: {
        path: CATALOG_PATH,
        sha256: sha256Bytes(catalogRaw),
      },
      raw_matrix_input: {
        path: matrixInput,
        sha256: sha256Bytes(matrixRaw),
      },
      raw_live_results_input: {
        path: liveResultsInput,
        sha256: sha256Bytes(liveResultsRaw),
      },
    },
    ...options,
  });

  const rendered = `${JSON.stringify(artifact, null, 2)}\n`;
  mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  writeFileSync(output, rendered, 'utf8');
  return artifact;
}

function parseUnsignedInteger(value, label) {
  invariant(/^\d+$/.test(value), `${label} must be an unsigned integer`);
  const number = Number(value);
  invariant(Number.isSafeInteger(number), `${label} is outside the safe integer range`);
  return number;
}

function parseRate(value) {
  const match = /^(\d+)(?:r\/s|requests?\/second)?$/i.exec(value);
  invariant(match, 'target rate limit must be an integer or use the form 5r/s');
  return parseUnsignedInteger(match[1], 'target rate limit');
}

export function parseArgs(argv) {
  if (argv.includes('--help') || argv.includes('-h')) return { help: true };
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--restored-policy') {
      const value = argv[index + 1];
      invariant(value !== undefined, '--restored-policy requires max-runs/min-seconds');
      const match = /^(\d+)\/(\d+)$/.exec(value);
      invariant(match, '--restored-policy must use max-runs/min-seconds form, for example 60/0');
      invariant(values.restoredMaxRunsPerHour === undefined, 'duplicate restored max-runs value');
      invariant(values.restoredMinSecondsBetweenRuns === undefined, 'duplicate restored min-seconds value');
      values.restoredMaxRunsPerHour = match[1];
      values.restoredMinSecondsBetweenRuns = match[2];
      index += 1;
      continue;
    }
    const key = CLI_ALIASES.get(argument);
    invariant(key, `unknown argument: ${argument}`);
    const value = argv[index + 1];
    invariant(value !== undefined, `${argument} requires a value`);
    invariant(values[key] === undefined, `duplicate argument for ${key}`);
    values[key] = value;
    index += 1;
  }
  for (const key of REQUIRED_CLI_VALUES) invariant(values[key] !== undefined, `missing required argument: ${key}`);
  return {
    ...values,
    targetRateLimitRps: parseRate(values.targetRateLimitRps),
    targetRateLimitBurst: parseUnsignedInteger(values.targetRateLimitBurst, 'target rate limit burst'),
    restoredMaxRunsPerHour: parseUnsignedInteger(values.restoredMaxRunsPerHour, 'restored max runs per hour'),
    restoredMinSecondsBetweenRuns: parseUnsignedInteger(
      values.restoredMinSecondsBetweenRuns,
      'restored min seconds between runs',
    ),
    help: false,
  };
}

export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  const artifact = generateFullCatalogLiveEvidence(options);
  process.stdout.write(
    `full-catalog-live-evidence: wrote ${artifact.rows.length} rows and ${artifact.check_results.length} check results to ${options.output}\n`,
  );
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main();
  } catch (error) {
    console.error(
      `full-catalog-live-evidence: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exitCode = 1;
  }
}
