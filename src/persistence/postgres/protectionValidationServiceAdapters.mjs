// Same rules as the dev store over protectionValidationRepository; Postgres mode never falls back to the dev store.
import { createProtectionValidationService } from '../../services/protectionValidation.mjs';

export const PROTECTION_VALIDATION_REPOSITORY_REQUIRED_METHODS = Object.freeze([
  'loadTargetContext',
  'getOriginBindings',
  'listEntryPathsByScope',
  'findEntryPathByIdempotencyKey',
  'insertEntryPath',
  'getEntryPath',
  'getEntryPaths',
  'archiveEntryPath',
  'listEntryPaths',
  'listExpectationsByScope',
  'findExpectationByIdempotencyKey',
  'insertExpectation',
  'getExpectation',
  'getExpectations',
  'archiveExpectation',
  'listExpectations',
  'loadRunEvidence',
  'findBaselineCaptureIdByKey',
  'insertBaselineCapture',
  'getBaselineCaptureRows',
  'getBaselineCaptureRowsByIds',
  'listBaselineCaptureHeads',
  'existingIds',
  'findEvaluationByDigest',
  'insertEvaluation',
  'getEvaluation',
  'listEvaluations',
]);

export function createPostgresProtectionValidationBackend(repository, audit) {
  const missing = PROTECTION_VALIDATION_REPOSITORY_REQUIRED_METHODS.filter((name) => typeof repository?.[name] !== 'function');
  if (missing.length) throw new Error(`protection validation repository is missing: ${missing.join(', ')}`);
  return {
    loadTargetContext: (ctx, ids) => repository.loadTargetContext(ctx, ids),
    getOriginBindings: (ctx, ids) => repository.getOriginBindings(ctx, ids),
    listEntryPathsByScope: (ctx, scope) => repository.listEntryPathsByScope(ctx, scope),
    findEntryPathByIdempotencyKey: (ctx, key) => repository.findEntryPathByIdempotencyKey(ctx, key),
    insertEntryPath: (ctx, row, entry) => repository.insertEntryPath(ctx, row, entry, audit),
    getEntryPath: (ctx, id) => repository.getEntryPath(ctx, id),
    getEntryPaths: (ctx, ids) => repository.getEntryPaths(ctx, ids),
    archiveEntryPath: (ctx, id, patch, entry) => repository.archiveEntryPath(ctx, id, patch, entry, audit),
    listEntryPaths: (ctx, filter) => repository.listEntryPaths(ctx, filter),
    listExpectationsByScope: (ctx, kind, scopeKey) => repository.listExpectationsByScope(ctx, kind, scopeKey),
    findExpectationByIdempotencyKey: (ctx, key) => repository.findExpectationByIdempotencyKey(ctx, key),
    insertExpectation: (ctx, row, entry, options) => repository.insertExpectation(ctx, row, entry, audit, options),
    getExpectation: (ctx, id) => repository.getExpectation(ctx, id),
    getExpectations: (ctx, ids) => repository.getExpectations(ctx, ids),
    archiveExpectation: (ctx, id, patch, entry) => repository.archiveExpectation(ctx, id, patch, entry, audit),
    listExpectations: (ctx, filter) => repository.listExpectations(ctx, filter),
    loadRunEvidence: (ctx, runIds) => repository.loadRunEvidence(ctx, runIds),
    findBaselineCaptureIdByKey: (ctx, key) => repository.findBaselineCaptureIdByKey(ctx, key),
    insertBaselineCapture: (ctx, rows, entry) => repository.insertBaselineCapture(ctx, rows, entry, audit),
    getBaselineCaptureRows: (ctx, captureId) => repository.getBaselineCaptureRows(ctx, captureId),
    getBaselineCaptureRowsByIds: (ctx, captureIds) => repository.getBaselineCaptureRowsByIds(ctx, captureIds),
    listBaselineCaptureHeads: (ctx, filter) => repository.listBaselineCaptureHeads(ctx, filter),
    existingIds: (ctx, ids) => repository.existingIds(ctx, ids),
    findEvaluationByDigest: (ctx, digest) => repository.findEvaluationByDigest(ctx, digest),
    ...(typeof repository.findEvaluationByIdempotencyKey === 'function'
      ? { findEvaluationByIdempotencyKey: (ctx, key) => repository.findEvaluationByIdempotencyKey(ctx, key) }
      : {}),
    insertEvaluation: (ctx, row, entry) => repository.insertEvaluation(ctx, row, entry, audit),
    getEvaluation: (ctx, id) => repository.getEvaluation(ctx, id),
    listEvaluations: (ctx, filter) => repository.listEvaluations(ctx, filter),
    ...Object.fromEntries(OPTIONAL_REPOSITORY_METHODS
      .filter((name) => typeof repository?.[name] === 'function')
      .map((name) => [name, (...args) => repository[name](...args)])),
  };
}

const OPTIONAL_REPOSITORY_METHODS = Object.freeze(['loadEdgeDetections', 'loadConfigurationSnapshots', 'listReportSources']);

export function createPostgresProtectionValidationServices({ repository, audit = null, approvedSourcePerspectives = null } = {}) {
  return createProtectionValidationService({
    backend: createPostgresProtectionValidationBackend(repository, audit),
    approvedSourcePerspectives,
  });
}
