// PV-03 declarations, baselines, and evaluations over a dev or Postgres backend; nothing here dispatches traffic.
import { randomBytes } from 'node:crypto';
import {
  classifyEntryPathWrite,
  classifyFirewallExpectationWrite,
  COMPARISON_KINDS,
  comparisonEvaluationDigest,
  ENTRY_PATH_RELATION_KINDS,
  entryPathAuthorizesExecution,
  entryPathDeclarationDigest,
  expectationDigest,
  firewallBaselineCaptureDigest,
  firewallExpectationScopeKey,
  isFinalizedRunStatus,
  MAX_COMPARISON_ITEMS,
  MAX_EVIDENCE_REFERENCES,
  normalizeComparisonBaseline,
  normalizeComparisonEvaluation,
  normalizeEntryPathDeclaration,
  normalizeEvidenceReference,
  normalizeFirewallBaselineCapture,
  normalizeFirewallBaselineRequest,
  normalizeFirewallExpectation,
  normalizePathValidationExpectation,
  PROTECTION_VALIDATION_AUDIT_ACTIONS,
  PROTECTION_VALIDATION_PAGE_LIMIT,
  PROTECTION_VALIDATION_PERMISSIONS,
  pathValidationExpectationScopeKey,
  ProtectionValidationError,
  RECORD_STATUSES,
  sha256Digest,
  validateEntryPathReferences,
  verifyBaselineDigest,
} from '../contracts/protectionValidation.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { requirePermission } from '../rbac.mjs';
import { audit as appendDevAudit } from '../audit.mjs';
import { clampPageLimit, decodeKeysetCursor, encodeKeysetCursor } from '../lib/cursorPagination.mjs';
import { getStore, persistStore } from '../store.mjs';
import { bindingRecordsFromStore, currentOriginProof } from './originBindings.mjs';
import { normalizeObservationTimestamp } from './targetHistory.mjs';

export const PROTECTION_VALIDATION_STORE_KEYS = Object.freeze({
  entryPaths: 'applicationEntryPaths',
  expectations: 'protectionExpectations',
  baselines: 'protectionComparisonBaselines',
  evaluations: 'protectionComparisonEvaluations',
});

export const PROTECTION_VALIDATION_EXTRA_AUDIT_ACTIONS = Object.freeze({
  path_validation_expectation_recorded: PROTECTION_VALIDATION_AUDIT_ACTIONS.path_validation_expectation_recorded,
  path_validation_expectation_archived: PROTECTION_VALIDATION_AUDIT_ACTIONS.path_validation_expectation_archived,
  path_validation_baseline_captured: PROTECTION_VALIDATION_AUDIT_ACTIONS.path_validation_baseline_captured,
  entry_path_comparison_evaluated: PROTECTION_VALIDATION_AUDIT_ACTIONS.entry_path_comparison_evaluated,
});

export const MAX_EVALUATION_ITEMS_JSON_BYTES = 4 * 1024 * 1024;

const P = PROTECTION_VALIDATION_PERMISSIONS;
const A = PROTECTION_VALIDATION_AUDIT_ACTIONS;
const X = PROTECTION_VALIDATION_EXTRA_AUDIT_ACTIONS;
const SIGNED_PRODUCER = 'signed_probe';
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const TCP_PROFILE_KINDS = new Set(['tcp_connect', 'port_scan_bounded']);
const UDP_PROFILE_KINDS = new Set(['udp_probe']);

function error(code, status, extra = {}) {
  return { error: code, status, ...extra };
}

function contractError(err) {
  if (err instanceof ProtectionValidationError) return err.toResponse();
  throw err;
}

function attempt(fn) {
  try {
    return { value: fn() };
  } catch (err) {
    return { failure: contractError(err) };
  }
}

function hasPermission(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return false;
  if (Array.isArray(ctx?.scopes)) return ctx.scopes.includes('*') || ctx.scopes.includes(permission);
  return true;
}

function gate(ctx, permissions, resourceType, options = {}) {
  if (!ctx?.tenantId) return error('invalid_tenant', 400);
  if (options.internal === true) return null;
  if (permissions.some((permission) => hasPermission(ctx, permission))) return null;
  const denied = requirePermission(ctx, permissions[0], { resource_type: resourceType });
  return error('forbidden', denied.status ?? 403, { permission: denied.body?.permission ?? permissions[0] });
}

function newRecordId(prefix) {
  return `${prefix}_${randomBytes(8).toString('hex')}`;
}

function stamp(options = {}) {
  return normalizeObservationTimestamp(options.now ?? new Date());
}

function isoMillis(value) {
  if (value == null) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function normalizeIdempotencyKey(value) {
  if (value == null || value === '') return { key: null };
  const key = String(value).trim();
  if (!IDEMPOTENCY_KEY_PATTERN.test(key)) return { failure: error('invalid_idempotency_key', 400, { field: 'Idempotency-Key' }) };
  return { key };
}

function actor(ctx, options = {}) {
  return ctx?.userId ?? options.actor ?? null;
}

function auditEntry(ctx, action, resourceType, resourceId, metadata, options = {}) {
  return {
    tenant_id: ctx.tenantId,
    actor_user_id: actor(ctx, options),
    actor_role: ctx.role ?? (options.internal ? 'system' : null),
    action,
    resource_type: resourceType,
    resource_id: resourceId,
    metadata,
  };
}

function targetActive(target) {
  return Boolean(target) && !target.deleted_at && !target.archived_at && target.status !== 'archived' && target.status !== 'deleted';
}

export { pathValidationExpectationScopeKey };

export function firewallProtocolForCheck(checkId) {
  const kind = getCheckById(checkId)?.probe_profile?.kind ?? null;
  if (!kind) return null;
  if (TCP_PROFILE_KINDS.has(kind)) return 'tcp';
  if (UDP_PROFILE_KINDS.has(kind)) return 'udp';
  return 'service';
}

export function baselineTargetForExpectation(expectation) {
  return expectation?.pre_post_mapping?.pre_destination_target_id ?? expectation?.destination_target_id ?? null;
}

function expectationPort(expectation) {
  return expectation.protocol === 'service' ? expectation.service_endpoint?.port ?? null : expectation.port ?? null;
}

function latestBy(rows, field) {
  return [...rows].sort((left, right) => String(right?.[field] ?? '').localeCompare(String(left?.[field] ?? '')))[0] ?? null;
}

/** Only a finalized signed-probe run with a completed signed, worker-leased job and a signed result qualifies. */
export function buildRunEvidenceReference(run, evidence = {}, options = {}) {
  if (!run) return error('not_found', 404, { field: 'test_run_ids' });
  if (!isFinalizedRunStatus(run.status)) {
    return error('evidence_not_finalized', 409, { field: 'test_run_ids', message: `Run ${run.id} is not finalized.` });
  }
  const notSigned = (reason) => error('invalid_evidence_reference', 409, {
    field: 'test_run_ids',
    reason,
    message: `Run ${run.id} is not finalized signed external evidence.`,
  });
  if (run.producer_kind !== SIGNED_PRODUCER) return notSigned('not_signed_external_evidence');
  const jobs = (evidence.jobs ?? []).filter((job) => job.test_run_id === run.id
    && job.status === 'completed'
    && typeof job.leased_by === 'string' && job.leased_by
    && typeof job.job_signature === 'string' && job.job_signature);
  const job = latestBy(jobs, 'completed_at');
  if (!job) return notSigned('signed_job_missing');
  const events = (evidence.events ?? []).filter((event) => event.test_run_id === run.id
    && event.signal_type === 'probe_result'
    && event.producer_kind === SIGNED_PRODUCER);
  const event = latestBy(events, 'timestamp');
  if (!event) return notSigned('signed_result_missing');
  const verdict = latestBy((evidence.verdicts ?? []).filter((row) => row.test_run_id === run.id), 'created_at');
  const source = typeof options.resolveSourcePerspective === 'function'
    ? options.resolveSourcePerspective(job.leased_by)
    : event.source_perspective ?? job.worker_metadata?.source_perspective ?? run.provenance?.source_perspective ?? null;
  const built = attempt(() => normalizeEvidenceReference({
    test_run_id: run.id,
    check_id: run.check_id,
    check_version: run.check_version ?? null,
    scenario_version: run.scenario_version ?? null,
    verdict_id: verdict?.id ?? null,
    evidence_ids: verdict?.evidence_ids ?? [],
    target_id: run.target_id,
    observed_at: event.timestamp,
    run_status: run.status,
    source_perspective: source,
    worker_id: job.leased_by,
  }));
  if (built.failure) return { ...built.failure, field: 'test_run_ids' };
  const port = Number.isInteger(job.target?.port) ? job.target.port : (Number.isInteger(job.probe_profile?.port) ? job.probe_profile.port : null);
  return { reference: built.value, protocol: firewallProtocolForCheck(run.check_id), port };
}

export function runMatchesFirewallExpectation(built, expectation) {
  const ref = built.reference;
  if (ref.target_id !== baselineTargetForExpectation(expectation)) return false;
  if (ref.source_perspective !== expectation.source_perspective) return false;
  if (built.protocol !== expectation.protocol) return false;
  if (built.port != null && built.port !== expectationPort(expectation)) return false;
  return true;
}

function maxObservedAt(references) {
  return references.map((ref) => ref.observed_at).sort().at(-1);
}

export function presentEntryPath(row, authorization = null) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    anchor_target_id: row.anchor_target_id,
    entry_target_id: row.entry_target_id,
    relation_kind: row.relation_kind,
    owner: row.owner,
    purpose: row.purpose,
    expected_behavior: row.expected_behavior,
    required_layers: [...(row.required_layers ?? [])],
    origin_binding_id: row.origin_binding_id ?? null,
    status: row.status,
    declaration_source: row.declaration_source ?? 'explicit',
    declaration_version: row.declaration_version,
    declaration_digest: row.declaration_digest,
    contract_version: row.contract_version,
    digest_verified: entryPathDeclarationDigest(row) === row.declaration_digest,
    currently_authorized: authorization?.authorized === true,
    authorization_state: authorization?.state ?? null,
    authorization_reason: authorization?.reason ?? null,
    created_at: row.created_at,
    created_by: row.created_by ?? null,
    archived_at: row.archived_at ?? null,
    archived_by: row.archived_by ?? null,
  };
}

export function presentExpectation(row) {
  if (!row) return null;
  const common = {
    id: row.id,
    tenant_id: row.tenant_id,
    kind: row.kind,
    status: row.status,
    expectation_version: row.expectation_version,
    digest: row.digest,
    digest_verified: expectationDigest(row) === row.digest,
    contract_version: row.contract_version,
    owner: row.owner ?? null,
    created_at: row.created_at,
    created_by: row.created_by ?? null,
    archived_at: row.archived_at ?? null,
    archived_by: row.archived_by ?? null,
  };
  if (row.kind === 'path_validation') {
    return { ...common, anchor_target_id: row.anchor_target_id, scenario: row.scenario, layer_outcomes: { ...row.layer_outcomes } };
  }
  return {
    ...common,
    destination_target_id: row.destination_target_id,
    protocol: row.protocol,
    port: row.port ?? null,
    service_endpoint: row.service_endpoint ? { ...row.service_endpoint } : null,
    expected: row.expected,
    source_perspective: row.source_perspective,
    change_id: row.change_id,
    pre_post_mapping: row.pre_post_mapping ? { ...row.pre_post_mapping } : null,
  };
}

function presentBaselineEntry(row) {
  return {
    kind: row.kind,
    tenant_id: row.tenant_id,
    anchor_target_id: row.anchor_target_id ?? null,
    entry_path_id: row.entry_path_id ?? null,
    expectation_id: row.expectation_id,
    expectation_version: row.expectation_version,
    expectation_digest: row.expectation_digest,
    declaration_digest: row.declaration_digest ?? null,
    target_id: row.target_id,
    destination_mapping: row.destination_mapping ? { ...row.destination_mapping } : null,
    references: (row.references ?? []).map((ref) => ({ ...ref, evidence_ids: [...(ref.evidence_ids ?? [])] })),
    captured_at: row.captured_at,
    freshness_window_seconds: row.freshness_window_seconds,
    contract_version: row.contract_version,
    immutable: true,
    baseline_digest: row.baseline_digest,
    ...(row.observations_digest ? {
      classifier_version: row.classifier_version ?? null,
      observations: (row.observations ?? []).map((obs) => ({ ...obs })),
      observations_digest: row.observations_digest,
    } : {}),
  };
}

export function presentBaselineCapture(rows) {
  if (!rows?.length) return null;
  const ordered = [...rows].sort((left, right) => left.capture_index - right.capture_index);
  const head = ordered[0];
  const entries = ordered.map(presentBaselineEntry);
  const entriesVerified = entries.every((entry) => verifyBaselineDigest(entry));
  const meta = {
    status: head.status,
    created_at: head.created_at,
    created_by: head.created_by ?? null,
    archived_at: head.archived_at ?? null,
  };
  if (head.kind === 'path_validation') {
    return { id: head.id, ...entries[0], declaration_version: head.declaration_version ?? null, ...meta, digest_verified: entriesVerified };
  }
  const capture = {
    contract_version: head.contract_version,
    kind: head.kind,
    tenant_id: head.tenant_id,
    change_id: head.change_id,
    captured_at: head.capture_captured_at,
    freshness_window_seconds: head.freshness_window_seconds,
    entries,
    immutable: true,
    baseline_digest: head.capture_digest,
  };
  const verified = entriesVerified
    && ordered.length === head.entry_count
    && firewallBaselineCaptureDigest(capture) === capture.baseline_digest;
  return {
    id: head.id,
    kind: capture.kind,
    tenant_id: capture.tenant_id,
    change_id: capture.change_id,
    captured_at: capture.captured_at,
    freshness_window_seconds: capture.freshness_window_seconds,
    immutable: true,
    baseline_digest: capture.baseline_digest,
    contract_version: capture.contract_version,
    entry_count: entries.length,
    entries,
    ...meta,
    digest_verified: verified,
  };
}

export function presentEvaluation(row) {
  if (!row) return null;
  const out = {
    id: row.id,
    kind: row.kind,
    tenant_id: row.tenant_id,
    baseline_id: row.baseline_id ?? null,
    baseline_digest: row.baseline_digest ?? null,
    anchor_target_id: row.anchor_target_id ?? null,
    primary_entry_path_id: row.primary_entry_path_id ?? null,
    reviewed_plan_digest: row.reviewed_plan_digest ?? null,
    change_id: row.change_id ?? null,
    compatibility: { ...row.compatibility, reasons: [...(row.compatibility?.reasons ?? [])] },
    summary: row.summary,
    limitations: [...(row.limitations ?? [])],
    evaluated_at: row.evaluated_at,
    evaluation_digest: row.evaluation_digest,
    contract_version: row.contract_version,
    created_at: row.created_at,
    created_by: row.created_by ?? null,
  };
  const provenance = row.provenance && typeof row.provenance === 'object' ? row.provenance : {};
  if (provenance.expectation_id) out.expectation_id = provenance.expectation_id;
  if (provenance.comparison_id) out.comparison_id = provenance.comparison_id;
  for (const field of PRESENTED_EVALUATION_PROVENANCE) {
    if (provenance[field] !== undefined) out[field] = provenance[field];
  }
  out.items = row.items;
  out.digest_verified = comparisonEvaluationDigest(row) === row.evaluation_digest;
  return out;
}

const PRESENTED_EVALUATION_PROVENANCE = Object.freeze([
  'post_test_run_ids', 'classifier_version', 'readiness_effect', 'observations', 'observations_truncated', 'statement',
]);
const MAX_EVALUATION_PROVENANCE_BYTES = 15_000;

/** Bounded additive provenance for an evaluation; oversize detail is dropped with an explicit marker. */
export function boundedEvaluationProvenance(extra = {}) {
  const out = {};
  for (const [key, value] of Object.entries(extra ?? {})) {
    if (value !== undefined) out[key] = value;
  }
  const size = (value) => Buffer.byteLength(JSON.stringify(value));
  if (size(out) > MAX_EVALUATION_PROVENANCE_BYTES && out.observations !== undefined) {
    delete out.observations;
    out.observations_truncated = true;
  }
  if (size(out) > MAX_EVALUATION_PROVENANCE_BYTES && out.statement !== undefined) {
    out.statement = { headline: out.statement?.headline ?? null, readiness_effect: out.statement?.readiness_effect ?? 'none', truncated: true };
  }
  return size(out) > MAX_EVALUATION_PROVENANCE_BYTES ? { observations_truncated: true } : out;
}

function decodePageCursor(cursor) {
  if (cursor == null || cursor === '') return { cursor: null };
  const decoded = decodeKeysetCursor(cursor);
  const createdAt = decoded && !decoded.legacy ? normalizeObservationTimestamp(decoded.created_at) : null;
  if (!createdAt) return { failure: error('invalid_cursor', 400, { field: 'cursor' }) };
  return { cursor: { created_at: createdAt, id: decoded.id } };
}

function pageLimit(value) {
  return clampPageLimit(value, { max: PROTECTION_VALIDATION_PAGE_LIMIT.max, fallback: PROTECTION_VALIDATION_PAGE_LIMIT.default });
}

function pageEnvelope(rows, limit, present) {
  const page = rows.slice(0, limit);
  const last = page.at(-1);
  return {
    items: page.map(present),
    count: page.length,
    next_cursor: rows.length > limit && last ? encodeKeysetCursor({ created_at: last.created_at, id: last.id }) : null,
  };
}

function enumFilter(value, allowed, field) {
  if (value == null || value === '') return { value: null };
  if (!allowed.includes(value)) return { failure: error('invalid_query', 400, { field }) };
  return { value };
}

function idFilter(value, field) {
  if (value == null || value === '') return { value: null };
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:#/-]{0,127}$/.test(value)) return { failure: error('invalid_query', 400, { field }) };
  return { value };
}

function resolveWriteConflict(rows, record, digestField, conflictCode, idempotencyKey) {
  const keyed = idempotencyKey ? rows.find((row) => row.idempotency_key === idempotencyKey) : null;
  if (keyed) {
    return keyed[digestField] === record[digestField] ? { row: keyed, replayed: true } : error('idempotency_conflict', 409, { existing_id: keyed.id });
  }
  const active = rows.find((row) => row.status === 'active');
  if (active && active[digestField] === record[digestField]) return { row: active, replayed: true };
  return error(conflictCode, 409, { existing_id: active?.id ?? null });
}

function nextVersion(rows, field) {
  return rows.reduce((max, row) => Math.max(max, Number(row[field]) || 0), 0) + 1;
}

/** Same rules for the dev store and Postgres; `backend` supplies tenant-scoped storage only. */
export function createProtectionValidationService({ backend, approvedSourcePerspectives = null, resolveSourcePerspective = null } = {}) {
  if (!backend) throw new Error('protection validation backend is required.');
  const approvedSources = Array.isArray(approvedSourcePerspectives) ? new Set(approvedSourcePerspectives) : null;

  async function targetContext(ctx, ids) {
    const unique = [...new Set(ids.filter(Boolean))];
    if (!unique.length) return { byId: new Map(), records: { targets: [], targetVerifications: [], wafConnectors: [], wafConnectorSnapshots: [] } };
    const loaded = await backend.loadTargetContext(ctx, unique);
    const byId = new Map(loaded.targets.filter((row) => row.tenant_id === ctx.tenantId).map((row) => [row.id, row]));
    return { byId, records: loaded.records };
  }

  function proofFor(ctx, context, targetId) {
    return currentOriginProof(context.records, ctx.tenantId, targetId);
  }

  async function bindingById(ctx, id) {
    if (!id) return null;
    const rows = await backend.getOriginBindings(ctx, [id]);
    return rows.find((row) => row.tenant_id === ctx.tenantId && row.id === id) ?? null;
  }

  function relationAuthorization(ctx, relation, context, binding) {
    const anchorTarget = context.byId.get(relation.anchor_target_id) ?? null;
    const entryTarget = context.byId.get(relation.entry_target_id) ?? null;
    const anchorProof = anchorTarget ? proofFor(ctx, context, anchorTarget.id) : null;
    const entryProof = entryTarget ? proofFor(ctx, context, entryTarget.id) : null;
    const exec = entryPathAuthorizesExecution(relation, { anchorTarget, entryTarget, originBinding: binding, tenantId: ctx.tenantId });
    const state = entryProof && !entryProof.verified ? entryProof.state : (anchorProof && !anchorProof.verified ? anchorProof.state : entryProof?.state ?? null);
    if (!exec.ok) return { authorized: false, state, reason: exec.error, field: exec.field ?? null, status: exec.status };
    if (!anchorProof?.verified) return { authorized: false, state: anchorProof?.state ?? null, reason: 'ownership_not_verified', field: 'anchor_target_id', status: 409 };
    if (!entryProof?.verified) return { authorized: false, state: entryProof?.state ?? null, reason: 'ownership_not_verified', field: 'entry_target_id', status: 409 };
    return { authorized: true, state: entryProof.state, reason: null, anchorTarget, entryTarget };
  }

  async function presentRelations(ctx, rows) {
    const context = await targetContext(ctx, rows.flatMap((row) => [row.anchor_target_id, row.entry_target_id]));
    const bindingIds = [...new Set(rows.map((row) => row.origin_binding_id).filter(Boolean))];
    const bindings = bindingIds.length ? await backend.getOriginBindings(ctx, bindingIds) : [];
    const bindingMap = new Map(bindings.filter((row) => row.tenant_id === ctx.tenantId).map((row) => [row.id, row]));
    return rows.map((row) => ({
      ...presentEntryPath(row, relationAuthorization(ctx, row, context, bindingMap.get(row.origin_binding_id) ?? null)),
      entry_target_value: context.byId.get(row.entry_target_id)?.value ?? null,
    }));
  }

  function requireActiveTarget(context, targetId, field) {
    const target = context.byId.get(targetId);
    if (!target) return error('unknown_target', 404, { field });
    if (!targetActive(target)) return error('target_not_active', 409, { field });
    return null;
  }

  async function createEntryPath(ctx, anchorTargetId, body = {}, options = {}) {
    const denied = gate(ctx, [P.declaration_write], 'application_entry_path', options);
    if (denied) return denied;
    const draft = attempt(() => normalizeEntryPathDeclaration(body, { tenantId: ctx.tenantId, anchorTargetId }));
    if (draft.failure) return draft.failure;
    const idempotency = normalizeIdempotencyKey(options.idempotencyKey);
    if (idempotency.failure) return idempotency.failure;
    const context = await targetContext(ctx, [draft.value.anchor_target_id, draft.value.entry_target_id]);
    const binding = await bindingById(ctx, draft.value.origin_binding_id);
    const refs = validateEntryPathReferences({
      tenantId: ctx.tenantId,
      relation: draft.value,
      anchorTarget: context.byId.get(draft.value.anchor_target_id) ?? null,
      entryTarget: context.byId.get(draft.value.entry_target_id) ?? null,
      originBinding: binding,
    });
    if (!refs.ok) return error(refs.error, refs.status, { field: refs.field });
    const scopeRows = await backend.listEntryPathsByScope(ctx, draft.value);
    const active = scopeRows.find((row) => row.status === 'active');
    const version = active ? active.declaration_version : nextVersion(scopeRows, 'declaration_version');
    const record = normalizeEntryPathDeclaration(body, { tenantId: ctx.tenantId, anchorTargetId, declarationVersion: version });
    if (idempotency.key) {
      const keyed = await backend.findEntryPathByIdempotencyKey(ctx, idempotency.key);
      if (keyed) {
        if (keyed.declaration_digest !== record.declaration_digest) return error('idempotency_conflict', 409, { existing_id: keyed.id });
        return { ...(await presentRelations(ctx, [keyed]))[0], replayed: true };
      }
    }
    const classified = classifyEntryPathWrite(scopeRows, record);
    if (classified.action === 'replay') return { ...(await presentRelations(ctx, [classified.existing]))[0], replayed: true };
    if (classified.action === 'conflict') return error('entry_path_conflict', 409, { existing_id: classified.existing.id });
    const row = {
      ...record,
      id: newRecordId('ep'),
      provenance: {},
      idempotency_key: idempotency.key,
      created_at: stamp(options),
      created_by: actor(ctx, options),
      archived_at: null,
      archived_by: null,
    };
    const entry = auditEntry(ctx, A.entry_path_created, 'application_entry_path', row.id, {
      anchor_target_id: row.anchor_target_id,
      entry_target_id: row.entry_target_id,
      relation_kind: row.relation_kind,
      expected_behavior: row.expected_behavior,
      required_layers: row.required_layers,
      origin_binding_id: row.origin_binding_id,
      declaration_version: row.declaration_version,
      declaration_digest: row.declaration_digest,
    }, options);
    const stored = await backend.insertEntryPath(ctx, row, entry);
    if (stored.conflictRows) {
      const resolved = resolveWriteConflict(stored.conflictRows, row, 'declaration_digest', 'entry_path_conflict', idempotency.key);
      if (resolved.error) return resolved;
      return { ...(await presentRelations(ctx, [resolved.row]))[0], replayed: true };
    }
    return { ...(await presentRelations(ctx, [stored.row]))[0], replayed: false };
  }

  async function getEntryPath(ctx, id) {
    const denied = gate(ctx, [P.declaration_read], 'application_entry_path');
    if (denied) return denied;
    const row = await backend.getEntryPath(ctx, id);
    if (!row) return error('not_found', 404);
    return (await presentRelations(ctx, [row]))[0];
  }

  async function listEntryPaths(ctx, targetId, query = {}) {
    const denied = gate(ctx, [P.declaration_read], 'application_entry_path');
    if (denied) return denied;
    const status = enumFilter(query.status, RECORD_STATUSES, 'status');
    if (status.failure) return status.failure;
    const kind = enumFilter(query.relation_kind, ENTRY_PATH_RELATION_KINDS, 'relation_kind');
    if (kind.failure) return kind.failure;
    const cursor = decodePageCursor(query.cursor);
    if (cursor.failure) return cursor.failure;
    const context = await targetContext(ctx, [targetId]);
    if (!context.byId.get(targetId)) return error('unknown_target', 404, { field: 'targetId' });
    const limit = pageLimit(query.limit);
    const rows = await backend.listEntryPaths(ctx, {
      target_id: targetId,
      status: status.value,
      relation_kind: kind.value,
      cursor: cursor.cursor,
      limit: limit + 1,
    });
    const page = rows.slice(0, limit);
    const presented = await presentRelations(ctx, page);
    const byId = new Map(presented.map((row) => [row.id, row]));
    return pageEnvelope(rows, limit, (row) => byId.get(row.id));
  }

  async function archiveEntryPath(ctx, id, options = {}) {
    const denied = gate(ctx, [P.declaration_write], 'application_entry_path', options);
    if (denied) return denied;
    const row = await backend.getEntryPath(ctx, id);
    if (!row) return error('not_found', 404);
    if (row.status !== 'active') return error('already_archived', 409);
    const patch = { archived_at: stamp(options), archived_by: actor(ctx, options) };
    const entry = auditEntry(ctx, A.entry_path_archived, 'application_entry_path', id, {
      anchor_target_id: row.anchor_target_id,
      entry_target_id: row.entry_target_id,
      relation_kind: row.relation_kind,
      declaration_version: row.declaration_version,
      declaration_digest: row.declaration_digest,
    }, options);
    const stored = await backend.archiveEntryPath(ctx, id, patch, entry);
    if (!stored) return error('already_archived', 409);
    return (await presentRelations(ctx, [stored]))[0];
  }

  /** Execution-time gate: archived relations, changed digests, deleted targets, and lapsed ownership never authorize. */
  async function authorizeEntryPathForExecution(ctx, id) {
    if (!ctx?.tenantId) return error('invalid_tenant', 400);
    const relation = await backend.getEntryPath(ctx, id);
    if (!relation) return error('not_found', 404);
    const context = await targetContext(ctx, [relation.anchor_target_id, relation.entry_target_id]);
    const binding = await bindingById(ctx, relation.origin_binding_id);
    const auth = relationAuthorization(ctx, relation, context, binding);
    if (!auth.authorized) return error(auth.reason, auth.status ?? 409, { field: auth.field ?? null, ownership_state: auth.state ?? null });
    return {
      ok: true,
      relation: presentEntryPath(relation, auth),
      anchor_target: auth.anchorTarget,
      entry_target: auth.entryTarget,
      origin_binding: binding,
    };
  }

  async function createFirewallExpectation(ctx, body = {}, options = {}) {
    const denied = gate(ctx, [P.declaration_write], 'firewall_expectation', options);
    if (denied) return denied;
    const draft = attempt(() => normalizeFirewallExpectation(body, { tenantId: ctx.tenantId }));
    if (draft.failure) return draft.failure;
    if (approvedSources && !approvedSources.has(draft.value.source_perspective)) {
      return error('invalid_firewall_expectation', 400, { field: 'source_perspective', message: 'source_perspective is not an approved source.' });
    }
    const idempotency = normalizeIdempotencyKey(options.idempotencyKey);
    if (idempotency.failure) return idempotency.failure;
    const mapping = draft.value.pre_post_mapping;
    const context = await targetContext(ctx, [draft.value.destination_target_id, mapping?.pre_destination_target_id, mapping?.post_destination_target_id]);
    for (const [targetId, field] of [
      [draft.value.destination_target_id, 'destination_target_id'],
      [mapping?.pre_destination_target_id, 'pre_post_mapping.pre_destination_target_id'],
      [mapping?.post_destination_target_id, 'pre_post_mapping.post_destination_target_id'],
    ]) {
      if (!targetId) continue;
      const invalid = requireActiveTarget(context, targetId, field);
      if (invalid) return invalid;
    }
    const scopeKey = firewallExpectationScopeKey(draft.value);
    const scopeRows = await backend.listExpectationsByScope(ctx, 'firewall_change', scopeKey);
    const active = scopeRows.find((row) => row.status === 'active');
    const version = active ? active.expectation_version : nextVersion(scopeRows, 'expectation_version');
    const record = normalizeFirewallExpectation(body, { tenantId: ctx.tenantId, expectationVersion: version });
    if (idempotency.key) {
      const keyed = await backend.findExpectationByIdempotencyKey(ctx, idempotency.key);
      if (keyed) {
        if (keyed.digest !== record.digest) return error('idempotency_conflict', 409, { existing_id: keyed.id });
        return { ...presentExpectation(keyed), replayed: true };
      }
    }
    const classified = classifyFirewallExpectationWrite(scopeRows, record);
    if (classified.action === 'replay') return { ...presentExpectation(classified.existing), replayed: true };
    if (classified.action === 'conflict') return error('firewall_expectation_conflict', 409, { existing_id: classified.existing.id });
    const row = {
      ...record,
      id: newRecordId('fwx'),
      scope_key: scopeKey,
      provenance: {},
      idempotency_key: idempotency.key,
      created_at: stamp(options),
      created_by: actor(ctx, options),
      archived_at: null,
      archived_by: null,
    };
    const entry = auditEntry(ctx, A.firewall_expectation_created, 'firewall_expectation', row.id, {
      change_id: row.change_id,
      destination_target_id: row.destination_target_id,
      protocol: row.protocol,
      port: row.port,
      service: row.service_endpoint?.service ?? null,
      expected: row.expected,
      source_perspective: row.source_perspective,
      expectation_version: row.expectation_version,
      digest: row.digest,
    }, options);
    const stored = await backend.insertExpectation(ctx, row, entry, {});
    if (stored.conflictRows) {
      const resolved = resolveWriteConflict(stored.conflictRows, row, 'digest', 'firewall_expectation_conflict', idempotency.key);
      if (resolved.error) return resolved;
      return { ...presentExpectation(resolved.row), replayed: true };
    }
    return { ...presentExpectation(stored.row), replayed: false };
  }

  /** Server-internal: a changed path expectation becomes a new version; older baselines keep the version they pinned. */
  async function recordPathValidationExpectation(ctx, body = {}, options = {}) {
    const denied = gate(ctx, [P.run_start, P.declaration_write], 'path_validation_expectation', options);
    if (denied) return denied;
    const draft = attempt(() => normalizePathValidationExpectation(body, { tenantId: ctx.tenantId }));
    if (draft.failure) return draft.failure;
    const context = await targetContext(ctx, [draft.value.anchor_target_id]);
    const invalid = requireActiveTarget(context, draft.value.anchor_target_id, 'anchor_target_id');
    if (invalid) return invalid;
    const scopeKey = pathValidationExpectationScopeKey(draft.value);
    const scopeRows = await backend.listExpectationsByScope(ctx, 'path_validation', scopeKey);
    const active = scopeRows.find((row) => row.status === 'active');
    if (active) {
      const same = normalizePathValidationExpectation(body, { tenantId: ctx.tenantId, expectationVersion: active.expectation_version });
      if (same.digest === active.digest) return { ...presentExpectation(active), replayed: true };
    }
    const record = normalizePathValidationExpectation(body, { tenantId: ctx.tenantId, expectationVersion: nextVersion(scopeRows, 'expectation_version') });
    const now = stamp(options);
    const row = {
      ...record,
      id: newRecordId('pvx'),
      scope_key: scopeKey,
      status: 'active',
      owner: null,
      provenance: {},
      idempotency_key: null,
      created_at: now,
      created_by: actor(ctx, options),
      archived_at: null,
      archived_by: null,
    };
    const entry = auditEntry(ctx, X.path_validation_expectation_recorded, 'path_validation_expectation', row.id, {
      anchor_target_id: row.anchor_target_id,
      scenario: row.scenario,
      expectation_version: row.expectation_version,
      digest: row.digest,
      superseded_id: active?.id ?? null,
    }, options);
    const stored = await backend.insertExpectation(ctx, row, entry, {
      supersede: active ? { id: active.id, archived_at: now, archived_by: actor(ctx, options) } : null,
    });
    if (stored.conflictRows) {
      const winner = stored.conflictRows.find((candidate) => candidate.status === 'active');
      if (winner && normalizePathValidationExpectation(body, { tenantId: ctx.tenantId, expectationVersion: winner.expectation_version }).digest === winner.digest) {
        return { ...presentExpectation(winner), replayed: true };
      }
      return error('invalid_behavior_expectation', 409, { field: 'expectation', message: 'A concurrent expectation change won; retry with the current expectation.' });
    }
    return { ...presentExpectation(stored.row), replayed: false };
  }

  async function getExpectation(ctx, id, options = {}) {
    const denied = gate(ctx, [P.declaration_read], 'protection_expectation');
    if (denied) return denied;
    const row = await backend.getExpectation(ctx, id);
    if (!row || (options.kind && row.kind !== options.kind)) return error('not_found', 404);
    return presentExpectation(row);
  }

  async function listExpectations(ctx, query = {}) {
    const denied = gate(ctx, [P.declaration_read], 'protection_expectation');
    if (denied) return denied;
    const kind = enumFilter(query.kind ?? 'firewall_change', COMPARISON_KINDS, 'kind');
    if (kind.failure) return kind.failure;
    const status = enumFilter(query.status, RECORD_STATUSES, 'status');
    if (status.failure) return status.failure;
    const filters = {};
    for (const field of ['change_id', 'destination_target_id', 'anchor_target_id']) {
      const parsed = idFilter(query[field], field);
      if (parsed.failure) return parsed.failure;
      filters[field] = parsed.value;
    }
    const cursor = decodePageCursor(query.cursor);
    if (cursor.failure) return cursor.failure;
    const limit = pageLimit(query.limit);
    const rows = await backend.listExpectations(ctx, { ...filters, kind: kind.value, status: status.value, cursor: cursor.cursor, limit: limit + 1 });
    return pageEnvelope(rows, limit, presentExpectation);
  }

  async function archiveExpectation(ctx, id, options = {}) {
    const denied = gate(ctx, [P.declaration_write], 'protection_expectation', options);
    if (denied) return denied;
    const row = await backend.getExpectation(ctx, id);
    if (!row || (options.kind && row.kind !== options.kind)) return error('not_found', 404);
    if (row.status !== 'active') return error('already_archived', 409);
    const firewall = row.kind === 'firewall_change';
    const entry = auditEntry(ctx, firewall ? A.firewall_expectation_archived : X.path_validation_expectation_archived,
      firewall ? 'firewall_expectation' : 'path_validation_expectation', id, {
        kind: row.kind,
        change_id: row.change_id ?? null,
        expectation_version: row.expectation_version,
        digest: row.digest,
      }, options);
    const stored = await backend.archiveExpectation(ctx, id, { archived_at: stamp(options), archived_by: actor(ctx, options) }, entry);
    if (!stored) return error('already_archived', 409);
    return presentExpectation(stored);
  }

  async function buildReferences(ctx, runIds) {
    const evidence = await backend.loadRunEvidence(ctx, runIds);
    const runs = new Map(evidence.runs.filter((run) => run.tenant_id === ctx.tenantId).map((run) => [run.id, run]));
    const built = [];
    for (const runId of runIds) {
      const run = runs.get(runId);
      if (!run) return { failure: error('not_found', 404, { field: 'test_run_ids' }) };
      const reference = buildRunEvidenceReference(run, evidence, { resolveSourcePerspective });
      if (reference.error) return { failure: reference };
      if (!reference.reference.source_perspective || !reference.reference.worker_id) {
        return { failure: error('invalid_comparison_baseline', 400, { field: 'test_run_ids', message: `Run ${runId} has no recorded source/worker identity.` }) };
      }
      if (approvedSources && !approvedSources.has(reference.reference.source_perspective)) {
        return { failure: error('invalid_comparison_baseline', 400, { field: 'test_run_ids', message: `Run ${runId} came from a source that is not approved.` }) };
      }
      built.push(reference);
    }
    return { built };
  }

  /** Server-internal: finalized signed references for explicitly selected runs, used to build comparison candidates. */
  async function resolveRunEvidence(ctx, runIds = [], options = {}) {
    const denied = gate(ctx, [P.evidence_read], 'comparison_evidence', options);
    if (denied) return denied;
    const ids = Array.isArray(runIds) ? [...new Set(runIds)].sort() : [];
    if (!ids.length || ids.length > MAX_EVIDENCE_REFERENCES) return error('invalid_comparison_request', 400, { field: 'test_run_ids' });
    const references = await buildReferences(ctx, ids);
    if (references.failure) return references.failure;
    return { items: references.built.map((built) => ({ reference: built.reference, protocol: built.protocol, port: built.port })) };
  }

  async function verifiedBaselineTargets(ctx, targetIds, field) {
    const context = await targetContext(ctx, targetIds);
    for (const targetId of targetIds) {
      const invalid = requireActiveTarget(context, targetId, field);
      if (invalid) return invalid;
      const proof = proofFor(ctx, context, targetId);
      if (!proof.verified) return error('ownership_not_verified', 409, { field, ownership_state: proof.state });
    }
    return null;
  }

  async function storeCapture(ctx, rows, entry, key, kindOption) {
    const stored = await backend.insertBaselineCapture(ctx, rows, entry);
    if (stored.error) return stored;
    const captureId = stored.replayed ? (await backend.findBaselineCaptureIdByKey(ctx, key)) ?? stored.capture_id : stored.capture_id;
    const capture = presentBaselineCapture(await backend.getBaselineCaptureRows(ctx, captureId));
    if (!capture || (kindOption && capture.kind !== kindOption)) return error('invalid_comparison_baseline', 409);
    return { ...capture, replayed: stored.replayed === true };
  }

  async function captureFirewallBaseline(ctx, body = {}, options = {}) {
    const denied = gate(ctx, [P.declaration_write], 'firewall_baseline', options);
    if (denied) return denied;
    const request = attempt(() => normalizeFirewallBaselineRequest(body));
    if (request.failure) return request.failure;
    const req = request.value;
    const key = `capture:${sha256Digest({ tenant_id: ctx.tenantId, ...req })}`;
    const existingId = await backend.findBaselineCaptureIdByKey(ctx, key);
    if (existingId) {
      const capture = presentBaselineCapture(await backend.getBaselineCaptureRows(ctx, existingId));
      if (capture) return { ...capture, replayed: true };
    }
    const expectations = await backend.getExpectations(ctx, req.expectation_ids);
    const byId = new Map(expectations.filter((row) => row.tenant_id === ctx.tenantId).map((row) => [row.id, row]));
    for (const id of req.expectation_ids) {
      const expectation = byId.get(id);
      if (!expectation || expectation.kind !== 'firewall_change') return error('not_found', 404, { field: 'expectation_ids' });
      if (expectation.status !== 'active') return error('invalid_comparison_baseline', 409, { field: 'expectation_ids', message: `Expectation ${id} is archived.` });
      if (expectation.change_id !== req.change_id) return error('invalid_comparison_request', 400, { field: 'change_id', message: `Expectation ${id} belongs to another change.` });
      if (expectationDigest(expectation) !== expectation.digest) return error('invalid_comparison_baseline', 409, { field: 'expectation_ids', message: `Expectation ${id} failed digest verification.` });
    }
    const selected = req.expectation_ids.map((id) => byId.get(id));
    const targetFailure = await verifiedBaselineTargets(ctx, [...new Set(selected.map(baselineTargetForExpectation))], 'expectation_ids');
    if (targetFailure) return targetFailure;
    const references = await buildReferences(ctx, req.test_run_ids);
    if (references.failure) return references.failure;
    const assigned = new Map(selected.map((expectation) => [expectation.id, []]));
    for (const built of references.built) {
      const matches = selected.filter((expectation) => runMatchesFirewallExpectation(built, expectation));
      const runId = built.reference.test_run_id;
      if (!matches.length) {
        return error('invalid_comparison_baseline', 400, { field: 'test_run_ids', message: `Run ${runId} does not match a selected expectation's destination, source, protocol, or port.` });
      }
      if (matches.length > 1) {
        return error('invalid_comparison_baseline', 400, { field: 'test_run_ids', message: `Run ${runId} matches several selected expectations; capture them separately.` });
      }
      assigned.get(matches[0].id).push(built.reference);
    }
    for (const [id, refs] of assigned) {
      if (!refs.length) return error('invalid_comparison_baseline', 400, { field: 'expectation_ids', message: `No finalized evidence was selected for expectation ${id}.` });
      if (refs.length > MAX_EVIDENCE_REFERENCES) return error('invalid_comparison_baseline', 400, { field: 'test_run_ids' });
    }
    const capturedAt = stamp(options);
    const capture = attempt(() => normalizeFirewallBaselineCapture({
      change_id: req.change_id,
      captured_at: isoMillis(capturedAt),
      freshness_window_seconds: req.freshness_window_seconds,
      entries: selected.map((expectation) => ({
        kind: 'firewall_change',
        tenant_id: ctx.tenantId,
        expectation_id: expectation.id,
        expectation_version: expectation.expectation_version,
        expectation_digest: expectation.digest,
        declaration_digest: null,
        target_id: baselineTargetForExpectation(expectation),
        destination_mapping: expectation.pre_post_mapping ?? null,
        references: assigned.get(expectation.id),
        captured_at: maxObservedAt(assigned.get(expectation.id)),
      })),
    }));
    if (capture.failure) return capture.failure;
    const captureId = newRecordId('fwb');
    const rows = capture.value.entries.map((entry, index) => ({
      ...entry,
      id: index === 0 ? captureId : `${captureId}.${index}`,
      capture_id: captureId,
      capture_index: index,
      capture_digest: capture.value.baseline_digest,
      capture_captured_at: capture.value.captured_at,
      change_id: req.change_id,
      entry_count: capture.value.entries.length,
      declaration_version: null,
      status: 'active',
      idempotency_key: index === 0 ? key : null,
      created_at: capturedAt,
      created_by: actor(ctx, options),
      archived_at: null,
      archived_by: null,
    }));
    const entry = auditEntry(ctx, A.firewall_baseline_captured, 'firewall_baseline', captureId, {
      change_id: req.change_id,
      expectation_ids: req.expectation_ids,
      test_run_ids: req.test_run_ids,
      baseline_digest: capture.value.baseline_digest,
      entry_count: rows.length,
    }, options);
    return storeCapture(ctx, rows, entry, key, 'firewall_change');
  }

  /** Server-internal: pins the relation declaration and expectation version/digest for one entry path. */
  async function capturePathValidationBaseline(ctx, input = {}, options = {}) {
    const denied = gate(ctx, [P.run_start], 'path_validation_baseline', options);
    if (denied) return denied;
    const runIds = Array.isArray(input.test_run_ids) ? [...new Set(input.test_run_ids)].sort() : [];
    if (!runIds.length || runIds.length > MAX_EVIDENCE_REFERENCES) return error('invalid_comparison_request', 400, { field: 'test_run_ids' });
    const relation = await backend.getEntryPath(ctx, input.entry_path_id);
    if (!relation) return error('not_found', 404, { field: 'entry_path_id' });
    const authorized = await authorizeEntryPathForExecution(ctx, relation.id);
    if (authorized.error) return authorized;
    const expectation = await backend.getExpectation(ctx, input.expectation_id);
    if (!expectation || expectation.kind !== 'path_validation') return error('not_found', 404, { field: 'expectation_id' });
    if (expectation.status !== 'active') return error('invalid_comparison_baseline', 409, { field: 'expectation_id', message: 'Expectation is archived.' });
    if (expectation.anchor_target_id !== relation.anchor_target_id) return error('invalid_comparison_baseline', 409, { field: 'expectation_id', message: 'Expectation belongs to another anchor.' });
    if (expectationDigest(expectation) !== expectation.digest) return error('invalid_comparison_baseline', 409, { field: 'expectation_id' });
    const references = await buildReferences(ctx, runIds);
    if (references.failure) return references.failure;
    const refs = references.built.map((built) => built.reference);
    const offTarget = refs.find((ref) => ref.target_id !== relation.entry_target_id);
    if (offTarget) return error('invalid_comparison_baseline', 400, { field: 'test_run_ids', message: `Run ${offTarget.test_run_id} did not observe this entry path target.` });
    const baseline = attempt(() => normalizeComparisonBaseline({
      kind: 'path_validation',
      tenant_id: ctx.tenantId,
      anchor_target_id: relation.anchor_target_id,
      entry_path_id: relation.id,
      expectation_id: expectation.id,
      expectation_version: expectation.expectation_version,
      expectation_digest: expectation.digest,
      declaration_digest: relation.declaration_digest,
      target_id: relation.entry_target_id,
      references: refs,
      captured_at: maxObservedAt(refs),
      freshness_window_seconds: input.freshness_window_seconds ?? undefined,
    }));
    if (baseline.failure) return baseline.failure;
    const key = `pvbase:${baseline.value.baseline_digest}`;
    const id = newRecordId('pvb');
    const row = {
      ...baseline.value,
      id,
      capture_id: id,
      capture_index: 0,
      capture_digest: baseline.value.baseline_digest,
      capture_captured_at: baseline.value.captured_at,
      change_id: null,
      entry_count: 1,
      declaration_version: relation.declaration_version,
      status: 'active',
      idempotency_key: key,
      created_at: stamp(options),
      created_by: actor(ctx, options),
      archived_at: null,
      archived_by: null,
    };
    const existing = await backend.findBaselineCaptureIdByKey(ctx, key);
    if (existing) return { ...presentBaselineCapture(await backend.getBaselineCaptureRows(ctx, existing)), replayed: true };
    const entry = auditEntry(ctx, X.path_validation_baseline_captured, 'path_validation_baseline', id, {
      entry_path_id: relation.id,
      expectation_id: expectation.id,
      expectation_version: expectation.expectation_version,
      declaration_version: relation.declaration_version,
      baseline_digest: row.baseline_digest,
      test_run_ids: runIds,
    }, options);
    return storeCapture(ctx, [row], entry, key, 'path_validation');
  }

  async function getBaselineCapture(ctx, id, options = {}) {
    const denied = gate(ctx, [P.evidence_read], 'comparison_baseline');
    if (denied) return denied;
    const rows = await backend.getBaselineCaptureRows(ctx, id);
    const capture = presentBaselineCapture(rows);
    if (!capture || (options.kind && capture.kind !== options.kind)) return error('not_found', 404);
    return capture;
  }

  async function listBaselineCaptures(ctx, query = {}) {
    const denied = gate(ctx, [P.evidence_read], 'comparison_baseline');
    if (denied) return denied;
    const kind = enumFilter(query.kind ?? 'firewall_change', COMPARISON_KINDS, 'kind');
    if (kind.failure) return kind.failure;
    const status = enumFilter(query.status, RECORD_STATUSES, 'status');
    if (status.failure) return status.failure;
    const filters = {};
    for (const field of ['change_id', 'entry_path_id', 'expectation_id']) {
      const parsed = idFilter(query[field], field);
      if (parsed.failure) return parsed.failure;
      filters[field] = parsed.value;
    }
    const cursor = decodePageCursor(query.cursor);
    if (cursor.failure) return cursor.failure;
    const limit = pageLimit(query.limit);
    const rows = await backend.listBaselineCaptureHeads(ctx, { ...filters, kind: kind.value, status: status.value, cursor: cursor.cursor, limit: limit + 1 });
    const captureIds = rows.slice(0, limit).map((row) => row.capture_id);
    const grouped = new Map(captureIds.map((id) => [id, []]));
    for (const row of captureIds.length ? await backend.getBaselineCaptureRowsByIds(ctx, captureIds) : []) grouped.get(row.capture_id)?.push(row);
    return pageEnvelope(rows, limit, (head) => presentBaselineCapture(grouped.get(head.capture_id)));
  }

  /** Server-internal recorder used by firewall comparison and entry-path comparison finalization. */
  async function recordComparisonEvaluation(ctx, input = {}, options = {}) {
    const kind = input?.kind;
    const permissions = kind === 'path_validation' ? [P.run_start] : [P.declaration_write];
    const denied = gate(ctx, permissions, 'comparison_evaluation', options);
    if (denied) return denied;
    const normalized = attempt(() => normalizeComparisonEvaluation({ ...input, tenant_id: ctx.tenantId }));
    if (normalized.failure) return normalized.failure;
    const evaluation = normalized.value;
    if (evaluation.items.length > MAX_COMPARISON_ITEMS) return error('invalid_comparison_evaluation', 400, { field: 'items' });
    if (evaluation.items.some((item) => item.evidence_refs.length > MAX_EVIDENCE_REFERENCES)) {
      return error('invalid_comparison_evaluation', 400, { field: 'items', message: `Each item may carry at most ${MAX_EVIDENCE_REFERENCES} evidence references.` });
    }
    if (Buffer.byteLength(JSON.stringify(evaluation.items)) > MAX_EVALUATION_ITEMS_JSON_BYTES) {
      return error('invalid_comparison_evaluation', 400, { field: 'items', message: 'Evaluation items are too large.' });
    }
    const reviewedPlanDigest = input.reviewed_plan_digest ?? null;
    if (reviewedPlanDigest != null && !DIGEST_PATTERN.test(String(reviewedPlanDigest))) return error('invalid_comparison_evaluation', 400, { field: 'reviewed_plan_digest' });
    let changeId = null;
    let anchorTargetId = null;
    let primaryEntryPathId = null;
    if (evaluation.kind === 'firewall_change') {
      if (!evaluation.baseline_id) return error('invalid_comparison_evaluation', 400, { field: 'baseline_id' });
      const capture = presentBaselineCapture(await backend.getBaselineCaptureRows(ctx, evaluation.baseline_id));
      if (!capture || capture.kind !== 'firewall_change') return error('not_found', 404, { field: 'baseline_id' });
      if (!capture.digest_verified || capture.baseline_digest !== evaluation.baseline_digest) {
        return error('baseline_not_comparable', 409, { field: 'baseline_digest' });
      }
      const covered = new Set(capture.entries.map((entry) => entry.expectation_id));
      const uncovered = evaluation.items.filter((item) => !covered.has(item.expectation_id));
      if (uncovered.some((item) => item.status !== 'not_tested' || item.evidence_refs.length)) {
        return error('invalid_comparison_evaluation', 400, { field: 'items', message: 'Only untested expectations of the same change may be listed outside the baseline.' });
      }
      if (uncovered.length) {
        const extra = await backend.getExpectations(ctx, uncovered.map((item) => item.expectation_id));
        const sameChange = new Set(extra.filter((row) => row.tenant_id === ctx.tenantId && row.kind === 'firewall_change' && row.change_id === capture.change_id).map((row) => row.id));
        if (uncovered.some((item) => !sameChange.has(item.expectation_id))) {
          return error('invalid_comparison_evaluation', 400, { field: 'items', message: 'Every item must belong to the baseline or its change.' });
        }
      }
      changeId = capture.change_id;
    } else {
      anchorTargetId = input.anchor_target_id ?? null;
      primaryEntryPathId = input.primary_entry_path_id ?? null;
      const context = await targetContext(ctx, [anchorTargetId]);
      if (!anchorTargetId || !context.byId.get(anchorTargetId)) return error('unknown_target', 404, { field: 'anchor_target_id' });
      const pathIds = [...new Set([primaryEntryPathId, ...evaluation.items.map((item) => item.entry_path_id)].filter(Boolean))];
      const paths = new Map((await backend.getEntryPaths(ctx, pathIds)).filter((row) => row.tenant_id === ctx.tenantId).map((row) => [row.id, row]));
      for (const pathId of pathIds) {
        const relation = paths.get(pathId);
        if (!relation) {
          // Reviewed plans retain unknown paths as skipped; they carry no target evidence or execution authority.
          const items = evaluation.items.filter((item) => item.entry_path_id === pathId);
          if (items.length && items.every((item) => item.outcome === 'skipped' && item.evidence_refs.length === 0)) continue;
          return error('not_found', 404, { field: 'entry_path_id' });
        }
        if (relation.anchor_target_id !== anchorTargetId) return error('invalid_comparison_evaluation', 409, { field: 'entry_path_id', message: 'Entry path belongs to another anchor.' });
      }
      if (evaluation.baseline_id && !(await backend.getBaselineCaptureRows(ctx, evaluation.baseline_id)).length) return error('not_found', 404, { field: 'baseline_id' });
    }
    const refs = evaluation.items.flatMap((item) => item.evidence_refs);
    const existing = await backend.existingIds(ctx, {
      runs: [...new Set(refs.map((ref) => ref.test_run_id))],
      verdicts: [...new Set(refs.map((ref) => ref.verdict_id).filter(Boolean))],
      targets: [...new Set(refs.map((ref) => ref.target_id))],
    });
    if (refs.some((ref) => !existing.runs.has(ref.test_run_id) || !existing.targets.has(ref.target_id) || (ref.verdict_id && !existing.verdicts.has(ref.verdict_id)))) {
      return error('not_found', 404, { field: 'items' });
    }
    const idempotency = normalizeIdempotencyKey(options.idempotencyKey);
    if (idempotency.failure) return idempotency.failure;
    if (idempotency.key && typeof backend.findEvaluationByIdempotencyKey === 'function') {
      const keyed = await backend.findEvaluationByIdempotencyKey(ctx, idempotency.key);
      if (keyed) return { ...presentEvaluation(keyed), replayed: true };
    }
    const prior = await backend.findEvaluationByDigest(ctx, evaluation.evaluation_digest);
    if (prior) return { ...presentEvaluation(prior), replayed: true };
    const firewall = evaluation.kind === 'firewall_change';
    const extraProvenance = boundedEvaluationProvenance({
      ...(input.provenance && typeof input.provenance === 'object' && !Array.isArray(input.provenance) ? input.provenance : {}),
      ...(!firewall && input.expectation_id ? { expectation_id: String(input.expectation_id) } : {}),
      ...(!firewall && input.comparison_id ? { comparison_id: String(input.comparison_id) } : {}),
    });
    const row = {
      ...evaluation,
      id: newRecordId(firewall ? 'fwc' : 'pvc'),
      anchor_target_id: anchorTargetId,
      primary_entry_path_id: primaryEntryPathId,
      reviewed_plan_digest: reviewedPlanDigest,
      change_id: changeId,
      provenance: { ...extraProvenance, ...(changeId ? { change_id: changeId } : {}) },
      idempotency_key: idempotency.key,
      created_at: stamp(options),
      created_by: actor(ctx, options),
    };
    const entry = auditEntry(ctx, firewall ? A.firewall_comparison_evaluated : X.entry_path_comparison_evaluated,
      firewall ? 'firewall_comparison' : 'entry_path_comparison', row.id, {
        kind: row.kind,
        baseline_id: row.baseline_id,
        anchor_target_id: row.anchor_target_id,
        change_id: changeId,
        total: row.summary.total,
        evaluated: row.summary.evaluated,
        accepted: row.summary.accepted,
        comparable: row.compatibility.comparable,
        evaluation_digest: row.evaluation_digest,
        ...(options.auditMetadata && typeof options.auditMetadata === 'object' ? options.auditMetadata : {}),
      }, options);
    const stored = await backend.insertEvaluation(ctx, row, entry);
    if (stored.error) return stored;
    return { ...presentEvaluation(stored.row), replayed: stored.replayed === true };
  }

  async function getEvaluation(ctx, id, options = {}) {
    const denied = gate(ctx, [P.evidence_read], 'comparison_evaluation');
    if (denied) return denied;
    const row = await backend.getEvaluation(ctx, id);
    if (!row || (options.kind && row.kind !== options.kind)) return error('not_found', 404);
    return presentEvaluation(row);
  }

  async function listEvaluations(ctx, query = {}) {
    const denied = gate(ctx, [P.evidence_read], 'comparison_evaluation');
    if (denied) return denied;
    const kind = enumFilter(query.kind ?? 'firewall_change', COMPARISON_KINDS, 'kind');
    if (kind.failure) return kind.failure;
    const filters = {};
    for (const field of ['change_id', 'baseline_id', 'anchor_target_id']) {
      const parsed = idFilter(query[field], field);
      if (parsed.failure) return parsed.failure;
      filters[field] = parsed.value;
    }
    const cursor = decodePageCursor(query.cursor);
    if (cursor.failure) return cursor.failure;
    const limit = pageLimit(query.limit);
    const rows = await backend.listEvaluations(ctx, { ...filters, kind: kind.value, cursor: cursor.cursor, limit: limit + 1 });
    return pageEnvelope(rows, limit, presentEvaluation);
  }

  /** Server-internal: every baseline target must be active and currently owned. */
  async function verifyBaselineTargets(ctx, targetIds = [], field = 'expectation_ids') {
    const ids = [...new Set((Array.isArray(targetIds) ? targetIds : []).filter(Boolean))];
    if (!ctx?.tenantId) return error('invalid_tenant', 400);
    return ids.length ? verifiedBaselineTargets(ctx, ids, field) : null;
  }

  return {
    createEntryPath,
    getEntryPath,
    listEntryPaths,
    archiveEntryPath,
    authorizeEntryPathForExecution,
    verifyBaselineTargets,
    createFirewallExpectation,
    recordPathValidationExpectation,
    getExpectation,
    listExpectations,
    archiveExpectation,
    captureFirewallBaseline,
    capturePathValidationBaseline,
    getBaselineCapture,
    listBaselineCaptures,
    resolveRunEvidence,
    recordComparisonEvaluation,
    getEvaluation,
    listEvaluations,
  };
}

function storeArrays(store) {
  for (const key of Object.values(PROTECTION_VALIDATION_STORE_KEYS)) {
    if (!Array.isArray(store[key])) store[key] = [];
  }
  return store;
}

function clone(row) {
  return row == null ? null : structuredClone(row);
}

function newestFirst(left, right) {
  if (left.created_at !== right.created_at) return left.created_at < right.created_at ? 1 : -1;
  if (left.id === right.id) return 0;
  return left.id < right.id ? 1 : -1;
}

function beforeCursor(row, cursor) {
  if (!cursor) return true;
  return row.created_at < cursor.created_at || (row.created_at === cursor.created_at && row.id < cursor.id);
}

function devPage(rows, ctx, filter, predicate) {
  return rows
    .filter((row) => row.tenant_id === ctx.tenantId && predicate(row) && beforeCursor(row, filter.cursor))
    .sort(newestFirst)
    .slice(0, filter.limit)
    .map(clone);
}

function sameEntryScope(row, scope) {
  return row.anchor_target_id === scope.anchor_target_id
    && row.entry_target_id === scope.entry_target_id
    && row.relation_kind === scope.relation_kind
    && (row.origin_binding_id ?? null) === (scope.origin_binding_id ?? null);
}

function devRunEvidence(store, tenantId, runIds) {
  const wanted = new Set(runIds);
  const owned = (row) => row.tenant_id === tenantId && wanted.has(row.test_run_id);
  return {
    runs: (store.testRuns ?? []).filter((run) => run.tenant_id === tenantId && wanted.has(run.id)).map((run) => ({
      id: run.id,
      tenant_id: run.tenant_id,
      target_id: run.target_id ?? null,
      check_id: run.check_id,
      status: run.status,
      check_version: run.check_version ?? null,
      scenario_version: run.scenario_version ?? null,
      producer_kind: run.producer_kind ?? null,
      completed_at: run.completed_at ?? null,
      provenance: run.provenance_json ?? run.provenance ?? {},
    })),
    jobs: (store.probeJobs ?? []).filter(owned).map((job) => ({
      id: job.id,
      test_run_id: job.test_run_id,
      status: job.status,
      leased_by: job.leased_by ?? null,
      job_signature: job.job_signature ?? null,
      target: job.target ?? null,
      probe_profile: job.probe_profile ?? null,
      worker_metadata: job.worker_metadata ?? {},
      completed_at: job.completed_at ?? null,
    })),
    verdicts: (store.verdicts ?? []).filter(owned).map((row) => ({
      id: row.id,
      test_run_id: row.test_run_id,
      evidence_ids: [...(row.evidence_ids ?? [])],
      created_at: row.created_at ?? null,
    })),
    events: (store.events ?? []).filter(owned).map((row) => ({
      id: row.id,
      test_run_id: row.test_run_id,
      signal_type: row.signal_type,
      producer_kind: row.producer_kind ?? null,
      timestamp: row.timestamp,
      source_perspective: row.metadata?.source_perspective ?? null,
    })),
  };
}

/** Dev JSON store backend. Each write is one synchronous step, so the row and its audit land together. */
export function createDevProtectionValidationBackend({ audit = appendDevAudit } = {}) {
  const K = PROTECTION_VALIDATION_STORE_KEYS;
  const store = () => storeArrays(getStore());
  const commit = (entry) => {
    if (entry) audit(entry);
    persistStore();
  };
  return {
    async loadTargetContext(ctx, ids) {
      const s = getStore();
      const wanted = new Set(ids);
      return {
        targets: (s.targets ?? []).filter((row) => row.tenant_id === ctx.tenantId && wanted.has(row.id)).map(clone),
        records: bindingRecordsFromStore(s, ctx.tenantId),
      };
    },
    async getOriginBindings(ctx, ids) {
      const wanted = new Set(ids);
      return (getStore().originBindings ?? []).filter((row) => row.tenant_id === ctx.tenantId && wanted.has(row.id)).map(clone);
    },
    async listEntryPathsByScope(ctx, scope) {
      return store()[K.entryPaths].filter((row) => row.tenant_id === ctx.tenantId && sameEntryScope(row, scope)).map(clone);
    },
    async findEntryPathByIdempotencyKey(ctx, key) {
      return clone(store()[K.entryPaths].find((row) => row.tenant_id === ctx.tenantId && row.idempotency_key === key));
    },
    async insertEntryPath(ctx, row, entry) {
      const rows = store()[K.entryPaths];
      const conflicts = rows.filter((existing) => existing.tenant_id === ctx.tenantId && (
        (row.idempotency_key && existing.idempotency_key === row.idempotency_key)
        || (sameEntryScope(existing, row) && (existing.status === 'active' || existing.declaration_version === row.declaration_version))
      ));
      if (conflicts.length) return { conflictRows: conflicts.map(clone) };
      rows.push(clone(row));
      commit(entry);
      return { row: clone(row) };
    },
    async getEntryPath(ctx, id) {
      return clone(store()[K.entryPaths].find((row) => row.tenant_id === ctx.tenantId && row.id === id));
    },
    async getEntryPaths(ctx, ids) {
      const wanted = new Set(ids);
      return store()[K.entryPaths].filter((row) => row.tenant_id === ctx.tenantId && wanted.has(row.id)).map(clone);
    },
    async archiveEntryPath(ctx, id, patch, entry) {
      const row = store()[K.entryPaths].find((candidate) => candidate.tenant_id === ctx.tenantId && candidate.id === id && candidate.status === 'active');
      if (!row) return null;
      Object.assign(row, { status: 'archived', archived_at: patch.archived_at, archived_by: patch.archived_by });
      commit(entry);
      return clone(row);
    },
    async listEntryPaths(ctx, filter) {
      return devPage(store()[K.entryPaths], ctx, filter, (row) => (row.anchor_target_id === filter.target_id || row.entry_target_id === filter.target_id)
        && (!filter.status || row.status === filter.status)
        && (!filter.relation_kind || row.relation_kind === filter.relation_kind));
    },
    async listExpectationsByScope(ctx, kind, scopeKey) {
      return store()[K.expectations].filter((row) => row.tenant_id === ctx.tenantId && row.kind === kind && row.scope_key === scopeKey).map(clone);
    },
    async findExpectationByIdempotencyKey(ctx, key) {
      return clone(store()[K.expectations].find((row) => row.tenant_id === ctx.tenantId && row.idempotency_key === key));
    },
    async insertExpectation(ctx, row, entry, options = {}) {
      const rows = store()[K.expectations];
      const superseded = options.supersede
        ? rows.find((candidate) => candidate.tenant_id === ctx.tenantId && candidate.id === options.supersede.id && candidate.status === 'active')
        : null;
      if (options.supersede && !superseded) {
        return { conflictRows: rows.filter((candidate) => candidate.tenant_id === ctx.tenantId && candidate.kind === row.kind && candidate.scope_key === row.scope_key).map(clone) };
      }
      const conflicts = rows.filter((existing) => existing.tenant_id === ctx.tenantId && existing !== superseded && (
        (row.idempotency_key && existing.idempotency_key === row.idempotency_key)
        || (existing.kind === row.kind && existing.scope_key === row.scope_key
          && (existing.status === 'active' || existing.expectation_version === row.expectation_version))
      ));
      if (conflicts.length) return { conflictRows: conflicts.map(clone) };
      if (superseded) Object.assign(superseded, { status: 'archived', archived_at: options.supersede.archived_at, archived_by: options.supersede.archived_by });
      rows.push(clone(row));
      commit(entry);
      return { row: clone(row) };
    },
    async getExpectation(ctx, id) {
      return clone(store()[K.expectations].find((row) => row.tenant_id === ctx.tenantId && row.id === id));
    },
    async getExpectations(ctx, ids) {
      const wanted = new Set(ids);
      return store()[K.expectations].filter((row) => row.tenant_id === ctx.tenantId && wanted.has(row.id)).map(clone);
    },
    async archiveExpectation(ctx, id, patch, entry) {
      const row = store()[K.expectations].find((candidate) => candidate.tenant_id === ctx.tenantId && candidate.id === id && candidate.status === 'active');
      if (!row) return null;
      Object.assign(row, { status: 'archived', archived_at: patch.archived_at, archived_by: patch.archived_by });
      commit(entry);
      return clone(row);
    },
    async listExpectations(ctx, filter) {
      return devPage(store()[K.expectations], ctx, filter, (row) => row.kind === filter.kind
        && (!filter.status || row.status === filter.status)
        && (!filter.change_id || row.change_id === filter.change_id)
        && (!filter.destination_target_id || row.destination_target_id === filter.destination_target_id)
        && (!filter.anchor_target_id || row.anchor_target_id === filter.anchor_target_id));
    },
    async loadRunEvidence(ctx, runIds) {
      return devRunEvidence(getStore(), ctx.tenantId, runIds);
    },
    async findBaselineCaptureIdByKey(ctx, key) {
      return store()[K.baselines].find((row) => row.tenant_id === ctx.tenantId && row.idempotency_key === key)?.capture_id ?? null;
    },
    async insertBaselineCapture(ctx, rows, entry) {
      const existing = store()[K.baselines];
      const keyed = rows[0].idempotency_key
        ? existing.find((row) => row.tenant_id === ctx.tenantId && row.idempotency_key === rows[0].idempotency_key)
        : null;
      if (keyed) return { capture_id: keyed.capture_id, replayed: true };
      const digests = new Set(rows.map((row) => row.baseline_digest));
      if (existing.some((row) => row.tenant_id === ctx.tenantId && digests.has(row.baseline_digest))) {
        return error('invalid_comparison_baseline', 409, { message: 'This evidence is already captured in another baseline.' });
      }
      existing.push(...rows.map(clone));
      commit(entry);
      return { capture_id: rows[0].capture_id, replayed: false };
    },
    async getBaselineCaptureRows(ctx, captureId) {
      return store()[K.baselines]
        .filter((row) => row.tenant_id === ctx.tenantId && row.capture_id === captureId)
        .sort((left, right) => left.capture_index - right.capture_index)
        .map(clone);
    },
    async getBaselineCaptureRowsByIds(ctx, captureIds) {
      const wanted = new Set(captureIds);
      return store()[K.baselines]
        .filter((row) => row.tenant_id === ctx.tenantId && wanted.has(row.capture_id))
        .sort((left, right) => left.capture_index - right.capture_index)
        .map(clone);
    },
    async listBaselineCaptureHeads(ctx, filter) {
      return devPage(store()[K.baselines], ctx, filter, (row) => row.capture_index === 0
        && row.kind === filter.kind
        && (!filter.status || row.status === filter.status)
        && (!filter.change_id || row.change_id === filter.change_id)
        && (!filter.entry_path_id || row.entry_path_id === filter.entry_path_id)
        && (!filter.expectation_id || row.expectation_id === filter.expectation_id));
    },
    async existingIds(ctx, { runs = [], verdicts = [], targets = [] }) {
      const s = getStore();
      const owned = (rows, ids) => new Set((rows ?? []).filter((row) => row.tenant_id === ctx.tenantId && ids.includes(row.id)).map((row) => row.id));
      return { runs: owned(s.testRuns, runs), verdicts: owned(s.verdicts, verdicts), targets: owned(s.targets, targets) };
    },
    async findEvaluationByDigest(ctx, digest) {
      return clone(store()[K.evaluations].find((row) => row.tenant_id === ctx.tenantId && row.evaluation_digest === digest));
    },
    async findEvaluationByIdempotencyKey(ctx, key) {
      return clone(store()[K.evaluations].find((row) => row.tenant_id === ctx.tenantId && row.idempotency_key === key));
    },
    async insertEvaluation(ctx, row, entry) {
      const rows = store()[K.evaluations];
      const prior = rows.find((existing) => existing.tenant_id === ctx.tenantId && (existing.evaluation_digest === row.evaluation_digest
        || (row.idempotency_key && existing.idempotency_key === row.idempotency_key)));
      if (prior) return { row: clone(prior), replayed: true };
      rows.push(clone(row));
      commit(entry);
      return { row: clone(row), replayed: false };
    },
    async getEvaluation(ctx, id) {
      return clone(store()[K.evaluations].find((row) => row.tenant_id === ctx.tenantId && row.id === id));
    },
    async loadEdgeDetections(ctx, targetIds) {
      const wanted = new Set(targetIds);
      return (getStore().targetEdgeDetections ?? []).filter((row) => row.tenant_id === ctx.tenantId && wanted.has(row.target_id)).map(clone);
    },
    async loadConfigurationSnapshots(ctx, { limit = 1000 } = {}) {
      const s = getStore();
      const snapshots = (s.wafConnectorSnapshots ?? [])
        .filter((row) => row.tenant_id === ctx.tenantId)
        .sort((left, right) => String(right.observed_at ?? '').localeCompare(String(left.observed_at ?? '')))
        .slice(0, limit)
        .map(clone);
      const connectors = (s.wafConnectors ?? []).filter((row) => row.tenant_id === ctx.tenantId).map((row) => ({
        id: row.id,
        provider: row.provider ?? null,
        status: row.status ?? null,
        health: row.health ?? row.health_status ?? null,
        permission_gaps: row.permission_gaps ?? row.health_json?.permission_gaps ?? [],
      }));
      return { snapshots, connectors };
    },
    async listReportSources(ctx, { limit = 500 } = {}) {
      const s = storeArrays(getStore());
      const owned = (rows) => (rows ?? []).filter((row) => row.tenant_id === ctx.tenantId).sort(newestFirst).slice(0, limit).map(clone);
      const entryPaths = owned(s[K.entryPaths]);
      const ids = new Set(entryPaths.flatMap((row) => [row.anchor_target_id, row.entry_target_id]));
      const expectations = owned(s[K.expectations]);
      for (const row of expectations) for (const id of [row.anchor_target_id, row.destination_target_id]) if (id) ids.add(id);
      return {
        targets: (s.targets ?? []).filter((row) => row.tenant_id === ctx.tenantId && ids.has(row.id)).map(clone),
        entryPaths,
        expectations,
        evaluations: owned(s[K.evaluations]),
      };
    },
    async listEvaluations(ctx, filter) {
      return devPage(store()[K.evaluations], ctx, filter, (row) => row.kind === filter.kind
        && (!filter.change_id || row.change_id === filter.change_id)
        && (!filter.baseline_id || row.baseline_id === filter.baseline_id)
        && (!filter.anchor_target_id || row.anchor_target_id === filter.anchor_target_id));
    },
  };
}

export const devProtectionValidationService = createProtectionValidationService({ backend: createDevProtectionValidationBackend() });

export const {
  createEntryPath,
  getEntryPath,
  listEntryPaths,
  archiveEntryPath,
  authorizeEntryPathForExecution,
  createFirewallExpectation,
  recordPathValidationExpectation,
  getExpectation,
  listExpectations,
  archiveExpectation,
  captureFirewallBaseline,
  capturePathValidationBaseline,
  getBaselineCapture,
  listBaselineCaptures,
  resolveRunEvidence,
  recordComparisonEvaluation,
  getEvaluation,
  listEvaluations,
  verifyBaselineTargets,
} = devProtectionValidationService;
