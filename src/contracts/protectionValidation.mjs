import { createHash } from 'node:crypto';

export const PROTECTION_VALIDATION_CONTRACT_VERSION = 'protection-validation-v1';

export const PROTECTION_LAYERS = Object.freeze(['waf', 'cdn_edge', 'network_firewall', 'ddos']);

export const ENTRY_PATH_RELATION_KINDS = Object.freeze([
  'primary_route',
  'alternate_hostname',
  'declared_api_url',
  'declared_login_url',
  'origin',
  'fallback_backend_route',
]);

export const ENTRY_PATH_EXPECTED_BEHAVIORS = Object.freeze([
  'must_be_protected_by_layers',
  'intentionally_public',
  'must_not_be_reachable',
]);

export const RECORD_STATUSES = Object.freeze(['active', 'archived']);
export const ENTRY_PATH_STATUSES = RECORD_STATUSES;
export const FIREWALL_EXPECTATION_STATUSES = RECORD_STATUSES;

export const COMPARISON_KINDS = Object.freeze(['path_validation', 'firewall_change']);

export const PATH_LAYER_EXPECTED_OUTCOMES = Object.freeze(['enforce', 'allow', 'not_reachable', 'no_expectation']);

export const FIREWALL_PROTOCOLS = Object.freeze(['tcp', 'udp', 'service']);
export const FIREWALL_EXPECTED_BEHAVIORS = Object.freeze(['allow', 'deny']);

export const FINALIZED_RUN_STATUSES = Object.freeze(['verdicted', 'completed']);

export const PATH_VALIDATION_OUTCOMES = Object.freeze([
  'intentional_public_access',
  'reachability_exposure',
  'weaker_observed_enforcement',
  'suspected_alternate_application_route',
  'scoped_application_bypass',
  'consistent_enforcement',
  'inconclusive',
  'not_tested',
  'skipped',
]);

export const FIREWALL_COMPARISON_STATUSES = Object.freeze([
  'matched',
  'regression',
  'improvement',
  'inconclusive',
  'not_tested',
  'stale',
  'not_comparable',
]);

export const FIREWALL_GAP_KINDS = Object.freeze([
  'forbidden_service_newly_reachable',
  'required_service_newly_unavailable',
]);

export const PATH_ENTRY_OBSERVATIONS = Object.freeze([
  'response_observed',
  'application_identity_confirmed',
  'explicit_denial_observed',
  'no_response',
  'transport_error',
  'not_tested',
]);

export const PATH_ENFORCEMENT_OBSERVATIONS = Object.freeze(['enforced', 'partial', 'not_enforced', 'unknown']);

export const BASELINE_HEALTH_STATES = Object.freeze(['healthy', 'unhealthy', 'not_available']);

export const FIREWALL_OBSERVATION_CLASSES = Object.freeze([
  'service_response_observed',
  'reachable_transport_only',
  'explicit_denial_observed',
  'no_response',
  'transport_error',
  'udp_silence',
  'not_tested',
]);

export const FIREWALL_SIDE_STATES = Object.freeze(['satisfied', 'violated', 'not_observed', 'unverified', 'not_tested']);

export const MIN_SAMPLES_FOR_UNAVAILABILITY = 2;

export const LAYER_EVIDENCE_DIMENSIONS = Object.freeze([
  'declared_intent',
  'vendor_detection',
  'observed_enforcement',
  'application_identity',
  'suspected_bypass',
  'confirmed_scoped_bypass',
  'evidence_limitations',
]);

export const LAYER_EVIDENCE_STATES = Object.freeze({
  declared_intent: Object.freeze(['required', 'not_required', 'undeclared']),
  vendor_detection: Object.freeze(['detected', 'not_detected', 'unknown']),
  observed_enforcement: Object.freeze(['enforced', 'partially_enforced', 'not_enforced', 'inconclusive', 'not_tested']),
  application_identity: Object.freeze(['confirmed', 'suspected', 'not_established', 'not_tested']),
  suspected_bypass: Object.freeze(['suspected', 'not_suspected', 'unknown']),
  confirmed_scoped_bypass: Object.freeze(['confirmed', 'not_confirmed', 'unknown']),
});

export const LAYER_ATTRIBUTIONS = Object.freeze(['attributed', 'unattributed', 'not_applicable']);

export const PROTECTION_VALIDATION_LIMITATIONS = Object.freeze([
  'external_only',
  'sampled_public_ingress_only',
  'rule_table_equivalence_not_established',
  'routing_nat_egress_east_west_not_established',
  'not_capacity_assurance',
  'appliance_traversal_not_established',
  'firewall_traversal_not_established',
  'stacked_layer_attribution_not_established',
  'transport_reachability_not_enforcement',
  'udp_silence_ambiguous',
  'marker_scope_only',
  'vendor_label_not_proof',
  'configuration_evidence_not_behavior',
  'untested_paths_not_covered',
  'layer_not_measured_by_scenario',
]);

export const REQUIRED_LIMITATIONS = Object.freeze({
  path_validation: Object.freeze([
    'external_only',
    'not_capacity_assurance',
    'firewall_traversal_not_established',
    'stacked_layer_attribution_not_established',
    'marker_scope_only',
    'untested_paths_not_covered',
  ]),
  firewall_change: Object.freeze([
    'external_only',
    'sampled_public_ingress_only',
    'rule_table_equivalence_not_established',
    'routing_nat_egress_east_west_not_established',
    'not_capacity_assurance',
    'appliance_traversal_not_established',
    'transport_reachability_not_enforcement',
  ]),
});

const UNKNOWN_ALTERNATIVE = Object.freeze({
  path: 'inconclusive',
  firewall: 'inconclusive',
});

export const EVIDENCE_REQUIREMENTS = Object.freeze({
  path_validation: Object.freeze({
    intentional_public_access: Object.freeze({ requires: 'Explicit intentionally_public declaration plus a finalized response observation on this entry path.', unknown_alternative: 'not_tested' }),
    reachability_exposure: Object.freeze({ requires: 'Finalized response observation on a path declared must_not_be_reachable, or on an origin/fallback route whose enforcement was not measured.', unknown_alternative: UNKNOWN_ALTERNATIVE.path }),
    weaker_observed_enforcement: Object.freeze({ requires: 'Healthy primary baseline enforcing the scenario and the same compatible scenario only partially enforced on this path.', unknown_alternative: UNKNOWN_ALTERNATIVE.path }),
    suspected_alternate_application_route: Object.freeze({ requires: 'Healthy enforcing primary baseline and a non-enforced response on this path without nonce-bound application identity.', unknown_alternative: UNKNOWN_ALTERNATIVE.path }),
    scoped_application_bypass: Object.freeze({ requires: 'Healthy enforcing primary baseline, application identity confirmed by a nonce-bound canary, and the same scenario not enforced on this path.', unknown_alternative: 'suspected_alternate_application_route' }),
    consistent_enforcement: Object.freeze({ requires: 'Healthy enforcing primary baseline and the same compatible scenario enforced on this path, or an explicit denial on a must_not_be_reachable path.', unknown_alternative: UNKNOWN_ALTERNATIVE.path }),
    inconclusive: Object.freeze({ requires: 'Used when evidence is missing, incompatible, a timeout/transport error, or the primary baseline is not healthy and enforcing.', unknown_alternative: 'inconclusive' }),
    not_tested: Object.freeze({ requires: 'No finalized observation exists for this path and scenario.', unknown_alternative: 'not_tested' }),
    skipped: Object.freeze({ requires: 'Path was in the reviewed plan but was not executed (ineligible, unauthorized, cancelled, or killed).', unknown_alternative: 'skipped' }),
  }),
  firewall_change: Object.freeze({
    matched: Object.freeze({ requires: 'Compatible fresh pre/post evidence for the same expectation, source, check, and version with the same side state.', unknown_alternative: UNKNOWN_ALTERNATIVE.firewall }),
    regression: Object.freeze({ requires: 'Pre-change side satisfied and post-change side violated or repeatedly not observed under compatible evidence.', unknown_alternative: UNKNOWN_ALTERNATIVE.firewall }),
    improvement: Object.freeze({ requires: 'Pre-change side violated or not observed and post-change side satisfied under compatible evidence.', unknown_alternative: UNKNOWN_ALTERNATIVE.firewall }),
    inconclusive: Object.freeze({ requires: 'Used when either side is unverified, mixed, ambiguous (UDP silence, timeout), or states differ without an observed gap.', unknown_alternative: 'inconclusive' }),
    not_tested: Object.freeze({ requires: 'No finalized post-change evidence exists for this expectation.', unknown_alternative: 'not_tested' }),
    stale: Object.freeze({ requires: 'Baseline or candidate evidence falls outside the recorded freshness window.', unknown_alternative: 'stale' }),
    not_comparable: Object.freeze({ requires: 'Expectation, source, target mapping, check, version, or finalization differ between baseline and candidate.', unknown_alternative: 'not_comparable' }),
  }),
  layer: Object.freeze({
    declared_intent: Object.freeze({ requires: 'Explicit customer entry-path declaration; never inferred from tags, logos, or vendor names.', unknown_alternative: 'undeclared' }),
    vendor_detection: Object.freeze({ requires: 'External fingerprint signal (CNAME, address, header, or response signature); a label alone is not proof of enforcement.', unknown_alternative: 'unknown' }),
    observed_enforcement: Object.freeze({ requires: 'Finalized signed run on this exact path with explicit denial for the scenario after a healthy permitted baseline.', unknown_alternative: 'inconclusive' }),
    application_identity: Object.freeze({ requires: 'Nonce-bound customer canary echo for confirmed; generic header/content similarity is at most suspected.', unknown_alternative: 'not_tested' }),
    suspected_bypass: Object.freeze({ requires: 'Non-enforced response on a path required to be protected while the primary route enforces.', unknown_alternative: 'unknown' }),
    confirmed_scoped_bypass: Object.freeze({ requires: 'Confirmed application identity plus enforcing primary and non-enforcing alternate for the same scenario.', unknown_alternative: 'unknown' }),
    evidence_limitations: Object.freeze({ requires: 'Every projection carries the limitations required for its comparison kind.', unknown_alternative: 'external_only' }),
  }),
});

export const COMPATIBILITY_REASONS = Object.freeze([
  'invalid_baseline',
  'invalid_candidate',
  'contract_version_mismatch',
  'kind_mismatch',
  'tenant_mismatch',
  'expectation_mismatch',
  'expectation_version_mismatch',
  'expectation_digest_mismatch',
  'anchor_mismatch',
  'entry_path_mismatch',
  'declaration_digest_mismatch',
  'declaration_changed',
  'destination_mismatch',
  'destination_mapping_missing',
  'evidence_missing',
  'evidence_not_finalized',
  'source_missing',
  'source_mismatch',
  'check_mismatch',
  'check_version_mismatch',
  'scenario_version_mismatch',
  'candidate_not_after_baseline',
  'baseline_stale',
  'candidate_stale',
]);

const STALE_REASONS = new Set(['baseline_stale', 'candidate_stale']);

export const DEFAULT_FRESHNESS_WINDOW_SECONDS = 30 * 24 * 3600;
export const MIN_FRESHNESS_WINDOW_SECONDS = 3600;
export const MAX_FRESHNESS_WINDOW_SECONDS = 180 * 24 * 3600;

export const PROTECTION_VALIDATION_PAGE_LIMIT = Object.freeze({ default: 50, max: 100 });
export const MAX_EVIDENCE_REFERENCES = 64;
export const MAX_EVIDENCE_IDS_PER_REFERENCE = 32;
export const MAX_COMPARISON_ITEMS = 200;
export const MAX_ENTRY_PATHS_PER_COMPARISON = 32;

export const PROTECTION_VALIDATION_PERMISSIONS = Object.freeze({
  declaration_read: 'target_group:read',
  declaration_write: 'target_group:write',
  evidence_read: 'evidence:read',
  run_start: 'test_run:start',
});

const P = PROTECTION_VALIDATION_PERMISSIONS;

function route(method, path, permission, passive, mutates, operation) {
  return Object.freeze({ method, path, permission, passive, mutates, operation });
}

export const PROTECTION_VALIDATION_ROUTES = Object.freeze([
  route('GET', '/v1/targets/:targetId/entry-paths', P.declaration_read, true, false, 'list_entry_paths'),
  route('POST', '/v1/targets/:targetId/entry-paths', P.declaration_write, true, true, 'create_entry_path'),
  route('GET', '/v1/entry-paths/:entryPathId', P.declaration_read, true, false, 'get_entry_path'),
  route('POST', '/v1/entry-paths/:entryPathId/archive', P.declaration_write, true, true, 'archive_entry_path'),
  route('GET', '/v1/targets/:targetId/protection-validation', P.evidence_read, true, false, 'get_protection_matrix'),
  route('POST', '/v1/entry-path-comparisons', P.run_start, false, true, 'plan_or_start_entry_path_comparison'),
  route('GET', '/v1/entry-path-comparisons', P.evidence_read, true, false, 'list_entry_path_comparisons'),
  route('GET', '/v1/entry-path-comparisons/:comparisonId', P.evidence_read, true, false, 'get_entry_path_comparison'),
  route('POST', '/v1/entry-path-comparisons/:comparisonId/cancel', P.run_start, true, true, 'cancel_entry_path_comparison'),
  route('GET', '/v1/firewall-expectations', P.declaration_read, true, false, 'list_firewall_expectations'),
  route('POST', '/v1/firewall-expectations', P.declaration_write, true, true, 'create_firewall_expectation'),
  route('POST', '/v1/firewall-expectations/:expectationId/archive', P.declaration_write, true, true, 'archive_firewall_expectation'),
  route('POST', '/v1/firewall-baselines', P.declaration_write, true, true, 'capture_firewall_baseline'),
  route('GET', '/v1/firewall-baselines', P.evidence_read, true, false, 'list_firewall_baselines'),
  route('GET', '/v1/firewall-baselines/:baselineId', P.evidence_read, true, false, 'get_firewall_baseline'),
  route('POST', '/v1/firewall-comparisons', P.declaration_write, true, true, 'evaluate_firewall_comparison'),
  route('GET', '/v1/firewall-comparisons', P.evidence_read, true, false, 'list_firewall_comparisons'),
  route('GET', '/v1/firewall-comparisons/:comparisonId', P.evidence_read, true, false, 'get_firewall_comparison'),
]);

export const ENTRY_PATH_COMPARISON_MODES = Object.freeze(['plan', 'start']);

export const PROTECTION_VALIDATION_AUDIT_ACTIONS = Object.freeze({
  entry_path_created: 'entry_path.created',
  entry_path_archived: 'entry_path.archived',
  entry_path_comparison_started: 'entry_path_comparison.started',
  firewall_expectation_created: 'firewall_expectation.created',
  firewall_expectation_archived: 'firewall_expectation.archived',
  firewall_baseline_captured: 'firewall_baseline.captured',
  firewall_comparison_evaluated: 'firewall_comparison.evaluated',
  path_validation_expectation_recorded: 'path_validation_expectation.recorded',
  path_validation_expectation_archived: 'path_validation_expectation.archived',
  path_validation_baseline_captured: 'path_validation_baseline.captured',
  entry_path_comparison_evaluated: 'entry_path_comparison.evaluated',
});

export const PROTECTION_VALIDATION_ERROR_CODES = Object.freeze([
  'invalid_entry_path',
  'invalid_behavior_expectation',
  'invalid_firewall_expectation',
  'invalid_evidence_reference',
  'invalid_comparison_baseline',
  'invalid_comparison_evaluation',
  'invalid_comparison_request',
  'server_owned_field',
  'scope_not_declared',
  'origin_binding_required',
  'origin_binding_not_allowed',
  'origin_binding_mismatch',
  'required_layers_conflict',
  'unknown_target',
  'unknown_origin_binding',
  'target_not_active',
  'entry_path_archived',
  'entry_path_conflict',
  'firewall_expectation_conflict',
  'evidence_not_finalized',
  'baseline_not_comparable',
  'reviewed_plan_mismatch',
  'already_archived',
]);

export const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
export const SCENARIO_PATTERN = /^[a-z0-9][a-z0-9_.:-]{0,95}$/;
export const SOURCE_PERSPECTIVE_PATTERN = /^[a-z0-9][a-z0-9_.:-]{0,63}$/;
export const CHANGE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:#/-]{0,63}$/;
export const SERVICE_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,127}$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

const ENTRY_SERVER_OWNED = Object.freeze([
  'id', 'tenant_id', 'status', 'declaration_version', 'declaration_digest', 'created_at', 'created_by',
  'archived_at', 'archived_by', 'contract_version',
]);
const EXPECTATION_SERVER_OWNED = Object.freeze([
  'id', 'tenant_id', 'status', 'expectation_version', 'digest', 'created_at', 'created_by',
  'archived_at', 'archived_by', 'contract_version',
]);

export const BANNED_SCOPE_KEYS = Object.freeze([
  'direct_ip',
  'discovered_endpoint',
  'discovered_endpoints',
  'endpoint',
  'destination',
  'host_override',
  'sni_override',
  'source_ip',
  'spoofed_source',
  'inferred_from',
  'credentials',
  'password',
  'api_key',
  'token',
  'secret',
  'raw_config',
]);
const BANNED_SCOPE_KEY_SET = new Set(BANNED_SCOPE_KEYS);

export const EVIDENCE_REFERENCE_FIELDS = Object.freeze([
  'test_run_id',
  'check_id',
  'check_version',
  'scenario_version',
  'verdict_id',
  'evidence_ids',
  'target_id',
  'observed_at',
  'run_status',
  'source_perspective',
  'worker_id',
]);

export class ProtectionValidationError extends Error {
  constructor(code, field, message, status = 400) {
    super(message);
    this.name = 'ProtectionValidationError';
    this.code = code;
    this.status = status;
    this.field = field ?? null;
  }

  toResponse() {
    return { error: this.code, status: this.status, field: this.field, message: this.message };
  }
}

function fail(code, field, message, status = 400) {
  throw new ProtectionValidationError(code, field, message, status);
}

function toResult(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (err) {
    if (err instanceof ProtectionValidationError) return { ok: false, ...err.toResponse() };
    throw err;
  }
}

function isPlainObject(value) {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

export function stableStringify(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

export function sha256Digest(value) {
  return createHash('sha256').update(stableStringify(value)).digest('hex');
}

export function findBannedScopeKey(value, depth = 0) {
  if (depth > 8 || value == null || typeof value !== 'object') return null;
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findBannedScopeKey(entry, depth + 1);
      if (found) return found;
    }
    return null;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (BANNED_SCOPE_KEY_SET.has(key)) return key;
    const found = findBannedScopeKey(entry, depth + 1);
    if (found) return found;
  }
  return null;
}

function rejectBanned(input) {
  const banned = findBannedScopeKey(input);
  if (banned) fail('scope_not_declared', banned, `Field "${banned}" is not accepted; destinations come only from declared targets.`);
}

function rejectServerOwned(input, fields, code) {
  for (const field of fields) {
    if (Object.hasOwn(input, field)) fail('server_owned_field', field, `Field "${field}" is server-derived and cannot be supplied (${code}).`);
  }
}

function requireId(value, field, code) {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) fail(code, field, `${field} must be an existing record id.`);
  return value;
}

function optionalId(value, field, code) {
  if (value == null || value === '') return null;
  return requireId(value, field, code);
}

function requireEnum(value, allowed, field, code) {
  if (typeof value !== 'string' || !allowed.includes(value)) fail(code, field, `${field} must be one of: ${allowed.join(', ')}.`);
  return value;
}

function boundedText(value, field, code, { min = 1, max }) {
  if (typeof value !== 'string') fail(code, field, `${field} must be a string.`);
  const trimmed = value.trim();
  if (trimmed.length < min || trimmed.length > max) fail(code, field, `${field} must be ${min}-${max} characters.`);
  if (CONTROL_CHARS.test(trimmed)) fail(code, field, `${field} must not contain control characters.`);
  return trimmed;
}

function positiveVersion(value, field, code, fallback = 1) {
  if (value == null) return fallback;
  if (!Number.isInteger(value) || value < 1 || value > 1_000_000) fail(code, field, `${field} must be a positive integer.`);
  return value;
}

function requirePort(value, field, code) {
  if (!Number.isInteger(value) || value < 1 || value > 65535) fail(code, field, `${field} must be an integer port 1-65535.`);
  return value;
}

export function normalizeIsoTimestamp(value, field = 'timestamp', code = 'invalid_comparison_baseline') {
  const date = value instanceof Date ? value : new Date(typeof value === 'string' || typeof value === 'number' ? value : NaN);
  if (value == null || Number.isNaN(date.getTime())) fail(code, field, `${field} must be an ISO timestamp.`);
  return date.toISOString();
}

export function normalizeRequiredLayers(input, field = 'required_layers', code = 'invalid_entry_path') {
  if (input == null) return [];
  if (!Array.isArray(input)) fail(code, field, `${field} must be an array.`);
  const seen = new Set();
  for (const layer of input) {
    requireEnum(layer, PROTECTION_LAYERS, field, code);
    seen.add(layer);
  }
  return PROTECTION_LAYERS.filter((layer) => seen.has(layer));
}

export function normalizeEntryPathDeclaration(input, context = {}) {
  const code = 'invalid_entry_path';
  if (!isPlainObject(input)) fail(code, null, 'Entry path body must be an object.');
  rejectBanned(input);
  rejectServerOwned(input, ENTRY_SERVER_OWNED, code);
  const anchorTargetId = requireId(context.anchorTargetId ?? input.anchor_target_id, 'anchor_target_id', code);
  if (context.anchorTargetId != null && input.anchor_target_id != null && input.anchor_target_id !== context.anchorTargetId) {
    fail(code, 'anchor_target_id', 'anchor_target_id must match the target in the route.');
  }
  const entryTargetId = requireId(input.entry_target_id, 'entry_target_id', code);
  const relationKind = requireEnum(input.relation_kind, ENTRY_PATH_RELATION_KINDS, 'relation_kind', code);
  const owner = boundedText(input.owner, 'owner', code, { max: 120 });
  const purpose = boundedText(input.purpose, 'purpose', code, { max: 500 });
  const expectedBehavior = requireEnum(input.expected_behavior, ENTRY_PATH_EXPECTED_BEHAVIORS, 'expected_behavior', code);
  const requiredLayers = normalizeRequiredLayers(input.required_layers, 'required_layers', code);
  if (expectedBehavior === 'must_be_protected_by_layers' && requiredLayers.length === 0) {
    fail('required_layers_conflict', 'required_layers', 'must_be_protected_by_layers requires at least one layer.');
  }
  if (expectedBehavior === 'intentionally_public' && requiredLayers.length > 0) {
    fail('required_layers_conflict', 'required_layers', 'intentionally_public paths cannot require protection layers.');
  }
  const originBindingId = optionalId(input.origin_binding_id, 'origin_binding_id', code);
  if (relationKind === 'origin' && !originBindingId) {
    fail('origin_binding_required', 'origin_binding_id', 'Origin relations must reference an existing origin binding.');
  }
  if (relationKind !== 'origin' && originBindingId) {
    fail('origin_binding_not_allowed', 'origin_binding_id', 'Only origin relations may reference an origin binding.');
  }
  if (anchorTargetId === entryTargetId && relationKind !== 'primary_route') {
    fail(code, 'entry_target_id', 'Only a primary_route may use the anchor target as its entry target.');
  }
  const declarationVersion = positiveVersion(context.declarationVersion, 'declaration_version', code);
  const record = {
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    tenant_id: context.tenantId ?? null,
    anchor_target_id: anchorTargetId,
    entry_target_id: entryTargetId,
    relation_kind: relationKind,
    owner,
    purpose,
    expected_behavior: expectedBehavior,
    required_layers: requiredLayers,
    origin_binding_id: originBindingId,
    status: 'active',
    declaration_source: 'explicit',
    declaration_version: declarationVersion,
  };
  record.declaration_digest = entryPathDeclarationDigest(record);
  return record;
}

export function validateEntryPathDeclaration(input, context = {}) {
  return toResult(() => normalizeEntryPathDeclaration(input, context));
}

export function entryPathDeclarationDigest(record) {
  return sha256Digest({
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    tenant_id: record.tenant_id ?? null,
    anchor_target_id: record.anchor_target_id,
    entry_target_id: record.entry_target_id,
    relation_kind: record.relation_kind,
    owner: record.owner,
    purpose: record.purpose,
    expected_behavior: record.expected_behavior,
    required_layers: [...(record.required_layers ?? [])],
    origin_binding_id: record.origin_binding_id ?? null,
    declaration_version: record.declaration_version,
  });
}

export function entryPathScopeKey(record) {
  return [record.tenant_id ?? '', record.anchor_target_id, record.entry_target_id, record.relation_kind, record.origin_binding_id ?? ''].join('|');
}

export function classifyEntryPathWrite(existingRecords, candidate) {
  const key = entryPathScopeKey(candidate);
  const active = (existingRecords ?? []).find((row) => row?.status === 'active' && entryPathScopeKey(row) === key);
  if (!active) return { action: 'create', existing: null };
  if (active.declaration_digest === candidate.declaration_digest) return { action: 'replay', existing: active };
  return { action: 'conflict', existing: active, error: 'entry_path_conflict', status: 409 };
}

function targetIsActive(target) {
  return Boolean(target) && !target.deleted_at && !target.archived_at && target.status !== 'archived' && target.status !== 'deleted';
}

function targetInTenant(target, tenantId) {
  return Boolean(target) && (tenantId == null || target.tenant_id === tenantId);
}

export function validateEntryPathReferences({ tenantId, relation, anchorTarget, entryTarget, originBinding } = {}) {
  if (!relation) return { ok: false, error: 'invalid_entry_path', status: 400, field: null };
  if (!anchorTarget || !targetInTenant(anchorTarget, tenantId) || anchorTarget.id !== relation.anchor_target_id) {
    return { ok: false, error: 'unknown_target', status: 404, field: 'anchor_target_id' };
  }
  if (!entryTarget || !targetInTenant(entryTarget, tenantId) || entryTarget.id !== relation.entry_target_id) {
    return { ok: false, error: 'unknown_target', status: 404, field: 'entry_target_id' };
  }
  if (!targetIsActive(anchorTarget)) return { ok: false, error: 'target_not_active', status: 409, field: 'anchor_target_id' };
  if (!targetIsActive(entryTarget)) return { ok: false, error: 'target_not_active', status: 409, field: 'entry_target_id' };
  if (relation.relation_kind === 'origin') {
    if (!originBinding || (tenantId != null && originBinding.tenant_id !== tenantId) || originBinding.id !== relation.origin_binding_id) {
      return { ok: false, error: 'unknown_origin_binding', status: 404, field: 'origin_binding_id' };
    }
    if (originBinding.status !== 'active') return { ok: false, error: 'unknown_origin_binding', status: 404, field: 'origin_binding_id' };
    if (originBinding.protected_target_id !== relation.anchor_target_id || originBinding.origin_target_id !== relation.entry_target_id) {
      return { ok: false, error: 'origin_binding_mismatch', status: 409, field: 'origin_binding_id' };
    }
  }
  return { ok: true };
}

export function entryPathAuthorizesExecution(relation, { anchorTarget, entryTarget, originBinding, tenantId } = {}) {
  if (!relation || relation.status !== 'active') return { ok: false, error: 'entry_path_archived', status: 409 };
  if (relation.declaration_digest !== entryPathDeclarationDigest(relation)) return { ok: false, error: 'invalid_entry_path', status: 409, field: 'declaration_digest' };
  return validateEntryPathReferences({ tenantId: tenantId ?? relation.tenant_id, relation, anchorTarget, entryTarget, originBinding });
}

export function normalizeLayerOutcomes(input, field = 'layer_outcomes', code = 'invalid_behavior_expectation') {
  if (!isPlainObject(input)) fail(code, field, `${field} must be an object keyed by protection layer.`);
  const out = {};
  for (const [layer, outcome] of Object.entries(input)) {
    requireEnum(layer, PROTECTION_LAYERS, field, code);
    out[layer] = requireEnum(outcome, PATH_LAYER_EXPECTED_OUTCOMES, `${field}.${layer}`, code);
  }
  if (!Object.keys(out).length) fail(code, field, `${field} must declare at least one layer.`);
  return Object.fromEntries(PROTECTION_LAYERS.filter((layer) => out[layer]).map((layer) => [layer, out[layer]]));
}

export function normalizePathValidationExpectation(input, context = {}) {
  const code = 'invalid_behavior_expectation';
  if (!isPlainObject(input)) fail(code, null, 'Expectation must be an object.');
  rejectBanned(input);
  rejectServerOwned(input, EXPECTATION_SERVER_OWNED, code);
  if (input.kind != null && input.kind !== 'path_validation') fail(code, 'kind', 'kind must be path_validation.');
  const anchorTargetId = requireId(context.anchorTargetId ?? input.anchor_target_id, 'anchor_target_id', code);
  const scenario = input.scenario;
  if (typeof scenario !== 'string' || !SCENARIO_PATTERN.test(scenario)) fail(code, 'scenario', 'scenario must be a catalog scenario id.');
  const record = {
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    kind: 'path_validation',
    tenant_id: context.tenantId ?? null,
    anchor_target_id: anchorTargetId,
    scenario,
    layer_outcomes: normalizeLayerOutcomes(input.layer_outcomes),
    expectation_version: positiveVersion(context.expectationVersion, 'expectation_version', code),
  };
  record.digest = expectationDigest(record);
  return record;
}

export function validatePathValidationExpectation(input, context = {}) {
  return toResult(() => normalizePathValidationExpectation(input, context));
}

export function checkExpectationAgainstRelation(expectation, relation) {
  const conflicts = [];
  if (!expectation || !relation) return { ok: false, conflicts: ['missing_input'] };
  if (expectation.anchor_target_id !== relation.anchor_target_id) conflicts.push('anchor_mismatch');
  const outcomes = expectation.layer_outcomes ?? {};
  if (relation.expected_behavior === 'must_be_protected_by_layers') {
    for (const layer of relation.required_layers ?? []) {
      if (outcomes[layer] === 'allow' || outcomes[layer] === 'no_expectation') conflicts.push(`required_layer_not_enforced:${layer}`);
    }
  }
  if (relation.expected_behavior === 'must_not_be_reachable') {
    for (const [layer, outcome] of Object.entries(outcomes)) {
      if (outcome === 'allow') conflicts.push(`unreachable_path_allows:${layer}`);
    }
  }
  return { ok: conflicts.length === 0, conflicts };
}

function normalizeServiceEndpoint(input, code) {
  if (!isPlainObject(input)) fail(code, 'service_endpoint', 'service_endpoint must be an object.');
  const service = input.service;
  if (typeof service !== 'string' || !SERVICE_NAME_PATTERN.test(service)) fail(code, 'service_endpoint.service', 'service must be a service identifier.');
  const port = requirePort(input.port, 'service_endpoint.port', code);
  let path = null;
  if (input.path != null) {
    if (typeof input.path !== 'string' || !input.path.startsWith('/') || input.path.length > 200 || CONTROL_CHARS.test(input.path) || input.path.includes('?')) {
      fail(code, 'service_endpoint.path', 'path must start with "/" and contain no query, at most 200 characters.');
    }
    path = input.path;
  }
  return { service, port, path };
}

function normalizePrePostMapping(input, code) {
  if (input == null) return null;
  if (!isPlainObject(input)) fail(code, 'pre_post_mapping', 'pre_post_mapping must be an object.');
  const pre = requireId(input.pre_destination_target_id, 'pre_post_mapping.pre_destination_target_id', code);
  const post = requireId(input.post_destination_target_id, 'pre_post_mapping.post_destination_target_id', code);
  if (pre === post) fail(code, 'pre_post_mapping', 'A mapping is only needed when the destination target changes.');
  if (input.declared_by_customer !== true) fail(code, 'pre_post_mapping.declared_by_customer', 'Mappings must be explicit customer declarations.');
  return { pre_destination_target_id: pre, post_destination_target_id: post, declared_by_customer: true };
}

export function normalizeFirewallExpectation(input, context = {}) {
  const code = 'invalid_firewall_expectation';
  if (!isPlainObject(input)) fail(code, null, 'Firewall expectation must be an object.');
  rejectBanned(input);
  rejectServerOwned(input, EXPECTATION_SERVER_OWNED, code);
  if (input.kind != null && input.kind !== 'firewall_change') fail(code, 'kind', 'kind must be firewall_change.');
  const destinationTargetId = requireId(input.destination_target_id, 'destination_target_id', code);
  const protocol = requireEnum(input.protocol, FIREWALL_PROTOCOLS, 'protocol', code);
  let port = null;
  let serviceEndpoint = null;
  if (protocol === 'service') {
    if (input.port != null) fail(code, 'port', 'Use service_endpoint.port for protocol service.');
    serviceEndpoint = normalizeServiceEndpoint(input.service_endpoint, code);
  } else {
    if (input.service_endpoint != null) fail(code, 'service_endpoint', 'service_endpoint is only valid for protocol service.');
    port = requirePort(input.port, 'port', code);
  }
  const expected = requireEnum(input.expected, FIREWALL_EXPECTED_BEHAVIORS, 'expected', code);
  const sourcePerspective = input.source_perspective;
  if (typeof sourcePerspective !== 'string' || !SOURCE_PERSPECTIVE_PATTERN.test(sourcePerspective)) {
    fail(code, 'source_perspective', 'source_perspective must be an approved source identifier.');
  }
  const changeId = input.change_id;
  if (typeof changeId !== 'string' || !CHANGE_ID_PATTERN.test(changeId)) fail(code, 'change_id', 'change_id must be a change identifier.');
  const mapping = normalizePrePostMapping(input.pre_post_mapping, code);
  if (mapping && mapping.post_destination_target_id !== destinationTargetId && mapping.pre_destination_target_id !== destinationTargetId) {
    fail(code, 'pre_post_mapping', 'Mapping must include destination_target_id.');
  }
  const owner = input.owner == null ? null : boundedText(input.owner, 'owner', code, { max: 120 });
  const record = {
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    kind: 'firewall_change',
    tenant_id: context.tenantId ?? null,
    destination_target_id: destinationTargetId,
    protocol,
    port,
    service_endpoint: serviceEndpoint,
    expected,
    source_perspective: sourcePerspective,
    change_id: changeId,
    pre_post_mapping: mapping,
    owner,
    status: 'active',
    expectation_version: positiveVersion(context.expectationVersion, 'expectation_version', code),
  };
  record.digest = expectationDigest(record);
  return record;
}

export function validateFirewallExpectation(input, context = {}) {
  return toResult(() => normalizeFirewallExpectation(input, context));
}

export function expectationDigest(record) {
  if (record.kind === 'firewall_change') {
    return sha256Digest({
      contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
      kind: record.kind,
      tenant_id: record.tenant_id ?? null,
      destination_target_id: record.destination_target_id,
      protocol: record.protocol,
      port: record.port ?? null,
      service_endpoint: record.service_endpoint ?? null,
      expected: record.expected,
      source_perspective: record.source_perspective,
      change_id: record.change_id,
      pre_post_mapping: record.pre_post_mapping ?? null,
      owner: record.owner ?? null,
      expectation_version: record.expectation_version,
    });
  }
  return sha256Digest({
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    kind: record.kind,
    tenant_id: record.tenant_id ?? null,
    anchor_target_id: record.anchor_target_id,
    scenario: record.scenario,
    layer_outcomes: record.layer_outcomes,
    expectation_version: record.expectation_version,
  });
}

export function firewallExpectationScopeKey(record) {
  const endpoint = record.protocol === 'service'
    ? `${record.service_endpoint?.service}:${record.service_endpoint?.port}:${record.service_endpoint?.path ?? ''}`
    : String(record.port);
  return [record.tenant_id ?? '', record.change_id, record.destination_target_id, record.protocol, endpoint, record.source_perspective].join('|');
}

export function pathValidationExpectationScopeKey(record) {
  return [record.tenant_id ?? '', record.anchor_target_id, record.scenario].join('|');
}

export function classifyFirewallExpectationWrite(existingRecords, candidate) {
  const key = firewallExpectationScopeKey(candidate);
  const active = (existingRecords ?? []).find((row) => row?.status === 'active' && firewallExpectationScopeKey(row) === key);
  if (!active) return { action: 'create', existing: null };
  if (active.digest === candidate.digest) return { action: 'replay', existing: active };
  return { action: 'conflict', existing: active, error: 'firewall_expectation_conflict', status: 409 };
}

export function isFinalizedRunStatus(status) {
  return FINALIZED_RUN_STATUSES.includes(status);
}

export function normalizeEvidenceReference(input) {
  const code = 'invalid_evidence_reference';
  if (!isPlainObject(input)) fail(code, null, 'Evidence reference must be an object.');
  const evidenceIds = input.evidence_ids ?? [];
  if (!Array.isArray(evidenceIds) || evidenceIds.length > MAX_EVIDENCE_IDS_PER_REFERENCE) {
    fail(code, 'evidence_ids', `evidence_ids must be an array of at most ${MAX_EVIDENCE_IDS_PER_REFERENCE} ids.`);
  }
  const ids = [...new Set(evidenceIds.map((id) => requireId(id, 'evidence_ids', code)))].sort();
  const versionOf = (value, field) => {
    if (value == null || value === '') return null;
    if (typeof value !== 'string' || !VERSION_PATTERN.test(value)) fail(code, field, `${field} must be a version string.`);
    return value;
  };
  const sourcePerspective = input.source_perspective == null || input.source_perspective === ''
    ? null
    : (SOURCE_PERSPECTIVE_PATTERN.test(String(input.source_perspective)) ? input.source_perspective : fail(code, 'source_perspective', 'Invalid source_perspective.'));
  const runStatus = typeof input.run_status === 'string' ? input.run_status : null;
  return {
    test_run_id: requireId(input.test_run_id, 'test_run_id', code),
    check_id: requireId(input.check_id, 'check_id', code),
    check_version: versionOf(input.check_version, 'check_version'),
    scenario_version: versionOf(input.scenario_version, 'scenario_version'),
    verdict_id: optionalId(input.verdict_id, 'verdict_id', code),
    evidence_ids: ids,
    target_id: requireId(input.target_id, 'target_id', code),
    observed_at: normalizeIsoTimestamp(input.observed_at, 'observed_at', code),
    run_status: runStatus,
    finalized: isFinalizedRunStatus(runStatus),
    source_perspective: sourcePerspective,
    worker_id: optionalId(input.worker_id, 'worker_id', code),
  };
}

function referenceSortKey(ref) {
  return `${ref.check_id}|${ref.source_perspective ?? ''}|${ref.target_id}|${ref.test_run_id}`;
}

export function normalizeComparisonEvidenceSet(input) {
  const code = 'invalid_comparison_baseline';
  if (!isPlainObject(input)) fail(code, null, 'Evidence set must be an object.');
  rejectBanned(input);
  const kind = requireEnum(input.kind, COMPARISON_KINDS, 'kind', code);
  const references = input.references;
  if (!Array.isArray(references) || references.length > MAX_EVIDENCE_REFERENCES) {
    fail(code, 'references', `references must be an array of at most ${MAX_EVIDENCE_REFERENCES} entries.`);
  }
  const expectationDigestValue = input.expectation_digest;
  if (typeof expectationDigestValue !== 'string' || !DIGEST_PATTERN.test(expectationDigestValue)) {
    fail(code, 'expectation_digest', 'expectation_digest must be a sha256 hex digest.');
  }
  const declarationDigest = input.declaration_digest == null ? null : input.declaration_digest;
  if (declarationDigest != null && (typeof declarationDigest !== 'string' || !DIGEST_PATTERN.test(declarationDigest))) {
    fail(code, 'declaration_digest', 'declaration_digest must be a sha256 hex digest.');
  }
  if (kind === 'path_validation' && declarationDigest == null) fail(code, 'declaration_digest', 'Path validation evidence must pin the entry path declaration digest.');
  const set = {
    contract_version: input.contract_version ?? PROTECTION_VALIDATION_CONTRACT_VERSION,
    kind,
    tenant_id: requireId(input.tenant_id, 'tenant_id', code),
    anchor_target_id: kind === 'path_validation' ? requireId(input.anchor_target_id, 'anchor_target_id', code) : optionalId(input.anchor_target_id, 'anchor_target_id', code),
    entry_path_id: kind === 'path_validation' ? requireId(input.entry_path_id, 'entry_path_id', code) : null,
    expectation_id: requireId(input.expectation_id, 'expectation_id', code),
    expectation_version: positiveVersion(input.expectation_version ?? null, 'expectation_version', code, null),
    expectation_digest: expectationDigestValue,
    declaration_digest: declarationDigest,
    target_id: requireId(input.target_id, 'target_id', code),
    destination_mapping: kind === 'firewall_change' ? normalizePrePostMapping(input.destination_mapping, code) : null,
    references: references.map((ref) => normalizeEvidenceReference(ref)).sort((a, b) => referenceSortKey(a).localeCompare(referenceSortKey(b))),
    captured_at: normalizeIsoTimestamp(input.captured_at, 'captured_at', code),
  };
  if (set.expectation_version == null) fail(code, 'expectation_version', 'expectation_version is required.');
  for (const ref of set.references) {
    if (ref.target_id !== set.target_id) fail(code, 'references', 'Every reference must belong to the evidence set target.');
  }
  return set;
}

export function normalizeComparisonBaseline(input, context = {}) {
  const code = 'invalid_comparison_baseline';
  const set = normalizeComparisonEvidenceSet(input);
  if (!set.references.length) fail('invalid_comparison_baseline', 'references', 'A baseline needs at least one finalized evidence reference.');
  const unfinished = set.references.find((ref) => !ref.finalized);
  if (unfinished) fail('evidence_not_finalized', 'references', `Run ${unfinished.test_run_id} is not finalized.`, 409);
  const missingSource = set.references.find((ref) => !ref.source_perspective || !ref.worker_id);
  if (missingSource) fail(code, 'references', `Run ${missingSource.test_run_id} has no recorded source/worker identity.`);
  const window = input.freshness_window_seconds ?? context.freshnessWindowSeconds ?? DEFAULT_FRESHNESS_WINDOW_SECONDS;
  if (!Number.isInteger(window) || window < MIN_FRESHNESS_WINDOW_SECONDS || window > MAX_FRESHNESS_WINDOW_SECONDS) {
    fail(code, 'freshness_window_seconds', `freshness_window_seconds must be ${MIN_FRESHNESS_WINDOW_SECONDS}-${MAX_FRESHNESS_WINDOW_SECONDS}.`);
  }
  const baseline = { ...set, freshness_window_seconds: window, immutable: true };
  baseline.baseline_digest = comparisonBaselineDigest(baseline);
  return baseline;
}

export function validateComparisonBaseline(input, context = {}) {
  return toResult(() => normalizeComparisonBaseline(input, context));
}

const EVIDENCE_SET_DIGEST_FIELDS = Object.freeze([
  'contract_version', 'kind', 'tenant_id', 'anchor_target_id', 'entry_path_id', 'expectation_id', 'expectation_version',
  'expectation_digest', 'declaration_digest', 'target_id', 'destination_mapping', 'references', 'captured_at',
]);

function pick(record, fields) {
  return Object.fromEntries(fields.map((field) => [field, record[field] ?? null]));
}

export function comparisonBaselineDigest(baseline) {
  const set = normalizeComparisonEvidenceSet(baseline);
  return sha256Digest({ ...pick(set, EVIDENCE_SET_DIGEST_FIELDS), freshness_window_seconds: baseline.freshness_window_seconds ?? null });
}

export function verifyBaselineDigest(baseline) {
  if (typeof baseline?.baseline_digest !== 'string') return false;
  try {
    return baseline.baseline_digest === comparisonBaselineDigest(baseline);
  } catch {
    return false;
  }
}

export function normalizeFirewallBaselineCapture(input, context = {}) {
  const code = 'invalid_comparison_baseline';
  if (!isPlainObject(input)) fail(code, null, 'Baseline capture must be an object.');
  rejectBanned(input);
  const changeId = input.change_id;
  if (typeof changeId !== 'string' || !CHANGE_ID_PATTERN.test(changeId)) fail(code, 'change_id', 'change_id is required.');
  if (!Array.isArray(input.entries) || input.entries.length < 1 || input.entries.length > MAX_COMPARISON_ITEMS) {
    fail(code, 'entries', `entries must list 1-${MAX_COMPARISON_ITEMS} expectation baselines.`);
  }
  const window = input.freshness_window_seconds ?? context.freshnessWindowSeconds ?? DEFAULT_FRESHNESS_WINDOW_SECONDS;
  const entries = input.entries.map((entry) => {
    if (entry?.kind !== 'firewall_change') fail(code, 'entries', 'Firewall baselines only contain firewall_change entries.');
    return normalizeComparisonBaseline({ ...entry, freshness_window_seconds: window }, context);
  });
  const tenantId = entries[0].tenant_id;
  if (entries.some((entry) => entry.tenant_id !== tenantId)) fail(code, 'entries', 'All entries must belong to one tenant.');
  const ids = entries.map((entry) => entry.expectation_id);
  if (new Set(ids).size !== ids.length) fail(code, 'entries', 'Each expectation may appear once per baseline.');
  entries.sort((a, b) => a.expectation_id.localeCompare(b.expectation_id));
  const capturedAt = normalizeIsoTimestamp(input.captured_at ?? context.now ?? new Date(), 'captured_at', code);
  const record = {
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    kind: 'firewall_change',
    tenant_id: tenantId,
    change_id: changeId,
    captured_at: capturedAt,
    freshness_window_seconds: window,
    entries,
    immutable: true,
  };
  record.baseline_digest = firewallBaselineCaptureDigest(record);
  return record;
}

export function validateFirewallBaselineCapture(input, context = {}) {
  return toResult(() => normalizeFirewallBaselineCapture(input, context));
}

export function firewallBaselineCaptureDigest(record) {
  return sha256Digest({
    contract_version: record.contract_version,
    kind: record.kind,
    tenant_id: record.tenant_id,
    change_id: record.change_id,
    captured_at: record.captured_at,
    freshness_window_seconds: record.freshness_window_seconds,
    entry_digests: (record.entries ?? []).map((entry) => [entry.expectation_id, entry.baseline_digest]),
  });
}

export function assessFreshness(capturedAt, windowSeconds, now = new Date()) {
  const captured = new Date(capturedAt).getTime();
  const reference = new Date(now).getTime();
  if (Number.isNaN(captured) || Number.isNaN(reference) || !Number.isInteger(windowSeconds)) {
    return { fresh: false, age_seconds: null, expires_at: null };
  }
  const age = Math.floor((reference - captured) / 1000);
  return {
    fresh: age >= 0 && age <= windowSeconds,
    age_seconds: age,
    expires_at: new Date(captured + windowSeconds * 1000).toISOString(),
  };
}

function groupRefs(references) {
  const map = new Map();
  for (const ref of references) {
    const key = `${ref.check_id}|${ref.source_perspective ?? ''}`;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(ref);
  }
  return map;
}

function compareByCheck(base, cand, reasons) {
  const baseGroups = groupRefs(base.references);
  const candGroups = groupRefs(cand.references);
  const baseChecks = new Set(base.references.map((ref) => ref.check_id));
  const candChecks = new Set(cand.references.map((ref) => ref.check_id));
  const sameChecks = baseChecks.size === candChecks.size && [...baseChecks].every((id) => candChecks.has(id));
  if (!sameChecks) {
    reasons.add('check_mismatch');
    return;
  }
  for (const [key, refs] of baseGroups) {
    const other = candGroups.get(key);
    if (!other) {
      reasons.add('source_mismatch');
      continue;
    }
    const versions = new Set(refs.map((ref) => ref.check_version));
    const otherVersions = new Set(other.map((ref) => ref.check_version));
    if ([...versions, ...otherVersions].some((v) => v == null) || versions.size !== 1 || otherVersions.size !== 1 || [...versions][0] !== [...otherVersions][0]) {
      reasons.add('check_version_mismatch');
    }
    if (new Set([...refs, ...other].map((ref) => ref.scenario_version ?? null)).size !== 1) reasons.add('scenario_version_mismatch');
  }
  for (const key of candGroups.keys()) {
    if (!baseGroups.has(key)) reasons.add('source_mismatch');
  }
}

function compareByScenario(base, cand, reasons) {
  const all = [...base.references, ...cand.references];
  const scenarios = new Set(all.map((ref) => ref.scenario_version ?? null));
  if (scenarios.has(null) || scenarios.size !== 1) reasons.add('scenario_version_mismatch');
  const baseSources = new Set(base.references.map((ref) => ref.source_perspective));
  const candSources = new Set(cand.references.map((ref) => ref.source_perspective));
  if (baseSources.size !== candSources.size || [...baseSources].some((source) => !candSources.has(source))) reasons.add('source_mismatch');
}

export function assessComparisonCompatibility(baseline, candidate, options = {}) {
  const reasons = new Set();
  let base;
  let cand;
  try {
    base = normalizeComparisonEvidenceSet(baseline);
  } catch {
    reasons.add('invalid_baseline');
  }
  try {
    cand = normalizeComparisonEvidenceSet(candidate);
  } catch {
    reasons.add('invalid_candidate');
  }
  if (!base || !cand) return finishCompatibility(reasons);
  if (baseline.baseline_digest != null && !verifyBaselineDigest(baseline)) reasons.add('invalid_baseline');
  if (base.contract_version !== cand.contract_version) reasons.add('contract_version_mismatch');
  if (base.kind !== cand.kind) {
    reasons.add('kind_mismatch');
    return finishCompatibility(reasons);
  }
  if (base.tenant_id !== cand.tenant_id) reasons.add('tenant_mismatch');
  if (base.expectation_id !== cand.expectation_id) reasons.add('expectation_mismatch');
  if (base.expectation_version !== cand.expectation_version) reasons.add('expectation_version_mismatch');
  if (base.expectation_digest !== cand.expectation_digest) reasons.add('expectation_digest_mismatch');
  const current = options.currentDeclarationDigests ?? null;
  if (base.kind === 'path_validation') {
    if (base.anchor_target_id !== cand.anchor_target_id) reasons.add('anchor_mismatch');
    if (options.sameEntryPath === true && base.entry_path_id !== cand.entry_path_id) reasons.add('entry_path_mismatch');
    if (base.entry_path_id === cand.entry_path_id && base.declaration_digest !== cand.declaration_digest) reasons.add('declaration_digest_mismatch');
  } else {
    if (base.declaration_digest !== cand.declaration_digest) reasons.add('declaration_digest_mismatch');
    if (base.target_id !== cand.target_id) {
      const mapping = base.destination_mapping ?? cand.destination_mapping;
      if (!mapping) reasons.add('destination_mapping_missing');
      else if (mapping.pre_destination_target_id !== base.target_id || mapping.post_destination_target_id !== cand.target_id) reasons.add('destination_mismatch');
    }
    if (Date.parse(cand.captured_at) <= Date.parse(base.captured_at)) reasons.add('candidate_not_after_baseline');
  }
  if (current) {
    for (const set of [base, cand]) {
      if (set.entry_path_id && set.declaration_digest && Object.hasOwn(current, set.entry_path_id) && current[set.entry_path_id] !== set.declaration_digest) {
        reasons.add('declaration_changed');
      }
    }
  }
  if (!base.references.length || !cand.references.length) reasons.add('evidence_missing');
  if ([...base.references, ...cand.references].some((ref) => !ref.finalized)) reasons.add('evidence_not_finalized');
  if ([...base.references, ...cand.references].some((ref) => !ref.source_perspective || !ref.worker_id)) reasons.add('source_missing');
  if (base.references.length && cand.references.length) {
    if (options.matchBy === 'scenario_version') compareByScenario(base, cand, reasons);
    else compareByCheck(base, cand, reasons);
  }
  const window = baseline.freshness_window_seconds ?? options.freshnessWindowSeconds ?? DEFAULT_FRESHNESS_WINDOW_SECONDS;
  if (base.kind === 'firewall_change' && !reasons.has('candidate_not_after_baseline') && !assessFreshness(base.captured_at, window, cand.captured_at).fresh) {
    reasons.add('baseline_stale');
  }
  if (base.kind === 'path_validation' && Math.abs(Date.parse(cand.captured_at) - Date.parse(base.captured_at)) > window * 1000) reasons.add('baseline_stale');
  if (options.now != null && !assessFreshness(cand.captured_at, window, options.now).fresh) reasons.add('candidate_stale');
  return finishCompatibility(reasons);
}

function finishCompatibility(reasons) {
  const ordered = COMPATIBILITY_REASONS.filter((reason) => reasons.has(reason));
  const stale = ordered.some((reason) => STALE_REASONS.has(reason));
  return { comparable: ordered.length === 0, stale, reasons: ordered };
}

export function compatibilityFailureStatus(compatibility) {
  if (!compatibility || compatibility.comparable) return null;
  return compatibility.reasons.every((reason) => STALE_REASONS.has(reason)) ? 'stale' : 'not_comparable';
}

export function aggregateFirewallSamples(samples) {
  const list = (Array.isArray(samples) ? samples : [samples]).filter((sample) => FIREWALL_OBSERVATION_CLASSES.includes(sample));
  const tested = list.filter((sample) => sample !== 'not_tested');
  if (!tested.length) return { observation: 'not_tested', samples: 0 };
  const distinct = [...new Set(tested)];
  return { observation: distinct.length === 1 ? distinct[0] : 'mixed', samples: tested.length, classes: distinct.sort() };
}

const UNAVAILABLE_CLASSES = new Set(['no_response', 'transport_error', 'udp_silence']);
const REACHABLE_CLASSES = new Set(['service_response_observed', 'reachable_transport_only']);

export function firewallSideState(expected, aggregate) {
  const observation = aggregate?.observation ?? 'not_tested';
  const samples = aggregate?.samples ?? 0;
  const classes = aggregate?.classes ?? [observation];
  if (observation === 'not_tested') return 'not_tested';
  if (expected === 'allow') {
    if (observation === 'service_response_observed') return 'satisfied';
    if (observation === 'explicit_denial_observed') return 'violated';
    if (UNAVAILABLE_CLASSES.has(observation)) return samples >= MIN_SAMPLES_FOR_UNAVAILABILITY ? 'not_observed' : 'unverified';
    return 'unverified';
  }
  if (expected === 'deny') {
    if (classes.some((cls) => REACHABLE_CLASSES.has(cls))) return 'violated';
    if (observation === 'explicit_denial_observed') return 'satisfied';
    return 'unverified';
  }
  return 'unverified';
}

export function classifyFirewallComparisonItem({ expectation, baseline, candidate, compatibility } = {}) {
  const expected = expectation?.expected;
  const limitations = [...REQUIRED_LIMITATIONS.firewall_change];
  const result = (status, extra = {}) => ({
    status,
    gap_kind: null,
    expectation_met: null,
    pre_state: null,
    post_state: null,
    reasons: [],
    compatibility_reasons: [],
    limitations,
    ...extra,
  });
  if (!FIREWALL_EXPECTED_BEHAVIORS.includes(expected)) return result('not_comparable', { reasons: ['expectation_missing'] });
  const post = aggregateFirewallSamples(candidate ?? []);
  if (post.observation === 'not_tested') return result('not_tested');
  const failure = compatibilityFailureStatus(compatibility ?? { comparable: false, reasons: ['evidence_missing'] });
  if (failure) return result(failure, { compatibility_reasons: [...(compatibility?.reasons ?? ['evidence_missing'])] });
  const pre = aggregateFirewallSamples(baseline ?? []);
  const preState = firewallSideState(expected, pre);
  const postState = firewallSideState(expected, post);
  if (post.classes?.includes('udp_silence') || pre.classes?.includes('udp_silence')) limitations.push('udp_silence_ambiguous');
  const base = { pre_state: preState, post_state: postState, expectation_met: postState === 'satisfied' ? true : (postState === 'violated' || postState === 'not_observed' ? false : null) };
  if (preState === 'not_tested') return result('inconclusive', { ...base, reasons: ['baseline_not_tested'] });
  if (postState === 'unverified' || preState === 'unverified') return result('inconclusive', { ...base, reasons: ['observation_unverified'] });
  if (preState === postState) return result('matched', base);
  if (preState === 'satisfied') {
    const gap = expected === 'deny' ? 'forbidden_service_newly_reachable' : 'required_service_newly_unavailable';
    return result('regression', { ...base, gap_kind: gap });
  }
  if (postState === 'satisfied') return result('improvement', base);
  return result('inconclusive', { ...base, reasons: ['states_differ_without_gap'] });
}

export function classifyPathValidationItem({
  relation,
  skipped = false,
  compatibility = null,
  primaryBaselineHealth = 'not_available',
  primaryEnforcement = 'unknown',
  observation = 'not_tested',
  enforcement = 'unknown',
} = {}) {
  const limitations = [...REQUIRED_LIMITATIONS.path_validation];
  const out = (outcome, reasons = [], compatibilityReasons = []) => ({
    outcome,
    reasons,
    compatibility_reasons: compatibilityReasons,
    limitations,
    attribution: 'unattributed',
  });
  if (skipped) return out('skipped');
  if (!relation || relation.status !== 'active') return out('inconclusive', ['relation_not_active']);
  if (!PATH_ENTRY_OBSERVATIONS.includes(observation) || observation === 'not_tested') return out('not_tested');
  if (compatibility && !compatibility.comparable) return out('inconclusive', ['evidence_not_comparable'], [...compatibility.reasons]);
  if (observation === 'no_response' || observation === 'transport_error') return out('inconclusive', [`${observation}_enforcement_unverified`]);
  const responded = observation === 'response_observed' || observation === 'application_identity_confirmed';
  if (relation.expected_behavior === 'intentionally_public') {
    return responded ? out('intentional_public_access') : out('inconclusive', ['denial_on_public_path']);
  }
  if (relation.expected_behavior === 'must_not_be_reachable') {
    if (observation === 'explicit_denial_observed') return out('consistent_enforcement');
    return out('reachability_exposure');
  }
  if (primaryBaselineHealth !== 'healthy') return out('inconclusive', ['primary_baseline_not_healthy']);
  if (primaryEnforcement !== 'enforced') return out('inconclusive', ['blocked_primary_baseline_missing']);
  if (observation === 'explicit_denial_observed' || enforcement === 'enforced') return out('consistent_enforcement');
  if (enforcement === 'partial') return out('weaker_observed_enforcement');
  if (enforcement === 'not_enforced') {
    if (observation === 'application_identity_confirmed') return out('scoped_application_bypass');
    return out('suspected_alternate_application_route', ['application_identity_not_confirmed']);
  }
  if (relation.relation_kind === 'origin' || relation.relation_kind === 'fallback_backend_route') {
    return out('reachability_exposure', ['enforcement_not_measured']);
  }
  return out('inconclusive', ['enforcement_not_measured']);
}

export function emptyLayerEvidence(layer, relation = null) {
  requireEnum(layer, PROTECTION_LAYERS, 'layer', 'invalid_comparison_evaluation');
  const declared = !relation
    ? 'undeclared'
    : (relation.required_layers ?? []).includes(layer) ? 'required' : 'not_required';
  return {
    layer,
    declared_intent: declared,
    vendor_detection: 'unknown',
    observed_enforcement: 'not_tested',
    application_identity: 'not_tested',
    suspected_bypass: 'unknown',
    confirmed_scoped_bypass: 'unknown',
    attribution: 'not_applicable',
    evidence_limitations: layer === 'ddos' ? ['external_only', 'not_capacity_assurance'] : ['external_only'],
    evidence_refs: [],
    freshness: null,
  };
}

export function emptyProtectionMatrixRow(relation) {
  if (!relation) fail('invalid_entry_path', null, 'A declared entry path is required.');
  return {
    entry_path_id: relation.id ?? null,
    anchor_target_id: relation.anchor_target_id,
    entry_target_id: relation.entry_target_id,
    relation_kind: relation.relation_kind,
    expected_behavior: relation.expected_behavior,
    required_layers: [...(relation.required_layers ?? [])],
    origin_binding_id: relation.origin_binding_id ?? null,
    status: relation.status,
    declaration_version: relation.declaration_version,
    declaration_digest: relation.declaration_digest,
    outcome: 'not_tested',
    attribution: 'unattributed',
    layers: PROTECTION_LAYERS.map((layer) => emptyLayerEvidence(layer, relation)),
    evidence_refs: [],
    latest_comparison_id: null,
    freshness: null,
    limitations: [...REQUIRED_LIMITATIONS.path_validation],
  };
}

export function normalizeLayerEvidence(input) {
  const code = 'invalid_comparison_evaluation';
  if (!isPlainObject(input)) fail(code, null, 'Layer evidence must be an object.');
  const layer = requireEnum(input.layer, PROTECTION_LAYERS, 'layer', code);
  const out = { layer };
  for (const [dimension, states] of Object.entries(LAYER_EVIDENCE_STATES)) {
    out[dimension] = requireEnum(input[dimension], states, dimension, code);
  }
  out.attribution = requireEnum(input.attribution ?? 'not_applicable', LAYER_ATTRIBUTIONS, 'attribution', code);
  const refs = Array.isArray(input.evidence_refs) ? input.evidence_refs.map((ref) => normalizeEvidenceReference(ref)) : [];
  if (refs.length > MAX_EVIDENCE_REFERENCES) fail(code, 'evidence_refs', 'Too many evidence references.');
  out.evidence_refs = refs;
  out.evidence_limitations = normalizeLimitations(input.evidence_limitations ?? ['external_only'], code);
  out.freshness = input.freshness ?? null;
  const proven = ['enforced', 'partially_enforced', 'not_enforced'].includes(out.observed_enforcement);
  if (proven && !refs.length) fail(code, 'observed_enforcement', 'Observed enforcement states require evidence references.');
  if (out.application_identity === 'confirmed' && !refs.length) fail(code, 'application_identity', 'Confirmed application identity requires evidence references.');
  if (out.confirmed_scoped_bypass === 'confirmed' && out.application_identity !== 'confirmed') {
    fail(code, 'confirmed_scoped_bypass', 'A confirmed scoped bypass requires confirmed application identity.');
  }
  if (out.attribution === 'attributed' && !refs.length) fail(code, 'attribution', 'Layer attribution requires evidence references.');
  if (layer === 'ddos' && !out.evidence_limitations.includes('not_capacity_assurance')) {
    out.evidence_limitations = normalizeLimitations([...out.evidence_limitations, 'not_capacity_assurance'], code);
  }
  return out;
}

export function normalizeLimitations(input, code = 'invalid_comparison_evaluation') {
  if (!Array.isArray(input)) fail(code, 'limitations', 'limitations must be an array.');
  const set = new Set();
  for (const value of input) set.add(requireEnum(value, PROTECTION_VALIDATION_LIMITATIONS, 'limitations', code));
  return PROTECTION_VALIDATION_LIMITATIONS.filter((value) => set.has(value));
}

export function summarizeComparisonItems(kind, items) {
  requireEnum(kind, COMPARISON_KINDS, 'kind', 'invalid_comparison_evaluation');
  const statuses = kind === 'firewall_change' ? FIREWALL_COMPARISON_STATUSES : PATH_VALIDATION_OUTCOMES;
  const byStatus = Object.fromEntries(statuses.map((status) => [status, 0]));
  const gaps = Object.fromEntries(FIREWALL_GAP_KINDS.map((gap) => [gap, 0]));
  const list = Array.isArray(items) ? items : [];
  for (const item of list) {
    const status = kind === 'firewall_change' ? item.status : item.outcome;
    if (Object.hasOwn(byStatus, status)) byStatus[status] += 1;
    if (item.gap_kind && Object.hasOwn(gaps, item.gap_kind)) gaps[item.gap_kind] += 1;
  }
  const total = list.length;
  const unresolved = kind === 'firewall_change'
    ? ['inconclusive', 'not_tested', 'stale', 'not_comparable']
    : ['inconclusive', 'not_tested', 'skipped'];
  const evaluated = total - unresolved.reduce((sum, status) => sum + byStatus[status], 0);
  const accepted = total > 0 && (kind === 'firewall_change'
    ? list.every((item) => (item.status === 'matched' || item.status === 'improvement') && item.expectation_met === true)
    : list.every((item) => item.outcome === 'consistent_enforcement' || item.outcome === 'intentional_public_access'));
  return { total, evaluated, by_status: byStatus, gaps, accepted };
}

export function normalizeComparisonEvaluation(input) {
  const code = 'invalid_comparison_evaluation';
  if (!isPlainObject(input)) fail(code, null, 'Evaluation must be an object.');
  rejectBanned(input);
  const kind = requireEnum(input.kind, COMPARISON_KINDS, 'kind', code);
  if (!Array.isArray(input.items) || input.items.length > MAX_COMPARISON_ITEMS) fail(code, 'items', `items must be an array of at most ${MAX_COMPARISON_ITEMS}.`);
  const items = input.items.map((item, index) => {
    if (!isPlainObject(item)) fail(code, `items[${index}]`, 'Each item must be an object.');
    const refs = Array.isArray(item.evidence_refs) ? item.evidence_refs.map((ref) => normalizeEvidenceReference(ref)) : [];
    const limitations = normalizeLimitations(item.limitations ?? [], code);
    const required = REQUIRED_LIMITATIONS[kind];
    for (const limitation of required) {
      if (!limitations.includes(limitation)) fail(code, `items[${index}].limitations`, `Missing required limitation ${limitation}.`);
    }
    const compatibilityReasons = (Array.isArray(item.compatibility_reasons) ? item.compatibility_reasons : [])
      .map((reason) => requireEnum(reason, COMPATIBILITY_REASONS, `items[${index}].compatibility_reasons`, code));
    if (kind === 'firewall_change') {
      const status = requireEnum(item.status, FIREWALL_COMPARISON_STATUSES, `items[${index}].status`, code);
      if (compatibilityReasons.length && !['stale', 'not_comparable', 'not_tested'].includes(status)) {
        fail('baseline_not_comparable', `items[${index}].status`, 'Incompatible evidence cannot produce matched/regression/improvement/inconclusive.', 409);
      }
      if (['stale', 'not_comparable'].includes(status) && !compatibilityReasons.length) {
        fail(code, `items[${index}].compatibility_reasons`, `${status} requires compatibility reasons.`);
      }
      const gap = item.gap_kind == null ? null : requireEnum(item.gap_kind, FIREWALL_GAP_KINDS, `items[${index}].gap_kind`, code);
      if (gap && status !== 'regression') fail(code, `items[${index}].gap_kind`, 'Only regressions carry an acceptance gap.');
      if (['matched', 'regression', 'improvement'].includes(status) && !refs.length) fail(code, `items[${index}].evidence_refs`, `${status} requires evidence references.`);
      return {
        expectation_id: requireId(item.expectation_id, `items[${index}].expectation_id`, code),
        status,
        gap_kind: gap,
        expectation_met: typeof item.expectation_met === 'boolean' ? item.expectation_met : null,
        pre_state: item.pre_state == null ? null : requireEnum(item.pre_state, FIREWALL_SIDE_STATES, `items[${index}].pre_state`, code),
        post_state: item.post_state == null ? null : requireEnum(item.post_state, FIREWALL_SIDE_STATES, `items[${index}].post_state`, code),
        reasons: Array.isArray(item.reasons) ? item.reasons.map(String).slice(0, 16) : [],
        compatibility_reasons: compatibilityReasons,
        evidence_refs: refs,
        limitations,
      };
    }
    const outcome = requireEnum(item.outcome, PATH_VALIDATION_OUTCOMES, `items[${index}].outcome`, code);
    if (!['inconclusive', 'not_tested', 'skipped'].includes(outcome) && !refs.length) {
      fail(code, `items[${index}].evidence_refs`, `${outcome} requires evidence references.`);
    }
    if (compatibilityReasons.length && !['inconclusive', 'not_tested', 'skipped'].includes(outcome)) {
      fail('baseline_not_comparable', `items[${index}].outcome`, 'Incompatible evidence can only produce inconclusive, not_tested, or skipped.', 409);
    }
    return {
      entry_path_id: requireId(item.entry_path_id, `items[${index}].entry_path_id`, code),
      scenario: typeof item.scenario === 'string' && SCENARIO_PATTERN.test(item.scenario) ? item.scenario : fail(code, `items[${index}].scenario`, 'scenario is required.'),
      outcome,
      attribution: requireEnum(item.attribution ?? 'unattributed', LAYER_ATTRIBUTIONS, `items[${index}].attribution`, code),
      reasons: Array.isArray(item.reasons) ? item.reasons.map(String).slice(0, 16) : [],
      compatibility_reasons: compatibilityReasons,
      evidence_refs: refs,
      limitations,
    };
  });
  const unionReasons = new Set(items.flatMap((item) => item.compatibility_reasons));
  const compatibility = {
    comparable: items.length > 0 && unionReasons.size === 0,
    stale: [...unionReasons].some((reason) => STALE_REASONS.has(reason)),
    reasons: COMPATIBILITY_REASONS.filter((reason) => unionReasons.has(reason)),
  };
  const evaluation = {
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    kind,
    tenant_id: requireId(input.tenant_id, 'tenant_id', code),
    baseline_id: optionalId(input.baseline_id, 'baseline_id', code),
    baseline_digest: input.baseline_digest == null ? null : (DIGEST_PATTERN.test(String(input.baseline_digest)) ? input.baseline_digest : fail(code, 'baseline_digest', 'Invalid baseline_digest.')),
    compatibility,
    items,
    summary: summarizeComparisonItems(kind, items),
    limitations: normalizeLimitations([...REQUIRED_LIMITATIONS[kind], ...(input.limitations ?? [])], code),
    evaluated_at: normalizeIsoTimestamp(input.evaluated_at, 'evaluated_at', code),
  };
  evaluation.evaluation_digest = comparisonEvaluationDigest(evaluation);
  return evaluation;
}

export function validateComparisonEvaluation(input) {
  return toResult(() => normalizeComparisonEvaluation(input));
}

const EVALUATION_DIGEST_FIELDS = Object.freeze([
  'contract_version', 'kind', 'tenant_id', 'baseline_id', 'baseline_digest', 'compatibility', 'items', 'summary', 'limitations', 'evaluated_at',
]);

export function comparisonEvaluationDigest(evaluation) {
  return sha256Digest(pick(evaluation, EVALUATION_DIGEST_FIELDS));
}

export function normalizeEntryPathComparisonRequest(input) {
  const code = 'invalid_comparison_request';
  if (!isPlainObject(input)) fail(code, null, 'Comparison request must be an object.');
  rejectBanned(input);
  const mode = requireEnum(input.mode ?? 'plan', ENTRY_PATH_COMPARISON_MODES, 'mode', code);
  const anchorTargetId = requireId(input.anchor_target_id, 'anchor_target_id', code);
  if (!Array.isArray(input.entry_path_ids) || input.entry_path_ids.length < 1 || input.entry_path_ids.length > MAX_ENTRY_PATHS_PER_COMPARISON) {
    fail(code, 'entry_path_ids', `entry_path_ids must list 1-${MAX_ENTRY_PATHS_PER_COMPARISON} declared entry paths.`);
  }
  const entryPathIds = [...new Set(input.entry_path_ids.map((id) => requireId(id, 'entry_path_ids', code)))].sort();
  const primaryEntryPathId = requireId(input.primary_entry_path_id, 'primary_entry_path_id', code);
  if (!entryPathIds.includes(primaryEntryPathId)) fail(code, 'primary_entry_path_id', 'primary_entry_path_id must be one of entry_path_ids.');
  const expectation = normalizePathValidationExpectation(input.expectation ?? {}, { anchorTargetId });
  let reviewedPlanDigest = null;
  if (mode === 'start') {
    if (typeof input.reviewed_plan_digest !== 'string' || !DIGEST_PATTERN.test(input.reviewed_plan_digest)) {
      fail(code, 'reviewed_plan_digest', 'Starting requires the digest of the reviewed plan.');
    }
    reviewedPlanDigest = input.reviewed_plan_digest;
  }
  return {
    mode,
    anchor_target_id: anchorTargetId,
    primary_entry_path_id: primaryEntryPathId,
    entry_path_ids: entryPathIds,
    expectation: { scenario: expectation.scenario, layer_outcomes: expectation.layer_outcomes },
    reviewed_plan_digest: reviewedPlanDigest,
  };
}

export function validateEntryPathComparisonRequest(input) {
  return toResult(() => normalizeEntryPathComparisonRequest(input));
}

export function entryPathComparisonPlanDigest(plan) {
  return sha256Digest({
    contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
    tenant_id: plan.tenant_id ?? null,
    anchor_target_id: plan.anchor_target_id,
    primary_entry_path_id: plan.primary_entry_path_id,
    expectation_digest: plan.expectation_digest ?? null,
    items: [...(plan.items ?? [])]
      .map((item) => ({
        entry_path_id: item.entry_path_id,
        declaration_digest: item.declaration_digest ?? null,
        target_id: item.target_id,
        check_id: item.check_id ?? null,
        check_version: item.check_version ?? null,
        origin_binding_id: item.origin_binding_id ?? null,
        eligible: item.eligible === true,
      }))
      .sort((a, b) => `${a.entry_path_id}|${a.check_id}`.localeCompare(`${b.entry_path_id}|${b.check_id}`)),
  });
}

export function normalizeFirewallBaselineRequest(input) {
  const code = 'invalid_comparison_request';
  if (!isPlainObject(input)) fail(code, null, 'Baseline request must be an object.');
  rejectBanned(input);
  const expectationIds = Array.isArray(input.expectation_ids) ? input.expectation_ids : null;
  if (!expectationIds || expectationIds.length < 1 || expectationIds.length > MAX_COMPARISON_ITEMS) fail(code, 'expectation_ids', 'expectation_ids must list declared expectations.');
  const runIds = Array.isArray(input.test_run_ids) ? input.test_run_ids : null;
  if (!runIds || runIds.length < 1 || runIds.length > MAX_EVIDENCE_REFERENCES) fail(code, 'test_run_ids', 'test_run_ids must list finalized runs.');
  const window = input.freshness_window_seconds ?? DEFAULT_FRESHNESS_WINDOW_SECONDS;
  if (!Number.isInteger(window) || window < MIN_FRESHNESS_WINDOW_SECONDS || window > MAX_FRESHNESS_WINDOW_SECONDS) fail(code, 'freshness_window_seconds', 'Invalid freshness window.');
  const changeId = input.change_id;
  if (typeof changeId !== 'string' || !CHANGE_ID_PATTERN.test(changeId)) fail(code, 'change_id', 'change_id is required.');
  return {
    change_id: changeId,
    expectation_ids: [...new Set(expectationIds.map((id) => requireId(id, 'expectation_ids', code)))].sort(),
    test_run_ids: [...new Set(runIds.map((id) => requireId(id, 'test_run_ids', code)))].sort(),
    freshness_window_seconds: window,
  };
}

export function validateFirewallBaselineRequest(input) {
  return toResult(() => normalizeFirewallBaselineRequest(input));
}

export function normalizeFirewallComparisonRequest(input) {
  const code = 'invalid_comparison_request';
  if (!isPlainObject(input)) fail(code, null, 'Comparison request must be an object.');
  rejectBanned(input);
  const runIds = Array.isArray(input.post_test_run_ids) ? input.post_test_run_ids : null;
  if (!runIds || runIds.length < 1 || runIds.length > MAX_EVIDENCE_REFERENCES) fail(code, 'post_test_run_ids', 'post_test_run_ids must list finalized post-change runs.');
  return {
    baseline_id: requireId(input.baseline_id, 'baseline_id', code),
    post_test_run_ids: [...new Set(runIds.map((id) => requireId(id, 'post_test_run_ids', code)))].sort(),
  };
}

export function validateFirewallComparisonRequest(input) {
  return toResult(() => normalizeFirewallComparisonRequest(input));
}

export function findProtectionValidationRoute(method, path) {
  return PROTECTION_VALIDATION_ROUTES.find((entry) => entry.method === method && entry.path === path) ?? null;
}
