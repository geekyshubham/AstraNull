// Mirrors the enums in src/contracts/protectionValidation.mjs; tests/unit/protection-validation-ui.test.mjs asserts parity.
import { ORIGIN_OBSERVATION_LABELS } from '../../../lib/origin-observation.mjs';

export const PROTECTION_LAYERS = Object.freeze(['waf', 'cdn_edge', 'network_firewall', 'ddos']);

export const LAYER_LABELS = Object.freeze({
  waf: 'WAF',
  cdn_edge: 'CDN / edge',
  network_firewall: 'Network firewall',
  ddos: 'DDoS mitigation',
});

export const RELATION_KIND_LABELS = Object.freeze({
  primary_route: 'Primary route',
  alternate_hostname: 'Alternate hostname',
  declared_api_url: 'Declared service URL',
  declared_login_url: 'Declared login URL',
  origin: 'Origin',
  fallback_backend_route: 'Fallback or backend route',
});

export const EXPECTED_BEHAVIOR_LABELS = Object.freeze({
  must_be_protected_by_layers: 'Must be protected by the required layers',
  intentionally_public: 'Intentionally public',
  must_not_be_reachable: 'Must not be reachable from the internet',
});

export const LAYER_OUTCOME_LABELS = Object.freeze({
  enforce: 'Expected to enforce',
  allow: 'Expected to allow',
  not_reachable: 'Expected not reachable',
  no_expectation: 'No expectation',
});

export const PATH_OUTCOME_LABELS = Object.freeze({
  intentional_public_access: 'Allowed for this scenario; declared intentionally public',
  reachability_exposure: 'Reachable although declared otherwise',
  weaker_observed_enforcement: 'Weaker enforcement observed than on the primary route',
  suspected_alternate_application_route: 'Suspected alternate application route',
  scoped_application_bypass: 'Application bypass confirmed for this path and scenario',
  consistent_enforcement: 'Enforced for this scenario, like the primary route',
  inconclusive: 'Inconclusive; enforcement unverified',
  not_tested: 'Not tested',
  skipped: 'Skipped; not executed',
});

export const PATH_OUTCOME_TONES = Object.freeze({
  intentional_public_access: 'muted',
  reachability_exposure: 'danger',
  weaker_observed_enforcement: 'warn',
  suspected_alternate_application_route: 'warn',
  scoped_application_bypass: 'danger',
  consistent_enforcement: 'success',
  inconclusive: 'warn',
  not_tested: 'muted',
  skipped: 'muted',
});

export const FIREWALL_STATUS_LABELS = Object.freeze({
  matched: 'Matched the pre-change behavior',
  regression: 'Regression observed',
  improvement: 'Improvement observed',
  inconclusive: 'Inconclusive',
  not_tested: 'Not tested after the change',
  stale: 'Stale evidence',
  not_comparable: 'Not comparable',
});

export const FIREWALL_STATUS_TONES = Object.freeze({
  matched: 'default',
  regression: 'danger',
  improvement: 'success',
  inconclusive: 'warn',
  not_tested: 'muted',
  stale: 'warn',
  not_comparable: 'warn',
});

export const FIREWALL_GAP_LABELS = Object.freeze({
  forbidden_service_newly_reachable: 'Forbidden service newly reachable',
  required_service_newly_unavailable: 'Required service newly unavailable',
});

export const FIREWALL_SIDE_STATE_LABELS = Object.freeze({
  satisfied: 'Expectation met',
  violated: 'Expectation not met',
  not_observed: 'Not observed in repeated samples',
  unverified: 'Unverified',
  not_tested: 'Not tested',
});

export const FIREWALL_OBSERVATION_LABELS = Object.freeze({
  service_response_observed: 'Service response observed',
  reachable_transport_only: 'Transport connection only; enforcement unverified',
  explicit_denial_observed: 'Explicit denial observed; responsible control not identified',
  no_response: 'No response; enforcement unverified',
  transport_error: 'Transport error; enforcement unverified',
  udp_silence: 'UDP silence; ambiguous',
  not_tested: 'Not tested',
});

export const PATH_OBSERVATION_LABELS = Object.freeze({
  ...ORIGIN_OBSERVATION_LABELS,
  response_observed: 'Response observed',
  application_identity_confirmed: 'Response observed; application identity confirmed',
});

/** Origin wording only for direct-origin relations; every other path uses path-neutral wording. */
export function pathObservationLabels(relationKind) {
  return relationKind === 'origin' ? ORIGIN_OBSERVATION_LABELS : PATH_OBSERVATION_LABELS;
}

export const LAYER_STATE_LABELS = Object.freeze({
  declared_intent: Object.freeze({ required: 'Required', not_required: 'Not required', undeclared: 'Not declared' }),
  vendor_detection: Object.freeze({ detected: 'Detected (label only)', not_detected: 'Not detected', unknown: 'Unknown' }),
  observed_enforcement: Object.freeze({
    enforced: 'Enforced for this scenario',
    partially_enforced: 'Partly enforced for this scenario',
    not_enforced: 'Allowed for this scenario',
    inconclusive: 'Inconclusive; enforcement unverified',
    not_tested: 'Not tested',
  }),
  application_identity: Object.freeze({
    confirmed: 'Confirmed by nonce-bound canary',
    suspected: 'Suspected; not confirmed',
    not_established: 'Not established',
    not_tested: 'Not tested',
  }),
  suspected_bypass: Object.freeze({ suspected: 'Suspected', not_suspected: 'Not suspected', unknown: 'Unknown' }),
  confirmed_scoped_bypass: Object.freeze({ confirmed: 'Confirmed for this path and scenario', not_confirmed: 'Not confirmed', unknown: 'Unknown' }),
});

export const LAYER_STATE_TONES = Object.freeze({
  observed_enforcement: Object.freeze({ enforced: 'success', partially_enforced: 'warn', not_enforced: 'warn', inconclusive: 'warn', not_tested: 'muted' }),
  application_identity: Object.freeze({ confirmed: 'default', suspected: 'warn', not_established: 'muted', not_tested: 'muted' }),
  suspected_bypass: Object.freeze({ suspected: 'warn', not_suspected: 'muted', unknown: 'muted' }),
  confirmed_scoped_bypass: Object.freeze({ confirmed: 'danger', not_confirmed: 'muted', unknown: 'muted' }),
});

export const LAYER_DIMENSION_LABELS = Object.freeze({
  declared_intent: 'Declared intent',
  vendor_detection: 'Vendor detection',
  observed_enforcement: 'Observed enforcement',
  application_identity: 'Application identity',
  suspected_bypass: 'Suspected bypass',
  confirmed_scoped_bypass: 'Confirmed scoped bypass',
});

export const LIMITATION_LABELS = Object.freeze({
  external_only: 'External observation only',
  sampled_public_ingress_only: 'Sampled public ingress only',
  rule_table_equivalence_not_established: 'Rule-table equivalence not established',
  routing_nat_egress_east_west_not_established: 'Routing, NAT, egress and east-west behavior not established',
  not_capacity_assurance: 'Not a capacity or DDoS-resilience assurance',
  appliance_traversal_not_established: 'Appliance traversal not established',
  firewall_traversal_not_established: 'Firewall traversal not established',
  stacked_layer_attribution_not_established: 'Stacked layers not attributed to one control',
  transport_reachability_not_enforcement: 'A transport connection shows reachability, not enforcement',
  udp_silence_ambiguous: 'UDP silence is ambiguous',
  marker_scope_only: 'A marker validates that marker only',
  vendor_label_not_proof: 'A vendor label is not proof of enforcement',
  configuration_evidence_not_behavior: 'Configuration evidence is not observed behavior',
  untested_paths_not_covered: 'Untested paths are not covered',
  layer_not_measured_by_scenario: 'This scenario does not measure this layer',
});

export const COMPATIBILITY_REASON_LABELS = Object.freeze({
  invalid_baseline: 'The baseline record no longer matches its digest',
  invalid_candidate: 'The post-change evidence is malformed',
  contract_version_mismatch: 'Recorded under a different contract version',
  kind_mismatch: 'Different comparison kind',
  tenant_mismatch: 'Different tenant',
  expectation_mismatch: 'Different expectation',
  expectation_version_mismatch: 'Expectation version changed',
  expectation_digest_mismatch: 'Expectation content changed',
  anchor_mismatch: 'Different application anchor',
  entry_path_mismatch: 'Different entry path',
  declaration_digest_mismatch: 'Entry-path declaration differs',
  declaration_changed: 'Entry-path declaration changed after capture',
  destination_mismatch: 'Different destination',
  destination_mapping_missing: 'Destination changed without a declared pre/post mapping',
  evidence_missing: 'Evidence missing',
  evidence_not_finalized: 'Evidence not finalized',
  source_missing: 'Source perspective or worker not recorded',
  source_mismatch: 'Different source perspective',
  check_mismatch: 'Different check',
  check_version_mismatch: 'Different check version',
  scenario_version_mismatch: 'Different scenario version',
  candidate_not_after_baseline: 'Post-change evidence is not newer than the baseline',
  baseline_stale: 'Baseline outside its freshness window',
  candidate_stale: 'Post-change evidence outside the freshness window',
});

export const FINALIZED_RUN_STATUSES = Object.freeze(['verdicted', 'completed']);
export const ACTIVE_RUN_STATUSES = Object.freeze(['planned', 'queued', 'running', 'collecting']);

const STALE_REASONS = new Set(['baseline_stale', 'candidate_stale']);
const FORBIDDEN_CLAIM = /all\s+controls\s+bypass|ddos[\s-]+protected|fully\s+protected/i;

function text(value) {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function humanize(value) {
  const raw = text(value);
  if (!raw) return '';
  const spaced = raw.replace(/[_.]+/g, ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function labelFrom(map, value, fallback = 'Not recorded') {
  const key = text(value);
  if (key && Object.hasOwn(map, key)) return map[key];
  return key ? humanize(key) : fallback;
}

export function toneFrom(map, value, fallback = 'muted') {
  const key = text(value);
  return key && Object.hasOwn(map, key) ? map[key] : fallback;
}

export function containsForbiddenClaim(value) {
  return FORBIDDEN_CLAIM.test(String(value ?? ''));
}

export function layerStateLabel(dimension, value) {
  const map = LAYER_STATE_LABELS[dimension];
  return map ? labelFrom(map, value, 'Not recorded') : labelFrom({}, value);
}

export function layerStateTone(dimension, value) {
  const map = LAYER_STATE_TONES[dimension];
  return map ? toneFrom(map, value) : 'muted';
}

export function limitationLabels(values) {
  return [...new Set(list(values).map(text).filter(Boolean))].map((value) => ({ id: value, label: labelFrom(LIMITATION_LABELS, value) }));
}

export function compatibilityReasonLabels(values) {
  return [...new Set(list(values).map(text).filter(Boolean))].map((value) => ({ id: value, label: labelFrom(COMPATIBILITY_REASON_LABELS, value) }));
}

/** One customer-facing view of `{ comparable, stale, reasons }`; absent compatibility is never treated as comparable. */
export function compatibilityView(compatibility) {
  const value = record(compatibility);
  const reasons = list(value?.reasons).map(text).filter(Boolean);
  if (!value) return { state: 'unknown', label: 'Comparability not recorded', reasons: [] };
  const onlyStale = reasons.length > 0 && reasons.every((reason) => STALE_REASONS.has(reason));
  if (value.stale === true || onlyStale) return { state: 'stale', label: 'Stale: evidence is outside the freshness window', reasons: compatibilityReasonLabels(reasons) };
  if (value.comparable !== true || reasons.length) return { state: 'incompatible', label: 'Not comparable with the selected baseline', reasons: compatibilityReasonLabels(reasons) };
  return { state: 'comparable', label: 'Comparable evidence', reasons: [] };
}

/** Freshness from the server (`fresh`, `expires_at`); a missing record is unknown, never fresh. */
export function freshnessView(freshness, now = Date.now()) {
  const value = record(freshness);
  if (!value) return { state: 'unknown', label: 'Freshness not recorded' };
  const expires = Date.parse(text(value.expires_at));
  const stale = value.fresh === false || value.stale === true || (Number.isFinite(expires) && expires <= now);
  if (stale) return { state: 'stale', label: 'Stale; retest for a current result' };
  if (value.fresh === true || Number.isFinite(expires)) return { state: 'fresh', label: 'Within its freshness window' };
  return { state: 'unknown', label: 'Freshness not recorded' };
}

/** Comparison summary counts read from the server; zero evaluated items never reads as accepted. */
export function summaryView(summary, kind) {
  const value = record(summary);
  const total = Number(value?.total);
  const evaluated = Number(value?.evaluated);
  const totalOk = Number.isInteger(total) && total >= 0;
  const evaluatedOk = Number.isInteger(evaluated) && evaluated >= 0;
  const accepted = value?.accepted === true && totalOk && total > 0;
  const partial = totalOk && evaluatedOk && evaluated < total;
  let label;
  if (!totalOk) label = 'Summary not recorded';
  else if (total === 0) label = 'Nothing was evaluated, so nothing is accepted';
  else if (accepted) label = kind === 'firewall_change' ? 'Every sampled expectation matched or improved' : 'Every tested path met the expectation for this scenario';
  else if (partial) label = `${evaluated} of ${total} evaluated; the rest stay visible as not tested, skipped or inconclusive`;
  else label = 'Not accepted; review each item';
  return {
    total: totalOk ? total : null,
    evaluated: evaluatedOk ? evaluated : null,
    accepted,
    partial,
    label,
    byStatus: record(value?.by_status) ?? {},
    gaps: record(value?.gaps) ?? {},
  };
}

export function isFinalizedRun(run) {
  return FINALIZED_RUN_STATUSES.includes(text(record(run)?.status));
}

export function isActiveRun(run) {
  return ACTIVE_RUN_STATUSES.includes(text(record(run)?.status));
}

/** Why a recorded run cannot be selected as baseline or post-change evidence, or '' when it can. */
export function runSelectionBlocker(run, allowedTargetIds) {
  const value = record(run);
  if (!value) return 'Run not recorded.';
  const targetId = text(value.target_id);
  const allowed = list(allowedTargetIds).map(text).filter(Boolean);
  if (allowed.length && targetId && !allowed.includes(targetId)) return 'Recorded on a different target.';
  if (!isFinalizedRun(value)) return 'Not finalized yet; only finished, verdicted runs are evidence.';
  return '';
}

/** Progress of a started comparison from its recorded items; unknown run states stay unknown. */
export function comparisonProgress(comparison, runStatuses = {}) {
  const items = list(record(comparison)?.items).map(record).filter(Boolean);
  let started = 0;
  let finished = 0;
  let running = 0;
  let skipped = 0;
  const activeRunIds = [];
  for (const item of items) {
    const runId = text(item.test_run_id);
    if (!runId) {
      if (text(item.outcome) === 'skipped') skipped += 1;
      continue;
    }
    started += 1;
    const status = text(runStatuses[runId]);
    const done = status
      ? FINALIZED_RUN_STATUSES.includes(status) || ['cancelled', 'canceled', 'failed', 'expired'].includes(status)
      : text(item.outcome) !== 'not_tested' && text(item.outcome) !== '';
    if (done) finished += 1;
    else {
      running += 1;
      activeRunIds.push(runId);
    }
  }
  const status = text(record(comparison)?.status);
  return { total: items.length, started, finished, running: status === 'running' ? running : 0, skipped, activeRunIds: status === 'running' ? activeRunIds : [], status };
}

/** Client-side mirror of the declaration rules so mistakes surface before review; the server stays authoritative. */
export function entryPathDraftErrors(draft, anchorTargetId) {
  const value = record(draft) ?? {};
  const errors = {};
  const kind = text(value.relation_kind);
  const entry = text(value.entry_target_id);
  const behavior = text(value.expected_behavior);
  const layers = list(value.required_layers).map(text).filter((layer) => PROTECTION_LAYERS.includes(layer));
  const owner = text(value.owner);
  const purpose = text(value.purpose);
  if (!Object.hasOwn(RELATION_KIND_LABELS, kind)) errors.relation_kind = 'Choose how this path relates to the application.';
  if (!entry) errors.entry_target_id = 'Choose an existing declared target.';
  else if (kind && kind !== 'primary_route' && entry === text(anchorTargetId)) errors.entry_target_id = 'Only the primary route can point at this same target.';
  else if (kind === 'primary_route' && entry !== text(anchorTargetId)) errors.entry_target_id = 'The primary route is this target itself.';
  if (!Object.hasOwn(EXPECTED_BEHAVIOR_LABELS, behavior)) errors.expected_behavior = 'Choose the expected behavior.';
  else if (behavior === 'must_be_protected_by_layers' && layers.length === 0) errors.required_layers = 'Choose at least one required layer.';
  else if (behavior === 'intentionally_public' && layers.length > 0) errors.required_layers = 'An intentionally public path has no required layers.';
  if (kind === 'origin' && !text(value.origin_binding_id)) errors.origin_binding_id = 'An origin path needs one of this target’s declared origin relations.';
  if (!owner || owner.length > 120 || /[\u0000-\u001f\u007f]/.test(owner)) errors.owner = 'Owner is 1 to 120 characters.';
  if (!purpose || purpose.length > 500 || /[\u0000-\u001f\u007f]/.test(purpose)) errors.purpose = 'Purpose is 1 to 500 characters.';
  return errors;
}

/** Request body for `POST /v1/targets/:targetId/entry-paths`; only declared fields, never destinations. */
export function entryPathCreateBody(draft) {
  const value = record(draft) ?? {};
  const kind = text(value.relation_kind);
  return {
    entry_target_id: text(value.entry_target_id),
    relation_kind: kind,
    owner: text(value.owner),
    purpose: text(value.purpose),
    expected_behavior: text(value.expected_behavior),
    required_layers: PROTECTION_LAYERS.filter((layer) => list(value.required_layers).map(text).includes(layer)),
    origin_binding_id: kind === 'origin' ? text(value.origin_binding_id) || null : null,
  };
}

const SOURCE_PATTERN = /^[a-z0-9][a-z0-9_.:-]{0,63}$/;
const CHANGE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:#/-]{0,63}$/;
const SERVICE_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

function portOf(value) {
  const raw = text(value);
  if (!/^\d{1,5}$/.test(raw)) return null;
  const port = Number(raw);
  return port >= 1 && port <= 65535 ? port : null;
}

export function firewallDraftErrors(draft) {
  const value = record(draft) ?? {};
  const errors = {};
  const protocol = text(value.protocol);
  if (!text(value.destination_target_id)) errors.destination_target_id = 'Choose the declared destination target.';
  if (!['tcp', 'udp', 'service'].includes(protocol)) errors.protocol = 'Choose TCP, UDP or a service endpoint.';
  if ((protocol === 'tcp' || protocol === 'udp') && portOf(value.port) === null) errors.port = 'Port is a whole number from 1 to 65535.';
  if (protocol === 'service') {
    if (!SERVICE_PATTERN.test(text(value.service))) errors.service = 'Service is a short lowercase name, for example https.';
    if (portOf(value.service_port) === null) errors.service_port = 'Port is a whole number from 1 to 65535.';
    const path = text(value.service_path);
    if (path && (!path.startsWith('/') || path.includes('?') || path.includes('#') || path.length > 512)) errors.service_path = 'Path starts with / and has no query.';
  }
  if (!['allow', 'deny'].includes(text(value.expected))) errors.expected = 'Choose allow or deny.';
  if (!SOURCE_PATTERN.test(text(value.source_perspective))) errors.source_perspective = 'Use the approved source perspective identifier.';
  if (!CHANGE_PATTERN.test(text(value.change_id))) errors.change_id = 'Use your change identifier (letters, digits, and . _ : # / -).';
  const owner = text(value.owner);
  if (owner.length > 120) errors.owner = 'Owner is at most 120 characters.';
  const pre = text(value.pre_destination_target_id);
  if (pre && pre === text(value.destination_target_id)) errors.pre_destination_target_id = 'The pre-change destination must differ from this target.';
  return errors;
}

/** Request body for `POST /v1/firewall-expectations`; a pre/post mapping is sent only when the customer declared one. */
export function firewallExpectationBody(draft) {
  const value = record(draft) ?? {};
  const protocol = text(value.protocol);
  const destination = text(value.destination_target_id);
  const body = {
    destination_target_id: destination,
    protocol,
    expected: text(value.expected),
    source_perspective: text(value.source_perspective),
    change_id: text(value.change_id),
  };
  if (protocol === 'service') {
    const endpoint = { service: text(value.service), port: portOf(value.service_port) };
    const path = text(value.service_path);
    if (path) endpoint.path = path;
    body.service_endpoint = endpoint;
  } else {
    body.port = portOf(value.port);
  }
  const owner = text(value.owner);
  if (owner) body.owner = owner;
  const pre = text(value.pre_destination_target_id);
  if (pre) body.pre_post_mapping = { pre_destination_target_id: pre, post_destination_target_id: destination, declared_by_customer: true };
  return body;
}

export function firewallScopeText(expectation) {
  const value = record(expectation);
  if (!value) return 'Scope not recorded';
  const protocol = text(value.protocol);
  const endpoint = record(value.service_endpoint);
  const target = protocol === 'service' && endpoint
    ? `${text(endpoint.service) || 'service'} on port ${text(endpoint.port) || '?'}${text(endpoint.path) ? ` path ${text(endpoint.path)}` : ''}`
    : `${protocol.toUpperCase() || 'Protocol not recorded'} port ${text(value.port) || '?'}`;
  return `${target} · expected ${text(value.expected) === 'deny' ? 'deny' : text(value.expected) === 'allow' ? 'allow' : 'not recorded'} · from ${text(value.source_perspective) || 'source not recorded'}`;
}

/** Customer copy for a failed protection-validation read or write. */
export function failureCopy(failure, subject = 'this section') {
  const value = record(failure) ?? {};
  switch (text(value.state)) {
    case 'unsupported':
      return `Managing ${subject} is not available from this server yet. Nothing was changed or started.`;
    case 'disabled':
      return `Entry-path and firewall change validation is not enabled for this workspace, so ${subject} cannot be shown. Nothing was changed or started.`;
    case 'forbidden':
      return `Your role cannot read ${subject}. Ask a tenant owner or admin if you need access.`;
    case 'transport_error':
      return `The server could not be reached, so ${subject} could not load. No check was started. Retry when the connection is back.`;
    default:
      return text(value.message) || `${humanize(subject)} could not load.`;
  }
}

/** Write-error copy keyed by the documented error codes. */
export function writeErrorCopy(code, fallback) {
  const messages = {
    entry_path_conflict: 'This path is already declared for this application with different details. Archive it first to declare a new version.',
    firewall_expectation_conflict: 'An active expectation already covers this change, destination, protocol and source with different details. Archive it first.',
    origin_binding_required: 'An origin path needs one of this target’s declared origin relations.',
    origin_binding_not_allowed: 'Only origin paths use an origin relation.',
    origin_binding_mismatch: 'That origin relation joins different targets.',
    unknown_origin_binding: 'That origin relation is missing or archived.',
    required_layers_conflict: 'The required layers do not fit the expected behavior.',
    unknown_target: 'That target is not one of your declared targets.',
    target_not_active: 'That target was removed.',
    already_archived: 'This was already archived. Earlier results stay in history.',
    reviewed_plan_mismatch: 'Declarations or authorization changed since your review. Nothing started. Review the updated plan.',
    evidence_not_finalized: 'A selected run has not finished. Only finalized runs can be evidence.',
    baseline_not_comparable: 'The selected evidence is not comparable with the baseline, so no comparison was recorded.',
    scope_not_declared: 'The request included a field that is not part of a declaration.',
    forbidden: 'Your role cannot make this change.',
    not_cancellable: 'That check already finished.',
  };
  return messages[text(code)] ?? fallback;
}

/** Paths anchored on this application are manageable here; paths only entering through it belong to other anchors. */
export function splitEntryPathsByAnchor(items, targetId) {
  const anchored = [];
  const referenced = [];
  for (const item of Array.isArray(items) ? items : []) {
    if (!item || typeof item !== 'object') continue;
    if (targetId && item.anchor_target_id === targetId) anchored.push(item);
    else referenced.push(item);
  }
  return { anchored, referenced };
}

export function authorizationView(path) {
  const value = record(path) ?? {};
  if (value.currently_authorized === true) return { authorized: true, label: 'Ownership current', tone: 'default' };
  if (value.currently_authorized === false) return { authorized: false, label: 'Ownership not current; checks on this path are skipped', tone: 'warn' };
  return { authorized: null, label: 'Ownership not reported', tone: 'muted' };
}
