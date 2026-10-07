import {
  COMPATIBILITY_REASONS,
  FIREWALL_EXPECTED_BEHAVIORS,
  FIREWALL_OBSERVATION_CLASSES,
  MAX_EVIDENCE_IDS_PER_REFERENCE,
  MAX_EVIDENCE_REFERENCES,
  MIN_SAMPLES_FOR_UNAVAILABILITY,
  ProtectionValidationError,
  REQUIRED_LIMITATIONS,
  aggregateFirewallSamples,
  assessComparisonCompatibility,
  compatibilityFailureStatus,
  expectationDigest,
  firewallSideState,
  isFinalizedRunStatus,
  normalizeComparisonBaseline,
  normalizeComparisonEvaluation,
  normalizeComparisonEvidenceSet,
  normalizeFirewallBaselineCapture,
  sha256Digest,
} from '../contracts/protectionValidation.mjs';
import { evidenceTierForProbeKind } from './probeEvidenceTiers.mjs';
import { originObservationOf } from './externalObservationOutcomes.mjs';

export const FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION = 'firewall-acceptance-v3';

/** A TCP refusal indicates a closed service, not firewall enforcement. */
export const FIREWALL_DENIAL_BASES = Object.freeze(['icmp_admin_prohibited']);

export const MAX_SAMPLES_PER_SIDE = 64;
export const MAX_REFERENCES_PER_SIDE = MAX_EVIDENCE_REFERENCES;

export const FIREWALL_SUPPORTED_SERVICES = Object.freeze(['http', 'https', 'tls']);

export const FIREWALL_EVIDENCE_PROFILES = Object.freeze({
  tcp_connect: Object.freeze({ protocols: Object.freeze(['tcp']), services: Object.freeze([]), path_aware: false }),
  port_scan_bounded: Object.freeze({ protocols: Object.freeze(['tcp']), services: Object.freeze([]), path_aware: false }),
  udp_probe: Object.freeze({ protocols: Object.freeze(['udp']), services: Object.freeze([]), path_aware: false }),
  reflection_service_probe: Object.freeze({ protocols: Object.freeze(['udp']), services: Object.freeze([]), path_aware: false }),
  tls_audit: Object.freeze({ protocols: Object.freeze(['tcp', 'service']), services: Object.freeze(['https', 'tls']), path_aware: false, default_port: 443 }),
  host_sni_bypass: Object.freeze({ protocols: Object.freeze(['tcp', 'service']), services: Object.freeze(['http', 'https']), path_aware: true }),
});

export const FIREWALL_ITEM_REASONS = Object.freeze([
  'expectation_missing',
  'baseline_not_tested',
  'observation_unverified',
  'service_response_required',
  'control_specific_denial_required',
  'udp_silence_ambiguous',
  'single_sample_not_unavailability',
  'mixed_samples',
  'states_differ_without_gap',
  'baseline_denial_not_control_specific',
  'denial_not_control_specific',
  'denial_evidence_no_longer_observed',
  'not_in_baseline',
  'post_change_not_sampled',
  'no_supported_evidence_for_endpoint',
  'icmp_admin_prohibited',
  'rst_after_change',
  'rst_without_open_baseline',
]);

const TRUSTED_PRODUCER = 'signed_probe';
const NO_ATTEMPT_ERRORS = new Set([
  'unsupported_target',
  'destination_unresolved',
  'destination_not_routable',
  'live_probe_not_authorized',
  'probe_not_authorized',
]);
const SILENT_TCP_CLASSES = new Set(['no_response', 'transport_error']);
const REFUSED_ERROR_PATTERN = /ECONNREFUSED|ECONNRESET|connection_refused/i;
const DENY_REACHABLE = new Set(['service_response_observed', 'reachable_transport_only']);
const CLASS_SET = new Set(FIREWALL_OBSERVATION_CLASSES);

function validPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

function declaredTargetPort(target) {
  if (!target) return null;
  const value = String(target.value ?? '').trim();
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      return validPort(url.port) ?? (url.protocol === 'https:' ? 443 : 80);
    } catch {
      return null;
    }
  }
  const lastColon = value.lastIndexOf(':');
  if (lastColon > 0 && value.indexOf(':') === lastColon) {
    const port = validPort(value.slice(lastColon + 1));
    if (port) return port;
  }
  return validPort(target.port);
}

function shortFingerprint(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  return sha256Digest({ destination: value.trim().toLowerCase() }).slice(0, 16);
}

function requestsAttempted(metadata) {
  const attestation = metadata?.safety_attestation;
  const counts = [attestation?.probe_requests_sent, attestation?.requests_sent, metadata?.probe_requests_sent]
    .map((value) => (Number.isInteger(value) ? value : null))
    .filter((value) => value != null);
  return counts.length ? Math.max(...counts) : null;
}

/** Build one sample from a signed probe event; identity fields come from server-stamped metadata only. */
export function firewallSampleFromProbeEvent({ event, run, target = null, verdictId = null, sourcePerspective = null } = {}) {
  const metadata = event?.metadata && typeof event.metadata === 'object' ? event.metadata : {};
  const probeKind = metadata.profile_kind ?? metadata.probe_kind ?? null;
  const originScope = run?.provenance_json?.origin_scope ?? null;
  return {
    evidence_id: event?.id ?? null,
    test_run_id: run?.id ?? event?.test_run_id ?? null,
    check_id: event?.check_id ?? run?.check_id ?? null,
    check_version: run?.check_version ?? null,
    scenario_version: run?.scenario_version ?? null,
    verdict_id: verdictId,
    target_id: event?.target_id ?? run?.target_id ?? null,
    observed_at: event?.timestamp ?? null,
    run_status: run?.status ?? null,
    signal_type: event?.signal_type ?? null,
    producer_kind: event?.producer_kind ?? null,
    probe_kind: probeKind,
    external_result: metadata.external_result ?? null,
    metadata,
    worker_id: typeof metadata.probe_worker_id === 'string' && metadata.probe_worker_id ? metadata.probe_worker_id : null,
    source_perspective: sourcePerspective,
    declared_port: declaredTargetPort(target),
    origin_scope_port: validPort(originScope?.port),
    destination_fingerprint: shortFingerprint(metadata.pinned_address ?? metadata.scan_host ?? null),
  };
}

function samplePort(sample, profile) {
  const metadata = sample.metadata ?? {};
  const observation = originObservationOf(metadata);
  return validPort(metadata.target_port)
    ?? validPort(metadata.port)
    ?? validPort(observation?.scope?.port)
    ?? sample.origin_scope_port
    ?? sample.declared_port
    ?? profile.default_port
    ?? null;
}

function expectationPort(expectation) {
  return expectation.protocol === 'service' ? expectation.service_endpoint?.port ?? null : expectation.port;
}

function notApplicable(reason) {
  return { applicable: false, reason, observation_class: null, evidence_tier: null, readiness_coverage: false };
}

function applicable(sample, observationClass, extra = {}) {
  return {
    applicable: true,
    reason: null,
    observation_class: observationClass,
    evidence_tier: evidenceTierForProbeKind(sample.probe_kind),
    readiness_coverage: false,
    ...extra,
  };
}

/** Any HTTP status (401/403/421/5xx included) or TLS reply proves the port answered; only ICMP 3/13 is a control-specific denial here. */
function hostSniClass(metadata) {
  const observation = originObservationOf(metadata);
  if (!observation) return { observation_class: null };
  switch (observation.outcome) {
    case 'response_observed':
    case 'application_identity_confirmed': {
      const generic = (Number(observation.status_code) >= 500) || observation.response_reason === 'generic_error_response';
      return { observation_class: generic ? 'reachable_transport_only' : 'service_response_observed' };
    }
    case 'explicit_denial_observed':
      return { observation_class: Number.isInteger(observation.status_code) ? 'service_response_observed' : 'reachable_transport_only' };
    case 'misdirected_request':
      return { observation_class: 'service_response_observed' };
    case 'probe_path_error':
      return { observation_class: 'not_tested', sample_reason: 'probe_path_error' };
    case 'not_applicable':
      return { observation_class: 'not_tested', sample_reason: 'cdn_edge_ip' };
    case 'no_response':
      return { observation_class: 'no_response' };
    case 'transport_error':
      return {
        observation_class: 'transport_error',
        ...(observation.error_reason === 'connection_refused' ? { denial_basis: 'connection_refused' } : {}),
      };
    default:
      return { observation_class: 'not_tested' };
  }
}

function icmpAdminProhibited(metadata) {
  return metadata?.icmp_admin_prohibited === true || (Number(metadata?.icmp_type) === 3 && Number(metadata?.icmp_code) === 13);
}

function refusalBasis(metadata) {
  return REFUSED_ERROR_PATTERN.test(String(metadata?.error_class ?? '')) ? { denial_basis: 'connection_refused' } : {};
}

/** Classify one signed sample against an exact expectation endpoint; E2 transport results never count as service responses. */
export function classifyFirewallSample(expectation, sample) {
  if (!expectation || !sample) return notApplicable('missing_input');
  if (sample.signal_type !== 'probe_result' || sample.producer_kind !== TRUSTED_PRODUCER) return notApplicable('untrusted_producer');
  const profile = FIREWALL_EVIDENCE_PROFILES[sample.probe_kind];
  if (!profile) return notApplicable('unsupported_probe_kind');
  if (!profile.protocols.includes(expectation.protocol)) return notApplicable('protocol_mismatch');
  if (expectation.protocol === 'service') {
    const service = expectation.service_endpoint?.service;
    if (!FIREWALL_SUPPORTED_SERVICES.includes(service) || !profile.services.includes(service)) return notApplicable('service_not_supported_by_check');
    if (expectation.service_endpoint?.path && !profile.path_aware) return notApplicable('path_not_observed_by_check');
  }
  const metadata = sample.metadata ?? {};
  const wantedPort = expectationPort(expectation);
  const result = sample.external_result;
  if (result === 'not_run') return applicable(sample, 'not_tested', { sample_reason: 'not_run' });
  const attempts = requestsAttempted(metadata);
  if (attempts === 0 || (result === 'error' && NO_ATTEMPT_ERRORS.has(metadata.error_class))) {
    return applicable(sample, 'not_tested', { sample_reason: 'no_request_sent' });
  }

  if (sample.probe_kind === 'port_scan_bounded') {
    const open = Array.isArray(metadata.open_ports) ? metadata.open_ports.map(Number) : [];
    const filtered = Array.isArray(metadata.filtered_ports) ? metadata.filtered_ports.map(Number) : [];
    const closed = Array.isArray(metadata.closed_ports) ? metadata.closed_ports.map(Number) : [];
    if (open.includes(wantedPort)) return applicable(sample, 'reachable_transport_only');
    if (filtered.includes(wantedPort)) return applicable(sample, 'no_response');
    if (closed.includes(wantedPort)) return applicable(sample, 'transport_error', { denial_basis: 'connection_refused' });
    return notApplicable('endpoint_not_sampled');
  }

  if (samplePort(sample, profile) !== wantedPort) return notApplicable('endpoint_mismatch');
  if (sample.probe_kind !== 'tls_audit' && sample.probe_kind !== 'host_sni_bypass' && icmpAdminProhibited(metadata)) {
    return applicable(sample, 'explicit_denial_observed', { denial_basis: 'icmp_admin_prohibited' });
  }

  switch (sample.probe_kind) {
    case 'tcp_connect':
      if (result === 'connected') return applicable(sample, 'reachable_transport_only');
      if (result === 'timeout') return applicable(sample, 'no_response');
      return applicable(sample, 'transport_error', refusalBasis(metadata));
    case 'udp_probe':
    case 'reflection_service_probe':
      if (result === 'connected' && metadata.response_received !== false) return applicable(sample, 'reachable_transport_only');
      if (result === 'timeout') return applicable(sample, 'udp_silence');
      return applicable(sample, 'transport_error');
    case 'tls_audit':
      if (typeof metadata.tls_protocol === 'string' && metadata.tls_protocol && !metadata.error_class) return applicable(sample, 'service_response_observed');
      if (result === 'timeout') return applicable(sample, 'no_response');
      return applicable(sample, 'transport_error', refusalBasis(metadata));
    case 'host_sni_bypass': {
      const declaredPath = expectation.service_endpoint?.path ?? null;
      const observation = originObservationOf(metadata);
      if (!observation) return notApplicable('legacy_observation_semantics');
      if (declaredPath && (observation.scope?.path ?? null) !== declaredPath) return notApplicable('endpoint_mismatch');
      const { observation_class: observationClass, ...extra } = hostSniClass(metadata);
      return applicable(sample, observationClass, extra);
    }
    default:
      return notApplicable('unsupported_probe_kind');
  }
}

/** Pre side uses the declared pre destination; post side the declared post destination. No mapping means both are the same target. */
export function firewallSidesFor(expectation) {
  const mapping = expectation?.pre_post_mapping ?? null;
  if (mapping?.declared_by_customer === true) {
    return { pre_target_id: mapping.pre_destination_target_id, post_target_id: mapping.post_destination_target_id, mapping };
  }
  return { pre_target_id: expectation?.destination_target_id ?? null, post_target_id: expectation?.destination_target_id ?? null, mapping: null };
}

function referenceKey(sample) {
  return `${sample.test_run_id}|${sample.check_id}|${sample.worker_id ?? ''}`;
}

function earliest(values) {
  const times = values.map((value) => Date.parse(value)).filter((value) => !Number.isNaN(value));
  return times.length ? new Date(Math.min(...times)).toISOString() : null;
}

function latest(values) {
  const times = values.map((value) => Date.parse(value)).filter((value) => !Number.isNaN(value));
  return times.length ? new Date(Math.max(...times)).toISOString() : null;
}

/** Group classified samples for one side into reference-only evidence links plus compact observation records. */
export function buildFirewallSideEvidence({ expectation, samples = [], targetId }) {
  const classified = [];
  const excluded = [];
  for (const sample of samples) {
    if (sample.target_id !== targetId) continue;
    const verdict = classifyFirewallSample(expectation, sample);
    if (!verdict.applicable) {
      excluded.push({ evidence_id: sample.evidence_id, test_run_id: sample.test_run_id, reason: verdict.reason });
      continue;
    }
    classified.push({ sample, verdict });
  }
  const groups = new Map();
  for (const entry of classified) {
    const key = referenceKey(entry.sample);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(entry);
  }
  const references = [...groups.values()].map((entries) => {
    const first = entries[0].sample;
    return {
      test_run_id: first.test_run_id,
      check_id: first.check_id,
      check_version: first.check_version,
      scenario_version: first.scenario_version,
      verdict_id: first.verdict_id,
      evidence_ids: entries.map((entry) => entry.sample.evidence_id).filter(Boolean),
      target_id: first.target_id,
      observed_at: latest(entries.map((entry) => entry.sample.observed_at)),
      run_status: first.run_status,
      source_perspective: first.source_perspective,
      worker_id: first.worker_id,
    };
  });
  const observations = classified
    .map(({ sample, verdict }) => ({
      evidence_id: sample.evidence_id,
      test_run_id: sample.test_run_id,
      check_id: sample.check_id,
      observation_class: verdict.observation_class,
      evidence_tier: verdict.evidence_tier,
      source_perspective: sample.source_perspective,
      worker_id: sample.worker_id,
      destination_fingerprint: sample.destination_fingerprint ?? null,
      observed_at: sample.observed_at,
      ...(verdict.denial_basis ? { denial_basis: verdict.denial_basis } : {}),
    }))
    .sort((a, b) => `${a.test_run_id}|${a.evidence_id}`.localeCompare(`${b.test_run_id}|${b.evidence_id}`));
  const overLimit = references.length > MAX_REFERENCES_PER_SIDE
    || observations.length > MAX_SAMPLES_PER_SIDE
    || references.some((ref) => ref.evidence_ids.length > MAX_EVIDENCE_IDS_PER_REFERENCE);
  return {
    target_id: targetId,
    references,
    observations,
    excluded,
    over_limit: overLimit,
    earliest_observed_at: earliest(observations.map((obs) => obs.observed_at)),
    latest_observed_at: latest(observations.map((obs) => obs.observed_at)),
  };
}

const OBSERVATION_FIELDS = Object.freeze([
  'evidence_id', 'test_run_id', 'check_id', 'observation_class', 'evidence_tier',
  'source_perspective', 'worker_id', 'destination_fingerprint', 'observed_at', 'denial_basis',
]);

export const MAX_ENCODED_OBSERVATIONS_BYTES = 12_288;

/** Positional encoding so a full side (64 samples) fits the 16 KiB baseline provenance bound. */
export function encodeFirewallObservations(observations = []) {
  return (Array.isArray(observations) ? observations : []).map((obs) => {
    const row = OBSERVATION_FIELDS.map((field) => obs?.[field] ?? null);
    return row[row.length - 1] == null ? row.slice(0, -1) : row;
  });
}

export function decodeFirewallObservations(encoded = []) {
  if (!Array.isArray(encoded)) return [];
  return encoded.map((row) => {
    if (!Array.isArray(row)) return { ...row };
    const decoded = Object.fromEntries(OBSERVATION_FIELDS.map((field, index) => [field, row[index] ?? null]));
    if (decoded.denial_basis == null) delete decoded.denial_basis;
    return decoded;
  });
}

export function firewallObservationsDigest(observations = []) {
  return sha256Digest({
    classifier_version: FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
    observations: observations.map((obs) => ({
      evidence_id: obs.evidence_id ?? null,
      test_run_id: obs.test_run_id ?? null,
      check_id: obs.check_id ?? null,
      observation_class: obs.observation_class ?? null,
      source_perspective: obs.source_perspective ?? null,
      worker_id: obs.worker_id ?? null,
      destination_fingerprint: obs.destination_fingerprint ?? null,
      ...(obs.denial_basis ? { denial_basis: obs.denial_basis } : {}),
    })),
  });
}

/** Evidence-set input for the contract; captured_at is the latest pre observation or the earliest post observation. */
export function firewallEvidenceSetInput({ tenantId, expectationId, expectation, side, evidence }) {
  const sides = firewallSidesFor(expectation);
  return {
    kind: 'firewall_change',
    tenant_id: tenantId,
    expectation_id: expectationId,
    expectation_version: expectation.expectation_version,
    expectation_digest: expectation.digest,
    declaration_digest: null,
    target_id: evidence.target_id,
    destination_mapping: sides.mapping,
    references: evidence.references,
    captured_at: side === 'pre' ? evidence.latest_observed_at : evidence.earliest_observed_at,
  };
}

function orderReasons(reasons) {
  return COMPATIBILITY_REASONS.filter((reason) => reasons.has(reason));
}

function finish(reasons) {
  const ordered = orderReasons(reasons);
  return {
    comparable: ordered.length === 0,
    stale: ordered.some((reason) => reason === 'baseline_stale' || reason === 'candidate_stale'),
    reasons: ordered,
  };
}

/** Contract compatibility plus firewall-specific source, expectation, observation-integrity and inferred-destination checks. */
export function assessFirewallEntryCompatibility({ baselineEntry, candidateSet, expectation, candidateObservations = [], now = null } = {}) {
  const reasons = new Set();
  let base;
  try {
    base = normalizeComparisonEvidenceSet(baselineEntry);
  } catch {
    reasons.add('invalid_baseline');
  }
  if (!base) return finish(reasons);
  const contract = assessComparisonCompatibility(baselineEntry, candidateSet, now ? { now } : {});
  for (const reason of contract.reasons) reasons.add(reason);
  const storedObservations = baselineEntry.observations;
  if (!Array.isArray(storedObservations) || baselineEntry.observations_digest !== firewallObservationsDigest(storedObservations)) {
    reasons.add('invalid_baseline');
  }
  if (baselineEntry.classifier_version != null && baselineEntry.classifier_version !== FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION) {
    reasons.add('check_version_mismatch');
  }
  if (!expectation || expectation.kind !== 'firewall_change' || expectation.status !== 'active') {
    reasons.add('expectation_mismatch');
  } else {
    if (expectationDigest(expectation) !== expectation.digest) reasons.add('expectation_digest_mismatch');
    const source = expectation.source_perspective;
    const refs = [...(base.references ?? []), ...(candidateSet?.references ?? [])];
    if (refs.some((ref) => ref.source_perspective && ref.source_perspective !== source)) reasons.add('source_mismatch');
  }
  const sameTarget = candidateSet && base.target_id === candidateSet.target_id;
  if (sameTarget && !base.destination_mapping) {
    const pre = new Set((storedObservations ?? []).map((obs) => obs.destination_fingerprint).filter(Boolean));
    const post = new Set(candidateObservations.map((obs) => obs.destination_fingerprint).filter(Boolean));
    if (pre.size && post.size && ![...post].some((fp) => pre.has(fp))) reasons.add('destination_mismatch');
  }
  return finish(reasons);
}

function sideClasses(observations = []) {
  return observations.map((obs) => obs.observation_class).filter((value) => CLASS_SET.has(value));
}

/** Contract side state, refined so repeated TCP/service silence on a deny expectation is "not observed", never "satisfied". */
export function firewallObservedSideState(expected, aggregate, protocol) {
  const state = firewallSideState(expected, aggregate);
  if (expected !== 'deny' || state !== 'unverified' || protocol === 'udp') return state;
  const classes = aggregate?.classes ?? [aggregate?.observation];
  const silent = classes.length > 0 && classes.every((cls) => SILENT_TCP_CLASSES.has(cls));
  return silent && (aggregate?.samples ?? 0) >= MIN_SAMPLES_FOR_UNAVAILABILITY ? 'not_observed' : state;
}

function testedObservations(observations = []) {
  return observations.filter((obs) => CLASS_SET.has(obs?.observation_class) && obs.observation_class !== 'not_tested');
}

function allRefused(observations) {
  const tested = testedObservations(observations);
  return tested.length > 0 && tested.every((obs) => obs.observation_class === 'transport_error' && obs.denial_basis === 'connection_refused');
}

/** Basis for a control-specific firewall denial on the post side, or null. */
export function firewallDenialBasis(baselineObservations = [], candidateObservations = []) {
  const post = testedObservations(candidateObservations);
  if (post.length && post.every((obs) => obs.observation_class === 'explicit_denial_observed' && obs.denial_basis === 'icmp_admin_prohibited')) {
    return 'icmp_admin_prohibited';
  }
  return null;
}

function unverifiedReasons(expected, aggregate, protocol) {
  const reasons = [];
  const classes = aggregate?.classes ?? [];
  if (aggregate?.observation === 'mixed') reasons.push('mixed_samples');
  if (classes.includes('udp_silence')) reasons.push('udp_silence_ambiguous');
  if (expected === 'allow' && classes.includes('reachable_transport_only')) reasons.push('service_response_required');
  if (expected === 'allow' && (aggregate?.samples ?? 0) < MIN_SAMPLES_FOR_UNAVAILABILITY
    && classes.length && classes.every((cls) => cls === 'no_response' || cls === 'transport_error' || cls === 'udp_silence')) {
    reasons.push('single_sample_not_unavailability');
  }
  if (expected === 'deny' && protocol !== 'udp' && classes.length && !classes.some((cls) => DENY_REACHABLE.has(cls))) {
    reasons.push('control_specific_denial_required');
  }
  return reasons;
}

function itemResult(status, limitations, extra = {}) {
  return {
    status,
    gap_kind: null,
    expectation_met: null,
    pre_state: null,
    post_state: null,
    reasons: [],
    compatibility_reasons: [],
    limitations,
    ...extra,
  };
}

/** Per-expectation pre/post classification. Gaps are observed acceptance gaps only; no rule id or root cause is produced. */
export function classifyFirewallChangeItem({ expectation, baselineObservations = [], candidateObservations = [], compatibility = null } = {}) {
  const limitations = [...REQUIRED_LIMITATIONS.firewall_change];
  const expected = expectation?.expected;
  if (!FIREWALL_EXPECTED_BEHAVIORS.includes(expected)) {
    return itemResult('not_comparable', limitations, { reasons: ['expectation_missing'], compatibility_reasons: ['expectation_mismatch'] });
  }
  const protocol = expectation.protocol;
  const post = aggregateFirewallSamples(sideClasses(candidateObservations));
  if (post.observation === 'not_tested') return itemResult('not_tested', limitations, { reasons: ['post_change_not_sampled'] });
  const failure = compatibilityFailureStatus(compatibility ?? { comparable: false, reasons: ['evidence_missing'] });
  if (failure) return itemResult(failure, limitations, { compatibility_reasons: [...(compatibility?.reasons ?? ['evidence_missing'])] });
  const pre = aggregateFirewallSamples(sideClasses(baselineObservations));
  const basis = firewallDenialBasis(baselineObservations, candidateObservations);
  const preState = firewallObservedSideState(expected, pre, protocol);
  const postState = firewallObservedSideState(expected, post, protocol);
  if ([...(pre.classes ?? []), ...(post.classes ?? [])].includes('udp_silence')) limitations.push('udp_silence_ambiguous');
  let met = null;
  if (postState === 'satisfied') met = true;
  else if (postState === 'violated' || (expected === 'allow' && postState === 'not_observed')) met = false;
  const base = { pre_state: preState, post_state: postState, expectation_met: met };
  const basisReasons = basis ? [basis] : [];
  const resolved = (status, extra = {}) => itemResult(status, limitations, {
    ...base,
    ...extra,
    reasons: [...new Set([...(extra.reasons ?? []), ...basisReasons])],
  });
  const unresolved = (reasons) => itemResult('inconclusive', limitations, { ...base, reasons: [...new Set(reasons)] });
  const preTested = testedObservations(baselineObservations);
  const refusedWithoutOpenBaseline = !basis && allRefused(candidateObservations)
    ? [preTested.length && preTested.every((obs) => DENY_REACHABLE.has(obs.observation_class)) ? 'rst_after_change' : 'rst_without_open_baseline'] : [];

  if (preState === 'not_tested') return unresolved(['baseline_not_tested']);
  if (preState === 'unverified' || postState === 'unverified') {
    return unresolved([
      'observation_unverified',
      ...(preState === 'unverified' ? unverifiedReasons(expected, pre, protocol) : []),
      ...(postState === 'unverified' ? unverifiedReasons(expected, post, protocol) : []),
      ...refusedWithoutOpenBaseline,
    ]);
  }

  if (expected === 'allow') {
    if (preState === postState) return resolved('matched');
    if (preState === 'satisfied') return resolved('regression', { gap_kind: 'required_service_newly_unavailable' });
    if (postState === 'satisfied') return resolved('improvement');
    return unresolved(['states_differ_without_gap']);
  }

  if (postState === 'violated') {
    if (preState === 'violated') return resolved('matched');
    const reasons = preState === 'not_observed' ? ['baseline_denial_not_control_specific'] : [];
    return resolved('regression', { gap_kind: 'forbidden_service_newly_reachable', reasons });
  }
  if (postState === 'satisfied') {
    if (preState === 'satisfied') return resolved('matched');
    return resolved('improvement');
  }
  if (preState === 'satisfied') return unresolved(['denial_evidence_no_longer_observed', 'control_specific_denial_required', ...refusedWithoutOpenBaseline]);
  return unresolved(['denial_not_control_specific', 'control_specific_denial_required', ...refusedWithoutOpenBaseline]);
}

export function sideObservationSummary(expected, observations, protocol, baselineObservations = null) {
  const aggregate = aggregateFirewallSamples(sideClasses(observations));
  const basis = baselineObservations ? firewallDenialBasis(baselineObservations, observations) : null;
  const tiers = [...new Set(observations.map((obs) => obs.evidence_tier).filter(Boolean))].sort();
  const sources = [...new Set(observations.map((obs) => obs.source_perspective).filter(Boolean))].sort();
  const workers = [...new Set(observations.map((obs) => obs.worker_id).filter(Boolean))].sort();
  return {
    observation: aggregate.observation,
    samples: aggregate.samples,
    classes: aggregate.classes ?? [],
    state: firewallObservedSideState(expected, aggregate, protocol),
    denial_basis: basis,
    evidence_tiers: tiers,
    source_perspectives: sources,
    worker_ids: workers,
    readiness_coverage: false,
  };
}

const STATUS_LABELS = Object.freeze({
  matched: 'matched',
  regression: 'regressed',
  improvement: 'improved',
  inconclusive: 'inconclusive',
  not_tested: 'not tested',
  stale: 'stale',
  not_comparable: 'not comparable',
});

/** Customer-facing statement: sampled public-ingress behaviour only; equivalence beyond that is never established. */
export function firewallAcceptanceStatement(evaluation, { changeId = null, sourcePerspectives = [] } = {}) {
  const summary = evaluation?.summary ?? { total: 0, evaluated: 0, by_status: {}, gaps: {}, accepted: false };
  const counts = Object.entries(summary.by_status ?? {})
    .filter(([, count]) => count > 0)
    .map(([status, count]) => `${count} ${STATUS_LABELS[status] ?? status}`);
  const sources = sourcePerspectives.length ? sourcePerspectives.join(', ') : 'no approved source';
  const scope = `Sampled public-ingress behaviour${changeId ? ` for change ${changeId}` : ''} from ${sources}`;
  const verdict = summary.total === 0
    ? 'No expectations were evaluated, so this is not an acceptance.'
    : summary.accepted
      ? `All ${summary.total} declared expectations matched or improved with the expectation met.`
      : `${summary.evaluated} of ${summary.total} expectations were evaluated (${counts.join(', ') || 'none'}); the change is not accepted.`;
  const gaps = summary.gaps ?? {};
  const gapText = [];
  if (gaps.forbidden_service_newly_reachable) gapText.push(`${gaps.forbidden_service_newly_reachable} forbidden service newly reachable`);
  if (gaps.required_service_newly_unavailable) gapText.push(`${gaps.required_service_newly_unavailable} required service newly unavailable`);
  return {
    headline: `${scope}: ${verdict}`,
    gaps: gapText.length ? `Observed acceptance gaps: ${gapText.join('; ')}. No rule or root cause is identified.` : null,
    scope: 'Results describe sampled external probes from the approved source perspective to the declared destinations only.',
    not_established: 'Full rule-table, routing, NAT, egress and east-west equivalence are not established. Appliance traversal and capacity are not established. A port connection shows reachability, not enforcement; UDP silence is ambiguous.',
    readiness_effect: 'none',
  };
}

function itemEvidenceRefs(candidateSet) {
  return (candidateSet?.references ?? []).slice(0, MAX_EVIDENCE_REFERENCES);
}

/** Evaluate a stored capture against selected post-change samples; un-baselined active expectations of the change are reported not_tested. */
export function evaluateFirewallChange({
  tenantId,
  baseline,
  expectations = {},
  candidateSamples = [],
  extraExpectations = [],
  evaluatedAt,
  now = null,
} = {}) {
  const entries = Array.isArray(baseline?.entries) ? baseline.entries : [];
  const items = [];
  const observations = [];
  const sources = new Set();
  const claimedPostTargets = new Set(entries.map((entry) => {
    const expectation = expectations[entry.expectation_id];
    return expectation ? firewallSidesFor(expectation).post_target_id : entry.target_id;
  }));
  for (const entry of entries) {
    const expectation = expectations[entry.expectation_id] ?? null;
    if (!expectation) {
      items.push({
        expectation_id: entry.expectation_id,
        ...classifyFirewallChangeItem({ expectation: null }),
        evidence_refs: [],
      });
      continue;
    }
    if (expectation.source_perspective) sources.add(expectation.source_perspective);
    const sides = firewallSidesFor(expectation);
    let evidence = buildFirewallSideEvidence({ expectation, samples: candidateSamples, targetId: sides.post_target_id });
    if (!evidence.observations.length && !sides.mapping) {
      const unmapped = [...new Set(candidateSamples.map((sample) => sample.target_id))]
        .filter((targetId) => targetId && !claimedPostTargets.has(targetId))
        .sort()
        .map((targetId) => buildFirewallSideEvidence({ expectation, samples: candidateSamples, targetId }))
        .find((candidate) => candidate.observations.length > 0);
      if (unmapped) evidence = unmapped;
    }
    const baselineObservations = Array.isArray(entry.observations) ? entry.observations : [];
    let compatibility = null;
    let candidateSet = null;
    if (evidence.observations.length) {
      candidateSet = firewallEvidenceSetInput({ tenantId, expectationId: entry.expectation_id, expectation, side: 'post', evidence });
      compatibility = assessFirewallEntryCompatibility({
        baselineEntry: entry,
        candidateSet,
        expectation,
        candidateObservations: evidence.observations,
        now,
      });
      if (evidence.over_limit) compatibility = finish(new Set([...compatibility.reasons, 'invalid_candidate']));
    }
    const classified = classifyFirewallChangeItem({
      expectation,
      baselineObservations,
      candidateObservations: evidence.observations,
      compatibility,
    });
    items.push({
      expectation_id: entry.expectation_id,
      ...classified,
      evidence_refs: classified.status === 'not_tested' ? [] : itemEvidenceRefs(candidateSet),
    });
    observations.push({
      expectation_id: entry.expectation_id,
      pre: sideObservationSummary(expectation.expected, baselineObservations, expectation.protocol),
      post: sideObservationSummary(expectation.expected, evidence.observations, expectation.protocol, baselineObservations),
      post_target_id: evidence.target_id,
      excluded_post_samples: evidence.excluded.length,
    });
  }
  const baselined = new Set(entries.map((entry) => entry.expectation_id));
  for (const expectation of extraExpectations) {
    if (!expectation?.id || baselined.has(expectation.id)) continue;
    items.push({
      expectation_id: expectation.id,
      ...itemResult('not_tested', [...REQUIRED_LIMITATIONS.firewall_change], { reasons: ['not_in_baseline'] }),
      evidence_refs: [],
    });
  }
  const evaluation = normalizeComparisonEvaluation({
    kind: 'firewall_change',
    tenant_id: tenantId,
    baseline_id: baseline?.id ?? null,
    baseline_digest: baseline?.baseline_digest ?? null,
    items,
    limitations: items.some((item) => item.limitations.includes('udp_silence_ambiguous')) ? ['udp_silence_ambiguous'] : [],
    evaluated_at: evaluatedAt,
  });
  return {
    evaluation,
    observations,
    statement: firewallAcceptanceStatement(evaluation, { changeId: baseline?.change_id ?? null, sourcePerspectives: [...sources].sort() }),
  };
}

function baselineError(code, field, message, status = 400) {
  return new ProtectionValidationError(code, field, message, status);
}

/** Build one immutable baseline entry from finalized pre-change samples on the declared pre destination. */
export function buildFirewallBaselineEntry({ tenantId, expectationId, expectation, samples = [], freshnessWindowSeconds }) {
  if (!expectation || expectation.kind !== 'firewall_change') {
    throw baselineError('invalid_comparison_baseline', 'expectation_ids', `Expectation ${expectationId} is not a firewall expectation.`);
  }
  if (expectation.status !== 'active') throw baselineError('invalid_comparison_baseline', 'expectation_ids', `Expectation ${expectationId} is archived.`, 409);
  if (expectationDigest(expectation) !== expectation.digest) {
    throw baselineError('invalid_comparison_baseline', 'expectation_ids', `Expectation ${expectationId} failed its digest check.`, 409);
  }
  const sides = firewallSidesFor(expectation);
  const evidence = buildFirewallSideEvidence({ expectation, samples, targetId: sides.pre_target_id });
  const tested = evidence.observations.filter((obs) => obs.observation_class !== 'not_tested');
  if (!tested.length) {
    throw baselineError('invalid_comparison_baseline', 'test_run_ids', `No finalized signed evidence for expectation ${expectationId} on its declared endpoint.`);
  }
  if (evidence.over_limit) {
    throw baselineError('invalid_comparison_baseline', 'test_run_ids', `Expectation ${expectationId} exceeds ${MAX_SAMPLES_PER_SIDE} samples or ${MAX_REFERENCES_PER_SIDE} references.`);
  }
  const mismatched = evidence.references.find((ref) => ref.source_perspective && ref.source_perspective !== expectation.source_perspective);
  if (mismatched) {
    throw baselineError('invalid_comparison_baseline', 'test_run_ids', `Run ${mismatched.test_run_id} was not observed from the declared source perspective.`);
  }
  const entry = normalizeComparisonBaseline(
    firewallEvidenceSetInput({ tenantId, expectationId, expectation, side: 'pre', evidence }),
    { freshnessWindowSeconds },
  );
  return {
    entry,
    observations: evidence.observations,
    excluded: evidence.excluded,
  };
}

/** Assemble the per-change capture; observation records are re-attached because the contract keeps only digest fields. */
export function buildFirewallBaselineCapture({ tenantId, changeId, expectations = [], samples = [], freshnessWindowSeconds, capturedAt }) {
  const built = expectations.map(({ id, record }) => {
    if (record?.change_id && record.change_id !== changeId) {
      throw baselineError('invalid_comparison_baseline', 'expectation_ids', `Expectation ${id} belongs to a different change.`);
    }
    return { id, ...buildFirewallBaselineEntry({ tenantId, expectationId: id, expectation: record, samples, freshnessWindowSeconds }) };
  });
  const capture = normalizeFirewallBaselineCapture({
    change_id: changeId,
    entries: built.map((item) => item.entry),
    captured_at: capturedAt,
    freshness_window_seconds: freshnessWindowSeconds,
  });
  const byId = new Map(built.map((item) => [item.id, item]));
  capture.entries = capture.entries.map((entry) => {
    const item = byId.get(entry.expectation_id);
    return {
      ...entry,
      classifier_version: FIREWALL_ACCEPTANCE_CLASSIFIER_VERSION,
      observations: item.observations,
      observations_digest: firewallObservationsDigest(item.observations),
    };
  });
  const usedRuns = new Set(built.flatMap((item) => item.entry.references.map((ref) => ref.test_run_id)));
  return { capture, used_test_run_ids: [...usedRuns].sort() };
}

export function isFinalizedRun(run) {
  return isFinalizedRunStatus(run?.status);
}
