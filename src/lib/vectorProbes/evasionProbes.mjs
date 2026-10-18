/**
 * WAF-evasion marker probe — bounded, inert normalization tester.
 * Wraps an EXISTING inert benign marker (SQLi/XSS/path) in an evasion transform
 * (encoding, canonicalization, lexical mutation, parser/framing differential, parameter
 * location, method/protocol choice) and grades whether the edge WAF still blocks it.
 * The underlying marker stays inert: we test the inspector's normalization, never deliver
 * a working payload. No count/rate/concurrency/repeat parameter is exposed.
 */

import { SUPPORTED_EVASION_TRANSFORMS } from '../probeEvidenceTiers.mjs';
import { isLiveCapabilityProbeAuthorized } from '../capabilityProbeAuth.mjs';
import { BENIGN_CLASS_MARKERS, EVASION_VARIANT_MARKERS } from '../inertWafMarkers.mjs';
import {
  markerBaselineHealth,
  markerDenialSignature,
  markerResponseSnapshot,
  readSignatureBody,
} from '../outsideInWafScanner.mjs';
import { resolveProbeRequestBudget } from '../probeRequestBudget.mjs';
import {
  applyCacheBuster,
  deriveRunNonce,
  enforcementFromGraded,
  extractSignatureBasis,
  gradeMarkerSnapshot,
  gradingMeta,
  isGradedLeg,
  postureFromEnforcement,
  redactedResponseFeature,
  shuffleWithRng,
  withSuspectedSignature,
} from './wafProbeSupport.mjs';

export const WAF_EVASION_PROBE_KIND = 'waf_evasion_marker_probe';
export const MAX_WAF_EVASION_MARKER_REQUESTS = 8;
export const EVASION_MARKER_CLASSES = Object.freeze(['sqli', 'xss', 'path_traversal']);

const MARKER_MAX_LEN = 128;

function baseMarker(markerClass) {
  return BENIGN_CLASS_MARKERS[markerClass] ?? BENIGN_CLASS_MARKERS.sqli;
}

function hex(code, width) {
  return code.toString(16).padStart(width, '0');
}

function toFullwidth(value) {
  return [...value].map((c) => {
    const code = c.codePointAt(0);
    if (code === 0x20) return '\u3000';
    if (code >= 0x21 && code <= 0x7e) return String.fromCodePoint(code + 0xfee0);
    return c;
  }).join('');
}

export const OBSERVATION_ONLY_TRANSFORMS = Object.freeze(['base64_wrap', 'numeric_repr', 'homoglyph']);
const BENIGN_PADDING_BYTES = 2048;
const MARKER_DELIVERY_MAX_BYTES = 8192;
const DEFAULT_HEADERS = Object.freeze({
  accept: 'text/html,application/xhtml+xml',
  'accept-language': 'en-US,en;q=0.9',
});

function toHomoglyph(value) {
  return value.replace(/a/g, 'а').replace(/o/gi, 'о');
}

function htmlEntities(value) {
  return [...value].map((c) => `&#${c.charCodeAt(0)};`).join('');
}

function jsEscapes(value) {
  return [...value].map((c) => `\\x${hex(c.charCodeAt(0), 2)}`).join('');
}

function jsonUnicodeEscapes(value) {
  return [...value].map((c) => `\\u${hex(c.charCodeAt(0), 4)}`).join('');
}

function cssEscapes(value) {
  return [...value].map((c) => `\\${hex(c.charCodeAt(0), 2)} `).join('');
}

function numericHex(value) {
  return [...value].map((c) => `0x${hex(c.charCodeAt(0), 2)}`).join('');
}

/**
 * Each encoder receives an inert marker and returns a variant descriptor.
 * `sent_value` is derived solely from the inert marker; supported delivery is attested on wire.
 */
function encodeComponent(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

const EVASION_TRANSFORM_ENCODERS = Object.freeze({
  double_url: (m) => ({ sent_value: encodeComponent(encodeComponent(m)) }),
  mixed_url: (m) => ({ sent_value: m.replace(/'/g, '%27').replace(/ /g, '%20').replace(/</g, '%3C') }),
  unicode_normalization: (m) => ({ sent_value: toFullwidth(m) }),
  homoglyph: (m) => ({ sent_value: toHomoglyph(m), observation_only: true }),
  overlong_utf8: (m) => ({ sent_value: encodeComponent(m).replace(/%27/g, '%C0%A7'), delivery: { encoding: 'overlong_utf8' } }),
  alt_charset: (m) => ({ sent_value: m, delivery: { content_type: 'text/plain; charset=ibm500' } }),
  html_entity: (m) => ({ sent_value: htmlEntities(m) }),
  js_escape: (m) => ({ sent_value: jsEscapes(m) }),
  json_unicode_escape: (m) => ({ sent_value: jsonUnicodeEscapes(m), delivery: { content_type: 'application/json', body_shape: 'json_string' } }),
  css_escape: (m) => ({ sent_value: cssEscapes(m) }),
  base64_wrap: (m) => ({ sent_value: Buffer.from(m, 'utf8').toString('base64'), delivery: { encoding: 'base64' }, observation_only: true }),
  numeric_repr: (m) => ({ sent_value: numericHex(m), delivery: { encoding: 'numeric' }, observation_only: true }),
  whitespace: (m) => ({ sent_value: m.replace(/ /g, '\t').replace(/-/g, '\t'), delivery: { encoding: 'whitespace_tab' } }),
  lexical_operator: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_comment : m }),
  lexical_tautology: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_case : m }),
  lexical_literal: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_case : m }),
  case_fold: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_case : m.toUpperCase() }),
  control_char: (m) => ({ sent_value: `%00${encodeComponent(m)}` }),
  path_matrix: (m) => ({ sent_value: m.replace(/\//, ';v=1/'), delivery: { where: 'path' } }),
  path_suffix: (m) => ({ sent_value: `${m}%2e`, delivery: { where: 'path' } }),
  ip_representation: (m) => ({ sent_value: m, delivery: { where: 'query', ip_form: 'decimal' } }),
  parser_hpp: (m) => ({ sent_value: m, delivery: { duplicate_param: true } }),
  parser_json_dup: (m) => ({ sent_value: m, delivery: { content_type: 'application/json', body_shape: 'duplicate_key' } }),
  parser_header_dup: (m) => ({ sent_value: m, delivery: { where: 'header', duplicate_header: true } }),
  framing_cl_te: (m) => ({ sent_value: m, delivery: { framing: 'cl_te', connection: 'close' } }),
  framing_transfer_coding: (m) => ({ sent_value: m, delivery: { framing: 'obfuscated_te', connection: 'close' } }),
  framing_h2_h1: (m) => ({ sent_value: m, delivery: { framing: 'h2_to_h1', http_version: '2', connection: 'close' } }),
  framing_line_ending: (m) => ({ sent_value: m, delivery: { framing: 'bare_lf', connection: 'close' } }),
  framing_chunk_ext: (m) => ({ sent_value: m, delivery: { framing: 'chunk_extension', connection: 'close' } }),
  body_gzip: (m) => ({ sent_value: Buffer.from(m, 'utf8').toString('base64'), delivery: { content_encoding: 'gzip' } }),
  body_nested_encoding: (m) => ({ sent_value: Buffer.from(m, 'utf8').toString('base64'), delivery: { content_encoding: 'gzip, deflate' } }),
  content_type_binary: (m) => ({ sent_value: m, delivery: { content_type: 'application/octet-stream' } }),
  struct_type_confusion: (m) => ({ sent_value: m, delivery: { content_type: 'application/json', body_shape: 'type_switch' } }),
  struct_deep_nesting: (m) => ({ sent_value: m, delivery: { content_type: 'application/json', body_shape: 'nested', depth: 6 } }),
  parameter_location: (m) => ({ sent_value: m, delivery: { where: 'cookie' } }),
  method_override: (m) => ({ sent_value: m, delivery: { method: 'POST', method_override: 'DELETE', nonce_hash_only: true } }),
  protocol_version: (m) => ({ sent_value: m, delivery: { http_version: '2' } }),
  protocol_upgrade: (m) => ({ sent_value: m, delivery: { where: 'path', upgrade: 'websocket' } }),
  benign_padding: (m) => ({ sent_value: `${'Aa'.repeat(BENIGN_PADDING_BYTES / 2)}${m}` }),
  polyglot_content: (m) => ({ sent_value: `<!--${m}-->`, delivery: { content_type: 'text/html', polyglot: true } }),
  protocol_h3_h1: (m) => ({ sent_value: m, delivery: { http_version: '3', framing: 'h3_to_h1' } }),
  protocol_qpack_hpack: (m) => ({ sent_value: m, delivery: { http_version: '3', header_compression: 'qpack' } }),
  multipart_charset: (m) => ({ sent_value: m, delivery: { content_type: 'multipart/form-data', per_part_charset: true } }),
  xml_attribute: (m) => ({ sent_value: `<a x="${m}"/>`, delivery: { content_type: 'application/xml' } }),
});

export const EVASION_TRANSFORMS = Object.freeze(Object.keys(EVASION_TRANSFORM_ENCODERS));

// Raw framing, body parsers, protocol translation and state-changing methods cannot
// be exercised by this safe GET transport. Never substitute a query GET for them.
export { SUPPORTED_EVASION_TRANSFORMS } from '../probeEvidenceTiers.mjs';
export function isSupportedEvasionTransform(transform) {
  return SUPPORTED_EVASION_TRANSFORMS.includes(transform);
}

/** Actual bounded request; unsupported descriptors never reach the transport. */
export function buildEvasionRequest(targetUrl, variant) {
  const url = new URL(targetUrl);
  const headers = { ...DEFAULT_HEADERS };
  const delivery = variant.delivery ?? {};
  if (variant.transform && !isSupportedEvasionTransform(variant.transform)) {
    throw new Error('unsupported_evasion_delivery');
  }
  const value = variant.sent_value == null ? null : String(variant.sent_value);
  if (value != null && Buffer.byteLength(value) > MARKER_DELIVERY_MAX_BYTES) throw new Error('marker_delivery_too_large');
  if (value != null && delivery.where === 'cookie') {
    headers.cookie = `astranull_probe=${encodeURIComponent(value)}`;
  } else if (value != null) {
    const rawEncoded = ['double_url', 'mixed_url', 'overlong_utf8', 'control_char'].includes(variant.transform);
    const encoded = rawEncoded ? value : encodeURIComponent(value);
    const prefix = url.search.slice(1);
    url.search = `${prefix ? `${prefix}&` : ''}${delivery.duplicate_param ? 'probe=astranull-permitted&' : ''}probe=${encoded}`;
  }
  return { url: url.href, method: 'GET', headers, delivery: {
    method: 'GET', where: value == null ? 'none' : (delivery.where === 'cookie' ? 'cookie' : 'query'),
    duplicate_param: delivery.duplicate_param === true, body_bytes: 0,
    path_unchanged: url.pathname === new URL(targetUrl).pathname,
    protocol: url.protocol.slice(0, -1), wire_value_bytes: value == null ? 0 : Buffer.byteLength(value),
  } };
}


export function isEvasionTransform(transform) {
  return Object.prototype.hasOwnProperty.call(EVASION_TRANSFORM_ENCODERS, transform);
}

/** Build a variant descriptor for a transform+class. Pure; never touches the network. */
export function applyEvasionTransform(transform, markerClass = 'sqli') {
  const encoder = EVASION_TRANSFORM_ENCODERS[transform];
  if (typeof encoder !== 'function') throw new Error(`unknown evasion transform: ${transform}`);
  const cls = EVASION_MARKER_CLASSES.includes(markerClass) ? markerClass : 'sqli';
  const marker = baseMarker(cls);
  const out = encoder(marker, cls) ?? {};
  return {
    transform,
    marker_class: cls,
    marker,
    sent_value: String(out.sent_value ?? marker),
    observation_only: out.observation_only === true || OBSERVATION_ONLY_TRANSFORMS.includes(transform),
    delivery: Object.freeze({ where: 'query', method: 'GET', ...(out.delivery ?? {}) }),
  };
}

/**
 * Build a bounded probe profile for a check. The internal budget input can only reduce or
 * cap a generated profile; no rate, concurrency, repeat, or runtime customer knob exists.
 */
export const EVASION_ENTRY_PATH_SCENARIOS = Object.freeze(['declared_login_path', 'declared_api_path']);

export function buildEvasionMarkerProfile({
  transform,
  marker_class = 'sqli',
  max_requests = 4,
  timeout_ms = 5000,
  entry_path_scenario = null,
} = {}) {
  if (!isEvasionTransform(transform)) throw new Error(`unknown evasion transform: ${transform}`);
  if (entry_path_scenario != null && !EVASION_ENTRY_PATH_SCENARIOS.includes(entry_path_scenario)) {
    throw new Error(`unknown entry_path_scenario: ${entry_path_scenario}`);
  }
  const cls = EVASION_MARKER_CLASSES.includes(marker_class) ? marker_class : 'sqli';
  const requested = Number.isInteger(max_requests) && max_requests > 0 ? max_requests : 4;
  const timeout = Number.isInteger(timeout_ms) && timeout_ms > 0
    ? Math.min(timeout_ms, 5000)
    : 5000;
  return Object.freeze({
    kind: WAF_EVASION_PROBE_KIND,
    max_requests: Math.min(requested, MAX_WAF_EVASION_MARKER_REQUESTS),
    timeout_ms: timeout,
    marker: baseMarker(cls).slice(0, MARKER_MAX_LEN),
    evasion_transform: transform,
    marker_class: cls,
    scenario_family: 'marker',
    marker_type: 'query',
    expected_action: 'block',
    nonce_hash_only: true,
    collect: ['status_code', 'waf_product_hint', 'evasion_bypass_suspected'],
    ...(entry_path_scenario ? { entry_path_scenario, permitted_baseline: true } : {}),
  });
}

function resolveTargetUrl(job) {
  const value = String(job?.target?.value ?? '').trim();
  if (!value) return null;
  try {
    return /^https?:\/\//i.test(value) ? new URL(value).href : new URL(`https://${value}/`).href;
  } catch {
    return null;
  }
}

function deadlineExceeded(job, deps) {
  const deadlineAt = Number(deps?.deadlineAt ?? job?.deadline_at ?? 0);
  if (!deadlineAt) return false;
  const now = typeof deps?.now === 'function' ? Number(deps.now()) : Date.now();
  return now >= deadlineAt;
}

function permittedSignature(snapshot) {
  if (!snapshot || snapshot.transport_error) return null;
  const signature = markerDenialSignature(snapshot, null);
  if (!signature) return null;
  const { challenge: _challenge, ...denial } = signature;
  return denial;
}

/** An evasion verdict needs the untransformed marker blocked first; anything else stays inconclusive. */
export function blockedBaselinePrerequisite(baselineBlocked) {
  if (baselineBlocked === true) return 'met';
  if (baselineBlocked === false) return 'not_met';
  return 'not_observed';
}

/**
 * Run the bounded evasion-marker probe. Sends at most MAX_WAF_EVASION_MARKER_REQUESTS inert
 * markers via the injected fetch function and grades each against a permitted baseline: blocked only
 * with a control-specific signature (a bare status code never counts). Retains status, signature id,
 * and length only; the bounded body prefix is read for signature matching and never stored.
 */
function headerGetFromResponse(res) {
  if (typeof res?.headers?.get === 'function') return (name) => res.headers.get(name);
  if (res?.headers && typeof res.headers === 'object') {
    const lower = Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [String(k).toLowerCase(), v]));
    return (name) => lower[String(name).toLowerCase()] ?? null;
  }
  return () => null;
}

function variantRow(variant, snapshot, graded, request) {
  return {
    label: variant.label ?? variant.transform,
    placement: variant.label ?? variant.transform,
    outcome: graded.outcome,
    status_code: snapshot.status_code || null,
    blocked: graded.blocked,
    allowed: graded.allowed,
    challenged: graded.challenged,
    redirected: graded.redirected,
    inconclusive: graded.inconclusive,
    block_suspected: graded.block_suspected,
    location_changed: graded.location_changed === true,
    cache_status: snapshot.cache_status ?? graded.cache_status ?? null,
    reason: graded.reason,
    ...(graded.matched_vendor ? { inconclusive_reason: graded.inconclusive_reason, matched_vendor: graded.matched_vendor } : {}),
    denial_signature: graded.denial_signature,
    signature_id: graded.denial_signature?.id ?? null,
    sent_length: variant.sent_value == null ? 0 : String(variant.sent_value).length,
    actual_delivery: request.delivery,
    ...(snapshot.transport_error ? { transport_error: true } : {}),
  };
}

export async function runWafEvasionMarkerProbe(job, deps = {}) {
  const kind = WAF_EVASION_PROBE_KIND;
  const profile = job?.probe_profile ?? {};
  const transform = profile.evasion_transform ?? profile.transform;
  const markerClass = profile.marker_class ?? 'sqli';

  if (!isLiveCapabilityProbeAuthorized(job, deps)) {
    return {
      external_result: 'error',
      metadata: {
        probe_kind: kind,
        error_class: 'live_probe_requires_signed_worker',
        simulation: 'SAFE_PROBE_SIMULATION',
        request_counting_basis: 'logical_operations',
      },
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  if (!isEvasionTransform(transform)) {
    return {
      external_result: 'error',
      metadata: { probe_kind: kind, error_class: 'invalid_evasion_transform', request_counting_basis: 'logical_operations' },
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  if (!isSupportedEvasionTransform(transform)) {
    return { external_result: 'inconclusive', metadata: {
      probe_kind: kind, classifier_version: 'marker-comparison-v4',
      evasion_transform: transform, delivery_supported: false,
      inconclusive_reason: 'unsupported_evasion_delivery',
      observation_only: true, readiness_conclusion: false, comparison_complete: false,
      planned_marker_legs: 2, completed_marker_legs: 0, variant_results: [],
      request_counting_basis: 'logical_operations',
    }, requests_sent: 0, duration_ms: 0 };
  }

  const targetUrl = resolveTargetUrl(job);
  const fetchFn = deps.fetchFn;
  if (!targetUrl || typeof fetchFn !== 'function') {
    return {
      external_result: 'error',
      metadata: { probe_kind: kind, error_class: 'unsupported_target', request_counting_basis: 'logical_operations' },
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const profileBudget = Math.max(1, Number(profile.max_requests) || 1);
  const budget = Math.min(
    profileBudget,
    resolveProbeRequestBudget(job),
    MAX_WAF_EVASION_MARKER_REQUESTS,
  );
  const declared = profile.declared_block_signature ?? null;
  const rng = typeof deps.rng === 'function' ? deps.rng : Math.random;
  const runNonce = deriveRunNonce(deps.nonce ?? job?.nonce ?? profile.nonce);
  const seq = { value: 0 };
  const applied = applyEvasionTransform(transform, markerClass);
  const observationOnly = applied.observation_only === true || OBSERVATION_ONLY_TRANSFORMS.includes(transform);

  const start = typeof deps.now === 'function' ? Number(deps.now()) : Date.now();
  const results = [];
  const features = [];
  let requestsSent = 0;
  let permitted = null;
  let trailingControl = null;
  let sourcePenalized = false;
  let transportError = false;

  const fetchSnapshot = async (variant) => {
    const request = buildEvasionRequest(targetUrl, variant);
    const busted = applyCacheBuster(request.url, runNonce, seq.value += 1);
    let snapshot;
    let headerGet = () => null;
    try {
      const response = await fetchFn(busted, { method: request.method, headers: request.headers, redirect: 'manual', signal: deps.signal });
      headerGet = headerGetFromResponse(response);
      const bodyText = await readSignatureBody(response, request.method);
      snapshot = withSuspectedSignature(markerResponseSnapshot(response, bodyText, declared), response, bodyText);
    } catch {
      snapshot = { ...markerResponseSnapshot(null), transport_error: true };
    }
    requestsSent += 1;
    return { request, snapshot: { ...snapshot, _headerGet: headerGet } };
  };

  if (!deadlineExceeded(job, deps) && !deps.signal?.aborted && !deps.jobDeadlineSignal?.aborted && budget >= 1) {
    const { snapshot } = await fetchSnapshot({ label: 'permitted_baseline', sent_value: null, delivery: { where: 'none', method: 'GET' } });
    permitted = snapshot;
    transportError = snapshot.transport_error === true;
  }

  const markerVariants = [
    { label: 'baseline', marker_class: markerClass, sent_value: baseMarker(markerClass), delivery: { where: 'query', method: 'GET' } },
    applied,
  ];
  const order = shuffleWithRng(markerVariants, rng);
  const remainingAfterPermitted = budget - requestsSent;
  const canCompleteSequence = !transportError && remainingAfterPermitted >= 3;
  const markerBudget = canCompleteSequence ? remainingAfterPermitted - 1 : 0;
  const legOrder = [];

  if (permitted && !transportError) {
    for (const variant of order.slice(0, markerBudget)) {
      if (deadlineExceeded(job, deps) || deps.signal?.aborted || deps.jobDeadlineSignal?.aborted) break;
      const { request, snapshot } = await fetchSnapshot(variant);
      const graded = gradeMarkerSnapshot(snapshot, permitted);
      const row = variantRow(variant, snapshot, graded, request);
      results.push(row);
      legOrder.push(row.label);
      features.push(redactedResponseFeature({
        placement: row.label,
        status_code: snapshot.status_code,
        signature_id: row.signature_id,
        headerGet: snapshot._headerGet,
        body_bytes: snapshot.body_bytes ?? 0,
        path: new URL(targetUrl).pathname,
        signature_basis: extractSignatureBasis(snapshot, graded),
        location_changed: graded?.location_changed === true,
        redirected: graded?.redirected === true || graded?.outcome === 'redirected',
      }));
      if (snapshot.transport_error) {
        transportError = true;
        break;
      }
    }
    if (!transportError && results.length > 0 && requestsSent < budget) {
      const { snapshot } = await fetchSnapshot({ label: 'trailing_control', sent_value: null, delivery: { where: 'none', method: 'GET' } });
      const graded = gradeMarkerSnapshot(snapshot, permitted);
      trailingControl = { outcome: graded.outcome, status_code: snapshot.status_code };
      sourcePenalized = graded.allowed !== true;
      features.push(redactedResponseFeature({
        placement: 'trailing_control',
        status_code: snapshot.status_code,
        signature_id: graded.denial_signature?.id ?? null,
        headerGet: snapshot._headerGet,
        body_bytes: snapshot.body_bytes ?? 0,
        path: new URL(targetUrl).pathname,
        signature_basis: extractSignatureBasis(snapshot, graded),
        location_changed: graded?.location_changed === true,
        redirected: graded?.redirected === true || graded?.outcome === 'redirected',
      }));
    }
  }

  const permittedHealth = permitted ? markerBaselineHealth(permitted) : 'not_available';
  const reference = results.find((row) => row.label === 'baseline') ?? null;
  const transformed = results.find((row) => row.label !== 'baseline') ?? null;
  const referenceOutcome = reference?.outcome ?? null;
  const transformOutcome = transformed?.outcome ?? null;
  const baselineBlocked = reference && !reference.inconclusive && !reference.transport_error
    ? reference.blocked === true : null;
  const prerequisite = blockedBaselinePrerequisite(baselineBlocked);
  const referenceNotEnforced = reference?.allowed === true;
  const bothGraded = isGradedLeg(reference) && isGradedLeg(transformed);
  const comparisonComplete = permittedHealth === 'healthy' && !sourcePenalized && bothGraded && !transportError;
  const normalizationGap = comparisonComplete && !observationOnly
    && reference?.blocked === true && transformed?.allowed === true;

  let externalResult;
  let evasionSuspected = false;
  let inconclusiveReason = null;
  if (permittedHealth !== 'healthy') {
    externalResult = 'inconclusive';
    inconclusiveReason = 'permitted_baseline_not_healthy';
  } else if (sourcePenalized) {
    externalResult = 'inconclusive';
    inconclusiveReason = 'source_penalized';
  } else if (prerequisite !== 'met') {
    externalResult = 'inconclusive';
    inconclusiveReason = prerequisite === 'not_met' ? 'baseline_marker_not_blocked' : 'baseline_marker_not_graded';
  } else if (normalizationGap) {
    externalResult = 'external_allowed';
    evasionSuspected = true;
  } else if (comparisonComplete && transformed?.blocked === true) {
    externalResult = 'external_blocked';
  } else if (observationOnly && comparisonComplete && transformed?.allowed === true) {
    externalResult = 'inconclusive';
    inconclusiveReason = 'observation_only_transform';
  } else {
    externalResult = 'inconclusive';
    inconclusiveReason = 'transformed_marker_not_graded';
  }

  const gradedPair = [reference, transformed].filter(isGradedLeg);
  const mapped = postureFromEnforcement(
    sourcePenalized ? 'unknown' : enforcementFromGraded(gradedPair),
    { sourcePenalized },
  );
  const end = typeof deps.now === 'function' ? Number(deps.now()) : Date.now();
  return {
    external_result: externalResult,
    metadata: {
      probe_kind: kind,
      profile_kind: kind,
      classifier_version: 'marker-comparison-v4',
      assurance_scope: 'inert_marker_rule_action_only',
      ...gradingMeta(),
      delivery_supported: true,
      planned_marker_legs: 2,
      completed_marker_legs: results.filter((row) => isGradedLeg(row)).length,
      comparison_complete: comparisonComplete,
      observation_only: observationOnly || externalResult === 'inconclusive',
      readiness_conclusion: !observationOnly && externalResult !== 'inconclusive',
      cache_buster: true,
      source_penalized: sourcePenalized,
      trailing_control: trailingControl,
      leg_order: legOrder,
      placements: results.map((row) => ({
        placement: row.placement,
        outcome: row.outcome,
        status_code: row.status_code,
        signature_id: row.signature_id,
        cache_status: row.cache_status,
        location_changed: row.location_changed,
      })),
      response_features: features,
      enforcement: mapped.enforcement,
      posture_status: mapped.posture_status,
      reference_outcome: referenceOutcome,
      transform_outcome: transformOutcome,
      normalization_gap: normalizationGap,
      reference_not_enforced: referenceNotEnforced,
      evasion_transform: transform,
      marker_class: EVASION_MARKER_CLASSES.includes(markerClass) ? markerClass : 'sqli',
      baseline_blocked: baselineBlocked,
      blocked_baseline_prerequisite: prerequisite,
      permitted_baseline_status: permitted && !permitted.connection_dropped ? permitted.status_code : null,
      permitted_baseline_health: permittedHealth,
      permitted_baseline: {
        status_code: permitted && !permitted.connection_dropped ? permitted.status_code : null,
        health: permittedHealth,
        denial_signature: permittedSignature(permitted),
      },
      baseline: permitted ? redactedResponseFeature({
        placement: 'baseline',
        status_code: permitted.status_code,
        signature_id: permittedSignature(permitted)?.id ?? null,
        headerGet: permitted._headerGet,
        body_bytes: permitted.body_bytes ?? 0,
        path: new URL(targetUrl).pathname,
      }) : null,
      ...(inconclusiveReason ? { inconclusive_reason: inconclusiveReason } : {}),
      ...(profile.entry_path_scenario && EVASION_ENTRY_PATH_SCENARIOS.includes(profile.entry_path_scenario)
        ? { entry_path_scenario: profile.entry_path_scenario }
        : {}),
      evasion_bypass_suspected: evasionSuspected,
      variant_results: results,
      request_counting_basis: 'logical_operations',
    },
    requests_sent: requestsSent,
    duration_ms: Math.max(0, end - start),
  };
}
