/**
 * WAF-evasion marker probe — bounded, inert normalization tester.
 * Wraps an EXISTING inert benign marker (SQLi/XSS/path) in an evasion transform
 * (encoding, canonicalization, lexical mutation, parser/framing differential, parameter
 * location, method/protocol choice) and grades whether the edge WAF still blocks it.
 * The underlying marker stays inert: we test the inspector's normalization, never deliver
 * a working payload. No count/rate/concurrency/repeat parameter is exposed.
 */

import { isLiveCapabilityProbeAuthorized } from '../capabilityProbeAuth.mjs';
import {
  BENIGN_CLASS_MARKERS,
  EVASION_VARIANT_MARKERS,
  isBlockedOrChallenged,
  markerBaselineHealth,
  markerDenialSignature,
  markerResponseSnapshot,
  readSignatureBody,
} from '../outsideInWafScanner.mjs';
import { resolveProbeRequestBudget } from '../probeRequestBudget.mjs';

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

const FULLWIDTH = Object.freeze({
  a: 'ａ', s: 'ｓ', t: 'ｔ', r: 'ｒ', n: 'ｕ', u: 'ｕ', l: 'ｌ',
});

function toFullwidth(value) {
  return [...value].map((c) => FULLWIDTH[c] ?? c).join('');
}

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
 * `sent_value` is derived solely from the inert marker; `delivery` is metadata only.
 */
const EVASION_TRANSFORM_ENCODERS = Object.freeze({
  double_url: (m) => ({ sent_value: encodeURIComponent(encodeURIComponent(m)) }),
  mixed_url: (m) => ({ sent_value: m.replace(/'/g, '%27').replace(/ /g, '%20').replace(/</g, '%3C') }),
  unicode_normalization: (m) => ({ sent_value: toFullwidth(m) }),
  homoglyph: (m) => ({ sent_value: toHomoglyph(m) }),
  overlong_utf8: (m) => ({ sent_value: m.replace(/'/g, '%C0%A7'), delivery: { encoding: 'overlong_utf8' } }),
  alt_charset: (m) => ({ sent_value: m, delivery: { content_type: 'text/plain; charset=ibm500' } }),
  html_entity: (m) => ({ sent_value: htmlEntities(m) }),
  js_escape: (m) => ({ sent_value: jsEscapes(m) }),
  json_unicode_escape: (m) => ({ sent_value: jsonUnicodeEscapes(m), delivery: { content_type: 'application/json', body_shape: 'json_string' } }),
  css_escape: (m) => ({ sent_value: cssEscapes(m) }),
  base64_wrap: (m) => ({ sent_value: Buffer.from(m, 'utf8').toString('base64'), delivery: { encoding: 'base64' } }),
  numeric_repr: (m) => ({ sent_value: numericHex(m), delivery: { encoding: 'numeric' } }),
  whitespace: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_comment : m.replace(/-/g, '%09') }),
  lexical_operator: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_comment : m }),
  lexical_tautology: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_case : m }),
  lexical_literal: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_case : m }),
  case_fold: (m, cls) => ({ sent_value: cls === 'sqli' ? EVASION_VARIANT_MARKERS.sqli_case : m.toUpperCase() }),
  control_char: (m) => ({ sent_value: `%00${m}` }),
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
  benign_padding: (m) => ({ sent_value: `padding-padding-${m}` }),
  polyglot_content: (m) => ({ sent_value: `<!--${m}-->`, delivery: { content_type: 'text/html', polyglot: true } }),
  protocol_h3_h1: (m) => ({ sent_value: m, delivery: { http_version: '3', framing: 'h3_to_h1' } }),
  protocol_qpack_hpack: (m) => ({ sent_value: m, delivery: { http_version: '3', header_compression: 'qpack' } }),
  multipart_charset: (m) => ({ sent_value: m, delivery: { content_type: 'multipart/form-data', per_part_charset: true } }),
  xml_attribute: (m) => ({ sent_value: `<a x="${m}"/>`, delivery: { content_type: 'application/xml' } }),
});

export const EVASION_TRANSFORMS = Object.freeze(Object.keys(EVASION_TRANSFORM_ENCODERS));

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

function variantSequence(transform, markerClass) {
  const cls = EVASION_MARKER_CLASSES.includes(markerClass) ? markerClass : 'sqli';
  return [
    { label: 'permitted_baseline', marker_class: cls, sent_value: null, delivery: { where: 'none', method: 'GET' } },
    { label: 'baseline', marker_class: cls, sent_value: baseMarker(cls), delivery: { where: 'query', method: 'GET' } },
    applyEvasionTransform(transform, cls),
  ];
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
export async function runWafEvasionMarkerProbe(job, deps = {}) {
  const kind = WAF_EVASION_PROBE_KIND;
  const profile = job?.probe_profile ?? {};
  const transform = profile.evasion_transform;
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
  const variants = variantSequence(transform, markerClass).slice(0, budget);
  const declared = profile.declared_block_signature ?? null;

  const start = typeof deps.now === 'function' ? Number(deps.now()) : Date.now();
  const results = [];
  let requestsSent = 0;
  let permitted = null;
  let baselineBlocked = null;

  for (const variant of variants) {
    if (deadlineExceeded(job, deps)) break;
    const requestUrl = new URL(targetUrl);
    if (variant.sent_value != null) requestUrl.searchParams.set('probe', variant.sent_value.slice(0, 512));
    const method = variant.delivery?.method === 'POST' ? 'GET' : (variant.delivery?.method ?? 'GET');
    let snapshot;
    try {
      const response = await fetchFn(requestUrl.href, { method, redirect: 'manual', signal: deps.signal });
      snapshot = markerResponseSnapshot(response, await readSignatureBody(response, method), declared);
    } catch {
      snapshot = { ...markerResponseSnapshot(null), transport_error: true };
    }
    requestsSent += 1;
    if (variant.label === 'permitted_baseline') {
      permitted = snapshot;
      if (snapshot.transport_error) break;
      continue;
    }
    const graded = isBlockedOrChallenged(snapshot, permitted);
    if (variant.label === 'baseline' && !graded.inconclusive) baselineBlocked = graded.blocked === true;
    results.push({
      label: variant.label ?? variant.transform,
      status_code: snapshot.status_code || null,
      blocked: graded.blocked,
      allowed: graded.allowed,
      inconclusive: graded.inconclusive,
      block_suspected: graded.block_suspected,
      reason: graded.reason,
      denial_signature: graded.denial_signature,
      sent_length: variant.sent_value.length,
      ...(snapshot.transport_error ? { transport_error: true } : {}),
    });
    if (snapshot.transport_error || requestsSent >= budget) break;
  }

  const permittedHealth = permitted ? markerBaselineHealth(permitted) : 'not_available';
  const prerequisite = blockedBaselinePrerequisite(baselineBlocked);
  const transformedResults = results.filter((r) => r.label !== 'baseline' && !r.inconclusive && !r.transport_error);
  const anyTransformedAllowed = transformedResults.some((r) => r.allowed);
  const allTransformedBlocked = transformedResults.length > 0 && transformedResults.every((r) => r.blocked);

  let externalResult;
  let evasionSuspected = false;
  let inconclusiveReason = null;
  if (permittedHealth !== 'healthy') {
    externalResult = 'inconclusive';
    inconclusiveReason = 'permitted_baseline_not_healthy';
  } else if (prerequisite !== 'met') {
    externalResult = 'inconclusive';
    inconclusiveReason = prerequisite === 'not_met' ? 'baseline_marker_not_blocked' : 'baseline_marker_not_graded';
  } else if (anyTransformedAllowed) {
    externalResult = 'external_allowed';
    evasionSuspected = true;
  } else if (allTransformedBlocked) {
    externalResult = 'external_blocked';
  } else {
    externalResult = 'inconclusive';
    inconclusiveReason = 'transformed_marker_not_graded';
  }

  const end = typeof deps.now === 'function' ? Number(deps.now()) : Date.now();
  return {
    external_result: externalResult,
    metadata: {
      probe_kind: kind,
      profile_kind: kind,
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
