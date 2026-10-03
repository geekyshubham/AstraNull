/**
 * Shared WAF/CDN edge-detection projection.
 *
 * One source of truth for turning a signed probe-result's `edge_signature` into the WAF/CDN answer
 * shown in the API, stored per target, and rendered in the portal. Provider families come only from
 * typed corpus evidence — response vendor matches and the corpus's explicit address/CNAME type — never
 * from a provider name heuristic (ADR-0005).
 *
 * Output carries signal labels and provider names only. Raw header values, cookie values, and
 * block-page bodies never reach this layer and must never be added to it.
 */

import { buildEdgeLayers } from './edgeFingerprint.mjs';

const MAX_LIST_ITEMS = 64;
const MAX_EVIDENCE_VENDORS = 5;
const MAX_EVIDENCE_MATCHES = 12;
const MAX_CHAIN_ITEMS = 12;

export const EDGE_DETECTION_STATUSES = Object.freeze([
  'detected',
  'not_detected',
  'inconclusive',
  'error',
  'pending',
]);

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function boundedString(value, maxLength = 160) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function boundedList(value, limit = MAX_LIST_ITEMS) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const entry of value.slice(0, limit)) {
    const text = boundedString(entry);
    if (text && !out.includes(text)) out.push(text);
  }
  return out;
}


function boundedConfidence(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(1, Math.max(0, number)) : 0;
}

function boundedPortList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.slice(0, MAX_LIST_ITEMS)
    .map(Number)
    .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65_535))]
    .sort((left, right) => left - right);
}

function markerClassStatus(markerResults, family) {
  const row = markerResults.find((entry) => (
    entry?.family === family && entry?.variant === 'plain'
  ));
  if (!row) return 'not_tested';
  if (boundedString(row.error_class) || row.inconclusive === true) return 'inconclusive';
  if (row.blocked === true && row.allowed !== true) return 'blocked';
  if (row.allowed === true && row.blocked !== true) return 'passed';
  return 'inconclusive';
}

function groupedMarkerStatus(rows) {
  if (!rows.length) return 'not_tested';
  if (rows.some((row) => row.allowed === true && row.blocked !== true)) return 'bypass_observed';
  if (rows.some((row) => (
    boundedString(row.error_class)
    || row.inconclusive === true
    || row.blocked === row.allowed
  ))) return 'inconclusive';
  return rows.every((row) => row.blocked === true) ? 'blocked' : 'inconclusive';
}

/**
 * Effectiveness is computed only from definitive, bounded marker outcomes. A transport failure is
 * never a block, and a zero denominator is represented as null rather than a fictitious 0% score.
 */
export function assessWafEffectiveness({
  wafPresent = null,
  markerResults = [],
  coverageComplete,
  transportError = false,
  inspectionLimitBypassSuspected,
} = {}) {
  const rows = (Array.isArray(markerResults) ? markerResults : [])
    .slice(0, MAX_LIST_ITEMS)
    .filter((row) => asRecord(row));
  let blockedCount = 0;
  let passedCount = 0;
  let inconclusiveCount = 0;
  for (const row of rows) {
    const hasError = boundedString(row.error_class) || row.inconclusive === true;
    if (!hasError && row.blocked === true && row.allowed !== true) blockedCount += 1;
    else if (!hasError && row.allowed === true && row.blocked !== true) passedCount += 1;
    else inconclusiveCount += 1;
  }

  const testedCount = blockedCount + passedCount;
  const percentage = testedCount === 0
    ? null
    : Math.round((blockedCount / testedCount) * 10_000) / 100;
  const requiredClassCoverageComplete = [
    'sqli_marker',
    'xss_marker',
    'path_traversal_marker',
  ].every((family) => ['blocked', 'passed'].includes(markerClassStatus(rows, family)));
  let status = 'inconclusive';
  if (!transportError && inconclusiveCount === 0) {
    if (wafPresent === false) status = 'no_waf_detected';
    else if (wafPresent === true && testedCount > 0) {
      if (passedCount > 0) {
        status = blockedCount === 0 && requiredClassCoverageComplete
          ? 'present_but_not_effective'
          : 'partially_effective';
      } else if (requiredClassCoverageComplete) {
        status = 'effective_for_tested_probes';
      }
    }
  }

  const labels = {
    no_waf_detected: 'No WAF detected',
    present_but_not_effective: 'Present but not effective',
    effective_for_tested_probes: 'Effective for tested probes',
    partially_effective: 'Partially effective',
    inconclusive: 'Inconclusive',
  };
  const evasionRows = rows.filter((row) => row.variant && row.variant !== 'plain'
    && row.family !== 'combined_marker');
  return {
    status,
    label: labels[status],
    attempted_count: rows.length,
    tested_count: testedCount,
    blocked_count: blockedCount,
    passed_count: passedCount,
    inconclusive_count: inconclusiveCount,
    percentage: status === 'no_waf_detected' ? null : percentage,
    coverage_complete: typeof coverageComplete === 'boolean' ? coverageComplete : null,
    required_class_coverage_complete: requiredClassCoverageComplete,
    per_class: {
      sqli: markerClassStatus(rows, 'sqli_marker'),
      xss: markerClassStatus(rows, 'xss_marker'),
      path_traversal: markerClassStatus(rows, 'path_traversal_marker'),
      evasion_variants: groupedMarkerStatus(evasionRows),
      content_type_confusion: groupedMarkerStatus(
        rows.filter((row) => row.family === 'content_type_confusion'),
      ),
      multipart_confusion: groupedMarkerStatus(
        rows.filter((row) => row.family === 'multipart_confusion'),
      ),
      inspection_limit: inspectionLimitBypassSuspected === true
        ? 'bypass_observed'
        : inspectionLimitBypassSuspected === false ? 'no_bypass_observed' : 'not_tested',
    },
  };
}

function sanitizeLayers(edgeSignature) {
  const source = Array.isArray(edgeSignature.layers)
    ? edgeSignature.layers
    : buildEdgeLayers({
        vendorMatches: Array.isArray(edgeSignature.vendor_matches) ? edgeSignature.vendor_matches : [],
        addressMatches: Array.isArray(edgeSignature.address_matches) ? edgeSignature.address_matches : [],
        cnameMatches: Array.isArray(edgeSignature.cname_matches) ? edgeSignature.cname_matches : [],
        genericWafDetected: edgeSignature.waf_generic_detected === true,
        conflictingVendorSignals: edgeSignature.conflicting_vendor_signals === true,
      });
  return source.slice(0, MAX_LIST_ITEMS).flatMap((raw) => {
    const layer = asRecord(raw);
    const family = boundedString(layer?.family, 32).toLowerCase();
    const provider = boundedString(layer?.provider);
    if (!layer || !['cdn', 'waf', 'cloud'].includes(family) || !provider) return [];
    return [{
      family,
      provider,
      display_name: boundedString(layer.display_name, 200) || null,
      sources: boundedList(layer.sources, 8),
      confidence: boundedConfidence(layer.confidence),
      evidence_consistency: boundedString(layer.evidence_consistency, 32) || 'single_source',
      matched_signal_count: Math.max(0, Number(layer.matched_signal_count) || 0),
      conflicting: layer.conflicting === true,
    }];
  });
}

function projectNetworkFirewall(metadata) {
  const reported = asRecord(metadata.network_firewall);
  const reportedDirect = asRecord(reported?.direct_origin_reachability);
  const phaseAttempted = Array.isArray(metadata.scan_plan)
    && metadata.scan_plan.includes('origin_bypass');
  const attempted = reportedDirect
    ? reportedDirect.status !== 'not_tested'
    : phaseAttempted || metadata.origin_bypass_status_code != null;
  const reachable = reportedDirect?.reachable === true
    || metadata.direct_origin_reachable === true
    || metadata.origin_bypass_confirmed === true;
  const directStatus = reachable
    ? 'exposed'
    : reportedDirect?.status === 'no_exposure_observed'
      ? 'no_exposure_observed'
      : attempted ? 'inconclusive' : 'not_tested';
  const direct = {
    status: directStatus,
    reachable,
    application_bypass_confirmed: metadata.origin_bypass_confirmed === true
      || reportedDirect?.application_bypass_confirmed === true,
    status_code: Number.isInteger(reportedDirect?.status_code)
      ? reportedDirect.status_code
      : Number.isInteger(metadata.origin_bypass_status_code)
        ? metadata.origin_bypass_status_code
        : null,
  };

  const reportedPorts = asRecord(reported?.port_exposure);
  const openPorts = boundedPortList(reportedPorts?.open_ports);
  const portStatus = reportedPorts
    ? boundedString(reportedPorts.status, 32) || 'inconclusive'
    : 'not_tested';
  const ports = {
    status: portStatus,
    open_ports: openPorts,
    tested_count: Math.max(0, Number(reportedPorts?.tested_count) || 0),
    reason: boundedString(reportedPorts?.reason, 120)
      || (portStatus === 'not_tested' ? 'separate_bounded_port_scan_required' : null),
  };
  const status = direct.status === 'exposed' || ports.status === 'exposed'
    ? 'exposed'
    : direct.status === 'inconclusive' || ports.status === 'inconclusive'
      ? 'inconclusive'
      : direct.status === 'no_exposure_observed' || ports.status === 'no_exposure_observed'
        ? 'no_exposure_observed'
        : 'not_tested';
  return { status, direct_origin_reachability: direct, port_exposure: ports };
}

function projectProtection(metadata, waf, effectiveness) {
  const reported = boundedString(metadata.posture_status, 32).toLowerCase();
  const hasError = boundedString(metadata.error_class)
    || ['error', 'timeout'].includes(boundedString(metadata.external_result).toLowerCase());
  let status = 'detected_only';
  if (hasError || effectiveness.status === 'inconclusive') status = 'inconclusive';
  else if (metadata.origin_bypass_confirmed === true
    || ['present_but_not_effective', 'partially_effective'].includes(effectiveness.status)) {
    status = 'underprotected';
  } else if (waf.status === 'not_detected') status = 'unprotected';
  else if (waf.status !== 'detected') status = 'inconclusive';
  else if (reported === 'unprotected' || reported === 'underprotected') status = reported;
  else if (effectiveness.status === 'effective_for_tested_probes') {
    status = reported === 'protected' && metadata.origin_lockdown_confirmed === true
      ? 'protected'
      : 'edge_protected';
  }
  const labels = {
    protected: 'Protected · edge block and origin lockdown',
    edge_protected: 'Effective at the edge; origin lockdown not verified',
    underprotected: 'Underprotected',
    unprotected: 'Unprotected',
    detected_only: 'WAF detected; effectiveness not established',
    inconclusive: 'Inconclusive',
  };
  const tiers = {
    protected: 'external_edge_and_origin_lockdown',
    edge_protected: 'external_probe_only',
    underprotected: 'external_probe_gap',
    unprotected: 'absence_or_gap_observed',
    detected_only: 'presence_only',
    inconclusive: 'insufficient_evidence',
  };
  return {
    status,
    label: labels[status],
    evidence_tier: tiers[status],
    origin_lockdown_confirmed: metadata.origin_lockdown_confirmed === true,
  };
}

/**
 * Three-valued read over possibly-absent booleans. `observed` distinguishes "the worker reported
 * no match" from "the worker never reported this signal", which is what keeps a missing signal
 * out of a `not_detected` verdict.
 */
export function explicitEdgeBoolean(values) {
  const observed = values.filter((value) => typeof value === 'boolean');
  return {
    observed: observed.length > 0,
    value: observed.includes(true),
    conflict: observed.includes(true) && observed.includes(false),
  };
}

/** First typed provider for a family, preferring address ranges over CNAME suffixes. */
export function findEdgeProviderMatch(edgeSignature, family) {
  for (const [field, discriminator, type] of [
    ['address_matches', 'family', 'address_range'],
    ['cname_matches', 'type', 'cname_suffix'],
  ]) {
    const values = Array.isArray(edgeSignature?.[field])
      ? edgeSignature[field].slice(0, MAX_LIST_ITEMS)
      : [];
    for (const raw of values) {
      const match = asRecord(raw);
      if (!match || boundedString(match[discriminator]).toLowerCase() !== family) continue;
      const provider = boundedString(match.provider);
      if (provider) return { provider, type };
    }
  }
  return null;
}

function signalProjection(signal, details, providerField) {
  const status = signal.conflict
    ? 'inconclusive'
    : signal.observed
      ? signal.value ? 'detected' : 'not_detected'
      : 'inconclusive';
  return {
    status,
    ...(status === 'detected' && details?.provider
      ? { [providerField]: details.provider, type: details.type }
      : {}),
    ...(signal.conflict ? { reason: 'conflicting_edge_signals' } : {}),
    ...(!signal.observed ? { reason: 'signal_not_reported' } : {}),
  };
}

function evidenceSummary(edgeSignature) {
  const vendorMatches = Array.isArray(edgeSignature.vendor_matches)
    ? edgeSignature.vendor_matches.slice(0, MAX_EVIDENCE_VENDORS)
    : [];
  return {
    vendor_matches: vendorMatches.map((raw) => {
      const match = asRecord(raw) ?? {};
      return {
        vendor: boundedString(match.vendor),
        name: boundedString(match.name, 200),
        confidence: Number(match.confidence) || 0,
        matched_signals: (Array.isArray(match.matched_signals) ? match.matched_signals : [])
          .slice(0, MAX_EVIDENCE_MATCHES)
          .map((signalRaw) => {
            const signal = asRecord(signalRaw) ?? {};
            return {
              signal: boundedString(signal.signal, 200),
              tier: boundedString(signal.tier, 32),
            };
          }),
      };
    }),
    address_matches: (Array.isArray(edgeSignature.address_matches)
      ? edgeSignature.address_matches.slice(0, MAX_EVIDENCE_MATCHES)
      : []).map((raw) => {
      const match = asRecord(raw) ?? {};
      return { family: boundedString(match.family, 32), provider: boundedString(match.provider) };
    }),
    cname_matches: (Array.isArray(edgeSignature.cname_matches)
      ? edgeSignature.cname_matches.slice(0, MAX_EVIDENCE_MATCHES)
      : []).map((raw) => {
      const match = asRecord(raw) ?? {};
      return {
        provider: boundedString(match.provider),
        type: boundedString(match.type, 32),
        suffix: boundedString(match.suffix, 253),
      };
    }),
    wafw00f: wafw00fSummary(edgeSignature.wafw00f),
    cdncheck: cdncheckSummary(edgeSignature.cdncheck),
  };
}

function wafw00fSummary(raw) {
  const record = asRecord(raw);
  if (!record) return null;
  const generic = asRecord(record.generic);
  return {
    detected: record.detected === true,
    firewall: boundedString(record.firewall, 200) || 'None',
    manufacturer: boundedString(record.manufacturer, 200) || 'None',
    plugin: boundedString(record.plugin) || null,
    all_matches: boundedList(record.all_matches, MAX_EVIDENCE_MATCHES),
    generic: generic
      ? {
          found: generic.found === true,
          reason_code: boundedString(generic.reason_code, 64) || null,
          reason: boundedString(generic.reason, 200) || null,
        }
      : null,
  };
}

function cdncheckSummary(raw) {
  const record = asRecord(raw);
  if (!record) return null;
  return {
    matched: record.matched === true,
    provider: boundedString(record.provider) || null,
    item_type: boundedString(record.item_type, 16) || null,
    source: boundedString(record.source, 16) || null,
    value: boundedString(record.value, 253) || null,
  };
}

/**
 * Project a signed probe-result metadata object into the canonical edge-detection answer.
 *
 * @param {object} metadata worker `probe_result` metadata (already redacted upstream)
 * @returns {{
 *   status: string, reason: string|null, waf: object, cdn: object, cloud: object,
 *   waf_providers: string[], cdn_providers: string[], cloud_providers: string[],
 *   detected_vendor: string,
 *   confidence: number, conflicting_vendor_signals: boolean, corpus_version: string,
 *   evidence: object, dns_cname_chain: string[], dns_resolved_ips: string[],
 * }}
 */
export function projectEdgeDetection(metadata = {}) {
  const meta = asRecord(metadata) ?? {};
  const edgeSignature = asRecord(meta.edge_signature) ?? {};
  const bestVendor = asRecord(edgeSignature.best_vendor);

  // `edge_signature` is canonical. Legacy top-level posture summaries may be recomputed during
  // agent enrichment without that nested input, so consult them only when the canonical boolean
  // is absent rather than manufacturing a contradiction.
  const genericWaf = edgeSignature.waf_generic_detected === true;
  const wafSignal = explicitEdgeBoolean(typeof edgeSignature.waf_present === 'boolean'
    ? [edgeSignature.waf_present || genericWaf]
    : [meta.waf_fingerprint_detected, meta.waf_detected]);
  // A missing or null CDN answer means DNS was never observed: inconclusive, never not_detected.
  const cdnSignal = explicitEdgeBoolean('cdn_detected' in edgeSignature
    ? [edgeSignature.cdn_detected]
    : [meta.cdn_detected]);
  const cloudSignal = explicitEdgeBoolean([edgeSignature.cloud_hosted]);

  const conflictingVendorSignals = edgeSignature.conflicting_vendor_signals === true;
  const conflictingProviderSignals = edgeSignature.conflicting_provider_signals === true
    || conflictingVendorSignals;
  const layers = sanitizeLayers(edgeSignature);
  const wafTypedMatch = findEdgeProviderMatch(edgeSignature, 'waf');
  const cdnTypedMatch = findEdgeProviderMatch(edgeSignature, 'cdn');
  const responseProvider = boundedString(meta.detected_vendor) || boundedString(bestVendor?.vendor);

  const waf = signalProjection(
    wafSignal,
    conflictingVendorSignals ? null : {
      provider: responseProvider || wafTypedMatch?.provider || (genericWaf ? 'generic' : undefined),
      type: responseProvider
        ? 'response_fingerprint'
        : wafTypedMatch?.type ?? (genericWaf ? 'generic_behavior' : undefined),
    },
    'vendor',
  );
  const cdn = signalProjection(cdnSignal, cdnTypedMatch, 'provider');
  const cloudTypedMatch = findEdgeProviderMatch(edgeSignature, 'cloud');
  const cloud = signalProjection(cloudSignal, cloudTypedMatch, 'provider');

  const positive = (wafSignal.value && !wafSignal.conflict)
    || (cdnSignal.value && !cdnSignal.conflict)
    || (cloudSignal.value && !cloudSignal.conflict);
  const completeNoMatch = wafSignal.observed && cdnSignal.observed
    && !wafSignal.conflict && !cdnSignal.conflict
    && !wafSignal.value && !cdnSignal.value;
  const baseStatus = positive ? 'detected' : completeNoMatch ? 'not_detected' : 'inconclusive';
  const transportError = Boolean(boundedString(meta.error_class))
    || ['error', 'timeout'].includes(boundedString(meta.external_result).toLowerCase());
  const status = transportError ? 'inconclusive' : baseStatus;
  const directEffectiveness = meta.waf_effectiveness && typeof meta.waf_effectiveness === 'object' && Number(meta.waf_effectiveness.tested_count) > 0
    ? meta.waf_effectiveness
    : null;
  const effectiveness = (!transportError && directEffectiveness)
    ? directEffectiveness
    : assessWafEffectiveness({
        wafPresent: waf.status === 'detected' ? true : waf.status === 'not_detected' ? false : null,
        markerResults: meta.marker_probes,
        coverageComplete: meta.coverage_complete,
        transportError,
        inspectionLimitBypassSuspected: typeof meta.inspection_limit_bypass_suspected === 'boolean'
          ? meta.inspection_limit_bypass_suspected
          : undefined,
      });
  const protection = projectProtection(meta, waf, effectiveness);
  const networkFirewall = projectNetworkFirewall(meta);
  const layerConfidence = layers.length
    ? Math.max(...layers.map((layer) => layer.confidence))
    : boundedConfidence(bestVendor?.confidence);
  const reportedConfidence = Number(edgeSignature.confidence);
  const confidence = Number.isFinite(reportedConfidence)
    ? boundedConfidence(reportedConfidence)
    : Number((conflictingProviderSignals ? layerConfidence * 0.65 : layerConfidence).toFixed(3));

  return {
    status,
    reason: transportError
      ? 'worker_result_error'
      : status === 'not_detected'
        ? 'completed_no_signature_match'
        : status === 'inconclusive'
          ? (wafSignal.conflict || cdnSignal.conflict
            ? 'conflicting_edge_signals'
            : 'edge_signature_incomplete')
          : null,
    waf,
    cdn,
    cloud,
    layers,
    effectiveness,
    protection,
    network_firewall: networkFirewall,
    waf_providers: boundedList(edgeSignature.waf_providers),
    cdn_providers: boundedList(edgeSignature.cdn_providers),
    cloud_providers: boundedList(edgeSignature.cloud_providers),
    detected_vendor: responseProvider,
    confidence,
    evidence_consistency: boundedString(edgeSignature.evidence_consistency, 32)
      || (conflictingProviderSignals ? 'conflict' : layers.length > 1 ? 'multiple_layers' : 'single_source'),
    conflicting_vendor_signals: conflictingVendorSignals,
    conflicting_provider_signals: conflictingProviderSignals,
    corpus_version: boundedString(meta.edge_signature_corpus_version)
      || boundedString(edgeSignature.corpus_version),
    dns_cname_chain: boundedList(meta.dns_cname_chain, MAX_CHAIN_ITEMS),
    dns_resolved_ips: boundedList(meta.dns_resolved_ips, MAX_CHAIN_ITEMS),
    evidence: evidenceSummary(edgeSignature),
  };
}

/**
 * Should a signed probe result be recorded as a durable per-target detection?
 * Only trusted, non-simulated `waf.fingerprint.safe` worker results with a real edge signature.
 */
export function isPersistableEdgeDetection(metadata = {}) {
  const meta = asRecord(metadata) ?? {};
  if (meta.simulation === 'SAFE_PROBE_SIMULATION') return false;
  const externalResult = boundedString(meta.external_result).toLowerCase();
  if (externalResult === 'error' || externalResult === 'timeout') return false;
  if (boundedString(meta.error_class)) return false;
  return asRecord(meta.edge_signature) !== null;
}

/** Flatten a projection into the durable `target_edge_detections` column set. */
export function edgeDetectionRowFields(projection, { testRunId = null, observedAt = null } = {}) {
  return {
    test_run_id: testRunId,
    status: projection.status,
    reason: projection.reason,
    waf_status: projection.waf.status,
    waf_vendor: projection.waf.vendor ?? null,
    waf_type: projection.waf.type ?? null,
    waf_providers: projection.waf_providers,
    cdn_status: projection.cdn.status,
    cdn_provider: projection.cdn.provider ?? null,
    cdn_type: projection.cdn.type ?? null,
    cdn_providers: projection.cdn_providers,
    confidence: projection.confidence,
    conflicting_vendor_signals: projection.conflicting_vendor_signals,
    corpus_version: projection.corpus_version || null,
    evidence_json: {
      ...projection.evidence,
      cloud: projection.cloud,
      cloud_providers: projection.cloud_providers,
      layers: projection.layers,
      effectiveness: projection.effectiveness,
      protection: projection.protection,
      network_firewall: projection.network_firewall,
      evidence_consistency: projection.evidence_consistency,
      conflicting_provider_signals: projection.conflicting_provider_signals,
      dns_cname_chain: projection.dns_cname_chain,
      dns_resolved_ips: projection.dns_resolved_ips,
    },
    observed_at: observedAt,
  };
}
