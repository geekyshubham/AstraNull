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
    || (cdnSignal.value && !cdnSignal.conflict);
  const completeNoMatch = wafSignal.observed && cdnSignal.observed
    && !wafSignal.conflict && !cdnSignal.conflict
    && !wafSignal.value && !cdnSignal.value;
  const status = positive ? 'detected' : completeNoMatch ? 'not_detected' : 'inconclusive';

  return {
    status,
    reason: status === 'not_detected'
      ? 'completed_no_signature_match'
      : status === 'inconclusive'
        ? (wafSignal.conflict || cdnSignal.conflict
          ? 'conflicting_edge_signals'
          : 'edge_signature_incomplete')
        : null,
    waf,
    cdn,
    cloud,
    waf_providers: boundedList(edgeSignature.waf_providers),
    cdn_providers: boundedList(edgeSignature.cdn_providers),
    cloud_providers: boundedList(edgeSignature.cloud_providers),
    detected_vendor: responseProvider,
    confidence: Number(bestVendor?.confidence) || 0,
    conflicting_vendor_signals: conflictingVendorSignals,
    corpus_version: boundedString(meta.edge_signature_corpus_version),
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
      dns_cname_chain: projection.dns_cname_chain,
      dns_resolved_ips: projection.dns_resolved_ips,
    },
    observed_at: observedAt,
  };
}
