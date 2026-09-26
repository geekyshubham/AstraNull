/**
 * Present a stored `target_edge_detections` row as the API/UI edge-detection object.
 * Runtime-agnostic: accepts either the in-memory record or a mapped Postgres row.
 */

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function boundedString(value, maxLength = 200) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function stringList(value) {
  return Array.isArray(value)
    ? value.map((entry) => boundedString(entry)).filter(Boolean)
    : [];
}

function familyPresentation(status, provider, type) {
  return {
    status: boundedString(status) || 'inconclusive',
    ...(provider ? { provider: boundedString(provider) } : {}),
    ...(type ? { type: boundedString(type, 48) } : {}),
  };
}

/**
 * @param {object|null} row stored detection row (in-memory record or mapped PG row)
 * @returns {object|null} the presented detection, or null when there is none
 */
export function presentTargetEdgeDetection(row) {
  const record = asRecord(row);
  if (!record) return null;

  const evidence = asRecord(record.evidence_json) ?? {};
  return {
    status: boundedString(record.status) || 'inconclusive',
    reason: boundedString(record.reason) || null,
    waf: familyPresentation(record.waf_status, record.waf_vendor, record.waf_type),
    cdn: familyPresentation(record.cdn_status, record.cdn_provider, record.cdn_type),
    cloud: familyPresentation(
      asRecord(evidence.cloud)?.status,
      asRecord(evidence.cloud)?.provider,
      asRecord(evidence.cloud)?.type,
    ),
    waf_providers: stringList(record.waf_providers),
    cdn_providers: stringList(record.cdn_providers),
    cloud_providers: stringList(evidence.cloud_providers),
    confidence: Number(record.confidence) || 0,
    conflicting_vendor_signals: record.conflicting_vendor_signals === true,
    corpus_version: boundedString(record.corpus_version) || null,
    test_run_id: boundedString(record.test_run_id) || null,
    observed_at: record.observed_at ? new Date(record.observed_at).toISOString() : null,
    updated_at: record.updated_at ? new Date(record.updated_at).toISOString() : null,
    evidence: {
      vendor_matches: Array.isArray(evidence.vendor_matches) ? evidence.vendor_matches : [],
      address_matches: Array.isArray(evidence.address_matches) ? evidence.address_matches : [],
      cname_matches: Array.isArray(evidence.cname_matches) ? evidence.cname_matches : [],
      wafw00f: asRecord(evidence.wafw00f),
      cdncheck: asRecord(evidence.cdncheck),
      dns_cname_chain: stringList(evidence.dns_cname_chain),
      dns_resolved_ips: stringList(evidence.dns_resolved_ips),
    },
  };
}
