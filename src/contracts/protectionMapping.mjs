/**
 * Application protection mapping: hostname (+ scheme/port/path) -> production
 * property/CDN config -> WAF match-target/policy -> origin -> Site Shield map.
 *
 * This module is a pure reconciliation of already-collected, metadata-only connector
 * snapshot evidence (dns_record, cdn_property, waf_policy) against a declared WAF asset.
 * It does not call any provider API and does not probe anything; it only explains what
 * evidence is and is not present, and how stale/incomplete it is, per the correlation
 * gap identified for this customer's use case: "identify an exposed application, map its
 * actual protection, and prove whether an alternate route bypasses that protection."
 *
 * A missing snapshot kind is reported as a named gap rather than silently treated as
 * "no protection" — see classifyWafPosture's coverageGapEvidence gate for the same
 * principle applied to posture classification.
 */

export const PROTECTION_MAPPING_GAP_CODES = Object.freeze([
  'no_dns_record_evidence',
  'no_cdn_property_evidence',
  'no_waf_policy_evidence',
  'no_site_shield_evidence',
  'hostname_not_in_property',
  'hostname_not_in_policy_scope',
  'stale_dns_record_evidence',
  'stale_cdn_property_evidence',
  'stale_waf_policy_evidence',
  'stale_site_shield_evidence',
  'connector_permission_gap',
  'ambiguous_match_target_ordering',
]);

const GAP_CODE_SET = new Set(PROTECTION_MAPPING_GAP_CODES);

export const DEFAULT_PROTECTION_MAPPING_STALE_AFTER_MS = 24 * 60 * 60 * 1000;

function normalizeHostname(value) {
  return String(value ?? '').trim().replace(/\.+$/, '').toLowerCase();
}

function hostnameFromCanonicalUrl(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return null;
  if (/^https?:\/\//i.test(raw)) {
    try {
      return normalizeHostname(new URL(raw).hostname);
    } catch {
      return null;
    }
  }
  return normalizeHostname(raw.split('/')[0].split(':')[0]);
}

function snapshotAgeMs(snapshot, now) {
  const observedMs = Date.parse(String(snapshot?.observed_at ?? ''));
  if (!Number.isFinite(observedMs)) return null;
  return Math.max(0, now - observedMs);
}

function isStale(snapshot, now, staleAfterMs) {
  const age = snapshotAgeMs(snapshot, now);
  return age === null ? true : age > staleAfterMs;
}

function summaryHostnames(snapshot) {
  const hostnames = snapshot?.summary?.hostnames;
  return Array.isArray(hostnames) ? hostnames.map(normalizeHostname).filter(Boolean) : [];
}

function latestByObservedAt(snapshots) {
  return [...snapshots].sort((a, b) => {
    const aMs = Date.parse(String(a?.observed_at ?? '')) || 0;
    const bMs = Date.parse(String(b?.observed_at ?? '')) || 0;
    return bMs - aMs;
  })[0] ?? null;
}

/**
 * Build the mapping for one declared WAF asset from a bag of already-fetched connector
 * snapshots. Snapshots are expected to be pre-filtered to the tenant/connector scope the
 * caller is authorized to read; this function does not enforce tenant isolation itself.
 *
 * @param {object} asset - normalized WAF asset (see normalizeWafAssetInput).
 * @param {object} evidence
 * @param {Array<object>} [evidence.dnsRecordSnapshots] - snapshot_kind 'dns_record'.
 * @param {Array<object>} [evidence.cdnPropertySnapshots] - snapshot_kind 'cdn_property'.
 * @param {Array<object>} [evidence.wafPolicySnapshots] - snapshot_kind 'waf_policy'.
 * @param {Array<object>} [evidence.siteShieldSnapshots] - snapshot_kind 'site_shield_map'.
 * @param {object} [options]
 * @param {Date|number} [options.now]
 * @param {number} [options.staleAfterMs]
 */
export function buildProtectionMapping(asset, evidence = {}, options = {}) {
  if (asset === null || asset === undefined || typeof asset !== 'object' || Array.isArray(asset)) {
    const err = new Error('Protection mapping requires a WAF asset object.');
    err.code = 'invalid_protection_mapping_input';
    throw err;
  }
  const hostname = hostnameFromCanonicalUrl(asset.canonical_url ?? asset.hostname);
  if (!hostname) {
    const err = new Error('Protection mapping requires a resolvable hostname from canonical_url.');
    err.code = 'invalid_protection_mapping_input';
    throw err;
  }

  const now = options.now instanceof Date
    ? options.now.getTime()
    : Number.isFinite(Number(options.now)) ? Number(options.now) : Date.now();
  const staleAfterMs = Number.isFinite(Number(options.staleAfterMs))
    ? Number(options.staleAfterMs)
    : DEFAULT_PROTECTION_MAPPING_STALE_AFTER_MS;

  const dnsRecordSnapshots = Array.isArray(evidence.dnsRecordSnapshots) ? evidence.dnsRecordSnapshots : [];
  const cdnPropertySnapshots = Array.isArray(evidence.cdnPropertySnapshots) ? evidence.cdnPropertySnapshots : [];
  const wafPolicySnapshots = Array.isArray(evidence.wafPolicySnapshots) ? evidence.wafPolicySnapshots : [];
  const siteShieldSnapshots = Array.isArray(evidence.siteShieldSnapshots) ? evidence.siteShieldSnapshots : [];

  const gaps = [];
  const permissionGaps = new Set();
  for (const snapshot of [...dnsRecordSnapshots, ...cdnPropertySnapshots, ...wafPolicySnapshots, ...siteShieldSnapshots]) {
    for (const gap of snapshot?.summary?.permission_gaps ?? []) {
      permissionGaps.add(String(gap).trim());
    }
  }
  if (permissionGaps.size > 0) gaps.push('connector_permission_gap');

  // DNS records naming this hostname or its zone (matches the record's own hostname or an
  // apex/zone the hostname belongs to).
  const matchingDnsRecords = dnsRecordSnapshots.filter((snapshot) => (
    summaryHostnames(snapshot).includes(hostname) || normalizeHostname(snapshot?.summary?.zone) === hostname
  ));
  const cnameRecords = matchingDnsRecords.filter((s) => s?.summary?.record_type === 'CNAME');
  const latestDnsRecord = latestByObservedAt(matchingDnsRecords);
  if (matchingDnsRecords.length === 0) {
    gaps.push('no_dns_record_evidence');
  } else if (isStale(latestDnsRecord, now, staleAfterMs)) {
    gaps.push('stale_dns_record_evidence');
  }

  // A CDN property (edge hostname / CDN config) that lists this hostname among its covered
  // hostnames. Per the assessment: an EdgeDNS CNAME alone is not proof of CDN/WAF coverage —
  // this only becomes evidence once matched against the property's own hostname list.
  const matchingProperties = cdnPropertySnapshots.filter((snapshot) => summaryHostnames(snapshot).includes(hostname));
  const latestProperty = latestByObservedAt(matchingProperties);
  if (cdnPropertySnapshots.length === 0) {
    gaps.push('no_cdn_property_evidence');
  } else if (matchingProperties.length === 0) {
    gaps.push('hostname_not_in_property');
  } else if (isStale(latestProperty, now, staleAfterMs)) {
    gaps.push('stale_cdn_property_evidence');
  }

  // A WAF policy/match-target snapshot whose hostname scope covers this hostname.
  const matchingPolicies = wafPolicySnapshots.filter((snapshot) => summaryHostnames(snapshot).includes(hostname));
  const latestPolicy = latestByObservedAt(matchingPolicies);
  if (wafPolicySnapshots.length === 0) {
    gaps.push('no_waf_policy_evidence');
  } else if (matchingPolicies.length === 0) {
    gaps.push('hostname_not_in_policy_scope');
  } else if (isStale(latestPolicy, now, staleAfterMs)) {
    gaps.push('stale_waf_policy_evidence');
  }
  // Akamai match-target ordering is significant (first match wins); more than one policy
  // claiming this hostname without an explicit order/priority field is ambiguous, not
  // resolvable, evidence.
  if (matchingPolicies.length > 1 && matchingPolicies.every((s) => s?.summary?.match_target_order == null)) {
    gaps.push('ambiguous_match_target_ordering');
  }

  const matchingSiteShieldMaps = siteShieldSnapshots.filter((snapshot) => summaryHostnames(snapshot).includes(hostname));
  const latestSiteShieldMap = latestByObservedAt(matchingSiteShieldMaps);
  if (siteShieldSnapshots.length === 0) {
    gaps.push('no_site_shield_evidence');
  } else if (isStale(latestSiteShieldMap, now, staleAfterMs)) {
    gaps.push('stale_site_shield_evidence');
  }

  const orderedGaps = [...new Set(gaps)].filter((code) => GAP_CODE_SET.has(code));

  return {
    hostname,
    waf_asset_id: asset.id ?? null,
    target_group_id: asset.target_group_id ?? null,
    dns_records: matchingDnsRecords.map((s) => ({
      record_type: s?.summary?.record_type ?? null,
      rdata: s?.summary?.record_rdata ?? [],
      observed_at: s?.observed_at ?? null,
      provider: s?.provider ?? null,
    })),
    cname_target: cnameRecords.length > 0 ? cnameRecords[0]?.summary?.record_rdata?.[0] ?? null : null,
    cdn_property: latestProperty ? {
      display_ref: latestProperty.display_ref ?? null,
      provider: latestProperty.provider ?? null,
      observed_at: latestProperty.observed_at ?? null,
    } : null,
    waf_policy: latestPolicy ? {
      display_ref: latestPolicy.display_ref ?? null,
      provider: latestPolicy.provider ?? null,
      policy_mode: latestPolicy?.summary?.policy_mode ?? null,
      observed_at: latestPolicy.observed_at ?? null,
    } : null,
    site_shield_map: latestSiteShieldMap ? {
      display_ref: latestSiteShieldMap.display_ref ?? null,
      provider: latestSiteShieldMap.provider ?? null,
      observed_at: latestSiteShieldMap.observed_at ?? null,
    } : null,
    gaps: orderedGaps,
    permission_gaps: [...permissionGaps],
    // Coverage is only "complete" evidence-wise when every layer resolved without a gap —
    // this is an evidence-completeness signal, not a claim that the application is protected.
    mapping_complete: orderedGaps.length === 0,
    evaluated_at: new Date(now).toISOString(),
  };
}

/**
 * Build mappings for a set of declared WAF assets against one evidence bag, deduplicating
 * shared connector evidence per asset.
 */
export function buildProtectionMappings(assets = [], evidence = {}, options = {}) {
  if (!Array.isArray(assets)) {
    const err = new Error('Protection mapping requires an array of WAF assets.');
    err.code = 'invalid_protection_mapping_input';
    throw err;
  }
  return assets.map((asset) => buildProtectionMapping(asset, evidence, options));
}
