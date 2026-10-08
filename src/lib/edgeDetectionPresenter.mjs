/**
 * Present a stored `target_edge_detections` row as the API/UI edge-detection object.
 * Runtime-agnostic: accepts either the in-memory record or a mapped Postgres row.
 */

import { EXTERNAL_OBSERVATION_OUTCOMES, externalObservationLabel } from './externalObservationOutcomes.mjs';
import { presentProductDetectionEvidence } from './productDetectionEvidence.mjs';

const PROVIDER_DISPLAY_NAMES = Object.freeze({
  amazon: 'Amazon',
  aws: 'AWS',
  akamai: 'Akamai',
  awswaf: 'AWS WAF',
  azure: 'Microsoft Azure',
  azure_front_door: 'Azure Front Door',
  bunnycdn: 'Bunny CDN',
  cdn77: 'CDN77',
  gcore: 'Gcore',
  incapsula: 'Imperva (Incapsula)',
  keycdn: 'KeyCDN',
  netlify: 'Netlify',
  stackpath: 'StackPath',
  sucuri: 'Sucuri',
  vercel: 'Vercel',
  cloudflare: 'Cloudflare',
  cloudfront: 'Amazon CloudFront',
  fastly: 'Fastly',
  framer: 'Framer',
  gcp: 'Google Cloud',
  google: 'Google Cloud',
  modsecurity: 'ModSecurity',
  hetzner: 'Hetzner',
  digitalocean: 'DigitalOcean',
  ovh: 'OVHcloud',
  vultr: 'Vultr',
  linode: 'Linode',
  scaleway: 'Scaleway',
  leaseweb: 'Leaseweb',
  contabo: 'Contabo',
  hostinger: 'Hostinger',
  upcloud: 'UpCloud',
  equinix: 'Equinix Metal',
  alibaba: 'Alibaba Cloud',
  tencent: 'Tencent Cloud',
  oracle: 'Oracle Cloud',
  cachefly: 'CacheFly',
  edgecast: 'Edgecast',
});

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function boundedString(value, maxLength = 200) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function stringList(value, limit = 64) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.slice(0, limit).map((entry) => boundedString(entry)).filter(Boolean))];
}

function boundedNumber(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : 0;
}

function optionalNumber(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : null;
}

function isoOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function familyPresentation(status, provider, type) {
  return {
    status: boundedString(status) || 'inconclusive',
    ...(provider ? { provider: boundedString(provider) } : {}),
    ...(type ? { type: boundedString(type, 48) } : {}),
  };
}

function layerPresentation(raw, evidence = {}) {
  const layer = asRecord(raw);
  const family = boundedString(layer?.family, 32).toLowerCase();
  const provider = boundedString(layer?.provider);
  if (!layer || !['cdn', 'waf', 'cloud'].includes(family) || !provider) return null;
  const sources = stringList(layer.sources, 8);
  if (sources.length === 0) {
    if (Array.isArray(evidence.vendor_matches) && evidence.vendor_matches.some((m) => m?.vendor === provider)) {
      sources.push('response_header');
    }
    if (family === 'waf' && (evidence.wafw00f?.detected || evidence.wafw00f?.generic?.found)) {
      sources.push('response_fingerprint');
    }
    if (Array.isArray(evidence.address_matches) && evidence.address_matches.some((m) => m?.provider === provider)) {
      sources.push('address_range');
    }
    if (evidence.cdncheck?.matched && evidence.cdncheck?.provider === provider) {
      if (!sources.includes('address_range')) sources.push('address_range');
    }
    if (Array.isArray(evidence.cname_matches) && evidence.cname_matches.some((m) => m?.provider === provider)) {
      sources.push('cname_suffix');
    }
    if (sources.length === 0) {
      sources.push(family === 'waf' ? 'response_fingerprint' : 'address_range');
    }
  }
  return {
    family,
    provider,
    display_name: boundedString(layer.display_name) || null,
    sources,
    confidence: boundedNumber(layer.confidence, { max: 1 }),
    evidence_consistency: boundedString(layer.evidence_consistency, 32) || (sources.length > 1 ? 'agreement' : 'single_source'),
    matched_signal_count: boundedNumber(layer.matched_signal_count) || sources.length,
    conflicting: layer.conflicting === true,
  };
}

function presentedLayers(evidence, record) {
  const layers = (Array.isArray(evidence.layers) ? evidence.layers : [])
    .map((raw) => layerPresentation(raw, evidence))
    .filter(Boolean);
  if (layers.length) return layers;

  const fallback = [];
  for (const [family, providers] of [
    ['cdn', record.cdn_providers],
    ['waf', record.waf_providers],
    ['cloud', evidence.cloud_providers],
  ]) {
    for (const provider of stringList(providers)) {
      fallback.push({
        family,
        provider,
        display_name: null,
        sources: ['legacy_provider_summary'],
        confidence: boundedNumber(record.confidence, { max: 1 }),
        evidence_consistency: 'single_source',
        matched_signal_count: 0,
        conflicting: record.conflicting_vendor_signals === true,
      });
    }
  }
  return fallback;
}

function effectivenessPresentation(raw, wafStatus) {
  const value = asRecord(raw);
  const attemptedCount = boundedNumber(value?.attempted_count);
  const status = attemptedCount === 0 && boundedNumber(value?.tested_count) === 0
    ? 'inconclusive'
    : boundedString(value?.status, 48)
    || (wafStatus === 'not_detected' ? 'no_waf_detected' : 'inconclusive');
  const testedCount = boundedNumber(value?.tested_count);
  const percentage = testedCount > 0
    ? optionalNumber(value?.percentage, { max: 100 })
    : null;
  const perClass = asRecord(value?.per_class) ?? {};
  return {
    status,
    label: status === 'inconclusive' ? 'Inconclusive'
      : boundedString(value?.label) || (status === 'no_waf_detected' ? 'No WAF detected' : 'Inconclusive'),
    attempted_count: attemptedCount,
    tested_count: testedCount,
    blocked_count: boundedNumber(value?.blocked_count),
    passed_count: boundedNumber(value?.passed_count),
    inconclusive_count: boundedNumber(value?.inconclusive_count),
    percentage,
    coverage_complete: typeof value?.coverage_complete === 'boolean' ? value.coverage_complete : null,
    required_class_coverage_complete: value?.required_class_coverage_complete === true,
    per_class: Object.fromEntries(Object.entries(perClass).slice(0, 16).map(([key, state]) => [
      boundedString(key, 64),
      boundedString(state, 64) || 'inconclusive',
    ]).filter(([key]) => key)),
  };
}

function protectionPresentation(raw, effectiveness, wafStatus) {
  const value = asRecord(raw);
  // Stored rows without an explicit-denial basis never present full protection (ADR-0008, PV-01).
  const originLockdownConfirmed = value?.origin_lockdown_confirmed === true
    && value?.origin_lockdown_basis === 'explicit_denial_observed';
  const allowedStatuses = new Set([
    'protected',
    'edge_protected',
    'underprotected',
    'unprotected',
    'detected_only',
    'inconclusive',
  ]);
  const reportedStatus = boundedString(value?.status, 48);
  let status = allowedStatuses.has(reportedStatus)
    ? reportedStatus
    : (wafStatus === 'not_detected' ? 'unprotected' : 'inconclusive');
  if (status === 'unprotected' && effectiveness.attempted_count === 0 && effectiveness.tested_count === 0) {
    status = 'inconclusive';
  }
  if (status === 'protected' || status === 'edge_protected') {
    if (['present_but_not_effective', 'partially_effective'].includes(effectiveness.status)) {
      status = 'underprotected';
    } else if (effectiveness.status !== 'effective_for_tested_probes') {
      status = 'inconclusive';
    } else if (status === 'protected' && !originLockdownConfirmed) {
      status = 'edge_protected';
    }
  }
  const labels = {
    protected: 'Protected for tested probes · edge block and direct-origin denial observed',
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
    origin_lockdown_confirmed: originLockdownConfirmed,
    origin_lockdown_basis: originLockdownConfirmed ? 'explicit_denial_observed' : null,
  };
}

function networkFirewallPresentation(raw) {
  const value = asRecord(raw) ?? {};
  const direct = asRecord(value.direct_origin_reachability) ?? {};
  const ports = asRecord(value.port_exposure) ?? {};
  const openPorts = [...new Set((Array.isArray(ports.open_ports) ? ports.open_ports : [])
    .slice(0, 64)
    .map(Number)
    .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65_535))]
    .sort((left, right) => left - right);
  return {
    status: boundedString(value.status, 32) || 'not_tested',
    direct_origin_reachability: {
      status: boundedString(direct.status, 32) || 'not_tested',
      outcome: EXTERNAL_OBSERVATION_OUTCOMES.includes(direct.outcome) ? direct.outcome : null,
      label: EXTERNAL_OBSERVATION_OUTCOMES.includes(direct.outcome) ? externalObservationLabel(direct.outcome) : null,
      reachable: direct.reachable === true,
      explicit_denial_observed: direct.outcome === 'explicit_denial_observed',
      application_bypass_confirmed: direct.application_bypass_confirmed === true,
      application_bypass_suspected: direct.application_bypass_suspected === true,
      status_code: optionalNumber(direct.status_code),
    },
    port_exposure: {
      status: boundedString(ports.status, 32) || 'not_tested',
      open_ports: openPorts,
      tested_count: boundedNumber(ports.tested_count),
      reason: boundedString(ports.reason, 120) || null,
    },
  };
}

function providerDisplayName(layer) {
  return PROVIDER_DISPLAY_NAMES[layer.provider.toLowerCase()]
    || layer.display_name
    || layer.provider.split(/[_-]+/).map((part) => (
      part ? `${part[0].toUpperCase()}${part.slice(1)}` : ''
    )).join(' ');
}

function englishList(values) {
  if (values.length < 2) return values[0] ?? '';
  if (values.length === 2) return `${values[0]} and ${values[1]}`;
  return `${values.slice(0, -1).join(', ')}, and ${values.at(-1)}`;
}

function layerLabels(layers) {
  const grouped = new Map();
  for (const layer of layers.filter((item) => item.family === 'cdn' || item.family === 'waf')) {
    const name = providerDisplayName(layer);
    const entry = grouped.get(name) ?? new Set();
    entry.add(layer.family);
    grouped.set(name, entry);
  }
  return [...grouped.entries()].map(([name, families]) => {
    if (families.size > 1) return `${name} (CDN and WAF)`;
    if (families.has('cdn')) return `${name} (CDN)`;
    return /\bwaf\b/i.test(name) ? name : `${name} (WAF)`;
  });
}

function buildPlainLanguageSummary(presented) {
  const labels = layerLabels(presented.layers);
  const cloudLabels = [...new Set(presented.layers
    .filter((layer) => layer.family === 'cloud')
    .map(providerDisplayName))];
  const hasCdn = presented.cdn.status === 'detected';
  let edge;
  if (presented.conflicting_provider_signals && labels.length) {
    edge = `Edge signals disagree; possible layers are ${englishList(labels)}.`;
  } else if (labels.length) {
    const prefix = presented.protection.status === 'protected' ? 'Protected by' : 'Detected';
    edge = `${prefix} ${englishList(labels)}.`;
    if (presented.waf.status === 'not_detected' && hasCdn) edge += ' No WAF was detected.';
  } else if (cloudLabels.length) {
    edge = `Resolved addresses map to ${englishList(cloudLabels)} cloud infrastructure. No WAF or CDN was detected.`;
  } else if (presented.waf.status === 'not_detected' && presented.cdn.status === 'not_detected') {
    edge = 'No WAF or CDN was detected.';
  } else if (presented.waf.status === 'not_detected') {
    edge = 'No WAF was detected.';
  } else {
    edge = 'Edge-service detection was inconclusive.';
  }

  const effect = presented.effectiveness;
  let effectiveness;
  if (effect.attempted_count === 0 && effect.tested_count === 0) {
    effectiveness = 'WAF effectiveness was not tested. A missing fingerprint does not establish that a WAF is absent.';
  } else if (effect.status === 'present_but_not_effective') {
    effectiveness = `A WAF is present but not effective: it blocked ${effect.blocked_count} of ${effect.tested_count} safe test probes (${effect.percentage ?? 0}%).`;
  } else if (['effective_for_tested_probes', 'partially_effective'].includes(effect.status)
    && effect.tested_count > 0 && effect.percentage !== null) {
    effectiveness = `The WAF blocked ${effect.blocked_count} of ${effect.tested_count} safe test probes (${effect.percentage}%).`;
  } else if (effect.status === 'no_waf_detected') {
    effectiveness = 'WAF effectiveness was not scored because no WAF was detected.';
  } else {
    effectiveness = 'WAF effectiveness is inconclusive because the scan did not produce enough usable marker evidence.';
  }

  const network = presented.network_firewall;
  let networkFirewall = 'Direct-origin reachability and exposed ports were not tested by this scan.';
  const direct = network.direct_origin_reachability;
  if (direct.status === 'denied' || (direct.status === 'exposed' && direct.explicit_denial_observed)) {
    networkFirewall = 'The declared direct origin answered the tested request with an explicit denial for this host, path, source, and time; the responsible control is not identified.';
  } else if (direct.status === 'exposed') {
    networkFirewall = direct.application_bypass_confirmed
      ? 'Origin response observed on the direct path, and application identity was confirmed for the tested request over a healthy permitted-path baseline.'
      : direct.application_bypass_suspected
        ? 'Origin response observed on the direct path. A bypass is suspected from supporting signals only; application identity over a healthy baseline was not confirmed.'
        : 'Origin response observed on the direct path, so it is reachable at the network layer; an application bypass was not confirmed.';
  } else if (direct.status === 'inconclusive') {
    networkFirewall = direct.outcome === 'no_response' || direct.outcome === 'transport_error'
      ? `${direct.label}: the direct-origin check did not establish lockdown.`
      : 'The direct-origin reachability check was inconclusive.';
  }
  if (network.port_exposure.status === 'exposed') {
    networkFirewall += ` ${network.port_exposure.open_ports.length} exposed port(s) were observed.`;
  } else if (network.port_exposure.status === 'not_tested') {
    networkFirewall += ' Exposed ports require the separate bounded firewall scan.';
  }

  return {
    plain_language_summary: [edge, effectiveness,
      network.status === 'exposed' ? networkFirewall : null].filter(Boolean).join(' '),
    summary: { edge, effectiveness, network_firewall: networkFirewall },
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
  const layers = presentedLayers(evidence, record);
  const cdnProvider = boundedString(record.cdn_provider)
    || stringList(record.cdn_providers)[0]
    || layers.find((l) => l.family === 'cdn')?.provider
    || '';
  const cdnProviders = stringList(record.cdn_providers);
  if (cdnProvider && !cdnProviders.includes(cdnProvider)) {
    cdnProviders.push(cdnProvider);
  }
  const cdnType = boundedString(record.cdn_type)
    || layers.find((l) => l.family === 'cdn')?.sources?.[0]
    || (record.cdn_status === 'detected' ? 'address_range' : '');
  const presented = {
    status: boundedString(record.status) || 'inconclusive',
    reason: boundedString(record.reason) || null,
    waf: familyPresentation(record.waf_status, record.waf_vendor, record.waf_type),
    cdn: familyPresentation(record.cdn_status, cdnProvider, cdnType),
    cloud: familyPresentation(
      asRecord(evidence.cloud)?.status,
      asRecord(evidence.cloud)?.provider,
      asRecord(evidence.cloud)?.type,
    ),
    layers,
    waf_providers: stringList(record.waf_providers),
    cdn_providers: cdnProviders,
    cloud_providers: stringList(evidence.cloud_providers),
    confidence: boundedNumber(record.confidence, { max: 1 }),
    evidence_consistency: boundedString(evidence.evidence_consistency, 32) || 'single_source',
    conflicting_vendor_signals: record.conflicting_vendor_signals === true,
    conflicting_provider_signals: evidence.conflicting_provider_signals === true
      || record.conflicting_vendor_signals === true,
    corpus_version: boundedString(record.corpus_version) || null,
    test_run_id: boundedString(record.test_run_id) || null,
    observed_at: isoOrNull(record.observed_at),
    updated_at: isoOrNull(record.updated_at),
    evidence: {
      asn_dataset_version: boundedString(evidence.asn_dataset_version, 80) || null,
      asn: asRecord(evidence.asn),
      asn_matches: Array.isArray(evidence.asn_matches) ? evidence.asn_matches : [],
      cname_cdn_matches: Array.isArray(evidence.cname_cdn_matches) ? evidence.cname_cdn_matches : [],
      vendor_matches: Array.isArray(evidence.vendor_matches) ? evidence.vendor_matches : [],
      address_matches: Array.isArray(evidence.address_matches) ? evidence.address_matches : [],
      cname_matches: Array.isArray(evidence.cname_matches) ? evidence.cname_matches : [],
      wafw00f: asRecord(evidence.wafw00f),
      cdncheck: asRecord(evidence.cdncheck),
      dns_cname_chain: stringList(evidence.dns_cname_chain),
      dns_resolved_ips: stringList(evidence.dns_resolved_ips),
    },
  };
  presented.effectiveness = effectivenessPresentation(evidence.effectiveness, presented.waf.status);
  presented.protection = protectionPresentation(
    evidence.protection,
    presented.effectiveness,
    presented.waf.status,
  );
  presented.network_firewall = networkFirewallPresentation(evidence.network_firewall);
  return presentProductDetectionEvidence({ ...presented, ...buildPlainLanguageSummary(presented) });
}
