import type { BadgeTone, DataItem } from './types';

export const CAPABILITY_PROBE_KIND_LABELS: Record<string, string> = {
  origin_leak_scan: 'Origin leak scan',
  host_sni_bypass: 'CDN/WAF bypass (Host/SNI)',
  port_scan_bounded: 'Firewall exposure scan',
  waf_enforcement_probe: 'WAF enforcement probe',
  outside_in_waf_scan: 'Outside-in WAF scanner',
  rate_limit_sequence: 'Rate-limit probe',
  dnssec_posture: 'DNSSEC posture',
  dns_axfr_leak: 'AXFR leak check',
  dns_open_recursion: 'Open recursion check',
  dns_failover_posture: 'DNS failover posture',
  tls_audit: 'TLS audit',
  cache_abuse_probe: 'Cache/CDN abuse check',
  api_surface_scan: 'API surface scan',
  cors_posture_probe: 'CORS posture',
  graphql_posture_probe: 'GraphQL posture',
  bot_challenge_probe: 'Bot/challenge probe',
};

export const REQUIRED_SETUP_LABELS: Record<string, string> = {
  declared_apex_domain: 'Declared apex domain',
  declared_host_sni_target: 'Host/SNI target + direct IP',
  declared_direct_origin_target: 'Declared direct origin',
  declared_scan_host: 'Declared scan host',
  declared_waf_asset: 'Declared WAF asset',
  customer_waf_marker_rule: 'WAF marker rule',
  customer_rate_limit_threshold: 'Rate-limit threshold',
  declared_authoritative_zone: 'Authoritative zone',
  declared_zone_for_axfr_check: 'Zone for AXFR check',
  customer_authorizes_axfr_probe: 'AXFR probe authorization',
  declared_resolver_target: 'Resolver target',
  declared_secondary_dns_targets: 'Secondary DNS targets',
  failover_policy_declaration: 'Failover policy',
  tls_terminated_endpoint: 'TLS-terminated endpoint',
  declared_cache_bust_path: 'Cache-bust path',
  declared_api_endpoint: 'API endpoint',
  url_target: 'URL target',
};

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export function formatRequiredSetupLabel(key: string) {
  return REQUIRED_SETUP_LABELS[key] ?? key.replaceAll('_', ' ');
}

export function formatRequiredSetupList(check: DataItem) {
  const setup = check.required_customer_setup;
  if (!Array.isArray(setup) || setup.length === 0) return [];
  return setup.map((entry) => formatRequiredSetupLabel(String(entry)));
}

export function capabilityProbeKindLabel(kind: string) {
  return CAPABILITY_PROBE_KIND_LABELS[kind] ?? kind.replaceAll('_', ' ');
}

export function probeEventMetadata(event: DataItem) {
  const meta = (event.metadata as DataItem | undefined) ?? {};
  const probeKind = getString(meta, ['probe_kind', 'profile_kind']);
  const externalResult =
    getString(event, ['external_result']) || getString(meta, ['external_result'], 'unknown');
  return { meta, probeKind, externalResult };
}

export function externalResultTone(result: string): 'success' | 'warn' | 'danger' | 'muted' {
  const normalized = result.toLowerCase();
  if (normalized === 'blocked') return 'success';
  if (normalized === 'connected') return 'warn';
  if (normalized === 'error' || normalized === 'timeout') return 'danger';
  return 'muted';
}

export const OUTSIDE_IN_POSTURE_LABELS: Record<string, string> = {
  Protected: 'Protected',
  'Detected, not validated': 'Detected, not validated',
  Underprotected: 'Underprotected',
  'Bypass Risk': 'Bypass Risk',
  Unprotected: 'Unprotected',
  Excluded: 'Excluded',
};

const OUTSIDE_IN_POSTURE_TONES: Record<string, BadgeTone> = {
  Protected: 'success',
  'Detected, not validated': 'warn',
  Underprotected: 'danger',
  'Bypass Risk': 'danger',
  Unprotected: 'danger',
  Excluded: 'muted',
};

const OUTSIDE_IN_POSTURE_STATUS_LABELS: Record<string, string> = {
  protected: 'Protected',
  underprotected: 'Underprotected',
  unknown: 'Detected, not validated',
  unprotected: 'Unprotected',
  excluded: 'Excluded',
};

export const DOM_XSS_VALIDATION_LABELS: Record<string, string> = {
  agent_required: 'Agent observation required',
  reflection_observed: 'DOM XSS reflection observed',
  agent_corroborated_blocked: 'Agent corroborated block',
  marker_reached_origin: 'Marker reached origin',
  agent_observed_no_reflection: 'Agent observed, no reflection',
};

const OUTSIDE_IN_POSTURE_EXPLANATIONS: Record<string, string> = {
  Protected: 'Safe attack markers were blocked at the edge and your agent confirmed enforcement.',
  'Detected, not validated':
    'A WAF was detected from the outside, but agent corroboration is still needed to confirm protection.',
  Underprotected: 'Safe attack markers were not consistently blocked by the edge WAF.',
  'Bypass Risk': 'Traffic may reach origin without WAF protection—review bypass paths immediately.',
  Unprotected: 'No WAF signals were detected on this asset from the outside-in scan.',
  Excluded: 'This asset is excluded from outside-in WAF scanning.',
};

function normalizeOutsideInPostureLabel(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return '';
  if (OUTSIDE_IN_POSTURE_LABELS[trimmed]) return trimmed;
  const fromStatus = OUTSIDE_IN_POSTURE_STATUS_LABELS[trimmed.toLowerCase()];
  return fromStatus ?? trimmed;
}

export function postureLabelTone(postureLabel: string): BadgeTone {
  const normalized = normalizeOutsideInPostureLabel(postureLabel);
  return OUTSIDE_IN_POSTURE_TONES[normalized] ?? 'muted';
}

export function outsideInPostureLabel(postureLabel: string) {
  const normalized = normalizeOutsideInPostureLabel(postureLabel);
  return OUTSIDE_IN_POSTURE_LABELS[normalized] ?? normalized.replaceAll('_', ' ');
}

export function outsideInPostureExplanation(postureLabel: string) {
  const normalized = normalizeOutsideInPostureLabel(postureLabel);
  return (
    OUTSIDE_IN_POSTURE_EXPLANATIONS[normalized]
    ?? 'Review outside-in WAF scan evidence and confirm enforcement with your agent.'
  );
}

export function domXssValidationLabel(value: string) {
  const normalized = value.trim().toLowerCase();
  return DOM_XSS_VALIDATION_LABELS[normalized] ?? value.replaceAll('_', ' ');
}