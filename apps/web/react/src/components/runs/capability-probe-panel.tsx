import { Badge } from '../ui/badge';
import {
  capabilityProbeKindLabel,
  externalResultTone,
  probeEventMetadata,
} from '../../lib/capability-probe-labels';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function formatList(values: unknown, fallback = '—') {
  if (!Array.isArray(values) || values.length === 0) return fallback;
  return values.map((entry) => String(entry)).join(', ');
}

function formatBool(value: unknown) {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return '—';
}

type EvidenceRow = { label: string; value: string };

function rowsForProbeKind(probeKind: string, meta: DataItem): EvidenceRow[] {
  switch (probeKind) {
    case 'origin_leak_scan':
      return [
        { label: 'Apex domain', value: getString(meta, ['apex_domain']) },
        { label: 'Leak signals', value: formatList(meta.leak_signals) },
        { label: 'Origin IPs', value: formatList(meta.origin_ips) },
        { label: 'IPv6 addresses', value: formatList(meta.ipv6_addrs) },
        { label: 'Subdomains scanned', value: formatList(meta.subdomains_scanned) },
        { label: 'Leak count', value: getString(meta, ['leak_count'], '0') },
      ];
    case 'host_sni_bypass':
      return [
        { label: 'Protected host', value: getString(meta, ['protected_host']) },
        { label: 'Direct IP', value: getString(meta, ['direct_ip']) },
        { label: 'Bypass signal', value: formatBool(meta.bypass_signal) },
        { label: 'Status code', value: getString(meta, ['status_code']) },
      ];
    case 'port_scan_bounded':
      return [
        { label: 'Scan host', value: getString(meta, ['scan_host']) },
        { label: 'Open ports', value: formatList(meta.open_ports) },
        { label: 'Risky admin ports open', value: formatList(meta.risky_admin_ports_open) },
        { label: 'Exposure count', value: getString(meta, ['exposure_count'], '0') },
      ];
    case 'waf_enforcement_probe':
      return [
        { label: 'Status code', value: getString(meta, ['status_code']) },
        { label: 'WAF enforced', value: formatBool(meta.waf_enforced) },
        { label: 'Monitor-only leak', value: formatBool(meta.monitor_only_leak) },
      ];
    case 'rate_limit_sequence':
      return [
        { label: 'Status sequence', value: formatList(meta.status_sequence) },
        { label: 'Throttled', value: formatBool(meta.throttled) },
        { label: 'Rate limit enforced', value: formatBool(meta.rate_limit_enforced) },
      ];
    case 'dnssec_posture':
      return [
        { label: 'DNSKEY count', value: getString(meta, ['dnskey_count'], '0') },
        { label: 'DS count', value: getString(meta, ['ds_count'], '0') },
        { label: 'DNSSEC configured', value: formatBool(meta.dnssec_configured) },
        { label: 'DNSSEC missing', value: formatBool(meta.dnssec_missing) },
      ];
    case 'dns_axfr_leak':
      return [
        { label: 'Zone', value: getString(meta, ['zone']) },
        { label: 'Nameserver', value: getString(meta, ['nameserver']) },
        { label: 'AXFR leak', value: formatBool(meta.axfr_leak) },
        { label: 'AXFR refused', value: formatBool(meta.axfr_refused) },
      ];
    case 'dns_open_recursion':
      return [
        { label: 'Resolver host', value: getString(meta, ['resolver_host']) },
        { label: 'Open recursion', value: formatBool(meta.open_recursion) },
      ];
    case 'dns_failover_posture':
      return [
        { label: 'Primary NS', value: formatList(meta.primary_nameservers) },
        { label: 'Secondary reachable', value: formatBool(meta.secondary_reachable) },
        { label: 'Failover gap', value: formatBool(meta.failover_gap) },
      ];
    case 'tls_audit':
      return [
        { label: 'TLS protocol', value: getString(meta, ['tls_protocol']) },
        { label: 'Cipher', value: getString(meta, ['cipher']) },
        { label: 'Cert subject', value: getString(meta, ['subject']) },
        { label: 'Days to expiry', value: getString(meta, ['days_to_expiry']) },
        { label: 'TLS issues', value: formatList(meta.tls_issues) },
      ];
    case 'cache_abuse_probe':
      return [
        { label: 'Cache signals', value: formatList(meta.cache_signals) },
        { label: 'Sensitive caching risk', value: formatBool(meta.sensitive_caching_risk) },
      ];
    case 'api_surface_scan':
      return [
        { label: 'Discovered paths', value: formatList(meta.discovered_paths) },
        { label: 'Exposure count', value: getString(meta, ['exposure_count'], '0') },
      ];
    case 'cors_posture_probe':
      return [
        { label: 'ACAO header', value: getString(meta, ['acao_header']) },
        { label: 'Permissive CORS', value: formatBool(meta.permissive_cors) },
      ];
    case 'graphql_posture_probe':
      return [
        { label: 'GraphQL path', value: getString(meta, ['graphql_path']) },
        { label: 'Introspection exposed', value: formatBool(meta.introspection_exposed) },
      ];
    case 'bot_challenge_probe':
      return [
        { label: 'Challenge headers', value: formatList(meta.challenge_headers) },
        { label: 'Bot challenge missing', value: formatBool(meta.bot_challenge_missing) },
      ];
    default:
      return Object.entries(meta)
        .filter(([key]) => !['probe_kind', 'profile_kind', 'external_result'].includes(key))
        .slice(0, 8)
        .map(([key, value]) => ({
          label: key.replaceAll('_', ' '),
          value: Array.isArray(value) ? formatList(value) : String(value),
        }));
  }
}

export function CapabilityProbeResultCard({ event }: { event: DataItem }) {
  const { meta, probeKind, externalResult } = probeEventMetadata(event);
  const rows = rowsForProbeKind(probeKind, meta);
  const errorClass = getString(meta, ['error_class']);

  return (
    <article className="capability-probe-card">
      <div className="capability-probe-card-head">
        <div>
          <strong>{capabilityProbeKindLabel(probeKind) || 'Probe observation'}</strong>
          <p className="muted small">{formatDate(event.timestamp ?? event.created_at)}</p>
        </div>
        <Badge tone={externalResultTone(externalResult)}>{externalResult}</Badge>
      </div>
      {errorClass ? <p className="muted small">Error: {errorClass}</p> : null}
      <div className="verdict-explanation-grid">
        {rows.map((row) => (
          <div key={row.label} className="verdict-explanation-item">
            <span>{row.label}</span>
            <strong>{row.value || '—'}</strong>
          </div>
        ))}
      </div>
    </article>
  );
}

export function CapabilityProbeResultsPanel({ events }: { events: DataItem[] }) {
  return (
    <div className="stack">
      {events.map((event, index) => (
        <CapabilityProbeResultCard key={getString(event, ['id'], String(index))} event={event} />
      ))}
    </div>
  );
}