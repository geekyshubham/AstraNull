import { ShieldHalf } from 'lucide-react';
import type { DataItem } from '../../lib/types';
// @ts-ignore Plain ESM keeps machine-code presentation directly testable with node:test.
import { plainEmptyReason } from '../../lib/plain-language.mjs';
import { EmptyState } from '../ui/empty-state';
import '../charts/charts.css';

function getNumber(item: DataItem | null | undefined, keys: string[], fallback: number | null = null) {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return fallback;
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getMetaString(item: DataItem, key: string) {
  const meta = item.meta;
  return meta && typeof meta === 'object' && !Array.isArray(meta)
    ? getString(meta as DataItem, [key])
    : '';
}

function WafKpi({
  label,
  value,
  note,
  unit,
}: {
  label: string;
  value: string | number;
  note: string;
  unit?: string;
}) {
  return (
    <div className="kpi-cell">
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">
        {value}
        {unit ? <span className="unit">{unit}</span> : null}
      </span>
      <span className="kpi-delta">{note}</span>
    </div>
  );
}

type VendorCoverage = {
  vendor: string;
  pct: number | null;
  passPct: number | null;
  warnPct: number | null;
  failPct: number | null;
  edgeProtected: number | null;
  total: number | null;
};

function VendorCoverageRow({
  vendor,
  pct,
  passPct,
  warnPct,
  failPct,
  edgeProtected,
  total,
}: VendorCoverage) {
  const coverage = pct === null ? 'Fully protected coverage unavailable' : `${pct}% fully protected`;
  const assetScope = total === null
    ? 'declared asset total unavailable'
    : `${total} declared asset${total === 1 ? '' : 's'}`;
  const edgeScope = edgeProtected === null
    ? 'edge-protected count unavailable'
    : `${edgeProtected} edge protected but not internally validated`;
  const description = `${vendor}: ${coverage}; ${assetScope}; ${edgeScope}. Observed validation and connector metadata.`;

  return (
    <div className="dw-vendor-row">
      <div className="mono text-sm">{vendor}</div>
      <div
        className="dw-vendor-bar"
        role="img"
        aria-label={description}
        title={description}
      >
        {passPct !== null && passPct > 0 ? <span className="seg pass" style={{ width: `${passPct}%` }} /> : null}
        {warnPct !== null && warnPct > 0 ? <span className="seg warn" style={{ width: `${warnPct}%` }} /> : null}
        {failPct !== null && failPct > 0 ? <span className="seg fail" style={{ width: `${failPct}%` }} /> : null}
      </div>
      <div className="mono text-sm">{pct === null ? '—' : `${pct}%`}</div>
    </div>
  );
}

function vendorRows(summary: DataItem | null): VendorCoverage[] {
  const byVendor = summary?.by_vendor;
  if (!byVendor || typeof byVendor !== 'object' || Array.isArray(byVendor)) return [];

  return Object.entries(byVendor as Record<string, DataItem>).map(([vendor, stats]) => {
    const assets = getNumber(stats, ['assets', 'assets_total']);
    const protectedCount = getNumber(stats, ['protected']);
    const edgeProtected = getNumber(stats, ['edge_protected']);
    const underprotected = getNumber(stats, ['underprotected']);
    const unknown = getNumber(stats, ['unknown']);
    const classifications = [protectedCount, edgeProtected, underprotected, unknown];
    const classificationsComplete = classifications.every((value) => value !== null);
    const total = assets ?? (classificationsComplete
      ? classifications.reduce<number>((sum, value) => sum + (value ?? 0), 0)
      : null);
    const explicitPct = getNumber(stats, ['coverage_pct']);
    const pct = explicitPct ?? (protectedCount !== null && total !== null && total > 0
      ? Math.round((protectedCount / total) * 100)
      : null);
    const passPct = protectedCount !== null && total !== null && total > 0
      ? Math.round((protectedCount / total) * 100)
      : null;
    const warnPct = edgeProtected !== null && total !== null && total > 0
      ? Math.round((edgeProtected / total) * 100)
      : null;
    const failPct = underprotected !== null && total !== null && total > 0
      ? Math.round((underprotected / total) * 100)
      : null;

    return { vendor, pct, passPct, warnPct, failPct, edgeProtected, total };
  });
}

function connectorHealthNote(degraded: number | null, disabled: number | null) {
  if (degraded === null && disabled === null) return 'Health metadata unavailable';
  const parts = [
    degraded === null ? null : `${degraded} degraded`,
    disabled === null ? null : `${disabled} disabled`,
  ].filter(Boolean);
  return `${parts.join(' · ')} · connector metadata`;
}

export function WafSummaryPanel({ summary }: { summary: DataItem | null }) {
  if (!summary) {
    return (
      <EmptyState
        icon={ShieldHalf}
        title="WAF summary unavailable."
        body="Coverage rollups appear when WAF posture is enabled and connectors publish asset metadata."
      />
    );
  }

  const protectedCount = getNumber(summary, ['protected']);
  const edgeProtected = getNumber(summary, ['edge_protected']);
  const underprotected = getNumber(summary, ['underprotected']);
  const unknown = getNumber(summary, ['unknown']);
  const coveragePct = getNumber(summary, ['coverage_pct']);
  const connectorsActive = getNumber(summary, ['connectors_active']);
  const connectorsDegraded = getNumber(summary, ['connectors_degraded']);
  const connectorsDisabled = getNumber(summary, ['connectors_disabled']);
  const vendors = vendorRows(summary);
  const emptyReason = getMetaString(summary, 'empty_reason');
  const classificationCounts = [protectedCount, edgeProtected, underprotected, unknown];

  if (
    emptyReason
    && classificationCounts.every((value) => value === null || value === 0)
    && vendors.length === 0
  ) {
    return (
      <EmptyState
        icon={ShieldHalf}
        title="No WAF assets in scope."
        body={plainEmptyReason(emptyReason)}
        actionLabel="Open targets"
        actionHref="#targets"
      />
    );
  }

  return (
    <div className="stack">
      <div className="kpi-row" aria-label="Observed WAF posture summary">
        <WafKpi
          label="Protection worked"
          value={protectedCount ?? '—'}
          note="Confirmed by external probe evidence"
        />
        <WafKpi
          label="Blocked at edge only"
          value={edgeProtected ?? '—'}
          note="Blocked at edge · origin not separately proven"
        />
        <WafKpi
          label="Protection needs work"
          value={underprotected ?? '—'}
          note="Observed drift or policy exception"
        />
        <WafKpi
          label="Not enough evidence"
          value={unknown ?? '—'}
          note="Insufficient observed evidence"
        />
        <WafKpi
          label="Fully validated"
          value={coveragePct ?? '—'}
          unit={coveragePct === null ? undefined : '%'}
          note="Observed validation · criticality weighted"
        />
        <WafKpi
          label="Connectors"
          value={connectorsActive ?? '—'}
          note={connectorHealthNote(connectorsDegraded, connectorsDisabled)}
        />
      </div>

      <section className="stack-tight" aria-labelledby="waf-vendor-coverage-title">
        <div className="stack-tight">
          <h3 className="card-title" id="waf-vendor-coverage-title">Protection by provider</h3>
          <p className="muted small">Provider names come from connector metadata. A detected provider or an unfilled bar segment is not proof that traffic was blocked.</p>
        </div>
        {vendors.length > 0 ? (
          <>
            <ul className="dw-legend" aria-label="Provider bar legend">
              <li><span className="dw-legend-swatch" data-tone="pass" aria-hidden="true" />Protection worked</li>
              <li><span className="dw-legend-swatch" data-tone="warn" aria-hidden="true" />Blocked at edge only</li>
              <li><span className="dw-legend-swatch" data-tone="fail" aria-hidden="true" />Needs work</li>
              <li><span className="dw-legend-swatch" data-tone="rest" aria-hidden="true" />Not enough evidence</li>
            </ul>
            <div className="dw-vendor-list">
              {vendors.map((row) => <VendorCoverageRow key={row.vendor} {...row} />)}
            </div>
          </>
        ) : (
          <p className="dash-waf-vendors--empty">
            Vendor coverage breakdown appears when connectors publish per-vendor asset metadata.
          </p>
        )}
      </section>
    </div>
  );
}
