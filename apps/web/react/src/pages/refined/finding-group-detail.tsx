import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, SearchX, TriangleAlert } from 'lucide-react';
import { Badge } from '../../components/ui/badge';
import { AnchorButton, Button } from '../../components/ui/button';
import { EmptyState } from '../../components/ui/empty-state';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { VariantSwitch } from '../../components/ui/variant-switch';
import { useDesignVariant, type DesignVariant } from '../../lib/design-variant';
import { readFindingRemediationFields } from '../../lib/finding-detail';
import {
  assetHasLifecycle,
  assetMembersInLifecycle,
  findGroupByKey,
  groupFindings,
  groupSlaSummary,
  type FindingGroupAsset,
  type FindingStatusBucket
} from '../../lib/finding-groups.mjs';
import { formatVectorFamilyLabel, summarizeFindingStatuses } from '../../lib/findings-helpers';
import { plainVerdictDescription } from '../../lib/plain-language.mjs';
import { buildDetailHref } from '../../lib/route-params';
import type { PortalConfig, PortalData, PortalDataset, Session } from '../../lib/types';
import { formatDate, formatSeverityLabel, pluralize } from '../../lib/utils';
import { FindingStatusBadge, SlaBadge, severityTone, slaPresentation } from './findings-refined';
import './findings-refined.css';
import './finding-group-detail.css';

/** Same props the router passes every list route; datasets and access mirror 'findings'. */
export interface FindingGroupDetailPageProps {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: (datasets?: readonly PortalDataset[]) => Promise<void>;
}

type AssetFilter = Exclude<FindingStatusBucket, 'other'> | 'all';

const ASSET_FILTERS: Array<{ id: AssetFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'open', label: 'Open' },
  { id: 'accepted', label: 'Accepted' },
  { id: 'closed', label: 'Closed' }
];

/** Returning to findings keeps the Refined view, since grouping only exists there. */
const FINDINGS_HREF = '#findings?variant=refined';

function readGroupKey() {
  const hash = window.location.hash.replace(/^#/, '');
  const index = hash.indexOf('?');
  return index >= 0 ? new URLSearchParams(hash.slice(index + 1)).get('key') ?? '' : '';
}

function textOf(value: unknown) {
  return typeof value === 'string' ? value.trim() : '';
}

export function FindingGroupDetailPage({ data, onRefresh }: FindingGroupDetailPageProps) {
  // This page only exists in the Refined presentation, so the switch always reports Refined.
  const [, setVariant] = useDesignVariant('findings');
  const variant: DesignVariant = 'refined';
  const [groupKey, setGroupKey] = useState(readGroupKey);
  const [assetFilter, setAssetFilter] = useState<AssetFilter>('all');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const onHashChange = () => setGroupKey(readGroupKey());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    setAssetFilter('all');
  }, [groupKey]);

  const groups = useMemo(
    () => groupFindings(data.findings, { targets: data.targets, checks: data.checks, targetGroups: data.targetGroups }),
    [data.findings, data.targets, data.checks, data.targetGroups]
  );
  const group = findGroupByKey(groups, groupKey);
  const loadError = data.loadErrors.findings ?? '';
  const loading = !data.loaded && data.findings.length === 0 && !loadError;

  const assetCounts = useMemo(() => {
    const counts: Record<AssetFilter, number> = { all: group?.assets.length ?? 0, open: 0, accepted: 0, closed: 0 };
    // An asset counts toward every lifecycle one of its member findings is in.
    group?.assets.forEach((asset) => {
      (['open', 'accepted', 'closed'] as const).forEach((bucket) => {
        if (assetHasLifecycle(asset, bucket)) counts[bucket] += 1;
      });
    });
    return counts;
  }, [group]);

  const visibleAssets = useMemo(
    () => (group?.assets ?? []).filter((asset) => assetHasLifecycle(asset, assetFilter)),
    [group, assetFilter]
  );

  function changeVariant(next: DesignVariant) {
    setVariant(next);
    // Grouping is a Refined-only view; choosing Classic returns to the classic finding queue.
    if (next === 'classic') window.location.hash = '#findings';
  }

  async function refresh() {
    setBusy(true);
    setError('');
    try {
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Refresh failed.');
    } finally {
      setBusy(false);
    }
  }

  const representative = group?.findings.find((finding) => String(finding.id ?? '') === group.representativeId) ?? group?.findings[0] ?? null;
  // wafActionItems is not a dataset on this route, so remediation comes from the finding record only.
  const remediation = representative ? readFindingRemediationFields(representative, data.wafActionItems ?? []) : null;
  const verdictMeaning = group ? plainVerdictDescription(group.verdict) : '';
  const notes = representative ? textOf(representative.notes) : '';
  const sla = group ? groupSlaSummary(group) : null;
  const slaHint = !sla
    ? ''
    : [
        sla.nearestDueAt ? `Earliest due ${formatDate(sla.nearestDueAt)}` : sla.undatedOpenCount > 0 ? '' : 'No open SLA due date',
        sla.undatedOpenCount > 0 ? `${sla.undatedOpenCount} open ${pluralize(sla.undatedOpenCount, 'finding')} not dated` : ''
      ].filter(Boolean).join(', ');

  const assetColumns: TableColumn<FindingGroupAsset>[] = [
    {
      key: 'asset',
      label: 'Asset',
      render: (asset) => (
        <span className="rf-cell-stack">
          <strong className="rf-asset-name">{asset.label}</strong>
          {asset.host && asset.host !== asset.label ? <span className="rf-mono">{asset.host}</span> : null}
          {asset.targetId ? <small className="rf-mono">{asset.targetId}</small> : null}
          {!asset.resolved && asset.targetId ? <small>Target not in the loaded inventory</small> : null}
        </span>
      )
    },
    {
      key: 'group',
      label: 'Target group',
      render: (asset) => asset.targetGroupNames.length
        ? asset.targetGroupNames.join(', ')
        : <span className="rf-cell-muted">Ungrouped</span>
    },
    {
      key: 'status',
      label: 'Status',
      render: (asset) => (
        <span className="rf-cell-stack">
          <FindingStatusBadge status={asset.status} />
          {asset.members.length > 1 ? <small>{asset.members.length} findings: {summarizeFindingStatuses(asset.statusBreakdown)}</small> : null}
          {asset.owners.length > 1 ? <small>Owners: {asset.owners.join(', ')}</small> : null}
        </span>
      )
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (asset) => <Badge tone={severityTone(asset.severity || 'unknown')}>{formatSeverityLabel(asset.severity || 'unknown')}</Badge>
    },
    {
      key: 'sla',
      label: 'SLA',
      render: (asset) => (
        <span className="rf-cell-stack">
          <SlaBadge {...slaPresentation(asset.slaState, asset.slaHoursLeft)} />
          {asset.slaDueAt ? <small>Due {formatDate(asset.slaDueAt)}</small> : null}
        </span>
      )
    },
    {
      key: 'opened',
      label: 'Opened',
      render: (asset) => <span className="tabular-nums">{formatDate(asset.openedAt)}</span>
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (asset) => (
        <span className="rf-row-actions">
          {/* One link per member finding in the active lifecycle filter, so no member is unreachable. */}
          {assetMembersInLifecycle(asset, assetFilter).filter((member) => member.findingId).map((member, index, shown) => (
            <AnchorButton
              key={member.findingId}
              size="sm"
              variant="secondary"
              href={buildDetailHref('finding-detail', member.findingId)}
              aria-label={`Open ${member.status.replace(/_/g, ' ')} finding ${member.findingId} for ${asset.label}`}
            >
              {shown.length > 1 ? `Open ${member.status.replace(/_/g, ' ')} finding` : 'Open finding'}
            </AnchorButton>
          ))}
          {asset.targetId ? (
            <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', asset.targetId)} aria-label={`Open target ${asset.label}`}>
              Open target
            </AnchorButton>
          ) : null}
        </span>
      )
    }
  ];

  return (
    <div className="content refined rf-finding-group">
      <a className="rf-back-link" href={FINDINGS_HREF}>
        <ArrowLeft size={16} aria-hidden="true" />
        Back to findings
      </a>

      <header className="rf-header">
        <div className="rf-header-copy">
          <p className="rf-eyebrow">Findings · alert</p>
          <h1>{group ? group.title : 'Alert'}</h1>
          {group ? (
            <div className="rf-alert-meta">
              <Badge tone={severityTone(group.severity || 'unknown')}>{formatSeverityLabel(group.severity || 'unknown')}</Badge>
              {group.checkLabel ? <span className="rf-chip">Check: {group.checkLabel}</span> : null}
              {group.vectorFamily ? <span className="rf-chip">Vector: {formatVectorFamilyLabel(group.vectorFamily)}</span> : null}
              <span className="rf-chip">{summarizeFindingStatuses(group.statusBreakdown)}</span>
            </div>
          ) : (
            <p className="rf-header-description">One alert grouped across every affected asset, each tied to its own external probe evidence.</p>
          )}
        </div>
        <div className="rf-header-actions">
          <VariantSwitch value={variant} onChange={changeVariant} />
          <Button size="sm" variant="secondary" loading={busy} disabled={busy} onClick={() => void refresh()}>Refresh</Button>
        </div>
      </header>

      {error || loadError ? <div className="form-banner error" role="alert">{error || loadError}</div> : null}

      {loading ? (
        <EmptyState icon={TriangleAlert} variant="skeleton" title="Loading alert" body="Fetching findings, declared targets, and the check catalog." />
      ) : !group ? (
        <EmptyState
          icon={SearchX}
          title="This finding group is unavailable."
          body={groupKey
            ? 'The alert may have closed or changed since the link was shared. Open the findings list for current alerts.'
            : 'Open an alert from the Refined findings view to see its affected assets.'}
          actionLabel="Open findings"
          actionHref={FINDINGS_HREF}
        />
      ) : (
        <>
          <section className="rf-summary-strip" aria-label="Alert summary">
            <div className="rf-stat">
              <span className="rf-stat-label">Affected assets</span>
              <span className="rf-stat-value">{group.assets.length}</span>
              <span className="rf-stat-hint">{group.findingIds.length} {pluralize(group.findingIds.length, 'finding')}</span>
            </div>
            <div className="rf-stat">
              <span className="rf-stat-label">Open</span>
              <span className="rf-stat-value">{group.openCount}</span>
              <span className="rf-stat-hint">{group.openAssetCount} {pluralize(group.openAssetCount, 'asset')} still exposed</span>
            </div>
            <div className="rf-stat" data-tone={sla?.state === 'breached' ? 'danger' : undefined}>
              <span className="rf-stat-label">SLA</span>
              <span className="rf-stat-value">
                {sla?.state === 'breached' ? <TriangleAlert size={16} aria-hidden="true" /> : null}
                {sla?.label}
              </span>
              <span className="rf-stat-hint">{slaHint}</span>
            </div>
            <div className="rf-stat">
              <span className="rf-stat-label">First opened</span>
              <span className="rf-stat-value rf-stat-date">{formatDate(group.earliestOpenedAt)}</span>
              <span className="rf-stat-hint">Last observed {formatDate(group.lastObservedAt)}</span>
            </div>
            <div className="rf-stat">
              <span className="rf-stat-label">Owners</span>
              <span className="rf-stat-value">{group.owners.length}</span>
              <span className="rf-stat-hint">
                {group.owners.length ? group.owners.slice(0, 2).join(', ') + (group.owners.length > 2 ? ` +${group.owners.length - 2}` : '') : 'Unassigned'}
                {group.owners.length && group.unassignedCount ? `, ${group.unassignedCount} unassigned` : ''}
              </span>
            </div>
          </section>

          <section className="rf-section" aria-labelledby="rf-group-meaning">
            <div className="rf-section-head">
              <h2 id="rf-group-meaning">What this means</h2>
            </div>
            <div className="rf-panel rf-meaning">
              <dl className="rf-meaning-list">
                <div>
                  <dt>Recorded verdict</dt>
                  <dd>
                    <strong>{group.verdictLabel || 'Not recorded'}</strong>
                    {verdictMeaning ? <span> {verdictMeaning}</span> : null}
                    {group.verdicts.length > 1 ? <span> Members record {group.verdicts.length} different verdicts; open each finding to compare.</span> : null}
                  </dd>
                </div>
                <div>
                  <dt>Check</dt>
                  <dd>{group.checkDescription || (group.checkLabel ? `${group.checkLabel}. No catalog description is loaded for this check.` : 'No check recorded on these findings.')}</dd>
                </div>
                <div>
                  <dt>Remediation</dt>
                  <dd>
                    {remediation?.remAction || remediation?.remDescription ? (
                      <>
                        {remediation.remAction ? <strong>{remediation.remAction}</strong> : null}
                        {remediation.remDescription ? <span> {remediation.remDescription}</span> : null}
                        {remediation.remSteps ? <span className="rf-meaning-steps">{remediation.remSteps}</span> : null}
                      </>
                    ) : (
                      <span className="rf-cell-muted">No remediation plan is recorded on the lead finding. Open it to see linked action items and evidence.</span>
                    )}
                  </dd>
                </div>
                {notes ? (
                  <div>
                    <dt>Triage notes</dt>
                    <dd>{notes}</dd>
                  </div>
                ) : null}
              </dl>
              {group.representativeId ? (
                <AnchorButton size="sm" variant="ghost" href={buildDetailHref('finding-detail', group.representativeId)}>
                  Open lead finding for full evidence
                </AnchorButton>
              ) : null}
            </div>
          </section>

          <section className="rf-section" aria-labelledby="rf-group-assets">
            <div className="rf-section-head">
              <h2 id="rf-group-assets">Affected assets</h2>
              <div className="rf-segmented" role="group" aria-label="Affected asset status filter">
                {ASSET_FILTERS.map((filter) => (
                  <button key={filter.id} type="button" aria-pressed={assetFilter === filter.id} onClick={() => setAssetFilter(filter.id)}>
                    {filter.label}
                    <span className="rf-tab-count tabular-nums">{assetCounts[filter.id]}</span>
                  </button>
                ))}
              </div>
            </div>
            <p className="rf-result-count">Open a finding for evidence, triage, safe retest, and custody export.</p>
            <div className="rf-panel rf-panel-flush rf-findings-table rf-stack-table">
              <DataTable
                columns={assetColumns}
                items={visibleAssets}
                getRowId={(asset) => asset.key}
                empty={(
                  <EmptyState
                    icon={SearchX}
                    title={`No ${assetFilter === 'all' ? '' : `${assetFilter} `}assets in this alert`}
                    body="Choose another status to see the remaining affected assets."
                  />
                )}
              />
            </div>
          </section>
        </>
      )}
    </div>
  );
}
