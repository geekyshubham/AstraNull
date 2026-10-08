import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, Eye, SearchX, TriangleAlert } from 'lucide-react';
import { Badge } from '../../components/ui/badge';
import { AnchorButton, Button } from '../../components/ui/button';
import { EmptyState } from '../../components/ui/empty-state';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { useInspectorRef, useOpenInspector } from '../../components/evidence/use-inspector';
import { usePublishInspectorSequence, type InspectorSequenceItem } from '../../components/evidence/inspector-sequence';
import { readFindingRemediationFields } from '../../lib/finding-detail';
import { findingGroupCheckId } from '../../lib/findings-query.mjs';
import { useProgressiveFindings } from '../../components/findings/use-server-findings';
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

// Lifecycle buckets over the members read so far; each names the exact statuses it includes.
const ASSET_FILTERS: Array<{ id: AssetFilter; label: string; statuses: string }> = [
  { id: 'all', label: 'All', statuses: 'every status' },
  { id: 'open', label: 'Open', statuses: 'open' },
  { id: 'accepted', label: 'Accepted', statuses: 'accepted risk or accepted' },
  { id: 'closed', label: 'Closed', statuses: 'resolved or closed' }
];

const FINDINGS_HREF = '#findings';

function readGroupKey() {
  const hash = window.location.hash.replace(/^#/, '');
  const index = hash.indexOf('?');
  return index >= 0 ? new URLSearchParams(hash.slice(index + 1)).get('key') ?? '' : '';
}

function textOf(value: unknown) {
  return typeof value === 'string' ? value.trim() : '';
}

export function FindingGroupDetailPage({ data, config, session, onRefresh }: FindingGroupDetailPageProps) {
  const inspected = useInspectorRef();
  const openInspector = useOpenInspector();
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

  // Members come from the server's exact check predicate across every status, read in pages and
  // narrowed to this group's issue identity. A group without a check id cannot be filtered on the
  // server, so its read covers every finding and only continues when asked.
  const checkId = findingGroupCheckId(groupKey);
  const [reloadKey, setReloadKey] = useState(0);
  const members = useProgressiveFindings(config, session, checkId ? { check_id: checkId } : {}, reloadKey, Boolean(groupKey));
  const groups = useMemo(
    () => groupFindings(members.items, { targets: data.targets, checks: data.checks }),
    [members.items, data.targets, data.checks]
  );
  const group = findGroupByKey(groups, groupKey);
  const complete = members.complete;
  const loadError = members.state === 'error' ? members.error : '';
  const loading = Boolean(groupKey) && members.state === 'loading';
  const unread = members.envelope?.total !== null && members.envelope?.total !== undefined ? Math.max(0, members.envelope.total - members.items.length) : null;

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

  // Every member finding under the active lifecycle filter, in table order. Each opens its own
  // original evidence; the inspector steps through them without wrapping or borrowing proof.
  const memberSequence = useMemo<InspectorSequenceItem[]>(() => visibleAssets.flatMap((asset) => (
    assetMembersInLifecycle(asset, assetFilter)
      .filter((member) => member.findingId)
      .map((member) => ({
        ref: { entry: 'group_member' as const, finding_id: member.findingId, target_id: asset.targetId || undefined },
        label: `${asset.label} · ${member.status.replace(/_/g, ' ')}`,
      }))
  )), [visibleAssets, assetFilter]);
  usePublishInspectorSequence(group ? { owner: `finding-group:${group.key}`, noun: 'affected targets in this group', items: memberSequence } : null);
  const inspectedMemberId = inspected?.entry === 'group_member' ? inspected.finding_id ?? '' : '';

  function inspectMember(findingId: string, targetId: string) {
    openInspector({ entry: 'group_member', finding_id: findingId, target_id: targetId || undefined }, `member-${findingId}`);
  }

  async function refresh() {
    setBusy(true);
    setError('');
    try {
      setReloadKey((value) => value + 1);
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
      label: 'Target',
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
      label: 'Evidence',
      render: (asset) => (
        <span className="rf-row-actions">
          {/* One evidence action per member finding in the active lifecycle filter, so no member is unreachable. */}
          {assetMembersInLifecycle(asset, assetFilter).filter((member) => member.findingId).map((member, _index, shown) => (
            <Button
              key={member.findingId}
              size="sm"
              variant={member.findingId === inspectedMemberId ? 'default' : 'secondary'}
              data-focus-key={`member-${member.findingId}`}
              aria-pressed={member.findingId === inspectedMemberId}
              aria-label={`View evidence for the ${member.status.replace(/_/g, ' ')} finding on ${asset.label}`}
              onClick={() => inspectMember(member.findingId, asset.targetId)}
            >
              <Eye size={14} aria-hidden="true" />
              {shown.length > 1 ? `View ${member.status.replace(/_/g, ' ')} evidence` : 'View evidence'}
            </Button>
          ))}
          {assetMembersInLifecycle(asset, assetFilter).filter((member) => member.findingId).slice(0, 1).map((member) => (
            <AnchorButton
              key={`full-${member.findingId}`}
              size="sm"
              variant="ghost"
              href={buildDetailHref('finding-detail', member.findingId)}
              aria-label={`Open full finding for ${asset.label}`}
            >
              Full finding
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
          <p className="rf-eyebrow">Findings · finding group</p>
          <h1>{group ? group.title : 'Finding group'}</h1>
          {group ? (
            <div className="rf-alert-meta">
              <Badge tone={severityTone(group.severity || 'unknown')}>{formatSeverityLabel(group.severity || 'unknown')}</Badge>
              {group.checkLabel ? <span className="rf-chip">Check: {group.checkLabel}</span> : null}
              {group.vectorFamily ? <span className="rf-chip">Vector: {formatVectorFamilyLabel(group.vectorFamily)}</span> : null}
              <span className="rf-chip">{summarizeFindingStatuses(group.statusBreakdown)}</span>
            </div>
          ) : (
            <p className="rf-header-description">One issue grouped across every affected target, each tied to its own external probe evidence.</p>
          )}
        </div>
        <div className="rf-header-actions">
          <Button size="sm" variant="secondary" loading={busy} disabled={busy} onClick={() => void refresh()}>Refresh</Button>
        </div>
      </header>

      {error || loadError ? <div className="form-banner error" role="alert">{error || loadError}</div> : null}

      {loading ? (
        <EmptyState icon={TriangleAlert} variant="skeleton" title="Loading finding group" body="Fetching findings, declared targets, and the check catalog." />
      ) : !group && !complete && members.state === 'ready' ? (
        <div className="rf-load-more">
          <p className="rf-pager-info">
            No member of this group is in the first <span className="tabular-nums">{members.items.length}</span> of <span className="tabular-nums">{members.envelope?.total ?? 'unknown'}</span> {checkId ? 'findings for this check' : 'findings'} read so far. Older findings have not been read yet; no other group is shown in its place.
          </p>
          {members.error ? <p className="rf-pager-info" role="alert">{members.error}</p> : null}
          <Button size="sm" variant="secondary" loading={members.loadingMore} onClick={members.loadMore}>Read more findings</Button>
        </div>
      ) : !group ? (
        <EmptyState
          icon={SearchX}
          title="This finding group is unavailable."
          body={groupKey
            ? 'No finding on the server matches this group key. The group may have closed or changed since the link was shared. No other group was substituted.'
            : 'This link has no group key. Open a finding group from the findings list.'}
          actionLabel="Open findings"
          actionHref={FINDINGS_HREF}
        />
      ) : (
        <>
          {!complete ? (
            <div className="rf-load-more" role="status">
              <p className="rf-pager-info">
                Partial group: built from <span className="tabular-nums">{members.items.length}</span> of <span className="tabular-nums">{members.envelope?.total ?? 'unknown'}</span> {checkId ? 'findings for this check' : 'findings'}. Counts below may grow{unread !== null ? `; ${unread} not read yet` : ''}.
              </p>
              {members.error ? <p className="rf-pager-info" role="alert">{members.error}</p> : null}
              <Button size="sm" variant="secondary" loading={members.loadingMore} onClick={members.loadMore}>Read more members</Button>
            </div>
          ) : null}
          <section className="rf-summary-strip" aria-label="Finding group summary">
            <div className="rf-stat">
              <span className="rf-stat-label">Affected targets</span>
              <span className="rf-stat-value">{group.assets.length}{complete ? '' : '+'}</span>
              <span className="rf-stat-hint">{group.findingIds.length} {pluralize(group.findingIds.length, 'finding')}{complete ? '' : ' read so far'}</span>
            </div>
            <div className="rf-stat">
              <span className="rf-stat-label">Open</span>
              <span className="rf-stat-value">{group.openCount}{complete ? '' : '+'}</span>
              <span className="rf-stat-hint">{group.openAssetCount} {pluralize(group.openAssetCount, 'target')} with an open finding</span>
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
                  <dt>Example verdict</dt>
                  <dd>
                    <strong>{group.verdictLabel || 'Not recorded'}</strong>
                    {verdictMeaning ? <span> {verdictMeaning}</span> : null}
                    <span className="rf-cell-muted"> Taken from one member. It is not a verdict for every target; view each target's own evidence below.</span>
                    {group.verdicts.length > 1 ? <span> Members record {group.verdicts.length} different verdicts.</span> : null}
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
                      <span className="rf-cell-muted">No remediation plan is recorded on the example finding.</span>
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
            </div>
          </section>

          <section className="rf-section" aria-labelledby="rf-group-assets">
            <div className="rf-section-head">
              <h2 id="rf-group-assets">Affected targets</h2>
              <div className="rf-segmented" role="group" aria-label="Affected target status filter">
                {ASSET_FILTERS.map((filter) => (
                  <button key={filter.id} type="button" aria-pressed={assetFilter === filter.id} title={`Targets with a finding that is ${filter.statuses}`} onClick={() => setAssetFilter(filter.id)}>
                    {filter.label}
                    <span className="rf-tab-count tabular-nums">{assetCounts[filter.id]}</span>
                  </button>
                ))}
              </div>
            </div>
            <p className="rf-result-count">
              {ASSET_FILTERS.find((filter) => filter.id === assetFilter)?.label} counts targets with a finding that is {ASSET_FILTERS.find((filter) => filter.id === assetFilter)?.statuses}{complete ? '' : ', among members read so far'}. View evidence opens each target's own original proof beside this list; Previous and Next step through the targets shown. A pass on one target never resolves another.
            </p>
            <div className="rf-panel rf-panel-flush rf-findings-table rf-stack-table">
              <DataTable
                columns={assetColumns}
                items={visibleAssets}
                getRowId={(asset) => asset.key}
                getRowProps={(asset) => (asset.members.some((member) => member.findingId === inspectedMemberId) ? { className: 'is-selected', 'aria-current': 'true' } : {})}
                empty={(
                  <EmptyState
                    icon={SearchX}
                    title={`No ${assetFilter === 'all' ? '' : `${assetFilter} `}targets in this group`}
                    body="Choose another status to see the remaining affected targets."
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
