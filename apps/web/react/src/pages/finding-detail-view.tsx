import { useEffect, useState } from 'react';
import type { HTMLAttributes, KeyboardEvent as ReactKeyboardEvent, MouseEvent as ReactMouseEvent } from 'react';
import { Check, FileCheck2, ShieldCheck, Target, TriangleAlert, UserCog, Wrench } from 'lucide-react';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { populateFindingAffectedTargets, populateFindingEvidence, readFindingRemediationFields } from '../lib/finding-detail';
import { VerifyChip } from '../lib/verify-chip';
import { requestJson } from '../lib/api';
import { sessionHasPermission } from '../lib/dataset-access.mjs';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate, formatSeverityLabel } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { RoleRestrictedCard } from '../components/ui/role-restricted';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { DataTable, type TableColumn } from '../components/ui/table';
import { findingSlaDueAt, findingStatus as readFindingStatus, isFindingSlaBreach, resolveFindingRetestAction } from '../lib/findings-helpers';
import { MetricCard } from './page-components';
import { useConfirmModal } from '../lib/crud-ui';

type StatTone = NonNullable<BadgeProps['tone']>;

const FINDING_DETAIL_STYLES_ID = 'finding-detail-view-styles';
const findingDetailStyles = `
.finding-detail-page { gap: var(--space-6); }
.finding-detail-page > .page-head { margin-bottom: 0; }
.finding-detail-page .finding-title-copy { min-width: 0; }
.finding-detail-page .finding-title-copy .page-title,
.finding-detail-page .finding-id { overflow-wrap: anywhere; word-break: break-word; }
.finding-detail-page .finding-summary-facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: var(--space-3); margin: 0; }
.finding-detail-page .finding-summary-fact { min-width: 0; padding: var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-md); background: color-mix(in oklab, var(--surface), var(--fg) 2%); }
.finding-detail-page .finding-summary-fact dt { margin-bottom: var(--space-1); color: var(--muted); font-family: var(--font-mono); font-size: var(--text-xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; }
.finding-detail-page .finding-summary-fact dd { min-width: 0; margin: 0; color: var(--fg); font-size: var(--text-sm); overflow-wrap: anywhere; word-break: break-word; }
.finding-detail-page .finding-relations { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; margin-top: var(--space-4); }
.finding-detail-page .finding-decision-ladder { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom: var(--space-4); }
.finding-detail-page .finding-digest { display: inline-block; min-width: 0; max-width: 42ch; overflow-wrap: anywhere; word-break: break-word; white-space: normal; }
.finding-detail-page .finding-artifact-row { cursor: pointer; }
.finding-detail-page .finding-custody-card .code { max-width: 100%; white-space: pre; }
@media (max-width: 720px) {
  .finding-detail-page .finding-summary-facts,
  .finding-detail-page .finding-decision-ladder { grid-template-columns: minmax(0, 1fr); }
}
`;

function ensureFindingDetailStyles() {
  if (typeof document === 'undefined' || document.getElementById(FINDING_DETAIL_STYLES_ID)) return;
  const node = document.createElement('style');
  node.id = FINDING_DETAIL_STYLES_ID;
  node.textContent = findingDetailStyles;
  document.head.appendChild(node);
}

type FindingDecisionStep = { id: string; label: string; done: boolean; meta: string };

/** Describe progress only from persisted finding/remediation facts; no unsupported status mutation is implied. */
function buildFindingDecisionSteps(status: string, owner: string, remState: string, hasPlaybook: boolean): FindingDecisionStep[] {
  const normalizedStatus = status.trim().toLowerCase();
  const normalizedOwner = owner.trim().toLowerCase();
  const ownerAssigned = Boolean(normalizedOwner && normalizedOwner !== 'unassigned' && normalizedOwner !== '—');
  const remediationTracked = hasPlaybook;
  const decisionRecorded = ['accepted_risk', 'closed'].includes(normalizedStatus);
  return [
    { id: 'opened', label: 'Finding opened', done: true, meta: `Recorded status: ${formatFindingLabel(status, 'Open')}` },
    { id: 'owned', label: 'Owner assigned', done: ownerAssigned, meta: ownerAssigned ? owner : 'No assignee recorded.' },
    { id: 'remediation', label: 'Remediation linked', done: remediationTracked, meta: remediationTracked ? formatFindingLabel(remState, 'Playbook linked') : 'No playbook or progressed remediation state.' },
    { id: 'decision', label: 'Decision recorded', done: decisionRecorded, meta: decisionRecorded ? formatFindingLabel(status) : 'Accept risk or close after review.' },
  ];
}

function findingSeverityTone(value: string): StatTone {
  const key = value.trim().toLowerCase();
  if (['critical', 'high', 's1', 's2'].includes(key)) return 'danger';
  if (['medium', 'moderate', 's3'].includes(key)) return 'warn';
  if (['low', 'info', 's4'].includes(key)) return 'info';
  return 'muted';
}

function findingStatusTone(value: string): StatTone {
  const key = value.trim().toLowerCase();
  if (key === 'closed') return 'success';
  if (key === 'accepted_risk') return 'muted';
  if (key === 'open') return 'warn';
  return 'info';
}

function formatFindingLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

/** Coerce an unknown API field into a list of object rows; returns null when the field is absent/not an array. */
function coerceItemArray(value: unknown): DataItem[] | null {
  if (!Array.isArray(value)) return null;
  return value.filter((row): row is DataItem => Boolean(row) && typeof row === 'object' && !Array.isArray(row));
}

/** Humanize a byte count for the evidence-bundle Size column (matches the prototype's KB/MB display). */
function formatBytes(value: unknown): string {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes <= 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Map the finding's `remStateClass` (badge--warn/--danger/--muted/--success, §7.6) to a Badge tone. */
function remStateTone(remStateClass: string, remState: string): StatTone {
  const cls = remStateClass.trim().toLowerCase();
  if (cls.includes('danger')) return 'danger';
  if (cls.includes('warn')) return 'warn';
  if (cls.includes('success')) return 'success';
  if (cls.includes('muted')) return 'muted';
  if (cls.includes('info')) return 'info';
  const state = remState.trim().toLowerCase();
  if (['resolved', 'delivered'].includes(state)) return 'success';
  if (state === 'accepted_risk') return 'muted';
  if (state === 'in_progress') return 'info';
  if (['open', 'remediation_pending'].includes(state)) return 'warn';
  return 'default';
}

/**
 * Whole-row click-through props to an artifact's evidence-detail route.
 * Matches the shared `role="link"` row convention (hash + `?id=` per lib/route-params);
 * ignores clicks that originate on nested interactive elements (e.g. the Export button).
 */
function evidenceRowNavProps(artifactId: string): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  if (!artifactId) return {};
  const navigate = () => {
    window.location.hash = `evidence-detail?id=${encodeURIComponent(artifactId)}`;
  };
  return {
    role: 'link',
    tabIndex: 0,
    className: 'finding-artifact-row',
    'aria-label': `Open evidence detail for artifact ${artifactId}`,
    onClick: (event: ReactMouseEvent<HTMLTableRowElement>) => {
      if ((event.target as HTMLElement).closest('a, button')) return;
      navigate();
    },
    onKeyDown: (event: ReactKeyboardEvent<HTMLTableRowElement>) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      navigate();
    }
  };
}

function DetailStatusBanners({ loadError, message, error }: { loadError: string; message: string; error: string }) {
  return (
    <>
      {loadError ? <div className="form-banner error" role="alert">{loadError}</div> : null}
      {(message || error) && !loadError ? (
        <div className={error ? 'form-banner error' : 'form-banner'} role={error ? 'alert' : 'status'}>
          {error || message}
        </div>
      ) : null}
    </>
  );
}

export function FindingDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  loading: boolean;
  loadError: string;
}) {
  ensureFindingDetailStyles();

  const { confirm } = useConfirmModal();
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [evidence, setEvidence] = useState<Awaited<ReturnType<typeof populateFindingEvidence>> | null>(null);
  const [evidenceReloadToken, setEvidenceReloadToken] = useState(0);
  const [affectedTargets, setAffectedTargets] = useState<DataItem[]>([]);
  const [affectedTargetsLoading, setAffectedTargetsLoading] = useState(true);
  const [affectedTargetsError, setAffectedTargetsError] = useState('');
  const [affectedTargetsReloadToken, setAffectedTargetsReloadToken] = useState(0);
  const [chainVerified, setChainVerified] = useState<boolean | null>(null);

  const remediation = readFindingRemediationFields(entity, data.wafActionItems);
  const canWriteFinding = sessionHasPermission(session, 'finding:write');
  const canStartFindingRetest = sessionHasPermission(session, 'test_run:start');
  const remSteps = remediation.remSteps.split('|').map((step) => step.trim()).filter(Boolean);
  const hasRemediationPlaybook = Boolean(
    remediation.remAction ||
    remediation.remDescription ||
    remediation.remSteps ||
    remediation.actionItemId
  );
  const title = getString(entity, ['title', 'summary'], entityId);
  const slaDueAt = findingSlaDueAt(entity);
  const severity = getString(entity, ['severity'], 'unknown');
  const findingStatus = readFindingStatus(entity);
  const owner = getString(entity, ['assignee', 'rem_owner'], 'unassigned');
  const targetGroupId = getString(entity, ['target_group_id'], '');
  const targetId = getString(entity, ['target_id'], '');
  const testRunId = getString(entity, ['test_run_id'], '');
  const checkId = getString(entity, ['check_id'], '');
  const vectorFamily = getString(entity, ['vector_family', 'vector'], '');
  const decisionSteps = buildFindingDecisionSteps(findingStatus, owner, remediation.remState, hasRemediationPlaybook);

  useEffect(() => {
    let cancelled = false;
    setEvidence(null);
    setChainVerified(null);
    populateFindingEvidence(config, session, entityId).then((payload) => {
      if (!cancelled) setEvidence(payload);
    });
    return () => { cancelled = true; };
  }, [config, session, entityId, evidenceReloadToken]);

  useEffect(() => {
    let cancelled = false;
    setAffectedTargets([]);
    setAffectedTargetsError('');
    // Primary source per §4.6.3: affected targets embedded on the finding payload
    // (GET /v1/findings/:id, passed in as `entity`). Prefer `affected_targets`, then `targets`.
    const embedded = coerceItemArray(entity.affected_targets) ?? coerceItemArray(entity.targets);
    if (embedded && embedded.length > 0) {
      setAffectedTargets(embedded);
      setAffectedTargetsLoading(false);
      return undefined;
    }
    // Fallback: resolve exact declared-target linkage through this finding's target group.
    const groupId = getString(entity, ['target_group_id'], '');
    if (!groupId) {
      setAffectedTargetsLoading(false);
      return undefined;
    }
    setAffectedTargetsLoading(true);
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(groupId)}`)
      .then((payload) => {
        if (cancelled) return;
        const targets = coerceItemArray((payload as DataItem).targets) ?? [];
        const directTargetId = getString(entity, ['target_id'], '');
        const matched = populateFindingAffectedTargets(entityId, targets);
        if (directTargetId && !matched.some((target) => getString(target, ['id'], '') === directTargetId)) {
          const direct = targets.find((target) => getString(target, ['id'], '') === directTargetId);
          if (direct) matched.unshift(direct);
        }
        setAffectedTargets(matched);
      })
      .catch((err) => {
        if (!cancelled) setAffectedTargetsError(err instanceof Error ? err.message : 'Could not load affected targets.');
      })
      .finally(() => {
        if (!cancelled) setAffectedTargetsLoading(false);
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, entity, affectedTargetsReloadToken]);

  async function runAction(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy('');
    }
  }

  async function patchFinding(body: Record<string, unknown>, success: string, action = 'update') {
    if (!canWriteFinding) return;
    await runAction(`finding-${action}-${entityId}`, () => requestJson(config, session, `/v1/findings/${entityId}`, { method: 'PATCH', body }), success);
  }

  async function markDelivered() {
    if (!canWriteFinding) return;
    if (!remediation.actionItemId) {
      setError('No remediation action item id returned by API.');
      return;
    }
    await runAction(`deliver-${entityId}`, () => requestJson(config, session, `/v1/waf/action-items/${encodeURIComponent(remediation.actionItemId)}/deliver`, { method: 'POST' }), 'Remediation marked delivered.');
  }

  async function verifyChain() {
    setChainVerified(null);
    await runAction(`verify-${entityId}`, async () => {
      // The verify endpoint recomputes the SHA-256 over the export payload and compares it to
      // the custody manifest digest, so it needs { payload, custody } — not { finding_id }.
      // The finding export is the canonical producer of that bound pair ({ ...payload, custody }).
      const exported = await requestJson(config, session, `/v1/findings/${entityId}/export`, { method: 'POST' }) as DataItem | null;
      if (!exported || typeof exported !== 'object') {
        throw new Error('Evidence export payload unavailable for verification.');
      }
      const { custody, ...payload } = exported;
      if (!custody || typeof custody !== 'object') {
        throw new Error('Custody manifest missing from evidence export.');
      }
      const verifyUrl = evidence?.verify_url ?? '/v1/custody/verify';
      const result = await requestJson(config, session, verifyUrl, { method: 'POST', body: { payload, custody } }) as DataItem | null;
      // The endpoint returns HTTP 200 even when verification fails, so inspect result.ok explicitly.
      if (!result || result.ok !== true) {
        setChainVerified(false);
        const verification = (result && typeof result.verification === 'object' ? result.verification : {}) as DataItem;
        const reason = getString(verification, ['error'], 'verification_failed');
        throw new Error(`Custody verification failed: ${formatFindingLabel(reason)}.`);
      }
      setChainVerified(true);
    }, 'Custody chain verified — SHA-256 digest matches the sealed manifest.');
  }

  async function exportBundle() {
    await runAction(`export-${entityId}`, () => requestJson(config, session, `/v1/findings/${entityId}/export`, { method: 'POST' }), 'Evidence bundle export requested.');
  }

  const affectedColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => <AnchorButton
        size="sm"
        variant="ghost"
        href={buildDetailHref('target-detail', getString(item, ['id'], ''))}
        aria-label={`Open target ${getString(item, ['value', 'id'], 'target')}`}
      >{getString(item, ['value', 'id'], '')}</AnchorButton>
    },
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
    { key: 'value', label: 'Value', render: (item) => <span className="mono">{getString(item, ['value'], '—')}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (item) => <VerifyChip state={getString(item, ['verification_state', 'verification'], 'unverified')} provenance={getString(item, ['verification_title'], 'Verification state from target API.')} />
    },
    { key: 'eligibility', label: 'Eligibility', render: (item) => getString(item, ['eligibility'], '—') },
    { key: 'verdict', label: 'Last verdict', render: (item) => getString(item, ['last_verdict'], '—') }
  ];

  const artifactColumns: TableColumn<DataItem>[] = [
    {
      key: 'artifact',
      label: 'Artifact',
      render: (item) => {
        const artifactId = getString(item, ['id'], '');
        const label = getString(item, ['id', 'kind'], '—');
        return artifactId
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('evidence-detail', artifactId)}>{label}</AnchorButton>
          : <span>{label}</span>;
      }
    },
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
    {
      key: 'run',
      label: 'Run',
      render: (item) => {
        const runId = getString(item, ['run_id'], '');
        return runId ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', runId)}>{runId}</AnchorButton> : <span>—</span>;
      }
    },
    { key: 'sha', label: 'SHA-256', render: (item) => <span className="mono small finding-digest" title={getString(item, ['sha256', 'content_sha256'], '—')}>{getString(item, ['sha256', 'content_sha256'], '—')}</span> },
    { key: 'sealed', label: 'Sealed', render: (item) => formatDate(item.sealed_at) },
    { key: 'size', label: 'Size', render: (item) => <span className="num">{formatBytes(item.size_bytes)}</span> },
    {
      key: 'export',
      label: '',
      render: (item) => <Button size="sm" variant="ghost" aria-label={`Export finding evidence bundle from artifact ${getString(item, ['id', 'kind'], 'artifact')}`} onClick={() => void exportBundle()}>Export bundle</Button>
    }
  ];

  const custodyChain = evidence?.custody_chain ?? [];
  const bundleSha256 = getString(evidence?.bundle, ['sha256'], '');
  const custodySealedAt = getString(evidence?.bundle, ['sealed_at'], '');
  const custodyStatus = chainVerified === true ? 'Verified' : chainVerified === false ? 'Verification failed' : 'Not checked';
  const custodyYaml = [
    `finding: ${entityId}`,
    `digest_kind: ${getString(evidence?.bundle, ['custody_schema_version'], 'json-key-sorted-v1')}`,
    ...(custodyChain.length
      ? ['chain:', ...custodyChain.flatMap((step) => [
          `  - artifact: ${getString(step, ['kind', 'step'], 'artifact')}`,
          `    sha256: ${getString(step, ['sha256'], '—')}`
        ])]
      : []),
    `bundle_sha256: ${bundleSha256 || '—'}`,
    ...(custodySealedAt ? [`sealed_at: ${custodySealedAt}`] : []),
    `verified: ${chainVerified === null ? 'not_checked' : chainVerified}`
  ].join('\n');

  return (
    <div className="content finding-detail-page" aria-busy={loading || undefined}>
      <div className="page-head">
        <div className="finding-title-copy">
          <p className="eyebrow">Evidence-backed finding</p>
          <h1 className="page-title">{title}</h1>
          <p className="muted mono finding-id">{entityId}</p>
          <div className="detail-status-line">
            <Badge tone={findingSeverityTone(severity)} title={`Severity ${severity} from finding API`}>{formatSeverityLabel(severity)}</Badge>
            <Badge tone={findingStatusTone(findingStatus)} title={`Status ${findingStatus} from finding API`}>{formatFindingLabel(findingStatus)}</Badge>
          </div>
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="secondary" href="#findings">← Findings</AnchorButton>
          <Button size="sm" variant="default" loading={busy === `export-${entityId}`} onClick={() => void exportBundle()}>Export evidence</Button>
        </div>
      </div>

      {loading ? <PortalLoadingSkeleton rows={2} /> : null}
      <DetailStatusBanners loadError={loadError} message={message} error={error} />

      {!loading ? (
        <>
      <div className="metric-grid four">
        <MetricCard label="Severity" value={formatSeverityLabel(severity)} sub="Impact class from finding API" icon={TriangleAlert} tone={findingSeverityTone(severity)} />
        <MetricCard label="Status" value={formatFindingLabel(findingStatus)} sub="Recorded finding state" icon={ShieldCheck} tone={findingStatusTone(findingStatus)} />
        <MetricCard label="Target group" value={targetGroupId || 'Not reported'} sub="Declared scope" icon={Target} tone="info" />
        <MetricCard label="Owner" value={owner} sub="Accountable owner" icon={UserCog} tone="muted" />
      </div>

      <Card className="finding-summary-card">
        <CardHeader>
          <div><CardTitle>Finding summary</CardTitle><CardDescription>Compact API-backed facts and exact relationships for triage and evidence review.</CardDescription></div>
        </CardHeader>
        <CardContent>
          <dl className="finding-summary-facts">
            <div className="finding-summary-fact"><dt>Finding ID</dt><dd className="mono">{entityId}</dd></div>
            <div className="finding-summary-fact"><dt>SLA due</dt><dd>{slaDueAt ? formatDate(slaDueAt) : 'Not reported'}{isFindingSlaBreach(entity) ? ' · breached' : ''}</dd></div>
            {checkId ? <div className="finding-summary-fact"><dt>Check</dt><dd className="mono">{checkId}</dd></div> : null}
            {vectorFamily ? <div className="finding-summary-fact"><dt>Vector</dt><dd>{formatFindingLabel(vectorFamily)}</dd></div> : null}
            {targetId ? <div className="finding-summary-fact"><dt>Target ID</dt><dd className="mono">{targetId}</dd></div> : null}
            {testRunId ? <div className="finding-summary-fact"><dt>Source run</dt><dd className="mono">{testRunId}</dd></div> : null}
            {entity.created_at ? <div className="finding-summary-fact"><dt>Opened</dt><dd>{formatDate(entity.created_at)}</dd></div> : null}
            {entity.updated_at ? <div className="finding-summary-fact"><dt>Updated</dt><dd>{formatDate(entity.updated_at)}</dd></div> : null}
          </dl>
          <div className="finding-relations" aria-label="Finding relationships">
            {targetGroupId ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-group-detail', targetGroupId)}>Target group</AnchorButton> : null}
            {targetId ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-detail', targetId)}>Target</AnchorButton> : null}
            {testRunId ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('run-detail', testRunId)}>Source run</AnchorButton> : null}
          </div>
        </CardContent>
      </Card>

      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Verdict explanation</CardTitle>
            <CardDescription className="detail-status-line">
              <Badge tone={findingSeverityTone(severity)} title={`Severity ${severity} from finding API`}>{formatSeverityLabel(severity)}</Badge>
              <span className="detail-status-sep" aria-hidden="true">·</span>
              <Badge tone={findingStatusTone(findingStatus)} title={`Status ${findingStatus} from finding API`}>{formatFindingLabel(findingStatus)}</Badge>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FindingExplanationPanel finding={entity} config={config} session={session} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Triage</CardTitle>
            <CardDescription>Assign an owner, record notes, and move the finding state.</CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="verify-ladder finding-decision-ladder" aria-label="Finding decision status">
              {decisionSteps.map((step, index) => {
                const now = !step.done && decisionSteps.slice(0, index).every((entry) => entry.done);
                return (
                  <li key={step.id} className={`vl-step${step.done ? ' is-done' : ''}${now ? ' is-now' : ''}`}>
                    <span className="vl-num" aria-hidden="true">{step.done ? <Check size={13} strokeWidth={2.6} /> : index + 1}</span>
                    <div className="vl-body"><strong>{step.label}</strong><span className="vl-meta">{step.meta}</span></div>
                  </li>
                );
              })}
            </ol>
            <div className="kv-list">
              <div><span>Assignee</span><strong>{getString(entity, ['assignee'], 'unassigned')}</strong></div>
              <div><span>SLA due</span><strong title="SLA derived from severity hours and created_at">{slaDueAt ? formatDate(slaDueAt) : '—'}{isFindingSlaBreach(entity) ? ' (breach)' : ''}</strong></div>
            </div>
            {canWriteFinding ? (
            <form className="product-form product-form--compact" onSubmit={(event) => {
              event.preventDefault();
              const form = new FormData(event.currentTarget);
              void patchFinding({ assignee: String(form.get('assignee') ?? '').trim(), notes: String(form.get('notes') ?? '').trim() }, 'Triage updated.', 'triage');
            }}>
              <label className="full"><span>Assignee</span><input name="assignee" defaultValue={getString(entity, ['assignee'], '')} /></label>
              <label className="full"><span>Notes</span><textarea name="notes" rows={3} defaultValue={getString(entity, ['notes'], '')} /></label>
              <div className="row-actions action-bar-compact full">
                <Button type="submit" size="sm" variant="secondary" loading={busy === `finding-triage-${entityId}`} disabled={busy !== ''}>Save triage</Button>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `finding-accept-risk-${entityId}`}
                  disabled={busy !== '' || ['accepted_risk', 'closed'].includes(findingStatus.toLowerCase())}
                  onClick={async () => {
                    if (!await confirm({ title: 'Accept finding risk', description: 'Accept this finding as risk? This records a terminal risk decision.', confirmLabel: 'Accept risk' })) return;
                    await patchFinding({ status: 'accepted_risk' }, 'Finding accepted risk.', 'accept-risk');
                  }}
                >Accept risk</Button>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `finding-close-${entityId}`}
                  disabled={busy !== '' || findingStatus.toLowerCase() === 'closed'}
                  onClick={async () => {
                    if (!await confirm({ title: 'Close finding', description: 'Close this finding after reviewing its evidence and remediation state?', confirmLabel: 'Close finding' })) return;
                    await patchFinding({ status: 'closed' }, 'Finding closed.', 'close');
                  }}
                >Close finding</Button>
                <Button size="sm" variant="secondary" loading={busy === `retest-${entityId}`} disabled={busy !== '' || !canStartFindingRetest} onClick={() => void runAction(`retest-${entityId}`, async () => {
                  const retest = resolveFindingRetestAction(entity);
                  if (!retest) throw new Error('Retest context missing from finding API.');
                  // Every kind resolveFindingRetestAction can return must dispatch a real
                  // request; otherwise runAction reports a false "Retest started." success.
                  // Mirrors retestFinding() in detail-pages.tsx.
                  if (retest.kind === 'waf-validation') {
                    await requestJson(config, session, '/v1/waf/validations', { method: 'POST', body: { waf_asset_id: retest.wafAssetId, modes: ['marker'] } });
                  } else if (retest.kind === 'cve-retest') {
                    await requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(retest.pipelineId)}/retest`, { method: 'POST' });
                  } else if (retest.kind === 'cve-retest-url') {
                    await requestJson(config, session, retest.retestUrl, { method: 'POST' });
                  } else if (retest.kind === 'safe-run') {
                    await requestJson(config, session, '/v1/test-runs', { method: 'POST', body: { check_id: retest.checkId, target_group_id: getString(entity, ['target_group_id'], ''), target_id: getString(entity, ['target_id'], '') } });
                  } else {
                    throw new Error('Unsupported retest kind for this finding.');
                  }
                }, 'Retest started.')}>Retest</Button>
              </div>
            </form>
            ) : <RoleRestrictedCard title="Finding triage is read-only for your role." />}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div><CardTitle>Affected targets</CardTitle><CardDescription>Embedded finding links first; exact target-group linkage is the fallback.</CardDescription></div>
        </CardHeader>
        <CardContent>
          {affectedTargetsLoading ? <PortalLoadingSkeleton rows={2} /> : affectedTargetsError ? (
            <EmptyState
              icon={TriangleAlert}
              title="Affected targets unavailable"
              body={`Could not load the target-group fallback: ${affectedTargetsError}`}
              actionLabel="Retry"
              onAction={() => setAffectedTargetsReloadToken((value) => value + 1)}
            />
          ) : affectedTargets.length === 0 ? (
            <EmptyState
              icon={TriangleAlert}
              title="No declared targets matched."
              body="It may apply at the target-group level — zone-wide, edge-wide — rather than to a single declared target."
            />
          ) : (
            <DataTable
              columns={affectedColumns}
              items={affectedTargets}
              getRowId={(item) => getString(item, ['id'], '')}
              empty={<span className="muted">No affected targets returned.</span>}
            />
          )}
        </CardContent>
      </Card>

      <Card data-od-id="finding-remediation" className="finding-remediation-card">
        <CardHeader>
          <div>
            <CardTitle>Remediation</CardTitle>
            <CardDescription>WAF action tracking and owner assignment when a playbook is linked to this finding.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="finding-remediation-body">
          {hasRemediationPlaybook ? (
            <>
              <div className="finding-remediation-meta">
                <div className="rem-cell"><span className="rem-label">Action</span><span className="rem-value mono">{remediation.remAction || '—'}</span></div>
                <div className="rem-cell"><span className="rem-label">Owner</span><span className="rem-value">{remediation.remOwner || '—'}</span></div>
                <div className="rem-cell"><span className="rem-label">State</span><Badge tone={remStateTone(remediation.remStateClass, remediation.remState)} title={`Remediation state ${remediation.remState} from finding API`}>{remediation.remState || '—'}</Badge></div>
                <div className="rem-cell"><span className="rem-label">SLA</span><span className="rem-value">{remediation.remSla || '—'}</span></div>
              </div>
              {remediation.remDescription ? (
                <p className="finding-remediation-desc">{remediation.remDescription}</p>
              ) : null}
              {remSteps.length > 0 ? (
                <ol className="rem-steps">
                  {remSteps.map((step, index) => (
                    <li key={`${index}-${step}`}><span className="mono">{String(index + 1).padStart(2, '0')}</span> {step}</li>
                  ))}
                </ol>
              ) : null}
              {canWriteFinding ? (
              <form className="product-form product-form--compact" onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                const owner = String(form.get('rem_owner') ?? '').trim();
                void patchFinding({ rem_owner: owner, assignee: owner }, 'Remediation owner reassigned.', 'remediation-owner');
              }}>
                <label className="full">
                  <span>Remediation owner</span>
                  <input key={remediation.remOwner} name="rem_owner" defaultValue={remediation.remOwner} placeholder="team or user" />
                </label>
                <div className="row-actions action-bar-compact full">
                  <Button type="submit" size="sm" variant="secondary" loading={busy === `finding-remediation-owner-${entityId}`} disabled={busy !== ''}>Reassign owner</Button>
                  <Button type="button" size="sm" variant="ghost" disabled={!remediation.actionItemId} loading={busy === `deliver-${entityId}`} onClick={() => void markDelivered()}>Mark delivered</Button>
                </div>
              </form>
              ) : <RoleRestrictedCard title="Remediation changes are read-only for your role." />}
            </>
          ) : (
            <EmptyState
              icon={Wrench}
              title="No remediation playbook linked"
              body="This finding has no WAF action item or remediation steps yet. Use triage above to assign an owner, or link a playbook when your integration provides one."
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Evidence bundle</CardTitle>
            <CardDescription>Artifacts, source runs, sealed digests, and custody positions returned by the finding evidence API.</CardDescription>
          </div>
          <div className="row-actions">
            <Button size="sm" variant="ghost" loading={busy === `verify-${entityId}`} disabled={evidence === null || busy !== ''} onClick={() => void verifyChain()}>Verify chain</Button>
            <Button size="sm" variant="secondary" loading={busy === `export-${entityId}`} disabled={busy !== ''} onClick={() => void exportBundle()}>Export bundle</Button>
          </div>
        </CardHeader>
        <CardContent>
          {evidence === null ? <PortalLoadingSkeleton rows={3} /> : evidence.error ? (
            <EmptyState
              icon={FileCheck2}
              title="Evidence unavailable"
              body={evidence.error}
              actionLabel="Retry"
              onAction={() => setEvidenceReloadToken((value) => value + 1)}
            />
          ) : evidence.artifacts.length > 0 ? (
            <>
              <p className="muted small">Select an artifact to open its evidence detail — payload, SHA-256 digest, and custody position.</p>
              <DataTable
                columns={artifactColumns}
                items={evidence.artifacts}
                getRowId={(item) => getString(item, ['id'], '')}
                getRowProps={(item) => evidenceRowNavProps(getString(item, ['id'], ''))}
                empty={<span className="muted">No artifacts in bundle.</span>}
              />
            </>
          ) : (
            <EmptyState icon={FileCheck2} title="No evidence artifacts." body={getString(evidence.meta, ['empty_reason'], 'Evidence bundle contains no artifacts for this finding.')} />
          )}
        </CardContent>
      </Card>

      <Card className="finding-custody-card">
        <CardHeader>
          <div><CardTitle>Custody chain</CardTitle><CardDescription>Hydrated manifest preview. Verification is reported only after the canonical export payload and custody manifest pass the verify endpoint.</CardDescription></div>
          <Badge tone={chainVerified === true ? 'success' : chainVerified === false ? 'danger' : 'muted'}>{custodyStatus}</Badge>
        </CardHeader>
        <CardContent>
          {evidence === null ? <PortalLoadingSkeleton rows={2} /> : evidence.error ? (
            <EmptyState icon={FileCheck2} title="Custody manifest unavailable" body={evidence.error} actionLabel="Retry" onAction={() => setEvidenceReloadToken((value) => value + 1)} />
          ) : (
            <pre className="code" tabIndex={0} role="region" aria-label="Finding custody chain YAML">{custodyYaml}</pre>
          )}
        </CardContent>
      </Card>
        </>
      ) : null}
    </div>
  );
}
