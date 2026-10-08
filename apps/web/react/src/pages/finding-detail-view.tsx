import { useEffect, useMemo, useRef, useState } from 'react';
import type { HTMLAttributes, MouseEvent as ReactMouseEvent } from 'react';
import { ArrowLeft, Check, Eye, FileCheck2, TriangleAlert, Wrench } from 'lucide-react';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { FindingDetectionHistory } from '../components/findings/finding-detection-history';
import { populateFindingAffectedTargets, populateFindingEvidence, readFindingRemediationFields } from '../lib/finding-detail';
import { readFindingLineage } from '../lib/finding-lineage.mjs';
import { useProgressiveFindings } from '../components/findings/use-server-findings';
import { VerifyChip } from '../lib/verify-chip';
import { requestJson } from '../lib/api';
import { apiErrorMessage } from '../lib/error-messages';
import { sessionHasPermission } from '../lib/dataset-access.mjs';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate, formatSeverityLabel, triggerJsonDownload } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { RoleRestrictedCard } from '../components/ui/role-restricted';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName, plainCodeLabel, plainEmptyReason, plainFindingTitle, plainVerdictLabel } from '../lib/plain-language.mjs';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { DataTable, type TableColumn } from '../components/ui/table';
import {
  FINDING_RULE_ASSETS_FOCUS,
  countFindingAssets,
  findingAssetLabel,
  findingObservedAt,
  findingRuleSiblings,
  findingRuleTitle,
  findingSlaDueAt,
  findingStatus as readFindingStatus,
  isFindingSlaBreach,
  resolveFindingRetestAction
} from '../lib/findings-helpers';
import '../components/findings/findings-groups.css';
import { ConfirmModal, useConfirmModal } from '../lib/crud-ui';
import { useInspectorRef, useOpenInspector } from '../components/evidence/use-inspector';
import { getRouteParam, replaceRouteParams } from '../lib/route-params';

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
.finding-detail-page .finding-summary-fact dd small { display: block; margin-top: 2px; color: var(--fg-2); }
.finding-detail-page .finding-lineage { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: var(--space-3); margin-top: var(--space-4); }
.finding-detail-page .finding-lineage-item { display: grid; gap: var(--space-1); min-width: 0; padding: var(--space-3) var(--space-4); border: 1px solid var(--border-soft); border-radius: var(--radius-md); font-size: var(--text-sm); overflow-wrap: anywhere; }
.finding-detail-page .finding-lineage-label { color: var(--fg-2); font-family: var(--font-mono); font-size: var(--text-xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; }
.finding-detail-page .rule-assets-more { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2) var(--space-3); margin-bottom: var(--space-3); }
.finding-detail-page .finding-lineage-runs { display: grid; gap: var(--space-1); margin: 0; padding: 0; list-style: none; }
.finding-detail-page .finding-lineage-runs li { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); }
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
  const ownerAssigned = Boolean(normalizedOwner && normalizedOwner !== 'unassigned' && normalizedOwner !== 'not reported');
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

function formatFindingLabel(value: string, fallback = 'Not reported') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = 'Not reported') {
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
  if (!Number.isFinite(bytes) || bytes <= 0) return 'Not reported';
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
 * Pointer convenience for artifact rows: a click on the row opens the same inspector as its View
 * button. The row is not a control itself (no role or tab stop), so the View button stays the only
 * keyboard and screen-reader target and nothing interactive is nested inside another control.
 */
function evidenceRowNavProps(artifactId: string, inspect: (artifactId: string) => void): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  if (!artifactId) return {};
  return {
    className: 'finding-artifact-row',
    onClick: (event: ReactMouseEvent<HTMLTableRowElement>) => {
      if ((event.target as HTMLElement).closest('a, button, input, select, textarea, summary')) return;
      if (window.getSelection()?.toString()) return;
      inspect(artifactId);
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
  const [retestReview, setRetestReview] = useState(() => getRouteParam('retest') === 'review');
  const openInspector = useOpenInspector();
  const inspected = useInspectorRef();

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
  const title = plainFindingTitle(entity, [...data.targets, ...affectedTargets], data.checks);
  const slaDueAt = findingSlaDueAt(entity);
  const severity = getString(entity, ['severity'], 'unknown');
  const findingStatus = readFindingStatus(entity);
  const owner = getString(entity, ['assignee', 'rem_owner'], 'unassigned');
  const targetId = getString(entity, ['target_id'], '');
  const testRunId = getString(entity, ['test_run_id'], '');
  const checkId = getString(entity, ['check_id'], '');
  const vectorFamily = getString(entity, ['vector_family', 'vector'], '');
  const lineage = readFindingLineage(entity);
  const originalRunId = lineage.originating?.testRunId || (testRunId === 'Not reported' ? '' : testRunId);
  const originalVerdictId = getString(entity, ['verdict_id'], '');
  const laterVerdictId = getString(entity, ['last_verdict_id'], '');
  const hasLaterVerdict = Boolean(laterVerdictId) && laterVerdictId !== originalVerdictId;
  const retestAction = resolveFindingRetestAction(entity);
  const retestCheck = data.checks.find((check) => getString(check, ['check_id', 'id'], '') === checkId) ?? null;
  const retestBound = Number((retestCheck?.probe_profile as DataItem | undefined)?.max_requests);
  const retestTarget = [...data.targets, ...affectedTargets].find((target) => getString(target, ['id'], '') === targetId) ?? null;

  function inspectOriginal() {
    openInspector({ entry: 'finding', finding_id: entityId, target_id: targetId && targetId !== 'Not reported' ? targetId : undefined, check_id: checkId && checkId !== 'Not reported' ? checkId : undefined }, 'finding-view-evidence');
  }

  function inspectRun(runId: string) {
    openInspector({ entry: 'check_result', target_id: targetId || undefined, check_id: checkId || undefined, test_run_id: runId }, `lineage-${runId}`);
  }

  function inspectArtifact(artifactId: string) {
    openInspector({ entry: 'artifact', evidence_id: artifactId, finding_id: entityId }, `artifact-${artifactId}`);
  }

  function inspectSibling(siblingId: string, siblingTarget: string) {
    openInspector({ entry: 'finding', finding_id: siblingId, target_id: siblingTarget || undefined }, `sibling-${siblingId}`);
  }

  function closeRetestReview() {
    setRetestReview(false);
    replaceRouteParams({ retest: null });
  }

  const decisionSteps = buildFindingDecisionSteps(findingStatus, owner, remediation.remState, hasRemediationPlaybook);
  // Every loaded finding that shares this finding's rule (same recorded outcome), this one included.
  // Rule siblings come from the server's exact check predicate across every status, read in pages.
  // A finding without a check id can only be compared with the loaded page, and says so.
  const ruleSource = useProgressiveFindings(config, session, { check_id: checkId }, 0, Boolean(checkId));
  const ruleRows = checkId ? ruleSource.items : (data.findings ?? []);
  const ruleComplete = checkId ? ruleSource.complete : data.findingsMeta ? !data.findingsMeta.hasMore : false;
  const ruleSiblings = useMemo(
    () => findingRuleSiblings(entity, ruleRows, data.targets ?? []),
    [entity, ruleRows, data.targets]
  );
  const ruleTitle = findingRuleTitle(entity, data.checks);
  const ruleAssetsRef = useRef<HTMLElement | null>(null);
  const ruleOpenCount = ruleSiblings.filter((item) => {
    const status = readFindingStatus(item).toLowerCase();
    return status === 'open' || status === 'remediation_pending';
  }).length;
  const ruleAssetCount = countFindingAssets(ruleSiblings, data.targets ?? []);
  const ruleHasSiblings = ruleSiblings.length > 1;
  const findingsListError = data.loadErrors?.findings ?? '';


  // A grouped queue row opens #finding-detail?id=...&focus=rule-assets; bring the asset list into view.
  useEffect(() => {
    if (loading) return;
    const query = window.location.hash.split('?')[1] ?? '';
    if (new URLSearchParams(query).get('focus') !== FINDING_RULE_ASSETS_FOCUS) return;
    const node = ruleAssetsRef.current;
    if (!node) return;
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    const frame = window.requestAnimationFrame(() => {
      node.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
      node.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [entityId, loading]);

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
    // Missing embedded context can be read only from the finding's exact declared target.
    const targetId = getString(entity, ['target_id'], '');
    if (!targetId) { setAffectedTargetsLoading(false); return undefined; }
    setAffectedTargetsLoading(true);
    requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}`)
      .then((payload) => {
        if (cancelled) return;
        const target = (payload as DataItem).target as DataItem | undefined;
        setAffectedTargets(target && getString(target, ['id'], '') === targetId ? [target] : []);
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
      setError(apiErrorMessage(err, 'Action failed.'));
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
      setError('No remediation action item is linked to this finding.');
      return;
    }
    await runAction(`deliver-${entityId}`, () => requestJson(config, session, `/v1/waf/action-items/${encodeURIComponent(remediation.actionItemId)}/deliver`, { method: 'POST' }), 'Remediation marked delivered.');
  }

  async function verifyChain() {
    setChainVerified(null);
    await runAction(`verify-${entityId}`, async () => {
      // The verify endpoint recomputes the SHA-256 over the export payload and compares it to
      // the custody manifest digest, so it needs { payload, custody }, not { finding_id }.
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
    }, 'Custody chain verified. The SHA-256 digest matches the sealed manifest.');
  }

  async function exportBundle() {
    // The export endpoint returns the sealed bundle synchronously (payload + custody manifest);
    // there is no queued job, so hand the file to the operator instead of discarding it.
    await runAction(`export-${entityId}`, async () => {
      const bundle = await requestJson(config, session, `/v1/findings/${encodeURIComponent(entityId)}/export`, { method: 'POST' });
      triggerJsonDownload(`finding-${entityId}-evidence.json`, bundle);
    }, 'Evidence bundle downloaded with its SHA-256 custody manifest.');
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
    { key: 'kind', label: 'Kind', render: (item) => plainCodeLabel(getString(item, ['kind'], ''), 'Not reported') },
    { key: 'value', label: 'Value', render: (item) => <span className="mono">{getString(item, ['value'], 'Not reported')}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (item) => <VerifyChip state={getString(item, ['verification_state', 'verification'], 'unverified')} provenance={getString(item, ['verification_title'], 'Recorded target verification state.')} />
    },
    { key: 'eligibility', label: 'Eligibility', render: (item) => plainCodeLabel(getString(item, ['eligibility'], ''), 'Not reported') },
    { key: 'verdict', label: 'Last verdict', render: (item) => { const verdict = getString(item, ['last_verdict'], ''); return verdict ? plainVerdictLabel(verdict) : 'No result yet'; } }
  ];

  const ruleAssetColumns: TableColumn<DataItem>[] = [
    {
      key: 'asset',
      label: 'Asset',
      render: (item) => {
        const siblingId = getString(item, ['id'], '');
        const label = findingAssetLabel(item, data.targets);
        if (siblingId === entityId) {
          return <span className="rule-asset-current"><strong>{label}</strong><small>This finding</small></span>;
        }
        return siblingId ? (
          <a className="rule-asset-link" href={buildDetailHref('finding-detail', siblingId)} aria-label={`Open finding on ${label}`}>
            <strong>{label}</strong>
            <small className="mono">{siblingId}</small>
          </a>
        ) : <span className="mono">{label}</span>;
      }
    },
    {
      key: 'check',
      label: 'Check',
      render: (item) => {
        const itemCheckId = getString(item, ['check_id', 'check'], '');
        if (!itemCheckId) return <span className="rule-asset-meta">Not reported</span>;
        const itemCheck = data.checks.find((check) => getString(check, ['check_id', 'id'], '') === itemCheckId);
        return <span className="rule-asset-stack"><span>{plainCheckName(getString(itemCheck ?? {}, ['name', 'title'], itemCheckId))}</span><small className="mono">{itemCheckId}</small></span>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = readFindingStatus(item);
        return <Badge tone={findingStatusTone(status)}>{formatFindingLabel(status)}</Badge>;
      }
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (item) => {
        const value = getString(item, ['severity'], 'unknown');
        return <Badge tone={findingSeverityTone(value)}>{formatSeverityLabel(value)}</Badge>;
      }
    },
    {
      key: 'observed',
      label: 'Last observed',
      render: (item) => {
        const observed = findingObservedAt(item);
        return observed ? formatDate(observed) : <span className="rule-asset-meta">Not reported</span>;
      }
    },
    {
      key: 'evidence',
      label: 'Evidence',
      render: (item) => {
        const siblingId = getString(item, ['id'], '');
        const evidenceCount = Array.isArray(item.evidence_ids) ? item.evidence_ids.filter(Boolean).length : 0;
        if (!siblingId) return <span className="rule-asset-evidence-missing">No finding ID recorded</span>;
        return (
          <Button
            size="sm"
            variant="ghost"
            data-focus-key={`sibling-${siblingId}`}
            aria-label={`View the original evidence for the finding on ${findingAssetLabel(item, data.targets)}`}
            onClick={() => inspectSibling(siblingId, getString(item, ['target_id'], ''))}
          >
            <Eye size={14} aria-hidden="true" />
            {evidenceCount ? `View ${evidenceCount} record${evidenceCount === 1 ? '' : 's'}` : 'View evidence'}
          </Button>
        );
      }
    }
  ];

  const artifactColumns: TableColumn<DataItem>[] = [
    {
      key: 'artifact',
      label: 'Artifact',
      render: (item) => {
        const artifactId = getString(item, ['id'], '');
        const label = plainCodeLabel(getString(item, ['kind'], ''), 'Evidence artifact');
        const cited = Array.isArray(entity.evidence_ids) && entity.evidence_ids.map(String).includes(artifactId);
        return (
          <span className="entity-cell-stack">
            <span>{label}</span>
            {artifactId ? null : <small>No artifact ID recorded</small>}
            <small>{cited ? 'Cited by this finding' : 'Recorded for the originating run'}</small>
          </span>
        );
      }
    },
    { key: 'kind', label: 'Kind', render: (item) => plainCodeLabel(getString(item, ['kind'], ''), 'Not reported') },
    {
      key: 'run',
      label: 'Run',
      render: (item) => {
        const runId = getString(item, ['run_id'], '');
        return runId ? <span className="mono">{runId}</span> : <span className="rule-asset-meta">Not reported</span>;
      }
    },
    { key: 'sha', label: 'Recorded digest', render: (item) => <span className="mono small finding-digest" title={getString(item, ['sha256', 'content_sha256'], 'Not reported')}>{getString(item, ['sha256', 'content_sha256'], 'Not reported')}</span> },
    { key: 'sealed', label: 'Sealed', render: (item) => formatDate(item.sealed_at) },
    { key: 'size', label: 'Size', render: (item) => <span className="num">{formatBytes(item.size_bytes)}</span> },
    {
      key: 'inspect',
      label: 'Inspect',
      render: (item) => {
        const artifactId = getString(item, ['id'], '');
        return artifactId ? (
          <Button size="sm" variant="ghost" data-focus-key={`artifact-${artifactId}`} onClick={(event) => { event.stopPropagation(); inspectArtifact(artifactId); }} aria-label={`View artifact ${artifactId} in the evidence inspector`}>
            <Eye size={14} aria-hidden="true" />View
          </Button>
        ) : null;
      }
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
          `    sha256: ${getString(step, ['sha256'], 'not_recorded')}`
        ])]
      : []),
    `bundle_sha256: ${bundleSha256 || 'not_recorded'}`,
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
            <Badge tone={findingSeverityTone(severity)} title={`Recorded severity: ${formatSeverityLabel(severity)}`}>{formatSeverityLabel(severity)}</Badge>
            <Badge tone={findingStatusTone(findingStatus)} title={`Recorded status: ${formatFindingLabel(findingStatus)}`}>{formatFindingLabel(findingStatus)}</Badge>
          </div>
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="ghost" href="#findings"><ArrowLeft size={14} aria-hidden="true" />Findings</AnchorButton>
          <Button size="sm" variant="default" data-focus-key="finding-view-evidence" onClick={inspectOriginal}><Eye size={14} aria-hidden="true" />View original evidence</Button>
        </div>
      </div>

      {loading ? <PortalLoadingSkeleton rows={2} /> : null}
      <DetailStatusBanners loadError={loadError} message={message} error={error} />

      {!loading ? (
        <>
      <Card className="finding-summary-card">
        <CardHeader>
          <div><CardTitle>Finding summary</CardTitle><CardDescription>Key facts and exact relationships for triage and evidence review.</CardDescription></div>
        </CardHeader>
        <CardContent>
          <dl className="finding-summary-facts">
            <div className="finding-summary-fact"><dt>Finding ID</dt><dd className="mono">{entityId}</dd></div>
            <div className="finding-summary-fact"><dt>SLA due</dt><dd>{slaDueAt ? formatDate(slaDueAt) : 'Not reported'}{isFindingSlaBreach(entity) ? ' · breached' : ''}</dd></div>
            {checkId ? <div className="finding-summary-fact"><dt>Check</dt><dd><span>{plainCheckName(getString(data.checks.find((check) => getString(check, ['check_id', 'id'], '') === checkId) ?? {}, ['name', 'title'], checkId))}</span><small className="mono">{checkId}</small></dd></div> : null}
            {vectorFamily ? <div className="finding-summary-fact"><dt>Vector</dt><dd>{formatFindingLabel(vectorFamily)}</dd></div> : null}
            {targetId ? <div className="finding-summary-fact"><dt>Target ID</dt><dd className="mono">{targetId}</dd></div> : null}
            {testRunId ? <div className="finding-summary-fact"><dt>Source run</dt><dd className="mono">{testRunId}</dd></div> : null}
            {entity.created_at ? <div className="finding-summary-fact"><dt>Opened</dt><dd>{formatDate(entity.created_at)}</dd></div> : null}
            {entity.updated_at ? <div className="finding-summary-fact"><dt>Updated</dt><dd>{formatDate(entity.updated_at)}</dd></div> : null}
          </dl>
          <div className="finding-relations" aria-label="Finding relationships">
            {targetId ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-detail', targetId)}>Target</AnchorButton> : null}
          </div>
          <section className="finding-lineage" aria-label="Original evidence and later results">
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Original evidence</span>
              <span>{originalRunId ? <>Recorded execution <span className="mono">{originalRunId}</span></> : 'Originating execution not recorded'}{originalVerdictId ? <> · verdict <span className="mono">{originalVerdictId}</span></> : null}</span>
              <span className="muted small">The observation that opened this finding. It is kept even after later results.</span>
            </div>
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Retests of this finding</span>
              {lineage.retests.length ? (
                <ul className="finding-lineage-runs">
                  {lineage.retests.map((run) => (
                    <li key={run.testRunId}>
                      <Button size="sm" variant="ghost" className="mono" data-focus-key={`lineage-${run.testRunId}`} aria-label={`View result of retest run ${run.testRunId}`} onClick={() => inspectRun(run.testRunId)}>{run.testRunId}</Button>
                      {run.createdAt ? <span className="muted small"> requested {formatDate(run.createdAt)}</span> : null}
                      {lineage.latest?.testRunId === run.testRunId ? (
                        <>
                          <Badge tone="muted">Most recent retest</Badge>
                          <span className="muted small">
                            {lineage.latest.pending || lineage.latest.finalized === false
                              ? `Not finished${lineage.latest.status ? ` (${lineage.latest.status.replace(/_/g, ' ')})` : ''}; no later result yet`
                              : lineage.latest.finalized ? `Finished${lineage.latest.completedAt ? ` ${formatDate(lineage.latest.completedAt)}` : ''}` : ''}
                          </span>
                        </>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : <span className="muted">No run has been recorded as a retest of this finding.</span>}
              <span className="muted small">Only runs started from Review retest are retests. A retest result does not close this finding or any other.</span>
            </div>
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Later runs, same target and check</span>
              {lineage.laterSamePair.length ? (
                <ul className="finding-lineage-runs">
                  {lineage.laterSamePair.map((run) => (
                    <li key={run.testRunId}>
                      <Button size="sm" variant="ghost" className="mono" data-focus-key={`lineage-${run.testRunId}`} aria-label={`View result of run ${run.testRunId}`} onClick={() => inspectRun(run.testRunId)}>{run.testRunId}</Button>
                      <span className="muted small">{run.finalized === false ? ' not finished' : run.finalized ? ' finished' : ''}</span>
                    </li>
                  ))}
                </ul>
              ) : <span className="muted">No other run of this target and check is recorded.</span>}
              <span className="muted small">Routine runs without retest intent. They are listed for context and do not change this finding.</span>
              {hasLaterVerdict ? <span className="small">Latest verdict recorded on this finding: <span className="mono">{laterVerdictId}</span></span> : null}
            </div>
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Closure</span>
              {lineage.closedAt ? <span>Closed {formatDate(lineage.closedAt)}</span> : <span className="muted">Not closed.</span>}
              <span className="muted small">Closure is a recorded status change, not proof of a fix. Findings on other targets are never closed with this one.</span>
            </div>
          </section>
        </CardContent>
      </Card>

      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Verdict explanation</CardTitle>
            <CardDescription className="detail-status-line">
              <Badge tone={findingSeverityTone(severity)} title={`Recorded severity: ${formatSeverityLabel(severity)}`}>{formatSeverityLabel(severity)}</Badge>
              <span className="detail-status-sep" aria-hidden="true">·</span>
              <Badge tone={findingStatusTone(findingStatus)} title={`Recorded status: ${formatFindingLabel(findingStatus)}`}>{formatFindingLabel(findingStatus)}</Badge>
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
              <div><span>SLA due</span><strong title="SLA derived from severity hours and created_at">{slaDueAt ? formatDate(slaDueAt) : 'Not reported'}{isFindingSlaBreach(entity) ? ' (breach)' : ''}</strong></div>
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
                <Button size="sm" variant="secondary" disabled={busy !== '' || !canStartFindingRetest || !retestAction} title={!retestAction ? 'Retest details are missing from this finding.' : undefined} onClick={() => setRetestReview(true)}>Review retest</Button>
              </div>
            </form>
            ) : <RoleRestrictedCard title="Finding triage is read-only for your role." />}
            <ConfirmModal
              open={retestReview && canStartFindingRetest && Boolean(retestAction)}
              title="Review this retest"
              description={(
                <div className="stack-tight scan-review">
                  <dl className="td-review-list">
                    <div><dt>Finding</dt><dd>{title} <span className="mono">{entityId}</span></dd></div>
                    <div><dt>Target</dt><dd className="mono">{getString(retestTarget, ['value'], targetId || 'Not recorded')}</dd></div>
                    <div><dt>Check</dt><dd>{checkId ? plainCheckName(getString(retestCheck ?? {}, ['name', 'title'], checkId)) : 'Not recorded'}</dd></div>
                    {retestAction?.kind === 'safe-run' ? <div><dt>Recorded as</dt><dd>Retest of this finding (same target and check)</dd></div> : null}
                    <div><dt>Upper bound</dt><dd>{retestAction?.kind === 'safe-run' ? (Number.isFinite(retestBound) ? `${retestBound} requests` : 'Not recorded in the catalog') : retestAction?.kind === 'waf-validation' ? 'WAF marker validation for the linked asset' : 'CVE pipeline retest'}</dd></div>
                  </dl>
                  <p>This starts a new bounded check on the same target and check. The server re-checks ownership, safe windows, rate, concurrency and kill-switch gates now; an expired scope is not replayed.</p>
                  <p>The original evidence stays. A passing retest is shown as a later result and never closes other domains.</p>
                </div>
              )}
              confirmLabel="Start retest"
              confirmTone="default"
              busy={busy === `retest-${entityId}`}
              onCancel={closeRetestReview}
              onConfirm={() => void runAction(`retest-${entityId}`, async () => {
                  const retest = retestAction;
                  if (!retest) throw new Error('Retest details are missing from this finding.');
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
                    if (!targetId) throw new Error('This finding has no declared target, so a retest cannot be recorded against it.');
                    await requestJson(config, session, '/v1/test-runs', { method: 'POST', body: { check_id: retest.checkId, target_id: targetId, retest_of_finding_id: entityId } });
                  } else {
                    throw new Error('Unsupported retest kind for this finding.');
                  }
                  closeRetestReview();
                }, 'Retest started. Its result appears as a later result; the original evidence is unchanged.')}
            />
          </CardContent>
        </Card>
      </div>

      <FindingDetectionHistory
        entity={entity}
        entityId={entityId}
        targetId={targetId}
        targetDisplay={targetId ? (getString(data.targets?.find((t) => t.id === targetId), ['value', 'hostname'], '') || getString(entity, ['target_hostname', 'target_value'], targetId)) : ''}
        checkId={checkId}
        checks={data.checks}
        dataFindings={data.findings}
        config={config}
        session={session}
        onInspectFinding={(finding) => {
          const id = getString(finding, ['id'], '');
          if (!id) return;
          openInspector({ entry: 'finding', finding_id: id, target_id: targetId || undefined, check_id: getString(finding, ['check_id'], '') || undefined }, `finding-${id}`);
        }}
        onInspectRun={(runId, runCheckId) => {
          if (!runId) return;
          openInspector({ entry: 'check_result', target_id: targetId || undefined, check_id: runCheckId || checkId, test_run_id: runId }, `run-${runId}`);
        }}
      />

      <Card>
        <CardHeader>
          <div><CardTitle>Affected targets</CardTitle><CardDescription>Embedded finding links first; the recorded target is the fallback.</CardDescription></div>
        </CardHeader>
        <CardContent>
          {affectedTargetsLoading ? <PortalLoadingSkeleton rows={2} /> : affectedTargetsError ? (
            <EmptyState
              icon={TriangleAlert}
              title="Affected targets unavailable"
              body={`Could not load the recorded target: ${affectedTargetsError}`}
              actionLabel="Retry"
              onAction={() => setAffectedTargetsReloadToken((value) => value + 1)}
            />
          ) : affectedTargets.length === 0 ? (
            <EmptyState
              icon={TriangleAlert}
              title="No declared targets matched."
              body="This finding does not record a matching declared target. No affected domain is inferred."
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

      <section
        id="rule-assets"
        ref={ruleAssetsRef}
        tabIndex={-1}
        className="rule-assets-section"
        aria-labelledby="rule-assets-title"
      >
      <Card className="rule-assets-card">
        <CardHeader>
          <div>
            <CardTitle id="rule-assets-title">Affected assets for this rule</CardTitle>
            <CardDescription>Every loaded finding that recorded &ldquo;{ruleTitle}&rdquo;. Open an asset for its own explanation, remediation, retest, and custody export.</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          {findingsListError ? (
            <div className="form-banner error" role="alert">
              Could not load the finding list, so other assets for this rule may be missing: {findingsListError}
            </div>
          ) : null}

          <p className="rule-assets-summary">
            {ruleHasSiblings ? (
              <>
                <span className="tabular-nums">{ruleSiblings.length}</span> findings on <span className="tabular-nums">{ruleAssetCount}</span> {ruleAssetCount === 1 ? 'asset' : 'assets'}, <span className="tabular-nums">{ruleOpenCount}</span> open{ruleComplete ? '' : ', among findings read so far'}
              </>
            ) : ruleComplete
              ? 'No other finding records this outcome. When validation records it on another asset, that asset is listed here.'
              : 'No other finding read so far records this outcome.'}
          </p>
          {checkId && !ruleComplete && ruleSource.state === 'ready' && ruleSource.envelope?.total !== null && ruleSource.envelope?.total !== undefined ? (
            <div className="rule-assets-more">
              <span className="muted small">{`Read ${ruleSource.items.length} of ${ruleSource.envelope.total} findings for this check.`}</span>
              {ruleSource.error ? <span className="small" role="alert">{ruleSource.error}</span> : null}
              <Button size="sm" variant="secondary" loading={ruleSource.loadingMore} onClick={ruleSource.loadMore}>Read more findings for this check</Button>
            </div>
          ) : null}
          {!checkId && !ruleComplete ? <p className="muted small">This finding has no check ID, so only the loaded page of findings is compared.</p> : null}
          {checkId && ruleSource.state === 'error' ? <p className="small" role="alert">{`Findings for this check could not load: ${ruleSource.error}`}</p> : null}
          {ruleHasSiblings ? (
            <DataTable
              className="rule-assets-table"
              columns={ruleAssetColumns}
              items={ruleSiblings}
              getRowId={(item, index) => getString(item, ['id'], String(index))}
              getRowProps={(item) => (getString(item, ['id'], '') === entityId ? { className: 'is-current-asset', 'aria-current': 'true' } : {})}
              empty={<span className="muted">No findings recorded for this rule.</span>}
            />
          ) : null}
        </CardContent>
      </Card>
      </section>

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
                <div className="rem-cell"><span className="rem-label">Action</span><span className="rem-value mono">{remediation.remAction || 'Not reported'}</span></div>
                <div className="rem-cell"><span className="rem-label">Owner</span><span className="rem-value">{remediation.remOwner || 'Not reported'}</span></div>
                <div className="rem-cell"><span className="rem-label">State</span><Badge tone={remStateTone(remediation.remStateClass, remediation.remState)} title={`Recorded remediation state: ${plainCodeLabel(remediation.remState)}`}>{plainCodeLabel(remediation.remState, 'Not reported')}</Badge></div>
                <div className="rem-cell"><span className="rem-label">SLA</span><span className="rem-value">{remediation.remSla || 'Not reported'}</span></div>
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
            <CardDescription>Recorded artifacts, source runs, sealed digests, and custody positions.</CardDescription>
          </div>
          <div className="row-actions">
            <Button size="sm" variant="ghost" loading={busy === `verify-${entityId}`} disabled={evidence === null || busy !== ''} onClick={() => void verifyChain()}>Verify chain</Button>
            <Button size="sm" variant="secondary" loading={busy === `export-${entityId}`} disabled={busy !== ''} onClick={() => void exportBundle()}>Export evidence</Button>
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
              <p className="muted small">Artifacts recorded for this finding's originating execution. Select one to inspect it; a recorded digest is not a verified custody chain until you run Verify chain.</p>
              <DataTable
                columns={artifactColumns}
                items={evidence.artifacts}
                getRowId={(item) => getString(item, ['id'], '')}
                getRowProps={(item) => {
                  const props = evidenceRowNavProps(getString(item, ['id'], ''), inspectArtifact);
                  return getString(item, ['id'], '') && inspected?.entry === 'artifact' && inspected.evidence_id === getString(item, ['id'], '')
                    ? { ...props, className: `${props.className ?? ''} is-selected`, 'aria-current': 'true' }
                    : props;
                }}
                empty={<span className="muted">No artifacts in bundle.</span>}
              />
            </>
          ) : (
            <EmptyState icon={FileCheck2} title="No evidence artifacts." body={plainEmptyReason(getString(evidence.meta, ['empty_reason'], 'Evidence bundle contains no artifacts for this finding.'))} />
          )}
        </CardContent>
      </Card>

      <Card className="finding-custody-card">
        <CardHeader>
          <div><CardTitle>Custody chain</CardTitle><CardDescription>Verification is shown only after the exported evidence and custody manifest pass the verification check.</CardDescription></div>
          <Badge tone={chainVerified === true ? 'success' : chainVerified === false ? 'danger' : 'muted'}>{custodyStatus}</Badge>
        </CardHeader>
        <CardContent>
          {evidence === null ? <PortalLoadingSkeleton rows={2} /> : evidence.error ? (
            <EmptyState icon={FileCheck2} title="Custody manifest unavailable" body={evidence.error} actionLabel="Retry" onAction={() => setEvidenceReloadToken((value) => value + 1)} />
          ) : (
            <details className="technical-disclosure">
              <summary>Show technical custody record</summary>
              <pre className="code" tabIndex={0} role="region" aria-label="Finding custody chain YAML">{custodyYaml}</pre>
            </details>
          )}
        </CardContent>
      </Card>
        </>
      ) : null}
    </div>
  );
}
