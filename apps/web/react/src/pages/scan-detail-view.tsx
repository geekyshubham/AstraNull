import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { History, ScanSearch } from 'lucide-react';
import { requestJson } from '../lib/api';
import { apiErrorMessage } from '../lib/error-messages';
import { createPayloadCommitGate } from '../lib/payload-commit-generation.mjs';
import { canStartRun } from '../lib/run-permissions.mjs';
import { buildDetailHref, getRouteEntityId } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, PortalDataset, Session } from '../lib/types';
import { formatDate, formatTargetKind } from '../lib/utils';
// @ts-ignore Plain ESM keeps verdict labels directly testable with node:test.
import { plainVerdictLabel, plainVerdictShortLabel } from '../lib/plain-language.mjs';
import { additionalInputReasonCopy, controlsHref, targetRequirementForReason } from '../lib/control-declarations.mjs';
import { requiredInputMissing, requiredInputMissingHref } from '../lib/missing-input.mjs';
import {
  SCAN_POLL_BASE_MS,
  SCAN_POLL_SCHEDULED_MS,
  formatRequestsSent,
  formatStepRequest,
  formatStepResponse,
  humanizeReason,
  isScanActive,
  isScanCancellable,
  isScanScheduled,
  isScanTerminal,
  isStepActive,
  mergeActivity,
  nextPollDelay,
  recurrenceLabel,
  scanDisplayName,
  scanProgressPercent,
  scanStatusLabel,
  scanStatusTone,
  scopeLabel,
  stepStatusLabel,
  stepStatusTone,
  type ActivityItem,
} from '../lib/validation-scan.mjs';
import { Badge } from '../components/ui/badge';
import { CheckClassChips } from '../components/checks/check-class-chips';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
import { CancelScanDialog } from '../components/runs/validation-scans-table';
import { DetailBackLink } from '../components/layout/detail-back-link';
import { useEntityDocumentTitle } from '../components/layout/app-shell';
import { PageContextSummary, PageHeader } from './page-components';
import './scan-detail-view.css';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function asItem(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function itemArray(value: unknown) {
  return Array.isArray(value) ? value as DataItem[] : [];
}

function scanTargetIds(scan: DataItem | null) {
  if (!scan) return [];
  if (Array.isArray(scan.target_ids)) return scan.target_ids.map(String).filter(Boolean);
  const single = getString(scan, ['target_id']);
  return single ? [single] : [];
}

function scanTargetLink(scan: DataItem | null) {
  const ids = scanTargetIds(scan);
  if (ids.length !== 1) return undefined;
  const [id] = ids;
  const targets = itemArray(scan?.targets);
  const label = getString(asItem(scan?.target), ['value']) || getString(targets[0], ['value']) || id;
  return { label, href: `${buildDetailHref('target-detail', id)}&tab=validate` };
}

const ROLE_LABELS: Record<string, string> = { owner: 'Owner', admin: 'Admin', engineer: 'Engineer' };

function scanCreatorLabel(scan: DataItem) {
  const named = getString(scan, ['created_by_name', 'created_by_email']);
  if (named) return `created by ${named}`;
  const role = getString(scan, ['created_by_role']).toLowerCase();
  if (!role) return 'creator not recorded';
  const label = ROLE_LABELS[role] ?? role.replace(/_/g, ' ');
  return `created by ${/^[aeiou]/i.test(label) ? 'an' : 'a'} ${label}`;
}

function numberOf(item: DataItem | null, key: string) {
  const value = Number(item?.[key]);
  return Number.isFinite(value) ? value : 0;
}

type PollState = {
  scanId: string;
  scan: DataItem | null;
  activity: ActivityItem[];
  status: 'loading' | 'ready' | 'missing' | 'error';
  error: string;
  errorCount: number;
  lastRefreshedAt: string;
};

function initialPollState(scanId: string): PollState {
  return { scanId, scan: null, activity: [], status: 'loading', error: '', errorCount: 0, lastRefreshedAt: '' };
}

function useScanPolling(config: PortalConfig, session: Session, scanId: string) {
  const [state, setState] = useState<PollState>(() => initialPollState(scanId));
  const [tick, setTick] = useState(0);
  const gateRef = useRef(createPayloadCommitGate(scanId));
  const cursorRef = useRef<string | null>(null);
  const statusRef = useRef<string>('');

  useEffect(() => {
    gateRef.current.activate(scanId);
    cursorRef.current = null;
    statusRef.current = '';
    setState(initialPollState(scanId));
  }, [scanId]);

  useEffect(() => {
    if (!scanId) return undefined;
    let timer: number | undefined;
    let stopped = false;
    const gate = gateRef.current;

    async function poll() {
      const ticket = gate.begin(scanId);
      const activityPath = `/v1/validation-scans/${encodeURIComponent(scanId)}/activity${cursorRef.current ? `?after=${encodeURIComponent(cursorRef.current)}` : ''}`;
      try {
        const [scan, activity] = await Promise.all([
          requestJson(config, session, `/v1/validation-scans/${encodeURIComponent(scanId)}`) as Promise<DataItem>,
          requestJson(config, session, activityPath) as Promise<DataItem>
        ]);
        if (stopped || !gate.isCurrent(ticket)) return;
        const items = itemArray(activity.items) as ActivityItem[];
        if (getString(activity, ['cursor'])) cursorRef.current = getString(activity, ['cursor']);
        const status = getString(scan, ['status']);
        statusRef.current = status;
        setState((current) => ({
          scanId,
          scan,
          activity: mergeActivity(current.scanId === scanId ? current.activity : [], items),
          status: 'ready',
          error: '',
          errorCount: 0,
          lastRefreshedAt: new Date().toISOString()
        }));
        const delay = nextPollDelay({ status, errorCount: 0 });
        if (delay !== null) timer = window.setTimeout(() => { void poll(); }, delay);
      } catch (err) {
        if (stopped || !gate.isCurrent(ticket)) return;
        const httpStatus = Number((err as { status?: unknown }).status);
        if (httpStatus === 404) {
          setState((current) => ({ ...current, scanId, status: current.scan ? current.status : 'missing', error: '' }));
          return;
        }
        let nextErrorCount = 0;
        setState((current) => {
          nextErrorCount = current.errorCount + 1;
          return {
            ...current,
            scanId,
            status: current.scan ? current.status : 'error',
            error: apiErrorMessage(err, 'The scan could not be refreshed.'),
            errorCount: nextErrorCount
          };
        });
        const delay = nextPollDelay({ status: statusRef.current || 'running', errorCount: Math.max(1, nextErrorCount) });
        if (delay !== null) timer = window.setTimeout(() => { void poll(); }, delay);
      }
    }

    void poll();
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [config, session, scanId, tick]);

  const refresh = useCallback(() => setTick((value) => value + 1), []);
  return { ...state, refresh };
}

function scanReasonText(reason: string) {
  return additionalInputReasonCopy(reason)?.label ?? humanizeReason(reason);
}

function StepStatusCell({ step }: { step: DataItem }) {
  const status = getString(step, ['status']);
  const reason = getString(step, ['error_code']) || getString(step, ['skip_reason']);
  return (
    <span className="scan-cell-stack">
      <span className="scan-status-line">
        {isStepActive(step) ? <span className="scan-live-dot" aria-hidden="true" /> : null}
        <Badge tone={stepStatusTone(status)}>{stepStatusLabel(status)}</Badge>
      </span>
      {reason ? <small className="muted">{scanReasonText(reason)}</small> : null}
      {status === 'deferred' && step.eligible_at ? <small className="muted">Eligible {formatDate(step.eligible_at)}</small> : null}
    </span>
  );
}

const SETTLED_STEP_STATUSES = new Set(['verdicted', 'completed', 'denied', 'skipped', 'cancelled']);
const VERDICT_EXPECTED_STATUSES = new Set(['verdicted', 'completed']);

function isStepSettled(step: DataItem) {
  return SETTLED_STEP_STATUSES.has(getString(step, ['status']).toLowerCase());
}

function StepRunLink({ step }: { step: DataItem }) {
  const runId = getString(step, ['test_run_id']);
  if (!runId) return null;
  return <small><a className="detail-entity-link" href={buildDetailHref('run-detail', runId)} aria-label={`Open run ${runId}`}>Open run</a></small>;
}

function VerdictCell({ step }: { step: DataItem }) {
  const verdict = asItem(step.verdict);
  if (!verdict) {
    return (
      <span className="scan-cell-stack">
        <span className="muted">{!isStepSettled(step) ? 'No verdict yet' : VERDICT_EXPECTED_STATUSES.has(getString(step, ['status']).toLowerCase()) ? 'Not recorded' : 'No verdict, step ended'}</span>
        <StepRunLink step={step} />
      </span>
    );
  }
  const notTested = requiredInputMissing(step);
  if (notTested) {
    const href = requiredInputMissingHref(notTested, getString(step, ['target_id']));
    return (
      <span className="scan-cell-stack">
        <strong>{notTested.label}</strong>
        <small className="muted">{notTested.message}</small>
        {href && notTested.cta ? <small><a className="detail-entity-link" href={href}>{notTested.cta}</a></small> : null}
        <StepRunLink step={step} />
      </span>
    );
  }
  const confidence = getString(verdict, ['confidence']);
  const verdictValue = getString(verdict, ['verdict'], 'unknown');
  return (
    <span className="scan-cell-stack">
      <strong>{plainVerdictShortLabel(verdictValue)}</strong>
      <small className="muted">{plainVerdictLabel(verdictValue)}</small>
      {confidence ? <small className="muted">Confidence {humanizeReason(confidence).toLowerCase()}</small> : null}
      {getString(verdict, ['severity']) ? <small className="muted">Severity {getString(verdict, ['severity'])}</small> : null}
      <StepRunLink step={step} />
    </span>
  );
}

const SCAN_SUMMARY_COUNTS = ['running', 'deferred', 'pending', 'verdicted', 'denied', 'skipped', 'cancelled'] as const;

function ActivityLogPanel({ items, loading }: { items: ActivityItem[]; loading: boolean }) {
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Activity log</CardTitle>
          <CardDescription>Metadata only: no request or response bodies are recorded. Entries are shown in recorded time order.</CardDescription>
        </div>
        <Badge tone="muted">{items.length} {items.length === 1 ? 'entry' : 'entries'}</Badge>
      </CardHeader>
      <CardContent>
        {loading && items.length === 0 ? <PortalLoadingSkeleton rows={2} label="Loading scan activity" /> : null}
        {!loading && items.length === 0 ? (
          <EmptyState icon={History} title="No activity recorded yet." body="Dispatch, deferral, and verdict entries appear here as this scan's steps run." />
        ) : null}
        {items.length > 0 ? (
          <ol className="activity-log" aria-label="Scan activity">
            {items.map((item) => {
              const metadata = asItem(item.metadata);
              const kind = getString(item, ['kind'], 'event');
              const runId = getString(item, ['test_run_id']);
              const checkId = getString(item, ['check_id']);
              return (
                <li key={String(item.id)} className="activity-log-item">
                  <time className="activity-log-time" dateTime={getString(item, ['at'])}>{formatDate(item.at)}</time>
                  <div className="activity-log-body">
                    <div className="activity-log-head">
                      <Badge tone={kind === 'scan' ? 'info' : kind === 'run' ? 'default' : 'muted'} mono>{kind}</Badge>
                      <span className="activity-log-summary">{humanizeReason(getString(item, ['summary'], getString(item, ['action'])))}</span>
                    </div>
                    <div className="activity-log-meta">
                      {checkId ? <code className="check-picker-row-id">{checkId}</code> : null}
                      {runId ? <a className="scan-link" href={buildDetailHref('run-detail', runId)}>Run {runId}</a> : null}
                      {getString(item, ['actor_role']) ? <span className="muted small">by {getString(item, ['actor_role'])}</span> : null}
                      {metadata ? Object.entries(metadata)
                        .filter(([, value]) => value !== null && value !== undefined && typeof value !== 'object')
                        .map(([key, value]) => (
                          <span key={key} className="activity-log-chip">
                            <span className="muted">{humanizeReason(key)}:</span> {key.endsWith('_id') ? String(value) : humanizeReason(String(value))}
                          </span>
                        )) : null}
                    </div>
                  </div>
                </li>
              );
            })}
          </ol>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function ScanDetailView({
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: (datasets?: readonly PortalDataset[]) => Promise<void>;
}) {
  const [routeTick, setRouteTick] = useState(0);
  useEffect(() => {
    const onHashChange = () => setRouteTick((value) => value + 1);
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  const scanId = useMemo(() => getRouteEntityId(''), [routeTick]);
  const polling = useScanPolling(config, session, scanId);
  const [cancelOpen, setCancelOpen] = useState(false);
  const [message, setMessage] = useState('');

  const scan = polling.scan;
  const status = getString(scan, ['status']);
  const summary = asItem(scan?.summary);
  const steps = itemArray(scan?.steps);
  const excluded = itemArray(scan?.excluded);
  const active = isScanActive(scan);
  const scheduled = isScanScheduled(scan);
  const terminal = isScanTerminal(scan);
  const canManage = canStartRun(session.role);
  const targetLink = scanTargetLink(scan);
  useEntityDocumentTitle(scan ? scanDisplayName(scan) : undefined);

  const liveText = !scan
    ? ''
    : active
      ? `Scan ${scanStatusLabel(status).toLowerCase()}. Refreshing every ${Math.round(SCAN_POLL_BASE_MS / 1000)} seconds. ${numberOf(summary, 'completed')} of ${numberOf(summary, 'total')} steps complete.`
      : scheduled
        ? `Scan scheduled. Checking for dispatch every ${Math.round(SCAN_POLL_SCHEDULED_MS / 1000)} seconds.`
        : `Scan ${scanStatusLabel(status).toLowerCase()}. Live updates stopped.`;

  const stepColumns: TableColumn<DataItem>[] = [
    { key: 'position', label: '#', render: (step) => <span className="tabular-nums">{Number(step.position ?? 0) + 1}</span> },
    {
      key: 'check',
      label: 'Check',
      render: (step) => (
        <span className="scan-cell-stack">
          <strong>{getString(step, ['check_name', 'check_id'])}</strong>
          <code className="check-picker-row-id">{getString(step, ['check_id'])}</code>
          <CheckClassChips check={step} />
          <small className="muted">{[getString(step, ['section_label']), getString(step, ['evidence_tier'])].filter(Boolean).join(' · ') || 'Section not recorded'}</small>
        </span>
      )
    },
    { key: 'verdict', label: 'Verdict', render: (step) => <VerdictCell step={step} /> },
    { key: 'status', label: 'Status', render: (step) => <StepStatusCell step={step} /> },
    {
      key: 'target',
      label: 'Target',
      render: (step) => {
        const targetId = getString(step, ['target_id']);
        const checkId = getString(step, ['check_id']);
        const targetValue = getString(step, ['target_value', 'target_id']);
        const href = targetId
          ? `${buildDetailHref('target-detail', targetId)}&tab=validate${checkId ? `&check=${encodeURIComponent(checkId)}` : ''}`
          : '';
        return (
          <span className="scan-cell-stack">
            {href
              ? <a className="detail-entity-link scan-step-target" href={href} title={targetId}>{targetValue}</a>
              : <span className="scan-step-target">{targetValue}</span>}
            <small className="muted">{formatTargetKind(getString(step, ['target_kind']), getString(step, ['target_value']))}</small>
          </span>
        );
      }
    },
    { key: 'request', label: 'Probe request', render: (step) => <span className="small scan-step-request">{formatStepRequest(step.request)}</span> },
    {
      key: 'response',
      label: 'Response',
      render: (step) => {
        const response = asItem(step.response);
        if (!response && isStepSettled(step)) return <span className="muted">Not recorded</span>;
        const formatted = formatStepResponse(response);
        const recordedError = getString(response ?? {}, ['error', 'error_class']);
        const responseLabel = response && formatted === 'Awaiting response' && isStepSettled(step)
          ? (recordedError ? `Recorded error: ${recordedError.replace(/_/g, ' ')}` : 'No result recorded')
          : formatted;
        return (
          <span className="scan-cell-stack">
            <span className="small">{responseLabel}</span>
            {response?.received_at ? <small className="muted">{formatDate(response.received_at)}</small> : null}
          </span>
        );
      }
    },
    { key: 'sent', label: 'Requests sent', render: (step) => <span className="tabular-nums small">{formatRequestsSent(step)}</span> }
  ];

  if (!scanId) {
    return (
      <div className="content">
        <DetailBackLink route="scan-detail" />
        <PageHeader route="scan-detail" title="Validation scan" description="Open a scan from a target to follow its steps." />
        <EmptyState icon={ScanSearch} title="No scan selected" body="Open a scan from a target to follow its steps." actionHref="#targets" actionLabel="Back to targets" />
      </div>
    );
  }

  if (polling.status === 'missing') {
    return (
      <div className="content">
        <DetailBackLink route="scan-detail" />
        <PageHeader route="scan-detail" title="Validation scan" description={scanId} />
        <EmptyState icon={ScanSearch} title="Scan not found" body="This validation scan does not exist in the current tenant or has been removed. Open a scan from a target to follow its steps." actionHref="#targets" actionLabel="Back to targets" />
      </div>
    );
  }

  return (
    <div className="content scan-detail-view" aria-busy={polling.status === 'loading' || undefined}>
      <DetailBackLink route="scan-detail" link={targetLink} />
      <PageHeader
        route="scan-detail"
        title={scan ? scanDisplayName(scan) : scanId}
        description={scan ? scopeLabel(scan) : 'Loading scan'}
        actions={(
          <>
            {targetLink ? <AnchorButton size="sm" variant="secondary" href={targetLink.href}>Open target</AnchorButton> : null}
            <Button size="sm" variant="ghost" onClick={polling.refresh}>Refresh</Button>
            {canManage && scan && isScanCancellable(scan) ? (
              <Button size="sm" variant="danger" aria-label={`Stop scan ${scanDisplayName(scan)}`} onClick={() => setCancelOpen(true)}>Stop scan</Button>
            ) : null}
          </>
        )}
      />
      {scan ? (
        <PageContextSummary>
          <Badge tone={scanStatusTone(status)}>{scanStatusLabel(status)}</Badge> ·{' '}
          <code>{scanId}</code> · <span title={getString(scan, ['created_by']) || undefined}>{scanCreatorLabel(scan)}</span> · {formatDate(scan.created_at)}
        </PageContextSummary>
      ) : null}
      <div className={terminal ? 'scan-live-region sr-only' : 'scan-live-region'} role="status" aria-live="polite">{liveText}</div>
      {polling.status === 'loading' ? <PortalLoadingSkeleton rows={3} label="Loading validation scan" /> : null}
      {polling.error ? (
        <div className="form-banner error" role="alert">
          {polling.error}{scan ? ' Showing the last successful refresh.' : ''}
        </div>
      ) : null}
      {message ? <div className="form-banner" role="status">{message}</div> : null}
      {!canManage && scan ? (
        <div className="form-banner neutral" role="note">Read-only view. Owners, admins, and engineers can stop or reschedule scans.</div>
      ) : null}
      {scan && scheduled ? (
        <div className="form-banner info" role="note">
          Scheduled for {formatDate(scan.scheduled_for)} · {recurrenceLabel(scan.recurrence)}
          {scan.next_occurrence_at ? ` · next occurrence ${formatDate(scan.next_occurrence_at)}` : ''}
        </div>
      ) : null}
      {scan && active && scan.next_eligible_at ? (
        <div className="form-banner info" role="note">Next step waits for the subscribed run allowance until {formatDate(scan.next_eligible_at)}.</div>
      ) : null}
      {scan && terminal ? (
        <div className={`form-banner ${status === 'completed' ? '' : 'neutral'}`} role="note">
          {scanStatusLabel(status)} {formatDate(scan.completed_at)}
          {scan.abort_reason ? ` · aborted: ${humanizeReason(scan.abort_reason)}` : ''}
          {scan.cancel_reason ? ` · reason: ${getString(scan, ['cancel_reason'])}` : ''}
          {scan.cancelled_by ? ` · cancelled by ${getString(scan, ['cancelled_by'])}` : ''}
          {scan.next_occurrence_at && scan.recurrence ? ` · next occurrence ${formatDate(scan.next_occurrence_at)}` : ''}
        </div>
      ) : null}

      {scan ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Progress</CardTitle>
              <CardDescription>Steps run one at a time. Each step is a bounded child run with its own evidence.</CardDescription>
            </div>
            <Badge tone="muted">{recurrenceLabel(scan.recurrence)}</Badge>
          </CardHeader>
          <CardContent className="stack-tight">
            <Progress value={scanProgressPercent(summary)} label="Scan progress" tone={status === 'completed' ? 'success' : status === 'denied' || status === 'cancelled' ? 'danger' : 'warn'} />
            <p className="scan-summary-line">
              <span className="nowrap"><span className="tabular-nums">{numberOf(summary, 'completed')}</span> of <span className="tabular-nums">{numberOf(summary, 'total')}</span> steps complete</span>
              {SCAN_SUMMARY_COUNTS.map((key) => (
                <span key={key}>{' · '}<span className="nowrap"><span className="tabular-nums">{numberOf(summary, key)}</span> {key}</span></span>
              ))}
            </p>
            {polling.lastRefreshedAt ? <p className="muted small">Last refreshed {formatDate(polling.lastRefreshedAt)}</p> : null}
          </CardContent>
        </Card>
      ) : null}

      {scan ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Steps</CardTitle>
              <CardDescription>Bounded probe request metadata, response metadata, requests sent, and verdict for each check and target pair. Payloads are never shown.</CardDescription>
            </div>
            <Badge tone="muted">{steps.length} {steps.length === 1 ? 'step' : 'steps'}</Badge>
          </CardHeader>
          <CardContent className="stack-tight">
            <DataTable
              className="scan-steps"
              columns={stepColumns}
              items={steps}
              getRowId={(step) => getString(step, ['step_id'])}
              empty={<p className="muted">This scan has no planned steps.</p>}
            />
            {excluded.length > 0 ? (
              <details className="scan-excluded">
                <summary>{excluded.length} check and target {excluded.length === 1 ? 'pair was' : 'pairs were'} recorded and not run</summary>
                <ul role="note" aria-label="Excluded check and target pairs">
                  {excluded.map((row, index) => {
                    const requirement = targetRequirementForReason(getString(row, ['reason']));
                    const targetId = getString(row, ['target_id']);
                    return (
                      <li key={`${getString(row, ['check_id'])}-${targetId}-${index}`}>
                        <code className="check-picker-row-id">{getString(row, ['check_id'])}</code> on {targetId}: {scanReasonText(getString(row, ['reason']))}
                        {requirement ? null : getString(row, ['target_kind']) ? ` (target kind ${getString(row, ['target_kind'])}` : ''}
                        {requirement ? null : Array.isArray(row.supported_targets) && row.supported_targets.length ? `, supports ${row.supported_targets.map(String).join(', ')})` : getString(row, ['target_kind']) ? ')' : ''}
                        {requirement && targetId ? <> · <a className="detail-entity-link" href={controlsHref(targetId, requirement.section)}>{requirement.cta}</a></> : null}
                      </li>
                    );
                  })}
                </ul>
              </details>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      {scan ? <ActivityLogPanel items={polling.activity} loading={polling.status === 'loading'} /> : null}

      <CancelScanDialog
        scan={cancelOpen ? scan : null}
        config={config}
        session={session}
        onClose={() => setCancelOpen(false)}
        onCancelled={(result) => {
          setCancelOpen(false);
          setMessage(`Scan ${scanDisplayName(result)} is ${scanStatusLabel(getString(result, ['status'])).toLowerCase()}.`);
          polling.refresh();
          void onRefresh(['validationScans', 'runs']);
        }}
      />
    </div>
  );
}
