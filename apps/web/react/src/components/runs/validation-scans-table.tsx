import { useId, useState } from 'react';
import { ScanSearch } from 'lucide-react';
import { requestJson } from '../../lib/api';
import { ConfirmModal } from '../../lib/crud-ui';
import { emptyStateFromApi } from '../../lib/empty-from-api';
import { apiErrorMessage } from '../../lib/error-messages';
import { buildDetailHref } from '../../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import {
  isScanActive,
  isScanCancellable,
  isScanEditable,
  isScanTerminal,
  recurrenceLabel,
  scanDisplayName,
  scanErrorMessage,
  scanStatusLabel,
  scanStatusTone,
  scopeLabel,
} from '../../lib/validation-scan.mjs';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { DataTable, type TableColumn } from '../ui/table';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function summaryOf(scan: DataItem) {
  return scan.summary && typeof scan.summary === 'object' && !Array.isArray(scan.summary) ? scan.summary as DataItem : null;
}

export type CancelScanDialogProps = {
  scan: DataItem | null;
  config: PortalConfig;
  session: Session;
  onClose: () => void;
  onCancelled: (scan: DataItem) => void;
};

export function CancelScanDialog({ scan, config, session, onClose, onCancelled }: CancelScanDialogProps) {
  const [reason, setReason] = useState('');
  const [cancelSeries, setCancelSeries] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const reasonId = useId();
  const scanId = getString(scan, ['id']);
  const recurring = Boolean(scan?.recurrence);
  const scheduled = getString(scan, ['status']) === 'scheduled';

  async function confirm() {
    if (!scan) return;
    setBusy(true);
    setError('');
    try {
      const result = await requestJson(config, session, `/v1/validation-scans/${encodeURIComponent(scanId)}/cancel`, {
        method: 'POST',
        body: { reason: reason.trim() || undefined, cancel_series: recurring && cancelSeries ? true : undefined }
      }) as DataItem;
      setReason('');
      setCancelSeries(false);
      onCancelled(result);
    } catch (err) {
      setError(scanErrorMessage((err as { payload?: unknown }).payload, apiErrorMessage(err, 'The scan could not be stopped.')));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ConfirmModal
      open={Boolean(scan)}
      title={scheduled ? 'Cancel this scheduled scan?' : 'Stop this validation scan?'}
      description={(
        <div className="stack-tight">
          <p>
            {scheduled
              ? `${scanDisplayName(scan)} will not dispatch. `
              : `${scanDisplayName(scan)} stops after the current child run is cancelled; pending steps are skipped and no further probes are sent. `}
            Completed steps keep their evidence.
          </p>
          <label className="scan-cancel-reason">
            <span>Reason (optional)</span>
            <input id={reasonId} value={reason} disabled={busy} onChange={(event) => setReason(event.target.value)} autoComplete="off" />
          </label>
          {recurring ? (
            <label className="check-row">
              <input type="checkbox" checked={cancelSeries} disabled={busy} onChange={(event) => setCancelSeries(event.target.checked)} />
              <span>Also cancel future occurrences of this recurring scan</span>
            </label>
          ) : null}
          {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        </div>
      )}
      confirmLabel={scheduled ? 'Cancel scan' : 'Stop scan'}
      busy={busy}
      onCancel={() => {
        setError('');
        onClose();
      }}
      onConfirm={() => void confirm()}
    />
  );
}

export type ValidationScansTableProps = {
  scans: DataItem[];
  meta: DataItem | null;
  loadError?: string;
  onRetry?: () => void;
  canManage: boolean;
  config: PortalConfig;
  session: Session;
  onEdit: (scan: DataItem) => void;
  onReschedule: (scan: DataItem) => void;
  onCancelled: (scan: DataItem) => void;
  showScope?: boolean;
  emptyFallback?: string;
};

export function ValidationScansTable({
  scans,
  meta,
  loadError = '',
  onRetry,
  canManage,
  config,
  session,
  onEdit,
  onReschedule,
  onCancelled,
  showScope = true,
  emptyFallback = 'No validation scans to show.'
}: ValidationScansTableProps) {
  const [cancelling, setCancelling] = useState<DataItem | null>(null);

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'scan',
      label: 'Scan',
      render: (scan) => (
        <span className="scan-cell-stack">
          <a href={buildDetailHref('scan-detail', getString(scan, ['id']))} className="scan-link">{scanDisplayName(scan)}</a>
          <code className="check-picker-row-id">{getString(scan, ['id'])}</code>
        </span>
      )
    },
    ...(showScope ? [{
      key: 'scope',
      label: 'Scope',
      render: (scan: DataItem) => <span className="small">{scopeLabel(scan)}</span>
    }] : []),
    {
      key: 'checks',
      label: 'Checks',
      render: (scan) => <span className="tabular-nums">{Array.isArray(scan.check_ids) ? scan.check_ids.length : 0}</span>
    },
    {
      key: 'scheduled',
      label: 'Scheduled for',
      render: (scan) => <span className="muted">{scan.scheduled_for ? formatDate(scan.scheduled_for) : 'Immediate'}</span>
    },
    {
      key: 'recurrence',
      label: 'Recurrence',
      render: (scan) => <span className="muted">{recurrenceLabel(scan.recurrence)}</span>
    },
    {
      key: 'next',
      label: 'Next occurrence',
      render: (scan) => <span className="muted">{scan.next_occurrence_at ? formatDate(scan.next_occurrence_at) : '—'}</span>
    },
    {
      key: 'status',
      label: 'Status',
      render: (scan) => {
        const status = getString(scan, ['status']);
        const summary = summaryOf(scan);
        const active = isScanActive(scan);
        return (
          <span className="scan-cell-stack">
            <span className="scan-status-line">
              {active ? <span className="scan-live-dot" aria-hidden="true" /> : null}
              <Badge tone={scanStatusTone(status)}>{scanStatusLabel(status)}</Badge>
            </span>
            {active && summary ? (
              <small className="muted">{String(summary.completed ?? 0)} of {String(summary.total ?? 0)} steps complete</small>
            ) : null}
            {!active && scan.abort_reason ? <small className="muted">{scanStatusLabel(scan.abort_reason)}</small> : null}
          </span>
        );
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (scan) => {
        const id = getString(scan, ['id']);
        const name = scanDisplayName(scan);
        return (
          <div className="row-end-actions">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('scan-detail', id)} aria-label={`Open scan ${name}`}>Open</AnchorButton>
            {canManage && isScanEditable(scan) ? (
              <Button size="sm" variant="ghost" aria-label={`Edit scan ${name}`} onClick={() => onEdit(scan)}>Edit</Button>
            ) : null}
            {canManage && isScanCancellable(scan) ? (
              <Button size="sm" variant="danger" aria-label={`Cancel scan ${name}`} onClick={() => setCancelling(scan)}>Cancel</Button>
            ) : null}
            {canManage && isScanTerminal(scan) && !scan.recurrence ? (
              <Button size="sm" variant="ghost" aria-label={`Schedule scan ${name} again`} onClick={() => onReschedule(scan)}>Schedule again</Button>
            ) : null}
          </div>
        );
      }
    }
  ];

  return (
    <>
      <DataTable
        className="validation-scans-table"
        columns={columns}
        items={scans}
        getRowId={(scan) => getString(scan, ['id'])}
        loadError={loadError}
        onRetry={onRetry}
        empty={emptyStateFromApi({ icon: ScanSearch, meta }) ?? <p className="muted">{emptyFallback}</p>}
      />
      {!canManage ? (
        <p className="muted small scan-readonly-note" role="note">
          Your role can review validation scans. Owners, admins, and engineers can start, edit, and stop them.
        </p>
      ) : null}
      <CancelScanDialog
        scan={cancelling}
        config={config}
        session={session}
        onClose={() => setCancelling(null)}
        onCancelled={(scan) => {
          setCancelling(null);
          onCancelled(scan);
        }}
      />
    </>
  );
}
