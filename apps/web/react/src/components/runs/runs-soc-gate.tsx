import { useEffect, useState, type ReactNode } from 'react';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { DataTable, type TableColumn } from '../ui/table';
import {
  GOVERNED_HIGH_SCALE_SCENARIOS,
  authorizationArtifactTypesForRequest,
  governedLimitDisplay,
  providerApprovalRequired,
  requestDomainDisplay
} from '../../lib/high-scale';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { sessionHasPermission } from '../../lib/dataset-access.mjs';
// @ts-ignore Plain ESM keeps status labels directly testable with node:test.
import { plainCodeLabel } from '../../lib/plain-language.mjs';
import { buildDetailHref } from '../../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate, formatNumber } from '../../lib/utils';
import { highScaleStateTone } from '../../lib/status-tone';

// Customer-safe boundary invariants:
// buildDetailHref('queue-detail'
// /v1/high-scale-requests

const PACK_ACTION_STATES = new Set(['submitted', 'under_review', 'soc_review']);

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '—') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

function requestScenarioDisplay(item: DataItem) {
  if (getString(item, ['policy_id'], '')) return 'Scheduled policy';
  const familyId = Array.isArray(item.requested_scenario_families)
    ? String(item.requested_scenario_families[0] ?? '')
    : '';
  return GOVERNED_HIGH_SCALE_SCENARIOS.find((entry) => entry.id === familyId)?.label ?? '—';
}

function errorStatus(error: unknown) {
  const status = (error as { status?: unknown } | null)?.status;
  return typeof status === 'number' ? status : 0;
}

function packBadgeTone(overall: string): 'success' | 'warn' | 'danger' | 'muted' {
  const normalized = overall.trim().toLowerCase();
  if (normalized === 'accepted') return 'success';
  if (normalized === 'missing' || !normalized || normalized === '—') return 'danger';
  return 'warn';
}

function authorizationPackProgress(item: DataItem) {
  const raw = item.authorization_pack_status;
  const status = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw as DataItem : {};
  const overall = getString(status, ['overall'], 'missing');
  const requirements = Array.isArray(status.requirements) ? status.requirements as DataItem[] : [];
  const accepted = requirements.filter((requirement) => getString(requirement, ['status'], '').toLowerCase() === 'accepted').length;
  const total = requirements.length || authorizationArtifactTypesForRequest(item).length;
  return {
    overall,
    accepted,
    total,
    label: requirements.length > 0 && overall.toLowerCase() !== 'accepted'
      ? `${formatNumber(accepted)}/${formatNumber(requirements.length)} accepted`
      : overall.replace(/_/g, ' '),
    detail: requirements.length > 0
      ? `${formatNumber(accepted)} of ${formatNumber(requirements.length)} required authorization artifacts accepted`
      : `Authorization pack status: ${overall}`
  };
}

function providerApprovalDisplay(item: DataItem): { label: string; detail: string; tone: 'success' | 'warn' | 'danger' | 'muted' } {
  if (!providerApprovalRequired(item)) {
    return { label: 'not required', detail: 'No provider approval requirement declared', tone: 'muted' };
  }
  const checklist = Array.isArray(item.provider_approval_checklist)
    ? (item.provider_approval_checklist as DataItem[]).filter((entry) => entry.required !== false)
    : [];
  if (checklist.length === 0) {
    return { label: 'missing', detail: 'Provider approval evidence has not been attached', tone: 'danger' };
  }
  const statuses = checklist.map((entry) => getString(entry, ['status'], 'missing').toLowerCase());
  const providers = checklist
    .map((entry) => getString(entry, ['provider_name'], ''))
    .filter((name) => name && name !== '—')
    .join(', ');
  if (statuses.every((status) => status === 'accepted')) {
    return { label: 'accepted', detail: providers || 'All required provider approvals accepted', tone: 'success' };
  }
  const blocking = statuses.find((status) => ['rejected', 'expired'].includes(status));
  if (blocking) return { label: blocking.replace(/_/g, ' '), detail: providers || 'Provider approval requires attention', tone: 'danger' };
  const pending = statuses.find((status) => status !== 'accepted') ?? 'pending';
  return { label: pending.replace(/_/g, ' '), detail: providers || 'Provider approval is not yet accepted', tone: 'warn' };
}


export type RunsSocGateProps = {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void> | void;
  onMessage: (message: string) => void;
  onError: (error: string) => void;
  busy: string;
  setBusy: (value: string) => void;
};

export function RunsSocGatePanel({
  data,
  config,
  session
}: RunsSocGateProps): ReactNode {
  const [queue, setQueue] = useState<DataItem[] | null>(null);
  const [loadError, setLoadError] = useState('');
  const [forbidden, setForbidden] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const isStaffPrincipal = session.principal === 'staff';
  const canWritePack = sessionHasPermission(session, 'high_scale:write');

  useEffect(() => {
    let cancelled = false;
    requestJson(config, session, '/v1/high-scale-requests?scope=my-tenant')
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: DataItem[] }).items
          : Array.isArray(payload) ? payload as DataItem[] : [];
        setQueue(items);
        setLoadError('');
        setForbidden(false);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        if (errorStatus(error) === 403) {
          setForbidden(true);
          setLoadError('');
          return;
        }
        setLoadError(apiErrorMessage(error, 'Validation requests could not be loaded.'));
      });
    return () => { cancelled = true; };
  }, [config, session, data.highScale?.length, reloadKey]);

  const items = queue ?? [];
  if (forbidden) return null;
  if (!loadError && items.length === 0) return null;

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'request',
      label: 'Request',
      render: (item) => {
        const requestId = getString(item, ['id'], '');
        const requestLabel = getString(item, ['objective', 'reason', 'name'], 'High-scale validation request');
        if (!requestId) return <span>{requestLabel}</span>;
        return (
          <a
            className="detail-entity-link"
            href={buildDetailHref('queue-detail', requestId)}
            title={requestId}
            aria-label={isStaffPrincipal
              ? `Open SOC workspace for request ${requestId}`
              : `Open authorization pack for request ${requestLabel}`}
          >
            {requestLabel}
          </a>
        );
      }
    },
    {
      key: 'scenario',
      label: 'Scenario',
      render: (item) => {
        const policy = getString(item, ['policy_id'], '');
        return <span title={policy || undefined}>{requestScenarioDisplay(item)}</span>;
      }
    },
    { key: 'domains', label: 'Domains', render: (item) => requestDomainDisplay(data, item).join(', ') },
    { key: 'limits', label: 'Governed limits', render: (item) => governedLimitDisplay(item) },
    {
      key: 'pack',
      label: 'Authorization pack',
      render: (item) => {
        const pack = authorizationPackProgress(item);
        return <Badge tone={packBadgeTone(pack.overall)} title={pack.detail}>{pack.label}</Badge>;
      }
    },
    {
      key: 'provider',
      label: 'Provider approval',
      render: (item) => {
        const provider = providerApprovalDisplay(item);
        return <Badge tone={provider.tone} title={provider.detail}>{provider.label}</Badge>;
      }
    },
    {
      key: 'state',
      label: 'State',
      render: (item) => {
        const state = getString(item, ['state']);
        return <Badge tone={highScaleStateTone(state)} title={`Recorded request state: ${plainCodeLabel(state)}`}>{plainCodeLabel(state)}</Badge>;
      }
    },
    {
      key: 'window',
      label: 'Window',
      render: (item) => {
        const start = getNestedString(item, ['requested_window', 'window_start'], '');
        const scheduled = getNestedString(item, ['scheduled_window', 'window_start'], '');
        const value = scheduled && scheduled !== '—' ? scheduled : start;
        return value && value !== '—' ? formatDate(value) : 'unscheduled';
      }
    },
    {
      key: 'action',
      label: 'Action',
      render: (item) => {
        const requestId = getString(item, ['id'], '');
        const state = getString(item, ['state'], '').toLowerCase();
        const pack = authorizationPackProgress(item);
        if (isStaffPrincipal || !requestId || pack.overall.toLowerCase() === 'accepted' || !PACK_ACTION_STATES.has(state)) {
          return <span className="muted">—</span>;
        }
        const progress = `${formatNumber(pack.accepted)}/${formatNumber(pack.total)}`;
        return (
          <span className="stack-tight runs-soc-gate-action">
            <AnchorButton
              size="sm"
              variant="secondary"
              href={buildDetailHref('queue-detail', requestId)}
              aria-label={canWritePack
                ? `Complete authorization pack (${progress} accepted) for request ${requestId}`
                : `View authorization pack for request ${requestId}`}
            >
              {canWritePack ? `Complete pack (${progress})` : 'View pack'}
            </AnchorButton>
            <small className="muted">
              {`SOC cannot approve until all ${formatNumber(pack.total)} authorization artifacts are accepted (${formatNumber(pack.accepted)} accepted).`}
            </small>
          </span>
        );
      }
    }
  ];

  return (
    <Card className="runs-soc-gate" density="compact">
      <CardHeader>
        <div>
          <CardTitle>Validation requests</CardTitle>
          <CardDescription>High-scale validation requests for your tenant. Only SOC can approve, schedule, and run them, after the authorization pack is accepted.</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        <DataTable
          columns={columns}
          items={items}
          getRowId={(item, index) => getString(item, ['id'], String(index))}
          loadError={loadError}
          onRetry={() => setReloadKey((value) => value + 1)}
          empty={<p className="muted">No requests recorded.</p>}
        />
      </CardContent>
    </Card>
  );
}

export function RunsPageHeadActions({
  onRefresh: _onRefresh,
  onStartSafeRun,
  onStartScan,
  refreshBusy: _refreshBusy,
  safeRunBusy,
  safeRunDisabled
}: {
  onRefresh: () => void;
  onStartSafeRun: () => void;
  onStartScan?: () => void;
  refreshBusy?: boolean;
  safeRunBusy?: boolean;
  safeRunDisabled?: boolean;
}) {
  const safeRunDisabledReason = safeRunDisabled
    ? 'Check library launch is unavailable until a declared domain and customer-runnable bounded check are ready.'
    : '';
  return (
    <>
      {onStartScan ? <Button size="sm" variant="default" onClick={onStartScan}>Start validation scan</Button> : null}
      <Button
        size="sm"
        variant="secondary"
        loading={safeRunBusy}
        disabled={safeRunDisabled}
        title={safeRunDisabledReason || undefined}
        aria-describedby={safeRunDisabledReason ? 'safe-run-disabled-reason' : undefined}
        onClick={onStartSafeRun}
      >Open check library</Button>
      {safeRunDisabledReason ? <span className="sr-only" id="safe-run-disabled-reason">{safeRunDisabledReason}</span> : null}
    </>
  );
}
