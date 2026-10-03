import { useEffect, useState, type ReactNode } from 'react';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { DataTable, type TableColumn } from '../ui/table';
import {
  GOVERNED_HIGH_SCALE_SCENARIOS,
  providerApprovalRequired
} from '../../lib/high-scale';
import { requestJson } from '../../lib/api';
// @ts-ignore Plain ESM keeps status labels directly testable with node:test.
import { plainCodeLabel } from '../../lib/plain-language.mjs';
import { buildDetailHref } from '../../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate, formatNumber } from '../../lib/utils';

// Customer-safe boundary invariants:
// buildDetailHref('queue-detail'
// /v1/high-scale-requests

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

function governedLimitDisplay(item: DataItem) {
  const familyId = Array.isArray(item.requested_scenario_families)
    ? String(item.requested_scenario_families[0] ?? '')
    : '';
  const scenario = GOVERNED_HIGH_SCALE_SCENARIOS.find((entry) => entry.id === familyId);
  const limits = item.requested_limits && typeof item.requested_limits === 'object' && !Array.isArray(item.requested_limits)
    ? item.requested_limits as DataItem
    : {};
  const rate = scenario && typeof limits[scenario.limit.field] === 'number'
    ? `${limits[scenario.limit.field]} ${scenario.limit.unit}`
    : '';
  const duration = typeof limits.max_duration_minutes === 'number'
    ? `${limits.max_duration_minutes} minutes`
    : '';
  return [rate, duration].filter(Boolean).join(' · ') || '—';
}

function targetGroupDisplayName(data: PortalData, groupId: string) {
  const group = data.targetGroups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId || '—');
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
  return {
    overall,
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

function stateBadgeTone(state: string): 'success' | 'warn' | 'danger' | 'info' | 'muted' {
  const normalized = state.trim().toLowerCase();
  if (['approved', 'scheduled'].includes(normalized)) return 'info';
  if (['running', 'executing', 'active', 'started'].includes(normalized)) return 'danger';
  if (['submitted', 'soc_review', 'under_review'].includes(normalized)) return 'warn';
  if (['closed', 'completed', 'cancelled', 'canceled'].includes(normalized)) return 'success';
  return 'muted';
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
  requestFormOpen?: boolean;
  onRequestFormOpenChange?: (open: boolean) => void;
};

export function RunsSocGatePanel({
  data,
  config,
  session
}: RunsSocGateProps): ReactNode {
  const [queue, setQueue] = useState<DataItem[] | null>(null);
  const isStaffPrincipal = session.principal === 'staff';

  useEffect(() => {
    let cancelled = false;
    requestJson(config, session, '/v1/high-scale-requests?scope=my-tenant')
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: DataItem[] }).items
          : Array.isArray(payload) ? payload as DataItem[] : [];
        setQueue(items);
      })
      .catch(() => {
        if (!cancelled) setQueue(null);
      });
    return () => { cancelled = true; };
  }, [config, session, data.highScale?.length]);

  if (!queue || queue.length === 0) {
    return null;
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'request',
      label: 'Request',
      render: (item) => {
        const requestId = getString(item, ['id'], '');
        const requestLabel = getString(item, ['objective', 'reason', 'name'], 'High-scale validation request');
        if (!isStaffPrincipal) {
          return <span title={requestId || undefined}>{requestLabel}</span>;
        }
        return (
          <AnchorButton
            variant="ghost"
            href={buildDetailHref('queue-detail', requestId)}
            aria-label={`Open SOC workspace for request ${requestId}`}
          >
            {requestLabel}
          </AnchorButton>
        );
      }
    },
    { key: 'policy', label: 'Policy', render: (item) => { const policy = getString(item, ['policy_id'], ''); const scenario = getString(item, ['requested_scenario_families'], 'soc_gated'); return <span title={policy || undefined}>{policy ? 'Scheduled policy' : plainCodeLabel(scenario)}</span>; } },
    { key: 'group', label: 'Target group', render: (item) => targetGroupDisplayName(data, getString(item, ['target_group_id'])) },
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
        return <Badge tone={stateBadgeTone(state)} title={`Recorded request state: ${plainCodeLabel(state)}`}>{plainCodeLabel(state)}</Badge>;
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
    }
  ];

  return (
    <Card className="runs-soc-gate" density="compact">
      <CardHeader>
        <div>
          <CardTitle>Validation requests</CardTitle>
          <CardDescription>Submitted high-scale evaluation requests.</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        <DataTable columns={columns} items={queue} empty={<p className="muted">No requests recorded.</p>} />
      </CardContent>
    </Card>
  );
}

export function RunsPageHeadActions({
  onRefresh: _onRefresh,
  onRequestSoc: _onRequestSoc,
  onStartSafeRun,
  onStartScan,
  refreshBusy: _refreshBusy,
  safeRunBusy,
  safeRunDisabled
}: {
  onRefresh: () => void;
  onRequestSoc?: () => void;
  onStartSafeRun: () => void;
  onStartScan?: () => void;
  refreshBusy?: boolean;
  safeRunBusy?: boolean;
  safeRunDisabled?: boolean;
}) {
  const safeRunDisabledReason = safeRunDisabled
    ? 'Vector library launch is unavailable until a declared target group and customer-runnable bounded check are ready.'
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
      >Open vector library</Button>
      {safeRunDisabledReason ? <span className="sr-only" id="safe-run-disabled-reason">{safeRunDisabledReason}</span> : null}
    </>
  );
}
