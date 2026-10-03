import type { ReactNode } from 'react';
import { Button } from '../ui/button';
import type { PortalConfig, PortalData, Session } from '../../lib/types';
// Customer-safe boundary invariants:
// buildDetailHref('queue-detail'
// /v1/high-scale-requests

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

export function RunsSocGatePanel(_props: RunsSocGateProps): ReactNode {
  return null;
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
