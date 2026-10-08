import { useEffect, useState } from 'react';
import { requestJson } from '../../lib/api';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { apiErrorMessage } from '../../lib/error-messages';
import { buildDetailHref } from '../../lib/route-params';

const REASONS: Record<string, string> = {
  ownership_not_verified: 'Waiting for domain ownership verification.',
  target_ownership_not_verified: 'Waiting for domain ownership verification.',
  target_validation_active: 'Waiting for this target’s active validation.',
  concurrent_run_blocked: 'Waiting for this target’s active check.',
  waf_feature_disabled: 'Waiting for WAF/CDN detection to be enabled.',
  safe_min_interval_active: 'Waiting for this target’s cooldown.',
  safe_window_closed: 'Waiting for its allowed testing window.',
  safe_rate_cap_exceeded: 'Waiting for the safe-run allowance to reset.',
  entitlement_limit_exceeded: 'Waiting for the safe-run allowance to reset.',
  kill_switch_active: 'Paused by the tenant stop control.',
};

export function InitialEdgeStatus({ targetId, config, session, onDispatched }: {
  targetId: string; config: PortalConfig; session: Session; onDispatched: () => Promise<unknown>;
}) {
  const [request, setRequest] = useState<DataItem | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController(); let timer: number | undefined;
    let reportedRunId = '';
    setRequest(null); setError('');
    async function read() {
      try {
        const result = await requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}/initial-detection`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setRequest(result.initial_detection ?? null); setError('');
        const runId = result.initial_detection?.test_run_id;
        if (runId && runId !== reportedRunId) { reportedRunId = runId; await onDispatched(); }
        if (['queued', 'leased'].includes(result.initial_detection?.status)) timer = window.setTimeout(() => void read(), 5000);
      } catch (failure) {
        if (!controller.signal.aborted) setError(apiErrorMessage(failure, 'Automatic provider detection status is unavailable.'));
      }
    }
    void read(); return () => { controller.abort(); window.clearTimeout(timer); };
  }, [config, session, targetId, onDispatched]);
  if (error) return <p className="td-muted" role="status">{error}</p>;
  if (!request || request.status === 'cancelled') return null;
  if (request.status === 'dispatched') return <p className="td-muted">Initial WAF/CDN detection was queued automatically. <a href={`${buildDetailHref('target-detail', targetId)}&tab=validate&check=waf.fingerprint.safe`}>Review its observation</a>.</p>;
  return <p role="status" className="td-muted">WAF/CDN detection queued automatically. {REASONS[String(request.blocked_reason)] ?? 'The scheduler will start it when this target’s execution requirements are met.'}</p>;
}
