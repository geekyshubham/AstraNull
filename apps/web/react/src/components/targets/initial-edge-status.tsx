import { useEffect, useState } from 'react';
import { requestJson } from '../../lib/api';
import type { DataItem, PortalConfig, Session } from '../../lib/types';

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
  useEffect(() => {
    const controller = new AbortController(); let timer: number | undefined;
    let reportedRunId = '';
    let failures = 0;
    setRequest(null);
    async function read() {
      try {
        const result = await requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}/initial-detection`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        failures = 0;
        setRequest(result.initial_detection ?? null);
        const runId = result.initial_detection?.test_run_id;
        if (runId && runId !== reportedRunId) { reportedRunId = runId; await onDispatched(); }
        if (['queued', 'leased'].includes(result.initial_detection?.status)) timer = window.setTimeout(() => void read(), 5000);
      } catch {
        if (controller.signal.aborted || failures >= 5) return;
        failures += 1;
        timer = window.setTimeout(() => void read(), 5000 * 2 ** failures);
      }
    }
    void read(); return () => { controller.abort(); window.clearTimeout(timer); };
  }, [config, session, targetId, onDispatched]);
  if (!request || request.status === 'cancelled' || request.status === 'dispatched') return null;
  const reason = REASONS[String(request.blocked_reason)];
  return reason ? <p role="status" className="td-muted td-edge-waiting">{`WAF and CDN detection: ${reason.charAt(0).toLowerCase()}${reason.slice(1)}`}</p> : null;
}
