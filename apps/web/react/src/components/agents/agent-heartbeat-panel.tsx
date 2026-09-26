import { useMemo, useState, type ReactNode } from 'react';
import { Activity, RefreshCw } from 'lucide-react';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { VerifyChip } from '../../lib/verify-chip';
import {
  buildHeartbeatTraceFromAudit,
  computeCadenceP50,
  formatRelativeAge,
  type HeartbeatTraceSegment
} from '../../lib/agent-heartbeat';
import { agentHeartbeatFreshness } from '../../lib/agent-helpers';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function validTimestamp(value: string) {
  return Number.isFinite(Date.parse(value)) ? value : '';
}

function resolveRecordedNonceStatus(agent: DataItem) {
  const installStatus = getString(agent, ['install_nonce_status'], '').trim().toLowerCase();
  const validationStatus = getString(agent, ['last_token_validation_status'], '').trim().toLowerCase();
  const validationAt = validTimestamp(getString(agent, ['last_token_validation_at'], ''));
  const bootstrapId = getString(agent, ['bootstrap_token_id'], '');

  if (installStatus) {
    return {
      label: installStatus.replace(/_/g, ' '),
      provenance: `Agent record install_nonce_status=${installStatus}${validationAt ? ` at ${formatDate(validationAt)}` : ''}.`
    };
  }
  if (validationStatus) {
    const matched = validationStatus === 'valid' && Boolean(bootstrapId);
    return {
      label: matched ? 'match' : validationStatus.replace(/_/g, ' '),
      provenance: `Agent record last_token_validation_status=${validationStatus}${bootstrapId ? ` for bootstrap token ID ${bootstrapId}` : ''}${validationAt ? ` at ${formatDate(validationAt)}` : ''}.`
    };
  }
  return {
    label: 'not recorded',
    provenance: bootstrapId
      ? `Bootstrap token ID ${bootstrapId} is present, but the agent record has no nonce validation state.`
      : 'The agent record has no bootstrap token ID or nonce validation state.'
  };
}

function heartbeatDotClass(tone: HeartbeatTraceSegment['tone']) {
  if (tone === 'slow') return 'hb-dot is-slow';
  if (tone === 'now') return 'hb-dot is-now';
  if (tone === 'ok') return 'hb-dot is-ok';
  return 'hb-dot';
}

function HbMetricCell({
  label,
  value,
  note,
  valueTitle
}: {
  label: string;
  value: ReactNode;
  note?: string;
  valueTitle?: string;
}) {
  return (
    <div className="hb-cell">
      <div className="hb-label">{label}</div>
      <div className="hb-value mono" title={valueTitle}>
        {value}
      </div>
      {note ? <div className="hb-note muted">{note}</div> : null}
    </div>
  );
}

function HeartbeatTraceDot({ segment }: { segment: HeartbeatTraceSegment }) {
  const label = `${formatDate(segment.at)}; ${segment.title}`;
  return <span className={heartbeatDotClass(segment.tone)} title={label} role="img" aria-label={label} />;
}

export function AgentHeartbeatPanel({
  agent,
  agentId,
  audit,
  auditRestricted = false,
  onRefresh,
  refreshing
}: {
  agent: DataItem;
  agentId: string;
  audit: DataItem[];
  auditRestricted?: boolean;
  onRefresh: () => void | Promise<void>;
  refreshing?: boolean;
}) {
  const [nowMs, setNowMs] = useState(Date.now());
  const [refreshPending, setRefreshPending] = useState(false);
  const [refreshError, setRefreshError] = useState('');
  const heartbeatAudit = useMemo(
    () =>
      audit
        .filter(
          (entry) =>
            getString(entry, ['action'], '') === 'agent.heartbeat' && getString(entry, ['resource_id'], '') === agentId
        )
        .map((entry) => ({
          entry,
          at: validTimestamp(getString(entry, ['created_at', 'timestamp'], ''))
        }))
        .filter((item) => Boolean(item.at))
        .sort((a, b) => Date.parse(a.at) - Date.parse(b.at)),
    [audit, agentId]
  );
  const segments = useMemo(() => buildHeartbeatTraceFromAudit(audit, agentId, { nowMs }), [audit, agentId, nowMs]);
  const cadence = computeCadenceP50(segments);
  const nonce = resolveRecordedNonceStatus(agent);
  const recordedFirstHeartbeatAt = validTimestamp(getString(agent, ['first_heartbeat_at'], ''));
  const recordedLastHeartbeatAt = validTimestamp(getString(agent, ['last_heartbeat_at'], ''));
  const firstAuditHeartbeat = heartbeatAudit[0];
  const latestAuditHeartbeat = heartbeatAudit[heartbeatAudit.length - 1];
  const firstHeartbeatAt = recordedFirstHeartbeatAt || firstAuditHeartbeat?.at || '';
  const latestHeartbeatAt = recordedLastHeartbeatAt || latestAuditHeartbeat?.at || '';
  const firstHeartbeatSource = recordedFirstHeartbeatAt
    ? 'agent record'
    : firstAuditHeartbeat
      ? `earliest loaded audit event ${getString(firstAuditHeartbeat.entry, ['id', 'audit_id'], 'ID not returned')}`
      : 'not recorded';
  const latestHeartbeatSource = recordedLastHeartbeatAt
    ? `agent record · ${agentHeartbeatFreshness(agent, nowMs)}`
    : latestAuditHeartbeat
      ? 'audit only; agent record timestamp absent'
      : 'not recorded';
  const evidenceState =
    recordedLastHeartbeatAt && latestAuditHeartbeat
      ? 'heartbeat_observed'
      : recordedLastHeartbeatAt
        ? 'record_only'
        : latestAuditHeartbeat
          ? 'audit_only'
          : 'awaiting_heartbeat';
  const provenance = [
    recordedLastHeartbeatAt
      ? `Agent record ${agentId} reports last_heartbeat_at ${formatDate(recordedLastHeartbeatAt)}.`
      : `Agent record ${agentId} has no last_heartbeat_at.`,
    latestAuditHeartbeat
      ? `Latest exact agent.heartbeat audit event ${getString(latestAuditHeartbeat.entry, ['id', 'audit_id'], 'ID not returned')} was recorded ${formatDate(latestAuditHeartbeat.at)}; ${heartbeatAudit.length} matching event${heartbeatAudit.length === 1 ? '' : 's'} loaded.`
      : 'No exact agent.heartbeat audit event is loaded for this agent.',
    'No run attribution or evidence custody is inferred here.'
  ].join(' ');
  const degradedMessage =
    recordedLastHeartbeatAt && !latestAuditHeartbeat
      ? 'The agent record reports a heartbeat, but no matching agent.heartbeat audit event is loaded. Cadence and trace verification are unavailable.'
      : !recordedLastHeartbeatAt && latestAuditHeartbeat
        ? 'Matching audit heartbeats are loaded, but the agent record has no last_heartbeat_at. Showing audit-only timing without claiming agent verification.'
        : !recordedLastHeartbeatAt && !latestAuditHeartbeat
          ? 'No agent-record or matching audit heartbeat is available yet. The panel will remain unverified until real data arrives.'
          : '';

  async function refreshEvidence() {
    setNowMs(Date.now());
    setRefreshPending(true);
    setRefreshError('');
    try {
      await onRefresh();
    } catch (err) {
      setRefreshError(err instanceof Error ? err.message : 'Heartbeat evidence refresh failed.');
    } finally {
      setRefreshPending(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Heartbeat verification</CardTitle>
          <CardDescription>
            Agent-record timing joined to exact matching heartbeat audit events. No run evidence or custody is implied.
          </CardDescription>
        </div>
        <div className="row-actions">
          <VerifyChip state={evidenceState} provenance={provenance} />
          <Button
            size="sm"
            variant="secondary"
            loading={refreshing || refreshPending}
            disabled={refreshing || refreshPending}
            onClick={() => void refreshEvidence()}
            aria-label={`Refresh heartbeat evidence for agent ${agentId}`}
          >
            {!refreshing && !refreshPending ? <RefreshCw size={15} aria-hidden="true" /> : null}
            Refresh evidence
          </Button>
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        <div className="hb-grid">
          <HbMetricCell
            label="First heartbeat"
            value={firstHeartbeatAt ? formatRelativeAge(firstHeartbeatAt, nowMs) : '—'}
            note={
              firstHeartbeatAt
                ? `${formatDate(firstHeartbeatAt)} · ${firstHeartbeatSource}`
                : 'No first heartbeat field or audit event'
            }
            valueTitle={firstHeartbeatAt ? formatDate(firstHeartbeatAt) : undefined}
          />
          <HbMetricCell
            label="Last heartbeat"
            value={latestHeartbeatAt ? formatRelativeAge(latestHeartbeatAt, nowMs) : '—'}
            note={
              latestHeartbeatAt
                ? `${formatDate(latestHeartbeatAt)} · ${latestHeartbeatSource}`
                : 'No heartbeat observed'
            }
            valueTitle={latestHeartbeatAt ? formatDate(latestHeartbeatAt) : undefined}
          />
          <HbMetricCell
            label="Cadence (p50)"
            value={cadence ? `${(cadence.p50Ms / 1000).toFixed(1)}s ± ${(cadence.spreadMs / 1000).toFixed(1)}s` : '—'}
            note={
              cadence
                ? `${segments.length} exact audit heartbeats loaded`
                : segments.length === 1
                  ? 'One audit heartbeat; two are required'
                  : 'No matching audit cadence'
            }
          />
          <HbMetricCell
            label="Install nonce"
            value={nonce.label}
            note={nonce.provenance}
            valueTitle={nonce.provenance}
          />
        </div>
        <div className="hb-trace-wrap">
          <div className="hb-trace-head">
            <span className="eyebrow">Recent heartbeat audit events</span>
            <span className="muted mono">{segments.length}/30 · newest →</span>
          </div>
          {segments.length === 0 ? (
            <p className="muted hb-trace-empty row" role="status">
              <Activity size={16} aria-hidden="true" />
              <span>
                {auditRestricted
                  ? 'Heartbeat audit events are not available for your role. The trace is not synthesized from agent status.'
                  : 'No matching heartbeat audit events are available. The trace is not synthesized from agent status.'}
              </span>
            </p>
          ) : (
            <div
              className="hb-trace"
              aria-label={`Heartbeat trace from ${segments.length} matching audit events, newest first`}
            >
              {segments.map((segment) => (
                <HeartbeatTraceDot key={segment.id} segment={segment} />
              ))}
            </div>
          )}
        </div>
        {degradedMessage ? (
          <p className="muted" role="status">
            {degradedMessage}
          </p>
        ) : null}
        {refreshError ? <div className="form-banner error" role="alert">{refreshError}</div> : null}
        <div className="kv-list" role="group" aria-label="Heartbeat evidence provenance">
          <div>
            <span>Agent source</span>
            <strong className="mono mono-hash">agent:{agentId}</strong>
          </div>
          <div>
            <span>Agent-record heartbeat</span>
            <strong className="mono mono-hash">
              {recordedLastHeartbeatAt ? formatDate(recordedLastHeartbeatAt) : 'not present'}
            </strong>
          </div>
          <div>
            <span>Audit source</span>
            <strong className="mono mono-hash">
              {latestAuditHeartbeat
                ? `agent.heartbeat · ${getString(latestAuditHeartbeat.entry, ['id', 'audit_id'], 'ID not returned')} · ${formatDate(latestAuditHeartbeat.at)} · ${heartbeatAudit.length} loaded`
                : 'No exact resource_id match'}
            </strong>
          </div>
          <div>
            <span>Nonce source</span>
            <strong className="mono mono-hash">{nonce.provenance}</strong>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
