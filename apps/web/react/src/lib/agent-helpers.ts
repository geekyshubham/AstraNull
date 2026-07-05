import { agentHasRecentHeartbeat } from './onboarding';
import type { DataItem } from './types';

export { formatPlacementOverview, formatPlacementStatus, placementStatusHint } from './placement-labels';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

const AGENT_STATUS_LABELS: Record<string, string> = {
  online: 'Online',
  offline: 'Offline',
  revoked: 'Revoked',
};

const HEARTBEAT_FRESHNESS_LABELS: Record<string, string> = {
  fresh: 'Responding',
  stale: 'Not responding',
  never: 'Never checked in',
  revoked: 'Revoked',
  unknown: 'Unknown',
};

const PLACEMENT_TYPE_LABELS: Record<string, string> = {
  host: 'On the server',
  sidecar: 'Beside the app',
  canary: 'Canary path',
  packet_mirror: 'Mirrored traffic',
  log_tail: 'From logs',
  unbound: 'Not assigned',
};

export function formatAgentCapabilities(agent: DataItem | null | undefined) {
  const capabilities = Array.isArray(agent?.capabilities) ? agent.capabilities as string[] : [];
  if (!capabilities.length) return '—';
  return capabilities
    .map((cap) => PLACEMENT_TYPE_LABELS[cap] ?? cap.replace(/_/g, ' '))
    .join(', ');
}

export function formatAgentPlacement(agent: DataItem | null | undefined) {
  const groupId = getString(agent, ['target_group_id'], '');
  const placement = getString(agent, ['placement_type', 'placement'], '');
  const placementLabel = PLACEMENT_TYPE_LABELS[placement] ?? (placement || 'Not set');
  if (!groupId) return `Not assigned · ${placementLabel}`;
  return `Assigned to group · ${placementLabel}`;
}

export function formatAgentHealth(agent: DataItem | null | undefined) {
  const status = getString(agent, ['status', 'state'], 'unknown');
  return AGENT_STATUS_LABELS[status] ?? status;
}

export function formatHeartbeatFreshness(freshness: string) {
  return HEARTBEAT_FRESHNESS_LABELS[freshness] ?? freshness;
}

export function agentHeartbeatFreshness(agent: DataItem | null | undefined, nowMs = Date.now()) {
  if (!agent) return 'unknown';
  if (getString(agent, ['status']) === 'revoked') return 'revoked';
  if (agentHasRecentHeartbeat(agent, nowMs)) return 'fresh';
  if (agent.last_heartbeat_at) return 'stale';
  return 'never';
}

export function placementFactorScore(state: DataItem | null | undefined) {
  const readiness = state?.readiness as DataItem | undefined;
  const factors = Array.isArray(readiness?.factors) ? readiness.factors as DataItem[] : [];
  const placement = factors.find((factor) => getString(factor, ['key']) === 'agent_placement');
  if (!placement) return null;
  const score = placement.score;
  return typeof score === 'number' && Number.isFinite(score) ? Math.round(score) : null;
}

export function filterAgentAuditEntries(audit: DataItem[], agentId?: string) {
  return audit.filter((entry) => {
    const resourceType = getString(entry, ['resource_type'], '');
    const action = getString(entry, ['action'], '');
    const resourceId = getString(entry, ['resource_id'], '');
    const isAgentLifecycle = resourceType === 'agent'
      || action.startsWith('agent.')
      || action.startsWith('agent_update.');
    if (!isAgentLifecycle) return false;
    if (agentId) {
      return resourceId === agentId
        || getNestedString(entry, ['metadata', 'agent_id']) === agentId;
    }
    return true;
  });
}

export function agentInstallApiBase() {
  return typeof window !== 'undefined' ? window.location.origin : '';
}