import { agentHasRecentHeartbeat } from './onboarding';
import type { DataItem } from './types';

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

export function formatAgentCapabilities(agent: DataItem | null | undefined) {
  const capabilities = Array.isArray(agent?.capabilities) ? agent.capabilities as string[] : [];
  return capabilities.length ? capabilities.join(', ') : '—';
}

export function formatAgentPlacement(agent: DataItem | null | undefined) {
  const placement = getString(agent, ['placement_type', 'placement'], '');
  return placement || 'undeclared';
}

export function formatAgentHealth(agent: DataItem | null | undefined) {
  return getString(agent, ['status', 'state'], 'unknown');
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