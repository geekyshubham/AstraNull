import type { DataItem } from './types';

export const ONBOARDING_HEARTBEAT_POLL_MS = 3000;
export const ONBOARDING_HEARTBEAT_TIMEOUT_MS = 120000;
export const ONBOARDING_PLACEMENT_TEST_CHECK_ID = 'path.protected_canary.safe';

export type OnboardingHeartbeatStatus = 'online' | 'timeout' | 'stale' | 'waiting';

export type OnboardingHeartbeatState = {
  status: OnboardingHeartbeatStatus;
  agents: DataItem[];
  elapsedMs: number;
};

export function agentHasRecentHeartbeat(agent: DataItem | null | undefined, nowMs = Date.now()) {
  if (!agent || getString(agent, ['status']) !== 'online') return false;
  const heartbeat = agent.last_heartbeat_at;
  if (!heartbeat) return false;
  const age = nowMs - Date.parse(String(heartbeat));
  return Number.isFinite(age) && age >= 0 && age < ONBOARDING_HEARTBEAT_TIMEOUT_MS;
}

export function resolveOnboardingHeartbeatState(
  agents: DataItem[],
  opts: { nowMs?: number; pollStartedAt?: number } = {}
): OnboardingHeartbeatState {
  const nowMs = opts.nowMs ?? Date.now();
  const startedAt = opts.pollStartedAt ?? nowMs;
  const list = agents ?? [];
  const online = list.filter((agent) => agentHasRecentHeartbeat(agent, nowMs));
  const elapsedMs = Math.max(0, nowMs - startedAt);
  if (online.length) {
    return { status: 'online', agents: online, elapsedMs };
  }
  if (elapsedMs >= ONBOARDING_HEARTBEAT_TIMEOUT_MS) {
    return { status: 'timeout', agents: list, elapsedMs };
  }
  const stale = list.some((agent) => agent.last_heartbeat_at && !agentHasRecentHeartbeat(agent, nowMs));
  return { status: stale ? 'stale' : 'waiting', agents: list, elapsedMs };
}

export function extractPlacementDiagnosticsFromReadiness(readiness: DataItem | null | undefined) {
  const factors = Array.isArray(readiness?.factors) ? readiness.factors as DataItem[] : [];
  const factor = factors.find((item) => getString(item, ['key']) === 'agent_placement');
  const diagnostics = factor?.placement_diagnostics;
  return diagnostics && typeof diagnostics === 'object' && !Array.isArray(diagnostics)
    ? diagnostics as DataItem
    : null;
}

export function summarizeOnboardingPlacementConfidenceHint(
  agent: DataItem | null | undefined,
  readinessDiagnostics: DataItem | null | undefined
) {
  const groups = Array.isArray(readinessDiagnostics?.groups) ? readinessDiagnostics.groups as DataItem[] : [];
  if (groups.some((group) => getString(group, ['status']) === 'proven')) {
    return 'Placement confidence is supported: baseline traffic was observed for a declared target group.';
  }
  const capabilities = Array.isArray(agent?.capabilities) ? agent.capabilities as string[] : [];
  if (capabilities.includes('canary')) {
    return 'Canary-capable agent detected — placement confidence improves when protected-path canary traffic is observed.';
  }
  if (groups.some((group) => getString(group, ['status']) === 'needs_baseline')) {
    return 'Placement confidence is limited until baseline or canary traffic is seen — run the optional placement test.';
  }
  if (agent) {
    return 'Heartbeat received. Run the optional placement test to strengthen placement confidence before the first validation.';
  }
  return 'Placement confidence cannot be proven yet — verify agent bind, observation mode, and protected-path visibility.';
}

export function placementTestComplete(runs: DataItem[]) {
  return runs.some((run) =>
    getString(run, ['check_id']) === ONBOARDING_PLACEMENT_TEST_CHECK_ID
    && ['completed', 'verdicted', 'running'].includes(getString(run, ['status']))
  );
}

function getString(item: DataItem, keys: string[]) {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return '';
}