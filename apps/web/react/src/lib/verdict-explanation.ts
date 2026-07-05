import type { DataItem } from './types';

export type VerdictExplanationField = { label: string; value: string };

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
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

function verdictExplanationMetaMode(event: DataItem) {
  const meta = (event.metadata as DataItem | undefined) ?? {};
  for (const key of ['observation_mode', 'mode', 'source', 'interface', 'log_source']) {
    const value = meta[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return getString(event, ['signal_type'], 'event');
}

export function summarizeExternalProbeEvidence(probeEvents: DataItem[]) {
  if (!probeEvents.length) {
    return 'No probe_result events recorded for this run yet; external probe evidence is missing or limited.';
  }
  return probeEvents
    .map((event) => {
      const parts: string[] = [];
      if (event.timestamp) parts.push(String(event.timestamp));
      if (event.source) parts.push(`source ${String(event.source)}`);
      const meta = (event.metadata as DataItem | undefined) ?? {};
      const externalResult = event.external_result ?? meta.external_result;
      if (externalResult) parts.push(`external_result ${String(externalResult)}`);
      if (meta.probe_profile_kind) parts.push(`profile ${String(meta.probe_profile_kind)}`);
      if (meta.simulation) parts.push(String(meta.simulation));
      if (meta.note) parts.push(String(meta.note));
      return parts.length ? parts.join(' · ') : getString(event, ['signal_type'], 'probe_result');
    })
    .join('; ');
}

export function summarizeInternalAgentEvidence(obsEvents: DataItem[], noObsEvents: DataItem[]) {
  const lines: string[] = [];
  if (obsEvents.length) {
    obsEvents.forEach((event) => {
      const parts: string[] = [];
      if (event.timestamp) parts.push(String(event.timestamp));
      if (event.agent_id) parts.push(`agent ${String(event.agent_id)}`);
      if (event.source) parts.push(`source ${String(event.source)}`);
      if (event.nonce_hash) parts.push('nonce correlated');
      const meta = (event.metadata as DataItem | undefined) ?? {};
      if (meta.reason) parts.push(String(meta.reason));
      lines.push(parts.length ? parts.join(' · ') : 'agent_observation recorded');
    });
  } else {
    lines.push('No agent_observation events in this run timeline.');
  }
  noObsEvents.forEach((event) => {
    const meta = (event.metadata as DataItem | undefined) ?? {};
    const reason = meta.reason ? String(meta.reason) : 'no observation within bounded window';
    lines.push(`agent_no_observation · ${reason}`);
  });
  return lines.join('; ');
}

export function summarizeObservationMode(events: DataItem[]) {
  const agentSignals = events.filter((event) => ['agent_observation', 'agent_no_observation'].includes(getString(event, ['signal_type'])));
  const pool = agentSignals.length ? agentSignals : events;
  if (!pool.length) return 'Observation mode cannot be determined — no agent or probe events yet.';
  const modes = [...new Set(pool.map((event) => verdictExplanationMetaMode(event)))];
  return modes.join(', ');
}

export function summarizePlacementConfidence(
  matchingObs: DataItem[],
  noObsEvents: DataItem[],
  verdictPlacement?: DataItem
) {
  if (verdictPlacement && typeof verdictPlacement === 'object') {
    const parts: string[] = [];
    if (verdictPlacement.level) parts.push(String(verdictPlacement.level));
    if (verdictPlacement.observation_mode) parts.push(`mode ${String(verdictPlacement.observation_mode)}`);
    if (verdictPlacement.reason) parts.push(String(verdictPlacement.reason));
    if (verdictPlacement.agent_id) parts.push(`agent ${String(verdictPlacement.agent_id)}`);
    if (parts.length) return parts.join(' · ');
  }
  if (matchingObs.length) {
    return 'Placement confidence is supported by job-bound agent observation correlated to this run.';
  }
  if (noObsEvents.length) {
    return 'Placement confidence is limited: bounded window ended with agent_no_observation and no matching observation.';
  }
  return 'Placement confidence cannot be proven from run events yet.';
}

export function buildVerdictExplanationFields(
  detail: DataItem | null,
  events: DataItem[],
  options: { remediationTemplate?: string } = {}
): VerdictExplanationField[] {
  if (!detail?.verdict || typeof detail.verdict !== 'object') return [];

  const probeEvents = events.filter((event) => getString(event, ['signal_type']) === 'probe_result');
  const obsEvents = events.filter((event) => getString(event, ['signal_type']) === 'agent_observation');
  const noObsEvents = events.filter((event) => getString(event, ['signal_type']) === 'agent_no_observation');
  const nonceHash = getNestedString(detail, ['correlation', 'nonce_hash'], '');
  const matchingObs = nonceHash
    ? obsEvents.filter((event) => getString(event, ['nonce_hash'], '') === nonceHash)
    : obsEvents;

  const verdict = detail.verdict as DataItem;
  const remediationRef = options.remediationTemplate ?? getString(detail, ['remediation_template'], '');
  const conclusion = `${getString(verdict, ['verdict'], '—')} · confidence ${getString(verdict, ['confidence'], '—')}. ${getString(verdict, ['explanation'], '')}`.trim();

  return [
    { label: 'External probe evidence', value: summarizeExternalProbeEvidence(probeEvents) },
    { label: 'Internal agent evidence', value: summarizeInternalAgentEvidence(obsEvents, noObsEvents) },
    { label: 'Observation mode', value: summarizeObservationMode(events) },
    {
      label: 'Placement confidence',
      value: summarizePlacementConfidence(matchingObs, noObsEvents, verdict.placement_confidence as DataItem | undefined),
    },
    { label: 'Conclusion', value: conclusion },
    {
      label: 'Remediation',
      value: remediationRef || 'No remediation template recorded for this run.',
    },
  ];
}

export function normalizeVerdictKey(verdict: string) {
  if (verdict === 'misplaced_agent') return 'misplaced';
  return verdict;
}

export function trafficHopState(hop: string, verdict?: string) {
  if (!verdict) return hop === 'probe' ? 'ok' : 'muted';
  if (verdict === 'protected') {
    if (hop === 'probe' || hop === 'edge') return 'ok';
    return 'muted';
  }
  if (verdict === 'bypassable' || verdict === 'penetrated') {
    if (hop === 'probe') return 'ok';
    if (hop === 'origin') return 'danger';
    return 'warn';
  }
  return 'warn';
}

export const TRUTH_TABLE_ROWS: Array<{ key: string; description: string }> = [
  { key: 'protected', description: 'Blocked before origin; observation absent or consistent with policy.' },
  { key: 'bypassable', description: 'Edge did not stop traffic; origin/agent observed the marker.' },
  { key: 'penetrated', description: 'Protection failed; unwanted reach confirmed by evidence.' },
  { key: 'misplaced', description: 'Agent or canary placement does not match the declared protected path.' },
];