/**
 * Resolve whether one authoritative run-events endpoint envelope attributes a run to an agent.
 *
 * Current target-group membership grants visibility only: multiple agents can observe the same
 * group, so a group-only run must not be presented as this agent's evidence. Evidence-vault rows,
 * caller-assembled event arrays, and unsupported run-level agent fields are deliberately ignored.
 */

export const AGENT_RUN_EVENT_CANDIDATE_LIMIT = 24;
export const AGENT_RUN_DISPLAY_LIMIT = 8;

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function stringValue(value) {
  return value === undefined || value === null ? '' : String(value).trim();
}

function boundedLimit(value, fallback) {
  return Number.isInteger(value) && value >= 0 ? value : fallback;
}

function endpointEventItems(response) {
  const envelope = asRecord(response);
  if (!envelope || !Array.isArray(envelope.items)) return [];
  return envelope.items.map(asRecord).filter(Boolean);
}

function runId(run) {
  const item = asRecord(run);
  return item ? stringValue(item.id ?? item.test_run_id ?? item.testRunId) : '';
}

function runRecency(run) {
  const item = asRecord(run);
  return item ? stringValue(item.updated_at ?? item.created_at) : '';
}

/**
 * Pick a bounded, newest-first run set whose endpoint envelopes may prove historical
 * attribution. This happens before target-group filtering and the smaller display slice so an
 * agent's current group assignment cannot hide a historical run before provenance is checked.
 *
 * @param {Array<Record<string, unknown>>} runs
 * @param {number} limit
 * @returns {Array<Record<string, unknown>>}
 */
export function selectAgentRunEventCandidates(runs, limit = AGENT_RUN_EVENT_CANDIDATE_LIMIT) {
  const candidateLimit = boundedLimit(limit, AGENT_RUN_EVENT_CANDIDATE_LIMIT);
  if (!Array.isArray(runs) || candidateLimit === 0) return [];
  return runs
    .map(asRecord)
    .filter((run) => run && runId(run))
    .sort((left, right) => runRecency(right).localeCompare(runRecency(left)))
    .slice(0, candidateLimit);
}

export const HISTORICAL_RUN_ATTRIBUTION_UNAVAILABLE = 'Historical run attribution unavailable';

/**
 * Fail closed when any candidate endpoint is unavailable. A failed envelope could contain the
 * newest exact observation, so loaded siblings cannot prove that the visible subset is complete.
 *
 * @param {Array<Record<string, unknown>>} candidateRuns
 * @param {Record<string, 'loading'|'loaded'|'error'>} runEventStatus
 * @returns {'loading'|'available'|'unavailable'}
 */
export function resolveAgentRunAttributionStatus(candidateRuns, runEventStatus) {
  if (!Array.isArray(candidateRuns) || candidateRuns.length === 0) return 'available';
  const statuses = asRecord(runEventStatus) ?? {};
  const candidateStatuses = candidateRuns
    .map((run) => runId(run))
    .filter(Boolean)
    .map((id) => stringValue(statuses[id]));
  if (candidateStatuses.includes('error')) return 'unavailable';
  return candidateStatuses.length === candidateRuns.length
    && candidateStatuses.every((status) => status === 'loaded')
    ? 'available'
    : 'loading';
}

/**
 * Filter already-selected candidates only after endpoint envelopes have been collected, then
 * cap the displayed list. Current target-group membership grants visibility, not attribution.
 *
 * @param {Array<Record<string, unknown>>} candidateRuns
 * @param {Record<string, Record<string, unknown>>} runEventsByRunId
 * @param {string} agentId
 * @param {string} targetGroupId
 * @param {number} limit
 * @returns {Array<Record<string, unknown>>}
 */
export function selectAgentRecentRuns(
  candidateRuns,
  runEventsByRunId,
  agentId,
  targetGroupId,
  limit = AGENT_RUN_DISPLAY_LIMIT,
) {
  const displayLimit = boundedLimit(limit, AGENT_RUN_DISPLAY_LIMIT);
  if (!Array.isArray(candidateRuns) || displayLimit === 0) return [];
  const eventEnvelopes = asRecord(runEventsByRunId) ?? {};
  const selectedTargetGroupId = stringValue(targetGroupId);

  return candidateRuns
    .map(asRecord)
    .filter((run) => {
      if (!run) return false;
      const selectedRunId = runId(run);
      const currentGroupVisible = Boolean(selectedTargetGroupId)
        && stringValue(run.target_group_id) === selectedTargetGroupId;
      return currentGroupVisible || runAgentAttribution(
        run,
        asRecord(eventEnvelopes[selectedRunId]) ?? { items: [] },
        agentId,
      ).attributed;
    })
    .slice(0, displayLimit);
}

/**
 * Return only runs whose authoritative endpoint envelope contains exact authenticated
 * observation provenance for the selected agent. Target-group membership never qualifies.
 *
 * @param {Array<Record<string, unknown>>} candidateRuns
 * @param {Record<string, Record<string, unknown>>} runEventsByRunId
 * @param {string} agentId
 * @param {number} limit
 * @returns {Array<Record<string, unknown>>}
 */
export function selectAgentAttributedRuns(
  candidateRuns,
  runEventsByRunId,
  agentId,
  limit = AGENT_RUN_DISPLAY_LIMIT,
) {
  const displayLimit = boundedLimit(limit, AGENT_RUN_DISPLAY_LIMIT);
  if (!Array.isArray(candidateRuns) || displayLimit === 0) return [];
  const eventEnvelopes = asRecord(runEventsByRunId) ?? {};

  return candidateRuns
    .map(asRecord)
    .filter((run) => {
      if (!run) return false;
      const selectedRunId = runId(run);
      return runAgentAttribution(
        run,
        asRecord(eventEnvelopes[selectedRunId]) ?? { items: [] },
        agentId,
      ).attributed;
    })
    .slice(0, displayLimit);
}

/**
 * @param {Record<string, unknown>} run
 * @param {Record<string, unknown>} runEventsResponse
 * @param {string} agentId
 * @returns {{ attributed: boolean, source: 'run_event'|null }}
 */
export function runAgentAttribution(run, runEventsResponse, agentId) {
  const selectedAgentId = stringValue(agentId);
  if (!selectedAgentId) return { attributed: false, source: null };

  const selectedRunId = runId(run);
  if (!selectedRunId) return { attributed: false, source: null };
  const attributedByAuthenticatedObservation = endpointEventItems(runEventsResponse).some((event) => (
    stringValue(event.test_run_id) === selectedRunId
    && stringValue(event.signal_type) === 'agent_observation'
    && stringValue(event.producer_kind) === 'authenticated_agent'
    && stringValue(event.agent_id) === selectedAgentId
  ));
  return attributedByAuthenticatedObservation
    ? { attributed: true, source: 'run_event' }
    : { attributed: false, source: null };
}
