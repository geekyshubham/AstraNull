export type AgentRunAttribution = {
  attributed: boolean;
  source: 'run_event' | null;
};

export type AgentRunRecord = Record<string, unknown>;

export type RunEventsEndpointResponse = Record<string, unknown> & {
  items?: readonly unknown[];
};

export declare const AGENT_RUN_EVENT_CANDIDATE_LIMIT: number;
export declare const AGENT_RUN_DISPLAY_LIMIT: number;


export type AgentRunAttributionStatus = 'loading' | 'available' | 'unavailable';
export type AgentRunEventLoadStatus = 'loading' | 'loaded' | 'error';

export declare const HISTORICAL_RUN_ATTRIBUTION_UNAVAILABLE: string;

export declare function resolveAgentRunAttributionStatus(
  candidateRuns: readonly AgentRunRecord[],
  runEventStatus: Readonly<Record<string, AgentRunEventLoadStatus | undefined>>,
): AgentRunAttributionStatus;
export declare function selectAgentRunEventCandidates(
  runs: readonly AgentRunRecord[],
  limit?: number,
): AgentRunRecord[];

export declare function selectAgentRecentRuns(
  candidateRuns: readonly AgentRunRecord[],
  runEventsByRunId: Readonly<Record<string, RunEventsEndpointResponse | undefined>>,
  agentId: string,
  targetGroupId: string,
  limit?: number,
): AgentRunRecord[];

export declare function selectAgentAttributedRuns(
  candidateRuns: readonly AgentRunRecord[],
  runEventsByRunId: Readonly<Record<string, RunEventsEndpointResponse | undefined>>,
  agentId: string,
  limit?: number,
): AgentRunRecord[];

export declare function runAgentAttribution(
  run: AgentRunRecord,
  runEventsResponse: RunEventsEndpointResponse,
  agentId: string,
): AgentRunAttribution;
