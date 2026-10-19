import { requestJson } from './api';
import { sanitizeQueuedJob, type QueuedJob } from './assistant-jobs';
import type { PortalConfig, Session } from './types';

export type RiskPlanPurpose = 'risk_story' | 'validation_plan';
export type RiskFact = { finding_id: string; check_id: string | null; status: string; severity: string; observed_at: string | null; data_labels: string[]; evidence_ids: string[] };
export type RiskStory = { source_finding_ids: string[]; hypothesis: string };
export type PlanCandidate = { check_id: string; name: string; max_requests: number | null; source_finding_ids: string[] };
export type RiskPlanComputed = {
  snapshot_id: string; target_id: string; as_of: string; incomplete: boolean;
  source_finding_ids: string[]; observed_facts: RiskFact[]; limitations: string[];
  stories?: RiskStory[]; candidates?: PlanCandidate[]; excluded?: { check_id: string; reason: string }[];
  check_ids?: string[]; selection_basis?: string; admission?: string;
};
export type RiskPlanAnnotation = { snapshot_id: string; target_id: string; ai: true; stories?: RiskStory[]; check_ids?: string[]; rationale?: string };
const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const record = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const ids = (value: unknown, max: number): value is string[] => Array.isArray(value) && value.length <= max && value.every((id) => typeof id === 'string' && ID.test(id)) && new Set(value).size === value.length;
const texts = (value: unknown, max: number): value is string[] => Array.isArray(value) && value.length <= max && value.every((text) => typeof text === 'string' && text.length <= 1200);
const stories = (value: unknown, sources: string[]): value is RiskStory[] => Array.isArray(value) && value.length <= 20 && value.every((item) => ids(item?.source_finding_ids, 20) && item.source_finding_ids.length > 0 && item.source_finding_ids.every((id: string) => sources.includes(id)) && typeof item.hypothesis === 'string' && item.hypothesis.length <= 1200);

export function sanitizeRiskPlanComputed(value: unknown, targetId: string, purpose: RiskPlanPurpose): RiskPlanComputed | null {
  const body = record(value);
  const scope = record(body.scope);
  if (body.target_id !== targetId || typeof body.snapshot_id !== 'string' || !ID.test(body.snapshot_id) || !ids(scope.target_ids, 1) || scope.target_ids[0] !== targetId || scope.includes_subdomains !== false || scope.confidence !== 'external_only' || !ids(body.source_finding_ids, 20) || !texts(body.limitations, 12) || typeof body.as_of !== 'string' || !Number.isFinite(Date.parse(body.as_of)) || typeof body.incomplete !== 'boolean') return null;
  if (!Array.isArray(body.observed_facts) || body.observed_facts.length > 20 || !body.observed_facts.every((fact) => Array.isArray(body.source_finding_ids) && body.source_finding_ids.includes(fact?.finding_id) && (fact.check_id === null || (typeof fact.check_id === 'string' && ID.test(fact.check_id))) && typeof fact.status === 'string' && fact.status.length <= 40 && typeof fact.severity === 'string' && fact.severity.length <= 40 && (fact.observed_at === null || typeof fact.observed_at === 'string') && texts(fact.data_labels, 5) && ids(fact.evidence_ids, 8))) return null;
  if (purpose === 'risk_story' && !stories(body.stories, body.source_finding_ids)) return null;
  if (purpose === 'validation_plan') {
    if (!Array.isArray(body.candidates) || body.candidates.length > 500 || !body.candidates.every((item) => typeof item?.check_id === 'string' && ID.test(item.check_id) && typeof item.name === 'string' && item.name.length <= 140 && (item.max_requests === null || (Number.isFinite(item.max_requests) && item.max_requests >= 0)) && ids(item.source_finding_ids, 20) && item.source_finding_ids.every((id: string) => (body.source_finding_ids as string[]).includes(id)))) return null;
    const candidateIds = body.candidates.map((item) => item.check_id);
    if (new Set(candidateIds).size !== candidateIds.length || !ids(body.check_ids, 12) || body.check_ids.some((id) => !candidateIds.includes(id)) || !Array.isArray(body.excluded) || body.excluded.length > 500 || !body.excluded.every((row) => typeof row?.check_id === 'string' && ID.test(row.check_id) && typeof row.reason === 'string' && row.reason.length <= 100) || typeof body.selection_basis !== 'string' || typeof body.admission !== 'string') return null;
  }
  return body as unknown as RiskPlanComputed;
}

export function sanitizeRiskPlanAnnotation(value: unknown, computed: RiskPlanComputed, purpose: RiskPlanPurpose): RiskPlanAnnotation | null {
  const body = record(value);
  if (body.target_id !== computed.target_id || body.snapshot_id !== computed.snapshot_id || body.ai !== true) return null;
  if (purpose === 'risk_story' && !stories(body.stories, computed.source_finding_ids)) return null;
  if (purpose === 'validation_plan' && (!ids(body.check_ids, 12) || !body.check_ids.length || body.check_ids.some((id) => !computed.candidates?.some((candidate) => candidate.check_id === id)) || typeof body.rationale !== 'string' || body.rationale.length > 1200)) return null;
  return body as unknown as RiskPlanAnnotation;
}

export async function generateRiskPlan(config: PortalConfig, session: Session, targetId: string, purpose: RiskPlanPurpose, signal: AbortSignal): Promise<{ computed: RiskPlanComputed; queued: QueuedJob }> {
  if (signal.aborted) throw new Error('Proposal request cancelled.');
  // Keep the creation response available after logical disposal so a late job can
  // be cancelled; aborting this POST's transport can lose its server-side job ID.
  const value = await requestJson(config, session, `/v1/assistant/${purpose === 'risk_story' ? 'risk-stories' : 'validation-plan'}`, { method: 'POST', body: { target_id: targetId } });
  const body = record(value);
  const queued = sanitizeQueuedJob(body.narrative);
  const computed = sanitizeRiskPlanComputed(body.computed, targetId, purpose);
  if (signal.aborted || !computed) {
    if (queued.status === 'queued') await requestJson(config, session, `/v1/assistant/jobs/${encodeURIComponent(queued.jobId)}`, { method: 'DELETE' }).catch(() => {});
    throw new Error(signal.aborted ? 'Proposal request cancelled.' : 'The proposal response did not match this target. Generate again.');
  }
  return { computed, queued };
}
