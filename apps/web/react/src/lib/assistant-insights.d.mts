import type { DataResult } from './assistant-visuals.mjs';

export type InsightTone = 'critical' | 'caution' | 'positive' | 'neutral';
export type InsightUnit = 'count' | 'percent' | 'score' | 'days';
export type InsightSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type InsightScope = { route: string; kind: string; label: string; subject?: string; entity?: { id: string }; finding_ids?: string[] };
export type InsightKpi = { id: string; label: string; value: number | null; unit: InsightUnit; tone: InsightTone; detail?: string };
export type InsightAction = { severity: InsightSeverity; title: string; detail?: string; route?: string };
export type InsightNarrative = { summary: string; takeaways: string[]; ai: boolean };
export type InsightSection = DataResult & { hint?: string };
export type InsightBoard = {
  kind: string;
  subject?: string;
  generated_at: string;
  verdict: { tone: InsightTone; score: number | null; headline: string };
  kpis: InsightKpi[];
  sections: InsightSection[];
  actions: InsightAction[];
  narrative: InsightNarrative;
  truncated: boolean;
  noAccess: boolean;
};
export type NarrativeState = { status: 'queued' | 'unavailable' | 'rate_limited' | 'not_requested'; jobId: string; reason: string };

export const INSIGHT_CACHE_TTL_MS: number;
export const MAX_GROUP_FINDINGS: number;
export function insightScopeForRoute(route: string, params?: Record<string, string>, override?: InsightScope | null): InsightScope | null;
export function sanitizeScope(value: unknown): InsightScope | null;
export function currentInsightScope(hash: string, override?: InsightScope | null): InsightScope | null;
export function insightRequestBody(scope: InsightScope, options?: { narrative?: boolean; refresh?: boolean }): Record<string, unknown>;
export function insightCacheKey(identity: string, scope: InsightScope): string;
export function sanitizeNarrative(value: unknown): InsightNarrative | null;
export function sanitizeBoard(value: unknown): InsightBoard | null;
export function sanitizeNarrativeState(value: unknown): NarrativeState;
export function formatKpi(kpi: InsightKpi): string;
export function kpiUnitSuffix(kpi: InsightKpi): string;
export function narrativeUnavailableMessage(state: NarrativeState): string;
