export type AssuranceId = 'verdict' | 'violation_only' | 'partial' | 'observation' | 'declaration' | 'soc_only' | 'missing' | 'not_assessable' | 'out_of_scope';
export type CoverageStatusId = 'covered_pass' | 'covered_fail' | 'inconclusive' | 'not_run' | 'needs_declaration' | 'not_assessable' | 'out_of_scope';
export type CoverageTone = 'success' | 'warn' | 'danger' | 'muted';

export const ASSURANCE_META: Readonly<Record<AssuranceId, Readonly<{ label: string; rank: number; description: string }>>>;
export const COVERAGE_STATUS_META: Readonly<Record<CoverageStatusId, Readonly<{ label: string; tone: CoverageTone; rank: number; description: string }>>>;
export const LAYER_META: Readonly<Record<'waf' | 'nfw', Readonly<{ label: string; short: string; description: string }>>>;

export type CoverageCheck = {
  checkId: string; name: string; present: boolean; assurance: string; status: string; statusLabel: string;
  stale: boolean; observedAt: string; verdict: string;
};
export type CoverageCategory = {
  id: string; layer: 'waf' | 'nfw'; name: string; description: string;
  assurance: string; assuranceLabel: string; assuranceReason: string; status: string; statusLabel: string; statusTone: CoverageTone;
  reason: string; requiredDeclarations: string[]; requiredSentence: string; missingDeclarations: string[]; missingWithoutCta: string;
  ctas: Array<{ key: string; label: string; cta: string; section: string; unlocks: string }>;
  checks: CoverageCheck[];
};
export const NOT_RUNNABLE_REASON_COPY: Readonly<Record<string, string>>;
export function assuranceMeta(id: unknown): Readonly<{ label: string; rank: number; description: string }>;
export function coverageStatusMeta(id: unknown): Readonly<{ label: string; tone: CoverageTone; rank: number; description: string }>;
export function normalizeRuleCoverage(payload: unknown): { version: string; targetId: string; freshnessDays: number | null; categories: CoverageCategory[] };
export function filterCoverageByLayer(categories: CoverageCategory[], layer: string): CoverageCategory[];
export function coverageStatusCounts(categories: CoverageCategory[]): Record<CoverageStatusId, number>;
export function assuranceCounts(categories: CoverageCategory[]): Record<AssuranceId, number>;
export function sortCoverageForAttention(categories: CoverageCategory[]): CoverageCategory[];
export function plainCoverageName(value: unknown): string;
