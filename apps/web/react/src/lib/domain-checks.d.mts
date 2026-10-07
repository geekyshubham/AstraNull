import type { DataItem } from './types';

export function retainedCoveragePairs(pairs: DataItem[]): DataItem[];

export type CategoryIcon = 'shield' | 'bug' | 'server' | 'globe' | 'workflow' | 'lock' | 'network' | 'dns' | 'radio' | 'waves' | 'activity' | 'bell';
export type CheckCategory = { id: string; label: string; layer: 'waf' | 'cdn' | 'origin' | 'ops' | 'other'; icon: CategoryIcon; how: string };
export type RowStatus = 'passed' | 'failed' | 'inconclusive' | 'observed' | 'running' | 'queued' | 'waiting' | 'blocked' | 'skipped' | 'cancelled' | 'not_run';
export type Tone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

export type CheckRow = {
  checkId: string;
  name: string;
  description: string;
  verdictLogic: string;
  tier: string;
  probeKind: string;
  maxRequests: number | null;
  timeoutMs: number | null;
  category: CheckCategory;
  status: RowStatus;
  label: string;
  tone: Tone;
  verdict: string;
  explanation: string;
  expectedBehavior?: string;
  reason: string;
  eligibleAt: string;
  runId: string;
  startedAt: string;
  finishedAt: string;
  request: DataItem | null;
  response: DataItem | null;
  requestsSent: number | null;
  requestsSimulated: boolean;
  source: 'scan' | 'run' | 'none';
};

export type CategoryGroup = { category: CheckCategory; rows: CheckRow[]; counts: Record<RowStatus, number> };

export type EfficacyStatus = 'protecting' | 'partial' | 'mostly_exposed' | 'not_protecting' | 'bypassable' | 'present_unmeasured' | 'absent' | 'unknown';
export type LayerEfficacy = {
  layer: 'waf' | 'cdn';
  status: EfficacyStatus;
  label: string;
  tone: Tone;
  detected: string;
  provider: string;
  passed: number;
  failed: number;
  tested: number;
  inconclusive: number;
  score: number | null;
  basis: 'checks' | 'fingerprint_markers';
  originExposed: boolean;
  exposedChecks: string[];
};

export type EvidenceLayer = {
  family: string;
  provider: string;
  name: string;
  logo: '' | 'cloudflare' | 'akamai' | 'route53' | 'azure' | 'google_cloud';
  confidence: number | null;
  agreement: string;
  conflicting: boolean;
  sources: Array<{ id: string; method: string; detail: string }>;
  signals: string[];
  evidenceSummary?: string;
};

export type EdgePhase = 'detected' | 'not_detected' | 'inconclusive' | 'error' | 'pending' | 'evaluating' | 'locked' | 'waiting' | 'no_result' | 'not_started' | string;

export const EDGE_DETECTION_CHECK_ID: string;
export const CHECK_CATEGORIES: Readonly<Record<string, CheckCategory>>;
export const ROW_STATUS_META: Readonly<Record<RowStatus, { label: string; tone: Tone }>>;
export const ROW_STATUS_ORDER: RowStatus[];
export function categoryForCheck(check: DataItem | null | undefined): CheckCategory;
export function isDeclarationOnlyCheck(check: DataItem | null | undefined): boolean;
export function assessmentChecks(checks: DataItem[], target: DataItem | null): DataItem[];
export function targetCheckRequirement(check: DataItem, target: DataItem | null): string;
export function individualChecks(checks: DataItem[], target: DataItem | null): DataItem[];
export function runAllChecks(checks: DataItem[], target: DataItem | null): DataItem[];
export function declarationOnlyChecks(checks: DataItem[], target: DataItem | null): DataItem[];
export function latestRunByCheck(runs: DataItem[]): Map<string, DataItem>;
export function buildCheckRows(input: { checks: DataItem[]; scan?: DataItem | null; runs?: DataItem[] }): CheckRow[];
export function countRowStatuses(rows: CheckRow[]): Record<RowStatus, number>;
export function groupRowsByCategory(rows: CheckRow[]): CategoryGroup[];
export function rowProgress(rows: CheckRow[]): { total: number; done: number; percent: number };
export function assessEdgeEfficacy(input: { rows?: CheckRow[]; edge?: DataItem | null }): { waf: LayerEfficacy; cdn: LayerEfficacy; originExposed: boolean };
export function efficacySentence(efficacy: LayerEfficacy): string;
export function providerName(code: string, displayName?: string): string;
export function providerLogoId(code: string): EvidenceLayer['logo'];
export function edgeEvidenceSignals(edge: DataItem | null | undefined): { layers: EvidenceLayer[]; facts: Array<{ id: string; label: string; value: string }> };
export function edgeDetectionPhase(input: { eligible: boolean; edge: DataItem | null | undefined; request?: DataItem | null; localRequest?: string; scanFingerprintActive?: boolean }): EdgePhase;
export function shouldAutoDetectEdge(input: { eligible: boolean; featureEnabled: boolean; canRun: boolean; edge: DataItem | null | undefined; request: DataItem | null | undefined; scanActive: boolean; attempted: boolean; hasPriorRuns: boolean }): boolean;
export function validationScansPathForTarget(targetGroupId: string, targetId: string): string;

export type ProviderFamily = 'cdn' | 'waf' | 'cloud' | 'origin_hosting' | 'dns';
export type ProviderFamilyRow = {
  family: ProviderFamily;
  title: string;
  status: string;
  statusLabel: string;
  tone: Tone;
  provider: string;
  providerName: string;
  logo: string;
  observedAt: string;
  testRunId: string;
  freshness: string;
  sources: Array<{ id: string; method: string; detail: string }>;
  confidence: number | null;
  reason: string;
  limitation: string;
  source: 'protection_profile' | 'edge_detection' | 'none';
};
export type MarkerEffectiveness = {
  blocked: number;
  allowed: number;
  inconclusive: number;
  notRun: number | null;
  definitive: number;
  percentage: number | null;
  source: 'protection_profile' | 'edge_detection';
};
export type TargetTab = 'overview' | 'validate' | 'findings' | 'history';
export const PROVIDER_FAMILY_ORDER: readonly ProviderFamily[];
export function providerFamilyRows(input: { protection_profile?: DataItem | null; edge_detection?: DataItem | null }): ProviderFamilyRow[];
export function markerEffectiveness(input: { protection_profile?: DataItem | null; edge_detection?: DataItem | null }): MarkerEffectiveness | null;
export function originExposureStatus(input: { protection_profile?: DataItem | null }): string;
export function targetTabFromParam(value: unknown): TargetTab;
export function normalizedHostKey(target: DataItem | null | undefined): string;
export function inventoryUnits(targets: DataItem[]): { records: number; distinctHosts: number; nonHostRecords: number };
export type ServiceRole = 'website' | 'api' | 'login' | 'dns' | 'network';
export type CriticalityValue = 'critical' | 'high' | 'medium' | 'low';
export type DeclarationDraft = { purpose: string; service_roles: ServiceRole[]; owner_label: string; criticality: CriticalityValue | '' };
export const SERVICE_ROLES: readonly ServiceRole[];
export const CRITICALITY_VALUES: readonly CriticalityValue[];
export function declarationDraftFrom(declaration: DataItem | null | undefined): DeclarationDraft;
export function declarationPatchBody(initial: DeclarationDraft, draft: DeclarationDraft): Record<string, unknown>;
export const DECLARATION_LIMITS: Readonly<{ purpose: number; owner_label: number }>;
export function validateDeclarationDraft(draft: DeclarationDraft): Partial<Record<'purpose' | 'owner_label', string>>;
export const COHORT_FILTER_KEYS: readonly string[];
export function canonicalCohortFilters(input: URLSearchParams | Record<string, unknown> | null | undefined): Record<string, string> | null;
export function cohortHrefFromListQuery(listQuery: unknown): string;
export type CoverageBucket = { key: string; label: string; group: string; count: number; href: string };
export function familyCoverageBuckets(payload: unknown): {
  denominator: number | null;
  parts: CoverageBucket[];
  unmeasured: number;
  reconciled: boolean;
  units: { targetRecords: number | null; normalizedHosts: number | null };
  unit: string;
  asOf: string;
  current: boolean;
  complete: boolean;
};
export function classifyCohortError(error: unknown): { action: 'refetch' | 'reset' | 'unsupported' | 'denied' | 'error'; reason: string };
export function originExposureDetail(input: { protection_profile?: DataItem | null }): {
  status: string; assurance: string; reachabilityStatus: string; testedTargetId: string; scenarioId: string; source: string; limitations: string[];
};
export function originBindingRole(target: DataItem | null | undefined): 'protected' | 'origin' | null;
export type OriginCandidate = { id: string; value: string; kind: string; state: string };
export function originBindingCandidates(targets: DataItem[], protectedTarget: DataItem | null | undefined): { ready: OriginCandidate[]; blocked: OriginCandidate[] };
export function originBindingErrorCode(error: unknown): string;
export function originBindingErrorMessage(error: unknown): string;
export function originBindingScope(input: { port?: string; path?: string }): { scope: { port?: number; path?: string }; errors: { port?: string; path?: string }; valid: boolean };
export type PresentedObservation = {
  id: string; family: string; outcome: string; outcomeLabel: string; attempt: string; attemptLabel: string;
  producer: string; producerLabel: string; live: boolean | null; observedAt: string; completedAt: string;
  checkId: string; testRunId: string; sourceKind: string; corpusVersion: string; scenarioVersion: string; checkVersion: string; bindingId: string;
};
export function presentObservation(item: unknown): PresentedObservation | null;
export function comparisonReasonLabel(reason: unknown): string;
export function changeDirectionLabel(direction: unknown): string;
