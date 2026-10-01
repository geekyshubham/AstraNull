import type { DataItem } from './types';

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
};

export type EdgePhase = 'detected' | 'not_detected' | 'inconclusive' | 'error' | 'pending' | 'evaluating' | 'locked' | 'waiting' | 'no_result' | 'not_started' | string;

export const EDGE_DETECTION_CHECK_ID: string;
export const CHECK_CATEGORIES: Readonly<Record<string, CheckCategory>>;
export const ROW_STATUS_META: Readonly<Record<RowStatus, { label: string; tone: Tone }>>;
export const ROW_STATUS_ORDER: RowStatus[];
export function categoryForCheck(check: DataItem | null | undefined): CheckCategory;
export function isDeclarationOnlyCheck(check: DataItem | null | undefined): boolean;
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
