export type PlainLanguageTone = 'success' | 'warn' | 'danger' | 'info' | 'muted';

export type EvidenceTierInfo = {
  code: 'E1' | 'E2' | 'E3' | 'E4' | 'E5';
  label: string;
  description: string;
};

export type EvidenceModePresentation = {
  label: string;
  detail: string;
  tone: PlainLanguageTone;
  live: boolean;
  code: string;
};

export const EVIDENCE_TIERS: readonly EvidenceTierInfo[];
export function plainVerdictLabel(value: unknown): string;
export function plainCodeLabel(value: unknown, fallback?: string): string;
export function plainEmptyReason(value: unknown): string;
export function plainInlineText(value: unknown): string;
export function plainCheckName(value: unknown): string;
export function plainFindingTitle(value: unknown, targets?: unknown[], checks?: unknown[]): string;
export function plainVerdictDescription(value: unknown): string;
export function plainVerificationLabel(value: unknown): string;
export function plainProtectionLabel(value: unknown): string;
export function evidenceTierInfo(value: unknown): EvidenceTierInfo | null;
export function evidenceModePresentation(value: unknown, catalogCheck?: unknown): EvidenceModePresentation;
export function dashboardReadinessMessage(input?: {
  score?: number | null;
  highPriorityFindings?: number;
  coveragePercent?: number | null;
  dataUnavailable?: boolean;
}): { headline: string; detail: string; tone: 'success' | 'warn' | 'danger' };
