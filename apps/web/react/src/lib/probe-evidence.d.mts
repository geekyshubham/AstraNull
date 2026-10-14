import type { DataItem } from './types';

export type EvidenceTone = 'success' | 'warn' | 'danger' | 'muted';
type Copy = Readonly<{ label: string; tone: EvidenceTone; help: string }>;

export const OUTCOME_META: Readonly<Record<'blocked' | 'challenged' | 'allowed' | 'redirected' | 'inconclusive' | 'error' | 'source_penalized', Copy>>;
export const PLACEMENT_LABELS: Readonly<Record<string, string>>;
export const TCP_OUTCOME_COPY: Readonly<Record<string, Copy>>;
export const UDP_OUTCOME_COPY: Readonly<Record<string, Copy>>;
export const ICMP_KIND_COPY: Readonly<Record<string, string>>;
export const PARITY_COPY: Readonly<Record<string, Copy>>;
export const ENFORCEMENT_COPY: Readonly<Record<string, string>>;
export const ASSURANCE_SCOPE_COPY: Readonly<Record<string, Readonly<{ label: string; help: string }>>>;
export const INCONCLUSIVE_REASON_COPY: Readonly<Record<string, string>>;
export const TERM_HELP: Readonly<Record<'normalization_gap' | 'perspective' | 'cache' | 'signature' | 'perspective_authentication' | 'request_budget', string>>;
export const VERSION_GAP_COPY: Readonly<Record<string, string>>;
export function versionGapLabel(reason: unknown): string;
export const PORT_RESULT_COPY: Readonly<Record<'violated' | 'no_violation_observed', Copy>>;
export const PERSPECTIVE_UNAUTHENTICATED: string;
export type PortResultRow = {
  protocol: string; port: number | null; outcome: string; outcomeLabel: string; help: string;
  result: string; resultLabel: string; resultTone: EvidenceTone; resultHelp: string; severity: string;
  parity: ({ id: string } & Copy) | null; icmp: string;
};
export function portResultRows(probeRows: unknown, verdictRows?: unknown): PortResultRow[];

export type PlacementRow = {
  placement: string; placementLabel: string; outcome: string; outcomeLabel: string; tone: EvidenceTone; help: string;
  statusCode: number | null; signature: string; cacheStatus: string; locationChanged: boolean; reasonLabel: string;
};
export type FamilyResult = { address: string; outcome: string; label: string; tone: EvidenceTone; help: string };
export type NetworkEvidence = {
  protocol: string; port: number | null; address: string; family: string; outcome: string; outcomeLabel: string; tone: EvidenceTone; help: string;
  icmp: string; serviceValidated: boolean | null; peerIsCdn: boolean | null;
  families: Array<{ key: string; label: string; result: FamilyResult | null }>;
  parity: ({ id: string } & Copy) | null; sampleAgreement: string; sampleCount: number;
  localError: boolean; reflectorReachable: boolean;
  portResults: PortResultRow[]; declaredDenyPorts: number[]; unprobedDenyPorts: number[];
};
export type ProbeEvidenceModel = {
  chips: Array<{ id: string } & Copy>;
  scope: { id: string; label: string; help: string } | null;
  enforcement: { id: string; text: string } | null;
  sourcePenalized: boolean;
  inconclusiveReason: string;
  trailing: { outcome: string; outcomeLabel: string; tone: EvidenceTone; statusCode: number | null } | null;
  placements: PlacementRow[];
  paths: string[];
  evasion: {
    transform: string; reference: string; referenceLabel: string; referenceTone: EvidenceTone;
    transformed: string; transformedLabel: string; transformedTone: EvidenceTone;
    normalizationGap: boolean; referenceNotEnforced: boolean;
  } | null;
  network: NetworkEvidence | null;
  connectionLimit: { port: number | null; attempted: number; accepted: number | null; refusedAfter: number | null; declaredLimit: number | null } | null;
  rateLimit: { threshold: number | null; windowSeconds: number | null; requestsSent: number | null; firstLimitedAt: number | null; limitedOutcome: string; limitedLabel: string } | null;
  methodResults: Array<{ method: string; outcome: string; outcomeLabel: string; tone: EvidenceTone; statusCode: number | null }>;
  perspective: { id: string; label: string; claimedId: string; authenticated: boolean | null } | null;
  metaRows: Array<{ label: string; value: string }>;
};
export function outcomeMeta(outcome: unknown): { label: string; tone: EvidenceTone; help: string };
export function probeEvidenceModel(metadata: unknown, options?: { verdictPortResults?: unknown }): ProbeEvidenceModel | null;
export function probeResultEvents(events: DataItem[]): DataItem[];
export function networkOutcomeSentence(network: NetworkEvidence | null): string;
export function exposedVerdictLabel(checkId: unknown, outcome: unknown): string;
