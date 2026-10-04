export type EvidenceInspectorEntry = 'finding' | 'group_member' | 'check_result' | 'provider' | 'artifact' | 'report' | 'audit';
export type EvidenceProviderFamily = 'waf' | 'cdn' | 'cloud' | 'dns' | 'origin_hosting';

export type EvidenceInspectorRef = {
  entry: EvidenceInspectorEntry;
  finding_id?: string;
  target_id?: string;
  check_id?: string;
  test_run_id?: string;
  family?: EvidenceProviderFamily;
  evidence_id?: string;
  report_id?: string;
  audit_id?: string;
};

export type InspectorState = 'loading' | 'ready' | 'no_refs' | 'partial' | 'denied' | 'not_found' | 'unavailable' | 'unbound' | 'expired' | 'auth';

export type InspectorObservation = {
  testRunId: string;
  verdictId: string;
  evidenceIds: string[];
  observedAt: string;
  relationship: string;
  integrity: {
    status: string;
    verifiedAt: string;
    method: string;
    refs: Array<{ evidenceId: string; status: string; verifiedAt: string; method: string }>;
  } | null;
  closesFinding: boolean;
};

export type InspectorSummaryBlock = { status: string; fields: Array<{ key: string; value: string }> };

export type EvidenceContextModel = {
  state: InspectorState;
  missingEvidenceIds: string[];
  proof: Record<'methods' | 'matched_signals' | 'cnames' | 'addresses' | 'fingerprints', string[]> | null;
  provider: { confidence: number | null; conflict: boolean; corpus: string; source: string };
  ref: EvidenceInspectorRef | null;
  subject: Record<string, string>;
  answer: { outcome: string; explanation: string; expected: string; observed: string } | null;
  limitations: string[];
  primary: InspectorObservation | null;
  /** Immutable originating record ids for a finding, present even when it cites no evidence. */
  originating: InspectorObservation | null;
  later: InspectorObservation | null;
  alternatives: InspectorObservation[];
  request: InspectorSummaryBlock;
  response: InspectorSummaryBlock;
  evaluation: InspectorSummaryBlock;
  unavailableReason: string;
};

export declare const EVIDENCE_INSPECTOR_EVENT: string;
export declare const INSPECTOR_ENTRIES: readonly EvidenceInspectorEntry[];
export declare const PROVIDER_FAMILIES: readonly EvidenceProviderFamily[];

export declare function isSafeInspectorId(value: unknown): boolean;
export declare function normalizeInspectorRef(input: unknown): EvidenceInspectorRef | null;
export declare function inspectorRefKey(input: unknown): string;
export declare function parseInspectorRef(hashOrHref: string): EvidenceInspectorRef | null;
export declare function stripInspectorParams(hashOrHref: string): string;
export declare function buildEvidenceInspectorHref(ref: EvidenceInspectorRef, baseHref?: string): string;
export declare function openEvidenceInspector(ref: EvidenceInspectorRef, options?: { focusKey?: string }): boolean;
export declare function replaceEvidenceInspector(ref: EvidenceInspectorRef): boolean;
export declare function inspectorOriginFocusKey(): string;
export declare function closeEvidenceInspector(): void;
export declare function evidenceContextPath(ref: EvidenceInspectorRef): string;
export declare function classifyInspectorError(error: unknown): { state: 'denied' | 'not_found' | 'route_missing' | 'auth' | 'unavailable'; permission: string };
export declare function normalizeEvidenceContext(payload: unknown, ref: EvidenceInspectorRef | null): EvidenceContextModel;
export declare function createInspectorGeneration(): {
  begin(scopeKey: string, refKey: string): string;
  isCurrent(token: string): boolean;
  cancel(): void;
};
export declare function limitationLabel(code: string): string;
export declare function fallbackRecordPath(ref: EvidenceInspectorRef): string;
export declare function fallbackContextFromRecord(ref: EvidenceInspectorRef, source: unknown): { payload: Record<string, unknown> | null; mismatch: boolean; unbound?: boolean };
export declare function looksLikeCredential(value: unknown): boolean;
export declare function sanitizeRouteParams(input: URLSearchParams | string): URLSearchParams;
export declare function inspectorLoadKey(scopeKey: string, refKey: string): string;
