import type { DataItem } from './types';

export const MAX_NETWORK_RULES: number;
export const MAX_MARKER_PATHS: number;
export const MAX_CONNECTION_LIMITS: number;
export const MAX_NOTE: number;
export const MAX_HEADER_NAME: number;
export const MAX_HEADER_VALUE: number;
export const MAX_PATH: number;

export type DeclarationKey = 'network_policy' | 'waf.rate_limit_canary' | 'canary_sink' | 'connection_limits' | 'origin.lockdown_expected' | 'perspectives';
export type DeclarationSection = 'network' | 'rate_limit' | 'canary_sink' | 'connection_limits' | 'origin' | 'perspectives';
export const DECLARATION_KEYS: Readonly<Record<DeclarationKey, Readonly<{ label: string; cta: string; section: DeclarationSection; unlocks: string }>>>;
export const EXPECTED_WAF_ACTIONS: ReadonlyArray<Readonly<{ value: 'block' | 'challenge' | 'block_or_challenge'; label: string; hint: string }>>;
export type RateLimitExpectedAction = 'block' | 'block_or_challenge';
export const RATE_LIMIT_EXPECTED_ACTIONS: ReadonlyArray<Readonly<{ value: RateLimitExpectedAction; label: string; hint: string }>>;

export type NetworkRuleDraft = { key: string; protocol: string; port: string; action: string; address_family: string; note: string };
export type ConnectionLimitDraft = { key: string; port: string; max: string };
export type DeclarationsDraft = {
  network_policy: NetworkRuleDraft[];
  block_header_name: string;
  block_header_value: string;
  block_status_codes: string;
  expected_action: string;
  rate_limit_enabled: boolean;
  rate_path: string;
  rate_method: string;
  rate_threshold: string;
  rate_window: string;
  rate_expected_action: string;
  marker_paths: string[];
  origin_lockdown: '' | 'expected' | 'not_expected';
  allowlisted_perspective_ids: string[];
  denied_perspective_ids: string[];
  canary_sink_url: string;
  connection_limits: ConnectionLimitDraft[];
};

export function emptyNetworkRule(): NetworkRuleDraft;
export function emptyConnectionLimit(): ConnectionLimitDraft;
export function draftFromDeclarations(input: unknown): DeclarationsDraft;
export function declarationsFromDraft(draft: DeclarationsDraft): Record<string, unknown>;
export function declarationsDraftSignature(draft: DeclarationsDraft): string;
export function validateDeclarationsDraft(draft: DeclarationsDraft, options?: { target?: DataItem | null; perspectiveIds?: string[] | null }): Record<string, string>;
export function serverFieldErrors(payload: unknown): Record<string, string>;
export function declarationPresent(declarations: unknown, key: string): boolean;
export function declarationSummary(declarations: unknown): {
  networkRules: number; deniedRules: number; blockSignature: boolean; expectedAction: string; rateLimitCanary: boolean;
  markerPaths: number; originLockdown: boolean | null; perspectives: number; canarySink: boolean; connectionLimits: number;
  updatedAt: string; updatedBy: string; empty: boolean;
};
export type CheckPrerequisiteState = 'ready' | 'soc_only' | 'checking' | 'needs_port' | 'needs_deny_or_port' | 'needs_declaration' | 'needs_perspectives' | 'needs_setup' | 'unavailable';
export type CheckPrerequisite = { state: CheckPrerequisiteState; label: string; missing: string[]; detail: string; reason: string; cta: string; section: string };
export type AdditionalInputReason =
  | 'port_required' | 'port_or_declared_deny_required' | 'declared_tcp_deny_required' | 'declared_udp_deny_required'
  | 'declared_connection_limit_required' | 'declared_rate_limit_canary_required' | 'declared_origin_lockdown_required'
  | 'declared_perspectives_required' | 'origin_binding_required' | 'two_perspectives_required' | 'target_bound_direct_address_required'
  | 'declared_probe_path_required' | 'alert_webhook_required' | 't7_probe_module_pending' | 'invalid_check_definition';
export type AdditionalInputReasonCopy = Readonly<{ state: CheckPrerequisiteState; label: string; cta: string; section: string; declaration: string; detail: string }>;
export const ADDITIONAL_INPUT_REASON_COPY: Readonly<Record<AdditionalInputReason, AdditionalInputReasonCopy>>;
export type RequiredDeclarationCopy = Readonly<{ label: string; cta: string; section: string; unlocks: string }>;
export const REQUIRED_DECLARATION_COPY: Readonly<Record<DeclarationKey | 'origin_binding', RequiredDeclarationCopy>>;
export const UNKNOWN_DECLARATION_COPY: RequiredDeclarationCopy;
export function requiredDeclarationCopy(key: unknown): RequiredDeclarationCopy;
export function inlineDeclarationLabel(label: unknown): string;
export function requiredDeclarationSentence(keys: unknown): string;
export function additionalInputReasonCopy(reason: unknown): AdditionalInputReasonCopy | null;
export function targetRequirementForReason(reason: unknown): AdditionalInputReasonCopy | null;
export function targetFixableReason(reason: unknown): boolean;
export function needsTargetAnswer(check: unknown): boolean;
export type ServerRunnableAnswer = { runnable: boolean; reason: string };
export function targetRunnableIndex(items: unknown): Map<string, ServerRunnableAnswer>;
export function checkPrerequisite(check: unknown, context?: { declarations?: unknown; perspectiveCount?: number; target?: DataItem | null; serverRunnable?: boolean | ServerRunnableAnswer; serverRunnableIndex?: Map<string, ServerRunnableAnswer | boolean> | null }): CheckPrerequisite;
export function prerequisiteCta(prerequisite: CheckPrerequisite | null | undefined): string;
export function prerequisiteTone(prerequisite: CheckPrerequisite | null | undefined): 'muted' | 'warn';
export function prerequisiteSection(prerequisite: CheckPrerequisite | null | undefined): string;
export function declarationsEtag(doc: unknown): string;
export type DeclarationsSaveConflict = { kind: 'conflict' | 'precondition'; revision: number | null; etag: string };
export function declarationsSaveConflict(error: unknown): DeclarationsSaveConflict | null;
export type DeclarationsDiffRow = { section: string; label: string; theirs: string; yours: string };
export function declarationsDraftDiff(latestDoc: unknown, draft: DeclarationsDraft | null): DeclarationsDiffRow[];
export const TARGET_LINK_SECTIONS: Readonly<Record<'origin_relations', Readonly<{ tab: string; section: string }>>>;
export function controlsHref(targetId: string, section?: string): string;
