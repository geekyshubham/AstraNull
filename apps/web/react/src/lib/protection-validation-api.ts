import { requestJson } from './api';
import { parseExpectationConflicts, type ExpectationConflict } from './expectation-conflicts.mjs';
import type { DataItem, PortalConfig, Session } from './types';

// Typed client for docs/api.md "Application entry paths and firewall change acceptance"; reads are passive and starts reuse gated run routes.

export type ProtectionLayer = 'waf' | 'cdn_edge' | 'network_firewall' | 'ddos';
export type RelationKind = 'primary_route' | 'alternate_hostname' | 'declared_api_url' | 'declared_login_url' | 'origin' | 'fallback_backend_route';
export type ExpectedBehavior = 'must_be_protected_by_layers' | 'intentionally_public' | 'must_not_be_reachable';
export type LayerExpectedOutcome = 'enforce' | 'allow' | 'not_reachable' | 'no_expectation';
export type PathOutcome =
  | 'intentional_public_access'
  | 'reachability_exposure'
  | 'weaker_observed_enforcement'
  | 'suspected_alternate_application_route'
  | 'scoped_application_bypass'
  | 'consistent_enforcement'
  | 'inconclusive'
  | 'not_tested'
  | 'skipped';
export type FirewallStatus = 'matched' | 'regression' | 'improvement' | 'inconclusive' | 'not_tested' | 'stale' | 'not_comparable';

export type EvidenceRef = {
  test_run_id: string;
  check_id: string;
  check_version: string | null;
  scenario_version: string | null;
  verdict_id: string | null;
  evidence_ids: string[];
  target_id: string;
  observed_at: string;
  run_status: string;
  finalized: boolean;
  source_perspective: string | null;
  worker_id: string | null;
};

export type Freshness = { fresh?: boolean; stale?: boolean; age_seconds?: number; expires_at?: string; captured_at?: string } | null;

export type EntryPath = {
  id: string;
  anchor_target_id: string;
  entry_target_id: string;
  entry_target_value: string;
  relation_kind: string;
  owner: string;
  purpose: string;
  expected_behavior: string;
  required_layers: string[];
  origin_binding_id: string | null;
  status: string;
  declaration_version: number | null;
  declaration_digest: string;
  currently_authorized: boolean | null;
  authorization_state: string;
  created_at: string;
  archived_at: string | null;
};

export type LayerEvidence = {
  layer: string;
  declared_intent: string;
  vendor_detection: string;
  observed_enforcement: string;
  application_identity: string;
  suspected_bypass: string;
  confirmed_scoped_bypass: string;
  attribution: string;
  evidence_limitations: string[];
  evidence_refs: EvidenceRef[];
  freshness: Freshness;
  observation: string;
};

export type MatrixPath = {
  entry_path_id: string;
  anchor_target_id: string;
  entry_target_id: string;
  entry_target_value: string;
  relation_kind: string;
  expected_behavior: string;
  required_layers: string[];
  origin_binding_id: string | null;
  status: string;
  declaration_version: number | null;
  outcome: string;
  attribution: string;
  observation: string;
  layers: LayerEvidence[];
  evidence_refs: EvidenceRef[];
  latest_comparison_id: string | null;
  freshness: Freshness;
  limitations: string[];
};

export type ProtectionMatrix = {
  target_id: string;
  generated_at: string;
  connectors_required: boolean;
  scope_complete?: boolean;
  paths: MatrixPath[];
  limitations: string[];
};

export type ComparisonExpectation = { scenario: string; layer_outcomes: Record<string, LayerExpectedOutcome> };

export type ComparisonPlanItem = {
  entry_path_id: string;
  target_id: string;
  declaration_digest: string;
  check_id: string;
  check_version: string | null;
  origin_binding_id: string | null;
  eligible: boolean;
  ineligible_reason: string | null;
};

export type ComparisonPlan = {
  plan_digest: string;
  anchor_target_id: string;
  primary_entry_path_id: string;
  expectation: DataItem | null;
  items: ComparisonPlanItem[];
  expectation_conflicts: ExpectationConflict[];
  limitations: string[];
};

export type Compatibility = { comparable: boolean; stale: boolean; reasons: string[] } | null;

export type PathComparisonItem = {
  entry_path_id: string;
  scenario: string;
  outcome: string;
  attribution: string;
  test_run_id: string | null;
  reasons: string[];
  compatibility_reasons: string[];
  evidence_refs: EvidenceRef[];
  limitations: string[];
};

export type PathComparison = {
  id: string;
  status: string;
  plan_digest: string;
  anchor_target_id: string;
  primary_entry_path_id: string;
  expectation: DataItem | null;
  items: PathComparisonItem[];
  compatibility: Compatibility;
  summary: DataItem | null;
  evaluated_at: string | null;
  created_at: string | null;
};

export type FirewallExpectation = {
  id: string;
  destination_target_id: string;
  protocol: string;
  port: number | null;
  service_endpoint: { service: string; port: number; path?: string } | null;
  expected: string;
  source_perspective: string;
  change_id: string;
  owner: string;
  pre_post_mapping: { pre_destination_target_id: string; post_destination_target_id: string } | null;
  status: string;
  expectation_version: number | null;
  created_at: string;
};

export type FirewallBaselineEntry = {
  expectation_id: string;
  expectation_version: number | null;
  target_id: string;
  references: EvidenceRef[];
  captured_at: string;
};

export type FirewallBaseline = {
  id: string;
  change_id: string;
  captured_at: string;
  freshness_window_seconds: number | null;
  baseline_digest: string;
  status: string;
  entries: FirewallBaselineEntry[];
};

export type FirewallComparisonItem = {
  expectation_id: string;
  status: string;
  gap_kind: string | null;
  expectation_met: boolean | null;
  pre_state: string;
  post_state: string;
  reasons: string[];
  compatibility_reasons: string[];
  evidence_refs: EvidenceRef[];
  limitations: string[];
};

export type FirewallComparison = {
  id: string;
  baseline_id: string;
  compatibility: Compatibility;
  items: FirewallComparisonItem[];
  summary: DataItem | null;
  limitations: string[];
  evaluated_at: string;
};

export type RunSummary = { id: string; check_id: string; target_id: string; status: string; created_at: string; completed_at: string; verdict: string; source_perspective: string };

export type Page<T> = { items: T[]; count: number; nextCursor: string };

export type PvFailure =
  | { state: 'unsupported' }
  | { state: 'disabled' }
  | { state: 'forbidden'; message: string }
  | { state: 'transport_error'; message: string }
  | { state: 'unavailable'; code: string; status: number; message: string };

export type PvResult<T> = { state: 'ready'; value: T } | PvFailure;

export type Written<T> = { record: T; replayed: boolean };

function rec(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

function strOrNull(value: unknown): string | null {
  const text = str(value);
  return text ? text : null;
}

function num(value: unknown): number | null {
  const parsed = typeof value === 'number' ? value : typeof value === 'string' && value.trim() ? Number(value) : NaN;
  return Number.isFinite(parsed) ? parsed : null;
}

function bool(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.map(str).filter(Boolean) : [];
}

function records(value: unknown): DataItem[] {
  return Array.isArray(value) ? value.map(rec).filter((item): item is DataItem => item !== null) : [];
}

export function pvErrorCode(err: unknown): string {
  return str(rec((err as { payload?: unknown })?.payload)?.error);
}

export function pvErrorStatus(err: unknown): number {
  return Number((err as { status?: number })?.status) || 0;
}

export function isAbort(err: unknown) {
  return (err as { name?: string })?.name === 'AbortError';
}

/** Missing route (bare 404, 405, 501, unwired Postgres) is unsupported; the tenant gate is disabled; no HTTP status is a transport error. */
export function pvFailureOf(err: unknown, options: { missingMeansUnsupported?: boolean } = {}): PvFailure {
  const status = pvErrorStatus(err);
  const code = pvErrorCode(err);
  const message = err instanceof Error ? err.message : 'Request failed.';
  if (!status) return { state: 'transport_error', message };
  if (status === 404 && code === 'protection_validation_disabled') return { state: 'disabled' };
  if (status === 403) return { state: 'forbidden', message };
  if (status === 501 || status === 405) return { state: 'unsupported' };
  if (status === 503 && code === 'postgres_route_not_wired') return { state: 'unsupported' };
  if (status === 404 && (options.missingMeansUnsupported ?? true) && (!code || code === 'not_found')) return { state: 'unsupported' };
  return { state: 'unavailable', code: code || String(status), status, message };
}

async function read<T>(config: PortalConfig, session: Session, path: string, parse: (payload: DataItem) => T, signal?: AbortSignal, options: { missingMeansUnsupported?: boolean } = {}): Promise<PvResult<T>> {
  try {
    const payload = rec(await requestJson(config, session, path, { signal })) ?? {};
    return { state: 'ready', value: parse(payload) };
  } catch (err) {
    if (isAbort(err)) throw err;
    return pvFailureOf(err, options);
  }
}

async function write<T>(config: PortalConfig, session: Session, path: string, body: unknown, parse: (payload: DataItem) => T): Promise<Written<T>> {
  const payload = rec(await requestJson(config, session, path, { method: 'POST', body })) ?? {};
  return { record: parse(payload), replayed: payload.replayed === true };
}

function query(params: Record<string, string | number | undefined | null>) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

function page<T>(payload: DataItem, parse: (item: DataItem) => T): Page<T> {
  const items = records(payload.items).map(parse);
  return { items, count: num(payload.count) ?? items.length, nextCursor: str(payload.next_cursor) };
}

export function parseEvidenceRef(value: unknown): EvidenceRef {
  const ref = rec(value) ?? {};
  return {
    test_run_id: str(ref.test_run_id),
    check_id: str(ref.check_id),
    check_version: strOrNull(ref.check_version),
    scenario_version: strOrNull(ref.scenario_version),
    verdict_id: strOrNull(ref.verdict_id),
    evidence_ids: strings(ref.evidence_ids),
    target_id: str(ref.target_id),
    observed_at: str(ref.observed_at),
    run_status: str(ref.run_status),
    finalized: ref.finalized === true,
    source_perspective: strOrNull(ref.source_perspective),
    worker_id: strOrNull(ref.worker_id),
  };
}

function refs(value: unknown) {
  return records(value).map(parseEvidenceRef).filter((ref) => ref.test_run_id);
}

function freshness(value: unknown): Freshness {
  return rec(value) as Freshness;
}

export function parseEntryPath(value: unknown): EntryPath {
  const item = rec(value) ?? {};
  return {
    id: str(item.id),
    anchor_target_id: str(item.anchor_target_id),
    entry_target_id: str(item.entry_target_id),
    entry_target_value: str(item.entry_target_value) || str(rec(item.entry_target)?.value),
    relation_kind: str(item.relation_kind),
    owner: str(item.owner),
    purpose: str(item.purpose),
    expected_behavior: str(item.expected_behavior),
    required_layers: strings(item.required_layers),
    origin_binding_id: strOrNull(item.origin_binding_id),
    status: str(item.status) || 'active',
    declaration_version: num(item.declaration_version),
    declaration_digest: str(item.declaration_digest),
    currently_authorized: bool(item.currently_authorized),
    authorization_state: str(item.authorization_state),
    created_at: str(item.created_at),
    archived_at: strOrNull(item.archived_at),
  };
}

function parseLayer(value: unknown): LayerEvidence {
  const layer = rec(value) ?? {};
  return {
    layer: str(layer.layer),
    declared_intent: str(layer.declared_intent),
    vendor_detection: str(layer.vendor_detection),
    observed_enforcement: str(layer.observed_enforcement),
    application_identity: str(layer.application_identity),
    suspected_bypass: str(layer.suspected_bypass),
    confirmed_scoped_bypass: str(layer.confirmed_scoped_bypass),
    attribution: str(layer.attribution),
    evidence_limitations: strings(layer.evidence_limitations),
    evidence_refs: refs(layer.evidence_refs),
    freshness: freshness(layer.freshness),
    observation: str(layer.observation),
  };
}

export function parseMatrix(value: unknown): ProtectionMatrix {
  const payload = rec(value) ?? {};
  return {
    target_id: str(payload.target_id),
    generated_at: str(payload.generated_at),
    connectors_required: payload.connectors_required === true,
    scope_complete: typeof payload.scope_complete === 'boolean' ? payload.scope_complete : undefined,
    limitations: strings(payload.limitations),
    paths: records(payload.paths).map((path) => ({
      entry_path_id: str(path.entry_path_id),
      anchor_target_id: str(path.anchor_target_id),
      entry_target_id: str(path.entry_target_id),
      entry_target_value: str(path.entry_target_value) || str(rec(path.entry_target)?.value),
      relation_kind: str(path.relation_kind),
      expected_behavior: str(path.expected_behavior),
      required_layers: strings(path.required_layers),
      origin_binding_id: strOrNull(path.origin_binding_id),
      status: str(path.status),
      declaration_version: num(path.declaration_version),
      outcome: str(path.outcome) || 'not_tested',
      attribution: str(path.attribution),
      observation: str(path.observation),
      layers: records(path.layers).map(parseLayer),
      evidence_refs: refs(path.evidence_refs),
      latest_comparison_id: strOrNull(path.latest_comparison_id),
      freshness: freshness(path.freshness),
      limitations: strings(path.limitations),
    })).filter((path) => path.entry_path_id),
  };
}

function parseCompatibility(value: unknown): Compatibility {
  const compat = rec(value);
  if (!compat) return null;
  return { comparable: compat.comparable === true, stale: compat.stale === true, reasons: strings(compat.reasons) };
}

function parsePlan(value: unknown): ComparisonPlan {
  const payload = rec(value) ?? {};
  return {
    plan_digest: str(payload.plan_digest),
    anchor_target_id: str(payload.anchor_target_id),
    primary_entry_path_id: str(payload.primary_entry_path_id),
    expectation: rec(payload.expectation),
    expectation_conflicts: parseExpectationConflicts(payload.expectation_conflicts),
    limitations: strings(payload.limitations),
    items: records(payload.items).map((item) => ({
      entry_path_id: str(item.entry_path_id),
      target_id: str(item.target_id),
      declaration_digest: str(item.declaration_digest),
      check_id: str(item.check_id),
      check_version: strOrNull(item.check_version),
      origin_binding_id: strOrNull(item.origin_binding_id),
      eligible: item.eligible === true,
      ineligible_reason: strOrNull(item.ineligible_reason),
    })),
  };
}

export function parsePathComparison(value: unknown): PathComparison {
  const payload = rec(value) ?? {};
  return {
    id: str(payload.id),
    status: str(payload.status),
    plan_digest: str(payload.plan_digest),
    anchor_target_id: str(payload.anchor_target_id),
    primary_entry_path_id: str(payload.primary_entry_path_id),
    expectation: rec(payload.expectation),
    compatibility: parseCompatibility(payload.compatibility),
    summary: rec(payload.summary),
    evaluated_at: strOrNull(payload.evaluated_at),
    created_at: strOrNull(payload.created_at),
    items: records(payload.items).map((item) => ({
      entry_path_id: str(item.entry_path_id),
      scenario: str(item.scenario),
      outcome: str(item.outcome) || 'not_tested',
      attribution: str(item.attribution),
      test_run_id: strOrNull(item.test_run_id),
      reasons: strings(item.reasons),
      compatibility_reasons: strings(item.compatibility_reasons),
      evidence_refs: refs(item.evidence_refs),
      limitations: strings(item.limitations),
    })),
  };
}

export function parseFirewallExpectation(value: unknown): FirewallExpectation {
  const item = rec(value) ?? {};
  const endpoint = rec(item.service_endpoint);
  const mapping = rec(item.pre_post_mapping);
  return {
    id: str(item.id),
    destination_target_id: str(item.destination_target_id),
    protocol: str(item.protocol),
    port: num(item.port),
    service_endpoint: endpoint ? { service: str(endpoint.service), port: num(endpoint.port) ?? 0, ...(str(endpoint.path) ? { path: str(endpoint.path) } : {}) } : null,
    expected: str(item.expected),
    source_perspective: str(item.source_perspective),
    change_id: str(item.change_id),
    owner: str(item.owner),
    pre_post_mapping: mapping ? { pre_destination_target_id: str(mapping.pre_destination_target_id), post_destination_target_id: str(mapping.post_destination_target_id) } : null,
    status: str(item.status) || 'active',
    expectation_version: num(item.expectation_version),
    created_at: str(item.created_at),
  };
}

export function parseFirewallBaseline(value: unknown): FirewallBaseline {
  const payload = rec(value) ?? {};
  return {
    id: str(payload.id),
    change_id: str(payload.change_id),
    captured_at: str(payload.captured_at),
    freshness_window_seconds: num(payload.freshness_window_seconds),
    baseline_digest: str(payload.baseline_digest),
    status: str(payload.status) || 'active',
    entries: records(payload.entries).map((entry) => ({
      expectation_id: str(entry.expectation_id),
      expectation_version: num(entry.expectation_version),
      target_id: str(entry.target_id),
      references: refs(entry.references),
      captured_at: str(entry.captured_at),
    })),
  };
}

export function parseFirewallComparison(value: unknown): FirewallComparison {
  const payload = rec(value) ?? {};
  return {
    id: str(payload.id),
    baseline_id: str(payload.baseline_id),
    compatibility: parseCompatibility(payload.compatibility),
    summary: rec(payload.summary),
    limitations: strings(payload.limitations),
    evaluated_at: str(payload.evaluated_at),
    items: records(payload.items).map((item) => ({
      expectation_id: str(item.expectation_id),
      status: str(item.status) || 'not_tested',
      gap_kind: strOrNull(item.gap_kind),
      expectation_met: bool(item.expectation_met),
      pre_state: str(item.pre_state),
      post_state: str(item.post_state),
      reasons: strings(item.reasons),
      compatibility_reasons: strings(item.compatibility_reasons),
      evidence_refs: refs(item.evidence_refs),
      limitations: strings(item.limitations),
    })),
  };
}

function parseRun(value: unknown): RunSummary {
  const run = rec(value) ?? {};
  const verdict = rec(run.verdict);
  return {
    id: str(run.id) || str(run.run_id),
    check_id: str(run.check_id),
    target_id: str(run.target_id),
    status: str(run.status),
    created_at: str(run.created_at),
    completed_at: str(run.completed_at),
    verdict: str(verdict?.verdict) || str(run.verdict),
    source_perspective: str(run.source_perspective) || str(rec(run.provenance)?.source_perspective),
  };
}

const enc = encodeURIComponent;

export function listEntryPaths(config: PortalConfig, session: Session, targetId: string, options: { cursor?: string; limit?: number; status?: string } = {}, signal?: AbortSignal) {
  return read(config, session, `/v1/targets/${enc(targetId)}/entry-paths${query({ cursor: options.cursor, limit: options.limit ?? 50, status: options.status })}`, (payload) => page(payload, parseEntryPath), signal);
}

export function getEntryPath(config: PortalConfig, session: Session, entryPathId: string, signal?: AbortSignal) {
  return read(config, session, `/v1/entry-paths/${enc(entryPathId)}`, parseEntryPath, signal, { missingMeansUnsupported: false });
}

export function getProtectionMatrix(config: PortalConfig, session: Session, targetId: string, signal?: AbortSignal) {
  return read(config, session, `/v1/targets/${enc(targetId)}/protection-validation`, parseMatrix, signal);
}

export function createEntryPath(config: PortalConfig, session: Session, targetId: string, body: DataItem) {
  return write(config, session, `/v1/targets/${enc(targetId)}/entry-paths`, body, parseEntryPath);
}

export function archiveEntryPath(config: PortalConfig, session: Session, entryPathId: string) {
  return write(config, session, `/v1/entry-paths/${enc(entryPathId)}/archive`, undefined, parseEntryPath);
}

export type ComparisonRequest = { anchor_target_id: string; primary_entry_path_id: string; entry_path_ids: string[]; expectation: ComparisonExpectation };

/** Passive: computes the reviewed plan and starts nothing. */
export async function planEntryPathComparison(config: PortalConfig, session: Session, body: ComparisonRequest) {
  const payload = await requestJson(config, session, '/v1/entry-path-comparisons', { method: 'POST', body: { mode: 'plan', ...body } });
  return parsePlan(payload);
}

/** Starts only the reviewed plan; the server returns 409 reviewed_plan_mismatch if anything changed. */
export async function startEntryPathComparison(config: PortalConfig, session: Session, body: ComparisonRequest, reviewedPlanDigest: string) {
  const payload = await requestJson(config, session, '/v1/entry-path-comparisons', { method: 'POST', body: { mode: 'start', ...body, reviewed_plan_digest: reviewedPlanDigest } });
  return parsePathComparison(payload);
}

export function listEntryPathComparisons(config: PortalConfig, session: Session, anchorTargetId: string, options: { cursor?: string; limit?: number } = {}, signal?: AbortSignal) {
  return read(config, session, `/v1/entry-path-comparisons${query({ anchor_target_id: anchorTargetId, cursor: options.cursor, limit: options.limit ?? 20 })}`, (payload) => page(payload, parsePathComparison), signal);
}

export function getEntryPathComparison(config: PortalConfig, session: Session, comparisonId: string, signal?: AbortSignal) {
  return read(config, session, `/v1/entry-path-comparisons/${enc(comparisonId)}`, parsePathComparison, signal, { missingMeansUnsupported: false });
}

/** Stop: skips outstanding paths and cancels running checks through the existing run cancel path. */
export function cancelEntryPathComparison(config: PortalConfig, session: Session, comparisonId: string, reason: string) {
  return write(config, session, `/v1/entry-path-comparisons/${enc(comparisonId)}/cancel`, { reason }, parsePathComparison);
}

export function listFirewallExpectations(config: PortalConfig, session: Session, filters: { destination_target_id?: string; change_id?: string; status?: string; cursor?: string; limit?: number } = {}, signal?: AbortSignal) {
  return read(config, session, `/v1/firewall-expectations${query({ ...filters, limit: filters.limit ?? 50 })}`, (payload) => page(payload, parseFirewallExpectation), signal);
}

export function createFirewallExpectation(config: PortalConfig, session: Session, body: DataItem) {
  return write(config, session, '/v1/firewall-expectations', body, parseFirewallExpectation);
}

export function archiveFirewallExpectation(config: PortalConfig, session: Session, expectationId: string) {
  return write(config, session, `/v1/firewall-expectations/${enc(expectationId)}/archive`, undefined, parseFirewallExpectation);
}

/** Captures an immutable baseline from finalized runs; sends no traffic. */
export function captureFirewallBaseline(config: PortalConfig, session: Session, body: { change_id: string; expectation_ids: string[]; test_run_ids: string[]; freshness_window_seconds?: number }) {
  return write(config, session, '/v1/firewall-baselines', body, parseFirewallBaseline);
}

export function listFirewallBaselines(config: PortalConfig, session: Session, filters: { change_id?: string; cursor?: string; limit?: number } = {}, signal?: AbortSignal) {
  return read(config, session, `/v1/firewall-baselines${query({ ...filters, limit: filters.limit ?? 20 })}`, (payload) => page(payload, parseFirewallBaseline), signal);
}

export function getFirewallBaseline(config: PortalConfig, session: Session, baselineId: string, signal?: AbortSignal) {
  return read(config, session, `/v1/firewall-baselines/${enc(baselineId)}`, parseFirewallBaseline, signal, { missingMeansUnsupported: false });
}

/** Evaluates explicitly selected post-change runs against a baseline; sends no traffic. */
export function evaluateFirewallComparison(config: PortalConfig, session: Session, body: { baseline_id: string; post_test_run_ids: string[] }) {
  return write(config, session, '/v1/firewall-comparisons', body, parseFirewallComparison);
}

export function listFirewallComparisons(config: PortalConfig, session: Session, filters: { change_id?: string; baseline_id?: string; cursor?: string; limit?: number } = {}, signal?: AbortSignal) {
  return read(config, session, `/v1/firewall-comparisons${query({ ...filters, limit: filters.limit ?? 20 })}`, (payload) => page(payload, parseFirewallComparison), signal);
}

export function getFirewallComparison(config: PortalConfig, session: Session, comparisonId: string, signal?: AbortSignal) {
  return read(config, session, `/v1/firewall-comparisons/${enc(comparisonId)}`, parseFirewallComparison, signal, { missingMeansUnsupported: false });
}

export type TargetCandidate = { id: string; value: string; kind: string; verification_state: string };

/** One server page of existing declared targets; the list is never treated as the whole estate. */
export function listTargetCandidates(config: PortalConfig, session: Session, options: { q?: string; cursor?: string; limit?: number } = {}, signal?: AbortSignal) {
  return read(config, session, `/v1/targets${query({ unit: 'target', q: options.q, cursor: options.cursor, limit: options.limit ?? 25 })}`, (payload) => {
    const block = rec(payload.page);
    const items = records(block?.items ?? payload.items).map((item) => ({
      id: str(item.id),
      value: str(item.value),
      kind: str(item.kind),
      verification_state: str(item.verification_state) || str(rec(item.verification)?.state),
    })).filter((item) => item.id);
    return { items, count: items.length, nextCursor: str(block?.next_cursor) || str(payload.next_cursor) } as Page<TargetCandidate>;
  }, signal, { missingMeansUnsupported: false });
}

export function listTargetRuns(config: PortalConfig, session: Session, targetId: string, signal?: AbortSignal) {
  return read(config, session, `/v1/test-runs${query({ target_id: targetId, limit: 100 })}`, (payload) => records(payload.items).map(parseRun).filter((run) => run.id), signal, { missingMeansUnsupported: false });
}

export async function getRunStatus(config: PortalConfig, session: Session, runId: string, signal?: AbortSignal) {
  const payload = rec(await requestJson(config, session, `/v1/test-runs/${enc(runId)}`, { signal })) ?? {};
  return str(payload.status) || str(rec(payload.run)?.status);
}

export function cancelRun(config: PortalConfig, session: Session, runId: string, reason: string) {
  return requestJson(config, session, `/v1/test-runs/${enc(runId)}/cancel`, { method: 'POST', body: { reason } });
}

/** Reviewed single-check retest through the existing gated run start; no destination fields are sent. */
export async function startReviewedRetest(config: PortalConfig, session: Session, body: { check_id: string; target_group_id: string; target_id: string }) {
  const payload = rec(await requestJson(config, session, '/v1/test-runs', { method: 'POST', body })) ?? {};
  return str(payload.id);
}
