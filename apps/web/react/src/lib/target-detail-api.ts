import { requestJson } from './api';
import { apiErrorMessage } from './error-messages';
import type { DataItem, PortalConfig, Session } from './types';

export type OwnershipChallenge = {
  id: string;
  target_id: string | null;
  record_name: string;
  record_value: string;
  ttl_seconds: number;
  state: string;
  issued_at: string;
  expires_at: string;
  resolved_at: string | null;
  last_checked_at: string | null;
} | null;

export type TargetDetailPayload = {
  target: DataItem | null;
  verification: DataItem | null;
  waf_posture: DataItem | null;
  edge_detection: DataItem | null;
  edge_detection_request?: DataItem | null;
  /** Additive server contract; null until the backend records it. */
  protection_profile?: DataItem | null;
  /** Applicable check-target pair coverage; null until the backend reports it. */
  coverage?: DataItem | null;
  /** Typed declaration on the target; null when absent or unsupported. */
  declaration?: DataItem | null;
  checks_applied: DataItem[];
  runs_recent: DataItem[];
  findings: DataItem[];
  loa: DataItem | null;
  counts: DataItem | null;
  tags: string[];
  ownership_challenge: OwnershipChallenge;
  meta?: DataItem | null;
  sectionMeta?: {
    runs: DataItem | null;
    findings: DataItem | null;
    checks: DataItem | null;
    waf: DataItem | null;
  };
  error?: string;
  /** HTTP status of a failed detail read, so 404, 403 and other failures stay distinct. */
  status?: number;
  loading: boolean;
};

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function asRecord(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as DataItem) : null;
}

function readSectionEmptyMeta(meta: DataItem | null, key: string): DataItem | null {
  const reason = getString(meta, [key]);
  return reason ? { empty_reason: reason } : null;
}

/** Read tags from the ADR-0008 top-level `tags` field, falling back to target metadata. */
export function readTargetTags(target: DataItem | null): string[] {
  if (!target) return [];
  const direct = Array.isArray(target.tags) ? target.tags : null;
  const metadata = asRecord(target.metadata) ?? asRecord(target.metadata_json);
  const fromMeta = metadata && Array.isArray(metadata.tags) ? metadata.tags : null;
  const source = direct ?? fromMeta ?? [];
  const out: string[] = [];
  for (const entry of source) {
    const text = typeof entry === 'string' ? entry.trim().toLowerCase() : '';
    if (text && !out.includes(text)) out.push(text);
    if (out.length >= 16) break;
  }
  return out;
}

/**
 * Read the active ownership challenge for THIS target from the group's DNS-ownership list.
 * A pending, unexpired challenge wins; otherwise the most recently issued one is surfaced so
 * a resolved record still shows the exact TXT that proved ownership. Never throws.
 */
async function fetchOwnershipChallenge(
  config: PortalConfig,
  session: Session,
  targetId: string,
): Promise<OwnershipChallenge> {
  if (!targetId) return null;
  try {
    const payload = await requestJson(
      config,
      session,
      `/v1/targets/${encodeURIComponent(targetId)}/dns-ownership`,
    ) as DataItem;
    const items = Array.isArray(payload.items) ? (payload.items as DataItem[]) : [];
    const mine = items
      .map(asRecord)
      .filter((row): row is DataItem => Boolean(row) && getString(row, ['target_id']) === targetId);
    if (mine.length === 0) return null;
    const now = Date.now();
    const pending = mine.find(
      (row) => getString(row, ['state']) === 'pending' && Date.parse(getString(row, ['expires_at'])) > now,
    );
    const chosen = pending ?? mine
      .slice()
      .sort((a, b) => String(getString(b, ['issued_at'])).localeCompare(getString(a, ['issued_at'])))[0];
    if (!chosen) return null;
    return {
      id: getString(chosen, ['id']),
      target_id: getString(chosen, ['target_id']) || null,
      record_name: getString(chosen, ['record_name']),
      record_value: getString(chosen, ['record_value']),
      ttl_seconds: Number(chosen.ttl_seconds ?? 60),
      state: getString(chosen, ['state'], 'unknown'),
      issued_at: getString(chosen, ['issued_at']),
      expires_at: getString(chosen, ['expires_at']),
      resolved_at: getString(chosen, ['resolved_at']) || null,
      last_checked_at: getString(chosen, ['last_checked_at']) || null,
    };
  } catch {
    // DNS-ownership listing is best-effort context; absence must not break the page.
    return null;
  }
}

/** Issue a fresh DNS TXT ownership challenge for this target. */
export async function issueOwnershipChallenge(
  config: PortalConfig,
  session: Session,
  targetId: string,
) {
  const payload = await requestJson(
    config,
    session,
    `/v1/targets/${encodeURIComponent(targetId)}/dns-ownership/issue`,
    { method: 'POST', body: {} },
  ) as DataItem;
  return asRecord(payload.challenge) ?? payload;
}

/** Ask the server to re-check the DNS TXT record for a challenge. */
export async function verifyOwnershipChallenge(
  config: PortalConfig,
  session: Session,
  targetId: string,
  challengeId: string,
) {
  return requestJson(
    config,
    session,
    `/v1/targets/${encodeURIComponent(targetId)}/dns-ownership/verify`,
    { method: 'POST', body: { challenge_id: challengeId } },
  ) as Promise<DataItem>;
}

/** Patch tags on the declared target directly. */
export async function patchTargetTags(config: PortalConfig, session: Session, targetId: string, tags: string[]) {
  return requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}`, { method: 'PATCH', body: { tags } }) as Promise<DataItem>;
}


export async function populateTargetDetail(
  config: PortalConfig,
  session: Session,
  entityId: string
): Promise<TargetDetailPayload> {
  const empty: TargetDetailPayload = {
    target: null,
    verification: null,
    waf_posture: null,
    edge_detection: null,
    checks_applied: [],
    runs_recent: [],
    findings: [],
    loa: null,
    counts: null,
    tags: [],
    ownership_challenge: null,
    meta: null,
    loading: false,
  };
  if (!entityId) return empty;

  try {
    const payload = await requestJson(config, session, `/v1/targets/${encodeURIComponent(entityId)}`) as DataItem;
    const target = asRecord(payload.target);
    const verification = asRecord(payload.verification);
    const wafPosture = asRecord(payload.waf_posture);
    const edgeDetection = asRecord(payload.edge_detection);
    const edgeDetectionRequest = asRecord(payload.edge_detection_request);
    const protectionProfile = asRecord(payload.protection_profile);
    const coverage = asRecord(payload.coverage);
    const checksApplied = Array.isArray(payload.checks_applied) ? payload.checks_applied as DataItem[] : [];
    const runsRecent = Array.isArray(payload.runs_recent) ? payload.runs_recent as DataItem[] : [];
    const findings = Array.isArray(payload.findings) ? payload.findings as DataItem[] : [];
    const loa = asRecord(payload.loa);
    const counts = asRecord(payload.counts);
    const meta = asRecord(payload.meta);
    const sectionMeta = {
      runs: readSectionEmptyMeta(meta, 'runs_empty_reason'),
      findings: readSectionEmptyMeta(meta, 'findings_empty_reason'),
      checks: readSectionEmptyMeta(meta, 'checks_empty_reason'),
      waf: readSectionEmptyMeta(meta, 'waf_empty_reason'),
    };

    if (!target) {
      return {
        ...empty,
        verification,
        waf_posture: wafPosture,
        edge_detection: edgeDetection,
        checks_applied: checksApplied,
        runs_recent: runsRecent,
        findings,
        loa,
        counts,
        meta: meta ?? (payload.error ? { empty_reason: getString(payload, ['error']) } : null),
        sectionMeta,
      };
    }

    const ownershipChallenge = await fetchOwnershipChallenge(config, session, entityId);

    return {
      target,
      verification,
      waf_posture: wafPosture,
      edge_detection: edgeDetection,
      edge_detection_request: edgeDetectionRequest,
      protection_profile: protectionProfile,
      coverage,
      declaration: asRecord(target.declaration),
      checks_applied: checksApplied,
      runs_recent: runsRecent,
      findings,
      loa,
      counts,
      tags: readTargetTags(target),
      ownership_challenge: ownershipChallenge,
      meta,
      sectionMeta,
      loading: false,
    };
  } catch (err) {
    const apiErr = err as Error & { payload?: DataItem; status?: number };
    const status = typeof apiErr.status === 'number' ? apiErr.status : 0;
    const payloadMeta = asRecord(asRecord(apiErr.payload)?.meta);
    // A server-written empty reason is shown only for a 4xx; a 5xx or network failure uses the safe
    // copy from requestJson, so raw server text never reaches the page.
    const emptyReason = (status >= 400 && status < 500 ? getString(payloadMeta, ['empty_reason']) : '')
      || apiErrorMessage(err, 'Target details could not load.');
    return {
      ...empty,
      meta: emptyReason ? { empty_reason: emptyReason } : null,
      error: emptyReason,
      status: typeof apiErr.status === 'number' ? apiErr.status : undefined,
    };
  }
}

export { SERVICE_ROLES, CRITICALITY_VALUES, declarationDraftFrom, declarationPatchBody } from './domain-checks.mjs';
export type { ServiceRole, CriticalityValue, DeclarationDraft } from './domain-checks.mjs';
import { declarationPatchBody, type DeclarationDraft } from './domain-checks.mjs';

export async function patchTargetDeclaration(
  config: PortalConfig,
  session: Session,
  targetId: string,
  initial: DeclarationDraft,
  draft: DeclarationDraft,
) {
  return requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}`, {
    method: 'PATCH',
    body: { declaration: declarationPatchBody(initial, draft) },
  }) as Promise<DataItem>;
}

export type ObservationHistory =
  | { state: 'ready'; items: DataItem[]; nextCursor: string; comparison: DataItem | null }
  | { state: 'unavailable'; message: string; code: string }
  | { state: 'unsupported' };

function errorCode(err: unknown) {
  const payload = (err as { payload?: unknown })?.payload;
  return payload && typeof payload === 'object' ? getString(payload as DataItem, ['error']) : '';
}

/**
 * The route is not usable on this server yet: a bare 404 (no code, or the router's not_found), or
 * a 503 `postgres_route_not_wired` while the service is not connected.
 */
function routeMissing(err: unknown) {
  const status = (err as { status?: number })?.status;
  const code = errorCode(err);
  return (status === 404 && (!code || code === 'not_found')) || (status === 503 && code === 'postgres_route_not_wired');
}

/**
 * One newest-first page of retained observations for one target. `cursor` is the server's opaque
 * `next_cursor`; a missing route is reported as unsupported, never faked.
 */
export async function fetchTargetObservations(
  config: PortalConfig,
  session: Session,
  targetId: string,
  signal?: AbortSignal,
  options: { cursor?: string; family?: string; limit?: number } = {},
): Promise<ObservationHistory> {
  const params = new URLSearchParams({ limit: String(options.limit ?? 50) });
  if (options.family) params.set('family', options.family);
  if (options.cursor) params.set('cursor', options.cursor);
  try {
    const payload = await requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}/observations?${params.toString()}`, { signal }) as DataItem;
    const items = Array.isArray(payload.items) ? payload.items as DataItem[] : [];
    const comparison = payload.comparison && typeof payload.comparison === 'object' && !Array.isArray(payload.comparison) ? payload.comparison as DataItem : null;
    return { state: 'ready', items, nextCursor: getString(payload, ['next_cursor']), comparison };
  } catch (err) {
    if (routeMissing(err)) return { state: 'unsupported' };
    return { state: 'unavailable', code: errorCode(err), message: err instanceof Error ? err.message : 'Observation history could not load.' };
  }
}

export type OriginBindingList =
  | { state: 'ready'; items: DataItem[] }
  | { state: 'unsupported' }
  | { state: 'unavailable'; message: string; code: string };

/** Declared origin relations that involve this target. Reads never write or start anything. */
export async function fetchTargetOriginBindings(config: PortalConfig, session: Session, targetId: string, signal?: AbortSignal): Promise<OriginBindingList> {
  try {
    const payload = await requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}/origin-bindings`, { signal }) as DataItem;
    const items = (Array.isArray(payload.items) ? payload.items as DataItem[] : [])
      .filter((item) => getString(item, ['protected_target_id']) === targetId || getString(item, ['origin_target_id']) === targetId);
    return { state: 'ready', items };
  } catch (err) {
    if (routeMissing(err)) return { state: 'unsupported' };
    return { state: 'unavailable', code: errorCode(err), message: err instanceof Error ? err.message : 'Origin relations could not load.' };
  }
}

/** Records a declared relation between two existing targets. Scope fields are optional choices inside the declaration. */
export function createOriginBinding(config: PortalConfig, session: Session, body: { protected_target_id: string; origin_target_id: string; scope: { port?: number; path?: string } }) {
  const payload: DataItem = { protected_target_id: body.protected_target_id, origin_target_id: body.origin_target_id };
  if (Object.keys(body.scope).length) payload.scope = body.scope;
  return requestJson(config, session, '/v1/origin-bindings', { method: 'POST', body: payload }) as Promise<DataItem>;
}

export function archiveOriginBinding(config: PortalConfig, session: Session, bindingId: string) {
  return requestJson(config, session, `/v1/origin-bindings/${encodeURIComponent(bindingId)}/archive`, { method: 'POST' }) as Promise<DataItem>;
}
