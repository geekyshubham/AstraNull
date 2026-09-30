import { requestJson } from './api';
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
  targetGroupId: string,
  targetId: string,
): Promise<OwnershipChallenge> {
  if (!targetGroupId || !targetId) return null;
  try {
    const payload = await requestJson(
      config,
      session,
      `/v1/target-groups/${encodeURIComponent(targetGroupId)}/dns-ownership`,
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
  targetGroupId: string,
  targetId: string,
) {
  const payload = await requestJson(
    config,
    session,
    `/v1/target-groups/${encodeURIComponent(targetGroupId)}/dns-ownership/issue`,
    { method: 'POST', body: { target_id: targetId } },
  ) as DataItem;
  return asRecord(payload.challenge) ?? payload;
}

/** Ask the server to re-check the DNS TXT record for a challenge. */
export async function verifyOwnershipChallenge(
  config: PortalConfig,
  session: Session,
  targetGroupId: string,
  challengeId: string,
) {
  return requestJson(
    config,
    session,
    `/v1/target-groups/${encodeURIComponent(targetGroupId)}/dns-ownership/verify`,
    { method: 'POST', body: { challenge_id: challengeId } },
  ) as Promise<DataItem>;
}

/**
 * Patch tags for a target. ADR-0008 defines `PATCH /v1/targets/:id`, but baselines that predate it
 * return 404. Fall back to the group-scoped target patch so tag edits still land.
 */
export async function patchTargetTags(
  config: PortalConfig,
  session: Session,
  targetGroupId: string,
  targetId: string,
  tags: string[],
) {
  try {
    return await requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}`, {
      method: 'PATCH',
      body: { tags },
    }) as DataItem;
  } catch (err) {
    const status = (err as { status?: number; payload?: DataItem })?.status
      ?? (err as { payload?: DataItem })?.payload?.status;
    if (status === 404 && targetGroupId) {
      return await requestJson(
        config,
        session,
        `/v1/target-groups/${encodeURIComponent(targetGroupId)}/targets/${encodeURIComponent(targetId)}`,
        { method: 'PATCH', body: { tags } },
      ) as DataItem;
    }
    throw err;
  }
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

    const targetGroupId = getString(target, ['target_group_id']);
    const ownershipChallenge = await fetchOwnershipChallenge(config, session, targetGroupId, entityId);

    return {
      target,
      verification,
      waf_posture: wafPosture,
      edge_detection: edgeDetection,
      edge_detection_request: edgeDetectionRequest,
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
    const apiErr = err as Error & { payload?: DataItem };
    const payload = asRecord(apiErr.payload);
    const payloadMeta = asRecord(payload?.meta);
    const emptyReason = getString(payloadMeta, ['empty_reason'])
      || getString(payload, ['error'])
      || (err instanceof Error ? err.message : '');
    return {
      ...empty,
      meta: emptyReason ? { empty_reason: emptyReason } : null,
      error: emptyReason,
    };
  }
}
