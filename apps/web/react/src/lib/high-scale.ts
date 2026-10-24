import type { DataItem } from './types';

export type GovernedHighScaleScenario = {
  id: string;
  label: string;
  deliveryPatterns: ReadonlyArray<{ id: string; label: string }>;
  limit: {
    field: 'max_gbps' | 'max_cps' | 'max_rps';
    label: string;
    unit: string;
    min: number;
    max: number;
    step: number;
    defaultValue: number;
  };
};

/** Customer-requestable subset of the backend governed scenario taxonomy. */
export const GOVERNED_HIGH_SCALE_SCENARIOS: ReadonlyArray<GovernedHighScaleScenario> = [
  {
    id: 'udp_flood',
    label: 'UDP volumetric',
    deliveryPatterns: [
      { id: 'direct', label: 'Direct' },
      { id: 'spoofed', label: 'Spoofed' }
    ],
    limit: {
      field: 'max_gbps',
      label: 'Maximum traffic rate',
      unit: 'Gbps',
      min: 0.001,
      max: 1000,
      step: 0.001,
      defaultValue: 0.5
    }
  },
  {
    id: 'syn_flood',
    label: 'SYN state exhaustion',
    deliveryPatterns: [
      { id: 'direct', label: 'Direct' },
      { id: 'spoofed', label: 'Spoofed' }
    ],
    limit: {
      field: 'max_cps',
      label: 'Maximum connection rate',
      unit: 'connections/second',
      min: 1,
      max: 10_000_000,
      step: 1,
      defaultValue: 1000
    }
  },
  {
    id: 'http_get_flood',
    label: 'HTTP GET flood',
    deliveryPatterns: [
      { id: 'direct', label: 'Direct' },
      { id: 'coordinated_swarm', label: 'Coordinated swarm' }
    ],
    limit: {
      field: 'max_rps',
      label: 'Maximum request rate',
      unit: 'requests/second',
      min: 1,
      max: 10_000_000,
      step: 1,
      defaultValue: 500
    }
  }
];

const GOVERNED_NUMERIC_LIMIT_FIELDS = [
  'max_gbps',
  'max_pps',
  'max_rps',
  'max_qps',
  'max_cps',
  'max_connections',
  'max_resets_per_sec',
  'max_duration_minutes'
] as const;

/** Required authorization-pack artifact types from `authorizationTemplates.mjs`. */
export const REQUIRED_AUTHORIZATION_ARTIFACT_TYPES = [
  'customer_authorization_letter',
  'target_ownership_confirmation',
  'emergency_contacts',
  'stop_criteria',
  'test_plan',
  'business_approval',
  'legal_approval',
  'scope_and_rate_plan',
  'abort_criteria'
] as const;

export const OPTIONAL_PROVIDER_ARTIFACT_TYPE = 'provider_approval' as const;

export type AuthorizationArtifactType =
  | (typeof REQUIRED_AUTHORIZATION_ARTIFACT_TYPES)[number]
  | typeof OPTIONAL_PROVIDER_ARTIFACT_TYPE;

export const AUTHORIZATION_ARTIFACT_CATALOG: ReadonlyArray<{
  artifact_type: AuthorizationArtifactType;
  title: string;
  purpose: string;
  legal_review_required?: boolean;
}> = [
  {
    artifact_type: 'customer_authorization_letter',
    title: 'Customer Authorization Letter',
    purpose: 'Customer confirms that AstraNull SOC is authorized to coordinate the validation.',
    legal_review_required: true
  },
  {
    artifact_type: 'target_ownership_confirmation',
    title: 'Target Ownership Confirmation',
    purpose: 'Customer confirms declared targets are owned, controlled, or explicitly authorized.',
    legal_review_required: true
  },
  {
    artifact_type: 'emergency_contacts',
    title: 'Emergency Contacts',
    purpose: 'Defines customer, SOC, and provider stop/escalation contacts during the window.'
  },
  {
    artifact_type: 'stop_criteria',
    title: 'Stop Criteria',
    purpose: 'Documents thresholds and authorities that pause or stop the validation.'
  },
  {
    artifact_type: 'test_plan',
    title: 'Test Plan',
    purpose: 'Defines scenario families, observations, monitoring, and completion criteria.'
  },
  {
    artifact_type: 'business_approval',
    title: 'Business Approval',
    purpose: 'Business owner accepts the timing, risk, communications, and recovery expectations.',
    legal_review_required: true
  },
  {
    artifact_type: 'legal_approval',
    title: 'Legal and Policy Approval',
    purpose: 'Legal/security owner confirms the validation is authorized under customer and provider rules.',
    legal_review_required: true
  },
  {
    artifact_type: 'scope_and_rate_plan',
    title: 'Scope and Rate Plan',
    purpose: 'Locks target scope, rate labels, duration caps, and change-control boundaries.',
    legal_review_required: true
  },
  {
    artifact_type: 'abort_criteria',
    title: 'Abort Criteria',
    purpose: 'Documents immediate abort conditions, customer/provider authority, and recovery steps.'
  },
  {
    artifact_type: 'provider_approval',
    title: 'Provider Approval',
    purpose: 'Captures cloud, CDN, carrier, partner, or lab approval metadata without requiring credentials.',
    legal_review_required: true
  }
];

const CATALOG_BY_TYPE = Object.fromEntries(
  AUTHORIZATION_ARTIFACT_CATALOG.map((entry) => [entry.artifact_type, entry])
) as Record<AuthorizationArtifactType, (typeof AUTHORIZATION_ARTIFACT_CATALOG)[number]>;

export function authorizationArtifactTitle(type: string) {
  return CATALOG_BY_TYPE[type as AuthorizationArtifactType]?.title ?? type.replace(/_/g, ' ');
}

export function authorizationArtifactPurpose(type: string) {
  return CATALOG_BY_TYPE[type as AuthorizationArtifactType]?.purpose ?? 'Authorization metadata reference.';
}

export function providerApprovalRequired(request: DataItem | null | undefined) {
  if (!request) return false;
  const providerContext = request.provider_context;
  if (!providerContext || typeof providerContext !== 'object' || Array.isArray(providerContext)) {
    return false;
  }
  const context = providerContext as DataItem;
  if (context.requires_provider_approval === true) return true;
  const providerName = String(context.provider_name ?? context.provider ?? context.name ?? '').trim();
  return providerName.length > 0;
}

export function authorizationArtifactTypesForRequest(request: DataItem | null | undefined) {
  const types: AuthorizationArtifactType[] = [...REQUIRED_AUTHORIZATION_ARTIFACT_TYPES];
  if (providerApprovalRequired(request)) types.push(OPTIONAL_PROVIDER_ARTIFACT_TYPE);
  return types;
}

export type LifecycleTimelineEvent = {
  action: string;
  at: string;
  by: string;
  metadata?: DataItem;
};

export function buildLifecycleTimeline(request: DataItem | null | undefined): LifecycleTimelineEvent[] {
  if (!request || !Array.isArray(request.audit_trail)) return [];
  const events: LifecycleTimelineEvent[] = [];
  for (const entry of request.audit_trail) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const event = entry as DataItem;
    const action = String(event.action ?? '').trim();
    const at = String(event.at ?? event.created_at ?? '').trim();
    if (!action || !at) continue;
    const metadata =
      event.metadata && typeof event.metadata === 'object' && !Array.isArray(event.metadata)
        ? event.metadata as DataItem
        : undefined;
    events.push({
      action,
      at,
      by: String(event.by ?? 'system'),
      ...(metadata ? { metadata } : {})
    });
  }
  return events.sort((left, right) => new Date(left.at).getTime() - new Date(right.at).getTime());
}

export function bestArtifactForType(artifacts: DataItem[], type: string) {
  const matches = artifacts.filter((artifact) => String(artifact.type ?? '') === type);
  const accepted = matches.find((artifact) => String(artifact.status ?? '') === 'accepted');
  if (accepted) return accepted;
  const pending = matches.find((artifact) => String(artifact.status ?? '') === 'pending_review');
  if (pending) return pending;
  const rejected = matches.filter((artifact) => String(artifact.status ?? '') === 'rejected');
  return rejected[rejected.length - 1] ?? null;
}

export function orderedArtifactsForType(artifacts: DataItem[], type: string) {
  const matches = artifacts.filter((artifact) => String(artifact.type ?? '') === type);
  const best = bestArtifactForType(matches, type);
  if (!best) return matches;
  const rest = matches
    .filter((artifact) => artifact !== best)
    .sort((left, right) => String(right.created_at ?? '').localeCompare(String(left.created_at ?? '')));
  return [best, ...rest];
}

export function killSwitchActiveForTenant(record: DataItem | null | undefined, tenantId: string | null | undefined) {
  if (!record || !(record.active ?? record.enabled)) return false;
  const tenants = record.tenants;
  if (tenants && typeof tenants === 'object' && !Array.isArray(tenants)) {
    return Boolean(tenantId && (tenants as Record<string, unknown>)[tenantId]);
  }
  const scoped = String(record.tenant_id ?? '').trim();
  if (!scoped) return true;
  return scoped === String(tenantId ?? '').trim();
}

export function packRequirementForType(packStatus: DataItem | null | undefined, type: string) {
  const requirements = Array.isArray(packStatus?.requirements) ? packStatus.requirements as DataItem[] : [];
  return requirements.find((requirement) => String(requirement.type ?? '') === type) ?? null;
}

export function artifactReviewState(artifact: DataItem | null | undefined) {
  if (!artifact) return 'missing';
  const status = String(artifact.status ?? 'pending_review');
  if (status === 'accepted' || status === 'rejected' || status === 'pending_review') return status;
  return status;
}

const MISSING_FIELD_LABELS: Record<string, string> = {
  valid_window: 'requested safe window',
  approval_reference: 'approval reference',
  approver: 'approver',
  approved_targets: 'approved targets',
  approved_scenario_families: 'approved scenario families',
  approved_delivery_patterns: 'approved delivery patterns',
  approved_limits: 'approved limits',
  emergency_contacts: 'emergency contacts',
  abort_criteria: 'abort criteria',
  content_sha256: 'file fingerprint (SHA-256)',
  reference_uri: 'reference',
  custody_uri: 'custody reference',
  authorization_binding: 'authorization binding',
  provider_name: 'provider name'
};

export function plainMissingFieldLabel(field: string) {
  return MISSING_FIELD_LABELS[field] ?? field.replace(/[._]/g, ' ');
}

export function explainArtifactReviewStatus(
  type: string,
  requirement: DataItem | null | undefined,
  artifact: DataItem | null | undefined
) {
  const requirementStatus = String(requirement?.status ?? 'missing');
  const reviewState = artifactReviewState(artifact);
  const missingFields = Array.isArray(requirement?.missing_fields)
    ? requirement.missing_fields.map((field) => plainMissingFieldLabel(String(field)))
    : [];

  if (requirementStatus === 'missing' && !artifact) {
    return `No ${authorizationArtifactTitle(type)} metadata uploaded yet. SOC cannot review this artifact until a metadata reference is submitted.`;
  }
  if (requirementStatus === 'expired') {
    return `${authorizationArtifactTitle(type)} was accepted but its valid window has expired. Upload refreshed metadata before SOC can approve the pack.`;
  }
  if (requirementStatus === 'rejected' || reviewState === 'rejected') {
    const notes = artifact?.review_notes != null ? String(artifact.review_notes) : '';
    return notes
      ? `SOC rejected ${authorizationArtifactTitle(type)}: ${notes}`
      : `SOC rejected ${authorizationArtifactTitle(type)}. Upload corrected metadata and wait for SOC re-review.`;
  }
  if (requirementStatus === 'partial' || missingFields.length > 0) {
    const fields = missingFields.length > 0 ? missingFields.join(', ') : 'required proof fields';
    return `${authorizationArtifactTitle(type)} is uploaded but still missing ${fields}.`;
  }
  if (requirementStatus === 'pending_review' || reviewState === 'pending_review') {
    return `${authorizationArtifactTitle(type)} metadata is uploaded and awaiting SOC review.`;
  }
  if (requirementStatus === 'accepted' && reviewState === 'accepted') {
    const reviewedAt = artifact?.reviewed_at != null ? String(artifact.reviewed_at) : requirement?.reviewed_at != null ? String(requirement.reviewed_at) : '';
    return reviewedAt
      ? `SOC accepted ${authorizationArtifactTitle(type)} on ${reviewedAt}.`
      : `SOC accepted ${authorizationArtifactTitle(type)}.`;
  }
  return `${authorizationArtifactTitle(type)} pack status is ${requirementStatus}; artifact review state is ${reviewState}.`;
}

function recordOf(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function parseInstant(value: unknown): number {
  if (value === null || value === undefined || value === '') return NaN;
  const ms = new Date(String(value)).getTime();
  return Number.isFinite(ms) ? ms : NaN;
}

export type WindowBounds = { start: number; end: number };

/** Mirrors the server window normalizer: both ends present, parseable, and start before end. */
export function windowBounds(raw: unknown): WindowBounds | null {
  const window = recordOf(raw);
  if (!window) return null;
  const start = parseInstant(window.window_start ?? window.valid_from ?? window.start);
  const end = parseInstant(window.window_end ?? window.valid_to ?? window.end);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) return null;
  return { start, end };
}

export function requestedWindowBounds(request: DataItem | null | undefined) {
  return windowBounds(request?.requested_window);
}

/** Valid window of the accepted customer authorization letter, when one is recorded. */
export function authorizationLetterValidWindow(request: DataItem | null | undefined) {
  const artifacts = Array.isArray(request?.artifacts) ? request.artifacts as DataItem[] : [];
  const letter = artifacts.find((artifact) => artifact.type === 'customer_authorization_letter' && artifact.status === 'accepted');
  return letter ? windowBounds(letter.valid_window) : null;
}

export type ScheduledWindowState = 'unscheduled' | 'upcoming' | 'open' | 'expired';

/** Same rule as the server `isWithinScheduledWindow`: open is inclusive at both ends. */
export function scheduledWindowState(start: unknown, end: unknown, nowMs = Date.now()): ScheduledWindowState {
  const bounds = windowBounds({ window_start: start, window_end: end });
  if (!bounds) return 'unscheduled';
  if (nowMs < bounds.start) return 'upcoming';
  if (nowMs > bounds.end) return 'expired';
  return 'open';
}

export type ScheduleWindowDraft = { window_start: string; window_end: string; timezone: string };
// `blocking: false` marks recorded context (requested window, letter validity) the server no longer enforces.
export type ScheduleWindowError = { field: 'window_start' | 'window_end'; message: string; blocking?: boolean };

const MINUTE_MS = 60_000;

/** Default SOC schedule: the customer-requested window (inside any letter validity), never starting in the past. */
export function defaultScheduleWindow(request: DataItem | null | undefined, nowMs = Date.now()): ScheduleWindowDraft | null {
  const requested = requestedWindowBounds(request);
  if (!requested) return null;
  const letter = authorizationLetterValidWindow(request);
  const startFloor = Math.max(requested.start, letter?.start ?? -Infinity, nowMs);
  const endCeiling = Math.min(requested.end, letter?.end ?? Infinity);
  const start = Math.ceil(startFloor / MINUTE_MS) * MINUTE_MS;
  const end = Math.floor(endCeiling / MINUTE_MS) * MINUTE_MS;
  if (end <= start) return null;
  const timezone = String(recordOf(request?.requested_window)?.timezone ?? '').trim() || 'UTC';
  return { window_start: new Date(start).toISOString(), window_end: new Date(end).toISOString(), timezone };
}

export function scheduleWindowErrors(
  request: DataItem | null | undefined,
  draft: { window_start: string; window_end: string },
  nowMs = Date.now()
): ScheduleWindowError[] {
  const start = parseInstant(draft.window_start);
  const end = parseInstant(draft.window_end);
  const errors: ScheduleWindowError[] = [];
  if (!Number.isFinite(start)) errors.push({ field: 'window_start', message: 'Enter a valid start date and time.' });
  if (!Number.isFinite(end)) errors.push({ field: 'window_end', message: 'Enter a valid end date and time.' });
  if (errors.length) return errors;
  if (end <= start) return [{ field: 'window_end', message: 'End must be after start.' }];
  if (end <= nowMs) errors.push({ field: 'window_end', message: 'This window has already ended.' });
  const requested = requestedWindowBounds(request);
  if (!requested) {
    errors.push({ field: 'window_start', message: 'The customer-requested window is not recorded, so no schedule can be checked against it.', blocking: false });
    return errors;
  }
  if (start < requested.start) errors.push({ field: 'window_start', message: 'Start is before the customer-requested window opens.', blocking: false });
  if (end > requested.end) errors.push({ field: 'window_end', message: 'End is after the customer-requested window closes.', blocking: false });
  const letter = authorizationLetterValidWindow(request);
  if (letter) {
    if (start < letter.start) errors.push({ field: 'window_start', message: 'Start is before the authorization letter becomes valid.', blocking: false });
    if (end > letter.end) errors.push({ field: 'window_end', message: 'End is after the authorization letter expires.', blocking: false });
  }
  return errors;
}

function pad2(value: number) {
  return String(value).padStart(2, '0');
}

/** ISO instant to a `datetime-local` value in the viewer's local time. */
export function toDatetimeLocalValue(iso: string) {
  const ms = parseInstant(iso);
  if (!Number.isFinite(ms)) return '';
  const date = new Date(ms);
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}T${pad2(date.getHours())}:${pad2(date.getMinutes())}`;
}

/** `datetime-local` value (viewer's local time) to an ISO instant; '' when unparseable. */
export function fromDatetimeLocalValue(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value.trim())) return '';
  const ms = new Date(value.trim()).getTime();
  return Number.isFinite(ms) ? new Date(ms).toISOString() : '';
}

const LIMIT_UNITS: Record<string, string> = {
  max_gbps: 'Gbps',
  max_pps: 'packets/second',
  max_rps: 'requests/second',
  max_qps: 'queries/second',
  max_cps: 'connections/second',
  max_connections: 'connections',
  max_resets_per_sec: 'resets/second'
};

function formatLimitNumber(value: number) {
  return new Intl.NumberFormat('en-US').format(value);
}

/** Recorded rate cap and duration for a governed request; '—' when none is recorded. */
export function governedLimitDisplay(item: DataItem | null | undefined) {
  const familyId = Array.isArray(item?.requested_scenario_families)
    ? String(item.requested_scenario_families[0] ?? '')
    : '';
  const scenario = GOVERNED_HIGH_SCALE_SCENARIOS.find((entry) => entry.id === familyId);
  const limits = recordOf(item?.requested_limits) ?? {};
  const rateFields = scenario ? [scenario.limit.field] : Object.keys(LIMIT_UNITS);
  const rates = rateFields.flatMap((field) => {
    const value = limits[field];
    if (typeof value !== 'number' || !Number.isFinite(value)) return [];
    return [`${formatLimitNumber(value)} ${scenario?.limit.unit ?? LIMIT_UNITS[field]}`];
  });
  const durationValue = limits.max_duration_minutes;
  const duration = typeof durationValue === 'number' && Number.isFinite(durationValue)
    ? `${formatLimitNumber(durationValue)} min`
    : '';
  return [...rates, duration].filter(Boolean).join(' · ') || '—';
}

export function governedScenarioLabel(id: string) {
  return GOVERNED_HIGH_SCALE_SCENARIOS.find((entry) => entry.id === id)?.label ?? id.replace(/_/g, ' ');
}

/** Declared domains in a request's scope: explicit target IDs first, else the members of its recorded scope. */
export function requestDomainDisplay(data: { targets?: DataItem[] } | null | undefined, item: DataItem | null | undefined): string[] {
  const targets = Array.isArray(data?.targets) ? data.targets : [];
  const valueOf = (target: DataItem | undefined) => String(target?.value ?? target?.hostname ?? '').trim();
  const ids = Array.isArray(item?.target_ids) && item.target_ids.length
    ? item.target_ids.map(String)
    : item?.target_id ? [String(item.target_id)] : [];
  if (ids.length) {
    return ids.map((id) => valueOf(targets.find((target) => String(target.id ?? '') === id)) || id);
  }
  const groupId = String(item?.target_group_id ?? '').trim();
  if (!groupId) return [];
  return targets
    .filter((target) => String(target.target_group_id ?? '') === groupId && !target.deleted_at)
    .map((target) => valueOf(target))
    .filter(Boolean);
}

export type AuthorizationPackProgress = { accepted: number; awaitingReview: number; toRecord: number; total: number };

export function authorizationPackProgress(packStatus: DataItem | null | undefined, types: readonly string[]): AuthorizationPackProgress {
  let accepted = 0;
  let awaitingReview = 0;
  for (const type of types) {
    const status = String(packRequirementForType(packStatus, type)?.status ?? 'missing');
    if (status === 'accepted') accepted += 1;
    else if (status === 'pending_review') awaitingReview += 1;
  }
  return { accepted, awaitingReview, toRecord: types.length - accepted - awaitingReview, total: types.length };
}

/** One-line pack progress, e.g. '3 of 9 accepted · 2 awaiting SOC review · 4 to record'. */
export function summarizeAuthorizationPackProgress(packStatus: DataItem | null | undefined, types: readonly string[]) {
  const progress = authorizationPackProgress(packStatus, types);
  return [
    `${progress.accepted} of ${progress.total} accepted`,
    progress.awaitingReview ? `${progress.awaitingReview} awaiting SOC review` : '',
    progress.toRecord ? `${progress.toRecord} to record` : ''
  ].filter(Boolean).join(' · ');
}

export function buildMetadataArtifactUploadBody(
  request: DataItem,
  type: string,
  fields: { filename: string; content_sha256: string; custody_id?: string }
) {
  const requestId = String(request.id ?? '').trim();
  const targetIds = Array.isArray(request.target_ids) ? request.target_ids.map(String) : request.target_id ? [String(request.target_id)] : [];
  const requestedWindow =
    request.requested_window && typeof request.requested_window === 'object' && !Array.isArray(request.requested_window)
      ? request.requested_window as DataItem
      : {};
  const requestedLimits =
    request.requested_limits && typeof request.requested_limits === 'object' && !Array.isArray(request.requested_limits)
      ? request.requested_limits as DataItem
      : {};
  const providerContext =
    request.provider_context && typeof request.provider_context === 'object' && !Array.isArray(request.provider_context)
      ? request.provider_context as DataItem
      : {};
  const scenarioFamilies = Array.isArray(request.requested_scenario_families)
    ? request.requested_scenario_families.map((item) => String(item).trim()).filter(Boolean)
    : [];
  const deliveryPatterns = Array.isArray(request.delivery_patterns)
    ? request.delivery_patterns.map((item) => String(item).trim()).filter(Boolean)
    : [];
  const approvedLimits: Record<string, number> = {};
  for (const field of GOVERNED_NUMERIC_LIMIT_FIELDS) {
    const value = requestedLimits[field];
    if (typeof value === 'number' && Number.isFinite(value)) approvedLimits[field] = value;
  }
  const emergencyContacts = Array.isArray(request.emergency_contacts) ? request.emergency_contacts : [];
  const abortCriteria =
    request.abort_criteria && typeof request.abort_criteria === 'object' && !Array.isArray(request.abort_criteria)
      ? request.abort_criteria
      : {};

  const body: DataItem = {
    type,
    filename: fields.filename,
    content_sha256: fields.content_sha256,
    reference_uri: `metadata://high-scale/${type}/${requestId}`,
    approval_reference: `metadata://${type}/${requestId}`,
    approver: 'customer-declared',
    valid_window: {
      window_start: requestedWindow.window_start ?? null,
      window_end: requestedWindow.window_end ?? null
    },
    approved_targets: targetIds,
    approved_scenario_families: scenarioFamilies,
    approved_delivery_patterns: deliveryPatterns,
    approved_limits: approvedLimits,
    ...(typeof approvedLimits.max_duration_minutes === 'number'
      ? { max_duration_minutes: approvedLimits.max_duration_minutes }
      : {}),
    emergency_contacts: emergencyContacts,
    abort_criteria: abortCriteria,
    retention_policy: {
      retain_days: 90,
      classification: 'governance'
    }
  };

  const tenantId = String(request.tenant_id ?? '').trim();
  const scopeHash = String(request.scope_hash ?? '').trim();
  if (tenantId && targetIds.length && scopeHash) {
    body.authorization_binding = {
      tenant_id: tenantId,
      target_ids: targetIds,
      scope_hash: scopeHash,
      requested_window: requestedWindow,
      approved_schedule_window: requestedWindow,
      delivery_patterns: deliveryPatterns
    };
  }

  const custodyId = String(fields.custody_id ?? '').trim();
  if (custodyId) {
    body.custody_uri = `custody://${custodyId}`;
  }

  const providerName = String(providerContext.provider_name ?? providerContext.provider ?? providerContext.name ?? '').trim();
  if (type === OPTIONAL_PROVIDER_ARTIFACT_TYPE && providerName) {
    body.provider_name = providerName;
  }

  return body;
}