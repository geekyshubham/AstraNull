import type { DataItem } from './types';

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
    purpose: 'Customer confirms that AstraNull SOC is authorized to coordinate the bounded validation.',
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

export function explainArtifactReviewStatus(
  type: string,
  requirement: DataItem | null | undefined,
  artifact: DataItem | null | undefined
) {
  const requirementStatus = String(requirement?.status ?? 'missing');
  const reviewState = artifactReviewState(artifact);
  const missingFields = Array.isArray(requirement?.missing_fields)
    ? requirement.missing_fields.map((field) => String(field))
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

/** Developer-validation schedule window for SOC schedule actions (matches legacy console). */
export function socDevScheduleWindow() {
  return {
    window_start: new Date(Date.now() - 60_000).toISOString(),
    window_end: new Date(Date.now() + 3_600_000).toISOString()
  };
}

export function buildMetadataArtifactUploadBody(
  request: DataItem,
  type: string,
  fields: { filename: string; content_sha256: string; custody_id?: string }
) {
  const requestId = String(request.id ?? '').trim();
  const targetGroupId = String(request.target_group_id ?? '').trim();
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
    ? request.requested_scenario_families.map((item) => String(item))
    : ['volumetric_metadata'];
  const emergencyContacts = Array.isArray(request.emergency_contacts) ? request.emergency_contacts : [];
  const abortCriteria =
    request.abort_criteria && typeof request.abort_criteria === 'object' && !Array.isArray(request.abort_criteria)
      ? request.abort_criteria
      : { threshold: 'error_rate_above_5pct', auto_stop: true };

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
    approved_targets: targetGroupId ? [targetGroupId] : [],
    approved_scenario_families: scenarioFamilies,
    max_rate: requestedLimits.max_rate ?? 'metadata-only-cap',
    max_duration_minutes: requestedLimits.max_duration_minutes ?? 30,
    emergency_contacts: emergencyContacts,
    abort_criteria: abortCriteria,
    retention_policy: {
      retain_days: 90,
      classification: 'governance'
    }
  };

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