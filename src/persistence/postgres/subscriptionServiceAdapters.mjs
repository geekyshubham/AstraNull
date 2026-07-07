import {
  buildDefaultEntitlementGrants,
  buildDefaultSubscription,
  getSubscriptionPlan,
  mergeEntitlementOverrides,
} from '../../contracts/subscriptions.mjs';

/**
 * Postgres-backed replacement for the dev `subscriptions` service used by
 * `GET /v1/subscription/current`. The dev service (src/services/subscriptions.mjs)
 * reads from the in-memory/dev-json store; in Postgres mode that path must never
 * run, so this adapter computes the SAME summary shape purely from tenant-scoped
 * Postgres repositories.
 */

/** Bounded lookup for safe runs started in the last hour. Plans cap safe runs
 * per hour well below this, so the newest-N window always covers the window. */
const SAFE_RUN_LOOKBACK_LIMIT = 500;
/** Findings in these states are considered closed (not "open"). */
const CLOSED_FINDING_STATES = new Set(['closed', 'resolved', 'accepted']);
/** High-scale request states that count as pending SOC work. */
const PENDING_HIGH_SCALE_STATES = new Set([
  'submitted',
  'under_review',
  'approved',
  'scheduled',
  'running',
]);
/** Number of recent audit entries surfaced in the summary. */
const RECENT_AUDIT_LIMIT = 10;
/** Default plan used when a tenant has no subscription row yet. */
const DEFAULT_PLAN_ID = 'starter';
const ONE_HOUR_MS = 60 * 60 * 1000;

/** @type {readonly string[]} */
export const SUBSCRIPTION_INTERNAL_MANAGEMENT_REPOSITORY_METHODS = Object.freeze([
  'getTenantDetail',
]);

/** @type {readonly string[]} */
export const SUBSCRIPTION_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['listTargetGroups']);

/** @type {readonly string[]} */
export const SUBSCRIPTION_AGENT_CONTROL_REPOSITORY_METHODS = Object.freeze(['listAgents']);

/** @type {readonly string[]} */
export const SUBSCRIPTION_VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'listTestRuns',
  'listFindings',
]);

/** @type {readonly string[]} */
export const SUBSCRIPTION_HIGH_SCALE_REPOSITORY_METHODS = Object.freeze(['listHighScaleRequests']);

/** @type {readonly string[]} */
export const POSTGRES_SUBSCRIPTION_SERVICE_METHODS = Object.freeze(['getCurrentSubscriptionSummary']);

function assertRepositoryMethods(repo, label, methods) {
  if (!repo || typeof repo !== 'object') {
    throw new Error(`Postgres subscription service adapter requires repositories.${label}.`);
  }
  for (const method of methods) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres subscription service adapter requires ${label}.${method}().`);
    }
  }
}

function parseMs(value) {
  if (!value) return NaN;
  return Date.parse(value);
}

/**
 * Mirror the dev service shape: `{ ...subscription, effective_entitlements, entitlement_grants }`.
 * Falls back to a default plan subscription when the tenant has no subscription row,
 * so the portal always receives a concrete plan/limit view instead of null.
 *
 * @param {Record<string, unknown> | null} rawSubscription
 * @param {string} tenantId
 */
function toSummarySubscription(rawSubscription, tenantId) {
  if (rawSubscription) {
    const grants = Array.isArray(rawSubscription.entitlement_grants)
      ? rawSubscription.entitlement_grants
      : [];
    return {
      ...rawSubscription,
      effective_entitlements: mergeEntitlementOverrides(rawSubscription, grants),
      entitlement_grants: grants,
    };
  }
  const defaultSubscription = buildDefaultSubscription(DEFAULT_PLAN_ID, tenantId);
  const defaultGrants = buildDefaultEntitlementGrants(DEFAULT_PLAN_ID, tenantId);
  return {
    ...defaultSubscription,
    effective_entitlements: mergeEntitlementOverrides(defaultSubscription, defaultGrants),
    entitlement_grants: defaultGrants,
  };
}

/**
 * getTenantDetail maps tenant audit rows through mapInternalAudit, which renames
 * `actor_role` -> `staff_role`. The customer subscription summary uses `actor_role`,
 * so translate back and keep the same field projection as the dev service.
 *
 * @param {Array<Record<string, unknown>>} recentTenantAudit
 */
function toRecentAudit(recentTenantAudit) {
  const rows = Array.isArray(recentTenantAudit) ? recentTenantAudit : [];
  return rows.slice(0, RECENT_AUDIT_LIMIT).map((entry) => ({
    id: entry.id,
    action: entry.action,
    actor_role: entry.actor_role ?? entry.staff_role ?? null,
    resource_type: entry.resource_type ?? null,
    resource_id: entry.resource_id ?? null,
    created_at: entry.created_at ?? null,
  }));
}

function emptySummary() {
  return {
    tenant_id: null,
    account: null,
    subscription: null,
    plan: null,
    usage: {
      users: 0,
      target_groups: 0,
      agents: 0,
      safe_runs_started_last_hour: 0,
      open_findings: 0,
      pending_high_scale_requests: 0,
      audit_events: 0,
    },
    support: {
      owner: null,
      lifecycle_state: 'unrecorded',
      region: null,
      escalation_state: 'nominal',
      recent_audit: [],
    },
  };
}

/**
 * @param {{
 *   internalManagement?: Record<string, unknown>,
 *   coreCatalog?: Record<string, unknown>,
 *   agentControl?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 *   highScale?: Record<string, unknown>,
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresSubscriptionServices(repositories, options = {}) {
  assertRepositoryMethods(
    repositories?.internalManagement,
    'internalManagement',
    SUBSCRIPTION_INTERNAL_MANAGEMENT_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(
    repositories?.coreCatalog,
    'coreCatalog',
    SUBSCRIPTION_CORE_CATALOG_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(
    repositories?.agentControl,
    'agentControl',
    SUBSCRIPTION_AGENT_CONTROL_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(
    repositories?.validationEvidence,
    'validationEvidence',
    SUBSCRIPTION_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(
    repositories?.highScale,
    'highScale',
    SUBSCRIPTION_HIGH_SCALE_REPOSITORY_METHODS,
  );

  const internalManagement = repositories.internalManagement;
  const coreCatalog = repositories.coreCatalog;
  const agentControl = repositories.agentControl;
  const validationEvidence = repositories.validationEvidence;
  const highScale = repositories.highScale;
  const nowFn = options.now ?? (() => new Date());

  return {
    async getCurrentSubscriptionSummary(ctx) {
      const tenantId = ctx?.tenantId ?? null;
      if (!tenantId) return emptySummary();

      const nowMs = nowFn().getTime();
      const oneHourAgo = nowMs - ONE_HOUR_MS;

      const [detail, groups, agents, runs, findings, highScaleRequests] = await Promise.all([
        internalManagement.getTenantDetail(tenantId),
        // listTargetGroups defaults to active groups only (archived/deleted excluded).
        coreCatalog.listTargetGroups(ctx),
        agentControl.listAgents(ctx),
        validationEvidence.listTestRuns(ctx, { limit: SAFE_RUN_LOOKBACK_LIMIT }),
        validationEvidence.listFindings(ctx),
        highScale.listHighScaleRequests(ctx),
      ]);

      const account = detail?.account ?? null;
      const users = Array.isArray(detail?.users) ? detail.users : [];
      const subscription = toSummarySubscription(detail?.subscription ?? null, tenantId);
      const plan = getSubscriptionPlan(subscription?.plan_id) ?? null;

      const groupList = Array.isArray(groups) ? groups : [];
      const agentList = Array.isArray(agents) ? agents : [];
      const runList = Array.isArray(runs) ? runs : [];
      const findingList = Array.isArray(findings) ? findings : [];
      const highScaleList = Array.isArray(highScaleRequests) ? highScaleRequests : [];

      const safeRunsStartedLastHour = runList.filter((run) => {
        const startedAt = parseMs(run.started_at ?? run.created_at ?? '');
        return Number.isFinite(startedAt) && startedAt >= oneHourAgo;
      }).length;

      const openFindings = findingList.filter(
        (finding) => !CLOSED_FINDING_STATES.has(String(finding.status ?? '').toLowerCase()),
      ).length;

      const pendingHighScale = highScaleList.filter(
        (request) => request.tenant_id === tenantId && PENDING_HIGH_SCALE_STATES.has(request.state),
      ).length;

      const recentAudit = toRecentAudit(detail?.recent_tenant_audit);

      return {
        tenant_id: tenantId,
        account,
        subscription,
        plan,
        usage: {
          users: users.length,
          target_groups: groupList.length,
          agents: agentList.length,
          safe_runs_started_last_hour: safeRunsStartedLastHour,
          open_findings: openFindings,
          pending_high_scale_requests: pendingHighScale,
          audit_events: recentAudit.length,
        },
        support: {
          owner: account?.support_owner ?? null,
          lifecycle_state: account?.lifecycle_state ?? 'unrecorded',
          region: account?.region ?? null,
          escalation_state:
            pendingHighScale > 0
              ? 'soc_review_pending'
              : openFindings > 0
                ? 'customer_review'
                : 'nominal',
          recent_audit: recentAudit,
        },
      };
    },
  };
}
