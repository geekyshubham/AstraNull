import {
  audit } from '../audit.mjs';
import {
  customerSelectableChecks,
  checkRequiresAdditionalInput,
  checkAdditionalInputReason,
  demoMissingInputRefusal,
  evaluateCheckPrerequisites,
  formatMissingInputMessage,
  getCheckById,
  isCustomerRunnable,
} from '../contracts/checks.mjs';
import { isExplicitDemoTenant } from '../lib/demoAutoVerify.mjs';
import { targetKindCompatibilityError } from '../contracts/checkTargetCompatibility.mjs';
import { validateReviewedOperationSelection } from '../contracts/reviewedOperationBinding.mjs';
import { targetDedupeKey } from '../contracts/targetManagement.mjs';
import { scanIncludesTarget } from '../lib/targetExecutionScope.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { redactObject } from '../lib/redact.mjs';
import { projectRunActivity } from '../lib/probeActivity.mjs';
import { deriveAssuranceScope } from '../lib/assuranceScope.mjs';
import { scrubRunForCustomer } from '../lib/outsideInEvidence.mjs';
import { recordEvidence } from './evidence.mjs';
import { newId } from '../lib/ids.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../lib/wafProductCatalog.mjs';
import { getStore, persistStore } from '../store.mjs';
import { correlateExternalOnlyVerdict, correlateOpsReadinessVerdict, probeEventHasProbeIo, probeResultCompletesEvidence } from './correlation.mjs';
import { controlDeclarationsFromTarget } from '../contracts/controlDeclarations.mjs';
import { authorizeFindingWrite, applyPassingRetestToFindings, upsertFindingFromVerdict } from './findings.mjs';
import {
  bindingRecordsFromStore,
  currentOriginProof,
  deriveBindingScope,
  validateOriginBindingForRun,
  historicalOriginBindingForRun,
} from './originBindings.mjs';
import { registerRetestLineage } from './retestLineage.mjs';
import { isProtectionValidationFinding, protectionRetestRunScopeMatches } from '../lib/protectionValidationFindings.mjs';
import { resolveDevProtectionRetestAuthorization } from './protectionValidationRetest.mjs';
import { executeOpsReadinessProbe, isOpsReadinessProbeKind, resolveOpsReadinessScenario } from '../lib/opsReadinessValidation.mjs';
import { simulateProbeResult } from './probeStub.mjs';
import { buildOriginIdentityPairSnapshot, originIdentityScenario } from '../lib/originIdentityPair.mjs';
import { reviewedOriginIdentityPair } from '../lib/entryPathComparison.mjs';
import { targetOwnershipProof } from './ownershipVerification.mjs';
import { getTestPolicyForDispatch } from './testPolicies.mjs';
import { isWithinPolicySafeWindow } from '../contracts/testPolicyManagement.mjs';
import { isTrustedProducerEvent } from '../lib/trustedEventProvenance.mjs';
import {
  approvedScenarioVersion,
  deriveRunEvidenceStamp,
  verdictExpectedBehaviorForRun,
} from '../lib/checkDefinitionVersion.mjs';
import {
  isOriginLockdownHostnameCheck,
  originLockdownProvenance,
  resolveOriginLockdownBinding,
  validateHostSniTargetBinding,
} from '../lib/probeJobs.mjs';
import { buildVerdictReplay } from '../lib/verdictReplay.mjs';
import { createProbeJob } from './probeCoordinator.mjs';
import { probeDispatchReady } from '../config.mjs';
import { computeReadiness } from './readiness.mjs';
import { notifyRunTerminal } from './runTerminalHooks.mjs';
import { normalizeCancelReason, withCheckSection } from '../contracts/validationScanManagement.mjs';
import { isArchivedTarget, isArchivedTargetGroup } from './targetGroups.mjs';
import {
  DEFAULT_MAX_RUNS_PER_HOUR,
  DEFAULT_MIN_SECONDS_BETWEEN_RUNS,
  countCustomerRunnableRunsLastHour,
  effectiveSafetyConstraints,
  isWithinSafeTestWindow,
  isWithinSafeTestWindowRaw,
  lastRunForTargetGroup,
  normalizeSafetyPolicy,
  wouldExceedEventCap,
} from './safeTestPolicy.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';
import { assertSubscriptionLimit, getTenantAccount } from './subscriptions.mjs';

export function listChecks(options = {}) {
  const catalog = getStore().checkCatalog ?? [];
  const tenantId = options.tenantId ?? options.target?.tenant_id;
  const context = { target: options.target ?? null, declarations: options.declarations, originBindings: options.originBindings, tenantId };
  if (options.scope === 'all') {
    return catalog.map((check) => {
      const requiresAdditionalInput = checkRequiresAdditionalInput(check, context);
      return {
        ...withCheckSection(check),
        requires_additional_input: requiresAdditionalInput,
        additional_input_reason: requiresAdditionalInput ? checkAdditionalInputReason(check, context) : null,
      };
    });
  }
  const selectable = customerSelectableChecks(catalog, context).map(withCheckSection);
  if (options.target || options.tenantId) {
    return selectable.map((check) => ({
      ...check,
      requires_additional_input: false,
      additional_input_reason: null,
    }));
  }
  return selectable;
}

const DEFAULT_TEST_RUN_LIST_LIMIT = 100;
// docs/api.md GET /v1/test-runs: limit default 100, max 100. Keep dev-json and Postgres aligned.
const MAX_TEST_RUN_LIST_LIMIT = 100;

function normalizeTestRunListLimit(limit) {
  const parsed = Number(limit);
  if (limit == null || !Number.isFinite(parsed) || parsed < 1) return DEFAULT_TEST_RUN_LIST_LIMIT;
  return Math.min(Math.floor(parsed), MAX_TEST_RUN_LIST_LIMIT);
}

export function listTestRuns(ctx, options = {}) {
  let rows = getStore().testRuns.filter((r) => r.tenant_id === ctx.tenantId);
  if (options.target_group_id) {
    rows = rows.filter((r) => r.target_group_id === options.target_group_id);
  }
  if (options.target_id) {
    rows = rows.filter((r) => r.target_id === options.target_id);
  }
  if (options.check_id) {
    rows = rows.filter((r) => r.check_id === options.check_id);
  }
  rows = rows.sort((a, b) =>
    String(b.started_at ?? b.created_at ?? '').localeCompare(
      String(a.started_at ?? a.created_at ?? ''),
    ) || String(b.id ?? '').localeCompare(String(a.id ?? '')),
  );
  rows = rows.slice(0, normalizeTestRunListLimit(options.limit));
  const verdicts = getStore().verdicts ?? [];
  return rows.map((run) =>
    // EVIDENCE-01 / ADR-0008: list items carry the same nested verdict as run detail; scrub it here too.
    // Authoritative resolution only: the same-tenant published verdict record backs every list
    // verdict. A raw run.verdict string (legacy row field) or the run status never invents one —
    // an unbacked run projects null, never a phantom PASS.
    scrubRunForCustomer({
      ...run,
      verdict: verdicts.find(
        (v) => v.tenant_id === ctx.tenantId && v.test_run_id === run.id,
      ) ?? null,
    }),
  );
}

export function listTestRunsEnvelope(ctx, options = {}) {
  const items = listTestRuns(ctx, options);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : options.target_group_id
          ? 'No test runs match this target group filter.'
          : options.target_id
            ? 'No test runs match this target filter.'
            : options.check_id
              ? 'No test runs have been recorded for this check yet.'
              : 'No test runs have been started for this tenant yet.',
    },
  };
}

function collectionDeadlineMs(check) {
  const seconds = check?.safety_constraints?.max_duration_seconds ?? 120;
  return seconds * 1000;
}

function isCollectionWindowExpired(run) {
  if (!run.collection_deadline_at) return false;
  return Date.now() >= new Date(run.collection_deadline_at).getTime();
}

function hasExternalProbeEvidence(run) {
  if (run.probe_external_result != null && run.probe_external_result !== '') return true;
  const store = getStore();
  return store.events.some(
    (e) =>
      e.test_run_id === run.id && e.tenant_id === run.tenant_id &&
      e.signal_type === 'probe_result' &&
      isTrustedProducerEvent(e) &&
      typeof run.correlation?.nonce_hash === 'string' && run.correlation.nonce_hash.length > 0 &&
      e.nonce_hash === run.correlation.nonce_hash,
  );
}

export function maybeFinalizeCollectingRun(run, { force = false } = {}) {
  if (!run || run.status !== 'collecting') return null;
  if (getStore().verdicts.some((v) => v.test_run_id === run.id)) return null;
  if (!hasExternalProbeEvidence(run)) return null;
  if (!force && !isCollectionWindowExpired(run)) return null;
  return finalizeNoObservation(run);
}

export function finalizeTestRun(ctx, id, { force = false } = {}) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  if (run.status !== 'collecting') {
    return { error: 'not_collecting', status: 409 };
  }
  if (!hasExternalProbeEvidence(run)) {
    return { error: 'external_probe_pending', status: 409 };
  }
  if (!force && !isCollectionWindowExpired(run)) {
    return { error: 'observation_window_active', status: 409 };
  }
  const verdict = maybeFinalizeCollectingRun(run, { force: true });
  if (!verdict) {
    return { error: 'cannot_finalize', status: 409 };
  }
  persistStore();
  return { run: getTestRun(ctx, id), verdict };
}

export function getRunActivity(ctx, id, options = {}) {
  const run = getStore().testRuns.find((entry) => entry.id === id && entry.tenant_id === ctx.tenantId);
  if (!run) return null;
  const job = getStore().probeJobs.find((entry) => entry.test_run_id === id && entry.tenant_id === ctx.tenantId) ?? null;
  return projectRunActivity(run, getRunEvents(ctx, id), { ...options, job });
}

export function getTestRun(ctx, id) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  maybeFinalizeCollectingRun(run);
  const verdict = getStore().verdicts.find((v) => v.test_run_id === id);
  // EVIDENCE-01 / ADR-0008: customer run detail must read external-only. Scrub the nested verdict
  // explanation / placement_confidence at this projection seam; stored rows are untouched.
  return scrubRunForCustomer({ ...run, verdict: verdict ?? null });
}

function devRunOriginBinding(run) {
  return historicalOriginBindingForRun(run);
}

export function getVerdictReplay(ctx, id) {
  const store = getStore();
  const run = store.testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  const target = store.targets.find((t) => t.id === run.target_id && t.tenant_id === ctx.tenantId) ?? null;
  const verdict = store.verdicts.find((v) => v.test_run_id === id && (v.tenant_id == null || v.tenant_id === ctx.tenantId));
  const probeEvent = store.events.find((e) => e.test_run_id === run.id && e.tenant_id === ctx.tenantId
    && e.signal_type === 'probe_result' && isTrustedProducerEvent(e) && e.nonce_hash === run.correlation?.nonce_hash);
  return buildVerdictReplay({
    run,
    storedVerdict: verdict ?? null,
    probeEvent: probeEvent ?? null,
    declarations: controlDeclarationsFromTarget(target),
    originBinding: devRunOriginBinding(run, target),
  });
}

const MAX_EVENT_ID_LOOKUP = 32;

function eventLookupIds(value) {
  if (!Array.isArray(value)) return null;
  const ids = [];
  for (const item of value) {
    if (typeof item !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(item) || ids.includes(item)) continue;
    ids.push(item);
    if (ids.length >= MAX_EVENT_ID_LOOKUP) break;
  }
  return ids;
}

export function getRunEvents(ctx, id, options = {}) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  const events = getStore().events.filter((e) => e.test_run_id === id && e.tenant_id === ctx.tenantId);
  const lookup = eventLookupIds(options?.ids);
  if (lookup) {
    const want = new Set(lookup);
    return events.filter((event) => {
      const matched = want.has(event.id) || (typeof event.event_id === 'string' && want.has(event.event_id));
      if (!matched) return false;
      if (options.target_id && event.target_id !== options.target_id) return false;
      if (options.check_id && event.check_id !== options.check_id) return false;
      return true;
    });
  }
  if (options?.limit == null) return events;
  const requested = Number(options.limit);
  if (!Number.isFinite(requested) || requested < 1) return events;
  // Callers that pass limit must not receive the rest of the run. sourceCount is the
  // in-memory total; it is non-enumerable so existing array comparisons stay stable.
  const capped = events.slice(0, Math.min(Math.floor(requested), 1000));
  Object.defineProperty(capped, 'sourceCount', { value: events.length });
  return capped;
}

function activeRunForGroup(tenantId, targetGroupId, targetId) {
  return getStore().testRuns.find(
    (r) =>
      r.tenant_id === tenantId &&
      r.target_group_id === targetGroupId &&
      (r.target_id === targetId || !r.target_id) &&
      ['running', 'collecting', 'planned'].includes(r.status),
  );
}

function validatePolicyBinding(ctx, body, group, check, options = {}) {
  const policyId = String(body.policy_id ?? '').trim();
  if (!policyId) return { policy: null };
  const policy = getTestPolicyForDispatch(ctx, policyId);
  if (!policy) return { error: 'test_policy_not_found', status: 404 };
  if (policy.state !== 'active' || policy.enabled !== true || policy.archived_at) {
    return { error: 'test_policy_disabled', status: 409 };
  }
  if (typeof policy.target_id !== 'string' || !policy.target_id.trim()) {
    return { error: 'test_policy_target_binding_missing', status: 409 };
  }
  if (policy.target_group_id !== group.id
    || policy.target_id !== body.target_id
    || policy.check_id !== check.check_id) {
    return { error: 'test_policy_binding_mismatch', status: 409 };
  }
  if (policy.max_concurrent_runs !== 1) return { error: 'unsafe_policy_concurrency', status: 409 };
  if (policy.safe_windows?.length && !isWithinPolicySafeWindow(policy)) {
    return { error: 'policy_safe_window_closed', status: 429 };
  }

  const trustedDispatch = options.policyDispatch;
  if (policy.cadence !== 'manual' && !trustedDispatch && !options.policyEvent) {
    return { error: 'trusted_policy_dispatch_required', status: 409 };
  }
  if (trustedDispatch) {
    const dispatch = (getStore().testPolicyDispatches ?? []).find(
      (row) => row.id === trustedDispatch.dispatch_id
        && row.tenant_id === ctx.tenantId
        && row.policy_id === policy.id,
    );
    if (!dispatch
      || dispatch.state !== 'leased'
      || dispatch.lease_token !== trustedDispatch.lease_token
      || dispatch.idempotency_key !== trustedDispatch.idempotency_key
      || policy.lease_token !== trustedDispatch.lease_token
      || new Date(dispatch.lease_expires_at) <= new Date()) {
      return { error: 'policy_lease_invalid', status: 409 };
    }
  }
  return { policy };
}

function validateScanBinding(ctx, body, group, check, options = {}) {
  const dispatch = options.scanDispatch;
  if (!dispatch) return { scan: null, step: null };
  if (options.policyDispatch || String(body.policy_id ?? '').trim()) {
    return { error: 'conflicting_dispatch_context', status: 409 };
  }
  const scan = (getStore().validationScans ?? []).find(
    (row) => row.id === dispatch.scan_id && row.tenant_id === ctx.tenantId,
  );
  if (!scan || !['pending', 'running'].includes(scan.status)) return { error: 'scan_dispatch_invalid', status: 409 };
  const reference = dispatch.now ? new Date(dispatch.now) : new Date();
  if (!scan.lease_token
    || scan.lease_token !== dispatch.lease_token
    || (scan.lease_expires_at && new Date(scan.lease_expires_at) <= reference)) {
    return { error: 'scan_dispatch_invalid', status: 409 };
  }
  const step = (scan.steps ?? []).find((row) => row.id === dispatch.step_id);
  if (!step
    || step.status !== 'starting'
    || step.check_id !== check.check_id
    || (scan.plan_snapshot?.target_policy_bindings?.[body.target_id] ?? scan.target_group_id) !== group.id
    || step.target_id !== body.target_id) {
    return { error: 'scan_dispatch_invalid', status: 409 };
  }
  return { scan, step };
}

function revalidateBeforeDispatch(ctx, body, check, initialTarget, probeWillLeaveThisHost, options = {}) {
  const group = getStore().targetGroups.find(
    (candidate) => candidate.id === body.target_group_id
      && candidate.tenant_id === ctx.tenantId
      && !isArchivedTargetGroup(candidate),
  );
  if (!group) return { error: 'target_group_not_found', status: 404 };
  const target = getStore().targets.find(
    (candidate) => candidate.id === initialTarget.id
      && candidate.tenant_id === ctx.tenantId
      && candidate.target_group_id === group.id
      && !isArchivedTarget(candidate),
  );
  if (!target) return { error: 'target_not_found', status: 404 };
  if (targetDedupeKey(target) !== targetDedupeKey(initialTarget)) {
    return { error: 'target_binding_changed', status: 409 };
  }
  const compatibilityError = targetKindCompatibilityError(check, target);
  if (compatibilityError) return compatibilityError;
  const binding = validatePolicyBinding(ctx, body, group, check, options);
  if (binding.error) return binding;
  if (probeWillLeaveThisHost) {
    const ownership = targetOwnershipProof(ctx, group, target.id);
    if (!ownership.verified) return { error: 'ownership_not_verified', status: 409, ownership_state: ownership.state };
  }
  return { group, target, policy: binding.policy };
}

const CANCELLABLE_STATUSES = new Set(['planned', 'running', 'collecting']);

function dropStartedRun(run) {
  const store = getStore();
  const runs = store.testRuns ?? [];
  const index = runs.indexOf(run);
  if (index >= 0) runs.splice(index, 1);
  if (!run?.retest_of_finding_id || !Array.isArray(store.findingRetestLineage)) return;
  store.findingRetestLineage = store.findingRetestLineage.filter((row) => row.test_run_id !== run.id
    || row.tenant_id !== run.tenant_id);
}

function denySafeStart(ctx, action, resourceId, metadata, error, status = 429) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action,
    resource_type: 'test_run',
    resource_id: resourceId,
    metadata,
  });
  persistStore();
  return { error, status };
}

function denyEventCap(ctx, run, metadata = {}) {
  return denySafeStart(
    ctx,
    'test_run.event_cap_denied',
    run.id,
    { check_id: run.check_id, ...metadata },
    'event_cap_exceeded',
    429,
  );
}

export function maybeFinalizeRunAfterProbeIngest(ctxOrRunId, maybeRunId) {
  let ctx = null;
  let runId;
  if (typeof ctxOrRunId === 'string') {
    runId = ctxOrRunId;
  } else if (ctxOrRunId != null && typeof ctxOrRunId === 'object' && maybeRunId != null) {
    ctx = ctxOrRunId;
    runId = maybeRunId;
  } else {
    return null;
  }
  if (!runId) return null;

  const store = getStore();
  const run = store.testRuns.find((r) => {
    if (r.id !== runId) return false;
    if (ctx?.tenantId) return r.tenant_id === ctx.tenantId;
    return true;
  });
  if (!run) return null;
  run.awaiting_external_probe = false;
  if (!hasExternalProbeEvidence(run)) return null;

  // ADR-0008: verdicts are produced from external probe evidence only. The run enters
  // 'collecting'; the collection-window sweeper (or an explicit finalize) publishes the verdict.
  if (run.status === 'running') run.status = 'collecting';
  const verdict = finalizeVerdictIfReady(run);
  persistStore();
  return verdict;
}

export function startTestRun(ctx, body, runtimeConfig = { probeMode: 'simulation' }, options = {}) {
  const selection = validateReviewedOperationSelection(body);
  if (!selection.ok) return { error: selection.error, status: selection.status };
  if (!selection.legacy) return { error: 'reviewed_operation_execution_unavailable', status: 409 };
  const check = getCheckById(body.check_id);
  if (!check) return { error: 'unknown_check', status: 400 };
  if (originIdentityScenario(check) && (!options.reviewedComparison || !body.origin_binding_id)) {
    return denySafeStart(ctx, 'test_run.origin_identity_review_denied', body.target_group_id,
      { check_id: check.check_id, origin_binding_id: body.origin_binding_id ?? null },
      'origin_identity_review_required', 409);
  }
  if (!isCustomerRunnable(check, ctx)) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.blocked_soc_gated',
      resource_type: 'check',
      resource_id: check.check_id,
    });
    persistStore();
    return { error: 'soc_gated_check', status: 403, message: 'This check requires SOC governance.' };
  }

  const targetGroupId = body.target_group_id;
  const group = getStore().targetGroups.find(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) return { error: 'target_group_not_found', status: 404 };

  if (isKillSwitchActiveForTenant(ctx.tenantId)) {
    return denySafeStart(
      ctx,
      'test_run.kill_switch_denied',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId },
      'kill_switch_active',
      423,
    );
  }

  const tenantAccount = getTenantAccount(ctx.tenantId);
  if (tenantAccount?.lifecycle_state === 'suspended') {
    return {
      error: 'tenant_suspended',
      status: 403,
      message: 'Tenant access is suspended.',
    };
  }

  const hourlyRuns = countCustomerRunnableRunsLastHour(ctx.tenantId);
  const subscriptionLimit = assertSubscriptionLimit(
    ctx.tenantId,
    'safe_runs_per_hour',
    hourlyRuns,
  );
  if (!subscriptionLimit.ok) {
    return {
      error: subscriptionLimit.error,
      status: 403,
      metric: subscriptionLimit.metric,
      limit: subscriptionLimit.limit,
      current: subscriptionLimit.current,
      message: 'Subscription safe-run limit reached.',
    };
  }

  const targetId = typeof body.target_id === 'string' ? body.target_id.trim() : '';
  if (!targetId) return { error: 'missing_target_id', status: 400 };
  const target = getStore().targets.find(
    (candidate) => candidate.id === targetId
      && candidate.tenant_id === ctx.tenantId
      && candidate.target_group_id === targetGroupId
      && !isArchivedTarget(candidate),
  );
  if (!target) return { error: 'target_not_found', status: 404 };
  if (activeRunForGroup(ctx.tenantId, targetGroupId, targetId)) {
    return { error: 'concurrent_run_blocked', status: 409 };
  }
  if ((getStore().validationScans ?? []).some((scan) => scan.tenant_id === ctx.tenantId
    && ['pending', 'running'].includes(scan.status) && scan.id !== options.scanDispatch?.scan_id
    && scanIncludesTarget(scan, targetId, targetGroupId))) return { error: 'concurrent_run_blocked', status: 409 };

  const scanBinding = validateScanBinding(ctx, body, group, check, options);
  if (scanBinding.error) return scanBinding;
  const policyBinding = validatePolicyBinding(ctx, body, group, check, options);
  if (policyBinding.error) return policyBinding;
  const policyDispatchId = options.policyDispatch?.dispatch_id ?? null;
  if (policyDispatchId) {
    const existingRun = getStore().testRuns.find(
      (run) => run.tenant_id === ctx.tenantId && run.policy_dispatch_id === policyDispatchId,
    );
    if (existingRun) return { run: getTestRun(ctx, existingRun.id), idempotent_replay: true };
  }
  const scanStepId = scanBinding.step?.id ?? null;
  if (scanStepId) {
    const existingRun = getStore().testRuns.find(
      (run) => run.tenant_id === ctx.tenantId && run.scan_step_id === scanStepId,
    );
    if (existingRun) return { run: getTestRun(ctx, existingRun.id), idempotent_replay: true };
  }

  const compatibilityError = targetKindCompatibilityError(check, target);
  if (compatibilityError) return compatibilityError;

  let originLockdown = null;
  const store = getStore();
  const targetBindings = (store.originBindings ?? []).filter((row) =>
    row.tenant_id === ctx.tenantId && row.status === 'active'
    && (row.protected_target_id === target.id || row.origin_target_id === target.id)
  );
  const bindingRecords = bindingRecordsFromStore(store, ctx.tenantId);
  if ((runtimeConfig.probeMode ?? 'simulation') === 'signed-worker') {
    if (isOriginLockdownHostnameCheck(check, target)) {
      originLockdown = resolveOriginLockdownBinding({
        check,
        target,
        tenantId: ctx.tenantId,
        bindings: targetBindings,
        records: bindingRecords,
        deriveBindingScope,
        currentOriginProof,
      });
    }
    const targetBindingError = validateHostSniTargetBinding(check, target, {
      originLockdown,
      originBindings: { bindings: targetBindings, records: bindingRecords },
    });
    if (targetBindingError) {
      const denied = denySafeStart(
        ctx,
        'test_run.destination_binding_denied',
        targetGroupId,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          target_id: target.id,
          reason: targetBindingError.error,
        },
        targetBindingError.error,
        targetBindingError.status,
      );
      return { ...denied, check_id: targetBindingError.check_id, message: targetBindingError.message };
    }
  }

  // Ownership gate — the last check before this run can put packets on the wire.
  //
  // Scoped to the egress path only: this is the exact condition under which the probe is
  // dispatched to an external worker instead of being computed in-process (see `inlineProbe`
  // below). Simulation and ops-readiness probes never leave the machine, so gating them would
  // block dev/CI flows without protecting anyone.
  //
  // Placed after target resolution (it needs `target.id`) but before any store mutation, so a
  // denial cannot leave a half-created run behind.
  //
  // No deadlock: the ownership challenge that *earns* verification builds its probe job
  // directly via createOwnershipChallengeJob and never passes through startTestRun.
  const probeWillLeaveThisHost =
    (runtimeConfig.probeMode ?? 'simulation') === 'signed-worker'
    && !isOpsReadinessProbeKind(check);

  if (probeWillLeaveThisHost) {
    const ownership = targetOwnershipProof(ctx, group, target.id);
    if (!ownership.verified) {
      return denySafeStart(
        ctx,
        'test_run.ownership_denied',
        targetGroupId,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          target_id: target.id,
          ownership_state: ownership.state,
        },
        'ownership_not_verified',
        409,
      );
    }
  }

  const missingPrereqs = evaluateCheckPrerequisites(check, { onlineAgents: [] });
  if (missingPrereqs.length) {
    return {
      error: 'prerequisites_not_met',
      status: 409,
      missing: missingPrereqs,
      message: `Missing prerequisites: ${missingPrereqs.join(', ')}`,
    };
  }

  const isDemo = isExplicitDemoTenant(ctx.tenantId);
  const nowMs = Date.now();
  const safeWindowBypassed = isDemo && (group.safe_test_windows ?? []).length > 0 && !isWithinSafeTestWindowRaw(group, nowMs);
  if (!isDemo && (group.safe_test_windows ?? []).length > 0 && !isWithinSafeTestWindow(group, nowMs, { tenantId: ctx.tenantId })) {
    return denySafeStart(
      ctx,
      'test_run.safe_window_denied',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId },
      'safe_window_closed',
      429,
    );
  }

  const normalMaxRuns = group.safety_policy?.max_runs_per_hour ?? DEFAULT_MAX_RUNS_PER_HOUR;
  const runsLastHour = countCustomerRunnableRunsLastHour(ctx.tenantId, nowMs);
  const hourlyCapBypassed = isDemo && (runsLastHour >= normalMaxRuns);
  const groupPolicy = normalizeSafetyPolicy(group.safety_policy, { tenantId: ctx.tenantId });
  if (runsLastHour >= groupPolicy.max_runs_per_hour) {
    return denySafeStart(
      ctx,
      'test_run.safe_rate_denied',
      targetGroupId,
      {
        check_id: check.check_id,
        max_runs_per_hour: groupPolicy.max_runs_per_hour,
      },
      'safe_rate_cap_exceeded',
      429,
    );
  }

  const targetDeclarations = controlDeclarationsFromTarget(target);
  const missingInput = isDemo ? demoMissingInputRefusal(check, { target, declarations: targetDeclarations, originBindings: { bindings: targetBindings, records: bindingRecords }, probeMode: runtimeConfig.probeMode }) : null;
  const inputRequirementBypassed = missingInput ? `input_requirement:${missingInput.error}` : null;

  const normalMinSeconds = group.safety_policy?.min_seconds_between_runs ?? DEFAULT_MIN_SECONDS_BETWEEN_RUNS;
  let minIntervalBypassed = false;
  const priorRun = getStore().testRuns.filter((run) => run.tenant_id === ctx.tenantId
    && run.target_id === targetId).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
  if (priorRun && isDemo && normalMinSeconds > 0) {
    const elapsedMs = Date.now() - new Date(priorRun.created_at).getTime();
    if (elapsedMs < normalMinSeconds * 1000) {
      minIntervalBypassed = true;
    }
  }
  if (priorRun && groupPolicy.min_seconds_between_runs > 0) {
    const elapsedMs = Date.now() - new Date(priorRun.created_at).getTime();
    if (elapsedMs < groupPolicy.min_seconds_between_runs * 1000) {
      return denySafeStart(
        ctx,
        'test_run.safe_interval_denied',
        priorRun.id,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          min_seconds_between_runs: groupPolicy.min_seconds_between_runs,
        },
        'safe_min_interval_active',
        429,
      );
    }
  }

  const demoBypassedGates = [];
  if (isDemo && !isCustomerRunnable(check)) demoBypassedGates.push('soc_gated');
  if (safeWindowBypassed) demoBypassedGates.push('safe_window');
  if (hourlyCapBypassed) demoBypassedGates.push('hourly_cap');
  if (minIntervalBypassed) demoBypassedGates.push('min_interval');
  if (inputRequirementBypassed) demoBypassedGates.push(inputRequirementBypassed);

  const finalValidation = revalidateBeforeDispatch(
    ctx,
    { ...body, target_group_id: targetGroupId },
    check,
    target,
    probeWillLeaveThisHost,
    options,
  );
  if (finalValidation.error) {
    if (finalValidation.error === 'ownership_not_verified') {
      return denySafeStart(
        ctx,
        'test_run.ownership_denied',
        targetGroupId,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          target_id: target.id,
          ownership_state: finalValidation.ownership_state,
          phase: 'pre_dispatch_revalidation',
        },
        finalValidation.error,
        finalValidation.status,
      );
    }
    return finalValidation;
  }

  const leavesHost = !isOpsReadinessProbeKind(check) && (runtimeConfig.probeMode ?? 'simulation') === 'signed-worker';
  if (leavesHost && !probeDispatchReady(runtimeConfig)) {
    return denySafeStart(
      ctx,
      'test_run.probe_signing_unavailable',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId, scan_id: scanBinding.scan?.id ?? null },
      'probe_signing_unavailable',
      503,
    );
  }

  const retestFindingId = typeof body.retest_of_finding_id === 'string' ? body.retest_of_finding_id.trim() : '';
  let retestAuthorization = null;
  if (retestFindingId) {
    const allowed = authorizeFindingWrite(ctx);
    if (!allowed.ok) return { error: 'forbidden', status: allowed.status ?? 403, permission: 'finding:write' };
    const finding = getStore().findings.find((row) => row.tenant_id === ctx.tenantId && row.id === retestFindingId);
    if (!finding) return { error: 'unknown_finding', status: 404 };
    if (finding.target_id !== target.id || finding.check_id !== check.check_id) {
      return { error: 'pair_mismatch', status: 409 };
    }
    if (isProtectionValidationFinding(finding)) {
      if (!protectionRetestRunScopeMatches(finding, body)) return { error: 'retest_not_authorized', status: 409, reason: 'retest_scope_mismatch' };
      retestAuthorization = resolveDevProtectionRetestAuthorization(ctx, finding);
      if (retestAuthorization?.ok !== true) {
        return {
          error: 'retest_not_authorized',
          status: retestAuthorization?.status >= 400 ? retestAuthorization.status : 409,
          reason: retestAuthorization?.error ?? 'authorization_not_rechecked',
        };
      }
    }
  }
  const originBindingId = typeof body.origin_binding_id === 'string' ? body.origin_binding_id.trim() : '';
  let originScopeSnapshot = null;
  let originAuthoritySnapshot = null;
  let originIdentityPairSnapshot = null;
  if (originBindingId) {
    const records = bindingRecordsFromStore(getStore(), ctx.tenantId);
    const binding = (getStore().originBindings ?? []).find((row) => row.tenant_id === ctx.tenantId && row.id === originBindingId);
    const protectedTarget = records.targets.find((row) => row.id === binding?.protected_target_id);
    const bindingDecision = validateOriginBindingForRun({
      binding,
      runTarget: target,
      protectedTarget,
      check,
      originProof: currentOriginProof(records, ctx.tenantId, target.id),
      protectedProof: currentOriginProof(records, ctx.tenantId, protectedTarget?.id),
      body,
    });
    if (bindingDecision.error) return bindingDecision;
    // Server-validated approved scope (exact existing binding, both current proofs). Only
    // these safe fields may leave this gate; carry them into the version stamp provenance
    // so the signed job serialization can sign the approved Host/SNI/port/path exactly.
    originScopeSnapshot = bindingDecision.scope;
    originAuthoritySnapshot = bindingDecision.authority;
    if (originIdentityScenario(check)) {
      const paired = buildOriginIdentityPairSnapshot({ check, binding, originTarget: target, protectedTarget,
        scope: originScopeSnapshot, records, tenantId: ctx.tenantId,
        reviewedPair: reviewedOriginIdentityPair(options.reviewedComparison, check, target, originBindingId) });
      if (paired.error) return paired;
      originIdentityPairSnapshot = paired.snapshot;
    }
  }
  const opsReadiness = isOpsReadinessProbeKind(check);
  const stamp = deriveRunEvidenceStamp(check, body, {
    probeMode: runtimeConfig.probeMode ?? 'simulation',
    opsReadiness,
    scenarioVersion: approvedScenarioVersion(check, opsReadiness ? resolveOpsReadinessScenario(check) : null),
  });

  const openWindowEnds = (group.safe_test_windows ?? []).filter((window) =>
    new Date(window.start_at).getTime() <= Date.now() && new Date(window.end_at).getTime() >= Date.now())
    .map((window) => new Date(window.end_at).getTime());
  const safetyConstraints = { ...effectiveSafetyConstraints(check, group),
    assurance_scope: deriveAssuranceScope({ target, policy: policyBinding.policy ?? null, targetGroup: group }),
    ...(openWindowEnds.length ? { safe_window_not_after: new Date(Math.max(...openWindowEnds)).toISOString() } : {}) };
  const runId = newId('run');
  const run = {
    id: runId,
    tenant_id: ctx.tenantId,
    target_group_id: targetGroupId,
    target_id: target.id,
    policy_id: policyBinding.policy?.id ?? null,
    policy_dispatch_id: options.policyDispatch?.dispatch_id ?? null,
    scan_id: scanBinding.scan?.id ?? null,
    scan_step_id: scanStepId,
    check_id: check.check_id,
    vector_family: check.vector_family,
    safety_class: check.safety_class ?? check.risk_class,
    remediation_template: check.remediation_template,
    safety_constraints: safetyConstraints,
    status: 'running',
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    correlation: { nonce_hash: null, window_ms: 120000 },
    collection_deadline_at: new Date(
      Date.now() + collectionDeadlineMs(check),
    ).toISOString(),
    check_version: stamp.check_version ?? null,
    scenario_version: stamp.scenario_version ?? null,
    producer_kind: stamp.producer_kind ?? null,
    expected_behavior: stamp.expected_behavior ?? null,
    expected_behavior_json: stamp.expected_behavior_json ?? null,
    provenance_json: originScopeSnapshot
      ? {
        ...(stamp.provenance_json ?? {}),
        ...(originAuthoritySnapshot ? { origin_authority: originAuthoritySnapshot } : {}),
        ...(originIdentityPairSnapshot ? { origin_identity_pair: originIdentityPairSnapshot } : {}),
        origin_scope: {
          host: originScopeSnapshot.host,
          sni: originScopeSnapshot.sni,
          port: originScopeSnapshot.port ?? null,
          path: originScopeSnapshot.path ?? null,
        },
      }
      : (originLockdownProvenance(originLockdown)
        ? { ...(stamp.provenance_json ?? {}), origin_lockdown: originLockdownProvenance(originLockdown) }
        : (stamp.provenance_json ?? null)),
    origin_binding_id: originBindingId || null,
    retest_of_finding_id: retestFindingId || null,
  };
  getStore().testRuns.push(run);
  if (retestFindingId) {
    const lineage = registerRetestLineage(ctx, {
      finding_id: retestFindingId,
      test_run_id: run.id,
      intent: 'retest',
    }, retestAuthorization ? { authorization: retestAuthorization } : {});
    if (lineage?.error) {
      dropStartedRun(run);
      return lineage;
    }
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_run.started',
    resource_type: 'test_run',
    resource_id: runId,
    metadata: { check_id: check.check_id, policy_id: run.policy_id, scan_id: run.scan_id, scan_step_id: run.scan_step_id },
  });

  if (demoBypassedGates.length > 0) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.demo_gates_bypassed',
      resource_type: 'test_run',
      resource_id: runId,
      metadata: {
        check_id: check.check_id,
        bypassed: demoBypassedGates,
      },
    });
  }

  if (missingInput) {
    const explanationMessage = formatMissingInputMessage(missingInput.error);
    const verdict = {
      id: newId('evidence'),
      tenant_id: run.tenant_id,
      test_run_id: run.id,
      target_id: run.target_id,
      check_id: run.check_id,
      verdict: 'inconclusive',
      confidence: 'external_only',
      explanation: explanationMessage,
      explanation_reason: 'required_input_missing',
      required_input: missingInput.error,
      evidence_ids: [],
      severity: 'info',
      placement_confidence: {
        explanation_reason: 'required_input_missing',
        reason: 'required_input_missing',
        required_input: missingInput.error,
        requests_sent: 0,
      },
      created_at: new Date().toISOString(),
    };
    getStore().verdicts.push(verdict);
    run.status = 'verdicted';
    run.completed_at = new Date().toISOString();
    run.probe_external_result = 'unsupported_target';
    run.summary = { requests_sent: 0, required_input_missing: missingInput.error };

    audit({
      tenant_id: run.tenant_id,
      actor_user_id: 'system',
      actor_role: 'system',
      action: 'verdict.published',
      resource_type: 'test_run',
      resource_id: run.id,
      metadata: {
        verdict: verdict.verdict,
        confidence: verdict.confidence,
      },
    });

    computeReadiness(run.tenant_id);
    notifyRunTerminal(run, { reason: 'verdicted' });
    incMetric('test_runs_started_total');
    persistStore();

    return { run, jobs_dispatched: 0, verdict };
  }

  const probeMode = runtimeConfig.probeMode ?? 'simulation';
  let probe;
  let probeEvent = null;
  let probeJob = null;

  const inlineProbe = isOpsReadinessProbeKind(check) || probeMode !== 'signed-worker';

  if (!inlineProbe) {
    if (wouldExceedEventCap(run, 1)) {
      dropStartedRun(run);
      return denyEventCap(ctx, run, { phase: 'probe_job' });
    }
    try {
      probeJob = createProbeJob(ctx, run, check, target, body.probe_profile, runtimeConfig);
    } catch (error) {
      dropStartedRun(run);
      // A bound run without its approved origin scope fails closed: the started run intent is
      // dropped, the explicit reason is audited, and no signed job exists to dispatch.
      return denySafeStart(
        ctx,
        'test_run.dispatch_failed',
        targetGroupId,
        {
          check_id: check.check_id,
          scan_id: run.scan_id,
          reason: error?.code === 'bound_run_missing_approved_origin_scope'
            ? 'bound_run_missing_approved_origin_scope'
            : 'probe_job_dispatch_failed',
        },
        'probe_job_dispatch_failed',
        503,
      );
    }
    run.correlation.nonce_hash = probeJob.nonce_hash;
    run.awaiting_external_probe = true;
    probe = { nonce: probeJob.nonce, nonce_hash: probeJob.nonce_hash, external_result: null };
  } else {
    probe = isOpsReadinessProbeKind(check)
      ? executeOpsReadinessProbe(ctx, check, target)
      : simulateProbeResult(check, target, body.probe_profile);
    run.correlation.nonce_hash = probe.nonce_hash;

    if (wouldExceedEventCap(run, 1)) {
      dropStartedRun(run);
      return denyEventCap(ctx, run, { phase: 'probe' });
    }

    const evidenceLabel = isOpsReadinessProbeKind(check)
      ? 'ops_readiness_probe_evidence'
      : 'probe_simulation_evidence';

    probeEvent = {
      id: probe.event_id,
      tenant_id: ctx.tenantId,
      test_run_id: runId,
      target_id: target.id,
      check_id: check.check_id,
      source: probe.source,
      signal_type: probe.signal_type,
      producer_kind: 'internal_simulation',
      timestamp: new Date().toISOString(),
      nonce_hash: probe.nonce_hash,
      metadata: { ...probe.metadata, external_result: probe.external_result },
    };
    getStore().events.push(probeEvent);

    recordEvidence(ctx, {
      test_run_id: runId,
      label: evidenceLabel,
      metadata: enrichProbeMetadataWithWafCatalog(
        {
          vector_family: check.vector_family,
          safety_class: check.safety_class,
          probe_event_id: probeEvent.id,
          ...(isOpsReadinessProbeKind(check)
            ? { ops_readiness: true }
            : { simulation: 'SAFE_PROBE_SIMULATION' }),
        },
        check.check_id,
      ),
      related_event_id: probeEvent.id,
    });
    run.status = 'collecting';
    run.probe_external_result = probe.external_result;

    if (isOpsReadinessProbeKind(check)) {
      // Ops-readiness runs execute inline with no agent and no external worker job.
      // Finalize to an honest verdict immediately so customer-runnable ops checks
      // never hang in 'collecting'.
      finalizeOpsReadinessVerdict(run, probe);
    }
  }

  incMetric('test_runs_started_total');
  persistStore();

  const result = { run, jobs_dispatched: 0 };
  if (probeEvent) result.probe_event = probeEvent;
  if (probeJob) {
    result.probe_job = {
      id: probeJob.id,
      status: probeJob.status,
      job_signature: probeJob.job_signature,
      nonce_hash: probeJob.nonce_hash,
    };
  }
  return result;
}


function finalizeNoObservation(run) {
  // Publication uses accepted evidence; it does not append another probe event.
  return finalizeVerdictIfReady(run, { finalizedWithoutObservation: true });
}

function finalizeOpsReadinessVerdict(run, probe) {
  const store = getStore();
  const existing = store.verdicts.find((v) => v.test_run_id === run.id);
  if (existing) return existing;

  const result = correlateOpsReadinessVerdict({
    externalResult: probe.external_result,
    opsValidationOk: probe.metadata?.ops_validation_ok,
  });

  // Retain only the inline result actually evaluated, never unrelated activity.
  const evidenceIds = store.events
    .filter((e) => e.id === probe.event_id && e.test_run_id === run.id && e.tenant_id === run.tenant_id)
    .map((e) => e.id);

  const verdict = {
    id: newId('evidence'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    verdict: result.verdict,
    confidence: result.confidence,
    explanation: result.explanation,
    evidence_ids: evidenceIds,
    severity: result.severity,
    created_at: new Date().toISOString(),
  };
  store.verdicts.push(verdict);
  run.status = 'verdicted';
  run.completed_at = new Date().toISOString();

  audit({
    tenant_id: run.tenant_id,
    actor_user_id: 'system',
    actor_role: 'system',
    action: 'verdict.published',
    resource_type: 'test_run',
    resource_id: run.id,
    metadata: {
      verdict: verdict.verdict,
      confidence: verdict.confidence,
      ops_readiness: true,
    },
  });

  computeReadiness(run.tenant_id);
  notifyRunTerminal(run, { reason: 'verdicted' });
  return verdict;
}

function finalizeVerdictIfReady(run, options = {}) {
  const store = getStore();
  if (store.verdicts.some((v) => v.test_run_id === run.id)) return store.verdicts.find((v) => v.test_run_id === run.id);
  if (!hasExternalProbeEvidence(run)) return null;
  const target = store.targets.find((t) => t.id === run.target_id);
  const probeEvent = store.events.find(
    (e) =>
      e.test_run_id === run.id && e.tenant_id === run.tenant_id &&
      e.signal_type === 'probe_result' &&
      isTrustedProducerEvent(e) &&
      typeof run.correlation?.nonce_hash === 'string' && run.correlation.nonce_hash.length > 0 &&
      e.nonce_hash === run.correlation.nonce_hash,
  );

  // A probe-only check's verdict cannot change after its trusted result; publish without waiting.
  if (
    !options.finalizedWithoutObservation
    && !isCollectionWindowExpired(run)
    && !(probeEvent && probeResultCompletesEvidence(getCheckById(run.check_id)))
  ) {
    return null;
  }

  const probeMetadata = probeEvent?.metadata ?? probeEvent?.metadata_json ?? {};
  const externalResult = probeMetadata.external_result ?? 'not_run';
  // Stamped runs finalize against the immutable start snapshot; legacy unstamped runs keep
  // the historical catalog fallback (see verdictExpectedBehaviorForRun).
  const expectedBehavior = verdictExpectedBehaviorForRun(run);
  const probeKind = getCheckById(run.check_id)?.probe_profile?.kind ?? null;
  const probeIoObserved = probeEventHasProbeIo(probeEvent);
  const originBinding = devRunOriginBinding(run);

  const signedJob = (store.probeJobs ?? []).find((j) => j.test_run_id === run.id);
  const signedDeclarations = signedJob?.probe_profile?.declarations ?? null;
  const declarations = controlDeclarationsFromTarget(target) ?? signedDeclarations ?? null;

  const safeProbeMetadata = { ...probeMetadata };
  delete safeProbeMetadata.declarations;
  delete safeProbeMetadata.expected_behavior;
  delete safeProbeMetadata.declared_limit;

  // ADR-0008: verdicts are produced from external probe evidence only.
  const result = correlateExternalOnlyVerdict({
    externalResult,
    expectedBehavior,
    probeKind,
    probeIoObserved,
    probeMetadata: safeProbeMetadata,
    declarations,
    originBinding,
    checkId: run.check_id,
  });

  // Cite exactly the accepted result used above. Activity is inspection metadata,
  // not verdict proof; including it makes an otherwise valid citation set invalid.
  const evidenceIds = probeEvent ? [probeEvent.id] : [];

  const verdict = {
    id: newId('evidence'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    verdict: result.verdict,
    confidence: result.confidence,
    explanation: result.explanation,
    explanation_reason: result.explanation_reason ?? null,
    evidence_ids: evidenceIds,
    severity: result.severity,
    grading_version: probeMetadata.grading_version ?? null,
    signature_corpus_version: probeMetadata.signature_corpus_version ?? null,
    source_perspective: probeMetadata.source_perspective ?? null,
    exposure_basis: result.metadata?.exposure_basis ?? null,
    ...(result.metadata?.port_results ? { port_results: result.metadata.port_results } : {}),
    placement_confidence: {
      explanation_reason: result.explanation_reason ?? null,
      reason: result.explanation_reason ?? null,
      grading_version: probeMetadata.grading_version ?? null,
      signature_corpus_version: probeMetadata.signature_corpus_version ?? null,
      source_perspective: probeMetadata.source_perspective ?? null,
      exposure_basis: result.metadata?.exposure_basis ?? null,
      ...(result.metadata?.port_results ? { port_results: result.metadata.port_results } : {}),
    },
    created_at: new Date().toISOString(),
  };
  store.verdicts.push(verdict);
  run.status = 'verdicted';
  run.completed_at = new Date().toISOString();

  audit({
    tenant_id: run.tenant_id,
    actor_user_id: 'system',
    actor_role: 'system',
    action: options.finalizedWithoutObservation ? 'verdict.finalized_no_observation' : 'verdict.published',
    resource_type: 'test_run',
    resource_id: run.id,
    metadata: {
      verdict: verdict.verdict,
      confidence: verdict.confidence,
    },
  });

  if (result.createsFinding) {
    upsertFindingFromVerdict(
      { tenantId: run.tenant_id, userId: 'system', role: 'system' },
      verdict,
      run,
      target,
    );
  }
  applyPassingRetestToFindings(
    { tenantId: run.tenant_id, userId: 'system', role: 'system' },
    { verdict, run, target },
  );

  computeReadiness(run.tenant_id);
  notifyRunTerminal(run, { reason: 'verdicted' });
  return verdict;
}

function revokeDispatchedJobsForRun(run) {
  const cancelledProbeJobIds = [];
  for (const job of getStore().probeJobs) {
    if (job.tenant_id !== run.tenant_id || job.test_run_id !== run.id) continue;
    if (!['pending', 'leased'].includes(job.status)) continue;
    job.status = 'cancelled';
    job.completed_at = run.completed_at;
    cancelledProbeJobIds.push(job.id);
  }
  return { cancelledProbeJobIds };
}

export function autoCancelActiveSafeRunsForKillSwitch(ctx, reason) {
  const cancelledRunIds = [];
  const cancelledRuns = [];
  for (const run of getStore().testRuns) {
    if (run.tenant_id !== ctx.tenantId) continue;
    if (!CANCELLABLE_STATUSES.has(run.status)) continue;
    run.status = 'cancelled';
    run.completed_at = new Date().toISOString();
    run.cancelled_by_kill_switch = true;
    const revoked = revokeDispatchedJobsForRun(run);
    run.summary = {
      ...(run.summary ?? {}),
      cancellation: {
        reason: reason ?? 'kill_switch',
        by: ctx.userId,
        role: ctx.role,
        source: 'kill_switch',
        scan_id: run.scan_id ?? null,
      },
    };
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.kill_switch_auto_cancel',
      resource_type: 'test_run',
      resource_id: run.id,
      metadata: {
        reason: reason ?? null,
        check_id: run.check_id,
        target_group_id: run.target_group_id,
        scan_id: run.scan_id ?? null,
        cancelled_probe_job_ids: revoked.cancelledProbeJobIds,
      },
    });
    cancelledRunIds.push(run.id);
    cancelledRuns.push(run);
  }
  if (cancelledRunIds.length) persistStore();
  for (const run of cancelledRuns) notifyRunTerminal(run, { reason: 'kill_switch' });
  return cancelledRunIds;
}

export function cancelTestRun(ctx, id, options = {}) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  if (!CANCELLABLE_STATUSES.has(run.status)) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.cancel_denied',
      resource_type: 'test_run',
      resource_id: id,
      metadata: { status: run.status },
    });
    persistStore();
    return { error: 'not_cancellable', status: 409 };
  }
  const reason = normalizeCancelReason(options.reason);
  const source = options.source ?? 'user';
  run.status = 'cancelled';
  run.completed_at = new Date().toISOString();
  const revoked = revokeDispatchedJobsForRun(run);
  run.summary = {
    ...(run.summary ?? {}),
    cancellation: {
      reason,
      by: ctx.userId,
      role: ctx.role,
      source,
      scan_id: options.scan_id ?? run.scan_id ?? null,
    },
  };
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_run.cancelled',
    resource_type: 'test_run',
    resource_id: id,
    metadata: {
      reason,
      cancelled_by: ctx.userId,
      cancelled_by_role: ctx.role,
      source,
      check_id: run.check_id,
      target_group_id: run.target_group_id,
      scan_id: options.scan_id ?? run.scan_id ?? null,
      cancelled_probe_job_ids: revoked.cancelledProbeJobIds,
    },
  });
  persistStore();
  notifyRunTerminal(run, { reason: 'cancelled', source });
  return { run };
}
