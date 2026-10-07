import {
  CHECK_CATALOG,
  customerSelectableChecks,
  evaluateCheckPrerequisites,
  getCheckById,
  isCustomerRunnable,
} from '../../contracts/checks.mjs';
import { targetKindCompatibilityError } from '../../contracts/checkTargetCompatibility.mjs';
import { targetDedupeKey } from '../../contracts/targetManagement.mjs';
import { probeDispatchReady } from '../../config.mjs';
import { approvedScenarioVersion, deriveRunEvidenceStamp, verdictExpectedBehaviorForRun } from '../../lib/checkDefinitionVersion.mjs';
import { projectRunActivity } from '../../lib/probeActivity.mjs';
import { newId } from '../../lib/ids.mjs';
import {
  VERDICT_INSERTED,
  verdictWasInserted,
} from './validationEvidenceRepository.mjs';
import { incMetric } from '../../lib/metrics.mjs';
import {
  buildSignedProbeJobRecord,
  validateHostSniTargetBinding,
} from '../../lib/probeJobs.mjs';
import { redactObject } from '../../lib/redact.mjs';
import {
  scrubFindingForCustomer,
  scrubRunForCustomer,
} from '../../lib/outsideInEvidence.mjs';
import {
  countCustomerRunnableRunsLastHour,
  effectiveSafetyConstraints,
  isWithinSafeTestWindow,
  lastRunForTargetGroup,
  wouldExceedEventCap,
} from '../../lib/safeTestGuards.mjs';
import { isTrustedProducerEvent } from '../../lib/trustedEventProvenance.mjs';
import { ownershipProofFromStates } from '../../lib/ownershipPolicy.mjs';
import { ownershipParentFor } from '../../lib/subdomainEnumeration.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../../lib/wafProductCatalog.mjs';
import {
  correlateExternalOnlyVerdict,
  correlateOpsReadinessVerdict,
  probeEventHasProbeIo,
} from '../../services/correlation.mjs';
import {
  buildOpsReadinessData,
  executeOpsReadinessProbe,
  isOpsReadinessProbeKind,
  resolveOpsReadinessScenario,
} from '../../lib/opsReadinessValidation.mjs';
import {
  buildFindingListEnvelope,
  findingListQueryFailure,
  parseFindingListQuery,
} from '../../lib/findingList.mjs';
import { authorizeFindingWrite, planFindingPatch } from '../../lib/findingLifecycle.mjs';
import { isProtectionValidationFinding, protectionRetestContext, protectionRetestRunScopeMatches } from '../../lib/protectionValidationFindings.mjs';
import { currentOriginProof, validateOriginBindingForRun } from '../../services/originBindings.mjs';
import { simulateProbeResult } from '../../services/probeStub.mjs';
import { LEAN_GROUP_LOOKUP } from './coreCatalogRepository.mjs';
import { isWithinPolicySafeWindow } from '../../contracts/testPolicyManagement.mjs';
import { normalizeCancelReason, withCheckSection } from '../../contracts/validationScanManagement.mjs';

/** @type {readonly string[]} */
export const VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'listTestRuns',
  'getTestRun',
  'getVerdictForRun',
  'listRunEvents',
  'listEvidence',
  'getEvidence',
  'listFindings',
  'getFinding',
  'patchFinding',
  'findEventByTenantEventId',
  'appendEventIdempotent',
  'appendEvidence',
  'createTestRun',
  'updateTestRun',
  'withRunMutationLock',
  'cancelTestRunAtomic',
  'appendEvent',
  'createVerdictIfAbsent',
  'findOpenFinding',
  'upsertOpenFindingFromVerdict',
]);

/** @type {readonly string[]} */
export const VALIDATION_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['getTargetGroup']);

/** @type {readonly string[]} */
export const VALIDATION_PROBE_JOB_REPOSITORY_METHODS = Object.freeze(['createProbeJob']);

/** @type {readonly string[]} */
export const VALIDATION_KILL_SWITCH_REPOSITORY_METHODS = Object.freeze([
  'isKillSwitchActiveForTenant',
]);

/** @type {readonly string[]} */
export const VALIDATION_AUDIT_REPOSITORY_METHODS = Object.freeze([
  'appendAuditEvent',
  'withTenantAuditLock',
]);

const ACTIVE_RUN_STATUSES = Object.freeze(['planned', 'running', 'collecting']);
const CANCELLABLE_STATUSES = new Set(['planned', 'running', 'collecting']);

const OBSERVATION_RAW_FIELD_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packet_data',
  'raw_payload',
  'payload',
  'body',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);
const OBSERVATION_RAW_FIELD_COMPACT_DENYLIST = new Set(
  [...OBSERVATION_RAW_FIELD_DENYLIST].map((key) => key.replace(/_/g, '')),
);

function normalizeObservationRawFieldKey(key) {
  return String(key)
    .trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function observationBodyContainsRawFields(body) {
  if (!body || typeof body !== 'object') return false;
  const scan = (value) => {
    if (value == null) return false;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (scan(item)) return true;
      }
      return false;
    }
    if (typeof value !== 'object') return false;
    for (const key of Object.keys(value)) {
      const normalized = normalizeObservationRawFieldKey(key);
      const compact = normalized.replace(/_/g, '');
      if (
        OBSERVATION_RAW_FIELD_DENYLIST.has(normalized)
        || OBSERVATION_RAW_FIELD_COMPACT_DENYLIST.has(compact)
        || normalized.startsWith('raw_')
        || compact.startsWith('raw')
      ) {
        return true;
      }
      if (scan(value[key])) return true;
    }
    return false;
  };
  return scan(body);
}

const RESERVED_PUBLIC_EVENT_SIGNAL_TYPES = new Set([
  'probe_activity',
  'probe_result',
  'agent_observation',
  'ownership_observation',
]);

const EVENT_RAW_FIELD_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packet_data',
  'raw_payload',
  'exploit_payload',
  'body',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);
const EVENT_RAW_FIELD_COMPACT_DENYLIST = new Set(
  [...EVENT_RAW_FIELD_DENYLIST].map((key) => key.replace(/_/g, '')),
);

function normalizeEventRawFieldKey(key) {
  return String(key)
    .trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function eventIngestContainsRawFields(value) {
  if (value == null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some((item) => eventIngestContainsRawFields(item));
  for (const [key, child] of Object.entries(value)) {
    const normalized = normalizeEventRawFieldKey(key);
    const compact = normalized.replace(/_/g, '');
    if (
      EVENT_RAW_FIELD_DENYLIST.has(normalized)
      || EVENT_RAW_FIELD_COMPACT_DENYLIST.has(compact)
      || normalized.startsWith('raw_')
      || compact.startsWith('raw')
    ) {
      return true;
    }
    if (eventIngestContainsRawFields(child)) return true;
  }
  return false;
}

function isCollectionWindowExpired(run, nowMs) {
  if (!run.collection_deadline_at) return false;
  return nowMs >= new Date(run.collection_deadline_at).getTime();
}

function hasExternalProbeEvidence(run, events) {
  if (run.probe_external_result != null && run.probe_external_result !== '') return true;
  const nonce = run.correlation?.nonce_hash;
  return events.some(
    (e) => e.test_run_id === run.id
      && e.signal_type === 'probe_result'
      && isTrustedProducerEvent(e)
      && e.nonce_hash === nonce,
  );
}

function findProbeEvent(run, events) {
  const nonce = run.correlation?.nonce_hash;
  return events.find(
    (e) =>
      e.test_run_id === run.id
      && e.signal_type === 'probe_result'
      && isTrustedProducerEvent(e)
      && e.nonce_hash === nonce,
  );
}

function collectionDeadlineMs(check) {
  const seconds = check?.safety_constraints?.max_duration_seconds ?? 120;
  return seconds * 1000;
}

/** @type {readonly string[]} */
export const POSTGRES_VALIDATION_TEST_RUNS_SERVICE_METHODS = Object.freeze([
  'listChecks',
  'listTestRuns',
  'getTestRun',
  'getRunEvents',
  'getRunActivity',
  'startTestRun',
  'finalizeTestRun',
  'cancelTestRun',
  'maybeFinalizeRunAfterProbeIngest',
  'registerRunTerminalHook',
  'notifyRunTerminal',
]);

/** @type {readonly string[]} */
export const POSTGRES_VALIDATION_EVIDENCE_SERVICE_METHODS = Object.freeze([
  'listEvidence',
  'getEvidence',
]);

/** @type {readonly string[]} */
export const POSTGRES_VALIDATION_FINDINGS_SERVICE_METHODS = Object.freeze([
  'listFindings',
  'listFindingsEnvelope',
  'getFinding',
  'patchFinding',
]);

/** @type {readonly string[]} */
export const POSTGRES_EVENTS_SERVICE_METHODS = Object.freeze(['ingestEvent']);

export const POSTGRES_VALIDATION_ORCHESTRATION_ERROR = 'postgres_validation_orchestration_not_wired';

function orchestrationNotWired() {
  return { error: POSTGRES_VALIDATION_ORCHESTRATION_ERROR, status: 503 };
}

function assertRepositoryMethods(repo, label, methods) {
  if (!repo || typeof repo !== 'object') {
    throw new Error(`Postgres validation service adapter requires repositories.${label}.`);
  }
  for (const method of methods) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres validation service adapter requires ${label}.${method}().`);
    }
  }
}

function assertValidationServiceDependencies(repositories) {
  assertRepositoryMethods(
    repositories?.validationEvidence,
    'validationEvidence',
    VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(repositories?.audit, 'audit', VALIDATION_AUDIT_REPOSITORY_METHODS);
  assertRepositoryMethods(
    repositories?.coreCatalog,
    'coreCatalog',
    VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(repositories?.probeJobs, 'probeJobs', VALIDATION_PROBE_JOB_REPOSITORY_METHODS);
  assertRepositoryMethods(
    repositories?.killSwitch,
    'killSwitch',
    VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
  );
}

/**
 * @param {{
 *   validationEvidence?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresValidationServices(repositories, options = {}) {
  assertValidationServiceDependencies(repositories);
  const validationEvidence = repositories.validationEvidence;
  const audit = repositories.audit;
  const coreCatalog = repositories.coreCatalog;
  const probeJobs = repositories.probeJobs;
  const killSwitch = repositories.killSwitch;
  const productionReleaseEvidence = repositories.productionReleaseEvidence;
  // Read by live-egress ownership gates only. Deliberately optional here so narrow service
  // callers still construct; every egress path fails closed when the repository is absent.
  const ownershipVerifications = repositories.ownershipVerifications;
  const testPolicies = repositories.testPolicies;
  // Optional: only wired when the validation scan slice is present. Scan dispatch fails closed without it.
  const validationScans = repositories.validationScans;
  const internalManagement = repositories.internalManagement ?? null;
  const nowFn = options.now ?? (() => new Date());
  const runTerminalHooks = new Set();

  async function notifyRunTerminal(run, context = {}) {
    if (!run) return;
    for (const hook of runTerminalHooks) {
      try {
        await hook(run, context);
      } catch {
        incMetric('run_terminal_hook_failed');
      }
    }
  }

  async function tenantSuspended(tenantId) {
    if (typeof internalManagement?.getTenantDetail !== 'function') return false;
    const detail = await internalManagement.getTenantDetail(tenantId);
    return detail?.account?.lifecycle_state === 'suspended';
  }

  async function validateScanBinding(ctx, body, group, check, dispatchOptions = {}) {
    const dispatch = dispatchOptions.scanDispatch;
    if (!dispatch) return { scan: null, step: null };
    if (dispatchOptions.policyDispatch || String(body.policy_id ?? '').trim()) {
      return { error: 'conflicting_dispatch_context', status: 409 };
    }
    if (typeof validationScans?.getScan !== 'function' || typeof validationScans?.getStep !== 'function') {
      return { error: 'scan_dispatch_invalid', status: 409 };
    }
    const scan = await validationScans.getScan(ctx, dispatch.scan_id);
    if (!scan || scan.tenant_id !== ctx.tenantId || !['pending', 'running'].includes(scan.status)) {
      return { error: 'scan_dispatch_invalid', status: 409 };
    }
    if (!scan.lease_token
      || scan.lease_token !== dispatch.lease_token
      || (scan.lease_expires_at && new Date(scan.lease_expires_at) <= nowFn())) {
      return { error: 'scan_dispatch_invalid', status: 409 };
    }
    const step = await validationScans.getStep(ctx, dispatch.step_id);
    if (!step
      || step.scan_id !== scan.id
      || step.status !== 'starting'
      || step.check_id !== check.check_id
      || scan.target_group_id !== group.id
      || step.target_id !== body.target_id) {
      return { error: 'scan_dispatch_invalid', status: 409 };
    }
    return { scan, step };
  }

  /**
   * Gather ops-readiness governance records from Postgres repositories so the
   * inline ops-readiness probe computes a real result from persisted data. Any
   * repository that is genuinely unavailable degrades to empty inputs, which
   * yields an accurate error/no-evidence verdict rather than a hardcoded pass.
   */
  async function gatherOpsReadinessData(ctx, check) {
    const scenario = resolveOpsReadinessScenario(check);
    let releaseEvidenceLedger = [];
    if (
      productionReleaseEvidence
      && typeof productionReleaseEvidence.listProductionReleaseEvidence === 'function'
    ) {
      releaseEvidenceLedger = await productionReleaseEvidence.listProductionReleaseEvidence(ctx);
    }
    let killSwitchRecord = null;
    let auditEntries = [];
    if (scenario === 'kill_switch_readiness') {
      if (typeof killSwitch.getKillSwitchRecord === 'function') {
        killSwitchRecord = await killSwitch.getKillSwitchRecord(ctx);
      }
      if (typeof audit.listAuditEntries === 'function') {
        auditEntries = await audit.listAuditEntries(ctx, { limit: 500 });
      }
    }
    return buildOpsReadinessData({
      scenario,
      tenantId: ctx.tenantId,
      releaseEvidenceLedger,
      killSwitchRecord,
      auditEntries,
    });
  }

  async function appendAudit(ctx, action, resourceType, resourceId, metadata, options = {}) {
    await audit.appendAuditEvent(
      {
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action,
        resource_type: resourceType,
        resource_id: resourceId,
        metadata: metadata == null ? undefined : redactObject(metadata),
      },
      {
        now: nowFn(),
        client: options.client,
        auditLockHeld: options.auditLockHeld,
        idempotency: options.idempotency,
      },
    );
  }

  async function denySafeStart(ctx, action, resourceId, metadata, error, status = 429, options = {}) {
    await appendAudit(ctx, action, 'test_run', resourceId, metadata, options);
    return { error, status };
  }

  async function validatePolicyBinding(ctx, body, group, check, dispatchOptions = {}) {
    const policyId = String(body.policy_id ?? '').trim();
    if (!policyId) return { policy: null };
    if (typeof testPolicies?.getActiveTestPolicy !== 'function') {
      return { error: 'policy_repository_unavailable', status: 503 };
    }
    const policy = await testPolicies.getActiveTestPolicy(ctx, policyId);
    if (!policy) return { error: 'test_policy_not_found', status: 404 };
    if (policy.state !== 'active' || policy.enabled !== true || policy.archived_at) {
      return { error: 'test_policy_disabled', status: 409 };
    }
    if (policy.target_group_id !== group.id
      || policy.target_id !== body.target_id
      || policy.check_id !== check.check_id) {
      return { error: 'test_policy_binding_mismatch', status: 409 };
    }
    if (Number(policy.max_concurrent_runs) !== 1) return { error: 'unsafe_policy_concurrency', status: 409 };
    if (policy.safe_windows?.length && !isWithinPolicySafeWindow(policy, nowFn())) {
      return { error: 'policy_safe_window_closed', status: 429 };
    }

    const trustedDispatch = dispatchOptions.policyDispatch;
    if (policy.cadence !== 'manual' && !trustedDispatch && !dispatchOptions.policyEvent) {
      return { error: 'trusted_policy_dispatch_required', status: 409 };
    }
    if (trustedDispatch && (
      policy.lease_token !== trustedDispatch.lease_token
      || !policy.lease_expires_at
      || new Date(policy.lease_expires_at) <= nowFn()
    )) {
      return { error: 'policy_lease_invalid', status: 409 };
    }
    return { policy };
  }

  /**
   * Replay a durable dispatch (policy occurrence or scan step) whose run row committed. Recreates a
   * missing signed probe job and repairs run correlation so a run is never left waiting forever.
   */
  async function repairSignedDispatch(ctx, existingRun, { body, check, target, targetGroupId, probeWillLeaveThisHost, runtimeConfig, dispatchOptions, phase }) {
    if (!probeDispatchReady(runtimeConfig)) {
      return { error: 'probe_signing_unavailable', status: 503, retryable: true };
    }
    const finalValidation = await revalidateBeforeDispatch(
      ctx,
      { ...body, target_group_id: targetGroupId },
      check,
      target,
      probeWillLeaveThisHost,
      dispatchOptions,
    );
    if (finalValidation.error) {
      return denySafeStart(
        ctx,
        finalValidation.error === 'ownership_not_verified'
          ? 'test_run.ownership_denied'
          : 'test_run.policy_dispatch_denied',
        existingRun.id,
        {
          check_id: check.check_id,
          policy_id: existingRun.policy_id ?? null,
          scan_id: existingRun.scan_id ?? null,
          target_group_id: targetGroupId,
          target_id: target.id,
          ownership_state: finalValidation.ownership_state,
          reason: finalValidation.reason,
          phase,
        },
        finalValidation.error,
        finalValidation.status,
      );
    }
    if (typeof probeJobs.getProbeJobByTestRun !== 'function') {
      return {
        error: 'probe_dispatch_recovery_unavailable',
        status: 503,
        retryable: true,
      };
    }

    let probeJob = await probeJobs.getProbeJobByTestRun(ctx, existingRun.id);
    const recoveredMissingJob = !probeJob;
    if (!probeJob) {
      const recoveryNow = nowFn();
      let builtJob;
      try {
        builtJob = buildSignedProbeJobRecord({
          run: existingRun,
          check,
          target,
          probeProfile: body.probe_profile,
          ownershipBinding: finalValidation.ownershipBinding,
          probeWorkerSecret: runtimeConfig.probeWorkerSecret,
          now: recoveryNow,
          newId: () => newId('pjob'),
        });
      } catch (error) {
        if (error?.code === 'bound_run_missing_approved_origin_scope') {
          // Fail closed: a bound legacy/recovery record without its stored approved origin
          // scope must never be re-signed from caller input or target metadata. Report the
          // blocked recovery and drop the unsafe job creation instead of dispatching a
          // wrong-scope job. The run intent stays committed (no orphan); the structured
          // error is permanent until the stored provenance is repaired by its owner.
          await appendAudit(ctx, 'probe_job.dispatch_recovery_blocked', 'probe_job', existingRun.id, {
            test_run_id: existingRun.id,
            check_id: check.check_id,
            origin_binding_id: existingRun.origin_binding_id ?? null,
            reason: 'bound_run_missing_approved_origin_scope',
          });
          return {
            error: 'probe_dispatch_recovery_scope_blocked',
            status: 503,
            retryable: false,
            message:
              'Recovery refused to rebuild this bound run\'s probe job without its stored approved origin scope.',
          };
        }
        throw error;
      }
      // createProbeJob serializes by tenant/run and returns an already-committed row if
      // another retry won the race, so this repair never creates duplicate outbound work.
      probeJob = await probeJobs.createProbeJob(ctx, builtJob);
    }

    const probeBindingValid = probeJob?.id
      && probeJob.test_run_id === existingRun.id
      && probeJob.check_id === existingRun.check_id
      && (probeJob.target_id ?? null) === (existingRun.target_id ?? null);
    const persistedNonceHash = existingRun.correlation?.nonce_hash ?? null;
    if (!probeBindingValid || (persistedNonceHash && persistedNonceHash !== probeJob.nonce_hash)) {
      return {
        error: 'probe_dispatch_binding_conflict',
        status: 503,
        retryable: true,
      };
    }

    const repairPatch = {};
    if (!persistedNonceHash) {
      repairPatch.correlation = { nonce_hash: probeJob.nonce_hash, window_ms: 120000 };
    }
    if (['pending', 'leased'].includes(probeJob.status) && existingRun.awaiting_external_probe !== true) {
      repairPatch.awaiting_external_probe = true;
    }
    const dispatchStateRepaired = Object.keys(repairPatch).length > 0;
    const replayRun = dispatchStateRepaired
      ? await validationEvidence.updateTestRun(ctx, existingRun.id, repairPatch)
      : existingRun;

    if (recoveredMissingJob || dispatchStateRepaired) {
      await appendAudit(ctx, 'probe_job.dispatch_recovered', 'probe_job', probeJob.id, {
        test_run_id: existingRun.id,
        check_id: check.check_id,
        probe_job_recreated: recoveredMissingJob,
        run_state_repaired: dispatchStateRepaired,
      });
    }

    return {
      run: replayRun,
      jobs_dispatched: 0,
      probe_job: {
        id: probeJob.id,
        status: probeJob.status,
        job_signature: probeJob.job_signature,
        nonce_hash: probeJob.nonce_hash,
      },
      idempotent_replay: true,
      dispatch_repaired: recoveredMissingJob || dispatchStateRepaired,
    };
  }

  async function authoritativeOwnership(ctx, group, target) {
    const own = await ownTargetOwnership(ctx, group, target);
    if (own.verified || own.unavailable) return own;
    const parent = ownershipParentFor(target, group.targets ?? []);
    if (!parent) return own;
    const inherited = await ownTargetOwnership(ctx, group, parent);
    if (!inherited.verified) return own;
    return {
      ...inherited,
      source: 'parent',
      inherited_from_target_id: parent.id,
      ownershipBinding: {
        ...inherited.ownershipBinding,
        target_id: target.id,
        inherited_from_target_id: parent.id,
      },
    };
  }

  async function ownTargetOwnership(ctx, group, target) {
    if (typeof ownershipVerifications?.getCurrentTargetVerification !== 'function') {
      return { verified: false, state: 'unverified', unavailable: true };
    }
    const current = await ownershipVerifications.getCurrentTargetVerification(
      ctx,
      group.id,
      target.id,
    );
    if (current && String(current.target_id) !== String(target.id)) {
      return { verified: false, state: 'unverified', reason: 'verification_target_mismatch' };
    }
    const proof = ownershipProofFromStates({ targetState: current?.state ?? null });
    if (!proof.verified) return proof;
    if (current?.state === 'provider_verified' && !current.provider_provenance) {
      return {
        verified: false,
        state: 'pending',
        reason: 'provider_provenance_incomplete',
      };
    }
    return {
      ...proof,
      ownershipBinding: {
        kind: current?.source_kind ?? 'unknown',
        state: current?.state ?? proof.state,
        target_id: target.id,
        transitioned_at: current?.transitioned_at ?? null,
        ...(current?.provider_provenance
          ? { provider_provenance: current.provider_provenance }
          : {}),
      },
    };
  }

  async function revalidateBeforeDispatch(ctx, body, check, initialTarget, probeWillLeaveThisHost, dispatchOptions = {}) {
    const group = await coreCatalog.getTargetGroup(ctx, body.target_group_id, LEAN_GROUP_LOOKUP);
    if (!group) return { error: 'target_group_not_found', status: 404 };
    const target = (group.targets ?? []).find((candidate) => candidate.id === initialTarget.id);
    if (!target) return { error: 'target_not_found', status: 404 };
    if (targetDedupeKey(target) !== targetDedupeKey(initialTarget)) {
      return { error: 'target_binding_changed', status: 409 };
    }
    const compatibilityError = targetKindCompatibilityError(check, target);
    if (compatibilityError) return compatibilityError;
    const binding = await validatePolicyBinding(ctx, body, group, check, dispatchOptions);
    if (binding.error) return binding;
    if (probeWillLeaveThisHost) {
      const ownership = await authoritativeOwnership(ctx, group, target);
      if (!ownership.verified) {
        return {
          error: 'ownership_not_verified', status: 409, ownership_state: ownership.state,
          reason: ownership.unavailable
            ? 'verification_repository_unavailable'
            : ownership.reason,
        };
      }
      return { group, target, policy: binding.policy, ownershipBinding: ownership.ownershipBinding };
    }
    return { group, target, policy: binding.policy };
  }

  async function denyEventCapForRun(ctx, run, metadata = {}, options = {}) {
    return denySafeStart(
      { tenantId: run.tenant_id, userId: ctx?.userId ?? 'system', role: ctx?.role ?? 'system' },
      'test_run.event_cap_denied',
      run.id,
      { check_id: run.check_id, ...metadata },
      'event_cap_exceeded',
      429,
      options,
    );
  }

  const FINDING_VERDICT_SEVERITY = Object.freeze({
    bypassable: 'high',
    penetrated: 'high',
    edge_exposed: 'medium',
  });
  function findingVerdictSeverity(verdict, run) {
    // Version 2 DNSSEC grades authoritative key presence, rather than origin reachability.
    if (verdict.verdict === 'exposed' && run.check_id === 'dns.dnssec_expensive_query.safe'
      && run.check_version === '2.0.0') return 'medium';
    return FINDING_VERDICT_SEVERITY[verdict.verdict];
  }
  const VERDICT_PUBLICATION_AUDIT_ACTIONS = Object.freeze([
    'verdict.published',
    'verdict.finalized_no_observation',
  ]);
  const FINDING_PUBLICATION_AUDIT_ACTIONS = Object.freeze([
    'finding.created',
    'finding.updated',
  ]);

  function assertDurableVerdictRunBinding(verdict, run) {
    const invalid = !verdict
      || !run
      || verdict.test_run_id !== run.id
      || verdict.target_id !== run.target_id
      || verdict.check_id !== run.check_id
      || (verdict.tenant_id != null && verdict.tenant_id !== run.tenant_id)
      || typeof run.target_group_id !== 'string'
      || run.target_group_id === ''
      || typeof run.target_id !== 'string'
      || run.target_id === ''
      || typeof run.check_id !== 'string'
      || run.check_id === '';
    if (invalid) {
      throw new Error(`verdict_run_binding_mismatch:${run?.id ?? 'missing'}:${verdict?.id ?? 'missing'}`);
    }
  }

  function exactFindingForVerdict(findings, verdictId) {
    return findings.find(
      (finding) => finding.verdict_id === verdictId || finding.last_verdict_id === verdictId,
    ) ?? null;
  }

  async function lockedFindingPublication(ctx, verdict, run, client) {
    const severity = findingVerdictSeverity(verdict, run);
    if (!severity) return null;
    assertDurableVerdictRunBinding(verdict, run);

    const binding = {
      target_group_id: run.target_group_id,
      target_id: run.target_id,
      check_id: run.check_id,
    };
    const existingRows = await validationEvidence.listFindings(ctx, {
      ...binding,
      forUpdate: true,
      client,
    });
    const findings = Array.isArray(existingRows) ? existingRows : [];
    const exact = exactFindingForVerdict(findings, verdict.id);
    if (exact) {
      return {
        finding: exact,
        disposition: 'already_published',
        auditAction: exact.verdict_id === verdict.id ? 'finding.created' : 'finding.updated',
      };
    }

    const priorOpen = findings.find((finding) => finding.status === 'open') ?? null;
    const nowIso = nowFn().toISOString();
    const findingId = priorOpen?.id ?? newId('finding');
    const finding = await validationEvidence.upsertOpenFindingFromVerdict(
      ctx,
      {
        id: findingId,
        target_group_id: run.target_group_id,
        target_id: run.target_id,
        test_run_id: run.id,
        check_id: run.check_id,
        // The target may have been archived after the immutable verdict committed. Use the
        // durable run binding rather than replay input or another currently-active target.
        title: `Finding: ${verdict.verdict} on ${run.target_id}`,
        severity,
        status: 'open',
        notes: verdict.explanation,
        evidence_ids: verdict.evidence_ids,
        remediation_template: run.remediation_template,
        verdict_id: priorOpen?.verdict_id ?? verdict.id,
        last_verdict_id: verdict.id,
        assignee: priorOpen?.assignee ?? null,
        created_at: priorOpen?.created_at ?? nowIso,
        updated_at: nowIso,
      },
      { client },
    );
    if (!finding) {
      // The SQL chronology guard refused an older/equal publication (including a newer closed
      // finding). Re-read while still holding the transaction locks so a concurrently-created
      // exact row is recognized, but never reopen or duplicate a newer publication.
      const refreshedRows = await validationEvidence.listFindings(ctx, {
        ...binding,
        forUpdate: true,
        client,
      });
      const refreshed = Array.isArray(refreshedRows) ? refreshedRows : [];
      const exactAfterGuard = exactFindingForVerdict(refreshed, verdict.id);
      if (exactAfterGuard) {
        return {
          finding: exactAfterGuard,
          disposition: 'already_published',
          auditAction: exactAfterGuard.verdict_id === verdict.id
            ? 'finding.created'
            : 'finding.updated',
        };
      }
      return { finding: null, disposition: 'superseded', auditAction: null };
    }

    return {
      finding,
      disposition: priorOpen ? 'advanced' : 'created',
      auditAction: priorOpen ? 'finding.updated' : 'finding.created',
    };
  }

  async function repairVerdictPublication(ctx, replayVerdict, replayRun, options = {}) {
    const tenantId = replayRun?.tenant_id ?? ctx.tenantId;
    const publicationCtx = { tenantId, userId: 'system', role: 'system' };

    const publishOnLockedClient = async (client) => {
      let run = await validationEvidence.getTestRun(publicationCtx, replayRun.id, { client });
      const verdict = await validationEvidence.getVerdictForRun(
        publicationCtx,
        replayRun.id,
        { client },
      );
      if (!run || !verdict) {
        throw new Error(`verdict_publication_snapshot_missing:${replayRun.id}`);
      }
      assertDurableVerdictRunBinding(verdict, run);

      if (run.status !== 'verdicted') {
        const repairedRun = await validationEvidence.updateTestRun(
          publicationCtx,
          run.id,
          {
            status: 'verdicted',
            completed_at: run.completed_at ?? verdict.created_at,
            expected_statuses: ['running', 'collecting'],
          },
          { client },
        );
        if (repairedRun) run = repairedRun;
      }

      const opsReadiness = isOpsReadinessProbeKind(getCheckById(run.check_id));
      const findingPublication = opsReadiness
        ? null
        : await lockedFindingPublication(publicationCtx, verdict, run, client);
      const placement = verdict.placement_confidence ?? {};
      const finalizedWithoutObservation = !opsReadiness
        && !findingVerdictSeverity(verdict, run);

      await appendAudit(
        publicationCtx,
        finalizedWithoutObservation
          ? 'verdict.finalized_no_observation'
          : 'verdict.published',
        'test_run',
        run.id,
        {
          verdict_id: verdict.id,
          verdict: verdict.verdict,
          confidence: verdict.confidence,
          placement_confidence_level: placement.level,
          placement_confidence_status: placement.status,
          ...(opsReadiness ? { ops_readiness: true } : {}),
        },
        {
          client,
          auditLockHeld: true,
          // Historical publication audits did not carry verdict_id. Resource/action
          // identity therefore remains the safe no-duplicate key for this one-verdict run.
          idempotency: {
            actions: [...VERDICT_PUBLICATION_AUDIT_ACTIONS],
            resourceType: 'test_run',
            resourceId: run.id,
          },
        },
      );

      if (findingPublication?.finding && findingPublication.auditAction) {
        await appendAudit(
          publicationCtx,
          findingPublication.auditAction,
          'finding',
          findingPublication.finding.id,
          {
            verdict_id: verdict.id,
            test_run_id: run.id,
            verdict: verdict.verdict,
          },
          {
            client,
            auditLockHeld: true,
            idempotency: {
              actions: [...FINDING_PUBLICATION_AUDIT_ACTIONS],
              resourceType: 'finding',
              resourceId: findingPublication.finding.id,
              metadata: { verdict_id: verdict.id },
            },
          },
        );
      }
      return verdict;
    };

    const locked = options.client
      ? { acquired: true, result: await publishOnLockedClient(options.client) }
      : await audit.withTenantAuditLock(
        tenantId,
        async ({ client: auditClient }) => validationEvidence.withRunMutationLock(
          publicationCtx,
          replayRun.id,
          publishOnLockedClient,
          { client: auditClient, wait: true },
        ),
      );

    if (!locked?.acquired) return replayVerdict;
    if (replayVerdict?.[VERDICT_INSERTED] === false) {
      return { ...locked.result, [VERDICT_INSERTED]: false };
    }
    return locked.result;
  }

  async function finalizeOpsReadinessVerdict(ctx, run, probe, options = {}) {
    const repositoryOptions = options.client ? { client: options.client } : {};
    const events = await validationEvidence.listRunEvents(ctx, run.id, {
      limit: 1000,
      ...repositoryOptions,
    });
    const existingVerdict = await validationEvidence.getVerdictForRun(
      ctx,
      run.id,
      repositoryOptions,
    );
    if (existingVerdict) {
      return repairVerdictPublication(ctx, existingVerdict, run, options);
    }

    const result = correlateOpsReadinessVerdict({
      externalResult: probe.external_result,
      opsValidationOk: probe.metadata?.ops_validation_ok,
    });

    const evidenceIds = events.map((e) => e.id);

    const nowIso = nowFn().toISOString();
    const verdictRecord = {
      id: newId('evidence'),
      test_run_id: run.id,
      target_id: run.target_id,
      check_id: run.check_id,
      verdict: result.verdict,
      confidence: result.confidence,
      explanation: result.explanation,
      evidence_ids: evidenceIds,
      created_at: nowIso,
    };
    const verdict = await validationEvidence.createVerdictIfAbsent(ctx, verdictRecord, {
      ...repositoryOptions,
      mutationLocksHeld: options.mutationLocksHeld === true,
    });
    if (!verdict) return null;
    if (verdictWasInserted(verdict)) {
      run.status = 'verdicted';
      run.completed_at = nowIso;
    }

    return repairVerdictPublication(ctx, verdict, run, options);
  }

  async function finalizeVerdictIfReady(ctx, run, options = {}) {
    const repositoryOptions = options.client ? { client: options.client } : {};
    const events = await validationEvidence.listRunEvents(ctx, run.id, {
      limit: 1000,
      ...repositoryOptions,
    });
    const existingVerdict = await validationEvidence.getVerdictForRun(
      ctx,
      run.id,
      repositoryOptions,
    );
    const check = getCheckById(run.check_id);
    if (existingVerdict && isOpsReadinessProbeKind(check)) {
      return repairVerdictPublication(ctx, existingVerdict, run, options);
    }
    if (existingVerdict) {
      return repairVerdictPublication(ctx, existingVerdict, run, options);
    }
    if (!hasExternalProbeEvidence(run, events)) return null;

    const probeEvent = findProbeEvent(run, events);

    if (
      !options.finalizedWithoutObservation
      && !isCollectionWindowExpired(run, nowFn().getTime())
    ) {
      return null;
    }

    const externalResult = run.probe_external_result ?? probeEvent?.metadata?.external_result;
    // Stamped runs finalize against the immutable start snapshot; legacy unstamped runs keep
    // the historical catalog fallback (see verdictExpectedBehaviorForRun).
    const expectedBehavior = verdictExpectedBehaviorForRun(run);
    const probeKind = check?.probe_profile?.kind ?? null;
    const probeIoObserved = probeEventHasProbeIo(probeEvent);
    // ADR-0008: verdicts are produced from external probe evidence only.
    const result = correlateExternalOnlyVerdict({ externalResult, expectedBehavior, probeKind, probeIoObserved, probeMetadata: probeEvent?.metadata ?? probeEvent?.metadata_json });

    const evidenceIds = events.map((event) => event.id);

    const nowIso = nowFn().toISOString();
    const verdictRecord = {
      id: newId('evidence'),
      test_run_id: run.id,
      target_id: run.target_id,
      check_id: run.check_id,
      verdict: result.verdict,
      confidence: result.confidence,
      explanation: result.explanation,
      evidence_ids: evidenceIds,
      created_at: nowIso,
    };
    const verdict = await validationEvidence.createVerdictIfAbsent(ctx, verdictRecord, {
      ...repositoryOptions,
      mutationLocksHeld: options.mutationLocksHeld === true,
    });
    if (!verdict) return null;
    if (verdictWasInserted(verdict)) {
      run.status = 'verdicted';
      run.completed_at = nowIso;
    }

    return repairVerdictPublication(ctx, verdict, run, options);
  }

  async function finalizeNoObservation(ctx, run, options = {}) {
    const repositoryOptions = options.client ? { client: options.client } : {};
    const events = await validationEvidence.listRunEvents(ctx, run.id, {
      limit: 1000,
      ...repositoryOptions,
    });
    if (wouldExceedEventCap(run, events.filter((event) => event.signal_type !== 'probe_activity').length, 1)) {
      await appendAudit(
        { tenantId: run.tenant_id, userId: 'system', role: 'system' },
        'test_run.event_cap_denied',
        'test_run',
        run.id,
        { phase: 'collection_window_elapsed' },
        {
          ...repositoryOptions,
          auditLockHeld: options.auditLockHeld === true,
        },
      );
      return null;
    }
    return finalizeVerdictIfReady(ctx, run, {
      ...options,
      finalizedWithoutObservation: true,
    });
  }

  async function maybeFinalizeCollectingRun(ctx, run, options = {}) {
    const force = options.force === true;
    const repositoryOptions = options.client ? { client: options.client } : {};
    if (!run || run.status !== 'collecting') return null;
    const existingVerdict = await validationEvidence.getVerdictForRun(
      ctx,
      run.id,
      repositoryOptions,
    );
    if (existingVerdict) {
      return finalizeVerdictIfReady(ctx, run, options);
    }
    const events = await validationEvidence.listRunEvents(ctx, run.id, {
      limit: 1000,
      ...repositoryOptions,
    });
    if (!hasExternalProbeEvidence(run, events)) return null;
    // ADR-0008: external probe evidence is the sole finalization source. A forced finalize
    // (explicit finalize or the collection-window sweep) publishes without waiting for the window.
    return finalizeVerdictIfReady(ctx, run, {
      ...options,
      finalizedWithoutObservation: options.finalizedWithoutObservation === true || force,
    });
  }

  const testRuns = {
    listChecks() {
      return customerSelectableChecks(CHECK_CATALOG).map(withCheckSection);
    },
    registerRunTerminalHook(hook) {
      if (typeof hook !== 'function') throw new TypeError('registerRunTerminalHook requires a function.');
      runTerminalHooks.add(hook);
      return () => runTerminalHooks.delete(hook);
    },
    notifyRunTerminal,
    // Mirrors the dev-json listTestRuns contract: target_group_id / target_id / limit filters are
    // honoured (they were silently ignored, so filtered lists returned the tenant's newest 100
    // runs) and every item carries its published verdict so list views can show outcomes.
    async listTestRuns(ctx, options = {}) {
      const runs = await validationEvidence.listTestRuns(ctx, {
        targetGroupId: options.target_group_id ?? options.targetGroupId,
        targetId: options.target_id ?? options.targetId,
        checkId: options.check_id ?? options.checkId,
        limit: options.limit,
      });
      if (!runs.length || typeof validationEvidence.listVerdictsForRuns !== 'function') return runs;
      const verdicts = await validationEvidence.listVerdictsForRuns(ctx, runs.map((run) => run.id));
      const byRun = new Map(verdicts.filter(Boolean).map((verdict) => [verdict.test_run_id, verdict]));
      return runs.map((run) => ({ ...run, verdict: byRun.get(run.id) ?? null }));
    },
    async listTestRunsEnvelope(ctx, options = {}) {
      const items = await this.listTestRuns(ctx, options);
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
    },
    async getTestRun(ctx, id) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      const verdict = await validationEvidence.getVerdictForRun(ctx, id);
      // EVIDENCE-01 / ADR-0008: customer run detail must read external-only. Scrub the nested
      // verdict explanation / placement_confidence at this projection seam. Stored rows are
      // untouched (the repository mapper returns raw historical evidence for internal use).
      return scrubRunForCustomer({ ...run, verdict: verdict ?? null });
    },
    /**
     * Finalize runs whose bounded collection window elapsed without any client call.
     *
     * Postgres mode has no read-path auto-finalizer, so without this sweep an expired
     * run stays `collecting` forever and keeps holding its `uniq_active_test_run` slot,
     * blocking every future run for the same (tenant_id, target_group_id).
     *
     * Scoped to a single tenant on purpose. The operator runner supplies an explicit
     * tenant list via scheduledTenantScope; cross-tenant enumeration is refused by RLS.
     *
     * @param {{ tenantId: string, userId?: string, role?: string }} ctx
     * @param {{ limit?: number, now?: string | null }} [options]
     */
    async sweepExpiredCollectingRuns(ctx, options = {}) {
      for (const method of ['listExpiredCollectingRuns', 'withRunFinalizationLock']) {
        if (typeof validationEvidence[method] !== 'function') {
          throw new Error(
            `sweepExpiredCollectingRuns requires validationEvidence.${method}().`,
          );
        }
      }

      const runs = await validationEvidence.listExpiredCollectingRuns(ctx, {
        limit: options.limit,
        now: options.now ?? null,
      });

      const summary = {
        tenant_id: ctx.tenantId,
        examined: runs.length,
        finalized: 0,
        skipped_locked: 0,
        skipped_not_finalizable: 0,
        errors: [],
        finalized_runs: [],
      };
      if (runs.length === 0) return summary;

      for (const staleRun of runs) {
        try {
          const { acquired, result } = await audit.withTenantAuditLock(
            ctx.tenantId,
            async ({ client: auditClient }) => validationEvidence.withRunFinalizationLock(
              ctx,
              staleRun.id,
              async (client) => {
                // Re-read under both locks: another sweeper or observation ingest may have
                // finalized this run between the listing query and this transaction.
                const fresh = await validationEvidence.getTestRun(
                  ctx,
                  staleRun.id,
                  { client },
                );
                if (!fresh) return null;
                const verdict = await maybeFinalizeCollectingRun(ctx, fresh, {
                  force: true,
                  client,
                  auditLockHeld: true,
                  mutationLocksHeld: true,
                });
                if (!verdict) return null;
                const finalizedRun = await validationEvidence.getTestRun(ctx, staleRun.id, { client });
                return { verdict, run: finalizedRun ?? fresh };
              },
              { client: auditClient },
            ),
          );

          if (!acquired) {
            summary.skipped_locked += 1;
          } else if (result) {
            summary.finalized += 1;
            summary.finalized_runs.push({ run_id: staleRun.id, verdict: result.verdict.verdict });
            await notifyRunTerminal(result.run, { reason: 'verdicted', source: 'collection_window_sweep' });
          } else {
            summary.skipped_not_finalizable += 1;
          }
        } catch (err) {
          // One bad run must not abort the sweep for the rest of the tenant.
          summary.errors.push({
            run_id: staleRun.id,
            message: err instanceof Error ? err.message : String(err),
          });
        }
      }

      return summary;
    },
    async getRunActivity(ctx, id, options = {}) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      return projectRunActivity(run, await validationEvidence.listRunEvents(ctx, id, { limit: 1000 }), options.limit);
    },

    async getRunEvents(ctx, id, options = {}) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      const listOptions = {};
      if (Array.isArray(options?.ids)) {
        listOptions.ids = options.ids;
        if (options.target_id != null) listOptions.target_id = options.target_id;
        if (options.check_id != null) listOptions.check_id = options.check_id;
        return validationEvidence.listRunEvents(ctx, id, listOptions);
      }
      if (options?.limit != null) listOptions.limit = options.limit;
      return validationEvidence.listRunEvents(ctx, id, listOptions);
    },
    async startTestRun(ctx, body, runtimeConfig = { probeMode: 'simulation' }, dispatchOptions = {}) {
      const check = getCheckById(body.check_id);
      if (!check) return { error: 'unknown_check', status: 400 };
      if (!isCustomerRunnable(check)) {
        await appendAudit(ctx, 'test_run.blocked_soc_gated', 'check', check.check_id);
        return {
          error: 'soc_gated_check',
          status: 403,
          message: 'This check requires SOC governance.',
        };
      }

      const targetGroupId = body.target_group_id;
      const group = await coreCatalog.getTargetGroup(ctx, targetGroupId, LEAN_GROUP_LOOKUP);
      if (!group) return { error: 'target_group_not_found', status: 404 };

      if (await killSwitch.isKillSwitchActiveForTenant(ctx)) {
        return denySafeStart(
          ctx,
          'test_run.kill_switch_denied',
          targetGroupId,
          { check_id: check.check_id, target_group_id: targetGroupId },
          'kill_switch_active',
          423,
        );
      }

      const policyDispatchId = dispatchOptions.policyDispatch?.dispatch_id ?? null;
      const existingPolicyRun = policyDispatchId
        && typeof validationEvidence.getTestRunByPolicyDispatchId === 'function'
        ? await validationEvidence.getTestRunByPolicyDispatchId(ctx, policyDispatchId)
        : null;
      const scanStepId = dispatchOptions.scanDispatch?.step_id ?? null;
      const existingScanRun = scanStepId
        && typeof validationEvidence.getTestRunByScanStepId === 'function'
        ? await validationEvidence.getTestRunByScanStepId(ctx, scanStepId)
        : null;
      const activeRuns = await validationEvidence.listTestRuns(ctx, {
        targetGroupId,
        statuses: [...ACTIVE_RUN_STATUSES],
        limit: 1,
      });
      if (activeRuns.length > 0 && !existingPolicyRun && !existingScanRun) {
        return { error: 'concurrent_run_blocked', status: 409 };
      }

      const targets = group.targets ?? [];
      const targetId = typeof body.target_id === 'string' ? body.target_id.trim() : '';
      if (!targetId) return { error: 'missing_target_id', status: 400 };
      let target = targets.find((candidate) => candidate.id === targetId);
      if (!target) return { error: 'target_not_found', status: 404 };
      const compatibilityError = targetKindCompatibilityError(check, target);
      if (compatibilityError) return compatibilityError;

      if ((runtimeConfig.probeMode ?? 'simulation') === 'signed-worker') {
        const targetBindingError = validateHostSniTargetBinding(check, target);
        if (targetBindingError) {
          const denied = await denySafeStart(
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

      const policyBinding = await validatePolicyBinding(ctx, body, group, check, dispatchOptions);
      if (policyBinding.error) return policyBinding;
      const scanBinding = await validateScanBinding(ctx, body, group, check, dispatchOptions);
      if (scanBinding.error) return scanBinding;
      if (scanBinding.scan && await tenantSuspended(ctx.tenantId)) {
        return denySafeStart(
          ctx,
          'test_run.tenant_suspended_denied',
          targetGroupId,
          { check_id: check.check_id, target_group_id: targetGroupId, scan_id: scanBinding.scan.id },
          'tenant_suspended',
          403,
        );
      }

      const probeMode = runtimeConfig.probeMode ?? 'simulation';
      const inlineProbe = isOpsReadinessProbeKind(check) || probeMode !== 'signed-worker';
      const probeWillLeaveThisHost = !inlineProbe;

      if (existingScanRun && scanBinding.step) {
        if (inlineProbe || !ACTIVE_RUN_STATUSES.includes(existingScanRun.status)) {
          return { run: await testRuns.getTestRun(ctx, existingScanRun.id), idempotent_replay: true };
        }
        const repaired = await repairSignedDispatch(ctx, existingScanRun, {
          body,
          check,
          target,
          targetGroupId,
          probeWillLeaveThisHost,
          runtimeConfig,
          dispatchOptions,
          phase: 'scan_dispatch_recovery',
        });
        if (!repaired.error || repaired.retryable) return repaired;
        const cancelledRun = await validationEvidence.updateTestRun(ctx, existingScanRun.id, {
          status: 'cancelled',
          completed_at: nowFn().toISOString(),
          summary: { dispatch_failed: true, reason: repaired.error },
          expected_statuses: ['running'],
        });
        if (cancelledRun) await notifyRunTerminal(cancelledRun, { reason: 'dispatch_failed' });
        return repaired;
      }
      if (probeWillLeaveThisHost && !probeDispatchReady(runtimeConfig)) {
        return denySafeStart(
          ctx,
          'test_run.probe_signing_unavailable',
          targetGroupId,
          { check_id: check.check_id, target_group_id: targetGroupId, scan_id: scanBinding.scan?.id ?? null },
          'probe_signing_unavailable',
          503,
        );
      }

      if (existingPolicyRun) {
        if (inlineProbe) return { run: existingPolicyRun, idempotent_replay: true };
        if (existingPolicyRun.status === 'cancelled') {
          return { error: 'policy_dispatch_run_cancelled', status: 409 };
        }

        return repairSignedDispatch(ctx, existingPolicyRun, {
          body,
          check,
          target,
          targetGroupId,
          probeWillLeaveThisHost,
          runtimeConfig,
          dispatchOptions,
          phase: 'policy_dispatch_recovery',
        });
      }

      // First live-egress gate. Group ownership is summary-only; authorization always reads the
      // current verification bound to this exact tenant/group/target. This runs before any write,
      // and revalidateBeforeDispatch repeats the same check at the final dispatch boundary.
      if (probeWillLeaveThisHost) {
        const ownership = await authoritativeOwnership(ctx, group, target);
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
              reason: ownership.unavailable
                ? 'verification_repository_unavailable'
                : ownership.reason,
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

      const now = nowFn();
      const nowMs = now.getTime();
      if ((group.safe_test_windows ?? []).length > 0 && !isWithinSafeTestWindow(group, nowMs)) {
        return denySafeStart(
          ctx,
          'test_run.safe_window_denied',
          targetGroupId,
          { check_id: check.check_id, target_group_id: targetGroupId },
          'safe_window_closed',
          429,
        );
      }

      const recentRuns = await validationEvidence.listTestRuns(ctx, { limit: 500 });
      const groupPolicy = effectiveSafetyConstraints(check, group);
      if (countCustomerRunnableRunsLastHour(recentRuns, ctx.tenantId, nowMs) >= groupPolicy.max_runs_per_hour) {
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

      const priorRun = lastRunForTargetGroup(recentRuns, ctx.tenantId, targetGroupId);
      if (priorRun && groupPolicy.min_seconds_between_runs > 0) {
        const elapsedMs = nowMs - new Date(priorRun.created_at).getTime();
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

      const finalValidation = await revalidateBeforeDispatch(
        ctx,
        { ...body, target_group_id: targetGroupId },
        check,
        target,
        probeWillLeaveThisHost,
        dispatchOptions,
      );
      if (finalValidation.error) {
        if (['target_group_not_found', 'target_not_found', 'target_binding_changed', 'target_kind_not_supported'].includes(
          finalValidation.error,
        )) {
          return finalValidation;
        }
        return denySafeStart(
          ctx,
          finalValidation.error === 'ownership_not_verified'
            ? 'test_run.ownership_denied'
            : 'test_run.policy_dispatch_denied',
          targetGroupId,
          {
            check_id: check.check_id,
            policy_id: policyBinding.policy?.id ?? null,
            target_group_id: targetGroupId,
            target_id: target.id,
            ownership_state: finalValidation.ownership_state,
            reason: finalValidation.reason,
            phase: 'pre_dispatch_revalidation',
          },
          finalValidation.error,
          finalValidation.status,
        );
      }
      target = finalValidation.target;

      const retestFindingId = typeof body.retest_of_finding_id === 'string' ? body.retest_of_finding_id.trim() : '';
      let retestComparisonContext = null;
      if (retestFindingId) {
        const allowed = authorizeFindingWrite(ctx);
        if (!allowed.ok) {
          return { error: 'forbidden', status: allowed.status ?? 403, permission: 'finding:write' };
        }
        const finding = typeof validationEvidence.getFinding === 'function'
          ? await validationEvidence.getFinding(ctx, retestFindingId)
          : null;
        if (!finding) return { error: 'unknown_finding', status: 404 };
        if (finding.tenant_id !== ctx.tenantId || finding.target_id !== target.id || finding.check_id !== check.check_id) {
          return { error: 'pair_mismatch', status: 409 };
        }
        if (isProtectionValidationFinding(finding)) {
          if (!protectionRetestRunScopeMatches(finding, body)) return { error: 'retest_not_authorized', status: 409, reason: 'retest_scope_mismatch' };
          const authorization = typeof options.resolveProtectionRetestAuthorization === 'function'
            ? await options.resolveProtectionRetestAuthorization(ctx, finding)
            : null;
          if (authorization?.ok !== true) {
            return {
              error: 'retest_not_authorized',
              status: authorization?.status >= 400 ? authorization.status : 409,
              reason: authorization?.error ?? 'authorization_not_rechecked',
            };
          }
          retestComparisonContext = protectionRetestContext(finding, authorization);
        }
      }
      const originBindingId = typeof body.origin_binding_id === 'string' ? body.origin_binding_id.trim() : '';
      let originScopeSnapshot = null;
      if (originBindingId) {
        if (typeof validationEvidence.loadOriginBindingProof !== 'function') {
          return { error: 'origin_binding_unavailable', status: 503 };
        }
        const loaded = await validationEvidence.loadOriginBindingProof(ctx, originBindingId);
        const records = {
          targets: loaded?.targets ?? [],
          targetVerifications: loaded?.targetVerifications ?? [],
          wafConnectors: loaded?.wafConnectors ?? [],
          wafConnectorSnapshots: loaded?.wafConnectorSnapshots ?? [],
        };
        const protectedTarget = records.targets.find((row) => row.id === loaded?.binding?.protected_target_id);
        const bindingDecision = validateOriginBindingForRun({
          binding: loaded?.binding,
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
        // so signed job creation — including repair/recovery rebuilds — signs the approved
        // Host/SNI/port/path exactly.
        originScopeSnapshot = bindingDecision.scope;
      }
      const opsReadiness = isOpsReadinessProbeKind(check);
      const stamp = deriveRunEvidenceStamp(check, body, {
        probeMode: runtimeConfig.probeMode ?? 'simulation',
        opsReadiness,
        scenarioVersion: approvedScenarioVersion(
          check,
          opsReadiness ? resolveOpsReadinessScenario(check) : null,
        ),
      });
      const safetyConstraints = effectiveSafetyConstraints(check, group);
      const runId = newId('run');
      const runRecord = {
        id: runId,
        tenant_id: ctx.tenantId,
        target_group_id: targetGroupId,
        target_id: target.id,
        policy_id: finalValidation.policy?.id ?? null,
        policy_dispatch_id: dispatchOptions.policyDispatch?.dispatch_id ?? null,
        scan_id: scanBinding.scan?.id ?? null,
        scan_step_id: scanBinding.step?.id ?? null,
        check_id: check.check_id,
        vector_family: check.vector_family,
        safety_class: check.safety_class ?? check.risk_class,
        remediation_template: check.remediation_template,
        safety_constraints: safetyConstraints,
        status: 'running',
        created_at: now.toISOString(),
        created_by: ctx.userId,
        correlation: { nonce_hash: null, window_ms: 120000 },
        collection_deadline_at: new Date(nowMs + collectionDeadlineMs(check)).toISOString(),
        check_version: stamp.check_version ?? null,
        scenario_version: stamp.scenario_version ?? null,
        producer_kind: stamp.producer_kind ?? null,
        expected_behavior: stamp.expected_behavior ?? null,
        expected_behavior_json: stamp.expected_behavior_json ?? null,
        provenance_json: originScopeSnapshot
          ? {
            ...(stamp.provenance_json ?? {}),
            origin_scope: {
              host: originScopeSnapshot.host,
              sni: originScopeSnapshot.sni,
              port: originScopeSnapshot.port ?? null,
              path: originScopeSnapshot.path ?? null,
            },
          }
          : (stamp.provenance_json ?? null),
        origin_binding_id: originBindingId || null,
        retest_of_finding_id: retestFindingId || null,
        ...(retestComparisonContext ? { retest_comparison_context: retestComparisonContext } : {}),
      };
      let run = await validationEvidence.createTestRun(ctx, runRecord);
      if (run?.error) return run;

      await appendAudit(ctx, 'test_run.started', 'test_run', runId, {
        check_id: check.check_id,
        policy_id: runRecord.policy_id,
        scan_id: runRecord.scan_id,
        scan_step_id: runRecord.scan_step_id,
      });

      let probe;
      let probeEvent = null;
      let probeJob = null;

      if (!inlineProbe) {
        if (wouldExceedEventCap(run, 0, 1)) {
          await validationEvidence.updateTestRun(ctx, runId, {
            status: 'cancelled',
            completed_at: now.toISOString(),
          });
          return denySafeStart(
            ctx,
            'test_run.event_cap_denied',
            runId,
            { check_id: check.check_id, phase: 'probe_job' },
            'event_cap_exceeded',
            429,
          );
        }
        try {
          const builtJob = buildSignedProbeJobRecord({
            run,
            check,
            target,
            probeProfile: body.probe_profile,
            ownershipBinding: finalValidation.ownershipBinding,
            probeWorkerSecret: runtimeConfig.probeWorkerSecret,
            now,
            newId: () => newId('pjob'),
          });
          probeJob = await probeJobs.createProbeJob(ctx, builtJob);
          run = await validationEvidence.updateTestRun(ctx, runId, {
            correlation: { nonce_hash: probeJob.nonce_hash, window_ms: 120000 },
            awaiting_external_probe: true,
          });
        } catch (error) {
          // Policy occurrences keep the committed run so lease reclaim can repair it via repairSignedDispatch.
          if (probeJob?.id || dispatchOptions.policyDispatch) throw error;
          const cancelledRun = await validationEvidence.updateTestRun(ctx, runId, {
            status: 'cancelled',
            completed_at: nowFn().toISOString(),
            summary: { dispatch_failed: true, reason: 'probe_job_dispatch_failed' },
            expected_statuses: ['running'],
          });
          await appendAudit(ctx, 'test_run.dispatch_failed', 'test_run', runId, {
            check_id: check.check_id,
            scan_id: runRecord.scan_id,
            reason: 'probe_job_dispatch_failed',
          });
          if (cancelledRun) await notifyRunTerminal(cancelledRun, { reason: 'dispatch_failed' });
          return { error: 'probe_job_dispatch_failed', status: 503, retryable: true };
        }
        probe = { nonce: probeJob.nonce, nonce_hash: probeJob.nonce_hash, external_result: null };
        await appendAudit(ctx, 'probe_job.created', 'probe_job', probeJob.id, {
          test_run_id: runId,
          check_id: check.check_id,
        });
      } else {
        probe = isOpsReadinessProbeKind(check)
          ? executeOpsReadinessProbe(ctx, check, target, await gatherOpsReadinessData(ctx, check))
          : simulateProbeResult(check, target, body.probe_profile);
        if (wouldExceedEventCap(run, 0, 1)) {
          await validationEvidence.updateTestRun(ctx, runId, {
            status: 'cancelled',
            completed_at: now.toISOString(),
          });
          return denySafeStart(
            ctx,
            'test_run.event_cap_denied',
            runId,
            { check_id: check.check_id, phase: 'probe' },
            'event_cap_exceeded',
            429,
          );
        }
        try {
          probeEvent = await validationEvidence.appendEvent(ctx, {
          id: probe.event_id,
          tenant_id: ctx.tenantId,
          test_run_id: runId,
          target_id: target.id,
          check_id: check.check_id,
          source: probe.source,
          signal_type: probe.signal_type,
          producer_kind: 'internal_simulation',
          timestamp: now.toISOString(),
          nonce_hash: probe.nonce_hash,
          metadata: { ...probe.metadata, external_result: probe.external_result },
        });
        await validationEvidence.appendEvidence(ctx, {
          id: newId('evidence'),
          test_run_id: runId,
          label: isOpsReadinessProbeKind(check)
            ? 'ops_readiness_probe_evidence'
            : 'probe_simulation_evidence',
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
          created_at: now.toISOString(),
        });
        run = await validationEvidence.updateTestRun(ctx, runId, {
          status: 'collecting',
          probe_external_result: probe.external_result,
          correlation: { nonce_hash: probe.nonce_hash, window_ms: 120000 },
        });

        if (isOpsReadinessProbeKind(check)) {
          // Ops-readiness runs execute inline with no agent and no external worker
          // job. Finalize to an honest verdict immediately so customer-runnable ops
          // checks never hang in 'collecting'.
          await finalizeOpsReadinessVerdict(ctx, run, probe);
          run = (await validationEvidence.getTestRun(ctx, runId)) ?? run;
        }
        } catch (error) {
          try {
            await validationEvidence.updateTestRun(ctx, runId, {
              status: 'cancelled',
              completed_at: nowFn().toISOString(),
              summary: { dispatch_failed: true, reason: 'inline_probe_persistence_failed' },
              expected_statuses: ['running', 'collecting'],
            });
          } catch (cancellationError) {
            cancellationError.cause = error;
            throw cancellationError;
          }
          throw error;
        }
      }

      incMetric('test_runs_started_total');

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
    },
    async finalizeTestRun(ctx, id, { force = false } = {}) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      if (run.status !== 'collecting') {
        return { error: 'not_collecting', status: 409 };
      }
      const events = await validationEvidence.listRunEvents(ctx, id, { limit: 1000 });
      if (!hasExternalProbeEvidence(run, events)) {
        return { error: 'external_probe_pending', status: 409 };
      }
      if (!force && !isCollectionWindowExpired(run, nowFn().getTime())) {
        return { error: 'observation_window_active', status: 409 };
      }
      const verdict = await maybeFinalizeCollectingRun(ctx, run, { force: true });
      if (!verdict) {
        return { error: 'cannot_finalize', status: 409 };
      }
      const updatedRun = await validationEvidence.getTestRun(ctx, id);
      const storedVerdict = await validationEvidence.getVerdictForRun(ctx, id);
      await notifyRunTerminal(updatedRun, { reason: 'verdicted' });
      return { run: { ...updatedRun, verdict: storedVerdict ?? null }, verdict };
    },
    async cancelTestRun(ctx, id, cancelOptions = {}) {
      const reason = normalizeCancelReason(cancelOptions.reason);
      const source = cancelOptions.source ?? 'user';
      const completed_at = nowFn().toISOString();
      const cancellation = await validationEvidence.cancelTestRunAtomic(ctx, id, {
        completed_at,
        cancellation: { reason, by: ctx.userId, role: ctx.role, source, scan_id: cancelOptions.scan_id ?? null },
      });
      if (!cancellation) return null;
      if (!cancellation.cancelled) {
        await appendAudit(ctx, 'test_run.cancel_denied', 'test_run', id, {
          status: cancellation.run.status,
        });
        return { error: 'not_cancellable', status: 409 };
      }
      const run = cancellation.run;
      const scanId = cancelOptions.scan_id ?? run.scan_id ?? null;
      await appendAudit(ctx, 'test_run.cancelled', 'test_run', id, {
        reason,
        cancelled_by: ctx.userId,
        cancelled_by_role: ctx.role,
        source,
        check_id: run.check_id,
        target_group_id: run.target_group_id,
        scan_id: scanId,
        cancelled_probe_job_ids: cancellation.cancelled_jobs.map((job) => job.id),
      });
      await notifyRunTerminal(run, { reason: 'cancelled', source });
      return { run };
    },
    async maybeFinalizeRunAfterProbeIngest(ctxOrRunId, maybeRunId) {
      if (typeof ctxOrRunId === 'string' || ctxOrRunId == null) return null;
      const verdict = await finalizeAfterProbeIngest(ctxOrRunId, maybeRunId);
      if (verdict) {
        const terminalRun = await validationEvidence.getTestRun(ctxOrRunId, maybeRunId);
        if (terminalRun?.status === 'verdicted') {
          await notifyRunTerminal(terminalRun, { reason: 'verdicted' });
        }
      }
      return verdict;
    },
  };

  async function finalizeAfterProbeIngest(ctx, runId) {
    if (!runId) return null;

    const run = await validationEvidence.getTestRun(ctx, runId);
    if (!run) return null;

    const events = await validationEvidence.listRunEvents(ctx, runId, { limit: 1000 });
    run.awaiting_external_probe = false;
    await validationEvidence.updateTestRun(ctx, runId, { awaiting_external_probe: false });

    if (!hasExternalProbeEvidence(run, events)) return null;

    // ADR-0008: external probe evidence is the sole finalization source. The run enters
    // 'collecting'; the collection-window sweeper (or an explicit finalize) publishes the verdict.
    if (run.status === 'running') {
      await validationEvidence.updateTestRun(ctx, runId, { status: 'collecting' });
      run.status = 'collecting';
    }
    return finalizeVerdictIfReady(ctx, run, { finalizedWithoutObservation: false });
  }

  const evidence = {
    async listEvidence(ctx) {
      return validationEvidence.listEvidence(ctx);
    },
    async getEvidence(ctx, id) {
      return validationEvidence.getEvidence(ctx, id);
    },
    async getTargetEdgeDetection(ctx, targetId) {
      if (typeof validationEvidence.getTargetEdgeDetection !== 'function') {
        throw new Error('missing_configured_read:getTargetEdgeDetection');
      }
      return validationEvidence.getTargetEdgeDetection(ctx, targetId);
    },
  };

  const findings = {
    async listFindings(ctx, options = {}) {
      const rows = await validationEvidence.listFindings(ctx, options);
      // EVIDENCE-01 / ADR-0008: customer list items must read external-only — scrub notes/remediation.
      return Array.isArray(rows) ? rows.map(scrubFindingForCustomer) : rows;
    },
    async listFindingsEnvelope(ctx, options = {}) {
      let query;
      try {
        query = parseFindingListQuery(options, { paginate: true });
      } catch (err) {
        const failure = findingListQueryFailure(err);
        if (failure) return failure;
        throw err;
      }
      if (typeof validationEvidence.listFindingsPage === 'function') {
        const page = await validationEvidence.listFindingsPage(ctx, options);
        const items = Array.isArray(page?.items) ? page.items.map(scrubFindingForCustomer) : [];
        return buildFindingListEnvelope(items, page?.total ?? 0, query);
      }
      const items = await this.listFindings(ctx, options);
      return buildFindingListEnvelope(items, items.length, query);
    },
    async getFinding(ctx, id) {
      // EVIDENCE-01 / ADR-0008: customer finding detail must read external-only; scrub the projection.
      const row = await validationEvidence.getFinding(ctx, id);
      if (!row) return null;
      const view = scrubFindingForCustomer(row);
      if (typeof validationEvidence.readFindingLineage === 'function') {
        const lineage = await validationEvidence.readFindingLineage(ctx, id);
        if (lineage && !lineage.error) {
          view.closed_at = row.closed_at ?? lineage.closed_at ?? null;
          view.lineage = lineage;
          view.retests = lineage.retests ?? [];
          view.originating = lineage.originating ?? null;
          view.latest = lineage.latest ?? null;
        }
      }
      return view;
    },
    async patchFinding(ctx, id, body) {
      const planned = planFindingPatch(body ?? {});
      if (planned.error) return planned;
      const updated_at = nowFn().toISOString();
      // Only customer lifecycle and assignment fields cross this boundary.
      // Evidence links and closure timestamps belong to the server writers.
      const patch = { ...planned.patch, updated_at };
      for (const key of ['assignee', 'notes']) {
        if (Object.hasOwn(body ?? {}, key)) patch[key] = body[key];
      }
      const row = await validationEvidence.patchFinding(ctx, id, patch);
      if (!row) return null;
      await audit.appendAuditEvent(
        {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'finding.updated',
          resource_type: 'finding',
          resource_id: id,
          metadata: redactObject(body),
        },
        { now: nowFn() },
      );
      // Scrub the customer-facing PATCH response; the stored row is unchanged.
      return scrubFindingForCustomer(row);
    },
  };

  const events = {
    async ingestEvent(ctx, body) {
      const tenantId = ctx.tenantId;
      if (body.tenant_id && body.tenant_id !== tenantId) {
        await audit.appendAuditEvent(
          {
            tenant_id: tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'event.ingest_rejected_cross_tenant',
            resource_type: 'event',
            resource_id: body.event_id ?? null,
            metadata: { attempted_tenant: body.tenant_id },
          },
          { now: nowFn() },
        );
        return { error: 'cross_tenant_mismatch', status: 403 };
      }

      const eventId = body.event_id;
      if (!eventId) return { error: 'missing_event_id', status: 400 };

      const signalType = String(body.signal_type ?? 'generic').trim().toLowerCase();
      if (RESERVED_PUBLIC_EVENT_SIGNAL_TYPES.has(signalType)) {
        return { error: 'reserved_signal_type', status: 400 };
      }

      const existing = await validationEvidence.findEventByTenantEventId(ctx, eventId);
      if (existing) return { duplicate: true, event: existing };

      if (eventIngestContainsRawFields(body)) {
        return { error: 'packet_payload_forbidden', status: 400 };
      }

      const metadata = redactObject(body.metadata ?? {});
      const record = {
        id: newId('event'),
        event_id: eventId,
        tenant_id: tenantId,
        test_run_id: body.test_run_id ?? null,
        source: body.source ?? 'internal',
        signal_type: body.signal_type ?? 'generic',
        producer_kind: 'public_api',
        timestamp: body.timestamp ?? nowFn().toISOString(),
        nonce_hash: body.nonce_hash ?? null,
        metadata,
      };
      const appended = await validationEvidence.appendEventIdempotent(ctx, record);

      if (body.evidence) {
        await validationEvidence.appendEvidence(ctx, {
          id: body.evidence.evidence_id ?? newId('evidence'),
          test_run_id: body.test_run_id ?? null,
          label: body.evidence.label ?? 'ingested_metadata',
          metadata: redactObject(body.evidence.metadata ?? metadata),
          related_event_id: appended.id,
          created_at: nowFn().toISOString(),
        });
      }

      incMetric('events_ingested_total');
      await audit.appendAuditEvent(
        {
          tenant_id: tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'event.ingested',
          resource_type: 'event',
          resource_id: eventId,
        },
        { now: nowFn() },
      );
      return { event: appended };
    },
  };

  return { testRuns, evidence, findings, events };
}
