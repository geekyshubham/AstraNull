import { validateArtifactUploadBody } from '../../lib/authorizationArtifactLedger.mjs';
import { buildArtifactFromUpload } from '../../lib/highScalePolicy.mjs';
import { newId } from '../../lib/ids.mjs';
import { computeScopeHashFromTargets } from '../../lib/scopeHash.mjs';
import {
  getOffensiveSuiteById,
  listOffensiveSuites as listOffensiveSuiteCatalog,
  normalizeOffensiveSuiteResult,
  offensiveAuthorizationPackComplete,
  offensiveAuthorizationPackStatus,
  validateOffensiveRequestIntake,
  WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES,
} from '../../contracts/wafOffensive.mjs';
import { LEAN_GROUP_LOOKUP } from './coreCatalogRepository.mjs';
import { WAF_OFFENSIVE_REPOSITORY_METHODS } from './wafOffensiveRepository.mjs';

export const POSTGRES_WAF_OFFENSIVE_SERVICE_METHODS = Object.freeze([
  'listOffensiveSuites',
  'createOffensiveRequest',
  'listOffensiveRequests',
  'getOffensiveRequest',
  'addArtifact',
  'reviewArtifact',
  'transitionOffensiveRequest',
  'recordOffensiveSuiteResults',
  'upsertOffensivePostTestReport',
  'getOffensivePostTestReport',
]);

function assertRepositories(repositories, wafPostureServices) {
  const repo = repositories?.wafOffensive;
  if (!repo || typeof repo !== 'object') {
    throw new Error('Postgres WAF offensive adapter requires repositories.wafOffensive.');
  }
  for (const method of WAF_OFFENSIVE_REPOSITORY_METHODS) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres WAF offensive adapter requires wafOffensive.${method}().`);
    }
  }
  if (typeof repositories?.wafPosture?.getWafAsset !== 'function') {
    throw new Error('Postgres WAF offensive adapter requires wafPosture.getWafAsset().');
  }
  if (typeof repositories?.coreCatalog?.getTargetGroup !== 'function') {
    throw new Error('Postgres WAF offensive adapter requires coreCatalog.getTargetGroup().');
  }
  if (typeof repositories?.killSwitch?.isKillSwitchActiveForTenant !== 'function') {
    throw new Error(
      'Postgres WAF offensive adapter requires killSwitch.isKillSwitchActiveForTenant().',
    );
  }
  if (typeof repositories?.audit?.appendAuditEvent !== 'function') {
    throw new Error('Postgres WAF offensive adapter requires audit.appendAuditEvent().');
  }
  if (typeof wafPostureServices?.createSocOffensiveWafValidation !== 'function') {
    throw new Error(
      'Postgres WAF offensive adapter requires wafPostureServices.createSocOffensiveWafValidation().',
    );
  }
}

async function appendAudit(auditRepo, ctx, action, resourceType, resourceId, metadata, client) {
  return auditRepo.appendAuditEvent(
    {
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action,
      resource_type: resourceType,
      resource_id: resourceId,
      metadata: metadata ?? {},
    },
    client ? { client } : {},
  );
}

function distinctSocApprovalCount(request) {
  return new Set((request.soc_approvals ?? []).map((approval) => approval.user_id)).size;
}

function refreshPackStatus(request) {
  request.authorization_pack_status = offensiveAuthorizationPackStatus(request);
  return request;
}

function isWithinScheduledWindow(window, nowMs) {
  if (!window?.window_start || !window?.window_end) return false;
  const start = Date.parse(window.window_start);
  const end = Date.parse(window.window_end);
  return Number.isFinite(start) && Number.isFinite(end) && nowMs >= start && nowMs <= end;
}

function formatOffensiveRequest(record) {
  return {
    id: record.id,
    tenant_id: record.tenant_id,
    waf_asset_id: record.waf_asset_id,
    target_group_id: record.target_group_id,
    objective: record.objective,
    requested_suites: record.requested_suites,
    emergency_contacts: record.emergency_contacts,
    requested_window: record.requested_window,
    stop_criteria: record.stop_criteria,
    abort_criteria: record.abort_criteria,
    staging_only: record.staging_only,
    scope_confirmation: record.scope_confirmation,
    state: record.state,
    soc_approvals: record.soc_approvals ?? [],
    artifacts: record.artifacts ?? [],
    authorization_pack_status: record.authorization_pack_status ?? null,
    scheduled_window: record.scheduled_window ?? null,
    scope_hash: record.scope_hash ?? null,
    waf_validation_run_id: record.waf_validation_run_id ?? null,
    suite_results: record.suite_results ?? [],
    created_at: record.created_at,
    created_by: record.created_by,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
    ...(record.rejected_at
      ? { rejected_at: record.rejected_at, rejection_reason: record.rejection_reason }
      : {}),
  };
}

async function getTargetScope(coreCatalog, ctx, targetGroupId, client) {
  const group = await coreCatalog.getTargetGroup(ctx, targetGroupId, {
    ...LEAN_GROUP_LOOKUP,
    ...(client ? { client } : {}),
  });
  if (!group) return { error: 'target_group_not_found', status: 404 };
  const targets = Array.isArray(group.targets) ? group.targets : [];
  if (targets.length === 0) return { error: 'target_group_empty', status: 400 };
  return { group, targets };
}

export function createPostgresWafOffensiveServices(repositories, options = {}) {
  const wafPostureServices = options.wafPostureServices;
  assertRepositories(repositories, wafPostureServices);
  const repo = repositories.wafOffensive;
  const wafRepo = repositories.wafPosture;
  const coreCatalog = repositories.coreCatalog;
  const killSwitchRepo = repositories.killSwitch;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listOffensiveSuites() {
      return { suites: listOffensiveSuiteCatalog() };
    },

    async createOffensiveRequest(ctx, body = {}) {
      const intake = validateOffensiveRequestIntake(body);
      if (intake.error) return intake;
      const asset = await wafRepo.getWafAsset(ctx, intake.waf_asset_id);
      if (!asset) return { error: 'waf_asset_not_found', status: 404 };

      const id = newIdFn('wof');
      const now = nowFn().toISOString();
      const record = refreshPackStatus({
        id,
        tenant_id: ctx.tenantId,
        waf_asset_id: intake.waf_asset_id,
        target_group_id: asset.target_group_id,
        objective: intake.objective,
        requested_suites: intake.requested_suites,
        emergency_contacts: intake.emergency_contacts,
        requested_window: intake.requested_window,
        stop_criteria: intake.stop_criteria,
        abort_criteria: intake.abort_criteria,
        staging_only: intake.staging_only,
        scope_confirmation: true,
        state: 'submitted',
        created_at: now,
        updated_at: now,
        created_by: ctx.userId,
        soc_approvals: [],
        artifacts: [],
        suite_results: [],
        scheduled_window: null,
        scope_hash: null,
        waf_validation_run_id: null,
      });
      const created = await repo.createOffensiveRequest(ctx, record);
      await appendAudit(
        auditRepo,
        ctx,
        'waf.offensive_request.submitted',
        'waf_offensive_request',
        id,
        {
          waf_asset_id: intake.waf_asset_id,
          requested_suites: intake.requested_suites,
          staging_only: intake.staging_only,
        },
      );
      return { offensive_request: formatOffensiveRequest(created) };
    },

    async listOffensiveRequests(ctx) {
      const items = await repo.listOffensiveRequests(ctx);
      return { items: items.map(formatOffensiveRequest) };
    },

    async getOffensiveRequest(ctx, id) {
      const request = await repo.getOffensiveRequest(ctx, id);
      return request ? { offensive_request: formatOffensiveRequest(request) } : null;
    },

    async addArtifact(ctx, requestId, body, artifactOptions = {}) {
      return repo.withLockedOffensiveRequest(ctx, requestId, async (request, { client }) => {
        const upload = validateArtifactUploadBody(body);
        if (upload.error) return upload;
        const artifactType = String(body.type ?? '').trim();
        if (!WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES.includes(artifactType)) {
          return { error: 'invalid_offensive_artifact_type', status: 400 };
        }

        const artifact = buildArtifactFromUpload(ctx, body, {
          uploadEnvelope: artifactOptions.uploadEnvelope,
        });
        request.artifacts.push(artifact);
        refreshPackStatus(request);
        request.updated_at = nowFn().toISOString();
        await repo.saveOffensiveRequest(ctx, request, { client });
        await appendAudit(
          auditRepo,
          ctx,
          'waf.offensive_artifact.uploaded',
          'waf_offensive_request',
          requestId,
          { artifact_id: artifact.id, type: artifact.type },
          client,
        );
        return { artifact };
      });
    },

    async reviewArtifact(ctx, requestId, artifactId, body = {}) {
      return repo.withLockedOffensiveRequest(ctx, requestId, async (request, { client }) => {
        const artifact = request.artifacts.find((entry) => entry.id === artifactId);
        if (!artifact) return { error: 'artifact_not_found', status: 404 };
        const status = String(body.status ?? '').trim();
        if (!['accepted', 'rejected', 'needs_revision'].includes(status)) {
          return { error: 'invalid_artifact_review_status', status: 400 };
        }
        artifact.status = status;
        artifact.reviewed_at = nowFn().toISOString();
        artifact.reviewed_by = ctx.userId;
        if (typeof body.notes === 'string' && body.notes.trim()) {
          artifact.review_notes = body.notes.trim();
        }
        refreshPackStatus(request);
        request.updated_at = nowFn().toISOString();
        await repo.saveOffensiveRequest(ctx, request, { client });
        await appendAudit(
          auditRepo,
          ctx,
          'waf.offensive_artifact.reviewed',
          'waf_offensive_request',
          requestId,
          { artifact_id: artifactId, status },
          client,
        );
        return { artifact, authorization_pack_status: request.authorization_pack_status };
      });
    },

    async transitionOffensiveRequest(ctx, id, action, metadata = {}) {
      return repo.withLockedOffensiveRequest(ctx, id, async (request, { client }) => {
        const allowed = {
          approve: ['submitted', 'under_review'],
          schedule: ['approved'],
          start: ['scheduled'],
          stop: ['running'],
          close: ['stopped'],
          reject: ['submitted', 'under_review'],
        };
        const nextState = {
          approve: 'approved',
          schedule: 'scheduled',
          start: 'running',
          stop: 'stopped',
          close: 'closed',
          reject: 'rejected',
        };
        if (!allowed[action]?.includes(request.state)) {
          return { error: 'invalid_transition', state: request.state, status: 409 };
        }
        if (action === 'close') {
          const report = await repo.getOffensiveReport(ctx, id, { client });
          if (!report) return { error: 'post_test_report_required', status: 409 };
        }

        let resolvedState = nextState[action];
        let auditAction;
        let auditMetadata = {};

        if (action === 'reject') {
          request.rejected_at = nowFn().toISOString();
          request.rejected_by = ctx.userId;
          request.rejection_reason = String(metadata.reason ?? '').trim() || 'soc_rejected';
          auditAction = 'waf.offensive_request.rejected';
          auditMetadata = { reason: request.rejection_reason };
        }

        if (action === 'approve') {
          refreshPackStatus(request);
          if (!offensiveAuthorizationPackComplete(request)) {
            return {
              error: 'authorization_pack_incomplete',
              status: 409,
              authorization_pack_status: request.authorization_pack_status,
            };
          }
          if (request.soc_approvals.some((approval) => approval.user_id === ctx.userId)) {
            return { error: 'duplicate_soc_approval', status: 409 };
          }
          if (distinctSocApprovalCount(request) < 1) {
            request.soc_approvals.push({ user_id: ctx.userId, at: nowFn().toISOString() });
            resolvedState = 'under_review';
            auditAction = 'waf.offensive_request.soc_approval_recorded';
            auditMetadata = { approvals: distinctSocApprovalCount(request) };
          } else {
            const scope = await getTargetScope(coreCatalog, ctx, request.target_group_id, client);
            if (scope.error) return scope;
            request.scope_hash = computeScopeHashFromTargets(
              request.target_group_id,
              scope.targets,
            );
            request.soc_approvals.push({ user_id: ctx.userId, at: nowFn().toISOString() });
            auditAction = 'waf.offensive_request.approved';
            auditMetadata = {
              scope_hash: request.scope_hash,
              suites: request.requested_suites,
            };
          }
        }

        if (action === 'schedule') {
          const window_start = metadata.window_start;
          const window_end = metadata.window_end;
          if (!window_start || !window_end) {
            return { error: 'missing_schedule_window', status: 409 };
          }
          if (!request.scope_hash) return { error: 'missing_scope_hash', status: 409 };
          request.scheduled_window = {
            window_start,
            window_end,
            scope_hash: request.scope_hash,
          };
          auditAction = 'waf.offensive_request.scheduled';
          auditMetadata = { window_start, window_end };
        }

        if (action === 'start') {
          refreshPackStatus(request);
          if (!offensiveAuthorizationPackComplete(request)) {
            return {
              error: 'authorization_pack_incomplete',
              status: 409,
              authorization_pack_status: request.authorization_pack_status,
            };
          }
          if (distinctSocApprovalCount(request) < 2) {
            return { error: 'insufficient_soc_approvals', status: 409 };
          }
          if (await killSwitchRepo.isKillSwitchActiveForTenant(ctx, { client })) {
            return { error: 'kill_switch_active', status: 409 };
          }
          if (!request.scheduled_window
            || !isWithinScheduledWindow(request.scheduled_window, nowFn().getTime())) {
            return { error: 'outside_schedule_window', status: 409 };
          }
          const scope = await getTargetScope(coreCatalog, ctx, request.target_group_id, client);
          if (scope.error) return scope;
          const currentScopeHash = computeScopeHashFromTargets(
            request.target_group_id,
            scope.targets,
          );
          if (currentScopeHash !== request.scope_hash) {
            return { error: 'scope_hash_mismatch', status: 409 };
          }
          const modes = request.requested_suites
            .map((suiteId) => getOffensiveSuiteById(suiteId)?.scenario_family)
            .filter(Boolean);
          const validation = await wafPostureServices.createSocOffensiveWafValidation(
            ctx,
            {
              waf_asset_id: request.waf_asset_id,
              modes,
              offensive_request_id: request.id,
              max_requests: request.requested_suites.reduce((sum, suiteId) => {
                return sum + (getOffensiveSuiteById(suiteId)?.max_requests ?? 0);
              }, 0),
            },
            { client },
          );
          if (!validation) {
            return { error: 'waf_offensive_validation_unavailable', status: 503 };
          }
          if (validation.error) return validation;
          request.waf_validation_run_id = validation.validation_run.id;
          auditAction = 'waf.offensive_request.execution_started';
          auditMetadata = {
            waf_validation_run_id: request.waf_validation_run_id,
            suites: request.requested_suites,
            note: 'SOC-gated offensive suite execution — governed probe worker only.',
          };
        }

        if (action === 'stop') {
          auditAction = 'waf.offensive_request.execution_stopped';
          auditMetadata = { reason: metadata.reason ?? 'soc_stop' };
        }
        if (action === 'close') {
          auditAction = 'waf.offensive_request.closed';
        }

        request.state = resolvedState;
        request.updated_at = nowFn().toISOString();
        const saved = await repo.saveOffensiveRequest(ctx, request, { client });
        await appendAudit(
          auditRepo,
          ctx,
          auditAction,
          'waf_offensive_request',
          id,
          auditMetadata,
          client,
        );
        return { offensive_request: formatOffensiveRequest(saved) };
      });
    },

    async recordOffensiveSuiteResults(ctx, requestId, body = {}) {
      return repo.withLockedOffensiveRequest(ctx, requestId, async (request, { client }) => {
        if (!['running', 'stopped'].includes(request.state)) {
          return { error: 'results_not_active', status: 409, state: request.state };
        }
        const entries = Array.isArray(body.suite_results) ? body.suite_results : [];
        if (entries.length === 0) return { error: 'missing_suite_results', status: 400 };

        const normalized = [];
        for (const entry of entries) {
          const suiteId = String(entry.suite_id ?? '').trim();
          try {
            normalized.push(normalizeOffensiveSuiteResult(entry, suiteId));
          } catch (err) {
            return {
              error: err.code ?? 'unsafe_offensive_evidence',
              status: 400,
              message: err.message,
            };
          }
        }
        request.suite_results = normalized;
        request.results_recorded_at = nowFn().toISOString();
        request.results_recorded_by = ctx.userId;
        request.updated_at = nowFn().toISOString();
        const saved = await repo.saveOffensiveRequest(ctx, request, { client });
        await appendAudit(
          auditRepo,
          ctx,
          'waf.offensive_request.results_recorded',
          'waf_offensive_request',
          requestId,
          {
            suite_count: normalized.length,
            passed_count: normalized.filter((result) => result.passed === true).length,
          },
          client,
        );
        return {
          offensive_request: formatOffensiveRequest(saved),
          suite_results: normalized,
        };
      });
    },

    async upsertOffensivePostTestReport(ctx, requestId, body = {}) {
      return repo.withLockedOffensiveRequest(ctx, requestId, async (request, { client }) => {
        if (request.state !== 'stopped') {
          return { error: 'report_requires_stopped_request', status: 409, state: request.state };
        }
        const existing = await repo.getOffensiveReport(ctx, requestId, { client });
        const now = nowFn().toISOString();
        const report = {
          id: existing?.id ?? newIdFn('wofrep'),
          tenant_id: ctx.tenantId,
          waf_offensive_request_id: requestId,
          executive_summary:
            String(body.executive_summary ?? body.summary ?? '').trim() || null,
          blocking_verdict: String(body.blocking_verdict ?? '').trim() || null,
          bypass_findings: Array.isArray(body.bypass_findings) ? body.bypass_findings : [],
          remediation_notes: String(body.remediation_notes ?? '').trim() || null,
          suite_results: request.suite_results ?? [],
          created_at: existing?.created_at ?? now,
          created_by: existing?.created_by ?? ctx.userId,
          updated_at: now,
          updated_by: ctx.userId,
        };
        const persisted = await repo.upsertOffensiveReport(ctx, requestId, report, { client });
        await appendAudit(
          auditRepo,
          ctx,
          existing ? 'waf.offensive_report.updated' : 'waf.offensive_report.created',
          'waf_offensive_report',
          persisted.id,
          { waf_offensive_request_id: requestId },
          client,
        );
        return { report: persisted, created: !existing };
      });
    },

    async getOffensivePostTestReport(ctx, requestId) {
      const request = await repo.getOffensiveRequest(ctx, requestId);
      if (!request) return null;
      const report = await repo.getOffensiveReport(ctx, requestId);
      if (!report) return { error: 'report_not_found', status: 404 };
      return { report };
    },
  };
}
