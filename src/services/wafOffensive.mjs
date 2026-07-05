import { audit } from '../audit.mjs';
import { validateArtifactUploadBody } from '../lib/authorizationArtifactLedger.mjs';
import { buildArtifactFromUpload } from '../lib/highScalePolicy.mjs';
import { computeTargetGroupScopeHash } from '../lib/scopeHash.mjs';
import { newId } from '../lib/ids.mjs';
import { redactObject } from '../lib/redact.mjs';
import {
  getOffensiveSuiteById,
  listOffensiveSuites as listOffensiveSuiteCatalog,
  normalizeOffensiveSuiteResult,
  offensiveAuthorizationPackComplete,
  offensiveAuthorizationPackStatus,
  validateOffensiveRequestIntake,
  WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES,
} from '../contracts/wafOffensive.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';
import { createSocOffensiveWafValidation } from './wafPosture.mjs';

function ensureStoreShape() {
  const store = getStore();
  if (!Array.isArray(store.wafOffensiveRequests)) store.wafOffensiveRequests = [];
  if (!Array.isArray(store.wafOffensiveReports)) store.wafOffensiveReports = [];
  return store;
}

function findRequest(ctx, id) {
  ensureStoreShape();
  return (
    getStore().wafOffensiveRequests.find(
      (r) => r.id === id && r.tenant_id === ctx.tenantId,
    ) ?? null
  );
}

function findAsset(ctx, wafAssetId) {
  ensureStoreShape();
  return (
    getStore().wafAssets.find((a) => a.id === wafAssetId && a.tenant_id === ctx.tenantId) ?? null
  );
}

function distinctSocApprovalCount(request) {
  const approvals = Array.isArray(request?.soc_approvals) ? request.soc_approvals : [];
  return new Set(approvals.map((a) => a.user_id)).size;
}

function isWithinScheduledWindow(window) {
  if (!window?.window_start || !window?.window_end) return false;
  const now = Date.now();
  const start = Date.parse(window.window_start);
  const end = Date.parse(window.window_end);
  return Number.isFinite(start) && Number.isFinite(end) && now >= start && now <= end;
}

function findReport(tenantId, requestId) {
  ensureStoreShape();
  return (
    getStore().wafOffensiveReports.find(
      (r) => r.tenant_id === tenantId && r.waf_offensive_request_id === requestId,
    ) ?? null
  );
}

function refreshPackStatus(request) {
  request.authorization_pack_status = offensiveAuthorizationPackStatus(request);
  return request;
}

export function listOffensiveSuites() {
  return { suites: listOffensiveSuiteCatalog() };
}

export function createOffensiveRequest(ctx, body = {}) {
  ensureStoreShape();

  const intake = validateOffensiveRequestIntake(body);
  if (intake.error) return intake;

  const asset = findAsset(ctx, intake.waf_asset_id);
  if (!asset) {
    return { error: 'waf_asset_not_found', status: 404 };
  }

  const id = newId('wof');
  const now = new Date().toISOString();
  const record = {
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
    created_by: ctx.userId,
    soc_approvals: [],
    artifacts: [],
    suite_results: [],
    scheduled_window: null,
    scope_hash: null,
    waf_validation_run_id: null,
    authorization_pack_status: null,
  };
  refreshPackStatus(record);
  getStore().wafOffensiveRequests.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.offensive_request.submitted',
    resource_type: 'waf_offensive_request',
    resource_id: id,
    metadata: {
      waf_asset_id: intake.waf_asset_id,
      requested_suites: intake.requested_suites,
      staging_only: intake.staging_only,
    },
  });
  persistStore();
  return { offensive_request: formatOffensiveRequest(record) };
}

export function listOffensiveRequests(ctx) {
  ensureStoreShape();
  return {
    items: getStore()
      .wafOffensiveRequests.filter((r) => r.tenant_id === ctx.tenantId)
      .map(formatOffensiveRequest),
  };
}

export function getOffensiveRequest(ctx, id) {
  const record = findRequest(ctx, id);
  if (!record) return null;
  return { offensive_request: formatOffensiveRequest(record) };
}

export function addArtifact(ctx, requestId, body, options = {}) {
  const req = findRequest(ctx, requestId);
  if (!req) return null;

  const upload = validateArtifactUploadBody(body);
  if (upload.error) return upload;
  const artifactType = String(body.type ?? '').trim();
  if (!WAF_OFFENSIVE_REQUIRED_ARTIFACT_TYPES.includes(artifactType)) {
    return { error: 'invalid_offensive_artifact_type', status: 400 };
  }

  const artifact = buildArtifactFromUpload(ctx, body, { uploadEnvelope: options.uploadEnvelope });
  if (!Array.isArray(req.artifacts)) req.artifacts = [];
  req.artifacts.push(artifact);
  refreshPackStatus(req);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.offensive_artifact.uploaded',
    resource_type: 'waf_offensive_request',
    resource_id: requestId,
    metadata: { artifact_id: artifact.id, type: artifact.type },
  });
  persistStore();
  return { artifact };
}

export function reviewArtifact(ctx, requestId, artifactId, body = {}) {
  const req = findRequest(ctx, requestId);
  if (!req) return null;
  const artifact = (req.artifacts ?? []).find((a) => a.id === artifactId);
  if (!artifact) return { error: 'artifact_not_found', status: 404 };

  const status = String(body.status ?? '').trim();
  if (!['accepted', 'rejected', 'needs_revision'].includes(status)) {
    return { error: 'invalid_artifact_review_status', status: 400 };
  }
  artifact.status = status;
  artifact.reviewed_at = new Date().toISOString();
  artifact.reviewed_by = ctx.userId;
  if (typeof body.notes === 'string' && body.notes.trim()) {
    artifact.review_notes = body.notes.trim();
  }
  refreshPackStatus(req);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.offensive_artifact.reviewed',
    resource_type: 'waf_offensive_request',
    resource_id: requestId,
    metadata: { artifact_id: artifactId, status },
  });
  persistStore();
  return { artifact, authorization_pack_status: req.authorization_pack_status };
}

export function transitionOffensiveRequest(ctx, id, action, metadata = {}) {
  const req = findRequest(ctx, id);
  if (!req) return null;

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

  if (!allowed[action]?.includes(req.state)) {
    return { error: 'invalid_transition', state: req.state, status: 409 };
  }

  if (action === 'close' && !findReport(ctx.tenantId, id)) {
    return { error: 'post_test_report_required', status: 409 };
  }

  let resolvedState = nextState[action];

  if (action === 'reject') {
    req.state = 'rejected';
    req.rejected_at = new Date().toISOString();
    req.rejected_by = ctx.userId;
    req.rejection_reason = String(metadata.reason ?? '').trim() || 'soc_rejected';
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.offensive_request.rejected',
      resource_type: 'waf_offensive_request',
      resource_id: id,
      metadata: { reason: req.rejection_reason },
    });
    persistStore();
    return { offensive_request: formatOffensiveRequest(req) };
  }

  if (action === 'approve') {
    if (!offensiveAuthorizationPackComplete(req)) {
      return {
        error: 'authorization_pack_incomplete',
        status: 409,
        authorization_pack_status: req.authorization_pack_status,
      };
    }
    if (!req.soc_approvals) req.soc_approvals = [];
    if (req.soc_approvals.some((a) => a.user_id === ctx.userId)) {
      return { error: 'duplicate_soc_approval', status: 409 };
    }
    req.soc_approvals.push({ user_id: ctx.userId, at: new Date().toISOString() });
    if (distinctSocApprovalCount(req) < 2) {
      resolvedState = 'under_review';
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'waf.offensive_request.soc_approval_recorded',
        resource_type: 'waf_offensive_request',
        resource_id: id,
        metadata: { approvals: distinctSocApprovalCount(req) },
      });
    } else {
      req.scope_hash = computeTargetGroupScopeHash(ctx.tenantId, req.target_group_id);
      resolvedState = 'approved';
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'waf.offensive_request.approved',
        resource_type: 'waf_offensive_request',
        resource_id: id,
        metadata: { scope_hash: req.scope_hash, suites: req.requested_suites },
      });
    }
  }

  if (action === 'schedule') {
    const window_start = metadata.window_start;
    const window_end = metadata.window_end;
    if (!window_start || !window_end) {
      return { error: 'missing_schedule_window', status: 409 };
    }
    if (!req.scope_hash) {
      return { error: 'missing_scope_hash', status: 409 };
    }
    req.scheduled_window = { window_start, window_end, scope_hash: req.scope_hash };
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.offensive_request.scheduled',
      resource_type: 'waf_offensive_request',
      resource_id: id,
      metadata: { window_start, window_end },
    });
  }

  if (action === 'start') {
    if (distinctSocApprovalCount(req) < 2) {
      return { error: 'insufficient_soc_approvals', status: 409 };
    }
    if (isKillSwitchActiveForTenant(ctx.tenantId)) {
      return { error: 'kill_switch_active', status: 409 };
    }
    if (!req.scheduled_window || !isWithinScheduledWindow(req.scheduled_window)) {
      return { error: 'outside_schedule_window', status: 409 };
    }
    const currentScope = computeTargetGroupScopeHash(ctx.tenantId, req.target_group_id);
    if (currentScope !== req.scope_hash) {
      return { error: 'scope_hash_mismatch', status: 409 };
    }
    const modes = req.requested_suites
      .map((suiteId) => getOffensiveSuiteById(suiteId)?.scenario_family)
      .filter(Boolean);
    const validation = createSocOffensiveWafValidation(ctx, {
      waf_asset_id: req.waf_asset_id,
      modes,
      offensive_request_id: req.id,
      max_requests: req.requested_suites.reduce((sum, suiteId) => {
        const suite = getOffensiveSuiteById(suiteId);
        return sum + (suite?.max_requests ?? 0);
      }, 0),
    });
    if (validation.error) return validation;
    req.waf_validation_run_id = validation.validation_run.id;
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.offensive_request.execution_started',
      resource_type: 'waf_offensive_request',
      resource_id: id,
      metadata: {
        waf_validation_run_id: req.waf_validation_run_id,
        suites: req.requested_suites,
        note: 'SOC-gated offensive suite execution — governed probe worker only.',
      },
    });
  }

  if (action === 'stop') {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.offensive_request.execution_stopped',
      resource_type: 'waf_offensive_request',
      resource_id: id,
      metadata: { reason: metadata.reason ?? 'soc_stop' },
    });
  }

  req.state = resolvedState;
  req.updated_at = new Date().toISOString();
  persistStore();
  return { offensive_request: formatOffensiveRequest(req) };
}

export function recordOffensiveSuiteResults(ctx, requestId, body = {}) {
  const req = findRequest(ctx, requestId);
  if (!req) return null;
  if (!['running', 'stopped'].includes(req.state)) {
    return { error: 'results_not_active', status: 409, state: req.state };
  }

  const entries = Array.isArray(body.suite_results) ? body.suite_results : [];
  if (entries.length === 0) {
    return { error: 'missing_suite_results', status: 400 };
  }

  const normalized = [];
  for (const entry of entries) {
    const suiteId = String(entry.suite_id ?? '').trim();
    try {
      normalized.push(normalizeOffensiveSuiteResult(entry, suiteId));
    } catch (err) {
      return { error: err.code ?? 'unsafe_offensive_evidence', status: 400, message: err.message };
    }
  }

  req.suite_results = normalized;
  req.results_recorded_at = new Date().toISOString();
  req.results_recorded_by = ctx.userId;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.offensive_request.results_recorded',
    resource_type: 'waf_offensive_request',
    resource_id: requestId,
    metadata: {
      suite_count: normalized.length,
      passed_count: normalized.filter((r) => r.passed === true).length,
    },
  });
  persistStore();
  return { offensive_request: formatOffensiveRequest(req), suite_results: normalized };
}

export function upsertOffensivePostTestReport(ctx, requestId, body = {}) {
  const req = findRequest(ctx, requestId);
  if (!req) return null;
  if (req.state !== 'stopped') {
    return { error: 'report_requires_stopped_request', status: 409, state: req.state };
  }

  const now = new Date().toISOString();
  const existing = findReport(ctx.tenantId, requestId);
  const summary = {
    executive_summary: String(body.executive_summary ?? body.summary ?? '').trim() || null,
    blocking_verdict: String(body.blocking_verdict ?? '').trim() || null,
    bypass_findings: Array.isArray(body.bypass_findings) ? body.bypass_findings : [],
    remediation_notes: String(body.remediation_notes ?? '').trim() || null,
  };

  let report;
  if (existing) {
    report = {
      ...existing,
      ...summary,
      suite_results: req.suite_results ?? [],
      updated_at: now,
      updated_by: ctx.userId,
    };
    const idx = getStore().wafOffensiveReports.findIndex((r) => r.id === existing.id);
    if (idx >= 0) getStore().wafOffensiveReports[idx] = report;
  } else {
    report = {
      id: newId('wofrep'),
      tenant_id: ctx.tenantId,
      waf_offensive_request_id: requestId,
      created_at: now,
      created_by: ctx.userId,
      updated_at: now,
      updated_by: ctx.userId,
      ...summary,
      suite_results: req.suite_results ?? [],
    };
    getStore().wafOffensiveReports.push(report);
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: existing ? 'waf.offensive_report.updated' : 'waf.offensive_report.created',
    resource_type: 'waf_offensive_report',
    resource_id: report.id,
    metadata: { waf_offensive_request_id: requestId },
  });
  persistStore();
  return { report, created: !existing };
}

export function getOffensivePostTestReport(ctx, requestId) {
  const req = findRequest(ctx, requestId);
  if (!req) return null;
  const report = findReport(ctx.tenantId, requestId);
  if (!report) return { error: 'report_not_found', status: 404 };
  return { report };
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
    ...(record.rejected_at ? { rejected_at: record.rejected_at, rejection_reason: record.rejection_reason } : {}),
  };
}