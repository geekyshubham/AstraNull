// One protection-validation service per persistence mode: PV-03 storage, PV-04 comparisons, PV-05 firewall acceptance,
// PV-06 matrix/report/findings, and PV-08 explanation-only configuration context.
import { CHECK_CATALOG } from '../contracts/checks.mjs';
import {
  PROTECTION_VALIDATION_CONTRACT_VERSION,
  PROTECTION_VALIDATION_PERMISSIONS,
  REQUIRED_LIMITATIONS,
} from '../contracts/protectionValidation.mjs';
import { roleHasPermission } from '../contracts/roles.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { buildConfigurationContext, attachConfigurationToMatrixRow } from '../lib/protectionConfigEnrichment.mjs';
import { projectProtectionMatrixRows } from '../lib/protectionValidationReport.mjs';
import { requirePermission } from '../rbac.mjs';
import { createFirewallChangeAcceptanceService } from './firewallChangeAcceptance.mjs';
import {
  baselineTargetForExpectation,
  presentBaselineCapture,
  presentEntryPath,
  presentEvaluation,
} from './protectionValidation.mjs';
import { createFirewallAcceptanceRepository } from './protectionValidationFirewall.mjs';
import { buildProtectionValidationReportProjection } from './reports.mjs';
import { getTenantDeploymentFeatures } from './tenantDeploymentFeatures.mjs';

const P = PROTECTION_VALIDATION_PERMISSIONS;
const MATRIX_PATH_LIMIT = 200;
const MATRIX_EVALUATION_LIMIT = 200;
const MATRIX_EXPECTATION_LIMIT = 100;
const MAX_CONFIG_SNAPSHOTS = 1000;

function hasPermission(ctx, permission) {
  if (!roleHasPermission(ctx?.role, permission)) return false;
  if (Array.isArray(ctx?.scopes)) return ctx.scopes.includes('*') || ctx.scopes.includes(permission);
  return true;
}

/** Connector-derived configuration follows the target-detail gate: WAF posture, connectors, and waf:connector_read. */
export function configurationAccess(ctx, runtimeConfig) {
  if (!runtimeConfig || runtimeConfig.featureFlags?.wafPostureEnabled !== true) return 'disabled';
  if (getTenantDeploymentFeatures(ctx, runtimeConfig).connectors !== true) return 'disabled';
  return hasPermission(ctx, 'waf:connector_read') ? 'granted' : 'redacted';
}

function forbidden(ctx, permission, resourceType) {
  if (!ctx?.tenantId) return { error: 'invalid_tenant', status: 400 };
  if (hasPermission(ctx, permission)) return null;
  const denied = requirePermission(ctx, permission, { resource_type: resourceType });
  return { error: 'forbidden', status: denied.status ?? 403, permission };
}

export function checkCatalogForReport(catalog = CHECK_CATALOG) {
  return catalog.map((check) => ({ check_id: check.check_id ?? check.id, probe_profile: check.probe_profile ?? null }));
}

function detectionState(status) {
  if (status === 'detected') return 'detected';
  if (status === 'not_detected') return 'not_detected';
  return 'unknown';
}

/** Vendor detection signals per layer; they never set observed enforcement. */
export function edgeDetectionSignals(rows = []) {
  const out = [];
  for (const row of rows ?? []) {
    if (!row?.target_id) continue;
    const families = [
      ['waf', row.waf_status, [...(row.waf_providers ?? []), row.waf_vendor]],
      ['cdn_edge', row.cdn_status, [...(row.cdn_providers ?? []), row.cdn_provider]],
    ];
    for (const [layer, status, providers] of families) {
      const named = [...new Set(providers.filter((value) => typeof value === 'string' && value.trim()))];
      for (const provider of named.length ? named : [null]) {
        out.push({ tenant_id: row.tenant_id ?? null, target_id: row.target_id, layer, provider, state: detectionState(status) });
      }
    }
  }
  return out;
}

function configurationScopeFor(target) {
  if (!target?.value) return {};
  const value = String(target.value);
  return /^https?:\/\//i.test(value) ? { url: value } : { hostname: value.replace(/:\d+$/, '') };
}

function connectorHealthFrom(sources) {
  const latest = new Map();
  for (const snapshot of sources?.snapshots ?? []) {
    if (!snapshot?.connector_id || latest.has(snapshot.connector_id)) continue;
    latest.set(snapshot.connector_id, snapshot);
  }
  const connectors = new Map((sources?.connectors ?? []).map((row) => [row.id, row]));
  return [...latest.entries()].map(([connectorId, snapshot]) => ({
    connector_id: connectorId,
    status: connectors.get(connectorId)?.status ?? null,
    permission_gaps: connectors.get(connectorId)?.permission_gaps ?? [],
    inventory_complete: snapshot.inventory_complete === true,
    inventory_truncated: snapshot.inventory_truncated === true,
  }));
}

function matrixCounts(rows) {
  const byOutcome = {};
  for (const row of rows) byOutcome[row.outcome] = (byOutcome[row.outcome] ?? 0) + 1;
  return { paths: rows.length, by_outcome: byOutcome };
}

/**
 * @param {{
 *   base: ReturnType<import('./protectionValidation.mjs').createProtectionValidationService>,
 *   backend: object,
 *   evidence?: object,
 *   resolveSourcePerspective?: (workerId: string | null) => string | null,
 *   comparisons?: Record<string, Function> | null,
 *   findings?: { upsertProtectionFindingsFromEvaluation: Function } | null,
 *   now?: () => Date,
 * }} deps
 */
export function createProtectionValidationFacade({
  base,
  backend,
  evidence = undefined,
  resolveSourcePerspective = undefined,
  comparisons = null,
  findings = null,
  now = () => new Date(),
} = {}) {
  if (!base || !backend) throw new Error('protection validation facade requires base service and backend');
  const repository = createFirewallAcceptanceRepository(backend, { recordComparisonEvaluation: base.recordComparisonEvaluation });
  const firewall = createFirewallChangeAcceptanceService({
    repository,
    ...(evidence ? { evidence } : {}),
    ...(resolveSourcePerspective ? { resolveSourcePerspective } : {}),
    now,
  });

  async function deriveFindings(ctx, evaluation, { entryPaths = [], expectations = [], baseline = null } = {}) {
    if (!findings?.upsertProtectionFindingsFromEvaluation || !evaluation?.id) return null;
    try {
      return await findings.upsertProtectionFindingsFromEvaluation(ctx, evaluation, { entryPaths, expectations, baseline });
    } catch {
      incMetric('protection_validation_findings_failed');
      return null;
    }
  }

  async function captureFirewallBaseline(ctx, body = {}) {
    const denied = forbidden(ctx, P.declaration_write, 'firewall_baseline');
    if (denied) return denied;
    const ids = Array.isArray(body?.expectation_ids)
      ? [...new Set(body.expectation_ids.filter((id) => typeof id === 'string'))].slice(0, 200)
      : [];
    if (ids.length) {
      const rows = (await backend.getExpectations(ctx, ids))
        .filter((row) => row.tenant_id === ctx.tenantId && row.kind === 'firewall_change' && row.status === 'active');
      const ownership = await base.verifyBaselineTargets(ctx, rows.map(baselineTargetForExpectation), 'expectation_ids');
      if (ownership) return ownership;
    }
    return firewall.captureFirewallBaseline(ctx, body);
  }

  async function evaluateFirewallComparison(ctx, body = {}) {
    const result = await firewall.evaluateFirewallComparison(ctx, body);
    if (result?.error || result?.replayed) return result;
    const expectationIds = [...new Set((result.items ?? []).map((item) => item.expectation_id).filter(Boolean))];
    const expectations = expectationIds.length ? await backend.getExpectations(ctx, expectationIds) : [];
    const baseline = presentBaselineCapture(await backend.getBaselineCaptureRows(ctx, result.baseline_id));
    await deriveFindings(ctx, result, { expectations, baseline });
    return result;
  }

  async function getProtectionMatrix(ctx, input = {}, options = {}) {
    const denied = forbidden(ctx, P.evidence_read, 'protection_matrix');
    if (denied) return denied;
    const targetId = typeof input.targetId === 'string' ? input.targetId : null;
    const context = await backend.loadTargetContext(ctx, targetId ? [targetId] : []);
    const target = (context.targets ?? []).find((row) => row.tenant_id === ctx.tenantId && row.id === targetId && !row.deleted_at);
    if (!target) return { error: 'unknown_target', status: 404, field: 'targetId' };
    const loadedRelations = await backend.listEntryPaths(ctx, { target_id: targetId, status: 'active', relation_kind: null, cursor: null, limit: MATRIX_PATH_LIMIT + 1 });
    const relations = loadedRelations.slice(0, MATRIX_PATH_LIMIT)
      .filter((row) => row.tenant_id === ctx.tenantId && row.anchor_target_id === targetId);
    const loadedEvaluations = await backend.listEvaluations(ctx, {
      kind: 'path_validation', change_id: null, baseline_id: null, anchor_target_id: targetId, cursor: null, limit: MATRIX_EVALUATION_LIMIT + 1,
    });
    const pathEvaluations = loadedEvaluations.slice(0, MATRIX_EVALUATION_LIMIT).map(presentEvaluation);
    const loadedExpectations = await backend.listExpectations(ctx, {
      kind: 'path_validation', status: null, change_id: null, destination_target_id: null, anchor_target_id: targetId, cursor: null, limit: MATRIX_EXPECTATION_LIMIT + 1,
    });
    const pathExpectations = loadedExpectations.slice(0, MATRIX_EXPECTATION_LIMIT);
    const sourceTruncation = { entry_paths: loadedRelations.length > MATRIX_PATH_LIMIT, evaluations: loadedEvaluations.length > MATRIX_EVALUATION_LIMIT, expectations: loadedExpectations.length > MATRIX_EXPECTATION_LIMIT };
    const entryIds = [...new Set(relations.map((row) => row.entry_target_id))];
    const entryContext = entryIds.length ? await backend.loadTargetContext(ctx, entryIds) : { targets: [] };
    const targetsById = new Map((entryContext.targets ?? []).filter((row) => row.tenant_id === ctx.tenantId).map((row) => [row.id, row]));
    const detections = typeof backend.loadEdgeDetections === 'function' && entryIds.length
      ? edgeDetectionSignals(await backend.loadEdgeDetections(ctx, entryIds))
      : [];
    const at = now();
    const projection = projectProtectionMatrixRows({
      tenantId: ctx.tenantId,
      entryPaths: relations,
      pathEvaluations,
      pathExpectations,
      detections,
      checkCatalog: checkCatalogForReport(),
      now: at,
    });
    const access = configurationAccess(ctx, options.runtimeConfig);
    const connectorsEnabled = access === 'granted';
    const configSources = connectorsEnabled && typeof backend.loadConfigurationSnapshots === 'function'
      ? await backend.loadConfigurationSnapshots(ctx, { limit: MAX_CONFIG_SNAPSHOTS })
      : null;
    const paths = projection.rows.map((row) => {
      const entryTarget = targetsById.get(row.entry_target_id) ?? null;
      if (access === 'redacted') return { ...row, entry_target_value: entryTarget?.value ?? null };
      const configuration = buildConfigurationContext({
        scope: configurationScopeFor(entryTarget),
        snapshots: configSources?.snapshots ?? [],
        connectorsEnabled,
        connectorHealth: connectorHealthFrom(configSources),
        now: at,
      });
      return {
        ...attachConfigurationToMatrixRow(row, configuration),
        entry_target_value: entryTarget?.value ?? null,
      };
    });
    return {
      target_id: targetId,
      contract_version: PROTECTION_VALIDATION_CONTRACT_VERSION,
      generated_at: at.toISOString(),
      connectors_required: false,
      configuration_access: access,
      scope_complete: !Object.values(sourceTruncation).some(Boolean),
      source_truncation: sourceTruncation,
      paths,
      counts: matrixCounts(paths),
      exclusions: projection.exclusions,
      limitations: [...REQUIRED_LIMITATIONS.path_validation],
    };
  }

  async function getProtectionValidationReport(ctx, query = {}) {
    const denied = forbidden(ctx, P.evidence_read, 'protection_validation_report');
    if (denied) return denied;
    if (typeof backend.listReportSources !== 'function') return { error: 'route_not_wired', status: 503 };
    const sources = await backend.listReportSources(ctx, { limit: 501 });
    const sourceTruncation = {};
    for (const key of ['entryPaths', 'expectations', 'evaluations']) {
      sourceTruncation[key] = (sources[key] ?? []).length > 500;
      sources[key] = (sources[key] ?? []).slice(0, 500);
    }
    const anchorIds = String(query.anchor_target_ids ?? query.anchor_target_id ?? '')
      .split(',').map((value) => value.trim()).filter(Boolean).slice(0, 100);
    const targetIds = [...new Set((sources.targets ?? []).map((row) => row.id))];
    const detections = typeof backend.loadEdgeDetections === 'function' && targetIds.length
      ? edgeDetectionSignals(await backend.loadEdgeDetections(ctx, targetIds))
      : [];
    const evaluations = (sources.evaluations ?? []).map((row) => (row.items && row.digest_verified !== undefined ? row : presentEvaluation(row)));
    return buildProtectionValidationReportProjection({
      tenantId: ctx.tenantId,
      generatedAt: now(),
      targets: sources.targets ?? [],
      entryPaths: (sources.entryPaths ?? []).map((row) => ({ ...row, ...presentEntryPath(row) })),
      expectations: sources.expectations ?? [],
      evaluations,
      detections,
      checkCatalog: checkCatalogForReport(),
      scope: { ...(anchorIds.length ? { anchor_target_ids: anchorIds } : {}), source_truncation: sourceTruncation },
      format: query.format,
    });
  }

  /** Explanation-only configuration context for one target; null when disabled, a redaction marker without waf:connector_read. */
  async function getTargetConfigurationContext(ctx, target, options = {}) {
    if (!ctx?.tenantId || !target?.value || typeof backend.loadConfigurationSnapshots !== 'function') return null;
    const access = configurationAccess(ctx, options.runtimeConfig);
    if (access === 'redacted') return { configuration_access: 'redacted' };
    if (access !== 'granted') return null;
    const sources = await backend.loadConfigurationSnapshots(ctx, { limit: MAX_CONFIG_SNAPSHOTS });
    return {
      ...buildConfigurationContext({
        scope: configurationScopeFor(target),
        snapshots: sources?.snapshots ?? [],
        connectorsEnabled: true,
        connectorHealth: connectorHealthFrom(sources),
        now: now(),
      }),
      configuration_access: 'granted',
    };
  }

  /** Records a finished entry-path comparison evaluation and derives findings from the stored record. */
  async function recordEntryPathComparisonEvaluation(comparison, record) {
    if (!comparison?.tenant_id || !record) return null;
    const ctx = { tenantId: comparison.tenant_id, userId: null, role: 'system' };
    const actor = comparison.created_by ?? 'system';
    const expectation = await base.recordPathValidationExpectation(ctx, {
      anchor_target_id: comparison.anchor_target_id,
      scenario: comparison.expectation?.scenario,
      layer_outcomes: comparison.expectation?.layer_outcomes,
    }, { internal: true, actor });
    if (expectation?.error) {
      incMetric('entry_path_comparison_record_failed');
      return expectation;
    }
    const stored = await base.recordComparisonEvaluation(ctx, {
      ...record,
      expectation_id: expectation.id,
      comparison_id: comparison.id,
    }, { internal: true, actor });
    if (stored?.error) {
      incMetric('entry_path_comparison_record_failed');
      return stored;
    }
    if (!stored.replayed) {
      const pathIds = [...new Set(stored.items.map((item) => item.entry_path_id).filter(Boolean))];
      const entryPaths = pathIds.length ? await backend.getEntryPaths(ctx, pathIds) : [];
      await deriveFindings(ctx, stored, { entryPaths, expectations: [expectation] });
    }
    return stored;
  }

  if (typeof comparisons?.setEvaluationRecorder === 'function') {
    comparisons.setEvaluationRecorder(recordEntryPathComparisonEvaluation);
  }

  const delegated = comparisons
    ? {
      planOrStartEntryPathComparison: comparisons.planOrStartEntryPathComparison,
      listEntryPathComparisons: comparisons.listEntryPathComparisons,
      getEntryPathComparison: comparisons.getEntryPathComparison,
      cancelEntryPathComparison: async (ctx, input = {}) => {
        const result = await comparisons.cancelEntryPathComparison(ctx, input.comparisonId, { reason: input.reason });
        return result?.comparison ?? result;
      },
    }
    : {};

  return {
    ...base,
    ...delegated,
    captureFirewallBaseline,
    evaluateFirewallComparison,
    getProtectionMatrix,
    getProtectionValidationReport,
    getTargetConfigurationContext,
    recordEntryPathComparisonEvaluation,
  };
}
