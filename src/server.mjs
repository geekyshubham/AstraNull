import http from 'node:http';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { isConnectorsEnabledForTenant, loadRuntimeConfig } from './config.mjs';
import { getBundledStagingJwksDocument, isBundledStagingOidcEnabled } from './lib/bundledStagingOidc.mjs';
import { requireAgentAuth } from './lib/agentAuth.mjs';
import { resolveHumanApiAuth } from './context.mjs';
import {
  isInternalAdminApiRoute,
  isInternalAdminPageRoute,
  isPublicApiRoute,
  resolveStaffAuth,
} from './lib/staffAuth.mjs';
import { requireStaffPermission } from './lib/staffRbac.mjs';
import * as signupIntake from './services/signupIntake.mjs';
import * as internalManagement from './services/internalManagement.mjs';
import * as breakGlass from './services/breakGlass.mjs';
import * as subscriptions from './services/subscriptions.mjs';
import * as publicSite from './services/publicSite.mjs';
import * as bundledStagingAuth from './services/bundledStagingAuth.mjs';
import { createPasswordAuthService } from './services/passwordAuth.mjs';
import { createDevPasswordAuthRepository } from './services/passwordAuthRepository.mjs';
import { exchangeGuardianBotDastSession } from './services/guardianbotDastSession.mjs';
import { getTenantDeploymentFeatures } from './services/tenantDeploymentFeatures.mjs';
import { readArtifactUploadBody } from './lib/authorizationArtifactLedger.mjs';
import {
  HttpBodyError,
  json,
  parseUrl,
  readBodyText,
  readJsonBody,
  respondBodyError,
  securityHeaders,
  serveStatic,
  text,
} from './lib/http.mjs';
import { isProbeWorkerRoute } from './context.mjs';
import * as probeCoordinator from './services/probeCoordinator.mjs';
import {
  REPORT_EXPORT_FORMATS,
  REPORT_PERIODS,
  normalizeReportPeriod,
  reportCapabilities,
} from './contracts/complianceReports.mjs';
import { requirePermission } from './rbac.mjs';
import { seedIfEmpty } from './seed.mjs';
import { getStore } from './store.mjs';
import * as agents from './services/agents.mjs';
import * as agentUpdates from './services/agentUpdates.mjs';
import * as highScale from './services/highScale.mjs';
import * as reports from './services/reports.mjs';
import * as targetGroups from './services/targetGroups.mjs';
import * as ownershipVerification from './services/ownershipVerification.mjs';
import * as dnsOwnership from './services/dnsOwnership.mjs';
import * as loa from './services/loa.mjs';
import * as targetDetail from './services/targetDetail.mjs';
import * as remediation from './services/remediation.mjs';
import * as testPolicies from './services/testPolicies.mjs';
import * as testRuns from './services/testRuns.mjs';
import * as tokens from './services/tokens.mjs';
import * as serviceAccounts from './services/serviceAccounts.mjs';
import * as secretVault from './services/secretVault.mjs';
import * as state from './services/state.mjs';
import * as placement from './services/placement.mjs';
import * as findings from './services/findings.mjs';
import * as tenants from './services/tenants.mjs';
import * as events from './services/events.mjs';
import * as evidence from './services/evidence.mjs';
import * as productionReleaseEvidence from './services/productionReleaseEvidence.mjs';
import * as custodyVerification from './services/custodyVerification.mjs';
import * as evidenceSnapshotSigning from './services/evidenceSnapshotSigning.mjs';
import * as wafPosture from './services/wafPosture.mjs';
import * as wafOffensive from './services/wafOffensive.mjs';
import * as wafOrchestrator from './services/wafOrchestrator.mjs';
import {
  blockPostgresWafDriftScanRoute,
  tryHandleWafDriftScanRoutes,
} from './routes/wafDriftRoutes.mjs';
import {
  isWafEdgeDetectionRoute,
  tryHandleWafEdgeDetectionRoutes,
} from './routes/wafEdgeDetectionRoutes.mjs';
import { isCveFeedInputError, resolveCveFeedItems } from './lib/cveFeedIngest.mjs';
import { redactDatabaseUrlInMessage } from './lib/pgErrorRedact.mjs';
import { formatNotificationRuleForRead } from './lib/notifications.mjs';
import * as cvePipeline from './services/cvePipeline.mjs';
import * as externalDiscovery from './services/externalDiscovery.mjs';
import * as supplyChainRisk from './services/supplyChainRisk.mjs';
import * as notificationProviderCredentials from './services/notificationProviderCredentials.mjs';
import * as notifications from './services/notifications.mjs';
import * as notificationRetry from './services/notificationRetry.mjs';
import * as notificationDlqRedrive from './services/notificationDlqRedrive.mjs';
import {
  metricsPlaintext,
  observabilityFromState,
  observabilityJson,
  incMetric,
} from './lib/metrics.mjs';
import { createFixedWindowRateLimiter, deriveClientKey } from './lib/rateLimit.mjs';
import * as adapterStub from './services/executionAdapterStub.mjs';
import {
  isAgentUpdateRoute,
  isNotificationManagementRoute,
  isHighScaleRoute,
  isPlacementRoute,
  isPortalRevampRoute,
  portalRevampServicesWired,
  requiredAgentUpdateServiceMethods,
  requiredHighScaleServiceMethods,
  requiredPlacementServiceMethods,
} from './lib/postgresRouteGuard.mjs';

function defaultServiceDeps() {
  return {
    tenants,
    targetGroups,
    ownershipVerification,
    dnsOwnership,
    testPolicies,
    subscriptions,
    tokens,
    serviceAccounts,
    agents,
    agentAuth: { requireAgentAuth },
    testRuns,
    evidence,
    findings: {
      listFindings: findings.listFindings,
      listFindingsEnvelope: findings.listFindingsEnvelope,
      getFinding: findings.getFinding,
      patchFinding: findings.patchFinding,
      getEvidenceBundle: findings.getEvidenceBundle,
    },
    loa,
    targetDetail,
    remediation,
    signupIntake,
    passwordAuth: createPasswordAuthService(createDevPasswordAuthRepository()),
    reports,
    secretVault,
    events,
    notifications,
    notificationProviderCredentials,
    productionReleaseEvidence,
    custodyVerification,
    evidenceSnapshotSigning,
    wafPosture,
    cvePipeline,
    externalDiscovery,
    supplyChainRisk,
    placement,
  };
}

function buildServiceDeps(runtimeConfig, injectedServices) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    return {
      agentAuth: { requireAgentAuth },
      custodyVerification,
      evidenceSnapshotSigning,
      ...(injectedServices ?? {}),
    };
  }
  return { ...defaultServiceDeps(), ...(injectedServices ?? {}) };
}

function respondPostgresRouteNotWired(res) {
  return json(res, 503, { error: 'postgres_route_not_wired' });
}

function isConnectorRoute(path) {
  return path === '/v1/connectors' || path.startsWith('/v1/connectors/');
}

function isWafPostureRoute(path) {
  if (isConnectorRoute(path)) return false;
  return path.startsWith('/v1/waf/');
}

function isWafActionItemRoute(path) {
  return (
    path === '/v1/waf/action-items'
    || /^\/v1\/waf\/action-items\/[^/]+$/.test(path)
    || /^\/v1\/waf\/action-items\/[^/]+\/deliver$/.test(path)
  );
}

function isWafCvePipelineRoute(path) {
  return path === '/v1/waf/cve-pipeline' || path.startsWith('/v1/waf/cve-pipeline/');
}

function isWafSupplyChainRoute(path) {
  return path.startsWith('/v1/waf/supply-chain');
}

function isWafOrchestratorRoute(path) {
  if (path === '/v1/waf/validation-plans' || path === '/v1/waf/validation-plans/scheduled') {
    return true;
  }
  if (/^\/v1\/waf\/validation-plans\/[^/]+\/(execute|cancel)$/.test(path)) {
    return true;
  }
  if (/^\/v1\/waf\/baselines\/[^/]+\/approve$/.test(path)) {
    return true;
  }
  if (/^\/v1\/waf\/drift-events\/[^/]+\/retest$/.test(path)) {
    return true;
  }
  if (path === '/v1/waf/retests') {
    return true;
  }
  if (/^\/v1\/waf\/retests\/[^/]+\/execute$/.test(path)) {
    return true;
  }
  if (/^\/v1\/waf\/retests\/[^/]+\/complete$/.test(path)) {
    return true;
  }
  return false;
}

function isWafCorePostureRoute(path) {
  if (!isWafPostureRoute(path)) return false;
  if (path === '/v1/waf/drift-scans/run' || path === '/v1/waf/drift-scans/latest') return false;
  if (isWafEdgeDetectionRoute(path)) return false;
  if (isWafActionItemRoute(path)) return false;
  if (isWafCvePipelineRoute(path)) return false;
  if (isWafSupplyChainRoute(path)) return false;
  if (isWafOrchestratorRoute(path)) return false;
  return true;
}

function blockWafFeatureDisabled(runtimeConfig, path, res) {
  if (!isWafPostureRoute(path) && !isConnectorRoute(path)) return false;
  if (runtimeConfig.featureFlags.wafPostureEnabled === true) return false;
  json(res, 404, { error: 'waf_feature_disabled' });
  return true;
}

function blockConnectorFeatureDisabled(runtimeConfig, ctx, path, res) {
  if (!isConnectorRoute(path)) return false;
  if (isConnectorsEnabledForTenant(runtimeConfig, ctx.tenantId)) return false;
  json(res, 404, { error: 'connector_feature_disabled' });
  return true;
}

function isDiscoveryRoute(path) {
  return path.startsWith('/v1/discovery/');
}

function blockDiscoveryFeatureDisabled(runtimeConfig, path, res) {
  if (!isDiscoveryRoute(path)) return false;
  if (runtimeConfig.featureFlags.externalDiscoveryEnabled === true) return false;
  json(res, 404, { error: 'discovery_feature_disabled' });
  return true;
}

function blockPostgresWafOrchestratorRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isWafOrchestratorRoute(path)) return false;
  if (serviceDeps.wafOrchestrator) return false;
  json(res, 503, { error: 'postgres_waf_orchestrator_unavailable' });
  return true;
}

function blockPostgresWafPostureRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isWafCorePostureRoute(path)) return false;
  if (serviceDeps.wafPosture) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresWafActionItemsRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isWafActionItemRoute(path)) return false;
  if (serviceDeps.actionItems) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresWafCvePipelineRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isWafCvePipelineRoute(path)) return false;
  if (serviceDeps.cvePipeline) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresWafSupplyChainRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isWafSupplyChainRoute(path)) return false;
  if (serviceDeps.supplyChainRisk) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresDiscoveryRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isDiscoveryRoute(path)) return false;
  if (serviceDeps.externalDiscovery) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function resolveWafPostureService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.wafPosture;
  return wafPosture;
}

function resolveWafOrchestratorService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.wafOrchestrator;
  return wafOrchestrator;
}

function resolveCvePipelineService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.cvePipeline;
  return cvePipeline;
}

function resolveExternalDiscoveryService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.externalDiscovery;
  return externalDiscovery;
}

function resolveSupplyChainRiskService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.supplyChainRisk;
  return supplyChainRisk;
}

function resolveActionItemsService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.actionItems;
  return wafPosture;
}

function resolveHighScaleService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.highScale;
  return highScale;
}

function blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isHighScaleRoute(path, method)) return false;
  const required = requiredHighScaleServiceMethods(path, method);
  const svc = serviceDeps.highScale;
  if (required.every((name) => typeof svc?.[name] === 'function')) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function isSecretVaultRoute(path, method) {
  if (path === '/v1/secrets' && (method === 'GET' || method === 'POST')) return true;
  return method === 'POST' && /^\/v1\/secrets\/[^/]+\/rotate$/.test(path);
}

function blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isSecretVaultRoute(path, method)) return false;
  if (serviceDeps.secretVault) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function isReportRoute(path, method) {
  if (path === '/v1/reports' && method === 'GET') return true;
  if (path === '/v1/reports' && method === 'POST') return true;
  if (method === 'GET' && /^\/v1\/reports\/[^/]+$/.test(path)) return true;
  if (method === 'GET' && /^\/v1\/reports\/[^/]+\/export$/.test(path)) return true;
  return method === 'POST' && /^\/v1\/findings\/[^/]+\/export$/.test(path);
}

function blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isReportRoute(path, method)) return false;
  if (serviceDeps.reports) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresAuditLogRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (method !== 'GET' || path !== '/v1/audit-log') return false;
  if (typeof serviceDeps.audit?.listAuditEntries === 'function') return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresEventsRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (method !== 'POST' || path !== '/v1/events') return false;
  if (typeof serviceDeps.events?.ingestEvent === 'function') return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (path === '/v1/notifications/retries/process' && method === 'POST') {
    if (typeof serviceDeps.notifications?.processDueNotificationRetries === 'function') return false;
    respondPostgresRouteNotWired(res);
    return true;
  }
  if (path === '/v1/notifications/dlq/redrive' && method === 'POST') {
    if (typeof serviceDeps.notifications?.redriveNotificationDlq === 'function') return false;
    respondPostgresRouteNotWired(res);
    return true;
  }
  if (!isNotificationManagementRoute(path, method)) return false;
  if (typeof serviceDeps.notifications?.listNotifications === 'function'
    && typeof serviceDeps.notifications?.createNotificationRule === 'function') {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresStateRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (method !== 'GET' || path !== '/v1/state') return false;
  if (typeof serviceDeps.state?.getState === 'function') return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresPlacementRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isPlacementRoute(path, method)) return false;
  const required = requiredPlacementServiceMethods(path, method);
  const svc = serviceDeps.placement;
  if (required.every((name) => typeof svc?.[name] === 'function')) {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isAgentUpdateRoute(path, method)) return false;
  const required = requiredAgentUpdateServiceMethods(path, method);
  const svc = serviceDeps.agentUpdates;
  if (required.every((name) => typeof svc?.[name] === 'function')) {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isPortalRevampRoute(path, method)) return false;
  if (portalRevampServicesWired(serviceDeps, path, method)) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresProbeJobsRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isProbeWorkerRoute(path, method)) return false;
  const svc = serviceDeps.probeJobs;
  if (
    typeof svc?.listPendingProbeJobsForWorker === 'function' &&
    typeof svc?.ingestProbeResult === 'function'
  ) {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function isProductionReleaseEvidenceAttestationRoute(path, method) {
  return method === 'GET' && path === '/v1/production-release-evidence/attestation';
}

function isProductionReleaseEvidenceRoute(path, method) {
  if (isProductionReleaseEvidenceAttestationRoute(path, method)) return true;
  if (path === '/v1/production-release-evidence' && (method === 'GET' || method === 'POST')) {
    return true;
  }
  return method === 'GET' && /^\/v1\/production-release-evidence\/[^/]+$/.test(path);
}

function blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isProductionReleaseEvidenceRoute(path, method)) return false;
  const svc = serviceDeps.productionReleaseEvidence;
  if (isProductionReleaseEvidenceAttestationRoute(path, method)) {
    if (typeof svc?.getProductionReleaseEvidenceAttestation === 'function') return false;
    respondPostgresRouteNotWired(res);
    return true;
  }
  if (
    typeof svc?.listProductionReleaseEvidence === 'function' &&
    typeof svc?.recordProductionReleaseEvidence === 'function' &&
    typeof svc?.getProductionReleaseEvidence === 'function'
  ) {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function blockTestPolicyRoute(serviceDeps, method, res) {
  const methodNameByHttpMethod = {
    GET: 'listTestPolicies',
    POST: 'createTestPolicy',
    PATCH: 'patchTestPolicy',
    DELETE: 'archiveTestPolicy',
  };
  const methodName = methodNameByHttpMethod[method];
  if (typeof serviceDeps.testPolicies?.[methodName] === 'function') return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function resolveProbeJobsService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    return serviceDeps.probeJobs;
  }
  return probeCoordinator;
}

function resolveAgentUpdateService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    return serviceDeps.agentUpdates;
  }
  return agentUpdates;
}

/** Readiness verdicts are reused for this long before another DB check runs. */
const READINESS_CACHE_TTL_MS = 3_000;

/**
 * Consecutive FRESH failing readiness checks before `/health` reports 503.
 * Hysteresis exists because `/health` is the orchestrator's restart probe: a
 * single transient Postgres blip (e.g. a failover) must not restart the
 * instance, which would turn a recoverable event into a restart loop.
 */
const HEALTH_FAILURE_THRESHOLD = 3;

/**
 * Probe endpoints get their own generous bucket, deliberately NOT the API limit.
 * They must be rate-limited (they were previously exempt, so anonymous traffic
 * could drive unbounded DB work), but throttling the orchestrator's own probe
 * would cause a healthy instance to be killed.
 */
const PROBE_RATE_LIMIT_MIN_MAX_REQUESTS = 1_200;

/**
 * `/health` gets its OWN bucket, separate from `/ready`, `/metrics` and JWKS.
 *
 * Why the split, given they are all "probes": the shared bucket made the restart
 * probe collateral damage of a flood against a DIFFERENT endpoint. `/health` is
 * the path the orchestrator polls (health_check http_path in both App Platform
 * specs, period_seconds 15, failure_threshold 5, instance_count 1), and the
 * limiter gate sits above the handler, so ~20 anonymous req/s of `/ready` used to
 * drain the shared allowance and the next five orchestrator polls got 429 — an
 * unauthenticated remote restart loop, which also wipes the in-memory limiter
 * state on every restart. The cost profiles are unrelated too: `/health` only
 * peeks a cached verdict (no I/O) while `/ready` awaits a database round-trip.
 *
 * Sizing, and this floor is load-bearing: it MUST NOT be below
 * PROBE_RATE_LIMIT_MIN_MAX_REQUESTS. Neither App Platform spec sets
 * ASTRANULL_RATE_LIMIT_MAX_REQUESTS, so the 600 default applies live; a smaller
 * floor here would hand `/health` a 600 ceiling where the pre-split shared
 * bucket gave it 1200, making a flood aimed DIRECTLY at the restart probe about
 * twice as cheap as before the split. Isolating a bucket must not shrink it.
 * Matching the probe floor keeps the change a strict improvement: the indirect
 * path is closed and the direct path is no worse.
 *
 * The real cadence is one poll per 15s, i.e. 4 per default 60s window, so 1200
 * is ~300x headroom — far more than the orchestrator needs, but the number is
 * chosen for the no-regression property above rather than for tightness. A
 * tighter bucket here buys nothing: `/health` peeks a cached verdict and does no
 * I/O, so there is no unbounded work to protect.
 *
 * RESIDUAL, stated plainly: `/health` must not be exempt from limiting — that
 * exemption was the original hole and is pinned by
 * tests/unit/control-plane-availability.test.mjs ('/health must not be exempt
 * from rate limiting'). A finite limit means a flood aimed DIRECTLY at `/health`
 * can still exhaust this bucket, because the pre-auth key collapses to the load
 * balancer's address until ASTRANULL_TRUST_PROXY_HEADERS is enabled. What the
 * split fixes is the much cheaper indirect path: traffic to any other probe
 * endpoint can no longer spend the restart probe's allowance.
 */
// Derived from the probe floor rather than restated as a literal, so the
// no-regression invariant cannot drift if that floor is ever raised.
const HEALTH_RATE_LIMIT_MIN_MAX_REQUESTS = PROBE_RATE_LIMIT_MIN_MAX_REQUESTS;

/**
 * Budget for the unauthenticated credential-exchange POST
 * (`/guardianbot/session`). Tight on purpose: the legitimate caller performs one
 * exchange per CI run, so a per-window allowance in the low tens is generous
 * while still bounding an offline guessing loop against the exchange token.
 *
 * The route was already hard to abuse — the comparison is timing-safe, the minted
 * token is capped at role `viewer` with a 60-900s TTL, and it 404s unless three
 * env vars are set (they are not set on the live deployment). This is about the
 * missing request budget, not about a live break.
 */
const CREDENTIAL_EXCHANGE_RATE_LIMIT_MAX_REQUESTS = 30;

const DEFAULT_MAX_CONNECTIONS = 1_024;
const DEFAULT_HEADERS_TIMEOUT_MS = 15_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/**
 * Module-level drain flag.
 *
 * Set one probe interval before `app.close()` so `/ready` starts reporting 503
 * while the process is still serving. That lets the load balancer pull this
 * instance out of rotation BEFORE it stops accepting connections, instead of
 * discovering the outage by way of failed customer requests.
 */
let draining = false;

/** Begin failing `/ready` ahead of shutdown. */
export function beginDraining() {
  draining = true;
}

export function isDraining() {
  return draining;
}

/** Test seam: module state would otherwise leak between server instances. */
export function resetDrainingState() {
  draining = false;
}

function parseBoundedEnvInt(value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number.parseInt(String(value ?? '').trim(), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

/**
 * Compare a presented token against the configured one in constant time.
 * Both sides are hashed first so `timingSafeEqual` never sees mismatched
 * lengths (it throws on those) and so the comparison cannot leak token length.
 */
function safeTokenEqual(presented, expected) {
  const a = createHash('sha256').update(String(presented)).digest();
  const b = createHash('sha256').update(String(expected)).digest();
  return timingSafeEqual(a, b);
}

function bearerToken(req) {
  const header = req.headers?.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer[ \t]+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

/**
 * TTL + single-flight cache around the readiness assessment.
 *
 * `/ready` was unauthenticated, un-rate-limited, and performed TWO Postgres
 * round trips per request (ping + `assertLatestMigrationApplied`) against a
 * 10-connection pool, so anonymous probe traffic alone could exhaust the pool.
 * Both round trips are retained — `assertLatestMigrationApplied` is the only
 * runtime signal that the running code matches the applied schema — but they now
 * happen at most once per TTL no matter how many callers arrive, and concurrent
 * callers share one in-flight check rather than each starting their own.
 */
function createReadinessCache({ runtimeConfig, runtimeHealth, ttlMs = READINESS_CACHE_TTL_MS, now = () => Date.now() }) {
  /** @type {{ at: number, verdict: any } | null} */
  let cached = null;
  /** @type {Promise<any> | null} */
  let inFlight = null;
  let consecutiveFailures = 0;
  let checkCount = 0;

  const isFresh = () => cached !== null && now() - cached.at < ttlMs;

  function refresh() {
    // Collapse concurrent callers onto a single DB check.
    if (inFlight) return inFlight;
    const pending = (async () => {
      checkCount += 1;
      const verdict = await assessControlPlaneReadiness(runtimeConfig, runtimeHealth);
      cached = { at: now(), verdict };
      if (verdict.ok) consecutiveFailures = 0;
      else consecutiveFailures += 1;
      return verdict;
    })();
    inFlight = pending;
    // Attach a handler to both outcomes so a rejected check cannot surface as an
    // unhandled rejection, and so the slot is always released.
    const release = () => {
      if (inFlight === pending) inFlight = null;
    };
    pending.then(release, release);
    return pending;
  }

  return {
    /** Awaited verdict, reusing a fresh cache entry when there is one. */
    async get() {
      if (isFresh()) return cached.verdict;
      return refresh();
    },
    /**
     * Last known verdict WITHOUT awaiting a DB call, kicking off a refresh when
     * stale. `/health` uses this so the restart probe can never block on a hung
     * database — a probe that hangs is indistinguishable from a dead process and
     * would get the instance killed.
     */
    peek() {
      if (!isFresh()) refresh().catch(() => {});
      return {
        verdict: cached?.verdict ?? null,
        consecutiveFailures,
      };
    },
    /** Diagnostics/tests: how many real assessments have run. */
    checkCount: () => checkCount,
  };
}

async function assessControlPlaneReadiness(runtimeConfig, runtimeHealth) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    if (typeof runtimeHealth !== 'function') {
      return { ok: false, reason: 'postgres_health_unavailable' };
    }
    try {
      await runtimeHealth();
      return { ok: true, persistence: 'postgres' };
    } catch {
      return { ok: false, reason: 'postgres_unhealthy' };
    }
  }
  try {
    const store = getStore();
    if (!store || !Array.isArray(store.tenants)) {
      return { ok: false, reason: 'store_unavailable' };
    }
    return { ok: true, persistence: runtimeConfig.persistenceMode };
  } catch {
    return { ok: false, reason: 'store_unavailable' };
  }
}

function respondRateLimited(res, retryAfterSeconds) {
  const payload = JSON.stringify({ error: 'rate_limited' });
  res.writeHead(429, {
    ...securityHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Retry-After': String(retryAfterSeconds),
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

function respondPasswordAuthResult(res, result) {
  if (!result?.error) return json(res, 200, result);
  const status = Number(result.status) || 400;
  if ((status === 429 || status === 423) && result.retry_after_seconds) {
    res.setHeader('Retry-After', String(result.retry_after_seconds));
  }
  const { status: _status, ...body } = result;
  return json(res, status, body);
}

function respondPasswordResetResult(res, result) {
  if (result?.status === 'password_reset' && !result.error) {
    return json(res, 200, { status: 'password_reset' });
  }
  if (!result?.error) {
    return json(res, 503, {
      error: 'password_login_unavailable',
      message: 'Password authentication is not available on this deployment.',
    });
  }
  const status = Number(result.status) || 400;
  if (status === 429 && result.retry_after_seconds) {
    res.setHeader('Retry-After', String(result.retry_after_seconds));
  }
  const body = {
    error: result.error,
    message: result.message,
    ...(Array.isArray(result.failures) ? { failures: result.failures } : {}),
    ...(Array.isArray(result.fields) ? { fields: result.fields } : {}),
  };
  return json(res, status, body);
}

function readPasswordSessionGeneration(headers) {
  const authorization = headers?.authorization;
  const match = typeof authorization === 'string'
    ? authorization.match(/^Bearer\s+(.+)$/i)
    : null;
  if (!match) return null;
  const parts = match[1].trim().split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (payload?.auth_source !== 'password') return null;
    const generation = Number(payload.session_generation);
    return {
      tagged: true,
      valid: Number.isSafeInteger(generation) && generation > 0,
      generation,
    };
  } catch {
    // Signature/shape verification has already run. A locally tagged token whose payload cannot
    // be parsed is nevertheless invalid and must not be treated as an untagged enterprise token.
    return { tagged: true, valid: false, generation: null };
  }
}

export function rejectsPasswordlessProtectedStagingSession(runtimeConfig, authCtx, passwordSession) {
  return runtimeConfig?.bundledStagingOidc === true
    && authCtx?.tenantId === 'ten_demo'
    && bundledStagingAuth.isPasswordProtectedBundledStagingCustomerId(authCtx?.userId)
    && passwordSession?.tagged !== true;
}

function isPasswordRecoveryPublicRoute(pathname, method) {
  return method === 'POST'
    && (pathname === '/v1/auth/request-password-reset' || pathname === '/v1/auth/reset-password');
}

export function createServer(options = {}) {
  const env = options.env ?? process.env;
  const runtimeConfig =
    options.runtimeConfig ?? loadRuntimeConfig(env);
  const serviceDeps = buildServiceDeps(runtimeConfig, options.services);
  const runtimeHealth = options.runtimeHealth ?? options.persistenceRuntime?.health;
  if (runtimeConfig.persistenceMode !== 'postgres') {
    seedIfEmpty();
  }

  const rateLimiter = runtimeConfig.rateLimit.disabled
    ? null
    : createFixedWindowRateLimiter({
        windowMs: runtimeConfig.rateLimit.windowMs,
        maxRequests: runtimeConfig.rateLimit.maxRequests,
      });

  // Separate, deliberately generous bucket for the unauthenticated infra
  // endpoints. They must not be exempt from limiting (that was the hole that let
  // anonymous traffic drive unbounded readiness work), but they must also not
  // share the API budget: the orchestrator's own probe would then be throttled by
  // unrelated API traffic and a healthy instance would be restarted.
  const probeRateLimiter = runtimeConfig.rateLimit.disabled
    ? null
    : createFixedWindowRateLimiter({
        windowMs: runtimeConfig.rateLimit.windowMs,
        maxRequests: Math.max(
          runtimeConfig.rateLimit.maxRequests,
          PROBE_RATE_LIMIT_MIN_MAX_REQUESTS,
        ),
      });

  // ...and a third bucket for `/health` alone, so a flood against `/ready`,
  // `/metrics` or JWKS cannot spend the restart probe's allowance. See
  // HEALTH_RATE_LIMIT_MIN_MAX_REQUESTS for why the restart probe needs isolating
  // from the other probes and not merely from the API budget.
  const healthRateLimiter = runtimeConfig.rateLimit.disabled
    ? null
    : createFixedWindowRateLimiter({
        windowMs: runtimeConfig.rateLimit.windowMs,
        maxRequests: Math.max(
          runtimeConfig.rateLimit.maxRequests,
          HEALTH_RATE_LIMIT_MIN_MAX_REQUESTS,
        ),
      });

  // The credential-exchange POST gets its own DELIBERATELY TIGHT bucket. It is
  // the only unauthenticated route that mints a bearer, so unlike the probe
  // buckets its correct size is small: a legitimate caller performs one exchange
  // per CI run. `Math.min` rather than `Math.max` because raising the API limit
  // must never loosen a credential surface, while lowering it should still
  // tighten this one. It is kept out of the probe bucket on purpose: GuardianBot
  // reaches both this route and the probes from the same egress address, so
  // sharing a bucket would let its own health traffic spend the exchange budget.
  const credentialExchangeRateLimiter = runtimeConfig.rateLimit.disabled
    ? null
    : createFixedWindowRateLimiter({
        windowMs: runtimeConfig.rateLimit.windowMs,
        maxRequests: Math.min(
          runtimeConfig.rateLimit.maxRequests,
          CREDENTIAL_EXCHANGE_RATE_LIMIT_MAX_REQUESTS,
        ),
      });

  const readinessCache = options.readinessCache ?? createReadinessCache({
    runtimeConfig,
    runtimeHealth,
    ttlMs: parseBoundedEnvInt(env.ASTRANULL_READINESS_CACHE_TTL_MS, READINESS_CACHE_TTL_MS, {
      min: 500,
      max: 30_000,
    }),
  });

  const metricsToken = String(env.ASTRANULL_METRICS_TOKEN ?? '').trim();
  const isProduction = String(env.NODE_ENV ?? '').trim() === 'production';

  /**
   * Server-side error sink. Injectable so tests can assert that a 500 actually
   * emits its correlation id — the id is worthless if it only reaches the client.
   */
  const logError = options.logError ?? ((line) => console.error(line));

  const server = http.createServer(async (req, res) => {
    const url = parseUrl(req);

    try {
      // `/health` is deliberately NOT part of isProbePath any more. It is still
      // rate limited — just against its own bucket — because exempting the
      // restart probe was the original hole and must stay closed.
      const isRestartProbePath = req.method === 'GET' && url.pathname === '/health';
      const isProbePath = req.method === 'GET'
        && (url.pathname === '/ready'
          || url.pathname === '/metrics'
          || url.pathname === '/.well-known/jwks.json');
      // Separate predicate rather than folding this into isProbePath: this is a
      // POST that mints a credential, so calling it a "probe" would misname the
      // allowlist and invite the next reader to widen it.
      const isCredentialExchangePath = req.method === 'POST'
        && url.pathname === '/guardianbot/session';

      // Pre-auth limiter gate. It sits ABOVE the infra handlers, not below them,
      // so an unauthenticated flood is rejected before it can do any work.
      const preAuthRateLimiter = isRestartProbePath
        ? healthRateLimiter
        : isProbePath
          ? probeRateLimiter
          : isCredentialExchangePath
            ? credentialExchangeRateLimiter
            : null;
      if (preAuthRateLimiter) {
        const preAuthKey = deriveClientKey(req, {
          trustProxyHeaders: runtimeConfig.rateLimit.trustProxyHeaders,
          trustedProxyHops: runtimeConfig.rateLimit.trustedProxyHops,
        });
        const decision = preAuthRateLimiter.check(preAuthKey);
        if (!decision.allowed) {
          incMetric('api_rate_limited_total');
          respondRateLimited(res, decision.retryAfterSeconds);
          return;
        }
      }

      if (req.method === 'GET' && url.pathname === '/health') {
        incMetric('http_requests_total');
        // Drain is reported here, not only on /ready, because /health is the path
        // the orchestrator actually polls (health_check http_path in both App
        // Platform specs). While only /ready observed the flip, the drain window
        // was decorative on App Platform: the balancer kept routing new work to an
        // instance that had already committed to exiting, which is exactly the
        // "pull me out of rotation first" behaviour startup.mjs sizes its 15s
        // delay for.
        //
        // Why a 503 here cannot cause a spurious restart: `draining` is only set
        // on the shutdown path (beginDraining() is called from the SIGTERM/SIGINT
        // handler in startup.mjs, which then always closes and exits, backed by a
        // hard grace timer). So this branch never reports 503 for an instance that
        // intends to keep running — the failure it announces is real and already
        // decided. It also cannot trip the restart threshold in practice: five
        // consecutive 15s polls is ~75s, far longer than the 15s drain before the
        // process exits on its own.
        //
        // The no-I/O property of this handler is preserved: this reads a
        // module-level boolean, it does not await anything.
        if (draining) {
          json(res, 503, {
            status: 'draining',
            service: 'astranull',
            reason: 'draining',
          });
          return;
        }
        // Non-blocking read of the cached verdict. /health is the RESTART probe,
        // so it must never await a database call: a probe that hangs on a wedged
        // DB looks identical to a dead process and gets the instance killed.
        const { verdict, consecutiveFailures } = readinessCache.peek();
        const failing = verdict !== null
          && verdict.ok === false
          && consecutiveFailures >= HEALTH_FAILURE_THRESHOLD;
        if (failing) {
          json(res, 503, {
            status: 'degraded',
            service: 'astranull',
            reason: verdict.reason,
            consecutive_failures: consecutiveFailures,
          });
          return;
        }
        json(res, 200, { status: 'ok', service: 'astranull' });
        return;
      }

      if (
        req.method === 'GET'
        && url.pathname === '/.well-known/jwks.json'
        && isBundledStagingOidcEnabled(env)
      ) {
        incMetric('http_requests_total');
        json(res, 200, getBundledStagingJwksDocument(env));
        return;
      }

      if (req.method === 'GET' && url.pathname === '/ready') {
        incMetric('http_requests_total');
        const timestamp = new Date().toISOString();
        // Fail readiness one probe interval before close() so the balancer drains
        // this instance while it can still serve in-flight work.
        if (draining) {
          json(res, 503, {
            status: 'not_ready',
            service: 'astranull',
            reason: 'draining',
            auth_mode: runtimeConfig.authMode,
            persistence: runtimeConfig.persistenceMode,
            timestamp,
          });
          return;
        }
        const check = await readinessCache.get();
        if (!check.ok) {
          json(res, 503, {
            status: 'not_ready',
            service: 'astranull',
            reason: check.reason,
            auth_mode: runtimeConfig.authMode,
            persistence: runtimeConfig.persistenceMode,
            timestamp,
          });
          return;
        }
        json(res, 200, {
          status: 'ready',
          service: 'astranull',
          auth_mode: runtimeConfig.authMode,
          persistence: check.persistence,
          probe_mode: runtimeConfig.probeMode,
          probe_worker_secret_configured: runtimeConfig.probeWorkerSecretConfigured,
          timestamp,
        });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/metrics') {
        incMetric('http_requests_total');
        // Counters describe internal volumes and error rates, so the endpoint is
        // bearer-gated. When no token is configured we fail CLOSED in production
        // and stay open elsewhere, so local/dev scrapes keep working without
        // silently shipping an open metrics endpoint to production.
        if (metricsToken) {
          const presented = bearerToken(req);
          if (!presented || !safeTokenEqual(presented, metricsToken)) {
            json(res, 401, { error: 'unauthorized' });
            return;
          }
        } else if (isProduction) {
          json(res, 401, { error: 'unauthorized', reason: 'metrics_token_not_configured' });
          return;
        }
        text(res, 200, metricsPlaintext());
        return;
      }

      if (req.method === 'POST' && url.pathname === '/guardianbot/session') {
        const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
        const result = exchangeGuardianBotDastSession({
          authorization: req.headers.authorization,
          body,
          env,
        });
        json(res, result.status, result.body);
        return;
      }

      if (isInternalAdminPageRoute(url.pathname, req.method, runtimeConfig)) {
        const served = await serveStatic(req, res, url, runtimeConfig);
        if (served) return;
      }

      if (req.method === 'GET' && (url.pathname === '/internal/soc' || url.pathname === '/internal-soc.html')) {
        const served = await serveStatic(req, res, url, runtimeConfig);
        if (served) return;
      }

      if (url.pathname.startsWith('/v1') || url.pathname.startsWith('/internal')) {
        const clientKey = deriveClientKey(req, {
          trustProxyHeaders: runtimeConfig.rateLimit.trustProxyHeaders,
          trustedProxyHops: runtimeConfig.rateLimit.trustedProxyHops,
        });
        if (rateLimiter) {
          const decision = rateLimiter.check(clientKey);
          if (!decision.allowed) {
            incMetric('api_rate_limited_total');
            respondRateLimited(res, decision.retryAfterSeconds);
            return;
          }
        }
        if (
          isPublicApiRoute(url.pathname, req.method)
          || isPasswordRecoveryPublicRoute(url.pathname, req.method)
        ) {
          await handlePublicApi(req, res, url, runtimeConfig, {
            clientKey,
            services: serviceDeps,
          });
          return;
        }
        if (isInternalAdminApiRoute(url.pathname, req.method, runtimeConfig)) {
          const staffAuth = await resolveStaffAuth(req.headers, runtimeConfig);
          if (!staffAuth.ok) {
            json(res, staffAuth.status, staffAuth.body);
            return;
          }
          await handleInternalAdminApi(req, res, url, staffAuth.ctx, runtimeConfig, {
            services: serviceDeps,
          });
          return;
        }
        let probeBodyText = '';
        if (
          isProbeWorkerRoute(url.pathname, req.method) &&
          req.method === 'POST' &&
          /^\/internal\/probe\/jobs\/[^/]+\/result$/.test(url.pathname)
        ) {
          probeBodyText = await readBodyText(req, runtimeConfig.maxJsonBodyBytes);
        }
        const auth = await resolveHumanApiAuth(req.headers, url.pathname, req.method, runtimeConfig, {
          bodyText: probeBodyText,
          services: serviceDeps,
        });
        if (!auth.ok) {
          json(res, auth.status, auth.body);
          return;
        }
        const passwordSession = readPasswordSessionGeneration(req.headers);
        if (rejectsPasswordlessProtectedStagingSession(runtimeConfig, auth.ctx, passwordSession)) {
          json(res, 401, { error: 'unauthorized', message: 'Missing or invalid session token.' });
          return;
        }
        if (passwordSession?.tagged) {
          const validatePasswordSession = serviceDeps.passwordAuth?.validatePasswordSession;
          if (!passwordSession.valid || typeof validatePasswordSession !== 'function') {
            json(res, 401, { error: 'unauthorized', message: 'Missing or invalid session token.' });
            return;
          }
          const sessionState = await validatePasswordSession({
            tenantId: auth.ctx?.tenantId,
            userId: auth.ctx?.userId,
            sessionGeneration: passwordSession.generation,
          });
          if (sessionState?.valid !== true) {
            json(res, 401, { error: 'unauthorized', message: 'Missing or invalid session token.' });
            return;
          }
        }
        const authCtx = auth.ctx ?? { tenantId: null, userId: null, role: 'viewer' };
        const ctx =
          runtimeConfig.persistenceMode === 'postgres'
            ? { ...authCtx, persistenceMode: 'postgres', auditService: serviceDeps.audit }
            : authCtx;
        await handleApi(req, res, url, ctx, runtimeConfig, {
          probeBodyText,
          services: serviceDeps,
        });
        return;
      }

      // HEAD is dispatched alongside GET: `serveStatic` answers it with the same status and
      // headers minus the body. Without this, `curl -I /react-app.js` fell through to 404.
      if (req.method === 'GET' || req.method === 'HEAD') {
        const served = await serveStatic(req, res, url, runtimeConfig);
        if (served) return;
        text(res, 404, 'Not found');
        return;
      }

      text(res, 404, 'Not found');
    } catch (err) {
      if (err instanceof HttpBodyError) {
        // Closes the connection when an oversized body was abandoned unread.
        respondBodyError(res, err);
        return;
      }
      // Driver errors carry schema, table, host and role text in their message, so
      // the response body must never echo them. The correlation id is the only
      // link between what the caller sees and the full stack, so it is logged
      // BEFORE responding — a failure to write the response must not lose the
      // only diagnostic. The stack is passed as a string (not the Error) because
      // the redactor reads `.message` off an Error and would drop the frames.
      const correlationId = randomUUID();
      logError(
        `astranull internal_error correlation_id=${correlationId} method=${req.method} path=${url.pathname} ${redactDatabaseUrlInMessage(err?.stack ?? err, env)}`,
      );
      json(res, 500, { error: 'internal_error', correlation_id: correlationId });
    }
  });

  // Explicit socket-level ceilings. Without these, Node's defaults let a caller
  // hold connections open indefinitely (slowloris) or open as many as the file
  // descriptor limit allows, which is a cheap way to take the control plane down
  // without ever passing authentication.
  server.maxConnections = parseBoundedEnvInt(
    env.ASTRANULL_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS,
    { min: 16, max: 65_535 },
  );
  // Time allowed to finish sending request HEADERS.
  server.headersTimeout = parseBoundedEnvInt(
    env.ASTRANULL_HEADERS_TIMEOUT_MS,
    DEFAULT_HEADERS_TIMEOUT_MS,
    { min: 1_000, max: 120_000 },
  );
  // Time allowed for the ENTIRE request, including the body.
  server.requestTimeout = parseBoundedEnvInt(
    env.ASTRANULL_REQUEST_TIMEOUT_MS,
    DEFAULT_REQUEST_TIMEOUT_MS,
    { min: 1_000, max: 300_000 },
  );

  return server;
}

async function handleApi(req, res, url, ctx, runtimeConfig, options = {}) {
  const path = url.pathname;
  const method = req.method;
  const serviceDeps = options.services ?? defaultServiceDeps();
  incMetric('http_requests_total');

  if (method === 'GET' && path === '/v1/observability') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (runtimeConfig.persistenceMode === 'postgres') {
      if (typeof serviceDeps.state?.getState !== 'function') {
        return respondPostgresRouteNotWired(res);
      }
      const tenantState = await serviceDeps.state.getState(ctx);
      return json(res, 200, observabilityFromState(tenantState));
    }
    return json(res, 200, observabilityJson());
  }

  if (method === 'GET' && path === '/v1/tenants/current') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const t = await serviceDeps.tenants.getCurrentTenant(ctx);
    if (!t) return json(res, 404, { error: 'not_found' });
    return json(res, 200, t);
  }
  if (method === 'GET' && path === '/v1/tenant/deployment-features') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, getTenantDeploymentFeatures(ctx, runtimeConfig));
  }
  if (method === 'GET' && path === '/v1/subscription/current') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (typeof serviceDeps.subscriptions?.getCurrentSubscriptionSummary !== 'function') {
      return respondPostgresRouteNotWired(res);
    }
    return json(res, 200, await serviceDeps.subscriptions.getCurrentSubscriptionSummary(ctx));
  }
  if (method === 'PATCH' && path === '/v1/tenants/current') {
    const gate = requirePermission(ctx, 'tenant:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const t = await serviceDeps.tenants.patchCurrentTenant(ctx, body);
    if (!t) return json(res, 404, { error: 'not_found' });
    return json(res, 200, t);
  }
  if (method === 'GET' && path === '/v1/environments') {
    const gate = requirePermission(ctx, 'environment:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.tenants.listEnvironments(ctx) });
  }
  if (method === 'POST' && path === '/v1/environments') {
    const gate = requirePermission(ctx, 'environment:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    return json(res, 201, await serviceDeps.tenants.createEnvironment(ctx, body));
  }
  const envMatch = path.match(/^\/v1\/environments\/([^/]+)$/);
  if (envMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'environment:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const env = await serviceDeps.tenants.patchEnvironment(ctx, envMatch[1], body);
    if (!env) return json(res, 404, { error: 'not_found' });
    return json(res, 200, env);
  }

  if (method === 'POST' && path === '/v1/events') {
    const gate = requirePermission(ctx, 'event:ingest');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresEventsRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.events.ingestEvent(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, result.duplicate ? 200 : 201, result);
  }
  if (method === 'GET' && path === '/v1/evidence') {
    const gate = requirePermission(ctx, 'evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.evidence.listEvidence(ctx) });
  }
  const evMatch = path.match(/^\/v1\/evidence\/([^/]+)$/);
  if (evMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const item = await serviceDeps.evidence.getEvidence(ctx, evMatch[1]);
    if (!item) return json(res, 404, { error: 'not_found' });
    return json(res, 200, item);
  }
  if (path === '/v1/evidence/snapshots/sign' && method === 'POST') {
    const gate = requirePermission(ctx, 'evidence:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.evidenceSnapshotSigning.signEvidenceSnapshotCustody(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }

  if (blockDiscoveryFeatureDisabled(runtimeConfig, path, res)) return;
  if (blockPostgresDiscoveryRoute(runtimeConfig, serviceDeps, path, res)) return;
  const discoverySvc = resolveExternalDiscoveryService(runtimeConfig, serviceDeps);

  if (method === 'GET' && path === '/v1/discovery/entities') {
    const gate = requirePermission(ctx, 'discovery:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await discoverySvc.listEntities(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result });
  }
  if (method === 'POST' && path === '/v1/discovery/entities') {
    const gate = requirePermission(ctx, 'discovery:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await discoverySvc.createEntity(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'GET' && path === '/v1/discovery/candidates') {
    const gate = requirePermission(ctx, 'discovery:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await discoverySvc.listCandidates(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result });
  }
  if (method === 'POST' && path === '/v1/discovery/candidates') {
    const gate = requirePermission(ctx, 'discovery:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await discoverySvc.createCandidate(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'POST' && path === '/v1/discovery/sources/ingest') {
    const gate = requirePermission(ctx, 'discovery:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await discoverySvc.ingestDiscoveryCandidates(ctx, body?.source, body?.records);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'GET' && path === '/v1/discovery/inbox') {
    const gate = requirePermission(ctx, 'discovery:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await discoverySvc.getDiscoveryInbox(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'GET' && path === '/v1/discovery/reports/summary') {
    const gate = requirePermission(ctx, 'discovery:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await discoverySvc.getDiscoveryReportSummary(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const discoveryApproveMatch = path.match(/^\/v1\/discovery\/candidates\/([^/]+)\/approve$/);
  if (discoveryApproveMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'discovery:approve');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await discoverySvc.approveCandidateToTarget(ctx, discoveryApproveMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const discoveryRejectMatch = path.match(/^\/v1\/discovery\/candidates\/([^/]+)\/reject$/);
  if (discoveryRejectMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'discovery:approve');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await discoverySvc.rejectCandidate(ctx, discoveryRejectMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const discoveryImportMatch = path.match(/^\/v1\/discovery\/candidates\/([^/]+)\/import$/);
  if (discoveryImportMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'discovery:approve');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await discoverySvc.importCandidateToTargetGroup(ctx, discoveryImportMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
  if (blockConnectorFeatureDisabled(runtimeConfig, ctx, path, res)) return;
  if (blockPostgresWafOrchestratorRoute(runtimeConfig, serviceDeps, path, res)) return;
  if (blockPostgresWafPostureRoute(runtimeConfig, serviceDeps, path, res)) return;
  if (blockPostgresWafDriftScanRoute(runtimeConfig, serviceDeps, path, res)) return;
  if (blockPostgresWafActionItemsRoute(runtimeConfig, serviceDeps, path, res)) return;
  if (blockPostgresWafCvePipelineRoute(runtimeConfig, serviceDeps, path, res)) return;
  if (blockPostgresWafSupplyChainRoute(runtimeConfig, serviceDeps, path, res)) return;
  const wafSvc = resolveWafPostureService(runtimeConfig, serviceDeps);
  const cveSvc = resolveCvePipelineService(runtimeConfig, serviceDeps);
  const supplyChainSvc = resolveSupplyChainRiskService(runtimeConfig, serviceDeps);
  const actionItemsSvc = resolveActionItemsService(runtimeConfig, serviceDeps);
  const wafOrchestratorSvc = resolveWafOrchestratorService(runtimeConfig, serviceDeps);

  if (method === 'GET' && path === '/v1/waf/validation-plans') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafOrchestratorSvc.listValidationPlans(ctx);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result.plans ?? [] });
  }
  if (method === 'POST' && path === '/v1/waf/validation-plans') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafOrchestratorSvc.createValidationPlan(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { validation_plan: result.validation_plan });
  }
  if (method === 'GET' && path === '/v1/waf/validation-plans/scheduled') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafOrchestratorSvc.getScheduledPlans(ctx);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result.plans ?? [] });
  }
  const wafPlanExecuteMatch = path.match(/^\/v1\/waf\/validation-plans\/([^/]+)\/execute$/);
  if (wafPlanExecuteMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafOrchestratorSvc.executeValidationPlan(
      ctx,
      wafPlanExecuteMatch[1],
      runtimeConfig,
    );
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const wafPlanCancelMatch = path.match(/^\/v1\/waf\/validation-plans\/([^/]+)\/cancel$/);
  if (wafPlanCancelMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafOrchestratorSvc.cancelValidationPlan(ctx, wafPlanCancelMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { validation_plan: result.validation_plan });
  }
  const wafBaselineApproveMatch = path.match(/^\/v1\/waf\/baselines\/([^/]+)\/approve$/);
  if (wafBaselineApproveMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafOrchestratorSvc.approveBaseline(ctx, wafBaselineApproveMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const wafDriftRetestMatch = path.match(/^\/v1\/waf\/drift-events\/([^/]+)\/retest$/);
  if (wafDriftRetestMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafOrchestratorSvc.requestRetest(ctx, wafDriftRetestMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { retest_request: result.retest_request });
  }
  if (method === 'GET' && path === '/v1/waf/retests') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafOrchestratorSvc.listRetests(ctx, {
      drift_event_id: url.searchParams.get('drift_event_id') || undefined,
      waf_asset_id: url.searchParams.get('waf_asset_id') || undefined,
      status: url.searchParams.get('status') || undefined,
    });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result.items ?? [] });
  }
  const wafRetestExecuteMatch = path.match(/^\/v1\/waf\/retests\/([^/]+)\/execute$/);
  if (wafRetestExecuteMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafOrchestratorSvc.executeRetest(
      ctx,
      wafRetestExecuteMatch[1],
      body,
      runtimeConfig,
    );
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const wafRetestCompleteMatch = path.match(/^\/v1\/waf\/retests\/([^/]+)\/complete$/);
  if (wafRetestCompleteMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafOrchestratorSvc.completeRetest(ctx, wafRetestCompleteMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/v1/waf/assets') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await wafSvc.listWafAssets(ctx) });
  }
  if (method === 'POST' && path === '/v1/waf/assets') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.createWafAsset(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { asset: result.asset });
  }
  const wafAssetMatch = path.match(/^\/v1\/waf\/assets\/([^/]+)$/);
  if (wafAssetMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const payload = await wafSvc.getWafAsset(ctx, wafAssetMatch[1]);
    if (!payload) return json(res, 404, { error: 'waf_asset_not_found' });
    return json(res, 200, payload);
  }
  if (wafAssetMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.patchWafAsset(ctx, wafAssetMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { asset: result.asset });
  }
  const wafAssetExceptionMatch = path.match(/^\/v1\/waf\/assets\/([^/]+)\/exception$/);
  if (wafAssetExceptionMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (typeof wafSvc.createWafException !== 'function') {
      return json(res, 503, { error: 'postgres_route_not_wired' });
    }
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.createWafException(ctx, wafAssetExceptionMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, {
      exception: result.exception,
      posture: result.posture ?? null,
    });
  }
  if (method === 'GET' && path === '/v1/waf/exceptions') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (typeof wafSvc.listWafExceptions !== 'function') {
      return json(res, 503, { error: 'postgres_route_not_wired' });
    }
    const items = await wafSvc.listWafExceptions(ctx);
    return json(res, 200, { items: Array.isArray(items) ? items : [] });
  }
  if (method === 'GET' && path === '/v1/waf/coverage') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const windowDays = url.searchParams.get('window_days');
    return json(res, 200, await wafSvc.getWafCoverage(ctx, {
      ...(windowDays ? { window_days: windowDays } : {}),
    }));
  }
  if (method === 'GET' && path === '/v1/waf/coverage/summary') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getSummaryFn = wafSvc.getCoverageSummary ?? wafPosture.getCoverageSummary;
    return json(res, 200, await getSummaryFn(ctx));
  }
  if (method === 'GET' && path === '/v1/waf/coverage/vendors') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, await wafSvc.getWafCoverageVendors(ctx));
  }
  if (method === 'GET' && path === '/v1/waf/coverage/entities') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const entityType = url.searchParams.get('entity_type');
    return json(res, 200, await wafSvc.getWafCoverageEntities(ctx, {
      ...(entityType ? { entity_type: entityType } : {}),
    }));
  }
  if (method === 'GET' && path === '/v1/waf/coverage/geography') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const regionCode = url.searchParams.get('region_code');
    return json(res, 200, await wafSvc.getWafCoverageGeography(ctx, {
      ...(regionCode ? { region_code: regionCode } : {}),
    }));
  }
  if (method === 'GET' && path === '/v1/waf/coverage/criticality') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const criticality = url.searchParams.get('business_criticality') ?? url.searchParams.get('criticality');
    return json(res, 200, await wafSvc.getWafCoverageCriticality(ctx, {
      ...(criticality ? { business_criticality: criticality } : {}),
    }));
  }
  if (method === 'GET' && path === '/v1/waf/coverage/risk-roadmap') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const query = {
      entity_id: url.searchParams.get('entity_id') || undefined,
      region_code: url.searchParams.get('region_code') || undefined,
      vendor: url.searchParams.get('vendor') || undefined,
      min_score: url.searchParams.get('min_score') || undefined,
      limit_per_tier: url.searchParams.get('limit_per_tier') || undefined,
    };
    return json(res, 200, await wafSvc.getWafRiskRoadmap(ctx, query));
  }
  if (method === 'GET' && path === '/v1/waf/coverage/vendor-consolidation') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, await wafSvc.getWafVendorConsolidation(ctx));
  }
  if (method === 'GET' && path === '/v1/waf/products') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (typeof wafSvc.listWafProducts !== 'function') {
      return json(res, 503, { error: 'postgres_route_not_wired' });
    }
    return json(res, 200, await wafSvc.listWafProducts(ctx));
  }
  if (method === 'GET' && path === '/v1/waf/scenario-intake') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (typeof wafSvc.listScenarioIntakes !== 'function') {
      return json(res, 503, { error: 'postgres_route_not_wired' });
    }
    return json(res, 200, await wafSvc.listScenarioIntakes(ctx));
  }
  if (method === 'POST' && path === '/v1/waf/scenario-intake') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (typeof wafSvc.submitScenarioIntake !== 'function') {
      return json(res, 503, { error: 'postgres_route_not_wired' });
    }
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.submitScenarioIntake(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 202, result);
  }
  if (method === 'GET' && path === '/v1/waf/offensive-suites') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = wafOffensive.listOffensiveSuites();
    if (result.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/waf/offensive-requests') {
    const gate = requirePermission(ctx, 'waf_offensive:request');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = wafOffensive.createOffensiveRequest(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'GET' && path === '/v1/waf/offensive-requests') {
    const gate = requirePermission(ctx, 'waf_offensive:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = wafOffensive.listOffensiveRequests(ctx);
    if (result.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }
  const wafOffensiveGetMatch = path.match(/^\/v1\/waf\/offensive-requests\/([^/]+)$/);
  if (wafOffensiveGetMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf_offensive:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = wafOffensive.getOffensiveRequest(ctx, wafOffensiveGetMatch[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }
  const wafOffensiveArtPost = path.match(/^\/v1\/waf\/offensive-requests\/([^/]+)\/artifacts$/);
  if (wafOffensiveArtPost && method === 'POST') {
    const gate = requirePermission(ctx, 'waf_offensive:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    let upload;
    try {
      upload = await readArtifactUploadBody(req, runtimeConfig.maxJsonBodyBytes);
    } catch (err) {
      if (err instanceof HttpBodyError) return respondBodyError(res, err);
      throw err;
    }
    const art = wafOffensive.addArtifact(ctx, wafOffensiveArtPost[1], upload.body, {
      uploadEnvelope: upload.envelope,
    });
    if (!art) return json(res, 404, { error: 'not_found' });
    if (art.error) return json(res, art.status ?? 400, art);
    return json(res, 201, art);
  }
  if (method === 'POST' && path === '/v1/waf/validations') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.createWafValidation(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { validation_run: result.validation_run });
  }
  if (method === 'GET' && path === '/v1/waf/validations') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await wafSvc.listWafValidations(ctx) });
  }
  const wafValidationMatch = path.match(/^\/v1\/waf\/validations\/([^/]+)$/);
  if (wafValidationMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const payload = await wafSvc.getWafValidation(ctx, wafValidationMatch[1]);
    if (!payload) return json(res, 404, { error: 'waf_asset_not_found' });
    return json(res, 200, payload);
  }
  const wafFinalizeMatch = path.match(/^\/v1\/waf\/validations\/([^/]+)\/finalize$/);
  if (wafFinalizeMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.finalizeWafValidation(ctx, wafFinalizeMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (await tryHandleWafDriftScanRoutes(req, res, url, ctx, runtimeConfig, serviceDeps)) return;
  if (await tryHandleWafEdgeDetectionRoutes(req, res, url, ctx, runtimeConfig, serviceDeps)) return;
  if (method === 'GET' && path === '/v1/waf/drift-events') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await wafSvc.listWafDriftEvents(ctx) });
  }
  const wafReportExportMatch = path.match(/^\/v1\/waf\/reports\/([^/]+)\/export$/);
  if (wafReportExportMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const format = url.searchParams.get('format') || 'json';
    const out = await wafSvc.exportWafReport(ctx, wafReportExportMatch[1], format);
    if (out?.error) return json(res, out.status ?? 400, out);
    if (format === 'markdown') {
      text(res, 200, out.content, 'text/markdown; charset=utf-8');
      return;
    }
    return json(res, 200, { payload: out.payload, custody: out.custody });
  }
  const wafDriftMatch = path.match(/^\/v1\/waf\/drift-events\/([^/]+)$/);
  if (wafDriftMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.patchWafDriftEvent(ctx, wafDriftMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { drift_event: result.drift_event });
  }

  if (method === 'GET' && path === '/v1/connectors') {
    const gate = requirePermission(ctx, 'waf:connector_read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const listFn = wafSvc.listConnectorsEnvelope ?? (async (scope) => {
      const items = await wafSvc.listConnectors(scope);
      return {
        items,
        count: items.length,
        meta: {
          empty_reason: items.length ? null : 'No connectors are configured for this tenant.',
        },
      };
    });
    return json(res, 200, await listFn(ctx));
  }
  if (method === 'POST' && path === '/v1/connectors') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.createConnector(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { connector: result.connector });
  }
  const connectorValidateMatch = path.match(/^\/v1\/connectors\/([^/]+)\/validate$/);
  if (connectorValidateMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafSvc.validateConnector(ctx, connectorValidateMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const connectorPollMatch = path.match(/^\/v1\/connectors\/([^/]+)\/poll$/);
  if (connectorPollMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.pollConnector(ctx, connectorPollMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 202, { poll_job: result.poll_job, snapshots: result.snapshots });
  }
  const connectorSnapshotsMatch = path.match(/^\/v1\/connectors\/([^/]+)\/snapshots$/);
  if (connectorSnapshotsMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:connector_read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafSvc.listConnectorSnapshots(ctx, connectorSnapshotsMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: Array.isArray(result) ? result : result.items });
  }
  const connectorDisableMatch = path.match(/^\/v1\/connectors\/([^/]+)\/disable$/);
  if (connectorDisableMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.disableConnector(ctx, connectorDisableMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { connector: result.connector });
  }
  const connectorInventoryMatch = path.match(/^\/v1\/connectors\/([^/]+)\/inventory$/);
  if (connectorInventoryMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:connector_read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getInventoryFn = wafSvc.getConnectorInventory ?? wafPosture.getConnectorInventory;
    const result = await getInventoryFn(ctx, connectorInventoryMatch[1], {
      cursor: url.searchParams.get('cursor') ?? undefined,
      limit: url.searchParams.get('limit') ?? undefined,
    });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/v1/waf/cve-pipeline') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await cveSvc.listCvePipelineItems(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/waf/cve-pipeline') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await cveSvc.createCvePipelineItem(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'POST' && path === '/v1/waf/cve-pipeline/ingest') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    // The try covers INPUT RESOLUTION ONLY. Persisting the feed is deliberately
    // outside it so a driver/connection fault propagates to the top-level 5xx
    // handler instead of being reported as a client error with the driver's
    // message attached.
    let feedItems;
    try {
      feedItems = await resolveCveFeedItems(body);
    } catch (err) {
      // Only codes on the module's frozen allowlist are known to carry a fixed,
      // input-derived message. Anything else is an infrastructure fault wearing
      // an error code (pg always sets one) and must not be answered with 400.
      if (!isCveFeedInputError(err)) throw err;
      return json(res, 400, {
        error: err.code,
        message: err.message,
      });
    }
    const result = await cveSvc.ingestCveFeed(ctx, feedItems);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 202, result);
  }
  const cveTriageMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/triage$/);
  if (cveTriageMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await cveSvc.triageCvePipelineItem(ctx, cveTriageMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const cveMatchMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/match$/);
  if (cveMatchMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await cveSvc.matchCveAssets(ctx, cveMatchMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const cveValidateMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/validate$/);
  if (cveValidateMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await cveSvc.executeSafeCveValidation(ctx, cveValidateMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const cveRetestMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/retest$/);
  if (cveRetestMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await cveSvc.executeCvePostMitigationRetest(ctx, cveRetestMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    const status = result.closure?.ready ? 200 : 201;
    return json(res, status, result);
  }
  const cvePlaybookMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/playbook$/);
  if (cvePlaybookMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await cveSvc.getCveMitigationPlaybook(ctx, cvePlaybookMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const cvePlaybookApproveMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/playbook\/approve$/);
  if (cvePlaybookApproveMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await cveSvc.approveCveMitigationPlaybook(ctx, cvePlaybookApproveMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const cveCoordinatedRetestMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/coordinated-retest$/);
  if (cveCoordinatedRetestMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await cveSvc.executeCoordinatedCveRetest(ctx, cveCoordinatedRetestMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    const status = result.closure?.ready ? 200 : 201;
    return json(res, status, result);
  }
  const cveRecommendMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/recommend$/);
  if (cveRecommendMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await cveSvc.createRecommendation(ctx, cveRecommendMatch[1], body.vendor);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const cveStageMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/stage$/);
  if (cveStageMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await cveSvc.patchCveItemStage(ctx, cveStageMatch[1], body.stage);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/v1/waf/supply-chain/risks') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const riskId = url.searchParams.get('risk_id');
    if (riskId) {
      const result = await supplyChainSvc.getSupplyChainRisk(ctx, riskId);
      if (result?.error) return json(res, result.status ?? 400, result);
      return json(res, 200, result);
    }
    const result = await supplyChainSvc.listSupplyChainRisks(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result });
  }
  const supplyChainRiskMatch = path.match(/^\/v1\/waf\/supply-chain\/risks\/([^/]+)$/);
  if (supplyChainRiskMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await supplyChainSvc.getSupplyChainRisk(ctx, supplyChainRiskMatch[1]);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/waf/supply-chain/risks') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await supplyChainSvc.createSupplyChainRisk(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'POST' && path === '/v1/waf/supply-chain/assess/dangling-cname') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await supplyChainSvc.assessDanglingCname(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/waf/supply-chain/assess/dangling-dependency') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await supplyChainSvc.assessDanglingDependency(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/waf/supply-chain/sources/ingest') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await supplyChainSvc.ingestSupplyChainSignals(ctx, body?.source, body?.records);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const supplyChainStateMatch = path.match(/^\/v1\/waf\/supply-chain\/risks\/([^/]+)\/state$/);
  if (supplyChainStateMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await supplyChainSvc.patchRiskState(ctx, supplyChainStateMatch[1], body.state, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const supplyChainTicketMatch = path.match(/^\/v1\/waf\/supply-chain\/risks\/([^/]+)\/ticket$/);
  if (supplyChainTicketMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await supplyChainSvc.createRemediationTicket(ctx, supplyChainTicketMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const supplyChainPhaseAuthMatch = path.match(/^\/v1\/waf\/supply-chain\/risks\/([^/]+)\/phase-authorization$/);
  if (supplyChainPhaseAuthMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await supplyChainSvc.getPhaseAuthorizations(ctx, supplyChainPhaseAuthMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (supplyChainPhaseAuthMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'supply_chain:authorize');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await supplyChainSvc.submitPhaseAuthorization(
      ctx,
      supplyChainPhaseAuthMatch[1],
      body,
    );
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }

  if (method === 'GET' && path === '/v1/waf/action-items') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await actionItemsSvc.listActionItems(ctx) });
  }
  if (method === 'POST' && path === '/v1/waf/action-items') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const findingId = body.finding_id ?? body.findingId;
    const finding = findingId ? await serviceDeps.findings.getFinding(ctx, findingId) : null;
    if (!finding) return json(res, 404, { error: 'not_found' });
    const result = await actionItemsSvc.createActionItemFromFinding(ctx, finding, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, result.created ? 201 : 200, result);
  }
  const actionItemMatch = path.match(/^\/v1\/waf\/action-items\/([^/]+)$/);
  if (actionItemMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await actionItemsSvc.patchActionItemStatus(ctx, actionItemMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const actionItemDeliverMatch = path.match(/^\/v1\/waf\/action-items\/([^/]+)\/deliver$/);
  if (actionItemDeliverMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const channel = body.channel ?? body.connector;
    const dryRun = body.dry_run !== false && body.dryRun !== false;
    const result = await actionItemsSvc.deliverActionItem(
      ctx,
      actionItemDeliverMatch[1],
      channel,
      { dry_run: dryRun, body },
    );
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/v1/production-release-evidence') {
    const gate = requirePermission(ctx, 'release_evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, {
      items: await serviceDeps.productionReleaseEvidence.listProductionReleaseEvidence(ctx),
    });
  }
  if (method === 'POST' && path === '/v1/production-release-evidence') {
    const gate = requirePermission(ctx, 'release_evidence:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.productionReleaseEvidence.recordProductionReleaseEvidence(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { evidence: result });
  }
  if (method === 'GET' && path === '/v1/production-release-evidence/attestation') {
    const gate = requirePermission(ctx, 'release_evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const releaseId = url.searchParams.get('release_id') ?? undefined;
    const payload = await serviceDeps.productionReleaseEvidence.getProductionReleaseEvidenceAttestation(ctx, {
      releaseId,
    });
    return json(res, 200, payload);
  }
  const releaseEvidenceMatch = path.match(/^\/v1\/production-release-evidence\/([^/]+)$/);
  if (releaseEvidenceMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'release_evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const item = await serviceDeps.productionReleaseEvidence.getProductionReleaseEvidence(
      ctx,
      releaseEvidenceMatch[1],
    );
    if (!item) return json(res, 404, { error: 'not_found' });
    return json(res, 200, item);
  }

  if (method === 'GET' && path === '/v1/notifications') {
    const gate = requirePermission(ctx, 'notification:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const listFn = serviceDeps.notifications?.listNotifications ?? notifications.listNotifications;
    const payload = await listFn(ctx);
    return json(res, 200, payload);
  }
  if (method === 'POST' && path === '/v1/notifications') {
    const gate = requirePermission(ctx, 'notification:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const createFn =
      serviceDeps.notifications?.createNotificationRule ?? notifications.createNotificationRule;
    const result = await createFn(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, formatNotificationRuleForRead(result));
  }
  if (method === 'POST' && path === '/v1/notifications/retries/process') {
    const gate = requirePermission(ctx, 'notification:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const processFn =
      serviceDeps.notifications?.processDueNotificationRetries
      ?? notificationRetry.processDueNotificationRetries;
    const result = await processFn(ctx, {
      dryRun: body.dry_run === true,
      asOf: body.as_of,
      deliveryMode: 'metadata_only',
    });
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/notifications/dlq/redrive') {
    const gate = requirePermission(ctx, 'notification:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const redriveFn =
      serviceDeps.notifications?.redriveNotificationDlq
      ?? notificationDlqRedrive.redriveNotificationDlq;
    const result = await redriveFn(ctx, {
      attemptIds: Array.isArray(body.attempt_ids) ? body.attempt_ids.map(String) : undefined,
      ruleId: body.rule_id,
      dryRun: body.dry_run === true,
      forceMetadataOnly: true,
    });
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/notifications/provider-credentials') {
    const gate = requirePermission(ctx, 'notification:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (runtimeConfig.persistenceMode === 'postgres' && !serviceDeps.secretVault) {
      return respondPostgresRouteNotWired(res);
    }
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const upsertFn =
      serviceDeps.notificationProviderCredentials?.upsertNotificationProviderCredential
      ?? notificationProviderCredentials.upsertNotificationProviderCredential;
    const result = await upsertFn(
      ctx,
      body,
      runtimeConfig.secretEncryptionKey,
      { secretVault: serviceDeps.secretVault },
    );
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    return json(res, result.rotated ? 200 : 201, { provider_credential: result.provider_credential });
  }

  if (method === 'GET' && path === '/v1/state') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresStateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getStateFn =
      runtimeConfig.persistenceMode === 'postgres' ? serviceDeps.state.getState : state.getState;
    const payload = await getStateFn(ctx);
    return json(res, 200, payload);
  }

  if (method === 'GET' && path === '/v1/placement/reviews') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPlacementRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const listReviewsFn =
      runtimeConfig.persistenceMode === 'postgres'
        ? serviceDeps.placement.listPlacementReviews
        : placement.listPlacementReviews;
    const targetGroupId = url.searchParams.get('target_group_id');
    const result = await Promise.resolve(
      listReviewsFn(ctx, { target_group_id: targetGroupId }),
    );
    if (result?.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }

  if (path === '/v1/targets' && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const targetService = serviceDeps.targetGroups;
    let envelope;
    if (typeof targetService?.listTargetsEnvelope === 'function') {
      envelope = await targetService.listTargetsEnvelope(ctx);
    } else if (typeof targetService?.listTargets === 'function') {
      const items = await targetService.listTargets(ctx);
      envelope = {
        items,
        count: items.length,
        meta: {
          empty_reason: items.length
            ? null
            : 'No targets have been declared for this tenant yet.',
        },
      };
    } else if (runtimeConfig.persistenceMode === 'postgres') {
      return respondPostgresRouteNotWired(res);
    } else {
      envelope = targetGroups.listTargetsEnvelope(ctx);
    }
    return json(res, 200, envelope);
  }

  if (path === '/v1/target-groups' && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const archived = url.searchParams.get('archived') === 'true';
    const tgSvc = serviceDeps.targetGroups;
    let envelope;
    if (tgSvc.listTargetGroupsEnvelope) {
      envelope = await tgSvc.listTargetGroupsEnvelope(ctx, { archived });
    } else if (tgSvc.listTargetGroups) {
      const items = await tgSvc.listTargetGroups(ctx, { archived });
      envelope = {
        items,
        count: items.length,
        meta: {
          empty_reason: items.length
            ? null
            : archived
              ? 'No archived target groups match this tenant.'
              : 'No target groups have been declared for this tenant yet.',
        },
      };
    } else {
      envelope = await targetGroups.listTargetGroupsEnvelope(ctx, { archived });
    }
    return json(res, 200, envelope);
  }
  if (path === '/v1/target-groups' && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const created = await serviceDeps.targetGroups.createTargetGroup(ctx, body);
    if (created && created.error) return json(res, created.status ?? 400, created);
    return json(res, 201, created);
  }
  const tgMatch = path.match(/^\/v1\/target-groups\/([^/]+)$/);
  if (tgMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const g = await serviceDeps.targetGroups.getTargetGroup(ctx, tgMatch[1]);
    if (!g) return json(res, 404, { error: 'not_found' });
    return json(res, 200, g);
  }
  if (tgMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const g = await serviceDeps.targetGroups.patchTargetGroup(ctx, tgMatch[1], body);
    if (!g) return json(res, 404, { error: 'not_found' });
    if (g.error) return json(res, g.status ?? 400, g);
    return json(res, 200, g);
  }
  if (tgMatch && method === 'DELETE') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.targetGroups.archiveTargetGroup(ctx, tgMatch[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const tgRestoreMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/restore$/);
  if (tgRestoreMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const restoreFn = serviceDeps.targetGroups.restoreArchived ?? targetGroups.restoreArchived;
    const result = await restoreFn(ctx, tgRestoreMatch[1]);
    if (result.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }
  const tgLoaMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/loa$/);
  if (tgLoaMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getActiveFn = serviceDeps.loa?.getActive ?? loa.getActive;
    return json(res, 200, await getActiveFn(ctx, tgLoaMatch[1]));
  }
  if (tgLoaMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const signFn = serviceDeps.loa?.sign ?? loa.sign;
    const result = await signFn(ctx, tgLoaMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const tgLoaRevokeMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/loa\/([^/]+)\/revoke$/);
  if (tgLoaRevokeMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const revokeFn = serviceDeps.loa?.revoke ?? loa.revoke;
    const result = await revokeFn(ctx, tgLoaRevokeMatch[2], body.reason);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const tgLadderMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/verification-ladder$/);
  if (tgLadderMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getLadderFn = serviceDeps.ownershipVerification?.getLadder
      ?? ownershipVerification.getLadder;
    const ladder = await getLadderFn(ctx, tgLadderMatch[1]);
    if (ladder.error) return json(res, ladder.status ?? 404, ladder);
    return json(res, 200, ladder);
  }
  const tgBulkImportMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/targets:bulk-import$/);
  if (tgBulkImportMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const bulkImportFn = serviceDeps.targetGroups.bulkImportTargets ?? targetGroups.bulkImportTargets;
    const result = await bulkImportFn(ctx, tgBulkImportMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const tgtMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/targets$/);
  if (tgtMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const t = await serviceDeps.targetGroups.addTarget(ctx, tgtMatch[1], body);
    if (!t) return json(res, 404, { error: 'not_found' });
    if (t.error) return json(res, t.status ?? 400, t);
    return json(res, 201, t);
  }
  const tgtConfirmMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/targets\/([^/]+):confirm$/);
  if (tgtConfirmMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const confirmFn = serviceDeps.ownershipVerification?.confirmTarget
      ?? ownershipVerification.confirmTarget;
    const result = await confirmFn(ctx, tgtConfirmMatch[1], tgtConfirmMatch[2], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const tgtIdMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/targets\/([^/]+)$/);
  if (tgtIdMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const t = await serviceDeps.targetGroups.patchTarget(ctx, tgtIdMatch[1], tgtIdMatch[2], body);
    if (!t) return json(res, 404, { error: 'not_found' });
    if (t.error) return json(res, t.status ?? 400, t);
    return json(res, 200, t);
  }
  if (tgtIdMatch && method === 'DELETE') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.targetGroups.deleteTarget(ctx, tgtIdMatch[1], tgtIdMatch[2]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  const dnsOwnershipVerifyMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/dns-ownership\/verify$/);
  const dnsOwnershipIssuePathMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/dns-ownership\/issue$/);
  const dnsOwnershipListMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/dns-ownership$/);
  const dnsOwnershipLegacyIssueMatch =
    dnsOwnershipListMatch && method === 'POST' ? dnsOwnershipListMatch : null;
  if (
    dnsOwnershipVerifyMatch
    || dnsOwnershipIssuePathMatch
    || dnsOwnershipListMatch
    || dnsOwnershipLegacyIssueMatch
  ) {
    if (!serviceDeps.dnsOwnership) {
      return respondPostgresRouteNotWired(res);
    }
    if (dnsOwnershipVerifyMatch && method === 'POST') {
      const gate = requirePermission(ctx, 'target_group:write');
      if (!gate.ok) return json(res, gate.status, gate.body);
      if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
      const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
      const result = await serviceDeps.dnsOwnership.verifyDnsOwnership(ctx, {
        target_group_id: dnsOwnershipVerifyMatch[1],
        challenge_id: body.challenge_id,
      });
      if (result.error) {
        if (result.status === 429) {
          if (result.retry_after_seconds) {
            res.setHeader('Retry-After', String(result.retry_after_seconds));
          }
          return json(res, 429, result);
        }
        return json(res, result.status ?? 400, result);
      }
      return json(res, 200, result);
    }
    const issueGroupId =
      dnsOwnershipIssuePathMatch?.[1]
      ?? dnsOwnershipLegacyIssueMatch?.[1]
      ?? null;
    if (issueGroupId && method === 'POST') {
      const gate = requirePermission(ctx, 'target_group:write');
      if (!gate.ok) return json(res, gate.status, gate.body);
      const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
      const result = await serviceDeps.dnsOwnership.issueDnsOwnershipChallenge(ctx, {
        target_group_id: issueGroupId,
        target_id: body.target_id,
      });
      if (result.error) return json(res, result.status ?? 400, result);
      if (result.challenge) return json(res, 201, result);
      return json(res, 201, { challenge: result, audit_entry_id: result.audit_entry_id });
    }
    if (dnsOwnershipListMatch && method === 'GET') {
      const gate = requirePermission(ctx, 'target_group:read');
      if (!gate.ok) return json(res, gate.status, gate.body);
      if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
      const listFn = serviceDeps.dnsOwnership.listChallenges ?? dnsOwnership.listChallenges;
      return json(res, 200, await listFn(ctx, dnsOwnershipListMatch[1]));
    }
  }

  const targetDetailMatch = path.match(/^\/v1\/targets\/([^/]+)$/);
  if (targetDetailMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getDetailFn = serviceDeps.targetDetail?.getTargetDetail ?? targetDetail.getTargetDetail;
    const payload = await getDetailFn(ctx, targetDetailMatch[1], {
      runs_limit: url.searchParams.get('runs_limit') ?? undefined,
      findings_limit: url.searchParams.get('findings_limit') ?? undefined,
      findings_cursor: url.searchParams.get('findings_cursor') ?? undefined,
    });
    if (payload?.error) return json(res, payload.status ?? 404, payload);
    return json(res, 200, payload);
  }

  const ownershipConfirmMatch = path.match(/^\/v1\/ownership-verifications\/([^/]+)\/confirm$/);
  const ownershipIdMatch = path.match(/^\/v1\/ownership-verifications\/([^/]+)$/);
  const isOwnershipPath =
    path === '/v1/ownership-verifications'
    || path === '/v1/ownership-verifications/verify-setup'
    || ownershipConfirmMatch
    || ownershipIdMatch;
  if (isOwnershipPath) {
    if (!serviceDeps.ownershipVerification) {
      return respondPostgresRouteNotWired(res);
    }
    if (path === '/v1/ownership-verifications/verify-setup' && method === 'POST') {
      const gate = requirePermission(ctx, 'target_group:read');
      if (!gate.ok) return json(res, gate.status, gate.body);
      const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
      const result = await serviceDeps.ownershipVerification.verifyOwnershipSetup(
        ctx,
        body,
        runtimeConfig,
      );
      if (result.ready === false && result.error) {
        return json(res, result.status ?? 400, result);
      }
      return json(res, 200, result);
    }
    if (path === '/v1/ownership-verifications' && method === 'POST') {
      const gate = requirePermission(ctx, 'target_group:write');
      if (!gate.ok) return json(res, gate.status, gate.body);
      const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
      const result = await serviceDeps.ownershipVerification.createOwnershipChallenge(
        ctx,
        body,
        runtimeConfig,
      );
      if (result.error) return json(res, result.status ?? 400, result);
      return json(res, 201, result);
    }
    if (path === '/v1/ownership-verifications' && method === 'GET') {
      const gate = requirePermission(ctx, 'target_group:read');
      if (!gate.ok) return json(res, gate.status, gate.body);
      return json(res, 200, {
        items: await serviceDeps.ownershipVerification.listOwnershipVerifications(ctx),
      });
    }
    if (ownershipConfirmMatch && method === 'POST') {
      const gate = requirePermission(ctx, 'target_group:write');
      if (!gate.ok) return json(res, gate.status, gate.body);
      const result = await serviceDeps.ownershipVerification.confirmOwnership(
        ctx,
        ownershipConfirmMatch[1],
      );
      if (result.error) return json(res, result.status ?? 400, result);
      return json(res, 200, result);
    }
    if (ownershipIdMatch && method === 'GET' && ownershipIdMatch[1] !== 'verify-setup') {
      const gate = requirePermission(ctx, 'target_group:read');
      if (!gate.ok) return json(res, gate.status, gate.body);
      const record = await serviceDeps.ownershipVerification.getOwnershipVerification(
        ctx,
        ownershipIdMatch[1],
      );
      if (!record) return json(res, 404, { error: 'not_found' });
      return json(res, 200, record);
    }
  }

  if (path === '/v1/bootstrap-tokens' && method === 'POST') {
    const gate = requirePermission(ctx, 'bootstrap_token:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const { token, secret } = await serviceDeps.tokens.createBootstrapToken(ctx, body);
    const { token_hash, token_salt, ...meta } = token;
    return json(res, 201, { ...meta, secret });
  }
  if (path === '/v1/bootstrap-tokens' && method === 'GET') {
    const gate = requirePermission(ctx, 'bootstrap_token:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.tokens.listBootstrapTokens(ctx) });
  }
  const revokeTok = path.match(/^\/v1\/bootstrap-tokens\/([^/]+)\/revoke$/);
  if (revokeTok && method === 'POST') {
    const gate = requirePermission(ctx, 'bootstrap_token:revoke');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const t = await serviceDeps.tokens.revokeBootstrapToken(ctx, revokeTok[1]);
    if (!t) return json(res, 404, { error: 'not_found' });
    return json(res, 200, t);
  }

  if (path === '/v1/service-accounts' && method === 'POST') {
    const gate = requirePermission(ctx, 'service_account:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.serviceAccounts.createServiceAccount(ctx, body);
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    const { account, secret } = result;
    const { secret_salt, secret_hash, ...meta } = account;
    return json(res, 201, { ...meta, secret });
  }
  if (path === '/v1/service-accounts' && method === 'GET') {
    const gate = requirePermission(ctx, 'service_account:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.serviceAccounts.listServiceAccounts(ctx) });
  }
  const revokeSvc = path.match(/^\/v1\/service-accounts\/([^/]+)\/revoke$/);
  if (revokeSvc && method === 'POST') {
    const gate = requirePermission(ctx, 'service_account:revoke');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const acct = await serviceDeps.serviceAccounts.revokeServiceAccount(ctx, revokeSvc[1]);
    if (!acct) return json(res, 404, { error: 'not_found' });
    return json(res, 200, acct);
  }
  const rotateSvc = path.match(/^\/v1\/service-accounts\/([^/]+)\/rotate$/);
  if (rotateSvc && method === 'POST') {
    const gate = requirePermission(ctx, 'service_account:rotate');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.serviceAccounts.rotateServiceAccount(ctx, rotateSvc[1]);
    if (result === null) return json(res, 404, { error: 'not_found' });
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    const { account, secret } = result;
    const { secret_salt, secret_hash, ...meta } = account;
    return json(res, 200, { ...meta, secret });
  }

  if (
    method === 'POST'
    && (
      path === '/v1/auth/mfa/enroll'
      || path === '/v1/auth/mfa/verify'
      || path === '/v1/auth/mfa/disable'
    )
  ) {
    const gate = requirePermission(ctx, 'profile:mfa');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const passwordAuthService = serviceDeps.passwordAuth;
    const methodName = path === '/v1/auth/mfa/enroll'
      ? 'beginMfaEnrollment'
      : path === '/v1/auth/mfa/verify'
        ? 'confirmMfaEnrollment'
        : 'disableMfa';
    if (typeof passwordAuthService?.[methodName] !== 'function') {
      return json(res, 503, {
        error: 'mfa_unavailable',
        message: 'Multi-factor authentication is not available on this deployment.',
      });
    }
    const body = path === '/v1/auth/mfa/enroll'
      ? {}
      : await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await passwordAuthService[methodName]({
      tenantId: ctx.tenantId,
      userId: ctx.userId,
      actorRole: ctx.role,
      code: body?.totp ?? body?.code,
    }, { runtimeConfig });
    if (result.error) {
      return json(res, result.status ?? 400, {
        error: result.error,
        message: result.message,
        fields: result.fields,
      });
    }
    return json(res, 200, result);
  }

  if (path === '/v1/secrets' && method === 'POST') {
    const gate = requirePermission(ctx, 'secret:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.secretVault.storeEncryptedSecret(
      ctx,
      body,
      runtimeConfig.secretEncryptionKey,
    );
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    return json(res, 201, result);
  }
  if (path === '/v1/secrets' && method === 'GET') {
    const gate = requirePermission(ctx, 'secret:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, { items: await serviceDeps.secretVault.listEncryptedSecrets(ctx) });
  }
  const rotateSecret = path.match(/^\/v1\/secrets\/([^/]+)\/rotate$/);
  if (rotateSecret && method === 'POST') {
    const gate = requirePermission(ctx, 'secret:rotate');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.secretVault.rotateEncryptedSecret(
      ctx,
      rotateSecret[1],
      body,
      runtimeConfig.secretEncryptionKey,
    );
    if (result === null) return json(res, 404, { error: 'not_found' });
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    return json(res, 200, result);
  }

  if (path === '/v1/agents/register' && method === 'POST') {
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const tenantId =
      runtimeConfig.authMode === 'dev-headers' ? ctx.tenantId : null;
    const result = await serviceDeps.agents.registerAgent(body, tenantId);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }
  if (path === '/v1/agents' && method === 'GET') {
    const gate = requirePermission(ctx, 'agent:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.agents.listAgents(ctx) });
  }
  const agentRevokeMatch = path.match(/^\/v1\/agents\/([^/]+)\/revoke$/);
  if (agentRevokeMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'agent:revoke');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.agents.revokeAgent(ctx, agentRevokeMatch[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    return json(res, 200, result);
  }
  const hbMatch = path.match(/^\/v1\/agents\/([^/]+)\/heartbeat$/);
  if (hbMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, hbMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.agents.heartbeatAgent(auth.agent, body);
    return json(res, 200, result);
  }
  const jobsMatch = path.match(/^\/v1\/agents\/([^/]+)\/jobs$/);
  if (jobsMatch && method === 'GET') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, jobsMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const poll = await serviceDeps.agents.pollJobs(auth.agent, 3000);
    return json(res, 200, { jobs: poll.jobs });
  }
  const ackMatch = path.match(/^\/v1\/agents\/([^/]+)\/jobs\/([^/]+)\/ack$/);
  if (ackMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, ackMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const job = await serviceDeps.agents.ackJob(auth.agent, ackMatch[2]);
    if (!job) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { job });
  }
  const obsMatch = path.match(/^\/v1\/agents\/([^/]+)\/observations$/);
  if (obsMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, obsMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const agentCtx = {
      ...ctx,
      tenantId: auth.agent.tenant_id,
      userId: 'agent',
      role: 'agent',
    };
    const result = await serviceDeps.testRuns.ingestObservation(agentCtx, auth.agent.id, body);
    if (result.error) return json(res, result.status, { error: result.error });
    return json(res, 201, result);
  }
  const agentUpdateSvc = resolveAgentUpdateService(runtimeConfig, serviceDeps);
  const agentUpdatePollMatch = path.match(/^\/v1\/agents\/([^/]+)\/update$/);
  if (agentUpdatePollMatch && method === 'GET') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, agentUpdatePollMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, await agentUpdateSvc.pollAgentUpdate(auth.agent));
  }
  const agentUpdateStatusMatch = path.match(/^\/v1\/agents\/([^/]+)\/update-status$/);
  if (agentUpdateStatusMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, agentUpdateStatusMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await agentUpdateSvc.recordAgentUpdateStatus(auth.agent, body);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }

  if (path === '/v1/agent-update-trust-keys' && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await agentUpdateSvc.createAgentUpdateTrustKey(ctx, body);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }
  if (path === '/v1/agent-update-trust-keys' && method === 'GET') {
    const gate = requirePermission(ctx, 'agent_update:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, { items: await agentUpdateSvc.listAgentUpdateTrustKeys(ctx) });
  }
  const agentUpdateTrustKeyRevokeMatch = path.match(/^\/v1\/agent-update-trust-keys\/([^/]+)\/revoke$/);
  if (agentUpdateTrustKeyRevokeMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await agentUpdateSvc.revokeAgentUpdateTrustKey(ctx, agentUpdateTrustKeyRevokeMatch[1]);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 200, result);
  }

  if (path === '/v1/agent-updates' && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await agentUpdateSvc.createAgentUpdateRelease(ctx, body);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }
  if (path === '/v1/agent-updates' && method === 'GET') {
    const gate = requirePermission(ctx, 'agent_update:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, { items: await agentUpdateSvc.listAgentUpdateReleases(ctx) });
  }
  const agentUpdateRollbackMatch = path.match(/^\/v1\/agent-updates\/([^/]+)\/rollback$/);
  if (agentUpdateRollbackMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:rollback');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await agentUpdateSvc.requestAgentUpdateRollback(ctx, agentUpdateRollbackMatch[1]);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 200, result);
  }

  if (path === '/v1/checks' && method === 'GET') {
    const gate = requirePermission(ctx, 'check:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.testRuns.listChecks() });
  }
  if (path === '/v1/test-policies' && method === 'GET') {
    const gate = requirePermission(ctx, 'test_policy:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockTestPolicyRoute(serviceDeps, method, res)) return;
    return json(res, 200, { items: await serviceDeps.testPolicies.listTestPolicies(ctx) });
  }
  if (path === '/v1/test-policies' && method === 'POST') {
    const gate = requirePermission(ctx, 'test_policy:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockTestPolicyRoute(serviceDeps, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.testPolicies.createTestPolicy(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const policyMatch = path.match(/^\/v1\/test-policies\/([^/]+)$/);
  if (policyMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'test_policy:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockTestPolicyRoute(serviceDeps, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.testPolicies.patchTestPolicy(ctx, policyMatch[1], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (policyMatch && method === 'DELETE') {
    const gate = requirePermission(ctx, 'test_policy:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockTestPolicyRoute(serviceDeps, method, res)) return;
    const result = await serviceDeps.testPolicies.archiveTestPolicy(ctx, policyMatch[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (path === '/v1/test-runs' && method === 'POST') {
    const gate = requirePermission(ctx, 'test_run:start');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.testRuns.startTestRun(ctx, body, runtimeConfig);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (path === '/v1/test-runs' && method === 'GET') {
    const gate = requirePermission(ctx, 'test_run:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const listOpts = {
      target_group_id: url.searchParams.get('target_group_id') ?? undefined,
      target_id: url.searchParams.get('target_id') ?? undefined,
      limit: url.searchParams.get('limit') ?? undefined,
    };
    if (typeof serviceDeps.testRuns.listTestRunsEnvelope === 'function') {
      return json(res, 200, await serviceDeps.testRuns.listTestRunsEnvelope(ctx, listOpts));
    }
    return json(res, 200, {
      items: await serviceDeps.testRuns.listTestRuns(ctx, listOpts),
      count: (await serviceDeps.testRuns.listTestRuns(ctx, listOpts)).length,
      meta: {},
    });
  }
  const runMatch = path.match(/^\/v1\/test-runs\/([^/]+)$/);
  if (runMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'test_run:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const run = await serviceDeps.testRuns.getTestRun(ctx, runMatch[1]);
    if (!run) return json(res, 404, { error: 'not_found' });
    return json(res, 200, run);
  }
  const runEvents = path.match(/^\/v1\/test-runs\/([^/]+)\/events$/);
  if (runEvents && method === 'GET') {
    const gate = requirePermission(ctx, 'test_run:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const events = await serviceDeps.testRuns.getRunEvents(ctx, runEvents[1]);
    if (events === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items: events });
  }
  const runFinalize = path.match(/^\/v1\/test-runs\/([^/]+)\/finalize$/);
  if (runFinalize && method === 'POST') {
    // Finalize mutates run state — require start/write ACL, not read-only roles.
    const gate = requirePermission(ctx, 'test_run:start');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.testRuns.finalizeTestRun(ctx, runFinalize[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, { error: result.error });
    return json(res, 200, result);
  }
  const runCancel = path.match(/^\/v1\/test-runs\/([^/]+)\/cancel$/);
  if (runCancel && method === 'POST') {
    const gate = requirePermission(ctx, 'test_run:start');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.testRuns.cancelTestRun(ctx, runCancel[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, { error: result.error });
    return json(res, 200, result.run);
  }

  if (path === '/v1/findings' && method === 'GET') {
    const gate = requirePermission(ctx, 'finding:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const listOpts = {
      target_group_id: url.searchParams.get('target_group_id') ?? undefined,
      target_id: url.searchParams.get('target_id') ?? undefined,
      test_run_id: url.searchParams.get('test_run_id') ?? undefined,
      limit: url.searchParams.get('limit') ?? undefined,
    };
    if (typeof serviceDeps.findings.listFindingsEnvelope === 'function') {
      return json(res, 200, await serviceDeps.findings.listFindingsEnvelope(ctx, listOpts));
    }
    const items = await serviceDeps.findings.listFindings(ctx, listOpts);
    return json(res, 200, { items, count: items.length, meta: {} });
  }
  const findingEvidenceMatch = path.match(/^\/v1\/findings\/([^/]+)\/evidence$/);
  if (findingEvidenceMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getBundleFn = serviceDeps.findings.getEvidenceBundle ?? findings.getEvidenceBundle;
    return json(res, 200, await getBundleFn(ctx, findingEvidenceMatch[1]));
  }
  const fMatch = path.match(/^\/v1\/findings\/([^/]+)$/);
  if (fMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'finding:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const f = await serviceDeps.findings.getFinding(ctx, fMatch[1]);
    if (!f) return json(res, 404, { error: 'not_found' });
    return json(res, 200, f);
  }
  if (fMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'finding:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const f = await serviceDeps.findings.patchFinding(ctx, fMatch[1], body);
    if (!f) return json(res, 404, { error: 'not_found' });
    return json(res, 200, f);
  }

  if (path === '/v1/reports' && method === 'POST') {
    const gate = requirePermission(ctx, 'report:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    // `period` is optional, but an unknown window must never be silently dropped or stored.
    const periodInput = body?.period;
    if (periodInput != null && String(periodInput).trim() !== '' && normalizeReportPeriod(periodInput) == null) {
      return json(res, 400, {
        error: 'unsupported_period',
        supported_periods: [...REPORT_PERIODS],
      });
    }
    return json(res, 201, await serviceDeps.reports.createReport(ctx, body));
  }
  if (path === '/v1/reports' && method === 'GET') {
    const gate = requirePermission(ctx, 'report:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, {
      items: await serviceDeps.reports.listReports(ctx, {
        limit: Number(url.searchParams.get('limit') ?? 100),
      }),
      // Report builders read their kind/format options from here, never from a client copy.
      capabilities: reportCapabilities(),
    });
  }
  const rptMatch = path.match(/^\/v1\/reports\/([^/]+)$/);
  if (rptMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'report:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const r = await serviceDeps.reports.getReport(ctx, rptMatch[1]);
    if (!r) return json(res, 404, { error: 'not_found' });
    return json(res, 200, r);
  }
  const rptExport = path.match(/^\/v1\/reports\/([^/]+)\/export$/);
  if (rptExport && method === 'GET') {
    const gate = requirePermission(ctx, 'report:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const format = url.searchParams.get('format') || 'json';
    if (!REPORT_EXPORT_FORMATS.includes(format)) {
      return json(res, 400, {
        error: 'unsupported_format',
        supported_formats: [...REPORT_EXPORT_FORMATS],
      });
    }
    const out = await serviceDeps.reports.exportReport(ctx, rptExport[1], format);
    if (!out) return json(res, 404, { error: 'not_found' });
    if (format === 'markdown') {
      text(res, 200, out.content, 'text/markdown; charset=utf-8');
      return;
    }
    if (format === 'html') {
      text(res, 200, out.content, 'text/html; charset=utf-8');
      return;
    }
    return json(res, 200, out);
  }
  const findingExport = path.match(/^\/v1\/findings\/([^/]+)\/export$/);
  if (findingExport && method === 'POST') {
    const gate = requirePermission(ctx, 'finding:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const out = await serviceDeps.reports.exportFinding(ctx, findingExport[1]);
    if (!out) return json(res, 404, { error: 'not_found' });
    return json(res, 200, out);
  }

  if (path === '/v1/custody/verify' && method === 'POST') {
    // Engineers who can export findings need to verify custody; align with evidence:read.
    const gate = requirePermission(ctx, 'evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.custodyVerification.verifyCustodyExport(ctx, body);
    return json(res, 200, result);
  }

  if (path === '/v1/audit-log' && method === 'GET') {
    const gate = requirePermission(ctx, 'audit:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAuditLogRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    if (runtimeConfig.persistenceMode === 'postgres') {
      const items = await serviceDeps.audit.listAuditEntries(ctx, { limit: 200 });
      return json(res, 200, { items });
    }
    const items = getStore().auditLog.filter((a) => a.tenant_id === ctx.tenantId).slice(-200);
    return json(res, 200, { items });
  }

  const hsSvc = resolveHighScaleService(runtimeConfig, serviceDeps);
  if (path === '/v1/high-scale-requests' && method === 'POST') {
    const gate = requirePermission(ctx, 'high_scale:request');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const created = await Promise.resolve(hsSvc.createHighScaleRequest(ctx, body));
    if (created?.error) return json(res, created.status ?? 400, created);
    return json(res, 201, created);
  }
  if (path === '/v1/high-scale-requests' && method === 'GET') {
    const gate = requirePermission(ctx, 'high_scale:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const scope = url.searchParams.get('scope') ?? undefined;
    const items = await Promise.resolve(hsSvc.listHighScaleRequests(ctx, { scope }));
    return json(res, 200, { items, count: items.length });
  }
  const hsArtPost = path.match(/^\/v1\/high-scale-requests\/([^/]+)\/artifacts$/);
  if (hsArtPost && method === 'POST') {
    const gate = requirePermission(ctx, 'high_scale:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    let upload;
    try {
      upload = await readArtifactUploadBody(req, runtimeConfig.maxJsonBodyBytes);
    } catch (err) {
      if (err instanceof HttpBodyError) return respondBodyError(res, err);
      throw err;
    }
    const art = await Promise.resolve(
      hsSvc.addArtifact(ctx, hsArtPost[1], upload.body, { uploadEnvelope: upload.envelope }),
    );
    if (!art) return json(res, 404, { error: 'not_found' });
    if (art.error) return json(res, art.status ?? 400, art);
    return json(res, 201, art);
  }
  if (hsArtPost && method === 'GET') {
    const gate = requirePermission(ctx, 'high_scale:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const items = await Promise.resolve(hsSvc.listArtifacts(ctx, hsArtPost[1]));
    if (items === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items });
  }
  const hsArtReview = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/artifacts\/([^/]+)\/review$/);
  if (hsArtReview && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await Promise.resolve(hsSvc.reviewArtifact(ctx, hsArtReview[1], hsArtReview[2], body));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status, result);
    return json(res, 200, result);
  }
  const hsNotes = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/notes$/);
  if (hsNotes && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const note = await Promise.resolve(hsSvc.addSocNote(ctx, hsNotes[1], body));
    if (!note) return json(res, 404, { error: 'not_found' });
    return json(res, 201, note);
  }
  if (hsNotes && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const items = await Promise.resolve(hsSvc.listSocNotes(ctx, hsNotes[1]));
    if (items === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items });
  }
  const hsAdapter = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/adapter-status$/);
  if (hsAdapter && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const status =
      runtimeConfig.persistenceMode === 'postgres'
        ? await hsSvc.getAdapterStatus(ctx, hsAdapter[1])
        : adapterStub.status(ctx, hsAdapter[1]);
    if (!status) return json(res, 404, { error: 'not_found' });
    return json(res, 200, status);
  }
  const hsTelemetryIngest = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/telemetry\/ingest$/);
  if (hsTelemetryIngest && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await Promise.resolve(
      hsSvc.ingestGovernedAdapterTelemetry(ctx, hsTelemetryIngest[1], body),
    );
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const hsTelemetry = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/telemetry$/);
  if (hsTelemetry && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await Promise.resolve(hsSvc.recordHighScaleTelemetry(ctx, hsTelemetry[1], body));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (hsTelemetry && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const items = await Promise.resolve(hsSvc.listHighScaleTelemetry(ctx, hsTelemetry[1]));
    if (items === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items });
  }
  const hsPostTestReport = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/post-test-report$/);
  if (hsPostTestReport && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await Promise.resolve(hsSvc.upsertPostTestReport(ctx, hsPostTestReport[1], body));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, result);
    return json(res, result.created ? 201 : 200, result.report);
  }
  if (hsPostTestReport && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await Promise.resolve(hsSvc.getPostTestReport(ctx, hsPostTestReport[1]));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }

  const socStart = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/start$/);
  if (socStart && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale', { resource_type: 'high_scale', metadata: { action: 'start' } });
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await Promise.resolve(
      hsSvc.transitionHighScale(ctx, socStart[1], 'start', {
        adapter_mode: runtimeConfig.highScaleAdapterMode,
      }),
    );
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, result);
    return json(res, 200, result);
  }
  for (const action of ['approve', 'schedule', 'stop', 'close']) {
    const m = path.match(new RegExp(`^/internal/soc/high-scale/([^/]+)/${action}$`));
    if (m && method === 'POST') {
      const gate = requirePermission(ctx, 'soc:high_scale');
      if (!gate.ok) return json(res, gate.status, gate.body);
      if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
      const body = action === 'schedule' ? await readJsonBody(req, runtimeConfig.maxJsonBodyBytes) : {};
      const result = await Promise.resolve(hsSvc.transitionHighScale(ctx, m[1], action, body));
      if (!result) return json(res, 404, { error: 'not_found' });
      if (result.error) return json(res, result.status ?? 409, result);
      return json(res, 200, result);
    }
  }
  if (path === '/internal/soc/kill-switch' && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:kill_switch');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const ks = await Promise.resolve(hsSvc.setKillSwitch(ctx, Boolean(body.active), body.reason));
    return json(res, 200, ks);
  }

  const wofArtReview = path.match(/^\/internal\/soc\/waf-offensive\/([^/]+)\/artifacts\/([^/]+)\/review$/);
  if (wofArtReview && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:waf_offensive');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = wafOffensive.reviewArtifact(ctx, wofArtReview[1], wofArtReview[2], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const wofResults = path.match(/^\/internal\/soc\/waf-offensive\/([^/]+)\/results$/);
  if (wofResults && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:waf_offensive');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = wafOffensive.recordOffensiveSuiteResults(ctx, wofResults[1], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const wofPostTestReport = path.match(/^\/internal\/soc\/waf-offensive\/([^/]+)\/post-test-report$/);
  if (wofPostTestReport && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:waf_offensive');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = wafOffensive.upsertOffensivePostTestReport(ctx, wofPostTestReport[1], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, result);
    return json(res, result.created ? 201 : 200, result.report);
  }
  if (wofPostTestReport && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:waf_offensive');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
    const result = wafOffensive.getOffensivePostTestReport(ctx, wofPostTestReport[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }
  const wofSocStart = path.match(/^\/internal\/soc\/waf-offensive\/([^/]+)\/start$/);
  if (wofSocStart && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:waf_offensive');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
    const result = wafOffensive.transitionOffensiveRequest(ctx, wofSocStart[1], 'start');
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, result);
    return json(res, 200, result);
  }
  for (const action of ['approve', 'schedule', 'stop', 'close', 'reject']) {
    const m = path.match(new RegExp(`^/internal/soc/waf-offensive/([^/]+)/${action}$`));
    if (m && method === 'POST') {
      const gate = requirePermission(ctx, 'soc:waf_offensive');
      if (!gate.ok) return json(res, gate.status, gate.body);
      if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
      const body = action === 'schedule' || action === 'reject'
        ? await readJsonBody(req, runtimeConfig.maxJsonBodyBytes)
        : {};
      const result = wafOffensive.transitionOffensiveRequest(ctx, m[1], action, body);
      if (!result) return json(res, 404, { error: 'not_found' });
      if (result.error) return json(res, result.status ?? 409, result);
      return json(res, 200, result);
    }
  }

  const probeJobsSvc = resolveProbeJobsService(runtimeConfig, serviceDeps);
  if (path === '/internal/probe/jobs' && method === 'GET') {
    if (!ctx.workerId) return json(res, 401, { error: 'unauthorized' });
    if (blockPostgresProbeJobsRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const jobs = await probeJobsSvc.listPendingProbeJobsForWorker(ctx, runtimeConfig);
    return json(res, 200, { jobs });
  }
  const probeResultMatch = path.match(/^\/internal\/probe\/jobs\/([^/]+)\/result$/);
  if (probeResultMatch && method === 'POST') {
    if (!ctx.workerId) return json(res, 401, { error: 'unauthorized' });
    if (blockPostgresProbeJobsRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    let body;
    try {
      const raw = options.probeBodyText ?? '';
      body = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      return json(res, 400, { error: 'invalid_json' });
    }
    const result = await probeJobsSvc.ingestProbeResult(
      ctx,
      probeResultMatch[1],
      body,
      runtimeConfig,
    );
    if (result.error) return json(res, result.status ?? 400, result);
    const finalizeFn = serviceDeps.testRuns?.maybeFinalizeRunAfterProbeIngest;
    if (typeof finalizeFn === 'function') {
      if (result.tenant_id) {
        await finalizeFn(
          { tenantId: result.tenant_id, userId: 'probe_worker', role: 'probe_worker' },
          result.run_id,
        );
      } else {
        await finalizeFn(result.run_id);
      }
    }
    return json(res, 201, result);
  }

  json(res, 404, { error: 'not_found' });
}

async function handlePublicApi(req, res, url, runtimeConfig, options = {}) {
  const path = url.pathname;
  const method = req.method;
  incMetric('http_requests_total');
  const signupService = options.services?.signupIntake
    ?? options.services?.internalManagement
    ?? signupIntake;

  if (method === 'GET' && path === '/v1/public/site-config') {
    return json(res, 200, publicSite.getPublicSiteConfig(runtimeConfig));
  }

  if (
    method === 'POST'
    && (
      path === '/v1/auth/login'
      || path === '/v1/auth/set-password'
      || path === '/v1/auth/request-password-reset'
      || path === '/v1/auth/reset-password'
    )
  ) {
    if (runtimeConfig.passwordLoginEnabled !== true) {
      return json(res, 403, {
        error: 'password_login_disabled',
        message: 'Password login is not enabled on this deployment.',
      });
    }
    const passwordAuthService = options.services?.passwordAuth;
    const methodName = path === '/v1/auth/login'
      ? 'loginWithPassword'
      : path === '/v1/auth/set-password'
        ? 'setPasswordWithInvite'
        : path === '/v1/auth/request-password-reset'
          ? 'requestPasswordReset'
          : 'resetPasswordWithToken';
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    if (typeof passwordAuthService?.[methodName] !== 'function') {
      if (methodName === 'requestPasswordReset') {
        return json(res, 200, { status: 'reset_requested' });
      }
      return json(res, 503, {
        error: 'password_login_unavailable',
        message: 'Password authentication is not available on this deployment.',
      });
    }
    const result = await passwordAuthService[methodName](body, {
      runtimeConfig,
      clientKey: options.clientKey,
      ...(methodName === 'requestPasswordReset'
        ? { delivery: options.services?.passwordRecoveryDelivery }
        : {}),
    });
    if (methodName === 'requestPasswordReset') {
      // Defense in depth: a custom/injected service cannot accidentally reintroduce account or
      // delivery-state enumeration through this public response.
      return json(res, 200, { status: 'reset_requested' });
    }
    if (methodName === 'resetPasswordWithToken') {
      return respondPasswordResetResult(res, result);
    }
    return respondPasswordAuthResult(res, result);
  }

  if (method === 'POST' && path === '/v1/auth/bundled-staging-login') {
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = bundledStagingAuth.loginBundledStagingPrincipal(body, runtimeConfig);
    if (result.error) {
      return json(res, result.status ?? 400, {
        error: result.error,
        message: result.message,
        fields: result.fields,
      });
    }
    return json(res, 200, result);
  }

  if (method === 'POST' && path === '/v1/signup-requests') {
    if (runtimeConfig.publicSite?.signupEnabled === false) {
      return json(res, 403, { error: 'signup_disabled' });
    }
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await signupService.createSignupRequest(body, { clientKey: options.clientKey });
    if (result.error === 'validation_failed') {
      return json(res, 400, result);
    }
    if (result.error === 'rate_limited') {
      res.setHeader('Retry-After', String(result.retry_after_seconds ?? 60));
      return json(res, 429, { error: 'rate_limited' });
    }
    if (result.error === 'duplicate_request') {
      return json(res, 409, result);
    }
    return json(res, 201, result);
  }

  const signupGet = path.match(/^\/v1\/signup-requests\/([^/]+)$/);
  if (signupGet && method === 'GET') {
    const record = await signupService.getSignupRequest(signupGet[1]);
    if (!record) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { request: signupService.sanitizeSignupForPublic(record) });
  }

  const signupEventsMatch = path.match(/^\/v1\/signup-requests\/([^/]+)\/events$/);
  if (signupEventsMatch && method === 'GET') {
    const serviceDeps = options.services ?? {};
    if (blockPostgresPortalRevampRoute(runtimeConfig, serviceDeps, path, method, res)) {
      return;
    }
    const listEventsFn = signupService.listEvents ?? signupIntake.listEvents;
    const result = await listEventsFn(signupEventsMatch[1], {
      rateLimitKey: `signup-events:${signupEventsMatch[1]}`,
    });
    if (result?.error === 'rate_limited') {
      return json(res, result.status ?? 429, {
        error: result.error,
        retry_after_seconds: result.retry_after_seconds,
      });
    }
    return json(res, 200, result);
  }

  return json(res, 404, { error: 'not_found' });
}

async function handleInternalAdminApi(req, res, url, ctx, runtimeConfig, options = {}) {
  const path = url.pathname;
  const method = req.method;
  incMetric('http_requests_total');
  const managementService = options.services?.internalManagement ?? internalManagement;
  const signupService = options.services?.signupIntake
    ?? options.services?.internalManagement
    ?? signupIntake;

  if (runtimeConfig.persistenceMode === 'postgres' && !options.services?.internalManagement) {
    return json(res, 503, { error: 'postgres_internal_admin_not_wired' });
  }

  if (method === 'GET' && path === '/internal/admin/overview') {
    const gate = requireStaffPermission(ctx, 'staff:signup:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, await managementService.getInternalOverview());
  }

  if (method === 'GET' && path === '/internal/admin/signup-requests') {
    const gate = requireStaffPermission(ctx, 'staff:signup:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const state = url.searchParams.get('state') ?? undefined;
    return json(res, 200, { items: await managementService.listSignupRequests({ state }) });
  }

  const signupApprove = path.match(/^\/internal\/admin\/signup-requests\/([^/]+)\/approve$/);
  if (signupApprove && method === 'POST') {
    const gate = requireStaffPermission(ctx, 'staff:signup:decide', {
      resource_type: 'signup_request',
      resource_id: signupApprove[1],
    });
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await signupService.approveSignupRequest(ctx, signupApprove[1], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, 409, result);
    return json(res, 200, result);
  }

  const signupReject = path.match(/^\/internal\/admin\/signup-requests\/([^/]+)\/reject$/);
  if (signupReject && method === 'POST') {
    const gate = requireStaffPermission(ctx, 'staff:signup:decide', {
      resource_type: 'signup_request',
      resource_id: signupReject[1],
    });
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await signupService.rejectSignupRequest(ctx, signupReject[1], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, 409, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/internal/admin/tenants') {
    const gate = requireStaffPermission(ctx, 'staff:tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, {
      items: await managementService.listTenants({ q: url.searchParams.get('q') ?? undefined }),
    });
  }

  const tenantDetail = path.match(/^\/internal\/admin\/tenants\/([^/]+)$/);
  if (tenantDetail && method === 'GET') {
    const gate = requireStaffPermission(ctx, 'staff:tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const detail = await managementService.getTenantDetail(tenantDetail[1]);
    if (!detail) return json(res, 404, { error: 'not_found' });
    return json(res, 200, detail);
  }

  if (tenantDetail && method === 'PATCH') {
    const gate = requireStaffPermission(ctx, 'staff:tenant:write', {
      resource_type: 'tenant',
      resource_id: tenantDetail[1],
    });
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const detail = await managementService.patchTenant(ctx, tenantDetail[1], body);
    if (!detail) return json(res, 404, { error: 'not_found' });
    if (detail.error) return json(res, 400, detail);
    return json(res, 200, detail);
  }

  const tenantSubscription = path.match(/^\/internal\/admin\/tenants\/([^/]+)\/subscription$/);
  if (tenantSubscription && method === 'GET') {
    const gate = requireStaffPermission(ctx, 'staff:subscription:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const subscription = await managementService.getTenantSubscription(tenantSubscription[1]);
    if (!subscription) return json(res, 404, { error: 'not_found' });
    return json(res, 200, subscription);
  }

  if (tenantSubscription && method === 'PATCH') {
    const gate = requireStaffPermission(ctx, 'staff:subscription:write', {
      resource_type: 'tenant_subscription',
      resource_id: tenantSubscription[1],
    });
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const subscription = await managementService.patchTenantSubscription(
      ctx,
      tenantSubscription[1],
      body,
    );
    if (!subscription) return json(res, 404, { error: 'not_found' });
    if (subscription.error) return json(res, 400, subscription);
    return json(res, 200, subscription);
  }

  const tenantEntitlements = path.match(/^\/internal\/admin\/tenants\/([^/]+)\/entitlements$/);
  if (tenantEntitlements && method === 'POST') {
    const gate = requireStaffPermission(ctx, 'staff:entitlement:write', {
      resource_type: 'entitlement_grant',
      resource_id: tenantEntitlements[1],
    });
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const grant = await managementService.upsertEntitlementGrant(ctx, tenantEntitlements[1], body);
    if (grant.error) return json(res, 400, grant);
    return json(res, 200, grant);
  }

  const resendInvite = path.match(/^\/internal\/admin\/tenants\/([^/]+)\/users\/([^/]+)\/resend-invite$/);
  if (resendInvite && method === 'POST') {
    const gate = requireStaffPermission(ctx, 'staff:support:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await managementService.resendOwnerInvite(ctx, resendInvite[1], {
      ...body,
      user_id: resendInvite[2],
    });
    if (!result) return json(res, 404, { error: 'not_found' });
    return json(res, 200, result);
  }

  const disableUser = path.match(/^\/internal\/admin\/tenants\/([^/]+)\/users\/([^/]+)\/disable$/);
  if (disableUser && method === 'POST') {
    const gate = requireStaffPermission(ctx, 'staff:support:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await managementService.disableTenantUser(ctx, disableUser[1], disableUser[2], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/internal/admin/approval-requests') {
    const gate = requireStaffPermission(ctx, 'staff:approval:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, {
      items: await managementService.listApprovalRequests({
        state: url.searchParams.get('state') ?? undefined,
        kind: url.searchParams.get('kind') ?? undefined,
      }),
    });
  }

  const approvalDecision = path.match(/^\/internal\/admin\/approval-requests\/([^/]+)\/decision$/);
  if (approvalDecision && method === 'POST') {
    const gate = requireStaffPermission(ctx, 'staff:approval:decide', {
      resource_type: 'internal_approval_request',
      resource_id: approvalDecision[1],
    });
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await managementService.decideApprovalRequest(ctx, approvalDecision[1], body);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, 409, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/internal/admin/audit-log') {
    const gate = requireStaffPermission(ctx, 'staff:audit:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, {
      items: await managementService.listInternalAudit({
        tenant_id: url.searchParams.get('tenant_id') ?? undefined,
        staff_id: url.searchParams.get('staff_id') ?? undefined,
        action: url.searchParams.get('action') ?? undefined,
        limit: Number(url.searchParams.get('limit') ?? 100),
      }),
    });
  }

  if (method === 'GET' && path === '/internal/admin/break-glass/status') {
    const gate = requireStaffPermission(ctx, 'staff:audit:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, await breakGlass.breakGlassStatus(new Date(), {
      store: managementService,
    }));
  }

  if (method === 'POST' && path === '/internal/admin/break-glass/activate') {
    const gate = requireStaffPermission(ctx, 'staff:signup:decide');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    // `audit` is a required writer, not an optional hook: both the in-memory and Postgres
    // internal-management services implement appendInternalAudit, and activateBreakGlass
    // throws rather than activating unaudited if it is ever missing.
    const result = await breakGlass.activateBreakGlass(ctx, body, {
      store: managementService,
      audit: (event) => managementService.appendInternalAudit(ctx, event),
    });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  return json(res, 404, { error: 'not_found' });
}
