import { CORE_PORTAL_DATASETS, PORTAL_ROUTE_DATASETS } from './types';
import type { DataItem, PortalConfig, PortalData, PortalDataset, RouteId, Session, StatePayload } from './types';
import { asArray, DEPLOYMENT_MODE_GAP_MESSAGE } from './utils';
// Plain ESM so node:test can exercise the real shipped logic rather than a copy of it. These
// used to be defined here and re-implemented inside the test file, so the tests could not
// observe a regression in them.
import {
  AUTH_MODE_UNKNOWN,
  buildApiHeaders,
  buildSocCustomerHeaders,
  isAuthFailure,
  isExternalAuthUrl,
  isOidcJwtMode,
  isSessionExpired,
  isStaffSocRole,
  portalSurface,
  resolveAuthMode,
  resolveLoginDestination,
  resolveOidcLoginRedirect,
  sessionFromLoginResponse,
  STAFF_SOC_ROLES,
} from './portal-auth-policy.mjs';

// Re-exported so existing consumers keep importing these from './api'.
export {
  AUTH_MODE_UNKNOWN,
  buildApiHeaders,
  buildSocCustomerHeaders,
  isAuthFailure,
  isExternalAuthUrl,
  isOidcJwtMode,
  isSessionExpired,
  isStaffSocRole,
  portalSurface,
  resolveLoginDestination,
  resolveOidcLoginRedirect,
  sessionFromLoginResponse,
  STAFF_SOC_ROLES,
};

const SESSION_KEY = 'astranull.portal.session.v1';

export type PortalSessionGate = {
  config: PortalConfig;
  session: Session | null;
  redirectToLogin: boolean;
  loginUrl?: string;
  errorMessage?: string;
};

export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Session;
    if (!parsed || typeof parsed !== 'object') return null;
    if (parsed.expires_at && Date.now() > Number(parsed.expires_at)) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function saveSession(session: Session) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession() {
  sessionStorage.removeItem(SESSION_KEY);
  resetPortalDataCache();
}

export function sessionIdentity(session: Session | null | undefined) {
  if (!session) return '';
  return JSON.stringify({
    tenant_id: session.tenant_id ?? '',
    user_id: session.user_id ?? '',
    principal: session.principal ?? '',
    staff_id: session.staff_id ?? '',
    role: session.role ?? '',
    staff_role: session.staff_role ?? ''
  });
}

const CONFIG_FETCH_ATTEMPTS = 3;

/** True only in a Vite dev build. Optional-chained so non-Vite hosts (node tests) are safe. */
function isDevBuild() {
  return import.meta.env?.DEV === true;
}

function configBackoffMs(attempt: number) {
  return Math.min(2000, 250 * 2 ** attempt);
}

/**
 * Fetch a discovery endpoint, retrying transient rejections.
 *
 * 429 and 503 both clear on their own (rate-limit window expiry, readiness
 * drain finishing), so a single unlucky probe must not be allowed to decide how
 * the portal authenticates. The LAST response is returned even when it is still
 * 429/503, because `/ready` reports `auth_mode` in its 503 body.
 */
async function fetchDiscovery(path: string): Promise<Response | null> {
  let last: Response | null = null;
  for (let attempt = 0; attempt < CONFIG_FETCH_ATTEMPTS; attempt += 1) {
    try {
      last = await fetch(path, { headers: { accept: 'application/json' } });
    } catch {
      last = null;
    }
    if (last && last.status !== 429 && last.status !== 503) return last;
    if (attempt < CONFIG_FETCH_ATTEMPTS - 1) {
      await new Promise((resolve) => setTimeout(resolve, configBackoffMs(attempt)));
    }
  }
  return last;
}

async function readJsonSafe(response: Response | null): Promise<Record<string, unknown>> {
  if (!response) return {};
  const parsed = await response.json().catch(() => null);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  return parsed as Record<string, unknown>;
}

export async function fetchPortalConfig(): Promise<PortalConfig> {
  const [readyRes, siteRes] = await Promise.all([
    fetchDiscovery('/ready'),
    fetchDiscovery('/v1/public/site-config')
  ]);
  // /ready reports auth_mode in its 503 (not_ready / draining) body as well as
  // its 200 body, so a degraded control plane still yields the REAL mode.
  const ready = await readJsonSafe(readyRes);
  const siteConfig = siteRes?.ok ? await readJsonSafe(siteRes) : {};
  // Fails CLOSED to AUTH_MODE_UNKNOWN — never to dev-headers. See portal-auth-policy.mjs.
  const authMode = resolveAuthMode(ready, siteConfig);
  return {
    authMode,
    siteConfig,
    bundledLoginEnabled: siteConfig.bundled_staging_login_enabled === true,
    passwordLoginEnabled: siteConfig.password_login_enabled === true,
    loginUrl: String(siteConfig.login_url ?? '/login'),
    portalPath: String(siteConfig.customer_portal_path ?? '/app'),
    staffLoginPath: '/internal/admin/login'
  };
}

export async function ensurePortalSession(surface: 'customer' | 'staff' = 'customer'): Promise<PortalSessionGate> {
  const config = await fetchPortalConfig();
  const session = loadSession();

  // Neither discovery endpoint yielded a mode. Treat as unauthenticated and send
  // the operator to login; NEVER save a session, because we cannot know whether
  // this deployment authenticates at all.
  if (config.authMode === AUTH_MODE_UNKNOWN) {
    return {
      config,
      session: null,
      redirectToLogin: true,
      loginUrl: surface === 'staff' ? config.staffLoginPath : config.loginUrl,
      errorMessage:
        'Could not determine how this deployment authenticates. Sign in again, or retry once the service is reachable.'
    };
  }

  if (config.authMode === 'dev-headers') {
    // The bootstrap below mints an admin/internal_admin identity with no
    // authentication. It is a local convenience only and must never be reachable
    // in a production bundle, even if a server somehow reports dev-headers.
    if (!session && !isDevBuild()) {
      return {
        config,
        session: null,
        redirectToLogin: true,
        loginUrl: surface === 'staff' ? config.staffLoginPath : config.loginUrl,
        errorMessage: 'Sign in is required. This build does not bootstrap local dev identities.'
      };
    }
    if (!session) {
      const bootstrap = surface === 'staff'
        ? {
          mode: 'dev-headers',
          principal: 'staff',
          staff_id: 'staff_admin',
          staff_role: 'internal_admin'
        }
        : {
          mode: 'dev-headers',
          principal: 'customer',
          tenant_id: 'ten_demo',
          user_id: 'usr_admin',
          role: 'admin'
        };
      saveSession(bootstrap);
      return { config, session: bootstrap, redirectToLogin: false };
    }
    return { config, session, redirectToLogin: false };
  }

  const loginPath = surface === 'staff'
    ? (session?.staff_login_path ?? config.staffLoginPath)
    : config.loginUrl;
  const hasToken = Boolean(String(session?.access_token ?? '').trim());
  const principalOk = surface === 'staff'
    ? session?.principal === 'staff'
    : session?.principal !== 'staff';

  if (!hasToken || !principalOk) {
    const idpRedirect = resolveOidcLoginRedirect(config, surface);
    if (idpRedirect) {
      return { config, session: null, redirectToLogin: true, loginUrl: idpRedirect };
    }
    if (config.bundledLoginEnabled) {
      return { config, session: null, redirectToLogin: true, loginUrl: loginPath };
    }
    // The credential lane is served from the login page itself, so an anonymous
    // visitor is sent there rather than told sign-in is unconfigured.
    if (config.passwordLoginEnabled && surface !== 'staff') {
      return { config, session: null, redirectToLogin: true, loginUrl: loginPath };
    }
    return {
      config,
      session: null,
      redirectToLogin: true,
      loginUrl: loginPath,
      errorMessage: 'Sign in is required. Configure enterprise SSO or enable bundled staging login for this environment.'
    };
  }

  return { config, session, redirectToLogin: false };
}

/** Custom event the app listens for to run exactly one re-authentication. */
export const REAUTH_REQUIRED_EVENT = 'astranull:reauth-required';

/**
 * One-shot latch. Fifteen hydrate calls run in parallel, so an expired session
 * produces fifteen simultaneous 401s; without this, each would dispatch its own
 * redirect and the portal would thrash.
 */
let reauthDispatched = false;

/** Test/boot seam: re-arm the latch after a successful sign-in. */
export function resetReauthGuard() {
  reauthDispatched = false;
}

export function reauthAlreadyDispatched() {
  return reauthDispatched;
}

/**
 * Clear the dead credential and ask the app to re-authenticate exactly once.
 * Storage is purged on EVERY auth failure (so the stale bearer token stops being
 * sent immediately); only the redirect is latched.
 */
function handleAuthFailure(status: number, payload: unknown) {
  if (!isAuthFailure(status, payload)) return;
  clearSession();
  if (reauthDispatched) return;
  reauthDispatched = true;
  if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
    window.dispatchEvent(new CustomEvent(REAUTH_REQUIRED_EVENT, { detail: { status } }));
  }
}

/** 503 from a postgres route guard means "this build has no such service wired". */
function isDeploymentModeGap(status: number, payload: unknown) {
  if (status !== 503) return false;
  const code = payload && typeof payload === 'object'
    ? String((payload as { error?: unknown }).error ?? '').trim()
    : '';
  return code === 'postgres_route_not_wired';
}

function friendlyHttpError(path: string, status: number, payload: unknown): string {
  if (status === 429) {
    return 'Too many requests right now. Wait a moment and try again.';
  }
  if (status === 503) {
    if (isDeploymentModeGap(status, payload)) {
      return DEPLOYMENT_MODE_GAP_MESSAGE;
    }
    return 'Service is temporarily unavailable. Try again shortly.';
  }
  if (status === 404) {
    return 'That record was not found, or you do not have access to it.';
  }
  // A 5xx message is server-authored diagnostic text that may carry schema or
  // topology detail. Never render it; 5xx falls through to the fixed copy below.
  if (payload && typeof payload === 'object' && status < 500) {
    const msg = (payload as { message?: unknown }).message;
    if (typeof msg === 'string' && msg.trim()) return msg.trim();
    const err = (payload as { error?: unknown }).error;
    if (typeof err === 'string' && err.trim()) {
      if (err === 'rate_limited') return 'Too many requests right now. Wait a moment and try again.';
      if (err === 'not_found') return 'That record was not found, or you do not have access to it.';
      // snake_case API codes → readable words
      if (/^[a-z][a-z0-9_]+$/.test(err)) return err.replace(/_/g, ' ');
      return err.trim();
    }
  }
  if (status >= 500) return 'Something went wrong on the server. Try again.';
  return `Request failed (${status}).`;
}

const RATE_LIMIT_FALLBACK_BACKOFF_MS = 2000;
const RATE_LIMIT_MAX_BACKOFF_MS = 10000;

function retryAfterMs(response: Response) {
  const value = response.headers.get('retry-after')?.trim();
  if (!value) return RATE_LIMIT_FALLBACK_BACKOFF_MS;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(RATE_LIMIT_MAX_BACKOFF_MS, seconds * 1000);
  }
  const retryAt = Date.parse(value);
  if (Number.isFinite(retryAt)) {
    return Math.min(RATE_LIMIT_MAX_BACKOFF_MS, Math.max(0, retryAt - Date.now()));
  }
  return RATE_LIMIT_FALLBACK_BACKOFF_MS;
}

async function fetchWithRateLimitRetry(path: string, init: RequestInit) {
  let response = await fetch(path, init);
  if (response.status !== 429) return response;
  await new Promise((resolve) => setTimeout(resolve, retryAfterMs(response)));
  response = await fetch(path, init);
  return response;
}

async function getJson(path: string, headers: Record<string, string>) {
  const response = await fetchWithRateLimitRetry(path, { headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    handleAuthFailure(response.status, payload);
    const error = new Error(friendlyHttpError(path, response.status, payload)) as Error & {
      status?: number;
      payload?: unknown;
    };
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return response.json();
}

async function requestWithHeaders(
  path: string,
  headers: Record<string, string>,
  options: { method?: string; body?: unknown } = {}
) {
  const response = await fetchWithRateLimitRetry(path, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    handleAuthFailure(response.status, payload);
    const error = new Error(friendlyHttpError(path, response.status, payload)) as Error & {
      status?: number;
      payload?: unknown;
    };
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

export async function requestJson(
  config: PortalConfig,
  session: Session,
  path: string,
  options: { method?: string; body?: unknown } = {}
) {
  return requestWithHeaders(path, buildApiHeaders(config, session), options);
}

export async function requestSocJson(
  config: PortalConfig,
  session: Session,
  path: string,
  options: { method?: string; body?: unknown; tenantId?: string } = {}
) {
  return requestWithHeaders(path, buildSocCustomerHeaders(config, session, options.tenantId), options);
}

/**
 * A hydrated dataset plus why it is empty, if it is.
 *
 * The value alone cannot distinguish "no findings" from "failed to load
 * findings" — both are `[]` — which is exactly the ambiguity an operator must
 * not be shown on a security surface.
 */
export type LoadResult<T> = { value: T; error: string | null };

function settled<T>(value: T): LoadResult<T> {
  return { value, error: null };
}

async function loadOptional<T>(
  path: string,
  headers: Record<string, string>,
  fallback: T
): Promise<LoadResult<T>> {
  try {
    return settled((await getJson(path, headers)) as T);
  } catch (err) {
    const status = (err as { status?: number } | null)?.status;
    // A record-detail lookup that 404s is a genuinely absent record, i.e. a real
    // empty state. Everything else (401/403/5xx/network) is a LOAD FAILURE and
    // must be surfaced rather than rendered as "nothing here".
    if (status === 404) return settled(fallback);
    const message = err instanceof Error ? err.message : `Request failed for ${path}`;
    return { value: fallback, error: message };
  }
}

function asObject(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export type FetchPortalDataOptions = {
  route?: RouteId;
  datasets?: readonly PortalDataset[];
  includeCore?: boolean;
  force?: boolean;
};

type PortalDataCacheEntry = {
  data: PortalData;
  loadedDatasets: Set<PortalDataset>;
};

const portalDataCache = new Map<string, PortalDataCacheEntry>();

const FEATURE_GATED_DATASETS = new Set<PortalDataset>([
  'connectors',
  'wafAssets',
  'wafCoverage',
  'wafCoverageSummary',
  'wafRiskRoadmap',
  'wafValidations',
  'wafDriftEvents',
  'wafExceptions',
  'wafValidationPlans',
  'wafRetests',
  'wafActionItems',
  'cvePipeline',
  'supplyChainRisks',
  'discoveryEntities',
  'discoveryCandidates',
  'discoveryInbox',
  'discoverySummary'
]);

const ALL_PORTAL_DATASETS: readonly PortalDataset[] = [
  ...CORE_PORTAL_DATASETS,
  'targetGroups',
  'targets',
  'agents',
  'checks',
  'testPolicies',
  'runs',
  'findings',
  'evidence',
  'highScale',
  'reports',
  'notifications',
  'releaseEvidence',
  'releaseAttestation',
  'audit',
  'connectors',
  'secrets',
  'bootstrapTokens',
  'serviceAccounts',
  'wafAssets',
  'wafCoverage',
  'wafCoverageSummary',
  'wafRiskRoadmap',
  'wafValidations',
  'wafDriftEvents',
  'wafExceptions',
  'wafValidationPlans',
  'wafRetests',
  'wafActionItems',
  'cvePipeline',
  'supplyChainRisks',
  'discoveryEntities',
  'discoveryCandidates',
  'discoveryInbox',
  'discoverySummary',
  'subscriptionSummary',
  'internalOverview',
  'internalSignupRequests',
  'internalTenants',
  'internalApprovalRequests',
  'internalAudit'
];

export function resetPortalDataCache() {
  portalDataCache.clear();
}

export function resolvePortalDatasets(route: RouteId, includeCore = true): readonly PortalDataset[] {
  return [...new Set([
    ...(includeCore ? CORE_PORTAL_DATASETS : []),
    ...PORTAL_ROUTE_DATASETS[route]
  ])];
}

function requestedPortalDatasets(options: FetchPortalDataOptions) {
  const includeCore = options.includeCore ?? options.datasets === undefined;
  const requested = new Set<PortalDataset>(
    options.datasets
      ?? (options.route ? resolvePortalDatasets(options.route, includeCore) : ALL_PORTAL_DATASETS)
  );
  if (includeCore) {
    CORE_PORTAL_DATASETS.forEach((dataset) => requested.add(dataset));
  }
  if ([...requested].some((dataset) => FEATURE_GATED_DATASETS.has(dataset))) {
    requested.add('deploymentFeatures');
  }
  return requested;
}

function getPortalDataCacheEntry(identity: string) {
  const cached = portalDataCache.get(identity);
  if (cached) return cached;
  const created: PortalDataCacheEntry = {
    data: { ...EMPTY_PORTAL_DATA, loadErrors: {} },
    loadedDatasets: new Set()
  };
  portalDataCache.set(identity, created);
  return created;
}

function datasetErrorKeys(dataset: PortalDataset): readonly string[] {
  if (dataset === 'notifications') return ['notificationRules', 'notificationEvents'];
  return [dataset];
}

function applyDatasetValue(data: PortalData, dataset: PortalDataset, value: unknown) {
  switch (dataset) {
    case 'state':
      data.state = (value ?? null) as StatePayload | null;
      break;
    case 'tenant':
      data.tenant = asObject(value);
      break;
    case 'targetGroups':
      data.targetGroups = asArray(value);
      data.targetGroupsMeta = asObject((value as { meta?: unknown } | null)?.meta);
      break;
    case 'targets':
      data.targets = asArray(value);
      data.targetsMeta = asObject((value as { meta?: unknown } | null)?.meta);
      break;
    case 'reports':
      data.reports = asArray(value);
      data.reportCapabilities = asObject((value as { capabilities?: unknown } | null)?.capabilities);
      break;
    case 'notifications': {
      const payload = asObject(value);
      data.notificationRules = Array.isArray(payload?.rules) ? payload.rules as DataItem[] : [];
      data.notificationEvents = Array.isArray(payload?.events) ? payload.events as DataItem[] : [];
      break;
    }
    case 'releaseAttestation':
      data.releaseAttestation = asObject(
        (value as { attestation?: unknown } | null)?.attestation ?? value
      );
      break;
    case 'deploymentFeatures':
    case 'wafCoverage':
    case 'wafCoverageSummary':
    case 'wafRiskRoadmap':
    case 'discoverySummary':
    case 'subscriptionSummary':
    case 'internalOverview':
      data[dataset] = asObject(value);
      break;
    default:
      data[dataset] = asArray(value);
  }
}

async function resolveLoadResults(
  entries: Partial<Record<PortalDataset, Promise<LoadResult<unknown>>>>
) {
  const keys = Object.keys(entries) as PortalDataset[];
  const values = await Promise.all(keys.map((key) => entries[key] as Promise<LoadResult<unknown>>));
  return new Map(keys.map((key, index) => [key, values[index]]));
}

export async function fetchPortalData(
  config: PortalConfig,
  session: Session,
  options: FetchPortalDataOptions = {}
): Promise<PortalData> {
  const identity = sessionIdentity(session);
  const requested = requestedPortalDatasets(options);
  const initialCache = getPortalDataCacheEntry(identity);
  const headers = buildApiHeaders(config, session);
  const isStaffSession = session.principal === 'staff';
  const wantsStaffSocHydrate =
    isStaffSession && isStaffSocRole(session) && (options.route === 'internal-soc' || options.route === 'queue-detail');
  const hydrateErrors: string[] = [];
  let useStaffSocTenantHeaders = wantsStaffSocHydrate;
  let tenantHeaders: Record<string, string> = headers;
  if (wantsStaffSocHydrate) {
    try {
      tenantHeaders = buildSocCustomerHeaders(config, session);
    } catch (err) {
      useStaffSocTenantHeaders = false;
      hydrateErrors.push(err instanceof Error ? err.message : 'Staff SOC needs an execution tenant.');
    }
  }
  // Staff customer-API calls only when impersonating (SOC headers). Otherwise skip /v1/* hydrate.
  // When SOC impersonating, ALL customer /v1 hydrate calls must use tenantHeaders — not raw staff headers.
  const customerHeaders = useStaffSocTenantHeaders
    ? tenantHeaders
    : isStaffSession
      ? null
      : headers;
  /**
   * Hydrate one dataset. A `null` header set means the call is NOT APPLICABLE to
   * this session (staff without SOC impersonation), which is a legitimate empty
   * state and must not be recorded as a load failure.
   */
  const opt = <T,>(path: string, h: Record<string, string> | null, fallback: T): Promise<LoadResult<T>> => {
    if (!h) return Promise.resolve(settled(fallback));
    return loadOptional(path, h, fallback);
  };
  const skip = <T,>(fallback: T): Promise<LoadResult<T>> => Promise.resolve(settled(fallback));

  const results = new Map<PortalDataset, LoadResult<unknown>>();
  const shouldLoadFeatures = requested.has('deploymentFeatures') && (
    options.force === true || !initialCache.loadedDatasets.has('deploymentFeatures')
  );
  if (shouldLoadFeatures) {
    const result = await opt('/v1/tenant/deployment-features', customerHeaders, null);
    results.set('deploymentFeatures', result);
  }
  const deploymentFeaturesResult = results.get('deploymentFeatures');
  const deploymentFeatures = deploymentFeaturesResult && !deploymentFeaturesResult.error
    ? deploymentFeaturesResult.value
    : initialCache.data.deploymentFeatures;
  const featureGateError = deploymentFeaturesResult?.error && !initialCache.loadedDatasets.has('deploymentFeatures')
    ? deploymentFeaturesResult.error
    : null;
  const connectorsEnabled =
    deploymentFeatures !== null &&
    typeof deploymentFeatures === 'object' &&
    (deploymentFeatures as { connectors?: unknown }).connectors === true;
  const wafEnabled =
    deploymentFeatures !== null &&
    typeof deploymentFeatures === 'object' &&
    (deploymentFeatures as { waf_posture?: unknown }).waf_posture === true;
  const discoveryEnabled =
    deploymentFeatures !== null &&
    typeof deploymentFeatures === 'object' &&
    (deploymentFeatures as { external_discovery?: unknown }).external_discovery === true;
  const socHeaders = useStaffSocTenantHeaders ? tenantHeaders : customerHeaders;
  const staffHeaders = isStaffSession ? headers : null;
  const gated = <T,>(enabled: boolean, path: string, fallback: T): Promise<LoadResult<T>> => {
    if (featureGateError) return Promise.resolve({ value: fallback, error: featureGateError });
    return enabled ? opt(path, customerHeaders, fallback) : skip(fallback);
  };
  const loaders: Record<PortalDataset, () => Promise<LoadResult<unknown>>> = {
    state: () => opt('/v1/state', socHeaders, null),
    tenant: () => opt('/v1/tenants/current', customerHeaders, null),
    deploymentFeatures: () => opt('/v1/tenant/deployment-features', customerHeaders, null),
    targetGroups: () => opt('/v1/target-groups', customerHeaders, { items: [] }),
    targets: () => opt('/v1/targets', customerHeaders, { items: [] }),
    agents: () => opt('/v1/agents', customerHeaders, { items: [] }),
    checks: () => opt('/v1/checks', customerHeaders, { items: [] }),
    testPolicies: () => opt('/v1/test-policies', customerHeaders, { items: [] }),
    runs: () => opt('/v1/test-runs', customerHeaders, { items: [] }),
    findings: () => opt('/v1/findings', socHeaders, { items: [] }),
    evidence: () => opt('/v1/evidence', customerHeaders, { items: [] }),
    highScale: () => opt('/v1/high-scale-requests', socHeaders, { items: [] }),
    reports: () => opt('/v1/reports', customerHeaders, { items: [] }),
    notifications: () => opt('/v1/notifications', customerHeaders, { rules: [], events: [] }),
    releaseEvidence: () => opt('/v1/production-release-evidence', customerHeaders, { items: [] }),
    releaseAttestation: () => opt('/v1/production-release-evidence/attestation', customerHeaders, null),
    audit: () => opt('/v1/audit-log', customerHeaders, { items: [] }),
    connectors: () => gated(connectorsEnabled, '/v1/connectors', { items: [] }),
    secrets: () => opt('/v1/secrets', customerHeaders, { items: [] }),
    bootstrapTokens: () => opt('/v1/bootstrap-tokens', customerHeaders, { items: [] }),
    serviceAccounts: () => opt('/v1/service-accounts', customerHeaders, { items: [] }),
    wafAssets: () => gated(wafEnabled, '/v1/waf/assets', { items: [] }),
    wafCoverage: () => gated(wafEnabled, '/v1/waf/coverage', null),
    wafCoverageSummary: () => gated(wafEnabled, '/v1/waf/coverage/summary', null),
    wafRiskRoadmap: () => gated(wafEnabled, '/v1/waf/coverage/risk-roadmap', null),
    wafValidations: () => gated(wafEnabled, '/v1/waf/validations', { items: [] }),
    wafDriftEvents: () => gated(wafEnabled, '/v1/waf/drift-events', { items: [] }),
    wafExceptions: () => gated(wafEnabled, '/v1/waf/exceptions', { items: [] }),
    wafValidationPlans: () => gated(wafEnabled, '/v1/waf/validation-plans', { items: [] }),
    wafRetests: () => gated(wafEnabled, '/v1/waf/retests', { items: [] }),
    wafActionItems: () => gated(wafEnabled, '/v1/waf/action-items', { items: [] }),
    cvePipeline: () => gated(wafEnabled, '/v1/waf/cve-pipeline', { items: [] }),
    supplyChainRisks: () => gated(wafEnabled, '/v1/waf/supply-chain/risks', { items: [] }),
    discoveryEntities: () => gated(discoveryEnabled, '/v1/discovery/entities', { items: [] }),
    discoveryCandidates: () => gated(discoveryEnabled, '/v1/discovery/candidates', { items: [] }),
    discoveryInbox: () => gated(discoveryEnabled, '/v1/discovery/inbox', { items: [] }),
    discoverySummary: () => gated(discoveryEnabled, '/v1/discovery/reports/summary', null),
    subscriptionSummary: () => opt('/v1/subscription/current', isStaffSession ? null : customerHeaders, null),
    internalOverview: () => opt('/internal/admin/overview', staffHeaders, null),
    internalSignupRequests: () => opt('/internal/admin/signup-requests', staffHeaders, { items: [] }),
    internalTenants: () => opt('/internal/admin/tenants', staffHeaders, { items: [] }),
    internalApprovalRequests: () => opt('/internal/admin/approval-requests', staffHeaders, { items: [] }),
    internalAudit: () => opt('/internal/admin/audit-log?limit=20', staffHeaders, { items: [] })
  };

  const loadEntries: Partial<Record<PortalDataset, Promise<LoadResult<unknown>>>> = {};
  requested.forEach((dataset) => {
    if (dataset === 'deploymentFeatures') return;
    if (options.force !== true && initialCache.loadedDatasets.has(dataset)) return;
    loadEntries[dataset] = loaders[dataset]();
  });
  const loadedResults = await resolveLoadResults(loadEntries);
  loadedResults.forEach((result, dataset) => results.set(dataset, result));

  const currentCache = getPortalDataCacheEntry(identity);
  const data: PortalData = {
    ...currentCache.data,
    loadErrors: { ...currentCache.data.loadErrors },
    loaded: true
  };
  const loadedDatasets = new Set(currentCache.loadedDatasets);
  if (shouldLoadFeatures && deploymentFeaturesResult && !deploymentFeaturesResult.error) {
    FEATURE_GATED_DATASETS.forEach((dataset) => loadedDatasets.delete(dataset));
  }
  results.forEach((result, dataset) => {
    const errorKeys = datasetErrorKeys(dataset);
    if (result.error) {
      errorKeys.forEach((key) => {
        data.loadErrors[key] = result.error as string;
      });
      loadedDatasets.delete(dataset);
      return;
    }
    applyDatasetValue(data, dataset, result.value);
    errorKeys.forEach((key) => delete data.loadErrors[key]);
    loadedDatasets.add(dataset);
  });
  const aggregateErrors = [...new Set([...hydrateErrors, ...Object.values(data.loadErrors)])];
  data.error = aggregateErrors.length > 0
    ? (aggregateErrors.length === 1
      ? aggregateErrors[0]
      : `${aggregateErrors[0]} (+${aggregateErrors.length - 1} more load issues)`)
    : null;
  portalDataCache.set(identity, { data, loadedDatasets });
  return data;
}

export function fetchPortalDatasets(
  config: PortalConfig,
  session: Session,
  datasets: readonly PortalDataset[]
) {
  return fetchPortalData(config, session, { datasets, includeCore: false, force: true });
}

export const EMPTY_PORTAL_DATA: PortalData = {
  state: null,
  tenant: null,
  targetGroups: [],
  targetGroupsMeta: null,
  targets: [],
  targetsMeta: null,
  agents: [],
  checks: [],
  testPolicies: [],
  runs: [],
  findings: [],
  evidence: [],
  highScale: [],
  reports: [],
  reportCapabilities: null,
  notificationRules: [],
  notificationEvents: [],
  releaseEvidence: [],
  releaseAttestation: null,
  audit: [],
  connectors: [],
  secrets: [],
  bootstrapTokens: [],
  serviceAccounts: [],
  wafAssets: [],
  wafCoverage: null,
  wafCoverageSummary: null,
  wafRiskRoadmap: null,
  wafValidations: [],
  wafDriftEvents: [],
  wafExceptions: [],
  wafValidationPlans: [],
  wafRetests: [],
  wafActionItems: [],
  cvePipeline: [],
  supplyChainRisks: [],
  discoveryEntities: [],
  discoveryCandidates: [],
  discoveryInbox: [],
  discoverySummary: null,
  subscriptionSummary: null,
  internalOverview: null,
  internalSignupRequests: [],
  internalTenants: [],
  internalApprovalRequests: [],
  internalAudit: [],
  deploymentFeatures: null,
  loadErrors: {},
  loaded: false,
  error: null
};
