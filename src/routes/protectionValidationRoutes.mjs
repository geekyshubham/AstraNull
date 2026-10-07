import { json, readJsonBody } from '../lib/http.mjs';
import { requirePermission } from '../rbac.mjs';
import { PROTECTION_VALIDATION_ROUTES } from '../contracts/protectionValidation.mjs';
import { devProtectionValidationService } from '../services/protectionValidation.mjs';
import { isProtectionValidationEnabled } from '../services/tenantDeploymentFeatures.mjs';

/** Operations whose service method lives in another slice (PV-04/PV-05) and is dispatched only when present. */
export const DELEGATED_PROTECTION_VALIDATION_OPERATIONS = Object.freeze({
  get_protection_matrix: 'getProtectionMatrix',
  plan_or_start_entry_path_comparison: 'planOrStartEntryPathComparison',
  list_entry_path_comparisons: 'listEntryPathComparisons',
  get_entry_path_comparison: 'getEntryPathComparison',
  cancel_entry_path_comparison: 'cancelEntryPathComparison',
  evaluate_firewall_comparison: 'evaluateFirewallComparison',
});

const FIREWALL = { kind: 'firewall_change' };

const OWNED_HANDLERS = Object.freeze({
  list_entry_paths: (svc, ctx, { params, query }) => svc.listEntryPaths(ctx, params.targetId, query),
  create_entry_path: (svc, ctx, { params, body, idempotencyKey }) => svc.createEntryPath(ctx, params.targetId, body, { idempotencyKey }),
  get_entry_path: (svc, ctx, { params }) => svc.getEntryPath(ctx, params.entryPathId),
  archive_entry_path: (svc, ctx, { params }) => svc.archiveEntryPath(ctx, params.entryPathId),
  list_firewall_expectations: (svc, ctx, { query }) => svc.listExpectations(ctx, { ...query, ...FIREWALL }),
  create_firewall_expectation: (svc, ctx, { body, idempotencyKey }) => svc.createFirewallExpectation(ctx, body, { idempotencyKey }),
  archive_firewall_expectation: (svc, ctx, { params }) => svc.archiveExpectation(ctx, params.expectationId, FIREWALL),
  capture_firewall_baseline: (svc, ctx, { body }) => svc.captureFirewallBaseline(ctx, body),
  list_firewall_baselines: (svc, ctx, { query }) => svc.listBaselineCaptures(ctx, { ...query, ...FIREWALL }),
  get_firewall_baseline: (svc, ctx, { params }) => svc.getBaselineCapture(ctx, params.baselineId, FIREWALL),
  list_firewall_comparisons: (svc, ctx, { query }) => svc.listEvaluations(ctx, { ...query, ...FIREWALL }),
  get_firewall_comparison: (svc, ctx, { params }) => svc.getEvaluation(ctx, params.comparisonId, FIREWALL),
});

const CREATE_OPERATIONS = new Set([
  'create_entry_path', 'create_firewall_expectation', 'capture_firewall_baseline', 'evaluate_firewall_comparison',
]);

function compile(route) {
  const names = [];
  const pattern = route.path.split('/').map((segment) => {
    if (!segment.startsWith(':')) return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    names.push(segment.slice(1));
    return '([^/]+)';
  }).join('/');
  return { ...route, regex: new RegExp(`^${pattern}$`), names };
}

const COMPILED = PROTECTION_VALIDATION_ROUTES.map(compile);

export function matchProtectionValidationRoute(method, pathname) {
  const candidates = COMPILED.filter((route) => route.regex.test(pathname));
  if (!candidates.length) return null;
  const route = candidates.find((candidate) => candidate.method === method);
  if (!route) return { route: null, methodNotAllowed: true };
  const values = pathname.match(route.regex).slice(1);
  let params;
  try {
    params = Object.fromEntries(route.names.map((name, index) => [name, decodeURIComponent(values[index])]));
  } catch {
    return { route, params: null };
  }
  return { route, params };
}

export function isProtectionValidationRoute(pathname) {
  return COMPILED.some((route) => route.regex.test(pathname));
}

function resolveService(runtimeConfig, serviceDeps) {
  if (serviceDeps?.protectionValidation) return serviceDeps.protectionValidation;
  return runtimeConfig?.persistenceMode === 'postgres' ? null : devProtectionValidationService;
}

function notWired(res, runtimeConfig) {
  return json(res, 503, { error: runtimeConfig?.persistenceMode === 'postgres' ? 'postgres_route_not_wired' : 'route_not_wired' });
}

function successStatus(operation, result) {
  if (operation === 'plan_or_start_entry_path_comparison') return result?.mode === 'start' ? 202 : 200;
  if (CREATE_OPERATIONS.has(operation)) return result?.replayed === true ? 200 : 201;
  return 200;
}

function errorBody(result) {
  const body = { error: result.error };
  for (const field of ['field', 'message', 'permission', 'existing_id', 'reason', 'ownership_state']) {
    if (result[field] != null) body[field] = result[field];
  }
  return body;
}

// Path parameters always win; a body or query naming a different value for one is rejected.
function delegatedInput(params, source) {
  const fields = source && typeof source === 'object' && !Array.isArray(source) ? source : {};
  for (const [key, value] of Object.entries(params ?? {})) {
    if (Object.hasOwn(fields, key) && fields[key] !== value) {
      return { error: 'path_parameter_mismatch', status: 400, field: key };
    }
  }
  return { value: { ...fields, ...params } };
}

// Passive except the delegated reviewed comparison start; returns true when the request was handled.
export async function tryHandleProtectionValidationRoutes(req, res, url, ctx, runtimeConfig, serviceDeps) {
  const matched = matchProtectionValidationRoute(req.method ?? 'GET', url.pathname);
  if (!matched) return false;
  if (matched.methodNotAllowed) {
    json(res, 405, { error: 'method_not_allowed' });
    return true;
  }
  if (!ctx?.tenantId) {
    json(res, 401, { error: 'unauthorized' });
    return true;
  }
  if (!isProtectionValidationEnabled(ctx, runtimeConfig)) {
    json(res, 404, { error: 'protection_validation_disabled' });
    return true;
  }
  const { route } = matched;
  const gate = requirePermission(ctx, route.permission, { resource_type: 'protection_validation' });
  if (!gate.ok) {
    json(res, gate.status, gate.body);
    return true;
  }
  if (!matched.params) {
    json(res, 404, { error: 'not_found' });
    return true;
  }
  const svc = resolveService(runtimeConfig, serviceDeps);
  if (!svc) {
    notWired(res, runtimeConfig);
    return true;
  }
  const delegated = DELEGATED_PROTECTION_VALIDATION_OPERATIONS[route.operation];
  const handler = OWNED_HANDLERS[route.operation]
    ?? (delegated && typeof svc[delegated] === 'function'
      ? (service, scope, input) => {
        const merged = delegatedInput(input.params, route.method === 'GET' ? input.query : input.body);
        if (merged.error) return merged;
        return service[delegated](scope, merged.value, { runtimeConfig, serviceDeps, idempotencyKey: input.idempotencyKey });
      }
      : null);
  if (!handler) {
    notWired(res, runtimeConfig);
    return true;
  }
  const body = route.method === 'POST' ? await readJsonBody(req, runtimeConfig?.maxJsonBodyBytes) : null;
  const query = Object.fromEntries(url.searchParams.entries());
  const header = req.headers?.['idempotency-key'];
  const idempotencyKey = Array.isArray(header) ? header[0] : header;
  const result = await handler(svc, ctx, { params: matched.params, query, body: body ?? {}, idempotencyKey });
  if (result?.error) {
    json(res, result.status ?? 400, errorBody(result));
    return true;
  }
  if (!result) {
    json(res, 404, { error: 'not_found' });
    return true;
  }
  json(res, successStatus(route.operation, result), result);
  return true;
}
