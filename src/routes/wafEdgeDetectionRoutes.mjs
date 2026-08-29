import { json, readJsonBody } from '../lib/http.mjs';
import { requirePermission } from '../rbac.mjs';
import * as wafEdgeDetection from '../services/wafEdgeDetection.mjs';

export function isWafEdgeDetectionRoute(path) {
  return path === '/v1/waf/edge-detection';
}

/**
 * Handle the hostname → WAF/CDN edge detection route.
 * Stateless (no persistence beyond audit), so one implementation serves dev-json and
 * Postgres modes; tests may inject a fake via serviceDeps.wafEdgeDetection.
 * @returns {Promise<boolean>} true when the request was handled.
 */
export async function tryHandleWafEdgeDetectionRoutes(req, res, url, ctx, runtimeConfig, serviceDeps) {
  const method = req.method ?? 'GET';
  const path = url.pathname;
  if (!isWafEdgeDetectionRoute(path)) return false;

  const svc = serviceDeps.wafEdgeDetection ?? wafEdgeDetection;

  if (method !== 'POST') {
    json(res, 405, { error: 'method_not_allowed' });
    return true;
  }

  // Gate on the server's authoritative runtime config (per-deployment env), consistent
  // with blockWafFeatureDisabled; the service keeps a process-env gate for direct calls.
  if (runtimeConfig.featureFlags.wafPostureEnabled !== true) {
    json(res, 404, { error: 'waf_feature_disabled' });
    return true;
  }

  const gate = requirePermission(ctx, 'waf:run');
  if (!gate.ok) {
    json(res, gate.status, gate.body);
    return true;
  }

  let body = {};
  try {
    body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
  } catch {
    json(res, 400, { error: 'invalid_json' });
    return true;
  }

  const result = await Promise.resolve(svc.runEdgeDetection(ctx, {
    hostname: body?.hostname,
    timeoutMs: body?.timeout_ms,
  }, serviceDeps.edgeDetectionDeps ?? {}));
  if (result?.skipped) {
    json(res, 404, { error: result.reason ?? 'waf_feature_disabled' });
    return true;
  }
  if (result?.error) {
    json(res, result.status ?? 400, result);
    return true;
  }
  json(res, 200, { detection: result.detection });
  return true;
}
