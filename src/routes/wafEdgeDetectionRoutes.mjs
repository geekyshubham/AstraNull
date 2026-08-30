import { json, readJsonBody } from '../lib/http.mjs';
import { requirePermission } from '../rbac.mjs';
import * as wafEdgeDetection from '../services/wafEdgeDetection.mjs';

const BASE_PATH = '/v1/waf/edge-detection';
const DETAIL_PATH = /^\/v1\/waf\/edge-detection\/([^/]+)$/;

export function isWafEdgeDetectionRoute(path) {
  return path === BASE_PATH || DETAIL_PATH.test(path);
}

/**
 * Queue or read WAF/CDN detection through tenant-scoped test-run services.
 * No request field is ever converted into a hostname or used for control-plane egress.
 * @returns {Promise<boolean>} true when the request was handled.
 */
export async function tryHandleWafEdgeDetectionRoutes(req, res, url, ctx, runtimeConfig, serviceDeps) {
  const method = req.method ?? 'GET';
  if (!isWafEdgeDetectionRoute(url.pathname)) return false;

  if (runtimeConfig.featureFlags?.wafPostureEnabled !== true) {
    json(res, 404, { error: 'waf_feature_disabled' });
    return true;
  }

  const detail = url.pathname.match(DETAIL_PATH);
  if (detail) {
    if (method !== 'GET') {
      json(res, 405, { error: 'method_not_allowed' });
      return true;
    }
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) {
      json(res, gate.status, gate.body);
      return true;
    }
    const result = await wafEdgeDetection.getEdgeDetection(ctx, detail[1], {
      testRuns: serviceDeps.testRuns,
      runtimeConfig,
    });
    if (result?.error) {
      json(res, result.status ?? 400, result);
      return true;
    }
    json(res, 200, result);
    return true;
  }

  if (method !== 'POST') {
    json(res, 405, { error: 'method_not_allowed' });
    return true;
  }
  const gate = requirePermission(ctx, 'waf:run');
  if (!gate.ok) {
    json(res, gate.status, gate.body);
    return true;
  }

  // Let HttpBodyError reach the server's canonical handler so oversized requests remain 413.
  const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
  const result = await wafEdgeDetection.runEdgeDetection(ctx, body, {
    testRuns: serviceDeps.testRuns,
    runtimeConfig,
  });
  if (result?.skipped) {
    json(res, 404, { error: result.reason ?? 'waf_feature_disabled' });
    return true;
  }
  if (result?.error) {
    json(res, result.status ?? 400, result);
    return true;
  }

  res.setHeader('Location', `${BASE_PATH}/${encodeURIComponent(result.request.test_run_id)}`);
  res.setHeader('Retry-After', '2');
  json(res, 202, { detection_request: result.request });
  return true;
}
