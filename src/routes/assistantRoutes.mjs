import { createHash, timingSafeEqual } from 'node:crypto';
import { json, readJsonBody } from '../lib/http.mjs';
import { requirePermission } from '../rbac.mjs';
import { assistantEnabledForTenant, assistantStore } from '../services/assistant.mjs';
import { buildInsightBoard, normalizeInsightRequest } from '../services/assistantInsights.mjs';

const RUNNER_LEASE = '/internal/assistant/runner/lease';
const RUNNER_RESULT = /^\/internal\/assistant\/runner\/jobs\/([A-Za-z0-9_]{1,64})\/result$/;
const RUNNER_TOOL = /^\/internal\/assistant\/runner\/jobs\/([A-Za-z0-9_]{1,64})\/tool$/;
const RUNNER_TOOL_BODY_LIMIT = 16 * 1024;
const JOB_PATH = /^\/v1\/assistant\/jobs\/([A-Za-z0-9_]{1,64})$/;
const INSIGHTS_PATH = '/v1/assistant/insights';
const RUNNER_BODY_LIMIT = 256 * 1024;

export function isAssistantRunnerRoute(pathname, method) {
  if (method !== 'POST') return false;
  return pathname === RUNNER_LEASE || RUNNER_RESULT.test(pathname) || RUNNER_TOOL.test(pathname);
}

function bearer(headers) {
  const match = String(headers?.authorization ?? '').match(/^Bearer\s+(\S+)$/i);
  return match ? match[1] : '';
}

function tokensMatch(given, expected) {
  const left = createHash('sha256').update(String(given)).digest();
  const right = createHash('sha256').update(String(expected)).digest();
  return timingSafeEqual(left, right);
}

async function recordRunnerDenial(req, url, runtimeConfig, serviceDeps, recordDevAudit) {
  const entry = {
    tenant_id: null,
    actor_user_id: 'assistant_runner',
    actor_role: 'assistant_runner',
    action: 'assistant_runner.auth_denied',
    resource_type: 'assistant_runner',
    resource_id: null,
    metadata: { method: req.method, path: url.pathname.slice(0, 256) },
  };
  try {
    if (runtimeConfig.persistenceMode === 'postgres') await serviceDeps?.audit?.appendAuditEvent?.(entry);
    else recordDevAudit?.(entry);
  } catch {
    // An audit write without a tenant can be refused; the request is still denied.
  }
}

/** Runner endpoints: authenticated only by the runner bearer token, never by a human session. */
export async function handleAssistantRunnerApi(req, res, url, runtimeConfig, { serviceDeps, recordDevAudit, assistantDeps } = {}) {
  const cfg = runtimeConfig.assistant ?? {};
  if (!cfg.enabled || !cfg.runnerToken) return json(res, 404, { error: 'not_found' });
  const token = bearer(req.headers);
  if (!token || !tokensMatch(token, cfg.runnerToken)) {
    await recordRunnerDenial(req, url, runtimeConfig, serviceDeps, recordDevAudit);
    return json(res, 401, { error: 'unauthorized', message: 'Missing or invalid assistant runner token.' });
  }
  if (url.pathname === RUNNER_LEASE) {
    const lease = assistantStore.leaseJob(runtimeConfig);
    if (!lease) {
      res.writeHead(204, { 'Cache-Control': 'no-store' });
      res.end();
      return undefined;
    }
    return json(res, 200, lease);
  }
  const toolMatch = url.pathname.match(RUNNER_TOOL);
  if (toolMatch) {
    const body = await readJsonBody(req, RUNNER_TOOL_BODY_LIMIT);
    const outcome = await assistantStore.runJobTool(toolMatch[1], body, runtimeConfig, assistantDeps ?? {});
    if (outcome.error) {
      const { status, ...rest } = outcome;
      return json(res, status, rest);
    }
    return json(res, 200, outcome);
  }
  const match = url.pathname.match(RUNNER_RESULT);
  const body = await readJsonBody(req, Math.min(runtimeConfig.maxJsonBodyBytes ?? RUNNER_BODY_LIMIT, RUNNER_BODY_LIMIT));
  const result = assistantStore.completeJob(match[1], body, runtimeConfig);
  if (result.error) return json(res, result.status, { error: result.error, ...(result.job_status ? { job_status: result.job_status } : {}) });
  return json(res, 200, result);
}

/** Customer chat endpoints. Returns true when the request was handled. */
export async function tryHandleAssistantRoutes(req, res, url, ctx, runtimeConfig, deps = {}) {
  const { pathname: path } = url;
  const method = req.method;
  const jobMatch = path.match(JOB_PATH);
  if (path !== '/v1/assistant/status' && path !== '/v1/assistant/jobs' && path !== INSIGHTS_PATH && !jobMatch) return false;
  const gate = requirePermission(ctx, 'finding:read');
  if (!gate.ok) {
    json(res, gate.status, gate.body);
    return true;
  }
  if (path === '/v1/assistant/status' && method === 'GET') {
    json(res, 200, assistantStore.status(ctx, runtimeConfig));
    return true;
  }
  if (path === '/v1/assistant/jobs' && method === 'POST') {
    const body = await readJsonBody(req, Math.min(runtimeConfig.maxJsonBodyBytes ?? 131072, 131072));
    const result = await assistantStore.createJob(ctx, body, runtimeConfig, deps);
    if (result.error) {
      const { status, ...rest } = result;
      if (status === 429 && rest.retry_after_seconds) res.setHeader('Retry-After', String(rest.retry_after_seconds));
      json(res, status, rest);
    } else {
      json(res, 202, result);
    }
    return true;
  }
  if (path === INSIGHTS_PATH && method === 'POST') {
    await handleInsights(req, res, ctx, runtimeConfig, deps);
    return true;
  }
  if (jobMatch && method === 'GET') {
    const job = assistantStore.getJob(ctx, jobMatch[1], runtimeConfig);
    json(res, job ? 200 : 404, job ?? { error: 'not_found' });
    return true;
  }
  if (jobMatch && method === 'DELETE') {
    const job = assistantStore.cancelJob(ctx, jobMatch[1], runtimeConfig);
    json(res, job ? 200 : 404, job ?? { error: 'not_found' });
    return true;
  }
  json(res, 405, { error: 'method_not_allowed' });
  return true;
}

async function handleInsights(req, res, ctx, runtimeConfig, deps) {
  if (!runtimeConfig.assistant?.enabled) return json(res, 404, { error: 'assistant_disabled' });
  if (!assistantEnabledForTenant(runtimeConfig, ctx)) return json(res, 403, { error: 'assistant_not_enabled_for_tenant' });
  const body = await readJsonBody(req, 16 * 1024);
  const request = normalizeInsightRequest(body);
  if (!request) return json(res, 400, { error: 'invalid_insight_request', message: 'Send { kind, entity?: { id }, finding_ids? } for a known page.' });
  const built = await buildInsightBoard(ctx, request, deps.tools ?? {});
  if (built.error) return json(res, built.status, { error: built.error });
  let narrative = { status: 'not_requested' };
  if (request.narrative && !built.board.scope.no_access) {
    const job = await assistantStore.createInsightJob(ctx, built.board, runtimeConfig, deps);
    if (job.error) {
      narrative = { status: job.status === 429 ? 'rate_limited' : 'unavailable', reason: job.error, ...(job.retry_after_seconds ? { retry_after_seconds: job.retry_after_seconds } : {}) };
    } else {
      narrative = { status: 'queued', job_id: job.job_id };
    }
  }
  res.setHeader('Cache-Control', 'no-store');
  return json(res, 200, { board: built.board, narrative });
}
