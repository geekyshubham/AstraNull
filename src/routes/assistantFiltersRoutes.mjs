import { json, readJsonBody } from '../lib/http.mjs';
import { normalizeFilterRequest, prepareFindingFilterPreview } from '../services/assistantFilters.mjs';
import { assistantFeatureGate, queueStructuredJob } from './assistantRouteHelpers.mjs';

/** POST {question,kind:'findings'} -> {filters|null,interpretation,narrative:{status,job_id?,reason?}}. */
async function handleFilters(req, res, ctx, runtimeConfig, deps) {
  res.setHeader('Cache-Control', 'no-store');
  if (assistantFeatureGate(res, ctx, runtimeConfig)) return;
  const request = normalizeFilterRequest(await readJsonBody(req, 4096));
  if (!request) return json(res, 400, { error: 'invalid_filter_request', message: 'Send only { question: a non-empty string up to 500 characters, kind: "findings" }.' });
  let preview;
  try {
    preview = await prepareFindingFilterPreview(ctx, request, deps.tools ?? {});
  } catch {
    return json(res, 503, { error: 'filter_entities_unavailable', message: 'Filter choices could not be authorized. No filters changed.' });
  }
  if (preview.error) return json(res, preview.status, { error: preview.error });
  const { job, ...body } = preview;
  if (job) body.narrative = await queueStructuredJob(ctx, job, runtimeConfig, deps);
  return json(res, 200, body);
}

export const ASSISTANT_FILTER_ROUTES = Object.freeze([
  { path: '/v1/assistant/filters', method: 'POST', handle: handleFilters },
]);
