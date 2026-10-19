import { HttpBodyError, json, readJsonBody, respondBodyError } from '../lib/http.mjs';
import { assistantFeatureGate, queueStructuredJob } from './assistantRouteHelpers.mjs';
import { AssistantWidgetError, assertWidgetActor, assertWidgetVersion, normalizeWidgetConfig,
  validateWidgetScope, listWidgetDefinitions, listVisibleWidgets, buildWidgetData, widgetCommentaryRequest } from '../services/assistantWidgets.mjs';

const COLLECTION = '/v1/assistant/widgets';
const ITEM = /^\/v1\/assistant\/widgets\/(aw_[a-f0-9]{24})$/;
const REFRESH = /^\/v1\/assistant\/widgets\/(aw_[a-f0-9]{24})\/refresh$/;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
function validateBody(body, fields) {
  if (!object(body) || Object.keys(body).some((key) => !fields.includes(key))) throw new AssistantWidgetError('invalid_widget_request');
}
function configOf(body) {
  const config = normalizeWidgetConfig(body.config);
  if (!config) throw new AssistantWidgetError('invalid_widget_config');
  return config;
}
function narrativeOf(body) {
  if (body.narrative !== undefined && typeof body.narrative !== 'boolean') throw new AssistantWidgetError('invalid_widget_request');
  return body.narrative === true;
}
function repositoryOf(deps) {
  if (['list', 'create', 'update', 'remove'].some((name) => typeof deps.widgets?.[name] !== 'function')) {
    throw new AssistantWidgetError('assistant_widgets_unavailable', 503);
  }
  return deps.widgets;
}
function route(method, path, operation) {
  return { method, path, async handle(req, res, ctx, runtimeConfig, deps, match) {
    res.setHeader('Cache-Control', 'no-store');
    if (assistantFeatureGate(res, ctx, runtimeConfig)) return;
    try {
      assertWidgetActor(ctx);
      const result = await operation(req, ctx, runtimeConfig, deps, match);
      return json(res, result.httpStatus ?? 200, result.body);
    } catch (error) {
      if (error instanceof HttpBodyError) return respondBodyError(res, error);
      if (error instanceof AssistantWidgetError) return json(res, error.status, { error: error.code, ...error.extra });
      // Never disclose SQL, definitions owned by others, evidence, or filesystem failures.
      return json(res, 503, { error: 'assistant_widgets_unavailable' });
    }
  } };
}
async function findVisible(ctx, id, deps) {
  const row = (await listVisibleWidgets(ctx, repositoryOf(deps), deps.tools)).find((item) => item.id === id);
  if (!row) throw new AssistantWidgetError('widget_not_found', 404);
  return row;
}
async function compute(ctx, config, narrative, runtimeConfig, deps) {
  const data = await buildWidgetData(ctx, config, deps.tools);
  return { data, narrative: narrative
    ? await queueStructuredJob(ctx, widgetCommentaryRequest(config, data), runtimeConfig, deps)
    : { status: 'not_requested' } };
}

export const ASSISTANT_WIDGET_ROUTES = Object.freeze([
  route('GET', COLLECTION, async (_req, ctx, _runtime, deps) => ({
    body: { widgets: await listWidgetDefinitions(ctx, repositoryOf(deps), deps.tools) },
  })),
  route('POST', `${COLLECTION}/preview`, async (req, ctx, runtimeConfig, deps) => {
    const body = await readJsonBody(req, 4096); validateBody(body, ['config', 'narrative']);
    return { body: await compute(ctx, configOf(body), narrativeOf(body), runtimeConfig, deps) };
  }),
  route('POST', COLLECTION, async (req, ctx, _runtime, deps) => {
    const body = await readJsonBody(req, 4096); validateBody(body, ['config']);
    const config = configOf(body);
    await validateWidgetScope(ctx, config, deps.tools);
    return { httpStatus: 201, body: { widget: await repositoryOf(deps).create(ctx, config) } };
  }),
  route('PATCH', ITEM, async (req, ctx, _runtime, deps, match) => {
    const body = await readJsonBody(req, 4096); validateBody(body, ['config', 'expected_version']);
    assertWidgetVersion(body.expected_version);
    await findVisible(ctx, match[1], deps);
    const config = configOf(body);
    await validateWidgetScope(ctx, config, deps.tools);
    return { body: { widget: await repositoryOf(deps).update(ctx, match[1], config, body.expected_version) } };
  }),
  route('DELETE', ITEM, async (req, ctx, _runtime, deps, match) => {
    const body = await readJsonBody(req, 4096); validateBody(body, ['expected_version']);
    assertWidgetVersion(body.expected_version);
    // Removal needs personal ownership and CAS, not access to a former data source.
    return { body: await repositoryOf(deps).remove(ctx, match[1], body.expected_version) };
  }),
  route('POST', REFRESH, async (req, ctx, runtimeConfig, deps, match) => {
    const body = await readJsonBody(req, 4096); validateBody(body, ['narrative']);
    const narrative = narrativeOf(body);
    const widget = await findVisible(ctx, match[1], deps);
    return { body: { widget, ...await compute(ctx, widget.config, narrative, runtimeConfig, deps) } };
  }),
]);
