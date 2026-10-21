// AI feature routes under /v1/assistant/*, dispatched after the finding:read gate.
// Each entry: { path: string | RegExp, method, handle(req, res, ctx, runtimeConfig, deps, match) }.
// Every handler checks the assistant switch with assistantFeatureGate and its own permissions.

import { ASSISTANT_FIX_PACK_ROUTES } from './assistantFixPackRoutes.mjs';
import { ASSISTANT_FILTER_ROUTES } from './assistantFiltersRoutes.mjs';
import { ASSISTANT_RISK_PLAN_ROUTES } from './assistantRiskPlanRoutes.mjs';
import { ASSISTANT_WIDGET_ROUTES } from './assistantWidgetRoutes.mjs';

export const ASSISTANT_FEATURE_ROUTES = Object.freeze([
  ...ASSISTANT_FIX_PACK_ROUTES,
  ...ASSISTANT_FILTER_ROUTES,
  ...ASSISTANT_RISK_PLAN_ROUTES,
  ...ASSISTANT_WIDGET_ROUTES,
]);
