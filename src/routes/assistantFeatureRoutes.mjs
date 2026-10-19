// AI feature routes under /v1/assistant/*, dispatched after the finding:read gate.
// Each entry: { path: string | RegExp, method, handle(req, res, ctx, runtimeConfig, deps, match) }.
// Every handler checks the assistant switch with assistantFeatureGate and its own permissions.

export const ASSISTANT_FEATURE_ROUTES = Object.freeze([
]);
