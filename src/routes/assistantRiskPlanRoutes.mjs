import { json, readJsonBody } from '../lib/http.mjs';
import { requirePermission } from '../rbac.mjs';
import { buildRiskPlan, buildRiskPlanPrompt, normalizeRiskPlanRequest } from '../services/assistantRiskPlan.mjs';
import { assistantFeatureGate, queueStructuredJob } from './assistantRouteHelpers.mjs';

function route(path, purpose) {
  return Object.freeze({ path, method: 'POST', async handle(req, res, ctx, runtimeConfig, deps) {
    res.setHeader('Cache-Control', 'no-store');
    if (assistantFeatureGate(res, ctx, runtimeConfig)) return;
    const permissions = ['target_group:read', 'finding:read', ...(purpose === 'validation_plan' ? ['check:read'] : [])];
    for (const permission of permissions) {
      const gate = requirePermission(ctx, permission);
      if (!gate.ok) return json(res, gate.status, gate.body);
    }
    const body = await readJsonBody(req, 8192);
    const request = normalizeRiskPlanRequest(body, purpose);
    if (!request) return json(res, 400, { error: 'invalid_risk_plan_request' });
    let built;
    try { built = await buildRiskPlan(ctx, request, purpose, deps.tools); } catch {
      return json(res, 503, { error: 'risk_plan_evidence_unavailable' });
    }
    if (built.error) return json(res, built.status, { error: built.error });
    const { computed } = built;
    await deps.recordAudit?.({
      tenant_id: ctx.tenantId, actor_user_id: ctx.userId, actor_role: ctx.role,
      action: `assistant.${purpose}_proposed`, resource_type: 'target', resource_id: computed.target_id,
      metadata: { target_id: computed.target_id, snapshot_id: computed.snapshot_id, source_finding_count: computed.source_finding_ids.length, execution_started: false },
    });
    const hasData = purpose === 'risk_story' ? computed.stories.length : computed.check_ids.length;
    let narrative = { status: 'not_requested' };
    if (hasData) {
      try {
        narrative = await queueStructuredJob(ctx, {
          purpose,
          prompt: buildRiskPlanPrompt(computed, purpose),
          context: { target_id: computed.target_id, snapshot_id: computed.snapshot_id },
          validation: { target_id: computed.target_id, snapshot_id: computed.snapshot_id, source_finding_ids: computed.source_finding_ids, candidate_check_ids: computed.candidates?.map((row) => row.check_id) ?? [] },
          requiredPermissions: permissions,
          requiredAccess: { finding_ids: computed.source_finding_ids, target_ids: [computed.target_id] },
        }, runtimeConfig, deps);
      } catch {
        narrative = { status: 'unavailable', reason: 'assistant_job_unavailable' };
      }
    }
    return json(res, 200, { computed, narrative });
  } });
}

export const ASSISTANT_RISK_PLAN_ROUTES = Object.freeze([
  route('/v1/assistant/risk-stories', 'risk_story'),
  route('/v1/assistant/validation-plan', 'validation_plan'),
]);
