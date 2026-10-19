import { json, readJsonBody } from '../lib/http.mjs';
import { assistantFeatureGate, queueStructuredJob } from './assistantRouteHelpers.mjs';
import { buildAssistantFixPack, buildAssistantFixPackPrompt, normalizeFixPackRequest } from '../services/assistantFixPacks.mjs';

export const ASSISTANT_FIX_PACK_ROUTES = Object.freeze([{
  path: '/v1/assistant/fix-packs', method: 'POST',
  async handle(req, res, ctx, runtimeConfig, deps) {
    if (assistantFeatureGate(res, ctx, runtimeConfig)) return;
    const request = normalizeFixPackRequest(await readJsonBody(req, 4096));
    if (!request) return json(res, 400, { error: 'invalid_fix_pack_request' });
    const built = await buildAssistantFixPack(ctx, request, deps);
    if (built.error) {
      const { status, ...body } = built;
      return json(res, status, body);
    }
    await deps.recordAudit?.({ tenant_id: ctx.tenantId, actor_user_id: ctx.userId, actor_role: ctx.role, action: 'assistant.fix_pack_requested', resource_type: 'finding', resource_id: request.finding_id, metadata: { provider: built.pack.provider } });
    const narrative = await queueStructuredJob(ctx, {
      purpose: 'fix_pack', prompt: buildAssistantFixPackPrompt(built.pack),
      context: { finding_id: built.pack.finding_id, provider: built.pack.provider, control_family: built.control_family },
      validation: { pack: built.pack }, requiredPermissions: ['finding:read'], requiredAccess: { finding_ids: [built.pack.finding_id] },
    }, runtimeConfig, deps);
    return json(res, 200, { pack: built.pack, narrative });
  },
}]);
