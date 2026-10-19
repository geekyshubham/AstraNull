import { json } from '../lib/http.mjs';
import { assistantEnabledForTenant, assistantStore } from '../services/assistant.mjs';

/** Shared switch check for AI feature routes; returns true when it already answered. */
export function assistantFeatureGate(res, ctx, runtimeConfig) {
  if (!runtimeConfig.assistant?.enabled) {
    json(res, 404, { error: 'assistant_disabled' });
    return true;
  }
  if (!assistantEnabledForTenant(runtimeConfig, ctx)) {
    json(res, 403, { error: 'assistant_not_enabled_for_tenant' });
    return true;
  }
  return false;
}

/** Answers with a structured AI job when the runner can take one, or says why not. */
export async function queueStructuredJob(ctx, request, runtimeConfig, deps) {
  const job = await assistantStore.createStructuredJob(ctx, request, runtimeConfig, deps);
  if (job.error) return { status: job.status === 429 ? 'rate_limited' : 'unavailable', reason: job.error, ...(job.retry_after_seconds ? { retry_after_seconds: job.retry_after_seconds } : {}) };
  return { status: 'queued', job_id: job.job_id };
}
