export const ASSISTANT_DEFAULT_MODEL = 'gemini-3.8-flash-high';
export const ASSISTANT_OPENAI_DEFAULT_MODEL = 'deepseek-v4-flash';
export const ASSISTANT_MIN_RUNNER_TOKEN_LENGTH = 32;

function enabledFlag(raw) {
  const value = String(raw ?? '').trim().toLowerCase();
  return value === '1' || value === 'true';
}

function tenantList(raw) {
  return [...new Set(String(raw ?? '').split(',').map((entry) => entry.trim()).filter(Boolean))];
}

/** Assistant settings from the environment. The runner token is only kept when long enough to be a real secret. */
export function loadAssistantConfig(env = process.env) {
  const token = typeof env.ASTRANULL_ASSISTANT_RUNNER_TOKEN === 'string' ? env.ASTRANULL_ASSISTANT_RUNNER_TOKEN.trim() : '';
  const model = String(env.ASTRANULL_ASSISTANT_MODEL ?? '').trim();
  const backend = String(env.ASTRANULL_ASSISTANT_RUNNER_BACKEND ?? '').trim().toLowerCase() === 'openai' ? 'openai' : 'agy';
  const fallbackModel = backend === 'openai' ? ASSISTANT_OPENAI_DEFAULT_MODEL : ASSISTANT_DEFAULT_MODEL;
  return Object.freeze({
    enabled: enabledFlag(env.ASTRANULL_ASSISTANT_ENABLED),
    tenants: Object.freeze(tenantList(env.ASTRANULL_ASSISTANT_TENANTS)),
    runnerToken: token.length >= ASSISTANT_MIN_RUNNER_TOKEN_LENGTH ? token : '',
    backend,
    webSearch: backend === 'agy',
    model: /^[a-z0-9][a-z0-9._-]{1,80}$/i.test(model) ? model : fallbackModel,
    perUserPerMinute: 6,
    perTenantPerMinute: 30,
    jobTtlMs: 3600000,
    leaseTimeoutMs: 300000,
  });
}
