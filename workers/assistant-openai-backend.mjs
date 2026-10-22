import { readFile, stat } from 'node:fs/promises';
import { isIP } from 'node:net';

export const DEFAULT_OPENAI_MODEL = 'deepseek-v4-flash';
const DEFAULT_MAX_TOKENS = 8192;
const MIN_MAX_TOKENS = 1024;
const MAX_MAX_TOKENS = 32768;
const MAX_TIMEOUT_SECONDS = 240;
const MAX_RESPONSE_BYTES = 2_000_000;
const MODEL_PATTERN = /^[a-z0-9][a-z0-9._:/-]{1,80}$/i;
const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HEADER_VALUE_PATTERN = /^[\x20-\x7e]{1,256}$/;
const MAX_STATIC_HEADERS = 8;
const RESERVED_HEADERS = new Set(['authorization', 'host', 'content-type', 'content-length', 'cookie', 'transfer-encoding', 'connection']);
const SEARCH_UNAVAILABLE_NOTE = '\n\nWeb search and page browsing are not available in this session. Answer from general knowledge, do not claim to have searched, and do not invent URLs; name the vendor documentation section to check instead.';

export function resolveRunnerBackend(env = process.env) {
  const raw = String(env.ASTRANULL_ASSISTANT_RUNNER_BACKEND ?? '').trim().toLowerCase();
  if (!raw) return 'agy';
  if (raw === 'agy' || raw === 'openai') return raw;
  throw new Error('ASTRANULL_ASSISTANT_RUNNER_BACKEND must be "agy" or "openai".');
}

function isLoopbackHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost') return true;
  if (isIP(host) === 4) return host.startsWith('127.');
  return isIP(host) === 6 && (host === '::1' || host === '::ffff:127.0.0.1');
}

export function parseLlmBaseUrl(raw) {
  let url;
  try {
    url = new URL(String(raw ?? '').trim());
  } catch {
    throw new Error('ASTRANULL_ASSISTANT_LLM_BASE_URL must be an absolute http(s) URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('ASTRANULL_ASSISTANT_LLM_BASE_URL must use http or https.');
  if (url.username || url.password || url.search || url.hash) throw new Error('ASTRANULL_ASSISTANT_LLM_BASE_URL must not contain credentials, a query or a fragment.');
  if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) throw new Error('ASTRANULL_ASSISTANT_LLM_BASE_URL may use plain http only for loopback hosts.');
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url;
}

function boundedInteger(raw, fallback, min, max, name) {
  if (raw === undefined || String(raw).trim() === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} must be an integer from ${min} to ${max}.`);
  return value;
}

async function readApiKey(env) {
  const file = String(env.ASTRANULL_ASSISTANT_LLM_API_KEY_FILE ?? '').trim();
  let key = '';
  if (file) {
    if ((await stat(file)).mode & 0o077) throw new Error('ASTRANULL_ASSISTANT_LLM_API_KEY_FILE must not be readable by group or others (use mode 0600).');
    key = (await readFile(file, 'utf8')).trim();
  } else {
    key = String(env.ASTRANULL_ASSISTANT_LLM_API_KEY ?? '').trim();
  }
  if (!key || /[\s\r\n]/.test(key)) throw new Error('A single-line API key is required in ASTRANULL_ASSISTANT_LLM_API_KEY_FILE or ASTRANULL_ASSISTANT_LLM_API_KEY.');
  return key;
}

export function parseStaticHeaders(raw) {
  const source = String(raw ?? '').trim();
  if (!source) return Object.freeze({});
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error('ASTRANULL_ASSISTANT_LLM_HEADERS must be a JSON object of string values.');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('ASTRANULL_ASSISTANT_LLM_HEADERS must be a JSON object of string values.');
  const entries = Object.entries(parsed);
  if (entries.length > MAX_STATIC_HEADERS) throw new Error(`ASTRANULL_ASSISTANT_LLM_HEADERS allows at most ${MAX_STATIC_HEADERS} headers.`);
  const headers = new Map();
  for (const [name, value] of entries) {
    const key = name.toLowerCase();
    if (!HEADER_NAME_PATTERN.test(name)) throw new Error('ASTRANULL_ASSISTANT_LLM_HEADERS contains an invalid header name.');
    if (RESERVED_HEADERS.has(key)) throw new Error('ASTRANULL_ASSISTANT_LLM_HEADERS contains a reserved header name.');
    if (headers.has(key)) throw new Error('ASTRANULL_ASSISTANT_LLM_HEADERS contains a duplicate header name.');
    if (typeof value !== 'string' || !HEADER_VALUE_PATTERN.test(value)) throw new Error('ASTRANULL_ASSISTANT_LLM_HEADERS values must be printable ASCII strings of 1 to 256 characters.');
    headers.set(key, value);
  }
  return Object.freeze(Object.fromEntries(headers));
}

export async function resolveOpenAiConfig(env = process.env) {
  const baseUrl = parseLlmBaseUrl(env.ASTRANULL_ASSISTANT_LLM_BASE_URL);
  const model = String(env.ASTRANULL_ASSISTANT_LLM_MODEL ?? '').trim() || DEFAULT_OPENAI_MODEL;
  if (!MODEL_PATTERN.test(model)) throw new Error('ASTRANULL_ASSISTANT_LLM_MODEL contains unsupported characters.');
  return Object.freeze({
    endpoint: `${baseUrl.origin}${baseUrl.pathname}/chat/completions`,
    origin: baseUrl.origin,
    model,
    apiKey: await readApiKey(env),
    headers: parseStaticHeaders(env.ASTRANULL_ASSISTANT_LLM_HEADERS),
    maxTokens: boundedInteger(env.ASTRANULL_ASSISTANT_LLM_MAX_TOKENS, DEFAULT_MAX_TOKENS, MIN_MAX_TOKENS, MAX_MAX_TOKENS, 'ASTRANULL_ASSISTANT_LLM_MAX_TOKENS'),
    timeoutCapSeconds: boundedInteger(env.ASTRANULL_ASSISTANT_LLM_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS, 5, MAX_TIMEOUT_SECONDS, 'ASTRANULL_ASSISTANT_LLM_TIMEOUT_SECONDS'),
  });
}

function failureForStatus(status) {
  if (status === 401 || status === 403) return 'llm_auth_failed';
  if (status === 429) return 'llm_rate_limited';
  if (status >= 500) return 'llm_unavailable';
  return 'llm_failed';
}

function stripInlineReasoning(content) {
  return content.replace(/^\s*<think>[\s\S]*?<\/think>/i, '').trim();
}

async function readBoundedBody(response) {
  if (Number(response.headers.get('content-length')) > MAX_RESPONSE_BYTES) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function requestOnce(config, prompt, signal) {
  let response;
  try {
    response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { ...config.headers, authorization: `Bearer ${config.apiKey}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ model: config.model, messages: [{ role: 'user', content: prompt }], max_tokens: config.maxTokens, stream: false }),
      redirect: 'error',
      signal,
    });
  } catch {
    return { error: signal.aborted ? 'llm_timeout' : 'llm_unreachable' };
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    return { error: failureForStatus(response.status), detail: `status=${response.status}` };
  }
  let payload;
  try {
    const raw = await readBoundedBody(response);
    if (raw === null) return { error: 'llm_bad_response', detail: 'oversized' };
    payload = JSON.parse(raw);
  } catch {
    return { error: signal.aborted ? 'llm_timeout' : 'llm_bad_response', detail: 'unparseable' };
  }
  const choice = payload?.choices?.[0];
  const content = typeof choice?.message?.content === 'string' ? stripInlineReasoning(choice.message.content) : '';
  return { content, finish: String(choice?.finish_reason ?? '').replace(/[^a-z_]/gi, '').slice(0, 20) };
}

/** Builds the single "run one model step" primitive for an OpenAI-compatible chat completions API. */
export function createOpenAiStepRunner(config) {
  return async function runOpenAiStep(job, prompt, timeoutSeconds) {
    const seconds = Math.max(1, Math.min(Number(timeoutSeconds) || 120, config.timeoutCapSeconds));
    const signal = AbortSignal.timeout(seconds * 1000);
    const note = (job.allowed_tools ?? []).includes('search_web') ? SEARCH_UNAVAILABLE_NOTE : '';
    let last = null;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      last = await requestOnce(config, `${prompt}${note}`, signal);
      if (last.error) return last;
      if (last.content) return { parsed: { content: last.content, searches: [], sources: [] } };
    }
    return { error: 'llm_empty_response', detail: `finish=${last.finish || 'none'}` };
  };
}
