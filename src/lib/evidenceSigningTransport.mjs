import { readFileSync } from 'node:fs';
import { evidenceSigningRequiresAsymmetric } from './evidenceSigning.mjs';

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_RESPONSE_BYTES = 16384;

function boundedInteger(value, fallback, ceiling) {
  const number = Number(value ?? fallback);
  return Number.isSafeInteger(number) && number > 0 && number <= ceiling ? number : null;
}

function signerConfig(config) {
  const env = config.env ?? process.env;
  let realMode;
  try {
    realMode = evidenceSigningRequiresAsymmetric(env);
  } catch {
    return { error: 'invalid_signing_deployment_config', status: 503 };
  }
  const endpoint = String(config.endpoint ?? env.ASTRANULL_KMS_SIGNING_ENDPOINT ?? '').trim().replace(/\/+$/, '');
  if (!endpoint) return { error: 'kms_signing_not_configured', status: 503 };
  let url;
  try { url = new URL(endpoint); } catch { return { error: 'kms_signing_endpoint_invalid', status: 503 }; }
  const localHttp = !realMode && env.ASTRANULL_DEPLOYMENT_PROFILE === 'local-staging'
    && url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !localHttp) || url.username || url.password || url.search || url.hash) {
    return { error: 'kms_signing_endpoint_invalid', status: 503 };
  }
  const allowedOrigins = String(env.ASTRANULL_KMS_SIGNING_ALLOWED_ORIGINS ?? '').split(',').map((value) => value.trim()).filter(Boolean);
  if (realMode && !allowedOrigins.length) return { error: 'kms_signing_origin_not_approved', status: 503 };
  if (allowedOrigins.length) {
    if (allowedOrigins.some((origin) => {
      try { return new URL(origin).origin !== origin || new URL(origin).protocol !== 'https:'; } catch { return true; }
    }) || !allowedOrigins.includes(url.origin)) return { error: 'kms_signing_origin_not_approved', status: 503 };
  }
  const fetchTimeoutMs = boundedInteger(config.fetchTimeoutMs ?? env.ASTRANULL_KMS_SIGNING_FETCH_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, 30000);
  const maxResponseBytes = boundedInteger(config.maxResponseBytes ?? env.ASTRANULL_KMS_SIGNING_MAX_RESPONSE_BYTES, DEFAULT_RESPONSE_BYTES, 65536);
  if (!fetchTimeoutMs || !maxResponseBytes) return { error: 'kms_signing_limits_invalid', status: 503 };
  let bearerToken = String(env.ASTRANULL_KMS_SIGNING_BEARER_TOKEN ?? '').trim();
  const tokenFile = String(env.ASTRANULL_KMS_SIGNING_BEARER_TOKEN_FILE ?? '').trim();
  if (!bearerToken && tokenFile) {
    try { bearerToken = readFileSync(tokenFile, 'utf8').trim(); } catch { return { error: 'kms_signing_auth_unavailable', status: 503 }; }
  }
  if ((realMode && !bearerToken) || (bearerToken && (!/^[\x21-\x7e]+$/.test(bearerToken) || bearerToken.length > 8192))) {
    return { error: 'kms_signing_auth_invalid', status: 503 };
  }
  return { endpoint, origin: url.origin, fetchTimeoutMs, maxResponseBytes, bearerToken };
}

/** Configuration-only validation; never emits credentials or contacts the signer. */
export function validateEvidenceSigningTransportConfig(config = {}) {
  const resolved = signerConfig(config);
  if (resolved.error) return resolved;
  return { ok: true, origin: resolved.origin };
}

/** A single absolute deadline bounds response headers AND body, including stalled readers. */
export function createEvidenceSigningTransport(config = {}) {
  const resolved = signerConfig(config);
  const fetchFn = config.fetchFn ?? globalThis.fetch;
  return async function callSigner(path, body) {
    if (resolved.error) return resolved;
    if (typeof fetchFn !== 'function') return { error: 'kms_signing_unavailable', status: 503, detail: 'fetch_unavailable' };
    const controller = new AbortController();
    let reader;
    let response;
    let completed = false;
    let timer;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(Object.assign(new Error('signer_deadline'), { code: 'signer_deadline' }));
      }, resolved.fetchTimeoutMs);
    });
    const consume = async () => {
      response = await fetchFn(`${resolved.endpoint}${path}`, {
        method: 'POST', redirect: 'manual', signal: controller.signal,
        headers: { 'content-type': 'application/json', accept: 'application/json',
          ...(resolved.bearerToken ? { authorization: `Bearer ${resolved.bearerToken}` } : {}) },
        body: JSON.stringify(body),
      });
      if (controller.signal.aborted) {
        // A custom fetch may resolve after the outer deadline/finally already ran.
        try {
          if (response?.body && !response.body.locked) Promise.resolve(response.body.cancel()).catch(() => {});
        } catch { /* Late cleanup must not replace the deadline result. */ }
        throw Object.assign(new Error('signer_deadline'), { code: 'signer_deadline' });
      }
      if (!response.ok) return { error: 'kms_signing_unavailable', status: 503, detail: `http_${response.status}` };
      const contentLength = response.headers?.get('content-length');
      if (contentLength != null && (!/^\d+$/.test(contentLength) || Number(contentLength) > resolved.maxResponseBytes)) {
        return { error: 'kms_signing_response_invalid', status: 502 };
      }
      const contentType = response.headers?.get('content-type');
      if (contentType && !/^application\/json(?:;|$)/i.test(contentType)) return { error: 'kms_signing_response_invalid', status: 502 };
      if (!response.body || typeof response.body.getReader !== 'function') return { error: 'kms_signing_response_invalid', status: 502 };
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      while (true) {
        const { value, done } = await reader.read();
        if (controller.signal.aborted) throw Object.assign(new Error('signer_deadline'), { code: 'signer_deadline' });
        if (done) { completed = true; break; }
        if (!(value instanceof Uint8Array)) return { error: 'kms_signing_response_invalid', status: 502 };
        size += value.byteLength;
        if (size > resolved.maxResponseBytes) return { error: 'kms_signing_response_invalid', status: 502 };
        chunks.push(Buffer.from(value));
      }
      let parsed;
      try {
        parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size)));
      } catch { return { error: 'kms_signing_response_invalid', status: 502 }; }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { error: 'kms_signing_response_invalid', status: 502 };
      return { body: parsed };
    };
    try {
      return await Promise.race([consume(), deadline]);
    } catch (err) {
      return { error: 'kms_signing_unavailable', status: 503,
        detail: controller.signal.aborted || err?.code === 'signer_deadline' ? 'timeout' : 'network_error' };
    } finally {
      clearTimeout(timer);
      if (!completed) {
        controller.abort();
        // Cancellation itself is not allowed to extend the deadline.
        try {
          if (reader) Promise.resolve(reader.cancel()).catch(() => {});
          else if (response?.body && !response.body.locked) Promise.resolve(response.body.cancel()).catch(() => {});
        } catch { /* Preserve the signing failure when a reader cannot be cancelled. */ }
      }
    }
  };
}
