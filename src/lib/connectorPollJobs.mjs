import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto';
import {
  CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS,
  CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS,
  CONNECTOR_POLL_MAX_ATTEMPTS,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
} from './connectorProviders/common.mjs';
import { DOMAIN_INVENTORY_RESPONSE_MAX_BYTES } from './connectorProviders/domainInventory.mjs';

export const CONNECTOR_POLL_JOB_VERSION = 2;
export const CONNECTOR_POLL_JOB_SIGNATURE_ALGORITHM = 'ed25519';
export const CONNECTOR_POLL_JOB_MAX_REQUESTS = 210;
export const CONNECTOR_POLL_JOB_MAX_DURATION_MS = 120_000;
export const CONNECTOR_POLL_JOB_SETTLEMENT_MARGIN_MS = 30_000;
export const CONNECTOR_POLL_JOB_MIN_REMAINING_MS =
  CONNECTOR_POLL_JOB_MAX_DURATION_MS + CONNECTOR_POLL_JOB_SETTLEMENT_MARGIN_MS;
export const CONNECTOR_POLL_JOB_TTL_MS = 10 * 60_000;
export const CONNECTOR_POLL_JOB_LEASE_TTL_MS = 5 * 60_000;

const DEV_CONNECTOR_JOB_KEYS = generateKeyPairSync('ed25519');

function encodePrivateKey(key) {
  return key.export({ format: 'der', type: 'pkcs8' }).toString('base64');
}

function encodePublicKey(key) {
  return key.export({ format: 'der', type: 'spki' }).toString('base64');
}

function parsePrivateKey(value) {
  try {
    const key = createPrivateKey({ key: Buffer.from(String(value ?? ''), 'base64'), format: 'der', type: 'pkcs8' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function parsePublicKey(value) {
  try {
    const key = createPublicKey({ key: Buffer.from(String(value ?? ''), 'base64'), format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

export function isConnectorJobPrivateKeyValid(value) {
  return parsePrivateKey(value) !== null;
}

export function isConnectorJobPublicKeyValid(value) {
  return parsePublicKey(value) !== null;
}

export function connectorJobPublicKeyFromPrivate(value) {
  const privateKey = parsePrivateKey(value);
  if (!privateKey) throw new Error('Connector job signing private key is invalid.');
  return encodePublicKey(createPublicKey(privateKey));
}

export function resolveConnectorJobPrivateKey(options = {}) {
  const configured = options.privateKey ?? options.env?.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY
    ?? process.env.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY;
  if (isConnectorJobPrivateKeyValid(configured)) return String(configured);
  if (options.required === true || options.env?.NODE_ENV === 'production' || process.env.NODE_ENV === 'production') {
    throw new Error('ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY must be a base64 DER Ed25519 PKCS8 key when connector job signing is enabled.');
  }
  return encodePrivateKey(DEV_CONNECTOR_JOB_KEYS.privateKey);
}

export function resolveConnectorJobPublicKey(options = {}) {
  const configured = options.publicKey ?? options.env?.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY
    ?? process.env.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY;
  if (isConnectorJobPublicKeyValid(configured)) return String(configured);
  if (options.privateKey && isConnectorJobPrivateKeyValid(options.privateKey)) {
    return connectorJobPublicKeyFromPrivate(options.privateKey);
  }
  if (options.required === true || options.env?.NODE_ENV === 'production' || process.env.NODE_ENV === 'production') {
    throw new Error('ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY must be a base64 DER Ed25519 SPKI key when connector job verification is enabled.');
  }
  return encodePublicKey(DEV_CONNECTOR_JOB_KEYS.publicKey);
}

function stableStringify(value) {
  if (value === undefined || value === null) return value === undefined ? 'null' : 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  return `{${Object.keys(value).sort().map(
    (key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`,
  ).join(',')}}`;
}

export function connectorPollJobId(connectorId, pollRevision) {
  return `connector_poll_${String(connectorId)}_${Number(pollRevision)}`;
}

export function connectorPollJobEnvelope({
  tenantId,
  connectorId,
  provider,
  pollRevision,
  secretId,
  secretRotation,
  issuedAt,
  expiresAt,
  maxAttempts = CONNECTOR_POLL_MAX_ATTEMPTS,
}) {
  const revision = Number(pollRevision);
  const rotation = Number(secretRotation);
  if (!tenantId || !connectorId || !provider || !secretId
    || !Number.isSafeInteger(revision) || revision <= 0
    || !Number.isSafeInteger(rotation) || rotation < 0) {
    throw new Error('Signed connector poll jobs require exact tenant, connector, provider, secret generation, and positive revision binding.');
  }
  const issuedMs = Date.parse(String(issuedAt));
  const expiresMs = Date.parse(String(expiresAt));
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)
    || expiresMs <= issuedMs || expiresMs - issuedMs > CONNECTOR_POLL_JOB_TTL_MS) {
    throw new Error('Signed connector poll job expiry is invalid or exceeds the hard TTL.');
  }
  return {
    version: CONNECTOR_POLL_JOB_VERSION,
    signature_algorithm: CONNECTOR_POLL_JOB_SIGNATURE_ALGORITHM,
    job_id: connectorPollJobId(connectorId, revision),
    tenant_id: String(tenantId),
    connector_id: String(connectorId),
    provider: String(provider),
    poll_revision: revision,
    secret_id: String(secretId),
    secret_rotation: rotation,
    operation: 'read_only_provider_inventory',
    issued_at: new Date(issuedMs).toISOString(),
    expires_at: new Date(expiresMs).toISOString(),
    constraints: {
      max_attempts: Math.max(1, Math.min(CONNECTOR_POLL_MAX_ATTEMPTS, Number(maxAttempts) || 1)),
      max_requests: CONNECTOR_POLL_JOB_MAX_REQUESTS,
      max_inventory_items: CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
      max_response_bytes: DOMAIN_INVENTORY_RESPONSE_MAX_BYTES,
      request_timeout_ms: Math.min(CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS, CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS),
      max_duration_ms: CONNECTOR_POLL_JOB_MAX_DURATION_MS,
      redirects: 'manual',
      private_networks: 'deny',
    },
  };
}

function connectorPollJobSigningPayload(envelope) {
  return Buffer.from(
    `astranull.connector-poll-job.v2\n${stableStringify(envelope)}`,
    'utf8',
  );
}

export function signConnectorPollJob(envelope, privateKeyValue) {
  const privateKey = parsePrivateKey(privateKeyValue);
  if (!privateKey) throw new Error('Connector job signing private key is missing or invalid.');
  return signBytes(null, connectorPollJobSigningPayload(envelope), privateKey).toString('base64url');
}

export function buildSignedConnectorPollJob(input, privateKeyValue) {
  const envelope = connectorPollJobEnvelope(input);
  return { envelope, signature: signConnectorPollJob(envelope, privateKeyValue) };
}

export function verifySignedConnectorPollJob(record, publicKeyValue, expected = {}, now = new Date()) {
  const envelope = record?.envelope_json ?? record?.envelope;
  const signature = String(record?.job_signature ?? record?.signature ?? '');
  const publicKey = parsePublicKey(publicKeyValue);
  if (!envelope || !signature || !publicKey) return false;
  let signatureBytes;
  try {
    signatureBytes = Buffer.from(signature, 'base64url');
  } catch {
    return false;
  }
  if (!verifyBytes(null, connectorPollJobSigningPayload(envelope), publicKey, signatureBytes)) {
    return false;
  }
  const issuedMs = Date.parse(String(envelope.issued_at));
  const expiresMs = Date.parse(String(envelope.expires_at));
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)
    || expiresMs <= issuedMs || expiresMs - issuedMs > CONNECTOR_POLL_JOB_TTL_MS) return false;
  if (envelope.version !== CONNECTOR_POLL_JOB_VERSION
    || envelope.signature_algorithm !== CONNECTOR_POLL_JOB_SIGNATURE_ALGORITHM
    || envelope.operation !== 'read_only_provider_inventory'
    || envelope.job_id !== connectorPollJobId(envelope.connector_id, envelope.poll_revision)
    || typeof envelope.secret_id !== 'string'
    || !Number.isSafeInteger(envelope.secret_rotation)
    || envelope.secret_rotation < 0
    || envelope.constraints?.redirects !== 'manual'
    || envelope.constraints?.private_networks !== 'deny'
    || envelope.constraints?.max_requests !== CONNECTOR_POLL_JOB_MAX_REQUESTS
    || envelope.constraints?.max_inventory_items !== CONNECTOR_POLL_MAX_INVENTORY_ITEMS
    || envelope.constraints?.max_response_bytes !== DOMAIN_INVENTORY_RESPONSE_MAX_BYTES
    || !Number.isSafeInteger(envelope.constraints?.max_attempts)
    || envelope.constraints.max_attempts < 1
    || envelope.constraints.max_attempts > CONNECTOR_POLL_MAX_ATTEMPTS
    || !Number.isSafeInteger(envelope.constraints?.request_timeout_ms)
    || envelope.constraints.request_timeout_ms < 1
    || envelope.constraints.request_timeout_ms > CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS
    || !Number.isSafeInteger(envelope.constraints?.max_duration_ms)
    || envelope.constraints.max_duration_ms < 1
    || envelope.constraints.max_duration_ms > CONNECTOR_POLL_JOB_MAX_DURATION_MS) return false;
  if (expected.tenantId != null && envelope.tenant_id !== String(expected.tenantId)) return false;
  if (expected.connectorId != null && envelope.connector_id !== String(expected.connectorId)) return false;
  if (expected.provider != null && envelope.provider !== String(expected.provider)) return false;
  if (expected.pollRevision != null && envelope.poll_revision !== Number(expected.pollRevision)) return false;
  if (expected.secretId != null && envelope.secret_id !== String(expected.secretId)) return false;
  if (expected.secretRotation != null && envelope.secret_rotation !== Number(expected.secretRotation)) return false;
  if (expected.expiresAt != null
    && new Date(expiresMs).toISOString() !== new Date(expected.expiresAt).toISOString()) return false;
  const nowMs = now instanceof Date ? now.getTime() : Date.parse(String(now));
  return Number.isFinite(nowMs)
    && issuedMs <= nowMs
    && nowMs < expiresMs;
}

export function createConnectorPollBudgetedFetch(fetchFn, envelope, options = {}) {
  if (typeof fetchFn !== 'function') throw new Error('Signed connector polling requires a fetch transport.');
  const constraints = envelope?.constraints ?? {};
  const maxRequests = Math.min(CONNECTOR_POLL_JOB_MAX_REQUESTS, Number(constraints.max_requests) || 0);
  const deadlineMs = (options.startedAtMs ?? Date.now())
    + Math.min(CONNECTOR_POLL_JOB_MAX_DURATION_MS, Number(constraints.max_duration_ms) || 0);
  let requests = 0;

  const budgetedFetch = async (url, init = {}) => {
    if (typeof options.guard === 'function' && await options.guard() !== true) {
      throw Object.assign(new Error('Signed connector poll lease or authority was revoked.'), {
        code: 'connector_poll_lease_lost',
      });
    }
    requests += 1;
    if (requests > maxRequests) {
      throw Object.assign(new Error('Signed connector poll request budget exceeded.'), {
        code: 'connector_request_budget_exceeded',
      });
    }
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) {
      throw Object.assign(new Error('Signed connector poll deadline exceeded.'), {
        code: 'connector_poll_deadline_exceeded',
      });
    }
    const requestTimeout = Math.min(
      remaining,
      CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS,
      Number(constraints.request_timeout_ms) || 0,
    );
    if (requestTimeout <= 0) {
      throw Object.assign(new Error('Signed connector poll request timeout is invalid.'), {
        code: 'connector_poll_deadline_exceeded',
      });
    }
    const deadlineSignal = AbortSignal.timeout(Math.max(1, requestTimeout));
    const signal = init.signal ? AbortSignal.any([init.signal, deadlineSignal]) : deadlineSignal;
    return fetchFn(url, { ...init, signal });
  };
  budgetedFetch.requestCount = () => requests;
  return budgetedFetch;
}
