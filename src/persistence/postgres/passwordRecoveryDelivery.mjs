import { randomUUID } from 'node:crypto';
import { deliverEmail } from '../../lib/notificationDelivery.mjs';
import {
  decryptSecret,
  encryptSecret,
  loadSecretEncryptionKey,
} from '../../lib/secrets.mjs';
import { withTenantContext } from './tenantContext.mjs';

export const PASSWORD_RECOVERY_DELIVERY_KIND = 'password_reset';
export const PASSWORD_RECOVERY_DELIVERY_STATUSES = Object.freeze([
  'queued',
  'leased',
  'retry',
  'delivered',
  'dead',
]);

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_LEASE_MS = 30_000;
const DEFAULT_RETRY_BASE_MS = 60_000;
const DEFAULT_RETRY_MAX_MS = 3_600_000;

function fixedError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function boundedInteger(value, fallback, min, max, name) {
  const resolved = value == null || String(value).trim() === ''
    ? fallback
    : Number(value);
  if (!Number.isInteger(resolved) || resolved < min || resolved > max) {
    throw fixedError(
      `Password recovery delivery ${name} must be an integer between ${min} and ${max}.`,
      'password_recovery_delivery_invalid_config',
    );
  }
  return resolved;
}

function resolveSettings(env, options) {
  const retryBaseMs = boundedInteger(
    options.retryBaseMs ?? env.ASTRANULL_PASSWORD_RECOVERY_RETRY_BASE_MS,
    DEFAULT_RETRY_BASE_MS,
    1_000,
    3_600_000,
    'retry base',
  );
  const retryMaxMs = boundedInteger(
    options.retryMaxMs ?? env.ASTRANULL_PASSWORD_RECOVERY_RETRY_MAX_MS,
    DEFAULT_RETRY_MAX_MS,
    retryBaseMs,
    86_400_000,
    'retry maximum',
  );
  return {
    maxAttempts: boundedInteger(
      options.maxAttempts ?? env.ASTRANULL_PASSWORD_RECOVERY_MAX_ATTEMPTS,
      DEFAULT_MAX_ATTEMPTS,
      1,
      10,
      'maximum attempts',
    ),
    leaseMs: boundedInteger(
      options.leaseMs ?? env.ASTRANULL_PASSWORD_RECOVERY_LEASE_MS,
      DEFAULT_LEASE_MS,
      15_000,
      300_000,
      'lease duration',
    ),
    retryBaseMs,
    retryMaxMs,
  };
}

function nowIso(now) {
  const value = now();
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw fixedError(
      'Password recovery delivery clock returned an invalid timestamp.',
      'password_recovery_delivery_invalid_clock',
    );
  }
  return date.toISOString();
}

function normalizeTenantId(tenantId) {
  const normalized = String(tenantId ?? '').trim();
  if (!normalized) {
    throw fixedError(
      'Password recovery delivery requires an explicit tenant id.',
      'password_recovery_delivery_tenant_required',
    );
  }
  return normalized;
}

function validateEnqueuePayload(payload) {
  const valid = payload
    && payload.kind === PASSWORD_RECOVERY_DELIVERY_KIND
    && typeof payload.tenant_id === 'string'
    && payload.tenant_id.trim()
    && typeof payload.user_id === 'string'
    && payload.user_id.trim()
    && typeof payload.idempotency_key === 'string'
    && payload.idempotency_key.trim()
    && typeof payload.email === 'string'
    && payload.email.trim()
    && !/[\r\n]/.test(payload.email)
    && typeof payload.reset_token === 'string'
    && payload.reset_token
    && typeof payload.expires_at === 'string'
    && Number.isFinite(Date.parse(payload.expires_at));
  if (!valid) {
    throw fixedError(
      'Password recovery delivery payload is invalid.',
      'password_recovery_delivery_invalid_payload',
    );
  }
  return {
    tenant_id: payload.tenant_id.trim(),
    user_id: payload.user_id.trim(),
    idempotency_key: payload.idempotency_key.trim(),
    kind: PASSWORD_RECOVERY_DELIVERY_KIND,
    email: payload.email.trim(),
    reset_token: payload.reset_token,
    expires_at: payload.expires_at,
  };
}

export function buildPasswordRecoveryDeliveryAad(record) {
  return {
    tenant_id: record.tenant_id,
    user_id: record.user_id,
    idempotency_key: record.idempotency_key,
    kind: record.kind,
  };
}

function resolvePublicBaseUrl(env) {
  const raw = String(env.ASTRANULL_PUBLIC_BASE_URL ?? '').trim();
  if (!raw) {
    throw fixedError(
      'Password recovery delivery requires ASTRANULL_PUBLIC_BASE_URL.',
      'password_recovery_delivery_base_url_required',
    );
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw fixedError(
      'Password recovery delivery requires a valid public base URL.',
      'password_recovery_delivery_invalid_base_url',
    );
  }
  const localHttp = url.protocol === 'http:'
    && (url.hostname === '127.0.0.1' || url.hostname === 'localhost');
  if ((url.protocol !== 'https:' && !localHttp) || url.username || url.password) {
    throw fixedError(
      'Password recovery delivery requires an HTTPS public base URL without credentials.',
      'password_recovery_delivery_invalid_base_url',
    );
  }
  return url.origin;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function buildPasswordRecoveryEmail(payload, env = process.env) {
  const resetUrl = new URL('/login', `${resolvePublicBaseUrl(env)}/`);
  resetUrl.searchParams.set('flow', 'password-reset');
  resetUrl.searchParams.set('token', payload.reset_token);
  const from = String(env.ASTRANULL_SMTP_FROM ?? '').trim() || 'noreply@astranull.local';
  if (/[\r\n]/.test(from) || /[\r\n]/.test(payload.email)) {
    throw fixedError(
      'Password recovery email envelope is invalid.',
      'password_recovery_delivery_invalid_email_envelope',
    );
  }
  return {
    from,
    to: payload.email,
    subject: '[AstraNull] Reset your password',
    html_body: `<!DOCTYPE html>
<html><body>
<p>A password reset was requested for your AstraNull account.</p>
<p><a href="${escapeHtml(resetUrl.toString())}">Reset your password</a></p>
<p>This link expires at ${escapeHtml(payload.expires_at)}.</p>
<p>If you did not request this change, you can ignore this email.</p>
</body></html>`,
  };
}

export function classifyPasswordRecoveryDeliveryResult(result) {
  if (result?.status === 'delivered_provider') {
    return { delivered: true, retryable: false, errorCode: null };
  }
  const reason = typeof result?.reason === 'string' ? result.reason : '';
  if (/^smtp_unexpected_response_5\d\d$/.test(reason)) {
    return { delivered: false, retryable: false, errorCode: 'smtp_permanent_rejection' };
  }
  if (result?.status === 'provider_failed_dlq') {
    return { delivered: false, retryable: false, errorCode: 'smtp_delivery_failed' };
  }
  if (result?.status === 'queued_provider_not_configured') {
    return { delivered: false, retryable: true, errorCode: 'smtp_not_configured' };
  }
  if (result?.status === 'provider_retry_scheduled') {
    return { delivered: false, retryable: true, errorCode: 'smtp_transient_failure' };
  }
  return { delivered: false, retryable: true, errorCode: 'email_delivery_error' };
}

export function passwordRecoveryRetryDelayMs(attemptCount, {
  baseMs = DEFAULT_RETRY_BASE_MS,
  maxMs = DEFAULT_RETRY_MAX_MS,
} = {}) {
  const exponent = Math.max(0, Number(attemptCount) - 1);
  return Math.min(maxMs, baseMs * (2 ** exponent));
}

function decodePasswordRecoveryPayload(row, key) {
  try {
    const envelope = typeof row.envelope === 'string'
      ? JSON.parse(row.envelope)
      : row.envelope;
    const plaintext = decryptSecret(
      envelope,
      key,
      buildPasswordRecoveryDeliveryAad(row),
    );
    const payload = JSON.parse(plaintext);
    if (
      !payload
      || typeof payload.email !== 'string'
      || !payload.email
      || /[\r\n]/.test(payload.email)
      || typeof payload.reset_token !== 'string'
      || !payload.reset_token
      || typeof payload.expires_at !== 'string'
      || !Number.isFinite(Date.parse(payload.expires_at))
    ) {
      throw new Error('invalid');
    }
    return payload;
  } catch {
    throw fixedError(
      'Password recovery delivery envelope could not be opened.',
      'password_recovery_delivery_envelope_invalid',
    );
  }
}

function smtpOptionsFromEnv(env) {
  const port = Number(env.ASTRANULL_SMTP_PORT ?? 587);
  return {
    smtpHost: String(env.ASTRANULL_SMTP_HOST ?? '').trim(),
    smtpPort: Number.isInteger(port) && port > 0 && port <= 65_535 ? port : 587,
    smtpStartTls: env.ASTRANULL_SMTP_STARTTLS === undefined
      ? true
      : String(env.ASTRANULL_SMTP_STARTTLS).toLowerCase() !== 'false',
    smtpUsername: String(env.ASTRANULL_SMTP_USERNAME ?? ''),
    smtpPassword: String(env.ASTRANULL_SMTP_PASSWORD ?? ''),
  };
}

/**
 * Durable, tenant-scoped password-recovery delivery outbox.
 * Enqueue is intentionally restricted to the caller's existing reset transaction.
 */
export function createPasswordRecoveryDelivery(pool, options = {}) {
  if (!pool) throw new TypeError('Password recovery delivery requires a Postgres pool.');
  const env = options.env ?? process.env;
  const now = options.now ?? (() => new Date());
  const randomUUIDFn = options.randomUUID ?? randomUUID;
  const emailDeliverer = options.deliverEmail ?? deliverEmail;

  async function enqueuePasswordReset(payload, transaction = {}) {
    const client = transaction?.client;
    if (!client || typeof client.query !== 'function') {
      throw fixedError(
        'Password recovery enqueue requires the existing transaction client.',
        'password_recovery_delivery_transaction_required',
      );
    }
    const record = validateEnqueuePayload(payload);
    const key = loadSecretEncryptionKey(env, { required: true });
    const settings = resolveSettings(env, options);
    const envelope = encryptSecret(
      JSON.stringify({
        email: record.email,
        reset_token: record.reset_token,
        expires_at: record.expires_at,
      }),
      key,
      buildPasswordRecoveryDeliveryAad(record),
    );
    const createdAt = nowIso(now);
    const id = `pwrd_${randomUUIDFn().replaceAll('-', '')}`;
    const result = await client.query(
      `INSERT INTO password_recovery_delivery_outbox (
         id, tenant_id, user_id, idempotency_key, kind, envelope, status,
         attempt_count, max_attempts, next_attempt_at, created_at
       ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,'queued',0,$7,$8::timestamptz,$8::timestamptz)
       ON CONFLICT (tenant_id, kind, idempotency_key) DO NOTHING
       RETURNING id`,
      [
        id,
        record.tenant_id,
        record.user_id,
        record.idempotency_key,
        record.kind,
        JSON.stringify(envelope),
        settings.maxAttempts,
        createdAt,
      ],
    );
    return {
      status: result.rowCount === 0 ? 'already_queued' : 'queued',
      id: result.rows?.[0]?.id ?? null,
    };
  }

  async function leaseNext(tenantId, settings, leasedAt) {
    const leaseExpiresAt = new Date(Date.parse(leasedAt) + settings.leaseMs).toISOString();
    return withTenantContext(pool, tenantId, async (client) => {
      await client.query(
        `UPDATE password_recovery_delivery_outbox
         SET status = 'dead', next_attempt_at = NULL, lease_expires_at = NULL,
             last_error_code = 'lease_expired_after_final_attempt'
         WHERE tenant_id = $1
           AND status = 'leased'
           AND lease_expires_at <= $2::timestamptz
           AND attempt_count >= max_attempts`,
        [tenantId, leasedAt],
      );
      const { rows } = await client.query(
        `WITH candidate AS (
           SELECT id
           FROM password_recovery_delivery_outbox
           WHERE tenant_id = $1
             AND attempt_count < max_attempts
             AND (
               (status IN ('queued', 'retry') AND next_attempt_at <= $2::timestamptz)
               OR (status = 'leased' AND lease_expires_at <= $2::timestamptz)
             )
           ORDER BY COALESCE(lease_expires_at, next_attempt_at), created_at, id
           FOR UPDATE SKIP LOCKED
           LIMIT 1
         )
         UPDATE password_recovery_delivery_outbox AS outbox
         SET status = 'leased',
             attempt_count = outbox.attempt_count + 1,
             lease_expires_at = $3::timestamptz,
             last_error_code = NULL
         FROM candidate
         WHERE outbox.tenant_id = $1 AND outbox.id = candidate.id
         RETURNING outbox.id, outbox.tenant_id, outbox.user_id,
                   outbox.idempotency_key, outbox.kind, outbox.envelope,
                   outbox.attempt_count, outbox.max_attempts,
                   outbox.lease_expires_at`,
        [tenantId, leasedAt, leaseExpiresAt],
      );
      return rows[0] ?? null;
    });
  }

  async function settleLease(row, patch) {
    const result = await withTenantContext(pool, row.tenant_id, (client) => client.query(
      `UPDATE password_recovery_delivery_outbox
       SET status = $5,
           next_attempt_at = $6::timestamptz,
           lease_expires_at = NULL,
           last_error_code = $7,
           delivered_at = $8::timestamptz
       WHERE tenant_id = $1
         AND id = $2
         AND status = 'leased'
         AND attempt_count = $3
         AND lease_expires_at = $4::timestamptz`,
      [
        row.tenant_id,
        row.id,
        Number(row.attempt_count),
        row.lease_expires_at,
        patch.status,
        patch.nextAttemptAt,
        patch.errorCode,
        patch.deliveredAt,
      ],
    ));
    return Number(result.rowCount ?? result.rows?.length ?? 0) === 1;
  }

  async function failLease(row, errorCode, retryable, settings, finishedAt) {
    const exhausted = Number(row.attempt_count) >= Number(row.max_attempts);
    const status = !retryable || exhausted ? 'dead' : 'retry';
    const nextAttemptAt = status === 'retry'
      ? new Date(
        Date.parse(finishedAt) + passwordRecoveryRetryDelayMs(row.attempt_count, {
          baseMs: settings.retryBaseMs,
          maxMs: settings.retryMaxMs,
        }),
      ).toISOString()
      : null;
    const updated = await settleLease(row, {
      status,
      nextAttemptAt,
      errorCode,
      deliveredAt: null,
    });
    return {
      status: updated ? status : 'lost_lease',
      id: row.id,
      attempt_count: Number(row.attempt_count),
      error_code: errorCode,
    };
  }

  async function processNext(tenantId) {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const key = loadSecretEncryptionKey(env, { required: true });
    resolvePublicBaseUrl(env);
    const settings = resolveSettings(env, options);
    const leasedAt = nowIso(now);
    const row = await leaseNext(normalizedTenantId, settings, leasedAt);
    if (!row) return { status: 'idle' };

    let payload;
    try {
      payload = decodePasswordRecoveryPayload(row, key);
    } catch {
      return failLease(
        row,
        'password_recovery_envelope_invalid',
        false,
        settings,
        nowIso(now),
      );
    }
    if (Date.parse(payload.expires_at) <= Date.parse(nowIso(now))) {
      return failLease(row, 'password_recovery_expired', false, settings, nowIso(now));
    }

    let result;
    try {
      result = await emailDeliverer(
        buildPasswordRecoveryEmail(payload, env),
        smtpOptionsFromEnv(env),
      );
    } catch {
      result = { status: 'email_delivery_exception' };
    }
    const classification = classifyPasswordRecoveryDeliveryResult(result);
    const finishedAt = nowIso(now);
    if (!classification.delivered) {
      return failLease(
        row,
        classification.errorCode,
        classification.retryable,
        settings,
        finishedAt,
      );
    }

    const updated = await settleLease(row, {
      status: 'delivered',
      nextAttemptAt: null,
      errorCode: null,
      deliveredAt: finishedAt,
    });
    return {
      status: updated ? 'delivered' : 'lost_lease',
      id: row.id,
      attempt_count: Number(row.attempt_count),
    };
  }

  return { enqueuePasswordReset, processNext };
}
