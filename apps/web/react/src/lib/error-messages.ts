/**
 * Turns backend error payloads into banner copy a customer can act on.
 *
 * API failures carry `{ error, message? }`. Surfaces rendered `payload?.message ?? payload?.error`,
 * so whenever the backend omitted `message` the raw code reached the banner verbatim — starting a
 * second run while one was in flight showed the literal `concurrent_run_blocked`. The contract is
 * unchanged; only the presentation is. Known codes get written copy, everything else is de-snaked
 * so no `snake_case` token can ever reach a user.
 */

import { SCAN_ERROR_COPY } from './validation-scan.mjs';

/** Written copy for codes whose bare name tells the user nothing about what to do next. */
const KNOWN_ERROR_COPY: Record<string, string> = {
  ...SCAN_ERROR_COPY,
  concurrent_run_blocked:
    'A run is already using this target’s execution slot. Cancel or finalize it before starting another.',
  not_found: 'That record no longer exists. Refresh and try again.',
  unauthorized: 'Your session is not authorized for this action. Sign in again or ask an admin for access.',
  forbidden: 'Your role does not permit this action.',
  invalid_token: 'Your session has expired. Sign in again to continue.',
  expired: 'Your session has expired. Sign in again to continue.',
  invalid_request: 'The request was rejected as invalid. Check the values entered and try again.',
  rate_limited: 'Too many requests. Wait a moment and try again.',
  payload_too_large: 'That upload is larger than the request limit.',
  internal_error: 'Something went wrong on our side. Try again, and quote the correlation id if it persists.'
};

/** Fixed operator copy for known deployment-configuration 5xx codes; server-authored text is never shown. */
const CONFIGURATION_ERROR_COPY: Record<string, string> = {
  encryption_not_configured:
    'The secret vault is not configured on this deployment. An operator must set ASTRANULL_SECRET_ENCRYPTION_KEY (local dev: restart `npm run dev:api` to use the generated key under .data/).',
  connector_encryption_not_configured:
    'Connector credentials cannot be stored: an operator must set ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY on this deployment.',
  postgres_internal_admin_not_wired: 'Staff administration is not wired for this deployment mode. Contact the platform operator.',
  governed_adapter_not_configured: 'No governed high-scale execution adapter is configured on this deployment. SOC must configure the adapter before start.',
  kms_signing_not_configured: 'Evidence snapshot signing (KMS) is not configured on this deployment. Contact the platform operator.'
};

export function configurationErrorMessage(payload: unknown): string {
  const code = payload && typeof payload === 'object'
    ? String((payload as { error?: unknown }).error ?? '').trim()
    : '';
  return CONFIGURATION_ERROR_COPY[code] ?? '';
}

/** Sentence-cases a raw code so an unmapped one still reads as prose. */
function humanizeUnknownCode(code: string): string {
  const words = code.trim().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (!words) return '';
  const sentence = `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
  return /[.!?]$/.test(sentence) ? sentence : `${sentence}.`;
}

/** Maps one backend error code to display copy. Never returns raw snake_case. */
export function humanizeErrorCode(code: unknown): string {
  if (typeof code !== 'string' || !code.trim()) return '';
  const normalized = code.trim();
  return KNOWN_ERROR_COPY[normalized] ?? humanizeUnknownCode(normalized);
}

type ApiErrorPayload = { error?: unknown; message?: unknown };

/**
 * Preferred banner text for a thrown API error: the backend's own `message` when it wrote one,
 * otherwise humanized copy for its `error` code, otherwise the thrown message, otherwise `fallback`.
 */
export function apiErrorMessage(err: unknown, fallback: string): string {
  const apiError = err as (Error & { payload?: unknown; status?: unknown }) | undefined;
  const payload = apiError?.payload as ApiErrorPayload | undefined;
  // requestJson/getJson already replace 5xx response text with fixed safe copy on
  // Error.message. Never re-open the attached raw payload at presentation time.
  if (Number(apiError?.status) >= 500) {
    const configurationCopy = configurationErrorMessage(payload);
    if (configurationCopy) return configurationCopy;
    return err instanceof Error && err.message.trim() ? err.message : fallback;
  }
  if (typeof payload?.message === 'string' && payload.message.trim()) return payload.message;
  const humanized = humanizeErrorCode(payload?.error);
  if (humanized) return humanized;
  if (err instanceof Error && err.message.trim()) return err.message;
  return fallback;
}

/** Fixed public/auth copy. These unauthenticated surfaces never render server-authored messages. */
const PUBLIC_ERROR_COPY: Record<string, string> = {
  invalid_json: 'The request could not be read. Refresh and try again.',
  payload_too_large: 'The request is too large. Check the values entered and try again.',
  rate_limited: 'Too many requests. Wait a moment and try again.',
  not_found: 'The requested record was not found.',
  validation_failed: 'Check the values entered and try again.',
  login_disabled: 'This sign-in method is not available on this deployment.',
  staff_login_disabled: 'Staff sign-in is not available on this deployment.',
  password_required: 'This account must sign in with its password.',
  password_login_disabled: 'Password authentication is not available on this deployment.'
};

/**
 * Extracts a public error code only when caller-specific handling is safe.
 * Server failures stay opaque so no payload code can bypass fixed 5xx copy.
 */
export function publicApiErrorCode(status: number, payload: unknown): string {
  if (Number(status) >= 500) return '';
  return payload && typeof payload === 'object'
    ? String((payload as { error?: unknown }).error ?? '').trim()
    : '';
}

/**
 * Safe display copy for direct unauthenticated fetches.
 *
 * Public endpoints can be fronted by proxies and custom services, so their
 * `message` field is untrusted diagnostic data. Known codes receive fixed copy;
 * unknown 4xx responses use the caller's fixed fallback; every 5xx response is
 * collapsed to one fixed availability message.
 */
export function publicApiErrorMessage(status: number, payload: unknown, fallback: string): string {
  if (Number(status) >= 500) return 'Service is temporarily unavailable. Try again.';
  return PUBLIC_ERROR_COPY[publicApiErrorCode(status, payload)] ?? fallback;
}
