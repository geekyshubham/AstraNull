/**
 * Turns backend error payloads into banner copy a customer can act on.
 *
 * API failures carry `{ error, message? }`. Surfaces rendered `payload?.message ?? payload?.error`,
 * so whenever the backend omitted `message` the raw code reached the banner verbatim — starting a
 * second run while one was in flight showed the literal `concurrent_run_blocked`. The contract is
 * unchanged; only the presentation is. Known codes get written copy, everything else is de-snaked
 * so no `snake_case` token can ever reach a user.
 */

/** Written copy for codes whose bare name tells the user nothing about what to do next. */
const KNOWN_ERROR_COPY: Record<string, string> = {
  concurrent_run_blocked:
    'A run is already in progress for this target group. Cancel or finalize it before starting another.',
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
  const payload = (err as (Error & { payload?: unknown }) | undefined)?.payload as
    | ApiErrorPayload
    | undefined;
  if (typeof payload?.message === 'string' && payload.message.trim()) return payload.message;
  const humanized = humanizeErrorCode(payload?.error);
  if (humanized) return humanized;
  if (err instanceof Error && err.message.trim()) return err.message;
  return fallback;
}
