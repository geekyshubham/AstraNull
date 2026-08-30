/**
 * Pure control-plane validation for WAF/CDN edge detection.
 *
 * This module intentionally has no DNS, HTTP, socket, or other network imports. Live
 * detection belongs to the signed probe-worker path; the control plane accepts only
 * tenant-bound identifiers and delegates through the shared test-run service.
 */

export const WAF_EDGE_DETECTION_CHECK_ID = 'waf.fingerprint.safe';

const EDGE_REQUEST_FIELDS = new Set(['target_group_id', 'target_id']);
const OPAQUE_ID_PATTERN = /^[A-Za-z0-9_-]{1,160}$/;

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function normalizeOpaqueId(value, field) {
  if (typeof value !== 'string') return { error: `invalid_${field}` };
  const normalized = value.trim();
  if (!OPAQUE_ID_PATTERN.test(normalized)) return { error: `invalid_${field}` };
  return { value: normalized };
}

/**
 * Validate the only accepted request shape. Hostnames, URLs, IP literals, timeout
 * overrides, and arbitrary probe parameters are rejected before `startTestRun`.
 */
export function validateEdgeDetectionRequest(input) {
  const body = asRecord(input);
  if (!body) return { error: 'invalid_request', status: 400 };

  if (Object.prototype.hasOwnProperty.call(body, 'hostname')) {
    return { error: 'raw_hostname_not_allowed', status: 400 };
  }

  const unsupportedFields = Object.keys(body).filter((key) => !EDGE_REQUEST_FIELDS.has(key));
  if (unsupportedFields.length > 0) {
    return {
      error: 'unsupported_fields',
      status: 400,
      fields: unsupportedFields.sort(),
    };
  }

  const targetGroup = normalizeOpaqueId(body.target_group_id, 'target_group_id');
  if (targetGroup.error) return { ...targetGroup, status: 400 };
  const target = normalizeOpaqueId(body.target_id, 'target_id');
  if (target.error) return { ...target, status: 400 };

  return {
    target_group_id: targetGroup.value,
    target_id: target.value,
  };
}
