/**
 * WAF edge detection service — tenant-gated wrapper around `detectEdgeForHostname`.
 *
 * Stateless by design: nothing is persisted except the audit event, so the same
 * implementation serves dev-json and Postgres persistence modes. Audit goes through
 * the injected Postgres audit service when the request context carries one
 * (see server.mjs ctx wiring), otherwise through the dev chained audit store.
 */

import { loadRuntimeConfig } from '../config.mjs';
import { audit } from '../audit.mjs';
import { detectEdgeForHostname } from '../lib/edgeDetection.mjs';

function wafFeatureGate() {
  const enabled = loadRuntimeConfig().featureFlags.wafPostureEnabled === true;
  if (!enabled) return { skipped: true, reason: 'waf_feature_disabled' };
  return null;
}

function recordAudit(ctx, entry) {
  if (ctx?.persistenceMode === 'postgres' && typeof ctx?.auditService?.appendAuditEvent === 'function') {
    Promise.resolve(ctx.auditService.appendAuditEvent(entry)).catch(() => {});
    return;
  }
  audit(entry);
}

function auditMetadata(hostname, detection) {
  // Metadata-only: classification booleans, vendor key, and provenance counts. Never
  // raw response data, header values, or body text.
  return {
    hostname,
    tier: detection.tier,
    corpus_version: detection.corpus_version,
    waf_present: detection.waf_present,
    cdn_detected: detection.cdn_detected,
    detected_vendor: detection.best_vendor?.vendor ?? null,
    address_match_count: detection.address_matches.length,
    cname_match_count: detection.cname_matches.length,
    vendor_match_count: detection.vendor_matches.length,
    requests_sent: detection.requests_sent,
    baseline_status_code: detection.baseline_status_code,
    request_error_class: detection.request_error_class ?? null,
    duration_ms: detection.duration_ms,
  };
}

/**
 * Run one bounded edge detection for a declared hostname.
 * @param {{ tenantId?: string, userId?: string|null, persistenceMode?: string, auditService?: object }} ctx
 * @param {{ hostname?: string, timeoutMs?: number }} input
 * @param {object} [deps] injectable resolvers/fetch for tests.
 */
export function runEdgeDetection(ctx, input = {}, deps = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;

  const hostname = String(input.hostname ?? '').trim();
  if (!hostname) {
    return { status: 400, error: 'invalid_hostname' };
  }

  return detectEdgeForHostname({ ...input, hostname, ...deps })
    .then((detection) => {
      if (detection.error) return detection;
      recordAudit(ctx, {
        tenant_id: ctx?.tenantId ?? null,
        actor_user_id: ctx?.userId ?? null,
        action: 'waf.edge_detection_ran',
        metadata: auditMetadata(hostname, detection),
      });
      return { detection };
    })
    .catch((err) => ({
      status: 500,
      error: 'edge_detection_failed',
      detail: err?.code ?? err?.name ?? 'probe_failed',
    }));
}
