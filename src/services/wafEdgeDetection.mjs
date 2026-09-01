/**
 * WAF/CDN edge detection orchestration.
 *
 * The control plane never resolves or fetches a caller-provided host. It delegates the
 * tenant-owned target binding to `testRuns.startTestRun`, then reads only tenant-scoped run/event
 * metadata from that same service boundary.
 */

import { loadRuntimeConfig } from '../config.mjs';
import {
  validateEdgeDetectionRequest,
  WAF_EDGE_DETECTION_CHECK_ID,
} from '../lib/edgeDetection.mjs';
import { isTrustedProducerEvent } from '../lib/trustedEventProvenance.mjs';
import { projectEdgeDetection } from '../lib/edgeDetectionProjection.mjs';

const ACTIVE_RUN_STATUSES = new Set(['pending', 'planned', 'queued', 'running', 'collecting']);
const SUCCESSFUL_TERMINAL_RUN_STATUSES = new Set(['completed', 'verdicted']);
const ERROR_RUN_STATUSES = new Set(['failed', 'error', 'cancelled']);
const TRUSTED_EVENT_SOURCES = new Set(['probe_worker', 'probe_simulation_stub']);
const OPAQUE_ID_PATTERN = /^[A-Za-z0-9_-]{1,160}$/;

function asRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function boundedString(value, maxLength = 160) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function resolvedRuntimeConfig(runtimeConfig) {
  return runtimeConfig ?? loadRuntimeConfig();
}

function featureGate(runtimeConfig) {
  if (runtimeConfig?.featureFlags?.wafPostureEnabled === true) return null;
  return { skipped: true, reason: 'waf_feature_disabled' };
}

function unavailableTestRuns() {
  return { error: 'edge_detection_test_runs_unavailable', status: 503 };
}

function notFound() {
  return { error: 'edge_detection_not_found', status: 404 };
}

function workerMetadata(event) {
  const outer = asRecord(event?.metadata) ?? {};
  const nested = asRecord(outer.metadata) ?? {};
  return { ...nested, ...outer };
}

function latestTrustedWorkerEvent(events, run) {
  const runNonce = boundedString(asRecord(run.correlation)?.nonce_hash, 256);
  const boundedEvents = Array.isArray(events) ? events.slice(-256) : [];
  for (let index = boundedEvents.length - 1; index >= 0; index -= 1) {
    const event = asRecord(boundedEvents[index]);
    if (!event || event.signal_type !== 'probe_result') continue;
    if (!isTrustedProducerEvent(event)) continue;
    if (event.check_id !== WAF_EDGE_DETECTION_CHECK_ID) continue;
    if (!TRUSTED_EVENT_SOURCES.has(event.source)) continue;
    const eventNonce = boundedString(event.nonce_hash, 256);
    if (runNonce && eventNonce !== runNonce) continue;
    return event;
  }
  return null;
}

function projectWorkerResult(run, events) {
  const runStatus = boundedString(run.status).toLowerCase();
  if (ERROR_RUN_STATUSES.has(runStatus)) {
    return { status: 'error', reason: 'test_run_failed', detection: null };
  }
  if (ACTIVE_RUN_STATUSES.has(runStatus)) {
    return { status: 'pending', reason: 'worker_result_pending', detection: null };
  }
  if (!SUCCESSFUL_TERMINAL_RUN_STATUSES.has(runStatus)) {
    return { status: 'inconclusive', reason: 'test_run_not_successful', detection: null };
  }
  const event = latestTrustedWorkerEvent(events, run);
  if (!event) {
    return { status: 'inconclusive', reason: 'worker_result_not_observed', detection: null };
  }

  const metadata = workerMetadata(event);
  if (event.source === 'probe_simulation_stub' || metadata.simulation === 'SAFE_PROBE_SIMULATION') {
    return { status: 'inconclusive', reason: 'simulation_not_detection', detection: null };
  }

  const externalResult = boundedString(metadata.external_result).toLowerCase();
  const errorClass = boundedString(metadata.error_class);
  if (externalResult === 'error' || externalResult === 'timeout' || errorClass) {
    return {
      status: 'error',
      reason: 'worker_result_error',
      detection: null,
      ...(errorClass ? { error_class: errorClass } : {}),
    };
  }
  if (externalResult !== 'blocked' && externalResult !== 'connected') {
    return { status: 'inconclusive', reason: 'worker_result_incomplete', detection: null };
  }

  const projection = projectEdgeDetection(metadata);

  return {
    status: projection.status,
    reason: projection.reason,
    detection: {
      waf: projection.waf,
      cdn: projection.cdn,
      ...(projection.waf_providers.length ? { waf_providers: projection.waf_providers } : {}),
      ...(projection.cdn_providers.length ? { cdn_providers: projection.cdn_providers } : {}),
      ...(projection.confidence ? { confidence: projection.confidence } : {}),
      ...(projection.conflicting_vendor_signals ? { conflicting_vendor_signals: true } : {}),
      ...(projection.corpus_version ? { corpus_version: projection.corpus_version } : {}),
      evidence: projection.evidence,
      observed_at: boundedString(event.timestamp ?? event.created_at),
    },
  };
}

/** Queue `waf.fingerprint.safe` for an existing tenant-bound target. */
export async function runEdgeDetection(ctx, input = {}, deps = {}) {
  const runtimeConfig = resolvedRuntimeConfig(deps.runtimeConfig);
  const gate = featureGate(runtimeConfig);
  if (gate) return gate;

  const validated = validateEdgeDetectionRequest(input);
  if (validated.error) return validated;
  if (typeof deps.testRuns?.startTestRun !== 'function') return unavailableTestRuns();

  // Await durable run/audit/signed-job creation before acknowledging the asynchronous request.
  const result = await deps.testRuns.startTestRun(ctx, {
    check_id: WAF_EDGE_DETECTION_CHECK_ID,
    target_group_id: validated.target_group_id,
    target_id: validated.target_id,
  }, runtimeConfig);
  if (result?.error) return result;

  const run = result?.run;
  const runId = boundedString(run?.id);
  if (
    !runId
    || run?.check_id !== WAF_EDGE_DETECTION_CHECK_ID
    || run?.target_group_id !== validated.target_group_id
    || run?.target_id !== validated.target_id
  ) {
    return { error: 'edge_detection_dispatch_invalid_response', status: 502 };
  }

  return {
    request: {
      status: 'pending',
      test_run_id: runId,
      target_group_id: validated.target_group_id,
      target_id: validated.target_id,
      check_id: WAF_EDGE_DETECTION_CHECK_ID,
      run_status: boundedString(run.status) || 'running',
      test_run_url: `/v1/test-runs/${encodeURIComponent(runId)}`,
      events_url: `/v1/test-runs/${encodeURIComponent(runId)}/events`,
    },
  };
}

/** Read a metadata-only status projection for one tenant-scoped edge-detection run. */
export async function getEdgeDetection(ctx, id, deps = {}) {
  const runtimeConfig = resolvedRuntimeConfig(deps.runtimeConfig);
  const gate = featureGate(runtimeConfig);
  if (gate) return gate;
  if (!OPAQUE_ID_PATTERN.test(String(id ?? ''))) return notFound();
  if (
    typeof deps.testRuns?.getTestRun !== 'function'
    || typeof deps.testRuns?.getRunEvents !== 'function'
  ) return unavailableTestRuns();

  const run = await deps.testRuns.getTestRun(ctx, id);
  if (!run || run.check_id !== WAF_EDGE_DETECTION_CHECK_ID) return notFound();
  const events = await deps.testRuns.getRunEvents(ctx, id);
  if (events === null) return notFound();

  return {
    test_run_id: run.id,
    target_group_id: run.target_group_id,
    target_id: run.target_id,
    check_id: run.check_id,
    run_status: boundedString(run.status) || 'unknown',
    ...projectWorkerResult(run, events),
  };
}
