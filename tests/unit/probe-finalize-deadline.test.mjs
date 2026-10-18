import '../helpers/dev-data-dir.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { finalizeProbeOutcome } from '../../workers/probe-worker.mjs';

const timing = (overrides = {}) => ({
  durationMs: () => 10,
  remainingMs: () => 0,
  timeoutMs: 5,
  controller: { signal: { reason: null } },
  ...overrides,
});
const accounting = { probeLogicalAttempts: 1, destinationResolverAttempts: 0 };

test('a conclusive observation that crosses the deadline at finalize keeps its result', () => {
  const outcome = {
    external_result: 'connected',
    metadata: { probe_kind: 'tcp_connect', comparison_complete: true },
    requests_sent: 1,
    duration_ms: 10,
  };
  const finalized = finalizeProbeOutcome(outcome, timing(), accounting);
  assert.equal(finalized.external_result, 'connected');
  assert.notEqual(finalized.metadata.error_class, 'probe_job_deadline_exceeded');
  assert.notEqual(finalized.metadata.comparison_complete, false);
});

test('an incomplete probe that exceeds the deadline is still marked deadline-exceeded', () => {
  const outcome = {
    external_result: 'error',
    metadata: { probe_kind: 'tcp_connect', error_class: 'probe_execution_failed' },
    requests_sent: 1,
    duration_ms: 10,
  };
  const finalized = finalizeProbeOutcome(outcome, timing(), accounting);
  assert.equal(finalized.external_result, 'timeout');
  assert.equal(finalized.metadata.error_class, 'probe_job_deadline_exceeded');
  assert.equal(finalized.metadata.comparison_complete, false);
});
