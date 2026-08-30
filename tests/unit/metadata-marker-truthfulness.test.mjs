import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { validateProbeResultBody } from '../../src/lib/probeResultValidation.mjs';
import { correlateExternalOnlyVerdict, correlateVerdict } from '../../src/services/correlation.mjs';
import { simulateProbeResult } from '../../src/services/probeStub.mjs';
import { probeMetadataMarker } from '../../workers/probe-worker.mjs';

const markerJob = {
  probe_profile: { kind: 'metadata_marker', marker: 'astranull-safe-marker' },
};

describe('metadata-only probe truthfulness', () => {
  it('reports zero-request worker markers as not_run', () => {
    const outcome = probeMetadataMarker(markerJob);
    assert.equal(outcome.external_result, 'not_run');
    assert.equal(outcome.requests_sent, 0);
    assert.equal(outcome.metadata.not_run_reason, 'metadata_only_check_has_no_executable_probe');
  });

  it('keeps simulation markers not_run regardless of the requested blocked profile', () => {
    const outcome = simulateProbeResult(
      {
        check_id: 'metadata.declaration.only',
        vector_family: 'application_l7',
        probe_profile: markerJob.probe_profile,
        probe_simulation_profile: 'external_blocked',
      },
      { id: 'tgt_1', value: 'example.test' },
    );
    assert.equal(outcome.external_result, 'not_run');
  });

  it('accepts not_run at ingestion but never converts it to protection credit', () => {
    const validated = validateProbeResultBody({
      external_result: 'not_run',
      metadata: { probe_kind: 'metadata_marker' },
      safety_attestation: { requests_sent: 0, duration_ms: 0 },
    }, {
      max_requests: 1,
      timeout_ms: 5_000,
    }, {
      probeKind: 'metadata_marker',
    });
    assert.equal(validated.ok, true);
    assert.equal(validated.externalResult, 'not_run');

    const correlated = correlateVerdict({
      externalResult: 'not_run',
      agentObserved: false,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(correlated.verdict, 'inconclusive');
    assert.equal(correlated.createsFinding, false);

    const externalOnly = correlateExternalOnlyVerdict({
      externalResult: 'not_run',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(externalOnly.verdict, 'inconclusive');
    assert.equal(externalOnly.createsFinding, false);
  });
});
