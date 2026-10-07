import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  correlateExternalOnlyVerdict,
  correlateOpsReadinessVerdict,
} from '../../src/services/correlation.mjs';

// ADR-0008: agents are removed. Verdicts come from external probe evidence only, so the
// former agent-corroborated `correlateVerdict` truth table is gone. `correlateExternalOnlyVerdict`
// is the sole safe-run correlation entry point (confidence `external_only`).

describe('correlateExternalOnlyVerdict', () => {
  it('edge_protected when blocked with attested probe I/O and external_only confidence', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      probeIoObserved: true,
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'edge_protected');
    assert.equal(r.confidence, 'external_only');
    assert.equal(r.createsFinding, false);
  });

  it('edge_exposed when connected with external_only confidence', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'edge_exposed');
    assert.equal(r.confidence, 'external_only');
    assert.equal(r.createsFinding, true);
  });

  it('keeps blocked claims inconclusive without attested probe I/O', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'inconclusive');
    assert.match(r.explanation, /no attested probe I\/O/);
  });

  it('inconclusive for unknown external result', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'weird',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'inconclusive');
    assert.equal(r.confidence, 'external_only');
  });

  it('never describes a signed-worker probe as simulated', () => {
    for (const externalResult of ['blocked', 'connected', 'error']) {
      const r = correlateExternalOnlyVerdict({
        externalResult,
        expectedBehavior: 'must_block_before_origin',
        probeKind: 'http_head',
        probeIoObserved: true,
      });
      assert.doesNotMatch(r.explanation, /simulat/i, externalResult);
    }
  });
});

describe('evidence gaps are ignored for verdicts', () => {
  it('keeps unsigned marker responses inconclusive with the recorded reason and no finding', () => {
    for (const reason of ['authentication_gate_precedes_inspection', 'unattributed_denial', 'misdirected_request', 'probe_path_error', 'error_not_attributable']) {
      const r = correlateExternalOnlyVerdict({
        externalResult: 'not_run',
        expectedBehavior: 'must_block_before_origin',
        probeKind: 'waf_enforcement_probe',
        probeIoObserved: true,
        probeMetadata: { inconclusive_reason: reason },
      });
      assert.equal(r.verdict, 'inconclusive', reason);
      assert.equal(r.createsFinding, false);
      assert.doesNotMatch(r.explanation, /protected/i);
    }
  });

  it('keeps a CDN-edge answer on the direct-origin leg out of origin verdicts', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'error',
      expectedBehavior: 'must_block_before_origin',
      probeKind: 'host_sni_bypass',
      probeIoObserved: true,
      probeMetadata: { origin_observation: { semantics_version: 'external-observation-v2', outcome: 'not_applicable', status_code: 403 } },
    });
    assert.equal(r.verdict, 'inconclusive');
    assert.match(r.explanation, /CDN or WAF edge answered/);
  });
});

describe('correlateOpsReadinessVerdict', () => {
  it('protected/high when ops_validation_ok is true', () => {
    const r = correlateOpsReadinessVerdict({ externalResult: 'connected', opsValidationOk: true });
    assert.equal(r.verdict, 'protected');
    assert.equal(r.confidence, 'high');
    assert.equal(r.createsFinding, false);
    assert.match(r.explanation, /control-plane self-check/);
  });

  it('protected when ops_validation_ok is true even without connected external result', () => {
    const r = correlateOpsReadinessVerdict({ externalResult: undefined, opsValidationOk: true });
    assert.equal(r.verdict, 'protected');
    assert.equal(r.createsFinding, false);
  });

  it('inconclusive/low when ops_validation_ok is false', () => {
    const r = correlateOpsReadinessVerdict({ externalResult: 'error', opsValidationOk: false });
    assert.equal(r.verdict, 'inconclusive');
    assert.equal(r.confidence, 'low');
    assert.equal(r.createsFinding, false);
    assert.match(r.explanation, /could not be validated/);
  });

  it('inconclusive when connected but ops_validation_ok is not true (never creates a finding)', () => {
    const r = correlateOpsReadinessVerdict({ externalResult: 'connected', opsValidationOk: false });
    assert.equal(r.verdict, 'inconclusive');
    assert.equal(r.createsFinding, false);
  });
});
