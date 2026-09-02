import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  correlateExternalOnlyVerdict,
  correlateOpsReadinessVerdict,
  correlateVerdict,
  verdictSupportsReadiness,
} from '../../src/services/correlation.mjs';

describe('correlation truth table', () => {
  it('protected when blocked and not observed', () => {
    const r = correlateVerdict({
      externalResult: 'blocked',
      probeIoObserved: true,
      agentObserved: false,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'protected');
    assert.equal(r.confidence, 'medium');
  });

  it('keeps blocked/timeout claims inconclusive without attested probe I/O', () => {
    for (const externalResult of ['blocked', 'timeout']) {
      const correlated = correlateVerdict({
        externalResult,
        agentObserved: false,
        expectedBehavior: 'must_block_before_origin',
        agentOnline: true,
        agentBound: true,
      });
      const externalOnly = correlateExternalOnlyVerdict({
        externalResult,
        expectedBehavior: 'must_block_before_origin',
      });
      assert.equal(correlated.verdict, 'inconclusive', externalResult);
      assert.equal(externalOnly.verdict, 'inconclusive', externalResult);
      assert.match(correlated.explanation, /no attested probe I\/O/);
      assert.match(externalOnly.explanation, /no attested probe I\/O/);
    }
  });

  it('bypassable when connected and observed', () => {
    const r = correlateVerdict({
      externalResult: 'connected',
      agentObserved: true,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'bypassable');
    assert.equal(r.createsFinding, true);
  });

  it('penetrated when blocked but observed', () => {
    const r = correlateVerdict({
      externalResult: 'timeout',
      probeIoObserved: true,
      agentObserved: true,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'penetrated');
  });

  it('misplaced when connected without observation', () => {
    const r = correlateVerdict({
      externalResult: 'allowed',
      agentObserved: false,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'misplaced_agent');
  });
});

describe('observation-only correlation truthfulness', () => {
  for (const scenario of [
    { label: 'healthy DNS lookup', probeKind: 'dns_resolve', externalResult: 'connected' },
    { label: 'alert webhook delivery', probeKind: 'alert_webhook_ping', externalResult: 'connected' },
    { label: 'UDP silence', probeKind: 'udp_probe', externalResult: 'timeout' },
    { label: 'HTTP/2 settings metadata', probeKind: 'http2_settings', externalResult: 'connected' },
    { label: 'TLS session metadata', probeKind: 'tls_session', externalResult: 'connected' },
    { label: 'HTTP method policy metadata', probeKind: 'http_method_matrix', externalResult: 'connected' },
    { label: 'HTTP/3 Alt-Svc metadata', probeKind: 'http3_control_probe', externalResult: 'connected' },
  ]) {
    it(`${scenario.label} stays inconclusive and creates no finding/readiness`, () => {
      const correlated = correlateVerdict({
        externalResult: scenario.externalResult,
        agentObserved: scenario.externalResult === 'connected',
        expectedBehavior: 'must_block_before_origin',
        agentOnline: true,
        agentBound: true,
        probeKind: scenario.probeKind,
      });
      const externalOnly = correlateExternalOnlyVerdict({
        externalResult: scenario.externalResult,
        expectedBehavior: 'must_block_before_origin',
        probeKind: scenario.probeKind,
      });

      for (const result of [correlated, externalOnly]) {
        assert.equal(result.verdict, 'inconclusive');
        assert.equal(result.createsFinding, false);
        assert.equal(verdictSupportsReadiness(result.verdict), false);
        assert.match(result.explanation, /metadata only|did not establish/);
      }
    });
  }

  it('retains connected-as-weakness for a dedicated semantic AXFR probe', () => {
    const result = correlateVerdict({
      externalResult: 'connected',
      agentObserved: true,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
      probeKind: 'dns_axfr_leak',
    });
    assert.equal(result.verdict, 'bypassable');
    assert.equal(result.createsFinding, true);
    assert.equal(verdictSupportsReadiness(result.verdict), true);
  });
});

describe('correlateExternalOnlyVerdict', () => {
  it('edge_protected when blocked with external_only confidence', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      probeIoObserved: true,
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'edge_protected');
    assert.equal(r.confidence, 'external_only');
    assert.equal(r.placement, 'unverified');
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

  it('inconclusive for unknown external result', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'weird',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'inconclusive');
    assert.equal(r.confidence, 'external_only');
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