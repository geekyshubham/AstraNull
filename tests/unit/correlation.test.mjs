import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  correlateExternalOnlyVerdict,
  correlateOpsReadinessVerdict,
  probeResultCompletesEvidence,
} from '../../src/services/correlation.mjs';

// ADR-0008: agents are removed. Verdicts come from external probe evidence only, so the
// former agent-corroborated `correlateVerdict` truth table is gone. `correlateExternalOnlyVerdict`
// is the sole safe-run correlation entry point (confidence `external_only`).

describe('correlateExternalOnlyVerdict', () => {
  it('edge_protected when blocked with attested probe I/O and external_only confidence', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      probeKind: 'outside_in_waf_scan',
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
      probeKind: 'outside_in_waf_scan',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'edge_exposed');
    assert.equal(r.confidence, 'external_only');
    assert.equal(r.createsFinding, true);
  });

  it('never treats a timeout as protection when kind metadata is absent or malformed', () => {
    for (const probeKind of [undefined, null, '', 0, {}, 'unrecognized_kind']) {
      for (const expectedBehavior of ['must_block_before_origin', 'must_reach_canary']) {
        for (const probeIoObserved of [false, true]) {
          const result = correlateExternalOnlyVerdict({ externalResult: 'timeout', probeKind, expectedBehavior, probeIoObserved });
          assert.equal(result.verdict, 'inconclusive');
          assert.equal(result.createsFinding, false);
          assert.equal(result.confidence, 'external_only');
        }
      }
    }
  });

  it('keeps blocked claims inconclusive without attested probe I/O', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      probeKind: 'outside_in_waf_scan',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'inconclusive');
    assert.match(r.explanation, /no attested probe I\/O/);
  });

  it('inconclusive for unknown external result', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'weird',
      probeKind: 'outside_in_waf_scan',
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
        probeKind: 'outside_in_waf_scan',
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

describe('WAF/CDN fingerprint observation explanation', () => {
  const akamaiCdnOnly = {
    baseline_status_code: 302,
    edge_signature: {
      waf_present: null,
      layers: [{ family: 'cdn', provider: 'akamai', display_name: 'Akamai', sources: ['asn_lookup'] }],
    },
  };

  it('names the observed provider and source while staying inconclusive without a finding', () => {
    const result = correlateExternalOnlyVerdict({ externalResult: 'connected', probeKind: 'waf_fingerprint_observation', probeIoObserved: true, probeMetadata: akamaiCdnOnly });
    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.createsFinding, false);
    assert.match(result.explanation, /^Observed Akamai \(CDN, from address range\) on an HTTP 302 response\./);
    assert.match(result.explanation, /No WAF was identified: one ordinary GET cannot establish WAF presence or blocking/);
  });

  it('reports a detected WAF without claiming enforcement', () => {
    const result = correlateExternalOnlyVerdict({ externalResult: 'connected', probeKind: 'waf_fingerprint_observation', probeIoObserved: true, probeMetadata: {
      baseline_status_code: 200,
      edge_signature: { waf_present: true, layers: [{ family: 'waf', display_name: 'Cloudflare', sources: ['response_header'] }, { family: 'cdn', display_name: 'Cloudflare', sources: ['address_range', 'response_header'] }] },
    } });
    assert.equal(result.verdict, 'inconclusive');
    assert.match(result.explanation, /^Observed Cloudflare \(WAF, from response headers\), Cloudflare \(CDN, from address range and response headers\) on an HTTP 200 response\./);
    assert.match(result.explanation, /does not establish that requests are blocked/);
  });

  it('names layers whose stored display name is empty instead of dropping them', () => {
    const result = correlateExternalOnlyVerdict({ externalResult: 'connected', probeKind: 'waf_fingerprint_observation', probeIoObserved: true, probeMetadata: {
      baseline_status_code: 301,
      edge_signature: { waf_present: false, layers: [{ family: 'cdn', provider: 'cloudfront', display_name: '', sources: ['response_header', 'address_range'] }, { family: 'cloud', provider: 'aws', display_name: 'AWS', sources: ['address_range', 'asn_lookup'] }] },
    } });
    assert.match(result.explanation, /^Observed Amazon CloudFront \(CDN, from response headers and address range\), AWS \(CLOUD, from address range\) on an HTTP 301 response\./);
  });

  it('does not claim HTTP signals were evaluated when the ordinary GET timed out', () => {
    const result = correlateExternalOnlyVerdict({ externalResult: 'timeout', probeKind: 'waf_fingerprint_observation', probeIoObserved: true, probeMetadata: {
      error_class: 'probe_job_deadline_exceeded',
      edge_signature: { waf_present: null, layers: [{ family: 'cdn', provider: 'akamai', display_name: 'Akamai', sources: ['cname_suffix', 'asn_lookup'] }] },
    } });
    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.explanation, 'The ordinary GET timed out (probe_job_deadline_exceeded), so HTTP fingerprints were not evaluated. DNS and address signals show Akamai (CDN, from DNS CNAME and address range). WAF presence and blocking remain unverified.');
  });

  it('says nothing was identified when no provider signal matched', () => {
    const result = correlateExternalOnlyVerdict({ externalResult: 'connected', probeKind: 'waf_fingerprint_observation', probeIoObserved: true, probeMetadata: { baseline_status_code: 200, edge_signature: { waf_present: false, layers: [] } } });
    assert.match(result.explanation, /^No CDN or WAF provider was identified from HTTP, DNS or address signals on an HTTP 200 response\./);
  });
});

describe('probeResultCompletesEvidence', () => {
  it('is true only when the probe result is the sole required evidence', () => {
    assert.equal(probeResultCompletesEvidence({ evidence_required: ['probe_result'] }), true);
    assert.equal(probeResultCompletesEvidence({ evidence_required: ['probe_result', 'health_signal'] }), false);
    assert.equal(probeResultCompletesEvidence({ evidence_required: ['customer_declaration'] }), false);
    assert.equal(probeResultCompletesEvidence(null), false);
  });
});
