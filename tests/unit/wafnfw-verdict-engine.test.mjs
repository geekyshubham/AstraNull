import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  VERDICT_CAPABLE_PROBE_KINDS,
  isObservationOnlyProbeKind,
  isVerdictCapableProbeKind,
  OBSERVATION_ONLY_PROBE_KINDS,
} from '../../src/lib/probeEvidenceTiers.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { deriveWafSignalsFromBoundEvents } from '../../src/lib/wafBoundRunCorrelation.mjs';
import { coverageFrom, isCustomCanaryCheckId } from '../../src/lib/protectionCoverage.mjs';
import { SCENARIO_TO_CHECK } from '../../src/contracts/wafOrchestrator.mjs';
import { buildProtectionValidationReport } from '../../src/lib/protectionValidationReport.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion } from '../../src/lib/checkDefinitionVersion.mjs';
import { EXTERNAL_OBSERVATION_SEMANTICS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';

const denyTcp22 = {
  version: 1,
  network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }],
};

function nfw(kind, metadata, declarations, extra = {}) {
  return correlateExternalOnlyVerdict({
    probeKind: kind,
    externalResult: extra.externalResult ?? 'connected',
    expectedBehavior: extra.expectedBehavior ?? 'must_block_before_origin',
    probeIoObserved: true,
    probeMetadata: metadata,
    declarations,
    originBinding: extra.originBinding ?? null,
  });
}

describe('F28 verdict-capable allowlist', () => {
  it('exports VERDICT_CAPABLE_PROBE_KINDS and keeps isObservationOnlyProbeKind', () => {
    assert.ok(VERDICT_CAPABLE_PROBE_KINDS.includes('waf_class_marker_probe'));
    assert.ok(VERDICT_CAPABLE_PROBE_KINDS.includes('tcp_connect'));
    assert.ok(VERDICT_CAPABLE_PROBE_KINDS.includes('waf_method_policy_probe'));
    assert.ok(isVerdictCapableProbeKind('host_sni_bypass'));
    assert.ok(isVerdictCapableProbeKind('waf_method_policy_probe'));
    assert.equal(isObservationOnlyProbeKind('tcp_connect'), true);
    assert.equal(isObservationOnlyProbeKind('waf_class_marker_probe'), false);
    assert.ok(OBSERVATION_ONLY_PROBE_KINDS.includes('connection_limit_probe'));
    assert.ok(OBSERVATION_ONLY_PROBE_KINDS.includes('waf_method_policy_probe'));
  });

  it('never returns protected or exposed for a kind off the allowlist', () => {
    for (const probeKind of ['tls_audit', 'dnssec_posture', 'http_head', 'unrecognized_kind', undefined]) {
      for (const externalResult of ['blocked', 'connected']) {
        const result = correlateExternalOnlyVerdict({
          probeKind, externalResult, probeIoObserved: true, expectedBehavior: 'must_block_before_origin',
        });
        assert.ok(!['protected', 'exposed', 'edge_protected', 'edge_exposed'].includes(result.verdict), `${probeKind}/${externalResult}`);
      }
    }
  });
});

describe('F01 NFW violation-only verdict', () => {
  it('exposes a declared deny TCP handshake from a non-CDN peer', () => {
    const result = nfw('tcp_connect', {
      protocol: 'tcp', port: 22, tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree',
      address_family: 4, source_perspective: { id: 'default', label: 'default' },
    }, denyTcp22);
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.confidence, 'external_only');
    assert.equal(result.createsFinding, true);
    assert.equal(result.severity, 'high');
    assert.match(result.explanation, /tcp\/22/);
    assert.match(result.explanation, /ipv4/);
    assert.match(result.explanation, /default/);
    assert.match(result.explanation, /denial cannot be proven from outside/);
  });

  it('uses medium severity for a non-management deny port', () => {
    const declarations = { version: 1, network_policy: [{ protocol: 'tcp', port: 8080, action: 'deny', address_family: 'any' }] };
    const result = nfw('tcp_connect', { protocol: 'tcp', port: 8080, tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree', address_family: 4 }, declarations);
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'medium');
  });

  it('stays inconclusive on a CDN peer', () => {
    const result = nfw('tcp_connect', { protocol: 'tcp', port: 22, tcp_outcome: 'handshake', peer_is_cdn: true, sample_agreement: 'agree', address_family: 4 }, denyTcp22);
    assert.equal(result.verdict, 'inconclusive');
  });

  it('stays inconclusive when samples disagree', () => {
    const result = nfw('tcp_connect', { protocol: 'tcp', port: 22, tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'disagree', address_family: 4 }, denyTcp22);
    assert.equal(result.verdict, 'inconclusive');
  });

  it('stays inconclusive without a deny declaration', () => {
    const result = nfw('tcp_connect', { protocol: 'tcp', port: 22, tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree', address_family: 4 }, { version: 1, network_policy: [] });
    assert.equal(result.verdict, 'inconclusive');
  });

  it('never returns protected for NFW kinds', () => {
    for (const kind of ['tcp_connect', 'udp_probe', 'port_scan_bounded', 'reflection_service_probe', 'connection_limit_probe']) {
      const result = correlateExternalOnlyVerdict({
        probeKind: kind, externalResult: 'blocked', probeIoObserved: true,
        expectedBehavior: 'must_block_before_origin',
        probeMetadata: { tcp_outcome: 'refused_rst', port: 22, peer_is_cdn: false },
        declarations: denyTcp22,
      });
      assert.notEqual(result.verdict, 'protected', kind);
      assert.notEqual(result.verdict, 'edge_protected', kind);
    }
  });

  it('exposes a validated UDP reply against a declared deny', () => {
    const declarations = { version: 1, network_policy: [{ protocol: 'udp', port: 161, action: 'deny', address_family: 'any' }] };
    const result = nfw('udp_probe', { protocol: 'udp', port: 161, udp_outcome: 'validated_reply', peer_is_cdn: false, sample_agreement: 'agree', address_family: 4 }, declarations);
    assert.equal(result.verdict, 'exposed');
    assert.match(result.explanation, /udp\/161/);
  });

  it('exposes a port-scan open port that is declared deny', () => {
    const result = nfw('port_scan_bounded', {
      open_ports: [22, 443], peer_is_cdn: false, sample_agreement: 'agree',
      families: { ipv4: { open_ports: [22, 443] } },
    }, denyTcp22);
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'high');
  });

  it('exposes a protocol-validated reflector reply with no declaration when the service must not be reachable', () => {
    const result = nfw('reflection_service_probe', {
      protocol: 'udp', port: 11211, udp_outcome: 'validated_reply', peer_is_cdn: false, sample_agreement: 'agree',
    }, null, { expectedBehavior: 'must_not_be_reachable' });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'medium');
  });

  it('exposes a validated reflector reply as an open reflector regardless of catalog expected behavior', () => {
    const result = nfw('reflection_service_probe', {
      protocol: 'udp', port: 11211, udp_outcome: 'validated_reply', peer_is_cdn: false, sample_agreement: 'agree',
    }, null, { expectedBehavior: 'must_reach_canary' });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.metadata.exposure_basis, 'validated_reflector_reply');
    assert.doesNotMatch(result.explanation, /deny/i);
  });

  it('exposes connection-limit accepted_count above the declared limit', () => {
    const result = nfw('connection_limit_probe', { port: 443, accepted_count: 6, declared_limit: 3, attempted: 5 }, {
      version: 1, connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 3 }],
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'medium');
  });

  it('stays inconclusive when connection-limit does not exceed the declared limit', () => {
    const result = nfw('connection_limit_probe', { port: 443, accepted_count: 3, declared_limit: 3 }, null);
    assert.equal(result.verdict, 'inconclusive');
  });
});

describe('F14 IPv6 parity mismatch', () => {
  it('names the leaking family when only one family violates deny', () => {
    const declarations = {
      version: 1,
      network_policy: [
        { protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' },
      ],
    };
    const result = nfw('tcp_connect', {
      protocol: 'tcp', port: 22, tcp_outcome: 'handshake', peer_is_cdn: false, sample_agreement: 'agree',
      address_family: 4, parity: 'mismatch',
      families: {
        ipv4: { tcp_outcome: 'handshake', peer_is_cdn: false },
        ipv6: { tcp_outcome: 'refused_rst', peer_is_cdn: false },
      },
    }, declarations);
    assert.equal(result.verdict, 'exposed');
    assert.match(result.explanation, /leaking family/);
    assert.match(result.explanation, /ipv4/);
  });
});

describe('F17 F10 F02 challenge redirect penalty', () => {
  it('does not treat challenged as a block', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'challenged',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'challenged', posture_status: 'challenged' },
      declarations: { waf: { expected_action: 'block' } },
    });
    assert.equal(result.verdict, 'inconclusive');
    assert.match(result.explanation, /challenge/i);
  });

  it('protects when challenged matches a declared challenge expectation', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'challenged',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'challenged', posture_status: 'challenged' },
      declarations: { waf: { expected_action: 'challenge' } },
    });
    assert.equal(result.verdict, 'protected');
  });

  it('protects when challenged matches block_or_challenge', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'outside_in_waf_scan',
      externalResult: 'challenged',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'challenged' },
      declarations: { waf: { expected_action: 'block_or_challenge' } },
    });
    assert.equal(result.verdict, 'protected');
  });

  it('is inconclusive when source_penalized', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { source_penalized: true, enforcement: 'enforced', posture_status: 'source_penalized' },
    });
    assert.equal(result.verdict, 'inconclusive');
  });

  it('is inconclusive for redirected-only legs', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: {
        enforcement: 'unknown',
        placements: [
          { placement: 'query', outcome: 'redirected', location_changed: true },
          { placement: 'path', outcome: 'redirected', location_changed: true },
        ],
      },
    });
    assert.equal(result.verdict, 'inconclusive');
  });
});

describe('WAF class and managed markers', () => {
  it('protects when enforcement is enforced', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'enforced', assurance_scope: 'managed_rule_marker' },
    });
    assert.equal(result.verdict, 'protected');
    assert.equal(result.createsFinding, false);
  });

  it('exposes managed_rule_marker at medium when not_enforced', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'not_enforced', assurance_scope: 'managed_rule_marker' },
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'medium');
  });

  it('exposes custom_canary_rule at low and names the canary, not an attack class', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'not_enforced', assurance_scope: 'custom_canary_rule' },
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'low');
    assert.match(result.explanation, /custom canary rule for AstraNull's marker/);
    assert.doesNotMatch(result.explanation, /attack class blocked/i);
  });

  it('exposes partial at low and names unenforced placements', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: {
        enforcement: 'partial',
        assurance_scope: 'managed_rule_marker',
        placements: [
          { placement: 'query', outcome: 'blocked' },
          { placement: 'header', outcome: 'allowed', allowed: true },
        ],
      },
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'low');
    assert.match(result.explanation, /header/);
  });
});

describe('F05 F16 evasion symmetric', () => {
  it('exposes a normalization gap at medium for sqli', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_evasion_marker_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: {
        normalization_gap: true, reference_not_enforced: false,
        evasion_transform: 'double_url', marker_class: 'sqli',
        assurance_scope: 'inert_marker_rule_action_only',
      },
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'medium');
    assert.equal(result.explanation, 'normalization gap for double_url');
  });

  it('exposes a normalization gap at low for other families', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_evasion_marker_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { normalization_gap: true, evasion_transform: 'whitespace', marker_class: 'ssti' },
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'low');
  });

  it('is inconclusive when the reference marker is not enforced', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_evasion_marker_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { reference_not_enforced: true, normalization_gap: false },
    });
    assert.equal(result.verdict, 'inconclusive');
    assert.match(result.explanation, /managed-rule marker/);
  });
});

describe('F13 origin lockdown', () => {
  const binding = { id: 'ob_1', protected_target_id: 'tgt', origin_target_id: 'origin', status: 'active' };

  it('exposes a direct 2xx matching the baseline fingerprint from a non-CDN peer', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'host_sni_bypass',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      originBinding: binding,
      declarations: { origin: { lockdown_expected: true } },
      probeMetadata: {
        peer_is_cdn: false,
        application_bypass_confirmed: true,
        origin_observation: {
          semantics_version: EXTERNAL_OBSERVATION_SEMANTICS_VERSION,
          outcome: 'application_identity_confirmed',
          status_code: 200,
          application_bypass_confirmed: true,
          application_identity: { confirmed: true, method: 'nonce_canary' },
          baseline_comparable: true,
          baseline: 'healthy',
        },
      },
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'medium');
    assert.match(result.explanation, /origin was reachable directly/);
  });

  it('stays inconclusive on blocked, refused, or timeout', () => {
    for (const [externalResult, metadata] of [
      ['blocked', { origin_observation: { outcome: 'explicit_denial_observed', status_code: 403 } }],
      ['error', { origin_observation: { outcome: 'transport_error' } }],
      ['timeout', { origin_observation: { outcome: 'no_response' } }],
    ]) {
      const result = correlateExternalOnlyVerdict({
        probeKind: 'host_sni_bypass', externalResult, expectedBehavior: 'must_block_before_origin',
        probeIoObserved: true, originBinding: binding, probeMetadata: { peer_is_cdn: false, ...metadata },
      });
      assert.equal(result.verdict, 'inconclusive', externalResult);
    }
  });

  it('stays inconclusive without a declared origin binding', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'host_sni_bypass',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: {
        peer_is_cdn: false, application_bypass_confirmed: true,
        origin_observation: { outcome: 'application_identity_confirmed', status_code: 200, application_bypass_confirmed: true },
      },
    });
    assert.equal(result.verdict, 'inconclusive');
  });
});

describe('F22 rate-limit canary', () => {
  const canaryDeclarations = { waf: { rate_limit_canary: { threshold: 3, window_seconds: 10 } } };

  it('protects only when limited at threshold + 1 after the first threshold requests were allowed', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'rate_limit_canary_probe',
      externalResult: 'blocked',
      probeIoObserved: true,
      probeMetadata: { requests_sent: 4, first_limited_at: 4, allowed_before_limit: 3, limited_outcome: 'blocked' },
      declarations: canaryDeclarations,
    });
    assert.equal(result.verdict, 'protected');
  });

  it('exposes low when never limited', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'rate_limit_canary_probe',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: { requests_sent: 5, first_limited_at: null, limited_outcome: null, allowed_before_limit: 5 },
      declarations: canaryDeclarations,
    });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'low');
  });

  it('is inconclusive when limited after threshold + 2', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'rate_limit_canary_probe',
      externalResult: 'blocked',
      probeIoObserved: true,
      probeMetadata: { requests_sent: 8, first_limited_at: 7, limited_outcome: 'blocked' },
      declarations: canaryDeclarations,
    });
    assert.equal(result.verdict, 'inconclusive');
  });
});

describe('F08 readiness credit and custom-canary rollup', () => {
  it('rolls custom canary checks by distinct rule and keeps test clones independent', () => {
    assert.equal(isCustomCanaryCheckId('waf.ssrf_marker.safe'), true);
    assert.equal(isCustomCanaryCheckId('waf.sqli_managed_marker.safe'), false);
    assert.equal(isCustomCanaryCheckId('waf.test_marker_1.safe'), false);
    const ssrf = getCheckById('waf.ssrf_marker.safe');
    const xxe = getCheckById('waf.xxe_marker.safe');
    const clone = { ...structuredClone(ssrf), check_id: 'waf.test_marker_1.safe' };
    const catalog = [ssrf, xxe, clone];
    const now = '2026-10-04T12:00:00.000Z';
    const markerProof = {
      enforcement: 'enforced',
      classifier_version: 'marker-comparison-v4',
      comparison_complete: true,
      planned_marker_legs: 2,
      completed_marker_legs: 2,
      permitted_baseline_health: 'healthy',
    };
    const run = (check, id) => {
      const stamp = deriveCheckDefinitionVersion(check);
      return {
        id, target_id: 'tgt', tenant_id: 't', status: 'verdicted',
        completed_at: now, started_at: now, check_id: check.check_id,
        producer_kind: 'signed_probe', check_version: stamp.check_version,
        scenario_version: approvedScenarioVersion(check),
        probe_metadata: markerProof,
        readiness_result_metadata: [markerProof],
      };
    };
    const { coverage } = coverageFrom({
      target: { id: 'tgt', tenant_id: 't', kind: 'fqdn' },
      catalog,
      nowMs: Date.parse(now),
      observations: catalog.map((check, index) => ({
        check_id: check.check_id,
        evidence_verified: true,
        run: run(check, `run_${index}`),
        verdict: { verdict: 'protected', evidence_ids: ['e'] },
      })),
    });
    assert.equal(coverage.pairs.filter((pair) => pair.custom_canary_rollup).length, 0);
    assert.equal(coverage.pairs.some((pair) => pair.check_id === 'waf.test_marker_1.safe'), true);
    assert.ok(coverage.applicable_count <= 2);
  });

  it('credits dns zone transfer when enforcement is recorded', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'dns_axfr_leak',
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'enforced' },
    });
    assert.equal(result.verdict, 'protected');
  });
});

describe('F15 WAF bound-run posture', () => {
  it('excludes observation-only kinds from pass and fail', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_fp',
        nonce_hash: 'sha256:fp',
        metadata: { probe_kind: 'waf_fingerprint_observation', external_result: 'connected', waf_fingerprint_detected: true },
      }],
    });
    assert.equal(derived.validationFailed, false);
    assert.equal(derived.scenarioResults.length, 0);
  });

  it('maps SQLi/XSS/traversal to managed-marker checks and RCE to the SOC suite', () => {
    assert.equal(SCENARIO_TO_CHECK.sqli_marker, 'waf.sqli_managed_marker.safe');
    assert.equal(SCENARIO_TO_CHECK.xss_marker, 'waf.xss_managed_marker.safe');
    assert.equal(SCENARIO_TO_CHECK.path_traversal_marker, 'waf.path_traversal_managed_marker.safe');
    assert.equal(SCENARIO_TO_CHECK.rce_marker, 'waf.offensive_rce.soc');
    assert.notEqual(SCENARIO_TO_CHECK.sqli_marker, 'waf.marker_rule.safe');
  });
});

describe('call-site declaration wiring', () => {
  it('stamps grading, corpus and perspective onto the in-memory verdict shape', () => {
    const result = correlateExternalOnlyVerdict({
      probeKind: 'waf_class_marker_probe',
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: {
        enforcement: 'enforced',
        grading_version: 'waf-grading.v2',
        signature_corpus_version: 'waf-signatures.2026-10-13.2',
        source_perspective: { id: 'default' },
      },
      declarations: { waf: { expected_action: 'block' } },
    });
    assert.equal(result.verdict, 'protected');
  });
});

describe('F28 method-policy and perspective-allowlist verdicts', () => {
  it('maps method-policy enforcement to protected, not_enforced to exposed, and origin-only rejection to inconclusive', () => {
    const enforced = correlateExternalOnlyVerdict({
      probeKind: 'waf_method_policy_probe',
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'enforced', comparison_complete: true },
    });
    assert.equal(enforced.verdict, 'protected');
    const exposed = correlateExternalOnlyVerdict({
      probeKind: 'waf_method_policy_probe',
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
      probeIoObserved: true,
      probeMetadata: { enforcement: 'not_enforced', comparison_complete: true },
    });
    assert.equal(exposed.verdict, 'exposed');
    assert.equal(exposed.severity, 'low');
    const originReject = correlateExternalOnlyVerdict({
      probeKind: 'waf_method_policy_probe',
      externalResult: 'blocked',
      probeIoObserved: true,
      probeMetadata: {
        enforcement: 'not_enforced',
        inconclusive_reason: 'not_enforced_by_waf_but_rejected_by_origin',
      },
    });
    assert.equal(originReject.verdict, 'inconclusive');
    assert.match(originReject.explanation, /not_enforced_by_waf_but_rejected_by_origin/);
    const penalized = correlateExternalOnlyVerdict({
      probeKind: 'waf_method_policy_probe',
      externalResult: 'blocked',
      probeIoObserved: true,
      probeMetadata: { source_penalized: true, enforcement: 'enforced' },
    });
    assert.equal(penalized.verdict, 'inconclusive');
  });

  it('exposes a denied-perspective handshake and stays inconclusive otherwise', () => {
    const two = {
      ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([
        { id: 'eu', label: 'EU', egress_ips: [] },
        { id: 'us', label: 'US', egress_ips: [] },
      ]),
    };
    const exposed = correlateExternalOnlyVerdict({
      probeKind: 'tcp_connect',
      checkId: 'nfw.perspective_allowlist.safe',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: { tcp_outcome: 'handshake', source_perspective: { id: 'eu', label: 'EU' }, claimed_perspective_id: 'eu', perspective_authenticated: true },
      declarations: { perspectives: { denied_perspective_ids: ['eu'] } },
      env: two,
    });
    assert.equal(exposed.verdict, 'exposed');
    assert.equal(exposed.severity, 'medium');
    assert.match(exposed.explanation, /eu/);
    const other = correlateExternalOnlyVerdict({
      probeKind: 'tcp_connect',
      checkId: 'nfw.perspective_allowlist.safe',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: { tcp_outcome: 'handshake', source_perspective: { id: 'us' } },
      declarations: { perspectives: { denied_perspective_ids: ['eu'] } },
      env: two,
    });
    assert.equal(other.verdict, 'inconclusive');
    const one = correlateExternalOnlyVerdict({
      probeKind: 'tcp_connect',
      checkId: 'nfw.perspective_allowlist.safe',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: { tcp_outcome: 'handshake', source_perspective: { id: 'default' } },
      declarations: { perspectives: { denied_perspective_ids: ['default'] } },
      env: {},
    });
    assert.equal(one.verdict, 'inconclusive');
    assert.match(one.explanation, /two registered probe perspectives/);
  });
});

describe('F13 origin-lockdown coverage row', () => {
  it('reads Not assessable when no origin is declared', () => {
    const report = buildProtectionValidationReport({
      tenantId: 'ten',
      generatedAt: new Date('2026-10-04T12:00:00.000Z'),
      targets: [{ id: 'tgt', tenant_id: 'ten', kind: 'fqdn', value: 'app.example.test' }],
      checkCatalog: [],
    });
    assert.equal(report.origin_lockdown.status, 'not_assessable');
    assert.equal(report.origin_lockdown.display, 'Not assessable');
    assert.equal(report.origin_lockdown.reason, 'no_origin_declared');
    assert.equal(report.origin_lockdown.applicable_count, 0);
  });
});
