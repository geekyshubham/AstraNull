import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ALLOWED_PROBE_PROFILE_KINDS,
  CHECK_CATALOG,
  buildProbeProfile,
  getCheckById,
} from '../../src/contracts/checks.mjs';
import {
  OBSERVATION_ONLY_PROBE_KINDS,
  SEMANTIC_SAFE_PROBE_KINDS,
  evidenceTierForProbeKind,
} from '../../src/lib/probeEvidenceTiers.mjs';
import {
  correlateExternalOnlyVerdict,
  correlateVerdict,
  verdictSupportsReadiness,
} from '../../src/services/correlation.mjs';

const LIVE_UPGRADES = Object.freeze({
  'l7.slowloris.readiness': 'slow_header_probe',
  'l7.low_and_slow.readiness': 'slow_header_probe',
  'l7.hpack_bomb.readiness': 'http2_frame_probe',
  'origin.cdn_bypass.readiness': 'origin_leak_scan',
  'origin.dns_hostname_bypass.readiness': 'origin_leak_scan',
});

const INTENTIONALLY_DECLARATION_ONLY_EXAMPLES = Object.freeze([
  'l3.syn_flood.readiness',
  'l3.ack_flood.readiness',
  'l3.fragmentation_flood.readiness',
  'l7.http_post_flood.validation',
  'l7.large_body_post.readiness',
  'l7.json_xml_bomb.readiness',
  'l7.http2_priority_abuse.readiness',
  'l7.http2_push_promise.readiness',
  'protocol.websocket_message_rate.readiness',
  'tls.handshake_rate.readiness',
  'tls.zero_rtt.readiness',
]);

describe('honest declaration-only evidence upgrades', () => {
  it('promotes exactly the five checks backed by matching bounded executors', () => {
    const remainingMetadata = CHECK_CATALOG.filter(
      (check) => check.probe_profile?.kind === 'metadata_marker',
    );
    assert.equal(remainingMetadata.length, 72);

    for (const [checkId, kind] of Object.entries(LIVE_UPGRADES)) {
      const check = getCheckById(checkId);
      assert.equal(check?.probe_profile.kind, kind, checkId);
      assert.equal(check?.evidence_tier, 'E3', checkId);
    }
  });

  it('labels every E1 check as no-live-probe and requires stronger evidence', () => {
    const notice = /Declaration\/readiness only: no live network probe is executed; customer-provided control evidence or a SOC-governed test is required/i;
    for (const check of CHECK_CATALOG.filter((entry) => entry.evidence_tier === 'E1')) {
      assert.equal(check.probe_profile?.kind, 'metadata_marker', check.check_id);
      assert.match(check.description, notice, `${check.check_id} description`);
      assert.match(check.verdict_logic, notice, `${check.check_id} verdict_logic`);
      assert.match(check.explanation_template, notice, `${check.check_id} explanation`);
    }
  });

  it('keeps checks at E1 when an existing executor observes only a different property', () => {
    for (const checkId of INTENTIONALLY_DECLARATION_ONLY_EXAMPLES) {
      const check = getCheckById(checkId);
      assert.equal(check?.probe_profile.kind, 'metadata_marker', checkId);
      assert.equal(check?.evidence_tier, 'E1', checkId);
    }
  });

  it('allows only the reviewed HPACK SETTINGS assertion on HTTP/2 frame profiles', () => {
    assert.deepEqual(
      buildProbeProfile({
        kind: 'http2_frame_probe',
        max_requests: 1,
        settings_assertion: 'hpack_limits',
      }),
      {
        kind: 'http2_frame_probe',
        max_requests: 1,
        timeout_ms: 5000,
        settings_assertion: 'hpack_limits',
      },
    );
    assert.equal(
      'settings_assertion' in buildProbeProfile({
        kind: 'http2_frame_probe',
        settings_assertion: 'server_push',
      }),
      false,
    );
  });
});

describe('fail-closed evidence tiers and correlation', () => {
  it('maps every allowlisted profile kind explicitly and unknown/not-run kinds to E0', () => {
    for (const kind of ALLOWED_PROBE_PROFILE_KINDS) {
      assert.notEqual(evidenceTierForProbeKind(kind), 'E0', kind);
    }
    for (const kind of OBSERVATION_ONLY_PROBE_KINDS) {
      const expected = kind === 'metadata_marker' ? 'E1' : (kind === 'not_run' ? 'E0' : 'E2');
      assert.equal(evidenceTierForProbeKind(kind), expected, kind);
    }
    for (const kind of SEMANTIC_SAFE_PROBE_KINDS) {
      assert.equal(evidenceTierForProbeKind(kind), 'E3', kind);
    }
    assert.equal(evidenceTierForProbeKind('not_run'), 'E0');
    assert.equal(evidenceTierForProbeKind('typo_or_future_kind'), 'E0');
    assert.equal(evidenceTierForProbeKind(undefined), 'E0');
  });

  it('keeps semantic probe errors and execution timeouts inconclusive in both modes', () => {
    for (const externalResult of ['error', 'not_run', 'timeout']) {
      const correlated = correlateVerdict({
        externalResult,
        probeKind: 'origin_leak_scan',
        probeIoObserved: true,
        agentObserved: false,
        expectedBehavior: 'must_block_before_origin',
        agentOnline: true,
        agentBound: true,
      });
      const externalOnly = correlateExternalOnlyVerdict({
        externalResult,
        probeKind: 'origin_leak_scan',
        probeIoObserved: true,
        expectedBehavior: 'must_block_before_origin',
      });
      for (const result of [correlated, externalOnly]) {
        assert.equal(result.verdict, 'inconclusive', externalResult);
        assert.equal(result.createsFinding, false, externalResult);
        assert.equal(verdictSupportsReadiness(result.verdict), false, externalResult);
        assert.match(result.explanation, /cannot establish protection or exposure/i);
      }
    }
  });
});
