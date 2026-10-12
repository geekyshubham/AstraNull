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
      assert.equal(check?.evidence_tier, 'E2', checkId);
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
        observation_only: true,
        readiness_conclusion: false,
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

  it('withholds findings and readiness credit for error, timeout and not-run outcomes across all 251 definitions', () => {
    assert.equal(CHECK_CATALOG.length, 251);
    for (const check of CHECK_CATALOG) {
      for (const externalResult of ['error', 'timeout', 'not_run']) {
        const result = correlateExternalOnlyVerdict({
          externalResult,
          probeKind: check.probe_profile?.kind,
          probeIoObserved: externalResult !== 'not_run',
          expectedBehavior: check.default_expected_behavior,
        });
        const label = `${check.check_id}/${externalResult}`;
        assert.equal(result.verdict, 'inconclusive', label);
        assert.equal(result.createsFinding, false, label);
        assert.equal(verdictSupportsReadiness(result.verdict), false, label);
      }
    }
  });

  it('keeps semantic probe errors and execution timeouts inconclusive in both modes', () => {
    for (const externalResult of ['error', 'not_run', 'timeout']) {
      const externalOnly = correlateExternalOnlyVerdict({
        externalResult,
        probeKind: 'origin_leak_scan',
        probeIoObserved: true,
        expectedBehavior: 'must_block_before_origin',
      });
      for (const result of [externalOnly]) {
        assert.equal(result.verdict, 'inconclusive', externalResult);
        assert.equal(result.createsFinding, false, externalResult);
        assert.equal(verdictSupportsReadiness(result.verdict), false, externalResult);
        assert.match(result.explanation, /did not establish|cannot establish protection or exposure/i);
      }
    }
  });
});


describe('catalog semantic contracts across all definitions and vector mappings', () => {
  it('IPP is explicitly unsupported and cannot be upgraded by a profile override or appear runnable', async () => {
    const { checkRequiresAdditionalInput, customerSelectableChecks } = await import('../../src/contracts/checks.mjs');
    const { probeReflectionService, probeAlertWebhookPing } = await import('../../src/lib/safeNetworkProbes.mjs');
    const { buildVectorTargetMatrix } = await import('../../src/contracts/vectorTargetMatrix.mjs');
    const ipp = getCheckById('reflect.ipp_callback_exposure.safe');
    assert.equal(ipp.mechanism_supported, false);
    assert.equal(ipp.probe_profile.delivery_supported, false);
    assert.equal(buildProbeProfile({ ...ipp.probe_profile, delivery_supported: true }).delivery_supported, false);
    const result = await probeReflectionService({ target: { value: '203.0.113.7:631' }, probe_profile: ipp.probe_profile,
      constraints: { max_requests: 2, timeout_ms: 500 } }, { connectFn: () => { throw new Error('unsupported IPP attempted connect'); } });
    assert.equal(result.external_result, 'not_run');
    assert.equal(result.requests_sent, 0);
    assert.equal(result.metadata.delivery_supported, false);
    assert.equal(result.metadata.readiness_conclusion, false);
    const matrix = buildVectorTargetMatrix();
    const row = matrix.rows.find((entry) => entry.vector_id === 'AMP-057');
    assert.equal(row.target_disposition, 'not_runnable');
    assert.deepEqual(row.runnable_safe_check_ids, []);
    assert.ok(row.blocked_safe_checks.some((entry) => entry.check_id === ipp.check_id && entry.reasons.includes('unsupported_delivery')));
    const alert = getCheckById('ops.alert_workflow_marker.safe');
    assert.equal(alert.evidence_tier, 'E2');
    assert.equal(alert.readiness_conclusion, false);
    assert.ok(alert.required_customer_setup.includes('approved_signed_alert_webhook_scope'));
    assert.equal(checkRequiresAdditionalInput(alert), true);
    assert.equal(customerSelectableChecks(CHECK_CATALOG).some((entry) => entry.check_id === alert.check_id), false);
    const ping = await probeAlertWebhookPing({ target: { value: 'fixture.example.test', metadata: { alert_webhook_url: 'https://fixture.example.test/hook' } },
      probe_profile: alert.probe_profile, constraints: { max_requests: 1, timeout_ms: 500 } },
      { fetchFn: () => { throw new Error('ordinary target metadata became callback authority'); } });
    assert.equal(ping.external_result, 'not_run');
    assert.equal(ping.requests_sent, 0);
    assert.equal(ping.metadata.readiness_conclusion, false);
  });

  it('standalone origin checks remain E2 because the single-request executor has no permitted-baseline producer', () => {
    for (const check of CHECK_CATALOG.filter((row) => row.probe_profile?.kind === 'host_sni_bypass')) {
      assert.equal(check.evidence_tier, 'E2', check.check_id);
      assert.equal(check.probe_profile.observation_only, true, check.check_id);
      assert.equal(check.probe_profile.readiness_conclusion, false, check.check_id);
      assert.equal(check.probe_profile.scenario_version, 'probe-observation-v3', check.check_id);
      const override = buildProbeProfile({ ...check.probe_profile, observation_only: false, readiness_conclusion: true,
        declared_origin_lockdown: { header: { name: 'x-unapproved', value: 'denied' } } });
      assert.equal(override.observation_only, true);
      assert.equal(override.readiness_conclusion, false);
      assert.equal(override.declared_origin_lockdown, undefined);
    }
  });

  it('validates all 251 definitions and preserves signed semantic flags on rebuild', async () => {
    const { validateCheckDefinition } = await import('../../src/contracts/checks.mjs');
    const { targetKindCompatibilityError } = await import('../../src/contracts/checkTargetCompatibility.mjs');
    const { CAPABILITY_PROBE_DISPATCH } = await import('../../src/lib/capabilityProbes.mjs');
    const basicKinds = new Set(['http_head', 'tcp_connect', 'dns_resolve', 'metadata_marker', 'udp_probe',
      'quic_reachability', 'alert_webhook_ping', 'ops_readiness', 'ownership_challenge',
      'tls_session', 'http2_settings', 'reflection_service_probe', 'dns_wire_query', 'websocket_upgrade_posture']);
    assert.equal(CHECK_CATALOG.length, 251);
    assert.equal(new Set(CHECK_CATALOG.map((row) => row.check_id)).size, 251);
    for (const check of CHECK_CATALOG) {
      assert.deepEqual(validateCheckDefinition(check), [], check.check_id);
      const profile = check.probe_profile;
      if (!profile) { assert.equal(check.safety_class, 'soc_gated'); continue; }
      assert.ok(basicKinds.has(profile.kind) || typeof CAPABILITY_PROBE_DISPATCH[profile.kind] === 'function', check.check_id);
      const rebuilt = buildProbeProfile(profile);
      for (const key of ['kind', 'max_requests', 'timeout_ms', 'scenario_version', 'classifier_version',
        'observation_only', 'readiness_conclusion', 'delivery_supported', 'requires_complete_comparison']) {
        if (profile[key] != null) assert.equal(rebuilt[key], profile[key], `${check.check_id}.${key}`);
      }
      for (const kind of ['fqdn', 'url', 'ip', 'tcp', 'dns', 'canary']) {
        const mismatch = targetKindCompatibilityError(check, { kind, value: 'fixture.example.test' });
        assert.equal(mismatch == null, check.supported_targets.includes(kind), `${check.check_id}/${kind}`);
      }
      if (check.observation_only || profile.readiness_conclusion === false) assert.notEqual(check.evidence_tier, 'E3', check.check_id);
      if (check.mechanism_supported === false) {
        assert.equal(profile.delivery_supported, false, check.check_id);
        assert.equal(profile.readiness_conclusion, false, check.check_id);
      }
    }
  });

  it('assigns all 721 unique mappings explicit dispositions without counting shared executors as independent mechanisms', async () => {
    const { buildVectorTargetMatrix } = await import('../../src/contracts/vectorTargetMatrix.mjs');
    const matrix = buildVectorTargetMatrix();
    assert.equal(matrix.rows.length, 721);
    assert.equal(new Set(matrix.rows.map((row) => row.vector_id)).size, 721);
    for (const row of matrix.rows) {
      assert.ok(['safe_runnable', 'additional_input_required', 'target_incompatible', 'soc_gated', 'monitor_only', 'not_runnable'].includes(row.target_disposition), row.vector_id);
      for (const id of row.runnable_safe_check_ids) assert.ok(CHECK_CATALOG.some((check) => check.check_id === id && check.safety_class === 'safe'), id);
    }
    assert.equal(matrix.summary.runnable_safe_check_count, 161);
    for (const id of matrix.runnable_safe_check_ids) {
      const check = CHECK_CATALOG.find((row) => row.check_id === id);
      assert.notEqual(check.mechanism_supported, false, id);
      assert.notEqual(check.probe_profile?.delivery_supported, false, id);
    }
    assert.ok(new Set(CHECK_CATALOG.filter((check) => check.mechanism_id).map((check) => check.mechanism_id)).size < 251);
  });

  it('fails closed for malformed applicability and semantic override attempts', async () => {
    const { validateCheckDefinition } = await import('../../src/contracts/checks.mjs');
    const { targetKindCompatibilityError } = await import('../../src/contracts/checkTargetCompatibility.mjs');
    const valid = CHECK_CATALOG.find((check) => check.probe_profile?.kind === 'http_head');
    for (const supported_targets of [undefined, [], ['url', null], ['unknown'], ['url', 'unknown']]) {
      const malformed = { ...valid, supported_targets };
      assert.ok(validateCheckDefinition(malformed).length);
      assert.equal(targetKindCompatibilityError(malformed, { kind: 'url', value: 'https://fixture.example.test/' }).status, 400);
    }
    for (const kind of OBSERVATION_ONLY_PROBE_KINDS.filter((value) => ALLOWED_PROBE_PROFILE_KINDS.includes(value))) {
      const profile = buildProbeProfile({ kind, observation_only: false, readiness_conclusion: true });
      assert.equal(profile.observation_only, true, kind);
      assert.equal(profile.readiness_conclusion, false, kind);
    }
    const unsupported = buildProbeProfile({ kind: 'waf_evasion_marker_probe', evasion_transform: 'framing_cl_te', delivery_supported: true, readiness_conclusion: true });
    assert.equal(unsupported.delivery_supported, false);
    assert.equal(unsupported.readiness_conclusion, false);
    assert.throws(() => buildProbeProfile({ kind: 'http_head', max_requests: 1.5 }), /positive integers/);
    assert.throws(() => buildProbeProfile({ kind: 'http_head', readiness_conclusion: 'true' }), /semantic flag/);
    assert.throws(() => buildProbeProfile({ kind: 'http_head', classifier_version: 'bad version' }), /semantic version/);
  });
});
