import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { getCheckById, checkRequiresAdditionalInput, targetInputRefusal, rawTargetInputRefusal } from '../../src/contracts/checks.mjs';
import { normalizeControlDeclarations } from '../../src/contracts/controlDeclarations.mjs';
import { catalogRuleCoverage } from '../../src/contracts/ruleCoverage.mjs';
import { sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';
import { runWafClassMarkerProbe } from '../../src/lib/vectorProbes/wafClassProbes.mjs';
import { buildVerdictReplay } from '../../src/lib/verdictReplay.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { planFixVerifiedFromRetest, computeDenyRulesDigest } from '../../src/lib/findingLifecycle.mjs';
import { PROBE_EVENT_RESERVED_METADATA_KEYS, sanitizeWorkerProbeMetadata } from '../../src/lib/probeResultValidation.mjs';
import { versionGapFor, observationAssuranceGap } from '../../src/lib/protectionCoverage.mjs';
import { gradingSignatureVersionGap, approvedScenarioVersion, deriveCheckDefinitionVersion, verdictExpectedBehaviorForRun } from '../../src/lib/checkDefinitionVersion.mjs';
import { WAF_GRADING_VERSION, SIGNATURE_CORPUS_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import { assertProbeDestinationAllowed } from '../../src/lib/probeEndpoint.mjs';
import { classifyFirewallChangeItem } from '../../src/lib/firewallChangeAcceptance.mjs';

describe('R4 Verifier round-3 regression tests', () => {
  describe('Item 1: Verdict replay marker placement grading', () => {
    it('protected run with real probe output replays as protected with changed: false', async () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const fakeFetch = async (url, init) => {
        const carriesMarker = String(url).includes('astranull')
          || Boolean(init?.headers?.['x-astranull-marker'])
          || Boolean(init?.headers?.['user-agent']?.includes('astranull'));
        if (carriesMarker) {
          return new Response('blocked', { status: 403, headers: { 'content-type': 'text/plain', 'x-waf-block': '1' } });
        }
        return new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } });
      };

      const raw = await runWafClassMarkerProbe({
        url: 'https://example.com/app',
        marker_class: check.probe_profile?.marker_class ?? 'sqli',
        profile: check.probe_profile,
        fetchFn: fakeFetch,
      });

      const sanitized = sanitizeProbeMetadata(raw.metadata ?? raw);
      sanitized.safety_attestation = { probe_requests_sent: raw.requests_sent };
      assert.ok(sanitized.baseline, 'must store baseline feature');

      const replay = buildVerdictReplay({
        run: { id: 'r1', check_id: check.check_id },
        storedVerdict: { verdict: 'protected' },
        probeEvent: { metadata: sanitized },
      });

      assert.equal(replay.regraded, true);
      assert.equal(replay.rederived.verdict, 'protected');
      assert.equal(replay.changed, false);
    });

    it('returns baseline_not_recorded and regraded: false when baseline feature is missing', () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const replay = buildVerdictReplay({
        run: { id: 'r1', check_id: check.check_id },
        storedVerdict: { verdict: 'protected' },
        probeEvent: {
          metadata: {
            classifier_version: 'marker-comparison-v4',
            response_features: [
              { path: '/app', leg: 'query', status_code: 403, header_subset: { 'x-amz-cf-id': 'cf-1' } },
            ],
          },
        },
      });

      assert.equal(replay.regraded, false);
      assert.equal(replay.regrade_unavailable_reason, 'baseline_not_recorded');
    });
  });

  describe('Item 2: N12 closure gate tightening', () => {
    const id = 'nfw.declared_deny_tcp.safe';
    const decl = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };
    const P = { id: 'default', label: 'Default' };
    const finding = { id: 'f1', status: 'open', check_id: id, target_id: 't1', source_perspective: P, declared_deny_ports: [22], declaration_digest: computeDenyRulesDigest(decl) };

    it('stays open on local_error (EACCES)', () => {
      const md = {
        tcp_outcome: 'error', local_error: true, error_class: 'EACCES',
        samples: [{ tcp_outcome: 'error', local_error: true }, { tcp_outcome: 'error', local_error: true }],
        sample_agreement: 'agree', port: 22, protocol: 'tcp', address: '198.51.100.7', address_family: 4,
        source_perspective: P, declared_deny_ports: [22], ports_probed: [22], unprobed_deny_ports: [],
      };
      const run = { id: 'r2', check_id: id, target_id: 't1', status: 'verdicted', probe_profile: { kind: 'tcp_connect' }, probe_metadata: md };
      const verdict = { id: 'v2', check_id: id, target_id: 't1', verdict: 'inconclusive', creates_finding: false, source_perspective: P };
      const plan = planFixVerifiedFromRetest({ finding, run, verdict, declarations: decl });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'local_probe_error');
    });

    it('stays open on peer_is_cdn', () => {
      const md = {
        tcp_outcome: 'handshake', peer_is_cdn: true,
        samples: [{ tcp_outcome: 'handshake', peer_is_cdn: true }, { tcp_outcome: 'handshake', peer_is_cdn: true }],
        sample_agreement: 'agree', port: 22, protocol: 'tcp', address: '198.51.100.7', address_family: 4,
        source_perspective: P, declared_deny_ports: [22], ports_probed: [22], unprobed_deny_ports: [],
      };
      const run = { id: 'r2', check_id: id, target_id: 't1', status: 'verdicted', probe_profile: { kind: 'tcp_connect' }, probe_metadata: md };
      const verdict = { id: 'v2', check_id: id, target_id: 't1', verdict: 'inconclusive', creates_finding: false, source_perspective: P };
      const plan = planFixVerifiedFromRetest({ finding, run, verdict, declarations: decl });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'peer_is_cdn');
    });

    it('stays open on immediate_enetunreach (path not proven)', () => {
      const md = {
        tcp_outcome: 'rejected_icmp', icmp: { kind: 'net_unreachable', errno: 'ENETUNREACH' }, elapsed_ms: 0,
        samples: [{ tcp_outcome: 'rejected_icmp', elapsed_ms: 0 }, { tcp_outcome: 'rejected_icmp', elapsed_ms: 0 }],
        sample_agreement: 'agree', port: 22, protocol: 'tcp', address: '198.51.100.7', address_family: 4,
        source_perspective: P, declared_deny_ports: [22], ports_probed: [22], unprobed_deny_ports: [],
      };
      const run = { id: 'r2', check_id: id, target_id: 't1', status: 'verdicted', probe_profile: { kind: 'tcp_connect' }, probe_metadata: md };
      const verdict = { id: 'v2', check_id: id, target_id: 't1', verdict: 'inconclusive', creates_finding: false, source_perspective: P };
      const plan = planFixVerifiedFromRetest({ finding, run, verdict, declarations: decl });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'path_not_proven');
    });

    it('stays open when declaration changed', () => {
      const md = {
        tcp_outcome: 'timeout',
        samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
        sample_agreement: 'agree', port: 22, protocol: 'tcp', address: '198.51.100.7', address_family: 4,
        source_perspective: P, declared_deny_ports: [22], ports_probed: [22], unprobed_deny_ports: [],
      };
      const run = { id: 'r2', check_id: id, target_id: 't1', status: 'verdicted', probe_profile: { kind: 'tcp_connect' }, probe_metadata: md };
      const verdict = { id: 'v2', check_id: id, target_id: 't1', verdict: 'inconclusive', creates_finding: false, source_perspective: P };
      const changedDecl = { version: 1, network_policy: [{ protocol: 'tcp', port: 80, action: 'deny', address_family: 'any' }] };
      const plan = planFixVerifiedFromRetest({ finding, run, verdict, declarations: changedDecl });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'declaration_changed');
    });

    it('moves to fix_verified when every sample is a non-violation and declarations intact', () => {
      const md = {
        tcp_outcome: 'timeout',
        samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
        sample_agreement: 'agree', port: 22, protocol: 'tcp', address: '198.51.100.7', address_family: 4,
        source_perspective: P, declared_deny_ports: [22], ports_probed: [22], unprobed_deny_ports: [],
      };
      const run = { id: 'r2', check_id: id, target_id: 't1', status: 'verdicted', probe_profile: { kind: 'tcp_connect' }, probe_metadata: md };
      const verdict = { id: 'v2', check_id: id, target_id: 't1', verdict: 'inconclusive', creates_finding: false, source_perspective: P };
      const plan = planFixVerifiedFromRetest({ finding, run, verdict, declarations: decl });
      assert.equal(plan.action, 'fix_verified');
      assert.equal(plan.verification_basis, 'violation_not_reproduced');
    });
  });

  describe('Item 3: Rate-limit canary expected_action normalization and correlation', () => {
    it('accepts block and block_or_challenge for rate_limit_canary', () => {
      const norm1 = normalizeControlDeclarations({
        waf: { rate_limit_canary: { path: '/api', method: 'GET', threshold: 5, window_seconds: 10, expected_action: 'block' } },
      });
      assert.equal(norm1.waf.rate_limit_canary.expected_action, 'block');

      const norm2 = normalizeControlDeclarations({
        waf: { rate_limit_canary: { path: '/api', method: 'GET', threshold: 5, window_seconds: 10, expected_action: 'block_or_challenge' } },
      });
      assert.equal(norm2.waf.rate_limit_canary.expected_action, 'block_or_challenge');

      assert.throws(() => {
        normalizeControlDeclarations({
          waf: { rate_limit_canary: { path: '/api', method: 'GET', threshold: 5, window_seconds: 10, expected_action: 'invalid_action' } },
        });
      });
    });

    it('credits challenge when expected_action is block_or_challenge', () => {
      const decl = {
        waf: { rate_limit_canary: { threshold: 2, window_seconds: 10, expected_action: 'block_or_challenge' } },
      };
      const v = correlateExternalOnlyVerdict({
        probeKind: 'rate_limit_canary_probe',
        probeIoObserved: true,
        probeMetadata: { requests_sent: 5, first_limited_at: 3, first_limited_action: 'challenge' },
        declarations: decl,
      });
      assert.equal(v.verdict, 'protected');
    });
  });

  describe('Item 4: Rate-limit threshold from declarations only', () => {
    it('reserves threshold and window_seconds in probeResultValidation', () => {
      assert.ok(PROBE_EVENT_RESERVED_METADATA_KEYS.has('threshold'));
      assert.ok(PROBE_EVENT_RESERVED_METADATA_KEYS.has('window_seconds'));
      const sanitized = sanitizeWorkerProbeMetadata({ threshold: 5, window_seconds: 10, other: 'kept' });
      assert.equal(sanitized.threshold, undefined);
      assert.equal(sanitized.window_seconds, undefined);
      assert.equal(sanitized.other, 'kept');
    });

    it('returns inconclusive if declarations omit rate_limit_canary', () => {
      const v = correlateExternalOnlyVerdict({
        probeKind: 'rate_limit_canary_probe',
        probeMetadata: { requests_sent: 5, first_limited_at: 3, first_limited_action: 'block' },
        declarations: null,
      });
      assert.equal(v.verdict, 'inconclusive');
    });
  });

  describe('Item 5: Catalog rule coverage', () => {
    it('connection_limits is violation_only, allowlists_geo is violation_only, rate_limiting is verdict', () => {
      const coverage = catalogRuleCoverage();
      const conn = coverage.categories.find((c) => c.id === 'connection_limits');
      assert.equal(conn.assurance, 'violation_only');

      const geo = coverage.categories.find((c) => c.id === 'allowlists_geo');
      assert.equal(geo.assurance, 'violation_only');

      const rate = coverage.categories.find((c) => c.id === 'rate_limiting');
      assert.equal(rate.assurance, 'verdict');
    });

    it('declaration-gated checks are not marked not_assessable', () => {
      const coverage = catalogRuleCoverage();
      const gatedIds = [
        'nfw.declared_deny_tcp.safe',
        'nfw.declared_deny_udp.safe',
        'nfw.connection_limit.safe',
        'waf.rate_limit_canary.validation',
        'nfw.origin_lockdown.safe',
        'nfw.perspective_allowlist.safe',
      ];
      const allChecks = coverage.categories.flatMap((c) => c.checks);
      for (const id of gatedIds) {
        const check = allChecks.find((c) => c.check_id === id);
        assert.ok(check, `check ${id} must exist in catalog coverage`);
        assert.notEqual(check.assurance, 'not_assessable', `${id} must not be not_assessable`);
        assert.ok(Array.isArray(check.required_declarations) && check.required_declarations.length > 0, `${id} must list required_declarations`);
      }
    });
  });

  describe('Item 6: N9 readiness projection worker versions', () => {
    it('completed graded WAF run omitting worker versions gets version_not_reported', () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const current = deriveCheckDefinitionVersion(check);
      const scenario = approvedScenarioVersion(check);
      const run = {
        check_id: check.check_id,
        status: 'verdicted',
        check_version: current.check_version,
        ...(scenario ? { scenario_version: scenario } : {}),
        provenance_json: {
          grading_version: WAF_GRADING_VERSION,
          signature_corpus_version: SIGNATURE_CORPUS_VERSION,
        },
      };
      const verdict = { verdict: 'protected' };
      const gap = versionGapFor(check, run, verdict);
      assert.equal(gap, 'version_not_reported');
    });

    it('completed graded WAF run reading worker versions from readiness_result_metadata passes', () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const current = deriveCheckDefinitionVersion(check);
      const scenario = approvedScenarioVersion(check);
      const run = {
        check_id: check.check_id,
        status: 'verdicted',
        check_version: current.check_version,
        ...(scenario ? { scenario_version: scenario } : {}),
        readiness_result_metadata: [{
          grading_version: WAF_GRADING_VERSION,
          signature_corpus_version: SIGNATURE_CORPUS_VERSION,
        }],
      };
      const verdict = { verdict: 'protected' };
      const gap = versionGapFor(check, run, verdict);
      assert.equal(gap, null);
    });
  });

  describe('Item 7: F07 class forbidden port checks', () => {
    it('l3.forbidden_tcp_port.safe declares port_or_declared_tcp_deny but never blocks', () => {
      const check = getCheckById('l3.forbidden_tcp_port.safe');
      assert.deepEqual(check.runnable_requires, ['port_or_declared_tcp_deny']);
      assert.equal(checkRequiresAdditionalInput(check, { kind: 'fqdn', value: 'example.com' }), false);
      assert.equal(targetInputRefusal(check, { kind: 'fqdn', value: 'example.com' }), null);
      assert.equal(checkRequiresAdditionalInput(check, { kind: 'tcp', value: 'example.com:22', port: 22 }), false);
    });

    it('l3.forbidden_udp_port.safe declares port_or_declared_udp_deny but never blocks', () => {
      const check = getCheckById('l3.forbidden_udp_port.safe');
      assert.deepEqual(check.runnable_requires, ['port_or_declared_udp_deny']);
      assert.equal(checkRequiresAdditionalInput(check, { kind: 'fqdn', value: 'example.com' }), false);
      assert.equal(targetInputRefusal(check, { kind: 'fqdn', value: 'example.com' }), null);
      assert.equal(checkRequiresAdditionalInput(check, { kind: 'udp', value: 'example.com:53', port: 53 }), false);
    });
  });

  describe('Item 8: N3 residuals', () => {
    it('path proof strictly matches address family', () => {
      const baselines = [{
        test_run_id: 'r_base', observation_class: 'reachable_transport_only',
        source_perspective: 'us-1', address_family: 4, elapsed_ms: 10,
      }];
      const candidates = [{
        test_run_id: 'r_cand', observation_class: 'rejected_icmp',
        source_perspective: 'us-1', address_family: 6, elapsed_ms: 10,
      }];
      const result = classifyFirewallChangeItem({
        expectation: { expected: 'deny', protocol: 'tcp' },
        baselineObservations: baselines,
        candidateObservations: candidates,
        compatibility: { comparable: true, reasons: [] },
      });
      assert.equal(result.status, 'inconclusive');
      assert.ok(result.reasons.includes('path_not_proven'));
    });

    it('immediate baseline reject is gated and not treated as prior deny', () => {
      const baselines = [{
        test_run_id: 'r_base', observation_class: 'rejected_icmp',
        source_perspective: 'us-1', address_family: 4, elapsed_ms: 0,
      }];
      const candidates = [{
        test_run_id: 'r_cand', observation_class: 'rejected_icmp',
        source_perspective: 'us-1', address_family: 4, elapsed_ms: 10,
      }];
      const result = classifyFirewallChangeItem({
        expectation: { expected: 'deny', protocol: 'tcp' },
        baselineObservations: baselines,
        candidateObservations: candidates,
        compatibility: { comparable: true, reasons: [] },
      });
      assert.equal(result.status, 'inconclusive');
    });

    it('does not mutate caller observation objects', () => {
      const candidate = {
        test_run_id: 'r_cand', observation_class: 'rejected_icmp',
        source_perspective: 'us-1', address_family: 4, elapsed_ms: 0,
      };
      const baselines = [];
      const candidates = [candidate];
      classifyFirewallChangeItem({
        expectation: { expected: 'deny', protocol: 'tcp' },
        baselineObservations: baselines,
        candidateObservations: candidates,
        compatibility: { comparable: true, reasons: [] },
      });
      assert.equal(candidate.local_error, undefined);
      assert.equal(candidate.reason, undefined);
    });
  });

  describe('Item 10: Guard residuals', () => {
    it('denies SIIT ::ffff:0:0:0/96 and 0.0.0.0/8', () => {
      assert.equal(assertProbeDestinationAllowed('0.0.0.1').ok, false);
      assert.equal(assertProbeDestinationAllowed('0.255.255.255').ok, false);
      assert.equal(assertProbeDestinationAllowed('::ffff:0:127.0.0.1').ok, false);
      assert.equal(assertProbeDestinationAllowed('::ffff:0:10.0.0.1').ok, false);
      assert.equal(assertProbeDestinationAllowed('::ffff:0:169.254.169.254').ok, false);
      assert.equal(assertProbeDestinationAllowed('::ffff:0:1.1.1.1').ok, true);
    });
  });

  describe('Item 11: raw catalog contract origin binding validation', () => {
    const check = getCheckById('nfw.origin_lockdown.safe');
    const target = { id: 'tgt_fqdn', kind: 'fqdn', value: 'app.example.com' };
    const declarations = { origin: { lockdown_expected: true } };

    it('rawTargetInputRefusal refuses with origin_binding_required when originBindings is omitted or empty', () => {
      const omitted = rawTargetInputRefusal(check, target, declarations);
      assert.equal(omitted?.error, 'origin_binding_required');
      assert.equal(omitted?.status, 409);
      assert.equal(targetInputRefusal(check, target, declarations), null);

      const empty = rawTargetInputRefusal(check, target, declarations, { originBindings: [] });
      assert.equal(empty?.error, 'origin_binding_required');
      assert.equal(empty?.status, 409);
      assert.equal(targetInputRefusal(check, target, declarations, { originBindings: [] }), null);
    });

    it('rawTargetInputRefusal refuses when binding is unverified or inactive', () => {
      const inactive = rawTargetInputRefusal(check, target, declarations, {
        originBindings: [{
          id: 'b1', tenant_id: 'ten_1', protected_target_id: 'tgt_fqdn', origin_target_id: 'tgt_ip',
          status: 'pending', verification_state: 'verified',
        }],
      });
      assert.equal(inactive?.error, 'origin_binding_required');
      assert.equal(inactive?.status, 409);

      const unverified = rawTargetInputRefusal(check, target, declarations, {
        originBindings: [{
          id: 'b1', tenant_id: 'ten_1', protected_target_id: 'tgt_fqdn', origin_target_id: 'tgt_ip',
          status: 'active', verification_state: 'unverified',
        }],
      });
      assert.equal(unverified?.error, 'origin_binding_required');
      assert.equal(unverified?.status, 409);
    });

    it('allows when exactly one active verified binding is supplied', () => {
      const allowed = rawTargetInputRefusal(check, target, declarations, {
        originBindings: [{
          id: 'b1', tenant_id: 'ten_1', protected_target_id: 'tgt_fqdn', origin_target_id: 'tgt_ip',
          status: 'active', verification_state: 'verified',
        }],
      });
      assert.equal(allowed, null);
      assert.equal(checkRequiresAdditionalInput(check, {
        target,
        declarations,
        originBindings: [{
          id: 'b1', tenant_id: 'ten_1', protected_target_id: 'tgt_fqdn', origin_target_id: 'tgt_ip',
          status: 'active', verification_state: 'verified',
        }],
      }), false);
    });
  });
});
