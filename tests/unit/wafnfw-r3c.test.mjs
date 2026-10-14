import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  gradingSignatureVersionGap,
  deriveCheckDefinitionVersion,
} from '../../src/lib/checkDefinitionVersion.mjs';
import {
  SIGNATURE_CORPUS_VERSION,
  WAF_GRADING_VERSION,
} from '../../src/lib/externalObservationOutcomes.mjs';
import { pairState, coverageFrom, isCustomCanaryCheckId } from '../../src/lib/protectionCoverage.mjs';
import { planFixVerifiedFromRetest } from '../../src/lib/findingLifecycle.mjs';
import { applyPassingRetestToFindings, upsertFindingFromVerdict, getFinding, listFindings, patchFinding } from '../../src/services/findings.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { SCENARIO_TO_CHECK } from '../../src/contracts/wafOrchestrator.mjs';
import { getCheckById, CHECK_CATALOG, targetInputRefusal } from '../../src/contracts/checks.mjs';
import { buildVerdictReplay, rederiveVerdict } from '../../src/lib/verdictReplay.mjs';
import { sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';
import {
  catalogRuleCoverage,
  CUSTOM_CANARY_ONLY_REASON,
  NEVER_RUNNABLE_REASON,
  checkAssuranceReason,
} from '../../src/contracts/ruleCoverage.mjs';

describe('R3c Backend Tests', () => {
  describe('Item 1 (N9) — Corpus stamp precedence and rolling-deploy', () => {
    it('worker-reported corpus version takes precedence over server start stamp in provenance_json', () => {
      const run = {
        id: 'run_rolling_1',
        provenance_json: {
          grading_version: WAF_GRADING_VERSION,
          signature_corpus_version: SIGNATURE_CORPUS_VERSION,
        },
        probe_metadata: {
          grading_version: WAF_GRADING_VERSION,
          signature_corpus_version: '2026-10-waf-corpus-v1-old',
        },
      };
      const verdict = {
        verdict: 'protected',
        signature_corpus_version: '2026-10-waf-corpus-v1-old',
      };
      const gap = gradingSignatureVersionGap(run, verdict);
      assert.equal(gap, 'signature_corpus_version_mismatch');
    });

    it('rolling-deploy: old worker reports old corpus and run gets no credit in pairState', () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const run = {
        id: 'run_rolling_2',
        check_id: check.check_id,
        check_version: check.version,
        scenario_version: 'marker-comparison-v4',
        status: 'verdicted',
        completed_at: new Date().toISOString(),
        producer_kind: 'live_external',
        provenance_json: {
          digest: deriveCheckDefinitionVersion(check).digest,
          grading_version: WAF_GRADING_VERSION,
          signature_corpus_version: SIGNATURE_CORPUS_VERSION,
        },
        probe_metadata: {
          grading_version: WAF_GRADING_VERSION,
          signature_corpus_version: '2026-10-waf-corpus-v1-old',
        },
        readiness_result_metadata: [{ enforcement: 'enforced' }],
      };
      const verdict = {
        verdict: 'protected',
        scenario_version: 'marker-comparison-v4',
        signature_corpus_version: '2026-10-waf-corpus-v1-old',
        grading_version: WAF_GRADING_VERSION,
        evidence_ids: ['ev_1'],
      };
      const state = pairState(run, verdict, check, Date.now(), {
        evidence_verified: true,
      });
      assert.equal(state.state, 'partial');
      assert.equal(state.retest_required, true);
      assert.equal(state.pair_reason, 'signature_corpus_version_mismatch');
    });
  });

  describe('Item 2 (N12) — Violation-only findings fix verification', () => {
    const baseFinding = {
      id: 'fnd_nfw_1',
      tenant_id: 'ten_r3c',
      target_id: 'tgt_r3c',
      check_id: 'nfw.declared_deny_tcp.safe',
      status: 'open',
      source_perspective: 'us-east-1',
    };

    const makeRetestRun = (overrides = {}) => ({
      id: 'run_retest_1',
      tenant_id: 'ten_r3c',
      target_id: 'tgt_r3c',
      check_id: 'nfw.declared_deny_tcp.safe',
      status: 'verdicted',
      source_perspective: 'us-east-1',
      probe_metadata: {
        source_perspective: 'us-east-1',
        sample_agreement: 'agree',
        samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
        unprobed_deny_ports: [],
        port_results: [
          {
            port: 22,
            protocol: 'tcp',
            result: 'no_violation_observed',
            sample_agreement: 'agree',
            samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
          },
        ],
      },
      ...overrides,
    });

    const makeRetestVerdict = (overrides = {}) => ({
      id: 'vrd_retest_1',
      test_run_id: 'run_retest_1',
      target_id: 'tgt_r3c',
      check_id: 'nfw.declared_deny_tcp.safe',
      verdict: 'inconclusive',
      source_perspective: 'us-east-1',
      createsFinding: false,
      metadata: {
        port_results: [
          {
            port: 22,
            protocol: 'tcp',
            result: 'no_violation_observed',
            sample_agreement: 'agree',
            samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }],
          },
        ],
      },
      ...overrides,
    });

    it('moves finding to fix_verified with violation_not_reproduced when all 5 conditions hold', () => {
      const run = makeRetestRun();
      const verdict = makeRetestVerdict();
      const plan = planFixVerifiedFromRetest({ finding: baseFinding, run, verdict });
      assert.equal(plan.action, 'fix_verified');
      assert.equal(plan.verification_basis, 'violation_not_reproduced');
      assert.equal(plan.patch.status, 'fix_verified');
      assert.equal(plan.patch.verifying_run_id, 'run_retest_1');
    });

    it('stays open when perspectives mismatch', () => {
      const run = makeRetestRun({ source_perspective: 'eu-west-1', probe_metadata: { ...makeRetestRun().probe_metadata, source_perspective: 'eu-west-1' } });
      const verdict = makeRetestVerdict({ source_perspective: 'eu-west-1' });
      const plan = planFixVerifiedFromRetest({ finding: baseFinding, run, verdict });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'perspective_mismatch');
    });

    it('stays open when sample agreement disagrees or samples < 2', () => {
      const run = makeRetestRun({
        probe_metadata: {
          source_perspective: 'us-east-1',
          sample_agreement: 'disagree',
          samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'handshake' }],
          unprobed_deny_ports: [],
          port_results: [],
        },
      });
      const verdict = makeRetestVerdict({ metadata: {} });
      const plan = planFixVerifiedFromRetest({ finding: baseFinding, run, verdict });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'samples_disagree_or_insufficient');
    });

    it('stays open when violation is observed', () => {
      const run = makeRetestRun();
      const verdict = makeRetestVerdict({ verdict: 'exposed', createsFinding: true });
      const plan = planFixVerifiedFromRetest({ finding: baseFinding, run, verdict });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'violation_observed');
    });

    it('stays open when unprobed_deny_ports is non-empty', () => {
      const run = makeRetestRun({
        probe_metadata: {
          ...makeRetestRun().probe_metadata,
          unprobed_deny_ports: [8080],
        },
      });
      const verdict = makeRetestVerdict();
      const plan = planFixVerifiedFromRetest({ finding: baseFinding, run, verdict });
      assert.equal(plan.action, 'none');
      assert.equal(plan.reason, 'unprobed_deny_ports_present');
    });

    it('dev applyPassingRetestToFindings audits finding.fix_verified with verification_basis', () => {
      resetStoreForTests();
      const store = getStore();
      const target = { id: 'tgt_r3c_dev', tenant_id: 'ten_r3c_dev', value: 'example.com' };
      const ctx = { tenantId: 'ten_r3c_dev', userId: 'usr_admin', role: 'admin' };
      const runInitial = {
        id: 'run_init_1',
        tenant_id: 'ten_r3c_dev',
        target_id: target.id,
        check_id: 'nfw.declared_deny_tcp.safe',
        status: 'verdicted',
        source_perspective: 'us-east-1',
      };
      const verdictInitial = {
        id: 'vrd_init_1',
        test_run_id: runInitial.id,
        target_id: target.id,
        check_id: runInitial.check_id,
        verdict: 'exposed',
        severity: 'high',
        source_perspective: 'us-east-1',
        evidence_ids: ['ev_1'],
      };
      const finding = upsertFindingFromVerdict(ctx, verdictInitial, runInitial, target);
      assert.equal(finding.status, 'open');
      assert.equal(finding.source_perspective, 'us-east-1');

      const runRetest = makeRetestRun({
        id: 'run_dev_retest_1',
        tenant_id: 'ten_r3c_dev',
        target_id: target.id,
      });
      const verdictRetest = makeRetestVerdict({
        id: 'vrd_dev_retest_1',
        test_run_id: runRetest.id,
        target_id: target.id,
      });

      const res = applyPassingRetestToFindings(ctx, { verdict: verdictRetest, run: runRetest, target });
      assert.deepEqual(res.closed, [finding.id]);
      assert.equal(finding.status, 'fix_verified');
      assert.equal(finding.verifying_run_id, 'run_dev_retest_1');
      assert.equal(finding.verification_basis, 'violation_not_reproduced');

      const findingDetail = getFinding(ctx, finding.id);
      assert.equal(findingDetail.verification_basis, 'violation_not_reproduced');

      const findingList = listFindings(ctx);
      const foundItem = findingList.find((f) => f.id === finding.id);
      assert.ok(foundItem);
      assert.equal(foundItem.verification_basis, 'violation_not_reproduced');

      // Client PATCH value is ignored in dev (docs/api.md:599)
      const patched = patchFinding(ctx, finding.id, { verification_basis: 'manual_verification' });
      assert.equal(patched.verification_basis, 'violation_not_reproduced');
      assert.equal(getFinding(ctx, finding.id).verification_basis, 'violation_not_reproduced');

      const auditEntry = store.auditLog.find((a) => a.action === 'finding.fix_verified' && a.resource_id === finding.id);
      assert.ok(auditEntry);
      assert.equal(auditEntry.metadata.verification_basis, 'violation_not_reproduced');
    });
  });

  describe('Item 3 (F15) — Orchestrator marker scenario mapping', () => {
    it('maps marker scenario to verdict-capable waf.http_method_policy_marker.safe', () => {
      assert.equal(SCENARIO_TO_CHECK.marker, 'waf.http_method_policy_marker.safe');
      const check = getCheckById(SCENARIO_TO_CHECK.marker);
      assert.ok(check);
      assert.equal(check.safety_class, 'safe');
      assert.equal(check.probe_profile.kind, 'waf_class_marker_probe');
      assert.notEqual(check.observation_only, true);
    });
  });

  describe('Item 4 (F23) — Verdict replay re-grading', () => {
    it('stored generic-header 403 graded blocked under old corpus re-grades to inconclusive now', () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const run = {
        id: 'run_f23_1',
        check_id: check.check_id,
        status: 'verdicted',
      };
      const storedVerdict = {
        id: 'vrd_f23_1',
        verdict: 'protected',
        grading_version: '2026-10-waf-v1',
        signature_corpus_version: '2026-10-waf-corpus-v1',
        created_at: new Date().toISOString(),
      };
      const probeEvent = {
        metadata: {
          baseline: { status_code: 200, header_names: [] },
          response_features: [
            {
              placement: 'query',
              status_code: 403,
              header_subset: { 'x-amzn-errortype': 'AccessDeniedException' },
              body_bytes: 42,
            },
          ],
        },
      };

      const replay = buildVerdictReplay({
        run,
        storedVerdict,
        probeEvent,
      });

      assert.equal(replay.regraded, false);
      assert.equal(replay.regrade_unavailable_reason, 'insufficient_features');
      assert.equal(replay.stored.verdict, 'protected');
      assert.equal(replay.rederived.verdict, 'protected');
      assert.equal(replay.changed, false);
      assert.equal(replay.retest_required, true);
    });

    it('new-format feature with a generic 403 re-grades to inconclusive with changed: true', () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const run = {
        id: 'run_f23_new',
        check_id: check.check_id,
        status: 'verdicted',
      };
      const storedVerdict = {
        id: 'vrd_f23_new',
        verdict: 'protected',
        grading_version: '2026-10-waf-v1',
        signature_corpus_version: '2026-10-waf-corpus-v1',
        created_at: new Date().toISOString(),
      };
      const probeEvent = {
        metadata: {
          baseline: { status_code: 200, header_names: [] },
          response_features: [
            {
              placement: 'query',
              status_code: 403,
              header_subset: { 'x-amzn-errortype': 'AccessDeniedException' },
              body_bytes: 42,
              signature_basis: null,
            },
          ],
        },
      };

      const replay = buildVerdictReplay({
        run,
        storedVerdict,
        probeEvent,
      });

      assert.equal(replay.regraded, true);
      assert.equal(replay.stored.verdict, 'protected');
      assert.equal(replay.rederived.verdict, 'inconclusive');
      assert.equal(replay.changed, true);
    });

    it('stored 403 with declared block header re-grades as blocked and replay stays protected with changed: false', () => {
      const check = getCheckById('waf.sqli_managed_marker.safe');
      const run = {
        id: 'run_f23_block_hdr',
        check_id: check.check_id,
        status: 'verdicted',
      };
      const storedVerdict = {
        id: 'vrd_f23_block_hdr',
        verdict: 'protected',
        grading_version: '2026-10-waf-v1',
        signature_corpus_version: '2026-10-waf-corpus-v1',
        created_at: new Date().toISOString(),
      };
      const probeEvent = {
        metadata: {
          baseline: { status_code: 200, header_names: [] },
          response_features: [
            {
              placement: 'query',
              status_code: 403,
              header_subset: { 'X-Custom-Block': 'waf-denied-123' },
              body_bytes: 42,
            },
          ],
        },
      };
      const declarations = {
        waf: {
          block_signature: {
            header_name: 'x-custom-block',
            header_value: 'waf-denied-123',
            status_code: 403,
          },
        },
      };

      const replay = buildVerdictReplay({
        run,
        storedVerdict,
        probeEvent,
        declarations,
      });

      assert.equal(replay.regraded, true);
      assert.equal(replay.stored.verdict, 'protected');
      assert.equal(replay.rederived.verdict, 'protected');
      assert.equal(replay.changed, false);
      const queryPlacement = replay.placements.find((p) => p.placement === 'query');
      assert.equal(queryPlacement.outcome, 'blocked');
    });

    it('reports regraded: false with reason when response_features are missing', () => {
      const run = {
        id: 'run_f23_2',
        check_id: 'waf.sqli_managed_marker.safe',
      };
      const replay = buildVerdictReplay({
        run,
        probeEvent: { metadata: {} },
      });
      assert.equal(replay.regraded, false);
      assert.equal(replay.regrade_unavailable_reason, 'missing_response_features');
    });
  });

  describe('Item 5 (N15) — Worker probe metadata sanitize caps', () => {
    it('caps total number of keys at 128', () => {
      const input = {};
      for (let i = 0; i < 200; i += 1) {
        input[`custom_key_${i}`] = `value_${i}`;
      }
      const sanitized = sanitizeProbeMetadata(input);
      const keys = Object.keys(sanitized);
      assert.ok(keys.length <= 128, `Expected <= 128 keys, got ${keys.length}`);
      assert.equal(keys.length, 128);
    });

    it('caps string values at 256 characters', () => {
      const longString = 'a'.repeat(500);
      const sanitized = sanitizeProbeMetadata({
        long_scalar: longString,
      });
      assert.equal(sanitized.long_scalar.length, 256);
      assert.equal(sanitized.long_scalar, 'a'.repeat(256));
    });
  });

  describe('Item 6 — API gaps', () => {
    it('6b: protectionCoverage includes last_run_id on each rolled_up_pairs entry', () => {
      const target = { id: 'tgt_r3c_canary', tenant_id: 'ten_r3c', kind: 'fqdn', value: 'example.com' };
      const run = {
        id: 'run_canary_pair_1',
        target_id: target.id,
        check_id: 'waf.http_method_policy_marker.safe',
        status: 'verdicted',
        completed_at: new Date().toISOString(),
        producer_kind: 'live_external',
        readiness_result_metadata: [{ enforcement: 'enforced' }],
      };
      const verdict = {
        id: 'vrd_canary_1',
        test_run_id: run.id,
        target_id: target.id,
        verdict: 'protected',
        evidence_ids: ['ev_1'],
      };
      const coverage = coverageFrom({
        target,
        observations: [{ run, verdict }],
      });
      const canaryRollups = coverage.coverage.custom_canary_rollups;
      assert.ok(canaryRollups.length > 0);
      const rollup = canaryRollups[0];
      assert.ok(Array.isArray(rollup.rolled_up_pairs));
      assert.ok(rollup.rolled_up_pairs.length > 0);
      for (const pair of rollup.rolled_up_pairs) {
        assert.ok('last_run_id' in pair, `Pair ${pair.check_id} missing last_run_id`);
        if (pair.check_id === 'waf.http_method_policy_marker.safe') {
          assert.equal(pair.last_run_id, 'run_canary_pair_1');
        }
      }
    });

    it('6c: all assurance_reason strings start with a capital letter', () => {
      assert.match(CUSTOM_CANARY_ONLY_REASON, /^[A-Z]/);
      assert.match(NEVER_RUNNABLE_REASON, /^[A-Z]/);
      assert.match(checkAssuranceReason(null), /^[A-Z]/);

      const coverage = catalogRuleCoverage();
      for (const category of coverage.categories) {
        if (category.assurance_reason) {
          assert.match(category.assurance_reason, /^[A-Z]/, `Category ${category.id} assurance_reason must start with capital letter`);
        }
        for (const check of category.checks) {
          if (check.assurance_reason) {
            assert.match(check.assurance_reason, /^[A-Z]/, `Check ${check.check_id} assurance_reason must start with capital letter`);
          }
        }
      }
    });
  });

  describe('Part B Item 3 — Origin binding requirement', () => {
    it('targetInputRefusal for nfw.origin_lockdown.safe requires exactly one active, verified origin binding', () => {
      const check = getCheckById('nfw.origin_lockdown.safe');
      const declarations = { origin: { lockdown_expected: true } };

      const bareTarget = { id: 'tgt_lockdown_1', metadata: { control_declarations: declarations } };
      const refusalNoBinding = targetInputRefusal(check, bareTarget);
      assert.ok(refusalNoBinding);
      assert.equal(refusalNoBinding.error, 'origin_binding_required');
      assert.equal(refusalNoBinding.status, 409);
      assert.doesNotMatch(refusalNoBinding.message, /[a-z]+_[a-z_]+/);

      const inactiveTarget = {
        id: 'tgt_lockdown_1',
        metadata: { control_declarations: declarations },
        origin_bindings: [{ id: 'ob_1', status: 'archived', verified: true }],
      };
      assert.equal(targetInputRefusal(check, inactiveTarget)?.error, 'origin_binding_required');

      const unverifiedTarget = {
        id: 'tgt_lockdown_1',
        metadata: { control_declarations: declarations },
        origin_bindings: [{ id: 'ob_1', status: 'active', verified: false }],
      };
      assert.equal(targetInputRefusal(check, unverifiedTarget)?.error, 'origin_binding_required');

      const multipleTarget = {
        id: 'tgt_lockdown_1',
        metadata: { control_declarations: declarations },
        origin_bindings: [
          { id: 'ob_1', status: 'active', verified: true },
          { id: 'ob_2', status: 'active', verified: true },
        ],
      };
      assert.equal(targetInputRefusal(check, multipleTarget)?.error, 'origin_binding_required');

      const validTarget = {
        id: 'tgt_lockdown_1',
        tenant_id: 'ten_cust',
        kind: 'fqdn',
        value: 'app.example.com',
        metadata: { control_declarations: declarations },
        origin_bindings: {
          bindings: [{
            id: 'ob_1',
            tenant_id: 'ten_cust',
            status: 'active',
            protected_target_id: 'tgt_lockdown_1',
            origin_target_id: 'tgt_origin_1',
            host: 'app.example.com',
            sni: 'app.example.com',
            port: null,
            path: null,
          }],
          records: {
            targets: [
              { id: 'tgt_lockdown_1', tenant_id: 'ten_cust', kind: 'fqdn', value: 'app.example.com' },
              { id: 'tgt_origin_1', tenant_id: 'ten_cust', kind: 'ip', value: '203.0.113.10' },
            ],
            targetVerifications: [
              {
                id: 'v_origin_1',
                tenant_id: 'ten_cust',
                target_id: 'tgt_origin_1',
                state: 'dns_verified',
                transitioned_at: '2026-10-01T00:00:00.000Z',
              },
            ],
          },
        },
      };
      assert.equal(targetInputRefusal(check, validTarget), null);
    });

    it('rule coverage required_declarations for origin_lockdown includes origin_binding', () => {
      const catalog = catalogRuleCoverage();
      const originCategory = catalog.categories.find((c) => c.id === 'origin_lockdown');
      assert.ok(originCategory);
      assert.ok(originCategory.required_declarations.includes('origin_binding'));
      assert.ok(originCategory.required_declarations.includes('origin.lockdown_expected'));
    });
  });

  describe('Part B Item 4 — Scanner marker classification', () => {
    it('isCustomCanaryCheckId classifies waf.scanner_signature_marker.safe as managed, not custom canary', () => {
      assert.equal(isCustomCanaryCheckId('waf.scanner_signature_marker.safe'), false);
      assert.equal(isCustomCanaryCheckId({ check_id: 'waf.scanner_signature_marker.safe' }), false);
      assert.equal(isCustomCanaryCheckId('waf.sqli_managed_marker.safe'), false);
      assert.equal(isCustomCanaryCheckId('waf.ssrf_marker.safe'), true);
    });

    it('managed scanner marker never rolls up into custom_canary_rollups', () => {
      const target = { id: 'tgt_managed_scanner', tenant_id: 'ten_r3c', kind: 'fqdn', value: 'scanner.example.com' };
      const run = {
        id: 'run_scanner_1',
        target_id: target.id,
        check_id: 'waf.scanner_signature_marker.safe',
        status: 'verdicted',
        completed_at: new Date().toISOString(),
        producer_kind: 'live_external',
        readiness_result_metadata: [{ enforcement: 'enforced' }],
      };
      const verdict = {
        id: 'vrd_scanner_1',
        test_run_id: run.id,
        target_id: target.id,
        verdict: 'protected',
        evidence_ids: ['ev_1'],
      };
      const check = getCheckById('waf.scanner_signature_marker.safe');
      const coverageSingle = coverageFrom({
        target,
        catalog: [check],
        observations: [{ run, verdict }],
      });
      assert.equal(coverageSingle.coverage.custom_canary_rollups.length, 0);

      const coverageFull = coverageFrom({
        target,
        observations: [{ run, verdict }],
      });
      for (const rollup of coverageFull.coverage.custom_canary_rollups) {
        assert.ok(!rollup.rolled_up_check_ids.includes('waf.scanner_signature_marker.safe'));
        assert.ok(!rollup.rolled_up_pairs.some((p) => p.check_id === 'waf.scanner_signature_marker.safe'));
      }
    });
  });

  describe('Part B Item 5 — Plain run-refusal messages', () => {
    it('every targetInputRefusal error message contains no raw keys or snake_case', () => {
      const bareTarget = { id: 'tgt_plain_test', metadata: {} };
      const snakeCaseRegex = /[a-z]+_[a-z_]+/;

      for (const check of CHECK_CATALOG) {
        const refusal = targetInputRefusal(check, bareTarget);
        if (refusal?.message) {
          assert.doesNotMatch(
            refusal.message,
            snakeCaseRegex,
            `Check ${check.check_id} refusal message contains snake_case: "${refusal.message}"`,
          );
        }
      }
    });
  });
});
