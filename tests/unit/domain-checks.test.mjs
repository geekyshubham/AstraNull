import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, customerSelectableChecks, checkRequiresAdditionalInput } from '../../src/contracts/checks.mjs';
import { DEMO_ACCOUNT_TENANT_ID } from '../../src/lib/demoAutoVerify.mjs';
import { coverageFrom } from '../../src/lib/protectionCoverage.mjs';
import { targetRunnableIndex } from '../../apps/web/react/src/lib/control-declarations.mjs';
import { MAX_SCAN_CHECKS, MAX_SCAN_STEPS, planScanSteps, projectScanStep } from '../../src/contracts/validationScanManagement.mjs';
import {
  CHECK_CATEGORIES,
  EDGE_DETECTION_CHECK_ID,
  ROW_STATUS_META,
  recommendedStarterRow,
  wafRuleEnforcement,
  wafRuleSentences,
  rowEvidenceState,
  assessEdgeEfficacy,
  buildCheckRows,
  declarationOnlyChecks,
  edgeDetectionPhase,
  edgeEvidenceSignals,
  efficacySentence,
  groupRowsByCategory,
  rowProgress,
  retainedCoveragePairs,
  runAllChecks,
  individualChecks,
  originRelationCheckEligible,
  assessmentChecks,
  targetCheckRequirement,
  targetCheckAvailability,
  countRowStatuses,
  shouldAutoDetectEdge,
  withTargetRunnableChecks,
} from '../../apps/web/react/src/lib/domain-checks.mjs';

const CATALOG = customerSelectableChecks(CHECK_CATALOG);
const DOMAIN = { id: 'tgt_1', kind: 'fqdn', value: 'shop.example.com' };
const byId = (id) => CATALOG.find((check) => check.check_id === id);

it('only warns about ineligible recorded results, not current inconclusive or still-running checks', () => {
  const pair = (id, state, verdict, live = false) => ({ check_id: id, state, live_external: live, retained: { verdict } });
  assert.deepEqual(retainedCoveragePairs([
    pair('current-inconclusive', 'inconclusive', 'inconclusive'),
    pair('collecting', 'unknown', null),
    pair('current-conclusive', 'conclusive', 'edge_protected', true),
    pair('legacy-version', 'partial', 'edge_protected'),
    pair('old-proof', 'stale', 'edge_protected'),
    pair('simulated', 'unknown', 'edge_protected'),
  ]).map((entry) => entry.check_id), ['legacy-version', 'old-proof', 'simulated']);
});

function row(rows, id) {
  return rows.find((entry) => entry.checkId === id);
}

describe('run-all check set for a domain', () => {
  const runAll = runAllChecks(CATALOG, DOMAIN);

  it('includes only currently graded checks and keeps origin candidates first when any are eligible', () => {
    assert.ok(!runAll.some((check) => check.check_id === EDGE_DETECTION_CHECK_ID));
    const originCount = runAll.filter((check) => check.vector_family === 'origin').length;
    assert.ok(runAll.slice(0, originCount).every((check) => check.vector_family === 'origin'));
    assert.ok(!runAll.some((check) => check.check_id === 'origin.leak_scan.safe'), 'observational leak scan is not readiness proof');
    assert.ok(runAll.every((check) => check.evidence_tier !== 'E1' && check.probe_profile?.kind !== 'metadata_marker'));
    assert.ok(runAll.every((check) => check.evidence_tier !== 'E2'));
    assert.ok(runAll.every((check) => check.probe_profile?.kind !== 'ops_readiness'));
    assert.ok(runAll.every((check) => check.safety_class === 'safe' && check.risk_class !== 'soc_gated'));
    assert.ok(runAll.every((check) => (check.supported_targets ?? []).includes('fqdn')));
    assert.equal(new Set(runAll.map((check) => check.check_id)).size, runAll.length);
    assert.ok(declarationOnlyChecks(CATALOG, DOMAIN).length > 0);
  });

  it('fits in one scan under the server plan caps', () => {
    assert.ok(runAll.length <= MAX_SCAN_CHECKS);
    const plan = planScanSteps({ checks: runAll, targets: [DOMAIN], targetId: DOMAIN.id });
    assert.equal(plan.steps.length, runAll.length);
    assert.ok(plan.steps.length <= MAX_SCAN_STEPS);
    assert.equal(plan.excluded.length, 0);
  });

  it('maps every vector family in the catalog to a category', () => {
    for (const check of CATALOG) assert.ok(CHECK_CATEGORIES[check.vector_family], check.vector_family);
  });
});

describe('per-check status rows', () => {
  const checks = [byId(EDGE_DETECTION_CHECK_ID), byId('waf.marker_rule.safe'), byId('origin.leak_scan.safe'), byId('dns.authoritative_response.safe')];

  it('derives status from the latest scan step and keeps request/response metadata', () => {
    const scan = {
      created_at: '2030-01-01T00:00:00.000Z',
      steps: [
        { check_id: EDGE_DETECTION_CHECK_ID, status: 'verdicted', test_run_id: 'run_a', verdict: { verdict: 'edge_protected', explanation: 'Blocked at the edge.' }, request: { kind: 'outside_in_waf_scan' }, requests_sent: 9 },
        { check_id: 'waf.marker_rule.safe', status: 'collecting', test_run_id: 'run_b' },
        { check_id: 'origin.leak_scan.safe', status: 'deferred', eligible_at: '2030-01-01T01:00:00.000Z', error_code: 'safe_rate_cap_exceeded' },
        { check_id: 'dns.authoritative_response.safe', status: 'verdicted', verdict: { verdict: 'inconclusive' } },
      ],
    };
    const rows = buildCheckRows({ checks, scan });
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).status, 'observed', 'legacy positive fingerprint fields never claim current protection');
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).explanation, 'Blocked at the edge.');
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).requestsSent, 9);
    assert.equal(row(rows, 'waf.marker_rule.safe').status, 'running');
    assert.equal(row(rows, 'origin.leak_scan.safe').status, 'waiting');
    assert.equal(row(rows, 'origin.leak_scan.safe').eligibleAt, '2030-01-01T01:00:00.000Z');
    // Transport-only (E2) checks observe; they never claim a verdict.
    assert.equal(row(rows, 'dns.authoritative_response.safe').status, 'observed');
    assert.deepEqual(rowProgress(rows), { total: 4, done: 2, percent: 50 });
  });

  it('prefers a newer standalone run, and ignores verdicts that cite no evidence', () => {
    const scan = { created_at: '2030-01-01T00:00:00.000Z', steps: [{ check_id: EDGE_DETECTION_CHECK_ID, status: 'verdicted', test_run_id: 'run_a', verdict: { verdict: 'edge_protected' } }] };
    const runs = [
      { id: 'run_new', check_id: EDGE_DETECTION_CHECK_ID, status: 'completed', started_at: '2030-01-02T00:00:00.000Z', verdict: { verdict: 'edge_exposed', evidence_ids: ['evt_1'] } },
      { id: 'run_x', check_id: 'waf.marker_rule.safe', status: 'completed', started_at: '2030-01-02T00:00:00.000Z', verdict: { verdict: 'protected', evidence_ids: [] } },
    ];
    const rows = buildCheckRows({ checks, scan, runs });
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).status, 'observed', 'provider observations do not become graded gaps');
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).runId, 'run_new');
    assert.equal(row(rows, 'waf.marker_rule.safe').status, 'observed', 'legacy request-only enforcement remains an observation, not an installed custom-canary check');
    assert.equal(row(rows, 'origin.leak_scan.safe').status, 'not_run');
  });

  it('shows customer-facing check names, not raw catalog jargon', () => {
    const jwt = byId('waf.jwt_tamper_marker.safe');
    assert.match(jwt.name, /Custom Canary Rule/);
    const [rendered] = buildCheckRows({ checks: [jwt] });
    assert.match(rendered.name, /sign-in-token test label/i);
    assert.equal(rendered.producesVerdict, false);
    assert.equal(rendered.readinessCapable, false);
    assert.doesNotMatch(rendered.name, /waf_class_marker/i);
  });

  it('groups rows by category with current graded failures first and observations separate', () => {
    const protectedCheck = byId('waf.sqli_managed_marker.safe');
    const exposedCheck = byId('waf.xss_managed_marker.safe');
    const scan = { steps: [
      { check_id: protectedCheck.check_id, status: 'verdicted', verdict: { verdict: 'edge_protected', evidence_ids: ['evt_protected'] } },
      { check_id: exposedCheck.check_id, status: 'verdicted', verdict: { verdict: 'edge_exposed', evidence_ids: ['evt_exposed'] } },
    ] };
    const groups = groupRowsByCategory(buildCheckRows({ checks: [...checks, protectedCheck, exposedCheck], scan }));
    assert.equal(groups[0].category.id, 'waf');
    assert.equal(groups[0].rows[0].status, 'failed');
    assert.equal(groups[0].counts.passed, 1);
    assert.equal(groups[1].category.id, 'origin');
  });
});

describe('evaluated expectation, scoped verdict and current evidence', () => {
  const check = byId('waf.http_method_policy_enforced.safe');
  const run = { id: 'run_method', check_id: check.check_id, status: 'completed', started_at: '2030-01-02T00:00:00.000Z', expected_behavior: 'allow_as_expected', verdict: { verdict: 'protected', evidence_ids: ['evt_method'] } };

  it('keeps the expectation evaluated by the run or step, not the catalog default', () => {
    const [fromRun] = buildCheckRows({ checks: [check], runs: [run] });
    const [fromStep] = buildCheckRows({ checks: [check], scan: { steps: [{ ...run, status: 'verdicted', test_run_id: run.id }] } });
    assert.equal(fromRun.expectedBehavior, 'allow_as_expected');
    assert.equal(fromStep.expectedBehavior, 'allow_as_expected');
    assert.equal(fromRun.producesVerdict, true);
    assert.equal(fromRun.readinessCapable, false);
    assert.equal(fromRun.status, 'passed');
    const [failed] = buildCheckRows({ checks: [check], runs: [{ ...run, verdict: { verdict: 'edge_exposed', evidence_ids: ['evt_fail'] } }] });
    assert.equal(failed.status, 'failed');
  });

  it('preserves actual verdict citations through the real assessment API projection', () => {
    for (const [verdictValue, expected] of [['protected', 'passed'], ['edge_exposed', 'failed']]) {
      for (const evidenceIds of [['evt_method'], []]) {
        const verdict = { ...run.verdict, verdict: verdictValue, evidence_ids: evidenceIds };
        const step = projectScanStep({ step: { id: 'step_method', position: 0, status: 'verdicted', target_id: DOMAIN.id, check_id: check.check_id, test_run_id: run.id }, check, target: DOMAIN, run, verdict });
        const coverage = { pairs: [{ check_id: check.check_id, last_run_id: run.id, state: 'conclusive', live_external: true, fresh: true }] };
        const [projected] = buildCheckRows({ checks: [check], scan: { created_at: run.started_at, steps: [step] }, runs: [run], coverage });
        assert.equal(projected.status, evidenceIds.length ? expected : 'retained');
        assert.equal(projected.runId, run.id);
        assert.equal(projected.coverageReason, evidenceIds.length ? '' : 'no_evidence');
        assert.deepEqual(step.verdict.evidence_ids, evidenceIds);
        assert.deepEqual(verdict.evidence_ids, evidenceIds, 'projection must not rewrite original verdicts');
      }
    }
  });

  for (const [state, reason] of [['unknown', 'no_evidence'], ['unknown', 'invalid_or_unresolved_evidence'], ['unknown', 'future_reason'], ['partial', 'check_version_mismatch'], ['stale', 'stale_result']]) {
    it(`keeps ${state}/${reason} out of current pass and gap counts`, () => {
      const coverage = { pairs: [{ check_id: check.check_id, last_run_id: run.id, state, pair_reason: reason, live_external: false }] };
      const rows = buildCheckRows({ checks: [check], runs: [run], coverage });
      assert.equal(rows[0].status, 'retained');
      assert.equal(rows[0].coverageReason, reason);
      assert.doesNotMatch(rows[0].label, /Gap found|Protected/);
      const group = groupRowsByCategory(rows)[0];
      assert.equal(group.counts.passed, 0);
      assert.equal(group.counts.failed, 0);
      assert.equal(group.counts.retained, 1);
      assert.equal(rowEvidenceState(rows[0], { coverage }), state === 'partial' ? 'version_gap' : state === 'stale' ? 'stale' : 'unverified');
    });
  }

  it('retains historical custom-canary publications under current setup-only definitions without re-grading', () => {
    const current = byId('waf.jwt_tamper_marker.safe');
    assert.equal(current.produces_verdict, false);
    for (const [state, reason] of [['partial', 'check_version_mismatch'], ['unknown', 'invalid_or_unresolved_evidence']]) {
      const historical = { ...run, check_id: current.check_id, verdict: { verdict: 'edge_exposed', explanation: 'Historical rule failed', evidence_ids: ['evt_historical'] } };
      const coverage = { pairs: [{ check_id: current.check_id, last_run_id: historical.id, state, pair_reason: reason, live_external: false }] };
      for (const input of [{ runs: [historical] }, { scan: { steps: [{ ...historical, status: 'verdicted', test_run_id: historical.id }] } }]) {
        const rows = buildCheckRows({ checks: [current], coverage, ...input });
        assert.equal(rows[0].status, 'retained');
        assert.equal(rows[0].verdict, 'edge_exposed');
        assert.equal(rows[0].explanation, 'Historical rule failed');
        assert.equal(rows[0].coverageReason, reason);
        assert.equal(groupRowsByCategory(rows)[0].counts.failed, 0);
        assert.notEqual(rows[0].status, 'observed');
      }
    }
    const [setup] = buildCheckRows({ checks: [current], runs: [{ ...run, check_id: current.check_id, verdict: { verdict: 'inconclusive', evidence_ids: ['evt_setup'], explanation: 'Custom canary setup unavailable' } }] });
    assert.equal(setup.status, 'observed');
  });

  it('uses rolled-up member eligibility for current counts without changing unknown reasons', () => {
    for (const [state, reason, expected] of [['unknown', 'invalid_or_unresolved_evidence', 'unverified'], ['partial', 'check_version_mismatch', 'version_gap'], ['stale', 'stale', 'stale']]) {
      const coverage = { custom_canary_rollups: [{ rolled_up_pairs: [{ check_id: check.check_id, last_run_id: run.id, state, pair_reason: reason, fresh: false }] }] };
      const rows = buildCheckRows({ checks: [check], runs: [run], coverage });
      assert.equal(rows[0].status, 'retained');
      assert.equal(rows[0].coverageReason, reason);
      assert.equal(groupRowsByCategory(rows)[0].counts.passed, 0);
      assert.equal(rowEvidenceState(rows[0], { coverage }), expected);
    }
  });

  it('does not apply an old coverage pair to a newer exact run', () => {
    const [row] = buildCheckRows({ checks: [check], runs: [run], coverage: { pairs: [{ check_id: check.check_id, last_run_id: 'other_run', state: 'unknown', live_external: false }] } });
    assert.equal(row.status, 'passed');
  });

  it('a stored fail without any cited evidence is retained, never a current gap', () => {
    const rows = buildCheckRows({ checks: [check], runs: [{ ...run, verdict: { verdict: 'edge_exposed' } }] });
    assert.equal(rows[0].status, 'retained');
    assert.equal(rowEvidenceState(rows[0]), 'unverified');
  });
});

describe('WAF and CDN efficacy', () => {
  const NOW = Date.parse('2030-01-08T00:00:00.000Z');
  const FRESH = '2030-01-07T00:00:00.000Z';
  const OLD = '2029-12-01T00:00:00.000Z';
  let seq = 0;
  const mk = (layer, status, extra = {}) => {
    seq += 1;
    const categoryId = extra.categoryId ?? (layer === 'cdn' ? 'l7' : layer);
    return {
      checkId: extra.checkId ?? `${layer}.check_${seq}.safe`,
      name: extra.name ?? `${layer}-${status}-${seq}`,
      status,
      verdict: extra.verdict ?? (status === 'passed' ? 'protected' : status === 'failed' ? 'exposed' : ''),
      readinessCapable: extra.readinessCapable ?? true,
      probeKind: extra.probeKind ?? (layer === 'waf' ? 'waf_class_marker_probe' : `kind_${seq}`),
      markerClass: extra.markerClass ?? `class_${seq}`,
      assuranceScope: extra.assuranceScope ?? 'managed_rule_marker',
      runId: extra.runId ?? `run_${seq}`,
      finishedAt: extra.finishedAt ?? FRESH,
      startedAt: '',
      category: { id: categoryId, layer },
    };
  };
  const edge = { waf: { status: 'detected', vendor: 'cloudflare' }, cdn: { status: 'detected', provider: 'cloudflare' } };
  const assess = (rows, extra = {}) => assessEdgeEfficacy({ rows, edge, nowMs: NOW, ...extra });

  it('needs three fresh concluded checks across two rule categories before saying Protecting', () => {
    const tooFew = assess([mk('waf', 'passed'), mk('waf', 'passed'), mk('waf', 'inconclusive')]);
    assert.equal(tooFew.waf.status, 'insufficient');
    assert.equal(tooFew.waf.label, 'Not enough evidence');
    assert.match(efficacySentence(tooFew.waf), /Not enough evidence: 2 fresh concluded checks across 2 rule categories/);
    assert.match(efficacySentence(tooFew.waf), /1 inconclusive/);
    const oneCategory = assess([1, 2, 3].map(() => mk('waf', 'passed', { probeKind: 'waf_evasion_marker_probe' })));
    assert.equal(oneCategory.waf.status, 'insufficient', 'three passes in one rule category are not enough');
    const enough = assess([mk('waf', 'passed'), mk('waf', 'passed'), mk('waf', 'passed'), mk('waf', 'inconclusive')]);
    assert.equal(enough.waf.status, 'protecting');
    assert.match(efficacySentence(enough.waf), /Held on 3 of 3 fresh concluded WAF checks · 1 inconclusive/);
  });

  it('one pass with many inconclusive results is never Protecting', () => {
    const rows = [mk('waf', 'passed'), ...Array.from({ length: 28 }, () => mk('waf', 'inconclusive'))];
    const result = assess(rows);
    assert.equal(result.waf.status, 'insufficient');
    assert.equal(result.waf.inconclusive, 28);
  });

  it('ignores stale and version-gapped verdicts', () => {
    const stale = assess([mk('waf', 'passed', { finishedAt: OLD }), mk('waf', 'passed', { finishedAt: OLD }), mk('waf', 'passed', { finishedAt: OLD })]);
    assert.equal(stale.waf.status, 'insufficient');
    assert.equal(stale.waf.ignored, 3);
    assert.match(efficacySentence(stale.waf), /3 not counted \(stale, version-mismatched or unverified\)/);
    const rows = [mk('waf', 'passed', { checkId: 'waf.a.safe', runId: 'r1' }), mk('waf', 'passed'), mk('waf', 'passed')];
    const coverage = { pairs: [{ check_id: 'waf.a.safe', last_run_id: 'r1', state: 'partial', pair_reason: 'check_version_mismatch' }] };
    const gapped = assess(rows, { coverage });
    assert.equal(gapped.waf.tested, 2);
    assert.equal(gapped.waf.ignored, 1);
    assert.equal(rowEvidenceState(rows[0], { coverage, nowMs: NOW }), 'version_gap');
    const serverStale = { pairs: [{ check_id: 'waf.a.safe', last_run_id: 'r1', state: 'stale' }] };
    assert.equal(rowEvidenceState(rows[0], { coverage: serverStale, nowMs: NOW }), 'stale', 'server pair state wins over the row time');
  });

  it('scores partial and not-protecting from fresh exposed verdicts', () => {
    const partial = assess([mk('waf', 'passed'), mk('waf', 'passed'), mk('waf', 'failed', { name: 'SQLi marker' })]);
    assert.equal(partial.waf.status, 'partial');
    assert.deepEqual(partial.waf.exposedChecks, ['SQLi marker']);
    assert.match(efficacySentence(partial.waf), /1 check reached your application/);
    assert.equal(assess([mk('cdn', 'failed')]).cdn.status, 'not_protecting');
    const weak = assess([mk('waf', 'passed'), mk('waf', 'failed'), mk('waf', 'failed')]);
    assert.equal(weak.waf.status, 'mostly_exposed', 'blocking a minority of tested checks is not partial protection');
  });

  it('never lets DNS, network or observation results make the CDN Protecting', () => {
    const rows = [
      mk('cdn', 'passed', { categoryId: 'dns', probeKind: 'dns_axfr_leak' }),
      mk('cdn', 'passed', { categoryId: 'dns', probeKind: 'dns_axfr_leak' }),
      mk('cdn', 'passed', { categoryId: 'l3_l4' }),
      mk('cdn', 'passed', { readinessCapable: false }),
    ];
    const result = assess(rows);
    assert.equal(result.cdn.tested, 0);
    assert.equal(result.cdn.status, 'present_unmeasured');
  });

  it('says bypassable only from a fresh exposed origin-lockdown verdict', () => {
    const base = [mk('waf', 'passed'), mk('waf', 'passed'), mk('waf', 'passed')];
    const genericOrigin = assess([...base, mk('origin', 'failed', { checkId: 'origin.direct_bypass.safe', verdict: 'edge_exposed', categoryId: 'origin' })]);
    assert.equal(genericOrigin.waf.status, 'protecting', 'a direct 2xx elsewhere is not proof of the same application');
    const viaEdge = assessEdgeEfficacy({ rows: base, edge: { ...edge, network_firewall: { direct_origin_reachability: { status: 'exposed' } } }, nowMs: NOW });
    assert.equal(viaEdge.waf.status, 'protecting');
    const lockdown = assess([...base, mk('origin', 'failed', { checkId: 'nfw.origin_lockdown.safe', verdict: 'exposed', categoryId: 'origin', readinessCapable: false })]);
    assert.equal(lockdown.waf.status, 'bypassable');
    assert.equal(lockdown.originExposed, true);
    assert.match(efficacySentence(lockdown.waf), /origin-lockdown check found your origin answering directly/);
    const staleLockdown = assess([...base, mk('origin', 'failed', { checkId: 'nfw.origin_lockdown.safe', verdict: 'exposed', finishedAt: OLD })]);
    assert.equal(staleLockdown.originExposed, false);
  });

  it('never claims efficacy without evidence, and treats fingerprint markers as context only', () => {
    assert.equal(assessEdgeEfficacy({ rows: [], edge: null }).waf.status, 'unknown');
    assert.equal(assessEdgeEfficacy({ rows: [], edge }).waf.status, 'present_unmeasured');
    assert.equal(assessEdgeEfficacy({ rows: [], edge: { waf: { status: 'not_detected' }, cdn: { status: 'not_detected' } } }).cdn.status, 'absent');
    const markers = assessEdgeEfficacy({ rows: [], edge: { ...edge, effectiveness: { tested_count: 3, blocked_count: 3, passed_count: 0 } } });
    assert.equal(markers.waf.status, 'insufficient');
    assert.equal(markers.waf.basis, 'fingerprint_markers');
    assert.match(efficacySentence(markers.waf), /context, not proof/);
    assert.equal(markers.cdn.status, 'present_unmeasured');
  });

  it('no longer speaks of attack classes', () => {
    const result = assess([mk('waf', 'passed'), mk('waf', 'passed'), mk('waf', 'failed')]);
    assert.doesNotMatch(efficacySentence(result.waf), /attack class/i);
  });
});

describe('edge evidence and detection phase', () => {
  it('explains how each layer was found', () => {
    const { layers, facts } = edgeEvidenceSignals({
      layers: [{ family: 'cdn', provider: 'cloudflare', sources: ['cname_suffix', 'address_range'], confidence: 0.92, evidence_consistency: 'agreement' }],
      evidence: {
        vendor_matches: [{ vendor: 'cloudflare', matched_signals: [{ signal: 'server=cloudflare' }] }],
        dns_cname_chain: ['shop.example.com', 'shop.example.com.cdn.cloudflare.net'],
        dns_resolved_ips: ['104.16.0.1'],
        wafw00f: { detected: true, firewall: 'Cloudflare', manufacturer: 'Cloudflare Inc.' },
        cdncheck: { matched: true, provider: 'cloudflare', item_type: 'cdn', source: 'ip' },
      },
    });
    assert.equal(layers[0].name, 'Cloudflare');
    assert.equal(layers[0].logo, 'cloudflare');
    assert.equal(layers[0].confidence, 92);
    assert.deepEqual(layers[0].sources.map((source) => source.method), ['DNS CNAME', 'IP address range']);
    assert.deepEqual(facts.map((fact) => fact.id), ['cname', 'ips', 'waf_fingerprint', 'edge_classifier']);
    assert.equal(/wafw00f|cdncheck/i.test(JSON.stringify(facts)), false);
    assert.match(facts[0].value, /→/);
  });

  it('shows evaluating while queued and never auto-detects before ownership is proven', () => {
    assert.equal(edgeDetectionPhase({ eligible: false, edge: null }), 'locked');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: null, localRequest: 'pending' }), 'evaluating');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: null, request: { run_status: 'collecting' } }), 'evaluating');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: null, request: { run_status: 'completed' } }), 'no_result');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: { status: 'detected' } }), 'detected');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: { status: 'detected' }, localRequest: 'pending' }), 'evaluating');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: { status: 'detected' }, request: { run_status: 'collecting' } }), 'evaluating');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: { status: 'detected' }, localRequest: 'blocked' }), 'waiting');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: { status: 'detected' }, localRequest: 'error' }), 'error');
    const base = { eligible: true, featureEnabled: true, canRun: true, edge: null, request: null, scanActive: false, attempted: false, hasPriorRuns: false };
    assert.equal(shouldAutoDetectEdge(base), true);
    assert.equal(shouldAutoDetectEdge({ ...base, eligible: false }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, scanActive: true }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, request: { run_status: 'completed' } }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, attempted: true }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, hasPriorRuns: true }), false, 'only freshly onboarded domains auto-detect');
  });
});

it('individual selection retains compatible observations without adding them to readiness scans', () => {
  const checks = individualChecks(CATALOG, DOMAIN);
  assert.ok(checks.some((check) => check.check_id === EDGE_DETECTION_CHECK_ID));
  assert.ok(checks.some((check) => check.evidence_tier === 'E2'));
  assert.ok(checks.every((check) => check.evidence_tier !== 'E1' && check.probe_profile?.kind !== 'ops_readiness'));
  assert.ok(checks.every((check) => check.safety_class === 'safe' && check.risk_class !== 'soc_gated'));
  assert.ok(checks.every((check) => (check.supported_targets ?? []).includes('fqdn')));
  assert.equal(new Set(checks.map((check) => check.check_id)).size, checks.length);
  assert.ok(runAllChecks(CATALOG, DOMAIN).every((check) => checks.includes(check)));
});

it('full assessments include every compatible automatic network check, while readiness ignores observations', () => {
  const full = CHECK_CATALOG.map((check) => ({ ...check, requires_additional_input: checkRequiresAdditionalInput(check) }));
  const assessment = assessmentChecks(full, DOMAIN);
  assert.equal(assessment[0].check_id, EDGE_DETECTION_CHECK_ID);
  assert.deepEqual(new Set(assessment.map((check) => check.check_id)), new Set(individualChecks(CATALOG, DOMAIN).map((check) => check.check_id)));
  const plan = planScanSteps({ checks: assessment, targets: [DOMAIN], targetId: DOMAIN.id });
  assert.equal(plan.steps.length, assessment.length);
  assert.equal(plan.excluded.length, 0);
  const remaining = full.filter((check) => targetCheckRequirement(check, DOMAIN));
  assert.equal(remaining.length + assessment.length, CHECK_CATALOG.length);
  assert.match(targetCheckRequirement({ ...byId('origin.leak_scan.safe'), requires_additional_input: true }, DOMAIN), /Declare/);
  assert.match(targetCheckRequirement({ ...byId(EDGE_DETECTION_CHECK_ID), risk_class: 'soc_gated' }, DOMAIN), /SOC approval/);
  assert.match(targetCheckRequirement({ ...byId(EDGE_DETECTION_CHECK_ID), supported_targets: ['ip'] }, DOMAIN), /compatible endpoint/);
});


describe('complete target catalog inventory is separate from execution', () => {
  const full = CHECK_CATALOG.map((check) => ({ ...check, requires_additional_input: checkRequiresAdditionalInput(check) }));

  it('lets the demo account select and assess all 18 exploit, delivery-pattern and high-scale checks', () => {
    const catalog = CHECK_CATALOG.map((check) => ({ ...check, requires_additional_input: checkRequiresAdditionalInput(check, { tenantId: DEMO_ACCOUNT_TENANT_ID }) }));
    const context = { serverSuppliesInput: true, serverRunnableIndex: targetRunnableIndex(catalog) };
    const reported = catalog.filter((check) => ['exploit', 'pattern', 'high_scale'].includes(check.vector_family));
    assert.equal(reported.length, 18);
    const expanded = withTargetRunnableChecks(CATALOG, catalog, context);
    const individual = new Set(individualChecks(expanded, DOMAIN, context).map((check) => check.check_id));
    const assessment = new Set(assessmentChecks(expanded, DOMAIN, context).map((check) => check.check_id));
    for (const check of reported) {
      assert.equal(targetCheckAvailability(check, DOMAIN, context).state, 'ready', check.check_id);
      assert.equal(targetCheckRequirement(check, DOMAIN, context), '', check.check_id);
      assert.ok(individual.has(check.check_id), check.check_id);
      assert.ok(assessment.has(check.check_id), check.check_id);
      assert.notEqual(targetCheckAvailability(check, DOMAIN, { ...context, serverSuppliesInput: false }).state, 'ready', check.check_id);
      assert.notEqual(targetCheckAvailability(check, DOMAIN, { ...context, serverRunnableIndex: new Map() }).state, 'ready', check.check_id);
    }
    const rows = buildCheckRows({ checks: reported });
    assert.ok(rows.every((row) => row.status === 'not_run' && !row.producesVerdict));
    assert.equal(assessEdgeEfficacy({ rows }).waf.tested, 0);
    assert.equal(assessEdgeEfficacy({ rows }).cdn.tested, 0);
  });

  it('keeps target compatibility, unsupported delivery and server input refusals in demo mode', () => {
    const base = { ...byId(EDGE_DETECTION_CHECK_ID), requires_additional_input: false };
    for (const override of [{ supported_targets: ['ip'] }, { mechanism_supported: false }, { evidence_tier: 'E5' }]) {
      const check = { ...base, ...override };
      const context = { serverSuppliesInput: true, serverRunnableIndex: targetRunnableIndex([check]) };
      assert.notEqual(targetCheckAvailability(check, DOMAIN, context).state, 'ready');
      assert.deepEqual(individualChecks([check], DOMAIN, context), []);
    }
    const check = { ...base, requires_additional_input: true, additional_input_reason: 'origin_binding_required' };
    assert.notEqual(targetCheckAvailability(check, DOMAIN, { serverSuppliesInput: true, serverRunnableIndex: targetRunnableIndex([check]) }).state, 'ready');
  });

  it('keeps every definition and reconciles categories and results with empty, short and bounded history', () => {
    const expectedIds = CHECK_CATALOG.map((check) => check.check_id).sort();
    assert.equal(expectedIds.length, 275);
    for (const runs of [[], [{ id: 'one', check_id: EDGE_DETECTION_CHECK_ID, status: 'completed' }], Array.from({ length: 100 }, (_, index) => ({ id: `history_${index}`, check_id: EDGE_DETECTION_CHECK_ID, status: 'completed', created_at: `2030-01-01T00:00:${String(index % 60).padStart(2, '0')}.000Z` }))]) {
      const rows = buildCheckRows({ checks: full, runs });
      assert.deepEqual(rows.map((row) => row.checkId).sort(), expectedIds);
      assert.equal(Object.values(countRowStatuses(rows)).reduce((sum, count) => sum + count, 0), full.length);
      assert.equal(groupRowsByCategory(rows).reduce((sum, group) => sum + group.rows.length, 0), full.length);
      assert.equal(new Set(rows.map((row) => row.checkId)).size, full.length);
      for (const row of rows.filter((row) => row.checkId !== EDGE_DETECTION_CHECK_ID)) {
        assert.equal(row.status, 'not_run');
        assert.equal(row.source, 'none');
        assert.equal(row.runId, '');
        assert.equal(row.verdict, '');
      }
    }
  });

  it('does not let a server input-complete answer waive support, target or declaration restrictions', () => {
    const base = { ...byId(EDGE_DETECTION_CHECK_ID), requires_additional_input: false };
    const context = { serverRunnableIndex: targetRunnableIndex([base]), declarations: { version: 1 } };
    assert.equal(targetCheckAvailability(base, DOMAIN, context).state, 'ready');
    const cases = [
      [{ mechanism_supported: false }, 'Execution unavailable'],
      [{ probe_profile: { ...base.probe_profile, delivery_supported: false } }, 'Execution unavailable'],
      [{ probe_profile: { ...base.probe_profile, execution_supported: false } }, 'Execution unavailable'],
      [{ supported_targets: ['ip'] }, 'Different target type'],
      [{ evidence_tier: 'E1' }, 'Declaration only'],
      [{ probe_profile: { kind: 'metadata_marker' } }, 'Declaration only'],
      [{ probe_profile: { kind: 'ops_readiness' } }, 'Declaration only'],
      [{ evidence_tier: 'E5' }, 'Monitor only'],
      [{ risk_class: 'soc_gated' }, 'SOC only'],
      [{ safety_constraints: { customer_runnable: false } }, 'SOC only'],
    ];
    for (const [override, label] of cases) {
      const check = { ...base, ...override };
      const availability = targetCheckAvailability(check, DOMAIN, context);
      assert.notEqual(availability.state, 'ready', label);
      assert.equal(availability.label, label);
      assert.ok(availability.detail, label);
      assert.deepEqual(individualChecks([check], DOMAIN, context), []);
      assert.deepEqual(assessmentChecks([check], DOMAIN, context), []);
    }
  });

  it('keeps unmet target inputs and dedicated callbacks non-runnable without fabricating results', () => {
    const pending = { ...byId(EDGE_DETECTION_CHECK_ID), requires_additional_input: true, additional_input_reason: 'two_perspectives_required' };
    const context = { serverRunnableIndex: targetRunnableIndex([pending]) };
    const prerequisite = targetCheckAvailability(pending, DOMAIN, context);
    assert.equal(prerequisite.state, 'needs_perspectives');
    assert.ok(prerequisite.detail);
    assert.equal(buildCheckRows({ checks: [pending] })[0].status, 'not_run');
    const alert = CHECK_CATALOG.find((check) => check.check_id === 'ops.alert_workflow_marker.safe');
    const availability = targetCheckAvailability({ ...alert, requires_additional_input: false }, DOMAIN);
    assert.notEqual(availability.state, 'ready');
    assert.match(availability.detail, /approved signed alert-webhook scope/);
    assert.deepEqual(assessmentChecks(full, DOMAIN).map((check) => check.check_id), assessmentChecks(CATALOG, DOMAIN).map((check) => check.check_id));
  });
});


describe('origin relation check approval is separate from readiness eligibility', () => {
  const target = { id: 'tgt_origin', kind: 'ip', value: '203.0.113.10' };
  const { coverage } = coverageFrom({ target, catalog: CHECK_CATALOG });
  const check = CHECK_CATALOG.find((item) => item.check_id === 'origin.direct_bypass.safe');
  const pair = coverage.pairs.find((item) => item.check_id === check.check_id);

  it('offers exact compatible E2 origin definitions without granting readiness credit or changing pairs', () => {
    const before = structuredClone(pair);
    assert.equal(check.evidence_tier, 'E2');
    assert.equal(pair.exclusion_reason, 'observation_only');
    assert.equal(pair.launchable, null, 'runtime authorization is still unevaluated');
    assert.equal(originRelationCheckEligible(check, target, pair), true);
    assert.deepEqual(pair, before);
    assert.equal(originRelationCheckEligible(check, target, { ...pair, exclusion_reason: 'setup_required' }), true);
  });

  it('rejects mismatched target/check, missing metadata, incompatible or gated definitions', () => {
    for (const invalid of [null, { ...pair, target_id: 'other' }, { ...pair, check_id: 'other' }, { ...pair, mechanism: 'metadata_marker' }]) {
      assert.equal(originRelationCheckEligible(check, target, invalid), false);
    }
    for (const invalid of [null, { ...check, supported_targets: ['fqdn'] }, { ...check, supported_targets: [] }, { ...check, safety_class: 'soc' }, { ...check, risk_class: 'soc_gated' }, { ...check, safety_constraints: { customer_runnable: false } }, { ...check, probe_profile: { kind: 'metadata_marker' } }, { ...check, mechanism_supported: false }]) {
      assert.equal(originRelationCheckEligible(invalid, target, pair), false);
    }
    const hostnameOnly = CHECK_CATALOG.find((item) => item.check_id === 'origin.host_sni_bypass.safe');
    assert.equal(coverage.pairs.some((item) => item.check_id === hostnameOnly.check_id), false);
    assert.equal(originRelationCheckEligible(hostnameOnly, target, { ...pair, check_id: hostnameOnly.check_id }), false);
  });
});


it('never derives an alert callback or automatic assessment scope from catalog metadata alone', () => {
  const alert = CHECK_CATALOG.find((check) => check.check_id === 'ops.alert_workflow_marker.safe');
  assert.equal(checkRequiresAdditionalInput(alert), true);
  for (const input of [alert, { ...alert, requires_additional_input: true }, { ...alert, requires_additional_input: false }]) {
    assert.deepEqual(assessmentChecks([input], DOMAIN), []);
    assert.deepEqual(individualChecks([input], DOMAIN), []);
    assert.match(targetCheckRequirement(input, DOMAIN), /approved signed alert-webhook scope/);
  }
});


it('keeps unsupported mechanisms out of individual and automatic checks even on legacy flag projections', () => {
  const unsupported = CHECK_CATALOG.filter((check) => check.mechanism_supported === false || check.probe_profile?.delivery_supported === false || check.probe_profile?.execution_supported === false);
  for (const target of [DOMAIN, { id: 'ip', kind: 'ip', value: '203.0.113.10' }]) {
    assert.deepEqual(individualChecks(unsupported, target), []);
    assert.deepEqual(assessmentChecks(unsupported, target), []);
  }
  const ipp = CHECK_CATALOG.find((check) => check.check_id === 'reflect.ipp_callback_exposure.safe');
  const { mechanism_supported, ...legacy } = ipp;
  assert.deepEqual(individualChecks([legacy], DOMAIN), [], 'profile delivery flag remains authoritative if top-level flag is absent');
  const sample = { ...CHECK_CATALOG.find((check) => check.check_id === EDGE_DETECTION_CHECK_ID), probe_profile: { kind: 'waf_fingerprint' }, mechanism_supported: true };
  for (const flag of [{ mechanism_supported: false }, { probe_profile: { kind: 'waf_fingerprint', delivery_supported: false } }, { probe_profile: { kind: 'waf_fingerprint', execution_supported: false } }]) assert.deepEqual(assessmentChecks([{ ...sample, ...flag }], DOMAIN), []);
});

it('category guidance confines claims to bounded outside-in observations', () => {
  assert.match(CHECK_CATEGORIES.waf.how, /does not establish internal application receipt/);
  assert.match(CHECK_CATEGORIES.origin.how, /declared alternate endpoint/);
  assert.match(CHECK_CATEGORIES.origin.how, /response alone does not identify your application, confirm bypass, or prove origin lockdown/);
  assert.doesNotMatch(CHECK_CATEGORIES.origin.how, /bypass the WAF and CDN entirely/);
  assert.match(CHECK_CATEGORIES.reflection.how, /Silence does not establish/);
  assert.match(CHECK_CATEGORIES.amplification.how, /does not establish amplification or flood capacity/);
  assert.match(CHECK_CATEGORIES.path.how, /does not confirm arrival or protection inside/);
});

describe('readiness-capable rows and the recommended first check', () => {
  const rows = buildCheckRows({ checks: individualChecks(CATALOG, DOMAIN) });
  const row = (overrides) => ({ checkId: 'x.safe', status: 'not_run', probeKind: 'http_probe', readinessCapable: true, category: CHECK_CATEGORIES.waf, finishedAt: '', startedAt: '', ...overrides });

  it('marks only graded E3 checks that are not observation-only as verdict-capable', () => {
    const base = { check_id: 'demo.safe', name: 'Demo', evidence_tier: 'E3', probe_profile: { kind: 'waf_class_marker_probe', max_requests: 2 } };
    const capable = (check) => buildCheckRows({ checks: [check] })[0].readinessCapable;
    assert.equal(capable(base), true);
    assert.equal(capable({ ...base, evidence_tier: 'E2' }), false);
    assert.equal(capable({ ...base, observation_only: true }), false);
    assert.equal(capable({ ...base, probe_profile: { ...base.probe_profile, observation_only: true } }), false);
    assert.equal(capable({ ...base, probe_profile: { ...base.probe_profile, readiness_conclusion: false } }), false);
    assert.ok(rows.some((entry) => entry.readinessCapable), 'the live catalog has verdict-capable checks');
    assert.ok(rows.some((entry) => !entry.readinessCapable), 'the live catalog has observation checks');
    assert.equal(rows.filter((entry) => entry.readinessCapable && /rate_limit/.test(entry.probeKind) && entry.probeKind !== 'rate_limit_canary_probe').length, 0);
    assert.ok(buildCheckRows({ checks: CHECK_CATALOG }).some((entry) => entry.readinessCapable && entry.probeKind === 'rate_limit_canary_probe'), 'T7 rate-limit canary is verdict-capable');
  });

  it('recommends a not-run verdict-capable marker check and never a rate-limit or observation check', () => {
    const starter = recommendedStarterRow(rows);
    assert.ok(starter);
    assert.equal(starter.readinessCapable, true);
    assert.equal(starter.status, 'not_run');
    assert.equal(starter.probeKind, 'waf_class_marker_probe');
    assert.equal(recommendedStarterRow([row({ checkId: 'a.safe' }), row({ checkId: 'b.safe', probeKind: 'waf_class_marker_probe' })]).checkId, 'b.safe');
    assert.equal(recommendedStarterRow([row({ checkId: 'a.safe' })]).checkId, 'a.safe');
    assert.equal(recommendedStarterRow([row({ readinessCapable: false }), row({ probeKind: 'http_rate_limit_probe', checkId: 'r.safe' })]), null);
    assert.equal(recommendedStarterRow([]), null);
  });

  it('stops recommending once any row has a recorded verdict', () => {
    for (const status of ['passed', 'failed', 'inconclusive']) {
      assert.equal(recommendedStarterRow([row({ checkId: 'a.safe' }), row({ checkId: 'b.safe', status })]), null, status);
    }
    assert.equal(recommendedStarterRow([row({ checkId: 'a.safe' }), row({ checkId: 'b.safe', status: 'observed' })]).checkId, 'a.safe');
  });
});

describe('WAF managed rules versus custom canary rules', () => {
  const NOW = Date.parse('2030-01-08T00:00:00.000Z');
  const marker = (checkId, status, extra = {}) => ({
    checkId, status, readinessCapable: true, category: CHECK_CATEGORIES.waf, runId: `run_${checkId}`,
    probeKind: 'waf_class_marker_probe', assuranceScope: 'custom_canary_rule', markerClass: checkId,
    finishedAt: status === 'not_run' ? '' : '2030-01-07T00:00:00.000Z', startedAt: '', ...extra,
  });

  it('returns null when no marker check has a recorded result', () => {
    assert.equal(wafRuleEnforcement([]), null);
    assert.equal(wafRuleEnforcement([marker('waf.crlf_injection_marker.safe', 'not_run'), marker('waf.evasion_base64_wrap.safe', 'running', { probeKind: 'waf_evasion_marker_probe' })]), null);
    assert.equal(wafRuleEnforcement(buildCheckRows({ checks: individualChecks(CATALOG, DOMAIN) })), null);
  });

  it('splits managed rule markers from custom canary rules and rolls managed markers up by class', () => {
    const rows = [
      marker('waf.sqli_managed_marker.safe', 'passed', { assuranceScope: 'managed_rule_marker', markerClass: 'sqli' }),
      marker('waf.entry_path_login_marker.safe', 'passed', { assuranceScope: 'managed_rule_marker', markerClass: 'sqli' }),
      marker('waf.xss_managed_marker.safe', 'passed', { assuranceScope: 'managed_rule_marker', markerClass: 'xss' }),
      marker('waf.path_traversal_managed_marker.safe', 'failed', { assuranceScope: 'managed_rule_marker', markerClass: 'path_traversal' }),
      marker('waf.scanner_signature_marker.safe', 'inconclusive', { assuranceScope: 'managed_rule_marker', markerClass: 'scanner_user_agent' }),
      marker('waf.ssrf_marker.safe', 'passed'),
      marker('waf.xxe_marker.safe', 'passed'),
      marker('waf.crlf_injection_marker.safe', 'failed'),
      marker('waf.nosql_injection_marker.safe', 'passed', { finishedAt: '2029-01-01T00:00:00.000Z' }),
      marker('waf.evasion_double_url.safe', 'passed', { probeKind: 'waf_evasion_marker_probe', assuranceScope: '' }),
    ];
    const summary = wafRuleEnforcement(rows, { nowMs: NOW });
    assert.deepEqual(summary.managed, { enforced: 2, notEnforced: 1, inconclusive: 1, ignored: 0, notRun: 0, total: 4, tested: 3 });
    assert.deepEqual(summary.custom, { enforced: 2, notEnforced: 1, inconclusive: 0, ignored: 1, notRun: 0, total: 4, tested: 3 });
    assert.equal(summary.evasion.enforced, 1);
    const lines = wafRuleSentences(summary);
    assert.equal(lines[0].label, 'Managed rules enforced');
    assert.equal(lines[0].ratio, '2 of 3 markers');
    assert.match(lines[0].detail, /1 inconclusive/);
    assert.equal(lines[1].label, 'Custom canary rules enforced');
    assert.equal(lines[1].ratio, '2 of 3');
    assert.match(lines[1].detail, /1 not counted/);
  });

  it('excludes fingerprint, rate-limit, enforcement, exploit and observation rows', () => {
    const summary = wafRuleEnforcement([
      marker('waf.crlf_injection_marker.safe', 'passed'),
      marker(EDGE_DETECTION_CHECK_ID, 'passed', { probeKind: 'waf_fingerprint_observation' }),
      marker('waf.low_rate_limit.safe', 'failed', { probeKind: 'rate_limit_sequence' }),
      marker('waf.log4shell_marker.safe', 'failed', { category: CHECK_CATEGORIES.exploit }),
      marker('waf.observed_marker.safe', 'failed', { readinessCapable: false }),
    ], { nowMs: NOW });
    assert.equal(summary.custom.total, 1);
    assert.equal(summary.managed.total, 0);
  });

  it('labels every live class marker as managed or custom canary from the catalog', () => {
    const rows = buildCheckRows({ checks: individualChecks(CATALOG, DOMAIN) }).filter((entry) => entry.probeKind === 'waf_class_marker_probe');
    assert.ok(rows.length > 0);
    assert.ok(rows.every((entry) => ['managed_rule_marker', 'custom_canary_rule'].includes(entry.assuranceScope)), 'every class marker carries an assurance scope');
    assert.ok(rows.some((entry) => entry.assuranceScope === 'custom_canary_rule'));
  });
});

describe('check row vocabulary', () => {
  it('uses the shared verdict words for protected and gap rows', () => {
    assert.equal(ROW_STATUS_META.passed.label, 'Protected');
    assert.equal(ROW_STATUS_META.failed.label, 'Gap found');
  });

  it('never tells customers they can start or schedule high-scale scenarios', () => {
    assert.match(CHECK_CATEGORIES.high_scale.how, /customers cannot start or schedule them/);
    assert.doesNotMatch(CHECK_CATEGORIES.high_scale.how, /Customers request them/);
  });
});
