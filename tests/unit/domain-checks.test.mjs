import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, customerSelectableChecks } from '../../src/contracts/checks.mjs';
import { MAX_SCAN_CHECKS, MAX_SCAN_STEPS, planScanSteps } from '../../src/contracts/validationScanManagement.mjs';
import {
  CHECK_CATEGORIES,
  EDGE_DETECTION_CHECK_ID,
  assessEdgeEfficacy,
  buildCheckRows,
  declarationOnlyChecks,
  edgeDetectionPhase,
  edgeEvidenceSignals,
  efficacySentence,
  groupRowsByCategory,
  rowProgress,
  runAllChecks,
  shouldAutoDetectEdge,
} from '../../apps/web/react/src/lib/domain-checks.mjs';

const CATALOG = customerSelectableChecks(CHECK_CATALOG);
const DOMAIN = { id: 'tgt_1', kind: 'fqdn', value: 'shop.example.com' };
const byId = (id) => CATALOG.find((check) => check.check_id === id);

function row(rows, id) {
  return rows.find((entry) => entry.checkId === id);
}

describe('run-all check set for a domain', () => {
  const runAll = runAllChecks(CATALOG, DOMAIN);

  it('runs the fingerprint first, origin next, and never declaration-only or SOC-gated checks', () => {
    assert.equal(runAll[0].check_id, EDGE_DETECTION_CHECK_ID);
    assert.equal(runAll[1].vector_family, 'origin');
    assert.ok(runAll.every((check) => check.evidence_tier !== 'E1' && check.probe_profile?.kind !== 'metadata_marker'));
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
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).status, 'passed');
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
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).status, 'failed');
    assert.equal(row(rows, EDGE_DETECTION_CHECK_ID).runId, 'run_new');
    assert.equal(row(rows, 'waf.marker_rule.safe').status, 'inconclusive');
    assert.equal(row(rows, 'origin.leak_scan.safe').status, 'not_run');
  });

  it('shows customer-facing check names, not raw catalog jargon', () => {
    const jwt = byId('waf.jwt_tamper_marker.safe');
    assert.match(jwt.name, /API/);
    const [rendered] = buildCheckRows({ checks: [jwt] });
    assert.doesNotMatch(rendered.name, /\bAPI\b/);
  });

  it('groups rows by category with failures first', () => {
    const scan = { steps: [
      { check_id: EDGE_DETECTION_CHECK_ID, status: 'verdicted', verdict: { verdict: 'edge_protected' } },
      { check_id: 'waf.marker_rule.safe', status: 'verdicted', verdict: { verdict: 'edge_exposed' } },
    ] };
    const groups = groupRowsByCategory(buildCheckRows({ checks, scan }));
    assert.equal(groups[0].category.id, 'waf');
    assert.equal(groups[0].rows[0].status, 'failed');
    assert.equal(groups[0].counts.passed, 1);
    assert.equal(groups[1].category.id, 'origin');
  });
});

describe('WAF and CDN efficacy', () => {
  const mk = (layer, status, name = `${layer}-${status}`) => ({ status, name, category: { layer } });
  const edge = { waf: { status: 'detected', vendor: 'cloudflare' }, cdn: { status: 'detected', provider: 'cloudflare' } };

  it('reports protecting only when every tested class was blocked', () => {
    const result = assessEdgeEfficacy({ rows: [mk('waf', 'passed'), mk('waf', 'passed'), mk('cdn', 'passed'), mk('waf', 'inconclusive')], edge });
    assert.equal(result.waf.status, 'protecting');
    assert.equal(result.waf.score, 100);
    assert.equal(result.waf.inconclusive, 1);
    assert.equal(result.cdn.status, 'protecting');
    assert.match(efficacySentence(result.waf), /Blocked 2 of 2/);
  });

  it('scores partial and not-protecting from exposed verdicts', () => {
    const partial = assessEdgeEfficacy({ rows: [mk('waf', 'passed'), mk('waf', 'failed', 'SQLi marker')], edge });
    assert.equal(partial.waf.status, 'partial');
    assert.equal(partial.waf.score, 50);
    assert.deepEqual(partial.waf.exposedChecks, ['SQLi marker']);
    assert.equal(assessEdgeEfficacy({ rows: [mk('cdn', 'failed')], edge }).cdn.status, 'not_protecting');
    const weak = assessEdgeEfficacy({ rows: [mk('waf', 'passed'), mk('waf', 'failed', 'a'), mk('waf', 'failed', 'b')], edge });
    assert.equal(weak.waf.status, 'mostly_exposed', 'blocking a minority of tested classes is not partial protection');
    assert.equal(weak.waf.tone, 'danger');
  });

  it('downgrades to bypassable when the origin is reachable directly', () => {
    const viaRow = assessEdgeEfficacy({ rows: [mk('waf', 'passed'), mk('cdn', 'passed'), mk('origin', 'failed')], edge });
    assert.equal(viaRow.waf.status, 'bypassable');
    assert.equal(viaRow.cdn.status, 'bypassable');
    const viaEdge = assessEdgeEfficacy({ rows: [mk('waf', 'passed')], edge: { ...edge, network_firewall: { direct_origin_reachability: { status: 'exposed' } } } });
    assert.equal(viaEdge.waf.status, 'bypassable');
  });

  it('never claims efficacy without evidence, and falls back to fingerprint markers', () => {
    assert.equal(assessEdgeEfficacy({ rows: [], edge: null }).waf.status, 'unknown');
    assert.equal(assessEdgeEfficacy({ rows: [], edge }).waf.status, 'present_unmeasured');
    assert.equal(assessEdgeEfficacy({ rows: [], edge: { waf: { status: 'not_detected' }, cdn: { status: 'not_detected' } } }).cdn.status, 'absent');
    const markers = assessEdgeEfficacy({ rows: [], edge: { ...edge, effectiveness: { tested_count: 3, blocked_count: 2, passed_count: 1 } } });
    assert.equal(markers.waf.status, 'partial');
    assert.equal(markers.waf.basis, 'fingerprint_markers');
    assert.equal(markers.cdn.status, 'present_unmeasured');
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
    assert.deepEqual(facts.map((fact) => fact.id), ['cname', 'ips', 'wafw00f', 'cdncheck']);
    assert.match(facts[0].value, /→/);
  });

  it('shows evaluating while queued and never auto-detects before ownership is proven', () => {
    assert.equal(edgeDetectionPhase({ eligible: false, edge: null }), 'locked');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: null, localRequest: 'pending' }), 'evaluating');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: null, request: { run_status: 'collecting' } }), 'evaluating');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: null, request: { run_status: 'completed' } }), 'no_result');
    assert.equal(edgeDetectionPhase({ eligible: true, edge: { status: 'detected' } }), 'detected');
    const base = { eligible: true, featureEnabled: true, canRun: true, edge: null, request: null, scanActive: false, attempted: false, hasPriorRuns: false };
    assert.equal(shouldAutoDetectEdge(base), true);
    assert.equal(shouldAutoDetectEdge({ ...base, eligible: false }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, scanActive: true }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, request: { run_status: 'completed' } }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, attempted: true }), false);
    assert.equal(shouldAutoDetectEdge({ ...base, hasPriorRuns: true }), false, 'only freshly onboarded domains auto-detect');
  });
});
