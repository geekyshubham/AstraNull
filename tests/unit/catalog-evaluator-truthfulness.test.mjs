import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isBlockedOrChallenged } from '../../src/lib/outsideInWafScanner.mjs';
import { runWafClassMarkerProbe } from '../../src/lib/vectorProbes/wafClassProbes.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { probeWafMethodPolicy } from '../../src/lib/capabilityProbes.mjs';
import { WAF_GRADING_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';

const response = (status, headers = {}) => ({ status, headers: new Map(Object.entries(headers)) });
const baseline = { status_code: 200 };
const correlate = (probeKind, overrides = {}) => correlateExternalOnlyVerdict({ probeKind, externalResult: 'blocked', expectedBehavior: 'must_block_before_origin', probeIoObserved: true, ...overrides });

describe('catalog evaluator truthful comparison regressions', () => {
  it('missing Location never becomes an unchanged allowed redirect', () => {
    for (const previous of [undefined, '/login']) {
      const result = isBlockedOrChallenged({ status_code: 301 }, { status_code: 301, location: previous });
      assert.equal(result.allowed, false);
      assert.equal(result.inconclusive, true);
      assert.equal(result.reason, 'redirect_location_missing');
    }
    assert.equal(isBlockedOrChallenged({ status_code: 301, location: '/login' }, baseline).outcome, 'redirected');
    assert.equal(isBlockedOrChallenged({ status_code: 301, location: '/login' }, { status_code: 301, location: '/login' }).outcome, 'allowed');
  });
  it('keeps completed unsigned placements separate from graded placements', async () => {
    let n = 0;
    const result = await runWafClassMarkerProbe({ url: 'https://fixture.test/', marker_class: 'sqli', rng: () => 0.5,
      fetchFn: async () => { n += 1; return response(n === 2 ? 404 : n === 3 || n === 4 ? 403 : 200, n === 3 || n === 4 ? { 'x-waf-block': '1' } : {}); } });
    assert.equal(result.planned_marker_legs, 3);
    assert.equal(result.attempted_marker_legs, 3);
    assert.equal(result.completed_marker_legs, 3);
    assert.equal(result.graded_marker_legs, 2);
    assert.equal(result.ungraded_marker_legs, 1);
    assert.equal(result.missing_marker_legs, 0);
    assert.equal(result.comparison_complete, true);
    assert.equal(result.posture, 'protected');
  });
  it('does not call an aborted required leg complete after an earlier blocked leg', async () => {
    let n = 0;
    const result = await runWafClassMarkerProbe({ url: 'https://fixture.test/', marker_class: 'sqli', rng: () => 0.5,
      fetchFn: async () => { n += 1; if (n === 3) throw new Error('peer reset'); return n === 2 ? response(403, { 'x-waf-block': '1' }) : response(200); } });
    assert.equal(result.planned_marker_legs, 3);
    assert.equal(result.attempted_marker_legs, 2);
    assert.equal(result.completed_marker_legs, 1);
    assert.equal(result.graded_marker_legs, 1);
    assert.equal(result.missing_marker_legs, 2);
    assert.equal(result.comparison_complete, false);
    assert.equal(result.readiness_conclusion, false);
    assert.equal(result.enforcement, 'unknown');
  });
  for (const kind of ['waf_class_marker_probe', 'waf_method_policy_probe', 'dns_axfr_leak', 'rate_limit_canary_probe']) {
    for (const externalResult of ['not_run', 'timeout', 'error']) it(`${kind}: ${externalResult} cannot be overridden by enforced metadata`, () => {
      const result = correlate(kind, { externalResult, probeMetadata: { enforcement: 'enforced', comparison_complete: true, baseline_health: 'healthy', requests_sent: 4, first_limited_at: 3, allowed_before_limit: 2 }, declarations: { waf: { rate_limit_canary: { threshold: 2 } } } });
      assert.equal(result.verdict, 'inconclusive');
      assert.equal(result.createsFinding, false);
    });
    it(`${kind}: zero attested I/O cannot establish enforcement`, () => {
      const result = correlate(kind, { probeIoObserved: false, probeMetadata: { enforcement: 'enforced', requests_sent: 4, first_limited_at: 3, allowed_before_limit: 2 }, declarations: { waf: { rate_limit_canary: { threshold: 2 } } } });
      assert.equal(result.verdict, 'inconclusive');
      assert.equal(result.createsFinding, false);
    });
  }
  for (const budget of [1, 2, 3, 8]) it(`preserves a fixed budget-selected plan at cap ${budget}`, async () => {
    let calls = 0;
    const raw = await runWafClassMarkerProbe({ url: 'https://fixture.test/', marker_class: 'sqli', max_requests: budget,
      fetchFn: async () => { calls += 1; return response(200); } });
    assert.equal(raw.planned_marker_legs, Math.min(3, Math.max(0, budget - 2)));
    assert.equal(raw.completed_marker_legs, raw.planned_marker_legs);
    assert.equal(raw.missing_marker_legs, 0);
    assert.equal(raw.comparison_complete, budget >= 3);
    assert.ok(calls <= budget);
  });
  it('rejects contradictory, legacy or incomplete managed comparison metadata', async () => {
    const raw = await runWafClassMarkerProbe({ url: 'https://fixture.test/', marker_class: 'sqli', fetchFn: async () => response(200) });
    assert.equal(correlate('waf_class_marker_probe', { externalResult: 'connected', probeMetadata: raw }).verdict, 'exposed');
    for (const mutation of [
      { classifier_version: 'marker-comparison-v4' }, { grading_version: 'waf-grading.v2' },
      { completed_marker_legs: 2 }, { graded_marker_legs: 0 }, { missing_marker_legs: 1 },
      { source_penalized: true }, { baseline_health: 'unhealthy' }, { comparison_complete: false },
      { enforcement: 'enforced' },
    ]) {
      const result = correlate('waf_class_marker_probe', { externalResult: 'connected', probeMetadata: { ...raw, ...mutation } });
      assert.equal(result.verdict, 'inconclusive', JSON.stringify(mutation));
      assert.equal(result.createsFinding, false);
    }
  });
  it('preserves the actual-method scoped E2 verdict while forbidding readiness credit', async () => {
    const methods = [];
    const outcome = await probeWafMethodPolicy({
      constraints: { timeout_ms: 1000, max_requests: 8 },
      probe_profile: { kind: 'waf_method_policy_probe', max_requests: 8 },
      target: { kind: 'url', value: 'https://fixture.test/' },
    }, { signedJobVerified: true, fetchFn: async (_url, init) => {
      methods.push(init.method);
      return init.method === 'GET' ? response(200) : response(403, { 'x-waf-block': '1' });
    } });
    assert.deepEqual(methods, ['GET', 'TRACE', 'ASTRANULLPROBE', 'GET']);
    assert.equal(outcome.metadata.grading_version, WAF_GRADING_VERSION);
    assert.equal(outcome.metadata.produces_verdict, true);
    assert.equal(outcome.metadata.observation_only, true);
    assert.equal(outcome.metadata.readiness_conclusion, false);
    const verdict = correlate('waf_method_policy_probe', { externalResult: outcome.external_result, probeMetadata: outcome.metadata });
    assert.equal(verdict.verdict, 'protected');
    assert.equal(verdict.createsFinding, false);
  });
  it('does not expose nested installed-rule verdicts for setup-unavailable custom canaries', async () => {
    const raw = await runWafClassMarkerProbe({ url: 'https://fixture.test/', marker_class: 'ssrf', fetchFn: async () => response(200) });
    assert.equal(raw.posture, 'inconclusive');
    for (const path of raw.paths) {
      assert.equal(path.posture, 'inconclusive');
      assert.equal(path.enforcement, 'unknown');
    }
  });
  it('opaque canary without exact installed-token setup is an observation, not a failed installed rule', async () => {
    const raw = await runWafClassMarkerProbe({ url: 'https://fixture.test/', marker_class: 'http_method_policy', fetchFn: async () => response(301, { location: '/login' }) });
    assert.equal(raw.setup_required, true);
    assert.equal(raw.readiness_conclusion, false);
    const result = correlate('waf_class_marker_probe', { externalResult: 'connected', probeMetadata: raw });
    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.createsFinding, false);
    assert.doesNotMatch(result.explanation, /was not enforced|rule.*failed/i);
    assert.match(result.explanation, /setup|installed/i);
  });
});
