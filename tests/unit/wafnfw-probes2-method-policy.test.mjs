import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  METHOD_POLICY_DISALLOWED_METHODS,
  WAF_METHOD_POLICY_MAX_REQUESTS,
  WAF_METHOD_POLICY_PROBE_KIND,
  runWafMethodPolicyProbe,
} from '../../src/lib/vectorProbes/methodPolicyProbes.mjs';
import { CAPABILITY_PROBE_DISPATCH, probeWafMethodPolicy } from '../../src/lib/capabilityProbes.mjs';

function okResponse(status, headers = {}) {
  return { status, headers: new Map(Object.entries(headers)) };
}

function job(overrides = {}) {
  return {
    constraints: { timeout_ms: 1000, max_requests: 8 },
    probe_profile: { kind: WAF_METHOD_POLICY_PROBE_KIND, max_requests: 8 },
    target: { kind: 'url', value: 'https://edge.example.test/app' },
    ...overrides,
  };
}

describe('waf method policy probe', () => {
  it('registers the named executor', () => {
    assert.equal(CAPABILITY_PROBE_DISPATCH.waf_method_policy_probe.name, 'probeWafMethodPolicy');
  });

  it('blocks TRACE and ASTRANULLPROBE with a WAF signature', async () => {
    const result = await runWafMethodPolicyProbe({
      url: 'https://edge.example.test/app',
      fetchFn: async (_url, init) => {
        if (METHOD_POLICY_DISALLOWED_METHODS.includes(init.method)) {
          return okResponse(403, { 'x-waf-block': '1' });
        }
        return okResponse(200);
      },
    });
    assert.equal(result.enforcement, 'enforced');
    assert.equal(result.posture, 'protected');
    assert.equal(result.source_penalized, false);
    assert.equal(result.requests_sent, 4);
    assert.deepEqual(result.method_results.map((row) => row.method), ['TRACE', 'ASTRANULLPROBE']);
    assert.ok(result.method_results.every((row) => row.outcome === 'blocked'));
  });

  it('allows disallowed methods when the edge does not enforce', async () => {
    const result = await runWafMethodPolicyProbe({
      url: 'https://edge.example.test/app',
      fetchFn: async () => okResponse(200),
    });
    assert.equal(result.enforcement, 'not_enforced');
    assert.equal(result.posture, 'exposed');
    assert.ok(result.method_results.every((row) => row.outcome === 'allowed'));
  });

  it('grades 405/501 without a WAF signature as origin rejection', async () => {
    const result = await runWafMethodPolicyProbe({
      url: 'https://edge.example.test/app',
      fetchFn: async (_url, init) => {
        if (init.method === 'TRACE') return okResponse(405);
        if (init.method === 'ASTRANULLPROBE') return okResponse(501);
        return okResponse(200);
      },
    });
    assert.equal(result.inconclusive_reason, 'not_enforced_by_waf_but_rejected_by_origin');
    assert.equal(result.posture, 'inconclusive');
    assert.ok(result.method_results.every((row) => row.origin_rejected === true));
    assert.ok(result.method_results.every((row) => row.reason === 'not_enforced_by_waf_but_rejected_by_origin'));
  });

  it('marks source_penalized when the trailing GET is denied', async () => {
    let n = 0;
    const result = await runWafMethodPolicyProbe({
      url: 'https://edge.example.test/app',
      fetchFn: async () => {
        n += 1;
        return n === 4 ? okResponse(403, { 'x-waf-block': '1' }) : okResponse(200);
      },
    });
    assert.equal(result.source_penalized, true);
    assert.equal(result.posture_status, 'source_penalized');
    assert.equal(result.enforcement, 'unknown');
  });

  it('never sends a body and stays inside the request cap', async () => {
    const inits = [];
    const result = await runWafMethodPolicyProbe({
      url: 'https://edge.example.test/app',
      fetchFn: async (_url, init) => {
        inits.push(init);
        return okResponse(200);
      },
    });
    assert.ok(result.requests_sent <= WAF_METHOD_POLICY_MAX_REQUESTS);
    for (const init of inits) assert.equal(init.body, undefined);
    assert.deepEqual(inits.map((row) => row.method), ['GET', 'TRACE', 'ASTRANULLPROBE', 'GET']);
  });

  it('returns unsupported_target with zero requests without a URL', async () => {
    const result = await runWafMethodPolicyProbe({ fetchFn: async () => okResponse(200) });
    assert.equal(result.error_class, 'unsupported_target');
    assert.equal(result.requests_sent, 0);
  });

  it('delegated executor maps a blocked matrix to blocked', async () => {
    const outcome = await probeWafMethodPolicy(job(), {
      signedJobVerified: true,
      fetchFn: async (_url, init) => (
        METHOD_POLICY_DISALLOWED_METHODS.includes(init.method)
          ? okResponse(403, { 'x-waf-block': '1' })
          : okResponse(200)
      ),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.enforcement, 'enforced');
    assert.equal(outcome.requests_sent, 4);
  });
});
