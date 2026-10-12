import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { CHECK_CATALOG, getCheckById } from '../../src/contracts/checks.mjs';
import { executeProbeForJob } from '../../workers/probe-worker.mjs';
import { deliveryDisposition } from '../fixtures/check-delivery-coverage.mjs';
import { catalogSignedJob, createCheckDeliveryFixtures, executeMemoryDelivery } from '../helpers/check-delivery-fixtures.mjs';

// RED regressions are deliberately not skips or expected-failure tests. Only the
// existing production helper/worker repairs can turn these into passing claims.
describe('catalog-known no-execution selectors refuse before destination DNS', () => {
  for (const check of CHECK_CATALOG.filter((c) => ['unsupported_delivery', 'additional_signed_scope'].includes(deliveryDisposition(c).disposition))) {
    it(`${check.check_id}: exact refusal, zero resolvers and zero transports`, async () => {
      const calls = [];
      const job = catalogSignedJob(check);
      const result = await executeProbeForJob(job, {
        resolve4Fn: async (name) => { calls.push(['A', name]); return ['127.0.0.1']; },
        resolve6Fn: async (name) => { calls.push(['AAAA', name]); return []; },
        destinationPolicy: { allowLoopback: true },
        createSocket: () => { throw new Error('no-execution selector must not initialize UDP'); },
        connectFn: () => { throw new Error('no-execution selector must not initialize a stream'); },
        httpRequestFn: () => { throw new Error('no-execution selector must not initialize HTTP'); },
        httpsRequestFn: () => { throw new Error('no-execution selector must not initialize HTTPS'); },
      });
      assert.equal(result.external_result, 'not_run');
      const reason = result.metadata.inconclusive_reason ?? result.metadata.not_run_reason;
      assert.equal(reason, deliveryDisposition(check).reason);
      assert.deepEqual(calls, [], `${check.check_id} unexpectedly resolved before its known helper refusal`);
      assert.equal(result.probe_requests_sent, 0);
      assert.equal(result.destination_resolver_attempts, 0);
      assert.equal(result.total_operations, 0);
      assert.equal(result.metadata.readiness_conclusion, false);
    });
  }
});

describe('real signed semantic comparison and peer-settings regression proofs', () => {
  let fixtures;
  before(async () => { fixtures = await createCheckDeliveryFixtures(); });
  after(async () => { await fixtures?.close(); });
  const evasions = CHECK_CATALOG.filter((c) => c.probe_profile?.kind === 'waf_evasion_marker_probe' && c.mechanism_supported);
  for (const check of evasions) {
    it(`${check.check_id}: enforced complete real comparison earns only scoped scenario credit`, async () => {
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      assert.equal(result.started.error, undefined);
      assert.equal(result.outcome.external_result, 'blocked');
      assert.equal(result.outcome.metadata.comparison_complete, true);
      assert.equal(result.outcome.metadata.permitted_baseline_health, 'healthy');
      assert.equal(result.outcome.metadata.enforcement, 'enforced');
      assert.equal(result.event.metadata.enforcement, 'enforced');
      assert.equal(result.verdict.verdict, 'edge_protected');
      assert.equal(result.verdict.confidence, 'external_only');
      assert.equal(result.findings.length, 0);
      assert.equal(result.readiness.coverage.passed_count, 1);
      assert.equal(result.readiness.coverage.partial_count, 0);
      assert.equal(result.receipt.actual_wire.filter((row) => row.transport === 'http').length, 3);
    });
    for (const scenario of ['variant_allowed', 'partial', 'permitted_unhealthy', 'variant_unsigned']) {
      it(`${check.check_id}/${scenario}: never enforced and never readiness pass`, async () => {
        const result = await executeMemoryDelivery(check, fixtures.forCheck(check, { scenario }));
        assert.notEqual(result.outcome.metadata.enforcement, 'enforced');
        assert.equal(result.readiness.coverage.passed_count, 0);
        if (scenario === 'variant_allowed') {
          assert.equal(result.outcome.external_result, 'connected');
          assert.equal(result.outcome.metadata.enforcement, 'not_enforced');
          // Allowing an inert marker is not exploitability proof.
          assert.equal(result.verdict.verdict, 'inconclusive');
          assert.equal(result.findings.length, 0);
        } else {
          assert.equal(result.outcome.external_result, 'not_run');
          assert.equal(result.verdict.verdict, 'inconclusive');
          assert.equal(result.findings.length, 0);
        }
      });
    }
  }
  for (const id of ['l7.hpack_bomb.readiness', 'l7.request_parser_size.posture']) {
    it(`${id}: max_events=1 accepts one real event and publishes without charging a nonexistent event`, async () => {
      const check = getCheckById(id);
      assert.equal(check.safety_constraints.max_events, 1);
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      assert.equal(result.verdict.confidence, 'external_only');
      assert.equal(result.events.length, 1);
      assert.equal(result.events[0].id, result.event.id);
      assert.equal(result.audits.some((row) => row.action === 'test_run.event_cap_denied'), false);
      assert.equal(result.readiness.coverage.passed_count, 0);
    });
  }
  for (const id of ['protocol.http2_readiness.safe', 'protocol.http2_stream_concurrency.safe', 'protocol.http2_rapid_reset_readiness.safe']) {
    it(`${id}: peer SETTINGS, never Node's pre-peer defaults`, async () => {
      const check = getCheckById(id);
      const result = await executeMemoryDelivery(check, fixtures.forCheck(check));
      assert.equal(result.outcome.external_result, 'connected');
      assert.equal(result.outcome.metadata.max_concurrent_streams, 7);
      assert.equal(result.outcome.metadata.enable_push, false);
      assert.equal(result.verdict.verdict, 'inconclusive');
      assert.equal(result.readiness.coverage.passed_count, 0);
    });
  }
});
