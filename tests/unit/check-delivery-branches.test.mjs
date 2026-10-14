import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { CHECK_CATALOG, getCheckById } from '../../src/contracts/checks.mjs';
import { CHECK_DELIVERY_INVENTORY, accountDeliveryReceipts } from '../fixtures/check-delivery-coverage.mjs';
import { createCheckDeliveryFixtures, executeMemoryDelivery } from '../helpers/check-delivery-fixtures.mjs';
import { assertExistingBehaviorCase } from '../helpers/existing-behavior-coverage.mjs';
import { hardTimeoutSchedulerToleranceMs } from '../../src/lib/probeResultValidation.mjs';
import { assertDeliveredReflectorRequest } from '../helpers/check-delivery-payload-assertions.mjs';

// Each branch is an owned peer behavior, never a cloned or re-signed catalog profile.
// Definition invocations remain separately required; aliases share only identical
// full-delivery-fingerprint branch obligations. Unimplemented obligations stay gaps.
const FIRST_SLICE_IDS = new Set([
  'l7.expensive_endpoint.safe', 'waf.fingerprint.safe',
  'dns.authoritative_response.safe', 'dns.random_prefix_nxdomain.safe',
  'dns.zone_transfer_exposure.safe', 'tls.full_audit.safe',
  'tls.profile_exposure.safe', 'tls.idle_connection_timeout.safe',
  'protocol.grpc_reflection_stream.safe', 'protocol.websocket_connection_controls.safe',
]);
const branchReceipts = [];
const firstSlice = CHECK_DELIVERY_INVENTORY.branch_obligations.filter((row) => FIRST_SLICE_IDS.has(row.check_id) || row.kind === 'reflection_service_probe');

function assertBranch(obligation, result, fixture) {
  const { outcome, verdict, readiness, findings, receipt } = result;
  const evidence = fixture.peerEvidence();
  assert.ok(evidence.length > 0, 'actual owned peer branch evidence required');
  assert.equal(verdict.confidence, 'external_only');
  assert.equal(readiness.coverage.passed_count, 0);
  if (obligation.branch === 'axfr_transfer') {
    assert.equal(findings.length, 1, 'actual complete zone transfer supports only its direct exposure finding');
    assert.equal(verdict.verdict, 'exposed');
  } else if (
    obligation.kind === 'reflection_service_probe'
    && obligation.branch === 'payload_bytes'
    && outcome.metadata.protocol_identity_confirmed === true
  ) {
    assert.equal(findings.length, 1, 'protocol-validated reflector reply is a violation finding');
  } else assert.equal(findings.length, 0, 'negative/unconfirmed fixture is not exploitability proof');
  assert.ok(receipt.execution_receipt.digest);
  assert.ok(receipt.accepted_event.id && receipt.published_verdict.id);
  assert.ok(outcome.total_operations <= result.job.constraints.max_total_operations);
  assert.ok(outcome.duration_ms <= result.job.constraints.timeout_ms + hardTimeoutSchedulerToleranceMs(result.job.constraints.timeout_ms));
  if (obligation.kind === 'reflection_service_probe') {
    assertDeliveredReflectorRequest(receipt);
    assert.notEqual(outcome.metadata.readiness_conclusion, true);
    if (obligation.branch === 'unconfirmed_response') {
      assert.notEqual(outcome.metadata.protocol_identity_confirmed, true);
      assert.notEqual(outcome.metadata.reflector_confirmed, true);
    }
  }
  if (obligation.branch === 'timeout') {
    assert.equal(outcome.external_result, 'timeout', JSON.stringify(outcome));
    assert.ok(evidence.some((row) => row.event === 'response_withheld'));
  } else if (obligation.branch === 'cancel') {
    assert.ok(evidence.some((row) => row.event === 'cancel_requested'));
    assert.ok(evidence.some((row) => ['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(row.event)));
    assert.ok(outcome.duration_ms < 1000, `cancellation must settle promptly, not at unrelated signed deadline: ${outcome.duration_ms}ms`);
    assert.ok(['error', 'timeout', 'not_run'].includes(outcome.external_result), JSON.stringify(outcome));
  } else if (obligation.branch === 'peer_error' || obligation.branch === 'invalid_tls') {
    assert.ok(['error', 'timeout', 'not_run'].includes(outcome.external_result), JSON.stringify(outcome));
    assert.ok(evidence.some((row) => ['peer_reset', 'malformed_tls_sent'].includes(row.event)));
  } else if (obligation.branch === 'nxdomain') {
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.rcode, 3);
    assert.equal(outcome.metadata.protocol_identity_confirmed, true);
    assert.ok(evidence.some((row) => row.rcode === 3));
  } else if (obligation.branch === 'wrong_peer') {
    assert.equal(outcome.external_result, 'timeout');
    assert.ok(evidence.some((row) => row.event === 'wrong_peer_response_sent' && row.actual_port !== row.expected_port));
    assert.notEqual(outcome.metadata.protocol_identity_confirmed, true);
  } else if (obligation.branch === 'malformed_response') {
    assert.notEqual(outcome.metadata.protocol_identity_confirmed, true, JSON.stringify(outcome));
    assert.ok(evidence.some((row) => ['dns_response_constructed', 'grpc_response_sent'].includes(row.event)));
  } else if (obligation.branch === 'axfr_transfer') {
    assert.equal(outcome.metadata.transfer_complete, true, JSON.stringify(outcome));
    assert.equal(outcome.metadata.axfr_leak, true);
    assert.equal(outcome.metadata.protocol_identity_confirmed, true);
    assert.ok(evidence.some((row) => row.qtype === 252 && row.rcode === 0));
  } else if (obligation.branch === 'unimplemented') {
    assert.equal(outcome.metadata.grpc_status, '12');
    assert.notEqual(outcome.metadata.reflection_service_routed, true);
    assert.notEqual(outcome.metadata.protocol_identity_confirmed, true);
    assert.ok(evidence.some((row) => row.grpc_status === '12'));
  } else if (obligation.branch === 'invalid_upgrade') {
    assert.notEqual(outcome.metadata.websocket_upgrade_supported, true, JSON.stringify(outcome));
    assert.ok(evidence.some((row) => row.event === 'invalid_upgrade_sent'));
  }
  return ['owned peer branch observed without cloned signed profile', 'actual worker reservation ingestion custody and publication checked', 'negative/timeout/cancel response cannot earn readiness or exploitability credit'];
}

describe('finite required branch obligations: actual first owned protocol slices', () => {
  let fixtures;
  before(async () => { fixtures = await createCheckDeliveryFixtures(); });
  after(async () => { await fixtures?.close(); });
  for (const obligation of firstSlice) {
    it(`${obligation.check_id} / branch ${obligation.branch}`, { timeout: 15_000 }, async (t) => {
      const check = getCheckById(obligation.check_id);
      const fixture = fixtures.forCheck(check, { scenario: obligation.branch });
      const result = await executeMemoryDelivery(check, fixture);
      if (obligation.branch === 'cancel') await fixture.waitForCancelledSocketClose();
      result.receipt.branch_id = obligation.branch_id;
      result.receipt.branch_peer_evidence = fixture.peerEvidence();
      await assertExistingBehaviorCase(t, { channel: 'delivery', receipt: result.receipt }, async () => {
        const descriptions = assertBranch(obligation, result, fixture);
        result.receipt.branch_assertions = descriptions;
        branchReceipts.push(result.receipt);
        return descriptions;
      });
    });
  }
  it('missing required branches fail full acceptance even when definition accounting is separate', () => {
    const result = accountDeliveryReceipts(branchReceipts);
    assert.equal(result.complete, false);
    assert.equal(result.gaps.length, CHECK_CATALOG.length, 'branch receipts never multiply default definition coverage');
    assert.ok(result.branch_gaps.length > 0, 'remaining promised branch obligations are explicit gaps');
    assert.deepEqual(result.errors, []);
  });
});
