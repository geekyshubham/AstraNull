import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { CHECK_CATALOG, getCheckById } from '../../src/contracts/checks.mjs';
import { CHECK_DELIVERY_INVENTORY, accountDeliveryReceipts, validateDeliveryBranchEvidence } from '../fixtures/check-delivery-coverage.mjs';
import { createCheckDeliveryFixtures, executeMemoryDelivery } from '../helpers/check-delivery-fixtures.mjs';
import { assertExistingBehaviorCase } from '../helpers/existing-behavior-coverage.mjs';
import { hardTimeoutSchedulerToleranceMs } from '../../src/lib/probeResultValidation.mjs';
import { assertDeliveredReflectorRequest } from '../helpers/check-delivery-payload-assertions.mjs';
import { assertNativeSemanticBranch, assertNativeDnsNegative, assertNativeResolverCancellation, assertUnreachableBranchProof } from '../helpers/check-delivery-native-oracles.mjs';

// Each branch is an owned peer behavior, never a cloned or re-signed catalog profile.
// Definition invocations remain separately required; aliases share only identical
// full-delivery-fingerprint branch obligations. Unimplemented obligations stay gaps.
const TCP_LAB_KINDS = new Set(['tcp_connect', 'port_scan_bounded', 'connection_limit_probe']);
const branchReceipts = [];
const inapplicableObligations = CHECK_DELIVERY_INVENTORY.inapplicable_branch_obligations;
const nativeObligations = CHECK_DELIVERY_INVENTORY.branch_obligations.filter((row) => !TCP_LAB_KINDS.has(row.kind));

function assertBranch(obligation, result, fixture) {
  const { outcome, verdict, readiness, findings, receipt } = result;
  const evidence = fixture.peerEvidence();
  assert.ok(evidence.length > 0, 'actual owned peer branch evidence required');
  assert.equal(verdict.confidence, 'external_only');
  const semantic = assertNativeSemanticBranch(obligation, result, evidence);
  assert.equal(readiness.coverage.passed_count, semantic?.passed ?? 0);
  if (semantic) assert.equal(findings.length, semantic.findings);
  else if (obligation.branch === 'axfr_transfer') {
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
  if (['http2_settings', 'http2_frame_probe'].includes(obligation.kind) && ['timeout', 'cancel'].includes(obligation.branch)) {
    const withheld = evidence.find((row) => row.event === 'response_withheld' && row.transport === 'h2');
    assert.equal(withheld?.alpn, 'h2');
    assert.match(withheld?.tls_protocol ?? '', /^TLSv1\.[23]$/);
    assert.equal(withheld.phase, 'request');
    assert.equal(Buffer.from(withheld.request_hex, 'hex').subarray(0, 24).toString(), 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
    assert.ok(receipt.actual_wire.some((row) => row.transport === 'h2_client_preface' && row.connection_id === withheld.connection_id));
  }
  if (obligation.branch === 'timeout') {
    assert.equal(outcome.external_result, 'timeout', JSON.stringify(outcome));
    assert.ok(evidence.some((row) => row.event === 'response_withheld'));
  } else if (obligation.branch === 'cancel') {
    if (['dns_open_recursion', 'dns_failover_posture'].includes(obligation.kind)) assertNativeResolverCancellation(obligation, result, evidence);
    assert.ok(evidence.some((row) => row.event === 'cancel_requested'));
    assert.ok(evidence.some((row) => ['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(row.event)));
    assert.ok(outcome.duration_ms < 1000, `cancellation must settle promptly, not at unrelated signed deadline: ${outcome.duration_ms}ms`);
    assert.ok(['error', 'timeout', 'not_run'].includes(outcome.external_result), JSON.stringify(outcome));
  } else if (obligation.branch === 'peer_error' || obligation.branch === 'invalid_tls') {
    assert.equal(outcome.external_result, 'error', JSON.stringify(outcome));
    assert.ok(outcome.metadata.error_class, 'transport fault must retain its actual error class');
    assert.ok(evidence.some((row) => row.event === (obligation.branch === 'peer_error' ? 'peer_reset' : 'malformed_tls_sent')));
  } else if (obligation.branch === 'invalid_h2') {
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'ERR_HTTP2_ERROR');
    const fault = evidence.find((row) => row.event === 'malformed_h2_sent');
    assert.ok(fault, 'invalid H2 requires malformed frames after a real TLS handshake, never malformed TLS');
    assert.equal(fault.alpn, 'h2');
    assert.match(fault.tls_protocol, /^TLSv1\.[23]$/);
    assert.equal(Buffer.from(fault.request_hex, 'hex').subarray(0, 24).toString(), 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
    assert.equal(fault.response_hex, '00000104000000000000');
  } else if (obligation.branch === 'negative_dns') {
    assertNativeDnsNegative(obligation, result, evidence);
  } else if (obligation.branch === 'nxdomain') {
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.rcode, 3);
    assert.equal(outcome.metadata.protocol_identity_confirmed, true);
    assert.ok(evidence.some((row) => row.rcode === 3));
  } else if (obligation.branch === 'wrong_peer') {
    assert.notEqual(result.job.probe_profile.dns_transport, 'tcp',
      'BLOCKED: connected DNS TCP cannot receive a datagram from a wrong source; transaction mismatch, reset or rewritten socket identity is not wrong-peer proof. Original obligation retained.');
    assert.equal(outcome.external_result, 'timeout');
    assert.ok(evidence.some((row) => row.event === 'wrong_peer_response_sent' && row.actual_port !== row.expected_port));
    assert.notEqual(outcome.metadata.protocol_identity_confirmed, true);
  } else if (obligation.branch === 'malformed_response') {
    assert.equal(outcome.external_result, 'not_run', JSON.stringify(outcome));
    assert.notEqual(outcome.metadata.protocol_identity_confirmed, true, JSON.stringify(outcome));
    if (obligation.kind === 'grpc_reflection_probe') {
      assert.equal(outcome.metadata.grpc_status, '0');
      assert.equal(outcome.metadata.grpc_request_succeeded, false);
      assert.notEqual(outcome.metadata.reflection_service_routed, true);
      const malformed = Buffer.from(evidence.find((row) => row.event === 'grpc_response_sent').response_hex, 'hex');
      assert.equal(malformed.readUInt32BE(1), 99);
      assert.equal(malformed.length - 5, 1);
    } else {
      const malformed = evidence.find((row) => row.event === 'dns_response_constructed');
      const bytes = Buffer.from(malformed.response_hex, 'hex');
      assert.equal(bytes.readUInt16BE(6), 1, 'DNS peer claims one absent answer');
      assert.ok(receipt.actual_wire.some((row) => row.transaction_id === bytes.readUInt16BE(0) && Buffer.from(row.request_hex, 'hex').length === bytes.length));
    }
  } else if (obligation.branch === 'axfr_transfer') {
    assert.equal(outcome.metadata.transfer_complete, true, JSON.stringify(outcome));
    assert.equal(outcome.metadata.axfr_leak, true);
    assert.equal(outcome.metadata.protocol_identity_confirmed, true);
    assert.ok(evidence.some((row) => row.qtype === 252 && row.rcode === 0));
  } else if (obligation.branch === 'unimplemented') {
    assert.equal(outcome.external_result, 'not_run');
    assert.equal(outcome.metadata.grpc_status, '12');
    assert.notEqual(outcome.metadata.reflection_service_routed, true);
    assert.notEqual(outcome.metadata.protocol_identity_confirmed, true);
    assert.ok(evidence.some((row) => row.grpc_status === '12'));
  } else if (obligation.branch === 'invalid_upgrade') {
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.status_code, 101);
    assert.equal(outcome.metadata.upgrade_accepted, false);
    assert.equal(outcome.metadata.handshake_identity_confirmed, false);
    assert.ok(evidence.some((row) => row.event === 'invalid_upgrade_sent'));
  }
  return [
    `owned ${obligation.kind} peer independently proves ${obligation.branch} without cloned signed profile`,
    'actual worker reservation ingestion custody publication and signed operation/duration bounds checked',
    `exact branch result ${outcome.external_result}, findings ${findings.length} and readiness credit ${readiness.coverage.passed_count} checked`,
  ];
}

describe('finite required branch obligations: owned native protocol peers (TCP lab separate)', () => {
  let fixtures;
  it('derives 520 reachable obligations from 524 candidates and keeps 27 TCP-lab branches separate', () => {
    assert.equal(CHECK_DELIVERY_INVENTORY.candidate_branch_obligations.length, 524);
    assert.equal(CHECK_DELIVERY_INVENTORY.branch_obligations.length, 520);
    assert.equal(inapplicableObligations.length, 4);
    assert.equal(nativeObligations.length, 493);
    assert.equal(CHECK_DELIVERY_INVENTORY.branch_obligations.filter((row) => TCP_LAB_KINDS.has(row.kind)).length, 27);
  });
  before(async () => { fixtures = await createCheckDeliveryFixtures(); });
  after(async () => { await fixtures?.close(); });
  for (const obligation of nativeObligations) {
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
        assert.deepEqual(validateDeliveryBranchEvidence(result.receipt, obligation), [], 'causal branch receipt validation must pass before capture');
        branchReceipts.push(result.receipt);
        return descriptions;
      });
    });
  }
  for (const obligation of inapplicableObligations) {
    it(`${obligation.check_id} / branch ${obligation.branch} is provably unreachable (${obligation.reason}); no receipt`, { timeout: 15_000 }, async () => {
      const check = getCheckById(obligation.check_id);
      const fixture = fixtures.forCheck(check, { scenario: obligation.branch });
      const result = await executeMemoryDelivery(check, fixture);
      assertUnreachableBranchProof(obligation, result, fixture);
      assert.equal(CHECK_DELIVERY_INVENTORY.branch_obligations.some((row) => row.branch_id === obligation.branch_id), false);
    });
  }
  it('missing required branches fail full acceptance even when definition accounting is separate', (t) => {
    const result = accountDeliveryReceipts(branchReceipts);
    assert.equal(result.complete, false);
    assert.equal(result.gaps.length, CHECK_CATALOG.length, 'branch receipts never multiply default definition coverage');
    const expectedGaps = CHECK_DELIVERY_INVENTORY.branch_obligations.filter((row) => TCP_LAB_KINDS.has(row.kind));
    assert.deepEqual(result.branch_gaps.map((row) => row.branch_id).sort(), expectedGaps.map((row) => row.branch_id).sort(),
      'only the 27 separately owned TCP obligations remain explicit gaps in this file');
    assert.equal(result.invoked_branches, 493, 'only genuine causal proofs earn branch receipts');
    assert.deepEqual(result.errors, []);
    t.diagnostic('Native branch receipts 493/493 reachable; 4 candidates proven unreachable; TCP lab accounting is separate.');
  });
});
