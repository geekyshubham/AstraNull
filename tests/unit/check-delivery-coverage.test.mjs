import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { CHECK_DELIVERY_INVENTORY, accountDeliveryReceipts, validateDeliveryBranchEvidence } from '../fixtures/check-delivery-coverage.mjs';
import { createCheckDeliveryFixtures, executeMemoryDelivery } from '../helpers/check-delivery-fixtures.mjs';
import { createConnectFaultFixture, executeConnectFaultDelivery } from '../helpers/check-delivery-connect-fault.mjs';
import { assertNativeResolverCancellation } from '../helpers/check-delivery-native-oracles.mjs';

// Frozen pre-expansion identities of the full candidate set, not a dynamically lowered denominator.
it('preserves every original 524 candidate obligation identity and delivery fingerprint', () => {
  const candidates = CHECK_DELIVERY_INVENTORY.candidate_branch_obligations;
  assert.equal(candidates.length, 524);
  assert.equal(new Set(candidates.map((row) => row.branch_id)).size, 524);
  assert.equal(createHash('sha256').update(JSON.stringify(candidates)).digest('hex'), '3cc8f902c3e873d7a6010e87e5aafbb1cd686ee18aac5f3a810fc9ae365f18ff');
});

it('removes only the four code-proven unreachable candidates from the required denominator', () => {
  const { candidate_branch_obligations: candidates, branch_obligations: required, inapplicable_branch_obligations: inapplicable } = CHECK_DELIVERY_INVENTORY;
  assert.deepEqual(inapplicable.map((row) => [row.check_id, row.branch, row.reason]), [
    ['l7.waf_marker_rule.safe', 'permitted_unhealthy', 'single_marker_request_has_no_permitted_control'],
    ['waf.enforcement.safe', 'permitted_unhealthy', 'single_marker_request_has_no_permitted_control'],
    ['dns.tcp_fallback.readiness', 'wrong_peer', 'connected_tcp_has_no_datagram_source'],
    ['dns.multi_question_oversized.safe', 'wrong_peer', 'connected_tcp_has_no_datagram_source'],
  ]);
  assert.equal(required.length, candidates.length - inapplicable.length);
  const removed = new Set(inapplicable.map((row) => row.branch_id));
  assert.deepEqual(required.map((row) => row.branch_id), candidates.map((row) => row.branch_id).filter((id) => !removed.has(id)));
  const owners = (kind) => CHECK_DELIVERY_INVENTORY.rows.filter((row) => row.kind === kind);
  const udpWrongPeer = required.filter((row) => row.branch === 'wrong_peer');
  assert.ok(udpWrongPeer.length > 0);
  assert.ok(udpWrongPeer.every((row) => owners('dns_wire_query').find((owner) => owner.delivery_fingerprint === row.delivery_fingerprint).delivery_material.profile.dns_transport !== 'tcp'));
  assert.ok(required.some((row) => row.kind === 'waf_class_marker_probe' && row.branch === 'permitted_unhealthy'));
  assert.ok(required.some((row) => row.kind === 'waf_evasion_marker_probe' && row.branch === 'permitted_unhealthy'));
});

const samples = [
  ['l7.expensive_endpoint.safe', 'timeout'],
  ['l7.expensive_endpoint.safe', 'cancel'],
  ['l7.expensive_endpoint.safe', 'peer_error'],
  ['tls.profile_exposure.safe', 'invalid_tls'],
  ['protocol.http2_readiness.safe', 'invalid_h2'],
  ['dns.authoritative_response.safe', 'malformed_response'],
  ['dns.authoritative_response.safe', 'wrong_peer'],
  ['dns.random_prefix_nxdomain.safe', 'nxdomain'],
  ['dns.open_recursion_behavior.safe', 'negative_dns'],
  ['dns.dnssec_expensive_query.safe', 'negative_dns'],
  ['dns.secondary_failover.safe', 'negative_dns'],
  ['dns.zone_transfer_exposure.safe', 'axfr_transfer'],
  ['protocol.grpc_reflection_stream.safe', 'malformed_response'],
  ['protocol.grpc_reflection_stream.safe', 'unimplemented'],
  ['protocol.websocket_connection_controls.safe', 'invalid_upgrade'],
  ['waf.http_method_policy_marker.safe', 'permitted_unhealthy'],
  ['waf.http_method_policy_marker.safe', 'unsigned_denial'],
  ['waf.evasion_unicode_normalization.safe', 'variant_allowed'],
  ['waf.evasion_unicode_normalization.safe', 'partial'],
  ['reflect.ssdp_exposure.safe', 'payload_bytes'],
  ['reflect.ssdp_exposure.safe', 'unconfirmed_response'],
  ['l3.sip_voip_flood.readiness', 'unconfirmed_response'],
];

// Every positive input below is obtained from the actual signed local worker,
// reservation/ingestion/custody/publication path. Only negative mutations are copied.
describe('strict delivery receipt causal evidence mutations', { concurrency: false }, () => {
  let fixtures;
  before(async () => { fixtures = await createCheckDeliveryFixtures(); });
  after(async () => { await fixtures?.close(); });
  it('retains actual narrowly scoped positive readiness without relabelling it as a negative fault branch', async () => {
    const check = getCheckById('waf.evasion_unicode_normalization.safe');
    const fixture = fixtures.forCheck(check);
    const { receipt } = await executeMemoryDelivery(check, fixture);
    assert.equal(receipt.outcome.metadata.comparison_complete, true);
    assert.equal(receipt.outcome.metadata.permitted_baseline_health, 'healthy');
    assert.equal(receipt.outcome.metadata.enforcement, 'enforced');
    assert.equal(receipt.published_verdict.verdict, 'protected');
    assert.equal(receipt.published_verdict.confidence, 'external_only');
    assert.equal(receipt.readiness.coverage.passed_count, 1);
    assert.deepEqual(accountDeliveryReceipts([receipt]).errors, [], 'real complete healthy comparison retains its narrow original readiness');
    const obligation = CHECK_DELIVERY_INVENTORY.branch_obligations.find((row) => row.check_id === check.check_id && row.branch === 'variant_allowed');
    const relabelled = structuredClone(receipt);
    relabelled.branch_id = obligation.branch_id;
    relabelled.branch_peer_evidence = fixture.peerEvidence();
    relabelled.branch_assertions = ['relabelling an actual healthy enforced comparison is not a variant-allowed fault observation'];
    const report = accountDeliveryReceipts([relabelled]);
    assert.ok(report.errors.some((error) => error.startsWith('variant_allowed_branch_not_observed:')));
    assert.equal(report.invoked_branches, 0);
  });
  it('native refused attempts cannot omit a measured operation or change transport, timestamp, endpoint, or phase', async () => {
    const obligation = CHECK_DELIVERY_INVENTORY.branch_obligations.find((row) => row.kind === 'tcp_connect' && row.branch === 'peer_refused');
    const check = getCheckById(obligation.check_id);
    const fixture = await createConnectFaultFixture(fixtures, check, obligation.branch);
    try {
      const { receipt } = await executeConnectFaultDelivery(check, fixture);
      receipt.branch_id = obligation.branch_id;
      receipt.branch_assertions = ['actual native ECONNREFUSED operations and closes observed under signed custody'];
      assert.ok(receipt.actual_network_attempts.length > 1);
      assert.deepEqual(accountDeliveryReceipts([receipt]).errors, []);
      for (const mutate of [
        (row) => { row.actual_network_attempts.pop(); },
        (row) => { for (const route of row.transport_routes) route.transport = 'udp'; },
        (row) => { row.actual_network_attempts[0].closed_at = '2000-01-01T00:00:00.000Z'; },
        (row) => { row.actual_network_attempts[0].phase = 'request'; },
        (row) => { row.actual_network_attempts[0].fixture_port += 1; },
        (row) => { row.actual_network_attempts[0].invocation_id = 'foreign-invocation'; },
        (row) => { row.actual_network_attempts[0].accepted = true; },
        (row) => { row.branch_peer_evidence[0].at = '2000-01-01T00:00:00.000Z'; },
      ]) {
        const altered = structuredClone(receipt); mutate(altered);
        const rejected = accountDeliveryReceipts([altered]);
        assert.equal(rejected.invoked_branches, 0);
        assert.ok(rejected.errors.some((error) => error.startsWith('peer_refused_branch_not_observed:')));
      }
    } finally { await fixture.close(); }
  });
  it('native cancellation receipt timestamps must stay inside the signed execution and cleanup window', async () => {
    const obligation = CHECK_DELIVERY_INVENTORY.branch_obligations.find((row) => row.kind === 'tcp_connect' && row.branch === 'cancel');
    const check = getCheckById(obligation.check_id);
    const fixture = await createConnectFaultFixture(fixtures, check, obligation.branch);
    try {
      const { receipt } = await executeConnectFaultDelivery(check, fixture);
      receipt.branch_id = obligation.branch_id;
      receipt.branch_assertions = ['actual native handshake cancellation and closure observed under signed custody'];
      assert.deepEqual(accountDeliveryReceipts([receipt]).errors, []);
      const completed = Date.parse(receipt.result_body.safety_attestation.completed_at);
      const leased = Date.parse(receipt.signed_job.leased_at);
      for (const [name, mutate] of [
        ['stale cancellation and closure', (cancel, closed) => { cancel.at = closed.at = '2000-01-01T00:00:00.000Z'; }],
        ['missing cancellation timestamp', (cancel) => { delete cancel.at; }],
        ['noncanonical cancellation timestamp', (cancel) => { cancel.at = '2026-10-16'; }],
        ['cancellation before lease', (cancel) => { cancel.at = new Date(leased - 1).toISOString(); }],
        ['cancellation after completion', (cancel, closed) => { cancel.at = closed.at = new Date(completed + 1).toISOString(); }],
        ['closure outside cleanup bound', (_cancel, closed) => { closed.at = new Date(completed + 1001).toISOString(); }],
        ['missing closure timestamp', (_cancel, closed) => { delete closed.at; }],
        ['closure before cancellation', (cancel, closed) => { closed.at = new Date(Date.parse(cancel.at) - 1).toISOString(); }],
      ]) {
        const altered = structuredClone(receipt);
        const cancel = altered.branch_peer_evidence.find((row) => row.event === 'cancel_requested');
        const closed = altered.branch_peer_evidence.find((row) => row.event === 'owned_client_socket_closed' && row.attempt_id === cancel.attempt_id);
        mutate(cancel, closed);
        const rejected = accountDeliveryReceipts([altered]);
        assert.equal(rejected.invoked_branches, 0, name);
        assert.ok(rejected.errors.some((error) => error.startsWith('cancel_phase_binding_mismatch:')), name);
      }
    } finally { await fixture.close(); }
  });
  it('native invalid TLS receipt requires the actual malformed reply bytes', async () => {
    const check = getCheckById('tls.profile_exposure.safe');
    const obligation = CHECK_DELIVERY_INVENTORY.branch_obligations.find((row) => row.check_id === check.check_id && row.branch === 'invalid_tls');
    const fixture = fixtures.forCheck(check, { scenario: obligation.branch });
    const { receipt } = await executeMemoryDelivery(check, fixture);
    receipt.branch_id = obligation.branch_id;
    receipt.branch_peer_evidence = fixture.peerEvidence();
    receipt.branch_assertions = ['actual ClientHello and exact owned malformed TLS reply observed'];
    assert.equal(Buffer.from(receipt.branch_peer_evidence.find((row) => row.event === 'malformed_tls_sent').response_hex, 'hex').toString(), 'HTTP/1.1 400 Owned invalid TLS peer\r\n\r\n');
    assert.deepEqual(accountDeliveryReceipts([receipt]).errors, []);
    for (const response of [undefined, '', '00', 'not-bytes', '1603030000', Buffer.from('HTTP/1.1 200 OK\r\n\r\n').toString('hex')]) {
      const altered = structuredClone(receipt);
      const fault = altered.branch_peer_evidence.find((row) => row.event === 'malformed_tls_sent');
      if (response === undefined) delete fault.response_hex;
      else fault.response_hex = response;
      const rejected = accountDeliveryReceipts([altered]);
      assert.equal(rejected.invoked_branches, 0, `invalid TLS response bytes: ${response}`);
      assert.ok(rejected.errors.some((error) => error.startsWith('invalid_tls_branch_not_observed:')));
    }
  });
  for (const checkId of ['dns.open_recursion_behavior.safe', 'dns.secondary_failover.safe']) {
    it(`resolver cancellation closes the actual query before independent expiry: ${checkId}`, async () => {
      const check = getCheckById(checkId);
      const obligation = CHECK_DELIVERY_INVENTORY.branch_obligations.find((row) => row.check_id === checkId && row.branch === 'cancel');
      const fixture = fixtures.forCheck(check, { scenario: obligation.branch });
      const result = await executeMemoryDelivery(check, fixture);
      await fixture.waitForCancelledSocketClose({ timeoutMs: 1000 });
      const { receipt } = result;
      receipt.branch_id = obligation.branch_id;
      receipt.branch_peer_evidence = fixture.peerEvidence();
      receipt.branch_assertions = ['actual query-bound UDP close follows worker cancellation before independent resolver expiry under accepted worker custody'];
      assert.deepEqual(validateDeliveryBranchEvidence(receipt, obligation), [], 'resolver expiry must not count as actual producer cancellation');
      assertNativeResolverCancellation(obligation, result, receipt.branch_peer_evidence);
      const requested = receipt.branch_peer_evidence.find((row) => row.event === 'cancel_requested');
      assert.deepEqual(accountDeliveryReceipts([receipt]).errors, [], 'full signed worker custody remains required');
      assert.equal(accountDeliveryReceipts([receipt]).invoked_branches, 1);
      for (const [name, mutate] of [
        ['missing closure', (rows) => rows.filter((row) => !['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(row.event))],
        ['independent resolver timeout', (rows) => rows.map((row) => row.event === 'owned_client_socket_closed' ? { ...row, closure_cause: 'resolver_timeout' } : row)],
        ['premature closure', (rows) => rows.map((row) => row.event === 'owned_client_socket_closed' ? { ...row, observed_at_ms: requested.observed_at_ms - 1 } : row)],
        ['unrelated closure', (rows) => rows.map((row) => row.event === 'owned_client_socket_closed' ? { ...row, connection_id: 'unrelated-owned-resolver' } : row)],
        ['wrong query bytes', (rows) => rows.map((row) => row.event === 'owned_client_socket_closed' ? { ...row, request_hex: '00' } : row)],
        ['missing cancellation time', (rows) => rows.map((row) => row.event === 'cancel_requested' ? { ...row, observed_at_ms: undefined } : row)],
      ]) {
        const altered = structuredClone(receipt);
        altered.branch_peer_evidence = mutate(altered.branch_peer_evidence);
        assert.ok(validateDeliveryBranchEvidence(altered, obligation).length > 0, name);
        assert.equal(accountDeliveryReceipts([altered]).invoked_branches, 0, name);
      }
    });
  }
  for (const [checkId, branch] of samples) {
    it(`${checkId}/${branch}: actual causal proof accepted, label-only and altered evidence rejected`, { timeout: 20_000 }, async () => {
      const obligation = CHECK_DELIVERY_INVENTORY.branch_obligations.find((row) => row.check_id === checkId && row.branch === branch);
      assert.ok(obligation, 'sample must retain original obligation identity');
      const fixture = fixtures.forCheck(getCheckById(checkId), { scenario: branch });
      const { receipt } = await executeMemoryDelivery(getCheckById(checkId), fixture);
      if (branch === 'cancel') await fixture.waitForCancelledSocketClose();
      receipt.branch_id = obligation.branch_id;
      receipt.branch_peer_evidence = fixture.peerEvidence();
      receipt.branch_assertions = ['actual owned peer action, terminal result and accepted custody checked'];
      assert.deepEqual(validateDeliveryBranchEvidence(receipt, obligation), [], JSON.stringify(receipt.outcome));
      const accepted = accountDeliveryReceipts([receipt]);
      assert.deepEqual(accepted.errors, []);
      assert.equal(accepted.invoked_branches, 1);
      assert.equal(accepted.invoked_definitions, 0, 'branch proof never substitutes a definition invocation');
      assert.equal(accepted.branch_gaps.length, CHECK_DELIVERY_INVENTORY.branch_obligations.length - 1, 'every other required branch remains a gap');
      assert.equal(accepted.complete, false);

      const labelsOnly = structuredClone(receipt);
      labelsOnly.branch_peer_evidence = [{ event: branch, scenario: branch, observed: true }];
      const rejected = accountDeliveryReceipts([labelsOnly]);
      assert.ok(rejected.errors.length > 0, branch);
      assert.equal(rejected.invoked_branches, 0, 'invalid receipts must not count toward exercised obligations');
      assert.equal(rejected.branch_gaps.length, CHECK_DELIVERY_INVENTORY.branch_obligations.length);
      const noWire = structuredClone(receipt); noWire.actual_wire = [];
      assert.ok(accountDeliveryReceipts([noWire]).errors.some((error) => error.startsWith('actual_probe_wire_missing:')));
      const emptyAssertions = structuredClone(receipt); emptyAssertions.branch_assertions = [''];
      assert.ok(accountDeliveryReceipts([emptyAssertions]).errors.some((error) => error.startsWith('branch_assertion_missing:')));
      const missingReadiness = structuredClone(receipt); delete missingReadiness.readiness;
      assert.ok(accountDeliveryReceipts([missingReadiness]).errors.some((error) => error.startsWith('branch_readiness_missing:')));
      const wrongConfidence = structuredClone(receipt); wrongConfidence.published_verdict.confidence = 'internal';
      assert.ok(accountDeliveryReceipts([wrongConfidence]).errors.some((error) => error.startsWith('external_confidence_missing:')));
      const alteredOutcome = structuredClone(receipt); alteredOutcome.outcome.external_result = receipt.outcome.external_result === 'connected' ? 'blocked' : 'connected';
      assert.ok(accountDeliveryReceipts([alteredOutcome]).errors.some((error) => error.startsWith('accepted_custody_mismatch:') || error.startsWith('accepted_outcome_mismatch:')));
      for (const mutation of [
        (item) => { item.connection_id = 'foreign-response-connection'; },
        (item) => { item.remote_port = 9; },
        (item) => { item.remote_address = '192.0.2.1'; },
        (item) => { item.phase = 'unrelated-phase'; },
      ]) {
        const foreignResponse = structuredClone(receipt);
        for (const item of foreignResponse.branch_peer_evidence) mutation(item);
        assert.ok(validateDeliveryBranchEvidence(foreignResponse, obligation).length > 0, 'specialized causal responses must share the actual request tuple and phase');
      }
      if (obligation.kind.startsWith('dns')) {
        for (const mutate of [
          (item) => { item.request_hex = '00'; },
          (item) => { const bytes = Buffer.from(item.response_hex, 'hex'); bytes[13] ^= 1; item.response_hex = bytes.toString('hex'); },
        ]) {
          const otherQuery = structuredClone(receipt);
          for (const item of otherQuery.branch_peer_evidence.filter((entry) => entry.event === 'dns_response_constructed')) mutate(item);
          assert.ok(validateDeliveryBranchEvidence(otherQuery, obligation).length > 0, 'DNS response binds actual query bytes and echoed question, not only transaction ID/qtype');
        }
      }
      if (branch === 'wrong_peer') {
        const wrongSender = structuredClone(receipt);
        wrongSender.branch_peer_evidence.find((item) => item.event === 'wrong_peer_response_sent').response_sender.remote_port = 9;
        assert.ok(validateDeliveryBranchEvidence(wrongSender, obligation).some((error) => error.startsWith('wrong_peer_branch_not_observed:')), 'wrong-source response still targets the actual querying client endpoint');
      }
      const receiptTarget = structuredClone(receipt); receiptTarget.target_id = 'foreign-target';
      assert.ok(accountDeliveryReceipts([receiptTarget]).errors.some((error) => error.startsWith('accepted_binding_mismatch:')));
      const wrongIdentity = structuredClone(receipt); wrongIdentity.accepted_event.target_id = 'foreign-target';
      assert.ok(accountDeliveryReceipts([wrongIdentity]).errors.some((error) => error.startsWith('accepted_binding_mismatch:')));
      const orphaned = structuredClone(receipt); delete orphaned.branch_id;
      const orphanedReport = accountDeliveryReceipts([orphaned]);
      assert.ok(orphanedReport.errors.some((error) => error.startsWith('branch_identity_missing:')));
      assert.equal(orphanedReport.invoked_definitions, 0, 'removing a branch identity must not turn a fault proof into default definition coverage');
      if (['timeout', 'cancel', 'peer_error'].includes(branch)) {
        for (const mutation of [
          (item) => { item.connection_id = 'unrelated-owned-socket'; },
          (item) => { item.phase = 'unrelated-phase'; },
          (item) => { item.local_port += 1; },
        ]) {
          const wrongSocket = structuredClone(receipt);
          for (const item of wrongSocket.branch_peer_evidence) mutation(item);
          assert.ok(validateDeliveryBranchEvidence(wrongSocket, obligation).length > 0, 'generic causal labels cannot replace the actual socket tuple and protocol phase');
        }
        if (branch === 'cancel') {
          const unrelatedClose = structuredClone(receipt);
          for (const item of unrelatedClose.branch_peer_evidence.filter((entry) => ['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(entry.event))) item.connection_id = 'closed-unrelated-socket';
          assert.ok(validateDeliveryBranchEvidence(unrelatedClose, obligation).some((error) => error.startsWith('cancel_socket_binding_mismatch:')));
          const timerExpiry = structuredClone(receipt);
          for (const item of timerExpiry.branch_peer_evidence.filter((entry) => ['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(entry.event))) item.closure_cause = 'resolver_timeout';
          assert.ok(validateDeliveryBranchEvidence(timerExpiry, obligation).some((error) => error.startsWith('cancel_socket_binding_mismatch:')), 'resolver expiry is not producer cancellation');
          const prematureClose = structuredClone(receipt);
          for (const item of prematureClose.branch_peer_evidence.filter((entry) => ['owned_peer_socket_closed', 'owned_client_socket_closed'].includes(entry.event))) item.observed_at_ms = 1;
          assert.ok(validateDeliveryBranchEvidence(prematureClose, obligation).some((error) => error.startsWith('cancel_socket_binding_mismatch:')), 'a close before the actual cancellation cannot be its consequence');
        }
      }
      if (['permitted_unhealthy', 'unsigned_denial', 'variant_allowed', 'partial'].includes(branch)) {
        for (const mutation of [
          (item) => { item.local_port += 1; },
          (item) => { item.request_ordinal = 999; },
          (item) => { item.request_phase = 'invented'; },
          (item) => { item.path = '/unrelated-actual-request'; },
        ]) {
          const wrongPhaseOrEndpoint = structuredClone(receipt);
          for (const item of wrongPhaseOrEndpoint.branch_peer_evidence.filter((entry) => entry.event === 'response_sent')) mutation(item);
          assert.ok(validateDeliveryBranchEvidence(wrongPhaseOrEndpoint, obligation).length > 0, 'concrete status alone cannot replace the same actual request, phase and endpoint');
        }
      }
      if (!['payload_bytes', 'axfr_transfer'].includes(branch)) {
        const falseReadiness = structuredClone(receipt); falseReadiness.readiness.coverage.passed_count = 1;
        assert.ok(accountDeliveryReceipts([falseReadiness]).errors.some((error) => error.startsWith('negative_branch_readiness_credit:')));
      }

      const changedPeer = structuredClone(receipt);
      if (['timeout', 'cancel', 'peer_error'].includes(branch)) {
        changedPeer.branch_peer_evidence = changedPeer.branch_peer_evidence.map((item) => ({ ...item, transport: 'dns_udp' }));
      } else if (branch === 'invalid_h2') {
        changedPeer.branch_peer_evidence.find((item) => item.event === 'malformed_h2_sent').alpn = 'http/1.1';
      } else if (branch === 'invalid_tls') {
        changedPeer.branch_peer_evidence.find((item) => item.event === 'malformed_tls_sent').request_hex = 'not-bytes';
      } else if (['malformed_response', 'nxdomain', 'negative_dns', 'axfr_transfer', 'wrong_peer'].includes(branch) && obligation.kind !== 'grpc_reflection_probe') {
        for (const item of changedPeer.branch_peer_evidence.filter((entry) => entry.event === 'dns_response_constructed')) item.response_hex = '00';
      } else if (obligation.kind === 'grpc_reflection_probe') {
        for (const item of changedPeer.branch_peer_evidence.filter((entry) => entry.event === 'grpc_response_sent')) { item.response_hex = '0000000000'; item.grpc_status = '0'; }
      } else if (branch === 'invalid_upgrade') {
        changedPeer.branch_peer_evidence.find((item) => item.event === 'invalid_upgrade_sent').accept = 'invented';
      } else if (['permitted_unhealthy', 'unsigned_denial', 'variant_allowed', 'partial'].includes(branch)) {
        for (const item of changedPeer.branch_peer_evidence.filter((entry) => entry.event === 'response_sent')) item.status = 200;
        // An unsigned denial requires an actual denial, not just a missing signature.
      } else if (obligation.kind === 'udp_probe') {
        for (const item of changedPeer.branch_peer_evidence) item.transport = 'dns_udp';
      } else {
        for (const row of changedPeer.actual_wire.filter((entry) => entry.payload_profile)) row.request_hex = '00';
      }
      assert.ok(validateDeliveryBranchEvidence(changedPeer, obligation).length > 0, `changed peer bytes/status/transport must invalidate ${branch}`);
    });
  }
});
