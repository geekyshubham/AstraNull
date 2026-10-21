import assert from 'node:assert/strict';

// Expectations are authored from the owned peer contract, not copied from the
// classifier under test. Actual request/response pairs establish the phase.
const OBSERVATION_TRANSFORMS = new Set(['homoglyph', 'base64_wrap', 'numeric_repr']);

export function assertUnreachableBranchProof(obligation, result, fixture) {
  assert.ok(obligation.reason, 'only derived inapplicable obligations carry an unreachability proof');
  const evidence = fixture.peerEvidence();
  const wire = result.receipt.actual_wire;
  const m = result.outcome.metadata;
  if (obligation.reason === 'single_marker_request_has_no_permitted_control') {
    assert.equal(result.job.probe_profile.kind, 'waf_enforcement_probe');
    assert.equal(result.job.probe_profile.max_requests, 1);
    const requests = wire.filter((row) => ['http', 'https'].includes(row.transport));
    assert.equal(requests.length, 1);
    assert.ok(requests[0].request_headers['x-astranull-marker']);
    assert.equal(evidence.some((row) => row.event === 'response_sent' && row.request_phase === 'permitted'), false);
    assert.equal(result.outcome.external_result, 'not_run');
    assert.equal(m.not_run_reason, 'independent_permitted_baseline_not_available');
    assert.equal(m.comparison_complete, false);
    assert.equal(m.baseline_health, undefined);
    assert.equal(m.permitted_baseline_health, undefined);
  } else if (obligation.reason === 'connected_tcp_has_no_datagram_source') {
    assert.equal(result.job.probe_profile.kind, 'dns_wire_query');
    assert.equal(result.job.probe_profile.dns_transport, 'tcp');
    assert.ok(wire.some((row) => row.transport === 'dns_tcp'));
    const probeQuery = wire.filter((row) => row.transport === 'dns_tcp');
    assert.equal(probeQuery.length, 1);
    assert.equal(probeQuery[0].qtype, { ANY: 255, NS: 2 }[result.job.probe_profile.dns_qtype]);
    assert.ok(wire.filter((row) => row.transport === 'dns_udp').every((row) => row.transaction_id !== probeQuery[0].transaction_id));
    assert.equal(evidence.some((row) => row.event === 'wrong_peer_response_sent'), false);
    assert.equal(result.outcome.external_result, 'connected');
    assert.equal(m.protocol_identity_confirmed, true);
  } else assert.fail(`unknown unreachable branch reason: ${obligation.reason}`);
  assert.equal(result.readiness.coverage.passed_count, 0);
  assert.equal(result.findings.length, 0);
}
export function assertNativeResolverCancellation(obligation, result, evidence) {
  assert.equal(obligation.branch, 'cancel');
  assert.ok(['dns_open_recursion', 'dns_failover_posture'].includes(obligation.kind));
  const requested = evidence.find((row) => row.event === 'cancel_requested' && row.transport === 'dns_udp');
  assert.ok(requested && Number.isFinite(requested.observed_at_ms));
  const sameQuery = (row) => row.transport === requested.transport
    && ['connection_id', 'local_address', 'local_port', 'remote_address', 'remote_port', 'phase', 'request_hex'].every((key) => row[key] === requested[key]);
  assert.ok(evidence.some((row) => row.event === 'dns_request_received' && sameQuery(row)));
  assert.ok(evidence.some((row) => row.event === 'response_withheld' && sameQuery(row)));
  assert.ok(result.receipt.actual_wire.some(sameQuery), 'close must bind the actual delivered DNS query');
  const closed = evidence.find((row) => row.event === 'owned_client_socket_closed' && sameQuery(row));
  assert.ok(closed, 'actual operation-owned UDP close is required before fixture teardown');
  assert.equal(closed.closure_cause, 'worker_cancel');
  assert.ok(Number.isFinite(closed.observed_at_ms) && closed.observed_at_ms >= requested.observed_at_ms);
  assert.ok(closed.observed_at_ms - requested.observed_at_ms < 400, 'cancellation close must precede independent 500ms resolver expiry');
  assert.ok(Number.isFinite(closed.resolver_expires_at_ms) && closed.observed_at_ms < closed.resolver_expires_at_ms);
  assert.equal(result.outcome.probe_requests_sent, 1);
  assert.equal(result.outcome.external_result, 'timeout');
  assert.equal(result.outcome.metadata.error_class, 'probe_job_deadline_exceeded');
  assert.equal(result.readiness.coverage.passed_count, 0);
  assert.equal(result.findings.length, 0);
}

export function assertNativeSemanticBranch(obligation, result, evidence) {
  const { branch, kind } = obligation;
  if (!['permitted_unhealthy', 'unsigned_denial', 'variant_allowed', 'partial'].includes(branch)) return null;
  const m = result.outcome.metadata;
  const replies = evidence.filter((row) => row.event === 'response_sent');
  assert.ok(replies.length, 'actual HTTP response events required');
  for (const reply of replies) {
    assert.ok(result.receipt.actual_wire.some((wire) => wire.transport === reply.transport && wire.method === reply.method && wire.url === reply.path), 'response bound to actual delivered request');
  }
  const phase = (name, status) => replies.some((row) => row.request_phase === name && row.status === status);
  if (branch === 'permitted_unhealthy') {
    assert.ok(phase('permitted', 403), 'unhealthy permitted control must actually be requested and denied; a marker-only probe cannot prove this branch');
    assert.equal(m.baseline_health ?? m.permitted_baseline_health, 'unhealthy');
    assert.equal(m.enforcement, 'unknown');
    assert.equal(m.comparison_complete, false);
    assert.equal(result.outcome.external_result, 'not_run');
    return { findings: 0, passed: 0 };
  }
  assert.ok(phase('permitted', 200), 'healthy independent permitted control required');
  assert.equal(m.baseline_health ?? m.permitted_baseline_health, 'healthy');
  if (branch === 'unsigned_denial') {
    const denied = replies.filter((row) => ['reference', 'transform'].includes(row.request_phase));
    assert.ok(denied.length);
    for (const row of denied) {
      assert.equal(row.status, 403);
      assert.equal(row.headers['x-waf-block'], undefined);
      assert.equal(row.headers['cf-mitigated'], undefined);
    }
    assert.equal(m.enforcement, 'unknown');
    assert.equal(m.comparison_complete, false);
    assert.equal(result.outcome.external_result, 'not_run');
    return { findings: 0, passed: 0 };
  }
  assert.equal(kind, 'waf_evasion_marker_probe');
  assert.ok(phase('reference', 403));
  assert.ok(replies.some((row) => row.request_phase === 'reference' && row.headers['x-waf-block'] === '1'));
  assert.equal(m.baseline_blocked, true);
  if (branch === 'partial') {
    assert.ok(phase('transform', 503), 'partial comparison requires the actual transformed request to receive an ungradable 503');
    assert.equal(m.comparison_complete, false);
    assert.equal(m.completed_marker_legs, 1);
    assert.equal(m.inconclusive_reason, 'transformed_marker_not_graded');
    assert.equal(m.evasion_bypass_suspected, false);
    assert.equal(result.outcome.external_result, 'not_run');
    return { findings: 0, passed: 0 };
  }
  assert.ok(phase('transform', 200), 'actual transformed request must be allowed');
  assert.equal(m.comparison_complete, true);
  assert.equal(m.completed_marker_legs, 2);
  assert.equal(m.enforcement, 'partial');
  const observation = OBSERVATION_TRANSFORMS.has(result.job.probe_profile.evasion_transform);
  assert.equal(result.outcome.external_result, observation ? 'not_run' : 'connected');
  assert.equal(m.evasion_bypass_suspected, !observation);
  if (observation) assert.equal(m.inconclusive_reason, 'observation_only_transform');
  return { findings: observation ? 0 : 1, passed: 0 };
}

export function assertNativeDnsNegative(obligation, result, evidence) {
  const responses = evidence.filter((row) => row.event === 'dns_response_constructed');
  assert.ok(responses.some((row) => row.rcode === 3 && (Buffer.from(row.response_hex, 'hex').readUInt16BE(2) & 15) === 3), 'actual NXDOMAIN response required');
  const m = result.outcome.metadata;
  if (obligation.kind === 'dns_open_recursion') {
    assert.equal(result.outcome.external_result, 'connected');
    assert.equal(m.same_target_answer_observed, false);
    assert.equal(m.recursion_proof_available, false);
    assert.equal(m.open_recursion_detected, null);
  } else if (obligation.kind === 'dnssec_posture') {
    // This NXDOMAIN has no signed denial/SOA proof: strict DNSKEY posture must
    // reject it, not pretend the zone definitively has no DNSSEC material.
    assert.equal(result.outcome.external_result, 'error');
    assert.equal(m.rcode, 3);
    assert.equal(m.error_class, 'non_definitive_dns_response');
    assert.notEqual(m.protocol_identity_confirmed, true);
    assert.equal(m.dnskey_present, undefined);
    assert.equal(m.dnssec_configured, undefined);
  } else if (obligation.kind === 'dns_failover_posture') {
    // The resolver wrapper maps an authoritative negative NS lookup to an empty
    // list; it is an observed empty set, never exercised failover readiness.
    assert.equal(result.outcome.external_result, 'connected');
    assert.equal(m.nameserver_count, 0);
    assert.deepEqual(m.nameservers, []);
    assert.equal(m.nameserver_count_below_two, true);
    assert.equal(m.failover_exercised, false);
    assert.equal(m.weak_failover, null);
  } else assert.fail(`missing negative DNS oracle: ${obligation.kind}`);
}
