import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { deriveRunEvidenceStamp } from '../../src/lib/checkDefinitionVersion.mjs';
import { buildSignedProbeJobRecord } from '../../src/lib/probeJobs.mjs';
import { validateProbeResultBody } from '../../src/lib/probeResultValidation.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { deriveProtectionProfile } from '../../src/services/protectionProfile.mjs';
import { executeProbeForJob } from '../../workers/probe-worker.mjs';

test('transport-only observations cannot depress readiness coverage or inflate it with a passing legacy verdict', () => {
  const transport = { check_id: 'transport', version: '1', vector_family: 'l7', supported_targets: ['fqdn'], probe_profile: { kind: 'http_head' } };
  const semantic = { check_id: 'semantic', version: '1', vector_family: 'waf', supported_targets: ['fqdn'], probe_profile: { kind: 'waf_evasion_marker_probe' } };
  const run = { status: 'verdicted', completed_at: '2026-10-04T10:00:00Z', check_version: '1', producer_kind: 'signed_probe', probe_external_result: 'not_run' };
  const { coverage } = deriveProtectionProfile({
    now: '2026-10-04T11:00:00Z', target: { id: 'tgt', kind: 'fqdn' }, catalog: [transport, semantic],
    observations: [
      { check_id: 'transport', run, verdict: { verdict: 'edge_protected', evidence_ids: ['event'] } },
      { check_id: 'semantic', run, verdict: { verdict: 'inconclusive', evidence_ids: ['event'] } },
    ],
  });
  assert.equal(coverage.applicable_count, 1);
  assert.equal(coverage.observation_only_count, 1);
  assert.equal(coverage.conclusive_count, 0);
  assert.equal(coverage.inconclusive_count, 1);
  assert.equal(coverage.pairs.find(p => p.check_id === 'transport').exclusion_reason, 'observation_only');
  assert.equal(coverage.inconclusive_reasons[0].reason, 'baseline_comparison_unavailable');
  assert.equal(coverage.inconclusive_reasons.reduce((n, r) => n + r.count, 0), coverage.inconclusive_count);
});

test('an allowed baseline remains inconclusive but explains the observed blocker, not a transport failure', () => {
  const result = correlateExternalOnlyVerdict({ probeKind: 'waf_evasion_marker_probe', externalResult: 'not_run', probeIoObserved: true, probeMetadata: { baseline_blocked: false } });
  assert.equal(result.verdict, 'inconclusive');
  assert.equal(result.createsFinding, false);
  assert.match(result.explanation, /baseline harmless marker was allowed/);
  assert.doesNotMatch(result.explanation, /was not run|transport failure/);
});

function dnssecFixture({ key = true, malformed = false, authoritative = true, truncated = false, rcode = 0, wrongType = false, invalidProtocol = false } = {}) {
  return () => {
    const socket = new EventEmitter();
    socket.close = () => {};
    socket.send = (query, port, host, callback) => {
      assert.equal(query.readUInt16BE(query.length - 4), 48);
      assert.equal(port, 53);
      assert.equal(host, '8.8.8.8');
      const rdata = Buffer.from([1, 1, invalidProtocol ? 2 : 3, 8, 42]);
      const answer = Buffer.alloc(12 + rdata.length);
      answer.writeUInt16BE(0xc00c, 0);
      answer.writeUInt16BE(wrongType ? 1 : 48, 2);
      answer.writeUInt16BE(1, 4);
      answer.writeUInt16BE(rdata.length, 10);
      rdata.copy(answer, 12);
      const response = Buffer.concat([query, ...(key ? [answer] : [])]);
      response.writeUInt16BE(0x8000 | (authoritative ? 0x400 : 0) | (truncated ? 0x200 : 0) | rcode, 2);
      response.writeUInt16BE(key ? 1 : 0, 6);
      callback(null);
      queueMicrotask(() => socket.emit('message', malformed ? response.subarray(0, query.length + 5) : response, { address: host, port }));
    };
    return socket;
  };
}

async function executeDnssec(options) {
  const check = getCheckById('dns.dnssec_expensive_query.safe');
  const secret = 'dnssec-regression-secret-at-least-32-bytes';
  const job = buildSignedProbeJobRecord({
    run: { id: 'run', tenant_id: 'ten_demo', safety_constraints: {}, ...deriveRunEvidenceStamp(check) }, check,
    target: { id: 'tgt', kind: 'fqdn', value: 'example.test' },
    probeWorkerSecret: secret, now: new Date(), newId: () => 'job',
  });
  const result = await executeProbeForJob(job, {
    resolveNsFn: async () => ['ns.example.test'],
    resolve4Fn: async () => ['8.8.8.8'], resolve6Fn: async () => [],
    createSocket: dnssecFixture(options),
  });
  return { job, result };
}

test('signed DNSSEC uses a real DNSKEY wire query within attested probe and resolver caps', async () => {
  for (const key of [true, false]) {
    const { job, result } = await executeDnssec({ key });
    assert.equal(result.external_result, key ? 'blocked' : 'connected', JSON.stringify(result));
    assert.equal(result.metadata.dnskey_count, key ? 1 : 0);
    assert.equal(result.metadata.ds_count, null);
    assert.equal(result.metadata.dnssec_chain_validated, false);
    assert.equal(result.probe_requests_sent, 1);
    assert.equal(result.destination_resolver_attempts, 3);
    assert.equal(result.requests_sent, 4);
    const validation = validateProbeResultBody({ external_result: result.external_result, metadata: result.metadata, safety_attestation: { requests_sent: result.requests_sent, duration_ms: result.duration_ms, probe_requests_sent: 1, destination_resolver_attempts: 3, total_operations: 4 } }, job.constraints, { probeKind: 'dnssec_posture', probeProfile: job.probe_profile, target: job.target });
    assert.equal(validation.ok, true, JSON.stringify(validation));
    const verdict = correlateExternalOnlyVerdict({ probeKind: 'dnssec_posture', externalResult: result.external_result, probeMetadata: result.metadata, probeIoObserved: true });
    assert.equal(verdict.verdict, key ? 'protected' : 'exposed');
    assert.match(verdict.explanation, /key presence only|contained no DNSKEY/);
    assert.doesNotMatch(verdict.explanation, /blocked at the edge/);
  }
});

test('malformed, truncated, refused, and non-authoritative DNSKEY responses cannot prove DNSSEC posture', async () => {
  for (const options of [{ malformed: true }, { truncated: true }, { authoritative: false }, { rcode: 5 }, { wrongType: true }, { invalidProtocol: true }]) {
    const { result } = await executeDnssec(options);
    assert.equal(result.external_result, 'error', JSON.stringify(options));
    assert.equal(result.metadata.dnssec_configured, undefined);
    assert.equal(correlateExternalOnlyVerdict({ probeKind: 'dnssec_posture', externalResult: result.external_result, probeMetadata: result.metadata, probeIoObserved: true }).verdict, 'inconclusive');
  }
});
