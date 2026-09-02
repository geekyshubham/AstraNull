import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { executeCapabilityProbe } from '../../src/lib/capabilityProbes.mjs';
import { buildSignedProbeJobRecord } from '../../src/lib/probeJobs.mjs';

const VERIFY_SECRET = randomBytes(32).toString('hex');
const AXFR_CHECK = getCheckById('dns.zone_transfer_exposure.safe');
assert.ok(AXFR_CHECK, 'AXFR catalog check must exist');

function signedAxfrJob(zone) {
  return buildSignedProbeJobRecord({
    run: {
      id: 'run_live',
      tenant_id: 'ten_live',
      safety_constraints: { max_requests: 2 },
    },
    check: AXFR_CHECK,
    target: { id: 'tgt_live_axfr', kind: 'fqdn', value: zone },
    probeWorkerSecret: VERIFY_SECRET,
    now: new Date('2026-09-01T00:00:00.000Z'),
    newId: () => 'pjob_live_axfr',
  });
}

const runPublicDns = process.env.ASTRANULL_RUN_PUBLIC_DNS === '1';

// example.com is third-party infrastructure. Local loopback AXFR coverage is canonical;
// this supplemental public check requires an explicit operator opt-in.
describe('capability probes live public DNS (unaided I/O)', () => {
  it('signs coherent authoritative AXFR operation caps', () => {
    const job = signedAxfrJob('example.com');
    assert.equal(job.probe_profile.max_requests, 2);
    assert.equal(job.constraints.max_probe_requests, 2);
    assert.equal(job.constraints.min_destination_resolver_attempts, 2);
    assert.equal(job.constraints.max_destination_resolver_attempts, 4);
    assert.equal(job.constraints.max_total_operations, 6);
    assert.equal(job.constraints.max_requests, 6);
  });

  it('dns_axfr_leak uses real resolveNs + net.connect against example.com NS', {
    skip: runPublicDns
      ? false
      : 'set ASTRANULL_RUN_PUBLIC_DNS=1 to opt in to third-party DNS I/O',
  }, async () => {
    const job = signedAxfrJob('example.com');
    const outcome = await executeCapabilityProbe(
      job,
      { probeWorkerSecret: VERIFY_SECRET },
    );

    assert.equal(outcome.metadata.probe_kind, 'dns_axfr_leak');
    assert.equal(outcome.metadata.zone, 'example.com');
    assert.ok(outcome.metadata.nameserver, 'expected real nameserver hostname from public DNS');
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.notEqual(outcome.metadata.axfr_leak, true);
    if (outcome.metadata.rcode === 0) {
      assert.equal(outcome.metadata.answer_count ?? 0, 0, 'NOERROR must have zero answers to avoid leak verdict');
    } else {
      assert.ok(outcome.metadata.rcode >= 1 && outcome.metadata.rcode <= 15, `unexpected DNS rcode ${outcome.metadata.rcode}`);
    }
    assert.equal(outcome.metadata.resolver_attempts, 1);
    assert.equal(outcome.metadata.destination_vetting_resolver_attempts, 2);
    assert.equal(outcome.metadata.transport_attempts, 1);
    assert.equal(outcome.metadata.request_counting_basis, 'logical_operations');
    assert.equal(outcome.requests_sent, 2);
  });
});
