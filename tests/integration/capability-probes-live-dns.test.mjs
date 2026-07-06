import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { executeCapabilityProbe } from '../../src/lib/capabilityProbes.mjs';

const skipPublic = process.env.ASTRANULL_SKIP_PUBLIC_DNS === '1';

describe('capability probes live public DNS (unaided I/O)', { skip: skipPublic }, () => {
  it('dns_axfr_leak uses real resolveNs + net.connect against example.com NS', async () => {
    const job = {
      constraints: { timeout_ms: 15000, max_requests: 1 },
      probe_profile: { kind: 'dns_axfr_leak', zone: 'example.com' },
      target: { kind: 'fqdn', value: 'example.com' },
    };

    const outcome = await executeCapabilityProbe(job, { signedJobVerified: true });

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
    assert.equal(outcome.requests_sent, 1);
  });
});