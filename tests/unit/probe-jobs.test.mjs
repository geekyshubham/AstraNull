import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  buildSignedProbeJobRecord,
  resolveJobProbeProfile,
  targetDescriptor,
} from '../../src/lib/probeJobs.mjs';

const SECRET = 'a'.repeat(32);

describe('probeJobs capability profile plumbing', () => {
  it('resolveJobProbeProfile merges direct_ip and protected_host overrides', () => {
    const check = getCheckById('origin.host_sni_bypass.safe');
    const profile = resolveJobProbeProfile(check, {
      direct_ip: '198.51.100.7',
      protected_host: 'edge.example.test',
    });
    assert.equal(profile.kind, 'host_sni_bypass');
    assert.equal(profile.direct_ip, '198.51.100.7');
    assert.equal(profile.protected_host, 'edge.example.test');
  });

  // These checks ship no curated ports/paths/nameserver defaults, so "the key is dropped"
  // means the key is absent entirely and the probe falls back to its own curated list at
  // runtime. Assertions below are explicit about `undefined` rather than comparing against
  // a baseline that is itself undefined.
  it('resolveJobProbeProfile drops a non-routable resolver_host override', () => {
    const check = getCheckById('dns.open_recursion_behavior.safe');
    assert.equal(check.probe_profile.resolver_host, undefined);
    const profile = resolveJobProbeProfile(check, { resolver_host: '10.0.0.53' });
    assert.equal(profile.resolver_host, undefined);

    // A routable resolver literal is still accepted.
    assert.equal(
      resolveJobProbeProfile(check, { resolver_host: '8.8.8.8' }).resolver_host,
      '8.8.8.8',
    );
  });

  it('resolveJobProbeProfile drops metadata and loopback host overrides', () => {
    const check = getCheckById('origin.host_sni_bypass.safe');
    for (const unsafe of ['169.254.169.254', '127.0.0.1', '::1', '0.0.0.0', '::ffff:10.0.0.5']) {
      const profile = resolveJobProbeProfile(check, { direct_ip: unsafe });
      assert.notEqual(profile.direct_ip, unsafe, `accepted ${unsafe}`);
    }
    // A routable literal still comes through.
    assert.equal(
      resolveJobProbeProfile(check, { direct_ip: '198.51.100.7' }).direct_ip,
      '198.51.100.7',
    );
  });

  it('resolveJobProbeProfile keeps only curated risky admin ports', () => {
    const check = getCheckById('l3.firewall_exposure_scan.safe');

    // 2375 (docker) and 9200 (elasticsearch) are not curated — nothing survives, so the
    // key is dropped entirely and probePortScanBounded uses RISKY_ADMIN_PORTS instead.
    const dropped = resolveJobProbeProfile(check, { ports: [2375, 9200] });
    assert.equal(dropped.ports, undefined);

    // Mixed input keeps only the curated members.
    const filtered = resolveJobProbeProfile(check, { ports: [22, 2375, 443, 70000, -1, 'x'] });
    assert.deepEqual(filtered.ports, [22, 443]);
  });

  it('resolveJobProbeProfile keeps only curated API doc paths', () => {
    const check = getCheckById('l7.api_surface_scan.safe');

    const dropped = resolveJobProbeProfile(check, { paths: ['/etc/passwd', '/admin'] });
    assert.equal(dropped.paths, undefined);

    const filtered = resolveJobProbeProfile(check, { paths: ['/swagger.json', '/admin'] });
    assert.deepEqual(filtered.paths, ['/swagger.json']);
  });

  it('resolveJobProbeProfile filters unsafe secondary_nameservers entries', () => {
    const check = getCheckById('dns.secondary_failover.safe');
    const filtered = resolveJobProbeProfile(check, {
      secondary_nameservers: ['ns2.example.test', '10.0.0.53', '169.254.169.254'],
    });
    assert.deepEqual(filtered.secondary_nameservers, ['ns2.example.test']);

    const allDropped = resolveJobProbeProfile(check, {
      secondary_nameservers: ['10.0.0.53', '127.0.0.1'],
    });
    assert.equal(allDropped.secondary_nameservers, undefined);
  });

  it('resolveJobProbeProfile never accepts a scan_host override', () => {
    const check = getCheckById('l3.firewall_exposure_scan.safe');
    const profile = resolveJobProbeProfile(check, { scan_host: '169.254.169.254' });
    assert.equal(profile.scan_host, undefined);
  });

  it('buildSignedProbeJobRecord never signs an unsafe scan_host or resolver_host', () => {
    const check = getCheckById('l3.firewall_exposure_scan.safe');
    const job = buildSignedProbeJobRecord({
      run: { id: 'run_1', tenant_id: 'ten_1', safety_constraints: { max_requests: 1 } },
      check,
      target: {
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'edge.example.test',
        metadata: { scan_host: '169.254.169.254', resolver_host: '10.0.0.53' },
      },
      probeProfile: { scan_host: '169.254.169.254', resolver_host: '10.0.0.53' },
      probeWorkerSecret: SECRET,
      now: new Date('2026-07-06T00:00:00.000Z'),
      newId: () => 'pjob_ssrf',
    });
    assert.equal(job.probe_profile.scan_host, undefined);
    assert.notEqual(job.probe_profile.resolver_host, '10.0.0.53');
    assert.equal(JSON.stringify(job.probe_profile).includes('169.254.169.254'), false);
  });

  it('targetDescriptor passes direct_origin_ip in job metadata', () => {
    const descriptor = targetDescriptor({
      id: 'tgt_1',
      kind: 'fqdn',
      value: 'edge.example.test',
      metadata: { direct_origin_ip: '198.51.100.7' },
    });
    assert.equal(descriptor.metadata.direct_origin_ip, '198.51.100.7');
  });

  it('buildSignedProbeJobRecord enriches host_sni_bypass from target metadata', () => {
    const check = getCheckById('origin.host_sni_bypass.safe');
    const job = buildSignedProbeJobRecord({
      run: { id: 'run_1', tenant_id: 'ten_1', safety_constraints: { max_requests: 1 } },
      check,
      target: {
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'edge.example.test',
        metadata: {
          direct_origin_ip: '198.51.100.7',
          protected_host: 'edge.example.test',
        },
      },
      probeProfile: undefined,
      probeWorkerSecret: SECRET,
      now: new Date('2026-07-06T00:00:00.000Z'),
      newId: () => 'pjob_test',
    });
    assert.equal(job.probe_profile.direct_ip, '198.51.100.7');
    assert.equal(job.probe_profile.protected_host, 'edge.example.test');
    assert.equal(job.target.metadata.direct_origin_ip, '198.51.100.7');
  });

  it('buildSignedProbeJobRecord enriches direct reachability from target metadata', () => {
    const check = getCheckById('origin.direct_reachability.safe');
    const job = buildSignedProbeJobRecord({
      run: { id: 'run_1', tenant_id: 'ten_1', safety_constraints: { max_requests: 1 } },
      check,
      target: {
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'edge.example.test',
        metadata: {
          direct_origin_ip: '198.51.100.8',
          protected_host: 'edge.example.test',
        },
      },
      probeProfile: undefined,
      probeWorkerSecret: SECRET,
      now: new Date('2026-07-06T00:00:00.000Z'),
      newId: () => 'pjob_direct',
    });
    assert.equal(job.probe_profile.kind, 'host_sni_bypass');
    assert.equal(job.probe_profile.direct_ip, '198.51.100.8');
    assert.equal(job.probe_profile.protected_host, 'edge.example.test');
    assert.equal(job.target.metadata.direct_origin_ip, '198.51.100.8');
  });
});
