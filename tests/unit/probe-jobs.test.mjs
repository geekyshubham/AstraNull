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
    for (const unsafe of ['169.254.169.254', '127.0.0.1', '::1', '0.0.0.0', '::ffff:10.0.0.5', 'metadata.google.internal']) {
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

  it('drops authority-retargeting GraphQL and gRPC path overrides', () => {
    const check = {
      probe_profile: {
        kind: 'graphql_posture_probe',
        max_requests: 1,
        timeout_ms: 5_000,
        graphql_path: '/graphql',
      },
    };
    for (const unsafe of [
      '//evil.example/graphql',
      '/@evil.example/graphql',
      '/graphql?next=//evil.example',
      '/graphql#fragment',
      '/\\\\evil.example\\graphql',
      'https://evil.example/graphql',
    ]) {
      const profile = resolveJobProbeProfile(check, {
        graphql_path: unsafe,
        grpc_path: unsafe,
      });
      assert.equal(profile.graphql_path, '/graphql');
      assert.equal(profile.grpc_path, undefined);
    }
  });

  it('targetDescriptor strips alternate destinations but keeps same-host URLs and Host/SNI labels', () => {
    const descriptor = targetDescriptor({
      id: 'tgt_1',
      kind: 'fqdn',
      value: 'edge.example.test',
      metadata: {
        direct_origin_ip: '198.51.100.7',
        resolver_host: '8.8.8.8',
        alert_webhook_url: 'https://victim.example.test/alerts',
        webhook_url: 'https://edge.example.test/alerts?source=astranull',
        protected_host: 'protected.example.test',
      },
    });
    assert.equal(descriptor.metadata.direct_origin_ip, undefined);
    assert.equal(descriptor.metadata.resolver_host, undefined);
    assert.equal(descriptor.metadata.alert_webhook_url, undefined);
    assert.equal(descriptor.metadata.webhook_url, 'https://edge.example.test/alerts?source=astranull');
    assert.equal(descriptor.metadata.protected_host, 'protected.example.test');
  });

  it('binds catalog, body, and target-metadata destinations after every merge', () => {
    const catalogCheck = getCheckById('origin.host_sni_bypass.safe');
    const check = {
      ...catalogCheck,
      probe_profile: {
        ...catalogCheck.probe_profile,
        direct_ip: '198.51.100.40',
        resolver_host: '8.8.8.8',
        secondary_nameservers: ['ns.catalog-victim.example.test'],
      },
    };
    const job = buildSignedProbeJobRecord({
      run: { id: 'run_1', tenant_id: 'ten_1', safety_constraints: { max_requests: 1 } },
      check,
      target: {
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'edge.example.test',
        metadata: {
          direct_origin_ip: '198.51.100.41',
          resolver_host: '1.1.1.1',
          secondary_nameservers: ['ns.metadata-victim.example.test'],
          alert_webhook_url: 'https://webhook-victim.example.test/alerts',
          webhook_url: 'https://another-victim.example.test/alerts',
          protected_host: 'protected.example.test',
        },
      },
      probeProfile: {
        direct_ip: '198.51.100.42',
        resolver_host: '9.9.9.9',
        secondary_nameservers: ['ns.body-victim.example.test'],
        protected_host: 'customer-protected.example.test',
      },
      probeWorkerSecret: SECRET,
      now: new Date('2026-07-06T00:00:00.000Z'),
      newId: () => 'pjob_bound',
    });

    assert.equal(job.probe_profile.direct_ip, undefined);
    assert.equal(job.probe_profile.resolver_host, undefined);
    assert.equal(job.probe_profile.secondary_nameservers, undefined);
    assert.equal(job.probe_profile.protected_host, 'customer-protected.example.test');
    assert.equal(job.target.metadata?.direct_origin_ip, undefined);
    assert.equal(job.target.metadata?.resolver_host, undefined);
    assert.equal(job.target.metadata?.alert_webhook_url, undefined);
    assert.equal(job.target.metadata?.webhook_url, undefined);
    for (const victim of [
      '198.51.100.40', '8.8.8.8', 'ns.catalog-victim.example.test',
      '198.51.100.41', '1.1.1.1', 'ns.metadata-victim.example.test',
      'webhook-victim.example.test', 'another-victim.example.test',
      '198.51.100.42', '9.9.9.9', 'ns.body-victim.example.test',
    ]) {
      assert.equal(JSON.stringify(job).includes(victim), false, `signed alternate destination ${victim}`);
    }
  });

  it('allows exact literal-IP target destinations with a separate protected Host/SNI label', () => {
    const check = getCheckById('origin.host_sni_bypass.safe');
    const job = buildSignedProbeJobRecord({
      run: { id: 'run_1', tenant_id: 'ten_1', safety_constraints: { max_requests: 3 } },
      check,
      target: {
        id: 'tgt_1',
        kind: 'url',
        value: 'https://198.51.100.7/probe?bounded=1',
        metadata: {
          direct_origin_ip: '198.51.100.7',
          resolver_host: '198.51.100.7',
          webhook_url: 'https://198.51.100.7/hook?bounded=1',
          alert_webhook_url: 'https://198.51.100.99/victim',
        },
      },
      probeProfile: {
        protected_host: 'edge.example.test',
        direct_ip: '198.51.100.7',
        resolver_host: '198.51.100.99',
        secondary_nameservers: ['198.51.100.7', '198.51.100.99'],
      },
      probeWorkerSecret: SECRET,
      now: new Date('2026-07-06T00:00:00.000Z'),
      newId: () => 'pjob_literal',
    });

    assert.equal(job.probe_profile.protected_host, 'edge.example.test');
    assert.equal(job.probe_profile.direct_ip, '198.51.100.7');
    assert.equal(job.probe_profile.resolver_host, undefined);
    assert.deepEqual(job.probe_profile.secondary_nameservers, ['198.51.100.7']);
    assert.equal(job.target.metadata.direct_origin_ip, '198.51.100.7');
    assert.equal(job.target.metadata.resolver_host, '198.51.100.7');
    assert.equal(job.target.metadata.webhook_url, 'https://198.51.100.7/hook?bounded=1');
    assert.equal(job.target.metadata.alert_webhook_url, undefined);
    assert.equal(JSON.stringify(job).includes('198.51.100.99'), false);
  });

  it('exact-binds AXFR zone and declared-domain metadata after canonical comparison', () => {
    const check = getCheckById('dns.zone_transfer_exposure.safe');
    const build = ({ probeProfile, metadata }) => buildSignedProbeJobRecord({
      run: { id: 'run_axfr', tenant_id: 'ten_1', safety_constraints: { max_requests: 1 } },
      check,
      target: {
        id: 'tgt_axfr',
        kind: 'fqdn',
        value: 'Owned.Example.',
        metadata,
      },
      probeProfile,
      probeWorkerSecret: SECRET,
      now: new Date('2026-08-30T00:00:00.000Z'),
      newId: () => 'pjob_axfr',
    });

    const retargeted = build({
      probeProfile: {
        zone: 'victim.example',
        recursion_test_name: 'lookup-victim.example',
        secondary_nameservers: ['ns.victim.example'],
      },
      metadata: {
        zone: 'victim.example',
        declared_apex_domain: 'victim.example.',
      },
    });
    assert.equal(retargeted.probe_profile.zone, undefined);
    assert.equal(retargeted.probe_profile.recursion_test_name, undefined);
    assert.equal(retargeted.probe_profile.secondary_nameservers, undefined);
    assert.equal(retargeted.target.metadata?.zone, undefined);
    assert.equal(retargeted.target.metadata?.declared_apex_domain, undefined);
    assert.equal(JSON.stringify(retargeted).includes('victim.example'), false);

    const exact = build({
      probeProfile: {
        zone: 'owned.example',
        recursion_test_name: 'OWNED.EXAMPLE.',
        secondary_nameservers: ['Owned.Example.'],
      },
      metadata: {
        zone: 'OWNED.EXAMPLE.',
        declared_apex_domain: 'owned.example',
      },
    });
    assert.equal(exact.probe_profile.zone, 'owned.example');
    assert.equal(exact.probe_profile.recursion_test_name, 'owned.example');
    assert.deepEqual(exact.probe_profile.secondary_nameservers, ['owned.example']);
    assert.equal(exact.target.metadata.zone, 'owned.example');
    assert.equal(exact.target.metadata.declared_apex_domain, 'owned.example');
  });

});
