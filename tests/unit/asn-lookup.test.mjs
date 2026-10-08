import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  lookupAsnForIp,
  classifyCloudByAsn,
  queryAsnViaDns,
  parseCymruAsnTxt,
  ipToCymruDnsName,
  getKnownAsnInfo,
} from '../../src/lib/asnLookup.mjs';
import { classifyEdgeFingerprint } from '../../src/lib/edgeFingerprint.mjs';
import { generateAsnEdgeData } from '../../scripts/generate-asn-cloud-data.mjs';
import { ASN_EDGE_ADDRESS_RANGES_PACKED, ASN_EDGE_DATA_MANIFEST, ASN_EDGE_DATA_VERSION } from '../../src/lib/data/asnEdgeData.mjs';

describe('ASN offline database lookup', () => {
  it('binds the current packed snapshot and source timestamps to its recorded hash', () => {
    const hash = createHash('sha256').update(JSON.stringify({
      sources: ASN_EDGE_DATA_MANIFEST.sources, ranges: ASN_EDGE_ADDRESS_RANGES_PACKED,
    })).digest('hex');
    assert.equal(ASN_EDGE_DATA_VERSION, `sha256:${hash}`);
  });
  it('resolves known IPv4 prefixes for cloud and hosting providers', () => {
    // Hetzner
    const hetzner = lookupAsnForIp('49.12.1.2');
    assert.ok(hetzner, 'Expected Hetzner IP to resolve');
    assert.equal(hetzner.asn, 24940);
    assert.equal(hetzner.provider, 'hetzner');
    assert.equal(hetzner.org, 'Hetzner Online GmbH');
    assert.equal(hetzner.country, 'DE');

    // DigitalOcean
    const doResult = lookupAsnForIp('104.248.50.1');
    assert.ok(doResult, 'Expected DigitalOcean IP to resolve');
    assert.equal(doResult.asn, 14061);
    assert.equal(doResult.provider, 'digitalocean');
    assert.equal(doResult.org, 'DigitalOcean, LLC');

    // OVHcloud
    const ovhResult = lookupAsnForIp('51.255.100.2');
    assert.ok(ovhResult, 'Expected OVH IP to resolve');
    assert.equal(ovhResult.asn, 16276);
    assert.equal(ovhResult.provider, 'ovh');

    // Vultr
    const vultrResult = lookupAsnForIp('108.61.10.20');
    assert.ok(vultrResult, 'Expected Vultr IP to resolve');
    assert.equal(vultrResult.asn, 20473);
    assert.equal(vultrResult.provider, 'vultr');

    // Linode / Akamai Cloud
    const linodeResult = lookupAsnForIp('172.104.10.5');
    assert.ok(linodeResult, 'Expected Linode IP to resolve');
    assert.equal(linodeResult.asn, 63949);
    assert.equal(linodeResult.provider, 'linode');

    // Scaleway
    const scalewayResult = lookupAsnForIp('51.159.10.1');
    assert.ok(scalewayResult, 'Expected Scaleway IP to resolve');
    assert.equal(scalewayResult.asn, 12876);
    assert.equal(scalewayResult.provider, 'scaleway');

    // Leaseweb
    const leasewebResult = lookupAsnForIp('178.162.192.50');
    assert.ok(leasewebResult, 'Expected Leaseweb IP to resolve');
    assert.equal(leasewebResult.asn, 60781);
    assert.equal(leasewebResult.provider, 'leaseweb');
  });

  it('resolves known IPv6 prefixes for cloud providers', () => {
    // Hetzner IPv6
    const hetzner6 = lookupAsnForIp('2a01:4f8:1c1c:1::1');
    assert.ok(hetzner6, 'Expected Hetzner IPv6 to resolve');
    assert.equal(hetzner6.asn, 24940);
    assert.equal(hetzner6.provider, 'hetzner');

    // DigitalOcean IPv6
    const do6 = lookupAsnForIp('2604:a880:800:10::1');
    assert.ok(do6, 'Expected DigitalOcean IPv6 to resolve');
    assert.equal(do6.asn, 14061);
    assert.equal(do6.provider, 'digitalocean');

    // OVH IPv6
    const ovh6 = lookupAsnForIp('2001:41d0:1:1::1');
    assert.ok(ovh6, 'Expected OVH IPv6 to resolve');
    assert.equal(ovh6.asn, 16276);
    assert.equal(ovh6.provider, 'ovh');

    // Linode IPv6
    const linode6 = lookupAsnForIp('2600:3c00::1');
    assert.ok(linode6, 'Expected Linode IPv6 to resolve');
    assert.equal(linode6.asn, 63949);
    assert.equal(linode6.provider, 'linode');
  });

  it('returns null for uncatalogued, private, loopback, or invalid IP addresses', () => {
    assert.equal(lookupAsnForIp('127.0.0.1'), null);
    assert.equal(lookupAsnForIp('10.0.0.1'), null);
    assert.equal(lookupAsnForIp('192.168.1.1'), null);
    assert.equal(lookupAsnForIp('172.16.0.1'), null);
    assert.equal(lookupAsnForIp('::1'), null);
    assert.equal(lookupAsnForIp('invalid-ip'), null);
    assert.equal(lookupAsnForIp(''), null);
    assert.equal(lookupAsnForIp(null), null);
  });

  it('provides metadata lookup by ASN integer', () => {
    const info = getKnownAsnInfo(24940);
    assert.ok(info);
    assert.equal(info.provider, 'hetzner');
    assert.equal(info.org, 'Hetzner Online GmbH');

    assert.equal(getKnownAsnInfo(99999999), null);
  });
});

describe('Team Cymru ASN DNS query parsing', () => {
  it('formats IPv4 and IPv6 addresses into reverse DNS lookup names', () => {
    assert.equal(
      ipToCymruDnsName('49.12.1.2'),
      '2.1.12.49.origin.asn.cymru.com',
    );
    assert.equal(
      ipToCymruDnsName('2001:41d0:1:1::1'),
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.1.0.0.0.0.d.1.4.1.0.0.2.origin6.asn.cymru.com',
    );
    assert.equal(ipToCymruDnsName('invalid'), null);
  });

  it('parses standard Team Cymru TXT record responses', () => {
    const parsed = parseCymruAsnTxt('"24940 | 49.12.0.0/16 | DE | ripencc | 2017-06-27"');
    assert.ok(parsed);
    assert.equal(parsed.asn, 24940);
    assert.equal(parsed.prefix, '49.12.0.0/16');
    assert.equal(parsed.country, 'DE');
    assert.equal(parsed.registry, 'ripencc');
    assert.equal(parsed.allocated, '2017-06-27');
  });

  it('parses AS-path / multi-ASN TXT record responses', () => {
    const parsed = parseCymruAsnTxt('"15169 396982 | 8.8.8.0/24 | US | arin | 2014-03-14"');
    assert.ok(parsed);
    assert.equal(parsed.asn, 15169);
    assert.equal(parsed.prefix, '8.8.8.0/24');
    assert.equal(parsed.country, 'US');
  });

  it('handles mocked DNS TXT query', async () => {
    const mockResolveTxt = async (name) => {
      if (name === '2.1.12.49.origin.asn.cymru.com') {
        return [['24940 | 49.12.0.0/16 | DE | ripencc | 2017-06-27']];
      }
      throw new Error('NXDOMAIN');
    };

    const result = await queryAsnViaDns('49.12.1.2', { resolveTxtFn: mockResolveTxt });
    assert.ok(result);
    assert.equal(result.asn, 24940);
    assert.equal(result.provider, 'hetzner');
    assert.equal(result.org, 'Hetzner Online GmbH');
    assert.equal(result.source, 'cymru_dns');
  });
});

describe('classifyCloudByAsn aggregation', () => {
  it('aggregates cloud providers from a list of IP addresses', () => {
    const classification = classifyCloudByAsn(['49.12.1.2', '104.248.50.1']);
    assert.equal(classification.cloud_hosted, true);
    assert.deepEqual(classification.cloud_providers, ['digitalocean', 'hetzner']);
    assert.equal(classification.asn_matches.length, 2);
    assert.equal(classification.primary_asn.provider, 'hetzner');
  });

  it('returns empty classification when no IPs match cloud ASNs', () => {
    const classification = classifyCloudByAsn(['127.0.0.1', '192.0.2.1']);
    assert.equal(classification.cloud_hosted, false);
    assert.deepEqual(classification.cloud_providers, []);
    assert.deepEqual(classification.asn_matches, []);
    assert.equal(classification.primary_asn, null);
  });
});

describe('edgeFingerprint ASN integration', () => {
  it('identifies the recorded Barclays edge IP and a regional Akamai answer without inventing WAF or hosting', () => {
    for (const ip of ['69.192.16.127', '23.47.231.231', '::ffff:69.192.16.127']) {
      const result = classifyEdgeFingerprint({ normal: { statusCode: 302 }, resolvedIps: [ip], dnsObserved: true });
      assert.equal(result.cdn_detected, true);
      assert.deepEqual(result.cdn_providers, ['akamai']);
      assert.equal(result.asn.asn, 16625);
      assert.equal(result.asn.family, 'cdn');
      assert.equal(result.cloud_hosted, false);
      assert.equal(result.waf_present, false);
      assert.deepEqual(result.layers.map((layer) => layer.family), ['cdn']);
      assert.match(result.asn_dataset_version, /^sha256:[a-f0-9]{64}$/);
    }
  });

  it('excludes withdrawn routes and records reproducible provenance when generating the edge corpus', async () => {
    const fetchFn = async (url) => ({
      ok: true,
      json: async () => ({ status: 'ok', data: {
        resource: new URL(url).searchParams.get('resource'),
        latest_time: '2026-10-08T00:00:00',
        prefixes: [
          { prefix: '69.192.16.0/20', timelines: [{ starttime: '2026-10-01T00:00:00', endtime: '2026-10-08T00:00:00' }] },
          { prefix: '192.0.2.0/24', timelines: [{ starttime: '2026-10-01T00:00:00', endtime: '2026-10-07T00:00:00' }] },
        ],
      } }),
    });
    const module = await generateAsnEdgeData(fetchFn);
    assert.equal(module, await generateAsnEdgeData(fetchFn));
    const data = await import(`data:text/javascript,${encodeURIComponent(module)}`);
    assert.equal(data.ASN_EDGE_ADDRESS_RANGES_PACKED[16625].count, 1);
    assert.equal(data.ASN_EDGE_ADDRESS_RANGES_PACKED[16625].v4, '1445c010');
    assert.equal(data.ASN_EDGE_DATA_MANIFEST.sources[0].observed_at, '2026-10-08T00:00:00');
    await assert.rejects(generateAsnEdgeData(async () => ({ ok: false, status: 503 })), /RIS lookup failed/);
  });

  it('recognizes Framer anycast addresses as AWS network ownership without inferring AWS WAF', () => {
    const result = classifyEdgeFingerprint({ resolvedIps: ['31.43.160.19', '31.43.161.19'], dnsObserved: true });
    assert.equal(result.asn.asn, 16509);
    assert.deepEqual(result.cloud_providers, ['aws']);
    assert.equal(result.waf_present, false);
    assert.equal(result.cdn_detected, false, 'AWS ASN membership alone is not a CDN product');
  });
  it('detects Hetzner cloud hosting for domains resolving to Hetzner IPs', () => {
    const result = classifyEdgeFingerprint({
      resolvedIps: ['49.12.1.2'],
      dnsObserved: true,
    });

    assert.equal(result.cloud_hosted, true);
    assert.deepEqual(result.cloud_providers, ['hetzner']);
    assert.ok(result.asn);
    assert.equal(result.asn.asn, 24940);
    assert.equal(result.asn.org, 'Hetzner Online GmbH');
    assert.equal(result.asn.provider, 'hetzner');
    assert.equal(result.cdn_detected, false);

    // Layer check
    const hetznerLayer = result.layers.find(
      (layer) => layer.family === 'cloud' && layer.provider === 'hetzner',
    );
    assert.ok(hetznerLayer, 'Expected cloud:hetzner layer');
    assert.deepEqual(hetznerLayer.sources, ['asn_lookup']);
  });

  it('stacks CDN and cloud layers when using CDN CNAME with origin/edge IP on a cloud provider', () => {
    const result = classifyEdgeFingerprint({
      cnameChain: ['mycdn.b-cdn.net'],
      resolvedIps: ['49.12.1.2'],
      dnsObserved: true,
    });

    // Bunny CDN detected via modern curated CNAME
    assert.equal(result.cdn_detected, true);
    assert.deepEqual(result.cdn_providers, ['bunnycdn']);

    // Hetzner cloud detected via ASN
    assert.equal(result.cloud_hosted, true);
    assert.deepEqual(result.cloud_providers, ['hetzner']);

    // Both layers represented
    const cdnLayer = result.layers.find((l) => l.family === 'cdn' && l.provider === 'bunnycdn');
    const cloudLayer = result.layers.find((l) => l.family === 'cloud' && l.provider === 'hetzner');
    assert.ok(cdnLayer, 'Expected Bunny CDN layer');
    assert.ok(cloudLayer, 'Expected Hetzner cloud layer');
  });
});
