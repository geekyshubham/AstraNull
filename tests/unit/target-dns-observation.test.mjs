import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { targetDnsObservation } from '../../src/lib/targetDnsObservation.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { listTargets } from '../../src/services/targetGroups.mjs';
import { freshStore } from '../helpers/reset.mjs';

const OBSERVED_AT = '2026-10-14T09:30:00.000Z';

describe('targets list dns_observation', () => {
  it('keeps only bounded DNS answers and provider matches from a stored edge detection', () => {
    const summary = targetDnsObservation({
      observed_at: OBSERVED_AT,
      waf_vendor: 'cloudflare',
      evidence_json: {
        dns_cname_chain: ['shop.example.com', 'shop.example.com.cdn.cloudflare.net', 'shop.example.com', ''],
        dns_resolved_ips: Array.from({ length: 20 }, (_, i) => `198.51.100.${i}`),
        cname_matches: [{ host: 'shop.example.com.cdn.cloudflare.net', provider: 'cloudflare', family: 'CDN', raw: 'x' }, { host: 'n' }],
        address_matches: [{ provider: 'cloudflare', family: 'cdn', cidr: '198.51.100.0/24' }],
        wafw00f: { output: 'not part of the list contract' },
      },
    });
    assert.deepEqual(summary, {
      observed_at: OBSERVED_AT,
      evidence: {
        dns_cname_chain: ['shop.example.com', 'shop.example.com.cdn.cloudflare.net'],
        dns_resolved_ips: Array.from({ length: 16 }, (_, i) => `198.51.100.${i}`),
        cname_matches: [{ provider: 'cloudflare', family: 'cdn', host: 'shop.example.com.cdn.cloudflare.net' }],
        cname_cdn_matches: [],
        address_matches: [{ provider: 'cloudflare', family: 'cdn' }],
      },
    });
  });

  it('returns null when no edge detection is stored', () => {
    assert.equal(targetDnsObservation(null), null);
    assert.equal(targetDnsObservation(undefined), null);
  });

  it('adds the tenant’s own stored observation to in-memory list items', () => {
    const store = freshStore();
    const target = store.targets.find((row) => row.tenant_id === 'ten_demo');
    store.targetEdgeDetections = [
      { tenant_id: 'ten_demo', target_id: target.id, observed_at: OBSERVED_AT, evidence_json: { dns_cname_chain: [target.value], dns_resolved_ips: ['203.0.113.7'] } },
      { tenant_id: 'ten_other', target_id: target.id, observed_at: OBSERVED_AT, evidence_json: { dns_resolved_ips: ['192.0.2.1'] } },
    ];
    const item = listTargets({ tenantId: 'ten_demo' }).find((row) => row.id === target.id);
    assert.deepEqual(item.dns_observation.evidence.dns_resolved_ips, ['203.0.113.7']);
    assert.equal(item.dns_observation.observed_at, OBSERVED_AT);
  });

  it('maps the Postgres lateral DNS columns onto the same field', async () => {
    const row = {
      id: 'tgt_pg', tenant_id: 'ten_pg', target_group_id: 'tg_pg', target_group_name: 'Payments',
      ownership_status: 'dns_verified', kind: 'fqdn', value: 'pay.example.com', metadata_json: {},
      verification_state: 'dns_verified', created_at: new Date(OBSERVED_AT),
      dns_observed_at: new Date(OBSERVED_AT),
      dns_evidence: { dns_cname_chain: ['pay.example.com', 'pay.edge.example.net'], dns_resolved_ips: null },
    };
    const client = { async query(text) { return { rows: text.includes('FROM targets t') ? [row] : [] }; }, release() {} };
    const repository = createCoreCatalogRepository({ async connect() { return client; } });
    const [item] = await repository.listTargets({ tenantId: 'ten_pg' });
    assert.deepEqual(item.dns_observation, {
      observed_at: OBSERVED_AT,
      evidence: {
        dns_cname_chain: ['pay.example.com', 'pay.edge.example.net'],
        dns_resolved_ips: [],
        cname_matches: [],
        cname_cdn_matches: [],
        address_matches: [],
      },
    });
  });
});
