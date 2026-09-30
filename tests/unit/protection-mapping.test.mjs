
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildProtectionMapping,
  buildProtectionMappings,
  DEFAULT_PROTECTION_MAPPING_STALE_AFTER_MS,
  PROTECTION_MAPPING_GAP_CODES,
} from '../../src/contracts/protectionMapping.mjs';

function snapshot(kind, provider, overrides = {}) {
  return {
    snapshot_kind: kind,
    provider,
    display_ref: overrides.display_ref ?? 'snap',
    observed_at: overrides.observed_at ?? '2026-09-30T00:00:00.000Z',
    summary: {
      hostnames: [],
      ...overrides.summary,
    },
    ...overrides,
  };
}

describe('protection mapping reconciliation', () => {
  it('reports every layer missing when no connector evidence exists at all', () => {
    const mapping = buildProtectionMapping(
      { id: 'waf_1', target_group_id: 'tg_1', canonical_url: 'https://app.example.com/checkout' },
      {},
      { now: new Date('2026-09-30T12:00:00.000Z') },
    );
    assert.equal(mapping.hostname, 'app.example.com');
    assert.deepEqual(mapping.gaps, [
      'no_dns_record_evidence',
      'no_cdn_property_evidence',
      'no_waf_policy_evidence',
      'no_site_shield_evidence',
    ]);
    assert.equal(mapping.mapping_complete, false);
    assert.equal(mapping.cdn_property, null);
    assert.equal(mapping.waf_policy, null);
  });

  it('resolves a complete mapping when every layer has fresh, hostname-matching evidence', () => {
    const now = new Date('2026-09-30T12:00:00.000Z');
    const evidence = {
      dnsRecordSnapshots: [
        snapshot('dns_record', 'akamai_edgedns', {
          summary: { hostnames: ['app.example.com'], record_type: 'CNAME', record_rdata: ['app.example.com.edgekey.net'] },
        }),
      ],
      cdnPropertySnapshots: [
        snapshot('cdn_property', 'akamai_property_manager', {
          display_ref: 'prod-app-property-v12',
          summary: { hostnames: ['app.example.com'] },
        }),
      ],
      wafPolicySnapshots: [
        snapshot('waf_policy', 'akamai_appsec', {
          display_ref: 'prod-security-config::policy-1',
          summary: { hostnames: ['app.example.com'], policy_mode: 'block' },
        }),
      ],
      siteShieldSnapshots: [
        snapshot('site_shield_map', 'akamai_site_shield', {
          display_ref: 'map-prod-1',
          summary: { hostnames: ['app.example.com'] },
        }),
      ],
    };
    const mapping = buildProtectionMapping(
      { id: 'waf_1', target_group_id: 'tg_1', canonical_url: 'https://app.example.com/checkout' },
      evidence,
      { now },
    );
    assert.deepEqual(mapping.gaps, []);
    assert.equal(mapping.mapping_complete, true);
    assert.equal(mapping.cname_target, 'app.example.com.edgekey.net');
    assert.equal(mapping.cdn_property.display_ref, 'prod-app-property-v12');
    assert.equal(mapping.waf_policy.policy_mode, 'block');
    assert.equal(mapping.site_shield_map.display_ref, 'map-prod-1');
  });

  it('flags hostname_not_in_property/policy_scope when evidence exists but does not name this hostname', () => {
    const mapping = buildProtectionMapping(
      { id: 'waf_1', target_group_id: 'tg_1', canonical_url: 'https://app.example.com/' },
      {
        cdnPropertySnapshots: [snapshot('cdn_property', 'akamai_property_manager', { summary: { hostnames: ['other.example.com'] } })],
        wafPolicySnapshots: [snapshot('waf_policy', 'akamai_appsec', { summary: { hostnames: ['other.example.com'] } })],
      },
      { now: new Date('2026-09-30T12:00:00.000Z') },
    );
    assert.ok(mapping.gaps.includes('hostname_not_in_property'));
    assert.ok(mapping.gaps.includes('hostname_not_in_policy_scope'));
    // Missing dns/site-shield evidence entirely is a distinct gap from "wrong hostname".
    assert.ok(mapping.gaps.includes('no_dns_record_evidence'));
    assert.ok(mapping.gaps.includes('no_site_shield_evidence'));
  });

  it('flags stale evidence separately from missing evidence', () => {
    const now = new Date('2026-09-30T12:00:00.000Z');
    const staleObservedAt = new Date(now.getTime() - DEFAULT_PROTECTION_MAPPING_STALE_AFTER_MS - 1000).toISOString();
    const mapping = buildProtectionMapping(
      { id: 'waf_1', target_group_id: 'tg_1', canonical_url: 'https://app.example.com/' },
      {
        cdnPropertySnapshots: [snapshot('cdn_property', 'akamai_property_manager', {
          observed_at: staleObservedAt,
          summary: { hostnames: ['app.example.com'] },
        })],
      },
      { now },
    );
    assert.ok(mapping.gaps.includes('stale_cdn_property_evidence'));
    assert.ok(!mapping.gaps.includes('no_cdn_property_evidence'));
    assert.ok(!mapping.gaps.includes('hostname_not_in_property'));
  });

  it('surfaces connector permission gaps and ambiguous match-target ordering', () => {
    const now = new Date('2026-09-30T12:00:00.000Z');
    const mapping = buildProtectionMapping(
      { id: 'waf_1', target_group_id: 'tg_1', canonical_url: 'https://app.example.com/' },
      {
        cdnPropertySnapshots: [snapshot('cdn_property', 'akamai_property_manager', {
          summary: { hostnames: ['app.example.com'], permission_gaps: ['truncated_inventory'] },
        })],
        wafPolicySnapshots: [
          snapshot('waf_policy', 'akamai_appsec', { display_ref: 'policy-a', summary: { hostnames: ['app.example.com'] } }),
          snapshot('waf_policy', 'akamai_appsec', { display_ref: 'policy-b', summary: { hostnames: ['app.example.com'] } }),
        ],
      },
      { now },
    );
    assert.ok(mapping.gaps.includes('connector_permission_gap'));
    assert.ok(mapping.permission_gaps.includes('truncated_inventory'));
    assert.ok(mapping.gaps.includes('ambiguous_match_target_ordering'));
  });

  it('does not flag ambiguous ordering when policies declare an explicit match_target_order', () => {
    const now = new Date('2026-09-30T12:00:00.000Z');
    const mapping = buildProtectionMapping(
      { id: 'waf_1', target_group_id: 'tg_1', canonical_url: 'https://app.example.com/' },
      {
        wafPolicySnapshots: [
          snapshot('waf_policy', 'akamai_appsec', { display_ref: 'policy-a', summary: { hostnames: ['app.example.com'], match_target_order: 1 } }),
          snapshot('waf_policy', 'akamai_appsec', { display_ref: 'policy-b', summary: { hostnames: ['app.example.com'], match_target_order: 2 } }),
        ],
      },
      { now },
    );
    assert.ok(!mapping.gaps.includes('ambiguous_match_target_ordering'));
  });

  it('rejects an asset with no resolvable hostname', () => {
    assert.throws(
      () => buildProtectionMapping({ id: 'waf_1', target_group_id: 'tg_1' }, {}),
      /resolvable hostname/,
    );
  });

  it('rejects a non-object asset or non-array assets list', () => {
    assert.throws(() => buildProtectionMapping(null, {}), /WAF asset object/);
    assert.throws(() => buildProtectionMappings('not-an-array', {}), /array of WAF assets/);
  });

  it('builds mappings for multiple assets against a shared evidence bag', () => {
    const now = new Date('2026-09-30T12:00:00.000Z');
    const evidence = {
      cdnPropertySnapshots: [
        snapshot('cdn_property', 'akamai_property_manager', { summary: { hostnames: ['a.example.com'] } }),
      ],
    };
    const mappings = buildProtectionMappings(
      [
        { id: 'waf_a', target_group_id: 'tg_1', canonical_url: 'https://a.example.com/' },
        { id: 'waf_b', target_group_id: 'tg_1', canonical_url: 'https://b.example.com/' },
      ],
      evidence,
      { now },
    );
    assert.equal(mappings.length, 2);
    assert.equal(mappings[0].hostname, 'a.example.com');
    assert.ok(!mappings[0].gaps.includes('hostname_not_in_property'));
    assert.equal(mappings[1].hostname, 'b.example.com');
    assert.ok(mappings[1].gaps.includes('hostname_not_in_property'));
  });

  it('exports the full gap-code taxonomy as frozen', () => {
    assert.ok(Array.isArray(PROTECTION_MAPPING_GAP_CODES));
    assert.ok(Object.isFrozen(PROTECTION_MAPPING_GAP_CODES));
    assert.ok(PROTECTION_MAPPING_GAP_CODES.includes('hostname_not_in_property'));
  });
});
