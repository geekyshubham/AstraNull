import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  SubdomainSourceError,
  fetchVirusTotalSubdomains,
  normalizeSubdomainCandidate,
  ownershipParentFor,
  presentSubdomainRow,
  subdomainParentTag,
  summarizeSubdomains,
} from '../../src/lib/subdomainEnumeration.mjs';
import { recordDnsVerification } from '../helpers/subdomain-fixtures.mjs';
import { targetOwnershipProof } from '../../src/services/ownershipVerification.mjs';
import { createTargetDirect } from '../../src/services/targetGroups.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_sub', userId: 'u1', role: 'admin' };

function jsonResponse(status, body) {
  return { status, json: async () => body };
}

describe('normalizeSubdomainCandidate', () => {
  it('keeps strict subdomains and drops everything else', () => {
    assert.equal(normalizeSubdomainCandidate('API.Example.com.', 'example.com'), 'api.example.com');
    assert.equal(normalizeSubdomainCandidate('example.com', 'example.com'), null);
    assert.equal(normalizeSubdomainCandidate('*.example.com', 'example.com'), null);
    assert.equal(normalizeSubdomainCandidate('evil-example.com', 'example.com'), null);
    assert.equal(normalizeSubdomainCandidate('example.com.attacker.net', 'example.com'), null);
    assert.equal(normalizeSubdomainCandidate('10.0.0.1', 'example.com'), null);
  });
});

describe('fetchVirusTotalSubdomains', () => {
  it('refuses to run without an API key', async () => {
    await assert.rejects(
      fetchVirusTotalSubdomains('example.com', { apiKey: '', fetchFn: async () => jsonResponse(200, {}) }),
      (error) => error instanceof SubdomainSourceError && error.code === 'subdomain_source_not_configured',
    );
  });

  it('pages with the cursor, sends the key header, and filters foreign hosts', async () => {
    const calls = [];
    const pages = [
      { data: [{ id: 'a.example.com' }, { id: 'other.net' }], meta: { cursor: 'c2', count: 3 } },
      { data: [{ id: 'b.example.com' }, { id: 'a.example.com' }], meta: {} },
    ];
    const result = await fetchVirusTotalSubdomains('example.com', {
      apiKey: 'test-key',
      fetchFn: async (url, init) => {
        calls.push({ url: String(url), key: init.headers['x-apikey'], redirect: init.redirect });
        return jsonResponse(200, pages[calls.length - 1]);
      },
    });
    assert.deepEqual(result.hostnames, ['a.example.com', 'b.example.com']);
    assert.equal(result.pages, 2);
    assert.equal(result.truncated, false);
    assert.equal(calls[0].url, 'https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40');
    assert.match(calls[1].url, /cursor=c2$/);
    assert.ok(calls.every((call) => call.key === 'test-key' && call.redirect === 'manual'));
  });

  it('keeps collected hosts when the quota runs out after the first page', async () => {
    let count = 0;
    const result = await fetchVirusTotalSubdomains('example.com', {
      apiKey: 'k',
      fetchFn: async () => {
        count += 1;
        return count === 1
          ? jsonResponse(200, { data: [{ id: 'a.example.com' }], meta: { cursor: 'next' } })
          : jsonResponse(429, {});
      },
    });
    assert.deepEqual(result.hostnames, ['a.example.com']);
    assert.equal(result.stop_reason, 'rate_limited');
  });

  it('maps auth and first-page quota failures to typed errors', async () => {
    await assert.rejects(
      fetchVirusTotalSubdomains('example.com', { apiKey: 'k', fetchFn: async () => jsonResponse(401, {}) }),
      (error) => error.code === 'subdomain_source_auth_failed',
    );
    await assert.rejects(
      fetchVirusTotalSubdomains('example.com', { apiKey: 'k', fetchFn: async () => jsonResponse(429, {}) }),
      (error) => error.code === 'subdomain_source_rate_limited' && error.status === 429,
    );
  });

  it('stops at the result cap', async () => {
    const data = Array.from({ length: 40 }, (_, index) => ({ id: `h${index}.example.com` }));
    const result = await fetchVirusTotalSubdomains('example.com', {
      apiKey: 'k',
      maxResults: 5,
      fetchFn: async () => jsonResponse(200, { data, meta: { cursor: 'more' } }),
    });
    assert.equal(result.hostnames.length, 5);
    assert.equal(result.stop_reason, 'max_results');
  });
});

describe('subdomain rows', () => {
  it('derives exposure and provider counts from edge families', () => {
    const base = { target_group_id: 'tg', tags: [subdomainParentTag('tgt_p')] };
    const rows = [
      presentSubdomainRow({ ...base, id: 't1', value: 'a.example.com', protection_profile: { families: { waf: { status: 'detected', provider: 'Cloudflare', observed_at: 'x' }, cdn: { status: 'detected', provider: 'Cloudflare' } } }, edge_cloud: { status: 'detected', provider: 'AWS' } }, 'tgt_p'),
      presentSubdomainRow({ ...base, id: 't2', value: 'b.example.com', protection_profile: { families: { waf: { status: 'not_detected', observed_at: 'x' }, cdn: { status: 'not_detected' } } } }, 'tgt_p'),
      presentSubdomainRow({ id: 't3', target_group_id: 'tg', tags: [], value: 'c.example.com' }, 'tgt_p'),
    ];
    assert.deepEqual(rows.map((row) => row.exposure), ['protected', 'exposed', 'not_checked']);
    assert.deepEqual(rows.map((row) => row.origin), ['discovered', 'discovered', 'declared']);
    assert.equal(rows[0].cloud.provider, 'AWS');
    const summary = summarizeSubdomains(rows);
    assert.equal(summary.exposure.protected, 1);
    assert.equal(summary.exposure.exposed, 1);
    assert.ok(summary.providers.some((entry) => entry.layer === 'cloud' && entry.provider === 'AWS'));
  });
});

describe('subdomain ownership inheritance', () => {
  afterEach(() => freshStore());

  it('only names a real parent in the same group', () => {
    const parent = { id: 'tgt_p', kind: 'fqdn', value: 'example.com', target_group_id: 'tg' };
    const child = { id: 'tgt_c', kind: 'fqdn', value: 'api.example.com', target_group_id: 'tg', tags: [subdomainParentTag('tgt_p')] };
    assert.equal(ownershipParentFor(child, [parent])?.id, 'tgt_p');
    assert.equal(ownershipParentFor({ ...child, value: 'api.other.com' }, [parent]), null);
    assert.equal(ownershipParentFor(child, [{ ...parent, target_group_id: 'tg2' }]), null);
    assert.equal(ownershipParentFor({ ...child, tags: [] }, [parent]), null);
  });

  it('authorizes a discovered subdomain only while its parent is verified', () => {
    freshStore();
    const parent = createTargetDirect(ctx, { kind: 'fqdn', value: 'example.com' });
    const child = createTargetDirect(ctx, {
      kind: 'fqdn',
      value: 'api.example.com',
      target_group_id: parent.target_group_id,
      tags: [subdomainParentTag(parent.id)],
    });
    const group = { id: parent.target_group_id };
    assert.equal(targetOwnershipProof(ctx, group, child.id).verified, false);

    recordDnsVerification(ctx, parent);
    const proof = targetOwnershipProof(ctx, group, child.id);
    assert.equal(proof.verified, true);
    assert.equal(proof.inherited_from_target_id, parent.id);
  });
});
