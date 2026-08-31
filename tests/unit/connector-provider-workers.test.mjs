import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import {
  AWS_WAF_RESPONSE_MAX_BYTES,
  pollAwsWaf,
} from '../../src/lib/connectorProviders/awsWaf.mjs';
import { pollCloudflare } from '../../src/lib/connectorProviders/cloudflare.mjs';
import {
  DOMAIN_INVENTORY_RESPONSE_MAX_BYTES,
  PROVIDER_OWNERSHIP_MAX_AGE_MS,
  isCurrentSuccessfulProviderSnapshot,
  isProviderVerifiedDnsEvidence,
  pollAkamaiEdgeDns,
  pollGoDaddy,
  pollIbmNs1,
  pollNamecheap,
} from '../../src/lib/connectorProviders/domainInventory.mjs';
import {
  CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS,
  CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS,
  CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  hashRef,
  parseProviderSecret,
  resolveConnectorPollFetchTimeoutMs,
} from '../../src/lib/connectorProviders/common.mjs';
import {
  listConnectorProviders,
  OUTBOUND_POLL_PROVIDERS,
  supportsOutboundProviderPoll,
} from '../../src/lib/connectorProviders/index.mjs';
import {
  executeConnectorProviderPoll,
  shouldAttemptOutboundConnectorPoll,
} from '../../src/lib/connectorProviders/pollWorker.mjs';
import { withConnectorPollRetry } from '../../src/lib/connectorProviders/retry.mjs';
import { buildSecretAad, encryptSecret, loadSecretEncryptionKey } from '../../src/lib/secrets.mjs';
import * as wafPosture from '../../src/services/wafPosture.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_ENC_KEY_B64 = randomBytes(32).toString('base64');
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function demoCtx(role = 'admin', tenantId = 'ten_demo', userId = 'usr_admin') {
  return { tenantId, userId, role };
}

function seedConnector(overrides = {}) {
  const store = getStore();
  if (!Array.isArray(store.wafConnectors)) store.wafConnectors = [];
  if (!Array.isArray(store.wafConnectorSnapshots)) store.wafConnectorSnapshots = [];
  const connector = {
    id: 'conn_cf_1',
    tenant_id: 'ten_demo',
    provider: 'cloudflare',
    name: 'edge-readonly',
    secret_id: 'sec_cf_1',
    config_json: { read_only: true, zone_ref_hash: hashRef('cloudflare:zone:zone_1') },
    status: 'active',
    created_at: '2026-07-01T00:00:00.000Z',
    updated_at: '2026-07-01T00:00:00.000Z',
    last_success_at: null,
    ...overrides,
  };
  store.wafConnectors.push(connector);
  return connector;
}

function slowFetchMock() {
  return async (_url, init = {}) => new Promise((_resolve, reject) => {
    const onAbort = () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      reject(err);
    };
    if (init.signal?.aborted) {
      onAbort();
      return;
    }
    init.signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function seedEncryptedSecret({ id, purpose, name, plaintext, tenantId = 'ten_demo', provider = 'cloudflare' }) {
  const key = loadSecretEncryptionKey({ ASTRANULL_SECRET_ENCRYPTION_KEY: TEST_ENC_KEY_B64 });
  const record = {
    id,
    tenant_id: tenantId,
    purpose,
    name,
    metadata: { provider },
    rotation: 0,
    created_at: '2026-07-01T00:00:00.000Z',
    updated_at: '2026-07-01T00:00:00.000Z',
    created_by: 'usr_admin',
  };
  record.envelope = encryptSecret(plaintext, key, buildSecretAad(record));
  getStore().encryptedSecrets.push(record);
  return record;
}

afterEach(() => {
  restoreEnv();
  process.env.ASTRANULL_NO_PERSIST = '1';
});

describe('connector provider helpers', () => {
  it('lists every outbound poll provider with read-only metadata', () => {
    const providers = listConnectorProviders().map((entry) => entry.provider).sort();
    assert.deepEqual(providers, [...OUTBOUND_POLL_PROVIDERS].sort());
    for (const entry of listConnectorProviders()) {
      assert.equal(entry.read_only, true);
      assert.ok(Array.isArray(entry.required_scopes));
      assert.ok(Array.isArray(entry.snapshot_kinds));
      assert.equal(supportsOutboundProviderPoll(entry.provider), true);
    }
    assert.equal(supportsOutboundProviderPoll('generic_waf'), false);
  });

  it('parses cloudflare and aws_waf vault secret shapes', () => {
    assert.deepEqual(parseProviderSecret('cf-token-plain', 'cloudflare'), { api_token: 'cf-token-plain' });
    assert.deepEqual(
      parseProviderSecret('{"api_token":"cf-json-token"}', 'cloudflare'),
      { api_token: 'cf-json-token' },
    );
    assert.deepEqual(
      parseProviderSecret(
        '{"access_key_id":"AKIA","secret_access_key":"secret","region":"us-west-2"}',
        'aws_waf',
      ),
      {
        access_key_id: 'AKIA',
        secret_access_key: 'secret',
        region: 'us-west-2',
      },
    );
  });

  it('normalizes AWS WAF scope through the developer connector boundary', () => {
    freshStore();
    const cloudfront = wafPosture.createConnector(demoCtx(), {
      provider: 'aws_waf',
      name: 'Global WAF',
      status: 'active',
      config: { read_only: true, scope: 'CLOUDFRONT' },
    });
    const invalid = wafPosture.createConnector(demoCtx(), {
      provider: 'aws_waf',
      name: 'Invalid scope',
      status: 'active',
      config: { read_only: true, scope: 'arbitrary' },
    });
    assert.equal(cloudfront.connector.config.scope, 'cloudfront');
    assert.equal(invalid.connector.config.scope, undefined);
  });

  it('normalizes prefetched cloudflare metadata without raw config bodies', async () => {
    const result = await pollCloudflare({
      credentials: null,
      config: { zone_ref_hash: hashRef('cloudflare:zone:zone_1') },
      prefetchedMetadata: {
        zones: [
          {
            id: 'zone_1',
            name: 'app.example.com',
            status: 'active',
            security_level: 'high',
            rulesets: [{ phase: 'http_request_firewall', rules: [{ id: 'r1' }, { id: 'r2' }] }],
          },
        ],
      },
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.equal(result.snapshots.length, 1);
    const snap = result.snapshots[0];
    assert.equal(snap.snapshot_kind, 'dns_zone');
    assert.equal(snap.display_ref, 'app.example.com');
    assert.equal(snap.summary.policy_mode, 'block');
    assert.equal(snap.summary.rule_count, 2);
    assert.ok(snap.summary.tags.includes('resource_status:active'));
    assert.ok(snap.summary.tags.includes('ownership_eligible:true'));
    assert.ok(snap.summary.config_hash);
    assert.equal(snap.config_hash, snap.summary.config_hash);
    assert.ok(!JSON.stringify(snap).includes('raw_payload'));
  });

  it('only treats active Cloudflare zones as provider ownership evidence', async () => {
    const observedAt = new Date().toISOString();
    const result = await pollCloudflare({
      credentials: null,
      prefetchedMetadata: {
        zones: [
          { id: 'zone_active', name: 'active.example.com', status: 'active' },
          { id: 'zone_pending', name: 'pending.example.com', status: 'pending' },
          { id: 'zone_unknown', name: 'unknown.example.com' },
        ],
      },
      observedAt,
    });
    const connector = {
      provider: 'cloudflare',
      status: 'active',
      secret_id: 'sec_cf_1',
      last_success_at: observedAt,
    };
    const evidenceFor = (displayRef) => {
      const snapshot = result.snapshots.find((entry) => entry.display_ref === displayRef);
      return {
        ...snapshot,
        snapshot_id: `snap_${displayRef}`,
        resource_ref: snapshot.resource_ref_hash,
        evidence_source: 'provider_api',
        candidate_source: 'snapshot_inventory',
        kind: 'fqdn',
      };
    };

    assert.equal(isProviderVerifiedDnsEvidence(connector, evidenceFor('active.example.com')), true);
    assert.equal(isProviderVerifiedDnsEvidence(connector, evidenceFor('pending.example.com')), false);
    assert.equal(isProviderVerifiedDnsEvidence(connector, evidenceFor('unknown.example.com')), false);
    assert.ok(evidenceFor('pending.example.com').summary.tags.includes('resource_status:pending'));
    assert.ok(evidenceFor('unknown.example.com').summary.tags.includes('resource_status:unknown'));
  });

  it('requires the exact latest successful poll revision for provider ownership evidence', async () => {
    const observedAt = new Date().toISOString();
    const result = await pollCloudflare({
      credentials: null,
      prefetchedMetadata: {
        zones: [{ id: 'zone_active', name: 'active.example.com', status: 'active' }],
      },
      observedAt,
    });
    const evidence = {
      ...result.snapshots[0],
      snapshot_id: 'snap_stale',
      resource_ref: result.snapshots[0].resource_ref_hash,
      evidence_source: 'provider_api',
      candidate_source: 'snapshot_inventory',
      kind: 'fqdn',
      poll_revision: 4,
    };
    const connector = {
      provider: 'cloudflare',
      status: 'active',
      secret_id: 'sec_cf_1',
      last_success_at: observedAt,
      last_success_revision: 5,
    };

    assert.equal(isProviderVerifiedDnsEvidence(connector, evidence), false);
    assert.equal(
      isProviderVerifiedDnsEvidence(connector, { ...evidence, poll_revision: 5 }),
      true,
    );
  });

  it('expires provider ownership authority after the hard freshness window', () => {
    const successAt = '2026-07-10T12:00:00.000Z';
    const connector = {
      provider: 'cloudflare',
      last_success_at: successAt,
      last_success_revision: 7,
    };
    const snapshot = {
      provider: 'cloudflare',
      evidence_source: 'provider_api',
      observed_at: successAt,
      poll_revision: 7,
    };
    assert.equal(isCurrentSuccessfulProviderSnapshot(
      connector,
      snapshot,
      new Date(Date.parse(successAt) + PROVIDER_OWNERSHIP_MAX_AGE_MS),
    ), true);
    assert.equal(isCurrentSuccessfulProviderSnapshot(
      connector,
      snapshot,
      new Date(Date.parse(successAt) + PROVIDER_OWNERSHIP_MAX_AGE_MS + 1),
    ), false);
    assert.equal(isCurrentSuccessfulProviderSnapshot(
      connector,
      snapshot,
      new Date(Date.parse(successAt) - 1),
    ), false);
  });

  it('uses explicit scope and the us-east-1 global endpoint for aws_waf CloudFront polls', async () => {
    const capturedScopes = [];
    const capturedRequests = [];
    const fetchFn = async (url, init) => {
      const body = JSON.parse(init.body);
      capturedScopes.push(body.Scope);
      capturedRequests.push({ url, authorization: init.headers.authorization });
      if (body.Scope && !body.Id) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ WebACLs: [] }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ WebACL: {} }),
      };
    };

    await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-east-1',
      },
      config: {
        account_ref_hash: hashRef('aws:account:123456789012'),
        scope: 'regional',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.deepEqual(capturedScopes, ['REGIONAL']);

    capturedScopes.length = 0;
    await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-west-2',
      },
      config: {
        account_ref_hash: hashRef('aws:account:123456789012'),
        scope: 'cloudfront',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.deepEqual(capturedScopes, ['CLOUDFRONT']);
    assert.equal(capturedRequests.at(-1).url, 'https://wafv2.us-east-1.amazonaws.com/');
    assert.match(capturedRequests.at(-1).authorization, /\/us-east-1\/wafv2\/aws4_request/);
  });

  it('rejects malformed AWS WAF success bodies instead of authorizing empty inventory', async () => {
    const credentials = {
      access_key_id: 'AKIATEST',
      secret_access_key: 'secret',
      region: 'us-east-1',
    };
    await assert.rejects(
      () => pollAwsWaf({
        credentials,
        fetchFn: async () => ({ ok: true, status: 200, json: async () => ({}) }),
      }),
      (err) => err?.code === 'provider_response_invalid',
    );

    await assert.rejects(
      () => pollAwsWaf({
        credentials,
        fetchFn: async (_url, init) => {
          const body = JSON.parse(init.body);
          if (body.Scope && !body.Id) {
            return {
              ok: true,
              status: 200,
              json: async () => ({ WebACLs: [{ Id: 'acl_1', Name: 'demo' }] }),
            };
          }
          return { ok: true, status: 200, json: async () => ({}) };
        },
      }),
      (err) => err?.code === 'provider_response_invalid',
    );
  });

  it('normalizes prefetched aws_waf metadata summaries', async () => {
    const result = await pollAwsWaf({
      credentials: null,
      prefetchedMetadata: {
        web_acls: [
          {
            ARN: 'arn:aws:wafv2:us-east-1:123:regional/webacl/demo/abc',
            Name: 'demo-webacl',
            DefaultAction: { Block: {} },
            Rules: [{ Name: 'AWSManagedRulesCommonRuleSet' }],
          },
        ],
      },
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.equal(result.snapshots.length, 1);
    assert.equal(result.snapshots[0].summary.policy_mode, 'block');
    assert.equal(result.snapshots[0].summary.rule_count, 1);
    assert.equal(result.snapshots[0].summary.config_hash, result.snapshots[0].config_hash);
    assert.ok(result.snapshots[0].config_hash);
  });

  it('resolves connector poll fetch timeout from env with safe fallback', () => {
    assert.equal(resolveConnectorPollFetchTimeoutMs({}), CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS);
    assert.equal(
      resolveConnectorPollFetchTimeoutMs({ ASTRANULL_CONNECTOR_POLL_FETCH_TIMEOUT_MS: '5000' }),
      5000,
    );
    assert.equal(
      resolveConnectorPollFetchTimeoutMs({ ASTRANULL_CONNECTOR_POLL_FETCH_TIMEOUT_MS: '86400000' }),
      CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS,
    );
    assert.equal(
      resolveConnectorPollFetchTimeoutMs({ ASTRANULL_CONNECTOR_POLL_FETCH_TIMEOUT_MS: 'not-a-number' }),
      CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS,
    );
  });

  it('scopes cloudflare live poll permission_gaps to each zone snapshot', async () => {
    const fetchFn = async (url) => {
      if (url.includes('/zones?') && url.includes('per_page=')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({

            success: true,
            result: [
              { id: 'zone_1', name: 'app.example.com', status: 'active' },
              { id: 'zone_2', name: 'api.example.com', status: 'active' },
            ],
            result_info: { page: 1, per_page: 50, total_pages: 1 },
          }),
        };
      }
      if (url.endsWith('/zones/zone_1/rulesets')) {
        return {
          ok: false,
          status: 403,
          json: async () => ({
            success: false,
            errors: [{ message: 'Insufficient permissions' }],
          }),
        };
      }
      if (url.endsWith('/zones/zone_2/rulesets')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result: [{ phase: 'http_request_firewall', rules: [{ id: 'r1' }] }],
          }),
        };
      }
      throw new Error(`unexpected fetch url: ${url}`);
    };

    const result = await pollCloudflare({
      credentials: { api_token: 'cf-live-token' },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.equal(result.snapshots.length, 2);
    assert.equal(result.health, 'degraded');
    assert.deepEqual(result.permission_gaps, ['rulesets:zone_1']);

    const zone1 = result.snapshots.find((snap) => snap.display_ref === 'app.example.com');
    const zone2 = result.snapshots.find((snap) => snap.display_ref === 'api.example.com');
    assert.deepEqual(zone1.summary.permission_gaps, ['rulesets:zone_1']);
    assert.equal(zone2.summary.permission_gaps, undefined);
    assert.equal(zone2.summary.rule_count, 1);
  });

  it('classifies Cloudflare credential envelopes as hard authentication failures', async () => {
    for (const [status, code] of [[400, 6003], [400, 6111], [200, 9109], [200, 10000]]) {
      await assert.rejects(
        pollCloudflare({
          credentials: { api_token: 'invalid-token' },
          observedAt: '2026-07-02T12:00:00.000Z',
          fetchFn: async () => new Response(JSON.stringify({
            success: false,
            errors: [{ code, message: 'Invalid authentication credentials' }],
          }), {
            status,
            headers: { 'content-type': 'application/json' },
          }),
        }),
        (error) => error?.code === 'auth_failed',
      );
    }
  });

  it('fails cloudflare live poll when fetch exceeds bounded timeout', async () => {
    await assert.rejects(
      () => pollCloudflare({
        credentials: { api_token: 'cf-live-token' },
        fetchFn: slowFetchMock(),
        fetchTimeoutMs: 50,
        observedAt: '2026-07-02T12:00:00.000Z',
      }),
      (err) => {
        assert.equal(err.code, 'provider_poll_failed');
        assert.match(err.message, /bounded timeout/i);
        return true;
      },
    );
  });

  it('rejects Cloudflare redirects without following them', async () => {
    let requestInit;
    await assert.rejects(
      () => pollCloudflare({
        credentials: { api_token: 'cf-live-token' },
        fetchFn: async (_url, init) => {
          requestInit = init;
          return new Response(null, {
            status: 302,
            headers: { location: 'https://attacker.example.test/redirect' },
          });
        },
        observedAt: '2026-07-02T12:00:00.000Z',
      }),
      /redirects are not followed/i,
    );
    assert.equal(requestInit.redirect, 'manual');
  });

  it('keeps the Cloudflare timeout active while consuming the response body', async () => {
    await assert.rejects(
      () => pollCloudflare({
        credentials: { api_token: 'cf-live-token' },
        fetchFn: async () => new Response(new ReadableStream({ start() {} }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
        fetchTimeoutMs: 50,
        observedAt: '2026-07-02T12:00:00.000Z',
      }),
      (err) => err.code === 'provider_poll_failed' && /bounded timeout/i.test(err.message),
    );
  });

  it('rejects oversized Cloudflare response bodies', async () => {
    const oversized = JSON.stringify({
      success: true,
      result: [{ id: 'zone_1', name: 'app.example.com', padding: 'x'.repeat(DOMAIN_INVENTORY_RESPONSE_MAX_BYTES) }],
    });
    await assert.rejects(
      () => pollCloudflare({
        credentials: { api_token: 'cf-live-token' },
        fetchFn: async () => new Response(oversized, {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
        observedAt: '2026-07-02T12:00:00.000Z',
      }),
      (err) => err.code === 'provider_response_too_large',
    );
  });

  it('fails aws_waf live poll when fetch exceeds bounded timeout', async () => {
    await assert.rejects(
      () => pollAwsWaf({
        credentials: {
          access_key_id: 'AKIATESTKEY',
          secret_access_key: 'secret-test-key',
          region: 'us-east-1',
        },
        fetchFn: slowFetchMock(),
        fetchTimeoutMs: 50,
        observedAt: '2026-07-02T12:00:00.000Z',
      }),
      (err) => {
        assert.equal(err.code, 'provider_poll_failed');
        assert.match(err.message, /bounded timeout/i);
        return true;
      },
    );
  });

  it('rejects AWS region origin injection before issuing a request', async () => {
    for (const region of ['us-east-1.attacker.example', 'us-east-1/path']) {
      let requests = 0;
      await assert.rejects(
        () => pollAwsWaf({
          credentials: {
            access_key_id: 'AKIATESTKEY',
            secret_access_key: 'secret-test-key',
            region,
          },
          fetchFn: async () => {
            requests += 1;
            throw new Error('must not fetch');
          },
        }),
        (err) => {
          assert.equal(err.code, 'credentials_invalid');
          assert.match(err.message, /one safe AWS region label/i);
          return true;
        },
      );
      assert.equal(requests, 0);
    }
  });

  it('keeps AWS WAF requests under amazonaws.com and rejects redirects', async () => {
    const requests = [];
    await assert.rejects(
      () => pollAwsWaf({
        credentials: {
          access_key_id: 'AKIATESTKEY',
          secret_access_key: 'secret-test-key',
          region: 'us-west-2',
        },
        fetchFn: async (url, init) => {
          requests.push({ url: String(url), init });
          return { ok: false, status: 302, json: async () => ({}) };
        },
      }),
      (err) => {
        assert.equal(err.code, 'provider_redirect_not_allowed');
        assert.equal(err.status, 302);
        return true;
      },
    );
    assert.equal(requests.length, 1);
    const endpoint = new URL(requests[0].url);
    assert.equal(endpoint.hostname, 'wafv2.us-west-2.amazonaws.com');
    assert.equal(endpoint.hostname.endsWith('.amazonaws.com'), true);
    assert.equal(requests[0].init.redirect, 'manual');
  });

  it('applies the AWS timeout through response body consumption', async () => {
    await assert.rejects(
      () => pollAwsWaf({
        credentials: {
          access_key_id: 'AKIATESTKEY',
          secret_access_key: 'secret-test-key',
          region: 'us-east-1',
        },
        fetchFn: async () => ({
          ok: true,
          status: 200,
          json: async () => new Promise(() => {}),
        }),
        fetchTimeoutMs: 40,
      }),
      (err) => {
        assert.equal(err.code, 'provider_poll_failed');
        assert.match(err.message, /consume.*bounded timeout/i);
        return true;
      },
    );
  });

  it('rejects AWS response bodies above the byte cap', async () => {
    const oversized = JSON.stringify({
      WebACLs: [],
      padding: 'x'.repeat(AWS_WAF_RESPONSE_MAX_BYTES),
    });
    await assert.rejects(
      () => pollAwsWaf({
        credentials: {
          access_key_id: 'AKIATESTKEY',
          secret_access_key: 'secret-test-key',
          region: 'us-east-1',
        },
        fetchFn: async () => new Response(oversized, {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      }),
      (err) => {
        assert.equal(err.code, 'provider_response_too_large');
        assert.match(err.message, /byte limit/i);
        return true;
      },
    );
  });

  it('paginates cloudflare zones until inventory is exhausted', async () => {
    const zonePages = [
      Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
        id: `zone_page1_${index}`,
        name: `page1-${index}.example.com`,
      })),
      Array.from({ length: 25 }, (_entry, index) => ({
        id: `zone_page2_${index}`,
        name: `page2-${index}.example.com`,
      })),
    ];
    const requestedPages = [];

    const fetchFn = async (url) => {
      if (url.includes('/zones?') && url.includes('per_page=')) {
        const page = Number(new URL(url).searchParams.get('page') ?? '1');
        requestedPages.push(page);
        const result = zonePages[page - 1] ?? [];
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result,
            result_info: {
              page,
              per_page: CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
              total_pages: zonePages.length,
            },
          }),
        };
      }
      if (url.includes('/rulesets')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ success: true, result: [] }),
        };
      }
      throw new Error(`unexpected fetch url: ${url}`);
    };

    const result = await pollCloudflare({
      credentials: { api_token: 'cf-live-token' },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.deepEqual(requestedPages, [1, 2]);
    assert.equal(result.snapshots.length, 75);
    assert.equal(result.health, 'active');
    assert.deepEqual(result.permission_gaps, []);
  });

  it('caps cloudflare zone inventory at 200 items with truncated_inventory gap', async () => {
    const requestedPages = [];

    const fetchFn = async (url) => {
      if (url.includes('/zones?') && url.includes('per_page=')) {
        const page = Number(new URL(url).searchParams.get('page') ?? '1');
        requestedPages.push(page);
        const start = (page - 1) * CONNECTOR_POLL_INVENTORY_PAGE_SIZE;
        const result = Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
          id: `zone_${start + index}`,
          name: `zone-${start + index}.example.com`,
        }));
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result,
            result_info: {
              page,
              per_page: CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
              total_pages: 10,
            },
          }),
        };
      }
      if (url.includes('/rulesets')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ success: true, result: [] }),
        };
      }
      throw new Error(`unexpected fetch url: ${url}`);
    };

    const result = await pollCloudflare({
      credentials: { api_token: 'cf-live-token' },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.deepEqual(requestedPages, [1, 2, 3, 4]);
    assert.equal(result.snapshots.length, CONNECTOR_POLL_MAX_INVENTORY_ITEMS);
    assert.equal(result.health, 'degraded');
    assert.deepEqual(result.permission_gaps, ['truncated_inventory']);
  });

  it('paginates aws_waf web ACL inventory with NextMarker until exhausted', async () => {
    const listCalls = [];

    const fetchFn = async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.Scope && !body.Id) {
        listCalls.push(body);
        if (!body.NextMarker) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              WebACLs: Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
                Id: `acl_page1_${index}`,
                Name: `page1-acl-${index}`,
                ARN: `arn:aws:wafv2:us-east-1:123:regional/webacl/page1-acl-${index}/id`,
              })),
              NextMarker: 'page-2',
            }),
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            WebACLs: [
              {
                Id: 'acl_page2_0',
                Name: 'page2-acl-0',
                ARN: 'arn:aws:wafv2:us-east-1:123:regional/webacl/page2-acl-0/id',
              },
            ],
          }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ WebACL: { DefaultAction: { Allow: {} }, Rules: [] } }),
      };
    };

    const result = await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-east-1',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.equal(listCalls.length, 2);
    assert.equal(listCalls[0].Limit, CONNECTOR_POLL_INVENTORY_PAGE_SIZE);
    assert.equal(listCalls[1].NextMarker, 'page-2');
    assert.equal(result.snapshots.length, CONNECTOR_POLL_INVENTORY_PAGE_SIZE + 1);
    assert.equal(result.health, 'active');
    assert.deepEqual(result.permission_gaps, []);
  });

  it('caps aws_waf web ACL inventory at 200 items with truncated_inventory gap', async () => {
    const listCalls = [];

    const fetchFn = async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.Scope && !body.Id) {
        listCalls.push(body);
        return {
          ok: true,
          status: 200,
          json: async () => ({
            WebACLs: Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
              Id: `acl_${listCalls.length}_${index}`,
              Name: `acl-${listCalls.length}-${index}`,
              ARN: `arn:aws:wafv2:us-east-1:123:regional/webacl/acl-${listCalls.length}-${index}/id`,
            })),
            NextMarker: `page-${listCalls.length + 1}`,
          }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ WebACL: { DefaultAction: { Allow: {} }, Rules: [] } }),
      };
    };

    const result = await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-east-1',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.equal(listCalls.length, 4);
    assert.equal(result.snapshots.length, CONNECTOR_POLL_MAX_INVENTORY_ITEMS);
    assert.equal(result.health, 'degraded');
    assert.deepEqual(result.permission_gaps, ['truncated_inventory']);
  });

  it('polls Akamai EdgeDNS with EdgeGrid auth and returns bounded DNS zones', async () => {
    let request;
    const result = await pollAkamaiEdgeDns({
      credentials: {
        host: 'example.luna.akamaiapis.net',
        access_token: 'access',
        client_token: 'client',
        client_secret: 'secret',
      },
      observedAt: '2026-07-02T12:00:00.000Z',
      now: new Date('2026-07-02T12:00:00.000Z'),
      nonce: 'nonce-1',
      fetchFn: async (url, init) => {
        request = { url: String(url), init };
        return { ok: true, status: 200, json: async () => ({ zones: [{ zone: 'Example.COM.' }] }) };
      },
    });
    assert.match(request.url, /^https:\/\/example\.luna\.akamaiapis\.net\/config-dns\/v2\/zones\?showAll=true$/);
    assert.match(request.init.headers.Authorization, /^EG1-HMAC-SHA256 /);
    assert.equal(request.init.redirect, 'manual');
    assert.equal(result.snapshots[0].snapshot_kind, 'dns_zone');
    assert.equal(result.snapshots[0].display_ref, 'example.com');
    assert.equal(JSON.stringify(result).includes('secret'), false);
  });

  it('requires Namecheap client IP and normalizes XML domain inventory', async () => {
    let requestedUrl = '';
    await assert.rejects(
      () => pollNamecheap({ credentials: { api_username: 'user', api_key: 'key' } }),
      /client_ip/,
    );
    const result = await pollNamecheap({
      credentials: { api_username: 'user', api_key: 'key', client_ip: '203.0.113.10', env_type: 'sandbox' },
      observedAt: '2026-07-02T12:00:00.000Z',
      fetchFn: async (url, init) => {
        requestedUrl = String(url);
        assert.equal(init.redirect, 'manual');
        return {
          ok: true,
          status: 200,
          text: async () => '<ApiResponse Status="OK"><DomainGetListResult><Domain ID="7" Name="Example.com" /></DomainGetListResult><Paging TotalItems="1" /></ApiResponse>',
        };
      },
    });
    assert.match(requestedUrl, /^https:\/\/api\.sandbox\.namecheap\.com\/xml\.response\?/);
    assert.match(requestedUrl, /ClientIp=203\.0\.113\.10/);
    assert.equal(result.snapshots[0].display_ref, 'example.com');
    assert.equal(result.inventory_complete, true);
    assert.ok(result.snapshots[0].summary.tags.includes('provider_environment:sandbox'));
    assert.ok(result.snapshots[0].summary.tags.includes('ownership_eligible:false'));
    assert.equal(isProviderVerifiedDnsEvidence({
      provider: 'namecheap',
      status: 'active',
      secret_id: 'sec_namecheap_1',
      last_success_at: '2026-07-02T12:00:00.000Z',
    }, {
      ...result.snapshots[0],
      snapshot_id: 'snap_namecheap_sandbox',
      resource_ref: result.snapshots[0].resource_ref_hash,
      evidence_source: 'provider_api',

      candidate_source: 'snapshot_inventory',
      kind: 'fqdn',
    }), false);
  });

  it('grants Namecheap authority only to current non-expired production domains', async () => {
    const result = await pollNamecheap({
      credentials: { api_username: 'user', api_key: 'key', client_ip: '203.0.113.10', env_type: 'production' },
      observedAt: '2026-07-02T12:00:00.000Z',
      fetchFn: async () => ({
        ok: true,
        status: 200,
        text: async () => '<ApiResponse Status="OK"><DomainGetListResult>'
          + '<Domain ID="1" Name="active.example" IsExpired="false" Expires="12/31/2030" />'
          + '<Domain ID="2" Name="expired.example" IsExpired="true" Expires="01/01/2020" />'
          + '<Domain ID="3" Name="unknown.example" />'
          + '</DomainGetListResult><Paging><TotalItems>3</TotalItems></Paging></ApiResponse>',
      }),
    });
    const tags = (hostname) => result.snapshots.find((row) => row.display_ref === hostname).summary.tags;
    assert.ok(tags('active.example').includes('resource_status:active'));
    assert.ok(tags('active.example').includes('ownership_eligible:true'));
    assert.ok(tags('active.example').includes('provider_environment:production'));
    assert.ok(tags('expired.example').includes('resource_status:expired'));
    assert.ok(tags('expired.example').includes('ownership_eligible:false'));
    assert.ok(tags('unknown.example').includes('resource_status:unknown'));
    assert.ok(tags('unknown.example').includes('ownership_eligible:false'));
  });

  it('uses two documented Namecheap pages for 150 domains and truncates inventories above 200', async () => {
    const xmlPage = (start, count, total) => '<ApiResponse Status="OK"><DomainGetListResult>'
      + Array.from({ length: count }, (_entry, index) => {
        const id = start + index;
        return `<Domain ID="${id}" Name="d${id}.example" IsExpired="false" />`;
      }).join('')
      + `</DomainGetListResult><Paging><TotalItems>${total}</TotalItems></Paging></ApiResponse>`;

    const completeRequests = [];
    const complete = await pollNamecheap({
      credentials: { api_username: 'user', api_key: 'key', client_ip: '203.0.113.10', env_type: 'production' },
      fetchFn: async (url) => {
        const parsed = new URL(url);
        completeRequests.push(parsed);
        const page = Number(parsed.searchParams.get('Page'));
        return { ok: true, status: 200, text: async () => xmlPage(page === 1 ? 1 : 101, page === 1 ? 100 : 50, 150) };
      },
    });
    assert.equal(completeRequests.length, 2);
    assert.deepEqual(completeRequests.map((url) => url.searchParams.get('PageSize')), ['100', '100']);
    assert.deepEqual(completeRequests.map((url) => url.searchParams.get('Page')), ['1', '2']);
    assert.equal(complete.snapshots.length, 150);
    assert.equal(complete.inventory_complete, true);
    assert.equal(complete.inventory_truncated, false);

    let truncatedCalls = 0;
    const truncated = await pollNamecheap({
      credentials: { api_username: 'user', api_key: 'key', client_ip: '203.0.113.10', env_type: 'production' },
      fetchFn: async () => {
        truncatedCalls += 1;
        return { ok: true, status: 200, text: async () => xmlPage(truncatedCalls === 1 ? 1 : 101, 100, 201) };
      },
    });
    assert.equal(truncatedCalls, 2);
    assert.equal(truncated.snapshots.length, CONNECTOR_POLL_MAX_INVENTORY_ITEMS);
    assert.equal(truncated.inventory_complete, false);
    assert.equal(truncated.inventory_truncated, true);
    assert.equal(truncated.health, 'degraded');
  });

  it('grants GoDaddy authority only when lifecycle status is explicitly ACTIVE', async () => {
    const result = await pollGoDaddy({
      credentials: { key: 'key', secret: 'secret' },
      fetchFn: async () => ({
        ok: true,
        status: 200,
        json: async () => ([
          { domainId: '1', domain: 'active.example', status: 'ACTIVE' },
          { domainId: '2', domain: 'expired.example', status: 'EXPIRED' },
          { domainId: '3', domain: 'cancelled.example', status: 'CANCELLED' },
          { domainId: '4', domain: 'unknown.example' },
        ]),
      }),
    });
    const tags = (hostname) => result.snapshots.find((row) => row.display_ref === hostname).summary.tags;
    assert.ok(tags('active.example').includes('resource_status:active'));
    assert.ok(tags('active.example').includes('ownership_eligible:true'));
    for (const hostname of ['expired.example', 'cancelled.example', 'unknown.example']) {
      assert.ok(tags(hostname).includes('ownership_eligible:false'));
    }
    assert.ok(tags('expired.example').includes('resource_status:expired'));
    assert.ok(tags('cancelled.example').includes('resource_status:cancelled'));
    assert.ok(tags('unknown.example').includes('resource_status:unknown'));
  });

  it('polls GoDaddy and IBM NS1 only at fixed provider origins', async () => {
    const requests = [];
    const jsonResponse = (body) => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => body,
    });
    const godaddy = await pollGoDaddy({
      credentials: { key: 'key', secret: 'secret' },
      fetchFn: async (url, init) => {
        requests.push({ url: String(url), init });
        return jsonResponse([{ domain: 'one.example' }]);
      },
    });
    const ns1 = await pollIbmNs1({
      credentials: { api_key: 'ns1-key' },
      fetchFn: async (url, init) => {
        requests.push({ url: String(url), init });
        return jsonResponse([{ zone: 'two.example' }]);
      },
    });
    assert.match(requests[0].url, /^https:\/\/api\.godaddy\.com\/v1\/domains\?/);
    assert.match(requests[1].url, /^https:\/\/api\.nsone\.net\/v1\/zones\?/);
    assert.equal(requests.every((request) => request.init.redirect === 'manual'), true);
    assert.equal(godaddy.snapshots[0].display_ref, 'one.example');
    assert.equal(ns1.snapshots[0].display_ref, 'two.example');
  });

  it('parses allowlisted credential fields for each DNS provider', () => {
    assert.deepEqual(parseProviderSecret('{"host":"edge.luna.akamaiapis.net","access_token":"a","client_token":"c","client_secret":"s"}', 'akamai_edgedns'), {
      host: 'edge.luna.akamaiapis.net', access_token: 'a', client_token: 'c', client_secret: 's',
    });
    assert.deepEqual(parseProviderSecret('{"username":"u","key":"k","clientIp":"203.0.113.10","environment":"sandbox"}', 'namecheap'), {
      api_username: 'u', api_key: 'k', client_ip: '203.0.113.10', env_type: 'sandbox',
    });
    assert.deepEqual(parseProviderSecret('{"key":"k","secret":"s","ignored":"drop"}', 'godaddy'), { key: 'k', secret: 's' });
    assert.deepEqual(parseProviderSecret('plain-ns1-key', 'ibm_ns1'), { api_key: 'plain-ns1-key' });
  });

  it('retries transient provider failures and reports actual attempts made', async () => {
    let calls = 0;
    await assert.rejects(
      () => withConnectorPollRetry(async () => {
        calls += 1;
        const err = new Error('temporary provider outage');
        err.code = 'ECONNRESET';
        throw err;
      }, { maxAttempts: 3, baseBackoffMs: 1 }),
      (err) => err?.message === 'temporary provider outage' && err?.attempts === 3,
    );
    assert.equal(calls, 3);

    calls = 0;
    await assert.rejects(
      () => withConnectorPollRetry(async () => {
        calls += 1;
        const err = new Error('permanent request failure');
        err.status = 400;
        throw err;
      }, { maxAttempts: 3, baseBackoffMs: 1 }),
      (err) => err?.message === 'permanent request failure' && err?.attempts === 1,
    );
    assert.equal(calls, 1);
  });
});

describe('connector provider poll worker', () => {
  it('only attempts outbound poll for supported providers with secret_id', () => {
    const connector = {
      provider: 'cloudflare',
      secret_id: 'sec_1',
      status: 'active',
      config_json: { read_only: true },
    };
    assert.equal(shouldAttemptOutboundConnectorPoll(connector, {}), true);
    assert.equal(shouldAttemptOutboundConnectorPoll(connector, { snapshots: [{ snapshot_kind: 'waf_policy' }] }), false);
    assert.equal(shouldAttemptOutboundConnectorPoll({ ...connector, secret_id: null }, {}), false);
    assert.equal(
      shouldAttemptOutboundConnectorPoll({ ...connector, provider: 'generic_waf' }, {}),
      false,
    );
  });

  it('executes provider poll using vault-resolved credentials and prefetched metadata', async () => {
    const connector = seedConnector();
    const resolved = await executeConnectorProviderPoll({
      connector,
      ctx: demoCtx(),
      secretResolver: async () => ({ plaintext: 'cf-token' }),
      prefetchedMetadata: {
        zones: [{ id: 'zone_1', name: 'app.example.com', status: 'active', security_level: 'medium', rulesets: [] }],
      },
      now: '2026-07-02T12:00:00.000Z',
      maxAttempts: 1,
    });
    assert.equal(resolved.snapshots.length, 1);
    assert.equal(resolved.health.status, 'active');
    assert.equal(resolved.health.attempts, 1);
  });

  it('executes aws_waf provider poll worker with prefetched metadata', async () => {
    const connector = seedConnector({
      id: 'conn_aws_1',
      provider: 'aws_waf',
      secret_id: 'sec_aws_1',
      config_json: { read_only: true, scope: 'regional' },
    });
    const resolved = await executeConnectorProviderPoll({
      connector,
      ctx: demoCtx(),
      secretResolver: async () => ({
        plaintext: '{"access_key_id":"AKIATEST","secret_access_key":"secret","region":"us-east-1"}',
      }),
      prefetchedMetadata: {
        web_acls: [
          {
            ARN: 'arn:aws:wafv2:us-east-1:123:regional/webacl/demo/abc',
            Name: 'demo-webacl',
            DefaultAction: { Block: {} },
            Rules: [{ Name: 'AWSManagedRulesCommonRuleSet' }],
          },
        ],
      },
      now: '2026-07-02T12:00:00.000Z',
      maxAttempts: 1,
    });
    assert.equal(resolved.snapshots.length, 1);
    assert.equal(resolved.health.status, 'active');
    assert.equal(resolved.snapshots[0].snapshot_kind, 'waf_policy');
    assert.ok(!JSON.stringify(resolved).includes('AKIATEST'));
  });
});

describe('wafPosture pollConnector outbound slice', () => {
  it('queues a public connector poll without invoking fetch', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    const connector = seedConnector();
    let fetchCalls = 0;
    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {}, {
      fetchFn: async () => { fetchCalls += 1; throw new Error('must not fetch'); },
    });
    assert.equal(result.poll_job.status, 'pending');
    assert.equal(result.poll_job.id, `poll_${connector.id}_1`);
    assert.equal(fetchCalls, 0);
    assert.equal(connector.status, 'validating');
  });

  it('fails closed when outbound poll is requested without usable vault credentials', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    const connector = seedConnector();
    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {}, {
      executeOutbound: true,
    });
    assert.equal(result.error, 'connector_poll_failed');
    assert.equal(result.status, 503);
    assert.equal(result.health.health_code, 'encryption_not_configured');
    assert.equal(getStore().wafConnectors[0].status, 'degraded');
    assert.ok(getStore().wafConnectors[0].last_error_at);
  });

  it('revokes provider proof on authentication failure without advancing prior success', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    const connector = seedConnector();
    connector.last_success_at = '2026-07-01T12:00:00.000Z';
    seedEncryptedSecret({
      id: connector.secret_id,
      purpose: 'connector',
      name: 'cloudflare-readonly',
      plaintext: 'cf-revoked-token',
    });

    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {}, {
      executeOutbound: true,
      fetchFn: async () => new Response('{"success":false}', { status: 401 }),
      maxAttempts: 1,
    });
    assert.equal(result.error, 'connector_poll_failed');
    assert.equal(getStore().wafConnectors[0].status, 'revoked');
    assert.equal(getStore().wafConnectors[0].last_success_at, null);
  });

  it('keeps a connector disabled when an in-flight provider poll completes', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    const connector = seedConnector();
    connector.last_success_at = '2026-07-01T12:00:00.000Z';
    seedEncryptedSecret({
      id: connector.secret_id,
      purpose: 'connector',
      name: 'cloudflare-readonly',
      plaintext: 'cf-valid-token',
    });

    let releaseZones;
    let markStarted;
    const started = new Promise((resolve) => { markStarted = resolve; });
    const blocked = new Promise((resolve) => { releaseZones = resolve; });
    const poll = wafPosture.pollConnector(demoCtx(), connector.id, {}, {
      executeOutbound: true,
      maxAttempts: 1,
      fetchFn: async (url) => {
        if (url.includes('/zones?')) {
          markStarted();
          await blocked;
          return new Response(JSON.stringify({
            success: true,
            result: [{ id: 'zone_1', name: 'app.example.com', status: 'active' }],
            result_info: { page: 1, total_pages: 1 },
          }), { status: 200, headers: { 'content-type': 'application/json' } });
        }
        return new Response(JSON.stringify({ success: true, result: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });
    await started;
    wafPosture.disableConnector(demoCtx(), connector.id);
    releaseZones();
    await poll;

    assert.equal(connector.status, 'disabled');
    assert.equal(connector.last_success_at, null);
  });

  it('polls cloudflare via provider worker and stores metadata-only snapshots', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    const connector = seedConnector();
    seedEncryptedSecret({
      id: connector.secret_id,
      purpose: 'connector',
      name: 'cloudflare-readonly',
      plaintext: 'cf-live-token',
    });

    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {}, {
      executeOutbound: true,
      prefetchedMetadata: {
        zones: [
          {
            id: 'zone_1',
            name: 'app.example.com',
            status: 'active',
            security_level: 'high',
            rulesets: [{ phase: 'http_request_firewall', rules: [{ id: 'r1' }] }],
          },
        ],
      },
      maxAttempts: 1,
    });

    assert.equal(result.snapshots.length, 1);
    assert.equal(result.poll_job.status, 'completed');
    assert.equal(result.poll_job.health.status, 'active');
    assert.equal(getStore().wafConnectorSnapshots.length, 1);
    assert.ok(getStore().wafConnectorSnapshots[0].summary_json.tags.includes('resource_status:active'));
    assert.ok(getStore().wafConnectorSnapshots[0].summary_json.tags.includes('ownership_eligible:true'));
    assert.equal(getStore().wafConnectors[0].status, 'degraded');
    assert.equal(getStore().wafConnectors[0].last_success_at, null);
    assert.equal(JSON.stringify(result.snapshots).includes('cf-live-token'), false);
  });

  it('advances authoritative success for a complete real provider empty poll', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    const connector = seedConnector();
    seedEncryptedSecret({
      id: connector.secret_id,
      purpose: 'connector',
      name: 'cloudflare-readonly',
      plaintext: 'cf-live-token',
    });

    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {}, {
      executeOutbound: true,
      fetchFn: async () => new Response(JSON.stringify({
        success: true,
        result: [],
        result_info: { page: 1, total_pages: 1 },
      }), { status: 200, headers: { 'content-type': 'application/json' } }),
      maxAttempts: 1,
    });
    assert.equal(result.poll_job.status, 'completed_empty');
    assert.equal(result.poll_job.health.inventory_complete, true);
    assert.equal(getStore().wafConnectors[0].status, 'active');
    assert.ok(getStore().wafConnectors[0].last_success_at);
  });

  it('does not let stale provider success or failure overwrite a newer complete empty generation', async () => {
    for (const staleOutcome of ['success', 'failure']) {
      freshStore();
      process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
      const connector = seedConnector({
        id: `conn_godaddy_${staleOutcome}`,
        provider: 'godaddy',
        secret_id: `sec_godaddy_${staleOutcome}`,
      });
      let fetchCount = 0;
      let releaseFirst;
      const firstBlocked = new Promise((resolve) => { releaseFirst = resolve; });
      let markFirstStarted;
      const firstStarted = new Promise((resolve) => { markFirstStarted = resolve; });
      const options = {
        executeOutbound: true,
        secretResolver: async () => ({ plaintext: '{"key":"key","secret":"secret"}' }),
        maxAttempts: 1,
        fetchFn: async () => {
          fetchCount += 1;
          if (fetchCount === 1) {
            markFirstStarted();
            await firstBlocked;
            if (staleOutcome === 'failure') throw new Error('stale provider failure');
            return new Response(JSON.stringify([
              { domainId: 'stale', domain: 'stale.example', status: 'ACTIVE' },
            ]), { status: 200, headers: { 'content-type': 'application/json' } });
          }
          return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } });
        },
      };

      const stalePoll = wafPosture.pollConnector(demoCtx(), connector.id, {}, options);
      await firstStarted;
      const currentPoll = await wafPosture.pollConnector(demoCtx(), connector.id, {}, options);
      releaseFirst();
      const staleResult = await stalePoll;

      assert.equal(currentPoll.poll_job.status, 'completed_empty');
      assert.equal(staleResult.error, 'connector_poll_superseded');
      assert.equal(connector.poll_revision, 2);
      assert.equal(connector.last_success_revision, 2);
      assert.equal(connector.status, 'active');
      assert.equal(getStore().wafConnectorSnapshots.length, 0);
    }
  });

  it('keeps manual metadata poll working when snapshots are supplied', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    const connector = seedConnector({ secret_id: 'sec_cf_1' });
    connector.last_success_at = '2026-07-01T12:00:00.000Z';
    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {
      snapshots: [
        {
          snapshot_kind: 'waf_policy',
          resource_ref_hash: 'res_manual_1',
          display_ref: 'manual-zone',
          config_hash: 'cfg_manual_1',
          summary: { hostnames: ['manual.example.com'], policy_mode: 'block', rule_count: 4 },
        },
      ],
    });
    assert.equal(result.error, undefined);
    assert.equal(result.snapshots.length, 1);
    assert.equal(result.snapshots[0].summary.rule_count, 4);
    assert.equal(getStore().wafConnectorSnapshots.length, 1);
    assert.equal(getStore().wafConnectors[0].last_success_at, '2026-07-01T12:00:00.000Z');
  });

  it('validate exposes outbound_polling when secret_id is configured', () => {
    freshStore();
    const connector = seedConnector();
    const validated = wafPosture.validateConnector(demoCtx(), connector.id);
    assert.equal(validated.status, 'active');
    assert.equal(validated.capabilities.outbound_polling, true);
  });

  it('does not reactivate a disabled connector through local validation', () => {
    freshStore();
    const connector = seedConnector({ status: 'disabled' });
    const validated = wafPosture.validateConnector(demoCtx(), connector.id);
    assert.deepEqual(validated, { error: 'connector_disabled', status: 409 });
    assert.equal(connector.status, 'disabled');
  });
});


describe('DNS provider response bounds', () => {
  const akamaiCredentials = {
    host: 'example.luna.akamaiapis.net',
    access_token: 'access',
    client_token: 'client',
    client_secret: 'secret',
  };

  it('keeps the timeout active while consuming a provider response body', async () => {
    await assert.rejects(
      () => pollAkamaiEdgeDns({
        credentials: akamaiCredentials,
        fetchTimeoutMs: 5,
        fetchFn: async () => ({
          ok: true,
          status: 200,
          headers: { get: () => null },
          text: async () => new Promise(() => {}),
        }),
      }),
      (error) => error?.code === 'provider_poll_failed' && /timeout/i.test(error.message),
    );
  });

  it('aborts and cancels a streamed Response as soon as cumulative bytes exceed the cap', async () => {
    let cancelled = false;
    let requestSignal;
    const chunk = new Uint8Array(Math.floor(DOMAIN_INVENTORY_RESPONSE_MAX_BYTES / 2) + 1);
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(chunk);
        controller.enqueue(chunk);
        controller.enqueue(new Uint8Array([123, 125]));
      },
      cancel() {
        cancelled = true;
      },
    });

    await assert.rejects(
      () => pollAkamaiEdgeDns({
        credentials: akamaiCredentials,
        fetchFn: async (_url, init) => {
          requestSignal = init.signal;
          return new Response(body, { status: 200 });
        },
      }),
      (error) => error?.code === 'provider_response_too_large',
    );

    assert.equal(requestSignal.aborted, true);
    assert.equal(cancelled, true);
  });

  it('rejects DNS provider response bodies above the byte cap', async () => {
    const oversized = JSON.stringify({ zones: [], padding: 'x'.repeat(DOMAIN_INVENTORY_RESPONSE_MAX_BYTES) });
    await assert.rejects(
      () => pollAkamaiEdgeDns({
        credentials: akamaiCredentials,
        fetchFn: async () => new Response(oversized, { status: 200 }),
      }),
      (error) => error?.code === 'provider_response_too_large' && /byte limit/i.test(error.message),
    );
  });
});
