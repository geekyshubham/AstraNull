
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  akamaiApplicationSecurityProvider,
  pollAkamaiApplicationSecurity,
} from '../../src/lib/connectorProviders/akamaiAppSec.mjs';
import { CONNECTOR_POLL_MAX_INVENTORY_ITEMS } from '../../src/lib/connectorProviders/common.mjs';

const CREDENTIALS = {
  host: 'example.luna.akamaiapis.net',
  access_token: 'access',
  client_token: 'client',
  client_secret: 'secret',
};

function jsonResponse(body) {
  return { ok: true, status: 200, json: async () => body };
}

describe('Akamai Application Security poller', () => {
  it('resolves match targets against the active production version and derives block/monitor mode from attack-group actions', async () => {
    const requestedUrls = [];
    const result = await pollAkamaiApplicationSecurity({
      credentials: CREDENTIALS,
      observedAt: '2026-09-30T00:00:00.000Z',
      now: new Date('2026-09-30T00:00:00.000Z'),
      nonce: 'nonce-1',
      fetchFn: async (url) => {
        const path = String(url);
        requestedUrls.push(path);
        if (path.endsWith('/appsec/v1/configs')) {
          return jsonResponse({
            configurations: [
              { id: 111, name: 'prod-app-config', latestVersion: 9, stagingVersion: 8, productionVersion: 7 },
            ],
          });
        }
        if (path.endsWith('/versions/7/security-policies')) {
          return jsonResponse({ policies: [{ policyId: 'pol1', policyName: 'Prod Policy' }] });
        }
        if (path.endsWith('/security-policies/pol1/attack-groups')) {
          return jsonResponse({ attackGroupActions: [{ group: 'SQL', action: 'deny' }, { group: 'XSS', action: 'alert' }] });
        }
        if (path.endsWith('/versions/7/match-targets')) {
          return jsonResponse({
            matchTargets: {
              websiteTargets: [
                {
                  targetId: 555,
                  type: 'website',
                  hostnames: ['app.example.com'],
                  securityPolicy: { policyId: 'pol1' },
                  sequence: 1,
                },
              ],
            },
          });
        }
        throw new Error(`unexpected request: ${path}`);
      },
    });
    assert.ok(requestedUrls.some((u) => u.endsWith('/versions/7/match-targets')));
    // Never queries the unreleased latest (9) or unactivated staging (8) version.
    assert.ok(!requestedUrls.some((u) => u.includes('/versions/9/')));
    assert.ok(!requestedUrls.some((u) => u.includes('/versions/8/')));
    assert.equal(result.snapshots.length, 1);
    const snapshot = result.snapshots[0];
    assert.equal(snapshot.snapshot_kind, 'waf_policy');
    assert.deepEqual(snapshot.summary.hostnames, ['app.example.com']);
    assert.equal(snapshot.summary.policy_mode, 'block');
    assert.equal(snapshot.summary.match_target_order, 1);
    assert.equal(result.health, 'active');
    assert.equal(JSON.stringify(result).includes('secret'), false);
  });

  it('derives monitor mode when every attack group only alerts, and disabled when every action is none', async () => {
    async function pollWithActions(actions) {
      return pollAkamaiApplicationSecurity({
        credentials: CREDENTIALS,
        observedAt: '2026-09-30T00:00:00.000Z',
        now: new Date('2026-09-30T00:00:00.000Z'),
        fetchFn: async (url) => {
          const path = String(url);
          if (path.endsWith('/appsec/v1/configs')) {
            return jsonResponse({ configurations: [{ id: 1, productionVersion: 1 }] });
          }
          if (path.endsWith('/security-policies')) {
            return jsonResponse({ policies: [{ policyId: 'p1' }] });
          }
          if (path.endsWith('/attack-groups')) {
            return jsonResponse({ attackGroupActions: actions });
          }
          if (path.endsWith('/match-targets')) {
            return jsonResponse({ matchTargets: [{ targetId: 1, hostnames: ['a.example.com'], securityPolicy: { policyId: 'p1' } }] });
          }
          throw new Error(`unexpected: ${path}`);
        },
      });
    }
    const monitorOnly = await pollWithActions([{ action: 'alert' }, { action: 'alert' }]);
    assert.equal(monitorOnly.snapshots[0].summary.policy_mode, 'monitor');

    const disabled = await pollWithActions([{ action: 'none' }, { action: 'none' }]);
    assert.equal(disabled.snapshots[0].summary.policy_mode, 'disabled');
  });

  it('skips a configuration with no active production version and reports the gap', async () => {
    const result = await pollAkamaiApplicationSecurity({
      credentials: CREDENTIALS,
      observedAt: '2026-09-30T00:00:00.000Z',
      now: new Date('2026-09-30T00:00:00.000Z'),
      fetchFn: async (url) => {
        const path = String(url);
        if (path.endsWith('/appsec/v1/configs')) {
          // latestVersion exists but was never activated to production.
          return jsonResponse({ configurations: [{ id: 1, latestVersion: 3, productionVersion: null }] });
        }
        throw new Error(`unexpected request for unactivated config: ${path}`);
      },
    });
    assert.equal(result.snapshots.length, 0);
    assert.equal(result.health, 'degraded');
    assert.ok(result.permission_gaps.includes('no_active_production_version'));
  });

  it('degrades health and reports a permission gap when match-target fetch fails', async () => {
    const result = await pollAkamaiApplicationSecurity({
      credentials: CREDENTIALS,
      observedAt: '2026-09-30T00:00:00.000Z',
      now: new Date('2026-09-30T00:00:00.000Z'),
      fetchFn: async (url) => {
        const path = String(url);
        if (path.endsWith('/appsec/v1/configs')) {
          return jsonResponse({ configurations: [{ id: 1, productionVersion: 1 }] });
        }
        if (path.endsWith('/security-policies')) {
          return jsonResponse({ policies: [] });
        }
        if (path.endsWith('/match-targets')) {
          return { ok: false, status: 403, json: async () => ({ detail: 'forbidden' }) };
        }
        throw new Error(`unexpected: ${path}`);
      },
    });
    assert.equal(result.snapshots.length, 0);
    assert.equal(result.health, 'degraded');
    assert.ok(result.permission_gaps.includes('permission_insufficient'));
  });

  it('bounds total match-target snapshots at CONNECTOR_POLL_MAX_INVENTORY_ITEMS', async () => {
    const manyTargets = Array.from({ length: CONNECTOR_POLL_MAX_INVENTORY_ITEMS + 25 }, (_v, i) => ({
      targetId: i,
      hostnames: [`host${i}.example.com`],
      securityPolicy: { policyId: 'p1' },
      sequence: i,
    }));
    const result = await pollAkamaiApplicationSecurity({
      credentials: CREDENTIALS,
      observedAt: '2026-09-30T00:00:00.000Z',
      now: new Date('2026-09-30T00:00:00.000Z'),
      fetchFn: async (url) => {
        const path = String(url);
        if (path.endsWith('/appsec/v1/configs')) {
          return jsonResponse({ configurations: [{ id: 1, productionVersion: 1 }] });
        }
        if (path.endsWith('/security-policies')) {
          return jsonResponse({ policies: [{ policyId: 'p1' }] });
        }
        if (path.endsWith('/attack-groups')) {
          return jsonResponse({ attackGroupActions: [{ action: 'deny' }] });
        }
        if (path.endsWith('/match-targets')) {
          return jsonResponse({ matchTargets: manyTargets });
        }
        throw new Error(`unexpected: ${path}`);
      },
    });
    assert.equal(result.snapshots.length, CONNECTOR_POLL_MAX_INVENTORY_ITEMS);
    assert.equal(result.inventory_truncated, true);
    assert.ok(result.permission_gaps.includes('truncated_inventory'));
  });

  it('exposes provider metadata for the connector registry', () => {
    assert.equal(akamaiApplicationSecurityProvider.provider, 'akamai_appsec');
    assert.deepEqual(akamaiApplicationSecurityProvider.snapshot_kinds, ['waf_policy']);
    assert.equal(typeof akamaiApplicationSecurityProvider.poll, 'function');
  });

  it('requires all EdgeGrid credential fields', async () => {
    await assert.rejects(
      () => pollAkamaiApplicationSecurity({ credentials: { host: CREDENTIALS.host } }),
      /credentials are missing/,
    );
  });
});
