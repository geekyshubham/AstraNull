import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { seedPortalBaseline, PORTAL_BASELINE_IDS as IDS } from '../fixtures/portal-baseline/seed.mjs';

let baseUrl;
let server;

const owner = () => demoHeaders('owner', IDS.tenantId, 'usr_owner');
const otherTenant = () => demoHeaders('owner', IDS.tenantBId, 'usr_owner_b');

function addFinding(id, checkId, summary) {
  getStore().findings.push({
    id, tenant_id: IDS.tenantId, target_group_id: IDS.targetGroupId, target_id: IDS.targetId,
    check_id: checkId, title: `Finding: exposed on ${IDS.targetId}`, severity: 'high', status: 'open',
    system_summary: summary, evidence_ids: [], created_at: IDS.frozenAt, updated_at: IDS.frozenAt,
  });
}

before(async () => {
  seedPortalBaseline();
  server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0 }, resolve);
  });
  assert.equal(server.address().family, 'IPv4');
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

beforeEach(() => {
  seedPortalBaseline();
});

describe('missing control on findings and checks', () => {
  it('names the missing firewall control with the detected cloud provider first', async () => {
    addFinding('fnd_mc_nfw', 'nfw.management_port_exposure.safe',
      'Declared deny for tcp/3389 (ipv4) from external probe was violated; denial cannot be proven from outside.');
    getStore().targetEdgeDetections = [{
      id: 'ted_mc', tenant_id: IDS.tenantId, target_id: IDS.targetId, status: 'detected',
      waf_status: 'not_detected', cdn_status: 'not_detected',
      evidence_json: { cloud: { status: 'detected', provider: 'gcp', type: 'asn' }, cloud_providers: ['gcp'] },
      observed_at: IDS.frozenAt, updated_at: IDS.frozenAt,
    }];
    const res = await request(baseUrl, 'GET', '/v1/findings/fnd_mc_nfw', { headers: owner() });
    assert.equal(res.status, 200);
    const control = res.json.missing_control;
    assert.equal(control.status, 'missing');
    assert.equal(control.control_family, 'network_firewall_ingress');
    assert.equal(control.headline, 'Missing control: Network firewall ingress rules');
    assert.match(control.observed, /tcp\/3389/);
    assert.equal(control.provider_guidance[0].provider, 'gcp');
    assert.equal(control.provider_guidance[0].source, 'detected_edge');
    assert.equal(control.provider_guidance.at(-1).provider, 'generic');
    assert.equal(control.attribution, 'unattributed');
    assert.equal(res.json.title, `Finding: exposed on ${IDS.targetId}`, 'stored title stays stable for grouping');
  });

  it('falls back to vendor-neutral guidance when no provider was detected', async () => {
    addFinding('fnd_mc_waf', 'waf.sqli_managed_marker.safe', 'Managed-rule marker for SQL injection was not enforced: the edge let it through to the origin.');
    getStore().targetEdgeDetections = [];
    const res = await request(baseUrl, 'GET', '/v1/findings/fnd_mc_waf', { headers: owner() });
    assert.equal(res.status, 200);
    assert.equal(res.json.missing_control.control_family, 'waf_managed_rules');
    assert.deepEqual(res.json.missing_control.provider_guidance.map((row) => row.provider), ['generic']);
    assert.ok(res.json.missing_control.other_provider_guidance.length >= 5);
  });

  it('does not reveal another tenant finding', async () => {
    addFinding('fnd_mc_private', 'waf.sqli_managed_marker.safe', 'x');
    const res = await request(baseUrl, 'GET', '/v1/findings/fnd_mc_private', { headers: otherTenant() });
    assert.equal(res.status, 404);
    assert.equal(res.json.missing_control, undefined);
  });

  it('attaches the static missing control to every check in the catalog API', async () => {
    const list = await request(baseUrl, 'GET', '/v1/checks?scope=all', { headers: owner() });
    assert.equal(list.status, 200);
    assert.ok(list.json.items.length > 0);
    for (const item of list.json.items) {
      assert.ok(item.missing_control?.missing_control, `${item.check_id} missing_control`);
      assert.ok(item.missing_control.required_policy);
      assert.equal(item.missing_control.provider_guidance, undefined, 'catalog stays provider-neutral');
    }
    const one = await request(baseUrl, 'GET', '/v1/checks/waf.sqli_managed_marker.safe', { headers: owner() });
    assert.equal(one.status, 200);
    assert.equal(one.json.check.missing_control.control_family, 'waf_managed_rules');
  });
});
