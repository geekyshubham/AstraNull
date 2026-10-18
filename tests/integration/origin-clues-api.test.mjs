import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { createOriginClueService } from '../../src/services/originClues.mjs';
import { createDevOriginClueRepository } from '../../src/services/originClueRepository.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { request, demoHeaders, closeServer } from '../helpers/http.mjs';

let collected = 0;
const services = { originClues: createOriginClueService({ repository: createDevOriginClueRepository(), collectDns: async (hosts, includeMail) => {
  collected += 1;
  return { records: [{ candidate_ip: '8.8.8.8', associated_hostname: hosts[0], source_kind: 'dns_a', source_ref: `dns:${hosts[0]}:A`, source_observed_at: new Date().toISOString() }],
    sources: [{ hostname: hosts[0], type: 'A', status: 'observed' }], query_count: includeMail ? 5 : 3 };
} }) };
async function start(optIn) {
  const server = createServer({ env: { ...process.env, NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers', ASTRANULL_ORIGIN_CLUES_ENABLED_TENANTS: optIn ? '{"ten_demo":true}' : '' }, services });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` };
}
let enabled; let disabled;
before(async () => { enabled = await start(true); disabled = await start(false); });
after(async () => { await closeServer(enabled.server); await closeServer(disabled.server); });
beforeEach(() => { freshStore(); collected = 0; });
const input = { source_kind: 'historical_dns', source_ref: 'supplied:archive', records: [{ candidate_ip: '8.8.8.8', associated_hostname: 'origin.test' }] };
const headers = (key = 'reviewed-operation-1', role = 'admin') => ({ ...demoHeaders(role), 'Idempotency-Key': key });
const path = '/v1/targets/tgt_1/origin-clues';

test('tenant deployment features expose exact opt-in without enabling demo or foreign tenants', async () => {
  for (const [runtime, expected] of [[enabled, true], [disabled, false]]) {
    const result = await request(runtime.baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: headers() });
    assert.equal(result.status, 200);
    assert.equal(result.json.origin_clues, expected);
  }
  const foreign = await request(enabled.baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: { ...headers(), 'x-tenant-id': 'ten_other' } });
  assert.equal(foreign.status, 200);
  assert.equal(foreign.json.origin_clues, false);
  assert.equal(collected, 0);
});

test('all routes disabled without explicit tenant opt-in and never collect', async () => {
  for (const [method, endpoint, body] of [['GET', path], ['POST', `${path}/import`, input], ['POST', `${path}/collect`, {}]]) {
    const result = await request(disabled.baseUrl, method, endpoint, { headers: headers(), body });
    assert.equal(result.status, 404); assert.equal(result.json.error, 'origin_clues_feature_disabled');
  }
  assert.equal(collected, 0); assert.equal(getStore().originClues?.length ?? 0, 0);
});

test('persisted list is viewer-readable and never invokes source collection', async () => {
  const empty = await request(enabled.baseUrl, 'GET', path, { headers: headers('x', 'viewer') });
  assert.equal(empty.status, 200); assert.deepEqual(empty.json.items, []); assert.equal(empty.json.coverage.partial, true);
  assert.match(empty.json.label, /not verified/); assert.equal(collected, 0);
  const imported = await request(enabled.baseUrl, 'POST', `${path}/import`, { headers: headers(), body: input });
  assert.equal(imported.status, 200); assert.equal(imported.json.created, 1);
  const listed = await request(enabled.baseUrl, 'GET', `${path}?limit=1`, { headers: headers('x', 'viewer') });
  assert.equal(listed.json.items[0].candidate_ip, '8.8.8.8'); assert.equal(collected, 0);
  assert.equal(getStore().targets.length, 1); assert.equal(getStore().probeJobs.length, 0); assert.equal(getStore().testRuns.length, 0);
});

test('writes require existing target write RBAC and idempotency header', async () => {
  const denied = await request(enabled.baseUrl, 'POST', `${path}/collect`, { headers: headers('x', 'viewer'), body: {} });
  assert.equal(denied.status, 403); assert.equal(collected, 0);
  const missingKey = await request(enabled.baseUrl, 'POST', `${path}/collect`, { headers: demoHeaders(), body: {} });
  assert.equal(missingKey.status, 400); assert.equal(missingKey.json.error, 'origin_clue_idempotency_key_required');
  const missingTarget = await request(enabled.baseUrl, 'POST', '/v1/targets/no-such-target/origin-clues/collect', { headers: headers(), body: {} });
  assert.equal(missingTarget.status, 404); assert.equal(collected, 0);
});

test('reviewed collection replays without DNS or new audit and never creates binding/probe/target', async () => {
  const store = getStore(); const before = structuredClone({ targets: store.targets, bindings: store.originBindings, jobs: store.probeJobs, runs: store.testRuns });
  const first = await request(enabled.baseUrl, 'POST', `${path}/collect`, { headers: headers(), body: { include_mail: true } });
  assert.equal(first.status, 200); assert.equal(first.json.coverage.query_count, 5); assert.equal(collected, 1);
  const replay = await request(enabled.baseUrl, 'POST', `${path}/collect`, { headers: headers(), body: { include_mail: true } });
  assert.deepEqual(replay.json, first.json); assert.equal(collected, 1);
  const conflict = await request(enabled.baseUrl, 'POST', `${path}/collect`, { headers: headers(), body: { include_mail: false } });
  assert.equal(conflict.status, 409); assert.equal(collected, 1);
  assert.equal(store.auditLog.filter((row) => row.action === 'target.origin_clues_recorded').length, 1);
  assert.deepEqual({ targets: store.targets, bindings: store.originBindings, jobs: store.probeJobs, runs: store.testRuns }, before);
});

test('current-tenant erasure previews, confirms and audits even when optional collection is disabled', async () => {
  await request(enabled.baseUrl, 'POST', `${path}/import`, { headers: headers(), body: input });
  const endpoint = '/v1/tenants/current/origin-clues/erase';
  const body = { confirmation_tenant_id: 'ten_demo', reason: 'Reviewed customer erasure request', dry_run: true };
  const audits = getStore().auditLog.length;
  const preview = await request(disabled.baseUrl, 'POST', endpoint, { headers: headers(), body });
  assert.equal(preview.status, 200); assert.equal(preview.json.would_delete.originClues, 1);
  assert.equal(preview.json.audit_entry_id, null); assert.equal(getStore().auditLog.length, audits);
  const denied = await request(enabled.baseUrl, 'POST', endpoint, { headers: headers('x', 'engineer'), body });
  assert.equal(denied.status, 403);
  const invalid = await request(enabled.baseUrl, 'POST', endpoint, { headers: headers(), body: { ...body, confirmation_tenant_id: 'ten_other' } });
  assert.equal(invalid.status, 400);
  const erased = await request(disabled.baseUrl, 'POST', endpoint, { headers: headers(), body: { ...body, dry_run: false } });
  assert.equal(erased.status, 200); assert.equal(erased.json.deleted.originClues, 1);
  assert.ok(erased.json.audit_entry_id); assert.equal(getStore().originClueBatches.length, 0);
  assert.equal(collected, 0);
});

test('held current-tenant erasure returns 409 plus blocked counts and audit id, preview remains non-destructive', async () => {
  await request(enabled.baseUrl, 'POST', `${path}/import`, { headers: headers(), body: input });
  getStore().tenants[0].privacy_settings = { evidence_retention: { legal_hold: true } };
  const endpoint = '/v1/tenants/current/origin-clues/erase';
  const body = { confirmation_tenant_id: 'ten_demo', reason: 'Reviewed customer erasure request', dry_run: false };
  const result = await request(enabled.baseUrl, 'POST', endpoint, { headers: headers(), body });
  assert.equal(result.status, 409); assert.equal(result.json.error, 'origin_clue_erasure_legal_hold');
  assert.equal(result.json.blocked_deletions.originClues, 1); assert.ok(result.json.audit_entry_id);
  assert.equal(getStore().originClues.length, 1); assert.equal(collected, 0);
});

test('malformed/URL imports, oversized bodies, invalid cursors and unsupported methods fail closed', async () => {
  const url = await request(enabled.baseUrl, 'POST', `${path}/import`, { headers: headers(), body: { source_kind: 'historical_dns', source_ref: 'not-fetched', url: 'https://no-request.test/data' } });
  assert.equal(url.status, 400);
  const oversized = await request(enabled.baseUrl, 'POST', `${path}/import`, { headers: headers(), body: { ...input, source_ref: 'x'.repeat(128 * 1024) } });
  assert.equal(oversized.status, 413);
  // A body between the 64 KiB global default and the documented 128 KiB origin-clue limit must clear the transport cap and reach validation (400), not be truncated as 413.
  const withinImportLimit = await request(enabled.baseUrl, 'POST', `${path}/import`, { headers: headers(), body: { ...input, source_ref: 'x'.repeat(90 * 1024) } });
  assert.equal(withinImportLimit.status, 400);
  const invalid = await request(enabled.baseUrl, 'GET', `${path}?cursor=invalid`, { headers: headers() });
  assert.equal(invalid.status, 400);
  const method = await request(enabled.baseUrl, 'GET', `${path}/collect`, { headers: headers() });
  assert.equal(method.status, 405); assert.equal(collected, 0);
});
