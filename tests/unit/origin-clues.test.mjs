import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { verifyAuditChain } from '../../src/audit.mjs';
import {
  canonicalOriginIp, certificateMatchesHostname, normalizeOriginClue, originCluePage, originCluesEnabledFor,
  parseOriginClueImport, ORIGIN_CLUE_MAX_BYTES,
} from '../../src/lib/originClues.mjs';
import { collectDeclaredOriginDns, createOriginClueService } from '../../src/services/originClues.mjs';
import { createDevOriginClueRepository } from '../../src/services/originClueRepository.mjs';

const now = new Date('2026-10-16T12:00:00.000Z');
const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const enabled = { featureFlags: { originCluesEnabledTenants: { ten_demo: true, ten_other: true } } };
const options = (key = 'key-1', runtimeConfig = enabled) => ({ runtimeConfig, idempotencyKey: key });
const record = (extra = {}) => ({ candidate_ip: '8.8.8.8', associated_hostname: 'origin.test', ...extra });
const body = (records = [record()], extra = {}) => ({ source_kind: 'historical_dns', source_ref: 'supplied:history-1', records, ...extra });
function service(extra = {}) { return createOriginClueService({ repository: createDevOriginClueRepository(), now: () => now, ...extra }); }
function parse(input) { return parseOriginClueImport(input, 'origin.test', now); }
const errorCode = (code) => (error) => error.code === code;
beforeEach(() => freshStore());

test('tenant opt-in is disabled by default, named and independent of discovery/global flags', () => {
  const env = { NODE_ENV: 'test', ASTRANULL_AUTH_MODE: 'dev-headers' };
  assert.equal(originCluesEnabledFor(loadRuntimeConfig(env), 'ten_demo'), false);
  const config = loadRuntimeConfig({ ...env, ASTRANULL_ORIGIN_CLUES_ENABLED_TENANTS: '{"ten_demo":true,"ten_other":false}' });
  assert.equal(originCluesEnabledFor(config, 'ten_demo'), true);
  assert.equal(originCluesEnabledFor(config, 'ten_other'), false);
  assert.equal(originCluesEnabledFor({ featureFlags: { externalDiscoveryEnabled: true, originCluesEnabled: true } }, 'ten_demo'), false);
  assert.throws(() => loadRuntimeConfig({ ...env, ASTRANULL_ORIGIN_CLUES_ENABLED_TENANTS: 'true' }), /JSON object/);
});

test('canonical IPv4/IPv6 and known edge do not establish current origin identity', () => {
  assert.equal(canonicalOriginIp('2606:4700:4700:0000:0000:0000:0000:1111'), '2606:4700:4700::1111');
  assert.equal(canonicalOriginIp('8.8.8.8'), '8.8.8.8');
  for (const ip of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '::ffff:7f00:1', 'fe80::1%en0', '8.8.8.8/24', '1.2.3.004']) assert.throws(() => canonicalOriginIp(ip));
  const clue = parse(body([record({ candidate_ip: '104.16.0.1' })])).clues[0];
  assert.equal(clue.edge_classification, 'known_edge');
  assert.equal(clue.state, 'possible_origin_association');
  assert.equal(clue.source_observed_at, null);
  assert.match(clue.limitations.join(' '), /unknown.*retrieval time is not/);
});

test('scope uses exact DNS labels and strict single-label certificate wildcard semantics', () => {
  for (const host of ['evilorigin.test', 'origin.test.attacker.test', '*.origin.test', 'origin.test/path', 'ops@origin.test']) assert.throws(() => parse(body([record({ associated_hostname: host })])));
  assert.equal(parse(body([record({ associated_hostname: 'API.ORIGIN.TEST.' })])).clues[0].associated_hostname, 'api.origin.test');
  assert.equal(certificateMatchesHostname('*.origin.test', 'api.origin.test'), true);
  assert.equal(certificateMatchesHostname('*.origin.test', 'origin.test'), false);
  assert.equal(certificateMatchesHostname('*.origin.test', 'deep.api.origin.test'), false);
  const cert = (names, hostname = 'origin.test') => body([record({ certificate_names: names, associated_hostname: hostname })], { source_kind: 'certificate_host' });
  assert.throws(() => parse(cert(['*.origin.test'])), errorCode('origin_clue_certificate_name_mismatch'));
  assert.throws(() => parse(cert([])), errorCode('origin_clue_certificate_names_required'));
  assert.throws(() => parse(cert(['a*.origin.test'])), errorCode('invalid_origin_clue_hostname'));
  assert.equal(parse(cert(['*.origin.test'], 'api.origin.test')).clues.length, 1);
});

test('bounded imports reject malformed, oversized, future and unknown fields atomically', () => {
  assert.throws(() => parse(body(Array.from({ length: 201 }, () => record()))), errorCode('origin_clue_row_limit'));
  assert.throws(() => parse(body([], { source_ref: 'x'.repeat(ORIGIN_CLUE_MAX_BYTES) })), errorCode('origin_clue_import_too_large'));
  assert.throws(() => parse(body([record({ source_observed_at: '2026-10-17T00:00:00Z' })])), errorCode('invalid_origin_clue_observed_at'));
  assert.throws(() => parse(body([record({ source_observed_at: '2026-10-15' })])), errorCode('invalid_origin_clue_observed_at'));
  assert.throws(() => parse(body([record({ source_observed_at: '2026-02-30T00:00:00Z' })])), errorCode('invalid_origin_clue_observed_at'));
  assert.throws(() => parse(body([record({ url: 'https://never-fetch.test/' })])), errorCode('unknown_origin_clue_field'));
  const stale = parse(body([record({ source_observed_at: '2020-01-01T00:00:00Z' })])).clues[0];
  assert.equal(stale.source_observed_at, '2020-01-01T00:00:00.000Z');
  assert.match(stale.limitations.join(' '), /stale/);
});

test('documented Trickest CSV columns preserve quoted commas, unknown source time and skip unrelated certificates', () => {
  const input = { source_kind: 'trickest_csv', source_ref: 'supplied:trickest/cloud:file', csv:
    'IP Address,Common Name,Organization,Country,Locality,Province,Subject Alternative DNS Name,Subject Alternative IP address,Self-signed\r\n'
    + '8.8.8.8,origin.test,"Example, Inc.",US,City,State,"origin.test,*.origin.test",8.8.8.8,false\r\n'
    + '1.1.1.1,other.test,Other,US,City,State,other.test,1.1.1.1,false\r\n' };
  const parsed = parse(input);
  assert.equal(parsed.clues.length, 1);
  assert.equal(parsed.skipped, 1);
  assert.deepEqual(parsed.clues[0].certificate_names, ['*.origin.test', 'origin.test']);
  assert.equal(parsed.clues[0].source_observed_at, null);
  assert.throws(() => parse({ ...input, csv: 'ip,domain\n8.8.8.8,origin.test' }), errorCode('invalid_trickest_csv_headers'));
  assert.throws(() => parse({ ...input, csv: 'IP Address,Common Name\n8.8.8.8,"origin.test' }), errorCode('invalid_origin_clue_csv'));
});

test('shared service guards RBAC, tenant ownership, domain kind, deletion and group archive', async () => {
  const s = service();
  assert.equal((await s.list(ctx, 'tgt_1', {}, { runtimeConfig: {} })).error, 'origin_clues_feature_disabled');
  assert.equal((await s.import({ ...ctx, role: 'viewer' }, 'tgt_1', body(), options())).status, 403);
  assert.equal((await s.list({ ...ctx, tenantId: 'ten_other' }, 'tgt_1', {}, options())).status, 404);
  getStore().targets[0].kind = 'ip';
  assert.equal((await s.import(ctx, 'tgt_1', body(), options())).error, 'origin_clues_requires_domain');
  getStore().targets[0].kind = 'fqdn'; getStore().targets[0].deleted_at = now.toISOString();
  assert.equal((await s.list(ctx, 'tgt_1', {}, options())).status, 404);
  delete getStore().targets[0].deleted_at; getStore().targetGroups[0].archived_at = now.toISOString();
  assert.equal((await s.list(ctx, 'tgt_1', {}, options())).status, 404);
});

test('append-only provenance, canonical dedup, idempotency replay/conflict and audit never create execution scope', async () => {
  const s = service(); const store = getStore();
  const unchanged = structuredClone({ targets: store.targets, bindings: store.originBindings, jobs: store.probeJobs, runs: store.testRuns });
  const first = await s.import(ctx, 'tgt_1', body([record(), record()]), options());
  assert.equal(first.created, 1); assert.equal(first.deduplicated, 1);
  assert.equal(first.items.length, 1); assert.equal(first.items[0].tenant_id, undefined);
  assert.deepEqual(await s.import(ctx, 'tgt_1', body([record(), record()]), options()), first);
  assert.equal((await s.import(ctx, 'tgt_1', body([record({ candidate_ip: '1.1.1.1' })]), options())).status, 409);
  const second = await s.import(ctx, 'tgt_1', body(), options('key-2'));
  assert.equal(second.created, 0); assert.equal(second.deduplicated, 1);
  const independent = await s.import(ctx, 'tgt_1', body([record()], { source_ref: 'supplied:other-feed' }), options('key-3'));
  assert.equal(independent.created, 1);
  assert.equal(store.originClues.length, 2); assert.equal(store.originClueBatches.length, 3);
  assert.equal(store.auditLog.filter((row) => row.action === 'target.origin_clues_recorded').length, 3);
  assert.equal(verifyAuditChain(store.auditLog).valid, true);
  assert.deepEqual({ targets: store.targets, bindings: store.originBindings, jobs: store.probeJobs, runs: store.testRuns }, unchanged);
  const beforeAudit = store.auditLog.length;
  const listed = await s.list({ ...ctx, role: 'viewer' }, 'tgt_1', {}, options());
  assert.equal(listed.items.length, 2); assert.equal(listed.coverage.partial, true);
  assert.equal(store.auditLog.length, beforeAudit, 'GET does not append collection/audit or fetch');
});

test('bounded deterministic paging has no missing/duplicate same-time rows and cursor is target-bound', async () => {
  const s = service();
  await s.import(ctx, 'tgt_1', body([record(), record({ candidate_ip: '1.1.1.1' }), record({ candidate_ip: '9.9.9.9' })]), options());
  const ids = []; let cursor;
  do {
    const page = await s.list(ctx, 'tgt_1', { limit: 1, cursor }, options());
    assert.equal(page.items.length, 1); ids.push(page.items[0].id); cursor = page.next_cursor;
  } while (cursor);
  assert.equal(new Set(ids).size, 3);
  assert.throws(() => originCluePage({ limit: 101 }, 'tgt_1'), errorCode('invalid_limit'));
  assert.throws(() => originCluePage({ cursor: 'bad' }, 'tgt_1'), errorCode('invalid_cursor'));
  const first = await s.list(ctx, 'tgt_1', { limit: 1 }, options());
  assert.throws(() => originCluePage({ cursor: first.next_cursor }, 'other_target'), errorCode('invalid_cursor'));
});

test('declared-target DNS questions never resolve CNAME/MX/SPF references or enumerate names', async () => {
  const calls = []; let cancelled = 0;
  const resolver = Object.fromEntries(['resolve4', 'resolve6', 'resolveCname', 'resolveMx', 'resolveTxt'].map((method) => [method, async (host) => {
    calls.push([method, host]);
    return { resolve4: ['8.8.8.8'], resolve6: ['2606:4700::1111'], resolveCname: ['third-party.test'], resolveMx: [{ exchange: 'mail.third-party.test' }], resolveTxt: [['v=spf1 include:external.test ip4:8.0.0.0/8 -all'], ['verification-token=do-not-store']] }[method];
  }]));
  resolver.cancel = () => { cancelled += 1; };
  const result = await collectDeclaredOriginDns(['origin.test'], true, { resolver });
  assert.equal(result.query_count, 5); assert.equal(calls.length, 5); assert.ok(calls.every(([, host]) => host === 'origin.test'));
  assert.equal(result.records.length, 5); assert.equal(cancelled, 1);
  assert.equal(result.records.find((row) => row.source_kind === 'dns_mx').candidate_ip, null);
  assert.equal(result.records.find((row) => row.source_kind === 'dns_txt').reference, 'v=spf1 include:external.test ip4:8.0.0.0/8 -all');
  assert.ok(!JSON.stringify(result).includes('verification-token'));
  // Retrieval time is not an IP observation time; leaving it null keeps the dedup digest stable across repeat collections.
  assert.ok(result.records.every((row) => row.source_observed_at === null));
});

test('repeat DNS collection of an unchanged answer dedups instead of appending duplicates', async () => {
  const resolver = { resolve4: async () => ['8.8.8.8'], resolve6: async () => [], resolveCname: async () => [], resolveMx: async () => [], resolveTxt: async () => [], cancel() {} };
  const a = await collectDeclaredOriginDns(['origin.test'], false, { resolver });
  const b = await collectDeclaredOriginDns(['origin.test'], false, { resolver });
  const digest = (records) => records.map((r) => normalizeOriginClue(r, { parent: 'origin.test', sourceKind: r.source_kind, sourceRef: 'dns:a', now }).source_digest);
  assert.deepEqual(digest(a.records), digest(b.records));
});

test('DNS answer bounds and source failures remain explicit with no negative safety assurance', async () => {
  const resolver = {
    resolve4: async () => Array.from({ length: 100 }, () => '8.8.8.8'),
    resolve6: async () => { throw Object.assign(new Error(), { code: 'ENODATA' }); },
    resolveCname: async () => { throw Object.assign(new Error(), { code: 'ETIMEOUT' }); },
    cancel() {},
  };
  const result = await collectDeclaredOriginDns(['origin.test'], false, { resolver });
  assert.equal(result.records.length, 16); assert.equal(result.query_count, 3);
  assert.ok(result.sources.find((row) => row.type === 'A').truncated);
  assert.equal(result.sources.find((row) => row.type === 'AAAA').status, 'no_answer');
  assert.equal(result.sources.find((row) => row.type === 'CNAME').status, 'unavailable');
});

test('concurrent collection replay does not refetch, source failures persist as partial coverage', async () => {
  let calls = 0;
  const s = service({ collectDns: async () => { calls += 1; return { records: [], sources: [{ hostname: 'origin.test', type: 'A', status: 'unavailable' }], query_count: 3 }; } });
  const results = await Promise.all([s.collect(ctx, 'tgt_1', {}, options()), s.collect(ctx, 'tgt_1', {}, options())]);
  assert.deepEqual(results[0], results[1]); assert.equal(calls, 1);
  const listed = await s.list(ctx, 'tgt_1', {}, options());
  assert.equal(calls, 1); assert.equal(listed.items.length, 0);
  assert.equal(listed.coverage.sources[0].status, 'unavailable'); assert.equal(listed.coverage.partial, true);
  assert.match(listed.coverage.limitations.join(' '), /does not mean.*hidden or protected/);
});

test('latest persisted coverage is append-ordered even when collection/import clocks are identical', async () => {
  const s = service({ collectDns: async () => ({ records: [], sources: [{ type: 'A', hostname: 'origin.test', status: 'unavailable' }], query_count: 3 }) });
  await s.import(ctx, 'tgt_1', body(), options('before-collection'));
  await s.collect(ctx, 'tgt_1', {}, options('after-import'));
  const page = await s.list(ctx, 'tgt_1', {}, options());
  assert.equal(page.items.length, 1); assert.equal(page.coverage.sources[0].status, 'unavailable');
});

test('related collection is explicit declared scoped targets only and never creates child targets', async () => {
  getStore().targets.push({ ...getStore().targets[0], id: 'child', value: 'api.origin.test' }, { ...getStore().targets[0], id: 'foreign_name', value: 'other.test' });
  let queried;
  const s = service({ collectDns: async (hosts) => { queried = hosts; return { records: [], sources: [], query_count: 6 }; } });
  assert.equal((await s.collect(ctx, 'tgt_1', { related_target_ids: ['missing'] }, options())).status, 404);
  assert.equal((await s.collect(ctx, 'tgt_1', { related_target_ids: ['foreign_name'] }, options())).error, 'origin_clue_hostname_out_of_scope');
  const result = await s.collect(ctx, 'tgt_1', { related_target_ids: ['child'] }, options());
  assert.equal(result.error, undefined); assert.deepEqual(queried, ['origin.test', 'api.origin.test']);
  assert.equal(getStore().targets.length, 3); assert.equal(getStore().probeJobs.length, 0);
});

test('malformed final import row and repository transaction failure commit no staged clue/audit', async () => {
  const s = service();
  const failed = await s.import(ctx, 'tgt_1', body([record(), record({ candidate_ip: 'not-an-ip' })]), options());
  assert.equal(failed.error, 'invalid_origin_clue_ip');
  assert.equal(getStore().originClues?.length ?? 0, 0); assert.equal(getStore().auditLog.length, 0);
  const repository = createDevOriginClueRepository();
  await assert.rejects(repository.withBatch(ctx, 'tgt_1', async (tx) => { await tx.insertClue({ tenant_id: ctx.tenantId, target_id: 'tgt_1', fingerprint: 'x' }); throw new Error('rollback'); }), /rollback/);
  assert.equal(getStore().originClues?.length ?? 0, 0);
});
