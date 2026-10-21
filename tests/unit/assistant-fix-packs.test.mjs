import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildAssistantFixPack, buildAssistantFixPackPrompt, normalizeFixPackRequest, parseAssistantFixPack, isOfficialFixPackUrl } from '../../src/services/assistantFixPacks.mjs';
import { sanitizeFixPack, fixPackCopyText } from '../../apps/web/react/src/lib/assistant-fix-packs.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_test', role: 'viewer' };
const finding = { id: 'fnd_fix', tenant_id: 'ten_demo', check_id: 'l7.low_rate_rate_limit.safe', title: 'Authorization: Bearer never-send-this', raw_http: 'NEVER_CAPTURED_HTTP' };
const build = (request = { finding_id: finding.id, provider: 'cloudflare' }, row = finding) => buildAssistantFixPack(ctx, request, { getFinding: async () => row });

test('published provider fix packs are deterministic and read-only with authorized citations', async () => {
  const before = JSON.stringify(finding);
  const first = await build();
  assert.deepEqual(first, await build());
  assert.equal(JSON.stringify(finding), before);
  assert.ok(first.pack.steps.length);
  assert.match(first.pack.steps.join(' '), /rate/i);
  assert.deepEqual(first.pack.citations, [finding.id, ...first.pack.sources.map((source) => source.id)]);
  assert.ok(first.pack.sources.every((source) => isOfficialFixPackUrl(source.url)));
  const prompt = buildAssistantFixPackPrompt(first.pack);
  assert.match(prompt, /UNTRUSTED_DATA_BEGIN published fix pack/);
  assert.ok(!prompt.includes('never-send-this'));
  assert.ok(!prompt.includes('NEVER_CAPTURED_HTTP'));
  assert.ok(prompt.length < 30000);
});

test('unknown and foreign tenant findings have exactly the same denial', async () => {
  assert.deepEqual(await build(undefined, null), { status: 404, error: 'not_found' });
  assert.deepEqual(await build(undefined, { ...finding, tenant_id: 'ten_other' }), { status: 404, error: 'not_found' });
});

test('unsupported providers, arbitrary payloads and invalid ids cannot create a pack', () => {
  for (const input of [{ finding_id: 'fnd_fix', provider: 'f5' }, { finding_id: '../fnd_fix' }, { finding_id: 'fnd_fix', provider: 'Cloudflare' }, { finding_id: 'fnd_fix', prompt: 'instructions' }, { finding_id: 'fnd_fix', provider: null }]) assert.equal(normalizeFixPackRequest(input), null);
  assert.deepEqual(normalizeFixPackRequest({ finding_id: 'fnd_fix' }), { finding_id: 'fnd_fix' });
  for (const url of ['javascript:alert(1)', 'https://developers.cloudflare.com.evil.test/waf/', 'https://developers.cloudflare.com@evil.test/waf/', 'https://developers.cloudflare.com/waf/?secret=x', 'https://developers.cloudflare.com:444/waf/', 'http://developers.cloudflare.com/waf/']) assert.equal(isOfficialFixPackUrl(url), false);
});

test('strict structured parser and feature sanitizer reject invented ids, links and unknown fields', async () => {
  const { pack, control_family: controlFamily } = await build();
  const options = { validation: { pack } };
  const scope = { findingId: finding.id, provider: pack.provider, controlFamily, docs: pack.sources.map((source) => source.url) };
  assert.deepEqual(parseAssistantFixPack(JSON.stringify(pack), options), pack);
  assert.deepEqual(sanitizeFixPack(pack, scope), pack);
  for (const bad of [
    { ...pack, finding_id: 'foreign' }, { ...pack, provider: 'aws' }, { ...pack, citations: ['fnd_foreign'] },
    { ...pack, sources: [{ ...pack.sources[0], url: 'https://evil.test/' }] },
    { ...pack, sources: [{ ...pack.sources[0], url: 'javascript:alert(1)' }] },
    { ...pack, steps: ['Open https://evil.test/'] }, { ...pack, steps: ['x'.repeat(1201)] },
    { ...pack, steps: [] }, { ...pack, apply: true },
  ]) {
    assert.equal(parseAssistantFixPack(JSON.stringify(bad), options), null);
    assert.equal(sanitizeFixPack(bad, scope), null);
  }
  const inventedSources = pack.sources.map((source, index) => index ? source : { ...source, id: `remediation:${controlFamily}:${pack.provider}:99` });
  const inventedIds = { ...pack, sources: inventedSources, citations: [pack.finding_id, ...inventedSources.map((source) => source.id)] };
  assert.equal(sanitizeFixPack(inventedIds, scope), null);
  assert.equal(parseAssistantFixPack(JSON.stringify(inventedIds), options), null);
  assert.equal(parseAssistantFixPack(JSON.stringify(pack)), null);
  assert.equal(parseAssistantFixPack(`answer: ${JSON.stringify(pack)}`, options), null);
  assert.equal(parseAssistantFixPack('x'.repeat(30001), options), null);
  assert.match(fixPackCopyText(pack), /Rollback/);
});

test('model text is secret-redacted and snippets are inert plain text', async () => {
  const { pack } = await build();
  const tailored = { ...pack, steps: ['<script>alert(1)</script>', 'password=do-not-display'] };
  const parsed = parseAssistantFixPack(JSON.stringify(tailored), { validation: { pack } });
  assert.equal(parsed.steps[0], '<script>alert(1)</script>');
  assert.ok(!parsed.steps[1].includes('do-not-display'));
});
