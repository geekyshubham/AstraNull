import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { ORIGIN_IMPORT_MAX_BYTES, originClueImportBody, originClueSourceLabel, originCluesErrorState, originCluesPage } from '../../apps/web/react/src/lib/origin-exposure.mjs';

const draft = { sourceKind: 'historical_dns', sourceRef: 'Authorized export 2026-10-16', content: JSON.stringify([{ candidate_ip: '203.0.113.8', associated_hostname: 'checkout.example.test' }]) };

describe('origin exposure overview import and read boundaries', () => {
  it('preserves supplied data as an import, without executable target or binding fields', () => {
    const body = originClueImportBody(draft);
    assert.deepEqual(Object.keys(body).sort(), ['records', 'source_kind', 'source_ref']);
    assert.equal(body.records[0].candidate_ip, '203.0.113.8');
    assert.equal(body.source_ref, draft.sourceRef);
  });
  it('does not fetch provenance references and keeps CSV as supplied data', () => {
    const csv = 'IP Address,Common Name\n203.0.113.8,checkout.example.test';
    assert.deepEqual(originClueImportBody({ sourceKind: 'trickest_csv', sourceRef: 'https://untrusted.invalid/report', content: csv }), { source_kind: 'trickest_csv', source_ref: 'https://untrusted.invalid/report', csv });
  });
  it('rejects wrong sources, empty, malformed or oversized imports before review', () => {
    for (const change of [{ sourceKind: 'arbitrary_url' }, { sourceRef: '' }, { sourceRef: 'a'.repeat(513) }, { content: '' }, { content: '{broken' }, { content: '{}' }, { content: '[]' }, { content: '[null]' }, { content: '[[]]' }, { content: JSON.stringify(Array.from({ length: 201 }, () => ({}))) }]) assert.throws(() => originClueImportBody({ ...draft, ...change }));
    assert.throws(() => originClueImportBody({ ...draft, content: 'x'.repeat(ORIGIN_IMPORT_MAX_BYTES + 1) }), /128 KiB/);
    assert.throws(() => originClueImportBody({ ...draft, sourceKind: 'trickest_csv', content: '\n'.repeat(ORIGIN_IMPORT_MAX_BYTES / 2) + 'a' }), /complete import request/);
  });
  it('counts UTF-8 bytes, not JavaScript characters', () => {
    assert.throws(() => originClueImportBody({ ...draft, content: '🙂'.repeat(ORIGIN_IMPORT_MAX_BYTES / 3) }), /128 KiB/);
  });
  it('requires exact target and opt-in state on every page and every row', () => {
    const page = { target_id: 'tgt_one', enabled: true, items: [{ id: 'clue_one', target_id: 'tgt_one' }], coverage: { partial: true } };
    assert.equal(originCluesPage(page, 'tgt_one'), page);
    for (const payload of [{ ...page, target_id: 'tgt_other' }, { ...page, enabled: false }, { ...page, items: null }, { ...page, items: [{ id: 'clue_other', target_id: 'tgt_other' }] }]) assert.throws(() => originCluesPage(payload, 'tgt_one'));
  });
  it('distinguishes disabled, denied, unavailable and unknown server state', () => {
    assert.equal(originCluesErrorState({ payload: { error: 'origin_clues_feature_disabled' }, status: 404 }), 'disabled');
    assert.equal(originCluesErrorState({ payload: { error: 'forbidden' }, status: 403 }), 'forbidden');
    assert.equal(originCluesErrorState({ payload: { error: 'not_found' }, status: 404 }), 'unsupported');
    assert.equal(originCluesErrorState({ status: 503 }), 'error');
    assert.equal(originCluesErrorState(null), 'error');
    assert.equal(originClueSourceLabel('certificate_host'), 'Certificate host-index import');
    assert.equal(originClueSourceLabel('future_source'), 'Imported association');
  });
  it('places the real component in Overview and keeps mutations explicit and reviewed', () => {
    const source = readFileSync(new URL('../../apps/web/react/src/components/targets/origin-exposure.tsx', import.meta.url), 'utf8');
    const page = readFileSync(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');
    assert.match(page, /tab === 'overview'[\s\S]*?<OriginExposure/);
    assert.match(source, /onConfirm=\{\(\) => void confirm\(\)\}/);
    assert.match(source, /'Idempotency-Key': action.key/);
    assert.match(source, /load\.state !== 'ready'/);
    assert.match(source, /No association observed in these sources/);
    assert.match(source, /Observation time unknown/);
    assert.doesNotMatch(source, /dangerouslySetInnerHTML|\/v1\/test-runs|\/v1\/origin-bindings|method: 'PUT'/);
  });
});
