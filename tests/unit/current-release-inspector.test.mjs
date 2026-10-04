/**
 * Current release: shared evidence inspector contract and target protection truth helpers.
 * Pure functions only; no network, no browser, no store.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFileSync } from 'node:fs';
import {
  buildEvidenceInspectorHref,
  classifyInspectorError,
  createInspectorGeneration,
  evidenceContextPath,
  fallbackContextFromRecord,
  fallbackRecordPath,
  inspectorRefKey,
  normalizeEvidenceContext,
  normalizeInspectorRef,
  parseInspectorRef,
  stripInspectorParams,
} from '../../apps/web/react/src/lib/evidence-inspector.mjs';
import {
  inventoryUnits,
  markerEffectiveness,
  normalizedHostKey,
  originExposureStatus,
  providerFamilyRows,
  targetTabFromParam,
  edgeEvidenceSignals,
} from '../../apps/web/react/src/lib/domain-checks.mjs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');

describe('inspector refs (EI-05, ID-only state)', () => {
  it('accepts only exact safe ids and the entry-required fields', () => {
    assert.deepEqual(normalizeInspectorRef({ entry: 'finding', finding_id: 'fnd_1' }), { entry: 'finding', finding_id: 'fnd_1' });
    assert.equal(normalizeInspectorRef({ entry: 'finding' }), null, 'finding requires finding_id');
    assert.equal(normalizeInspectorRef({ entry: 'check_result', target_id: 't', check_id: 'c' }), null, 'check result requires the run');
    assert.equal(normalizeInspectorRef({ entry: 'finding', finding_id: 'a b' }), null);
    assert.equal(normalizeInspectorRef({ entry: 'finding', finding_id: 'Bearer abc.def' }), null);
    assert.equal(normalizeInspectorRef({ entry: 'finding', finding_id: 'x'.repeat(129) }), null);
    assert.equal(normalizeInspectorRef({ entry: 'provider', target_id: 't1', family: 'anycast' }), null);
    assert.equal(normalizeInspectorRef({ entry: 'session', finding_id: 'f' }), null);
  });

  it('drops fields that do not belong to the entry', () => {
    const ref = normalizeInspectorRef({ entry: 'audit', audit_id: 'aud_1', finding_id: 'fnd_1', token: 'secret' });
    assert.deepEqual(ref, { entry: 'audit', audit_id: 'aud_1' });
  });

  it('round-trips through the hash while keeping page state and stripping only inspector keys', () => {
    const href = buildEvidenceInspectorHref(
      { entry: 'check_result', target_id: 'tgt_1', check_id: 'origin.leak_scan.safe', test_run_id: 'run_9' },
      '/app#target-detail?id=tgt_1&tab=validate&check=origin.leak_scan.safe',
    );
    assert.match(href, /^\/app#target-detail\?id=tgt_1&tab=validate&check=origin\.leak_scan\.safe&inspect=check_result/);
    assert.deepEqual(parseInspectorRef(href), { entry: 'check_result', target_id: 'tgt_1', check_id: 'origin.leak_scan.safe', test_run_id: 'run_9' });
    assert.equal(stripInspectorParams(href), '/app#target-detail?id=tgt_1&tab=validate&check=origin.leak_scan.safe');
  });

  it('replaces an earlier inspector selection instead of stacking parameters', () => {
    const first = buildEvidenceInspectorHref({ entry: 'finding', finding_id: 'fnd_1' }, '#findings?status=open');
    const second = buildEvidenceInspectorHref({ entry: 'artifact', evidence_id: 'ev_2' }, first);
    assert.equal(second, '#findings?status=open&inspect=artifact&ev_evidence=ev_2');
    assert.equal(parseInspectorRef(second).entry, 'artifact');
  });

  it('keys distinguish members so Next/Previous never reuses another member', () => {
    assert.notEqual(
      inspectorRefKey({ entry: 'group_member', finding_id: 'fnd_a' }),
      inspectorRefKey({ entry: 'group_member', finding_id: 'fnd_b' }),
    );
  });
});

describe('evidence-context query and failure states (EI-06, EI-08)', () => {
  it('builds a GET query with ids only', () => {
    const path = evidenceContextPath({ entry: 'provider', target_id: 'tgt_1', family: 'cdn' });
    assert.equal(path, '/v1/evidence-context?entry=provider&target_id=tgt_1&family=cdn');
    assert.equal(evidenceContextPath({ entry: 'finding' }), '');
  });

  it('keeps denied, missing, route-missing and failed reads distinct', () => {
    assert.equal(classifyInspectorError({ status: 403, payload: { error: 'forbidden', permission: 'audit:read' } }).state, 'denied');
    assert.equal(classifyInspectorError({ status: 403, payload: { error: 'forbidden', permission: 'audit:read' } }).permission, 'audit:read');
    assert.equal(classifyInspectorError({ status: 404, payload: { error: 'not_found', state: 'not_found' } }).state, 'not_found');
    assert.equal(classifyInspectorError({ status: 404, payload: { error: 'not_found' } }).state, 'route_missing');
    assert.equal(classifyInspectorError({ status: 500, payload: {} }).state, 'unavailable');
    assert.equal(classifyInspectorError(new Error('network')).state, 'unavailable');
  });

  it('maps unavailable reasons without inventing evidence', () => {
    const ref = { entry: 'finding', finding_id: 'fnd_1' };
    assert.equal(normalizeEvidenceContext({ answer: { outcome: 'allowed' }, primary: null, unavailable_reason: 'no_refs' }, ref).state, 'no_refs');
    assert.equal(normalizeEvidenceContext({ unavailable_reason: 'permission_denied' }, ref).state, 'denied');
    assert.equal(normalizeEvidenceContext({ answer: {}, primary: { test_run_id: 'r' }, unavailable_reason: 'partial' }, ref).state, 'partial');
    assert.equal(normalizeEvidenceContext(null, ref).state, 'unavailable');
    const model = normalizeEvidenceContext({ answer: { outcome: 'allowed' }, primary: { test_run_id: 'run_open', verdict_id: 'v1', evidence_ids: ['ev_1'] } }, ref);
    assert.equal(model.request.status, 'not_recorded', 'absent request summary stays not recorded');
    assert.deepEqual(model.primary.evidenceIds, ['ev_1']);
  });

  it('shows a later result separately and never in place of the original (EI-03)', () => {
    const ref = { entry: 'finding', finding_id: 'fnd_1' };
    const model = normalizeEvidenceContext({
      answer: { outcome: 'allowed' },
      primary: { test_run_id: 'run_open', verdict_id: 'v_open', evidence_ids: ['ev_1'] },
      latest_distinct: { test_run_id: 'run_later', verdict_id: 'v_later', evidence_ids: ['ev_9'] },
    }, ref);
    assert.equal(model.primary.testRunId, 'run_open');
    assert.equal(model.later.testRunId, 'run_later');
    const same = normalizeEvidenceContext({
      primary: { test_run_id: 'run_open', verdict_id: 'v_open' },
      latest_distinct: { test_run_id: 'run_open', verdict_id: 'v_open' },
      answer: {},
    }, ref);
    assert.equal(same.later, null);
  });

  it('discards late responses after the selection or tenant changes (EI-07)', () => {
    const generation = createInspectorGeneration();
    const first = generation.begin('tenant-a|owner', 'finding|fnd_1');
    const second = generation.begin('tenant-a|owner', 'finding|fnd_2');
    assert.equal(generation.isCurrent(first), false);
    assert.equal(generation.isCurrent(second), true);
    generation.cancel();
    assert.equal(generation.isCurrent(second), false);
  });
});

describe('exact-record fallback never substitutes another record', () => {
  it('uses read-only exact paths', () => {
    assert.equal(fallbackRecordPath({ entry: 'check_result', target_id: 't', check_id: 'c', test_run_id: 'run_1' }), '/v1/test-runs/run_1');
    assert.equal(fallbackRecordPath({ entry: 'audit', audit_id: 'a' }), '');
    assert.doesNotMatch(fallbackRecordPath({ entry: 'provider', target_id: 't', family: 'cdn' }), /validation-scans/);
  });

  it('rejects a run that belongs to another target or check', () => {
    const ref = { entry: 'check_result', target_id: 'tgt_1', check_id: 'chk_a', test_run_id: 'run_1' };
    assert.equal(fallbackContextFromRecord(ref, { id: 'run_1', target_id: 'tgt_2', check_id: 'chk_a' }).mismatch, true);
    assert.equal(fallbackContextFromRecord(ref, { id: 'run_1', target_id: 'tgt_1', check_id: 'chk_b' }).mismatch, true);
    assert.equal(fallbackContextFromRecord(ref, { id: 'run_2', target_id: 'tgt_1', check_id: 'chk_a' }).mismatch, true);
  });

  it('uses the finding row evidence ids and keeps a later verdict separate', () => {
    const { payload } = fallbackContextFromRecord({ entry: 'finding', finding_id: 'fnd_1' }, {
      id: 'fnd_1', test_run_id: 'run_open', verdict_id: 'v_open', last_verdict_id: 'v_later', evidence_ids: ['ev_1', 'ev_2'], state: 'open',
    });
    const model = normalizeEvidenceContext(payload, { entry: 'finding', finding_id: 'fnd_1' });
    assert.deepEqual(model.primary.evidenceIds, ['ev_1', 'ev_2']);
    assert.equal(model.later.verdictId, 'v_later');
    assert.equal(model.subject.lifecycle, 'open');
    assert.equal(model.answer, null, 'triage notes are never presented as a verdict explanation');
  });

  it('never fills the CDN family from the WAF vendor (EI-02)', () => {
    const { payload } = fallbackContextFromRecord({ entry: 'provider', target_id: 'tgt_1', family: 'cdn' }, {
      target: { id: 'tgt_1' },
      edge_detection: { waf: { status: 'detected', vendor: 'cloudflare' }, cdn: { status: 'detected' }, layers: [{ family: 'waf', provider: 'cloudflare' }] },
    });
    assert.equal(JSON.stringify(payload).includes('cloudflare'), false);
  });
});

describe('provider families stay independent (doc 06 AC-1/AC-2)', () => {
  const edge = {
    status: 'detected',
    observed_at: '2026-10-01T00:00:00.000Z',
    test_run_id: 'run_fp',
    waf: { status: 'detected', provider: 'cloudflare' },
    cdn: { status: 'detected' },
    layers: [{ family: 'waf', provider: 'cloudflare', sources: ['response_fingerprint'] }],
  };

  it('does not borrow the WAF vendor for CDN, hosting or DNS', () => {
    const rows = Object.fromEntries(providerFamilyRows({ edge_detection: edge }).map((row) => [row.family, row]));
    assert.equal(rows.waf.providerName, 'Cloudflare');
    assert.equal(rows.cdn.provider, '');
    assert.equal(rows.cdn.sources.length, 0, 'no inferred CDN source');
    assert.equal(rows.origin_hosting.status, 'unknown');
    assert.equal(rows.dns.status, 'unknown');
    assert.equal(rows.cloud.status, 'not_recorded');
  });

  it('reports not checked when nothing was observed', () => {
    const rows = providerFamilyRows({});
    assert.ok(rows.filter((row) => ['cdn', 'waf', 'cloud'].includes(row.family)).every((row) => row.status === 'not_checked'));
  });

  it('prefers the server protection profile, family by family', () => {
    const rows = Object.fromEntries(providerFamilyRows({
      edge_detection: edge,
      protection_profile: { families: { cdn: { status: 'detected', provider: 'cloudfront', sources: ['address_range'], freshness: 'stale', observed_at: '2026-09-01T00:00:00.000Z' } } },
    }).map((row) => [row.family, row]));
    assert.equal(rows.cdn.providerName, 'Amazon CloudFront');
    assert.equal(rows.cdn.freshness, 'stale');
    assert.equal(rows.cdn.tone, 'warn');
    assert.equal(rows.waf.source, 'edge_detection');
  });

  it('records no source agreement or extra methods unless the server sent them', () => {
    const { layers } = edgeEvidenceSignals({ layers: [{ family: 'cdn', provider: 'fastly' }], evidence: { cdncheck: { matched: true, provider: 'fastly' } } });
    assert.deepEqual(layers[0].sources, []);
    assert.equal(layers[0].agreement, '');
  });

  it('keeps marker effectiveness separate with no percentage at a zero denominator', () => {
    assert.equal(markerEffectiveness({}), null);
    const none = markerEffectiveness({ edge_detection: { effectiveness: { blocked_count: 0, passed_count: 0, inconclusive_count: 2, tested_count: 2, percentage: 0 } } });
    assert.equal(none.percentage, null);
    const some = markerEffectiveness({ protection_profile: { effectiveness: { blocked_count: 9, allowed_count: 1, inconclusive_count: 0, percentage: 90 } } });
    assert.equal(some.percentage, 90);
    assert.equal(some.source, 'protection_profile');
  });

  it('never reads the legacy not_exposed origin default as an observation', () => {
    assert.equal(originExposureStatus({ protection_profile: null }), 'not_tested');
    assert.equal(originExposureStatus({ protection_profile: { origin: { status: 'reachable' } } }), 'reachable');
  });
});

describe('target workspace tabs and inventory units', () => {
  it('maps legacy tab names onto the unified tabs', () => {
    assert.equal(targetTabFromParam('protection'), 'overview');
    assert.equal(targetTabFromParam('edge'), 'overview');
    assert.equal(targetTabFromParam('runs'), 'history');
    assert.equal(targetTabFromParam('checks'), 'validate');
    assert.equal(targetTabFromParam('findings'), 'findings');
    assert.equal(targetTabFromParam('nonsense'), 'overview');
  });

  it('counts declared records and distinct hostnames as different units', () => {
    const units = inventoryUnits([
      { kind: 'fqdn', value: 'Shop.Example.com.' },
      { kind: 'url', value: 'https://shop.example.com/login' },
      { kind: 'fqdn', value: 'api.example.com' },
      { kind: 'ip', value: '203.0.113.7' },
      { kind: 'cidr', value: '203.0.113.0/24' },
    ]);
    assert.deepEqual(units, { records: 5, distinctHosts: 2, nonHostRecords: 2 });
    assert.equal(normalizedHostKey({ kind: 'ip', value: '203.0.113.7' }), '');
  });
});

describe('inspection never executes (EI-08) and target load never probes', () => {
  it('the inspector host and resolver contain no mutating request', () => {
    const host = read('apps/web/react/src/components/evidence/evidence-inspector.tsx');
    const resolver = read('apps/web/react/src/lib/evidence-inspector.mjs');
    for (const source of [host, resolver]) {
      assert.doesNotMatch(source, /method:\s*'(POST|PATCH|PUT|DELETE)'/);
      assert.doesNotMatch(source, /validation-scans|custody\/verify|\/export/);
    }
  });

  it('the target workspace no longer auto-starts edge detection on load', () => {
    const view = read('apps/web/react/src/pages/target-detail-view.tsx');
    assert.doesNotMatch(view, /shouldAutoDetectEdge/);
    assert.match(view, /setReview\(\{ mode: 'detect' \}\)/, 'detection starts only from a reviewed action');
    assert.doesNotMatch(view, /run-detail|scan-detail|DesignVariantSwitch/);
  });
});

describe('typed declaration edits keep group inheritance (B-DECL)', () => {
  it('sends only changed fields; untouched inherited fields are never cleared', async () => {
    const { declarationDraftFrom, declarationPatchBody } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    const initial = declarationDraftFrom({
      purpose: 'Checkout web', purpose_status: 'inherited',
      service_roles: ['website'], service_roles_status: 'inherited',
      owner: { status: 'inherited', label: 'Edge SRE', source: 'target_group' },
      criticality: { status: 'inherited', value: 'high', source: 'target_group' },
    });
    assert.equal(initial.owner_label, '', 'inherited owner is not copied into the target draft');
    assert.equal(initial.criticality, '');
    assert.deepEqual(declarationPatchBody(initial, { ...initial }), {});
    assert.deepEqual(declarationPatchBody(initial, { ...initial, service_roles: ['website', 'login'] }), { service_roles: ['website', 'login'] });
    assert.deepEqual(declarationPatchBody(initial, { ...initial, owner_label: 'Payments' }), { owner: { label: 'Payments' } });
    assert.deepEqual(declarationPatchBody({ ...initial, criticality: 'high' }, { ...initial, criticality: '' }), { criticality: null });
  });
});

describe('review fixes: route state allowlist (NAV-02)', () => {
  it('keeps defined route, filter and selection params and drops unknown or credential-like ones', async () => {
    const { sanitizeRouteParams } = await import('../../apps/web/react/src/lib/evidence-inspector.mjs');
    const kept = sanitizeRouteParams(new URLSearchParams({
      id: 'tgt_checkout_1',
      tab: 'validate',
      check: 'origin.leak_scan.safe',
      key: 'origin.leak_scan.safe|t:origin%20bypass',
      q: 'checkout login',
      status: 'open',
      auth_token: 'abc123',
      invite: 'pwi_secretcode',
      unrelated_metadata: 'x',
      password: 'hunter2',
    }));
    assert.deepEqual(Object.fromEntries(kept), {
      id: 'tgt_checkout_1',
      tab: 'validate',
      check: 'origin.leak_scan.safe',
      key: 'origin.leak_scan.safe|t:origin%20bypass',
      q: 'checkout login',
      status: 'open',
    });
  });

  it('drops credential-shaped values even under a known parameter name', async () => {
    const { sanitizeRouteParams, looksLikeCredential } = await import('../../apps/web/react/src/lib/evidence-inspector.mjs');
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl';
    assert.equal(looksLikeCredential(jwt), true);
    assert.equal(looksLikeCredential('Bearer abc.def'), true);
    assert.equal(looksLikeCredential('pwr_reset_token'), true);
    assert.equal(looksLikeCredential('A'.repeat(56)), true);
    assert.equal(looksLikeCredential('3f2504e0-4f89-11d3-9a0c-0305e82c3301'), false, 'UUIDs stay identifiers');
    assert.equal(looksLikeCredential('fnd_checkout_1'), false);
    assert.equal(sanitizeRouteParams(new URLSearchParams({ q: jwt, id: jwt })).toString(), '');
  });

  it('inspector addresses carry only safe page state over the base', () => {
    const href = buildEvidenceInspectorHref(
      { entry: 'finding', finding_id: 'fnd_1' },
      '/app#findings?status=open&invite_token=pwi_abc&debug=1&page=2',
    );
    assert.equal(href, '/app#findings?status=open&page=2&inspect=finding&ev_finding=fnd_1');
    assert.equal(stripInspectorParams('#findings?status=open&token=abc&inspect=finding&ev_finding=fnd_1'), '#findings?status=open');
  });
});

describe('review fixes: resolver honesty (EI-R01..R06)', () => {
  it('EI-R01: only a route-missing 404 is eligible for the record fallback', () => {
    assert.equal(classifyInspectorError({ status: 404, payload: { error: 'not_found' } }).state, 'route_missing');
    for (const status of [400, 500, 502, 503]) {
      assert.notEqual(classifyInspectorError({ status, payload: { error: 'x' } }).state, 'route_missing', `status ${status}`);
    }
    assert.equal(classifyInspectorError({ status: 404, payload: { error: 'not_found', state: 'not_found' } }).state, 'not_found');
    assert.equal(classifyInspectorError({ status: 401, payload: {} }).state, 'auth');
    const host = read('apps/web/react/src/components/evidence/evidence-inspector.tsx');
    assert.match(host, /if \(classified\.state !== 'route_missing'\)/);
  });

  it('EI-R02: a run that does not state its target and check is unbound, never matched by hint', () => {
    const ref = { entry: 'check_result', target_id: 'tgt_1', check_id: 'chk_a', test_run_id: 'run_1' };
    const missingTarget = fallbackContextFromRecord(ref, { id: 'run_1', check_id: 'chk_a', verdict: { verdict: 'pass' } });
    assert.equal(missingTarget.unbound, true);
    assert.equal(missingTarget.payload, null);
    assert.equal(fallbackContextFromRecord(ref, { id: 'run_1', target_id: 'tgt_1', verdict: { verdict: 'pass' } }).unbound, true);
    const bound = fallbackContextFromRecord(ref, { id: 'run_1', target_id: 'tgt_1', check_id: 'chk_a', verdict: { verdict: 'pass', evidence_ids: ['ev_1'] } });
    assert.equal(bound.payload.subject.target_id, 'tgt_1');
    assert.equal(fallbackContextFromRecord({ entry: 'provider', target_id: 'tgt_1', family: 'cdn' }, { edge_detection: {} }).unbound, true);
    assert.equal(fallbackContextFromRecord({ entry: 'artifact', evidence_id: 'ev_1', test_run_id: 'run_1' }, { id: 'ev_1' }).unbound, true);
  });

  it('EI-R03: no digest or verification is implied when none is recorded', () => {
    const finding = fallbackContextFromRecord({ entry: 'finding', finding_id: 'fnd_1' }, { id: 'fnd_1', test_run_id: 'run_1', evidence_ids: ['ev_1'] });
    assert.equal(finding.payload.primary.integrity, null);
    const artifactNoDigest = fallbackContextFromRecord({ entry: 'artifact', evidence_id: 'ev_1' }, { id: 'ev_1' });
    assert.equal(artifactNoDigest.payload.primary.integrity.status, 'not_recorded');
    const artifactDigest = fallbackContextFromRecord({ entry: 'artifact', evidence_id: 'ev_1' }, { id: 'ev_1', sha256: 'ab'.repeat(32) });
    assert.equal(artifactDigest.payload.primary.integrity.status, 'recorded_digest');
    const model = normalizeEvidenceContext({
      answer: {},
      primary: { test_run_id: 'r', evidence_ids: ['ev_1'], integrity: { status: 'not_recorded', refs: [{ evidence_id: 'ev_1', status: 'not_recorded' }] } },
      missing_evidence_ids: ['ev_1'],
    }, { entry: 'finding', finding_id: 'fnd_1' });
    assert.equal(model.primary.integrity.status, 'not_recorded');
    assert.deepEqual(model.missingEvidenceIds, ['ev_1']);
    const host = read('apps/web/react/src/components/evidence/evidence-inspector.tsx');
    assert.match(host, /No integrity record for these references/);
    assert.match(host, /Verification failed/);
    assert.match(host, /Reported verified, but no verification time is recorded/);
  });

  it('EI-R04: provider presence renders neutral, never as a passing outcome', () => {
    const host = read('apps/web/react/src/components/evidence/evidence-inspector.tsx');
    assert.match(host, /if \(key === 'detected'\) return 'default';/);
    assert.doesNotMatch(host, /const PASS = new Set\([^)]*'detected'/);
    assert.match(host, /ref\.entry === 'provider' \? providerTone\(outcome\)/);
  });

  it('EI-R05: null provider confidence is not recorded, never the string null', () => {
    const { payload } = fallbackContextFromRecord({ entry: 'provider', target_id: 'tgt_1', family: 'cdn' }, {
      target: { id: 'tgt_1' },
      protection_profile: { families: { cdn: { status: 'detected', provider: 'fastly', confidence: null, sources: ['cname_suffix'] } } },
    });
    assert.equal(Object.hasOwn(payload.evaluation, 'confidence'), false);
    const model = normalizeEvidenceContext({ subject: { confidence: null, proof: { methods: ['cname_suffix'], cnames: ['a.example', 'b.fastly.net'] } }, answer: { outcome: 'detected' } }, { entry: 'provider', target_id: 'tgt_1', family: 'cdn' });
    assert.equal(model.provider.confidence, null);
    assert.deepEqual(model.proof.cnames, ['a.example', 'b.fastly.net']);
  });

  it('EI-R06: a committed load is readable only for the same scope and ref', async () => {
    const { inspectorLoadKey } = await import('../../apps/web/react/src/lib/evidence-inspector.mjs');
    const ref = inspectorRefKey({ entry: 'finding', finding_id: 'fnd_1' });
    assert.notEqual(inspectorLoadKey('{"tenant_id":"a","role":"owner"}', ref), inspectorLoadKey('{"tenant_id":"a","role":"viewer"}', ref));
    assert.notEqual(inspectorLoadKey('{"tenant_id":"a"}', ref), inspectorLoadKey('{"tenant_id":"b"}', ref));
    assert.equal(inspectorLoadKey('scope', ''), '');
    const host = read('apps/web/react/src/components/evidence/evidence-inspector.tsx');
    assert.match(host, /const model = load\.key === loadKey \? load\.model : null;/);
    assert.match(host, /\}, \[loadKey, reload, config\]\);/);
  });
});

describe('review fixes: declarations are never cropped (DECL-INT01)', () => {
  it('validates bounds instead of truncating, and preserves unchanged long values', async () => {
    const { declarationPatchBody, validateDeclarationDraft, DECLARATION_LIMITS } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    assert.equal(DECLARATION_LIMITS.purpose, 200);
    const long = 'p'.repeat(180);
    const initial = { purpose: long, service_roles: [], owner_label: '', criticality: '' };
    assert.deepEqual(declarationPatchBody(initial, { ...initial, owner_label: 'Payments' }), { owner: { label: 'Payments' } }, 'an owner edit never resends or crops purpose');
    assert.deepEqual(validateDeclarationDraft({ ...initial, purpose: 'x'.repeat(201) }), { purpose: 'Purpose must be at most 200 characters.' });
    const tooLong = { ...initial, purpose: 'x'.repeat(201) };
    assert.equal(declarationPatchBody(initial, tooLong).purpose.length, 201, 'the body is never silently cropped');
  });
});

describe('server cohorts: dashboard analytics and filtered target lists', () => {
  const segment = (key, count) => ({ key, count, percentage: 0, list_query: { family: 'waf', unit: 'hostname', family_status: key } });
  const analytics = (overrides = {}) => ({
    scope: 'current', historical: false, snapshot_id: null, as_of: '2026-10-04T05:14:15.847Z', complete: true,
    unit: 'normalized_hostname', canonical_unit: 'hostname', denominator: 65,
    units: { target_records: 66, normalized_hosts: 65 },
    filters: { family: 'waf', unit: 'hostname' }, list_query: { query: { family: 'waf', unit: 'hostname' } },
    segments: [segment('detected', 10), segment('not_detected', 5), segment('inconclusive', 3), segment('not_checked', 30), segment('not_recorded', 7), segment('stale', 4), segment('conflict', 2)],
    unknown_count: 4,
    ...overrides,
  });

  it('keeps unknown_count as unknown only and groups not checked and not recorded with it', async () => {
    const { familyCoverageBuckets } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    const buckets = familyCoverageBuckets(analytics());
    const byKey = Object.fromEntries(buckets.parts.map((part) => [part.key, part]));
    assert.equal(byKey.unknown.count, 4);
    assert.equal(byKey.unknown.label, 'Unknown');
    assert.equal(buckets.unmeasured, 30 + 7 + 4, 'Unknown or not checked = not_checked + not_recorded + unknown');
    assert.equal(byKey.inconclusive.group, 'inconclusive');
    assert.equal(byKey.conflict.group, 'conflict');
    assert.equal(buckets.reconciled, true);
    assert.equal(buckets.current, true);
    assert.deepEqual(buckets.units, { targetRecords: 66, normalizedHosts: 65 });
    assert.equal(buckets.unit, 'hostname');
    assert.equal(byKey.not_checked.href, '#targets?family=waf&family_status=not_checked&unit=hostname');
    assert.equal(byKey.unknown.href, '#targets?family=waf&family_status=unknown&unit=hostname');
  });

  it('reports parts that do not add up, historical or incomplete scopes without inventing a total', async () => {
    const { familyCoverageBuckets } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    assert.equal(familyCoverageBuckets(analytics({ denominator: 70 })).reconciled, false);
    assert.equal(familyCoverageBuckets(analytics({ historical: true })).current, false);
    assert.equal(familyCoverageBuckets(analytics({ complete: false })).complete, false);
    const empty = familyCoverageBuckets({});
    assert.equal(empty.denominator, null);
    assert.deepEqual(empty.parts, []);
    assert.equal(empty.reconciled, false);
  });

  it('builds the exact cohort address from a list_query, dropping unsupported keys', async () => {
    const { cohortHrefFromListQuery } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    assert.equal(cohortHrefFromListQuery({ query: { family: 'cdn', unit: 'declared_target', family_status: 'stale', origin_status: 'exposed' } }), '#targets?family=cdn&family_status=stale&unit=target');
    assert.equal(cohortHrefFromListQuery({ service_role: 'login', criticality: 'high', unit: 'hostname', debug: '1' }), '#targets?service_role=login&criticality=high&unit=hostname');
    assert.equal(cohortHrefFromListQuery({ family_status: 'detected' }), '#targets', 'a family status without its family is not a cohort');
    assert.equal(cohortHrefFromListQuery(null), '#targets');
  });

  it('accepts canonical filters and aliases, canonical winning, and rejects unsafe values', async () => {
    const { canonicalCohortFilters } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    assert.deepEqual(
      canonicalCohortFilters(new URLSearchParams('group=tg_a&search=checkout&role=login&unit=normalized_hostname')),
      { target_group_id: 'tg_a', q: 'checkout', service_role: 'login', unit: 'hostname' },
    );
    assert.deepEqual(canonicalCohortFilters({ target_group_id: 'tg_canon', group: 'tg_alias' }), { target_group_id: 'tg_canon' });
    assert.equal(canonicalCohortFilters({ unit: 'hostname' }), null, 'a unit alone does not open a cohort');
    assert.equal(canonicalCohortFilters({ q: '<script>' }), null);
    assert.deepEqual(canonicalCohortFilters({ family: 'waf', unit: 'bogus' }), { family: 'waf' });
  });

  it('classifies cohort read failures into refetch, reset, unsupported, denied and error', async () => {
    const { classifyCohortError } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    const err = (status, error) => ({ status, payload: { error } });
    assert.deepEqual(classifyCohortError(err(409, 'cohort_changed')), { action: 'refetch', reason: 'cohort_changed' });
    assert.equal(classifyCohortError(err(409, 'cursor_clock_mismatch')).action, 'reset');
    assert.equal(classifyCohortError(err(409, 'cursor_filter_mismatch')).action, 'reset');
    assert.equal(classifyCohortError(err(400, 'invalid_cursor')).action, 'reset');
    assert.deepEqual(classifyCohortError(err(400, 'unknown_query_param')), { action: 'unsupported', reason: 'unknown_query_param' });
    assert.equal(classifyCohortError(err(403, 'forbidden')).action, 'denied');
    assert.equal(classifyCohortError(err(500)).action, 'error');
    assert.equal(classifyCohortError(new Error('offline')).action, 'error');
  });

  it('keeps audit and cohort params through the route sanitizer and nav state', async () => {
    const { sanitizeRouteParams } = await import('../../apps/web/react/src/lib/evidence-inspector.mjs');
    const kept = sanitizeRouteParams(new URLSearchParams({
      actor: 'usr_owner', category: 'target_change', resource: 'target:tgt_checkout_1', from: '2026-09-01', to: '2026-10-04T10:00:00Z',
      target_group_id: 'tg_checkout', verification_state: 'dns_verified', role: 'login', unit: 'hostname',
      metadata: '{"a":1}', api_key: 'sk_live_x',
    }));
    assert.deepEqual(Object.fromEntries(kept), {
      actor: 'usr_owner', category: 'target_change', resource: 'target:tgt_checkout_1', from: '2026-09-01', to: '2026-10-04T10:00:00Z',
      target_group_id: 'tg_checkout', verification_state: 'dns_verified', role: 'login', unit: 'hostname',
    });
    assert.equal(sanitizeRouteParams(new URLSearchParams({ from: 'yesterday', to: '2026-13-99x' })).toString(), '');
    const { sanitizeNavState } = await import('../../apps/web/react/src/lib/nav-state.mjs');
    const nav = sanitizeNavState({ filters: { unit: 'hostname', has_open_finding: 'true', target_group_id: 'tg_a', secret: 'x' } });
    assert.deepEqual(nav?.filters, { unit: 'hostname', has_open_finding: 'true', target_group_id: 'tg_a' });
  });

  it('target cohort list never picks a first member of a shared hostname and passes the server predicate', () => {
    const source = read('apps/web/react/src/components/targets/target-cohort.tsx');
    assert.match(source, /none is chosen for you/);
    assert.equal(source.match(/memberIds\[0\]/g)?.length, 1, 'one indexed read only');
    assert.match(source, /if \(members <= 1\) \{\s*const id = memberIds\[0\]/, 'and only for a single-member row');
    assert.doesNotMatch(source, /target_ids\)?\[0\]/);
    assert.match(source, /classifyCohortError/);
    assert.match(source, /earlier rows are not kept as a snapshot/);
    const findings = read('apps/web/react/src/pages/refined/findings-refined.tsx');
    // The group filter is one server predicate shared by the totals, the paged list and the grouped read.
    assert.match(findings, /target_group_id: groupFilter === 'all' \? '' : groupFilter/);
    assert.match(findings, /Groups and their counts are partial until every matching finding is read\./);
  });
});

describe('profile honesty: retained records and origin assurance', () => {
  it('reads origin reachability with its tested scope and keeps assurance as recorded', async () => {
    const { originExposureDetail } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    const detail = originExposureDetail({ protection_profile: { origin: {
      status: 'unknown', binding_id: null, assurance: 'none',
      reachability: { status: 'reachable', source: 'test_run', tested_target_id: 'tgt_checkout_1', scenario_id: 'origin.leak_scan.safe', limitations: ['no_origin_binding'] },
    } } });
    assert.deepEqual(detail, {
      status: 'unknown', assurance: 'none', reachabilityStatus: 'reachable', testedTargetId: 'tgt_checkout_1',
      scenarioId: 'origin.leak_scan.safe', source: 'test_run', limitations: ['no_origin_binding'],
    });
    assert.deepEqual(originExposureDetail({}), {
      status: 'not_tested', assurance: 'not_recorded', reachabilityStatus: 'not_tested', testedTargetId: '', scenarioId: '', source: '', limitations: [],
    });
  });

  it('labels simulated, manual or unversioned records as not current live evidence', () => {
    const view = read('apps/web/react/src/pages/target-detail-view.tsx');
    assert.match(view, /pair\.live_external === false && asDataItem\(pair\.retained\)/);
    assert.match(view, /Recorded, not counted as current live coverage/);
    for (const reason of ['simulation', 'manual_declaration', 'missing_check_version', 'missing_scenario_version']) {
      assert.match(view, new RegExp(`${reason}:`));
    }
    const queue = read('apps/web/react/src/components/targets/domain-protection.tsx');
    assert.match(queue, /Not live evidence/);
    assert.match(queue, /Origin assurance: /);
  });
});

describe('inspector operation facts (request counts, provenance, provider proof)', () => {
  const base = { entry: 'check_result', target_id: 'tgt_checkout_1', check_id: 'origin.leak_scan.safe', test_run_id: 'run_checkout_1' };
  const context = (overrides) => ({ ref: base, answer: { verdict: 'protected' }, primary: { test_run_id: 'run_checkout_1' }, ...overrides });

  it('renders recorded sent and simulated counts and never turns a missing count into zero', () => {
    const recorded = normalizeEvidenceContext(context({ request_summary: { status: 'recorded', request_count: { status: 'recorded', requests_sent: 0, requests_sent_source: 'metadata', requests_simulated: 4 } } }), base);
    assert.deepEqual(recorded.request.fields.filter((field) => field.key.startsWith('request')), [
      { key: 'requests_sent', value: '0' },
      { key: 'requests_simulated', value: '4' },
    ]);
    const missing = normalizeEvidenceContext(context({ request_summary: { status: 'recorded', request_count: { status: 'not_recorded' } } }), base);
    assert.deepEqual(missing.request.fields.filter((field) => field.key.startsWith('request')), [{ key: 'request_count', value: 'Not recorded' }]);
  });

  it('labels provenance as live external only when the server says so', () => {
    const live = normalizeEvidenceContext(context({ request_summary: { status: 'recorded', provenance: { status: 'recorded', kind: 'signed_probe', live_external: true } } }), base);
    assert.deepEqual(live.request.fields.find((field) => field.key === 'provenance'), { key: 'provenance', value: 'signed probe (live external)' });
    const simulated = normalizeEvidenceContext(context({ evaluation: { status: 'recorded', provenance: { status: 'recorded', kind: 'simulation', live_external: false } } }), base);
    assert.equal(simulated.evaluation.fields.find((field) => field.key === 'provenance').value, 'simulation (not live external evidence)');
    const none = normalizeEvidenceContext(context({ evaluation: { status: 'recorded', provenance: { status: 'not_recorded' } } }), base);
    assert.equal(none.evaluation.fields.find((field) => field.key === 'provenance').value, 'Not recorded');
  });

  it('reads the server provider proof string arrays and renders each list', () => {
    const ref = { entry: 'provider', target_id: 'tgt_checkout_1', family: 'cdn' };
    const model = normalizeEvidenceContext({ ref, subject: { family: 'cdn', status: 'detected', provider: 'cloudflare', proof: {
      matched_signals: ['cf-ray', 'server:cloudflare'], methods: ['http_headers'], cnames: ['checkout.acme.com', 'checkout.acme.com.cdn.cloudflare.net'], addresses: ['104.16.0.1'], fingerprints: [],
    } } }, ref);
    assert.deepEqual(model.proof, {
      methods: ['http_headers'], matched_signals: ['cf-ray', 'server:cloudflare'], cnames: ['checkout.acme.com', 'checkout.acme.com.cdn.cloudflare.net'], addresses: ['104.16.0.1'], fingerprints: [],
    });
    const view = read('apps/web/react/src/components/evidence/evidence-inspector.tsx');
    for (const label of ['Methods', 'Matched signals', 'CNAME chain', 'Address attribution', 'Response fingerprints']) assert.match(view, new RegExp(`<dt>${label}</dt>`));
  });
});

describe('history, origin relations and retest lineage (current-release history)', () => {
  it('assigns origin relation roles the way the server binding rule does', async () => {
    const { originBindingRole } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    assert.equal(originBindingRole({ kind: 'fqdn', value: 'checkout.example.test' }), 'protected');
    assert.equal(originBindingRole({ kind: 'url', value: 'https://checkout.example.test/login' }), 'protected');
    assert.equal(originBindingRole({ kind: 'ip', value: '203.0.113.10' }), 'origin');
    assert.equal(originBindingRole({ kind: 'url', value: 'https://203.0.113.10:8443/' }), 'origin');
    assert.equal(originBindingRole({ kind: 'cidr', value: '203.0.113.0/24' }), null);
    assert.equal(originBindingRole({ kind: 'tcp_endpoint', value: '203.0.113.10:22' }), null);
  });

  it('offers only existing, independently verified origin targets and never the target itself', async () => {
    const { originBindingCandidates } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    const host = { id: 'tgt_host', kind: 'fqdn', value: 'checkout.example.test', verification_state: 'dns_verified' };
    const { ready, blocked } = originBindingCandidates([
      host,
      { id: 'tgt_ip_ok', kind: 'ip', value: '203.0.113.10', verification_state: 'dns_verified' },
      { id: 'tgt_ip_confirmed', kind: 'ip', value: '203.0.113.12', verification: { state: 'user_confirmed' } },
      { id: 'tgt_ip_provider', kind: 'ip', value: '203.0.113.13', verification_state: 'provider_verified' },
      { id: 'tgt_ip_pending', kind: 'ip', value: '203.0.113.11', verification_state: null },
      { id: 'tgt_other_host', kind: 'fqdn', value: 'pay.example.test', verification_state: 'dns_verified' },
      { id: 'tgt_ip_deleted', kind: 'ip', value: '203.0.113.14', verification_state: 'dns_verified', deleted_at: '2026-09-01T00:00:00Z' },
    ], host);
    assert.deepEqual(ready.map((row) => row.id), ['tgt_ip_ok', 'tgt_ip_confirmed']);
    assert.deepEqual(blocked.map((row) => row.id), ['tgt_ip_provider', 'tgt_ip_pending'], 'provider proof on an IP is not origin proof');
  });

  it('validates the optional binding scope and omits empty choices', async () => {
    const { originBindingScope, originBindingErrorMessage } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    assert.deepEqual(originBindingScope({}), { scope: {}, errors: {}, valid: true });
    assert.deepEqual(originBindingScope({ port: '8443', path: '/login' }).scope, { port: 8443, path: '/login' });
    assert.equal(originBindingScope({ port: '70000' }).valid, false);
    assert.equal(originBindingScope({ port: '80; rm' }).valid, false);
    assert.equal(originBindingScope({ path: 'login' }).valid, false);
    assert.equal(originBindingScope({ path: '/a b' }).valid, false);
    assert.match(originBindingErrorMessage({ status: 409, payload: { error: 'ownership_not_verified' } }), /Ownership is not currently verified/);
    assert.match(originBindingErrorMessage({ status: 400, payload: { error: 'scope_not_declared' } }), /Undeclared destinations/);
  });

  it('presents observations as recorded and labels non-live producers', async () => {
    const { presentObservation, comparisonReasonLabel, changeDirectionLabel } = await import('../../apps/web/react/src/lib/domain-checks.mjs');
    const row = presentObservation({ id: 'obs_1', family: 'waf', outcome: 'timeout', attempt_class: 'failed_attempt', producer_kind: 'internal_simulation', observed_at: '2026-08-12T00:00:00.000000Z', check_id: 'waf.fingerprint.safe', check_version: null });
    assert.equal(row.outcomeLabel, 'Timed out');
    assert.equal(row.attemptLabel, 'Failed attempt');
    assert.equal(row.live, false);
    assert.equal(row.checkVersion, '');
    assert.equal(presentObservation({ family: 'waf' }), null, 'no id, no row');
    assert.equal(presentObservation({ id: 'o', producer_kind: 'signed_probe', outcome: 'detected', attempt_class: 'successful' }).live, true);
    assert.match(comparisonReasonLabel('check_version_changed'), /check definition changed/);
    assert.equal(changeDirectionLabel('disappeared'), 'Disappeared');
  });

  it('reads finding lineage: explicit retests only, later same-pair runs apart, closure without sibling closure', async () => {
    const { readFindingLineage } = await import('../../apps/web/react/src/lib/finding-lineage.mjs');
    const view = readFindingLineage({
      closed_at: '2026-09-10T00:00:00Z',
      lineage: {
        sibling_closure: false,
        originating: { test_run_id: 'run_a', relation: 'originating', status: 'completed' },
        retests: [{ id: 'rtln_1', test_run_id: 'run_b', intent: 'retest', relation: 'retest', created_at: '2026-09-01T00:00:00Z' }, { test_run_id: 'run_x', intent: 'other' }],
        later_same_pair: [{ test_run_id: 'run_c', relation: 'later_same_pair', reason: 'no_explicit_retest_intent', finalized: true }, { test_run_id: 'run_d', relation: 'not_comparable' }],
        latest: { test_run_id: 'run_b', relation: 'retest' },
      },
    });
    assert.equal(view.originating.testRunId, 'run_a');
    assert.deepEqual(view.retests.map((run) => run.testRunId), ['run_b']);
    assert.deepEqual(view.laterSamePair.map((run) => run.testRunId), ['run_c']);
    assert.equal(view.latest.testRunId, 'run_b');
    assert.equal(view.closedAt, '2026-09-10T00:00:00Z');
    assert.equal(view.siblingClosure, false);
    assert.deepEqual(readFindingLineage({}).retests, []);
  });

  it('wires retest intent, read-only scan reads and non-nested artifact rows', () => {
    const finding = read('apps/web/react/src/pages/finding-detail-view.tsx');
    assert.match(finding, /retest_of_finding_id: entityId/);
    assert.doesNotMatch(finding, /role: 'button',\s*tabIndex: 0,\s*className: 'finding-artifact-row'/, 'artifact rows are not controls wrapping the View button');
    assert.match(finding, /data-focus-key=\{`artifact-\$\{artifactId\}`\}/);
    assert.match(finding, /not proof of a fix/);
    const target = read('apps/web/react/src/pages/target-detail-view.tsx');
    assert.match(target, /\/v1\/validation-scans\/\$\{encodeURIComponent\(scanId\)\}\?advance=false/);
    const origin = read('apps/web/react/src/components/targets/origin-relations.tsx');
    assert.match(origin, /origin_binding_id: str\(review\.binding, 'id'\)/);
    assert.doesNotMatch(origin, /direct_ip|discovered_endpoint|destination:/);
    assert.match(origin, /not an origin lockdown/);
  });
});
