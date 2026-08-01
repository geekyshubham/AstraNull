import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
// The real shipped derivation, imported rather than re-implemented. See the note above the
// coverage suite for why this file used to hold a copy and what that copy hid.
import {
  VECTOR_FAMILIES,
  checkMatchesFamily,
  familyCheckIds,
  familyCoverage,
  itemCheckId,
  itemTargetGroupId,
} from '../../apps/web/react/src/lib/vector-coverage.mjs';

const ROOT = process.cwd();
const REACT_SRC = path.join(ROOT, 'apps/web/react/src');

function read(rel) {
  return readFileSync(path.join(REACT_SRC, rel), 'utf8');
}

/**
 * Regression guard for the "no fabricated runtime values in the portal" audit.
 * Under oidc-jwt nothing fabricated may be displayed or sent; dev/staging identity
 * literals must stay behind their existing dev-headers/bundled-staging gates only.
 */
describe('portal has no fabricated runtime fallbacks (audit FT-PROV)', () => {
  it('app-shell does not fabricate a "dev" environment or "ten_demo" tenant for display', () => {
    const src = read('components/layout/app-shell.tsx');
    assert.ok(!/environment[^\n]*\?\?\s*'dev'/.test(src), 'environment must not fall back to fabricated dev');
    assert.ok(!/tenantId\s*=\s*[^\n]*\?\?\s*'ten_demo'/.test(src), 'tenant label must not fabricate ten_demo');
    assert.ok(/environment[^\n]*\?\?\s*''/.test(src), 'environment should resolve to empty when unknown');
    assert.ok(/tenantId\s*=\s*[^\n]*\?\?\s*'unknown'/.test(src), 'tenant label should use neutral unknown when unresolved');
    assert.ok(/\{environment \? <> · \{environment\}<\/> : null\}/.test(src), 'environment separator should only render for real values');
  });

  it('login/staff forms do not prefill fabricated identities', () => {
    const src = read('pages/public-pages.tsx');
    assert.ok(!/useState\('usr_admin'\)/.test(src), 'customer login must not prefill usr_admin');
    assert.ok(!/useState\('staff_admin'\)/.test(src), 'staff login must not prefill staff_admin');
    assert.ok(!/\|\|\s*'usr_admin'/.test(src), 'no usr_admin identity fallback on submit');
    assert.ok(!/\|\|\s*'staff_admin'/.test(src), 'no staff_admin identity fallback on submit');
    // Identity is user-entered and trimmed.
    assert.ok(/user_id: userId\.trim\(\),/.test(src), 'customer user_id comes from the entered value');
    assert.ok(/staff_id: staffId\.trim\(\),/.test(src), 'staff_id comes from the entered value');
  });

  it('the tenant_id sent by bundled/dev login stays gated (not shown, not oidc identity)', () => {
    const src = read('pages/public-pages.tsx');
    // ten_demo may only appear inside gated dev/bundled login paths and the optional Try demo CTA
    // (all unreachable under a pure oidc-jwt build when loginDisabled short-circuits).
    const occurrences = src.match(/'ten_demo'/g) ?? [];
    assert.equal(occurrences.length, 3, 'ten_demo should only exist in gated login and Try demo paths');
  });

  it('api.ts no longer ships the dead ensureDevSession helper', () => {
    const src = read('lib/api.ts');
    assert.ok(!/ensureDevSession/.test(src), 'dead ensureDevSession with hardcoded identity must be removed');
  });

  it('App.tsx role change no longer fabricates identity', () => {
    const src = read('App.tsx');
    assert.ok(!/\?\?\s*'ten_demo'/.test(src), 'role change must not fabricate ten_demo');
    assert.ok(!/\?\?\s*'usr_admin'/.test(src), 'role change must not fabricate usr_admin');
  });

  it('governance/functional exports source tenant from real state, not ten_demo', () => {
    const gov = read('pages/governance-pages.tsx');
    const func = read('pages/functional-surfaces.tsx');
    assert.ok(!/\?\?\s*'ten_demo'/.test(gov), 'governance export must not fabricate ten_demo');
    assert.ok(!/\?\?\s*'ten_demo'/.test(func), 'custody export must not fabricate ten_demo');
    assert.ok(/data\.state\?\.tenant_id \?\? 'unknown'/.test(gov), 'governance export derives tenant from real state');
    assert.ok(/data\.state\?\.tenant_id \?\? 'unknown'/.test(func), 'custody export derives tenant from real state');
  });

  it('internal entitlement form does not default to a fabricated tenant', () => {
    const src = read('pages/page-components.tsx');
    assert.ok(!/\['tenant_id', 'id'\],\s*'ten_demo'/.test(src), 'entitlement tenant must not default to ten_demo');
    assert.ok(/\['tenant_id', 'id'\],\s*''\)/.test(src), 'entitlement tenant defaults to empty until a real tenant is chosen');
  });

  it('vector heatmap renders real coverage states, never invented percentages', () => {
    const src = read('components/charts/vector-heatmap.tsx');
    assert.ok(!/\$\{score\}%/.test(src), 'heatmap must not print invented percentages');
    assert.ok(!/return 100;|return 75;|return 50;/.test(src), 'heatmap must not bucket into heuristic scores');
    assert.ok(/'no-data'/.test(src) && /'No data'/.test(src), 'heatmap must expose an explicit no-data state');
  });
});

/**
 * The coverage derivation, exercised through the module the portal actually renders from.
 *
 * This suite used to re-implement `familyCoverage`, `itemCheckId` and `itemTargetGroupId`
 * locally, because `node --test` cannot load the `.tsx` they lived in. The copy had already
 * drifted: it resolved ids from `check_id`/`checkId` only, while the shipped version also falls
 * back to nested `check.check_id` and `target_group.id`. Those shapes were therefore handled in
 * production and asserted nowhere, and these tests would have kept passing regardless of what
 * the heatmap did. The logic now lives in `lib/vector-coverage.mjs`, imported by both the `.tsx`
 * and this file, so that class of drift cannot recur.
 */
describe('vector heatmap coverage derives from real data only', () => {
  const checkIds = new Set(['chk_1']);
  const gid = 'grp_1';

  it('reports no-data when no checks map to the family', () => {
    const cov = familyCoverage({ checkIds: new Set(), groupId: gid, testPolicies: [], runs: [], evidence: [] });
    assert.equal(cov.status, 'no-data');
  });

  it('reports no-data when there is no declared group', () => {
    const cov = familyCoverage({ checkIds, groupId: '', testPolicies: [], runs: [], evidence: [] });
    assert.equal(cov.status, 'no-data');
  });

  it('reports "none" when checks exist but no policy/run/evidence records do', () => {
    const cov = familyCoverage({ checkIds, groupId: gid, testPolicies: [], runs: [], evidence: [] });
    assert.equal(cov.status, 'none');
    assert.equal(cov.evidenceCount, 0);
  });

  it('promotes to policy, then run, then evidence as real records appear', () => {
    const policy = { target_group_id: gid, check_id: 'chk_1' };
    const run = { target_group_id: gid, check_id: 'chk_1' };
    const ev = { target_group_id: gid, check_id: 'chk_1' };

    assert.equal(familyCoverage({ checkIds, groupId: gid, testPolicies: [policy], runs: [], evidence: [] }).status, 'policy');
    assert.equal(familyCoverage({ checkIds, groupId: gid, testPolicies: [policy], runs: [run], evidence: [] }).status, 'run');
    const withEvidence = familyCoverage({ checkIds, groupId: gid, testPolicies: [policy], runs: [run], evidence: [ev] });
    assert.equal(withEvidence.status, 'evidence');
    assert.equal(withEvidence.evidenceCount, 1);
    assert.equal(withEvidence.runCount, 1);
    assert.equal(withEvidence.policyCount, 1);
  });

  it('ignores records from other target groups', () => {
    const otherPolicy = { target_group_id: 'grp_other', check_id: 'chk_1' };
    const cov = familyCoverage({ checkIds, groupId: gid, testPolicies: [otherPolicy], runs: [], evidence: [] });
    assert.equal(cov.status, 'none');
    assert.equal(cov.policyCount, 0);
  });

  it('counts records that carry ids in camelCase or nested objects', () => {
    // These four shapes all ship from different sources (raw API rows, hydrated portal state,
    // expanded joins). A record whose id fails to resolve silently drops out of every count,
    // which renders as "no coverage" rather than as a shape mismatch — so each shape that the
    // resolver accepts needs to be observably counted.
    const shapes = [
      { target_group_id: gid, check_id: 'chk_1' },
      { targetGroupId: gid, checkId: 'chk_1' },
      { target_group: { id: gid }, check: { check_id: 'chk_1' } },
      { target_group: { id: gid }, checkId: 'chk_1' },
    ];
    for (const record of shapes) {
      const cov = familyCoverage({ checkIds, groupId: gid, testPolicies: [record], runs: [], evidence: [] });
      assert.equal(cov.policyCount, 1, `unrecognised shape: ${JSON.stringify(record)}`);
      assert.equal(cov.status, 'policy');
    }
  });

  it('does not resolve an id out of an array or a missing nested object', () => {
    // Pins the outcome rather than the mechanism: any shape that does not actually carry an id
    // must resolve to '', so the record lands in no cell. An unresolvable id that resolved to
    // something non-empty is what would invent coverage. (Mutation-checked: the `Array.isArray`
    // guard in `nestedString` is not what these array cases exercise — arrays have no `id` or
    // `check_id`, so they resolve to '' with or without it.)
    assert.equal(itemCheckId({ check: ['chk_1'] }), '');
    assert.equal(itemTargetGroupId({ target_group: ['grp_1'] }), '');
    assert.equal(itemCheckId({}), '');
    assert.equal(itemTargetGroupId({ target_group: null }), '');
    // A record with no resolvable group id must not land in a cell.
    const cov = familyCoverage({
      checkIds, groupId: gid, testPolicies: [{ check_id: 'chk_1' }], runs: [], evidence: [],
    });
    assert.equal(cov.policyCount, 0, 'an unresolvable record must not be counted as coverage');
  });
});

describe('vector family assignment', () => {
  const dns = VECTOR_FAMILIES.find((f) => f.label === 'DNS');
  const origin = VECTOR_FAMILIES.find((f) => f.label === 'Origin');
  const gid = 'grp_1';

  it('exposes the families the heatmap grid is sized from', () => {
    assert.ok(VECTOR_FAMILIES.length > 0);
    const labels = VECTOR_FAMILIES.map((f) => f.label);
    assert.equal(new Set(labels).size, labels.length, 'labels are React keys and must be unique');
    for (const family of VECTOR_FAMILIES) {
      assert.ok(family.keys.length > 0, `${family.label} needs at least one match key`);
      assert.ok(family.keys.every((k) => k === k.toLowerCase()), `${family.label} keys must be lowercase`);
    }
  });

  it('classifies a check by family, category, name or id', () => {
    // Catalog entries predating `vector_family` carry the vector only in their name or id, so
    // all four fields are searched. Matching is case-insensitive.
    assert.ok(checkMatchesFamily({ vector_family: 'dns' }, dns));
    assert.ok(checkMatchesFamily({ category: 'DNS' }, dns));
    assert.ok(checkMatchesFamily({ name: 'DNS amplification' }, dns));
    assert.ok(checkMatchesFamily({ check_id: 'chk_dns_flood' }, dns));
    assert.ok(!checkMatchesFamily({ name: 'TLS handshake' }, dns));
    assert.ok(!checkMatchesFamily({}, dns), 'a check with no fields matches nothing');
  });

  it('collects only the matching check ids, accepting check_id or id', () => {
    const checks = [
      { check_id: 'chk_dns', vector_family: 'dns' },
      { id: 'chk_dns_legacy', name: 'DNS resolver saturation' },
      { check_id: 'chk_origin', vector_family: 'origin' },
      { vector_family: 'dns' },
    ];
    assert.deepEqual(
      [...familyCheckIds(checks, dns)].sort(),
      ['chk_dns', 'chk_dns_legacy'],
      'a matching check with no id at all must be dropped, not added as an empty string',
    );
    assert.deepEqual([...familyCheckIds(checks, origin)], ['chk_origin']);
    assert.equal(familyCheckIds([], dns).size, 0);
  });

  it('joins family matching to coverage end to end', () => {
    // The path the heatmap actually walks: checks -> family ids -> cell status. Exercised
    // together because the two halves resolve check ids by different key sets (`id` is accepted
    // when collecting a check, but a record must use `check_id`/`checkId`/nested `check`).
    const checks = [{ id: 'chk_dns_legacy', name: 'DNS resolver saturation' }];
    const ids = familyCheckIds(checks, dns);
    const cov = familyCoverage({
      checkIds: ids,
      groupId: gid,
      testPolicies: [{ target_group_id: gid, check_id: 'chk_dns_legacy' }],
      runs: [],
      evidence: [{ target_group: { id: gid }, check: { check_id: 'chk_dns_legacy' } }],
    });
    assert.equal(cov.status, 'evidence');
    assert.equal(cov.evidenceCount, 1);
    assert.equal(cov.policyCount, 1);
    assert.equal(familyCoverage({ checkIds: familyCheckIds(checks, origin), groupId: gid, testPolicies: [], runs: [], evidence: [] }).status, 'no-data');
  });
});
