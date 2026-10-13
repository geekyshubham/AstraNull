import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { latestEvidenceRunByTarget, latestRunVerdict } from '../../apps/web/react/src/lib/dashboard-metrics.ts';

const PAGES = new URL('../../apps/web/react/src/pages/', import.meta.url);
const readPage = (name) => readFileSync(new URL(name, PAGES), 'utf8');

describe('Targets portal contract', () => {
  it('renders the required inventory fields and safe add/edit/remove behavior', () => {
    const source = readPage('targets-page.tsx');

    // Current release: kind moves into the target cell; ownership and last validation are columns.
    for (const label of [
      'Target',
      'Ownership',
      'Last validation',
      'Tags',

      'Added from',
    ]) {
      assert.match(source, new RegExp(`label: '${label}'`));
    }
    assert.match(source, /<span>\{formatTargetKind\(getString\(item, \['kind'\], ''\), getString\(item, \['value'\], ''\)\)\}<\/span>/, 'kind stays visible in the target cell');
    assert.doesNotMatch(source, /function targetKindLabel/, 'kind labels come from the shared formatTargetKind');
    // Pending ownership is never counted as ready, and a missing timestamp is not "Never".
    assert.doesNotMatch(source, /Ready for validation/);
    assert.doesNotMatch(source, /Not available in inventory/);
    assert.match(source, /runsUnavailable \? 'Unavailable' : 'No result yet'/);
    assert.match(source, /\{runsUnavailable \? \(\s*<Badge[^>]*>Unavailable<\/Badge>/, 'a recorded date never pairs with "Not recorded" when runs failed to load');
    assert.doesNotMatch(source, /: 'Never'/);
    // ADR-0008: direct target creation via POST /v1/targets with top-level tags + optional group.
    assert.match(source, /requestJson\(config, session, '\/v1\/targets', \{ method: 'POST', body \}\)/);
    assert.doesNotMatch(source, /body\.target_group_id|label: 'Target group'/);
    // Per-target tag edit via PATCH /v1/targets/:id (kind/value immutable).
    assert.match(source, /\/v1\/targets\/\$\{encodeURIComponent\(editTargetId\)\}/);
    assert.match(source, /method: 'PATCH'/);
    assert.match(source, /method: 'DELETE'/);
    assert.match(source, /Existing evidence is retained/);
    // The "not automatic discovery" callout is removed in the revamp.
    assert.doesNotMatch(source, /Declared inventory is not automatic discovery/);
    // Tag input enforces the ADR tag rule inline.
    assert.match(source, /\^\[a-z0-9\]\[a-z0-9:_\.-\]\{0,47\}\$/);
    assert.match(source, /Add target/);
    assert.doesNotMatch(source, /Add single domain/);
  });

  it('uses explicit Open target links instead of focusable or clickable native rows', () => {
    const targets = readPage('targets-page.tsx');
    const finding = readPage('finding-detail-view.tsx');

    for (const source of [finding]) {
      assert.match(source, /aria-label={`Open target \$\{getString\(item,/);
    }
    // Targets leads each row with one explicit link: Verify ownership only for a pending target the
    // viewer can change, otherwise Open.
    assert.match(targets, /const promptVerify = !verified && canWriteTargets;/);
    assert.match(targets, /aria-label=\{promptVerify \? `Verify ownership of \$\{value\}` : `Open target \$\{value\}`\}/);
    assert.match(targets, /\{promptVerify \? 'Verify' : 'Open'\}/);
    assert.match(targets, /href=\{verified \? buildDetailHref\('target-detail', id\)/);
    assert.doesNotMatch(targets, /function rowProps|getRowProps=\{\(item\) => rowProps/);
    assert.doesNotMatch(finding, /targetRowNavProps/);
  });


  it('offers Validate only on ownership-verified rows for roles that can start a run', () => {
    const source = readPage('targets-page.tsx');
    assert.match(source, /import \{ canStartRun \} from '\.\.\/lib\/run-permissions\.mjs';/);
    assert.match(source, /const canRunChecks = canStartRun\(session\.role\);/);
    assert.match(source, /\{verified && canRunChecks \? \(\s*<AnchorButton[\s\S]*?href=\{`\$\{buildDetailHref\('target-detail', id\)\}&tab=validate`\}[\s\S]*?aria-label=\{`Validate \$\{value\}`\}/);
    assert.equal((source.match(/&tab=validate/g) ?? []).length, 1, 'the validate deep link appears only behind the verified-and-permitted guard');
  });

  it('opens the declare form from the #targets?add=1 deep link only for target writers, then strips the param', () => {
    const source = readPage('targets-page.tsx');
    assert.match(source, /useState\(\(\) => canWriteTargets && getRouteParam\('add'\) === '1'\)/);
    assert.match(source, /canWriteTargetsRef\.current = canWriteTargets;/, 'the hash listener reads current permissions, not the first render');
    assert.match(source, /if \(requested === '1' && canWriteTargetsRef\.current\) setShowAdd\(true\);\s*replaceRouteParams\(\{ add: null \}\);/);
    assert.match(source, /window\.addEventListener\('hashchange', sync\)/);
    assert.match(source, /if \(showAdd\) kindSelectRef\.current\?\.focus\(\);/, 'opening the form moves focus to Kind');
  });

  it('explains each add-target choice and never promises CIDR ranges', () => {
    const source = readPage('targets-page.tsx');
    assert.match(source, /<small id="add-kind-hint" className="muted">\{addKindOption\.hint\}<\/small>/);
    assert.match(source, /placeholder=\{addKindOption\.placeholder\}/);
    assert.match(source, /aria-describedby="add-behavior-hint"/);
    assert.match(source, /Ranges \(CIDR\) are not supported; declare each IP you own\./);
    assert.doesNotMatch(source, /hostnames, IPs and CIDRs|IP, CIDR or endpoint/);
    assert.match(source, /role="group" aria-label="Target inventory summary"/);
    assert.match(source, /addBehavior === UNDECIDED_BEHAVIOR \? \{\} : \{ expected_behavior: addBehavior \}/);
    assert.doesNotMatch(source, /declare one later on the target/, 'no promise of a post-creation expected-behaviour editor');
  });

  it('shows the latest evidence-backed result per target and "No result yet" for an unprobed target', () => {
    const runs = [
      { id: 'run_old', target_id: 'tgt_verified', status: 'completed', verdict: { id: 'vrd_1', verdict: 'gap' }, completed_at: '2026-09-01T10:00:00.000Z' },
      { id: 'run_new', target_id: 'tgt_verified', status: 'completed', verdict: { id: 'vrd_2', verdict: 'protected' }, completed_at: '2026-09-02T10:00:00.000Z' },
      { id: 'run_unbacked', target_id: 'tgt_verified', status: 'completed', verdict: 'gap', completed_at: '2026-09-03T10:00:00.000Z' }
    ];
    const latest = latestEvidenceRunByTarget(runs);
    const result = latestRunVerdict(latest.get('tgt_verified'));
    assert.equal(latest.get('tgt_verified')?.id, 'run_new', 'an unbacked newer run never replaces the evidence-backed result');
    assert.equal(result?.status, 'pass');
    assert.equal(result?.label, 'Pass');
    assert.equal(result?.completedAt, '2026-09-02T10:00:00.000Z');
    assert.equal(latest.has('tgt_unprobed'), false);
    assert.equal(latestRunVerdict(latest.get('tgt_unprobed')), null);
  });

  it('exposes disclosure semantics on the Add target toggle (A11Y-01)', () => {
    const source = readPage('targets-page.tsx');
    // The trigger announces expand/collapse state and the form it controls, mirroring the
    // mobile "Open navigation" disclosure pattern.
    assert.match(source, /aria-expanded=\{showAdd\}\s+aria-controls="target-declare-form"/);
    // The controlled form carries the stable id the trigger points at.
    assert.match(source, /<form id="target-declare-form"/);
  });

  it('collapses the targets toolbar to one column at <=620px; the search-plus-three-filters desktop grid applies only at >=1121px (TARGETS-01)', () => {
    const styles = readFileSync(new URL('../../apps/web/react/src/styles.css', import.meta.url), 'utf8');
    // The placeholder-clipping desktop rule must be scoped above the mobile breakpoint so it no
    // longer out-specifies the single-column @media(max-width:620px) rule.
    assert.match(
      styles,
      /@media \(min-width: 1121px\) \{\s*body \.targets-page \.targets-toolbar \{\s*grid-template-columns: minmax\(280px, 1\.7fr\) repeat\(3, minmax\(150px, 1fr\)\);/,
    );
    // No unconditional body-scoped toolbar grid rule may remain (that was the 928px-overflow cause).
    assert.doesNotMatch(
      styles,
      /^body \.targets-page \.targets-toolbar \{\s*\n\s*grid-template-columns: minmax\(280px/m,
    );
  });

  it('keeps integration domain intake and requested DNS providers visible', () => {
    const source = readPage('integrations-page.tsx');

    for (const provider of ['GoDaddy', 'Namecheap', 'Hetzner DNS']) {
      assert.match(source, new RegExp(`label: '${provider}'`));
    }
    assert.match(source, /No IP-discovery service is contacted/);
  });
});
