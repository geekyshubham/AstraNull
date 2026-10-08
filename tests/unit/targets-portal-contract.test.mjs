import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

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
      'Added',
    ]) {
      assert.match(source, new RegExp(`label: '${label}'`));
    }
    assert.match(source, /<span>\{targetKindLabel\(item\)\}<\/span>/, 'kind stays visible in the target cell');
    // Pending ownership is never counted as ready, and a missing timestamp is not "Never".
    assert.doesNotMatch(source, /Ready for validation/);
    assert.match(source, /Not available in inventory/);
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
    // Targets leads each row with one explicit link: Open, or Verify ownership while pending.
    assert.match(targets, /aria-label=\{verified \? `Open target \$\{value\}` : `Verify ownership of \$\{value\}`\}/);
    assert.match(targets, /href=\{verified \? buildDetailHref\('target-detail', id\)/);
    assert.doesNotMatch(targets, /function rowProps|getRowProps=\{\(item\) => rowProps/);
    assert.doesNotMatch(finding, /targetRowNavProps/);
  });


  it('exposes disclosure semantics on the Add target toggle (A11Y-01)', () => {
    const source = readPage('targets-page.tsx');
    // The trigger announces expand/collapse state and the form it controls, mirroring the
    // mobile "Open navigation" disclosure pattern.
    assert.match(source, /aria-expanded=\{showAdd\}\s+aria-controls="target-declare-form"/);
    // The controlled form carries the stable id the trigger points at.
    assert.match(source, /<form id="target-declare-form"/);
  });

  it('collapses the targets toolbar to one column at <=620px without a desktop rule overriding it (TARGETS-01)', () => {
    const styles = readFileSync(new URL('../../apps/web/react/src/styles.css', import.meta.url), 'utf8');
    // The placeholder-clipping desktop rule must be scoped above the mobile breakpoint so it no
    // longer out-specifies the single-column @media(max-width:620px) rule.
    assert.match(
      styles,
      /@media \(min-width: 621px\) \{\s*body \.targets-page \.targets-toolbar \{\s*grid-template-columns: minmax\(280px, 1\.7fr\) repeat\(4, minmax\(150px, 1fr\)\);/,
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
