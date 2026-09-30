import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const PAGES = new URL('../../apps/web/react/src/pages/', import.meta.url);
const readPage = (name) => readFileSync(new URL(name, PAGES), 'utf8');

describe('Targets portal contract', () => {
  it('renders the required inventory fields and safe add/edit/remove behavior', () => {
    const source = readPage('targets-page.tsx');

    for (const label of [
      'Target',
      'Kind',
      'Tags',
      'Target group',
      'Verification',
      'Test eligibility',
      'Added from',
      'Added',
    ]) {
      assert.match(source, new RegExp(`label: '${label}'`));
    }
    // ADR-0008: direct target creation via POST /v1/targets with top-level tags + optional group.
    assert.match(source, /requestJson\(config, session, '\/v1\/targets', \{ method: 'POST', body \}\)/);
    assert.match(source, /body\.target_group_id = groupId/);
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
    const targetGroup = readPage('target-group-detail-view.tsx');
    const finding = readPage('finding-detail-view.tsx');

    for (const source of [targets, targetGroup, finding]) {
      assert.match(source, /aria-label={`Open target \$\{getString\(item,/);
    }
    assert.doesNotMatch(targets, /function rowProps|getRowProps=\{\(item\) => rowProps/);
    assert.doesNotMatch(targetGroup, /targetRowNavProps|tg-target-row|isNestedInteractiveTarget/);
    assert.doesNotMatch(finding, /targetRowNavProps/);
    assert.match(targetGroup, />\s*Verify\s*<\/Button>[\s\S]*>\s*Run test\s*<\/Button>[\s\S]*Remove/m);
  });

  it('keeps target-group scheduling and removal on bounded, real APIs', () => {
    const source = readPage('target-group-detail-view.tsx');

    assert.match(source, /const \{ confirm \} = useConfirmModal\(\)/);
    assert.match(source, /if \(!await confirm\(\{/);
    assert.doesNotMatch(source, /window\.confirm\(/);
    assert.match(source, /method: 'DELETE'/);
    assert.match(source, /requestJson\(config, session, '\/v1\/test-policies'/);
    assert.match(source, /safe_windows: \[\{ day, start, end, timezone \}\]/);
    assert.match(source, /customer-runnable check/);
    assert.match(source, /They do not authorize or launch unmanaged DDoS traffic/);
  });

  it('keeps integration domain intake and requested DNS providers visible', () => {
    const source = readPage('integrations-page.tsx');

    for (const provider of ['GoDaddy', 'Namecheap', 'Hetzner DNS']) {
      assert.match(source, new RegExp(`label: '${provider}'`));
    }
    assert.match(source, /No IP-discovery service is contacted/);
  });
});
