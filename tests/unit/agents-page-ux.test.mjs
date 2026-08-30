import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';

const source = readFileSync(
  path.resolve('apps/web/react/src/pages/functional-surfaces.tsx'),
  'utf8',
);
const agentsStart = source.indexOf('export function AgentsPage(');
const agentsEnd = source.indexOf('export function ValidationSurfacePage(', agentsStart);
const agentsSource = source.slice(agentsStart, agentsEnd);

assert.ok(agentsStart >= 0 && agentsEnd > agentsStart, 'AgentsPage source block must be discoverable');

describe('Agents page UX contract', () => {
  it('puts the registered-agent evidence surface before secondary fleet context', () => {
    const table = agentsSource.indexOf('title="Registered agents"');
    const snapshot = agentsSource.indexOf('<CardTitle>Fleet snapshot</CardTitle>');
    const boundary = agentsSource.indexOf('aria-label="Agent network and placement boundaries"');

    assert.ok(table >= 0, 'registered-agent table must render');
    assert.ok(table < snapshot, 'registered-agent table must precede the fleet summary');
    assert.ok(table < boundary, 'registered-agent table must precede explanatory boundary content');
    assert.match(agentsSource, /key: 'target-group',[\s\S]*label: 'Target group'/);
  });

  it('preserves partial auxiliary results and renders failures instead of empty-state claims', () => {
    assert.match(agentsSource, /Promise\.allSettled\(\[/);
    assert.match(agentsSource, /setReleaseLoadError\(apiErrorMessage\(/);
    assert.match(agentsSource, /setTrustKeyLoadError\(apiErrorMessage\(/);
    assert.match(agentsSource, /loadError=\{releaseLoadError\}/);
    assert.match(agentsSource, /loadError=\{trustKeyLoadError\}/);
    assert.match(agentsSource, /error=\{error \|\| coreDatasetError \|\| auxiliaryError\}/);
    assert.doesNotMatch(
      agentsSource,
      /Promise\.all\(\[[\s\S]{0,400}agent-update-trust-keys[\s\S]{0,400}\.catch\(\(\) =>/,
      'the two auxiliary reads must not collapse into a silent shared catch',
    );
  });

  it('does not present failed core datasets as zero agents or no target groups', () => {
    assert.match(agentsSource, /const agentsLoadError = data\.loadErrors\.agents/);
    assert.match(agentsSource, /const targetGroupsLoadError = data\.loadErrors\.targetGroups/);
    assert.match(agentsSource, /loadError=\{agentsLoadError\}/);
    assert.match(agentsSource, /count: tab\.id === 'fleet' && !agentsLoadError/);
    assert.match(agentsSource, /\{!agentsLoadError \? \([\s\S]*<CardTitle>Fleet snapshot<\/CardTitle>/);
    assert.match(agentsSource, /targetGroupsLoadError \?[\s\S]*'Target groups unavailable'/);
    assert.match(agentsSource, /targetGroupsLoadError \? \([\s\S]*Target groups could not be refreshed/);
    assert.match(agentsSource, /actionsDisabled=\{busy !== '' \|\| Boolean\(targetGroupsLoadError\) \|\| !selectedTargetGroup\}/);
    assert.match(agentsSource, /Agent inventory unavailable/);
    assert.match(agentsSource, /Declared groups unavailable/);
  });

  it('requires an explicit target-group choice for every bootstrap token', () => {
    assert.match(agentsSource, /useState\(''\);\n  const \[tokenScope/);
    assert.match(agentsSource, /targetGroupsLoadError[\s\S]*\? 'Target groups unavailable'[\s\S]*'Select a target group'/);
    assert.match(agentsSource, /if \(targetGroupsLoadError\) \{[\s\S]*return;[\s\S]*if \(!selectedTargetGroup\)/);
    assert.match(agentsSource, /if \(!selectedTargetGroup\) \{[\s\S]*return;[\s\S]*const minutes/);
    assert.match(agentsSource, /target_group_id: getString\(selectedTargetGroup, \['id'\], ''\)/);
    assert.match(agentsSource, /actionsDisabled=\{busy !== '' \|\| Boolean\(targetGroupsLoadError\) \|\| !selectedTargetGroup\}/);
    assert.doesNotMatch(agentsSource, /targetGroups\[0\]/);
    assert.doesNotMatch(agentsSource, /Tenant only/);
  });

  it('keeps revoke actions compact and semantically dangerous without filled-danger dominance', () => {
    const compactRevokeActions = agentsSource.match(/className="agents-revoke-action"/g) ?? [];
    assert.equal(compactRevokeActions.length, 3, 'agent, token, and trust-key revokes share the compact treatment');
    assert.doesNotMatch(agentsSource, /variant="danger"/);
    assert.match(agentsSource, /\.agents-revoke-action \{[\s\S]*var\(--danger\)/);
  });

  it('contains tabs and dense layouts within the Agents page at tablet and mobile widths', () => {
    assert.match(agentsSource, /\.agents-page \.tabs \{[\s\S]*width: fit-content;[\s\S]*max-width: 100%/);
    assert.match(agentsSource, /\.agents-page \.tabs \.tab \{[\s\S]*width: auto;[\s\S]*flex: 0 0 auto/);
    assert.match(agentsSource, /@media \(max-width: 840px\)/);
    assert.match(agentsSource, /@media \(max-width: 420px\)/);
    assert.match(agentsSource, /\.agents-page \.table-wrap[\s\S]*min-width: 0;[\s\S]*max-width: 100%/);

    const localStyle = agentsSource.match(/<style>\{`([\s\S]*?)`\}<\/style>/)?.[1] ?? '';
    assert.ok(localStyle, 'Agents page-local styles must remain discoverable');
    assert.doesNotMatch(localStyle, /#[0-9a-f]{3,8}\b/i, 'page-local styles must use existing tokens, not raw colors');
  });

  it('does not invent release state and withdraws stale install credentials', () => {
    assert.doesNotMatch(agentsSource, /\['channel'\], 'stable'/);
    assert.doesNotMatch(agentsSource, /\['state'\], 'active'/);
    assert.doesNotMatch(agentsSource, /\['rollout', 'percentage'\], 100/);
    assert.match(agentsSource, /Signed agent release metadata is incomplete\./);
    assert.match(agentsSource, /tokenSecret=\{tokenRevoked \? '' : tokenSecret\}/);
    assert.match(agentsSource, /Scoped to <strong>\{tokenScope\.label\}<\/strong>/);
  });
});
