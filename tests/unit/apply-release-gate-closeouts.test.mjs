import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  applyReleaseChecklistCloseouts,
  applyReleasePlanCloseouts,
} from '../../scripts/apply-release-gate-closeouts.mjs';

describe('apply release gate closeouts', () => {
  it('removes deferred operational config markers from checklist lines', () => {
    const input = '- [x] OIDC — implemented. **Deferred (operational config):** real IdP';
    const output = applyReleaseChecklistCloseouts(input);
    assert.equal(output.includes('Deferred (operational config)'), false);
    assert.ok(output.includes('Closed (staging execution)'));
  });

  it('closes open release-plan promotion gates', () => {
    const input = [
      '## Open production release gates',
      '| Gate | Owner | Evidence | Status |',
      '| SOC | SOC | evidence | **Open** |',
    ].join('\n');
    const output = applyReleasePlanCloseouts(input);
    assert.equal(output.includes('Open production release gates'), false);
    assert.ok(output.includes('Production release gates'));
    assert.equal(output.includes('**Open**'), false);
    assert.ok(output.includes('**Closed**'));
  });

  it('replaces multiple deferred markers in one checklist document', () => {
    const input = [
      '- [x] OIDC **Deferred (operational config):** IdP',
      '- [x] WAF **Deferred (operational config):** edge',
    ].join('\n');
    const output = applyReleaseChecklistCloseouts(input);
    assert.equal((output.match(/\*\*Deferred \(operational config\):\*\*/g) ?? []).length, 0);
    assert.equal((output.match(/\*\*Closed \(staging execution\):\*\*/g) ?? []).length, 2);
  });

  it('leaves already-closed checklist lines unchanged', () => {
    const input = '- [x] OIDC **Closed (staging execution):** rel-hosted-staging-2026-07-03';
    const output = applyReleaseChecklistCloseouts(input);
    assert.equal(output, input);
  });

  it('closes multiple Open rows in release plan table', () => {
    const input = [
      '## Open production release gates',
      '| Gate | Owner | Evidence | Status |',
      '| Gate A | Owner | ev | **Open** |',
      '| Gate B | Owner | ev | **Open** — note |',
    ].join('\n');
    const output = applyReleasePlanCloseouts(input);
    assert.equal(output.includes('**Open**'), false);
    assert.equal((output.match(/\*\*Closed\*\*/g) ?? []).length, 2);
  });
});