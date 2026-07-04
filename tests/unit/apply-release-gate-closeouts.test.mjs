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
});