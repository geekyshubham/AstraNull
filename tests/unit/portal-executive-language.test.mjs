import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  dashboardReadinessMessage,
  evidenceModePresentation,
  evidenceTierInfo,
  plainProtectionLabel,
  plainVerdictLabel,
  plainVerificationLabel,
} from '../../apps/web/react/src/lib/plain-language.mjs';

const DASHBOARD_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/page-components.tsx', import.meta.url),
  'utf8',
);
const TARGET_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url),
  'utf8',
);

describe('portal executive language', () => {
  it('translates security verdicts without weakening or strengthening the result', () => {
    assert.equal(plainVerdictLabel('penetrated'), 'Attack traffic reached your server');
    assert.equal(plainVerdictLabel('bypassable'), 'A bypass path reached your server');
    assert.equal(plainVerdictLabel('protected'), 'Protection stopped the test traffic');
    assert.equal(plainVerdictLabel('inconclusive'), 'Not enough evidence');
  });

  it('gives ownership and protection states plain labels', () => {
    assert.equal(plainVerificationLabel('agent_verified'), 'Observed from inside');
    assert.equal(plainVerificationLabel('dns_verified'), 'Domain ownership verified');
    assert.equal(plainProtectionLabel('edge_protected'), 'Blocked at the edge only');
    assert.equal(plainProtectionLabel('underprotected'), 'Protection needs work');
  });

  it('defines all five evidence tiers in increasing operational context', () => {
    assert.equal(evidenceTierInfo('E1')?.label, 'Declared only');
    assert.equal(evidenceTierInfo('e2 transport')?.label, 'Connection observed');
    assert.equal(evidenceTierInfo('E3')?.label, 'Behavior observed');
    assert.equal(evidenceTierInfo('E4')?.label, 'SOC-governed');
    assert.equal(evidenceTierInfo('E5')?.label, 'Monitoring only');
  });

  it('never presents metadata markers or E1 declarations as live tests', () => {
    for (const record of [
      { probe_kind: 'metadata_marker', evidence_ids: ['evt_1'] },
      { evidence_tier: 'E1', last_run_id: 'run_1', last_verdict: 'pass' },
    ]) {
      const presentation = evidenceModePresentation(record);
      assert.equal(presentation.label, 'Not tested live');
      assert.equal(presentation.live, false);
      assert.match(presentation.detail, /Needs your evidence/);
    }
  });

  it('claims a live test only when a live-capable tier or probe also has a result', () => {
    assert.equal(evidenceModePresentation({ evidence_tier: 'E3' }).label, 'Live check available');
    assert.equal(
      evidenceModePresentation({ evidence_tier: 'E3', run_id: 'run_1', verdict: 'protected' }).label,
      'Tested live',
    );
    assert.equal(
      evidenceModePresentation({ evidence_ids: ['evt_1'] }).label,
      'Evidence recorded',
      'evidence without tier or probe kind must not be promoted to live',
    );
  });

  it('qualifies readiness by evidence coverage and high-priority gaps', () => {
    assert.match(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 1, coveragePercent: 100 }).headline,
      /Not ready yet/,
    );
    assert.match(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 0, coveragePercent: 50 }).headline,
      /Partly ready/,
    );
    assert.equal(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 0, coveragePercent: 100 }).headline,
      'Ready for the scenarios tested',
    );
    assert.doesNotMatch(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 0, coveragePercent: 100 }).headline,
      /^Ready for a DDoS attack$/,
    );
  });

  it('keeps executive and target summaries evidence-aware in source', () => {
    assert.match(DASHBOARD_SOURCE, /Are we ready for a DDoS attack\?/);
    assert.match(DASHBOARD_SOURCE, /Top fixes/);
    assert.match(DASHBOARD_SOURCE, /dashboardReadinessMessage/);
    assert.match(TARGET_SOURCE, /plain_language_summary/);
    assert.match(TARGET_SOURCE, /Protection at a glance/);
    assert.match(TARGET_SOURCE, /evidenceModePresentation/);
  });
});
