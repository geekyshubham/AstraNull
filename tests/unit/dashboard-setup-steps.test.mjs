import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { buildSetupSteps } from '../../apps/web/react/src/lib/dashboard-metrics.ts';

const DASHBOARD = readFileSync(new URL('../../apps/web/react/src/pages/dashboard-page.tsx', import.meta.url), 'utf8');
const detailHref = (route, id) => `#${route}?id=${encodeURIComponent(id)}`;

function data(targets = [], loadErrors = {}) {
  return { targets, loadErrors };
}

const unverified = (id) => ({ id, kind: 'fqdn', value: `${id}.example.com`, verification_state: 'unverified' });
const verified = (id) => ({ id, kind: 'fqdn', value: `${id}.example.com`, verification_state: 'dns_verified' });

function currentSteps(steps) {
  return steps.filter((step) => step.state === 'current');
}

describe('dashboard first-run setup steps', () => {
  it('starts with declaring a target and links only the current step', () => {
    const steps = buildSetupSteps(data(), false, detailHref);
    assert.deepEqual(steps.map((step) => step.key), ['declare-target', 'verify-ownership', 'first-run']);
    assert.deepEqual(steps.map((step) => step.state), ['current', 'upcoming', 'upcoming']);
    assert.equal(steps[0].title, 'Declare the first target to protect');
    assert.equal(steps[0].ctaLabel, 'Add target');
    assert.equal(steps[0].href, '#targets?add=1');
    for (const step of steps.slice(1)) {
      assert.equal(step.href, undefined, `${step.key} is not possible yet, so it has no link`);
      assert.equal(step.ctaLabel, undefined);
    }
  });

  it('never links the run step while no declared target is ownership-verified', () => {
    for (const targets of [[], [unverified('tgt_a')], [unverified('tgt_a'), unverified('tgt_b')]]) {
      const steps = buildSetupSteps(data(targets), false, detailHref);
      const run = steps.find((step) => step.key === 'first-run');
      assert.notEqual(run.state, 'current');
      assert.equal(run.href, undefined);
      assert.ok(steps.every((step) => step.href !== '#targets?verification=verified'), 'no dead verified-filter link');
    }
  });

  it('points ownership proof at the first unverified target', () => {
    const steps = buildSetupSteps(data([unverified('tgt_a'), unverified('tgt_b')]), false, detailHref);
    const [declare, verify] = steps;
    assert.equal(declare.state, 'done');
    assert.equal(verify.state, 'current');
    assert.equal(verify.title, 'Prove ownership on a declared target');
    assert.equal(verify.ctaLabel, 'Prove ownership');
    assert.equal(verify.href, '#target-detail?id=tgt_a');
  });

  it('opens the validate tab of a verified target for the first bounded check', () => {
    const steps = buildSetupSteps(data([unverified('tgt_a'), verified('tgt_v')]), false, detailHref);
    const run = steps.find((step) => step.key === 'first-run');
    assert.deepEqual(steps.map((step) => step.state), ['done', 'done', 'current']);
    assert.equal(run.title, 'Run the first bounded check');
    assert.equal(run.ctaLabel, 'Run first check');
    assert.equal(run.href, '#target-detail?id=tgt_v&tab=validate');
  });

  it('has exactly one current step until evidence exists, then none', () => {
    const fixtures = [[], [unverified('tgt_a')], [verified('tgt_v')], [unverified('tgt_a'), verified('tgt_v')]];
    for (const targets of fixtures) {
      assert.equal(currentSteps(buildSetupSteps(data(targets), false, detailHref)).length, 1, JSON.stringify(targets));
      const withEvidence = buildSetupSteps(data(targets), true, detailHref);
      assert.equal(currentSteps(withEvidence).length, 0);
      assert.ok(withEvidence.every((step) => step.state === 'done'));
    }
  });

  it('returns no steps when the target inventory failed to load', () => {
    assert.deepEqual(buildSetupSteps(data([], { targets: 'Targets unavailable' }), false, detailHref), []);
  });

  it('renders setup as "Get started" without finding badges, and findings as "What to fix first"', () => {
    assert.match(DASHBOARD, /\{showSetup \? 'Get started' : 'What to fix first'\}/);
    assert.match(DASHBOARD, /Three steps before AstraNull has evidence: declare a target, prove ownership, run a bounded check\./);
    assert.match(DASHBOARD, /const showSetup = findingSteps\.length === 0 && currentSetupIndex >= 0 && !priorityFixesUnavailable;/, 'a findings load error is never masked by Get started');
    assert.match(DASHBOARD, /\) : showSetup \? \([\s\S]*?\) : priorityFixesUnavailable \? \(\s*<EmptyState icon=\{TriangleAlert\} title="Priority fixes unavailable\."/);
    assert.match(DASHBOARD, /`\$\{formatNumber\(findingSteps\.length\)\} open`/);
    assert.match(DASHBOARD, /`Step \$\{currentSetupIndex \+ 1\} of \$\{setupSteps\.length\}`/);
    assert.match(DASHBOARD, /`Then: \$\{step\.title\}`/);
    assert.doesNotMatch(DASHBOARD, /TO REVIEW|>Review<\/AnchorButton>/);
  });

  it('shows no score, no donut and no factors before the first evidence-backed verdict', () => {
    assert.match(DASHBOARD, /const evidenceMissing = !coverageUnavailable && targetsWithEvidence === 0 && serverMeasured === 0 && \(openOverview\.total \?\? 0\) === 0;/);
    assert.match(DASHBOARD, /rollUpPostureRows\(buildTargetPostureRows\(data, undefined, \{ openFindings: sampleRows, openCounts \}\), topLevelOf\)/);
    assert.match(DASHBOARD, /const noEvidence = evidenceMissing \|\| scoreStatus === 'not_applicable' \|\| scoreStatus === 'incomplete_inputs';/);
    assert.match(DASHBOARD, /const score = noEvidence \? null : publishedScore;/);
    assert.match(DASHBOARD, /hasEvidence: !noEvidence/);
    assert.match(DASHBOARD, /title="No evidence-backed verdicts yet\."/);
    assert.match(DASHBOARD, /\{needsFirstTarget \? \(\s*canWriteTargets \? <AnchorButton href="#targets\?add=1"[^>]*>Add target<\/AnchorButton>/);
    assert.match(DASHBOARD, /Validate a target/);
  });

  it('announces penalties, classifies zero-weight factors by score, and names an incomplete pack at any approval count', () => {
    assert.doesNotMatch(DASHBOARD, /PENALTY_FACTOR_KEYS/, 'no factor is a penalty by key alone');
    assert.match(DASHBOARD, /if \(Number\(factor\.score\) < 0\) return 'penalty';\s*return 'context';/);
    assert.match(DASHBOARD, /<span className="factor-score" role="img" aria-label=\{`\$\{label\}: penalty of \$\{points\} points`\}>/);
    assert.match(DASHBOARD, /: gate\.packComplete \? '' : 'Authorization pack incomplete',\s*`SOC approvals \$\{gate\.approvals\}\/2`/);
    assert.match(DASHBOARD, /typeof gate\.pack_complete === 'boolean'/);
  });

  it('shows the current setup CTA only to roles that can complete that step', () => {
    assert.match(DASHBOARD, /'declare-target': canWriteTargets,\s*'verify-ownership': canRunChecks,\s*'first-run': canRunChecks/);
    assert.match(DASHBOARD, /\{setupStepAllowed\[step\.key\] \? <AnchorButton href=\{step\.href\} variant="default" size="sm">\{step\.ctaLabel\}<\/AnchorButton> : null\}/);
    assert.match(DASHBOARD, /Your role cannot do this step\. Ask a workspace admin to complete it\./);
  });
});
